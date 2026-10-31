//! Recherche de nombreux motifs d'octets à la fois, écrite pour Vanguard : le moteur commun des signatures (règles
//! YARA aujourd'hui, `moteur_yara`, et demain les signatures de corps de ClamAV). Un motif est une suite d'éléments :
//! octet connu (ou à moitié, `4?`), joker (`??`), saut borné (`[2-8]`), choix entre plusieurs suites (`( 8B | FF 15 )`).
//!
//! Comment : de chaque motif, on tire un « atome », quelques octets connus qui se suivent (au plus `ATOME_MAX`), choisis
//! parmi les moins banals. Tous les atomes vont dans un seul automate d'Aho et Corasick (« Efficient string matching:
//! an aid to bibliographic search », Communications of the ACM, 1975) : une lecture des données, un pas par octet,
//! trouve toutes les places de tous les atomes. Chaque place est ensuite vérifiée contre le motif entier : vers
//! l'avant pour ce qui suit l'atome, vers l'arrière pour ce qui le précède. Une vérification suit l'ensemble des
//! positions possibles (un saut l'élargit, un octet le filtre), jamais un retour en arrière : son coût est borné par la
//! longueur du motif fois le nombre de ses éléments, quelles que soient les données.
//!
//! Les données sont hostiles (fichiers, mémoire d'autres programmes) : rien n'y est cru, aucune position n'est lue hors
//! des données, un délai coupe une recherche trop longue. Les motifs viennent de règles de confiance moyenne : leur
//! taille, leur longueur et la profondeur de leurs choix sont bornées à la construction (`Motif::nouveau`), et
//! l'automate a un nombre d'états borné (`ETATS_MAX`).
//!
//! Module pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::io::Read;
use std::time::Instant;

/// Les octets d'un atome, au plus : quatre suffisent à rendre rares les fausses pistes, et gardent l'automate petit.
pub(crate) const ATOME_MAX: usize = 4;
/// La longueur la plus grande d'un motif (sauts compris), et son nombre d'éléments : bien au-delà des règles réelles
/// (quelques milliers d'octets), assez bas pour qu'une vérification reste brève.
pub(crate) const LONGUEUR_MAX: u32 = 1 << 16;
pub(crate) const ELEMENTS_MAX: usize = 1 << 16;
/// Le coût d'une vérification, au plus : éléments × positions suivies (la longueur du motif). Les règles réelles
/// restent sous quelques millions ; au-delà, une seule vérification pourrait dépasser de loin le délai.
pub(crate) const COUT_MAX: u64 = 1 << 24;
/// Le travail de vérification (en unités de coût) entre deux lectures de l'horloge.
const TRAVAIL_ENTRE_DELAIS: u64 = 1 << 20;
/// Des choix dans des choix : au-delà, refusé.
pub(crate) const PROFONDEUR_MAX: usize = 8;
/// Les états de l'automate, au plus (chacun garde ses transitions). En table complète (256 transitions par état),
/// seulement jusqu'à `ETATS_TABLE` états : 16 Mio au plus ; au-delà, l'automate suit ses liens d'échec, plus lent mais
/// sans grossir.
pub(crate) const ETATS_MAX: usize = 1 << 22;
const ETATS_TABLE: usize = 1 << 14;
/// Les données lues d'un coup dans un flux.
pub(crate) const BLOC: usize = 1 << 20;

// Les états, les motifs et les longueurs sont des u32 : ils doivent tenir dans un usize.
const _: () = assert!(usize::BITS >= u32::BITS);

/// Un état, un motif ou une longueur (u32) comme usize.
#[expect(
    clippy::as_conversions,
    reason = "usize a au moins 32 bits (assertion juste au-dessus) : conversion exacte"
)]
fn en_usize(n: u32) -> usize {
    n as usize
}

/// Un élément de motif.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Element {
    /// Un octet `o` tel que `o & masque == valeur` : `masque` 0xFF pour un octet connu, 0xF0 ou 0x0F pour un demi,
    /// 0 pour un joker.
    Octet { valeur: u8, masque: u8 },
    /// De `min` à `max` octets quelconques.
    Saut { min: u32, max: u32 },
    /// L'une des suites, au choix.
    Choix(Vec<Vec<Element>>),
}

/// Pourquoi un motif est refusé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refus {
    Vide,
    /// Un saut au début ou à la fin, ou un saut dont le minimum dépasse le maximum.
    Saut,
    /// Plus long que `LONGUEUR_MAX`, plus de `ELEMENTS_MAX` éléments, ou une vérification plus chère que `COUT_MAX`.
    TropLong,
    /// Des choix imbriqués au-delà de `PROFONDEUR_MAX`, ou un choix sans suite, ou une suite vide.
    Choix,
    /// Aucun octet connu hors des choix : rien à chercher dans l'automate.
    SansAtome,
}

/// Un motif prêt à chercher : ses éléments, et l'atome tiré de ses éléments du premier niveau.
#[derive(Clone, Debug)]
pub(crate) struct Motif {
    elements: Vec<Element>,
    atome: Vec<u8>,
    /// Les éléments avant l'atome, retournés (et leurs choix aussi) : la vérification vers l'arrière les lit dans
    /// l'ordre.
    avant: Vec<Element>,
    apres: Vec<Element>,
    /// La longueur la plus grande de ce qui précède l'atome, de ce qui le suit, et du motif entier.
    avant_max: u32,
    apres_max: u32,
    longueur_max: u32,
    /// Le coût d'une vérification, au plus (voir `COUT_MAX`).
    cout: u64,
}

/// Longueurs la plus petite et la plus grande d'une suite d'éléments, saturées.
fn longueurs(elements: &[Element]) -> (u64, u64) {
    let mut total = (0u64, 0u64);
    for e in elements {
        let (a, b) = match e {
            Element::Octet { .. } => (1, 1),
            Element::Saut { min, max } => (u64::from(*min), u64::from(*max)),
            Element::Choix(suites) => {
                let l: Vec<(u64, u64)> = suites.iter().map(|s| longueurs(s)).collect();
                (
                    l.iter().map(|x| x.0).min().unwrap_or(0),
                    l.iter().map(|x| x.1).max().unwrap_or(0),
                )
            }
        };
        total = (total.0.saturating_add(a), total.1.saturating_add(b));
    }
    total
}

/// Le coût d'une vérification de `elements` depuis `largeur` positions (au plus) : chaque élément coûte autant que les
/// positions suivies à son entrée ; un saut, ou des choix de longueurs différentes, en élargissent l'ensemble. Rend
/// (coût, largeur à la sortie), saturés.
fn cout(elements: &[Element], mut largeur: u64) -> (u64, u64) {
    let mut total = 0u64;
    for e in elements {
        total = total.saturating_add(largeur);
        match e {
            Element::Octet { .. } => {}
            // Les positions restent dans un intervalle : un saut l'élargit de sa marge.
            // `min` ≤ `max` : contrôlé avant (controler).
            Element::Saut { min, max } => largeur = largeur.saturating_add(u64::from(max.saturating_sub(*min))),
            Element::Choix(suites) => {
                let (court, long) = longueurs(std::slice::from_ref(e));
                for s in suites {
                    total = total.saturating_add(cout(s, largeur).0);
                }
                // Le plus court des minimums ne dépasse jamais le plus long des maximums.
                largeur = largeur.saturating_add(long.saturating_sub(court));
            }
        }
        // Les positions restent distinctes et dans la longueur du motif.
        largeur = largeur.min(u64::from(LONGUEUR_MAX) + 1);
    }
    (total, largeur)
}

/// Contrôle la forme d'une suite (choix non vides, profondeur, sauts dans l'ordre) et compte ses éléments.
fn controler(elements: &[Element], profondeur: usize, compte: &mut usize) -> Result<(), Refus> {
    if profondeur > PROFONDEUR_MAX {
        return Err(Refus::Choix);
    }
    for e in elements {
        *compte = compte.saturating_add(1);
        if *compte > ELEMENTS_MAX {
            return Err(Refus::TropLong);
        }
        match e {
            Element::Octet { .. } => {}
            Element::Saut { min, max } => {
                if min > max {
                    return Err(Refus::Saut);
                }
            }
            Element::Choix(suites) => {
                if suites.is_empty() || suites.iter().any(Vec::is_empty) {
                    return Err(Refus::Choix);
                }
                for s in suites {
                    // Borné : au-delà de PROFONDEUR_MAX, refusé dès l'entrée.
                    controler(s, profondeur.saturating_add(1), compte)?;
                }
            }
        }
    }
    Ok(())
}

/// Une suite retournée, choix compris : lue de droite à gauche.
fn retourner(elements: &[Element]) -> Vec<Element> {
    elements
        .iter()
        .rev()
        .map(|e| match e {
            Element::Choix(suites) => Element::Choix(suites.iter().map(|s| retourner(s)).collect()),
            autre => autre.clone(),
        })
        .collect()
}

/// La valeur d'un octet comme atome : les octets de remplissage ou de code banal (zéros, 0xFF, int3, nop, espace,
/// retours à la ligne) se retrouvent partout et donnent de fausses pistes.
fn rarete(o: u8) -> u32 {
    match o {
        0x00 | 0xFF => 1,
        0xCC | 0x90 | 0x20 | 0x0A | 0x0D | 0x01 | 0x8B | 0x89 | 0xE8 => 3,
        _ => 6,
    }
}

/// La meilleure fenêtre d'au plus `ATOME_MAX` octets connus qui se suivent au premier niveau : (début, longueur).
fn choisir_atome(elements: &[Element]) -> Option<(usize, usize)> {
    let connu = |e: &Element| matches!(e, Element::Octet { masque: 0xFF, .. });
    let octet = |e: &Element| match e {
        Element::Octet { valeur, .. } => *valeur,
        _ => 0,
    };
    let mut meilleur: Option<(u32, usize, usize)> = None;
    // Les suites d'éléments tous connus ou tous inconnus, et la position de chacune.
    let mut position = 0usize;
    for suite in elements.chunk_by(|a, b| connu(a) == connu(b)) {
        if suite.first().is_some_and(connu) {
            for decalage in 0..suite.len() {
                let fenetre: Vec<u8> = suite.iter().skip(decalage).take(ATOME_MAX).map(octet).collect();
                let mut distincts = fenetre.clone();
                distincts.sort_unstable();
                distincts.dedup();
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "ATOME_MAX = 4 octets de rareté ≤ 6, 3 distincts de plus au plus : note ≤ 4 × 6 + 2 × 3"
                )]
                let note = fenetre.iter().map(|o| rarete(*o)).sum::<u32>()
                    + 2 * u32::try_from(distincts.len().saturating_sub(1)).unwrap_or(0);
                if meilleur.is_none_or(|(m, _, _)| note > m) {
                    meilleur = Some((note, position.checked_add(decalage)?, fenetre.len()));
                }
            }
        }
        // Une somme de longueurs de tranches de `elements` : ne dépasse pas elements.len().
        position = position.checked_add(suite.len())?;
    }
    meilleur.map(|(_, d, n)| (d, n))
}

impl Motif {
    pub(crate) fn nouveau(elements: Vec<Element>) -> Result<Motif, Refus> {
        if elements.is_empty() {
            return Err(Refus::Vide);
        }
        if matches!(elements.first(), Some(Element::Saut { .. }))
            || matches!(elements.last(), Some(Element::Saut { .. }))
        {
            return Err(Refus::Saut);
        }
        controler(&elements, 0, &mut 0)?;
        let (_, max) = longueurs(&elements);
        if max > u64::from(LONGUEUR_MAX) {
            return Err(Refus::TropLong);
        }
        let cout = cout(&elements, 1).0;
        if cout > COUT_MAX {
            return Err(Refus::TropLong);
        }
        let (debut, n) = choisir_atome(&elements).ok_or(Refus::SansAtome)?;
        // L'atome a été choisi dans `elements` : la coupe ne peut manquer, mais si elle manquait, la chaîne serait
        // refusée, jamais cherchée de travers.
        let (avant, reste) = elements.split_at_checked(debut).ok_or(Refus::SansAtome)?;
        let (atome, apres) = reste.split_at_checked(n).ok_or(Refus::SansAtome)?;
        let atome = atome
            .iter()
            .map(|e| match e {
                Element::Octet { valeur, .. } => *valeur,
                _ => 0,
            })
            .collect();
        let avant = retourner(avant);
        let apres = apres.to_vec();
        // Les trois longueurs tiennent dans LONGUEUR_MAX, contrôlé plus haut.
        let borne = |n: u64| u32::try_from(n).unwrap_or(LONGUEUR_MAX);
        let avant_max = borne(longueurs(&avant).1);
        let apres_max = borne(longueurs(&apres).1);
        Ok(Motif {
            elements,
            atome,
            avant,
            apres,
            avant_max,
            apres_max,
            longueur_max: borne(max),
            cout,
        })
    }

    pub(crate) fn longueur_max(&self) -> u32 {
        self.longueur_max
    }

    #[cfg(test)]
    pub(crate) fn atome(&self) -> &[u8] {
        &self.atome
    }

    /// Le motif commence-t-il exactement à `donnees[0]` ? `donnees` : à partir de la position voulue, jusqu'à la fin des
    /// données ou au moins `longueur_max` octets.
    pub(crate) fn commence_ici(&self, donnees: &[u8]) -> bool {
        !etendre(&self.elements, vec![0], &|d| donnees.get(en_usize(d)).copied()).is_empty()
    }

    /// Le motif se trouve-t-il autour de l'atome qui commence à `donnees[atome]` ?
    fn autour(&self, donnees: &[u8], atome: usize) -> bool {
        let Some(fin) = atome.checked_add(self.atome.len()) else {
            return false;
        };
        // L'atome lui-même a été trouvé par l'automate ; seul ce qui l'entoure reste à voir.
        let apres = etendre(&self.apres, vec![0], &|d| {
            fin.checked_add(en_usize(d)).and_then(|p| donnees.get(p).copied())
        });
        if apres.is_empty() {
            return false;
        }
        !etendre(&self.avant, vec![0], &|d| {
            atome
                .checked_sub(en_usize(d))
                .and_then(|p| p.checked_sub(1))
                .and_then(|p| donnees.get(p).copied())
        })
        .is_empty()
    }

    /// La position qui suit tout ce que le motif peut lire après l'atome qui commence à `atome`.
    fn fin_possible(&self, atome: u64) -> Option<u64> {
        atome
            .checked_add(u64::try_from(self.atome.len()).ok()?)?
            .checked_add(u64::from(self.apres_max))
    }
}

/// Les positions atteintes après `elements`, depuis `positions` (triées, sans doublon), `lire(d)` donnant l'octet à la
/// distance `d` de l'ancre (None hors des données).
fn etendre(elements: &[Element], mut positions: Vec<u32>, lire: &impl Fn(u32) -> Option<u8>) -> Vec<u32> {
    for e in elements {
        if positions.is_empty() {
            break;
        }
        match e {
            Element::Octet { valeur, masque } => {
                positions.retain(|&p| lire(p).is_some_and(|o| o & masque == *valeur));
                for p in &mut positions {
                    // Comme pour les sauts : saturé, au-delà de toute donnée lue.
                    *p = p.saturating_add(1);
                }
            }
            Element::Saut { min, max } => {
                // Les intervalles [p+min, p+max], fusionnés : les positions restent triées et uniques.
                let mut nouvelles = Vec::new();
                let mut courant: Option<(u32, u32)> = None;
                for &p in &positions {
                    let (a, b) = (p.saturating_add(*min), p.saturating_add(*max));
                    match courant {
                        Some((ca, cb)) if a <= cb.saturating_add(1) => courant = Some((ca, cb.max(b))),
                        Some((ca, cb)) => {
                            nouvelles.extend(ca..=cb);
                            courant = Some((a, b));
                        }
                        None => courant = Some((a, b)),
                    }
                }
                if let Some((ca, cb)) = courant {
                    nouvelles.extend(ca..=cb);
                }
                positions = nouvelles;
            }
            Element::Choix(suites) => {
                let mut union = Vec::new();
                for s in suites {
                    union.extend(etendre(s, positions.clone(), lire));
                }
                union.sort_unstable();
                union.dedup();
                positions = union;
            }
        }
    }
    positions
}

/// Pourquoi une recherche s'est arrêtée avant la fin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Echec {
    /// Le délai est passé.
    Delai,
    /// Les données ne se lisent plus.
    Lecture,
}

/// Un état de l'automate en construction.
#[derive(Default)]
struct Noeud {
    /// Transitions, triées par octet.
    fils: Vec<(u8, u32)>,
    echec: u32,
    /// Les motifs dont l'atome finit ici, et l'état suivant (par les liens d'échec) qui en a aussi : la chaîne des
    /// sorties, sans les recopier d'un état à l'autre.
    sorties: Vec<u32>,
    sortie_suivante: u32,
}

/// L'automate des atomes.
pub(crate) struct Automate {
    noeuds: Vec<Noeud>,
    /// Table complète des transitions (état × 256), quand elle tient dans `ETATS_TABLE`.
    table: Option<Vec<u32>>,
}

/// Aucun état : fin de la chaîne des sorties (l'état 0, la racine, n'a jamais de sortie, aucun atome n'étant vide).
const AUCUN: u32 = 0;

impl Automate {
    /// L'automate des atomes `atomes[i]` (le motif `i`). `None` : plus de `ETATS_MAX` états.
    fn construire(atomes: &[&[u8]]) -> Option<Automate> {
        let mut noeuds = vec![Noeud::default()];
        // Les états ne sont jamais lus par un index : un état hors de `noeuds` (impossible, chacun y est poussé avant
        // d'être noté) refuserait l'automate au lieu de faire planter l'analyse.
        for (i, atome) in atomes.iter().enumerate() {
            let mut etat = 0usize;
            for &o in *atome {
                let compte = noeuds.len();
                let noeud = noeuds.get_mut(etat)?;
                etat = match noeud.fils.binary_search_by_key(&o, |f| f.0) {
                    Ok(k) => en_usize(noeud.fils.get(k)?.1),
                    Err(k) => {
                        if compte >= ETATS_MAX {
                            return None;
                        }
                        let nouveau = u32::try_from(compte).ok()?;
                        noeud.fils.insert(k, (o, nouveau));
                        noeuds.push(Noeud::default());
                        compte
                    }
                };
            }
            noeuds.get_mut(etat)?.sorties.push(u32::try_from(i).ok()?);
        }
        // Liens d'échec, en largeur : l'échec d'un état est le plus long suffixe de son chemin qui soit aussi un état.
        let mut file: std::collections::VecDeque<u32> = noeuds.first()?.fils.iter().map(|f| f.1).collect();
        while let Some(etat) = file.pop_front() {
            let courant = noeuds.get(en_usize(etat))?;
            let depart = courant.echec;
            for (o, fils) in courant.fils.clone() {
                let mut e = depart;
                let echec = loop {
                    let n = noeuds.get(en_usize(e))?;
                    if let Some(&(_, f)) = n
                        .fils
                        .binary_search_by_key(&o, |f| f.0)
                        .ok()
                        .and_then(|k| n.fils.get(k))
                    {
                        break f;
                    }
                    if e == 0 {
                        break 0;
                    }
                    e = n.echec;
                };
                let cible = noeuds.get(en_usize(echec))?;
                let suivante = if cible.sorties.is_empty() {
                    cible.sortie_suivante
                } else {
                    echec
                };
                let n = noeuds.get_mut(en_usize(fils))?;
                n.echec = echec;
                n.sortie_suivante = suivante;
                file.push_back(fils);
            }
        }
        // Tout état noté (transition, échec, sortie suivante, et les sorties : des motifs) existe : `noeud` s'y fie
        // pendant l'analyse, sans rien vérifier par octet lu.
        let compte = u32::try_from(noeuds.len()).ok()?;
        let motifs = u32::try_from(atomes.len()).ok()?;
        let valide = |n: &Noeud| {
            n.echec < compte
                && n.sortie_suivante < compte
                && n.fils.iter().all(|f| f.1 < compte)
                && n.sorties.iter().all(|&m| m < motifs)
        };
        if !noeuds.iter().all(valide) {
            return None;
        }
        let mut automate = Automate { noeuds, table: None };
        if automate.noeuds.len() <= ETATS_TABLE {
            let mut table = vec![0u32; automate.noeuds.len().checked_mul(256)?];
            for (etat, ligne) in (0u32..).zip(table.as_chunks_mut::<256>().0) {
                for (o, case) in (0..=255u8).zip(ligne.iter_mut()) {
                    *case = automate.suivant_par_echecs(etat, o);
                }
            }
            automate.table = Some(table);
        }
        Some(automate)
    }

    /// L'état `etat`, qui vient toujours de l'automate lui-même.
    fn noeud(&self, etat: u32) -> &Noeud {
        #[expect(
            clippy::indexing_slicing,
            reason = "construire refuse l'automate si un état noté sort de `noeuds`, et rien ne le change ensuite"
        )]
        &self.noeuds[en_usize(etat)]
    }

    fn suivant_par_echecs(&self, mut etat: u32, o: u8) -> u32 {
        loop {
            let n = self.noeud(etat);
            if let Some(&(_, f)) = n
                .fils
                .binary_search_by_key(&o, |f| f.0)
                .ok()
                .and_then(|k| n.fils.get(k))
            {
                return f;
            }
            if etat == 0 {
                return 0;
            }
            etat = n.echec;
        }
    }

    pub(crate) fn etats(&self) -> usize {
        self.noeuds.len()
    }

    /// Avance sur `octets` depuis `etat` ; `trouve(i, motif)` pour chaque atome qui finit à `octets[i]`.
    fn avancer(&self, etat: &mut u32, octets: &[u8], mut trouve: impl FnMut(usize, u32)) {
        let mut e = *etat;
        for (i, &o) in octets.iter().enumerate() {
            // La table a 256 cases par état (construire) ; hors d'elle, la même transition se calcule par les échecs.
            e = match &self.table {
                Some(t) => en_usize(e)
                    .checked_mul(256)
                    .and_then(|k| k.checked_add(usize::from(o)))
                    .and_then(|k| t.get(k))
                    .copied()
                    .unwrap_or_else(|| self.suivant_par_echecs(e, o)),
                None => self.suivant_par_echecs(e, o),
            };
            let courant = self.noeud(e);
            let mut s = if courant.sorties.is_empty() {
                courant.sortie_suivante
            } else {
                e
            };
            while s != AUCUN {
                let n = self.noeud(s);
                for &m in &n.sorties {
                    trouve(i, m);
                }
                s = n.sortie_suivante;
            }
        }
        *etat = e;
    }
}

/// Ajoute le coût d'une vérification au travail fait, et lit l'horloge chaque fois qu'il passe
/// `TRAVAIL_ENTRE_DELAIS` : vrai si le délai est passé. Une vérification chère compte pour beaucoup, si bien que le
/// délai est lu assez souvent quel que soit le coût des motifs.
/// Une taille ou une position comme u64 ; `Echec::Lecture` si elle n'y tenait pas (jamais sur 32 ou 64 bits).
fn en_u64(n: usize) -> Result<u64, Echec> {
    u64::try_from(n).map_err(|_| Echec::Lecture)
}

fn delai_passe(travail: &mut u64, cout: u64, echeance: Option<Instant>) -> bool {
    *travail = travail.saturating_add(cout);
    if *travail < TRAVAIL_ENTRE_DELAIS {
        return false;
    }
    *travail = 0;
    echeance.is_some_and(|e| Instant::now() >= e)
}

/// Un ensemble de motifs et leur automate : on y cherche lesquels se trouvent dans des données.
pub(crate) struct Recherche {
    motifs: Vec<Motif>,
    automate: Automate,
    /// La plus grande longueur de motif : ce qu'un flux garde de ses données d'avant.
    garde: usize,
}

impl Recherche {
    /// `None` : trop d'états (voir `ETATS_MAX`).
    pub(crate) fn nouvelle(motifs: Vec<Motif>) -> Option<Recherche> {
        let atomes: Vec<&[u8]> = motifs.iter().map(|m| m.atome.as_slice()).collect();
        let automate = Automate::construire(&atomes)?;
        let garde = motifs.iter().map(|m| en_usize(m.longueur_max)).max().unwrap_or(0);
        Some(Recherche {
            motifs,
            automate,
            garde,
        })
    }

    /// Aucun motif : l'automate n'a que sa racine, sans rien qui puisse manquer.
    pub(crate) fn vide() -> Recherche {
        Recherche {
            motifs: Vec::new(),
            automate: Automate {
                noeuds: vec![Noeud::default()],
                table: None,
            },
            garde: 0,
        }
    }

    pub(crate) fn motifs(&self) -> &[Motif] {
        &self.motifs
    }

    pub(crate) fn automate(&self) -> &Automate {
        &self.automate
    }

    /// Marque dans `vus` les motifs présents dans `donnees`, sauf ceux que `utile` écarte (déjà vus, ou sans règle
    /// qui puisse encore correspondre).
    pub(crate) fn dans_tampon(
        &self,
        donnees: &[u8],
        vus: &mut [bool],
        utile: &[bool],
        echeance: Option<Instant>,
    ) -> Result<(), Echec> {
        let mut etat = 0;
        let mut travail = 0u64;
        let mut arret: Option<Echec> = None;
        for (morceau, base) in donnees.chunks(BLOC).zip((0_usize..).step_by(BLOC)) {
            if echeance.is_some_and(|e| Instant::now() >= e) {
                return Err(Echec::Delai);
            }
            self.automate.avancer(&mut etat, morceau, |i, m| {
                if arret.is_some() {
                    return;
                }
                let m = en_usize(m);
                // Un motif que `vus` ou `utile` ne connaissent pas : rien n'est conclu, plutôt qu'un motif tu.
                let (Some(motif), Some(vu), Some(&sert)) = (self.motifs.get(m), vus.get_mut(m), utile.get(m)) else {
                    arret = Some(Echec::Lecture);
                    return;
                };
                if *vu || !sert {
                    return;
                }
                if delai_passe(&mut travail, motif.cout, echeance) {
                    arret = Some(Echec::Delai);
                    return;
                }
                // L'atome finit à `base + i` : il commence dans les données.
                let Some(atome) = base
                    .checked_add(i)
                    .and_then(|f| f.checked_add(1))
                    .and_then(|f| f.checked_sub(motif.atome.len()))
                else {
                    arret = Some(Echec::Lecture);
                    return;
                };
                if motif.autour(donnees, atome) {
                    *vu = true;
                }
            });
            if let Some(e) = arret {
                return Err(e);
            }
        }
        Ok(())
    }

    /// Comme `dans_tampon`, sur un flux lu par blocs de `bloc` octets, sans jamais le garder en entier : de quoi lire un
    /// fichier plus grand que la mémoire. Au plus `limite` octets sont lus ; rend le nombre d'octets lus.
    pub(crate) fn dans_flux(
        &self,
        source: &mut impl Read,
        limite: u64,
        vus: &mut [bool],
        utile: &[bool],
        echeance: Option<Instant>,
        bloc: usize,
    ) -> Result<u64, Echec> {
        let bloc = bloc.max(1);
        // La fenêtre : les données à partir de la position `base`. Après chaque bloc, on n'en garde que ce que les
        // vérifications en attente et les atomes à venir peuvent encore lire.
        // Une capacité de départ, sans plus : `bloc` seul si la somme ne tenait pas.
        let capacite = self
            .garde
            .checked_mul(2)
            .and_then(|g| g.checked_add(bloc))
            .unwrap_or(bloc);
        let mut fenetre: Vec<u8> = Vec::with_capacity(capacite);
        let mut base = 0u64;
        let mut lus = 0u64;
        let mut etat = 0;
        // (motif, position absolue du début de l'atome) : ce qui suit l'atome n'est pas encore lu.
        let mut attente: Vec<(u32, u64)> = Vec::new();
        let mut travail = 0u64;
        let mut arret: Option<Echec> = None;
        loop {
            if echeance.is_some_and(|e| Instant::now() >= e) {
                return Err(Echec::Delai);
            }
            let ancien = fenetre.len();
            // `lus` ne dépasse jamais `limite` : chaque lecture est bornée par ce qui reste.
            let voulu = usize::try_from(limite.saturating_sub(lus)).map_or(bloc, |reste| reste.min(bloc));
            fenetre.resize(ancien.checked_add(voulu).ok_or(Echec::Lecture)?, 0);
            let n = remplir(source, fenetre.get_mut(ancien..).ok_or(Echec::Lecture)?)?;
            fenetre.truncate(ancien.checked_add(n).ok_or(Echec::Lecture)?);
            lus = lus.checked_add(en_u64(n)?).ok_or(Echec::Lecture)?;
            let fin = n < voulu || lus >= limite;
            let debut_neuf = base.checked_add(en_u64(ancien)?).ok_or(Echec::Lecture)?;
            let bout = base.checked_add(en_u64(fenetre.len())?).ok_or(Echec::Lecture)?;
            // Ce qui précède l'atome est encore dans la fenêtre (voir la coupe plus bas) : avant son début, il n'y a que
            // ce qui précéderait le début des données, qui n'existe pas. La position relative suffit. Un motif inconnu
            // de `self.motifs` ou de `vus` n'est jamais tu : rien n'est conclu.
            let verifier = |m: u32, atome: u64, vus: &mut [bool], travail: &mut u64| -> Result<(), Echec> {
                let motif = self.motifs.get(en_usize(m)).ok_or(Echec::Lecture)?;
                if delai_passe(travail, motif.cout, echeance) {
                    return Err(Echec::Delai);
                }
                debug_assert!(atome.saturating_sub(u64::from(motif.avant_max)) >= base || base == 0);
                if atome
                    .checked_sub(base)
                    .and_then(|r| usize::try_from(r).ok())
                    .is_some_and(|relatif| motif.autour(&fenetre, relatif))
                {
                    *vus.get_mut(en_usize(m)).ok_or(Echec::Lecture)? = true;
                }
                Ok(())
            };
            // Un atome dont tout ce qui suit est déjà dans la fenêtre est vérifié tout de suite : seuls attendent ceux
            // des derniers octets du bloc, si bien que l'attente reste bornée par la garde, quelles que soient les
            // données (un atome que partagent des dizaines de motifs, répété sur tout un bloc).
            let neuf = fenetre.get(ancien..).ok_or(Echec::Lecture)?;
            self.automate.avancer(&mut etat, neuf, |i, m| {
                if arret.is_some() {
                    return;
                }
                let mi = en_usize(m);
                let (Some(motif), Some(&vu), Some(&sert)) = (self.motifs.get(mi), vus.get(mi), utile.get(mi)) else {
                    arret = Some(Echec::Lecture);
                    return;
                };
                if vu || !sert {
                    return;
                }
                // L'atome finit à `debut_neuf + i` : il commence dans les données.
                let atome = en_u64(i)
                    .ok()
                    .and_then(|i| debut_neuf.checked_add(i))
                    .and_then(|f| f.checked_add(1))
                    .and_then(|f| f.checked_sub(u64::try_from(motif.atome.len()).ok()?));
                let Some((atome, besoin)) = atome.and_then(|a| Some((a, motif.fin_possible(a)?))) else {
                    arret = Some(Echec::Lecture);
                    return;
                };
                if besoin > bout && !fin {
                    attente.push((m, atome));
                } else if let Err(e) = verifier(m, atome, vus, &mut travail) {
                    arret = Some(e);
                }
            });
            if let Some(e) = arret {
                return Err(e);
            }
            let mut restantes = Vec::new();
            for (m, atome) in attente.drain(..) {
                let motif = self.motifs.get(en_usize(m)).ok_or(Echec::Lecture)?;
                if vus.get(en_usize(m)).copied().ok_or(Echec::Lecture)? {
                    continue;
                }
                let besoin = motif.fin_possible(atome).ok_or(Echec::Lecture)?;
                if besoin > bout && !fin {
                    restantes.push((m, atome));
                    continue;
                }
                verifier(m, atome, vus, &mut travail)?;
            }
            attente = restantes;
            if fin {
                return Ok(lus);
            }
            // La coupe : garder la fin de la fenêtre (un atome à cheval sur deux blocs a besoin de ce qui le précède)
            // et tout ce que les vérifications en attente liront.
            // Saturer la marge, c'est tout garder : jamais moins que voulu.
            let mut coupe = bout.saturating_sub(en_u64(self.garde.saturating_add(ATOME_MAX))?);
            for (m, atome) in &attente {
                let avant_max = self.motifs.get(en_usize(*m)).ok_or(Echec::Lecture)?.avant_max;
                coupe = coupe.min(atome.saturating_sub(u64::from(avant_max)));
            }
            let coupe = coupe.max(base);
            let coupe_relative = coupe.checked_sub(base).ok_or(Echec::Lecture)?;
            let coupe_relative = usize::try_from(coupe_relative).map_or(fenetre.len(), |c| c.min(fenetre.len()));
            fenetre.drain(..coupe_relative);
            base = coupe;
        }
    }
}

/// Remplit `tampon` depuis `source`, jusqu'à la fin des données : le nombre d'octets lus.
fn remplir(source: &mut impl Read, mut tampon: &mut [u8]) -> Result<usize, Echec> {
    let mut n = 0_usize;
    while !tampon.is_empty() {
        match source.read(tampon) {
            Ok(0) => break,
            // Une source qui dit avoir lu plus que le tampon ne se croit pas.
            Ok(k) => {
                tampon = std::mem::take(&mut tampon).get_mut(k..).ok_or(Echec::Lecture)?;
                n = n.checked_add(k).ok_or(Echec::Lecture)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Echec::Lecture),
        }
    }
    Ok(n)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn o(valeur: u8) -> Element {
        Element::Octet { valeur, masque: 0xFF }
    }

    fn joker() -> Element {
        Element::Octet { valeur: 0, masque: 0 }
    }

    fn saut(min: u32, max: u32) -> Element {
        Element::Saut { min, max }
    }

    /// Les motifs présents, par le tampon.
    fn presents(motifs: Vec<Motif>, donnees: &[u8]) -> Vec<bool> {
        let r = Recherche::nouvelle(motifs).unwrap();
        let mut vus = vec![false; r.motifs().len()];
        let utile = vec![true; r.motifs().len()];
        r.dans_tampon(donnees, &mut vus, &utile, None).unwrap();
        vus
    }

    /// Les mêmes par le flux, lu par blocs de `bloc` octets.
    fn presents_flux(motifs: Vec<Motif>, donnees: &[u8], bloc: usize) -> Vec<bool> {
        let r = Recherche::nouvelle(motifs).unwrap();
        let mut vus = vec![false; r.motifs().len()];
        let utile = vec![true; r.motifs().len()];
        let lus = r
            .dans_flux(
                &mut std::io::Cursor::new(donnees),
                u64::MAX,
                &mut vus,
                &utile,
                None,
                bloc,
            )
            .unwrap();
        assert_eq!(lus, donnees.len() as u64);
        vus
    }

    /// L'exemple de l'article d'Aho et Corasick (he, she, his, hers) : atomes qui se chevauchent, liens d'échec, en
    /// table complète comme par les liens seuls.
    #[test]
    fn automate_de_l_article() {
        let mots: [&[u8]; 4] = [b"he", b"she", b"his", b"hers"];
        let mut automate = Automate::construire(&mots).unwrap();
        let mut avec_table = Vec::new();
        automate.avancer(&mut 0, b"ushers", |i, m| avec_table.push((i, m)));
        avec_table.sort_unstable();
        assert_eq!(avec_table, [(3, 0), (3, 1), (5, 3)]);
        automate.table = None;
        let mut sans_table = Vec::new();
        automate.avancer(&mut 0, b"ushers", |i, m| sans_table.push((i, m)));
        sans_table.sort_unstable();
        assert_eq!(sans_table, avec_table);
    }

    #[test]
    fn motifs_refuses() {
        assert_eq!(Motif::nouveau(vec![]).err(), Some(Refus::Vide));
        assert_eq!(Motif::nouveau(vec![saut(1, 2), o(1)]).err(), Some(Refus::Saut));
        assert_eq!(Motif::nouveau(vec![o(1), saut(1, 2)]).err(), Some(Refus::Saut));
        assert_eq!(Motif::nouveau(vec![o(1), saut(3, 2), o(1)]).err(), Some(Refus::Saut));
        assert_eq!(Motif::nouveau(vec![joker(), joker()]).err(), Some(Refus::SansAtome));
        assert_eq!(
            Motif::nouveau(vec![Element::Choix(vec![vec![o(1)], vec![o(2)]])]).err(),
            Some(Refus::SansAtome)
        );
        assert_eq!(
            Motif::nouveau(vec![o(1), Element::Choix(vec![])]).err(),
            Some(Refus::Choix)
        );
        assert_eq!(
            Motif::nouveau(vec![o(1), Element::Choix(vec![vec![], vec![o(2)]])]).err(),
            Some(Refus::Choix)
        );
        assert_eq!(
            Motif::nouveau(vec![o(1), saut(0, LONGUEUR_MAX), o(1)]).err(),
            Some(Refus::TropLong)
        );
        // Des choix dans des choix, au-delà de la borne.
        let mut e = vec![o(1)];
        for _ in 0..=PROFONDEUR_MAX {
            e = vec![Element::Choix(vec![e, vec![o(2)]])];
        }
        e.insert(0, o(3));
        assert_eq!(Motif::nouveau(e).err(), Some(Refus::Choix));
    }

    /// L'atome évite les octets banals quand le motif en offre d'autres.
    #[test]
    fn atome_peu_banal() {
        let m = Motif::nouveau(vec![
            o(0),
            o(0),
            o(0),
            o(0),
            joker(),
            o(0x4D),
            o(0x5A),
            o(0x90),
            o(0x37),
        ])
        .unwrap();
        assert_eq!(m.atome(), [0x4D, 0x5A, 0x90, 0x37]);
        let m = Motif::nouveau(vec![o(0), o(0), joker(), o(0)]).unwrap();
        assert_eq!(m.atome(), [0, 0]);
    }

    /// Sauts, choix de longueurs différentes, demi-octets, jokers aux bords : vérifiés de part et d'autre de l'atome,
    /// jamais hors des données.
    #[test]
    fn verifications() {
        let demi = Element::Octet {
            valeur: 0x40,
            masque: 0xF0,
        };
        let motifs = vec![
            // 41 [1-2] 42
            Motif::nouveau(vec![o(0x41), saut(1, 2), o(0x42)]).unwrap(),
            // ?? 41 42 : il faut un octet avant
            Motif::nouveau(vec![joker(), o(0x41), o(0x42)]).unwrap(),
            // 41 42 ?? : il faut un octet après
            Motif::nouveau(vec![o(0x41), o(0x42), joker()]).unwrap(),
            // 4? 5A ( 01 | 02 03 ) 99
            Motif::nouveau(vec![
                demi,
                o(0x5A),
                Element::Choix(vec![vec![o(1)], vec![o(2), o(3)]]),
                o(0x99),
            ])
            .unwrap(),
        ];
        assert_eq!(presents(motifs.clone(), b"AxxB"), [true, false, false, false]);
        assert_eq!(presents(motifs.clone(), b"AxxxB"), [false, false, false, false]);
        assert_eq!(presents(motifs.clone(), b"AB"), [false, false, false, false]);
        assert_eq!(presents(motifs.clone(), b"xAB"), [false, true, false, false]);
        assert_eq!(presents(motifs.clone(), b"ABx"), [false, false, true, false]);
        assert_eq!(
            presents(motifs.clone(), b"\x4fZ\x02\x03\x99"),
            [false, false, false, true]
        );
        assert_eq!(
            presents(motifs.clone(), b"\x5fZ\x02\x03\x99"),
            [false, false, false, false]
        );
        assert_eq!(presents(motifs, b"\x40Z\x02\x99"), [false, false, false, false]);
        // commence_ici : la correspondance doit commencer au premier octet.
        let m = Motif::nouveau(vec![o(0x41), saut(0, 2), o(0x42)]).unwrap();
        assert!(m.commence_ici(b"AB") && m.commence_ici(b"AxxB") && !m.commence_ici(b"xAB") && !m.commence_ici(b"A"));
    }

    /// Un motif fait pour coûter (des sauts larges qui se suivent) sur des données faites pour lui (l'atome partout) :
    /// le coût est polynomial (positions suivies × éléments, par place de l'atome), jamais exponentiel ; au-delà, le délai
    /// coupe la recherche, et le fichier est dit non vérifié.
    #[test]
    fn motif_couteux_borne() {
        let mut e = vec![o(0x41)];
        for _ in 0..40 {
            e.push(saut(0, 16));
            e.push(joker());
        }
        e.push(o(0x42));
        let motif = Motif::nouveau(e).unwrap();
        let debut = Instant::now();
        assert_eq!(presents(vec![motif.clone()], &[0x41u8; 1024]), [false]);
        assert!(debut.elapsed().as_secs() < 20, "{:?}", debut.elapsed());
        // Sur beaucoup plus de données, le délai s'en charge, et vite.
        let r = Recherche::nouvelle(vec![motif]).unwrap();
        let debut = Instant::now();
        let echeance = Some(debut + std::time::Duration::from_millis(300));
        assert_eq!(
            r.dans_tampon(&vec![0x41u8; 1 << 20], &mut [false], &[true], echeance),
            Err(Echec::Delai)
        );
        assert!(debut.elapsed().as_secs() < 5, "{:?}", debut.elapsed());
    }

    /// Le délai coupe une recherche, qui le dit.
    #[test]
    fn delai() {
        let r = Recherche::nouvelle(vec![Motif::nouveau(vec![o(0x41), o(0x42)]).unwrap()]).unwrap();
        let passe = Some(Instant::now());
        assert_eq!(r.dans_tampon(b"xx", &mut [false], &[true], passe), Err(Echec::Delai));
        assert_eq!(
            r.dans_flux(&mut std::io::Cursor::new(b"xx"), 2, &mut [false], &[true], passe, BLOC),
            Err(Echec::Delai)
        );
    }

    /// Un flux qui casse en route : erreur de lecture, jamais « rien trouvé ».
    #[test]
    fn flux_casse() {
        struct Casse(usize);
        impl Read for Casse {
            fn read(&mut self, t: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("disque"));
                }
                self.0 -= 1;
                t[0] = b'x';
                Ok(1)
            }
        }
        let r = Recherche::nouvelle(vec![Motif::nouveau(vec![o(0x41)]).unwrap()]).unwrap();
        assert_eq!(
            r.dans_flux(&mut Casse(10), 100, &mut [false], &[true], None, 4),
            Err(Echec::Lecture)
        );
    }

    fn element_au_hasard() -> impl Strategy<Value = Element> {
        let octet = prop_oneof![
            4 => (0x41u8..0x44).prop_map(o),
            1 => Just(joker()),
            1 => Just(Element::Octet { valeur: 0x40, masque: 0xF0 }),
        ];
        octet.prop_recursive(2, 8, 3, |dedans| {
            prop_oneof![
                3 => dedans.clone(),
                1 => proptest::collection::vec(proptest::collection::vec(dedans, 1..3), 2..3).prop_map(Element::Choix),
            ]
        })
    }

    proptest! {
        /// Le flux, quelle que soit la taille de ses blocs, trouve exactement ce que trouve le tampon : une chaîne à
        /// cheval sur deux blocs, ou dont ce qui précède l'atome est dans un bloc déjà passé, est vue.
        #[test]
        fn flux_comme_tampon(
            motifs in proptest::collection::vec(
                (proptest::collection::vec(element_au_hasard(), 0..4), 0x41u8..0x44, proptest::collection::vec(element_au_hasard(), 0..4), 0u32..5),
                1..6,
            ),
            donnees in proptest::collection::vec(0x40u8..0x45, 0..200),
            bloc in 1usize..20,
        ) {
            let motifs: Vec<Motif> = motifs
                .into_iter()
                .filter_map(|(avant, connu, apres, s)| {
                    let mut e = avant;
                    if s > 0 && !e.is_empty() {
                        e.push(saut(1, s));
                    }
                    e.push(o(connu));
                    e.extend(apres);
                    Motif::nouveau(e).ok()
                })
                .collect();
            prop_assume!(!motifs.is_empty());
            prop_assert_eq!(presents_flux(motifs.clone(), &donnees, bloc), presents(motifs, &donnees));
        }
    }
}
