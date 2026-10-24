//! Le moteur YARA de Vanguard : les règles lues par `regles_yara`, leurs chaînes cherchées toutes ensemble par `motifs`,
//! leurs conditions évaluées comme YARA-X les évalue (valeurs indéfinies comprises), les modules `pe` (par `crate::pe`)
//! et `elf` (ici). Il remplace YARA-X dans le programme ; YARA-X reste l'oracle des tests, en développement
//! seulement : mêmes règles, mêmes fichiers, mêmes correspondances (un seul écart connu, voulu : après un saut de 256
//! octets ou plus, YARA-X manque des correspondances réelles que ce moteur trouve, voir oracle_yara.rs).
//!
//! Évaluation, d'après la documentation de YARA et de YARA-X (« Undefined values ») : une lecture hors des données
//! (`uint16(1000)` sur un petit fichier), un champ de module absent (`pe.entry_point` d'un fichier qui n'est pas un PE)
//! sont indéfinis ; une comparaison ou un `not` d'un indéfini est indéfini ; `and` et `or` le prennent pour faux ; une
//! condition indéfinie ne correspond pas.
//!
//! Avant de lire un fichier en entier, les conditions sont évaluées sans les chaînes (elles valent « inconnu ») : une
//! règle qui ne peut plus correspondre (`uint16(0) == 0x5A4D` sur une image) ne fait chercher aucune de ses chaînes,
//! et un fichier qu'aucune règle ne peut viser n'est lu qu'à son début. Le résultat est le même, plus vite.
//!
//! Module pur, sans `crate::` (sauf `crate::pe`) : le banc de fuzzing l'inclut par son chemin.

use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

use super::motifs::{self, Echec, Motif, Recherche};
use super::regles_yara::{self, Comparaison, Entier, Expr, Meta, Quantite, Raison, Refus};

/// Une règle prête : son nom, ses métadonnées, sa condition, et pour chacune de ses chaînes les motifs de ses formes.
struct RegleCompilee {
    nom: String,
    meta: Meta,
    condition: Expr,
    /// Chaîne (rang dans la règle) → motifs (rang dans la recherche).
    chaines: Vec<Vec<usize>>,
}

/// Les règles compilées, et celles refusées.
pub(crate) struct Regles {
    liste: Vec<RegleCompilee>,
    recherche: Recherche,
    /// Motif → règle.
    regle_du_motif: Vec<usize>,
    refus: Vec<Refus>,
    /// Les octets lus d'un coup dans un fichier : `motifs::BLOC`, plus petit dans les tests (chaînes à cheval).
    bloc: usize,
}

/// La description d'un refus de motif, pour `Raison::Motif`.
fn refus_motif(r: motifs::Refus) -> String {
    match r {
        motifs::Refus::Vide => "vide",
        motifs::Refus::Saut => "saut au bord ou à l'envers",
        motifs::Refus::TropLong => "trop longue",
        motifs::Refus::Choix => "choix vide ou trop imbriqué",
        motifs::Refus::SansAtome => "aucun octet connu hors des choix",
    }
    .to_string()
}

impl Regles {
    /// Lit et compile `source`. Ne manque jamais : ce qui n'a pas pu être compris est dans `refus()`.
    pub(crate) fn compiler(source: &str) -> Regles {
        let lu = regles_yara::lire(source);
        let mut refus = lu.refus;
        let mut regles = Vec::new();
        let mut motifs_liste: Vec<Motif> = Vec::new();
        let mut regle_du_motif = Vec::new();
        for r in lu.regles {
            let mut chaines = Vec::new();
            let mut neufs = Vec::new();
            let mut echec = None;
            for c in &r.chaines {
                let mut rangs = Vec::new();
                for forme in &c.formes {
                    match Motif::nouveau(forme.clone()) {
                        Ok(m) => {
                            rangs.push(motifs_liste.len() + neufs.len());
                            neufs.push(m);
                        }
                        Err(e) => {
                            echec = Some(format!("{} : {}", c.nom, refus_motif(e)));
                            break;
                        }
                    }
                }
                if echec.is_some() {
                    break;
                }
                chaines.push(rangs);
            }
            if let Some(e) = echec {
                refus.push(Refus {
                    regle: Some(r.nom),
                    ligne: r.ligne,
                    raison: Raison::Motif(e),
                });
                continue;
            }
            regle_du_motif.extend(std::iter::repeat_n(regles.len(), neufs.len()));
            motifs_liste.extend(neufs);
            regles.push(RegleCompilee {
                nom: r.nom,
                meta: r.meta,
                condition: r.condition,
                chaines,
            });
        }
        let recherche = Recherche::nouvelle(motifs_liste).unwrap_or_else(|| {
            // Trop d'états : aucune règle ne s'applique, et toutes sont dites.
            for r in regles.drain(..) {
                refus.push(Refus {
                    regle: Some(r.nom),
                    ligne: 0,
                    raison: Raison::Borne("automate"),
                });
            }
            regle_du_motif.clear();
            Recherche::nouvelle(Vec::new()).expect("automate vide")
        });
        Regles {
            liste: regles,
            recherche,
            regle_du_motif,
            refus,
            bloc: motifs::BLOC,
        }
    }

    #[cfg(any(test, fuzzing))]
    pub(crate) fn avec_bloc(mut self, bloc: usize) -> Regles {
        self.bloc = bloc;
        self
    }

    /// Les règles appliquées.
    pub(crate) fn nombre(&self) -> usize {
        self.liste.len()
    }

    /// Les règles refusées (non vérifiées), dans l'ordre du texte.
    pub(crate) fn refus(&self) -> &[Refus] {
        &self.refus
    }

    pub(crate) fn nom(&self, regle: usize) -> &str {
        &self.liste[regle].nom
    }

    #[cfg(test)]
    pub(crate) fn noms(&self) -> impl Iterator<Item = &str> {
        self.liste.iter().map(|r| r.nom.as_str())
    }

    #[allow(dead_code)] // pour le constat commun des analyses (lot suivant) : auteur, référence
    pub(crate) fn meta(&self, regle: usize) -> &Meta {
        &self.liste[regle].meta
    }

    /// Les états de l'automate, pour la mesure.
    #[allow(dead_code)]
    pub(crate) fn etats(&self) -> usize {
        self.recherche.automate().etats()
    }

    /// Les règles (leurs rangs) qui correspondent à `donnees`, lues comme un fichier : un tampon de la mémoire d'un
    /// processus se lit ainsi, positions comptées depuis son début.
    pub(crate) fn analyser_tampon(&self, donnees: &[u8], echeance: Option<Instant>) -> Result<Vec<usize>, Echec> {
        let mut acces = Tampon(donnees);
        self.analyser(&mut acces, echeance)
    }

    /// Comme `analyser_tampon`, sur une source qu'on lit par blocs (un fichier), sans jamais la garder en entière ; au
    /// plus `taille` octets en sont lus, et une source plus courte qu'annoncé (fichier raccourci entre-temps) est une
    /// erreur de lecture, jamais un fichier sain.
    pub(crate) fn analyser_flux<S: Read + Seek>(
        &self,
        source: &mut S,
        taille: u64,
        echeance: Option<Instant>,
    ) -> Result<Vec<usize>, Echec> {
        let mut acces = Flux {
            source,
            taille,
            position: 0,
            erreur: false,
            bloc: self.bloc,
        };
        let resultat = self.analyser(&mut acces, echeance);
        if acces.erreur {
            return Err(Echec::Lecture);
        }
        resultat
    }

    fn analyser<A: Acces>(&self, acces: &mut A, echeance: Option<Instant>) -> Result<Vec<usize>, Echec> {
        let mut ctx = Contexte {
            acces,
            vus: vec![false; self.recherche.motifs().len()],
            pe: std::cell::OnceCell::new(),
            elf: std::cell::OnceCell::new(),
            signature: None,
        };
        // D'abord sans les chaînes : quelles règles peuvent encore correspondre ?
        let possibles: Vec<bool> = self
            .liste
            .iter()
            .map(|r| Ok(matches!(ctx.possible(&r.condition)?, Tri::Vrai | Tri::Inconnu)))
            .collect::<Result<_, Echec>>()?;
        if !possibles.iter().any(|p| *p) {
            return Ok(Vec::new());
        }
        let utile: Vec<bool> = self.regle_du_motif.iter().map(|&r| possibles[r]).collect();
        if utile.iter().any(|u| *u) {
            ctx.acces.chercher(&self.recherche, &mut ctx.vus, &utile, echeance)?;
        }
        let mut trouvees = Vec::new();
        for (k, r) in self.liste.iter().enumerate() {
            if possibles[k] && ctx.evaluer(&r.condition, &r.chaines, &self.recherche)? == Some(true) {
                trouvees.push(k);
            }
        }
        Ok(trouvees)
    }
}

/// Les données analysées, vues par le moteur.
trait Acces {
    fn taille(&self) -> u64;
    /// Au plus `n` octets à `position` (moins à la fin des données, aucun après).
    fn lire(&mut self, position: u64, n: usize) -> Vec<u8>;
    fn chercher(
        &mut self,
        recherche: &Recherche,
        vus: &mut [bool],
        utile: &[bool],
        echeance: Option<Instant>,
    ) -> Result<(), Echec>;
    fn champs_pe(&mut self) -> Option<crate::pe::ChampsYara>;
    fn signature(&mut self, champs: &crate::pe::ChampsYara) -> bool;
    fn entree_elf(&mut self) -> Option<u64>;
}

struct Tampon<'a>(&'a [u8]);

impl Acces for Tampon<'_> {
    fn taille(&self) -> u64 {
        self.0.len() as u64
    }

    fn lire(&mut self, position: u64, n: usize) -> Vec<u8> {
        let Ok(debut) = usize::try_from(position) else {
            return Vec::new();
        };
        self.0
            .get(debut..)
            .map_or_else(Vec::new, |r| r[..n.min(r.len())].to_vec())
    }

    fn chercher(
        &mut self,
        recherche: &Recherche,
        vus: &mut [bool],
        utile: &[bool],
        echeance: Option<Instant>,
    ) -> Result<(), Echec> {
        recherche.dans_tampon(self.0, vus, utile, echeance)
    }

    fn champs_pe(&mut self) -> Option<crate::pe::ChampsYara> {
        crate::pe::champs_yara(&mut std::io::Cursor::new(self.0), self.taille())
    }

    fn signature(&mut self, champs: &crate::pe::ChampsYara) -> bool {
        crate::pe::signature_presente(&mut std::io::Cursor::new(self.0), self.taille(), champs)
    }

    fn entree_elf(&mut self) -> Option<u64> {
        entree_elf(&mut std::io::Cursor::new(self.0), self.taille())
    }
}

/// Une source lue par morceaux. Une erreur de lecture, où qu'elle arrive (recherche, en-têtes des modules, `at`), est
/// notée, comme une fin de données avant la taille annoncée (le fichier a raccourci pendant l'analyse : les lecteurs
/// des modules contrôlent leurs positions contre cette taille, et un manque n'est donc pas « hors du fichier ») : le
/// fichier sera dit illisible, jamais jugé sur des données qui manquent.
struct Flux<'a, S> {
    source: &'a mut S,
    taille: u64,
    position: u64,
    erreur: bool,
    bloc: usize,
}

impl<S: Read + Seek> Read for Flux<'_, S> {
    fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
        let r = self.source.read(tampon);
        match &r {
            Ok(0) if !tampon.is_empty() && self.position < self.taille => self.erreur = true,
            Ok(n) => self.position += *n as u64,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => self.erreur = true,
        }
        r
    }
}

impl<S: Read + Seek> Seek for Flux<'_, S> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let r = self.source.seek(position);
        match &r {
            Ok(p) => self.position = *p,
            Err(_) => self.erreur = true,
        }
        r
    }
}

impl<S: Read + Seek> Acces for Flux<'_, S> {
    fn taille(&self) -> u64 {
        self.taille
    }

    fn lire(&mut self, position: u64, n: usize) -> Vec<u8> {
        if position >= self.taille {
            return Vec::new();
        }
        let n = n.min(usize::try_from(self.taille - position).unwrap_or(usize::MAX));
        let mut tampon = vec![0u8; n];
        if self.seek(SeekFrom::Start(position)).is_err() || self.read_exact(&mut tampon).is_err() {
            self.erreur = true;
            return Vec::new();
        }
        tampon
    }

    fn chercher(
        &mut self,
        recherche: &Recherche,
        vus: &mut [bool],
        utile: &[bool],
        echeance: Option<Instant>,
    ) -> Result<(), Echec> {
        if self.seek(SeekFrom::Start(0)).is_err() {
            return Err(Echec::Lecture);
        }
        let taille = self.taille;
        let bloc = self.bloc;
        let lus = recherche.dans_flux(self, taille, vus, utile, echeance, bloc)?;
        if lus < taille {
            return Err(Echec::Lecture);
        }
        Ok(())
    }

    fn champs_pe(&mut self) -> Option<crate::pe::ChampsYara> {
        let taille = self.taille;
        crate::pe::champs_yara(self, taille)
    }

    fn signature(&mut self, champs: &crate::pe::ChampsYara) -> bool {
        let taille = self.taille;
        crate::pe::signature_presente(self, taille, champs)
    }

    fn entree_elf(&mut self) -> Option<u64> {
        let taille = self.taille;
        entree_elf(self, taille)
    }
}

/// Trois valeurs et l'inconnu : l'évaluation sans les chaînes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tri {
    Vrai,
    Faux,
    Indefini,
    Inconnu,
}

/// L'évaluation d'un fichier : ses accès, les motifs trouvés, et les champs des modules, lus à la première demande.
struct Contexte<'a, A> {
    acces: &'a mut A,
    vus: Vec<bool>,
    pe: std::cell::OnceCell<Option<crate::pe::ChampsYara>>,
    elf: std::cell::OnceCell<Option<u64>>,
    signature: Option<bool>,
}

impl<A: Acces> Contexte<'_, A> {
    fn pe(&mut self) -> Option<crate::pe::ChampsYara> {
        *self.pe.get_or_init(|| self.acces.champs_pe())
    }

    fn entier(&mut self, e: &Entier) -> Option<i64> {
        match e {
            Entier::Nombre(n) => Some(*n),
            Entier::TailleFichier => i64::try_from(self.acces.taille()).ok(),
            Entier::Lire {
                octets,
                signe,
                gros,
                position,
            } => {
                let p = u64::try_from(self.entier(position)?).ok()?;
                let n = usize::from(*octets);
                let lu = self.acces.lire(p, n);
                if lu.len() < n {
                    return None;
                }
                let mut valeur = 0u64;
                for k in 0..n {
                    let o = if *gros { lu[k] } else { lu[n - 1 - k] };
                    valeur = (valeur << 8) | u64::from(o);
                }
                if *signe {
                    // Étendre le signe de la largeur lue (1 à 4 octets).
                    let decalage = 64 - 8 * u32::from(*octets);
                    Some((valeur << decalage).cast_signed() >> decalage)
                } else {
                    i64::try_from(valeur).ok()
                }
            }
            Entier::PeEntree => self.pe()?.point_d_entree.and_then(|p| i64::try_from(p).ok()),
            Entier::ElfEntree => self
                .elf
                .get_or_init(|| self.acces.entree_elf())
                .and_then(|p| i64::try_from(p).ok()),
        }
    }

    /// Un entier « bon marché » : sans module ni chaîne, lisible dès le début du fichier.
    fn bon_marche(e: &Entier) -> bool {
        match e {
            Entier::Nombre(_) | Entier::TailleFichier => true,
            Entier::Lire { position, .. } => Self::bon_marche(position),
            Entier::PeEntree | Entier::ElfEntree => false,
        }
    }

    fn comparer(g: i64, op: Comparaison, d: i64) -> bool {
        match op {
            Comparaison::Egal => g == d,
            Comparaison::Different => g != d,
            Comparaison::Inferieur => g < d,
            Comparaison::InferieurOuEgal => g <= d,
            Comparaison::Superieur => g > d,
            Comparaison::SuperieurOuEgal => g >= d,
        }
    }

    /// La condition sans les chaînes (ni les modules, plus chers) : faux ou indéfini veut dire que la règle ne peut pas
    /// correspondre, quoi que contiennent les données.
    fn possible(&mut self, e: &Expr) -> Result<Tri, Echec> {
        Ok(match e {
            Expr::Vrai => Tri::Vrai,
            Expr::Faux => Tri::Faux,
            Expr::Chaine(_) | Expr::ChaineA(..) | Expr::Ensemble(..) | Expr::SignaturePresente => Tri::Inconnu,
            Expr::Comparer(g, op, d) => {
                if Self::bon_marche(g) && Self::bon_marche(d) {
                    match (self.entier(g), self.entier(d)) {
                        (Some(g), Some(d)) if Self::comparer(g, *op, d) => Tri::Vrai,
                        (Some(_), Some(_)) => Tri::Faux,
                        _ => Tri::Indefini,
                    }
                } else {
                    Tri::Inconnu
                }
            }
            Expr::Non(x) => match self.possible(x)? {
                Tri::Vrai => Tri::Faux,
                Tri::Faux => Tri::Vrai,
                autre => autre,
            },
            Expr::Et(termes) => {
                let mut inconnu = false;
                for t in termes {
                    match self.possible(t)? {
                        Tri::Faux | Tri::Indefini => return Ok(Tri::Faux),
                        Tri::Inconnu => inconnu = true,
                        Tri::Vrai => {}
                    }
                }
                if inconnu { Tri::Inconnu } else { Tri::Vrai }
            }
            Expr::Ou(termes) => {
                let mut inconnu = false;
                for t in termes {
                    match self.possible(t)? {
                        Tri::Vrai => return Ok(Tri::Vrai),
                        Tri::Inconnu => inconnu = true,
                        Tri::Faux | Tri::Indefini => {}
                    }
                }
                if inconnu { Tri::Inconnu } else { Tri::Faux }
            }
        })
    }

    /// La chaîne (ses formes) a-t-elle été trouvée ?
    fn trouvee(&self, motifs: &[usize]) -> bool {
        motifs.iter().any(|&m| self.vus[m])
    }

    /// La condition : `Some(vrai/faux)`, ou `None` si indéfinie.
    fn evaluer(&mut self, e: &Expr, chaines: &[Vec<usize>], recherche: &Recherche) -> Result<Option<bool>, Echec> {
        Ok(match e {
            Expr::Vrai => Some(true),
            Expr::Faux => Some(false),
            Expr::Chaine(c) => Some(self.trouvee(&chaines[*c])),
            Expr::ChaineA(c, position) => {
                let Some(p) = self.entier(position) else {
                    return Ok(None);
                };
                let Ok(p) = u64::try_from(p) else {
                    return Ok(Some(false));
                };
                let mut trouve = false;
                for &m in &chaines[*c] {
                    let motif = &recherche.motifs()[m];
                    let morceau = self.acces.lire(p, motif.longueur_max() as usize);
                    if motif.commence_ici(&morceau) {
                        trouve = true;
                        break;
                    }
                }
                Some(trouve)
            }
            Expr::Ensemble(quantite, rangs) => {
                let n = rangs.iter().filter(|&&c| self.trouvee(&chaines[c])).count() as u64;
                Some(match quantite {
                    Quantite::Toutes => n == rangs.len() as u64,
                    Quantite::AuMoins(k) => n >= *k,
                    Quantite::Aucune => n == 0,
                })
            }
            Expr::Comparer(g, op, d) => match (self.entier(g), self.entier(d)) {
                (Some(g), Some(d)) => Some(Self::comparer(g, *op, d)),
                _ => None,
            },
            Expr::SignaturePresente => {
                let Some(champs) = self.pe() else {
                    return Ok(None);
                };
                if self.signature.is_none() {
                    self.signature = Some(self.acces.signature(&champs));
                }
                self.signature
            }
            Expr::Non(x) => self.evaluer(x, chaines, recherche)?.map(|v| !v),
            Expr::Et(termes) => {
                for t in termes {
                    if self.evaluer(t, chaines, recherche)? != Some(true) {
                        return Ok(Some(false));
                    }
                }
                Some(true)
            }
            Expr::Ou(termes) => {
                for t in termes {
                    if self.evaluer(t, chaines, recherche)? == Some(true) {
                        return Ok(Some(true));
                    }
                }
                Some(false)
            }
        })
    }
}

// --- Le champ elf.entry_point ---
//
// Comme pour le module « pe » (voir `crate::pe::champs_yara`), établi en boîte noire contre YARA-X sur des ELF
// fabriqués et les ELF de ce PC, puis gardé par les tests de l'oracle.

/// Lit `n` octets à `position`, s'ils sont tous avant `taille`.
fn morceau<S: Read + Seek>(source: &mut S, taille: u64, position: u64, n: usize) -> Option<Vec<u8>> {
    if position.checked_add(n as u64)? > taille {
        return None;
    }
    source.seek(SeekFrom::Start(position)).ok()?;
    let mut tampon = vec![0u8; n];
    source.read_exact(&mut tampon).ok()?;
    Some(tampon)
}

/// Les entrées d'une table lues au plus d'un coup.
const TABLE_PAR_LECTURE: u64 = 1024;

/// elf.entry_point : la position dans le fichier de l'adresse d'entrée (e_entry). Pour un exécutable ou une
/// bibliothèque (ET_EXEC, ET_DYN), par la table des segments : le premier segment (de tout type) dont l'étendue en
/// mémoire la contient ; pour les autres types, par la table des sections : la première (ni SHT_NULL ni SHT_NOBITS)
/// qui la contient. Les entrées sont lues à leur taille de la norme (32 ou 56 octets, 40 ou 64), quelle que soit
/// celle qu'annonce l'en-tête, et la table doit tenir entière dans le fichier. Une adresse d'entrée nulle, ou contenue
/// nulle part, un nombre de sections d'au moins 0xFF00, une entrée qui déborde 64 bits avant la bonne : indéfini.
pub(crate) fn entree_elf<S: Read + Seek>(source: &mut S, taille: u64) -> Option<u64> {
    let ident = morceau(source, taille, 0, 16)?;
    if &ident[..4] != b"\x7fELF" {
        return None;
    }
    let large = match ident[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let gros = match ident[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let entete = morceau(source, taille, 0, if large { 64 } else { 52 })?;
    let lire = |o: &[u8], a: usize, n: usize| -> u64 {
        let mut v = 0u64;
        for k in 0..n {
            let x = if gros { o[a + k] } else { o[a + n - 1 - k] };
            v = (v << 8) | u64::from(x);
        }
        v
    };
    let mot = if large { 8 } else { 4 };
    let sorte = lire(&entete, 16, 2);
    let entree = lire(&entete, 24, mot);
    if entree == 0 {
        return None;
    }
    let (table_segments, table_sections) = (lire(&entete, 24 + mot, mot), lire(&entete, 24 + 2 * mot, mot));
    let nombres = 24 + 3 * mot + 4 + 2;
    let (segments, sections) = (lire(&entete, nombres + 2, 2), lire(&entete, nombres + 6, 2));
    // Un nombre de sections dans la plage réservée (SHN_LORESERVE, 0xFF00, et au-delà) : indéfini, quel que soit le type
    // (vérifié en boîte noire contre YARA-X).
    if sections >= 0xFF00 {
        return None;
    }
    // (position de la table, nombre, taille d'une entrée, et de chaque entrée : type, adresse, position, étendue)
    let par_segments = sorte == 2 || sorte == 3;
    let (debut, nombre, pas) = if par_segments {
        (table_segments, segments, if large { 56 } else { 32 })
    } else {
        (table_sections, sections, if large { 64 } else { 40 })
    };
    if debut.checked_add(nombre * pas)? > taille {
        return None;
    }
    let mut k = 0;
    while k < nombre {
        let lot = (nombre - k).min(TABLE_PAR_LECTURE);
        let octets = morceau(source, taille, debut + k * pas, usize::try_from(lot * pas).ok()?)?;
        for e in octets.chunks_exact(usize::try_from(pas).ok()?) {
            let (genre, adresse, position, etendue) = match (par_segments, large) {
                (true, true) => (lire(e, 0, 4), lire(e, 16, 8), lire(e, 8, 8), lire(e, 40, 8)),
                (true, false) => (lire(e, 0, 4), lire(e, 8, 4), lire(e, 4, 4), lire(e, 20, 4)),
                (false, true) => (lire(e, 4, 4), lire(e, 16, 8), lire(e, 24, 8), lire(e, 32, 8)),
                (false, false) => (lire(e, 4, 4), lire(e, 12, 4), lire(e, 16, 4), lire(e, 20, 4)),
            };
            if !par_segments && (genre == 0 || genre == 8) {
                continue;
            }
            // Une entrée dont la fin dépasse 64 bits rend le champ indéfini, comme dans
            // YARA-X, si elle vient avant celle qui contient l'entrée (relecture adverse, vérifié en boîte noire).
            adresse.checked_add(etendue)?;
            if adresse <= entree && entree - adresse < etendue {
                return (entree - adresse).checked_add(position);
            }
        }
        k += lot;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trouvees(source: &str, donnees: &[u8]) -> Vec<String> {
        let r = Regles::compiler(source);
        assert_eq!(r.refus(), [], "{source}");
        let t: Vec<String> = r
            .analyser_tampon(donnees, None)
            .unwrap()
            .into_iter()
            .map(|k| r.nom(k).to_string())
            .collect();
        let f: Vec<String> = r
            .analyser_flux(&mut std::io::Cursor::new(donnees), donnees.len() as u64, None)
            .unwrap()
            .into_iter()
            .map(|k| r.nom(k).to_string())
            .collect();
        assert_eq!(t, f, "{source}");
        t
    }

    /// Les valeurs indéfinies, comme YARA-X (vérifié contre lui en boîte noire) : `not` d'un indéfini reste indéfini,
    /// une comparaison d'un indéfini aussi ; `and` et `or` le prennent pour faux.
    #[test]
    fn valeurs_indefinies() {
        let source = r#"
            import "pe"
            rule non_lecture_hors { condition: not (uint16(1000) == 1) }
            rule different_hors { condition: uint16(1000) != 1 }
            rule non_entree { strings: $a = "AB" condition: not ($a at pe.entry_point) }
            rule ou_vrai { condition: uint16(1000) == 1 or true }
            rule non_et { condition: not (uint16(1000) == 1 and true) }
            rule signe { condition: int8(0) < 0 and int16be(0) < 0 and int32(0) > 0 and uint8(0) == 255 }
            rule gros { condition: uint16be(0) == 0xFFFE and uint32(0) == 0x4241FEFF }
            rule taille { condition: filesize == 4 }
        "#;
        assert_eq!(
            trouvees(source, b"\xFF\xFEAB"),
            ["ou_vrai", "non_et", "signe", "gros", "taille"]
        );
    }

    /// Un fichier qu'aucune règle ne peut viser n'est lu qu'à son début.
    #[test]
    fn rien_de_plus_que_l_en_tete() {
        struct Compte<'a>(std::io::Cursor<&'a [u8]>, u64);
        impl Read for Compte<'_> {
            fn read(&mut self, t: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(t)?;
                self.1 += n as u64;
                Ok(n)
            }
        }
        impl Seek for Compte<'_> {
            fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
                self.0.seek(p)
            }
        }
        let r = Regles::compiler(r#"rule pe { strings: $a = "MZ" condition: uint16(0) == 0x5A4D and $a }"#);
        let image = vec![0x89u8; 1 << 20];
        let mut source = Compte(std::io::Cursor::new(&image), 0);
        assert_eq!(r.analyser_flux(&mut source, image.len() as u64, None), Ok(vec![]));
        assert!(source.1 <= 16, "{} octets lus", source.1);
        let mut pe = image.clone();
        pe[..2].copy_from_slice(b"MZ");
        let mut source = Compte(std::io::Cursor::new(&pe), 0);
        assert_eq!(r.analyser_flux(&mut source, pe.len() as u64, None), Ok(vec![0]));
        assert!(source.1 >= pe.len() as u64);
    }

    /// Un fichier plus court qu'annoncé (raccourci pendant l'analyse) n'est jamais jugé : erreur de lecture.
    #[test]
    fn fichier_raccourci() {
        let r = Regles::compiler(r#"rule t { strings: $a = "zz" condition: $a or true }"#);
        let d = b"abc";
        assert_eq!(
            r.analyser_flux(&mut std::io::Cursor::new(&d[..]), 10, None),
            Err(Echec::Lecture)
        );
        let r = Regles::compiler(r#"import "pe" rule t { condition: pe.entry_point == 0 or uint32(8) == 0 }"#);
        assert_eq!(
            r.analyser_flux(&mut std::io::Cursor::new(&b"MZ"[..]), 0x100, None),
            Err(Echec::Lecture)
        );
    }

    #[test]
    fn ensembles() {
        let source = r#"
            rule tous { strings: $a1 = "aa" $a2 = "bb" $c = "cc" condition: all of ($a*) and not $c }
            rule aucun { strings: $a = "aa" $b = "zz" condition: none of ($b) and $a }
            rule deux { strings: $a = "aa" $b = "bb" $c = "cc" condition: 2 of them }
            rule trois { strings: $a = "aa" $b = "bb" $c = "cc" condition: 3 of ($a, $b, $c) }
            rule un { strings: $a = "aa" $b = "zz" condition: any of them }
            rule a_deux { strings: $a = "bb" condition: $a at 2 }
        "#;
        assert_eq!(trouvees(source, b"aabb"), ["tous", "aucun", "deux", "un", "a_deux"]);
    }
}
