//! Les fichiers composés OLE (Compound File Binary, [MS-CFB]) : documents Office 97-2003 (.doc, .xls, .ppt), projet
//! VBA (vbaProject.bin), MSI, documents OOXML chiffrés. Un système de fichiers dans un fichier : en-tête de 512
//! octets (signature D0CF11E0A1B11AE1, version 3 à secteurs de 512 octets ou 4 à secteurs de 4 096), DIFAT (109
//! entrées dans l'en-tête, puis une chaîne de secteurs DIFAT dont le dernier mot désigne le suivant), FAT, mini-FAT
//! pour les flux de moins de 4 096 octets (secteurs de 64 octets dans le « mini-flux » de l'entrée racine),
//! répertoire d'entrées de 128 octets rangées en arbre rouge-noir (frères gauche et droit, enfant).
//!
//! Un fichier piégé peut faire boucler chaque chaîne (FAT, DIFAT, mini-FAT, répertoire) et l'arbre : chaque chaîne
//! est suivie avec un témoin des secteurs déjà vus (une chaîne qui revient sur elle-même est refusée, comme le veut
//! la spécification : « A sector chain MUST NOT link to a sector appearing earlier in the same chain »), bornée par le
//! nombre de secteurs que le fichier peut contenir ; l'arbre est parcouru avec un témoin des entrées vues. Les
//! entrées allouées que l'arbre n'atteint pas (orphelines : un lecteur qui parcourt l'arbre ne les voit pas, un autre
//! qui lit le répertoire à la suite, si) sont rendues à part.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

use super::lecture::{tranche, u16le, u32le, u64le, utf16le};

pub(crate) const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;
const MAXREGSECT: u32 = 0xFFFF_FFFA;
const NOSTREAM: u32 = 0xFFFF_FFFF;
/// Au-delà, une entrée de répertoire n'est pas suivie : un document réel en a quelques centaines.
const ENTREES_MAX: usize = 16_384;
/// Les stockages imbriqués suivis (un document réel en a trois ou quatre niveaux), et la longueur d'un chemin : sans
/// elles, une chaîne de stockages coûterait le carré de sa longueur en chemins gardés.
const PROFONDEUR_MAX: usize = 32;
const CHEMIN_MAX: usize = 1024;
const MINI_SECTEUR: usize = 64;
const SEUIL_MINI: u64 = 4096;

/// Pourquoi le fichier ou un flux ne se lit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defaut {
    /// Pas la signature, ou un en-tête hors de la spécification (version, ordre des octets, taille de secteur).
    EnTete,
    /// Une chaîne de secteurs qui boucle, sort du fichier ou désigne une valeur réservée.
    Chaine,
    /// Un flux plus court que sa taille annoncée (fichier coupé).
    Tronque,
    /// Au-delà de la borne donnée par l'appelant.
    Limite,
    /// Le répertoire ou l'entrée racine ne se lit pas.
    Repertoire,
}

/// Une entrée du répertoire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entree {
    pub nom: String,
    /// 0 libre, 1 stockage, 2 flux, 5 racine.
    pub type_: u8,
    pub gauche: u32,
    pub droite: u32,
    pub enfant: u32,
    pub clsid: [u8; 16],
    pub debut: u32,
    pub taille: u64,
}

/// Un flux ou un stockage atteint par l'arbre : son numéro d'entrée et son chemin (« Macros/VBA/dir »).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Place {
    pub entree: usize,
    pub chemin: String,
    /// Le numéro de l'entrée du stockage qui la contient.
    pub parent: usize,
}

/// Un fichier composé lu : ses tables et son répertoire.
#[allow(clippy::struct_excessive_bools)] // des constats, chacun pour lui-même
#[derive(Debug)]
pub(crate) struct Cfb<'a> {
    octets: &'a [u8],
    secteur: usize,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    /// Le mini-flux (données de l'entrée racine), lu une fois.
    mini_flux: Vec<u8>,
    pub entrees: Vec<Entree>,
    /// Ce que l'arbre atteint, dans l'ordre du parcours.
    pub places: Vec<Place>,
    /// Les entrées allouées (stockage ou flux) que l'arbre n'atteint pas.
    pub orphelines: Vec<usize>,
    /// L'arbre revient sur une entrée déjà vue (boucle, ou deux chemins vers elle).
    pub arbre_boucle: bool,
    /// Des entrées ne sont pas vues : répertoire plus long que la borne, ou stockages trop imbriqués.
    pub limite_atteinte: bool,
    /// Pour chaque stockage, les places qu'il contient directement.
    enfants: std::collections::HashMap<usize, Vec<usize>>,
    /// Le mini-flux ou la mini-FAT ne se lisent pas : les petits flux non plus.
    pub mini_illisible: bool,
    /// La FAT ne se lit pas en entier (DIFAT coupée, secteur hors du fichier).
    pub fat_incomplete: bool,
}

impl<'a> Cfb<'a> {
    /// Le fichier composé `octets`, lu dans `limite` octets de tables et de mini-flux au plus.
    pub(crate) fn lire(octets: &'a [u8], limite: usize) -> Result<Cfb<'a>, Defaut> {
        if octets.get(..8) != Some(&SIGNATURE[..]) {
            return Err(Defaut::EnTete);
        }
        let majeure = u16le(octets, 26).ok_or(Defaut::EnTete)?;
        let ordre = u16le(octets, 28).ok_or(Defaut::EnTete)?;
        let decalage = u16le(octets, 30).ok_or(Defaut::EnTete)?;
        let mini = u16le(octets, 32).ok_or(Defaut::EnTete)?;
        // Version 3 : secteurs de 512 octets ; version 4 : 4 096. Ordre des octets 0xFFFE, mini-secteurs de 64.
        let secteur = match (majeure, decalage) {
            (3, 9) => 512usize,
            (4, 12) => 4096,
            _ => return Err(Defaut::EnTete),
        };
        if ordre != 0xFFFE || mini != 6 {
            return Err(Defaut::EnTete);
        }
        let champ = |a: usize| u32le(octets, a).ok_or(Defaut::EnTete);
        let nombre_fat = champ(44)? as usize;
        let premier_repertoire = champ(48)?;
        let premier_mini_fat = champ(60)?;
        let premier_difat = champ(68)?;
        // Le nombre de secteurs que le fichier peut contenir : aucune chaîne n'est plus longue.
        let secteurs_du_fichier = octets.len().saturating_sub(secteur) / secteur + 1;
        let mut c = Cfb {
            octets,
            secteur,
            fat: Vec::new(),
            mini_fat: Vec::new(),
            mini_flux: Vec::new(),
            entrees: Vec::new(),
            places: Vec::new(),
            orphelines: Vec::new(),
            arbre_boucle: false,
            limite_atteinte: false,
            enfants: std::collections::HashMap::new(),
            mini_illisible: false,
            fat_incomplete: false,
        };
        // La DIFAT : 109 entrées dans l'en-tête, puis sa propre chaîne (le dernier mot de chaque secteur désigne le
        // suivant), avec son témoin.
        let mut secteurs_fat = Vec::new();
        for k in 0..109 {
            let s = champ(76 + 4 * k)?;
            if s <= MAXREGSECT {
                secteurs_fat.push(s);
            }
        }
        let mut difat = premier_difat;
        let mut vus = vec![false; secteurs_du_fichier];
        while difat <= MAXREGSECT && secteurs_fat.len() < nombre_fat.min(secteurs_du_fichier) {
            let Some(vu) = vus.get_mut(difat as usize) else {
                c.fat_incomplete = true;
                break;
            };
            if *vu {
                c.fat_incomplete = true;
                break;
            }
            *vu = true;
            let Some(donnees) = c.secteur_brut(difat) else {
                c.fat_incomplete = true;
                break;
            };
            let mots = secteur / 4;
            for k in 0..mots - 1 {
                let s = u32le(donnees, 4 * k).unwrap_or(FREESECT);
                if s <= MAXREGSECT {
                    secteurs_fat.push(s);
                }
            }
            difat = u32le(donnees, 4 * (mots - 1)).unwrap_or(ENDOFCHAIN);
        }
        secteurs_fat.truncate(nombre_fat.min(secteurs_du_fichier));
        // La FAT : au plus un mot par secteur que le fichier peut contenir (le reste ne désignerait rien).
        let utiles = secteurs_du_fichier;
        for s in secteurs_fat {
            match c.secteur_brut(s) {
                Some(d) => {
                    for mot in d.as_chunks::<4>().0 {
                        if c.fat.len() >= utiles {
                            break;
                        }
                        c.fat.push(u32::from_le_bytes([mot[0], mot[1], mot[2], mot[3]]));
                    }
                }
                None => c.fat_incomplete = true,
            }
            if c.fat.len() >= utiles || c.fat.len().saturating_mul(4) > limite {
                break;
            }
        }
        // Le répertoire.
        let chaine = Self::chaine(premier_repertoire, &c.fat, utiles).map_err(|_| Defaut::Repertoire)?;
        for s in chaine {
            let Some(donnees) = c.secteur_brut(s) else {
                return Err(Defaut::Repertoire);
            };
            for e in donnees.as_chunks::<128>().0 {
                if c.entrees.len() >= ENTREES_MAX {
                    c.limite_atteinte = true;
                    break;
                }
                c.entrees.push(entree(e));
            }
        }
        if c.entrees.first().map(|r| r.type_) != Some(5) {
            return Err(Defaut::Repertoire);
        }
        // La mini-FAT et le mini-flux (les données de l'entrée racine, par la FAT).
        let racine = c.entrees[0].clone();
        match Self::chaine(premier_mini_fat, &c.fat, utiles) {
            Ok(chaine) => {
                for s in chaine {
                    let Some(d) = c.secteur_brut(s) else {
                        c.mini_illisible = true;
                        break;
                    };
                    c.mini_fat.extend(
                        d.as_chunks::<4>()
                            .0
                            .iter()
                            .map(|m| u32::from_le_bytes([m[0], m[1], m[2], m[3]])),
                    );
                    if c.mini_fat.len().saturating_mul(4) > limite {
                        c.mini_illisible = true;
                        break;
                    }
                }
            }
            Err(_) => c.mini_illisible = true,
        }
        if racine.taille > 0 {
            match c.lire_par_fat(racine.debut, racine.taille, limite) {
                Ok(m) => c.mini_flux = m,
                Err(_) => c.mini_illisible = true,
            }
        }
        c.parcourir_arbre();
        Ok(c)
    }

    /// Les octets du secteur `s` (le secteur 0 suit l'en-tête : position (s + 1) × taille).
    fn secteur_brut(&self, s: u32) -> Option<&'a [u8]> {
        let position = (s as usize).checked_add(1)?.checked_mul(self.secteur)?;
        let octets: &'a [u8] = self.octets;
        // Le dernier secteur peut être coupé par la fin du fichier : ce qui en reste est rendu.
        let fin = position.checked_add(self.secteur)?.min(octets.len());
        octets.get(position..fin).filter(|d| !d.is_empty())
    }

    /// La chaîne qui commence en `debut` dans `table`, d'au plus `max` maillons, sans boucle.
    fn chaine(debut: u32, table: &[u32], max: usize) -> Result<Vec<u32>, Defaut> {
        // Le témoin a la taille de la chaîne, pas celle de la table : lire mille petits flux d'un gros fichier ne
        // coûte pas mille fois la table.
        let mut chaine = Vec::new();
        let mut vus = std::collections::HashSet::new();
        let mut s = debut;
        while s != ENDOFCHAIN {
            let i = s as usize;
            if s > MAXREGSECT || i >= table.len() || chaine.len() >= max || !vus.insert(s) {
                return Err(Defaut::Chaine);
            }
            chaine.push(s);
            s = table[i];
        }
        Ok(chaine)
    }

    /// `taille` octets par la FAT depuis le secteur `debut`, au plus `limite`.
    fn lire_par_fat(&self, debut: u32, taille: u64, limite: usize) -> Result<Vec<u8>, Defaut> {
        let taille = usize::try_from(taille).map_err(|_| Defaut::Limite)?;
        if taille > limite {
            return Err(Defaut::Limite);
        }
        let maillons = taille.div_ceil(self.secteur);
        let chaine = Self::chaine(debut, &self.fat, maillons)?;
        let mut donnees = Vec::with_capacity(taille.min(chaine.len().saturating_mul(self.secteur)));
        for s in chaine {
            let d = self.secteur_brut(s).ok_or(Defaut::Chaine)?;
            donnees.extend_from_slice(&d[..d.len().min(taille - donnees.len())]);
        }
        if donnees.len() < taille {
            return Err(Defaut::Tronque);
        }
        Ok(donnees)
    }

    /// Le contenu du flux de l'entrée `i`, au plus `limite` octets. Pour un fichier version 3, les 32 bits de poids
    /// fort de la taille sont ignorés, comme le recommande la spécification.
    pub(crate) fn flux(&self, i: usize, limite: usize) -> Result<Vec<u8>, Defaut> {
        let e = self.entrees.get(i).ok_or(Defaut::Repertoire)?;
        let taille = if self.secteur == 512 {
            e.taille & 0xFFFF_FFFF
        } else {
            e.taille
        };
        if taille == 0 {
            return Ok(Vec::new());
        }
        if taille >= SEUIL_MINI {
            return self.lire_par_fat(e.debut, taille, limite);
        }
        if self.mini_illisible {
            return Err(Defaut::Chaine);
        }
        let taille = usize::try_from(taille).map_err(|_| Defaut::Limite)?;
        if taille > limite {
            return Err(Defaut::Limite);
        }
        let chaine = Self::chaine(e.debut, &self.mini_fat, taille.div_ceil(MINI_SECTEUR))?;
        let mut donnees = Vec::with_capacity(taille);
        for s in chaine {
            let position = (s as usize).checked_mul(MINI_SECTEUR).ok_or(Defaut::Chaine)?;
            let d = tranche(&self.mini_flux, position, MINI_SECTEUR)
                .or_else(|| self.mini_flux.get(position..))
                .filter(|d| !d.is_empty())
                .ok_or(Defaut::Tronque)?;
            donnees.extend_from_slice(&d[..d.len().min(taille - donnees.len())]);
        }
        if donnees.len() < taille {
            return Err(Defaut::Tronque);
        }
        Ok(donnees)
    }

    /// L'arbre, depuis l'enfant de la racine : chaque stockage a ses entrées en arbre (frères gauche et droit), son
    /// propre arbre sous son enfant. Une pile, un témoin.
    fn parcourir_arbre(&mut self) {
        let mut vus = vec![false; self.entrees.len()];
        vus[0] = true;
        // (entrée, numéro du stockage qui la contient, sa place s'il en a une, profondeur)
        let mut pile: Vec<(u32, usize, Option<usize>, usize)> = vec![(self.entrees[0].enfant, 0, None, 0)];
        while let Some((id, parent, place_parent, profondeur)) = pile.pop() {
            if id == NOSTREAM {
                continue;
            }
            let i = id as usize;
            if i >= self.entrees.len() {
                continue;
            }
            if vus[i] {
                self.arbre_boucle = true;
                continue;
            }
            vus[i] = true;
            let e = &self.entrees[i];
            let mut chemin = match place_parent {
                Some(k) => format!("{}/{}", self.places[k].chemin, e.nom),
                None => e.nom.clone(),
            };
            if chemin.len() > CHEMIN_MAX {
                let mut fin = CHEMIN_MAX;
                while !chemin.is_char_boundary(fin) {
                    fin -= 1;
                }
                chemin.truncate(fin);
            }
            pile.push((e.droite, parent, place_parent, profondeur));
            pile.push((e.gauche, parent, place_parent, profondeur));
            let (type_, enfant) = (e.type_, e.enfant);
            if matches!(type_, 1 | 2) {
                self.places.push(Place {
                    entree: i,
                    chemin,
                    parent,
                });
                let k = self.places.len() - 1;
                self.enfants.entry(parent).or_default().push(k);
                if type_ == 1 {
                    if profondeur + 1 < PROFONDEUR_MAX {
                        pile.push((enfant, i, Some(k), profondeur + 1));
                    } else if enfant != NOSTREAM {
                        self.limite_atteinte = true;
                    }
                }
            }
        }
        self.orphelines = (1..self.entrees.len())
            .filter(|&i| !vus[i] && matches!(self.entrees[i].type_, 1 | 2))
            .collect();
    }

    /// Le flux nommé `nom` (sans tenir compte de la casse, comme le fichier composé compare ses noms) directement
    /// sous le stockage `stockage`.
    pub(crate) fn flux_nomme(&self, stockage: usize, nom: &str) -> Option<usize> {
        self.enfants
            .get(&stockage)?
            .iter()
            .map(|&k| self.places[k].entree)
            .find(|&e| self.entrees[e].type_ == 2 && egaux_sans_casse(&self.entrees[e].nom, nom))
    }
}

/// La comparaison des noms du fichier composé : sans tenir compte de la casse (une majuscule simple suffit pour les
/// noms qu'on cherche ici).
pub(crate) fn egaux_sans_casse(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_uppercase)
        .eq(b.chars().flat_map(char::to_uppercase))
}

/// Une entrée de 128 octets : nom UTF-16 (64 octets, longueur en octets nul compris), type, frères, enfant, CLSID,
/// premier secteur, taille.
fn entree(e: &[u8]) -> Entree {
    let longueur = usize::from(u16le(e, 64).unwrap_or(0)).min(64);
    let nom = utf16le(&e[..longueur.saturating_sub(2)]);
    let mut clsid = [0u8; 16];
    clsid.copy_from_slice(&e[80..96]);
    Entree {
        nom,
        type_: e[66],
        gauche: u32le(e, 68).unwrap_or(NOSTREAM),
        droite: u32le(e, 72).unwrap_or(NOSTREAM),
        enfant: u32le(e, 76).unwrap_or(NOSTREAM),
        clsid,
        debut: u32le(e, 116).unwrap_or(ENDOFCHAIN),
        taille: u64le(e, 120).unwrap_or(0),
    }
}

#[cfg(test)]
pub(crate) mod essais {
    //! Des fichiers composés fabriqués ici (version 3, secteurs de 512 octets) : aucun document tiers.

    /// Un flux ou un stockage à écrire : chemin (« VBA/dir ») et contenu (`None` : un stockage).
    pub(crate) type Element<'a> = (&'a str, Option<&'a [u8]>);

    /// Un fichier composé : chaque stockage et flux, les flux de moins de 4 096 octets dans le mini-flux. Les
    /// entrées d'un même stockage sont chaînées par leur frère droit (un arbre dégénéré, permis : la couleur n'est
    /// pas lue).
    pub(crate) fn fichier(elements: &[Element<'_>]) -> Vec<u8> {
        const S: usize = 512;
        // Entrées : 0 racine, puis une par élément.
        let mut noms: Vec<String> = vec!["Root Entry".into()];
        let mut types: Vec<u8> = vec![5];
        let mut parents: Vec<usize> = vec![usize::MAX];
        for (chemin, contenu) in elements {
            let (dossier, nom) = chemin.rsplit_once('/').unwrap_or(("", chemin));
            let parent = if dossier.is_empty() {
                0
            } else {
                1 + elements.iter().position(|(c, d)| c == &dossier && d.is_none()).unwrap()
            };
            noms.push(nom.to_string());
            types.push(if contenu.is_some() { 2 } else { 1 });
            parents.push(parent);
        }
        let n = noms.len();
        let gauche = vec![u32::MAX; n];
        let mut droite = vec![u32::MAX; n];
        let mut enfant = vec![u32::MAX; n];
        for i in 1..n {
            let p = parents[i];
            // Le premier enfant d'un stockage devient son enfant ; les suivants, frère droit du précédent.
            let freres: Vec<usize> = (1..i).filter(|&j| parents[j] == p).collect();
            match freres.last() {
                None => enfant[p] = u32::try_from(i).unwrap(),
                Some(&f) => droite[f] = u32::try_from(i).unwrap(),
            }
        }
        // Le mini-flux : les petits flux, à la suite, en mini-secteurs de 64 octets.
        let mut mini = Vec::new();
        let mut mini_fat: Vec<u32> = Vec::new();
        let mut gros: Vec<(usize, &[u8])> = Vec::new();
        let mut debuts = vec![0u32; n];
        let mut tailles = vec![0u64; n];
        for (k, (_, contenu)) in elements.iter().enumerate() {
            let Some(c) = contenu else { continue };
            tailles[k + 1] = c.len() as u64;
            if c.len() >= 4096 {
                gros.push((k + 1, c));
                continue;
            }
            if c.is_empty() {
                debuts[k + 1] = 0xFFFF_FFFE;
                continue;
            }
            let premier = u32::try_from(mini.len() / 64).unwrap();
            debuts[k + 1] = premier;
            let morceaux = c.len().div_ceil(64);
            for m in 0..morceaux {
                mini_fat.push(if m + 1 == morceaux {
                    0xFFFF_FFFE
                } else {
                    premier + u32::try_from(m).unwrap() + 1
                });
            }
            mini.extend_from_slice(c);
            mini.resize(mini.len().next_multiple_of(64), 0);
        }
        // Les secteurs : FAT (1), répertoire, mini-FAT, mini-flux, gros flux.
        let mut secteurs: Vec<Vec<u8>> = Vec::new();
        let mut fat: Vec<u32> = Vec::new();
        let chaine = |secteurs: &mut Vec<Vec<u8>>, fat: &mut Vec<u32>, donnees: &[u8]| -> u32 {
            if donnees.is_empty() {
                return 0xFFFF_FFFE;
            }
            let premier = u32::try_from(secteurs.len()).unwrap();
            let morceaux = donnees.len().div_ceil(S);
            for m in 0..morceaux {
                let mut s = donnees[m * S..((m + 1) * S).min(donnees.len())].to_vec();
                s.resize(S, 0);
                secteurs.push(s);
                fat.push(if m + 1 == morceaux {
                    0xFFFF_FFFE
                } else {
                    premier + u32::try_from(m).unwrap() + 1
                });
            }
            premier
        };
        secteurs.push(vec![0u8; S]);
        fat.push(0xFFFF_FFFD);
        let mut repertoire = vec![0u8; n.div_ceil(4) * 4 * 128];
        let premier_repertoire = u32::try_from(secteurs.len()).unwrap();
        let _ = chaine(&mut secteurs, &mut fat, &repertoire.clone());
        let mini_fat_octets: Vec<u8> = mini_fat.iter().flat_map(|m| m.to_le_bytes()).collect();
        let premier_mini_fat = chaine(&mut secteurs, &mut fat, &mini_fat_octets);
        let premier_mini = chaine(&mut secteurs, &mut fat, &mini);
        for (i, c) in gros {
            debuts[i] = chaine(&mut secteurs, &mut fat, c);
        }
        debuts[0] = premier_mini;
        tailles[0] = mini.len() as u64;
        for i in 0..n {
            let e = &mut repertoire[i * 128..(i + 1) * 128];
            let unites: Vec<u16> = noms[i].encode_utf16().chain([0]).collect();
            for (k, u) in unites.iter().enumerate() {
                e[2 * k..2 * k + 2].copy_from_slice(&u.to_le_bytes());
            }
            e[64..66].copy_from_slice(&u16::try_from(unites.len() * 2).unwrap().to_le_bytes());
            e[66] = types[i];
            e[67] = 1;
            e[68..72].copy_from_slice(&gauche[i].to_le_bytes());
            e[72..76].copy_from_slice(&droite[i].to_le_bytes());
            e[76..80].copy_from_slice(&enfant[i].to_le_bytes());
            e[116..120].copy_from_slice(&debuts[i].to_le_bytes());
            e[120..128].copy_from_slice(&tailles[i].to_le_bytes());
        }
        for (k, morceau) in repertoire.chunks(S).enumerate() {
            secteurs[premier_repertoire as usize + k][..morceau.len()].copy_from_slice(morceau);
        }
        assert!(fat.len() <= 128, "une seule FAT dans ce fabricant");
        let mut table = vec![0xFFu8; S];
        for (k, f) in fat.iter().enumerate() {
            table[4 * k..4 * k + 4].copy_from_slice(&f.to_le_bytes());
        }
        secteurs[0] = table;
        let mut v = vec![0u8; S];
        v[..8].copy_from_slice(&super::SIGNATURE);
        v[24..26].copy_from_slice(&0x3Eu16.to_le_bytes());
        v[26..28].copy_from_slice(&3u16.to_le_bytes());
        v[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        v[30..32].copy_from_slice(&9u16.to_le_bytes());
        v[32..34].copy_from_slice(&6u16.to_le_bytes());
        v[44..48].copy_from_slice(&1u32.to_le_bytes());
        v[48..52].copy_from_slice(&premier_repertoire.to_le_bytes());
        v[56..60].copy_from_slice(&4096u32.to_le_bytes());
        v[60..64].copy_from_slice(&premier_mini_fat.to_le_bytes());
        v[64..68].copy_from_slice(&u32::try_from(mini_fat_octets.len().div_ceil(S)).unwrap().to_le_bytes());
        v[68..72].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        for k in 0..109 {
            let s: u32 = if k == 0 { 0 } else { 0xFFFF_FFFF };
            v[76 + 4 * k..80 + 4 * k].copy_from_slice(&s.to_le_bytes());
        }
        for s in secteurs {
            v.extend(s);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::essais::fichier;
    use super::*;

    fn chemins(c: &Cfb<'_>) -> Vec<String> {
        let mut v: Vec<String> = c.places.iter().map(|p| p.chemin.clone()).collect();
        v.sort();
        v
    }

    #[test]
    fn arbre_et_flux() {
        let gros = vec![b'g'; 5000];
        let f = fichier(&[
            ("Macros", None),
            ("Macros/VBA", None),
            ("Macros/VBA/dir", Some(b"\x01abc")),
            ("Macros/VBA/Module1", Some(&gros)),
            ("WordDocument", Some(b"\xec\xa5")),
        ]);
        let c = Cfb::lire(&f, 1 << 20).unwrap();
        assert_eq!(
            chemins(&c),
            [
                "Macros",
                "Macros/VBA",
                "Macros/VBA/Module1",
                "Macros/VBA/dir",
                "WordDocument"
            ]
        );
        assert!(c.orphelines.is_empty() && !c.arbre_boucle && !c.mini_illisible && !c.fat_incomplete);
        let vba = c.places.iter().find(|p| p.chemin == "Macros/VBA").unwrap().entree;
        let dir = c.flux_nomme(vba, "DIR").unwrap();
        assert_eq!(c.flux(dir, 1 << 20).unwrap(), b"\x01abc");
        let module = c.flux_nomme(vba, "module1").unwrap();
        assert_eq!(c.flux(module, 1 << 20).unwrap(), gros);
        assert_eq!(c.flux(module, 100), Err(Defaut::Limite));
    }

    #[test]
    fn boucles_orphelines_et_coupures() {
        let f = fichier(&[("A", Some(b"un")), ("B", Some(b"deux")), ("C", Some(&[7u8; 4500]))]);
        assert!(Cfb::lire(&f, 1 << 20).is_ok());
        // Le frère droit de C désigne A : une boucle dans l'arbre, vue et arrêtée.
        let mut boucle = f.clone();
        let repertoire = 512 * 2; // en-tête, FAT (secteur 0), puis le répertoire (secteur 1)
        let c_entree = repertoire + 3 * 128;
        boucle[c_entree + 72..c_entree + 76].copy_from_slice(&1u32.to_le_bytes());
        let c = Cfb::lire(&boucle, 1 << 20).unwrap();
        assert!(c.arbre_boucle);
        assert_eq!(c.places.len(), 3);
        // B n'est plus désigné par A : B et C (atteint par B) deviennent orphelines.
        let mut orphelin = f.clone();
        let a_entree = repertoire + 128;
        orphelin[a_entree + 72..a_entree + 76].copy_from_slice(&u32::MAX.to_le_bytes());
        let c = Cfb::lire(&orphelin, 1 << 20).unwrap();
        assert_eq!(c.orphelines, [2, 3]);
        // La FAT qui boucle sur elle-même pour le gros flux C.
        let c_ok = Cfb::lire(&f, 1 << 20).unwrap();
        let debut = c_ok.entrees[3].debut as usize;
        let mut fat_boucle = f.clone();
        fat_boucle[512 + 4 * debut..512 + 4 * debut + 4].copy_from_slice(&u32::try_from(debut).unwrap().to_le_bytes());
        let c = Cfb::lire(&fat_boucle, 1 << 20).unwrap();
        assert_eq!(c.flux(3, 1 << 20), Err(Defaut::Chaine));
        // Coupé : le gros flux ne se lit plus en entier.
        let coupe = &f[..f.len() - 600];
        if let Ok(c) = Cfb::lire(coupe, 1 << 20) {
            assert!(c.flux(3, 1 << 20).is_err());
        }
        // En-têtes refusés.
        let mut version = f.clone();
        version[26] = 5;
        assert_eq!(Cfb::lire(&version, 1 << 20).err(), Some(Defaut::EnTete));
        assert_eq!(Cfb::lire(b"pas un cfb", 1 << 20).err(), Some(Defaut::EnTete));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(i in 0usize..6000, x in proptest::num::u8::ANY, j in 0usize..6000, y in proptest::num::u8::ANY) {
            let mut f = fichier(&[("VBA", None), ("VBA/dir", Some(b"\x01\x00\x00")), ("Gros", Some(&[1u8; 4200]))]);
            let n = f.len();
            f[i % n] = x;
            f[j % n] = y;
            if let Ok(c) = Cfb::lire(&f, 1 << 16) {
                for k in 0..c.entrees.len() {
                    if let Ok(d) = c.flux(k, 1 << 16) {
                        proptest::prop_assert!(d.len() <= 1 << 16);
                    }
                }
            }
        }
    }
}
