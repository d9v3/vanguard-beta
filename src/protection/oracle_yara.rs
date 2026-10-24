//! L'oracle du moteur YARA de Vanguard (tests seulement) : YARA-X, compilé en dépendance de développement, applique
//! les mêmes règles aux mêmes données, et les deux doivent trouver exactement les mêmes règles.
//!
//! - Corpus fabriqué : pour chacune des 308 règles, des données qui remplissent sa condition, faites de ses propres
//!   chaînes (jokers, sauts et choix tirés au hasard, graine fixe), avec l'en-tête PE ou ELF qu'elle demande, la
//!   chaîne de `at pe.entry_point` au point d'entrée, une signature Authenticode fabriquée (noms inventés) quand elle en
//!   exige une. Chaque règle doit y être trouvée par YARA-X (sinon le corpus ne prouve rien), et les deux moteurs
//!   doivent donner la même liste, en mémoire comme en flux lu par petits blocs (chaînes à cheval sur deux blocs).
//! - Fichiers sains de ce PC (exécutables, bibliothèques) : mêmes résultats, aucune détection attendue ; et les champs
//!   des modules (pe.entry_point, pe.is_pe, elf.entry_point) comparés un à un, comme pe.number_of_signatures > 0.
//! - Au hasard (proptest) : motifs hexadécimaux et données tirés dans un petit alphabet, `$a` et `$a at k` pour
//!   chaque position ; en-têtes PE et ELF abîmés de mille façons, champs comparés.
//!
//! Rien de ce qui est lu sur ce PC n'est gardé ni montré, seulement le chemin d'un écart.

// Des données fabriquées, de quelques Kio : les conversions de tailles et de positions y tiennent toujours.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::protection::moteur_yara::{Regles, entree_elf};
use crate::protection::motifs::Element;
use crate::protection::regles_yara::{self, Entier, Expr};

const ORIGINE: &str = include_str!("../../assets/yara/reversinglabs.yara");
const ALLEGEES: &str = include_str!(concat!(env!("OUT_DIR"), "/reversinglabs.yara"));

fn yara_x_regles(source: &str) -> yara_x::Rules {
    let mut c = yara_x::Compiler::new();
    c.add_source(source).unwrap();
    c.build()
}

fn par_yara_x(regles: &yara_x::Rules, donnees: &[u8]) -> BTreeSet<String> {
    let mut s = yara_x::Scanner::new(regles);
    s.scan(donnees)
        .unwrap()
        .matching_rules()
        .map(|m| m.identifier().to_string())
        .collect()
}

fn par_vanguard(regles: &Regles, donnees: &[u8]) -> BTreeSet<String> {
    regles
        .analyser_tampon(donnees, None)
        .unwrap()
        .into_iter()
        .map(|k| regles.nom(k).to_string())
        .collect()
}

fn par_vanguard_flux(regles: &Regles, donnees: &[u8]) -> BTreeSet<String> {
    regles
        .analyser_flux(&mut std::io::Cursor::new(donnees), donnees.len() as u64, None)
        .unwrap()
        .into_iter()
        .map(|k| regles.nom(k).to_string())
        .collect()
}

/// Un générateur pseudo-aléatoire minimal (xorshift), à graine fixe : le corpus est le même à chaque passage.
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn jusqua(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.suivant() % n }
    }

    fn octet(&mut self) -> u8 {
        (self.suivant() >> 24) as u8
    }
}

/// Des octets qui remplissent une suite d'éléments : `simple` prend le premier choix, les sauts au plus court et des
/// zéros pour les jokers ; sinon tout est tiré au hasard.
fn remplir(elements: &[Element], h: &mut Hasard, simple: bool, sortie: &mut Vec<u8>) {
    for e in elements {
        match e {
            Element::Octet { valeur, masque } => {
                let libre = if simple { 0 } else { h.octet() };
                sortie.push(valeur | (libre & !masque));
            }
            Element::Saut { min, max } => {
                let n = if simple {
                    *min
                } else {
                    *min + h.jusqua(u64::from(max - min) + 1) as u32
                };
                for _ in 0..n {
                    sortie.push(if simple { 0 } else { h.octet() });
                }
            }
            Element::Choix(suites) => {
                let k = if simple {
                    0
                } else {
                    h.jusqua(suites.len() as u64) as usize
                };
                remplir(&suites[k], h, simple, sortie);
            }
        }
    }
}

/// Ce qu'une condition demande de la forme du fichier.
#[derive(Default)]
struct Plan {
    pe: bool,
    elf: bool,
    signature: bool,
    /// La chaîne à mettre au point d'entrée (la première citée), et celles à une position fixe.
    entree: Option<usize>,
    fixes: Vec<(usize, u64)>,
}

fn planifier(e: &Expr, plan: &mut Plan) {
    match e {
        Expr::Et(t) | Expr::Ou(t) => t.iter().for_each(|x| planifier(x, plan)),
        Expr::Non(x) => planifier(x, plan),
        Expr::Comparer(
            Entier::Lire {
                octets: 2, position, ..
            },
            _,
            Entier::Nombre(0x5A4D),
        ) if **position == Entier::Nombre(0) => {
            plan.pe = true;
        }
        Expr::Comparer(
            Entier::Lire {
                octets: 4, position, ..
            },
            _,
            Entier::Nombre(0x464C_457F),
        ) if **position == Entier::Nombre(0) => {
            plan.elf = true;
        }
        Expr::ChaineA(c, Entier::PeEntree | Entier::ElfEntree) => {
            if plan.entree.is_none() {
                plan.entree = Some(*c);
            }
        }
        Expr::ChaineA(c, Entier::Nombre(n)) => plan.fixes.push((*c, *n as u64)),
        Expr::SignaturePresente => plan.signature = true,
        _ => {}
    }
}

/// Une signature Authenticode minimale, aux noms inventés, que YARA-X compte (vérifié en boîte noire : il lui faut un
/// signataire avec ses attributs signés contentType et messageDigest) ; jamais valide, ce qui ne change pas le compte.
fn signature_fabriquee() -> Vec<u8> {
    fn enc(etiquette: u8, contenu: &[u8]) -> Vec<u8> {
        let mut v = vec![etiquette];
        let longueur = contenu.len();
        if let Ok(court) = u8::try_from(longueur)
            && court < 0x80
        {
            v.push(court);
        } else {
            let octets = longueur.to_be_bytes();
            let debut = octets.iter().position(|x| *x != 0).unwrap();
            v.push(0x80 | u8::try_from(octets.len() - debut).unwrap());
            v.extend_from_slice(&octets[debut..]);
        }
        v.extend_from_slice(contenu);
        v
    }
    let cat = |k: &[Vec<u8>]| k.concat();
    let seq = |k: &[Vec<u8>]| enc(0x30, &cat(k));
    let set = |k: &[Vec<u8>]| enc(0x31, &cat(k));
    let oid = |h: &[u8]| enc(0x06, h);
    let sha256 = seq(&[
        oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
        enc(0x05, &[]),
    ]);
    let rsa = seq(&[
        oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]),
        enc(0x05, &[]),
    ]);
    let spc_indirect = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
    let nom = seq(&[set(&[seq(&[oid(&[0x55, 0x04, 0x03]), enc(0x0C, b"Salon")])])]);
    let spc = seq(&[
        seq(&[
            oid(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F]),
            seq(&[]),
        ]),
        seq(&[sha256.clone(), enc(0x04, &[0x11; 32])]),
    ]);
    let attributs = cat(&[
        seq(&[
            oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]),
            set(&[oid(&spc_indirect)]),
        ]),
        seq(&[
            oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]),
            set(&[enc(0x04, &[0x33; 32])]),
        ]),
    ]);
    let signataire = seq(&[
        enc(0x02, &[1]),
        seq(&[nom, enc(0x02, &[7])]),
        sha256.clone(),
        enc(0xA0, &attributs),
        rsa,
        enc(0x04, &[0x22; 64]),
    ]);
    let donnees_signees = seq(&[
        enc(0x02, &[1]),
        set(&[sha256]),
        seq(&[oid(&spc_indirect), enc(0xA0, &spc)]),
        set(&[signataire]),
    ]);
    seq(&[
        oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]),
        enc(0xA0, &donnees_signees),
    ])
}

/// Des données qui remplissent la condition de `regle` : toutes ses chaînes (sa condition n'a pas de `not`, ce que
/// le test vérifie), placées après l'en-tête, celle du point d'entrée en premier.
fn fabriquer(regle: &regles_yara::Regle, h: &mut Hasard, simple: bool) -> Vec<u8> {
    let mut plan = Plan::default();
    planifier(&regle.condition, &mut plan);
    let mut d = vec![0u8; 0x400];
    let debut_chaines = 0x400u64;
    if plan.pe {
        d[..2].copy_from_slice(b"MZ");
        // L'en-tête PE loin de 0x40, où une règle attend une chaîne.
        let pe = 0x200usize;
        d[0x3C..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        d[pe..pe + 4].copy_from_slice(b"PE\0\0");
        d[pe + 4..pe + 6].copy_from_slice(&0x014C_u16.to_le_bytes());
        d[pe + 6..pe + 8].copy_from_slice(&1_u16.to_le_bytes());
        d[pe + 20..pe + 22].copy_from_slice(&0xE0_u16.to_le_bytes());
        let oh = pe + 24;
        d[oh..oh + 2].copy_from_slice(&0x10B_u16.to_le_bytes());
        // Point d'entrée : RVA 0x1000, au début de l'unique section, dont les données commencent à 0x400.
        d[oh + 16..oh + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        d[oh + 32..oh + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        d[oh + 36..oh + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        let s = oh + 0xE0;
        d[s..s + 8].copy_from_slice(b".text\0\0\0");
        d[s + 8..s + 12].copy_from_slice(&0x0100_0000_u32.to_le_bytes());
        d[s + 12..s + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        d[s + 16..s + 20].copy_from_slice(&0x0100_0000_u32.to_le_bytes());
        d[s + 20..s + 24].copy_from_slice(&0x400_u32.to_le_bytes());
    }
    if plan.elf {
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[6] = 1;
        d[16..18].copy_from_slice(&2_u16.to_le_bytes());
        // Un segment de 0x400000, qui commence au début du fichier : l'entrée 0x400400 tombe à 0x400.
        d[24..32].copy_from_slice(&(0x40_0000 + debut_chaines).to_le_bytes());
        d[32..40].copy_from_slice(&0x40_u64.to_le_bytes());
        d[54..56].copy_from_slice(&56_u16.to_le_bytes());
        d[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let p = 0x40;
        d[p..p + 4].copy_from_slice(&1_u32.to_le_bytes());
        d[p + 16..p + 24].copy_from_slice(&0x40_0000_u64.to_le_bytes());
        d[p + 40..p + 48].copy_from_slice(&0x0100_0000_u64.to_le_bytes());
    }
    for (c, position) in &plan.fixes {
        let mut o = Vec::new();
        remplir(&regle.chaines[*c].formes[0], h, simple, &mut o);
        let p = *position as usize;
        d[p..p + o.len()].copy_from_slice(&o);
    }
    let mut ordre: Vec<usize> = plan.entree.into_iter().collect();
    ordre.extend((0..regle.chaines.len()).filter(|c| Some(*c) != plan.entree && !plan.fixes.iter().any(|f| f.0 == *c)));
    for c in ordre {
        let formes = &regle.chaines[c].formes;
        let k = if simple {
            0
        } else {
            h.jusqua(formes.len() as u64) as usize
        };
        remplir(&formes[k], h, simple, &mut d);
        for _ in 0..=h.jusqua(16) {
            d.push(if simple { 0 } else { h.octet() });
        }
    }
    if plan.signature {
        while !d.len().is_multiple_of(8) {
            d.push(0);
        }
        let der = signature_fabriquee();
        let mut certificat = Vec::new();
        certificat.extend_from_slice(&((8 + der.len()) as u32).to_le_bytes());
        certificat.extend_from_slice(&0x200_u16.to_le_bytes());
        certificat.extend_from_slice(&2_u16.to_le_bytes());
        certificat.extend_from_slice(&der);
        while !certificat.len().is_multiple_of(8) {
            certificat.push(0);
        }
        let oh = 0x200 + 24;
        let repertoire = oh + 96 + 8 * 4;
        let position = d.len() as u32;
        d[repertoire..repertoire + 4].copy_from_slice(&position.to_le_bytes());
        d[repertoire + 4..repertoire + 8].copy_from_slice(&(certificat.len() as u32).to_le_bytes());
        d.extend_from_slice(&certificat);
    }
    d
}

fn sans_non(e: &Expr) -> bool {
    match e {
        Expr::Non(_) => false,
        Expr::Et(t) | Expr::Ou(t) => t.iter().all(sans_non),
        _ => true,
    }
}

/// Le corpus fabriqué : chaque règle trouvée par YARA-X dans ses propres données, et les deux moteurs d'accord, sur
/// le tampon comme sur le flux lu par blocs de 7, 64 et 4096 octets, avec les règles d'origine comme allégées.
#[test]
fn corpus_fabrique_sans_ecart() {
    let oracle = yara_x_regles(ORIGINE);
    let origine = Regles::compiler(ORIGINE);
    let allegees = Regles::compiler(ALLEGEES);
    assert_eq!(origine.refus(), []);
    let lues = regles_yara::lire(ORIGINE);
    assert_eq!(lues.regles.len(), 308);
    let flux: Vec<(usize, Regles)> = [7, 64, 4096]
        .into_iter()
        .map(|b| (b, Regles::compiler(ALLEGEES).avec_bloc(b)))
        .collect();
    let mut h = Hasard(0x5EED_2026_1024);
    let mut ecarts = Vec::new();
    for regle in &lues.regles {
        assert!(
            sans_non(&regle.condition),
            "{} : une condition avec `not` demanderait un autre corpus",
            regle.nom
        );
        for simple in [true, false] {
            let d = fabriquer(regle, &mut h, simple);
            let attendu = par_yara_x(&oracle, &d);
            if !attendu.contains(&regle.nom) {
                ecarts.push(format!(
                    "{} : non trouvée par YARA-X dans ses propres données (simple={simple})",
                    regle.nom
                ));
            }
            for (forme, obtenu) in [
                ("tampon, origine", par_vanguard(&origine, &d)),
                ("tampon, allégées", par_vanguard(&allegees, &d)),
            ] {
                if obtenu != attendu {
                    ecarts.push(format!(
                        "{} ({forme}, simple={simple}) : YARA-X {attendu:?}, Vanguard {obtenu:?}",
                        regle.nom
                    ));
                }
            }
            let (bloc, par_blocs) = &flux[h.jusqua(3) as usize];
            let obtenu = par_vanguard_flux(par_blocs, &d);
            if obtenu != attendu {
                ecarts.push(format!(
                    "{} (flux par {bloc}, simple={simple}) : YARA-X {attendu:?}, Vanguard {obtenu:?}",
                    regle.nom
                ));
            }
        }
    }
    assert!(ecarts.is_empty(), "{} écart(s) :\n{}", ecarts.len(), ecarts.join("\n"));
}

/// Les fichiers d'un dossier de ce PC, sans suivre les liens, jusqu'à `max` fichiers de `taille_max` octets au plus.
fn fichiers_du_pc(dossiers: &[PathBuf], max: usize, taille_max: u64, garder: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut trouves = Vec::new();
    let mut a_voir: Vec<PathBuf> = dossiers.to_vec();
    while let Some(d) = a_voir.pop() {
        let Ok(entrees) = std::fs::read_dir(&d) else { continue };
        let mut liste: Vec<_> = entrees.flatten().collect();
        liste.sort_by_key(std::fs::DirEntry::file_name);
        for e in liste {
            let Ok(m) = e.metadata() else { continue };
            let p = e.path();
            if m.file_type().is_symlink() {
                continue;
            }
            if m.is_dir() {
                a_voir.push(p);
            } else if m.is_file() && m.len() <= taille_max && garder(&p) {
                trouves.push(p);
                if trouves.len() >= max {
                    return trouves;
                }
            }
        }
    }
    trouves
}

fn dossiers_du_pc() -> Vec<PathBuf> {
    let maison = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    [
        PathBuf::from("/usr/bin"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/x86_64-w64-mingw32"),
        maison.join(".local/share/Steam"),
    ]
    .into_iter()
    .filter(|d| d.is_dir())
    .collect()
}

fn commence_par(p: &Path, magie: &[u8]) -> bool {
    use std::io::Read;
    let mut t = vec![0u8; magie.len()];
    std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut t)).is_ok() && t == magie
}

/// Des exécutables et bibliothèques sains de ce PC (PE et ELF) : les deux moteurs d'accord, et aucune détection. Plus
/// de fichiers avec VANGUARD_ORACLE_YARA=complet.
#[test]
fn fichiers_sains_du_pc_sans_ecart() {
    let dossiers = dossiers_du_pc();
    if dossiers.is_empty() {
        return crate::essais::saute("aucun dossier d'exécutables sur ce système");
    }
    let complet = std::env::var("VANGUARD_ORACLE_YARA").is_ok_and(|v| v == "complet");
    let (max, taille) = if complet { (20_000, 64 << 20) } else { (120, 4 << 20) };
    let liste = fichiers_du_pc(&dossiers, max, taille, |p| {
        commence_par(p, b"MZ") || commence_par(p, b"\x7fELF")
    });
    let oracle = yara_x_regles(ALLEGEES);
    let moteur = Regles::compiler(ALLEGEES);
    let mut ecarts = Vec::new();
    for f in &liste {
        let Ok(d) = std::fs::read(f) else { continue };
        let attendu = par_yara_x(&oracle, &d);
        let obtenu = par_vanguard_flux(&moteur, &d);
        if attendu != obtenu || !obtenu.is_empty() {
            ecarts.push(format!("{} : YARA-X {attendu:?}, Vanguard {obtenu:?}", f.display()));
        }
    }
    eprintln!("{} fichiers sains comparés", liste.len());
    assert!(ecarts.is_empty(), "{}", ecarts.join("\n"));
}

/// Les champs des modules, comparés à ceux de YARA-X.
fn comparer_pe(d: &[u8]) -> Option<String> {
    let oracle = yara_x::mods::invoke::<yara_x::mods::PE>(d);
    let (oracle_pe, oracle_entree, oracle_signatures) = match &oracle {
        Some(p) => (p.is_pe(), p.entry_point, p.number_of_signatures()),
        None => (false, None, 0),
    };
    let champs = crate::pe::champs_yara(&mut std::io::Cursor::new(d), d.len() as u64);
    let entree = champs.and_then(|c| c.point_d_entree).map(|p| p as i64);
    let signature =
        champs.is_some_and(|c| crate::pe::signature_presente(&mut std::io::Cursor::new(d), d.len() as u64, &c));
    let oracle_entree = if oracle_pe { oracle_entree } else { None };
    if champs.is_some() != oracle_pe || entree != oracle_entree.map(i64::from) && oracle_pe {
        return Some(format!(
            "is_pe {oracle_pe} / {}, entry_point {oracle_entree:?} / {entree:?}",
            champs.is_some()
        ));
    }
    // Une signature que YARA-X compte est toujours vue ici (l'inverse n'est pas exigé : voir pe::signature_presente).
    if oracle_signatures > 0 && !signature {
        return Some(format!("signatures {oracle_signatures} / aucune"));
    }
    None
}

fn comparer_elf(d: &[u8]) -> Option<String> {
    let oracle = yara_x::mods::invoke::<yara_x::mods::ELF>(d).and_then(|e| e.entry_point);
    let obtenu = entree_elf(&mut std::io::Cursor::new(d), d.len() as u64).map(|v| v as i64);
    (oracle != obtenu).then(|| format!("elf.entry_point {oracle:?} / {obtenu:?}"))
}

/// Les PE et ELF de ce PC : champs des modules identiques à ceux de YARA-X ; et sur les PE, la signature vue ici
/// exactement quand YARA-X en compte une (sur des fichiers réels, sans signature abîmée, les deux coïncident).
#[test]
fn champs_des_modules_sur_les_fichiers_du_pc() {
    let dossiers = dossiers_du_pc();
    if dossiers.is_empty() {
        return crate::essais::saute("aucun dossier d'exécutables sur ce système");
    }
    let complet = std::env::var("VANGUARD_ORACLE_YARA").is_ok_and(|v| v == "complet");
    let max = if complet { 50_000 } else { 1500 };
    let liste = fichiers_du_pc(&dossiers, max, 64 << 20, |p| {
        commence_par(p, b"MZ") || commence_par(p, b"\x7fELF")
    });
    let mut ecarts = Vec::new();
    let mut signes = 0;
    for f in &liste {
        let Ok(d) = std::fs::read(f) else { continue };
        let ecart = if d.starts_with(b"MZ") {
            let signe = yara_x::mods::invoke::<yara_x::mods::PE>(&d).is_some_and(|p| p.number_of_signatures() > 0);
            signes += usize::from(signe);
            let vu = crate::pe::champs_yara(&mut std::io::Cursor::new(&d[..]), d.len() as u64)
                .is_some_and(|c| crate::pe::signature_presente(&mut std::io::Cursor::new(&d[..]), d.len() as u64, &c));
            comparer_pe(&d).or_else(|| (signe != vu).then(|| format!("signature {signe} / {vu}")))
        } else {
            comparer_elf(&d)
        };
        if let Some(e) = ecart {
            ecarts.push(format!("{} : {e}", f.display()));
        }
    }
    eprintln!("{} fichiers comparés, dont {signes} PE signés", liste.len());
    assert!(ecarts.is_empty(), "{}", ecarts.join("\n"));
}

mod hasard {
    use super::*;
    use proptest::prelude::*;
    use std::fmt::Write;

    /// Un élément de motif en texte YARA, dans un petit alphabet (41 à 44) pour que les correspondances abondent.
    fn element(profondeur: u32) -> BoxedStrategy<String> {
        let octet = prop_oneof![
            4 => (0x41u8..0x45).prop_map(|o| format!("{o:02X}")),
            1 => Just("??".to_string()),
            1 => Just("4?".to_string()),
            1 => (1u8..5).prop_map(|o| format!("?{o:X}")),
        ];
        if profondeur == 0 {
            return octet.boxed();
        }
        prop_oneof![
            6 => octet,
            1 => proptest::collection::vec(proptest::collection::vec(element(profondeur - 1), 1..4), 2..4)
                .prop_map(|suites| format!("( {} )", suites.iter().map(|s| s.join(" ")).collect::<Vec<_>>().join(" | "))),
        ]
        .boxed()
    }

    /// Un motif : des éléments, des sauts entre eux (jamais au bord), et au moins un octet connu hors des choix,
    /// sans quoi le moteur le refuse (rien à mettre dans l'automate).
    fn motif() -> impl Strategy<Value = String> {
        (
            proptest::collection::vec(element(2), 1..6),
            proptest::collection::vec(proptest::option::of((0u32..4, 0u32..4)), 7),
            0usize..6,
            0x41u8..0x45,
        )
            .prop_map(|(mut elements, sauts, place, connu)| {
                elements.insert(place.min(elements.len()), format!("{connu:02X}"));
                let mut t = String::new();
                for (k, e) in elements.iter().enumerate() {
                    if k > 0
                        && let Some((a, b)) = sauts[k]
                    {
                        let _ = write!(t, "[{}-{}] ", a.min(b), a.max(b).max(1));
                    }
                    t.push_str(e);
                    t.push(' ');
                }
                t
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 200, failure_persistence: None, ..ProptestConfig::default() })]

        /// `$a` et `$a at k` pour chaque position : mêmes réponses que YARA-X.
        #[test]
        fn motifs_au_hasard(motif in motif(), donnees in proptest::collection::vec(0x41u8..0x45, 0..40)) {
            let mut source = format!("rule existe {{ strings: $a = {{ {motif} }} condition: $a }}\n");
            for k in 0..=donnees.len() {
                let _ = writeln!(source, "rule a{k} {{ strings: $a = {{ {motif} }} condition: $a at {k} }}");
            }
            let moteur = Regles::compiler(&source);
            prop_assert_eq!(moteur.refus(), &[], "{}", motif);
            let oracle = yara_x_regles(&source);
            let attendu = par_yara_x(&oracle, &donnees);
            prop_assert_eq!(&par_vanguard(&moteur, &donnees), &attendu, "{}", motif);
            prop_assert_eq!(&par_vanguard_flux(&Regles::compiler(&source).avec_bloc(3), &donnees), &attendu, "{}", motif);
        }

        /// Des PE abîmés : en-têtes, sections, alignements, tailles tirés au hasard autour d'une forme valide.
        #[test]
        fn pe_au_hasard(
            e_lfanew in prop_oneof![Just(0x40u32), Just(0x80), 0u32..0x400],
            sections in 0u16..6,
            facultatif in prop_oneof![Just(0xE0u16), Just(0xF0), 0u16..0x120],
            magie in prop_oneof![Just(0x10Bu16), Just(0x20B), any::<u16>()],
            entree in prop_oneof![0u32..0x6000, any::<u32>()],
            alignements in (prop_oneof![Just(0x1000u32), Just(0x200), 0u32..0x2001, any::<u32>()], prop_oneof![Just(0x200u32), Just(0x1000), 0u32..0x401, any::<u32>()]),
            table in proptest::collection::vec((prop_oneof![0u32..0x3000, any::<u32>()], prop_oneof![0x1000u32..0x6000, 0u32..0x1000, any::<u32>()], prop_oneof![0u32..0x3000, any::<u32>()], prop_oneof![0u32..0x2000, any::<u32>()]), 6),
            taille in 0usize..0x1200,
        ) {
            let mut d = vec![0u8; 0x1200];
            d[..2].copy_from_slice(b"MZ");
            d[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
            let pe = e_lfanew as usize;
            if pe + 24 + 0x120 + 6 * 40 < d.len() {
                d[pe..pe + 4].copy_from_slice(b"PE\0\0");
                d[pe + 6..pe + 8].copy_from_slice(&sections.to_le_bytes());
                d[pe + 20..pe + 22].copy_from_slice(&facultatif.to_le_bytes());
                let oh = pe + 24;
                d[oh..oh + 2].copy_from_slice(&magie.to_le_bytes());
                d[oh + 16..oh + 20].copy_from_slice(&entree.to_le_bytes());
                d[oh + 32..oh + 36].copy_from_slice(&alignements.0.to_le_bytes());
                d[oh + 36..oh + 40].copy_from_slice(&alignements.1.to_le_bytes());
                for (k, (vs, va, rs, rp)) in table.iter().enumerate() {
                    let s = oh + usize::from(facultatif) + 40 * k;
                    d[s + 8..s + 12].copy_from_slice(&vs.to_le_bytes());
                    d[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
                    d[s + 16..s + 20].copy_from_slice(&rs.to_le_bytes());
                    d[s + 20..s + 24].copy_from_slice(&rp.to_le_bytes());
                }
            }
            d.truncate(taille);
            prop_assert_eq!(comparer_pe(&d), None);
        }

        /// Des ELF abîmés : classe, boutisme, type, tables de segments et de sections tirés au hasard.
        #[test]
        fn elf_au_hasard(
            classe in prop_oneof![Just(1u8), Just(2), any::<u8>()],
            boutisme in prop_oneof![Just(1u8), Just(2), any::<u8>()],
            sorte in prop_oneof![Just(1u16), Just(2), Just(3), any::<u16>()],
            entree in prop_oneof![Just(0u64), 0x40_0000u64..0x40_3000, any::<u64>()],
            nombres in (0u16..5, 0u16..5),
            tables in (prop_oneof![Just(0x40u64), 0u64..0x200, any::<u64>()], prop_oneof![Just(0x400u64), 0u64..0x800]),
            entrees in proptest::collection::vec((any::<u32>(), prop_oneof![0x40_0000u64..0x40_3000, any::<u64>()], 0u64..0x3000, prop_oneof![0u64..0x3000, any::<u64>()]), 5),
            taille in 0usize..0xC00,
        ) {
            let mut d = vec![0u8; 0xC00];
            d[..4].copy_from_slice(b"\x7fELF");
            d[4] = classe;
            d[5] = boutisme;
            let large = classe != 1;
            let gros = boutisme == 2;
            let ecrire = |d: &mut Vec<u8>, a: usize, v: u64, n: usize| {
                for k in 0..n {
                    let o = (v >> (8 * k)) as u8;
                    let place = if gros { a + n - 1 - k } else { a + k };
                    if place < d.len() {
                        d[place] = o;
                    }
                }
            };
            let mot = if large { 8 } else { 4 };
            ecrire(&mut d, 16, u64::from(sorte), 2);
            ecrire(&mut d, 24, entree, mot);
            ecrire(&mut d, 24 + mot, tables.0, mot);
            ecrire(&mut d, 24 + 2 * mot, tables.1, mot);
            let nombres_a = 24 + 3 * mot + 6;
            ecrire(&mut d, nombres_a + 2, u64::from(nombres.0), 2);
            ecrire(&mut d, nombres_a + 6, u64::from(nombres.1), 2);
            for (k, (genre, adresse, position, etendue)) in entrees.iter().enumerate() {
                if let Ok(t) = usize::try_from(tables.0) && t < 0xC00 {
                    let (pas, champs) = if large { (56, [(0, 4), (16, 8), (8, 8), (40, 8)]) } else { (32, [(0, 4), (8, 4), (4, 4), (20, 4)]) };
                    let e = t + k * pas;
                    for ((a, n), v) in champs.iter().zip([u64::from(*genre), *adresse, *position, *etendue]) {
                        ecrire(&mut d, e + a, v, *n);
                    }
                }
                if let Ok(t) = usize::try_from(tables.1) {
                    let (pas, champs) = if large { (64, [(4, 4), (16, 8), (24, 8), (32, 8)]) } else { (40, [(4, 4), (12, 4), (16, 4), (20, 4)]) };
                    let e = t + k * pas;
                    for ((a, n), v) in champs.iter().zip([u64::from(*genre % 10), *adresse, *position, *etendue]) {
                        ecrire(&mut d, e + a, v, *n);
                    }
                }
            }
            d.truncate(taille);
            prop_assert_eq!(comparer_elf(&d), None);
        }
    }
}
