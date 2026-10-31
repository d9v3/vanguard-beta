//! Les en-têtes d'un exécutable ELF (Linux, BSD…), d'après elf(5) et la spécification System V (gABI) : en-tête,
//! segments (table des programmes, ce que lit le chargeur), sections (table des sections, ce que lisent les outils),
//! interpréteur (PT_INTERP), pile exécutable (PT_GNU_STACK), et la fin des données décrites, au-delà de laquelle des
//! octets ajoutés (overlay) sont à analyser à part. 32 et 64 bits, petit et gros-boutiste ; les comptes étendus
//! (PN_XNUM, e_shnum nul, SHN_XINDEX) lus dans la section 0, comme le dit elf(5).
//!
//! Lecteur pur : le fichier est en mémoire, chaque position contrôlée ; tout ce qui sort de la forme donne `None` ou
//! un drapeau, jamais une panique. Sans `crate::` : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use super::lecture::{Ordre, chaine_c, en_u64};

pub(crate) const PT_LOAD: u32 = 1;
pub(crate) const PT_INTERP: u32 = 3;
pub(crate) const PT_GNU_STACK: u32 = 0x6474_e551;
pub(crate) const PF_X: u32 = 1;
pub(crate) const PF_W: u32 = 2;
const SHT_NOBITS: u32 = 8;
const PN_XNUM: u16 = 0xffff;
const SHN_XINDEX: u16 = 0xffff;
/// Le noyau Linux refuse plus de 64 Kio de table des programmes : bien au-delà de tout exécutable réel.
const SEGMENTS_MAX: usize = 4096;
/// Des sections, il y en a des dizaines de milliers dans un gros programme compilé avec une section par fonction.
const SECTIONS_MAX: usize = 65_536;
const NOM_MAX: usize = 256;
const INTERPRETEUR_MAX: usize = 4096;

/// Un segment de la table des programmes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Segment {
    pub type_: u32,
    pub drapeaux: u32,
    pub position: u64,
    pub adresse: u64,
    pub taille_fichier: u64,
    pub taille_memoire: u64,
}

impl Segment {
    pub(crate) fn executable(&self) -> bool {
        self.drapeaux & PF_X != 0
    }

    pub(crate) fn ecrivable(&self) -> bool {
        self.drapeaux & PF_W != 0
    }
}

/// Une section de la table des sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SectionElf {
    pub nom: String,
    pub type_: u32,
    pub drapeaux: u64,
    pub position: u64,
    pub taille: u64,
}

/// Ce que disent les en-têtes.
#[allow(clippy::struct_excessive_bools)] // des drapeaux lus, chacun pour lui-même
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Elf {
    pub bits64: bool,
    pub gros_boutiste: bool,
    /// e_type : 1 objet, 2 exécutable, 3 objet partagé (ou exécutable à position indépendante), 4 core.
    pub type_: u16,
    pub machine: u16,
    pub point_entree: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<SectionElf>,
    pub interpreteur: Option<String>,
    /// PT_GNU_STACK : la pile est-elle exécutable ? `None` sans ce segment.
    pub pile_executable: Option<bool>,
    /// La table des segments ne se lit pas en entier (hors du fichier, trop grande).
    pub segments_illisibles: bool,
    /// La table des sections ne se lit pas en entier, ou ses noms non plus : un programme peut l'abîmer exprès
    /// (le chargeur ne la lit pas) pour gêner les outils.
    pub sections_illisibles: bool,
    /// La fin de ce que décrivent les en-têtes : au-delà, des octets ajoutés.
    pub fin_des_donnees: u64,
}

impl Elf {
    /// Le point d'entrée est-il dans un segment chargé et exécutable ? (Un objet sans point d'entrée l'est.)
    pub(crate) fn point_entree_executable(&self) -> bool {
        self.point_entree == 0
            || self.segments.iter().any(|s| {
                s.type_ == PT_LOAD
                    && s.executable()
                    && self
                        .point_entree
                        .checked_sub(s.adresse)
                        .is_some_and(|d| d < s.taille_memoire.max(s.taille_fichier))
            })
    }
}

/// Les en-têtes de l'ELF `octets`. `None` : pas un ELF, ou en-tête principal illisible.
pub(crate) fn lire(octets: &[u8]) -> Option<Elf> {
    if !octets.starts_with(b"\x7fELF") {
        return None;
    }
    let bits64 = match octets.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let gros_boutiste = match octets.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let o = Ordre { gros_boutiste };
    // Elf32_Ehdr / Elf64_Ehdr : seules les tailles des adresses changent.
    let (entree, phoff, shoff, apres) = if bits64 {
        (o.u64(octets, 24)?, o.u64(octets, 32)?, o.u64(octets, 40)?, 48)
    } else {
        (
            u64::from(o.u32(octets, 24)?),
            u64::from(o.u32(octets, 28)?),
            u64::from(o.u32(octets, 32)?),
            36,
        )
    };
    let type_ = o.u16(octets, 16)?;
    let machine = o.u16(octets, 18)?;
    // La suite de l'en-tête, après les adresses.
    let suite = octets.get(apres..)?;
    let ehsize = o.u16(suite, 4)?;
    let phentsize = usize::from(o.u16(suite, 6)?);
    let mut phnum = usize::from(o.u16(suite, 8)?);
    let shentsize = usize::from(o.u16(suite, 10)?);
    let mut shnum = usize::from(o.u16(suite, 12)?);
    let mut shstrndx = usize::from(o.u16(suite, 14)?);
    let taille_sh = if bits64 { 64 } else { 40 };
    // Les comptes étendus, dans la section 0 (elf(5)).
    let entete_zero = (shoff != 0 && shentsize >= taille_sh)
        .then(|| usize::try_from(shoff).ok())
        .flatten();
    let champ0 = |decalage32: usize, decalage64: usize| -> Option<u64> {
        let s = entete_zero?;
        if bits64 {
            o.u64(octets, s.checked_add(decalage64)?)
        } else {
            o.u32(octets, s.checked_add(decalage32)?).map(u64::from)
        }
    };
    if phnum == usize::from(PN_XNUM) {
        // sh_info de la section 0 (32 bits dans les deux formes).
        phnum = entete_zero
            .and_then(|s| o.u32(octets, s.checked_add(if bits64 { 44 } else { 28 })?))
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0);
    }
    if shnum == 0 && shoff != 0 {
        // sh_size de la section 0.
        shnum = champ0(20, 32).and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
    }
    if shstrndx == usize::from(SHN_XINDEX) {
        // sh_link de la section 0.
        shstrndx = entete_zero
            .and_then(|s| o.u32(octets, s.checked_add(if bits64 { 40 } else { 24 })?))
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(usize::MAX);
    }
    let mut fin_des_donnees = u64::from(ehsize).min(en_u64(octets.len()));
    // Les segments.
    let (segments, segments_illisibles) = lire_segments(
        octets,
        o,
        bits64,
        Table {
            debut: phoff,
            nombre: phnum,
            taille_entree: phentsize,
        },
        &mut fin_des_donnees,
    );
    let (interpreteur, pile_executable) = lire_programme(octets, &segments, &mut fin_des_donnees);
    // Les sections et leurs noms.
    let (sections, sections_illisibles) = lire_sections(
        octets,
        o,
        bits64,
        Table {
            debut: shoff,
            nombre: shnum,
            taille_entree: shentsize,
        },
        shstrndx,
        &mut fin_des_donnees,
    );
    Some(Elf {
        bits64,
        gros_boutiste,
        type_,
        machine,
        point_entree: entree,
        segments,
        sections,
        interpreteur,
        pile_executable,
        segments_illisibles,
        sections_illisibles,
        fin_des_donnees,
    })
}

/// Une table de l'en-tête (segments ou sections) : sa position, son nombre d'entrées et la taille d'une entrée.
#[derive(Clone, Copy)]
struct Table {
    debut: u64,
    nombre: usize,
    taille_entree: usize,
}

/// Les segments (table des programmes) et `true` si elle est illisible ; la fin des données s'étend à ce qui est lu.
fn lire_segments(
    octets: &[u8],
    o: Ordre,
    bits64: bool,
    table: Table,
    fin_des_donnees: &mut u64,
) -> (Vec<Segment>, bool) {
    let Table {
        debut: phoff,
        nombre: phnum,
        taille_entree: phentsize,
    } = table;
    let taille_entree_ph = if bits64 { 56 } else { 32 };
    let mut segments = Vec::new();
    let mut segments_illisibles = false;
    if phoff != 0 && phnum > 0 {
        if phentsize < taille_entree_ph || phnum > SEGMENTS_MAX {
            segments_illisibles = true;
        } else {
            for k in 0..phnum {
                let Some(p) = usize::try_from(phoff)
                    .ok()
                    .and_then(|d| d.checked_add(k.checked_mul(phentsize)?))
                else {
                    segments_illisibles = true;
                    break;
                };
                let segment = if bits64 {
                    (|| {
                        let e = octets.get(p..)?;
                        Some(Segment {
                            type_: o.u32(e, 0)?,
                            drapeaux: o.u32(e, 4)?,
                            position: o.u64(e, 8)?,
                            adresse: o.u64(e, 16)?,
                            taille_fichier: o.u64(e, 32)?,
                            taille_memoire: o.u64(e, 40)?,
                        })
                    })()
                } else {
                    (|| {
                        let e = octets.get(p..)?;
                        Some(Segment {
                            type_: o.u32(e, 0)?,
                            position: u64::from(o.u32(e, 4)?),
                            adresse: u64::from(o.u32(e, 8)?),
                            taille_fichier: u64::from(o.u32(e, 16)?),
                            taille_memoire: u64::from(o.u32(e, 20)?),
                            drapeaux: o.u32(e, 24)?,
                        })
                    })()
                };
                let Some(segment) = segment else {
                    segments_illisibles = true;
                    break;
                };
                segments.push(segment);
            }
            let fin_table = phoff.saturating_add(en_u64(phnum).saturating_mul(en_u64(phentsize)));
            *fin_des_donnees = (*fin_des_donnees).max(fin_table.min(en_u64(octets.len())));
        }
    }
    (segments, segments_illisibles)
}

/// L'interpréteur demandé (PT_INTERP) et la pile exécutable ou non (PT_GNU_STACK) ; la fin des données s'étend aux
/// segments contenus dans le fichier.
fn lire_programme(octets: &[u8], segments: &[Segment], fin_des_donnees: &mut u64) -> (Option<String>, Option<bool>) {
    let mut interpreteur = None;
    let mut pile_executable = None;
    for s in segments {
        let fin = s.position.saturating_add(s.taille_fichier);
        if s.taille_fichier > 0 && fin <= en_u64(octets.len()) {
            *fin_des_donnees = (*fin_des_donnees).max(fin);
        }
        match s.type_ {
            PT_INTERP if interpreteur.is_none() => {
                interpreteur = usize::try_from(s.position).ok().and_then(|p| {
                    let max = usize::try_from(s.taille_fichier)
                        .unwrap_or(usize::MAX)
                        .min(INTERPRETEUR_MAX);
                    chaine_c(octets, p, max)
                });
            }
            PT_GNU_STACK => pile_executable = Some(s.executable()),
            _ => {}
        }
    }
    (interpreteur, pile_executable)
}

/// Les sections, nommées par la table des noms `shstrndx`, et `true` si elles sont illisibles ; la fin des données
/// s'étend à ce qui est lu.
fn lire_sections(
    octets: &[u8],
    o: Ordre,
    bits64: bool,
    table: Table,
    shstrndx: usize,
    fin_des_donnees: &mut u64,
) -> (Vec<SectionElf>, bool) {
    let Table {
        debut: shoff,
        nombre: shnum,
        taille_entree: shentsize,
    } = table;
    let taille_sh = if bits64 { 64 } else { 40 };
    let mut sections_illisibles = false;
    let mut sections = Vec::new();
    if shoff != 0 && shnum > 0 {
        if shentsize < taille_sh || shnum > SECTIONS_MAX {
            sections_illisibles = true;
        } else {
            let mut brutes = Vec::new();
            for k in 0..shnum {
                let Some(p) = usize::try_from(shoff)
                    .ok()
                    .and_then(|d| d.checked_add(k.checked_mul(shentsize)?))
                else {
                    sections_illisibles = true;
                    break;
                };
                let s = if bits64 {
                    (|| {
                        let e = octets.get(p..)?;
                        Some((o.u32(e, 0)?, o.u32(e, 4)?, o.u64(e, 8)?, o.u64(e, 24)?, o.u64(e, 32)?))
                    })()
                } else {
                    (|| {
                        let e = octets.get(p..)?;
                        Some((
                            o.u32(e, 0)?,
                            o.u32(e, 4)?,
                            u64::from(o.u32(e, 8)?),
                            u64::from(o.u32(e, 16)?),
                            u64::from(o.u32(e, 20)?),
                        ))
                    })()
                };
                let Some(s) = s else {
                    sections_illisibles = true;
                    break;
                };
                brutes.push(s);
            }
            let fin_table = shoff.saturating_add(en_u64(shnum).saturating_mul(en_u64(shentsize)));
            if fin_table <= en_u64(octets.len()) {
                *fin_des_donnees = (*fin_des_donnees).max(fin_table);
            }
            let noms = brutes.get(shstrndx).copied();
            if noms.is_none() && !brutes.is_empty() {
                sections_illisibles = true;
            }
            for &(nom, type_, drapeaux, position, taille) in &brutes {
                let nom = noms
                    .and_then(|(_, _, _, debut, taille_noms)| {
                        let d = usize::try_from(debut).ok()?;
                        let n = usize::try_from(nom).ok()?;
                        if u64::from(nom) >= taille_noms {
                            return None;
                        }
                        chaine_c(octets, d.checked_add(n)?, NOM_MAX)
                    })
                    .unwrap_or_default();
                let fin = position.saturating_add(taille);
                if type_ != SHT_NOBITS && taille > 0 {
                    if fin <= en_u64(octets.len()) {
                        *fin_des_donnees = (*fin_des_donnees).max(fin);
                    } else {
                        sections_illisibles = true;
                    }
                }
                sections.push(SectionElf {
                    nom,
                    type_,
                    drapeaux,
                    position,
                    taille,
                });
            }
        }
    }
    (sections, sections_illisibles)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
pub(crate) mod essais {
    //! Un ELF minimal fabriqué ici : aucun binaire tiers dans le dépôt.

    /// Un ELF 64 bits petit-boutiste : un segment PT_INTERP, un PT_LOAD (droits `droits`), un PT_GNU_STACK (pile
    /// exécutable ou non), trois sections (nulle, .text, .shstrtab), puis `ajout` après la fin.
    pub(crate) fn elf64(droits: u32, pile_x: bool, entree: u64, ajout: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        v[6] = 1;
        let mot16 = |v: &mut Vec<u8>, a: usize, x: u16| v[a..a + 2].copy_from_slice(&x.to_le_bytes());
        let mot32 = |v: &mut Vec<u8>, a: usize, x: u32| v[a..a + 4].copy_from_slice(&x.to_le_bytes());
        let mot64 = |v: &mut Vec<u8>, a: usize, x: u64| v[a..a + 8].copy_from_slice(&x.to_le_bytes());
        mot16(&mut v, 16, 2);
        mot16(&mut v, 18, 62);
        mot32(&mut v, 20, 1);
        mot64(&mut v, 24, entree);
        mot64(&mut v, 32, 0x40);
        mot64(&mut v, 40, 0x140);
        mot16(&mut v, 52, 64);
        mot16(&mut v, 54, 56);
        mot16(&mut v, 56, 3);
        mot16(&mut v, 58, 64);
        mot16(&mut v, 60, 3);
        mot16(&mut v, 62, 2);
        // PT_INTERP : la chaîne à 0x100.
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        v[0x100..0x100 + interp.len()].copy_from_slice(interp);
        let p = 0x40;
        mot32(&mut v, p, 3);
        mot32(&mut v, p + 4, 4);
        mot64(&mut v, p + 8, 0x100);
        mot64(&mut v, p + 16, 0x400_100);
        mot64(&mut v, p + 32, interp.len() as u64);
        mot64(&mut v, p + 40, interp.len() as u64);
        // PT_LOAD : tout le fichier, à 0x400000.
        let p = 0x40 + 56;
        mot32(&mut v, p, 1);
        mot32(&mut v, p + 4, droits);
        mot64(&mut v, p + 8, 0);
        mot64(&mut v, p + 16, 0x40_0000);
        mot64(&mut v, p + 32, 0x200);
        mot64(&mut v, p + 40, 0x200);
        // PT_GNU_STACK.
        let p = 0x40 + 112;
        mot32(&mut v, p, super::PT_GNU_STACK);
        mot32(&mut v, p + 4, if pile_x { 7 } else { 6 });
        // Sections à 0x140 : nulle, .text (0x180, 0x20 octets), .shstrtab (noms à 0x120).
        let noms = b"\0.text\0.shstrtab\0";
        v[0x120..0x120 + noms.len()].copy_from_slice(noms);
        let s = 0x140 + 64;
        mot32(&mut v, s, 1);
        mot32(&mut v, s + 4, 1);
        mot64(&mut v, s + 8, 6);
        mot64(&mut v, s + 24, 0x180);
        mot64(&mut v, s + 32, 0x20);
        let s = 0x140 + 128;
        mot32(&mut v, s, 7);
        mot32(&mut v, s + 4, 3);
        mot64(&mut v, s + 24, 0x120);
        mot64(&mut v, s + 32, noms.len() as u64);
        // La table des sections finit à 0x140 + 3 × 64 = 0x200 : le fichier aussi, avant l'ajout.
        v.extend_from_slice(ajout);
        v
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::essais::elf64;
    use super::*;

    #[test]
    fn segments_sections_interpreteur() {
        let elf = lire(&elf64(5, false, 0x40_0180, b"")).unwrap();
        assert!(elf.bits64 && !elf.gros_boutiste && elf.type_ == 2 && elf.machine == 62);
        assert_eq!(elf.interpreteur.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
        assert_eq!(elf.pile_executable, Some(false));
        assert_eq!(elf.segments.len(), 3);
        let noms: Vec<&str> = elf.sections.iter().map(|s| s.nom.as_str()).collect();
        assert_eq!(noms, ["", ".text", ".shstrtab"]);
        assert!(!elf.sections_illisibles && !elf.segments_illisibles);
        assert_eq!(elf.fin_des_donnees, 0x200);
        assert!(elf.point_entree_executable());
        assert!(!elf.segments.iter().any(|s| s.ecrivable() && s.executable()));
        // Écrivable et exécutable, pile exécutable, point d'entrée hors segment, octets ajoutés.
        let elf = lire(&elf64(7, true, 0x90_0000, b"ajoute")).unwrap();
        assert!(elf.segments.iter().any(|s| s.ecrivable() && s.executable()));
        assert_eq!(elf.pile_executable, Some(true));
        assert!(!elf.point_entree_executable());
        assert_eq!(elf.fin_des_donnees, 0x200);
    }

    #[test]
    fn formes_refusees_ou_abimees() {
        assert!(lire(b"\x7fELF").is_none());
        assert!(lire(b"MZ").is_none());
        let mut v = elf64(5, false, 0, b"");
        v[4] = 3;
        assert!(lire(&v).is_none());
        // Table des sections hors du fichier : les segments restent lus.
        let mut v = elf64(5, false, 0, b"");
        v[40..48].copy_from_slice(&0xFFFF_FFFF_FFFFu64.to_le_bytes());
        let elf = lire(&v).unwrap();
        assert!(elf.sections_illisibles && elf.sections.is_empty() && elf.segments.len() == 3);
        // Index des noms hors table.
        let mut v = elf64(5, false, 0, b"");
        v[62] = 9;
        assert!(lire(&v).unwrap().sections_illisibles);
        // Trop de segments annoncés.
        let mut v = elf64(5, false, 0, b"");
        v[56..58].copy_from_slice(&0xfff0u16.to_le_bytes());
        assert!(lire(&v).unwrap().segments_illisibles);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(i in 0usize..0x260, x in proptest::num::u8::ANY, j in 0usize..0x260, y in proptest::num::u8::ANY) {
            let mut v = elf64(5, false, 0x40_0180, b"zz");
            let n = v.len();
            v[i % n] = x;
            v[j % n] = y;
            if let Some(elf) = lire(&v) {
                proptest::prop_assert!(elf.fin_des_donnees <= v.len() as u64);
                proptest::prop_assert!(elf.segments.len() <= SEGMENTS_MAX);
            }
        }
    }
}
