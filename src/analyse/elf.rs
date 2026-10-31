//! Les en-têtes d'un exécutable ELF (Linux, BSD…), d'après elf(5) et la spécification System V (gABI) : en-tête,
//! segments (table des programmes, ce que lit le chargeur), sections (table des sections, ce que lisent les outils),
//! interpréteur (PT_INTERP), pile exécutable (PT_GNU_STACK), protections de l'éditeur de liens (PT_GNU_RELRO, la
//! section dynamique PT_DYNAMIC et ses entrées DT_FLAGS, DT_FLAGS_1, DT_BIND_NOW, la propriété x86 de CET dans
//! PT_GNU_PROPERTY), et la fin des données décrites, au-delà de laquelle des octets ajoutés (overlay) sont à analyser
//! à part. 32 et 64 bits, petit et gros-boutiste ; les comptes étendus
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
pub(crate) const PT_DYNAMIC: u32 = 2;
pub(crate) const PT_INTERP: u32 = 3;
pub(crate) const PT_GNU_STACK: u32 = 0x6474_e551;
pub(crate) const PT_GNU_RELRO: u32 = 0x6474_e552;
pub(crate) const PT_GNU_PROPERTY: u32 = 0x6474_e553;
/// e_type d'un objet partagé, la forme d'un exécutable à position indépendante (PIE).
pub(crate) const ET_DYN: u16 = 3;
/// e_machine de x86-64, la seule architecture Linux livrée.
pub(crate) const EM_X86_64: u16 = 62;
/// Les entrées de la section dynamique lues ici (elf(5)).
const DT_NULL: u64 = 0;
const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// DT_FLAGS : DF_BIND_NOW ; DT_FLAGS_1 : DF_1_NOW et DF_1_PIE (ce que l'éditeur de liens écrit pour `-pie`).
pub(crate) const DF_BIND_NOW: u64 = 0x8;
pub(crate) const DF_1_NOW: u64 = 0x1;
pub(crate) const DF_1_PIE: u64 = 0x0800_0000;
/// La note des propriétés GNU (NT_GNU_PROPERTY_TYPE_0) et sa propriété x86 des protections du flot (CET) : IBT, SHSTK.
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
pub(crate) const CET_IBT: u32 = 0x1;
pub(crate) const CET_SHSTK: u32 = 0x2;
/// Entrées lues dans la section dynamique : un vrai programme en a quelques dizaines.
const ENTREES_DYNAMIQUES_MAX: usize = 4096;
/// Les notes de propriétés : quelques dizaines d'octets dans un vrai programme.
const PROPRIETES_MAX: usize = 4096;
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
    /// PT_GNU_RELRO : une plage que le chargeur remet en lecture seule après la liaison.
    pub relro: bool,
    /// La section dynamique (PT_DYNAMIC), `None` sans ce segment ou quand elle ne se lit pas.
    pub dynamique: Option<Dynamique>,
    /// La section dynamique est là mais ne se lit pas : deux segments PT_DYNAMIC, hors du fichier, sans DT_NULL
    /// avant sa fin, trop longue.
    pub dynamique_illisible: bool,
    /// Les protections x86 du flot (CET) annoncées par PT_GNU_PROPERTY : CET_IBT, CET_SHSTK. `None` sans la note.
    pub cet: Option<u32>,
    /// La table des segments ne se lit pas en entier (hors du fichier, trop grande).
    pub segments_illisibles: bool,
    /// La table des sections ne se lit pas en entier, ou ses noms non plus : un programme peut l'abîmer exprès
    /// (le chargeur ne la lit pas) pour gêner les outils.
    pub sections_illisibles: bool,
    /// La fin de ce que décrivent les en-têtes : au-delà, des octets ajoutés.
    pub fin_des_donnees: u64,
}

/// Ce que dit la section dynamique de la liaison : les drapeaux, chacun `None` sans son entrée. Une entrée répétée :
/// la dernière vaut, comme chez le chargeur de glibc et celui de musl.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Dynamique {
    /// DT_FLAGS.
    pub drapeaux: Option<u64>,
    /// DT_FLAGS_1.
    pub drapeaux_1: Option<u64>,
    /// DT_BIND_NOW, l'ancienne forme de DF_BIND_NOW.
    pub bind_now: bool,
}

impl Dynamique {
    /// Liaison immédiate (BIND_NOW) : tous les symboles résolus au chargement, avant que RELRO ne rende la table des
    /// adresses (GOT) en lecture seule. L'une des trois formes suffit.
    pub(crate) fn liaison_immediate(&self) -> bool {
        self.bind_now
            || self.drapeaux.is_some_and(|d| d & DF_BIND_NOW != 0)
            || self.drapeaux_1.is_some_and(|d| d & DF_1_NOW != 0)
    }

    /// DF_1_PIE : l'éditeur de liens dit un exécutable à position indépendante, pas une bibliothèque.
    pub(crate) fn pie(&self) -> bool {
        self.drapeaux_1.is_some_and(|d| d & DF_1_PIE != 0)
    }
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

/// La plage en mémoire de `s` ([p_vaddr, p_vaddr + p_memsz), non vide) tient-elle dans celle d'un PT_LOAD ? Un
/// PT_GNU_RELRO hors de toute plage chargée ne protège rien : il n'y a rien à cette adresse.
pub(crate) fn en_memoire_dans_un_load(segments: &[Segment], s: &Segment) -> bool {
    let Some(fin) = s.adresse.checked_add(s.taille_memoire) else {
        return false;
    };
    s.taille_memoire > 0
        && segments.iter().any(|l| {
            l.type_ == PT_LOAD
                && l.adresse <= s.adresse
                && l.adresse.checked_add(l.taille_memoire).is_some_and(|f| fin <= f)
        })
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
    let relro = segments.iter().any(|s| s.type_ == PT_GNU_RELRO);
    let (dynamique, dynamique_illisible) = lire_dynamique(octets, o, bits64, &segments);
    let cet = lire_cet(octets, o, bits64, &segments);
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
        relro,
        dynamique,
        dynamique_illisible,
        cet,
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

/// Les octets d'un segment dans le fichier, s'ils y sont tous.
fn contenu<'a>(octets: &'a [u8], s: &Segment) -> Option<&'a [u8]> {
    let debut = usize::try_from(s.position).ok()?;
    let fin = debut.checked_add(usize::try_from(s.taille_fichier).ok()?)?;
    octets.get(debut..fin)
}

/// Le segment `s` est-il dans un même PT_LOAD dans le fichier et en mémoire, au même décalage ? Alors les octets lus
/// à p_offset sont ceux que le programme trouve à p_vaddr une fois chargé.
fn charge_tel_quel(segments: &[Segment], s: &Segment) -> bool {
    let (Some(fin_fichier), Some(fin_memoire)) = (
        s.position.checked_add(s.taille_fichier),
        s.adresse.checked_add(s.taille_memoire),
    ) else {
        return false;
    };
    segments.iter().any(|l| {
        l.type_ == PT_LOAD
            && s.position
                .checked_sub(l.position)
                .is_some_and(|d| s.adresse.checked_sub(l.adresse) == Some(d))
            && l.position
                .checked_add(l.taille_fichier)
                .is_some_and(|f| fin_fichier <= f)
            && l.adresse
                .checked_add(l.taille_memoire)
                .is_some_and(|f| fin_memoire <= f)
    })
}

/// La section dynamique (PT_DYNAMIC), lue jusqu'à DT_NULL dans les octets du segment, et `true` si elle est là mais
/// illisible. Plus d'un PT_DYNAMIC : illisible, on ne sait pas lequel le chargeur prend. Hors de tout PT_LOAD, ou
/// chargée à un autre décalage que celui du fichier : illisible aussi, car le démarrage lit la section à son adresse
/// (p_vaddr) et nous à sa position (p_offset) ; deux tables différentes feraient croire à des drapeaux absents.
fn lire_dynamique(octets: &[u8], o: Ordre, bits64: bool, segments: &[Segment]) -> (Option<Dynamique>, bool) {
    let mut trouves = segments.iter().filter(|s| s.type_ == PT_DYNAMIC);
    let Some(segment) = trouves.next() else {
        return (None, false);
    };
    if trouves.next().is_some() || !charge_tel_quel(segments, segment) {
        return (None, true);
    }
    let lue = (|| {
        let table = contenu(octets, segment)?;
        let taille_entree: usize = if bits64 { 16 } else { 8 };
        let mut dynamique = Dynamique::default();
        for k in 0..ENTREES_DYNAMIQUES_MAX {
            let e = table.get(k.checked_mul(taille_entree)?..)?;
            let (etiquette, valeur) = if bits64 {
                (o.u64(e, 0)?, o.u64(e, 8)?)
            } else {
                (u64::from(o.u32(e, 0)?), u64::from(o.u32(e, 4)?))
            };
            match etiquette {
                DT_NULL => return Some(dynamique),
                DT_BIND_NOW => dynamique.bind_now = true,
                DT_FLAGS => dynamique.drapeaux = Some(valeur),
                DT_FLAGS_1 => dynamique.drapeaux_1 = Some(valeur),
                _ => {}
            }
        }
        None
    })();
    let illisible = lue.is_none();
    (lue, illisible)
}

/// Arrondi de `n` au multiple de `pas` (une puissance de deux) suivant.
fn aligne(n: usize, pas: usize) -> Option<usize> {
    let masque = pas.checked_sub(1)?;
    Some(n.checked_add(masque)? & !masque)
}

/// Les protections x86 du flot (CET) annoncées par la note GNU de PT_GNU_PROPERTY : `None` sans elle ou illisible.
fn lire_cet(octets: &[u8], o: Ordre, bits64: bool, segments: &[Segment]) -> Option<u32> {
    let segment = segments.iter().find(|s| s.type_ == PT_GNU_PROPERTY)?;
    let notes = contenu(octets, segment)?;
    let notes = notes.get(..notes.len().min(PROPRIETES_MAX))?;
    // Une seule note : namesz, descsz, type, puis le nom « GNU\0 » et la description, alignée sur 8 en 64 bits.
    let pas = if bits64 { 8 } else { 4 };
    let taille_nom = usize::try_from(o.u32(notes, 0)?).ok()?;
    let taille_desc = usize::try_from(o.u32(notes, 4)?).ok()?;
    if o.u32(notes, 8)? != NT_GNU_PROPERTY_TYPE_0 || notes.get(12..16)? != b"GNU\0" || taille_nom != 4 {
        return None;
    }
    let debut = aligne(12usize.checked_add(taille_nom)?, pas)?;
    let desc = notes.get(debut..debut.checked_add(taille_desc)?)?;
    let mut i = 0usize;
    while i < desc.len() {
        let type_ = o.u32(desc, i)?;
        let taille = usize::try_from(o.u32(desc, i.checked_add(4)?)?).ok()?;
        let donnees = i.checked_add(8)?;
        if type_ == GNU_PROPERTY_X86_FEATURE_1_AND && taille >= 4 {
            return o.u32(desc, donnees);
        }
        i = aligne(donnees.checked_add(taille)?, pas)?;
    }
    None
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

    /// Les protections d'un exécutable durci, chacune retirable pour l'essai.
    #[allow(clippy::struct_excessive_bools)] // une protection par champ
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Durci {
        /// ET_DYN et DF_1_PIE ; sans : ET_EXEC, DF_1_PIE retiré.
        pub pie: bool,
        /// PT_GNU_RELRO.
        pub relro: bool,
        /// DF_BIND_NOW et DF_1_NOW.
        pub liaison_immediate: bool,
        /// PT_GNU_STACK sans PF_X ; sans : pile exécutable.
        pub pile_non_executable: bool,
        /// Sans PT_INTERP (statique) ; sans : un interpréteur demandé.
        pub statique: bool,
        /// La note PT_GNU_PROPERTY de CET (IBT et SHSTK), affichée seulement.
        pub cet: bool,
    }

    impl Durci {
        pub(crate) const COMPLET: Durci = Durci {
            pie: true,
            relro: true,
            liaison_immediate: true,
            pile_non_executable: true,
            statique: true,
            cet: false,
        };
    }

    /// La classe, l'ordre des octets et l'architecture d'un ELF fabriqué.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Forme {
        pub bits64: bool,
        pub gros_boutiste: bool,
        pub machine: u16,
    }

    impl Forme {
        /// Celle du programme livré : 64 bits, petit-boutiste, x86-64.
        pub(crate) const X86_64: Forme = Forme {
            bits64: true,
            gros_boutiste: false,
            machine: super::EM_X86_64,
        };
    }

    /// Un ELF 64 bits petit-boutiste comme celui de Vanguard (static-pie de musl) : PT_LOAD (lecture, exécution),
    /// PT_DYNAMIC (DT_FLAGS, DT_FLAGS_1, DT_NULL, à 0x180), PT_GNU_RELRO, PT_GNU_STACK, selon `d` PT_INTERP et
    /// PT_GNU_PROPERTY ; sans sections.
    pub(crate) fn elf64_durci(d: Durci) -> Vec<u8> {
        elf_durci(d, Forme::X86_64)
    }

    /// Comme `elf64_durci`, dans la forme `f` (32 ou 64 bits, petit- ou gros-boutiste, autre architecture) : les
    /// mêmes segments aux mêmes positions.
    pub(crate) fn elf_durci(d: Durci, f: Forme) -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = if f.bits64 { 2 } else { 1 };
        v[5] = if f.gros_boutiste { 2 } else { 1 };
        v[6] = 1;
        let be = f.gros_boutiste;
        let mot16 = |v: &mut Vec<u8>, a: usize, x: u16| {
            v[a..a + 2].copy_from_slice(&if be { x.to_be_bytes() } else { x.to_le_bytes() });
        };
        let mot32 = |v: &mut Vec<u8>, a: usize, x: u32| {
            v[a..a + 4].copy_from_slice(&if be { x.to_be_bytes() } else { x.to_le_bytes() });
        };
        let mot64 = |v: &mut Vec<u8>, a: usize, x: u64| {
            v[a..a + 8].copy_from_slice(&if be { x.to_be_bytes() } else { x.to_le_bytes() });
        };
        // Un mot de la taille d'une adresse : 8 octets en 64 bits, 4 en 32.
        let mot = |v: &mut Vec<u8>, a: usize, x: u64| {
            if f.bits64 {
                mot64(v, a, x);
            } else {
                mot32(v, a, u32::try_from(x).unwrap());
            }
        };
        mot16(&mut v, 16, if d.pie { super::ET_DYN } else { 2 });
        mot16(&mut v, 18, f.machine);
        mot32(&mut v, 20, 1);
        mot(&mut v, 24, 0x100);
        // e_phoff, puis e_ehsize, e_phentsize, e_phnum.
        let (phoff, apres, taille_ph) = if f.bits64 { (0x40, 52, 56) } else { (0x34, 40, 32) };
        mot(&mut v, if f.bits64 { 32 } else { 28 }, phoff as u64);
        mot16(&mut v, apres, if f.bits64 { 64 } else { 52 });
        mot16(&mut v, apres + 2, u16::try_from(taille_ph).unwrap());
        // (type, drapeaux, position, taille)
        let mut segments = vec![
            (super::PT_LOAD, 5u32, 0u64, 0x200u64),
            (super::PT_DYNAMIC, 6, 0x180, 0x30),
            (super::PT_GNU_STACK, if d.pile_non_executable { 6 } else { 7 }, 0, 0),
        ];
        if d.relro {
            segments.push((super::PT_GNU_RELRO, 4, 0x180, 0x30));
        }
        if !d.statique {
            let interp = b"/lib/ld-musl-x86_64.so.1\0";
            v[0x160..0x160 + interp.len()].copy_from_slice(interp);
            segments.push((super::PT_INTERP, 4, 0x160, interp.len() as u64));
        }
        if d.cet {
            // namesz 4, descsz 16, NT_GNU_PROPERTY_TYPE_0, « GNU », puis X86_FEATURE_1_AND = IBT | SHSTK.
            let n = 0x1C0;
            mot32(&mut v, n, 4);
            mot32(&mut v, n + 4, 16);
            mot32(&mut v, n + 8, 5);
            v[n + 12..n + 16].copy_from_slice(b"GNU\0");
            mot32(&mut v, n + 16, 0xc000_0002);
            mot32(&mut v, n + 20, 4);
            mot32(&mut v, n + 24, 3);
            segments.push((super::PT_GNU_PROPERTY, 4, 0x1C0, 0x20));
        }
        mot16(&mut v, apres + 4, u16::try_from(segments.len()).unwrap());
        for (i, (type_, drapeaux, position, taille)) in segments.into_iter().enumerate() {
            let p = phoff + taille_ph * i;
            mot32(&mut v, p, type_);
            if f.bits64 {
                mot32(&mut v, p + 4, drapeaux);
                mot64(&mut v, p + 8, position);
                mot64(&mut v, p + 16, position);
                mot64(&mut v, p + 32, taille);
                mot64(&mut v, p + 40, taille);
            } else {
                let (position, taille) = (u32::try_from(position).unwrap(), u32::try_from(taille).unwrap());
                mot32(&mut v, p + 4, position);
                mot32(&mut v, p + 8, position);
                mot32(&mut v, p + 16, taille);
                mot32(&mut v, p + 20, taille);
                mot32(&mut v, p + 24, drapeaux);
            }
        }
        // La section dynamique : DT_FLAGS, DT_FLAGS_1, DT_NULL (le reste, à zéro).
        let (flags, flags_1) = match (d.liaison_immediate, d.pie) {
            (true, true) => (super::DF_BIND_NOW, super::DF_1_NOW | super::DF_1_PIE),
            (true, false) => (super::DF_BIND_NOW, super::DF_1_NOW),
            (false, true) => (0, super::DF_1_PIE),
            (false, false) => (0, 0),
        };
        let pas = if f.bits64 { 8 } else { 4 };
        for (k, x) in [30, flags, 0x6fff_fffb, flags_1].into_iter().enumerate() {
            mot(&mut v, 0x180 + pas * k, x);
        }
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
    use super::essais::{Durci, elf64, elf64_durci};
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

    #[test]
    fn protections_de_l_editeur_de_liens() {
        // Celui de Vanguard : PIE, RELRO, BIND_NOW, pile non exécutable, sans interpréteur.
        let elf = lire(&elf64_durci(Durci::COMPLET)).unwrap();
        assert_eq!(elf.type_, ET_DYN);
        assert!(elf.relro && !elf.dynamique_illisible && elf.interpreteur.is_none());
        let d = elf.dynamique.unwrap();
        assert_eq!(d.drapeaux, Some(DF_BIND_NOW));
        assert_eq!(d.drapeaux_1, Some(DF_1_NOW | DF_1_PIE));
        assert!(d.pie() && d.liaison_immediate() && !d.bind_now);
        assert_eq!(elf.pile_executable, Some(false));
        assert_eq!(elf.cet, None);
        // Chacune retirée.
        let sans = |f: fn(&mut Durci)| {
            let mut d = Durci::COMPLET;
            f(&mut d);
            lire(&elf64_durci(d)).unwrap()
        };
        let elf = sans(|d| d.pie = false);
        assert!(elf.type_ == 2 && !elf.dynamique.unwrap().pie() && elf.dynamique.unwrap().liaison_immediate());
        assert!(!sans(|d| d.relro = false).relro);
        let elf = sans(|d| d.liaison_immediate = false);
        assert!(!elf.dynamique.unwrap().liaison_immediate() && elf.dynamique.unwrap().pie());
        assert_eq!(sans(|d| d.pile_non_executable = false).pile_executable, Some(true));
        assert_eq!(
            sans(|d| d.statique = false).interpreteur.as_deref(),
            Some("/lib/ld-musl-x86_64.so.1")
        );
        assert_eq!(sans(|d| d.cet = true).cet, Some(CET_IBT | CET_SHSTK));
        // Les deux autres formes de BIND_NOW : DT_BIND_NOW seul, DF_1_NOW seul.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x180..0x190].copy_from_slice(&[24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v[0x198..0x1A0].copy_from_slice(&DF_1_PIE.to_le_bytes());
        let d = lire(&v).unwrap().dynamique.unwrap();
        assert!(d.bind_now && d.liaison_immediate() && d.drapeaux.is_none());
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x188..0x190].fill(0);
        assert!(lire(&v).unwrap().dynamique.unwrap().liaison_immediate());
        // Une entrée répétée : la dernière vaut (DT_FLAGS_1 sans NOW après DT_FLAGS remis à rien).
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x180..0x188].copy_from_slice(&0x6fff_fffbu64.to_le_bytes());
        v[0x188..0x190].copy_from_slice(&(DF_1_NOW | DF_1_PIE).to_le_bytes());
        v[0x198..0x1A0].copy_from_slice(&DF_1_PIE.to_le_bytes());
        assert!(!lire(&v).unwrap().dynamique.unwrap().liaison_immediate());
    }

    #[test]
    fn segment_en_memoire_dans_un_load() {
        let seg = |type_, adresse, taille_memoire| Segment {
            type_,
            drapeaux: 4,
            position: 0,
            adresse,
            taille_fichier: 0,
            taille_memoire,
        };
        let loads = [seg(PT_LOAD, 0x1000, 0x2000), seg(PT_GNU_STACK, 0, u64::MAX)];
        assert!(en_memoire_dans_un_load(&loads, &seg(PT_GNU_RELRO, 0x1000, 0x2000)));
        assert!(en_memoire_dans_un_load(&loads, &seg(PT_GNU_RELRO, 0x2FFF, 1)));
        // Vide, débordant, avant, hors de tout PT_LOAD (le PT_GNU_STACK ne compte pas), adresse qui déborde.
        assert!(!en_memoire_dans_un_load(&loads, &seg(PT_GNU_RELRO, 0x1000, 0)));
        assert!(!en_memoire_dans_un_load(&loads, &seg(PT_GNU_RELRO, 0x2FFF, 2)));
        assert!(!en_memoire_dans_un_load(&loads, &seg(PT_GNU_RELRO, 0xFFF, 2)));
        assert!(!en_memoire_dans_un_load(&loads, &seg(PT_GNU_RELRO, 0x10_0000, 0x10)));
        assert!(!en_memoire_dans_un_load(&loads, &seg(PT_GNU_RELRO, u64::MAX, 2)));
    }

    #[test]
    fn section_dynamique_abimee() {
        let illisible = |v: &[u8]| {
            let elf = lire(v).unwrap();
            elf.dynamique_illisible && elf.dynamique.is_none()
        };
        // Sans DT_NULL avant la fin du segment.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x1A0..0x1B0].fill(0xAA);
        v[0x40 + 56 + 32..0x40 + 56 + 40].copy_from_slice(&0x28u64.to_le_bytes());
        assert!(illisible(&v));
        // Hors du fichier.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x40 + 56 + 8..0x40 + 56 + 16].copy_from_slice(&0x1F0u64.to_le_bytes());
        assert!(illisible(&v));
        // Chargée à un autre décalage que celui du fichier (p_vaddr 0x100, p_offset 0x180, PT_LOAD à 0 et 0) : ce que
        // lit le démarrage n'est pas ce qu'on lit.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x40 + 56 + 16..0x40 + 56 + 24].copy_from_slice(&0x100u64.to_le_bytes());
        assert!(illisible(&v));
        // Débordant du PT_LOAD en mémoire.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x40 + 32..0x40 + 40].copy_from_slice(&0x190u64.to_le_bytes());
        v[0x40 + 40..0x40 + 48].copy_from_slice(&0x190u64.to_le_bytes());
        assert!(illisible(&v));
        // Le même décalage, à une autre adresse (PT_LOAD et PT_DYNAMIC déplacés de 0x1000 ensemble) : lisible.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x40 + 16..0x40 + 24].copy_from_slice(&0x1000u64.to_le_bytes());
        v[0x40 + 56 + 16..0x40 + 56 + 24].copy_from_slice(&0x1180u64.to_le_bytes());
        let elf = lire(&v).unwrap();
        assert!(!elf.dynamique_illisible && elf.dynamique.is_some_and(|d| d.liaison_immediate()));
        // Deux PT_DYNAMIC : le PT_GNU_STACK devient le second.
        let mut v = elf64_durci(Durci::COMPLET);
        v[0x40 + 112..0x40 + 116].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        assert!(illisible(&v));
        // Sans PT_DYNAMIC du tout : rien à lire, rien d'illisible.
        let elf = lire(&elf64(5, false, 0x40_0180, b"")).unwrap();
        assert!(elf.dynamique.is_none() && !elf.dynamique_illisible && !elf.relro && elf.cet.is_none());
        // Une note de propriétés qui ment sur sa taille : pas de CET lu, sans planter.
        let mut d = Durci::COMPLET;
        d.cet = true;
        let mut v = elf64_durci(d);
        v[0x1C4..0x1C8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(lire(&v).unwrap().cet, None);
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

        #[test]
        fn durci_abime(i in 0usize..0x200, x in proptest::num::u8::ANY, j in 0usize..0x200, y in proptest::num::u8::ANY, cet in proptest::bool::ANY) {
            let mut d = Durci::COMPLET;
            d.cet = cet;
            let mut v = elf64_durci(d);
            v[i] = x;
            v[j] = y;
            if let Some(elf) = lire(&v) {
                proptest::prop_assert!(!(elf.dynamique.is_some() && elf.dynamique_illisible));
            }
        }
    }
}
