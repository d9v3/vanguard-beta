//! Les en-têtes d'un exécutable Mach-O (macOS), d'après les en-têtes d'Apple (mach-o/loader.h de xnu, mach-o/fat.h
//! de cctools, sur github.com/apple-oss-distributions) : fichier universel (« fat », toujours gros-boutiste,
//! fat_arch de 20 octets ou fat_arch_64 de 32), en-tête mach_header(_64), commandes de chargement : segments
//! (LC_SEGMENT, LC_SEGMENT_64, droits initprot/maxprot), éditeur de liens (LC_LOAD_DYLINKER), bibliothèques
//! (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB), point d'entrée (LC_MAIN), signature de code
//! (LC_CODE_SIGNATURE, présence seulement) et chiffrement (LC_ENCRYPTION_INFO(_64), cryptid non nul : le texte est
//! chiffré, illisible ici).
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

use super::lecture::{Ordre, chaine_c};

pub(crate) const MH_MAGIC: u32 = 0xfeed_face;
pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_MAGIC_64: u32 = 0xcafe_babf;
const LC_SEGMENT: u32 = 0x1;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_MAIN: u32 = 0x8000_0028;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub(crate) const VM_PROT_WRITE: u32 = 0x2;
pub(crate) const VM_PROT_EXECUTE: u32 = 0x4;
/// Un fichier universel réel a deux ou trois architectures ; une classe Java commence aussi par 0xCAFEBABE, suivie
/// de ses numéros de version (mineure, puis majeure : 45 et plus) : en deçà de 45, c'est un fichier universel.
pub(crate) const TRANCHES_MAX: u32 = 44;
const COMMANDES_MAX: u32 = 4096;
const NOM_MAX: usize = 1024;
const BIBLIOTHEQUES_MAX: usize = 1024;

/// Une architecture d'un fichier universel : sa place dans le fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tranche {
    pub cpu: u32,
    pub position: u64,
    pub taille: u64,
}

/// Un fichier universel : ses architectures, et si l'une d'elles n'est pas dans le fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Universel {
    pub tranches: Vec<Tranche>,
    pub tranches_hors_fichier: usize,
    pub fin_des_donnees: u64,
}

/// Le fichier universel `octets`. `None` : pas un fichier universel (ni l'une ni l'autre des deux formes, ou un
/// nombre d'architectures qui n'en est pas un).
pub(crate) fn universel(octets: &[u8]) -> Option<Universel> {
    let o = Ordre { gros_boutiste: true };
    let magie = o.u32(octets, 0)?;
    let n = o.u32(octets, 4)?;
    if !matches!(magie, FAT_MAGIC | FAT_MAGIC_64) || n == 0 || n > TRANCHES_MAX {
        return None;
    }
    let (taille_entree, bits64) = if magie == FAT_MAGIC_64 { (32, true) } else { (20, false) };
    let mut u = Universel {
        tranches: Vec::new(),
        tranches_hors_fichier: 0,
        fin_des_donnees: 8 + u64::from(n) * taille_entree as u64,
    };
    for k in 0..n as usize {
        let p = 8 + k * taille_entree;
        let cpu = o.u32(octets, p)?;
        let (position, taille) = if bits64 {
            (o.u64(octets, p + 8)?, o.u64(octets, p + 16)?)
        } else {
            (u64::from(o.u32(octets, p + 8)?), u64::from(o.u32(octets, p + 12)?))
        };
        match position.checked_add(taille) {
            Some(fin) if fin <= octets.len() as u64 && taille > 0 => {
                u.fin_des_donnees = u.fin_des_donnees.max(fin);
                u.tranches.push(Tranche { cpu, position, taille });
            }
            _ => u.tranches_hors_fichier += 1,
        }
    }
    Some(u)
}

/// Un segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SegmentMachO {
    pub nom: String,
    pub adresse: u64,
    pub taille_memoire: u64,
    pub position: u64,
    pub taille_fichier: u64,
    pub maxprot: u32,
    pub initprot: u32,
}

impl SegmentMachO {
    pub(crate) fn ecrivable_executable(&self) -> bool {
        let w_x = VM_PROT_WRITE | VM_PROT_EXECUTE;
        self.initprot & w_x == w_x
    }
}

/// Ce que disent l'en-tête et les commandes de chargement.
#[allow(clippy::struct_excessive_bools)] // des drapeaux lus, chacun pour lui-même
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachO {
    pub bits64: bool,
    pub gros_boutiste: bool,
    pub cpu: u32,
    /// filetype : 2 exécutable, 6 bibliothèque, 8 module (bundle)…
    pub type_fichier: u32,
    pub drapeaux: u32,
    pub segments: Vec<SegmentMachO>,
    pub editeur_de_liens: Option<String>,
    pub bibliotheques: Vec<String>,
    /// LC_MAIN : position (dans le fichier, depuis __TEXT) du point d'entrée.
    pub point_entree: Option<u64>,
    pub signature: bool,
    /// LC_ENCRYPTION_INFO avec cryptid non nul : (position, taille) de la partie chiffrée.
    pub chiffre: Option<(u32, u32)>,
    /// Les commandes ne se lisent pas toutes (taille fausse, hors de leur place).
    pub commandes_illisibles: bool,
    pub fin_des_donnees: u64,
}

/// Le Mach-O « mince » `octets` (une seule architecture). `None` : pas un Mach-O.
pub(crate) fn lire(octets: &[u8]) -> Option<MachO> {
    let premier = Ordre { gros_boutiste: false }.u32(octets, 0)?;
    let (bits64, gros_boutiste) = match premier {
        MH_MAGIC => (false, false),
        MH_MAGIC_64 => (true, false),
        _ if premier.swap_bytes() == MH_MAGIC => (false, true),
        _ if premier.swap_bytes() == MH_MAGIC_64 => (true, true),
        _ => return None,
    };
    let o = Ordre { gros_boutiste };
    let cpu = o.u32(octets, 4)?;
    let type_fichier = o.u32(octets, 12)?;
    let ncmds = o.u32(octets, 16)?;
    let sizeofcmds = o.u32(octets, 20)?;
    let drapeaux = o.u32(octets, 24)?;
    let debut = if bits64 { 32usize } else { 28 };
    let mut m = MachO {
        bits64,
        gros_boutiste,
        cpu,
        type_fichier,
        drapeaux,
        segments: Vec::new(),
        editeur_de_liens: None,
        bibliotheques: Vec::new(),
        point_entree: None,
        signature: false,
        chiffre: None,
        commandes_illisibles: false,
        fin_des_donnees: 0,
    };
    let fin_commandes = debut as u64 + u64::from(sizeofcmds);
    if fin_commandes > octets.len() as u64 || ncmds > COMMANDES_MAX {
        m.commandes_illisibles = true;
        m.fin_des_donnees = (debut as u64).min(octets.len() as u64);
        return Some(m);
    }
    m.fin_des_donnees = fin_commandes;
    let Ok(fin_commandes) = usize::try_from(fin_commandes) else {
        m.commandes_illisibles = true;
        return Some(m);
    };
    let mut p = debut;
    for _ in 0..ncmds {
        let (Some(cmd), Some(taille)) = (o.u32(octets, p), o.u32(octets, p + 4)) else {
            m.commandes_illisibles = true;
            break;
        };
        let taille = taille as usize;
        // cmdsize : au moins l'en-tête de la commande, multiple de 4, dans la place annoncée (loader.h).
        if taille < 8 || !taille.is_multiple_of(4) || p + taille > fin_commandes {
            m.commandes_illisibles = true;
            break;
        }
        let Some(commande) = octets.get(p..p + taille) else {
            m.commandes_illisibles = true;
            break;
        };
        commande_de_chargement(o, octets, cmd, commande, &mut m);
        p += taille;
    }
    Some(m)
}

/// Une commande de chargement, lue dans ses propres octets (`commande`, sa taille annoncée).
fn commande_de_chargement(o: Ordre, octets: &[u8], cmd: u32, commande: &[u8], m: &mut MachO) {
    let taille_fichier = octets.len() as u64;
    // Une chaîne lc_str : sa position depuis le début de la commande, dans la commande.
    let lc_str = |a: usize| -> Option<String> {
        let decalage = o.u32(commande, a)? as usize;
        let max = commande.len().checked_sub(decalage)?.min(NOM_MAX);
        chaine_c(commande, decalage, max)
    };
    match cmd {
        LC_SEGMENT | LC_SEGMENT_64 => {
            let s = if cmd == LC_SEGMENT_64 {
                (|| {
                    Some(SegmentMachO {
                        nom: nom_segment(commande.get(8..24)?),
                        adresse: o.u64(commande, 24)?,
                        taille_memoire: o.u64(commande, 32)?,
                        position: o.u64(commande, 40)?,
                        taille_fichier: o.u64(commande, 48)?,
                        maxprot: o.u32(commande, 56)?,
                        initprot: o.u32(commande, 60)?,
                    })
                })()
            } else {
                (|| {
                    Some(SegmentMachO {
                        nom: nom_segment(commande.get(8..24)?),
                        adresse: u64::from(o.u32(commande, 24)?),
                        taille_memoire: u64::from(o.u32(commande, 28)?),
                        position: u64::from(o.u32(commande, 32)?),
                        taille_fichier: u64::from(o.u32(commande, 36)?),
                        maxprot: o.u32(commande, 40)?,
                        initprot: o.u32(commande, 44)?,
                    })
                })()
            };
            match s {
                Some(s) => {
                    let fin = s.position.saturating_add(s.taille_fichier);
                    if fin <= taille_fichier {
                        m.fin_des_donnees = m.fin_des_donnees.max(fin);
                    } else {
                        m.commandes_illisibles = true;
                    }
                    m.segments.push(s);
                }
                None => m.commandes_illisibles = true,
            }
        }
        LC_LOAD_DYLINKER => match lc_str(8) {
            Some(nom) => m.editeur_de_liens = Some(nom),
            None => m.commandes_illisibles = true,
        },
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => match lc_str(8) {
            Some(nom) if m.bibliotheques.len() < BIBLIOTHEQUES_MAX => m.bibliotheques.push(nom),
            Some(_) => {}
            None => m.commandes_illisibles = true,
        },
        LC_MAIN => m.point_entree = o.u64(commande, 8),
        LC_CODE_SIGNATURE => {
            m.signature = true;
            if let (Some(position), Some(taille)) = (o.u32(commande, 8), o.u32(commande, 12)) {
                let fin = u64::from(position) + u64::from(taille);
                if fin <= taille_fichier {
                    m.fin_des_donnees = m.fin_des_donnees.max(fin);
                }
            }
        }
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            if let (Some(position), Some(taille), Some(id)) =
                (o.u32(commande, 8), o.u32(commande, 12), o.u32(commande, 16))
                && id != 0
            {
                m.chiffre = Some((position, taille));
            }
        }
        _ => {}
    }
}

fn nom_segment(nom: &[u8]) -> String {
    // Jusqu'au premier nul (le champ entier sans nul).
    String::from_utf8_lossy(nom.split(|&o| o == 0).next().unwrap_or(nom)).into_owned()
}

#[cfg(test)]
pub(crate) mod essais {
    //! Des Mach-O minimaux fabriqués ici.

    /// Un Mach-O 64 bits petit-boutiste : un segment __TEXT (droits `initprot`), LC_LOAD_DYLINKER, une
    /// bibliothèque, LC_MAIN, et éventuellement LC_ENCRYPTION_INFO_64 (cryptid 1) ; 0x400 octets.
    pub(crate) fn macho64(initprot: u32, chiffre: bool) -> Vec<u8> {
        let mut commandes: Vec<u8> = Vec::new();
        let mut n = 0u32;
        let mut ajouter = |c: &mut Vec<u8>, corps: Vec<u8>| {
            c.extend(corps);
            n += 1;
        };
        let mut seg = Vec::new();
        seg.extend(0x19u32.to_le_bytes());
        seg.extend(72u32.to_le_bytes());
        let mut nom = [0u8; 16];
        nom[..6].copy_from_slice(b"__TEXT");
        seg.extend(nom);
        for v in [0x1_0000_0000u64, 0x400, 0, 0x400] {
            seg.extend(v.to_le_bytes());
        }
        seg.extend(7u32.to_le_bytes());
        seg.extend(initprot.to_le_bytes());
        seg.extend([0u8; 8]);
        ajouter(&mut commandes, seg);
        let mut dyld = Vec::new();
        dyld.extend(0xeu32.to_le_bytes());
        dyld.extend(32u32.to_le_bytes());
        dyld.extend(12u32.to_le_bytes());
        let mut chemin = b"/usr/lib/dyld".to_vec();
        chemin.resize(20, 0);
        dyld.extend(chemin);
        ajouter(&mut commandes, dyld);
        let mut lib = Vec::new();
        lib.extend(0xcu32.to_le_bytes());
        lib.extend(56u32.to_le_bytes());
        lib.extend(24u32.to_le_bytes());
        lib.extend([0u8; 12]);
        let mut chemin = b"/usr/lib/libSystem.B.dylib".to_vec();
        chemin.resize(32, 0);
        lib.extend(chemin);
        ajouter(&mut commandes, lib);
        let mut main = Vec::new();
        main.extend(0x8000_0028u32.to_le_bytes());
        main.extend(24u32.to_le_bytes());
        main.extend(0x300u64.to_le_bytes());
        main.extend(0u64.to_le_bytes());
        ajouter(&mut commandes, main);
        if chiffre {
            let mut c = Vec::new();
            c.extend(0x2cu32.to_le_bytes());
            c.extend(24u32.to_le_bytes());
            c.extend(0x200u32.to_le_bytes());
            c.extend(0x100u32.to_le_bytes());
            c.extend(1u32.to_le_bytes());
            c.extend(0u32.to_le_bytes());
            ajouter(&mut commandes, c);
        }
        let mut v = Vec::new();
        v.extend(super::MH_MAGIC_64.to_le_bytes());
        v.extend(0x0100_0007u32.to_le_bytes());
        v.extend(3u32.to_le_bytes());
        v.extend(2u32.to_le_bytes());
        v.extend(n.to_le_bytes());
        v.extend(u32::try_from(commandes.len()).unwrap().to_le_bytes());
        v.extend(0x0020_0085u32.to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend(commandes);
        v.resize(0x400, 0);
        v
    }

    /// Un fichier universel (fat_arch, gros-boutiste) qui contient `tranches`, alignées sur 0x1000.
    pub(crate) fn universel(tranches: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(super::FAT_MAGIC.to_be_bytes());
        v.extend(u32::try_from(tranches.len()).unwrap().to_be_bytes());
        let mut position = 0x1000u32;
        for t in tranches {
            v.extend(0x0100_0007u32.to_be_bytes());
            v.extend(3u32.to_be_bytes());
            v.extend(position.to_be_bytes());
            v.extend(u32::try_from(t.len()).unwrap().to_be_bytes());
            v.extend(12u32.to_be_bytes());
            position += u32::try_from(t.len()).unwrap().next_multiple_of(0x1000);
        }
        for t in tranches {
            v.resize(v.len().next_multiple_of(0x1000), 0);
            v.extend(t);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::essais::{macho64, universel as fat};
    use super::*;

    #[test]
    fn commandes_lues() {
        let m = lire(&macho64(5, false)).unwrap();
        assert!(m.bits64 && !m.gros_boutiste && m.type_fichier == 2);
        assert_eq!(m.segments.len(), 1);
        assert_eq!(m.segments[0].nom, "__TEXT");
        assert!(!m.segments[0].ecrivable_executable());
        assert_eq!(m.editeur_de_liens.as_deref(), Some("/usr/lib/dyld"));
        assert_eq!(m.bibliotheques, ["/usr/lib/libSystem.B.dylib"]);
        assert_eq!(m.point_entree, Some(0x300));
        assert!(!m.signature && m.chiffre.is_none() && !m.commandes_illisibles);
        assert_eq!(m.fin_des_donnees, 0x400);
        let m = lire(&macho64(7, true)).unwrap();
        assert!(m.segments[0].ecrivable_executable());
        assert_eq!(m.chiffre, Some((0x200, 0x100)));
    }

    #[test]
    fn universel_et_formes_refusees() {
        let u = universel(&fat(&[macho64(5, false), macho64(5, true)])).unwrap();
        assert_eq!(u.tranches.len(), 2);
        assert_eq!(u.tranches[1].position, 0x2000);
        assert_eq!(u.tranches_hors_fichier, 0);
        // Une classe Java : 0xCAFEBABE puis ses versions (mineure 0, majeure 65).
        assert!(universel(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65]).is_none());
        // Une tranche annoncée hors du fichier.
        let mut v = fat(&[macho64(5, false)]);
        v[16..20].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
        assert_eq!(universel(&v).unwrap().tranches_hors_fichier, 1);
        // Commandes plus grandes que le fichier, commande de taille nulle.
        let mut v = macho64(5, false);
        v[20..24].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        assert!(lire(&v).unwrap().commandes_illisibles);
        let mut v = macho64(5, false);
        v[36..40].copy_from_slice(&0u32.to_le_bytes());
        assert!(lire(&v).unwrap().commandes_illisibles);
        assert!(lire(b"\xcf\xfa\xed").is_none());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(i in 0usize..0x400, x in proptest::num::u8::ANY, j in 0usize..0x400, y in proptest::num::u8::ANY) {
            let mut v = macho64(5, true);
            v[i] = x;
            v[j] = y;
            if let Some(m) = lire(&v) {
                proptest::prop_assert!(m.fin_des_donnees <= v.len() as u64);
            }
            let mut f = fat(&[macho64(5, false)]);
            let n = f.len();
            f[i % 64 % n] = x;
            let _ = universel(&f);
        }
    }
}
