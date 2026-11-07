//! La lecture des événements de fanotify et de /proc/self/mountinfo : du code pur, borné, qui ne panique jamais, lu
//! aussi par le banc de fuzzing (fuzz/fuzz_targets/fanotify.rs). Ce que le noyau écrit dans le tampon d'un `read` du
//! groupe est découpé ici en événements (`struct fanotify_event_metadata`, puis ses enregistrements d'information,
//! dont le PIDFD) ; une version de métadonnées inconnue, une longueur qui sort du tampon ou un enregistrement mal
//! formé arrêtent la lecture : ce qui suit n'est pas cru (le garde ferme alors son groupe, ce qui laisse passer toutes
//! les demandes en attente). Aucun descripteur n'est ouvert ni fermé ici : ce module ne fait que lire des octets.
//!
//! Les montages : les systèmes de fichiers locaux à marquer, d'après la liste blanche des types (`local`) ; jamais
//! fuse, nfs, cifs, 9p, overlay ni squashfs (une demande de permission sur eux peut attendre un service qui, lui-même,
//! attend : interblocage).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// La version des métadonnées que ce lecteur connaît (FANOTIFY_METADATA_VERSION de linux/fanotify.h).
pub(crate) const VERSION: u8 = 3;
/// La taille de `struct fanotify_event_metadata` : event_len (u32), vers (u8), reserved (u8), metadata_len (u16),
/// mask (u64), fd (s32), pid (s32).
pub(crate) const TAILLE_METADONNEES: usize = 24;
/// L'en-tête d'un enregistrement d'information : info_type (u8), pad (u8), len (u16).
const TAILLE_EN_TETE_INFO: usize = 4;
/// Le type de l'enregistrement PIDFD (FAN_EVENT_INFO_TYPE_PIDFD) et sa taille : l'en-tête puis pidfd (s32).
const INFO_PIDFD: u8 = 4;
const TAILLE_INFO_PIDFD: usize = 8;
/// Au plus autant d'enregistrements d'information par événement : le noyau en écrit un ou deux.
const INFOS_MAX: usize = 16;
/// Au plus autant d'événements par tampon : un tampon de 64 Kio n'en tient pas plus.
pub(crate) const EVENEMENTS_MAX: usize = 4096;

/// Un événement lu : les nombres tels que le noyau les a écrits. `fd` et `pidfd` sont des descripteurs ouverts dans
/// le processus qui lit, à prendre en charge tout de suite (`fd` négatif : FAN_NOFD, la file a débordé).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Evenement {
    pub masque: u64,
    pub fd: i32,
    pub pid: i32,
    /// Le PIDFD du processus, s'il y en a un ; `None` : pas d'enregistrement (groupe sans FAN_REPORT_PIDFD), ou le
    /// noyau n'a pas pu l'ouvrir (FAN_NOPIDFD, FAN_EPIDFD : processus déjà parti).
    pub pidfd: Option<i32>,
}

/// Ce qui a arrêté la lecture d'un tampon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Defaut {
    /// La version des métadonnées n'est pas celle que ce lecteur connaît.
    Version(u8),
    /// Un événement coupé, plus court que ses métadonnées, ou qui sort du tampon.
    Longueur,
    /// Un enregistrement d'information mal formé (longueur, PIDFD en double ou de mauvaise taille).
    Enregistrement,
    /// Plus d'événements que `EVENEMENTS_MAX`.
    Trop,
}

/// Les événements lus d'un tampon, dans l'ordre, et ce qui a arrêté la lecture avant la fin s'il y a lieu : ceux lus
/// avant le défaut restent rendus (leurs descripteurs sont à prendre en charge et à répondre).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Lecture {
    pub evenements: Vec<Evenement>,
    pub defaut: Option<Defaut>,
}

fn u16_a(t: &[u8], i: usize) -> Option<u16> {
    let o: [u8; 2] = t.get(i..i.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_ne_bytes(o))
}

fn u32_a(t: &[u8], i: usize) -> Option<u32> {
    let o: [u8; 4] = t.get(i..i.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_ne_bytes(o))
}

fn i32_a(t: &[u8], i: usize) -> Option<i32> {
    let o: [u8; 4] = t.get(i..i.checked_add(4)?)?.try_into().ok()?;
    Some(i32::from_ne_bytes(o))
}

fn u64_a(t: &[u8], i: usize) -> Option<u64> {
    let o: [u8; 8] = t.get(i..i.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_ne_bytes(o))
}

/// Le PIDFD des enregistrements d'information d'un événement (`infos` : ce qui suit ses métadonnées).
fn pidfd_de(infos: &[u8]) -> Result<Option<i32>, Defaut> {
    let mut pidfd = None;
    let mut vu = false;
    let mut i = 0usize;
    let mut n = 0usize;
    while i < infos.len() {
        n = n.checked_add(1).ok_or(Defaut::Enregistrement)?;
        if n > INFOS_MAX {
            return Err(Defaut::Enregistrement);
        }
        let genre = *infos.get(i).ok_or(Defaut::Enregistrement)?;
        let longueur =
            usize::from(u16_a(infos, i.checked_add(2).ok_or(Defaut::Enregistrement)?).ok_or(Defaut::Enregistrement)?);
        let fin = i.checked_add(longueur).ok_or(Defaut::Enregistrement)?;
        if longueur < TAILLE_EN_TETE_INFO || fin > infos.len() {
            return Err(Defaut::Enregistrement);
        }
        if genre == INFO_PIDFD {
            if vu || longueur != TAILLE_INFO_PIDFD {
                return Err(Defaut::Enregistrement);
            }
            vu = true;
            let p = i32_a(infos, i.checked_add(TAILLE_EN_TETE_INFO).ok_or(Defaut::Enregistrement)?)
                .ok_or(Defaut::Enregistrement)?;
            pidfd = (p >= 0).then_some(p);
        }
        i = fin;
    }
    Ok(pidfd)
}

/// Découpe le tampon d'un `read` du groupe en événements.
pub(crate) fn evenements(tampon: &[u8]) -> Lecture {
    let mut l = Lecture::default();
    let mut i = 0usize;
    while i < tampon.len() {
        if l.evenements.len() >= EVENEMENTS_MAX {
            l.defaut = Some(Defaut::Trop);
            break;
        }
        match un(tampon, i) {
            Ok((e, fin)) => {
                l.evenements.push(e);
                i = fin;
            }
            Err(d) => {
                l.defaut = Some(d);
                break;
            }
        }
    }
    l
}

/// L'événement qui commence à `i`, et où commence le suivant.
fn un(t: &[u8], i: usize) -> Result<(Evenement, usize), Defaut> {
    let longueur = usize::try_from(u32_a(t, i).ok_or(Defaut::Longueur)?).map_err(|_| Defaut::Longueur)?;
    let version = *t
        .get(i.checked_add(4).ok_or(Defaut::Longueur)?)
        .ok_or(Defaut::Longueur)?;
    if version != VERSION {
        return Err(Defaut::Version(version));
    }
    let a = |d: usize| i.checked_add(d).ok_or(Defaut::Longueur);
    let meta = usize::from(u16_a(t, a(6)?).ok_or(Defaut::Longueur)?);
    let fin = a(longueur)?;
    if meta < TAILLE_METADONNEES || longueur < meta || fin > t.len() {
        return Err(Defaut::Longueur);
    }
    let masque = u64_a(t, a(8)?).ok_or(Defaut::Longueur)?;
    let fd = i32_a(t, a(16)?).ok_or(Defaut::Longueur)?;
    let pid = i32_a(t, a(20)?).ok_or(Defaut::Longueur)?;
    let infos = t.get(a(meta)?..fin).ok_or(Defaut::Longueur)?;
    let pidfd = pidfd_de(infos)?;
    Ok((Evenement { masque, fd, pid, pidfd }, fin))
}

/// Un événement écrit comme le noyau l'écrit (essais et graines du fuzzing) : ses métadonnées, puis un
/// enregistrement PIDFD si `pidfd` est donné.
#[cfg(any(test, fuzzing))]
pub(crate) fn ecrire(e: &Evenement, avec_pidfd: Option<i32>) -> Vec<u8> {
    let longueur = TAILLE_METADONNEES.saturating_add(if avec_pidfd.is_some() { TAILLE_INFO_PIDFD } else { 0 });
    let mut v = Vec::with_capacity(longueur);
    v.extend_from_slice(&u32::try_from(longueur).unwrap_or(u32::MAX).to_ne_bytes());
    v.push(VERSION);
    v.push(0);
    v.extend_from_slice(&u16::try_from(TAILLE_METADONNEES).unwrap_or(u16::MAX).to_ne_bytes());
    v.extend_from_slice(&e.masque.to_ne_bytes());
    v.extend_from_slice(&e.fd.to_ne_bytes());
    v.extend_from_slice(&e.pid.to_ne_bytes());
    if let Some(p) = avec_pidfd {
        v.push(INFO_PIDFD);
        v.push(0);
        v.extend_from_slice(&u16::try_from(TAILLE_INFO_PIDFD).unwrap_or(u16::MAX).to_ne_bytes());
        v.extend_from_slice(&p.to_ne_bytes());
    }
    v
}

/// Les types de systèmes de fichiers locaux, sur disque ou en mémoire, que le garde marque : ceux dont une demande de
/// permission ne dépend d'aucun service ni du réseau.
const LOCAUX: [&str; 13] = [
    "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "tmpfs", "vfat", "exfat", "msdos", "ntfs3", "bcachefs", "jfs",
];

/// Un système de fichiers local à marquer ? Liste blanche : un type inconnu n'est jamais marqué (fuse, fuseblk, nfs,
/// nfs4, cifs, smb3, 9p, overlay, squashfs, et tout ce qui viendra).
pub(crate) fn local(genre: &str) -> bool {
    LOCAUX.contains(&genre)
}

/// Le type d'un système de fichiers d'après son numéro magique (f_type de fstatfs), parmi les `LOCAUX` seulement : un
/// numéro inconnu (fuse, nfs…) n'en a pas. ext2, ext3 et ext4 partagent le leur ; vfat et msdos aussi.
pub(crate) fn genre_de_magie(magie: u64) -> Option<&'static str> {
    Some(match magie {
        0xEF53 => "ext4",
        0x9123_683E => "btrfs",
        0x5846_5342 => "xfs",
        0xF2F5_2010 => "f2fs",
        0x0102_1994 => "tmpfs",
        0x4D44 => "vfat",
        0x2011_BAB0 => "exfat",
        0x7366_746E => "ntfs3",
        0xCA45_1A4E => "bcachefs",
        0x3153_464A => "jfs",
        _ => return None,
    })
}

/// Une ligne de /proc/self/mountinfo, réduite à ce que le garde en fait.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Montage {
    /// major:minor du système de fichiers : deux montages du même (liaison, sous-volume) ne se marquent qu'une fois.
    pub dev: (u32, u32),
    /// Le point de montage, échappements (\040, \011, \012, \134) défaits.
    pub point: String,
    pub genre: String,
}

/// Au plus autant de montages lus : bien plus qu'un ordinateur n'en a.
pub(crate) const MONTAGES_MAX: usize = 8192;

/// Un champ de mountinfo, échappements octaux du noyau défaits ; `None` : échappement mal formé, ou pas de l'UTF-8.
fn sans_echappement(champ: &str) -> Option<String> {
    let octets = champ.as_bytes();
    let mut sortie = Vec::with_capacity(octets.len());
    let mut i = 0usize;
    while let Some(&c) = octets.get(i) {
        if c == b'\\' {
            let chiffres = octets.get(i.checked_add(1)?..i.checked_add(4)?)?;
            let mut valeur = 0u8;
            for d in chiffres {
                if !(b'0'..=b'7').contains(d) {
                    return None;
                }
                valeur = valeur.checked_mul(8)?.checked_add(d.checked_sub(b'0')?)?;
            }
            sortie.push(valeur);
            i = i.checked_add(4)?;
        } else {
            sortie.push(c);
            i = i.checked_add(1)?;
        }
    }
    String::from_utf8(sortie).ok()
}

/// Une ligne de mountinfo : « id parent major:minor racine point options [facultatifs…] - type source options ».
fn montage(ligne: &str) -> Option<Montage> {
    let mots: Vec<&str> = ligne.split(' ').collect();
    let (major, minor) = mots.get(2)?.split_once(':')?;
    let dev = (major.parse().ok()?, minor.parse().ok()?);
    let point = sans_echappement(mots.get(4)?)?;
    let tiret = mots.iter().skip(6).position(|m| *m == "-")?.checked_add(6)?;
    let genre = (*mots.get(tiret.checked_add(1)?)?).to_string();
    point.starts_with('/').then_some(Montage { dev, point, genre })
}

/// Les systèmes de fichiers locaux de mountinfo, un par major:minor (le premier point de montage lu), au plus
/// `MONTAGES_MAX` lignes lues ; une ligne illisible est sautée.
pub(crate) fn locaux(mountinfo: &str) -> Vec<Montage> {
    let mut v: Vec<Montage> = Vec::new();
    for m in mountinfo.lines().take(MONTAGES_MAX).filter_map(montage) {
        if local(&m.genre) && !v.iter().any(|x| x.dev == m.dev) {
            v.push(m);
        }
    }
    v
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    const EXEC: u64 = 0x0004_0000;

    fn ev(fd: i32, pid: i32) -> Evenement {
        Evenement {
            masque: EXEC,
            fd,
            pid,
            pidfd: None,
        }
    }

    /// Chaque numéro magique connu donne un type local ; FUSE, NFS, CIFS, overlay, squashfs et 9p n'en donnent pas.
    #[test]
    fn numeros_magiques_des_seuls_locaux() {
        for m in [
            0xEF53,
            0x9123_683E,
            0x5846_5342,
            0xF2F5_2010,
            0x0102_1994,
            0x4D44,
            0x2011_BAB0,
            0x7366_746E,
        ] {
            assert!(genre_de_magie(m).is_some_and(local), "{m:#x}");
        }
        for m in [
            0x6573_5546,
            0x6969,
            0xFF53_4D42,
            0x794C_7630,
            0x7371_7368,
            0x0102_1997,
            0,
        ] {
            assert_eq!(genre_de_magie(m), None, "{m:#x}");
        }
    }

    #[test]
    fn un_evenement_avec_et_sans_pidfd() {
        let mut t = ecrire(&ev(7, 1234), None);
        t.extend(ecrire(&ev(8, 99), Some(9)));
        let l = evenements(&t);
        assert_eq!(l.defaut, None);
        assert_eq!(
            l.evenements,
            vec![
                ev(7, 1234),
                Evenement {
                    pidfd: Some(9),
                    ..ev(8, 99)
                }
            ]
        );
    }

    #[test]
    fn pidfd_absent_ou_en_erreur() {
        // FAN_NOPIDFD (-1) et FAN_EPIDFD (-2) : aucun descripteur à fermer.
        for p in [-1, -2] {
            let l = evenements(&ecrire(&ev(3, 5), Some(p)));
            assert_eq!(l.evenements, vec![ev(3, 5)]);
            assert_eq!(l.defaut, None);
        }
    }

    #[test]
    fn version_inconnue_arrete() {
        let mut t = ecrire(&ev(3, 5), None);
        let mut b = ecrire(&ev(4, 6), None);
        b[4] = 2;
        t.extend(b);
        let l = evenements(&t);
        assert_eq!(l.evenements, vec![ev(3, 5)]);
        assert_eq!(l.defaut, Some(Defaut::Version(2)));
    }

    #[test]
    fn longueurs_hostiles() {
        let bon = ecrire(&ev(3, 5), None);
        // Coupé.
        for n in 1..bon.len() {
            assert_eq!(evenements(&bon[..n]).defaut, Some(Defaut::Longueur), "{n}");
        }
        // event_len nul, plus court que les métadonnées, plus long que le tampon, démesuré.
        for longueur in [0u32, 8, 23, 25, u32::MAX] {
            let mut t = bon.clone();
            t[..4].copy_from_slice(&longueur.to_ne_bytes());
            let l = evenements(&t);
            assert!(l.evenements.is_empty(), "{longueur}");
            assert!(l.defaut.is_some(), "{longueur}");
        }
        // metadata_len plus court que la structure, ou plus long que l'événement.
        for meta in [0u16, 16, 25, u16::MAX] {
            let mut t = bon.clone();
            t[6..8].copy_from_slice(&meta.to_ne_bytes());
            assert_eq!(evenements(&t).defaut, Some(Defaut::Longueur), "{meta}");
        }
    }

    #[test]
    fn enregistrements_hostiles() {
        // Longueur d'enregistrement nulle (boucle sans fin), trop courte, qui sort de l'événement.
        for longueur in [0u16, 3, 9, u16::MAX] {
            let mut t = ecrire(&ev(3, 5), Some(4));
            t[26..28].copy_from_slice(&longueur.to_ne_bytes());
            assert_eq!(evenements(&t).defaut, Some(Defaut::Enregistrement), "{longueur}");
        }
        // Deux PIDFD.
        let mut t = ecrire(&ev(3, 5), Some(4));
        t.extend_from_within(24..32);
        t[..4].copy_from_slice(&40u32.to_ne_bytes());
        assert_eq!(evenements(&t).defaut, Some(Defaut::Enregistrement));
        // Un enregistrement inconnu est sauté.
        let mut t = ecrire(&ev(3, 5), Some(4));
        t[24] = 77;
        let l = evenements(&t);
        assert_eq!((l.evenements, l.defaut), (vec![ev(3, 5)], None));
    }

    #[test]
    fn nombre_borne() {
        let un = ecrire(&ev(3, 5), None);
        let t: Vec<u8> = un
            .iter()
            .copied()
            .cycle()
            .take(un.len() * (EVENEMENTS_MAX + 3))
            .collect();
        let l = evenements(&t);
        assert_eq!(l.evenements.len(), EVENEMENTS_MAX);
        assert_eq!(l.defaut, Some(Defaut::Trop));
        assert_eq!(evenements(&[]), Lecture::default());
    }

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - btrfs /dev/nvme0n1p2 rw,ssd,subvol=/@
23 22 259:2 /@home /home rw,relatime shared:2 - btrfs /dev/nvme0n1p2 rw,subvol=/@home
24 22 0:22 / /proc rw,nosuid shared:5 - proc proc rw
25 22 0:23 / /tmp rw,nosuid,nodev shared:6 - tmpfs tmpfs rw
26 22 0:50 / /home/alice/Mon\\040disque rw shared:7 master:3 - vfat /dev/sda1 rw
27 22 0:51 / /mnt/reseau rw - nfs4 serveur:/ rw
28 22 0:52 / /run/user/1000/doc rw - fuse.portal portal rw
29 22 0:53 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw
30 22 7:0 / /snap/core/1 ro - squashfs /dev/loop0 ro
31 22 0:54 / /mnt/9p rw - 9p hote rw
32 22 0:55 / /mnt/smb rw - cifs //s/p rw
33 22 0:56 / /mnt/cle rw - fuseblk /dev/sdb1 rw
34 22 0:57 / /mnt/x\\9zz rw - ext4 /dev/sdc1 rw
ligne illisible
";

    #[test]
    fn seuls_les_locaux_sont_marques() {
        let l = locaux(MOUNTINFO);
        let points: Vec<&str> = l.iter().map(|m| m.point.as_str()).collect();
        // /home, même btrfs (259:2) que /, n'est marqué qu'une fois ; l'échappement \040 défait ; un échappement
        // faux (\9zz) fait sauter la ligne.
        assert_eq!(points, ["/", "/tmp", "/home/alice/Mon disque"]);
        for genre in [
            "fuse",
            "fuseblk",
            "fuse.portal",
            "nfs",
            "nfs4",
            "cifs",
            "smb3",
            "9p",
            "overlay",
            "squashfs",
            "proc",
        ] {
            assert!(!local(genre), "{genre}");
        }
        for genre in ["ext4", "btrfs", "xfs", "tmpfs", "vfat", "exfat"] {
            assert!(local(genre), "{genre}");
        }
    }
}
