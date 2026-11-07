//! L'ensemble CERTAIN du garde, relu en root sans aucun lecteur de format (P22) : deux fichiers d'enregistrements de
//! 32 octets triés, sans en-tête, préparés par le Vanguard du compte (`compte::preparer_listes`) depuis MalwareBazaar et
//! la base ClamAV. Le garde ne vérifie que « multiple de 32, trié, sans doublon » ; une liste forgée ne peut que
//! rendre plus strict (les exceptions P11 gardent le système), une liste illisible laisse l'ancienne en place.
//!
//! - `certain-sha256.bin` : des SHA-256 de fichiers entiers ;
//! - `certain-md5.bin` : la taille (u64 gros-boutiste), le MD5, huit zéros (`Signatures::liste_md5_taille`).
//!
//! Le hachage d'un fichier lancé fait les deux d'une seule lecture (`hacher`), et y cherche la marque d'essai EICAR.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::io::Read;
use std::path::Path;

use md5::Digest;

use crate::protection::clamav::hashes::ListeSha256;

use super::decision::Certitude;

/// La taille d'une liste, au plus (MalwareBazaar en entier tient en ~32 Mo) : deux listes et leur relecture tiennent
/// sous le MemoryMax de l'unité (256 Mo).
pub(crate) const TAILLE_MAX: u64 = 64 << 20;

/// L'ensemble CERTAIN en mémoire.
#[derive(Debug, Default)]
pub(crate) struct Certain {
    pub sha256: Option<ListeSha256>,
    pub md5: Option<ListeSha256>,
}

impl Certain {
    pub(crate) fn nombre(&self) -> usize {
        let n = |l: &Option<ListeSha256>| l.as_ref().map_or(0, ListeSha256::nombre);
        n(&self.sha256).saturating_add(n(&self.md5))
    }

    /// Le fichier haché est-il certain ?
    pub(crate) fn juger(&self, h: &Hache) -> Option<Certitude> {
        let dans = |l: &Option<ListeSha256>, e: &[u8; 32]| l.as_ref().is_some_and(|l| l.contient(e));
        if dans(&self.sha256, &h.sha256) || dans(&self.md5, &enregistrement_md5(&h.md5, h.taille)) {
            Some(Certitude::Liste)
        } else if h.essai {
            Some(Certitude::Essai)
        } else {
            None
        }
    }
}

/// L'enregistrement de 32 octets d'un MD5 et d'une taille.
pub(crate) fn enregistrement_md5(md5: &[u8; 16], taille: u64) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..8].copy_from_slice(&taille.to_be_bytes());
    e[8..24].copy_from_slice(md5);
    e
}

/// Un fichier haché.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hache {
    pub sha256: [u8; 32],
    pub md5: [u8; 16],
    pub taille: u64,
    /// Un exécutable qui porte la marque d'essai EICAR.
    pub essai: bool,
}

/// Un lecteur qui calcule le MD5 et compte les octets de ce qui passe.
struct Double<R> {
    dedans: R,
    md5: md5::Md5,
    lus: u64,
}

impl<R: Read> Read for Double<R> {
    fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
        let n = self.dedans.read(tampon)?;
        let lu = tampon
            .get(..n)
            .ok_or_else(|| std::io::Error::other("lecture plus longue que le tampon"))?;
        self.md5.update(lu);
        self.lus = self.lus.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }
}

/// Hache tout ce que `lu` donne : SHA-256, MD5, taille et marque d'essai, en une seule lecture.
pub(crate) fn hacher(lu: impl Read) -> Option<Hache> {
    let mut d = Double {
        dedans: lu,
        md5: md5::Md5::new(),
        lus: 0,
    };
    let (sha256, essai) = crate::protection::sources::hacher_et_guetter(&mut d)?;
    Some(Hache {
        sha256,
        md5: d.md5.finalize().into(),
        taille: d.lus,
        essai,
    })
}

/// Relit une liste du compte : sans suivre de lien, sans attendre (un tube), un fichier ordinaire à ce compte, pas
/// trop gros, bien formé. `None` : absente ou refusée (la raison est rendue pour etat.json).
pub(crate) fn lire(chemin: &Path, compte: u32) -> Result<ListeSha256, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(chemin)
        .map_err(|e| format!("{}: {e}", chemin.display()))?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() {
        return Err(format!("{}: pas un fichier ordinaire", chemin.display()));
    }
    if m.uid() != compte {
        return Err(format!("{}: n'est pas au compte {compte}", chemin.display()));
    }
    if m.len() > TAILLE_MAX {
        return Err(format!("{}: plus de {TAILLE_MAX} octets", chemin.display()));
    }
    let mut octets = Vec::new();
    f.take(TAILLE_MAX.saturating_add(1))
        .read_to_end(&mut octets)
        .map_err(|e| e.to_string())?;
    if u64::try_from(octets.len()).unwrap_or(u64::MAX) > TAILLE_MAX {
        return Err(format!("{}: a grandi pendant la lecture", chemin.display()));
    }
    ListeSha256::lire(octets).ok_or_else(|| format!("{}: pas une liste triée de 32 octets", chemin.display()))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn hache_de(octets: &[u8]) -> Hache {
        hacher(octets).unwrap()
    }

    #[test]
    fn une_seule_lecture_donne_les_deux_empreintes() {
        let h = hache_de(b"abc");
        // Les empreintes connues de « abc ».
        assert_eq!(
            crate::protection::empreintes::hex(&h.sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut md5 = [0u8; 32];
        md5[..16].copy_from_slice(&h.md5);
        assert!(crate::protection::empreintes::hex(&md5).starts_with("900150983cd24fb0d6963f7d28e17f72"));
        assert_eq!((h.taille, h.essai), (3, false));
    }

    #[test]
    fn certain_par_sha_par_md5_et_taille_ou_par_la_marque() {
        let h = hache_de(b"un programme malveillant");
        let rien = Certain::default();
        assert_eq!(rien.juger(&h), None);
        let sha = Certain {
            sha256: ListeSha256::lire([[0u8; 32], h.sha256, [0xff; 32]].concat()),
            md5: None,
        };
        assert_eq!(sha.juger(&h), Some(Certitude::Liste));
        let md5 = Certain {
            sha256: None,
            md5: ListeSha256::lire(enregistrement_md5(&h.md5, h.taille).to_vec()),
        };
        assert_eq!(md5.juger(&h), Some(Certitude::Liste));
        // Le même MD5 pour une autre taille : rien.
        assert_eq!(
            md5.juger(&Hache {
                taille: h.taille + 1,
                ..h
            }),
            None
        );
        assert_eq!(rien.juger(&Hache { essai: true, ..h }), Some(Certitude::Essai));
        assert_eq!(sha.nombre() + md5.nombre(), 4);
    }

    #[test]
    fn listes_du_compte_relues_avec_prudence() {
        use std::os::unix::fs::MetadataExt;
        let d = crate::essais::Jetable::nouveau("garde-listes");
        let moi = std::fs::metadata(&*d).unwrap().uid();
        let bonne = d.join("bonne.bin");
        std::fs::write(&bonne, [[1u8; 32], [2u8; 32]].concat()).unwrap();
        assert_eq!(lire(&bonne, moi).unwrap().nombre(), 2);
        // Un autre compte, une liste en désordre ou tronquée, un lien, un dossier, rien : refusées.
        assert!(lire(&bonne, moi.wrapping_add(1)).is_err());
        let desordre = d.join("desordre.bin");
        std::fs::write(&desordre, [[2u8; 32], [1u8; 32]].concat()).unwrap();
        assert!(lire(&desordre, moi).is_err());
        let doublon = d.join("doublon.bin");
        std::fs::write(&doublon, [[1u8; 32], [1u8; 32]].concat()).unwrap();
        assert!(lire(&doublon, moi).is_err());
        let tronquee = d.join("tronquee.bin");
        std::fs::write(&tronquee, [1u8; 33]).unwrap();
        assert!(lire(&tronquee, moi).is_err());
        let lien = d.join("lien.bin");
        std::os::unix::fs::symlink(&bonne, &lien).unwrap();
        assert!(lire(&lien, moi).is_err());
        assert!(lire(&d, moi).is_err());
        assert!(lire(&d.join("absente"), moi).is_err());
        // Vide : une liste valide, sans rien.
        let vide = d.join("vide.bin");
        std::fs::write(&vide, []).unwrap();
        assert_eq!(lire(&vide, moi).unwrap().nombre(), 0);
    }
}
