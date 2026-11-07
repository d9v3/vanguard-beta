//! Le cache des fichiers déjà hachés, pur : la clé est (périphérique, inode, ctime, taille). Un fichier réécrit change
//! de ctime (le noyau la met à jour à chaque écriture, et personne d'autre que root ne la recule) : il est haché de
//! nouveau. Borné ; vidé entier quand il est plein, et quand l'ensemble CERTAIN ou les réglages changent (un ancien
//! « propre » pourrait ne plus l'être).
//!
//! Sur FAT et exFAT, la ctime n'a qu'une granularité grossière (deux secondes sur FAT) : un fichier réécrit dans la
//! même tranche, à la même taille, garderait sa clé. Rien n'y est mis en cache : chaque lancement y est haché.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashMap;

/// Les entrées, au plus.
pub(crate) const ENTREES_MAX: usize = 65_536;

/// La clé d'un fichier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Cle {
    pub dev: u64,
    pub ino: u64,
    pub ctime: i64,
    pub ctime_ns: i64,
    pub taille: u64,
    /// La ctime de son système de fichiers est assez fine pour dire qu'il a changé (`ctime_fiable`).
    pub fiable: bool,
}

/// La ctime du système de fichiers (son numéro magique, lu par fstatfs) dit-elle chaque écriture ? Seulement sur les
/// systèmes locaux connus à la nanoseconde ; FAT, exFAT et l'inconnu : non.
pub(crate) fn ctime_fiable(magie: Option<u64>) -> bool {
    matches!(
        magie.and_then(crate::machine::linux::fanotify::lecture::genre_de_magie),
        Some("ext4" | "btrfs" | "xfs" | "f2fs" | "tmpfs" | "ntfs3" | "bcachefs" | "jfs")
    )
}

/// Ce qu'on sait d'un fichier haché.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Connu {
    pub sha256: [u8; 32],
    /// Dans l'ensemble CERTAIN (ou marqué EICAR).
    pub certain: Option<super::decision::Certitude>,
}

/// Le cache.
#[derive(Debug, Default)]
pub(crate) struct Cache {
    entrees: HashMap<Cle, Connu>,
    /// Les fois où il a été vidé parce que plein.
    pub vidages: u64,
}

impl Cache {
    pub(crate) fn lire(&self, cle: &Cle) -> Option<Connu> {
        if !cle.fiable {
            return None;
        }
        self.entrees.get(cle).copied()
    }

    pub(crate) fn noter(&mut self, cle: Cle, connu: Connu) {
        if !cle.fiable {
            return;
        }
        if self.entrees.len() >= ENTREES_MAX && !self.entrees.contains_key(&cle) {
            self.entrees.clear();
            self.vidages = self.vidages.saturating_add(1);
        }
        self.entrees.insert(cle, connu);
    }

    pub(crate) fn vider(&mut self) {
        self.entrees.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entrees.len()
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn cle(ino: u64) -> Cle {
        Cle {
            dev: 2049,
            ino,
            ctime: 1_700_000_000,
            ctime_ns: 5,
            taille: 4096,
            fiable: true,
        }
    }

    const PROPRE: Connu = Connu {
        sha256: [1; 32],
        certain: None,
    };

    #[test]
    fn un_fichier_change_n_est_plus_connu() {
        let mut c = Cache::default();
        c.noter(cle(7), PROPRE);
        assert_eq!(c.lire(&cle(7)), Some(PROPRE));
        for autre in [
            Cle { ctime_ns: 6, ..cle(7) },
            Cle {
                ctime: 1_700_000_001,
                ..cle(7)
            },
            Cle { taille: 4097, ..cle(7) },
            Cle { dev: 2050, ..cle(7) },
            cle(8),
        ] {
            assert_eq!(c.lire(&autre), None, "{autre:?}");
        }
        c.vider();
        assert_eq!(c.lire(&cle(7)), None);
    }

    /// m1 : sur FAT ou exFAT (ou un système inconnu), rien n'est gardé : chaque lancement est haché.
    #[test]
    fn rien_en_cache_sans_ctime_fine() {
        assert!(ctime_fiable(Some(0xEF53)));
        assert!(ctime_fiable(Some(0x9123_683E)));
        for magie in [Some(0x4D44), Some(0x2011_BAB0), Some(0x6969), None] {
            assert!(!ctime_fiable(magie), "{magie:?}");
        }
        let mut c = Cache::default();
        let fat = Cle {
            fiable: false,
            ..cle(7)
        };
        c.noter(fat, PROPRE);
        assert_eq!(c.lire(&fat), None);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn borne_et_vide_quand_plein() {
        let mut c = Cache::default();
        for i in 0..ENTREES_MAX as u64 {
            c.noter(cle(i), PROPRE);
        }
        assert_eq!(c.len(), ENTREES_MAX);
        // Réécrire une entrée présente ne vide rien.
        c.noter(cle(0), PROPRE);
        assert_eq!((c.len(), c.vidages), (ENTREES_MAX, 0));
        c.noter(cle(u64::MAX), PROPRE);
        assert_eq!((c.len(), c.vidages), (1, 1));
        assert_eq!(c.lire(&cle(u64::MAX)), Some(PROPRE));
    }
}
