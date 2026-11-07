//! Le cache des fichiers déjà hachés, pur : la clé est (périphérique, inode, ctime, taille). Un fichier réécrit change
//! de ctime (le noyau la met à jour à chaque écriture, et personne d'autre que root ne la recule) : il est haché de
//! nouveau. Borné ; vidé entier quand il est plein, et quand l'ensemble CERTAIN ou les réglages changent (un ancien
//! « propre » pourrait ne plus l'être).

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
        self.entrees.get(cle).copied()
    }

    pub(crate) fn noter(&mut self, cle: Cle, connu: Connu) {
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
