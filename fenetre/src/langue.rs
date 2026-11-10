//! La langue de la fenêtre : celle que `vanguard` lui donne (`--langue fr|en`), sinon VANGUARD_LANG, sinon celle du
//! système (LC_ALL, LC_MESSAGES, LANG), sinon le français. Changeable dans la fenêtre (rubrique Vanguard) : les
//! commandes lancées ensuite reçoivent la même (VANGUARD_LANG), pour que leurs textes suivent.

use std::sync::atomic::{AtomicBool, Ordering};

static ANGLAIS: AtomicBool = AtomicBool::new(false);

/// L'interface est-elle en anglais ?
pub fn anglais() -> bool {
    ANGLAIS.load(Ordering::Relaxed)
}

/// Pose la langue : celle demandée, sinon celle de l'environnement.
pub fn choisir(demandee: Option<bool>) {
    let lue = |nom: &str| std::env::var(nom).ok().filter(|v| !v.is_empty());
    let anglais = demandee.unwrap_or_else(|| {
        lue("VANGUARD_LANG")
            .or_else(|| lue("LC_ALL"))
            .or_else(|| lue("LC_MESSAGES"))
            .or_else(|| lue("LANG"))
            .is_some_and(|v| est_anglais(&v))
    });
    ANGLAIS.store(anglais, Ordering::Relaxed);
}

/// Passe à l'autre langue.
pub fn basculer() {
    ANGLAIS.store(!anglais(), Ordering::Relaxed);
}

/// Une durée en secondes, à une décimale, avec la virgule en français : « 2,1 s », « 2.1 s ». Une seule forme
/// partout (console, écrans, Coulisses), au lieu de « 2 s » ici et « 2.1 s » là.
pub fn secondes(s: f32) -> String {
    let t = format!("{s:.1} s");
    if anglais() { t } else { t.replace('.', ",") }
}

/// « en », « en_CA.UTF-8 », « english » : de l'anglais ; le reste, du français.
pub fn est_anglais(valeur: &str) -> bool {
    valeur.get(..2).is_some_and(|d| d.eq_ignore_ascii_case("en"))
}

/// Un texte dans la langue de l'interface : `tr!("Bilan", "Check")`.
#[macro_export]
macro_rules! tr {
    ($fr:literal, $en:literal $(,)?) => {
        if $crate::langue::anglais() { $en } else { $fr }
    };
}

/// `format!` dans la langue de l'interface : `trf!("{n} tâche", "{n} task")`.
#[macro_export]
macro_rules! trf {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { format!($en $(, $arg)*) } else { format!($fr $(, $arg)*) }
    };
}

/// Un compte, pour l'accord : les comptes de la fenêtre sont des `usize`, ceux lus dans un JSON des `u64`.
pub trait Compte: Copy + std::fmt::Display {
    fn valeur(self) -> u64;
}

impl Compte for usize {
    fn valeur(self) -> u64 {
        u64::try_from(self).unwrap_or(u64::MAX)
    }
}

impl Compte for u64 {
    fn valeur(self) -> u64 {
        self
    }
}

/// Le mot accordé à `n`, dans la langue de l'interface : le français met 0 et 1 au singulier (« 0 alerte »), l'anglais
/// 1 seulement (« 0 alerts »).
pub fn accord(n: impl Compte, fr: [&'static str; 2], en: [&'static str; 2]) -> &'static str {
    accord_en(anglais(), n.valeur(), fr, en)
}

fn accord_en(anglais: bool, n: u64, fr: [&'static str; 2], en: [&'static str; 2]) -> &'static str {
    if anglais {
        if n == 1 { en[0] } else { en[1] }
    } else if n <= 1 {
        fr[0]
    } else {
        fr[1]
    }
}

/// Un mot accordé à un nombre, sans le nombre : `tra!(n, "vérifié", "vérifiés", "checked", "checked")`.
#[macro_export]
macro_rules! tra {
    ($n:expr, $fr:literal, $frs:literal, $en:literal, $ens:literal $(,)?) => {
        $crate::langue::accord($n, [$fr, $frs], [$en, $ens])
    };
}

/// Un nombre et son nom accordé : `trn!(n, "ligne", "lignes", "line", "lines")` donne « 3 lignes », « 1 line ».
#[macro_export]
macro_rules! trn {
    ($n:expr, $fr:literal, $frs:literal, $en:literal, $ens:literal $(,)?) => {{
        let n = $n;
        format!("{} {}", n, $crate::langue::accord(n, [$fr, $frs], [$en, $ens]))
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnait_l_anglais() {
        assert!(est_anglais("en"));
        assert!(est_anglais("en_CA.UTF-8"));
        assert!(est_anglais("EN"));
        assert!(!est_anglais("fr_CA.UTF-8"));
        assert!(!est_anglais("e"));
        assert!(!est_anglais(""));
        assert!(!est_anglais("é"));
    }

    /// 0 et 1 au singulier en français, 1 seulement en anglais. Sans changer la langue de tout le programme d'essai :
    /// d'autres essais, en même temps, lisent des textes français.
    #[test]
    fn accorde_au_nombre() {
        let fr = ["alerte", "alertes"];
        let en = ["alert", "alerts"];
        let mots: Vec<_> = [0, 1, 2].iter().map(|&n| accord_en(false, n, fr, en)).collect();
        assert_eq!(mots, ["alerte", "alerte", "alertes"]);
        let mots: Vec<_> = [0, 1, 2].iter().map(|&n| accord_en(true, n, fr, en)).collect();
        assert_eq!(mots, ["alerts", "alert", "alerts"]);
    }
}
