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
}
