//! La fiche du système Linux (os-release) : son nom à montrer, et ce qui dit la distribution. Lue une fois par
//! lancement, avec le repli prévu par os-release(5) quand /etc n'en a pas (/usr/lib/os-release) : quatre copies la
//! relisaient sans ce repli.

use std::sync::OnceLock;

/// Le texte d'os-release, vide quand aucun des deux fichiers ne se lit.
pub(crate) fn os_release() -> &'static str {
    static TEXTE: OnceLock<String> = OnceLock::new();
    TEXTE.get_or_init(|| {
        std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .unwrap_or_default()
    })
}

/// La valeur de `cle` dans un texte d'os-release, sans ses guillemets (doubles ou simples, os-release(5)).
// Le nom ne sert qu'aux fiches de Linux ; le texte, lui, se demande aussi ailleurs, à l'exécution (le guide).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn valeur<'a>(texte: &'a str, cle: &str) -> Option<&'a str> {
    texte.lines().find_map(|l| {
        let v = l.strip_prefix(cle)?.strip_prefix('=')?.trim();
        Some(v.trim_matches('"').trim_matches('\''))
    })
}

/// Le nom du système à montrer (« Arch Linux », « Ubuntu 24.04.1 LTS ») ; « Linux » quand os-release ne le dit pas.
#[cfg(target_os = "linux")]
pub(crate) fn nom() -> String {
    valeur(os_release(), "PRETTY_NAME")
        .filter(|v| !v.is_empty())
        .unwrap_or("Linux")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valeurs_d_os_release() {
        let texte = "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nID_LIKE='debian ubuntu'\nPRETTY=x\n";
        assert_eq!(valeur(texte, "PRETTY_NAME"), Some("Arch Linux"));
        assert_eq!(valeur(texte, "ID"), Some("arch"));
        assert_eq!(valeur(texte, "ID_LIKE"), Some("debian ubuntu"));
        // « PRETTY » n'est pas le début de « PRETTY_NAME ».
        assert_eq!(valeur(texte, "PRETTY"), Some("x"));
        assert_eq!(valeur(texte, "VERSION_ID"), None);
    }
}
