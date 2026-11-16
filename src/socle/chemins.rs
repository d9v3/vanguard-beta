//! Les chemins de Windows sous leurs deux formes : étendue (« \\?\C:\… », celle de `canonicalize`) et courante
//! (« C:\… », celle qu'on tape). Deux besoins, deux fonctions, à ne pas confondre :
//! - **comparer** deux chemins (`composants`) : le préfixe et la casse s'ôtent toujours, rien n'est touché ;
//! - **agir ou montrer** (`sans_verbatim`) : le préfixe ne s'ôte que si la forme courante désigne sans doute possible
//!   le même fichier ; sinon on garderait un nom que Windows réinterprète (« dossier. » devient « dossier »).

use std::path::Path;

/// « \\?\C:\… » → « C:\… », « \\?\UNC\serveur\partage\… » → « \\serveur\partage\… », seulement quand la forme
/// courte désigne sans doute possible le même fichier. Sans « \\?\ », Windows réinterprète le chemin : point ou espace
/// final retiré, « . » et « .. » résolus, CON, NUL, COM1… pris pour des périphériques, longueur bornée (MAX_PATH).
/// « C:\x\dossier. », créé exprès par qui veut se cacher, deviendrait « C:\x\dossier », un autre dossier, sain. Dans
/// ces cas, et pour toute autre forme (« \\?\Volume{…}\ »), `None` : le chemin reste tel quel, et rien n'agit sur un
/// autre fichier à sa place.
pub(crate) fn sans_verbatim(chemin: &str) -> Option<String> {
    // Au moins le serveur et le partage pour un chemin réseau ; un nom pour un lecteur.
    let (court, noms, minimum) = if let Some(reseau) = chemin.strip_prefix(r"\\?\UNC\") {
        (format!(r"\\{reseau}"), reseau, 2)
    } else {
        let local = chemin.strip_prefix(r"\\?\")?;
        let mut c = local.chars();
        let (Some(lettre), Some(':'), Some('\\')) = (c.next(), c.next(), c.next()) else {
            return None;
        };
        if !lettre.is_ascii_alphabetic() {
            return None;
        }
        // La racine du lecteur, « C:\ », n'a pas de nom après elle.
        let noms = c.as_str();
        if noms.is_empty() {
            return Some(local.to_string());
        }
        (local.to_string(), noms, 1)
    };
    let noms: Vec<&str> = noms.split('\\').collect();
    let sur = noms.len() >= minimum
        && noms.iter().all(|n| nom_sans_ambiguite(n))
        // MAX_PATH : 260 caractères UTF-16, le nul final compris.
        && court.encode_utf16().count() < 260;
    sur.then_some(court)
}

/// Un nom que Windows lit tel quel hors de « \\?\ » : ni vide, ni « . » ou « .. », sans point ni espace final, sans
/// caractère interdit, et pas un nom de périphérique (« CON », « nul.txt », « COM¹ »…), même suivi d'une extension.
pub(crate) fn nom_sans_ambiguite(nom: &str) -> bool {
    const PERIPHERIQUES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    let souche = nom.split('.').next().unwrap_or_default().trim_end().to_uppercase();
    let numerote = ["COM", "LPT"].iter().any(|p| {
        souche.strip_prefix(p).is_some_and(|n| {
            matches!(
                n,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    !nom.is_empty()
        && !nom.ends_with(['.', ' '])
        && !nom.chars().any(|c| c.is_control() || "<>:\"/|?*".contains(c))
        && !PERIPHERIQUES.contains(&souche.as_str())
        && !numerote
}

/// Un chemin ramené à une forme comparable, composant par composant. Sous Windows, sans le préfixe étendu
/// (« \\?\C: » vaut « C: », « \\?\UNC\serveur\partage » vaut « \\serveur\partage ») et sans casse.
pub(crate) fn composants(chemin: &Path) -> Vec<std::ffi::OsString> {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        chemin
            .components()
            .map(|c| match c {
                Component::Prefix(p) => match p.kind() {
                    Prefix::Disk(l) | Prefix::VerbatimDisk(l) => format!("{}:", char::from(l.to_ascii_lowercase())),
                    Prefix::UNC(s, d) | Prefix::VerbatimUNC(s, d) => {
                        format!(r"\\{}\{}", s.to_string_lossy(), d.to_string_lossy()).to_lowercase()
                    }
                    _ => c.as_os_str().to_string_lossy().to_lowercase(),
                },
                _ => c.as_os_str().to_string_lossy().to_lowercase(),
            })
            .map(std::ffi::OsString::from)
            .collect()
    }
    #[cfg(not(windows))]
    chemin.components().map(|c| c.as_os_str().to_os_string()).collect()
}

#[cfg(test)]
mod essais {
    use super::*;

    #[test]
    fn prefixe_etendu_retire_seulement_sans_ambiguite() {
        let s = |c: &str| sans_verbatim(c);
        assert_eq!(
            s(r"\\?\C:\Users\Public\vg-essai-eicar").as_deref(),
            Some(r"C:\Users\Public\vg-essai-eicar")
        );
        assert_eq!(s(r"\\?\d:\").as_deref(), Some(r"d:\"));
        assert_eq!(
            s(r"\\?\C:\Données\été 2026\a.b.txt").as_deref(),
            Some(r"C:\Données\été 2026\a.b.txt")
        );
        assert_eq!(s(r"\\?\UNC\nas\partage\x").as_deref(), Some(r"\\nas\partage\x"));
        assert_eq!(s(r"\\?\UNC\nas\partage").as_deref(), Some(r"\\nas\partage"));
        // Déjà court, ou une forme sans équivalent court : tel quel.
        for c in [
            r"C:\Users\alice",
            r"\\nas\partage",
            r"\\?\Volume{1234}\a",
            r"\\?\GLOBALROOT\Device\x",
            r"\\?\UNC\nas",
            r"\\?\UNC\",
            r"\\?\",
            r"\\?\C:",
            r"\\?\1:\x",
            r"\\.\C:\x",
        ] {
            assert_eq!(s(c), None, "{c}");
        }
        // Ce que Windows réinterpréterait sans « \\?\ » : un autre fichier, ou un périphérique.
        for c in [
            r"\\?\C:\x\dossier.",
            r"\\?\C:\x\dossier ",
            r"\\?\C:\x\..\y",
            r"\\?\C:\x\.\y",
            r"\\?\C:\x\\y",
            r"\\?\C:\x\",
            r"\\?\C:\x\CON",
            r"\\?\C:\x\nul.txt",
            r"\\?\C:\x\Aux .log",
            r"\\?\C:\x\com1",
            r"\\?\C:\x\LPT¹",
            r"\\?\C:\x\CONOUT$",
            r"\\?\C:\x\a:flux",
            r"\\?\C:\x\a*b",
            "\\\\?\\C:\\x\\a\u{1}b",
            r"\\?\UNC\nas\partage.\x",
        ] {
            assert_eq!(s(c), None, "{c}");
        }
        // Les noms qui ressemblent sans l'être restent courts.
        assert!(s(r"\\?\C:\x\CONSOLE\com10\nul2.txt\.config").is_some());
        // MAX_PATH : 259 caractères au plus, le nul final en plus.
        let long = |n: usize| format!(r"\\?\C:\{}", "a".repeat(n - 3));
        assert!(s(&long(259)).is_some());
        assert_eq!(s(&long(260)), None);
    }
}
