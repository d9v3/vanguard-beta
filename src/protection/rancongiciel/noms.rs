//! Les noms de fichiers, jugés en fonctions pures : une même extension ajoutée partout, une extension inconnue d'une
//! table maison, un nom tiré au hasard, une note de rançon. Un rançongiciel laisse l'une ou l'autre de ces traces ;
//! aucune ne suffit seule, mais ensemble elles séparent une rafale de chiffrement d'un `git clone` ou d'un `tar x`.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// L'extension ajoutée à un fichier renommé « rapport.docx » → « rapport.docx.locked » : « locked ». `None` si le
/// nouveau nom n'est pas l'ancien suivi d'un point et d'un suffixe.
pub(crate) fn extension_ajoutee(ancien: &str, nouveau: &str) -> Option<String> {
    let reste = nouveau.strip_prefix(ancien)?.strip_prefix('.')?;
    (!reste.is_empty() && !reste.contains('/') && !reste.contains('\\')).then(|| reste.to_ascii_lowercase())
}

/// Les extensions courantes d'un ordinateur de maison : un fichier dont l'extension finale n'y est pas, ajoutée en
/// rafale, est suspect. La table est volontairement large (documents, images, son, vidéo, archives, code, données) :
/// mieux vaut rater une extension rare que crier sur un format courant.
const EXTENSIONS_CONNUES: &[&str] = &[
    // Documents et texte.
    "txt", "md", "rtf", "doc", "docx", "odt", "pdf", "xls", "xlsx", "ods", "csv", "ppt", "pptx", "odp", "pages",
    "numbers", "key", "epub", "mobi", "tex", "log", "ini", "conf", "cfg", "json", "xml", "yaml", "yml", "toml", "html",
    "htm", "css", "nfo", // Images.
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp", "heic", "heif", "svg", "ico", "raw", "cr2", "nef",
    "arw", "dng", "psd", "xcf", "ai", "eps", // Son.
    "mp3", "wav", "flac", "aac", "ogg", "oga", "opus", "m4a", "wma", "aiff", "mid", "midi", // Vidéo.
    "mp4", "m4v", "mkv", "avi", "mov", "wmv", "flv", "webm", "mpg", "mpeg", "3gp", "ts",
    // Archives et paquets.
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "zst", "lz4", "iso", "deb", "rpm", "jar", "apk", "dmg", "cab",
    // Code et données.
    "rs", "c", "h", "cpp", "hpp", "py", "js", "ts", "go", "java", "kt", "rb", "php", "sh", "bat", "ps1", "sql", "db",
    "sqlite", "bak", "dat", "bin", "exe", "dll", "so", "o", "a", "lib", "msi", "lock",
    // Divers courants.
    "torrent", "ics", "vcf", "gpg", "asc", "pem", "crt", "key",
];

/// L'extension finale est-elle connue ? (casse ignorée) Un nom sans point n'a pas d'extension : connu (on ne juge pas
/// un dossier ou un binaire sans extension).
pub(crate) fn extension_connue(nom: &str) -> bool {
    match nom.rsplit_once('.') {
        // Rien à juger : pas d'extension, ou un nom caché « .bashrc » (racine vide).
        None | Some(("", _)) => true,
        Some((_, ext)) => EXTENSIONS_CONNUES.contains(&ext.to_ascii_lowercase().as_str()),
    }
}

/// Un nom tiré au hasard, comme « 7Gq3xZ9pLmTkWvАб.xyz » : au moins 16 caractères dont l'entropie de Shannon dépasse
/// 4 bits par caractère. Le calcul porte sur la racine du nom (sans l'extension) : « rapport-2024-final.docx » reste
/// un nom lisible. Les lettres accentuées et la casse comptent ; les séparateurs courants (« - », « _ », espace) ne
/// trahissent rien.
pub(crate) fn nom_au_hasard(nom: &str) -> bool {
    let racine = nom
        .rsplit_once('.')
        .map_or(nom, |(avant, _)| if avant.is_empty() { nom } else { avant });
    let caracteres: Vec<char> = racine.chars().collect();
    if caracteres.len() < 16 {
        return false;
    }
    entropie_caracteres(&caracteres) >= 4.0
}

/// L'entropie de Shannon d'une suite de caractères, en bits par caractère.
#[allow(clippy::cast_precision_loss)] // une mesure statistique : la précision du f32 suffit largement
#[expect(
    clippy::as_conversions,
    reason = "vers f32, Rust n'a que `as` : une mesure, la précision suffit"
)]
fn entropie_caracteres(caracteres: &[char]) -> f32 {
    use std::collections::HashMap;
    if caracteres.is_empty() {
        return 0.0;
    }
    let mut compte: HashMap<char, u32> = HashMap::new();
    for &c in caracteres {
        let fois = compte.entry(c).or_default();
        *fois = fois.saturating_add(1);
    }
    let total = caracteres.len() as f32;
    compte
        .values()
        .map(|&c| {
            let p = c as f32 / total;
            -p * p.log2()
        })
        .sum()
}

/// Les racines de noms qu'un rançongiciel laisse dans chaque dossier (note de rançon), en minuscules et sans
/// l'extension : README, HOW_TO_DECRYPT, RESTORE_FILES… Reconnues par des mots-clés, pas par une liste figée (chaque
/// famille a le sien).
const MOTS_DE_RANCON: &[&str] = &[
    "decrypt",
    "restore",
    "recover",
    "readme",
    "read_me",
    "read-me",
    "how_to",
    "howto",
    "how-to",
    "unlock",
    "ransom",
    "your_files",
    "yourfiles",
    "files_encrypted",
    "help_decrypt",
    "recovery",
    "attention",
    "important",
];

/// Ce nom est-il une note de rançon ? Un fichier texte (ou .hta) dont le nom contient un mot-clé de rançon. La casse,
/// les tirets et les soulignés ne comptent pas. Un simple « README.md » dans un dépôt de code n'est pas pris seul :
/// R4 n'alerte que lorsqu'un MÊME nouveau fichier de ce genre paraît dans plusieurs dossiers (score.rs).
pub(crate) fn note_de_rancon(nom: &str) -> bool {
    let bas = nom.to_ascii_lowercase();
    let extension_texte = bas
        .rsplit_once('.')
        .is_some_and(|(_, e)| matches!(e, "txt" | "html" | "htm" | "hta"));
    if !extension_texte {
        return false;
    }
    let normalise: String = bas.chars().filter(char::is_ascii_alphanumeric).collect();
    MOTS_DE_RANCON
        .iter()
        .any(|m| normalise.contains(&m.chars().filter(char::is_ascii_alphanumeric).collect::<String>()))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_ajoutee_reconnue() {
        assert_eq!(
            extension_ajoutee("rapport.docx", "rapport.docx.locked").as_deref(),
            Some("locked")
        );
        assert_eq!(
            extension_ajoutee("photo.jpg", "photo.jpg.CRYPT").as_deref(),
            Some("crypt")
        );
        assert_eq!(extension_ajoutee("a.txt", "b.txt.x"), None);
        assert_eq!(extension_ajoutee("a.txt", "a.txt"), None);
        assert_eq!(extension_ajoutee("a", "a.b/c"), None);
    }

    #[test]
    fn extensions_connues_et_inconnues() {
        assert!(extension_connue("rapport.docx"));
        assert!(extension_connue("photo.JPG"));
        assert!(extension_connue("Makefile"));
        assert!(extension_connue(".bashrc"));
        assert!(!extension_connue("rapport.docx.locked"));
        assert!(!extension_connue("photo.jpg.wannacry"));
    }

    #[test]
    fn noms_au_hasard() {
        assert!(nom_au_hasard("7Gq3xZ9pLmTkWvQr.xyz"));
        assert!(!nom_au_hasard("rapport-final-2024.docx"));
        assert!(!nom_au_hasard("court.txt"));
        assert!(!nom_au_hasard("aaaaaaaaaaaaaaaaaaaa.txt"));
    }

    #[test]
    fn notes_de_rancon() {
        assert!(note_de_rancon("HOW_TO_DECRYPT.txt"));
        assert!(note_de_rancon("RESTORE-MY-FILES.html"));
        assert!(note_de_rancon("readme.hta"));
        assert!(!note_de_rancon("README.md"));
        assert!(!note_de_rancon("rapport.docx"));
        assert!(!note_de_rancon("decrypt.rs"));
    }
}
