//! Ce que dit un nom (celui du fichier, ou le chemin d'une entrée dans une archive) : caractères qui retournent
//! l'écriture (U+202E et ses semblables : « facture[U+202E]fdp.exe » s'affiche « factureexe.pdf »), double extension
//! (« .pdf.exe »), blancs qui repoussent la vraie extension hors de la vue, points et espaces finaux que Windows
//! retire, caractères de contrôle, chemin qui sort de l'archive (« ../ ») ou absolu. Des FAITS pour les heuristiques
//! (AV4), jamais un verdict à eux seuls.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Un fait relevé dans un nom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FaitNom {
    /// Un caractère de contrôle de la direction d'écriture (U+202A à U+202E, U+2066 à U+2069, U+200E, U+200F).
    Bidi(char),
    /// « .pdf.exe » : une extension de document suivie d'une extension de programme.
    DoubleExtension { avant: String, extension: String },
    /// Une suite de blancs juste avant l'extension (« facture.pdf          .exe »).
    BlancsAvantExtension,
    /// Des points ou des espaces en fin de nom, que Windows retire à l'ouverture.
    FinDeNom,
    /// Des caractères de contrôle (sauts de ligne, tabulations…) dans le nom.
    Controle,
    /// Un composant « .. » : l'entrée s'écrirait hors du dossier où l'archive est extraite.
    CheminSortant,
    /// Un chemin absolu (« /etc/… », « C:\… », « \\serveur\… »).
    CheminAbsolu,
}

/// Extensions de programmes, de scripts et de raccourcis : ce qui s'exécute quand on l'ouvre.
pub(crate) const PROGRAMMES: &[&str] = &[
    "exe",
    "scr",
    "com",
    "pif",
    "bat",
    "cmd",
    "msi",
    "msix",
    "msp",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "hta",
    "ps1",
    "psm1",
    "jar",
    "lnk",
    "url",
    "scf",
    "cpl",
    "msc",
    "reg",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "dll",
    "sys",
    "apk",
    "app",
    "sh",
    "run",
    "bin",
    "elf",
    "appimage",
    "dmg",
    "pkg",
    "command",
    "desktop",
    "chm",
    "xll",
    "iqy",
    "slk",
    "appref-ms",
    "one",
];

/// Extensions de documents, d'images et de médias : un programme qui en porte une se déguise.
pub(crate) const DOCUMENTS: &[&str] = &[
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods", "odp", "rtf", "txt",
    "csv", "jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "svg", "mp3", "mp4", "avi", "mkv", "mov", "wav", "zip",
    "rar", "7z", "html", "htm", "eml", "msg",
];

/// L'extension du dernier composant de `chemin`, en minuscules, sans blancs ni points finaux.
pub(crate) fn extension(chemin: &str) -> Option<String> {
    let dernier = chemin.rsplit(['/', '\\']).next().unwrap_or(chemin);
    let propre = dernier.trim_end_matches(['.', ' ']);
    let (avant, ext) = propre.rsplit_once('.')?;
    (!avant.is_empty() || dernier.starts_with('.'))
        .then(|| ext.trim().to_lowercase())
        .filter(|e| !e.is_empty())
}

/// Les faits de `chemin`.
pub(crate) fn examiner(chemin: &str) -> Vec<FaitNom> {
    let mut faits = Vec::new();
    if let Some(c) = chemin
        .chars()
        .find(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'))
    {
        faits.push(FaitNom::Bidi(c));
    }
    if chemin.chars().any(char::is_control) {
        faits.push(FaitNom::Controle);
    }
    let composants: Vec<&str> = chemin.split(['/', '\\']).collect();
    if composants.contains(&"..") {
        faits.push(FaitNom::CheminSortant);
    }
    let octets = chemin.as_bytes();
    if chemin.starts_with('/')
        || chemin.starts_with('\\')
        || matches!(octets, [lecteur, b':', ..] if lecteur.is_ascii_alphabetic())
    {
        faits.push(FaitNom::CheminAbsolu);
    }
    let dernier = composants.last().copied().unwrap_or("");
    if dernier.len() > 1
        && (dernier.ends_with('.') || dernier.ends_with(' '))
        && !dernier.trim_matches(['.', ' ']).is_empty()
    {
        faits.push(FaitNom::FinDeNom);
    }
    // Les morceaux entre les points, blancs autour retirés : « facture.pdf .exe » reste une double extension.
    let propre = dernier.to_lowercase();
    let propre = propre.trim_end_matches(['.', ' ']);
    let morceaux: Vec<&str> = propre.split('.').collect();
    // Au moins trois morceaux : un nom, puis les deux extensions.
    if let [_, .., avant, extension] = morceaux.as_slice() {
        let (avant, extension) = (avant.trim(), extension.trim());
        if DOCUMENTS.contains(&avant) && PROGRAMMES.contains(&extension) {
            faits.push(FaitNom::DoubleExtension {
                avant: avant.to_string(),
                extension: extension.to_string(),
            });
        }
    }
    if let Some((avant, _)) = propre.rsplit_once('.')
        && avant.chars().rev().take_while(|c| c.is_whitespace()).count() >= 3
    {
        faits.push(FaitNom::BlancsAvantExtension);
    }
    faits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faits_des_noms() {
        assert_eq!(
            examiner("facture.pdf.exe"),
            [FaitNom::DoubleExtension {
                avant: "pdf".into(),
                extension: "exe".into()
            }]
        );
        assert_eq!(examiner("photo\u{202e}gpj.scr"), [FaitNom::Bidi('\u{202e}')]);
        let rembourre = examiner("facture.pdf          .exe");
        assert!(rembourre.contains(&FaitNom::BlancsAvantExtension));
        assert!(rembourre.iter().any(|f| matches!(f, FaitNom::DoubleExtension { .. })));
        assert_eq!(examiner("programme.exe. . "), [FaitNom::FinDeNom]);
        assert_eq!(examiner("../../.bashrc"), [FaitNom::CheminSortant]);
        assert_eq!(examiner("..\\Démarrage\\a.lnk"), [FaitNom::CheminSortant]);
        assert_eq!(examiner("/etc/cron.d/x"), [FaitNom::CheminAbsolu]);
        assert_eq!(examiner("C:\\Users\\alice\\a.txt"), [FaitNom::CheminAbsolu]);
        assert_eq!(examiner("a\nb.txt"), [FaitNom::Controle]);
        assert_eq!(examiner("rapport.final.docx"), []);
        assert_eq!(examiner("setup.exe"), []);
        assert!(examiner("..").contains(&FaitNom::CheminSortant));
        assert_eq!(examiner(""), []);
        assert_eq!(extension("dossier/Facture.PDF.exe. ").as_deref(), Some("exe"));
        assert_eq!(extension("sans"), None);
        assert_eq!(extension(".bashrc").as_deref(), Some("bashrc"));
    }
}
