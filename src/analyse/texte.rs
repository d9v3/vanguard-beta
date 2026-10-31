//! Le texte et les scripts, reconnus par leur contenu : encodage (marque d'ordre UTF-8 ou UTF-16, UTF-16 sans marque
//! reconnu à ses octets nuls alternés, UTF-8, sinon octets pris un par un), texte borné, puis le langage DEVINÉ
//! (ligne « #! », sinon des marques propres à chaque langage : PowerShell, VBScript, JScript, lot de commandes,
//! HTML et HTA, XML et WSF, raccourci Internet). Deviner n'est pas juger : le langage est un fait, l'extension du nom
//! en est un autre, et les heuristiques (AV4) comparent les deux.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// L'encodage reconnu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encodage {
    Utf8,
    Utf8Bom,
    Utf16Le {
        bom: bool,
    },
    Utf16Be {
        bom: bool,
    },
    /// Ni UTF-8 ni UTF-16 : une page de code sur un octet (Windows-1252, ISO-8859-1…), lue octet par octet.
    UnOctet,
}

impl Encodage {
    pub(crate) fn utf16(self) -> bool {
        matches!(self, Encodage::Utf16Le { .. } | Encodage::Utf16Be { .. })
    }
}

/// Le langage deviné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Langage {
    PowerShell,
    VbScript,
    JScript,
    Batch,
    Shell,
    Python,
    Perl,
    Ruby,
    /// HTML, dont les applications HTA.
    Html,
    /// XML, dont les fichiers de script Windows (.wsf).
    Xml,
    /// `[InternetShortcut]` : un raccourci .url.
    RaccourciInternet,
    /// Un autre interpréteur nommé par « #! ».
    AutreInterpreteur,
    /// Du texte sans marque de langage.
    Texte,
}

/// Ce que dit un texte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Texte {
    pub encodage: Encodage,
    /// Le texte décodé, au plus la limite donnée (`tronque` sinon).
    pub contenu: String,
    pub tronque: bool,
    pub langage: Langage,
    /// L'interpréteur d'une ligne « #! ».
    pub interpreteur: Option<String>,
    pub lignes: usize,
    pub plus_longue_ligne: usize,
}

/// Ce qu'on regarde pour décider si c'est du texte et deviner son langage.
const ECHANTILLON: usize = 64 << 10;

/// `octets` lus comme du texte, au plus `limite` octets décodés. `None` : ce n'est pas du texte (octets nuls,
/// caractères de contrôle, UTF-8 invalide au-delà d'une page de code sur un octet plausible).
pub(crate) fn lire(octets: &[u8], limite: usize) -> Option<Texte> {
    let (encodage, corps) = if let Some(r) = octets.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        (Encodage::Utf8Bom, r)
    } else if let Some(r) = octets.strip_prefix(&[0xFF, 0xFE]) {
        (Encodage::Utf16Le { bom: true }, r)
    } else if let Some(r) = octets.strip_prefix(&[0xFE, 0xFF]) {
        (Encodage::Utf16Be { bom: true }, r)
    } else if let Some(gros) = utf16_sans_marque(octets) {
        (
            if gros {
                Encodage::Utf16Be { bom: false }
            } else {
                Encodage::Utf16Le { bom: false }
            },
            octets,
        )
    } else {
        (Encodage::Utf8, octets)
    };
    if corps.is_empty() && encodage == Encodage::Utf8 {
        return None;
    }
    let (texte, tronque, encodage) = match encodage {
        Encodage::Utf16Le { .. } | Encodage::Utf16Be { .. } => {
            let gros = matches!(encodage, Encodage::Utf16Be { .. });
            // Au plus `limite` unités (l'octet impair de la fin, sans paire, n'en est pas une).
            let toutes = corps.as_chunks::<2>().0;
            let paires = toutes.get(..limite).unwrap_or(toutes);
            let unites = paires.iter().map(|&p| {
                if gros {
                    u16::from_be_bytes(p)
                } else {
                    u16::from_le_bytes(p)
                }
            });
            let texte: String = char::decode_utf16(unites)
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect();
            let mut texte = texte;
            let coupe = texte.len() > limite;
            if coupe {
                texte.truncate(texte.floor_char_boundary(limite));
            }
            (texte, coupe || paires.len() < toutes.len(), encodage)
        }
        _ => {
            let tranche = corps.get(..limite).unwrap_or(corps);
            let n = tranche.len();
            match std::str::from_utf8(tranche) {
                Ok(t) => (t.to_string(), n < corps.len(), encodage),
                // Un caractère coupé par la limite seulement : de l'UTF-8 quand même.
                Err(e) if e.error_len().is_none() && n < corps.len() => (
                    String::from_utf8_lossy(tranche.get(..e.valid_up_to()).unwrap_or(tranche)).into_owned(),
                    true,
                    encodage,
                ),
                Err(_) => (
                    tranche.iter().map(|&o| char::from(o)).collect(),
                    n < corps.len(),
                    if encodage == Encodage::Utf8 {
                        Encodage::UnOctet
                    } else {
                        encodage
                    },
                ),
            }
        }
    };
    if !ressemble_a_du_texte(&texte) {
        return None;
    }
    let (langage, interpreteur) = deviner(&texte);
    let lignes = texte.lines().count();
    let plus_longue = texte.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    Some(Texte {
        encodage,
        contenu: texte,
        tronque,
        langage,
        interpreteur,
        lignes,
        plus_longue_ligne: plus_longue,
    })
}

/// De l'UTF-16 sans marque : dans les premiers octets, un octet sur deux nul (`Some(true)` : gros-boutiste).
fn utf16_sans_marque(octets: &[u8]) -> Option<bool> {
    let debut = octets.get(..1024).unwrap_or(octets).as_chunks::<2>().0;
    if debut.len() < 4 {
        return None;
    }
    let paires = debut.len();
    let nuls_impairs = debut.iter().filter(|p| p[1] == 0 && p[0] != 0).count();
    let nuls_pairs = debut.iter().filter(|p| p[0] == 0 && p[1] != 0).count();
    // Au moins 90 % des paires.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "au plus 512 paires (les 1 024 premiers octets) : ni n × 10 ni paires × 9 ne débordent"
    )]
    let presque_toutes = |n: usize| n * 10 >= paires * 9;
    if presque_toutes(nuls_impairs) {
        Some(false)
    } else if presque_toutes(nuls_pairs) {
        Some(true)
    } else {
        None
    }
}

/// Pas de nul, et au plus 1 % de caractères de contrôle (hors tabulation, retours, saut de page, échappement).
fn ressemble_a_du_texte(texte: &str) -> bool {
    // Tout le texte lu, pas un échantillon : du binaire après 64 Kio de texte n'en est pas.
    if texte.contains('\0') {
        return false;
    }
    let total = texte.chars().count();
    let controles = texte
        .chars()
        .filter(|&c| c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\x0c' | '\x1b'))
        .count();
    // controles × 100 ≤ total, sans multiplier.
    total > 0 && controles <= total / 100
}

/// Le langage, par la ligne « #! » puis par des marques.
fn deviner(texte: &str) -> (Langage, Option<String>) {
    if let Some(ligne) = texte.strip_prefix("#!") {
        let ligne = ligne.lines().next().unwrap_or("").trim();
        let mut mots = ligne.split_whitespace();
        let programme = mots.next().unwrap_or("");
        // « #!/usr/bin/env python3 » : le programme est le premier argument d'env.
        let nom = if programme.ends_with("/env") {
            mots.find(|m| !m.starts_with('-')).unwrap_or("")
        } else {
            programme
        };
        let base = nom.rsplit('/').next().unwrap_or(nom).to_ascii_lowercase();
        let langage = match base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.') {
            "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "busybox" => Langage::Shell,
            "python" => Langage::Python,
            "perl" => Langage::Perl,
            "ruby" => Langage::Ruby,
            "node" | "nodejs" | "deno" | "bun" => Langage::JScript,
            "pwsh" | "powershell" => Langage::PowerShell,
            _ => Langage::AutreInterpreteur,
        };
        return (langage, Some(ligne.to_string()));
    }
    let echantillon: String = texte.chars().take(ECHANTILLON).collect::<String>().to_ascii_lowercase();
    let debut = echantillon.trim_start();
    if debut.starts_with("[internetshortcut]") {
        return (Langage::RaccourciInternet, None);
    }
    let marques: &[(Langage, &[&str])] = &[
        (
            Langage::PowerShell,
            &[
                "$env:",
                "write-host",
                "invoke-",
                "new-object ",
                "-encodedcommand",
                "[system.",
                "get-",
                "set-",
                "$psscriptroot",
                "param(",
                "-erroraction",
                "[convert]::",
                "start-process",
                "$null",
            ],
        ),
        (
            Langage::VbScript,
            &[
                "wscript.",
                "createobject(",
                "dim ",
                "end sub",
                "end function",
                "on error resume next",
                "set ",
                "msgbox ",
                "chr(",
                "& vbcrlf",
            ],
        ),
        (
            Langage::JScript,
            &[
                "activexobject",
                "function(",
                "function ",
                "var ",
                "let ",
                "const ",
                "=>",
                "eval(",
                "string.fromcharcode",
                "document.",
                "wscript.createobject",
                "new activexobject",
            ],
        ),
        (
            Langage::Batch,
            &[
                "@echo off",
                "%~dp0",
                "setlocal",
                "goto ",
                "%comspec%",
                "rem ",
                "echo off",
                "%errorlevel%",
                "set /a",
            ],
        ),
        (
            Langage::Shell,
            &["#!/bin/", "export ", "fi\n", "then\n", "esac", "$(", "${"],
        ),
        (Langage::Python, &["import ", "def ", "__name__", "print("]),
    ];
    let mut meilleur = (Langage::Texte, 0usize);
    for (langage, liste) in marques {
        let score = liste.iter().filter(|m| echantillon.contains(*m)).count();
        if score > meilleur.1 {
            meilleur = (*langage, score);
        }
    }
    if debut.starts_with("<?xml") || debut.starts_with("<job") || debut.starts_with("<package") {
        return (Langage::Xml, None);
    }
    if debut.starts_with("<!doctype html") || debut.starts_with("<html") || echantillon.contains("<hta:application") {
        return (Langage::Html, None);
    }
    if meilleur.1 >= 2 {
        return (meilleur.0, None);
    }
    (Langage::Texte, None)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(t: &str, bom: bool) -> Vec<u8> {
        let mut v = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
        v.extend(t.encode_utf16().flat_map(u16::to_le_bytes));
        v
    }

    #[test]
    fn encodages() {
        let ps = "$env:TEMP\r\nWrite-Host 'bonjour'\r\nInvoke-Expression $x\r\n";
        for (octets, encodage) in [
            (ps.as_bytes().to_vec(), Encodage::Utf8),
            ([&[0xEF, 0xBB, 0xBF][..], ps.as_bytes()].concat(), Encodage::Utf8Bom),
            (utf16le(ps, true), Encodage::Utf16Le { bom: true }),
            (utf16le(ps, false), Encodage::Utf16Le { bom: false }),
        ] {
            let t = lire(&octets, 1 << 20).unwrap();
            assert_eq!(
                (t.encodage, t.langage, t.contenu.as_str()),
                (encodage, Langage::PowerShell, ps)
            );
            assert!(!t.tronque);
        }
        // UTF-16 gros-boutiste avec marque.
        let mut be = vec![0xFE, 0xFF];
        be.extend("@echo off\r\nset /a x=1\r\n".encode_utf16().flat_map(u16::to_be_bytes));
        let t = lire(&be, 1 << 20).unwrap();
        assert_eq!(
            (t.encodage, t.langage),
            (Encodage::Utf16Be { bom: true }, Langage::Batch)
        );
        // Windows-1252 : un octet par caractère.
        let t = lire(b"@echo off\r\nrem caf\xe9\r\n", 1 << 20).unwrap();
        assert_eq!((t.encodage, t.langage), (Encodage::UnOctet, Langage::Batch));
        assert!(t.contenu.contains("café"));
        // Pas du texte.
        assert!(lire(b"MZ\x90\x00\x03\x00\x00\x00", 1 << 20).is_none());
        assert!(lire(&[1, 2, 3, 4, 5, 6, 7, 8, 9], 1 << 20).is_none());
        assert!(lire(b"", 1 << 20).is_none());
    }

    #[test]
    fn langages_et_bornes() {
        let cas: &[(&str, Langage)] = &[
            ("#!/bin/sh\necho x\n", Langage::Shell),
            ("#!/usr/bin/env python3\nprint(1)\n", Langage::Python),
            ("#!/usr/bin/env -S node --x\n", Langage::JScript),
            (
                "Dim o\r\nSet o = CreateObject(\"WScript.Shell\")\r\n",
                Langage::VbScript,
            ),
            (
                "var s = new ActiveXObject(\"WScript.Shell\");\neval(x);\n",
                Langage::JScript,
            ),
            ("<html><head><HTA:APPLICATION id=a></head></html>", Langage::Html),
            (
                "<?xml version=\"1.0\"?><job><script language=\"VBScript\"></script></job>",
                Langage::Xml,
            ),
            (
                "[InternetShortcut]\r\nURL=file://exemple.invalid/a\r\n",
                Langage::RaccourciInternet,
            ),
            ("Bonjour,\nceci est une lettre.\n", Langage::Texte),
        ];
        for (t, langage) in cas {
            assert_eq!(lire(t.as_bytes(), 1 << 20).unwrap().langage, *langage, "{t}");
        }
        assert_eq!(
            lire(b"#!/usr/bin/env python3\n", 100).unwrap().interpreteur.as_deref(),
            Some("/usr/bin/env python3")
        );
        // La limite : coupé, et dit ; un caractère coupé par la limite ne fait pas passer l'UTF-8 pour autre chose.
        let t = lire("éééé".as_bytes(), 3).unwrap();
        assert!(t.tronque && t.encodage == Encodage::Utf8 && t.contenu == "é");
        let t = lire(&utf16le("abcdef", true), 2).unwrap();
        assert!(t.tronque && t.contenu == "ab");
        let long = format!("{}\nfin\n", "x".repeat(5000));
        let t = lire(long.as_bytes(), 1 << 20).unwrap();
        assert_eq!((t.lignes, t.plus_longue_ligne), (2, 5000));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..3000), limite in 0usize..4000) {
            if let Some(t) = lire(&octets, limite) {
                proptest::prop_assert!(t.contenu.len() <= limite.max(4) * 3);
            }
        }
    }
}
