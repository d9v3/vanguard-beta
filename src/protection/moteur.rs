//! Le moteur d'analyse d'un fichier, commun aux analyses à la demande, et son verdict. Le fichier est lu une seule
//! fois par le socle d'analyse (`analyse::analyser_fichier`), qui le découpe en parties (lui-même, les entrées de ses
//! archives, les flux d'un document OLE, la source de ses macros, les octets ajoutés après un exécutable…), et chaque
//! partie passe à toutes les sources pendant cette lecture : empreintes de MalwareBazaar, règles YARA, signatures
//! ClamAV (empreintes, sections, corps, logiques, listes blanches), marque d'essai EICAR (P23) et heuristiques. Un
//! programme caché dans un zip, ou une macro compressée dans un document Office, est vu comme s'il était seul.
//!
//! Le verdict (`Verdict`) : « certain » (un contenu exact connu : empreinte, ou la marque d'essai dans un exécutable),
//! « famille » (une règle YARA, une signature de corps ou logique de ClamAV), « suspect » (des heuristiques seules,
//! jamais de geste automatique), « sain » (tout lu, toutes les sources attendues présentes ; les sources facultatives
//! absentes restent dites en réserve) ou « non vérifié » (avec ses raisons) : ce que le socle n'a pas pu lire (format
//! reconnu mais non ouvert, chiffré, coupé, borne atteinte) ou une source attendue qui manque n'est jamais compté
//! sain.
//!
//! Le veilleur et le garde (P21, P22) n'ont que l'empreinte d'un fichier : `juger_empreintes`, sans lecture de
//! format.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::path::Path;
#[cfg(not(test))]
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::analyse::{self, Bornes, Partie, Raison, Type};
use crate::protection::clamav::base::{self, Base, Designation, Juge};
use crate::protection::clamav::signatures::Mode;
#[cfg(not(test))]
use crate::protection::clamav::signatures::Options;
use crate::protection::empreintes::{self, Empreintes};
use crate::protection::heuristiques::{self, Heuristique, Lieu, Signe};
use crate::protection::moteur_yara::Regles;
use crate::protection::sources::porte_la_marque_d_essai;
use crate::{tr, trf};

/// Un manque du socle qui laisse une partie non vérifiée. Ni un format inconnu (ses octets sont passés tels quels aux
/// règles, comme avant le socle), ni une « quine » (le contenu, égal à l'un de ses ancêtres, a déjà été vérifié).
pub(crate) fn laisse_non_verifie(raison: &Raison) -> bool {
    !matches!(raison, Raison::FormatInconnu | Raison::Quine)
}

/// Le nom d'un format reconnu que Vanguard n'ouvre pas.
fn nom_du_format(t: Type) -> &'static str {
    match t {
        Type::ExecutableDos => tr!("programme DOS ou 16 bits", "DOS or 16-bit program"),
        Type::ClasseJava => tr!("classe Java", "Java class"),
        Type::PresentationPowerPoint => "PowerPoint",
        Type::SeptZip => "7z",
        Type::Rar => "RAR",
        Type::Cab => "CAB",
        Type::Iso => "ISO",
        Type::Bzip2 => "bzip2",
        Type::Xz => "xz",
        Type::Zstd => "zstd",
        Type::Lzip => "lzip",
        Type::Pdf => "PDF",
        Type::Rtf => "RTF",
        Type::OneNote => "OneNote",
        Type::Chm => "CHM",
        Type::Wim => "WIM",
        Type::DisqueVirtuel => tr!("disque virtuel", "virtual disk"),
        Type::Dmg => "DMG",
        Type::Xar => "XAR",
        Type::Ar => "ar",
        Type::Rpm => "RPM",
        Type::Cpio => "cpio",
        Type::SquashFs => "SquashFS",
        _ => tr!("ce format", "this format"),
    }
}

/// Un manque, en quelques mots.
pub(crate) fn raison(r: &Raison) -> String {
    match r {
        Raison::FormatInconnu => tr!("format inconnu", "unknown format").into(),
        Raison::FormatNonLu(t) => trf!("contenu {} non ouvert", "{} content not opened", nom_du_format(*t)),
        Raison::Chiffre => tr!("chiffré", "encrypted").into(),
        Raison::Tronque => tr!("coupé", "truncated").into(),
        Raison::Illisible(quoi) => trf!("structure illisible ({quoi})", "unreadable structure ({quoi})"),
        Raison::Methode(m) => trf!("méthode de compression {m} non lue", "compression method {m} not read"),
        Raison::TropGros => tr!("trop gros", "too large").into(),
        Raison::Profondeur => tr!("trop d'archives imbriquées", "too many nested archives").into(),
        Raison::TropDeParties => tr!("trop de parties", "too many parts").into(),
        Raison::Production => tr!("trop d'octets décompressés", "too many decompressed bytes").into(),
        Raison::TauxDeCompression => tr!("taux de compression d'une bombe", "compression ratio of a bomb").into(),
        Raison::Quine => tr!("se contient lui-même", "contains itself").into(),
        Raison::Delai => tr!("trop long à lire", "too slow to read").into(),
        Raison::EntreesLimitees => tr!("trop d'entrées", "too many entries").into(),
        Raison::CibleNonDecodee => tr!("cible du raccourci non décodée", "shortcut target not decoded").into(),
        Raison::SourceVbaIllisible => tr!("source de macro illisible", "unreadable macro source").into(),
        Raison::Travail => tr!("trop d'octets à examiner", "too many bytes to examine").into(),
        Raison::MacrosXlmNonDecodees => tr!("macros Excel 4.0 non décodées", "Excel 4.0 macros not decoded").into(),
        Raison::Paquete(p) => trf!("compressé par {p}, code non lu", "packed with {p}, code not read"),
        Raison::FinIntrouvable => tr!("fin du format introuvable", "end of format not found").into(),
        Raison::PcodeNonLu => tr!("code compilé de macro non lu", "compiled macro code not read").into(),
    }
}

/// Ce qui a reconnu un fichier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    EmpreinteMalwareBazaar,
    /// Une empreinte de fichier entier de la base ClamAV (.hdb, .hsb).
    EmpreinteClamav,
    Yara,
    /// Une signature de corps, de section ou logique de la base ClamAV (.ndb, .mdb, .ldb…).
    ClamavCorps,
    Heuristique,
    /// La marque d'essai EICAR dans un exécutable (P23).
    EssaiEicar,
}

impl Source {
    /// Son code stable (`--json`, journal).
    pub(crate) fn id(self) -> &'static str {
        match self {
            Source::EmpreinteMalwareBazaar => "malwarebazaar",
            Source::EmpreinteClamav => "clamav-empreinte",
            Source::Yara => "yara",
            Source::ClamavCorps => "clamav-corps",
            Source::Heuristique => "heuristique",
            Source::EssaiEicar => "essai-eicar",
        }
    }

    pub(crate) fn nom(self) -> &'static str {
        match self {
            Source::EmpreinteMalwareBazaar => tr!("empreinte MalwareBazaar", "MalwareBazaar fingerprint"),
            Source::EmpreinteClamav => tr!("empreinte ClamAV", "ClamAV fingerprint"),
            Source::Yara => tr!("règle YARA", "YARA rule"),
            Source::ClamavCorps => tr!("signature ClamAV", "ClamAV signature"),
            Source::Heuristique => tr!("heuristique", "heuristic"),
            Source::EssaiEicar => tr!("essai EICAR", "EICAR test"),
        }
    }

    /// Une source qui reconnaît un contenu exact : son verdict est certain. Les autres décrivent une famille.
    pub(crate) fn certaine(self) -> bool {
        matches!(
            self,
            Source::EmpreinteMalwareBazaar | Source::EmpreinteClamav | Source::EssaiEicar
        )
    }
}

/// Le début du nom d'une correspondance par empreinte de MalwareBazaar : « `MalwareBazaar sha256:<empreinte>` ».
pub(crate) const MALWAREBAZAAR: &str = "MalwareBazaar sha256:";

/// Le nom donné à la marque d'essai trouvée.
pub(crate) const NOM_EICAR: &str = "EICAR-Test-File";

/// Le verdict sur un fichier, du plus grave au plus rassurant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Un contenu exact reconnu : la quarantaine est proposée (automatique seulement selon les réglages du blocage).
    Certain(Source, String),
    /// Une famille reconnue : la quarantaine est proposée, en un geste de la personne.
    Famille(Source, String),
    /// Des heuristiques seules : dit, aucun geste automatique.
    Suspect(Vec<Heuristique>),
    /// Tout lu par toutes les sources attendues, rien trouvé.
    Sain,
    /// Rien trouvé, mais une partie ou une source manquait : jamais compté sain.
    NonVerifie(Vec<String>),
}

impl Verdict {
    /// Son code stable (`--json`, journal).
    pub(crate) fn id(&self) -> &'static str {
        match self {
            Verdict::Certain(..) => "certain",
            Verdict::Famille(..) => "famille",
            Verdict::Suspect(_) => "suspect",
            Verdict::Sain => "sain",
            Verdict::NonVerifie(_) => "non-verifie",
        }
    }
}

/// Une reconnaissance par une source de signatures (pas une heuristique), dans une partie du fichier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Trouvaille {
    pub source: Source,
    /// Le nom de la règle, de la signature, ou l'empreinte (« MalwareBazaar sha256:… »).
    pub nom: String,
    /// La partie, depuis le fichier (« archive.zip › programme.exe »), telle que son auteur l'a nommée : à rendre
    /// inoffensive avant de l'afficher.
    pub partie: String,
}

/// Un signe d'une heuristique dans une partie du fichier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Indice {
    pub heuristique: Heuristique,
    /// Ce qui l'a levée, en données brutes (section, extension, interpréteur, marque).
    pub detail: String,
    pub partie: String,
    /// La clé « normales » qui la fait taire (`heuristique|<code>|sha256:<empreinte de la partie>`) : liée au contenu
    /// exact. `None` : la partie n'a pas d'empreinte (non lue), l'indice ne se tait pas.
    pub cle: Option<String>,
}

impl Indice {
    /// Ce que l'heuristique a vu, en une phrase.
    pub(crate) fn texte(&self) -> String {
        let d = crate::ui::affichable(&self.detail);
        match self.heuristique {
            Heuristique::PeNonSigne if d.is_empty() => tr!(
                "programme Windows sans signature, dans un dossier temporaire ou de téléchargement",
                "unsigned Windows program, in a temporary or download folder"
            )
            .into(),
            Heuristique::PeNonSigne => tr!(
                "programme Windows à la signature illisible, dans un dossier temporaire ou de téléchargement",
                "Windows program with an unreadable signature, in a temporary or download folder"
            )
            .into(),
            Heuristique::EcrivableExecutable => trf!(
                "code écrivable et exécutable à la fois ({d})",
                "code both writable and executable ({d})"
            ),
            Heuristique::Paqueteur => trf!("code compressé ou chiffré ({d})", "packed or encrypted code ({d})"),
            Heuristique::NomTrompeur => trf!(
                "nom qui trompe sur la nature du fichier ({d})",
                "name that misleads about the file type ({d})"
            ),
            Heuristique::MacroAOuverture => trf!(
                "macro Office lancée à l'ouverture ({d})",
                "Office macro run on opening ({d})"
            ),
            Heuristique::PowerShellEncode => {
                trf!("commande PowerShell encodée ({d})", "encoded PowerShell command ({d})")
            }
            Heuristique::Telechargeur => trf!(
                "télécharge puis lance un programme ({d})",
                "downloads then runs a program ({d})"
            ),
            Heuristique::RaccourciInterpreteur => trf!(
                "raccourci qui lance un interpréteur ({d})",
                "shortcut that launches an interpreter ({d})"
            ),
        }
    }
}

/// Ce que le moteur a vu dans un fichier lu.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Resultat {
    /// Les reconnaissances des sources de signatures, chacune une fois.
    pub trouvailles: Vec<Trouvaille>,
    /// Les signes des heuristiques, hors ceux déclarés normaux.
    pub indices: Vec<Indice>,
    /// Les signes tus par une alerte déclarée normale (`normales`).
    pub tus: usize,
    /// Ce qui n'a pas été lu, une phrase par manque (« archive.zip › doc.pdf : contenu PDF non ouvert »), prête à
    /// montrer. Vide : tout le fichier a été lu.
    pub non_verifie: Vec<String>,
    /// Les sources attendues qui manquaient (règles YARA refusées…) : rien n'est sain sans elles.
    pub manquantes: Vec<String>,
    /// Les sources facultatives absentes (base ClamAV, empreintes de MalwareBazaar) : dites avec un verdict sain.
    pub reserves: Vec<String>,
    /// L'empreinte SHA-256 du fichier, s'il a été lu.
    pub sha256: Option<[u8; 32]>,
}

impl Resultat {
    /// Le verdict : certain, puis famille, puis suspect, puis non vérifié, puis sain.
    pub(crate) fn verdict(&self) -> Verdict {
        if let Some(t) = self.trouvailles.iter().find(|t| t.source.certaine()) {
            return Verdict::Certain(t.source, t.nom.clone());
        }
        if let Some(t) = self.trouvailles.first() {
            return Verdict::Famille(t.source, t.nom.clone());
        }
        if !self.indices.is_empty() {
            let mut h: Vec<Heuristique> = self.indices.iter().map(|i| i.heuristique).collect();
            h.sort_unstable();
            h.dedup();
            return Verdict::Suspect(h);
        }
        if !self.manquantes.is_empty() || !self.non_verifie.is_empty() {
            return Verdict::NonVerifie(self.manquantes.iter().chain(&self.non_verifie).cloned().collect());
        }
        Verdict::Sain
    }

    /// Le résultat pour `--json` : le verdict et tout ce qui le fonde, ce qui manque compris (jamais un « sain » muet).
    pub(crate) fn json(&self) -> serde_json::Value {
        let verdict = self.verdict();
        let (source, nom) = match &verdict {
            Verdict::Certain(s, n) | Verdict::Famille(s, n) => (Some(s.id()), Some(n.clone())),
            _ => (None, None),
        };
        serde_json::json!({
            "verdict": verdict.id(),
            "source": source,
            "nom": nom,
            "sha256": self.sha256.as_ref().map(empreintes::hex),
            "trouvailles": self.trouvailles.iter().map(|t| serde_json::json!({
                "source": t.source.id(),
                "nom": t.nom,
                "partie": t.partie,
            })).collect::<Vec<_>>(),
            "heuristiques": self.indices.iter().map(|i| serde_json::json!({
                "code": i.heuristique.code(),
                "detail": i.detail,
                "partie": i.partie,
                "cle": i.cle,
            })).collect::<Vec<_>>(),
            "tus": self.tus,
            "non_verifie": self.non_verifie,
            "sources_manquantes": self.manquantes,
            "reserves": self.reserves,
        })
    }
}

/// Les sources d'une analyse. Construites une fois (`sources`), ou par les essais.
pub(crate) struct Sources<'a> {
    pub yara: Option<&'a Regles>,
    pub malwarebazaar: Option<&'a Empreintes>,
    pub clamav: Option<&'a Base>,
    pub heuristiques: bool,
    /// Le lieu du fichier pour les heuristiques ; `None` : déduit de son chemin.
    pub lieu: Option<Lieu>,
    /// Une alerte déclarée normale (`normales::est_normale`).
    pub normale: fn(&str) -> bool,
    pub manquantes: Vec<String>,
    pub reserves: Vec<String>,
}

/// L'usage d'une analyse, qui choisit la base ClamAV et les empreintes chargées (P21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Usage {
    /// À la demande : base ClamAV complète, empreintes de MalwareBazaar rafraîchies si besoin.
    ALaDemande,
    /// En continu (blocage) : empreintes ClamAV seules, empreintes de MalwareBazaar déjà gardées, rien téléchargé.
    EnContinu,
}

/// La base ClamAV de l'ordinateur, chargée une fois par lancement et par mode. Jamais sous `cfg(test)` : un essai ne
/// lit pas les données de l'ordinateur.
fn base_clamav(mode: Mode) -> Result<&'static Base, &'static str> {
    #[cfg(test)]
    {
        let _ = mode;
        Err(tr!(
            "base ClamAV non lue par les essais",
            "ClamAV database not read by tests"
        ))
    }
    #[cfg(not(test))]
    {
        static COMPLETE: OnceLock<Result<Base, String>> = OnceLock::new();
        static COMPLETE_PUA: OnceLock<Result<Base, String>> = OnceLock::new();
        static EMPREINTES: OnceLock<Result<Base, String>> = OnceLock::new();
        // P20 : les PUA seulement à la demande, et si la personne l'a choisi ; jamais en continu (veilleur, garde),
        // où une empreinte connue met en quarantaine toute seule. Relu à chaque chargement : un choix changé dans
        // les Paramètres vaut à l'analyse suivante, même dans le même lancement.
        let pua = mode == Mode::Complete && crate::parametres::pua();
        let charger = || base::charger(Options { mode, pua }).map_err(|r| r.to_string());
        match (mode, pua) {
            (Mode::Complete, false) => COMPLETE.get_or_init(charger).as_ref().map_err(String::as_str),
            (Mode::Complete, true) => COMPLETE_PUA.get_or_init(charger).as_ref().map_err(String::as_str),
            (Mode::Empreintes, _) => EMPREINTES.get_or_init(charger).as_ref().map_err(String::as_str),
        }
    }
}

/// La base ClamAV des analyses à la demande, pour le détail de l'écran de l'antivirus : ce qu'elle ne lit pas,
/// compté par raison. La même que celle d'une analyse (chargée une fois par lancement).
pub(crate) fn base_a_la_demande() -> Result<&'static Base, &'static str> {
    base_clamav(Mode::Complete)
}

/// Les sources de Vanguard pour un usage : ce qui manque est rangé, attendu (règles YARA) ou en réserve (base ClamAV,
/// empreintes de MalwareBazaar, qui demandent une installation ou une clé).
pub(crate) fn sources(usage: Usage) -> Sources<'static> {
    let mut manquantes = Vec::new();
    let mut reserves = Vec::new();
    let yara = match crate::protection::yara::regles() {
        Ok(r) => {
            manquantes.extend(crate::protection::yara::non_verifiees(r));
            Some(r)
        }
        Err(e) => {
            manquantes.push(trf!("règles YARA inutilisables : {e}", "YARA rules unusable: {e}"));
            None
        }
    };
    let chargees = match usage {
        Usage::ALaDemande => empreintes::connues(),
        Usage::EnContinu => empreintes::gardees(),
    };
    let malwarebazaar = match chargees {
        Ok(e) => {
            reserves.extend(e.avertissement.clone());
            Some(e)
        }
        Err(raison) => {
            reserves.push(trf!(
                "empreintes de MalwareBazaar {raison}",
                "MalwareBazaar fingerprints {raison}"
            ));
            None
        }
    };
    let mode = match usage {
        Usage::ALaDemande => Mode::Complete,
        Usage::EnContinu => Mode::Empreintes,
    };
    let (clamav, manques_clamav) = clamav_et_manques(mode);
    reserves.extend(manques_clamav);
    if clamav.is_some() && mode == Mode::Empreintes {
        reserves.push(
            tr!(
                "base ClamAV : empreintes seules (analyse en continu)",
                "ClamAV database: fingerprints only (continuous scan)"
            )
            .into(),
        );
    }
    Sources {
        yara,
        malwarebazaar,
        clamav,
        heuristiques: true,
        lieu: None,
        normale: crate::protection::normales::est_normale,
        manquantes,
        reserves,
    }
}

/// La base ClamAV d'un usage et ce qui lui manque (base absente, refusée ou fichiers écartés), sans la note
/// « empreintes seules » du continu, qui est un choix (P21) et non un manque : le blocage le dit avec ses résultats.
pub(crate) fn reserves_clamav(usage: Usage) -> Vec<String> {
    let mode = match usage {
        Usage::ALaDemande => Mode::Complete,
        Usage::EnContinu => Mode::Empreintes,
    };
    clamav_et_manques(mode).1
}

fn clamav_et_manques(mode: Mode) -> (Option<&'static Base>, Vec<String>) {
    match base_clamav(mode) {
        Ok(b) => (
            Some(b),
            b.ecartes
                .iter()
                .map(|(nom, raison)| {
                    trf!(
                        "base ClamAV : {nom} écarté ({raison})",
                        "ClamAV database: {nom} skipped ({raison})"
                    )
                })
                .collect(),
        ),
        Err(raison) => (
            None,
            vec![trf!(
                "{raison} : empreintes, YARA et heuristiques seulement",
                "{raison}: fingerprints, YARA and heuristics only"
            )],
        ),
    }
}

/// Le lieu d'un fichier pour les heuristiques : le dossier des téléchargements, un dossier temporaire, ou ailleurs.
fn lieu_de(chemin: &Path) -> Lieu {
    let chemin = std::path::absolute(chemin).unwrap_or_else(|_| chemin.to_path_buf());
    if crate::protection::telechargement::dossier_telechargements().is_some_and(|d| chemin.starts_with(d)) {
        return Lieu::Telechargements;
    }
    #[cfg(unix)]
    let ailleurs = ["/tmp", "/var/tmp", "/dev/shm"];
    #[cfg(windows)]
    let ailleurs: [&str; 0] = [];
    if chemin.starts_with(std::env::temp_dir()) || ailleurs.iter().any(|t| chemin.starts_with(t)) {
        Lieu::Temporaire
    } else {
        Lieu::Ordinaire
    }
}

/// Le juge de la base ClamAV ; `None` en administrateur (P22). Les essais jugent aussi sous root (espace de noms).
#[cfg_attr(
    test,
    allow(clippy::unnecessary_wraps, reason = "hors essais, `None` en administrateur")
)]
fn juge(base: &Base) -> Option<Juge<'_>> {
    #[cfg(test)]
    return Some(Juge::sans_garde(base));
    #[cfg(not(test))]
    Juge::nouveau(base)
}

/// Ce qu'une source a relevé dans une partie, avant de savoir son numéro.
enum Releve {
    Trouvaille(Source, String),
    Signe(Signe),
}

/// Le fichier à `chemin`, lu une fois par le socle d'analyse, chaque partie passée à toutes les `sources`, le tout en
/// moins de `delai`. `Err` : le fichier n'a pas pu être lu (absent, illisible, lien, tube, pas un fichier ordinaire),
/// ou une source n'a pas fini à temps : rien n'est conclu. Une partie qui manque est dite dans `non_verifie`.
pub(crate) fn examiner(chemin: &Path, sources: &Sources<'_>, delai: Duration) -> Result<Resultat, ()> {
    examiner_par(chemin, sources, delai, &mut |bornes, visiteur| {
        analyse::analyser_fichier(chemin, bornes, visiteur)
    })
}

/// Comme [`examiner`], pour un fichier déjà ouvert par l'appelant (le veilleur l'ouvre sous le dossier qu'il
/// surveille, sans suivre de lien) ; `chemin` ne sert qu'à nommer et situer ce qui est trouvé, jamais à rouvrir.
#[cfg(target_os = "linux")]
pub(crate) fn examiner_ouvert(
    fichier: std::fs::File,
    chemin: &Path,
    sources: &Sources<'_>,
    delai: Duration,
) -> Result<Resultat, ()> {
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut fichier = Some(fichier);
    examiner_par(chemin, sources, delai, &mut |bornes, visiteur| {
        let f = fichier.take().ok_or_else(|| std::io::Error::other("fichier déjà lu"))?;
        analyse::analyser_ouvert(f, nom.clone(), bornes, visiteur)
    })
}

/// La lecture d'un fichier par le socle d'analyse, chaque partie passée au visiteur.
type Lire<'a> = dyn FnMut(&Bornes, &mut dyn FnMut(&Partie, &[u8])) -> std::io::Result<analyse::Analyse> + 'a;

fn examiner_par(chemin: &Path, sources: &Sources<'_>, delai: Duration, lire: &mut Lire<'_>) -> Result<Resultat, ()> {
    let echeance = Instant::now().checked_add(delai);
    let bornes = Bornes {
        delai,
        ..Bornes::default()
    };
    let lieu = sources.lieu.unwrap_or_else(|| lieu_de(chemin));
    let mut reserves = sources.reserves.clone();
    let mut juge = sources.clamav.and_then(juge);
    if sources.clamav.is_some() && juge.is_none() {
        reserves.push(base::Refus::Administrateur.to_string());
    }
    let mut releves: Vec<(Designation, Vec<Releve>)> = Vec::new();
    let mut echec = false;
    let mut visiteur = |p: &Partie, octets: &[u8]| {
        if echec {
            return;
        }
        let mut vus: Vec<Releve> = Vec::new();
        if let Some(regles) = sources.yara {
            let Ok(trouvees) = regles.analyser_tampon(octets, echeance) else {
                echec = true;
                return;
            };
            vus.extend(
                trouvees
                    .into_iter()
                    .map(|k| Releve::Trouvaille(Source::Yara, regles.nom(k).into())),
            );
        }
        if let (Some(e), Some(h)) = (sources.malwarebazaar, p.sha256.as_ref())
            && e.contient(h)
        {
            vus.push(Releve::Trouvaille(
                Source::EmpreinteMalwareBazaar,
                format!("{MALWAREBAZAAR}{}", empreintes::hex(h)),
            ));
        }
        if porte_la_marque_d_essai(octets) {
            vus.push(Releve::Trouvaille(Source::EssaiEicar, NOM_EICAR.into()));
        }
        if let Some(j) = juge.as_mut() {
            j.partie(p, octets, echeance);
        }
        if sources.heuristiques {
            vus.extend(heuristiques::juger(p, octets, lieu).into_iter().map(Releve::Signe));
        }
        if !vus.is_empty() {
            releves.push(((p.parent, p.chemin.clone(), p.sha256), vus));
        }
    };
    let analyse = lire(&bornes, &mut visiteur).map_err(|_| ())?;
    if echec {
        return Err(());
    }
    let (clamav, blanches) = match juge {
        Some(j) => j.conclure(&analyse)?,
        None => (Vec::new(), Vec::new()),
    };
    let mut r = Resultat {
        reserves,
        manquantes: sources.manquantes.clone(),
        sha256: analyse.parties.first().and_then(|p| p.sha256),
        ..Resultat::default()
    };
    // Une même reconnaissance une fois, dans la partie la plus profonde (les parties sont visitées avant leur
    // parent) : une archive stockée sans compression contient aussi les octets de son entrée.
    let mut ajouter = |t: Trouvaille| {
        if !r.trouvailles.iter().any(|v| v.source == t.source && v.nom == t.nom) {
            r.trouvailles.push(t);
        }
    };
    for t in clamav {
        ajouter(Trouvaille {
            source: if t.entiere {
                Source::EmpreinteClamav
            } else {
                Source::ClamavCorps
            },
            nom: t.nom,
            partie: t.partie,
        });
    }
    let mut signes: Vec<(usize, Signe)> = Vec::new();
    for (designation, vus) in releves {
        let Some(i) = base::numero(&analyse, &designation) else {
            continue;
        };
        for v in vus {
            match v {
                Releve::Trouvaille(source, nom) => ajouter(Trouvaille {
                    source,
                    nom,
                    partie: analyse.chemin_complet(i),
                }),
                Releve::Signe(s) => signes.push((i, s)),
            }
        }
    }
    // Un contenu que la liste blanche de la base ClamAV dit sain (son empreinte exacte) ne lève aucune heuristique.
    for (i, s) in signes {
        if base::sous_une_blanche(&analyse, &blanches, i) {
            continue;
        }
        let cle = designation_cle(s.heuristique, analyse.parties.get(i).and_then(|p| p.sha256));
        if cle.as_deref().is_some_and(sources.normale) {
            r.tus = r.tus.saturating_add(1);
            continue;
        }
        let indice = Indice {
            heuristique: s.heuristique,
            detail: s.detail,
            partie: analyse.chemin_complet(i),
            cle,
        };
        if !r.indices.contains(&indice) {
            r.indices.push(indice);
        }
    }
    for (i, raison_du_manque) in analyse.manques() {
        if laisse_non_verifie(raison_du_manque) && !base::sous_une_blanche(&analyse, &blanches, i) {
            let phrase = format!("{} : {}", analyse.chemin_complet(i), raison(raison_du_manque));
            if !r.non_verifie.contains(&phrase) {
                r.non_verifie.push(phrase);
            }
        }
    }
    Ok(r)
}

/// La clé « normales » d'un signe : l'heuristique et l'empreinte exacte de la partie.
fn designation_cle(h: Heuristique, sha256: Option<[u8; 32]>) -> Option<String> {
    sha256.map(|e| format!("heuristique|{}|sha256:{}", h.code(), empreintes::hex(&e)))
}

/// Le verdict d'un fichier dont on n'a que les empreintes (MD5, SHA-1, SHA-256) et la taille, sans lecture de format
/// (P22) : pour le veilleur et le garde (P21 : empreintes ClamAV seules). Certain s'il est connu ; sinon non vérifié,
/// jamais sain (son contenu n'a pas été lu). La marque d'essai, elle, se cherche en hachant (`sources::Guetteur`).
#[allow(
    dead_code,
    reason = "interface du veilleur et du garde, branchés sur le moment au lot AV5"
)]
pub(crate) fn juger_empreintes(
    e: &crate::protection::clamav::hashes::Empreintes,
    taille: u64,
    malwarebazaar: Option<&Empreintes>,
    clamav: Option<&Base>,
) -> Verdict {
    if malwarebazaar.is_some_and(|m| m.contient(&e.sha256)) {
        return Verdict::Certain(
            Source::EmpreinteMalwareBazaar,
            format!("{MALWAREBAZAAR}{}", empreintes::hex(&e.sha256)),
        );
    }
    if let Some(nom) = clamav.and_then(|b| b.signatures.par_empreintes(e, taille)) {
        return Verdict::Certain(Source::EmpreinteClamav, nom.to_string());
    }
    Verdict::NonVerifie(vec![
        tr!("contenu non lu : empreinte seule", "content not read: fingerprint only").into(),
    ])
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::heuristiques::corpus;

    fn essai() -> Regles {
        let r = Regles::compiler(
            r##"rule Programme { strings: $a = "#!/bin/sh" $b = "vanguard-essai-moteur" condition: $a at 0 and $b }
               rule Texte { strings: $a = "vanguard-essai-texte" condition: $a }"##,
        );
        assert_eq!(r.refus(), []);
        r
    }

    /// Des sources d'essai : rien ne manque, rien n'est déclaré normal, le lieu est ordinaire.
    fn sources_essai<'a>(
        yara: Option<&'a Regles>,
        malwarebazaar: Option<&'a Empreintes>,
        clamav: Option<&'a Base>,
    ) -> Sources<'a> {
        Sources {
            yara,
            malwarebazaar,
            clamav,
            heuristiques: true,
            lieu: Some(Lieu::Ordinaire),
            normale: |_| false,
            manquantes: Vec::new(),
            reserves: Vec::new(),
        }
    }

    fn examiner_octets(sources: &Sources<'_>, dossier: &Path, nom: &str, octets: &[u8]) -> Resultat {
        let f = dossier.join(nom);
        std::fs::write(&f, octets).unwrap();
        examiner(&f, sources, Duration::from_secs(30)).unwrap()
    }

    fn noms(r: &Resultat) -> Vec<&str> {
        r.trouvailles.iter().map(|t| t.nom.as_str()).collect()
    }

    fn sha256(octets: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(octets).into()
    }

    /// Un script caché dans un zip, compressé : la règle qui exige « #! » au début le trouve dans sa partie, pas dans
    /// les octets compressés du zip (famille) ; son empreinte, connue de MalwareBazaar, le rend certain, la partie
    /// nommée depuis l'archive.
    #[test]
    fn une_partie_cachee_dans_un_zip_est_vue() {
        let regles = essai();
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let programme = b"#!/bin/sh\necho vanguard-essai-moteur vanguard-essai-moteur vanguard-essai-moteur\n".to_vec();
        let zip = crate::archives::zip::essais::archive_controlee(&[
            ("facture.sh", 8, &programme),
            ("lisez-moi.txt", 0, b"rien"),
        ]);
        assert!(!zip.windows(21).any(|w| w == b"vanguard-essai-moteur"));
        let r = examiner_octets(&sources_essai(Some(&regles), None, None), &d, "colis.zip", &zip);
        assert_eq!(noms(&r), ["Programme"]);
        assert_eq!(r.trouvailles[0].partie, "colis.zip › facture.sh");
        assert_eq!(r.non_verifie, Vec::<String>::new());
        assert_eq!(r.verdict(), Verdict::Famille(Source::Yara, "Programme".into()));
        assert_eq!(r.sha256, Some(sha256(&zip)));
        let connues = Empreintes::depuis(vec![sha256(&programme)]);
        let r = examiner_octets(
            &sources_essai(Some(&regles), Some(&connues), None),
            &d,
            "colis.zip",
            &zip,
        );
        let nom = format!("{MALWAREBAZAAR}{}", empreintes::hex(&sha256(&programme)));
        assert_eq!(r.verdict(), Verdict::Certain(Source::EmpreinteMalwareBazaar, nom));
        assert!(r.trouvailles.iter().all(|t| t.partie == "colis.zip › facture.sh"));
        // Le même programme seul : vu aussi.
        let r = examiner_octets(&sources_essai(Some(&regles), None, None), &d, "facture.sh", &programme);
        assert_eq!(noms(&r), ["Programme"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ce qui n'est pas ouvert (un 7z dans un zip) est dit non vérifié, avec son chemin ; un format inconnu, lu tel
    /// quel, ne l'est pas : il est sain.
    #[test]
    fn un_contenu_non_ouvert_est_non_verifie() {
        let regles = essai();
        let sources = sources_essai(Some(&regles), None, None);
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let sept = b"7z\xBC\xAF\x27\x1C\x00\x04 rien".to_vec();
        let zip = crate::archives::zip::essais::archive_controlee(&[("archive.7z", 0, &sept)]);
        let r = examiner_octets(&sources, &d, "colis.zip", &zip);
        assert_eq!(r.non_verifie.len(), 1, "{:?}", r.non_verifie);
        assert!(
            r.non_verifie[0].contains("colis.zip › archive.7z") && r.non_verifie[0].contains("7z"),
            "{:?}",
            r.non_verifie
        );
        assert!(matches!(r.verdict(), Verdict::NonVerifie(raisons) if raisons == r.non_verifie));
        // Une trouvaille dans ce qui a été lu l'emporte, le manque reste dit.
        let sept = b"7z\xBC\xAF\x27\x1C\x00\x04 vanguard-essai-texte".to_vec();
        let zip = crate::archives::zip::essais::archive_controlee(&[("archive.7z", 0, &sept)]);
        let r = examiner_octets(&sources, &d, "colis.zip", &zip);
        assert_eq!(noms(&r), ["Texte"]);
        assert_eq!(r.non_verifie.len(), 1);
        let r = examiner_octets(&sources, &d, "donnees.bin", &[0x17_u8, 0x42, 0x99, 0x03, 0xEE, 0x10]);
        assert_eq!(r.verdict(), Verdict::Sain);
        assert_eq!(r.non_verifie, Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un lien, un tube, un fichier absent : rien n'est lu, et c'est une erreur, jamais un résultat vide.
    #[cfg(unix)]
    #[test]
    fn rien_de_lu_n_est_pas_un_constat() {
        let regles = essai();
        let sources = sources_essai(Some(&regles), None, None);
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let vrai = d.join("vrai.txt");
        std::fs::write(&vrai, b"vanguard-essai-texte").unwrap();
        let lien = d.join("lien.txt");
        std::os::unix::fs::symlink(&vrai, &lien).unwrap();
        let tube = d.join("tube");
        crate::essais::tube_nomme(&tube).unwrap();
        assert_eq!(
            noms(&examiner(&vrai, &sources, Duration::from_secs(30)).unwrap()),
            ["Texte"]
        );
        for cible in [lien, tube, d.join("absent")] {
            assert!(
                examiner(&cible, &sources, Duration::from_secs(30)).is_err(),
                "{}",
                cible.display()
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La marque d'essai (démasquée à l'exécution, P23) dans un exécutable : certain (essai). Dans un texte, ou sans
    /// tête d'exécutable : rien.
    #[test]
    fn la_marque_d_essai_dans_un_executable_est_certaine() {
        let sources = sources_essai(None, None, None);
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let mut elf = corpus::elf_sain();
        elf.extend(crate::protection::sources::marque_d_essai());
        let r = examiner_octets(&sources, &d, "essai", &elf);
        assert_eq!(r.verdict(), Verdict::Certain(Source::EssaiEicar, NOM_EICAR.into()));
        let mut texte = b"La chaine d'essai : ".to_vec();
        texte.extend(crate::protection::sources::marque_d_essai());
        assert_eq!(
            examiner_octets(&sources, &d, "note.txt", &texte).verdict(),
            Verdict::Sain
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La base ClamAV : une empreinte de fichier entier rend certain, une signature de corps une famille.
    #[test]
    fn la_base_clamav_rend_certain_ou_famille() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let base = crate::protection::clamav::base::essais::base(
            &d.join("base"),
            &[(b"contenu exact de l'essai", "Essai.Exact-1")],
            &[("Essai.Corps-1", b"marque-corps")],
        );
        let sources = sources_essai(None, None, Some(&base));
        let f = d.join("f");
        std::fs::create_dir(&f).unwrap();
        let r = examiner_octets(&sources, &f, "a", b"contenu exact de l'essai");
        assert_eq!(
            r.verdict(),
            Verdict::Certain(Source::EmpreinteClamav, "Essai.Exact-1".into())
        );
        let r = examiner_octets(&sources, &f, "b", b"xx marque-corps xx");
        assert_eq!(
            r.verdict(),
            Verdict::Famille(Source::ClamavCorps, "Essai.Corps-1".into())
        );
        assert_eq!(examiner_octets(&sources, &f, "c", b"rien").verdict(), Verdict::Sain);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une heuristique seule : suspect, avec sa clé liée au contenu ; déclarée normale, elle se tait (comptée).
    #[test]
    fn une_heuristique_rend_suspect_et_se_tait_par_sa_cle() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let elf = corpus::elf_wx();
        let r = examiner_octets(&sources_essai(None, None, None), &d, "outil", &elf);
        assert_eq!(r.verdict(), Verdict::Suspect(vec![Heuristique::EcrivableExecutable]));
        let cle = format!(
            "heuristique|ecrivable-executable|sha256:{}",
            empreintes::hex(&sha256(&elf))
        );
        assert_eq!(r.indices[0].cle.as_deref(), Some(cle.as_str()));
        assert_ne!(r.indices[0].texte(), "");
        let mut tue = sources_essai(None, None, None);
        tue.normale = |c| c.starts_with("heuristique|ecrivable-executable|sha256:");
        let r = examiner_octets(&tue, &d, "outil", &elf);
        assert_eq!((r.verdict(), r.tus), (Verdict::Sain, 1));
        // Sans heuristiques : rien.
        let mut sans = sources_essai(None, None, None);
        sans.heuristiques = false;
        assert_eq!(examiner_octets(&sans, &d, "outil", &elf).verdict(), Verdict::Sain);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le corpus fabriqué : chaque heuristique levée par le moteur sur un fichier entier, et les mêmes formats sains.
    #[test]
    fn corpus_fabrique() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let mut telecharge = sources_essai(None, None, None);
        telecharge.lieu = Some(Lieu::Telechargements);
        let ordinaire = sources_essai(None, None, None);
        let code = corpus::alea(4096);
        let sans_signature = corpus::pe(&[(".text", corpus::RX, &code[..64])], false);
        let signe = corpus::pe(&[(".text", corpus::RX, &code[..64])], true);
        let paquete = corpus::pe(&[(".text", corpus::RX, &code)], true);
        let cas: [(&Sources<'_>, &str, Vec<u8>, Option<Heuristique>); 10] = [
            (
                &telecharge,
                "setup.exe",
                sans_signature.clone(),
                Some(Heuristique::PeNonSigne),
            ),
            (&ordinaire, "setup.exe", sans_signature, None),
            (&telecharge, "setup.exe", signe.clone(), None),
            (&ordinaire, "outil.exe", paquete, Some(Heuristique::Paqueteur)),
            (&ordinaire, "facture.pdf.exe", signe, Some(Heuristique::NomTrompeur)),
            (
                &ordinaire,
                "rapport.doc",
                corpus::doc_a_macro("Sub AutoOpen()\r\nEnd Sub\r\n"),
                Some(Heuristique::MacroAOuverture),
            ),
            (
                &ordinaire,
                "rapport.doc",
                corpus::doc_a_macro("Sub Calcul()\r\nEnd Sub\r\n"),
                None,
            ),
            (
                &ordinaire,
                "photo.lnk",
                corpus::lnk(r"C:\Windows\System32\cmd.exe", Some("/c start x")),
                Some(Heuristique::RaccourciInterpreteur),
            ),
            (
                &ordinaire,
                "maj.ps1",
                format!(
                    "powershell -enc {}",
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAu"
                )
                .into_bytes(),
                Some(Heuristique::PowerShellEncode),
            ),
            (
                &ordinaire,
                "notes.txt",
                b"Liste des courses : pain, lait.".to_vec(),
                None,
            ),
        ];
        for (sources, nom, octets, attendue) in cas {
            let r = examiner_octets(sources, &d, nom, &octets);
            let h: Vec<Heuristique> = r.indices.iter().map(|i| i.heuristique).collect();
            if let Some(a) = attendue {
                assert!(h.contains(&a), "{nom} : {h:?}");
            } else {
                // Sans signe ni reconnaissance ; un document à macros garde son code compilé non lu (non vérifié).
                assert!(
                    r.indices.is_empty() && r.trouvailles.is_empty(),
                    "{nom} : {:?}",
                    r.indices
                );
                if nom != "rapport.doc" {
                    assert_eq!(r.verdict(), Verdict::Sain, "{nom}");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'ordre des verdicts, et « sain » jamais avec un manque : une source attendue absente rend non vérifié, une
    /// réserve reste dite avec le sain.
    #[test]
    fn ordre_des_verdicts() {
        let trouvaille = |source| Trouvaille {
            source,
            nom: "N".into(),
            partie: "p".into(),
        };
        let indice = Indice {
            heuristique: Heuristique::Paqueteur,
            detail: "UPX".into(),
            partie: "p".into(),
            cle: None,
        };
        let mut r = Resultat {
            trouvailles: vec![trouvaille(Source::Yara), trouvaille(Source::EmpreinteClamav)],
            indices: vec![indice.clone()],
            non_verifie: vec!["x".into()],
            manquantes: vec!["m".into()],
            ..Resultat::default()
        };
        assert_eq!(r.verdict(), Verdict::Certain(Source::EmpreinteClamav, "N".into()));
        r.trouvailles.remove(1);
        assert_eq!(r.verdict(), Verdict::Famille(Source::Yara, "N".into()));
        r.trouvailles.clear();
        assert_eq!(r.verdict(), Verdict::Suspect(vec![Heuristique::Paqueteur]));
        r.indices.clear();
        assert_eq!(r.verdict(), Verdict::NonVerifie(vec!["m".into(), "x".into()]));
        r.non_verifie.clear();
        assert_eq!(r.verdict(), Verdict::NonVerifie(vec!["m".into()]));
        r.manquantes.clear();
        r.reserves.push("base ClamAV absente".into());
        assert_eq!(r.verdict(), Verdict::Sain);
        assert_eq!(r.json()["reserves"][0], "base ClamAV absente");
        for s in [
            Source::EmpreinteMalwareBazaar,
            Source::EmpreinteClamav,
            Source::Yara,
            Source::ClamavCorps,
            Source::Heuristique,
            Source::EssaiEicar,
        ] {
            assert!(!s.nom().is_empty() && !s.id().is_empty());
        }
        for h in Heuristique::TOUTES {
            let i = Indice {
                heuristique: h,
                ..indice.clone()
            };
            assert!(i.texte().chars().count() > 10);
        }
    }

    /// Le `--json` dit le verdict et ce qui le fonde : un fichier non lu en entier n'y est jamais « sain ».
    #[test]
    fn le_json_dit_ce_qui_manque() {
        let r = Resultat {
            non_verifie: vec!["colis.zip › a.7z : contenu 7z non ouvert".into()],
            reserves: vec!["base ClamAV absente".into()],
            ..Resultat::default()
        };
        let j = r.json();
        assert_eq!(j["verdict"], "non-verifie");
        assert_eq!(j["non_verifie"][0], "colis.zip › a.7z : contenu 7z non ouvert");
        assert_eq!(j["source"], serde_json::Value::Null);
        let r = Resultat {
            trouvailles: vec![Trouvaille {
                source: Source::EssaiEicar,
                nom: NOM_EICAR.into(),
                partie: "essai".into(),
            }],
            ..Resultat::default()
        };
        let j = r.json();
        assert_eq!(
            (j["verdict"].as_str(), j["source"].as_str()),
            (Some("certain"), Some("essai-eicar"))
        );
    }

    /// L'interface du veilleur et du garde : certain par une empreinte connue, sinon non vérifié, jamais sain.
    #[test]
    fn juger_par_les_empreintes_seules() {
        use crate::protection::clamav::hashes::Empreintes as Hashes;
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let base = crate::protection::clamav::base::essais::base(&d, &[(b"contenu clamav", "Essai.Exact-1")], &[]);
        let mb = Empreintes::depuis(vec![sha256(b"contenu bazaar")]);
        let juger = |c: &[u8]| juger_empreintes(&Hashes::de(c), c.len() as u64, Some(&mb), Some(&base));
        assert!(matches!(
            juger(b"contenu bazaar"),
            Verdict::Certain(Source::EmpreinteMalwareBazaar, _)
        ));
        assert_eq!(
            juger(b"contenu clamav"),
            Verdict::Certain(Source::EmpreinteClamav, "Essai.Exact-1".into())
        );
        assert!(matches!(juger(b"autre"), Verdict::NonVerifie(r) if r.len() == 1));
        assert!(matches!(
            juger_empreintes(&Hashes::de(b"x"), 1, None, None),
            Verdict::NonVerifie(_)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le lieu se déduit du chemin : un dossier temporaire, ou ailleurs.
    #[test]
    fn le_lieu_vient_du_chemin() {
        #[cfg(unix)]
        assert_eq!(lieu_de(Path::new("/var/tmp/x/a.exe")), Lieu::Temporaire);
        #[cfg(unix)]
        assert_eq!(lieu_de(Path::new("/dev/shm/a")), Lieu::Temporaire);
        #[cfg(unix)]
        assert_eq!(lieu_de(Path::new("/usr/bin/ls")), Lieu::Ordinaire);
    }

    /// Chaque manque se dit, dans les deux langues, et seuls le format inconnu et la quine ne laissent rien de non
    /// vérifié.
    #[test]
    fn chaque_manque_se_dit() {
        for r in [
            Raison::FormatInconnu,
            Raison::FormatNonLu(Type::Pdf),
            Raison::Chiffre,
            Raison::Tronque,
            Raison::Illisible("en-tête"),
            Raison::Methode(14),
            Raison::TropGros,
            Raison::Profondeur,
            Raison::TropDeParties,
            Raison::Production,
            Raison::TauxDeCompression,
            Raison::Quine,
            Raison::Delai,
            Raison::EntreesLimitees,
            Raison::CibleNonDecodee,
            Raison::SourceVbaIllisible,
            Raison::Travail,
            Raison::MacrosXlmNonDecodees,
            Raison::Paquete("UPX"),
            Raison::FinIntrouvable,
            Raison::PcodeNonLu,
        ] {
            assert_ne!(raison(&r), "");
            assert_eq!(
                laisse_non_verifie(&r),
                !matches!(r, Raison::FormatInconnu | Raison::Quine)
            );
        }
        assert!(raison(&Raison::FormatNonLu(Type::SeptZip)).contains("7z"));
    }
}
