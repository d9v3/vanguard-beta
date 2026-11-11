//! Les témoins d'une alerte : ce qu'un choix « c'est normal chez moi » déclare normal, relevé au bilan qui l'a
//! montrée. Pour une ligne de lancement : le fichier qui la porte (son contenu entier, et s'il est un lien, vers où) et
//! les fichiers qu'elle lance ou précharge (leur contenu). Le choix retient l'empreinte de l'ensemble (`empreinte`) :
//! un fichier changé ou remplacé, devenu un lien, un programme lancé changé, une ligne ajoutée ou une autre source
//! dans la même alerte, et l'empreinte n'est plus la même — l'alerte revient.
//!
//! Ce qui ne se relève pas (fichier illisible, trop gros, tube nommé, commande ambiguë, trop de lignes, caractère
//! invisible dans la ligne) donne `Temoins::Refuse` : l'alerte ne peut pas être déclarée normale, et la raison est
//! dite. Le relevé est borné avant de lire : un fichier ordinaire seulement (jamais un périphérique ouvert), une taille
//! par fichier et un budget par bilan (`Budget`).

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Sous Windows, aucune règle ne relève encore de témoins (les tâches et les clés Run restent reconnues à leur clé) :
// seul `Aucun` y sert, le reste attend.
#![cfg_attr(windows, allow(dead_code))]

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::{tr, trf};

/// Pourquoi une ligne ne se relève pas pour un choix « normal » : une phrase prête à montrer. Ce n'est pas une panne
/// de Vanguard : rien n'est noté au journal des erreurs, l'alerte reste seulement à corriger soi-même.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refus(pub String);

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Au plus autant de lignes dans une alerte qu'on peut déclarer normale : chacune est montrée avant le choix.
pub(crate) const TEMOINS_MAX: usize = 12;
/// Une ligne montrée plus longue est coupée (« … ») : son empreinte, elle, porte la ligne entière.
const LIGNE_MONTREE: usize = 300;
/// Au-delà, un fichier lancé n'est pas relu à chaque bilan : l'alerte ne peut pas être déclarée normale. La borne
/// annoncée (32 Mio, comme les fichiers examinés) : assez pour un shell ou python, pas pour node ou deno (plus de
/// 100 Mio), dont une ligne reste donc non déclarable ; jamais pour un fichier creux qui figerait le bilan.
#[cfg(unix)]
const TAILLE_MAX: u64 = 32 * 1024 * 1024;
/// Le budget d'un bilan : au plus autant de fichiers lancés relus, et d'octets lus pour eux. Au-delà, le relevé est
/// refusé sans lire : des centaines de lignes qui désignent de gros fichiers ne figent pas le bilan.
#[cfg(unix)]
const BUDGET_FICHIERS: usize = 96;
#[cfg(unix)]
const BUDGET_OCTETS: u64 = 512 * 1024 * 1024;
/// Un fichier lancé assez petit, et lisible comme du texte, se montre en entier avant le choix : ce qui est montré
/// est exactement ce qui a été haché (pas une relecture qu'on pourrait échanger entre les deux).
const APERCU_OCTETS: usize = 4096;
const APERCU_LIGNES: usize = 60;

/// Ce qu'un choix « normal » déclarerait normal.
#[derive(Clone, Debug, Default)]
pub enum Temoins {
    /// La règle ne relève rien : un choix la reconnaît à sa clé (ou son texte), comme avant ces témoins.
    #[default]
    Aucun,
    /// Chaque ligne signalée, avec ce qu'elle désigne.
    Releves(Vec<Temoin>),
    /// Ne peut pas être déclarée normale : pourquoi (déjà traduit, prêt à montrer).
    Refuse(String),
}

/// Un fichier qu'une ligne lance ou précharge, tel qu'il se montre.
#[derive(Clone, Debug)]
pub struct Cible {
    /// Le chemin (affichable).
    pub chemin: String,
    /// « sha256 … », « absent », « lien vers … ; sha256 … ».
    pub etat: String,
    /// Le contenu lui-même, ligne par ligne (affichable), pour un petit fichier texte.
    pub apercu: Option<Vec<String>>,
    /// Le fichier existe, mais son contenu ne se montre pas (trop long, pas du texte, caractère invisible) : il est
    /// lié par son empreinte seulement, et c'est dit.
    pub cache: bool,
}

/// La trace d'une ligne au moment d'un choix, gardée avec lui : quand l'alerte revient, chaque ligne se dit déjà
/// acceptée, nouvelle, ou changée (le fichier qui la porte, ou ce qu'elle lance). Pour le dire seulement : le choix
/// lui-même tient à l'empreinte de l'ensemble.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// D'où vient la ligne (sans son numéro) et son texte.
    pub ligne: String,
    /// Le fichier qui la porte.
    pub fichier: String,
    /// Ce qu'elle lance.
    pub cibles: String,
    /// Les fichiers d'ajout (drop-ins) de son unité, à part : un ajout se dit « ajout changé », pas « programme ».
    #[serde(default)]
    pub ajouts: String,
    /// Les variables des sessions liées (`[env]`), à part aussi.
    #[serde(default)]
    pub environnement: String,
    /// Ce que lancent les autres lignes Exec de son unité (« ExecStartPre=… → … »), à part : quand seule la cible
    /// d'une autre ligne change, celle-ci ne se dit pas « programme changé » (troisième vérification de la campagne E).
    #[serde(default)]
    pub autres: String,
}

/// Une ligne qui revient, comparée aux traces du choix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marque {
    DejaAcceptee,
    Nouvelle,
    FichierChange,
    ProgrammeChange,
    AutreLigneChangee,
    AjoutChange,
    EnvironnementChange,
}

impl Marque {
    pub fn libelle(self) -> &'static str {
        match self {
            Marque::DejaAcceptee => tr!("déjà acceptée", "already accepted"),
            Marque::Nouvelle => tr!("ligne nouvelle ou changée", "new or changed line"),
            Marque::FichierChange => tr!("fichier changé", "file changed"),
            Marque::ProgrammeChange => tr!("programme changé", "program changed"),
            Marque::AutreLigneChangee => tr!(
                "ce que lance une autre ligne Exec de l'unité a changé",
                "what another Exec line of the unit starts changed"
            ),
            Marque::AjoutChange => tr!("ajout de l'unité changé", "unit drop-in changed"),
            Marque::EnvironnementChange => tr!("variable des sessions changée", "session variable changed"),
        }
    }
}

/// Une ligne signalée, telle qu'elle sera montrée avant le choix, et son empreinte.
#[derive(Clone, Debug)]
pub struct Temoin {
    /// « ~/.config/systemd/user/x.service:6 », « crontab:3 », « LD_PRELOAD de cette session » (affichable).
    pub ou: String,
    /// La ligne (affichable, coupée).
    pub ligne: String,
    /// Le fichier qui la porte : « sha256 … », « lien vers … ; sha256 … » ; `None` : pas un fichier.
    pub contenant: Option<String>,
    /// Les fichiers qu'elle lance ou précharge.
    pub cibles: Vec<Cible>,
    pub trace: Trace,
    empreinte: [u8; 32],
    /// Ce que le système disait des fichiers au relevé (`Vu`) : comparé au moment de confirmer.
    vus: [u8; 32],
    /// La ligne ne se montre pas en entier (plus de `LIGNE_MONTREE` colonnes) : ce qui passe la coupure ne serait
    /// pas vu avant le choix.
    coupee: bool,
    /// La ligne a un caractère que l'écran ne montre pas tel quel (invisible, blanc inhabituel, contrôle) : ce qui
    /// est montré ne serait pas ce que lisent systemd ou le shell.
    trompeuse: bool,
}

impl Temoin {
    /// Cette ligne, comparée aux traces d'un choix.
    pub fn marque(&self, traces: &[Trace]) -> Marque {
        let Some(t) = traces.iter().find(|t| t.ligne == self.trace.ligne) else {
            return Marque::Nouvelle;
        };
        if t.fichier != self.trace.fichier {
            Marque::FichierChange
        } else if t.cibles != self.trace.cibles {
            Marque::ProgrammeChange
        } else if t.autres != self.trace.autres {
            Marque::AutreLigneChangee
        } else if t.ajouts != self.trace.ajouts {
            Marque::AjoutChange
        } else if t.environnement != self.trace.environnement {
            Marque::EnvironnementChange
        } else {
            Marque::DejaAcceptee
        }
    }
}

impl Temoins {
    /// L'empreinte de l'ensemble (64 chiffres hexadécimaux), indépendante de l'ordre de lecture ; `None` sans relevé.
    pub fn empreinte(&self) -> Option<String> {
        let Temoins::Releves(liste) = self else {
            return None;
        };
        let mut e: Vec<[u8; 32]> = liste.iter().map(|t| t.empreinte).collect();
        e.sort_unstable();
        e.dedup();
        let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 temoins d'une alerte v2");
        h.update(&u64::try_from(e.len()).unwrap_or(u64::MAX).to_le_bytes());
        for x in &e {
            h.update(x);
        }
        Some(h.finalize().to_hex().to_string())
    }

    /// L'empreinte de ce que le système disait des fichiers (`Vu`) : deux relevés au même contenu, mais dont un fichier
    /// a été touché entre les deux (échangé puis remis), diffèrent ici.
    pub fn vus(&self) -> Option<String> {
        let Temoins::Releves(liste) = self else {
            return None;
        };
        let mut e: Vec<[u8; 32]> = liste.iter().map(|t| t.vus).collect();
        e.sort_unstable();
        e.dedup();
        let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 vus d'une alerte");
        for x in &e {
            h.update(x);
        }
        Some(h.finalize().to_hex().to_string())
    }

    /// Les lignes relevées, sans double (une ligne lue deux fois compte une fois).
    pub fn lignes(&self) -> Vec<&Temoin> {
        let Temoins::Releves(liste) = self else {
            return Vec::new();
        };
        let mut vus: Vec<[u8; 32]> = Vec::new();
        liste
            .iter()
            .filter(|t| {
                let neuf = !vus.contains(&t.empreinte);
                vus.push(t.empreinte);
                neuf
            })
            .collect()
    }

    /// Les traces des lignes, à garder avec un choix.
    pub fn traces(&self) -> Vec<Trace> {
        self.lignes().iter().map(|t| t.trace.clone()).collect()
    }

    /// Les témoins d'une alerte à partir de chaque ligne relevée : le premier refus l'emporte, et au-delà de
    /// `TEMOINS_MAX` lignes distinctes, l'alerte est trop chargée pour être montrée en entier avant le choix.
    pub(crate) fn de(releves: Vec<Result<Temoin, Refus>>) -> Temoins {
        let mut liste = Vec::with_capacity(releves.len());
        for r in releves {
            match r {
                Ok(t) if t.coupee => {
                    return Temoins::Refuse(trf!(
                        "la ligne {} est trop longue pour être montrée en entier avant un tel choix",
                        "line {} is too long to be shown in full before such a choice",
                        t.ou
                    ));
                }
                Ok(t) if t.trompeuse => {
                    return Temoins::Refuse(trf!(
                        "la ligne {} contient un caractère invisible ou un blanc inhabituel : l'écran ne la montre pas telle que systemd ou le shell la lisent",
                        "line {} contains an invisible character or an unusual space: the screen does not show it the way systemd or the shell reads it",
                        t.ou
                    ));
                }
                Ok(t) => liste.push(t),
                Err(raison) => return Temoins::Refuse(raison.to_string()),
            }
        }
        let t = Temoins::Releves(liste);
        let n = t.lignes().len();
        if n > TEMOINS_MAX {
            return Temoins::Refuse(trop_de_lignes(n));
        }
        if n == 0 {
            return Temoins::Refuse(tr!("aucune ligne relevée", "no line recorded").to_string());
        }
        t
    }
}

/// « n lignes signalées, plus que les 12… », prêt à montrer.
pub(crate) fn trop_de_lignes(n: usize) -> String {
    trf!(
        "{n} lignes signalées, plus que les {TEMOINS_MAX} qui se montrent avant un tel choix",
        "{n} reported lines, more than the {TEMOINS_MAX} that can be shown before such a choice"
    )
}

/// Ce que le système dit d'un fichier au moment du relevé : appareil, numéro, taille, dates de contenu et de
/// changement (ctime, que le compte ne peut pas remettre), et de chaque dossier au-dessus de lui jusqu'à la racine
/// (appareil, numéro, ctime). Hors de l'empreinte (un fichier recopié à l'identique ne fait pas revenir l'alerte) :
/// seulement pour voir, au moment de confirmer, qu'un fichier a été touché depuis le relevé, même remis ensuite au
/// même contenu, ou qu'un dossier au-dessus a été échangé puis remis (renommer un dossier change son ctime ; le
/// fichier, lui, ne bouge pas : vérification de la campagne E, N5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Vu {
    soi: [i64; 7],
    parents: [u8; 32],
}

impl Vu {
    /// Ce que le système dit d'un fichier, sans ses dossiers (un texte assemblé, un essai).
    #[cfg(unix)]
    pub(crate) fn de(m: &std::fs::Metadata) -> Vu {
        use std::os::unix::fs::MetadataExt as _;
        let n = |x: u64| i64::try_from(x).unwrap_or(i64::MAX);
        Vu {
            soi: [
                n(m.dev()),
                n(m.ino()),
                n(m.size()),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            ],
            parents: [0; 32],
        }
    }

    /// Ce que le système dit du fichier `chemin` (`m`) et de chaque dossier au-dessus de lui, jusqu'à la racine :
    /// ceux du chemin écrit, puis ceux du chemin résolu. Derrière un lien de dossier (« ~/.lien -> .d/1 »), les
    /// dossiers traversés ne sont pas ceux du chemin écrit ; un vrai dossier renommé puis remis passerait sinon
    /// inaperçu (deuxième vérification de la campagne E, N5).
    #[cfg(unix)]
    pub(crate) fn de_dans(m: &std::fs::Metadata, chemin: &std::path::Path) -> Vu {
        use std::os::unix::fs::MetadataExt as _;
        let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 dossiers au-dessus d'un fichier");
        let dossier = |h: &mut blake3::Hasher, d: &std::path::Path| match std::fs::symlink_metadata(d) {
            Ok(d) => {
                h.update(b"D");
                h.update(&d.dev().to_le_bytes());
                h.update(&d.ino().to_le_bytes());
                h.update(&d.ctime().to_le_bytes());
                h.update(&d.ctime_nsec().to_le_bytes());
            }
            Err(_) => {
                h.update(b"-");
            }
        };
        for d in chemin.ancestors().skip(1) {
            dossier(&mut h, d);
        }
        h.update(b"R");
        match chemin.parent().map(std::fs::canonicalize) {
            Some(Ok(resolu)) => {
                for d in resolu.ancestors() {
                    dossier(&mut h, d);
                }
            }
            _ => {
                h.update(b"-");
            }
        }
        Vu {
            parents: *h.finalize().as_bytes(),
            ..Vu::de(m)
        }
    }

    fn ecrire(self, h: &mut blake3::Hasher) {
        for x in self.soi {
            h.update(&x.to_le_bytes());
        }
        h.update(&self.parents);
    }
}

/// L'état d'un fichier, tel qu'il entre dans une empreinte et se montre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Etat {
    Absent,
    /// Le SHA-256 du contenu (comparable à `sha256sum`), et le contenu d'un petit fichier texte, pour le montrer.
    Fichier {
        empreinte: [u8; 32],
        apercu: Option<Vec<String>>,
        vu: Vu,
    },
    Lien {
        vers: String,
        puis: Box<Etat>,
        vu: Vu,
    },
}

impl Etat {
    fn ecrire(&self, h: &mut blake3::Hasher) {
        match self {
            Etat::Absent => {
                h.update(b"A");
            }
            Etat::Fichier { empreinte, .. } => {
                h.update(b"F");
                h.update(empreinte);
            }
            Etat::Lien { vers, puis, .. } => {
                h.update(b"L");
                champ(h, vers);
                puis.ecrire(h);
            }
        }
    }

    /// Ce que le système en dit (`Vu`), pour l'empreinte de confirmation.
    fn ecrire_vu(&self, h: &mut blake3::Hasher) {
        match self {
            Etat::Absent => {
                h.update(b"A");
            }
            Etat::Fichier { vu, .. } => {
                h.update(b"F");
                vu.ecrire(h);
            }
            Etat::Lien { puis, vu, .. } => {
                h.update(b"L");
                vu.ecrire(h);
                puis.ecrire_vu(h);
            }
        }
    }

    /// Un fichier dont le contenu existe mais ne se montre pas (trop long, pas du texte, caractère invisible).
    fn cache(&self) -> bool {
        match self {
            Etat::Absent => false,
            Etat::Fichier { apercu, .. } => apercu.is_none(),
            Etat::Lien { puis, .. } => puis.cache(),
        }
    }

    fn montre(&self) -> String {
        match self {
            Etat::Absent => tr!("absent", "missing").to_string(),
            Etat::Fichier { empreinte, .. } => format!("sha256 {}", hex(empreinte)),
            Etat::Lien { vers, puis, .. } => trf!(
                "lien vers {} ; {}",
                "link to {}; {}",
                crate::ui::affichable(vers),
                puis.montre()
            ),
        }
    }

    fn apercu(&self) -> Option<Vec<String>> {
        match self {
            Etat::Absent => None,
            Etat::Fichier { apercu, .. } => apercu.clone(),
            Etat::Lien { puis, .. } => puis.apercu(),
        }
    }

    /// Un état du contenu `octets` (déjà lu) : son SHA-256. Pour les essais : la crontab du compte, qui s'en servait,
    /// ne se déclare plus normale.
    #[cfg(test)]
    pub(crate) fn du_contenu(octets: &[u8]) -> Etat {
        Etat::Fichier {
            empreinte: sha2::Sha256::digest(octets).into(),
            apercu: None,
            vu: Vu::default(),
        }
    }

    /// Un état lié par le SHA-256 de `octets` (un texte assemblé, sans langue) et montré par d'autres lignes, plus
    /// courtes et lisibles (rendues affichables ici).
    pub(crate) fn lie_et_montre(octets: &[u8], montre: Vec<String>) -> Etat {
        Etat::Fichier {
            empreinte: sha2::Sha256::digest(octets).into(),
            apercu: Some(montre.into_iter().map(|l| crate::ui::affichable(&l)).collect()),
            vu: Vu::default(),
        }
    }
}

/// « sha256 … » d'un contenu, comme `sha256sum` le donne.
pub(crate) fn sha256_de(octets: &[u8]) -> String {
    format!("sha256 {}", hex(&<[u8; 32]>::from(sha2::Sha256::digest(octets))))
}

fn hex(octets: &[u8]) -> String {
    octets.iter().fold(String::with_capacity(64), |mut s, o| {
        use std::fmt::Write as _;
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// Un champ d'une empreinte, précédé de sa longueur : « ab » puis « c » ne s'écrit pas comme « a » puis « bc ».
fn champ(h: &mut blake3::Hasher, texte: &str) {
    h.update(&u64::try_from(texte.len()).unwrap_or(u64::MAX).to_le_bytes());
    h.update(texte.as_bytes());
}

/// 32 chiffres d'une empreinte de trace (128 bits : pour dire ce qui a changé, pas pour décider).
fn trace_de(cle: &str, f: impl FnOnce(&mut blake3::Hasher)) -> String {
    let mut h = blake3::Hasher::new_derive_key(cle);
    f(&mut h);
    hex(h.finalize().as_bytes().get(..16).unwrap_or_default())
}

/// Pour la trace seulement (dire ce qui a changé) : 0 un fichier lancé, 1 un fichier d'ajout d'unité
/// (« ….d/….conf »), 2 les variables des sessions (« [env] … »).
fn sorte_de_cible(chemin: &str) -> u8 {
    // systemd compare les noms tels quels : « .CONF » n'est pas un ajout.
    let extension = |s: &str, e: &str| std::path::Path::new(s).extension().is_some_and(|x| x == e);
    if chemin.starts_with("[env]") {
        2
    } else if chemin.starts_with("Exec") {
        // « ExecStartPre=… → chemin » : ce que lance une autre ligne de l'unité (`persistance::unite`) ; un chemin
        // lu commence par « / » ou « ~/ ».
        3
    } else {
        u8::from(
            chemin
                .rsplit_once('/')
                .is_some_and(|(dossier, f)| extension(dossier, "d") && extension(f, "conf")),
        )
    }
}

/// La ligne telle que systemd et le shell la lisent, sans blancs autour (espace et tabulation ASCII seulement).
fn sans_blancs(ligne: &str) -> &str {
    ligne.trim_matches([' ', '\t', '\r'])
}

/// La ligne contient-elle un caractère que l'écran ne montre pas tel quel ? La tabulation est un blanc ordinaire.
fn trompeuse(ligne: &str) -> bool {
    let l = ligne.replace('\t', " ");
    crate::ui::affichable(&l) != l
}

/// Un témoin : `ou_brut` (« chemin:numéro ») et `ligne_brute` tels que lus (l'empreinte les porte entiers), `ou`
/// déjà affichable, `contenant` l'état du fichier qui porte la ligne, `cibles` (chemin tel que lu, état) ce qu'elle
/// désigne.
pub(crate) fn temoin(
    ou_brut: &str,
    ou: String,
    ligne_brute: &str,
    contenant: Option<&Etat>,
    cibles: &[(String, Etat)],
) -> Temoin {
    let ligne = sans_blancs(ligne_brute);
    let mut h = blake3::Hasher::new_derive_key("vanguard 2026-11 temoin d'une ligne v2");
    champ(&mut h, ou_brut);
    champ(&mut h, ligne);
    match contenant {
        Some(e) => {
            h.update(b"C");
            e.ecrire(&mut h);
        }
        None => {
            h.update(b"-");
        }
    }
    h.update(&u64::try_from(cibles.len()).unwrap_or(u64::MAX).to_le_bytes());
    for (chemin, etat) in cibles {
        champ(&mut h, chemin);
        etat.ecrire(&mut h);
    }
    // L'identité de la ligne pour la trace : sa source sans le numéro (une ligne ajoutée au-dessus la décale).
    let source = match ou_brut.rsplit_once(':') {
        Some((s, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => s,
        _ => ou_brut,
    };
    let trace = Trace {
        ligne: trace_de("vanguard 2026-11 trace d'une ligne", |h| {
            champ(h, source);
            champ(h, ligne);
        }),
        fichier: trace_de("vanguard 2026-11 trace d'un fichier", |h| match contenant {
            Some(e) => e.ecrire(h),
            None => {
                h.update(b"-");
            }
        }),
        cibles: trace_de("vanguard 2026-11 trace des cibles", |h| {
            for (chemin, etat) in cibles.iter().filter(|(c, _)| sorte_de_cible(c) == 0) {
                champ(h, chemin);
                etat.ecrire(h);
            }
        }),
        ajouts: trace_de("vanguard 2026-11 trace des ajouts", |h| {
            for (chemin, etat) in cibles.iter().filter(|(c, _)| sorte_de_cible(c) == 1) {
                champ(h, chemin);
                etat.ecrire(h);
            }
        }),
        environnement: trace_de("vanguard 2026-11 trace de l'environnement", |h| {
            for (chemin, etat) in cibles.iter().filter(|(c, _)| sorte_de_cible(c) == 2) {
                champ(h, chemin);
                etat.ecrire(h);
            }
        }),
        autres: trace_de("vanguard 2026-11 trace des autres lignes", |h| {
            for (chemin, etat) in cibles.iter().filter(|(c, _)| sorte_de_cible(c) == 3) {
                champ(h, chemin);
                etat.ecrire(h);
            }
        }),
    };
    let mut v = blake3::Hasher::new_derive_key("vanguard 2026-11 vus d'une ligne");
    champ(&mut v, ou_brut);
    if let Some(e) = contenant {
        e.ecrire_vu(&mut v);
    }
    for (chemin, etat) in cibles {
        champ(&mut v, chemin);
        etat.ecrire_vu(&mut v);
    }
    let entiere = crate::ui::affichable(ligne);
    Temoin {
        ou,
        coupee: crate::ui::largeur_affichee(&entiere) > LIGNE_MONTREE,
        trompeuse: trompeuse(ligne),
        ligne: crate::ui::couper(&entiere, LIGNE_MONTREE),
        contenant: contenant.map(Etat::montre),
        cibles: cibles
            .iter()
            .map(|(c, e)| Cible {
                chemin: crate::ui::affichable(c),
                etat: e.montre(),
                apercu: e.apercu(),
                cache: e.cache(),
            })
            .collect(),
        trace,
        empreinte: *h.finalize().as_bytes(),
        vus: *v.finalize().as_bytes(),
    }
}

/// Le contenu d'un petit fichier texte, prêt à montrer ligne par ligne ; `None` s'il est trop gros, pas du texte,
/// ou s'il a un caractère que l'écran ne montrerait pas tel quel (il reste lié, sans être montré).
fn apercu_de(octets: &[u8]) -> Option<Vec<String>> {
    if octets.len() > APERCU_OCTETS {
        return None;
    }
    let texte = std::str::from_utf8(octets).ok()?;
    let lignes: Vec<String> = texte.lines().map(|l| l.replace('\t', "    ")).collect();
    if lignes.len() > APERCU_LIGNES
        || lignes
            .iter()
            .any(|l| crate::ui::affichable(l) != *l || l.contains('\r'))
    {
        return None;
    }
    Some(lignes)
}

/// Le budget d'un bilan pour relire les fichiers lancés (`BUDGET_FICHIERS`, `BUDGET_OCTETS`).
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct Budget {
    fichiers: usize,
    octets: u64,
}

#[cfg(unix)]
impl Default for Budget {
    fn default() -> Self {
        Budget {
            fichiers: BUDGET_FICHIERS,
            octets: BUDGET_OCTETS,
        }
    }
}

#[cfg(unix)]
impl Budget {
    /// Prend de quoi lire un fichier de `taille` octets ; `false` : le budget n'y suffit plus, rien n'est pris.
    pub(crate) fn prendre(&mut self, taille: u64) -> bool {
        match (self.fichiers.checked_sub(1), self.octets.checked_sub(taille)) {
            (Some(f), Some(o)) => {
                self.fichiers = f;
                self.octets = o;
                true
            }
            _ => false,
        }
    }
}

/// Un fichier de configuration lu avec ses bornes : `entier` est faux s'il dépasse ce qui a été lu.
#[cfg(unix)]
pub(crate) struct Lu {
    pub octets: Vec<u8>,
    pub entier: bool,
}

/// Ouvre un fichier ordinaire pour le lire, sans jamais ouvrir autre chose : le type est vu avant d'ouvrir (un
/// périphérique ouvert réinitialise parfois l'appareil branché), puis l'ouverture ne bloque pas (un tube nommé
/// attendrait son écrivain), ne prend pas de terminal de contrôle, et ne suit pas un lien quand `suivre` est faux ;
/// enfin, ce qui est ouvert est bien le fichier vu (même appareil, même numéro).
#[cfg(unix)]
fn ouvrir(chemin: &std::path::Path, vu: &std::fs::Metadata, suivre: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt as _;
    let pas_ordinaire = || std::io::Error::other(tr!("pas un fichier ordinaire", "not a regular file"));
    if !vu.is_file() {
        return Err(pas_ordinaire());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    let mut drapeaux = libc::O_NONBLOCK | libc::O_NOCTTY;
    if !suivre {
        drapeaux |= libc::O_NOFOLLOW;
    }
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, drapeaux);
    let fichier = options.open(chemin)?;
    let ouvert = fichier.metadata()?;
    if !ouvert.is_file() || ouvert.dev() != vu.dev() || ouvert.ino() != vu.ino() {
        return Err(pas_ordinaire());
    }
    Ok(fichier)
}

/// Lit un fichier de configuration (suivi s'il est un lien), au plus `max` octets, sans jamais ouvrir autre chose
/// qu'un fichier ordinaire (`ouvrir`).
#[cfg(unix)]
pub(crate) fn lire_borne(chemin: &std::path::Path, max: u64) -> std::io::Result<Lu> {
    use std::io::Read as _;
    let vu = std::fs::metadata(chemin)?;
    let fichier = ouvrir(chemin, &vu, true)?;
    let mut octets = Vec::new();
    fichier.take(max.saturating_add(1)).read_to_end(&mut octets)?;
    let entier = u64::try_from(octets.len()).unwrap_or(u64::MAX) <= max;
    octets.truncate(usize::try_from(max).unwrap_or(usize::MAX));
    Ok(Lu { octets, entier })
}

/// L'état du fichier `f` qui porte une ligne, dont `octets` est le contenu déjà lu : ce contenu, et s'il est un lien,
/// vers où il pointe (un fichier remplacé par un lien vers un autre au même contenu se voit aussi). `Err` : un lien
/// vers un chemin qui n'est pas de l'UTF-8 (deux tels chemins se montreraient pareil).
#[cfg(unix)]
pub(crate) fn etat_du_contenant(f: &std::path::Path, octets: &[u8]) -> Result<Etat, Refus> {
    par_un_chemin_fixe(f)?;
    let vu = |m: std::io::Result<std::fs::Metadata>| m.as_ref().map(|m| Vu::de_dans(m, f)).unwrap_or_default();
    let contenu = Etat::Fichier {
        empreinte: sha2::Sha256::digest(octets).into(),
        apercu: None,
        vu: vu(std::fs::metadata(f)),
    };
    match std::fs::read_link(f) {
        Ok(vers) => Ok(Etat::Lien {
            vers: vers_lisible(f, &vers)?,
            puis: Box::new(contenu),
            vu: vu(std::fs::symlink_metadata(f)),
        }),
        Err(_) => Ok(contenu),
    }
}

/// Où mène le lien `f`, s'il se dit en UTF-8 ; sinon le refus.
#[cfg(unix)]
fn vers_lisible(f: &std::path::Path, vers: &std::path::Path) -> Result<String, Refus> {
    vers.to_str().map(str::to_string).ok_or_else(|| {
        Refus(trf!(
            "{} mène vers un chemin qui n'est pas du texte (UTF-8)",
            "{} leads to a path that is not text (UTF-8)",
            crate::ui::chemin_affichable(f)
        ))
    })
}

/// Au plus autant de liens suivis pour résoudre un chemin (la borne du noyau, ELOOP).
#[cfg(unix)]
const LIENS_MAX: usize = 40;

/// Un chemin dont chaque lien, suivi pas à pas, reste hors de /proc et /dev : là, un chemin « absolu »
/// (« /proc/self/cwd/… », « /dev/fd/0 ») se résout selon le processus qui le lit, et Vanguard lirait un autre fichier
/// que le programme lancé (vérification de la campagne E, N1). Suivi pas à pas, pas résolu d'un coup : un lien vers
/// « /proc/self/cwd » se résoudrait pour Vanguard lui-même, hors de /proc. `Err` : il y mène, ou par trop de liens.
#[cfg(unix)]
pub(crate) fn par_un_chemin_fixe(chemin: &std::path::Path) -> Result<(), Refus> {
    use std::path::{Component, Path, PathBuf};
    let mouvant = |p: &Path| p.starts_with("/proc") || p.starts_with("/dev");
    let refus = || {
        Refus(trf!(
            "{} passe par /proc ou /dev : le fichier qu'il désigne change selon le programme qui le lit",
            "{} goes through /proc or /dev: the file it names changes with the program that reads it",
            crate::ui::chemin_affichable(chemin)
        ))
    };
    if !chemin.is_absolute() {
        return Ok(());
    }
    // Les parties qui restent à suivre, la prochaine à la fin ; « .. » se défait sur un dossier déjà résolu.
    let empiler = |pile: &mut Vec<std::ffi::OsString>, p: &Path| {
        for c in p.components().rev() {
            match c {
                Component::Normal(x) => pile.push(x.to_os_string()),
                Component::ParentDir => pile.push("..".into()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    };
    let mut pile = Vec::new();
    empiler(&mut pile, chemin);
    let mut fait = PathBuf::from("/");
    let mut liens = 0usize;
    while let Some(partie) = pile.pop() {
        if partie == ".." {
            fait.pop();
            continue;
        }
        let suivant = fait.join(&partie);
        if mouvant(&suivant) {
            return Err(refus());
        }
        match std::fs::symlink_metadata(&suivant) {
            Ok(m) if m.file_type().is_symlink() => {
                liens = liens.saturating_add(1);
                if liens > LIENS_MAX {
                    return Err(Refus(trf!(
                        "{} passe par trop de liens",
                        "{} goes through too many links",
                        crate::ui::chemin_affichable(chemin)
                    )));
                }
                let Ok(vers) = std::fs::read_link(&suivant) else {
                    fait = suivant;
                    continue;
                };
                if vers.is_absolute() {
                    fait = PathBuf::from("/");
                }
                empiler(&mut pile, &vers);
            }
            _ => fait = suivant,
        }
    }
    Ok(())
}

/// L'état d'un fichier lancé ou préchargé : absent, son contenu, ou un lien (vers où, puis ce qu'il désigne).
/// `programme` : le programme lancé lui-même, ou une bibliothèque préchargée, qui peut être un binaire ELF (lié par son
/// empreinte, sans être montré) ; tout autre fichier (le script d'un interpréteur, un argument) doit être du texte
/// qui se lit à l'écran comme il s'exécute. `Err` : il ne se relève pas (illisible, dossier, périphérique, tube, trop
/// gros, pas du texte, chemin par /proc, budget du bilan épuisé), et la raison, prête à montrer.
#[cfg(unix)]
pub(crate) fn etat_de_la_cible(chemin: &std::path::Path, programme: bool, budget: &mut Budget) -> Result<Etat, Refus> {
    use std::io::ErrorKind;
    let montre = || crate::ui::chemin_affichable(chemin);
    let illisible = |e: std::io::Error| Refus(trf!("{} ne se lit pas ({e})", "{} cannot be read ({e})", montre()));
    par_un_chemin_fixe(chemin)?;
    match std::fs::symlink_metadata(chemin) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Etat::Absent),
        Err(e) => Err(illisible(e)),
        Ok(m) if m.file_type().is_symlink() => {
            let vers = std::fs::read_link(chemin).map_err(illisible)?;
            let puis = match std::fs::metadata(chemin) {
                Err(e) if e.kind() == ErrorKind::NotFound => Etat::Absent,
                Err(e) => return Err(illisible(e)),
                Ok(vu) => contenu(chemin, &vu, true, programme, budget)?,
            };
            Ok(Etat::Lien {
                vers: vers_lisible(chemin, &vers)?,
                puis: Box::new(puis),
                vu: Vu::de_dans(&m, chemin),
            })
        }
        Ok(vu) => contenu(chemin, &vu, false, programme, budget),
    }
}

/// Le contenu d'un fichier ordinaire déjà vu (`vu`), borné avant d'ouvrir, puis lu en entier.
#[cfg(unix)]
fn contenu(
    chemin: &std::path::Path,
    vu: &std::fs::Metadata,
    suivre: bool,
    programme: bool,
    budget: &mut Budget,
) -> Result<Etat, Refus> {
    use std::io::Read as _;
    let montre = || crate::ui::chemin_affichable(chemin);
    let illisible = |e: std::io::Error| Refus(trf!("{} ne se lit pas ({e})", "{} cannot be read ({e})", montre()));
    let trop_gros = || {
        Refus(trf!(
            "{} est trop gros pour être relu à chaque bilan",
            "{} is too large to be re-read at each check",
            montre()
        ))
    };
    if !vu.is_file() {
        return Err(Refus(trf!(
            "{} n'est pas un fichier ordinaire : son contenu ne se suit pas",
            "{} is not a regular file: its content cannot be tracked",
            montre()
        )));
    }
    if vu.len() > TAILLE_MAX {
        return Err(trop_gros());
    }
    if !budget.prendre(vu.len()) {
        return Err(Refus(
            tr!(
                "trop de fichiers à relire pour un seul bilan",
                "too many files to re-read for a single check"
            )
            .to_string(),
        ));
    }
    let fichier = ouvrir(chemin, vu, suivre).map_err(illisible)?;
    let ouvert = Vu::de_dans(&fichier.metadata().map_err(illisible)?, chemin);
    let mut h = sha2::Sha256::new();
    let mut debut: Vec<u8> = Vec::new();
    let mut lus: u64 = 0;
    let mut tampon = vec![0u8; 64 * 1024];
    let mut lecteur = fichier.take(TAILLE_MAX.saturating_add(1));
    loop {
        let n = lecteur.read(&mut tampon).map_err(illisible)?;
        let Some(morceau) = tampon.get(..n).filter(|m| !m.is_empty()) else {
            break;
        };
        h.update(morceau);
        lus = lus.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if debut.len() <= TEXTE_LU {
            debut.extend_from_slice(morceau);
        }
    }
    // Grossi pendant la lecture : on ne lie pas un choix à un contenu qu'on n'a pas lu en entier.
    if lus > TAILLE_MAX {
        return Err(trop_gros());
    }
    // Un binaire ELF, seulement à la place du programme : le noyau le charge, aucun interpréteur ne le lit comme un
    // texte. Tout le reste est vérifié sur ses octets bruts, en entier (vérification de la campagne E, N4 : un seul
    // octet non UTF-8 ne fait plus sauter la recherche du retour chariot).
    if !programme && binaire_elf(&debut) {
        return Err(Refus(trf!(
            "{} est un programme (ELF) donné à lire à un autre programme : ce qu'il en fait ne se suit pas",
            "{} is a program (ELF) given to another program to read: what it does with it cannot be followed",
            montre()
        )));
    }
    if !binaire_elf(&debut) {
        if lus > u64::try_from(TEXTE_LU).unwrap_or(u64::MAX) {
            return Err(Refus(trf!(
                "{} n'est pas un programme (ELF) et dépasse ce qui se vérifie comme un texte (1 Mio)",
                "{} is not a program (ELF) and exceeds what can be checked as a text (1 MiB)",
                montre()
            )));
        }
        match defaut_du_texte(&debut) {
            None => {}
            Some(DefautDuTexte::Octet) => {
                return Err(Refus(trf!(
                    "{} n'est ni un programme (ELF) ni du texte (UTF-8) : ce qu'un interpréteur y lit ne se montre pas",
                    "{} is neither a program (ELF) nor text (UTF-8): what an interpreter reads in it cannot be shown",
                    montre()
                )));
            }
            Some(DefautDuTexte::Trompeur) => {
                return Err(Refus(trf!(
                    "{} est un texte avec un retour chariot ou un caractère invisible : à l'écran (cat, éditeur), il ne se lit pas comme il s'exécute",
                    "{} is a text with a carriage return or an invisible character: on screen (cat, editor), it does not read the way it runs",
                    montre()
                )));
            }
        }
    }
    Ok(Etat::Fichier {
        empreinte: h.finalize().into(),
        apercu: apercu_de(&debut),
        vu: ouvert,
    })
}

/// Un fichier texte lu en entier jusqu'à cette taille : vérifié pour ce qui le ferait lire autrement qu'il s'exécute.
#[cfg(unix)]
const TEXTE_LU: usize = 1024 * 1024;

/// Un binaire ELF : l'en-tête « \x7fELF », et un octet nul dans ses 16 premiers octets avant tout saut de ligne
/// (l'identification d'un vrai ELF en a toujours ; bash refuse aussi de lire comme un script un fichier dont la
/// première ligne en a un).
fn binaire_elf(octets: &[u8]) -> bool {
    octets.starts_with(b"\x7fELF") && octets.iter().take(16).take_while(|o| **o != b'\n').any(|o| *o == 0)
}

/// Ce qui empêche un fichier de se lire à l'écran comme il s'exécute.
#[derive(Debug, PartialEq, Eq)]
enum DefautDuTexte {
    /// Un octet qui n'est pas de l'UTF-8.
    Octet,
    /// Un retour chariot, ou un caractère que l'écran ne montre pas tel quel.
    Trompeur,
}

/// Le défaut d'un texte, vérifié sur ses octets bruts : pas de l'UTF-8, ou une ligne avec un retour chariot ou un
/// caractère que l'écran ne montre pas tel quel (un « cat » ou un éditeur le montreraient autrement que
/// l'interpréteur le lit) ; `None` : il se lit tel qu'il s'exécute.
fn defaut_du_texte(octets: &[u8]) -> Option<DefautDuTexte> {
    // L'octet d'abord : un fichier qui n'est pas du texte se dit tel, même s'il contient aussi un retour chariot.
    let Ok(t) = std::str::from_utf8(octets) else {
        return Some(DefautDuTexte::Octet);
    };
    if octets.contains(&b'\r') {
        return Some(DefautDuTexte::Trompeur);
    }
    t.split('\n')
        .any(|l| {
            let l = l.replace('\t', " ");
            crate::ui::affichable(&l) != l
        })
        .then_some(DefautDuTexte::Trompeur)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fichier(octets: &[u8]) -> Etat {
        Etat::du_contenu(octets)
    }

    fn un(ligne: &str, contenant: &Etat, cibles: &[(String, Etat)]) -> Temoin {
        temoin(
            "~/.config/systemd/user/a.service:1",
            "a:1".into(),
            ligne,
            Some(contenant),
            cibles,
        )
    }

    /// Chaque changement d'un témoin change l'empreinte de l'ensemble ; l'ordre et une ligne relue deux fois, non.
    #[test]
    fn empreinte_de_l_ensemble() {
        let ligne = "ExecStart=%h/.cache-x/rappel.sh";
        let c = fichier(b"[Service]\nExecStart=%h/.cache-x/rappel.sh\n");
        let cible = (
            "/home/alice/.cache-x/rappel.sh".to_string(),
            fichier(b"#!/bin/sh\necho ok\n"),
        );
        let base = Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&cible))]).empreinte();
        let autre_contenant = fichier(b"[Service]\nExecStart=%h/.cache-x/rappel.sh\nNice=5\n");
        let autre_cible = (cible.0.clone(), fichier(b"#!/bin/sh\ncurl x | sh\n"));
        let lien = Etat::Lien {
            vers: "/tmp/x.service".into(),
            puis: Box::new(c.clone()),
            vu: Vu::default(),
        };
        let seconde = un("ExecStartPre=/opt/b", &c, &[]);
        for e in [
            Temoins::Releves(vec![un(ligne, &autre_contenant, std::slice::from_ref(&cible))]),
            Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&autre_cible))]),
            Temoins::Releves(vec![un(ligne, &lien, std::slice::from_ref(&cible))]),
            Temoins::Releves(vec![un(ligne, &c, &[(cible.0.clone(), Etat::Absent)])]),
            Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&cible)), seconde.clone()]),
        ] {
            assert_ne!(e.empreinte(), base);
        }
        let deux = Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&cible)), seconde.clone()]);
        let deux_inverses = Temoins::Releves(vec![
            seconde.clone(),
            un(ligne, &c, std::slice::from_ref(&cible)),
            seconde,
        ]);
        assert_eq!(deux.empreinte(), deux_inverses.empreinte());
        assert_eq!(deux_inverses.lignes().len(), 2);
        assert_eq!(Temoins::Aucun.empreinte(), None);
        assert_eq!(Temoins::Refuse("x".into()).empreinte(), None);
    }

    /// C1 : l'empreinte montrée est le SHA-256 du contenu, celui de `sha256sum`.
    #[test]
    fn empreinte_comparable_a_sha256sum() {
        let t = un("ExecStart=/opt/a", &fichier(b""), &[("/opt/a".into(), fichier(b"abc"))]);
        assert_eq!(
            t.cibles[0].etat,
            "sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            t.contenant.as_deref(),
            Some("sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    /// C8 : une ligne qui revient se dit déjà acceptée, nouvelle, ou changée (le fichier, ou ce qu'elle lance).
    #[test]
    fn marques_au_retour() {
        const ENV: &str = "[env] LD_*, PYTHON*";
        let ligne = "ExecStart=%h/.cache-x/rappel.sh";
        let c = fichier(b"[Service]\n");
        let cible = ("/home/alice/.cache-x/rappel.sh".to_string(), fichier(b"ok"));
        let avant = Temoins::Releves(vec![un(ligne, &c, std::slice::from_ref(&cible))]).traces();
        assert_eq!(
            un(ligne, &c, std::slice::from_ref(&cible)).marque(&avant),
            Marque::DejaAcceptee
        );
        assert_eq!(un("ExecStart=/opt/b", &c, &[]).marque(&avant), Marque::Nouvelle);
        assert_eq!(
            un(ligne, &fichier(b"[Service]\nNice=1\n"), std::slice::from_ref(&cible)).marque(&avant),
            Marque::FichierChange
        );
        assert_eq!(
            un(ligne, &c, &[(cible.0.clone(), fichier(b"ko"))]).marque(&avant),
            Marque::ProgrammeChange
        );
        // Décalée d'une ligne dans le même fichier : la même ligne.
        let decalee = temoin(
            "~/.config/systemd/user/a.service:2",
            "a:2".into(),
            ligne,
            Some(&c),
            std::slice::from_ref(&cible),
        );
        assert_eq!(decalee.marque(&avant), Marque::DejaAcceptee);
        // Campagne E, M-a : un ajout de l'unité ou une variable des sessions changés se disent comme tels.
        let ajout = |t: &[u8]| ("~/.config/systemd/user/rappel.service.d/x.conf".to_string(), fichier(t));
        let env = |t: &[u8]| {
            (
                ENV.to_string(),
                Etat::lie_et_montre(t, vec![String::from_utf8_lossy(t).into_owned()]),
            )
        };
        let lie = |a: &[u8], e: &[u8]| un(ligne, &c, &[cible.clone(), ajout(a), env(e)]);
        let avant = Temoins::Releves(vec![lie(b"Nice=1", b"")]).traces();
        assert_eq!(lie(b"Nice=1", b"").marque(&avant), Marque::DejaAcceptee);
        assert_eq!(lie(b"Nice=5", b"").marque(&avant), Marque::AjoutChange);
        assert_eq!(
            lie(b"Nice=1", b"BASH_ENV=/x").marque(&avant),
            Marque::EnvironnementChange
        );
        // Troisième vérification : seule la cible d'une autre ligne Exec change ; celle-ci le dit, sans se dire
        // « programme changé ».
        let pre = |t: &[u8]| ("ExecStartPre=%h/.x/avant.sh → ~/.x/avant.sh".to_string(), fichier(t));
        let avec = |t: &[u8]| un(ligne, &c, &[cible.clone(), pre(t)]);
        let avant = Temoins::Releves(vec![avec(b"a")]).traces();
        assert_eq!(avec(b"a").marque(&avant), Marque::DejaAcceptee);
        assert_eq!(avec(b"b").marque(&avant), Marque::AutreLigneChangee);
        assert_eq!(
            un(ligne, &c, &[(cible.0.clone(), fichier(b"ko")), pre(b"a")]).marque(&avant),
            Marque::ProgrammeChange
        );
    }

    #[test]
    fn trop_de_lignes_ou_un_refus() {
        let c = fichier(b"x");
        let n = |i: usize| Ok(un(&format!("ExecStart=/opt/{i}"), &c, &[]));
        assert!(matches!(
            Temoins::de((0..TEMOINS_MAX).map(n).collect()),
            Temoins::Releves(_)
        ));
        assert!(matches!(
            Temoins::de((0..=TEMOINS_MAX).map(n).collect()),
            Temoins::Refuse(_)
        ));
        assert!(matches!(
            Temoins::de(vec![n(0), Err(Refus("illisible".into()))]),
            Temoins::Refuse(r) if r == "illisible"
        ));
        assert!(matches!(Temoins::de(Vec::new()), Temoins::Refuse(_)));
        // Ce qui passerait la coupure ne serait pas vu avant le choix : la ligne longue ne se déclare pas.
        let pleine = format!("ExecStart=/opt/a{}", " ".repeat(LIGNE_MONTREE));
        assert!(matches!(
            Temoins::de(vec![Ok(un(&format!("{pleine}/tmp/x"), &c, &[]))]),
            Temoins::Refuse(_)
        ));
        assert!(matches!(
            Temoins::de(vec![Ok(un(&format!("{pleine}   "), &c, &[]))]),
            Temoins::Releves(_)
        ));
    }

    /// B1 : une ligne que l'écran ne montre pas telle quelle (U+2003, U+00A0, largeur nulle) ne se déclare pas ;
    /// une tabulation, si.
    #[test]
    fn ligne_trompeuse_refusee() {
        let c = fichier(b"x");
        for l in [
            "ExecStart=%h/.cache-x/a\u{2003}/home/alice/.cache-x/b",
            "ExecStart=%h/.cache-x/a\u{00A0}/home/alice/.cache-x/b",
            "ExecStart=/opt/a\u{200B}",
        ] {
            assert!(
                matches!(Temoins::de(vec![Ok(un(l, &c, &[]))]), Temoins::Refuse(r) if r.contains("invisible")),
                "{l:?}"
            );
        }
        assert!(matches!(
            Temoins::de(vec![Ok(un("ExecStart=/opt/a\t/opt/b", &c, &[]))]),
            Temoins::Releves(_)
        ));
    }

    /// Sur de vrais fichiers : absent, contenu (et son aperçu), lien, dossier, tube nommé et périphérique (refusés
    /// sans les ouvrir), trop gros, budget du bilan.
    #[cfg(unix)]
    #[test]
    fn etats_des_cibles() {
        let d = crate::essais::temporaire().join(format!("vanguard-temoins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut b = Budget::default();
        let p = d.join("rappel.sh");
        assert_eq!(etat_de_la_cible(&p, true, &mut b), Ok(Etat::Absent));
        std::fs::write(&p, b"#!/bin/sh\necho ok\n").unwrap();
        let avant = etat_de_la_cible(&p, true, &mut b).unwrap();
        assert_eq!(
            avant.apercu(),
            Some(vec!["#!/bin/sh".to_string(), "echo ok".to_string()])
        );
        assert!(matches!(
            &avant,
            Etat::Fichier { empreinte, .. } if *empreinte == <[u8; 32]>::from(sha2::Sha256::digest(b"#!/bin/sh\necho ok\n"))
        ));
        std::fs::write(&p, b"#!/bin/sh\necho ko\n").unwrap();
        assert_ne!(etat_de_la_cible(&p, true, &mut b).unwrap(), avant);
        // Un caractère que l'écran cacherait, ou un retour chariot (campagne E, F3) : un texte qui ne se lit pas comme
        // il s'exécute, refusé.
        std::fs::write(&p, "#!/bin/sh\necho\u{200B} ok\n").unwrap();
        assert!(etat_de_la_cible(&p, true, &mut b).is_err());
        std::fs::write(&p, "#!/bin/sh\necho ok\rcurl x\n").unwrap();
        assert!(etat_de_la_cible(&p, true, &mut b).is_err());
        // Un programme (pas du texte) : lié, pas montré, et dit caché.
        std::fs::write(&p, b"\x7fELF\x02\x01\x01\x00\xff\xfe").unwrap();
        let programme = etat_de_la_cible(&p, true, &mut b).unwrap();
        assert_eq!(programme.apercu(), None);
        assert!(programme.cache());
        // Un long script : lié, pas montré, dit caché.
        std::fs::write(&p, "echo ok\n".repeat(100)).unwrap();
        assert!(etat_de_la_cible(&p, true, &mut b).unwrap().cache());
        std::fs::write(&p, b"#!/bin/sh\necho ok\n").unwrap();
        assert!(!etat_de_la_cible(&p, true, &mut b).unwrap().cache());
        let l = d.join("lien");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(matches!(etat_de_la_cible(&l, true, &mut b), Ok(Etat::Lien { .. })));
        assert!(etat_de_la_cible(&d, true, &mut b).is_err());
        assert!(etat_de_la_cible(std::path::Path::new("/dev/null"), true, &mut b).is_err());
        let tube = d.join("tube");
        if std::process::Command::new("mkfifo")
            .arg(&tube)
            .status()
            .is_ok_and(|s| s.success())
        {
            assert!(etat_de_la_cible(&tube, true, &mut b).is_err());
            assert!(lire_borne(&tube, 10).is_err());
        }
        // Un fichier creux plus gros que la borne : refusé sans être lu.
        let creux = d.join("creux");
        std::fs::File::create(&creux).unwrap().set_len(TAILLE_MAX + 1).unwrap();
        assert!(etat_de_la_cible(&creux, true, &mut b).is_err());
        // Le budget épuisé : refusé sans lire.
        let mut vide = Budget { fichiers: 0, octets: 0 };
        assert!(etat_de_la_cible(&p, true, &mut vide).is_err());
        let lu = lire_borne(&p, 4).unwrap();
        assert_eq!((lu.octets.len(), lu.entier), (4, false));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Campagne E, F3 : un fichier échangé contre un autre au même contenu (ou réécrit) garde son empreinte, pas ce
    /// qui en est vu (appareil, inode, dates) : la confirmation d'un choix compare aussi les deux.
    #[cfg(unix)]
    /// Deux relevés de suite égaux, rendus ; les dossiers au-dessus (le dossier temporaire commun) changent quand un
    /// autre essai y écrit en même temps : on relève jusqu'à deux relevés égaux (20 essais au plus).
    fn stable(releve: &dyn Fn() -> Temoins) -> Temoins {
        for _ in 0..20 {
            let a = releve();
            if a.vus() == releve().vus() {
                return a;
            }
        }
        panic!("les dossiers au-dessus ne cessent de changer");
    }

    #[cfg(unix)]
    #[test]
    fn vus_d_un_fichier_echange() {
        let d = crate::essais::temporaire().join(format!("vanguard-temoins-vus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("rappel.sh");
        std::fs::write(&p, b"#!/bin/sh\necho ok\n").unwrap();
        let releve = || {
            let mut b = Budget::default();
            let e = etat_de_la_cible(&p, true, &mut b).unwrap();
            Temoins::de(vec![Ok(temoin(
                "a:1",
                "a:1".into(),
                "ExecStart=/x",
                None,
                &[("/x".into(), e)],
            ))])
        };
        let avant = stable(&releve);
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"#!/bin/sh\necho ok\n").unwrap();
        let apres = releve();
        assert_eq!(avant.empreinte(), apres.empreinte());
        assert_ne!(avant.vus(), apres.vus());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Vérification de la campagne E, N4 : le retour chariot se cherche sur les octets bruts, même si un octet du
    /// fichier n'est pas de l'UTF-8 ; un fichier lu par un interpréteur (pas le programme lancé) est du texte, un en-tête
    /// ELF ne l'exempte pas ; N1 : un lien qui passe par /proc ou /dev n'est jamais lié.
    #[cfg(unix)]
    #[test]
    fn cibles_qui_ne_se_lisent_pas_comme_elles_s_executent() {
        let d = crate::essais::temporaire().join(format!("vanguard-temoins-n4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut b = Budget::default();
        let p = d.join("rappel.sh");
        for octets in [
            &b"#!/bin/sh\necho ok\rcurl x\n#\xff\n"[..],
            b"#!/bin/sh\necho ok\n#\xff\n",
            b"\x7fELF\x02\x01\x01\x00\n#\xff\ncurl x\n",
        ] {
            std::fs::write(&p, octets).unwrap();
            assert!(etat_de_la_cible(&p, false, &mut b).is_err(), "{octets:?}");
        }
        // Le retour chariot sans octet illisible ni ELF : refusé même pour le programme lancé.
        std::fs::write(&p, b"#!/bin/sh\necho ok\rcurl x\n").unwrap();
        assert!(etat_de_la_cible(&p, true, &mut b).is_err());
        // Un vrai en-tête ELF : lié seulement à la place du programme.
        std::fs::write(&p, b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\xff").unwrap();
        assert!(etat_de_la_cible(&p, true, &mut b).is_ok());
        assert!(etat_de_la_cible(&p, false, &mut b).is_err());
        // « \x7fELF » sans octet nul avant le saut de ligne : bash le lirait comme un script.
        std::fs::write(&p, b"\x7fELF\ncurl x\n\xff").unwrap();
        assert!(etat_de_la_cible(&p, true, &mut b).is_err());
        for (nom, vers) in [
            ("cwd", "/proc/self/cwd/rappel.sh"),
            ("fd", "/dev/fd/0"),
            ("stdin", "/dev/stdin"),
        ] {
            let l = d.join(nom);
            std::os::unix::fs::symlink(vers, &l).unwrap();
            assert!(etat_de_la_cible(&l, true, &mut b).is_err(), "{vers}");
            assert!(etat_du_contenant(&l, b"").is_err(), "{vers}");
        }
        // Par un lien de dossier relatif qui remonte vers /proc.
        std::os::unix::fs::symlink(format!("{}proc/self", "../".repeat(40)), d.join("soi")).unwrap();
        assert!(etat_de_la_cible(&d.join("soi/cwd/rappel.sh"), true, &mut b).is_err());
        assert!(etat_de_la_cible(std::path::Path::new("/proc/self/cwd/x"), true, &mut b).is_err());
        // Une boucle de liens : refusée, sans tourner sans fin.
        std::os::unix::fs::symlink(d.join("boucle-b"), d.join("boucle-a")).unwrap();
        std::os::unix::fs::symlink(d.join("boucle-a"), d.join("boucle-b")).unwrap();
        assert!(etat_de_la_cible(&d.join("boucle-a"), true, &mut b).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Vérification de la campagne E, N5 : un dossier au-dessus du fichier renommé puis remis (ou échangé contre un
    /// autre au même contenu) change ce qui en est vu, même si le fichier garde son inode et ses dates.
    #[cfg(unix)]
    #[test]
    fn vus_d_un_dossier_echange() {
        let d = crate::essais::temporaire().join(format!("vanguard-temoins-n5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("outils")).unwrap();
        let p = d.join("outils/rappel.sh");
        std::fs::write(&p, b"#!/bin/sh\necho ok\n").unwrap();
        let releve = || {
            let mut b = Budget::default();
            let e = etat_de_la_cible(&p, true, &mut b).unwrap();
            Temoins::de(vec![Ok(temoin(
                "a:1",
                "a:1".into(),
                "ExecStart=/x",
                None,
                &[("/x".into(), e)],
            ))])
        };
        let avant = stable(&releve);
        std::fs::rename(d.join("outils"), d.join("ailleurs")).unwrap();
        std::fs::rename(d.join("ailleurs"), d.join("outils")).unwrap();
        let apres = releve();
        assert_eq!(avant.empreinte(), apres.empreinte());
        assert_ne!(avant.vus(), apres.vus());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le script atteint par un lien de dossier : le vrai dossier, renommé puis remis pendant la lecture du détail,
    /// se voit aussi (deuxième vérification de la campagne E, N5 par un lien).
    #[cfg(unix)]
    #[test]
    fn vus_derriere_un_lien_de_dossier() {
        let d = crate::essais::temporaire().join(format!("vanguard-temoins-n5b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".d/1")).unwrap();
        std::fs::write(d.join(".d/1/rappel.sh"), b"#!/bin/sh\necho ok\n").unwrap();
        std::os::unix::fs::symlink(".d/1", d.join(".lien")).unwrap();
        let p = d.join(".lien/rappel.sh");
        let releve = || {
            let mut b = Budget::default();
            let e = etat_de_la_cible(&p, true, &mut b).unwrap();
            Temoins::de(vec![Ok(temoin(
                "a:1",
                "a:1".into(),
                "ExecStart=/x",
                None,
                &[("/x".into(), e)],
            ))])
        };
        let avant = stable(&releve);
        std::fs::rename(d.join(".d/1"), d.join(".d/2")).unwrap();
        std::fs::rename(d.join(".d/2"), d.join(".d/1")).unwrap();
        let apres = releve();
        assert_eq!(avant.empreinte(), apres.empreinte());
        assert_ne!(avant.vus(), apres.vus());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un binaire donné à lire à un autre programme se dit tel, même avec un retour chariot dedans.
    #[cfg(unix)]
    #[test]
    fn argument_binaire_dit_tel() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-temoins-elf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let donnee = dossier.join("donnee");
        std::fs::write(&donnee, b"\x7fELF\x02\x01\x01\x00\x00\x00\r\n\xff").unwrap();
        let mut budget = Budget::default();
        assert!(etat_de_la_cible(&donnee, true, &mut budget).is_ok());
        let e = etat_de_la_cible(&donnee, false, &mut budget).unwrap_err().0;
        assert!(e.contains("ELF"), "{e}");
        assert!(!e.contains("retour chariot") && !e.contains("carriage return"), "{e}");
        let texte = dossier.join("texte");
        std::fs::write(&texte, b"echo \xff\r\n").unwrap();
        let e = etat_de_la_cible(&texte, false, &mut budget).unwrap_err().0;
        assert!(e.contains("UTF-8"), "{e}");
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
