//! Collecter les traces : après une infection, avant de nettoyer ou de réinstaller, garder ce qu'un spécialiste (ou la
//! personne elle-même, plus tard) voudra voir, dans l'ordre où cela disparaît : processus, connexions, ce qui se lance
//! tout seul, comptes, journaux des 7 derniers jours, fichiers récents des endroits à risque, et ce que Vanguard a
//! lui-même vu et fait (ses alertes, ses blocages et quarantaines avec la preuve relevée avant chaque geste, voir
//! `vanguard`). Chaque partie a son fichier texte ; CHRONOLOGIE.txt remet ce qu'elles ont de daté dans l'ordre du temps (voir `chronologie`) ;
//! LISEZMOI.txt dit ce que contient chacun et ce qui n'a pas pu être lu, et pourquoi ; MANIFESTE.txt donne
//! l'empreinte SHA-256 de chaque fichier, pour prouver plus tard qu'ils n'ont pas changé.
//!
//! Lecture seule : aucun processus arrêté, aucun fichier déplacé ; les fichiers récents sont décrits, pas copiés (seuls
//! les fichiers d'état de Vanguard le sont, pour que le MANIFESTE les couvre).
//! Rien ne part sur Internet : le bilan joint est fait sans ses règles de mises à jour, les seules qui interrogent des
//! serveurs.

mod chronologie;
// Lu par la chronologie sous Windows ; ses essais tournent partout.
#[cfg_attr(not(windows), allow(dead_code))]
mod journaux_windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
pub(crate) mod vanguard;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(windows)]
use windows as os;

use std::fmt::Write as _;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use crate::ui::*;

/// Les journaux, au plus : une semaine de journal d'un ordinateur ordinaire, sans le remplir d'une machine bavarde.
/// (Sous Windows, wevtutil exporte les 7 jours entiers : leur place est mesurée d'avance.)
#[cfg(any(unix, test))]
const BORNE_JOURNAL: u64 = 50 << 20;
/// Les fichiers récents dont l'empreinte est calculée : programmes et scripts de moins de 64 Mo (un installateur de
/// plusieurs Go prendrait des minutes, et VirusTotal n'en connaît pas l'empreinte s'il ne l'a jamais reçu).
const TAILLE_EMPREINTE: u64 = 64 << 20;
/// Les programmes en marche, eux, se lisent jusqu'à 256 Mo : un navigateur ou un éditeur moderne en approche.
const TAILLE_PROGRAMME: u64 = 256 << 20;
/// Le temps donné aux empreintes de chaque partie (processus, fichiers récents) : quelques secondes d'ordinaire, mais
/// un dossier temporaire plein d'outils de développement en demanderait des minutes.
const DELAI_EMPREINTES: Duration = Duration::from_secs(20);
/// Un fichier est récent s'il a été écrit, changé ou créé depuis ce nombre de jours : une infection s'installe
/// souvent des jours ou des semaines avant qu'on la remarque.
const JOURS_RECENTS: u64 = 30;
/// Ce que prennent, au plus, les parties hors journaux (processus, réseau, démarrage, bilan, fichiers récents).
const PLACE_HORS_JOURNAUX: u64 = 20 << 20;
/// Le contenu d'un fichier de configuration recopié dans les traces, au plus.
const BORNE_FICHIER: u64 = 1 << 20;

/// Un texte en français et en anglais : l'écran le montre dans la langue de l'interface, le LISEZMOI dans les deux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bi {
    fr: String,
    en: String,
}

impl Bi {
    pub(crate) fn new(fr: impl Into<String>, en: impl Into<String>) -> Bi {
        Bi {
            fr: fr.into(),
            en: en.into(),
        }
    }

    /// Le même texte dans les deux langues (un nom de commande, une erreur du système).
    pub(crate) fn meme(t: impl Into<String>) -> Bi {
        let t = t.into();
        Bi { fr: t.clone(), en: t }
    }
}

/// `format!` dans les deux langues : `bi!("{n} processus", "{n} processes")`.
macro_rules! bi {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        $crate::traces::Bi::new(format!($fr $(, $arg)*), format!($en $(, $arg)*))
    };
}
pub(crate) use bi;

/// Pourquoi quelque chose n'a pas pu être lu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Raison {
    /// Réservé à root (Linux, macOS) ou à l'administrateur (Windows).
    Droits,
    /// La commande n'existe pas sur cet ordinateur.
    Absente(String),
    /// La commande n'a pas répondu dans ce délai, en secondes.
    Delai(u64),
    /// Pas assez de place libre : (libre, nécessaire).
    Place(u64, u64),
    /// Coupé à cette taille : le reste n'est pas gardé.
    Borne(u64),
    /// Rien de tel sur cet ordinateur.
    Introuvable,
    /// PowerShell n'a pas répondu (absent, bloqué par une stratégie, délai dépassé).
    #[cfg_attr(not(windows), allow(dead_code))]
    SansPowerShell,
    /// Un lien posé par un compte ordinaire, vers cette cible : pas suivi (voir `lien_sur`).
    LienNonSuivi(String),
    /// Tant de lignes de plus, au-delà de la borne de la chronologie : pas gardées.
    Lignes(usize),
    /// Coupé à tant d'entrées, les plus récentes gardées.
    Entrees(usize),
    /// Vanguard ne l'a lu que sur cette étendue, par choix (« 10 Mo », la fin d'un fichier ; « 1 jour ») : le reste
    /// existe peut-être.
    #[cfg_attr(windows, allow(dead_code))]
    LuSur(Bi),
    /// Le système ne l'a pas gardé (journal tourné ou vidé), alors que Vanguard l'a lu en entier, avec les droits.
    #[cfg_attr(windows, allow(dead_code))]
    NonGarde,
    /// Le relevé de Vanguard et la sortie de l'outil qu'il remplace ne disent pas la même chose (ce qui diffère) :
    /// un outil remplacé qui cache quelque chose, ou un changement entre les deux lectures.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Ecart(Bi),
    /// Ce que le système a répondu.
    Erreur(String),
}

impl Raison {
    fn texte(&self) -> Bi {
        let taille = |o: u64| {
            #[allow(clippy::cast_precision_loss)]
            let mo = o as f64 / f64::from(1u32 << 20);
            (format!("{mo:.0} Mo"), format!("{mo:.0} MB"))
        };
        match self {
            Raison::Droits if cfg!(windows) => Bi::new("réservé à l'administrateur", "administrator only"),
            Raison::Droits => Bi::new("réservé à root", "root only"),
            Raison::Absente(c) => bi!("commande « {c} » absente", "“{c}” command missing"),
            Raison::Delai(s) => bi!("pas de réponse en {s} s", "no answer within {s} s"),
            Raison::Place(libre, besoin) => {
                let ((l, l_en), (b, b_en)) = (taille(*libre), taille(*besoin));
                bi!(
                    "place insuffisante ({l} libres, {b} nécessaires)",
                    "not enough space ({l_en} free, {b_en} needed)"
                )
            }
            Raison::Borne(o) => {
                let (fr, en) = taille(*o);
                bi!(
                    "coupé à {fr}, le reste n'est pas gardé",
                    "cut at {en}, the rest is not kept"
                )
            }
            Raison::Introuvable => Bi::new("introuvable", "not found"),
            Raison::SansPowerShell => Bi::new("PowerShell n'a pas répondu", "PowerShell did not answer"),
            Raison::LienNonSuivi(c) => bi!(
                "lien vers {c}, posé par un compte : pas suivi",
                "link to {c}, set by an account: not followed"
            ),
            Raison::Lignes(n) => bi!(
                "{n} lignes de plus ne sont pas gardées ({} au plus)",
                "{n} more lines are not kept ({} at most)",
                chronologie::MAX_LIGNES
            ),
            Raison::Entrees(n) => bi!(
                "coupé à {n} entrées, les plus anciennes ne sont pas gardées",
                "cut at {n} entries, the oldest are not kept"
            ),
            Raison::LuSur(etendue) => Bi::new(
                format!("lu sur {} par Vanguard", etendue.fr),
                format!("only {} read by Vanguard", etendue.en),
            ),
            Raison::NonGarde => Bi::new("le système ne l'a pas gardé", "the system did not keep it"),
            Raison::Ecart(ce_qui) => Bi::new(
                format!(
                    "le relevé de Vanguard et l'outil diffèrent ({}) : l'outil a peut-être été remplacé, ou la machine a changé entre les deux lectures",
                    ce_qui.fr
                ),
                format!(
                    "Vanguard's reading and the tool differ ({}): the tool may have been replaced, or the machine changed between the two readings",
                    ce_qui.en
                ),
            ),
            Raison::Erreur(e) => Bi::meme(e.clone()),
        }
    }

    /// La raison dite dans un fichier des traces, dans les deux langues : « (commande « x » absente / “x” command
    /// missing) ».
    fn note(&self) -> String {
        let t = self.texte();
        if t.fr == t.en {
            format!("({})", t.fr)
        } else {
            format!("({} / {})", t.fr, t.en)
        }
    }
}

/// Ce qui manque à une partie, et pourquoi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Manque {
    pub quoi: Bi,
    pub raison: Raison,
}

/// Un fichier produit et ce qu'il contient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Produit {
    pub nom: String,
    pub contenu: Bi,
}

/// Une partie collectée : son titre, ce qu'elle a trouvé (`None` : rien n'a pu être lu), ce qui lui manque, ses
/// fichiers, et ce qu'elle a lu de daté pour la chronologie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Partie {
    pub titre: Bi,
    pub compte: Option<Bi>,
    pub manques: Vec<Manque>,
    pub fichiers: Vec<Produit>,
    pub evenements: Vec<chronologie::Evenement>,
}

impl Partie {
    pub(crate) fn new(titre: Bi) -> Partie {
        Partie {
            titre,
            compte: None,
            manques: Vec::new(),
            fichiers: Vec::new(),
            evenements: Vec::new(),
        }
    }

    pub(crate) fn manque(&mut self, quoi: Bi, raison: Raison) {
        self.manques.push(Manque { quoi, raison });
    }

    /// Écrit un fichier de la partie (réservé au compte sous Linux et macOS) et le note ; un échec devient un manque.
    pub(crate) fn ecrire(&mut self, dossier: &Path, nom: &str, contenu: &str, description: Bi) -> bool {
        let ecrit = creer_fichier(&dossier.join(nom)).and_then(|mut f| f.write_all(contenu.as_bytes()));
        self.noter(nom, description, ecrit)
    }

    /// Note un fichier écrit par ailleurs (journal exporté par le système) ; `Err` devient un manque.
    pub(crate) fn noter(&mut self, nom: &str, contenu: Bi, ecrit: std::io::Result<()>) -> bool {
        match ecrit {
            Ok(()) => {
                self.fichiers.push(Produit {
                    nom: nom.to_string(),
                    contenu,
                });
                true
            }
            Err(e) => {
                self.manque(Bi::meme(nom), Raison::Erreur(e.to_string()));
                false
            }
        }
    }

    /// Les lignes de l'écran et du résumé : « ✔ Processus : 213 », puis « ⚠ quoi : raison » pour chaque manque
    /// (faux : un manque).
    fn lignes(&self, anglais: bool) -> Vec<(bool, String)> {
        let l = |b: &Bi| if anglais { b.en.clone() } else { b.fr.clone() };
        let deux_points = if anglais { ": " } else { " : " };
        let mut lignes = Vec::new();
        if let Some(c) = &self.compte {
            lignes.push((true, format!("{}{deux_points}{}", l(&self.titre), l(c))));
        }
        for m in &self.manques {
            lignes.push((false, format!("{}{deux_points}{}", l(&m.quoi), l(&m.raison.texte()))));
        }
        if lignes.is_empty() {
            lignes.push((false, l(&self.titre)));
        }
        lignes
    }
}

/// Un fichier texte des traces, écrit section par section : la sortie de chaque commande sous son nom, le contenu de
/// chaque fichier sous son chemin, et ce qui n'a pas pu être lu, dit à sa place.
pub(crate) struct Feuille {
    pub texte: String,
    /// Les sections lues.
    pub lues: usize,
    pub manques: Vec<Manque>,
    /// La date de modification de chaque fichier et dossier listé ou recopié : la chronologie la reprend sans relire.
    pub dates: Vec<(String, SystemTime)>,
}

impl Feuille {
    pub(crate) fn new(titre: &Bi) -> Feuille {
        Feuille {
            texte: entete(titre),
            lues: 0,
            manques: Vec::new(),
            dates: Vec::new(),
        }
    }

    pub(crate) fn section(&mut self, titre: &str) {
        let _ = write!(self.texte, "\n== {} ==\n", champ_texte(titre));
    }

    /// Ajoute du texte tel quel (déjà mis en forme), sans caractère de contrôle.
    pub(crate) fn ajouter(&mut self, texte: &str) {
        self.texte.push_str(&texte_sur(texte));
        if !self.texte.ends_with('\n') {
            self.texte.push('\n');
        }
    }

    /// Lance la commande et recopie sa sortie sous « $ commande ». `importante` : son absence est un manque, dit à
    /// l'écran ; sinon (un outil que beaucoup de systèmes n'ont pas), seulement dit dans le fichier. Rend la sortie.
    pub(crate) fn commande(&mut self, commande: &mut Command, secondes: u64, importante: bool) -> Option<String> {
        let nom = affichage_commande(commande);
        self.section(&format!("$ {nom}"));
        let debut = Instant::now();
        let Some(r) = crate::commande::lancer(commande, secondes) else {
            let programme = commande.get_program().to_string_lossy().into_owned();
            let raison = if debut.elapsed() >= Duration::from_secs(secondes) {
                Raison::Delai(secondes)
            } else {
                Raison::Absente(programme)
            };
            let _ = writeln!(self.texte, "{}", raison.note());
            if importante {
                self.manques.push(Manque {
                    quoi: Bi::meme(nom),
                    raison,
                });
            }
            return None;
        };
        self.ajouter(&r.sortie);
        if r.code == Some(0) {
            self.lues += 1;
        } else {
            let erreurs = r.erreurs.trim();
            let _ = writeln!(
                self.texte,
                "(code {} ; {})",
                r.code.map_or_else(|| "?".to_string(), |c| c.to_string()),
                texte_sur(&erreurs.chars().take(500).collect::<String>())
            );
        }
        Some(r.sortie)
    }

    /// Recopie un fichier (son début, `BORNE_FICHIER` au plus) sous son chemin ; absent, rien n'est écrit.
    /// `importante` : illisible faute de droits, c'est un manque dit à l'écran.
    pub(crate) fn fichier(&mut self, chemin: &Path, importante: bool) {
        self.fichier_avec(chemin, importante, false);
    }

    /// Un fichier du shell (.bashrc, .zshrc…) : recopié comme `fichier`, mais la valeur des variables au nom de secret
    /// masquée (`masquer_secrets`).
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn fichier_shell(&mut self, chemin: &Path) {
        self.fichier_avec(chemin, false, true);
    }

    fn fichier_avec(&mut self, chemin: &Path, importante: bool, masquer: bool) {
        let Ok(lien) = std::fs::symlink_metadata(chemin) else {
            return;
        };
        let est_lien = lien.file_type().is_symlink();
        if est_lien && !lien_sur(&lien) {
            self.noter_date(chemin, &lien);
            self.section(&chemin.to_string_lossy());
            let cible = std::fs::read_link(chemin).map_or_else(|_| String::new(), |c| champ(&c.to_string_lossy()));
            let _ = writeln!(self.texte, "{}", Raison::LienNonSuivi(cible).note());
            return;
        }
        let Ok(meta) = std::fs::metadata(chemin) else {
            return;
        };
        // Un lien se date par lui-même : un service activé l'est quand son lien est posé, pas quand une mise à jour
        // réécrit le fichier du paquet qu'il désigne (ce qui ferait un faux « service ajouté » dans la chronologie).
        self.noter_date(chemin, &lien);
        self.section(&chemin.to_string_lossy());
        match lire_debut(chemin, BORNE_FICHIER, !est_lien) {
            Ok(texte) => {
                self.lues += 1;
                self.ajouter(&if masquer { masquer_secrets(&texte) } else { texte });
                if meta.len() > BORNE_FICHIER {
                    let _ = writeln!(self.texte, "{}", Raison::Borne(BORNE_FICHIER).note());
                }
            }
            Err(e) => {
                let raison = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    Raison::Droits
                } else {
                    Raison::Erreur(e.to_string())
                };
                let _ = writeln!(self.texte, "{}", raison.note());
                if importante {
                    self.manques.push(Manque {
                        quoi: Bi::meme(chemin.to_string_lossy()),
                        raison,
                    });
                }
            }
        }
    }

    /// Les fichiers d'un dossier : la liste (taille, date), puis le contenu de chacun, `max` au plus.
    pub(crate) fn dossier(&mut self, dossier: &Path, max: usize, importante: bool) {
        let entrees = match std::fs::read_dir(dossier) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                self.section(&dossier.to_string_lossy());
                let raison = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    Raison::Droits
                } else {
                    Raison::Erreur(e.to_string())
                };
                let _ = writeln!(self.texte, "{}", raison.note());
                if importante {
                    self.manques.push(Manque {
                        quoi: Bi::meme(dossier.to_string_lossy()),
                        raison,
                    });
                }
                return;
            }
        };
        let mut chemins: Vec<PathBuf> = entrees.flatten().map(|e| e.path()).collect();
        chemins.sort();
        self.section(&format!("{} ({})", dossier.to_string_lossy(), chemins.len()));
        for c in &chemins {
            let m = std::fs::symlink_metadata(c);
            if let Ok(m) = &m {
                self.noter_date(c, m);
            }
            let (taille, date) = m.as_ref().map_or((0, String::new()), |m| {
                (m.len(), m.modified().ok().map(date_iso).unwrap_or_default())
            });
            let lien = std::fs::read_link(c)
                .map(|l| format!(" -> {}", champ(&l.to_string_lossy())))
                .unwrap_or_default();
            let _ = writeln!(
                self.texte,
                "{date}  {taille:>10}  {}{lien}",
                champ(&c.to_string_lossy())
            );
        }
        for c in chemins.iter().filter(|c| c.is_file()).take(max) {
            self.fichier(c, false);
        }
    }

    /// Note la date de modification d'un fichier lu ou listé, pour la chronologie.
    fn noter_date(&mut self, chemin: &Path, m: &std::fs::Metadata) {
        if let Ok(t) = m.modified() {
            self.dates.push((chemin.to_string_lossy().into_owned(), t));
        }
    }
}

/// La commande telle qu'elle s'écrit : « ss -tunap ».
fn affichage_commande(c: &Command) -> String {
    std::iter::once(c.get_program())
        .chain(c.get_args())
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// L'en-tête de chaque fichier : Vanguard, sa version, la partie et l'heure de la collecte.
pub(crate) fn entete(titre: &Bi) -> String {
    format!(
        "# Vanguard {} — {} / {}\n# {}\n",
        env!("CARGO_PKG_VERSION"),
        titre.fr,
        titre.en,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S %:z")
    )
}

/// Un champ d'une ligne des fichiers de traces (processus, fichiers récents) : tel quel, sauf ce qui casserait la
/// ligne ou piloterait le terminal qui l'afficherait (« cat ») : barre oblique inverse, tabulation, barre verticale,
/// sauts de ligne et autres caractères de contrôle ou d'inversion du sens, écrits « \t », « \u{1b} »… Un nom de
/// fichier ou une ligne de commande vient de n'importe qui.
pub(crate) fn champ(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    for c in t.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '\t' => s.push_str("\\t"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '|' => s.push_str("\\x7c"),
            c if c.is_control() || piege(c) => {
                let _ = write!(s, "\\u{{{:x}}}", u32::from(c));
            }
            c => s.push(c),
        }
    }
    s
}

/// Un titre de section : sur une ligne.
fn champ_texte(t: &str) -> String {
    texte_sur(t).replace('\n', " ")
}

/// La sortie d'une commande ou le contenu d'un fichier, recopiés tels quels, lignes et tabulations comprises ; les
/// autres caractères de contrôle (une séquence qui piloterait le terminal) sont écrits « \u{1b} ».
pub(crate) fn texte_sur(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    for c in t.chars() {
        match c {
            '\n' | '\t' => s.push(c),
            '\r' => {}
            c if c.is_control() || piege(c) => {
                let _ = write!(s, "\\u{{{:x}}}", u32::from(c));
            }
            c => s.push(c),
        }
    }
    s
}

/// Le début d'un fichier, en texte (les octets qui ne sont pas de l'UTF-8 deviennent « � »).
/// Les fichiers du shell gardent souvent des secrets (« export GITHUB_TOKEN=… ») : les traces partent chez un
/// spécialiste, pas les secrets. La valeur d'une variable dont un morceau du nom désigne un secret (TOKEN, SECRET,
/// PASSWORD, KEY…) devient « (masqué) », comme le mot de passe d'une adresse « ://nom:mot@ ». Le reste reste tel quel :
/// LD_PRELOAD=, PATH=, un alias, c'est justement ce qu'il faut voir.
fn masquer_secrets(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len());
    for ligne in texte.split_inclusive('\n') {
        let (corps, fin) = ligne.strip_suffix('\n').map_or((ligne, ""), |c| (c, "\n"));
        sortie.push_str(&masquer_adresse(&masquer_affectation(corps)));
        sortie.push_str(fin);
    }
    sortie
}

/// « [export|declare -x|typeset -x|local|readonly] NOM=valeur » ou, en fish, « set [-gx…] NOM valeur ».
fn masquer_affectation(ligne: &str) -> String {
    let debut = ligne.len() - ligne.trim_start().len();
    let mots: Vec<&str> = ligne[debut..].split_whitespace().collect();
    if mots.first() == Some(&"set") {
        if let Some(nom) = mots.iter().skip(1).find(|m| !m.starts_with('-'))
            && nom_de_secret(nom)
            && let Some(i) = ligne.find(&format!(" {nom} "))
        {
            return format!("{}(masqué)", &ligne[..i + nom.len() + 2]);
        }
        return ligne.to_string();
    }
    let Some(egal) = ligne.find('=') else {
        return ligne.to_string();
    };
    let avant = ligne[..egal].trim();
    let nom = avant.rsplit(char::is_whitespace).next().unwrap_or(avant);
    let prefixe = avant[..avant.len() - nom.len()].split_whitespace().collect::<Vec<_>>();
    let mots_permis = ["export", "declare", "typeset", "local", "readonly", "-x", "-gx", "-r"];
    if !nom.is_empty()
        && nom.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && prefixe.iter().all(|m| mots_permis.contains(m))
        && nom_de_secret(nom)
    {
        format!("{}(masqué)", &ligne[..=egal])
    } else {
        ligne.to_string()
    }
}

/// Un morceau du nom (séparé par « _ ») désigne-t-il un secret ? Par morceau : KEYBOARD ou PWD ne sont pas des secrets.
fn nom_de_secret(nom: &str) -> bool {
    const MOTS: &[&str] = &[
        "KEY",
        "APIKEY",
        "TOKEN",
        "SECRET",
        "PASS",
        "PASSWD",
        "PASSWORD",
        "PASSPHRASE",
        "AUTH",
        "CREDENTIAL",
        "CREDENTIALS",
        "PRIVATE",
        "COOKIE",
        "PAT",
        "MDP",
        "CLE",
        "JETON",
    ];
    nom.to_ascii_uppercase()
        .split('_')
        .any(|m| MOTS.contains(&m) || ["TOKEN", "SECRET", "PASSWORD", "APIKEY"].iter().any(|s| m.ends_with(s)))
}

/// « scheme://nom:mot@hôte » : le mot devient « (masqué) ».
fn masquer_adresse(ligne: &str) -> String {
    let mut sortie = String::new();
    let mut reste = ligne;
    while let Some(i) = reste.find("://") {
        let (avant, apres) = reste.split_at(i + 3);
        sortie.push_str(avant);
        let fin = apres
            .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(apres.len());
        let hote = &apres[..fin];
        match (hote.rfind('@'), hote.find(':')) {
            (Some(a), Some(d)) if d < a => {
                sortie.push_str(&hote[..=d]);
                sortie.push_str("(masqué)");
                sortie.push_str(&hote[a..]);
            }
            _ => sortie.push_str(hote),
        }
        reste = &apres[fin..];
    }
    sortie.push_str(reste);
    sortie
}

/// Avec `sans_lien`, l'ouverture refuse un lien (O_NOFOLLOW) : un fichier vérifié comme n'en étant pas un, puis
/// remplacé par un lien avant d'être ouvert, n'est pas suivi pour autant.
fn lire_debut(chemin: &Path, borne: u64, sans_lien: bool) -> std::io::Result<String> {
    let mut octets = Vec::new();
    ouvrir_ordinaire(chemin, sans_lien)?
        .take(borne)
        .read_to_end(&mut octets)?;
    Ok(String::from_utf8_lossy(&octets).into_owned())
}

/// Ouvre un fichier ordinaire seulement. Un tube nommé (FIFO) de /tmp bloquait son ouverture jusqu'à ce que quelqu'un y
/// écrive, et avec elle toute la collecte (ceux des compilations en parallèle, vus le 20 octobre) : l'ouverture est
/// non bloquante, puis tout ce qui n'est pas un fichier ordinaire (tube, socket, périphérique) est refusé sans être lu.
/// Avec `sans_lien`, un lien est refusé aussi (O_NOFOLLOW).
fn ouvrir_ordinaire(chemin: &Path, sans_lien: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NONBLOCK | if sans_lien { libc::O_NOFOLLOW } else { 0 },
    );
    #[cfg(windows)]
    let _ = sans_lien;
    let f = options.open(chemin)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("pas un fichier ordinaire"));
    }
    Ok(f)
}

/// Un lien qu'on peut suivre : posé par root, qu'un programme sans droits ne peut pas imiter (/etc/resolv.conf, les
/// services activés de /etc/systemd/system). Celui d'un compte ordinaire n'est pas suivi : lancée avec sudo, la
/// collecte recopiait la cible, et un lien de ~/.config/autostart vers /etc/shadow y mettait le fichier des mots de
/// passe. Sous Windows, créer un lien demande déjà des droits.
fn lien_sur(m: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        let uid = std::os::unix::fs::MetadataExt::uid(m);
        #[cfg(test)]
        if tests::LIENS_SURS_DE.get() == Some(uid) {
            return true;
        }
        uid == 0
    }
    #[cfg(windows)]
    {
        let _ = m;
        true
    }
}

/// Une date en UTC, sans ambiguïté pour qui lira les traces ailleurs : « 2026-10-20T12:03:22Z ».
pub(crate) fn date_iso(t: SystemTime) -> String {
    let secondes = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    };
    date_iso_secondes(secondes)
}

pub(crate) fn date_iso_secondes(secondes: i64) -> String {
    chrono::DateTime::from_timestamp(secondes, 0)
        .map_or_else(String::new, |d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Crée un fichier neuf des traces : jamais un fichier existant écrasé, réservé au compte sous Linux et macOS.
pub(crate) fn creer_fichier(chemin: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(chemin)
}

// ───────────────────────────── Empreintes ─────────────────────────────

/// L'empreinte d'un programme ou d'un fichier, ou pourquoi elle manque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Empreinte {
    Sha256(String),
    /// Rien à lire : fil du noyau, processus du système sans programme.
    Aucune,
    Droits,
    TropGros,
    Illisible,
    /// Le temps donné aux empreintes était écoulé.
    Delai,
}

impl Empreinte {
    /// Le champ écrit dans les fichiers : l'empreinte, ou la raison entre parenthèses, dans les deux langues.
    fn champ(&self) -> String {
        match self {
            Empreinte::Sha256(h) => h.clone(),
            Empreinte::Aucune => "-".into(),
            Empreinte::Droits => "(droits/rights)".into(),
            Empreinte::TropGros => "(trop gros/too big)".into(),
            Empreinte::Illisible => "(illisible/unreadable)".into(),
            Empreinte::Delai => "(délai/timeout)".into(),
        }
    }
}

/// L'empreinte SHA-256 de ce qui se lit dans `lecteur`, en hexadécimal minuscule comme sha256sum.
pub(crate) fn sha256_de(mut lecteur: impl Read) -> std::io::Result<String> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 256 << 10];
    loop {
        let n = lecteur.read(&mut tampon)?;
        if n == 0 {
            break;
        }
        #[expect(clippy::indexing_slicing, reason = "Read::read rend au plus tampon.len() octets")]
        h.update(&tampon[..n]);
    }
    Ok(h.finalize().iter().fold(String::with_capacity(64), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    }))
}

/// L'empreinte d'un fichier de `max` octets au plus.
pub(crate) fn empreinte(chemin: &Path, max: u64) -> Empreinte {
    let lire = || -> std::io::Result<Empreinte> {
        let f = ouvrir_ordinaire(chemin, false)?;
        if f.metadata()?.len() > max {
            return Ok(Empreinte::TropGros);
        }
        Ok(Empreinte::Sha256(sha256_de(f)?))
    };
    match lire() {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Empreinte::Droits,
        Err(_) => Empreinte::Illisible,
    }
}

// ───────────────────────────── Processus ─────────────────────────────

/// Un processus en marche.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Processus {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub compte: String,
    /// Heure de démarrage, telle que le système la donne (heure locale).
    pub debut: String,
    pub programme: String,
    /// Ce qui cloche dans son programme (effacé, en mémoire seulement…), dans les deux langues ; vide sinon.
    pub etat: &'static str,
    pub ligne: String,
    pub empreinte: Empreinte,
}

pub(crate) const ENTETE_PROCESSUS: &str = "PID\tPPID\tCOMPTE/ACCOUNT\tDÉBUT/START\tSHA-256\tPROGRAMME/PROGRAM\t\
                                           ÉTAT/STATE\tLIGNE DE COMMANDE/COMMAND LINE";

/// Une ligne du fichier des processus, ses champs séparés par des tabulations.
pub(crate) fn ligne_processus(p: &Processus) -> String {
    [
        p.pid.to_string(),
        p.ppid.map_or_else(String::new, |x| x.to_string()),
        champ(&p.compte),
        champ(&p.debut),
        p.empreinte.champ(),
        champ(&p.programme),
        p.etat.to_string(),
        champ(&p.ligne),
    ]
    .join("\t")
}

/// La partie des processus, écrite dans 01-processus.txt.
pub(crate) fn partie_processus(dossier: &Path, mut liste: Vec<Processus>, mut manques: Vec<Manque>) -> Partie {
    let mut p = Partie::new(Bi::new("Processus", "Processes"));
    liste.sort_by_key(|x| x.pid);
    if !liste.is_empty() {
        let mut texte = entete(&p.titre);
        texte.push_str(ENTETE_PROCESSUS);
        texte.push('\n');
        for x in &liste {
            texte.push_str(&ligne_processus(x));
            texte.push('\n');
        }
        let n = liste.len();
        let empreintes = liste
            .iter()
            .filter(|x| matches!(x.empreinte, Empreinte::Sha256(_)))
            .count();
        if p.ecrire(
            dossier,
            "01-processus.txt",
            &texte,
            Bi::new(
                "processus en marche : PID, parent, compte, heure de démarrage, empreinte SHA-256 du programme (à chercher sur VirusTotal), programme, ce qui cloche (effacé, en mémoire seulement, dossier temporaire), ligne de commande ; un par ligne, champs séparés par des tabulations",
                "running processes: PID, parent, account, start time, SHA-256 of the program (to look up on VirusTotal), program, what is wrong (deleted, in memory only, temporary folder), command line; one per line, tab-separated fields",
            ),
        ) {
            p.compte = Some(bi!("{n} ({empreintes} empreintes)", "{n} ({empreintes} fingerprints)"));
        }
    }
    p.manques.append(&mut manques);
    p
}

// ───────────────────────────── Processus de macOS (ps) ─────────────────────────────

/// « ps -axww -o pid=,ppid=,user=,lstart=,comm= » (en anglais) : « 4242 1 alice Mon Oct 20 14:03:22 2026
/// /Applications/X.app/Contents/MacOS/X ». La date de démarrage fait toujours cinq mots ; le programme, à la fin,
/// peut contenir des espaces.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn lire_ps(sortie: &str) -> Vec<(u32, Option<u32>, String, String, String)> {
    sortie
        .lines()
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            // Neuf mots au moins : pid, parent, compte, la date en cinq mots, puis le programme.
            let [pid, parent, compte, d1, d2, d3, d4, d5, _, ..] = mots[..] else {
                return None;
            };
            let pid = pid.parse().ok()?;
            let parent = parent.parse().ok();
            let debut = [d1, d2, d3, d4, d5].join(" ");
            // Le programme : tout ce qui suit la date, espaces compris.
            let programme = apres_mots(l, 8)?;
            Some((pid, parent, compte.to_string(), debut, programme.to_string()))
        })
        .collect()
}

/// Ce qui suit les `n` premiers mots d'une ligne.
#[cfg(any(target_os = "macos", test))]
fn apres_mots(l: &str, n: usize) -> Option<&str> {
    let mut reste = l;
    for _ in 0..n {
        reste = reste.trim_start();
        let fin = reste.find(char::is_whitespace)?;
        reste = &reste[fin..];
    }
    Some(reste.trim())
}

/// « ps -axww -o pid=,args= » : la ligne de commande de chaque processus.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn lire_args(sortie: &str) -> std::collections::HashMap<u32, String> {
    sortie
        .lines()
        .filter_map(|l| {
            let (pid, args) = l.trim_start().split_once(' ')?;
            Some((pid.parse().ok()?, args.trim().to_string()))
        })
        .collect()
}

// ───────────────────────────── Fichiers récents ─────────────────────────────

/// Extensions de fichiers dont l'empreinte compte, en plus des programmes et scripts reconnus à leur contenu :
/// installateurs, archives et images disque (la façon de livrer un programme), documents à macros, lanceurs et
/// fichiers de démarrage, bibliothèques.
const A_EMPREINTER: &[&str] = &[
    "zip", "rar", "7z", "iso", "img", "vhd", "vhdx", "docm", "xlsm", "pptm", "one", "py", "pl", "rb", "php", "desktop",
    "plist", "service", "timer", "so", "dll", "sys", "dylib", "ko", "url", "reg", "inf", "chm", "cpl", "ocx",
];

/// Ce fichier mérite-t-il une empreinte ? Un programme ou un script (d'après son nom, ses premiers octets ou le droit
/// d'exécution), une archive, un document à macros, un lanceur.
pub(crate) fn a_empreinter(nom: &str, debut: &[u8], executable: bool) -> bool {
    let extension = nom.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();
    let programme = matches!(
        debut,
        [b'M', b'Z', ..]
            | [0x7f, b'E', b'L', b'F', ..]
            | [0xcf | 0xce, 0xfa, 0xed, 0xfe, ..]
            | [0xca, 0xfe, 0xba, 0xbe, ..]
            | [b'#', b'!', ..]
    );
    programme
        || executable
        || crate::protection::telechargement::PROGRAMMES.contains(&extension.as_str())
        || A_EMPREINTER.contains(&extension.as_str())
}

/// Un fichier d'un endroit à risque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entree {
    pub chemin: String,
    pub taille: u64,
    pub modifie: Option<SystemTime>,
    /// Sous Linux et macOS, le dernier changement de ses métadonnées (droits, nom, contenu) : un fichier antidaté
    /// (date de modification mise dans le passé) ne peut pas reculer celle-ci.
    pub change: Option<SystemTime>,
    pub cree: Option<SystemTime>,
    /// Droits sous Linux et macOS (« 0755 »), « l » pour un lien ; vide sous Windows.
    pub mode: String,
    pub empreinte: Option<Empreinte>,
    /// Caché par son attribut (Windows) ; sous Linux et macOS, un nom en « . » le dit déjà.
    pub cache: bool,
}

pub(crate) const ENTETE_FICHIERS: &str =
    "# SHA-256|CHEMIN/PATH|TAILLE/SIZE|MODIFIÉ/MODIFIED|CHANGÉ/CHANGED|CRÉÉ/CREATED|MODE";

/// Une ligne du fichier des fichiers récents, à la manière d'un « bodyfile » : champs séparés par « | », dates en UTC,
/// « 0 » à la place d'une empreinte non calculée (fichier qui n'est ni programme ni script, ou trop gros).
pub(crate) fn ligne_fichier(e: &Entree) -> String {
    let date = |t: Option<SystemTime>| t.map(date_iso).unwrap_or_default();
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        e.empreinte.as_ref().map_or_else(|| "0".to_string(), Empreinte::champ),
        champ(&e.chemin),
        e.taille,
        date(e.modifie),
        date(e.change),
        date(e.cree),
        e.mode
    )
}

/// Récent : écrit, changé ou créé après `depuis`.
pub(crate) fn recent(e: &Entree, depuis: SystemTime) -> bool {
    [e.modifie, e.change, e.cree].into_iter().flatten().any(|t| t >= depuis)
}

/// Ce que la lecture des endroits à risque a donné.
struct Parcours {
    entrees: Vec<Entree>,
    vus: usize,
    illisibles: Vec<String>,
    interrompu: bool,
}

/// Les fichiers récents de `racines`, sous-dossiers compris (8 niveaux), sans suivre les liens ni entrer dans
/// `exclu` (le dossier des traces lui-même) ; 200 000 fichiers et 20 secondes au plus. Jamais dans un autre système de
/// fichiers : un montage FUSE de /tmp (presse-papiers de xfreerdp, AppImage) peut ne jamais répondre, et une seule
/// lecture bloquée figeait la collecte au-delà de toute limite (vu le 20 octobre, la VM Windows ouverte). Les points
/// de `montages` sont écartés sans être interrogés ; ailleurs (macOS), un dossier d'un autre appareil que sa racine.
fn parcourir(racines: &[PathBuf], exclu: &Path, depuis: SystemTime, montages: &[PathBuf]) -> Parcours {
    let fin = Instant::now() + Duration::from_secs(20);
    let mut p = Parcours {
        entrees: Vec::new(),
        vus: 0,
        illisibles: Vec::new(),
        interrompu: false,
    };
    let mut a_voir: Vec<(PathBuf, usize, Option<u64>)> = racines
        .iter()
        .map(|r| (r.clone(), 0, std::fs::metadata(r).ok().map(|m| appareil(&m))))
        .collect();
    while let Some((dossier, profondeur, racine)) = a_voir.pop() {
        if Instant::now() > fin || p.vus > 200_000 {
            p.interrompu = true;
            break;
        }
        let entrees = match std::fs::read_dir(&dossier) {
            Ok(e) => e,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    p.illisibles.push(dossier.to_string_lossy().into_owned());
                }
                continue;
            }
        };
        for e in entrees.flatten() {
            p.vus += 1;
            let chemin = e.path();
            if chemin.starts_with(exclu) || montages.contains(&chemin) {
                continue;
            }
            let Ok(m) = std::fs::symlink_metadata(&chemin) else {
                continue;
            };
            if m.is_dir() {
                if profondeur < 8 && racine.is_none_or(|r| r == appareil(&m)) {
                    a_voir.push((chemin, profondeur + 1, racine));
                }
                continue;
            }
            let entree = decrire(&chemin, &m);
            if recent(&entree, depuis) {
                p.entrees.push(entree);
            }
        }
    }
    p
}

/// L'appareil (système de fichiers) qui porte ce fichier ; sous Windows, un seul (les montages y sont des lecteurs).
fn appareil(m: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::dev(m)
    }
    #[cfg(windows)]
    {
        let _ = m;
        0
    }
}

/// Un fichier décrit (sans son empreinte) d'après ses métadonnées.
fn decrire(chemin: &Path, m: &std::fs::Metadata) -> Entree {
    #[cfg(unix)]
    let (change, mode) = {
        use std::os::unix::fs::MetadataExt;
        let change = u64::try_from(m.ctime())
            .ok()
            .map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s));
        let mode = if m.file_type().is_symlink() {
            "l".to_string()
        } else {
            format!("{:04o}", m.mode() & 0o7777)
        };
        (change, mode)
    };
    #[cfg(windows)]
    let (change, mode) = (None, String::new());
    // FILE_ATTRIBUTE_HIDDEN.
    #[cfg(windows)]
    let cache = std::os::windows::fs::MetadataExt::file_attributes(m) & 0x2 != 0;
    #[cfg(unix)]
    let cache = false;
    Entree {
        chemin: chemin.to_string_lossy().into_owned(),
        taille: m.len(),
        modifie: m.modified().ok(),
        change,
        cree: m.created().ok(),
        mode,
        empreinte: None,
        cache,
    }
}

/// Les premiers octets d'un fichier, pour reconnaître un programme ou un script.
fn premiers_octets(chemin: &Path) -> Vec<u8> {
    let mut debut = Vec::with_capacity(4);
    if let Ok(f) = ouvrir_ordinaire(chemin, false) {
        let _ = f.take(4).read_to_end(&mut debut);
    }
    debut
}

/// Les endroits à risque : ceux de l'antivirus et de YARA (téléchargements, bureau, démarrage), et les dossiers
/// temporaires, où atterrit ce qu'un programme dépose.
fn endroits() -> Vec<PathBuf> {
    let mut liste = crate::protection::yara::endroits_a_risque();
    liste.extend(os::endroits_temporaires());
    let mut vus: Vec<PathBuf> = Vec::new();
    for d in liste {
        let reel = d.canonicalize().unwrap_or_else(|_| d.clone());
        if d.is_dir() && !vus.iter().any(|v| reel.starts_with(v)) {
            vus.push(reel);
        }
    }
    vus
}

/// La partie des fichiers récents, écrite dans 06-fichiers-recents.txt.
fn fichiers_recents(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Fichiers récents", "Recent files"));
    let racines = endroits();
    let depuis = SystemTime::now() - Duration::from_secs(JOURS_RECENTS * 86_400);
    let mut parcours = parcourir(&racines, dossier, depuis, &os::points_de_montage());
    let mut empreintes = 0;
    let fin = Instant::now() + DELAI_EMPREINTES;
    let mut en_retard = 0;
    for e in &mut parcours.entrees {
        if e.mode == "l" {
            continue;
        }
        let chemin = Path::new(&e.chemin);
        let nom = chemin
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let executable = u32::from_str_radix(&e.mode, 8).is_ok_and(|m| m & 0o111 != 0);
        if a_empreinter(&nom, &premiers_octets(chemin), executable) {
            if Instant::now() > fin {
                en_retard += 1;
                e.empreinte = Some(Empreinte::Delai);
                continue;
            }
            let x = empreinte(chemin, TAILLE_EMPREINTE);
            if matches!(x, Empreinte::Sha256(_)) {
                empreintes += 1;
            }
            e.empreinte = Some(x);
        }
    }
    parcours.entrees.sort_by(|a, b| a.chemin.cmp(&b.chemin));
    // Pour la chronologie : la date de modification de chaque fichier, et son empreinte si elle a été calculée ; un
    // fichier « parlant » (programme, script, caché, dans un dossier de démarrage) a sa ligne, les autres sont
    // comptés par dossier sous l'endroit à risque et par heure.
    let fichiers: Vec<chronologie::FichierRecent> = parcours
        .entrees
        .iter()
        .filter_map(|e| {
            let chemin = Path::new(&e.chemin);
            let racine = racines.iter().find(|r| chemin.starts_with(r))?;
            let relatif = chemin.strip_prefix(racine).ok()?;
            // Le dossier du compte : celui sous l'endroit à risque (/tmp/x pour /tmp/x/y/z), ou l'endroit lui-même.
            let dossier = match relatif.components().next() {
                Some(premier) if relatif.components().nth(1).is_some() => racine.join(premier),
                _ => racine.clone(),
            };
            let executable = u32::from_str_radix(&e.mode, 8).is_ok_and(|m| m & 0o111 != 0);
            Some(chronologie::FichierRecent {
                parlant: chronologie::parlant(&e.chemin, relatif, executable, e.cache),
                chemin: e.chemin.clone(),
                dossier: dossier.to_string_lossy().into_owned(),
                quand: chronologie::secondes(e.modifie?)?,
                taille: e.taille,
                empreinte: match &e.empreinte {
                    Some(Empreinte::Sha256(h)) => Some(h.clone()),
                    _ => None,
                },
            })
        })
        .collect();
    p.evenements = chronologie::evenements_des_fichiers(&fichiers, &chrono::Local);
    let mut texte = entete(&p.titre);
    let _ = writeln!(
        texte,
        "# Endroits / places : {}",
        racines
            .iter()
            .map(|r| champ(&r.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(
        texte,
        "# Fichiers écrits, changés ou créés depuis {JOURS_RECENTS} jours / files written, changed or created in the last {JOURS_RECENTS} days"
    );
    texte.push_str(ENTETE_FICHIERS);
    texte.push('\n');
    for e in &parcours.entrees {
        texte.push_str(&ligne_fichier(e));
        texte.push('\n');
    }
    let n = parcours.entrees.len();
    if p.ecrire(
        dossier,
        "06-fichiers-recents.txt",
        &texte,
        bi!(
            "fichiers écrits, changés ou créés depuis {JOURS_RECENTS} jours dans les endroits à risque (téléchargements, bureau, démarrage, dossiers temporaires), à la manière d'un « bodyfile » : empreinte SHA-256 des programmes, scripts, archives et lanceurs de moins de 64 Mo (« 0 » sinon), chemin, taille, dates en UTC (modifié, changé, créé), droits ; les fichiers eux-mêmes ne sont pas copiés",
            "files written, changed or created in the last {JOURS_RECENTS} days in the risky places (downloads, desktop, startup, temporary folders), bodyfile-style: SHA-256 of programs, scripts, archives and launchers under 64 MB (“0” otherwise), path, size, UTC dates (modified, changed, created), permissions; the files themselves are not copied"
        ),
    ) {
        p.compte = Some(bi!(
            "{n} ({empreintes} empreintes, {} fichiers parcourus)",
            "{n} ({empreintes} fingerprints, {} files looked at)",
            parcours.vus
        ));
    }
    if racines.is_empty() {
        p.manque(Bi::new("Endroits à risque", "Risky places"), Raison::Introuvable);
    }
    if en_retard > 0 {
        p.manque(
            bi!(
                "Empreintes de {en_retard} fichiers",
                "Fingerprints of {en_retard} files"
            ),
            Raison::Delai(DELAI_EMPREINTES.as_secs()),
        );
    }
    if parcours.interrompu {
        p.manque(
            Bi::new(
                "Fichiers au-delà de 20 s ou 200 000 fichiers",
                "Files beyond 20 s or 200,000 files",
            ),
            Raison::Delai(20),
        );
    }
    for d in parcours.illisibles.iter().take(5) {
        p.manque(Bi::meme(d.clone()), Raison::Droits);
    }
    p
}

// ───────────────────────────── Bilan ─────────────────────────────

/// Les règles du bilan gardées : toutes, sauf les mises à jour (Windows Update, gestionnaires de paquets, failles
/// connues) : elles interrogent Internet, et peuvent prendre des minutes.
pub(crate) fn regle_gardee(id: &str) -> bool {
    !id.contains("-MAJ-")
}

/// Le bilan de Vanguard en JSON (03-bilan.json) : ce qu'il juge suspect dans ce qui se lance tout seul, les comptes,
/// les fichiers, le réseau.
fn bilan(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Bilan de Vanguard", "Vanguard check"));
    let audit = crate::machine::auditer_seulement(regle_gardee);
    let json = serde_json::to_string_pretty(&audit).unwrap_or_default();
    let problemes = audit.constats.iter().filter(|c| c.probleme.is_some()).count();
    let impossibles = audit.impossibles();
    if p.ecrire(
        dossier,
        "03-bilan.json",
        &json,
        Bi::new(
            "le bilan de Vanguard (sans les mises à jour, qui interrogent Internet), en JSON : chaque constat, sa catégorie, sa gravité, son message et la règle qui l'a produit ; ce qui se lance tout seul et paraît suspect y est jugé",
            "Vanguard's check (without updates, which query the Internet), as JSON: each finding, its category, severity, message and the rule that produced it; what starts by itself and looks suspicious is judged there",
        ),
    ) {
        p.compte = Some(bi!(
            "{} constats, {problemes} problèmes, {impossibles} non vérifiés",
            "{} findings, {problemes} problems, {impossibles} not checked",
            audit.constats.len()
        ));
    }
    p
}

// ───────────────────────────── Dossier ─────────────────────────────

/// Où les traces sont écrites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lieu {
    /// Le dossier donné en argument.
    Argument,
    /// La clé VANGUARD d'où tourne le programme, à côté de donnees/ (jamais dedans : ce dossier peut être chiffré).
    Cle,
    /// Le dossier de Vanguard de cet ordinateur.
    Local,
}

/// Le dossier qui reçoit le dossier daté : celui donné, sinon `traces` sur la clé (si Vanguard en tourne et qu'elle
/// s'écrit), sinon `traces` dans le dossier de Vanguard de l'ordinateur.
pub(crate) fn choisir_parent(argument: Option<&Path>, cle: Option<&Path>, local: &Path) -> (PathBuf, Lieu) {
    match (argument, cle) {
        (Some(a), _) => (a.to_path_buf(), Lieu::Argument),
        (None, Some(c)) => (c.join("traces"), Lieu::Cle),
        (None, None) => (local.join("traces"), Lieu::Local),
    }
}

/// « traces-20261020-140322 » ; `n` > 1 pour une deuxième collecte dans la même seconde.
pub(crate) fn nom_du_dossier(date: chrono::NaiveDateTime, n: u32) -> String {
    let base = format!("traces-{}", date.format("%Y%m%d-%H%M%S"));
    if n > 1 { format!("{base}-{n}") } else { base }
}

/// Crée le dossier daté, réservé au compte sous Linux et macOS (0700) ; jamais un dossier existant réutilisé.
fn creer_dossier(parent: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(parent)?;
    let maintenant = chrono::Local::now().naive_local();
    let mut derniere = None;
    for n in 1..10 {
        let d = parent.join(nom_du_dossier(maintenant, n));
        #[cfg(unix)]
        let b = {
            let mut b = std::fs::DirBuilder::new();
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b
        };
        #[cfg(windows)]
        let b = std::fs::DirBuilder::new();
        match b.create(&d) {
            Ok(()) => return Ok(d),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => derniere = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(derniere.unwrap_or_else(|| std::io::Error::other("traces")))
}

/// Le dossier est-il bien réservé au compte ? Une clé ou un disque en exFAT ou FAT ne garde pas les droits.
#[cfg(unix)]
fn reserve_au_compte(d: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(d).is_ok_and(|m| {
        let groupe_et_autres = m.permissions().mode() & 0o077;
        groupe_et_autres == 0
    })
}

/// Place libre sur le disque de `d`.
fn place_libre(d: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        crate::socle::volume(d).map(|(libre, _)| libre)
    }
    #[cfg(windows)]
    {
        windows::place_libre(d)
    }
}

/// La taille de tout ce qui est dans le dossier.
fn taille_du_dossier(d: &Path) -> u64 {
    std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

// ───────────────────────────── LISEZMOI et manifeste ─────────────────────────────

/// Ce que le LISEZMOI dit de la collecte.
pub(crate) struct Contexte {
    pub date: String,
    pub systeme: String,
    pub machine: String,
    pub compte: String,
    /// Lancé en root ou en administrateur.
    pub privilegie: bool,
    pub duree: Duration,
}

/// Le LISEZMOI : en français puis en anglais, la date, le système, la version de Vanguard, ce que contient chaque
/// fichier, ce qui n'a pas pu être lu et pourquoi, comment vérifier le manifeste, et l'avertissement sur les données
/// personnelles.
pub(crate) fn lisezmoi(c: &Contexte, parties: &[Partie]) -> String {
    let mut t = String::new();
    for anglais in [false, true] {
        let l = |b: &Bi| if anglais { b.en.clone() } else { b.fr.clone() };
        let s = |fr: &str, en: &str| if anglais { en.to_string() } else { fr.to_string() };
        let dp = if anglais { ": " } else { " : " };
        if anglais {
            t.push_str("\n\n================================================================================\n\n");
        }
        let _ = writeln!(
            t,
            "{}",
            s("TRACES COLLECTÉES PAR VANGUARD", "TRACES COLLECTED BY VANGUARD")
        );
        let _ = writeln!(t);
        let droits = if c.privilegie {
            s("oui", "yes")
        } else {
            s(
                "non : une partie est réservée et manque (voir plus bas)",
                "no: some parts are restricted and missing (see below)",
            )
        };
        let lignes = [
            (s("Date", "Date"), c.date.clone()),
            (s("Système", "System"), c.systeme.clone()),
            (s("Ordinateur", "Computer"), c.machine.clone()),
            (s("Compte", "Account"), c.compte.clone()),
            (s("Administrateur ou root", "Administrator or root"), droits),
            (s("Vanguard", "Vanguard"), env!("CARGO_PKG_VERSION").to_string()),
            (s("Durée", "Duration"), format!("{} s", c.duree.as_secs())),
        ];
        for (k, v) in lignes {
            let _ = writeln!(t, "{k:<24}{dp}{v}");
        }
        let _ = writeln!(t);
        t.push_str(&s(
            "ATTENTION : ce dossier contient des données personnelles (noms de fichiers, comptes, adresses, programmes, lignes de commande, journaux). Ne le donne qu'à quelqu'un de confiance, et ne le publie pas. Vanguard n'a rien envoyé : tout est ici.",
            "WARNING: this folder contains personal data (file names, accounts, addresses, programs, command lines, logs). Only give it to someone you trust, and do not publish it. Vanguard sent nothing: everything is here.",
        ));
        t.push_str("\n\n");
        t.push_str(&s(
            "Lecture seule : aucun processus n'a été arrêté, aucun fichier déplacé ni effacé. Des fichiers récents, seuls le chemin, la taille, les dates et l'empreinte sont notés ; les fichiers de démarrage et de configuration, petits, sont recopiés dans le texte. Les parties sont collectées dans l'ordre où elles disparaissent : processus et connexions d'abord.",
            "Read-only: no process was stopped, no file moved or deleted. Of the recent files, only the path, size, dates and fingerprint are noted; the small startup and configuration files are copied into the text. The parts are collected in the order they vanish: processes and connections first.",
        ));
        t.push_str("\n\n");
        let _ = writeln!(t, "{}", s("RÉSUMÉ", "SUMMARY"));
        for p in parties {
            for (ok, ligne) in p.lignes(anglais) {
                let _ = writeln!(t, "  {} {ligne}", if ok { "✔" } else { "⚠" });
            }
        }
        let _ = writeln!(t);
        let _ = writeln!(t, "{}", s("FICHIERS", "FILES"));
        let _ = writeln!(t, "  LISEZMOI.txt{dp}{}", s("ce fichier", "this file"));
        for p in parties {
            for f in &p.fichiers {
                let _ = writeln!(t, "  {}{dp}{}", f.nom, l(&f.contenu));
            }
        }
        let _ = writeln!(
            t,
            "  MANIFESTE.txt{dp}{}",
            s(
                "l'empreinte SHA-256 de chaque fichier ci-dessus, pour prouver plus tard qu'il n'a pas changé",
                "the SHA-256 fingerprint of each file above, to prove later that it has not changed"
            )
        );
        let _ = writeln!(t);
        let _ = writeln!(t, "{}", s("CE QUI N'A PAS PU ÊTRE LU", "WHAT COULD NOT BE READ"));
        let manques: Vec<&Manque> = parties.iter().flat_map(|p| &p.manques).collect();
        if manques.is_empty() {
            let _ = writeln!(t, "  {}", s("Rien : tout a été lu.", "Nothing: everything was read."));
        }
        for m in manques {
            let _ = writeln!(t, "  - {}{dp}{}", l(&m.quoi), l(&m.raison.texte()));
        }
        if !c.privilegie {
            let _ = writeln!(
                t,
                "  {}",
                s(
                    "Ce qui est « réservé » se lit en relançant la collecte en administrateur (Windows) ou avec sudo (Linux, macOS).",
                    "What is “restricted” can be read by running the collection again as administrator (Windows) or with sudo (Linux, macOS)."
                )
            );
        }
        let _ = writeln!(t);
        let _ = writeln!(t, "{}", s("VÉRIFIER LE MANIFESTE", "CHECKING THE MANIFEST"));
        let _ = writeln!(t, "  Linux : sha256sum -c MANIFESTE.txt");
        let _ = writeln!(t, "  macOS : shasum -a 256 -c MANIFESTE.txt");
        let _ = writeln!(t, "  Windows (PowerShell) : Get-FileHash -Algorithm SHA256 *");
    }
    t
}

/// Le manifeste, au format de sha256sum (« empreinte, deux espaces, nom »), trié par nom : `sha256sum -c` le vérifie
/// tel quel.
pub(crate) fn manifeste(empreintes: &[(String, String)]) -> String {
    let mut lignes: Vec<&(String, String)> = empreintes.iter().collect();
    lignes.sort_by(|a, b| a.0.cmp(&b.0));
    lignes.iter().fold(String::new(), |mut t, (nom, h)| {
        let _ = writeln!(t, "{h}  {nom}");
        t
    })
}

/// L'empreinte de chaque fichier du dossier, sauf le manifeste lui-même.
fn empreintes_du_dossier(d: &Path) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        // Le fichier lui-même, jamais la cible d'un lien ; ouvert sans attendre (un tube posé entre-temps ne fige
        // pas la collecte).
        if nom == "MANIFESTE.txt" || !std::fs::symlink_metadata(e.path()).is_ok_and(|m| m.file_type().is_file()) {
            continue;
        }
        if let Ok(f) = ouvrir_ordinaire(&e.path(), true)
            && let Ok(h) = sha256_de(f)
        {
            v.push((nom, h));
        }
    }
    v
}

// ───────────────────────────── Collecte ─────────────────────────────

/// Le nom de l'ordinateur et du compte, pour le LISEZMOI.
fn machine_et_compte() -> (String, String) {
    #[cfg(target_os = "linux")]
    let machine = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    // gethostname, ce qu'affiche `hostname`, sans le lancer.
    #[cfg(target_os = "macos")]
    let machine = crate::machine::macos::nom_hote()
        .or_else(|| crate::commande::lancer(&mut Command::new("hostname"), 5).map(|r| r.sortie))
        .unwrap_or_default();
    #[cfg(windows)]
    let machine = std::env::var("COMPUTERNAME").unwrap_or_default();
    let compte = ["USER", "LOGNAME", "USERNAME"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.is_empty());
    // Sans variable (service, conteneur) : le numéro du compte, et son nom d'après /etc/passwd.
    #[cfg(unix)]
    let compte = compte.or_else(|| {
        // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
        let uid = unsafe { libc::geteuid() };
        // macOS : l'annuaire (getpwuid_r) ; /etc/passwd n'y liste pas les comptes des personnes.
        #[cfg(target_os = "macos")]
        let nom = crate::machine::macos::noyau::compte(uid);
        #[cfg(not(target_os = "macos"))]
        let nom = std::fs::read_to_string("/etc/passwd").ok().and_then(|t| {
            t.lines().find_map(|l| {
                let c: Vec<&str> = l.split(':').collect();
                let [nom, _, id, ..] = c[..] else { return None };
                (id == uid.to_string()).then(|| nom.to_string())
            })
        });
        Some(nom.map_or_else(|| uid.to_string(), |n| format!("{n} ({uid})")))
    });
    (machine.trim().to_string(), compte.unwrap_or_default())
}

/// Lancé en root ou en administrateur ?
pub(crate) fn privilegie() -> bool {
    #[cfg(unix)]
    {
        // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        windows::administrateur()
    }
}

/// Une partie et le temps qu'elle a pris.
fn chrono(partie: impl FnOnce() -> Partie) -> (Partie, Duration) {
    let debut = Instant::now();
    let p = partie();
    (p, debut.elapsed())
}

/// Affiche une partie dès qu'elle est collectée.
fn afficher(p: &Partie) {
    for (ok, ligne) in p.lignes(crate::langue::anglais()) {
        let ligne = affichable(&ligne);
        let marque = if ok {
            format!("{VERT}✔{RESET}")
        } else {
            format!("{}⚠{RESET}", couleur(crate::risk::Niveau::Moyen))
        };
        afficher_aligne(&format!("  {marque} "), &ligne, 4, "");
    }
}

/// Collecte les traces dans un dossier daté, sous `argument` ou à l'endroit par défaut ; rend le dossier, ou `None`
/// s'il n'a pas pu être créé.
pub fn collecter(argument: Option<&Path>) -> Option<PathBuf> {
    titre(tr!("Collecter les traces", "Collect the traces"));
    afficher_aligne(
        "  ",
        tr!(
            "Lecture seule : rien n'est arrêté, déplacé ni envoyé. Ce qui disparaît le plus vite d'abord (processus, connexions), puis ce qui se lance tout seul, les comptes, les journaux et les fichiers récents ; enfin, la chronologie de l'incident.",
            "Read-only: nothing is stopped, moved or sent. What vanishes fastest first (processes, connections), then what starts by itself, accounts, logs and recent files; last, the incident timeline."
        ),
        2,
        GRIS,
    );
    let cle_du_programme = crate::reseau::cle_du_programme();
    let cle = cle_du_programme.as_deref().filter(|c| crate::reseau::modifiable(c));
    let local = crate::socle::dossier_local();
    let (parent, lieu) = choisir_parent(argument, cle, &local);
    let dossier = match creer_dossier(&parent) {
        // Un chemin complet : le parcours des fichiers récents doit reconnaître ce dossier pour ne pas s'y décrire.
        Ok(d) => std::path::absolute(&d).unwrap_or(d),
        Err(e) => {
            trp!(
                "  {}✖{RESET} Dossier impossible à créer dans {} : {e}",
                "  {}✖{RESET} Cannot create the folder in {}: {e}",
                couleur(crate::risk::Niveau::Eleve),
                chemin_affichable(&parent)
            );
            return None;
        }
    };
    let montre = chemin_affichable(&dossier);
    println!();
    afficher_aligne(&format!("  {}", tr!("Dossier : ", "Folder: ")), &montre, 4, ACCENT);
    match lieu {
        Lieu::Cle => {
            let chiffree = cle_du_programme
                .as_deref()
                .is_some_and(|c| crate::chiffrement::protegee(&c.join("donnees")));
            if chiffree {
                afficher_aligne(
                    "  ",
                    tr!(
                        "Sur la clé VANGUARD, à côté de donnees/ et pas dedans : la phrase de la clé ne protège que donnees/, les traces y sont en clair.",
                        "On the VANGUARD key, next to donnees/ and not inside: the key's passphrase only protects donnees/, the traces are in clear text."
                    ),
                    2,
                    GRIS,
                );
            } else {
                afficher_aligne(
                    "  ",
                    tr!(
                        "Sur la clé VANGUARD, à côté de donnees/.",
                        "On the VANGUARD key, next to donnees/."
                    ),
                    2,
                    GRIS,
                );
            }
        }
        Lieu::Local if cle_du_programme.is_some() => afficher_aligne(
            "  ",
            tr!(
                "La clé est en lecture seule sur cet ordinateur : les traces restent dans le dossier de Vanguard de l'ordinateur. Copiez-les ensuite sur un autre disque.",
                "The key is read-only on this computer: the traces stay in this computer's Vanguard folder. Copy them to another disk afterwards."
            ),
            2,
            GRIS,
        ),
        _ => {}
    }
    #[cfg(unix)]
    if !reserve_au_compte(&dossier) {
        afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Moyen)),
            tr!(
                "Ce disque ne garde pas les droits (exFAT, FAT) : le dossier n'y est pas réservé à votre compte.",
                "This disk does not keep permissions (exFAT, FAT): the folder is not restricted to your account there."
            ),
            4,
            "",
        );
    }
    let besoin_journaux = os::place_des_journaux();
    let besoin = besoin_journaux + PLACE_HORS_JOURNAUX;
    let libre = place_libre(&dossier);
    let place = |o: u64| crate::socle::taille_lisible(o);
    match libre {
        Some(l) => trp!(
            "  {GRIS}Place nécessaire : {} au plus ; libre : {}.{RESET}",
            "  {GRIS}Space needed: {} at most; free: {}.{RESET}",
            place(besoin),
            place(l)
        ),
        None => trp!(
            "  {GRIS}Place nécessaire : {} au plus ; place libre inconnue.{RESET}",
            "  {GRIS}Space needed: {} at most; free space unknown.{RESET}",
            place(besoin)
        ),
    }
    println!();
    trp!(
        "  {GRIS}Collecte en cours (moins d'une minute en général)…{RESET}",
        "  {GRIS}Collecting (usually less than a minute)…{RESET}"
    );
    let debut = Instant::now();
    let mut parties = Vec::new();
    let montrer = |(p, duree): (Partie, Duration)| {
        // VANGUARD_CHRONO : le temps de chaque partie sur la sortie d'erreur, comme pour le bilan.
        if std::env::var_os("VANGUARD_CHRONO").is_some() {
            eprintln!("chrono {:>6} ms  {}", duree.as_millis(), p.titre.fr);
        }
        afficher(&p);
        p
    };
    // Dans l'ordre de volatilité : les processus et les connexions changent d'une seconde à l'autre.
    parties.push(montrer(chrono(|| os::processus(&dossier))));
    parties.push(montrer(chrono(|| os::reseau(&dossier))));
    // Le reste en même temps : chacun attend surtout des commandes du système.
    let place_pour_journaux = libre.is_none_or(|l| l >= besoin);
    let resultats = std::thread::scope(|s| {
        let fils = [
            s.spawn(|| chrono(|| os::demarrage(&dossier))),
            s.spawn(|| chrono(|| bilan(&dossier))),
            s.spawn(|| chrono(|| os::comptes(&dossier))),
            s.spawn(|| {
                chrono(|| {
                    if place_pour_journaux {
                        os::journaux(&dossier)
                    } else {
                        let mut p = Partie::new(Bi::new("Journaux", "Logs"));
                        p.manque(
                            Bi::new("Journaux des 7 derniers jours", "Logs of the last 7 days"),
                            Raison::Place(libre.unwrap_or(0), besoin),
                        );
                        p
                    }
                })
            }),
            s.spawn(|| chrono(|| fichiers_recents(&dossier))),
            // Ce que Vanguard a lui-même vu et fait : ses alertes, ses gestes et leur preuve.
            s.spawn(|| chrono(|| vanguard::partie(&dossier))),
        ];
        fils.map(|f| {
            f.join().unwrap_or_else(|_| {
                let mut p = Partie::new(Bi::new("Partie", "Part"));
                p.manque(
                    Bi::new("Partie", "Part"),
                    Raison::Erreur("erreur interne / internal error".into()),
                );
                (p, Duration::ZERO)
            })
        })
    });
    for p in resultats {
        parties.push(montrer(p));
    }
    // Enfin, ce que les parties ont lu de daté, dans l'ordre du temps : après les journaux, qu'elle reprend.
    let maintenant = chronologie::secondes(SystemTime::now()).unwrap_or(0);
    let c = montrer(chrono(|| {
        chronologie::partie(&dossier, &parties, os::evenements_des_journaux(&dossier), maintenant)
    }));
    parties.push(c);
    let (machine, compte) = machine_et_compte();
    let contexte = Contexte {
        date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S %:z").to_string(),
        systeme: crate::journal::systeme().to_string(),
        machine,
        compte,
        privilegie: privilegie(),
        duree: debut.elapsed(),
    };
    let mut ecrit = creer_fichier(&dossier.join("LISEZMOI.txt"))
        .and_then(|mut f| f.write_all(lisezmoi(&contexte, &parties).as_bytes()))
        .is_ok();
    ecrit &= creer_fichier(&dossier.join("MANIFESTE.txt"))
        .and_then(|mut f| f.write_all(manifeste(&empreintes_du_dossier(&dossier)).as_bytes()))
        .is_ok();
    if !ecrit {
        trp!(
            "  {}✖{RESET} LISEZMOI.txt ou MANIFESTE.txt n'a pas pu être écrit.",
            "  {}✖{RESET} LISEZMOI.txt or MANIFESTE.txt could not be written.",
            couleur(crate::risk::Niveau::Eleve)
        );
    }
    println!();
    afficher_aligne(&format!("  {}", tr!("Traces : ", "Traces: ")), &montre, 4, ACCENT);
    trp!(
        "  {GRIS}{} en {} s.{RESET}",
        "  {GRIS}{} in {} s.{RESET}",
        place(taille_du_dossier(&dossier)),
        debut.elapsed().as_secs()
    );
    afficher_aligne(
        &format!("  {} ", ampoule()),
        tr!(
            "Gardez ce dossier tel quel et copiez-le sur un autre disque avant de nettoyer. Il contient des données personnelles (noms de fichiers, comptes, adresses) : ne le donnez qu'à quelqu'un de confiance. LISEZMOI.txt dit ce que contient chaque fichier.",
            "Keep this folder as it is and copy it to another disk before cleaning up. It contains personal data (file names, accounts, addresses): only give it to someone you trust. LISEZMOI.txt says what each file contains."
        ),
        5,
        "",
    );
    Some(dossier)
}

/// « vanguard depanner traces `[dossier]` » : faux si le dossier n'a pas pu être créé.
pub fn commande(dossier: Option<&Path>) -> bool {
    collecter(dossier).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    thread_local! {
        /// Le compte dont les liens sont tenus pour sûrs, comme ceux de root, dans le fil d'un test seulement.
        pub(super) static LIENS_SURS_DE: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    }

    fn bi(fr: &str, en: &str) -> Bi {
        Bi::new(fr, en)
    }

    #[test]
    fn champs_sans_rien_qui_casse_la_ligne() {
        assert_eq!(champ("C:\\Users\\alice\\a b.exe"), "C:\\\\Users\\\\alice\\\\a b.exe");
        assert_eq!(champ("a\tb\nc|d\re"), "a\\tb\\nc\\x7cd\\re");
        // Une séquence qui piloterait le terminal, et un caractère qui retournerait la fin du nom.
        assert_eq!(champ("x\u{1b}[2Ky"), "x\\u{1b}[2Ky");
        assert_eq!(champ("fdp.\u{202e}exe"), "fdp.\\u{202e}exe");
        assert_eq!(champ("Téléchargements/été 🌞"), "Téléchargements/été 🌞");
        // La sortie d'une commande garde ses lignes et ses tabulations, pas le reste.
        assert_eq!(texte_sur("a\tb\r\nc\u{7}"), "a\tb\nc\\u{7}");
    }

    #[test]
    fn ligne_d_un_processus() {
        let p = Processus {
            pid: 4242,
            ppid: Some(1),
            compte: "alice".into(),
            debut: "2026-10-20 14:03:22".into(),
            programme: "/tmp/.x/mineur (deleted)".into(),
            etat: "effacé d'un temporaire/deleted from temp",
            ligne: "./mineur --pool\tpool.example:3333".into(),
            empreinte: Empreinte::Sha256("ab".repeat(32)),
        };
        let l = ligne_processus(&p);
        let champs: Vec<&str> = l.split('\t').collect();
        assert_eq!(champs.len(), ENTETE_PROCESSUS.split('\t').count());
        assert_eq!(champs[0], "4242");
        assert_eq!(champs[4], "ab".repeat(32));
        assert_eq!(champs[7], "./mineur --pool\\tpool.example:3333");
        let sans = Processus {
            ppid: None,
            empreinte: Empreinte::Droits,
            ..p
        };
        let champs: Vec<String> = ligne_processus(&sans).split('\t').map(String::from).collect();
        assert_eq!(champs[1], "");
        assert_eq!(champs[4], "(droits/rights)");
    }

    #[test]
    fn ligne_d_un_fichier() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_670_602);
        let e = Entree {
            chemin: "/home/alice/Téléchargements/facture|2.pdf.exe".into(),
            taille: 1234,
            modifie: Some(t),
            change: None,
            cree: Some(t),
            mode: "0755".into(),
            empreinte: Some(Empreinte::Sha256("0f".repeat(32))),
            cache: false,
        };
        assert_eq!(
            ligne_fichier(&e),
            format!(
                "{}|/home/alice/Téléchargements/facture\\x7c2.pdf.exe|1234|2026-10-22T12:03:22Z||2026-10-22T12:03:22Z|0755",
                "0f".repeat(32)
            )
        );
        assert_eq!(ligne_fichier(&e).split('|').count(), ENTETE_FICHIERS.split('|').count());
        let sans = Entree {
            empreinte: None,
            ..e.clone()
        };
        assert!(ligne_fichier(&sans).starts_with("0|"));
        // Récent : une seule des trois dates suffit (un fichier antidaté garde sa date de changement).
        let vieux = SystemTime::UNIX_EPOCH;
        let antidate = Entree {
            modifie: Some(vieux),
            cree: Some(vieux),
            change: Some(t),
            ..e
        };
        assert!(recent(&antidate, t - Duration::from_mins(1)));
        assert!(!recent(&antidate, t + Duration::from_mins(1)));
    }

    #[test]
    fn programmes_et_scripts_reconnus() {
        assert!(a_empreinter("facture.pdf", b"MZ\x90\x00", false));
        assert!(a_empreinter("photo.jpg", b"\x7fELF", false));
        assert!(a_empreinter("lanceur", b"#!/b", false));
        assert!(a_empreinter("outil", b"\0\0\0\0", true));
        assert!(a_empreinter("Setup.EXE", b"", false));
        assert!(a_empreinter("archive.zip", b"PK\x03\x04", false));
        assert!(a_empreinter("com.exemple.agent.plist", b"bpli", false));
        assert!(!a_empreinter("notes.txt", b"bonj", false));
        assert!(!a_empreinter("photo.jpg", b"\xff\xd8\xff\xe0", false));
    }

    #[test]
    fn empreinte_de_reference() {
        // Empreintes connues de SHA-256 (FIPS 180-2) : « abc » et le texte vide.
        assert_eq!(
            sha256_de(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_de(&b""[..]).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let dossier = crate::socle::dossier_local().join("empreintes");
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join("abc");
        std::fs::write(&f, b"abc").unwrap();
        assert!(matches!(empreinte(&f, 1000), Empreinte::Sha256(h) if h.starts_with("ba7816bf")));
        assert_eq!(empreinte(&f, 2), Empreinte::TropGros);
        assert_eq!(empreinte(&dossier.join("absent"), 1000), Empreinte::Illisible);
    }

    #[test]
    fn dossier_choisi() {
        let local = Path::new("/home/alice/.local/share/vanguard");
        let cle = Path::new("/run/media/alice/VANGUARD");
        let donne = Path::new("/media/alice/DISQUE/enquete");
        assert_eq!(
            choisir_parent(Some(donne), Some(cle), local),
            (donne.to_path_buf(), Lieu::Argument)
        );
        // Sur la clé : à côté de donnees/, jamais dedans.
        let (sur_la_cle, lieu) = choisir_parent(None, Some(cle), local);
        assert_eq!((sur_la_cle.clone(), lieu), (cle.join("traces"), Lieu::Cle));
        assert!(!sur_la_cle.starts_with(cle.join("donnees")));
        assert_eq!(choisir_parent(None, None, local), (local.join("traces"), Lieu::Local));
        let date = chrono::NaiveDate::from_ymd_opt(2026, 10, 20)
            .unwrap()
            .and_hms_opt(14, 3, 22)
            .unwrap();
        assert_eq!(nom_du_dossier(date, 1), "traces-20261020-140322");
        assert_eq!(nom_du_dossier(date, 2), "traces-20261020-140322-2");
    }

    #[test]
    fn dossier_neuf_reserve_au_compte() {
        let parent = crate::socle::dossier_local().join("essai-traces");
        let a = creer_dossier(&parent).unwrap();
        let b = creer_dossier(&parent).unwrap();
        assert_ne!(a, b, "un dossier existant n'est jamais réutilisé");
        #[cfg(unix)]
        assert!(reserve_au_compte(&a));
        let f = a.join("x.txt");
        creer_fichier(&f).unwrap();
        assert!(creer_fichier(&f).is_err(), "un fichier existant n'est jamais écrasé");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn manifeste_au_format_de_sha256sum() {
        let m = manifeste(&[
            ("LISEZMOI.txt".into(), "b".repeat(64)),
            ("01-processus.txt".into(), "a".repeat(64)),
        ]);
        assert_eq!(
            m,
            format!(
                "{}  01-processus.txt\n{}  LISEZMOI.txt\n",
                "a".repeat(64),
                "b".repeat(64)
            )
        );
    }

    fn parties() -> Vec<Partie> {
        let mut processus = Partie::new(bi("Processus", "Processes"));
        processus.compte = Some(bi("213", "213"));
        processus.fichiers.push(Produit {
            nom: "01-processus.txt".into(),
            contenu: bi("processus en marche", "running processes"),
        });
        processus.manque(
            bi("Programme de 12 processus", "Program of 12 processes"),
            Raison::Droits,
        );
        let mut journaux = Partie::new(bi("Journaux", "Logs"));
        journaux.manque(
            bi("Journal de sécurité", "Security log"),
            Raison::Absente("wevtutil".into()),
        );
        journaux.manque(bi("Journal du système", "System log"), Raison::Borne(BORNE_JOURNAL));
        vec![processus, journaux]
    }

    #[test]
    fn lisezmoi_en_deux_langues() {
        let c = Contexte {
            date: "2026-10-20 14:03:22 +02:00".into(),
            systeme: "Linux".into(),
            machine: "portable".into(),
            compte: "alice".into(),
            privilegie: false,
            duree: Duration::from_secs(12),
        };
        let t = lisezmoi(&c, &parties());
        let (fr, en) = t.split_once("========").unwrap();
        assert!(fr.contains("TRACES COLLECTÉES PAR VANGUARD") && en.contains("TRACES COLLECTED BY VANGUARD"));
        assert!(fr.contains(env!("CARGO_PKG_VERSION")) && en.contains(env!("CARGO_PKG_VERSION")));
        assert!(fr.contains("données personnelles") && en.contains("personal data"));
        assert!(fr.contains("✔ Processus : 213") && en.contains("✔ Processes: 213"));
        assert!(fr.contains("01-processus.txt : processus en marche"));
        assert!(en.contains("01-processus.txt: running processes"));
        assert!(fr.contains("MANIFESTE.txt") && fr.contains("LISEZMOI.txt"));
        // Ce qui manque, et pourquoi.
        assert!(
            fr.contains("Journal de sécurité : commande « wevtutil » absente"),
            "{fr}"
        );
        assert!(en.contains("Security log: “wevtutil” command missing"), "{en}");
        assert!(fr.contains("coupé à 50 Mo") && en.contains("cut at 50 MB"));
        assert!(fr.contains("relançant la collecte en administrateur"));
        assert!(fr.contains("sha256sum -c MANIFESTE.txt"));
        let tout_lu = lisezmoi(&Contexte { privilegie: true, ..c }, &[]);
        assert!(tout_lu.contains("Rien : tout a été lu.") && !tout_lu.contains("relançant"));
    }

    #[test]
    fn lignes_du_resume() {
        let p = &parties()[0];
        let lignes = p.lignes(false);
        assert_eq!(lignes[0], (true, "Processus : 213".to_string()));
        assert!(!lignes[1].0);
        assert!(lignes[1].1.starts_with("Programme de 12 processus : réservé à "));
        // Rien lu : seulement les manques.
        let j = &parties()[1];
        assert!(j.lignes(false).iter().all(|(ok, _)| !ok));
        assert!(j.lignes(true)[0].1.starts_with("Security log: "));
    }

    #[test]
    fn mises_a_jour_hors_du_bilan_joint() {
        assert!(!regle_gardee("LNX-MAJ-003") && !regle_gardee("WIN-MAJ-001") && !regle_gardee("COM-MAJ-001"));
        assert!(regle_gardee("LNX-PRS-001") && regle_gardee("COM-DIS-001"));
        // Les règles des mises à jour existent bien sous ce nom : sinon le filtre ne retirerait plus rien.
        let regles = crate::machine::regles::regles(crate::machine::regles::Os::actuel());
        assert!(regles.iter().any(|r| !regle_gardee(r.id)));
    }

    #[test]
    fn feuille_dit_ce_qui_manque() {
        let mut f = Feuille::new(&bi("Réseau", "Network"));
        assert!(f.texte.starts_with("# Vanguard ") && f.texte.contains("Réseau / Network"));
        let sortie = f.commande(&mut Command::new("vanguard-commande-qui-n-existe-pas"), 5, true);
        assert!(sortie.is_none());
        assert_eq!(f.manques.len(), 1);
        assert_eq!(
            f.manques[0].raison,
            Raison::Absente("vanguard-commande-qui-n-existe-pas".into())
        );
        f.commande(&mut Command::new("vanguard-autre-absente"), 5, false);
        assert_eq!(
            f.manques.len(),
            1,
            "une commande facultative absente est dite dans le fichier seulement"
        );
        assert!(f.texte.contains("== $ vanguard-autre-absente ==\n") && f.texte.contains("absente"));
        // Un fichier absent n'écrit rien ; un fichier lu est recopié sous son chemin.
        let dossier = crate::socle::dossier_local().join("feuille");
        std::fs::create_dir_all(&dossier).unwrap();
        f.fichier(&dossier.join("absent"), true);
        assert_eq!(f.lues, 0);
        std::fs::write(dossier.join("hosts"), "127.0.0.1 localhost\n\u{1b}[2J").unwrap();
        f.fichier(&dossier.join("hosts"), true);
        assert_eq!(f.lues, 1);
        assert!(f.texte.contains("127.0.0.1 localhost\n\\u{1b}[2J"));
        // Un lien posé par un compte ordinaire est dit, jamais suivi : sa cible (ici un faux secret) n'est pas recopiée.
        #[cfg(unix)]
        // SAFETY : geteuid n'a ni pointeur ni effet de bord.
        if unsafe { libc::geteuid() } != 0 {
            std::fs::write(dossier.join("secret"), "mot-de-passe-de-root\n").unwrap();
            std::os::unix::fs::symlink(dossier.join("secret"), dossier.join("lien")).unwrap();
            f.fichier(&dossier.join("lien"), true);
            f.dossier(&dossier, 10, false);
            assert!(f.texte.contains("pas suivi") && f.texte.contains("secret"));
            assert_eq!(
                f.texte.matches("mot-de-passe-de-root").count(),
                1,
                "seul le fichier lui-même est recopié"
            );
        }
        // Un tube nommé ne bloque ni l'empreinte, ni le début lu, ni la copie : refusé aussitôt, sans écrivain en face.
        #[cfg(unix)]
        {
            let tube = dossier.join("tube");
            let nom = std::ffi::CString::new(tube.to_string_lossy().as_bytes()).unwrap();
            // SAFETY : mkfifo lit le chemin terminé par un zéro que `nom` garde en vie pendant l'appel.
            assert_eq!(unsafe { libc::mkfifo(nom.as_ptr(), 0o600) }, 0);
            let debut = Instant::now();
            assert_eq!(empreinte(&tube, 1024), Empreinte::Illisible);
            assert_eq!(premiers_octets(&tube), Vec::<u8>::new());
            f.fichier(&tube, false);
            assert!(debut.elapsed() < Duration::from_secs(2));
        }
    }

    /// Chaque fichier listé ou recopié garde sa date pour la chronologie, sans être relu.
    #[test]
    fn feuille_garde_les_dates() {
        let dossier = crate::socle::dossier_local().join("feuille-dates");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(dossier.join("sous")).unwrap();
        std::fs::write(dossier.join("a.service"), "[Unit]\n").unwrap();
        let mut f = Feuille::new(&bi("Démarrage", "Startup"));
        f.dossier(&dossier, 10, false);
        f.fichier(&dossier.join("absent"), false);
        let chemins: Vec<String> = f.dates.iter().map(|(c, _)| c.clone()).collect();
        let a = dossier.join("a.service").to_string_lossy().into_owned();
        let sous = dossier.join("sous").to_string_lossy().into_owned();
        // Listé puis recopié : deux fois la même date, une seule ligne dans la chronologie.
        assert_eq!(chemins.iter().filter(|c| **c == a).count(), 2, "{chemins:?}");
        assert!(chemins.contains(&sous));
        assert_eq!(chemins.len(), 3);
        let maintenant = chronologie::secondes(SystemTime::now()).unwrap();
        let v = chronologie::garder(chronologie::lancements(&f.dates), maintenant - 60, maintenant + 60);
        assert_eq!(v.len(), 2);
        assert_eq!(
            Raison::Lignes(12).texte(),
            bi(
                "12 lignes de plus ne sont pas gardées (5000 au plus)",
                "12 more lines are not kept (5000 at most)"
            )
        );
    }

    /// Un lien de root, comme un service activé de systemd, se date par lui-même et jamais par sa cible, que la mise à
    /// jour d'un paquet réécrit. Un lien et sa cible inventés dans un dossier jetable ; le lien, posé par ce compte,
    /// est tenu pour sûr le temps du test (`LIENS_SURS_DE`), pour passer par le même chemin qu'un lien de root.
    #[cfg(unix)]
    #[test]
    fn lien_date_par_lui_meme() {
        let d = crate::socle::dossier_local().join("essai-lien-date");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let cible = d.join("service-du-paquet.service");
        std::fs::write(&cible, "[Service]\nExecStart=/usr/bin/true\n").unwrap();
        // La cible réécrite par une « mise à jour » datée de 2001 : rien ne doit l'en faire sortir.
        let ancienne = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(&cible)
            .unwrap()
            .set_modified(ancienne)
            .unwrap();
        let lien = d.join("service-active.service");
        std::os::unix::fs::symlink(&cible, &lien).unwrap();
        let m = std::fs::symlink_metadata(&lien).unwrap();
        let attendue = m.modified().unwrap();
        assert_ne!(attendue, ancienne);
        let dates_de = |f: &Feuille| -> Vec<SystemTime> {
            f.dates
                .iter()
                .filter(|(c, _)| Path::new(c) == lien)
                .map(|(_, t)| *t)
                .collect()
        };
        // Sûr : la cible est recopiée, et le lien daté par lui-même.
        LIENS_SURS_DE.set(Some(std::os::unix::fs::MetadataExt::uid(&m)));
        assert!(lien_sur(&m));
        let mut f = Feuille::new(&bi("Démarrage", "Startup"));
        f.fichier(&lien, false);
        LIENS_SURS_DE.set(None);
        let dates = dates_de(&f);
        assert!(!dates.is_empty() && dates.iter().all(|t| *t == attendue), "{dates:?}");
        assert!(f.texte.contains("ExecStart=/usr/bin/true"), "{}", f.texte);
        // Pas sûr (posé par un compte ordinaire) : pas suivi, daté par lui-même aussi.
        if std::os::unix::fs::MetadataExt::uid(&m) != 0 {
            let mut f = Feuille::new(&bi("Démarrage", "Startup"));
            f.fichier(&lien, false);
            let dates = dates_de(&f);
            assert!(!dates.is_empty() && dates.iter().all(|t| *t == attendue), "{dates:?}");
            assert!(!f.texte.contains("ExecStart"), "{}", f.texte);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn secrets_du_shell_masques() {
        let texte = "export GITHUB_TOKEN=ghp_abc123\n\
            CLE_API=\"x\" # commentaire\n\
            declare -x DB_PASSWORD='p'\n\
            set -gx OPENAI_API_KEY sk-123\n\
            export LD_PRELOAD=/tmp/x.so\n\
            export PATH=$HOME/bin:$PATH\n\
            XKB_KEYBOARD=fr\n\
            alias ll='ls -l'\n\
            git clone https://alice:hunter2@exemple.org/depot\n\
            export PWD_DE_BASE=/home\n";
        let m = masquer_secrets(texte);
        for secret in ["ghp_abc123", "\"x\"", "'p'", "sk-123", "hunter2"] {
            assert!(!m.contains(secret), "{secret} visible :\n{m}");
        }
        for garde in [
            "export GITHUB_TOKEN=(masqué)",
            "set -gx OPENAI_API_KEY (masqué)",
            "export LD_PRELOAD=/tmp/x.so",
            "export PATH=$HOME/bin:$PATH",
            "XKB_KEYBOARD=fr",
            "alias ll='ls -l'",
            "https://alice:(masqué)@exemple.org/depot",
            "export PWD_DE_BASE=/home",
        ] {
            assert!(m.contains(garde), "{garde} manque :\n{m}");
        }
        assert_eq!(m.lines().count(), texte.lines().count());
    }

    #[test]
    fn sorties_de_ps() {
        let ps = "  4242     1 alice    Mon Oct 20 14:03:22 2026     /Applications/Mon Outil.app/Contents/MacOS/Mon Outil\n\
                  1     0 root     Sun Oct 19 08:00:01 2026     /sbin/launchd\n\
                  2026  1 bob      Sun Oct 19 08:00:01 2026     /tmp/2026 x\n\
                  incomplet\n";
        let l = lire_ps(ps);
        assert_eq!(l.len(), 3);
        assert_eq!(l[2].4, "/tmp/2026 x");
        assert_eq!(l[0].0, 4242);
        assert_eq!(l[0].2, "alice");
        assert_eq!(l[0].3, "Mon Oct 20 14:03:22 2026");
        assert_eq!(l[0].4, "/Applications/Mon Outil.app/Contents/MacOS/Mon Outil");
        assert_eq!(l[1].4, "/sbin/launchd");
        let args =
            lire_args("  4242 /Applications/Mon Outil.app/Contents/MacOS/Mon Outil -psn_0\n    1 /sbin/launchd\n");
        assert_eq!(args.get(&1).map(String::as_str), Some("/sbin/launchd"));
        assert!(args.get(&4242).is_some_and(|a| a.ends_with("-psn_0")));
    }
}
