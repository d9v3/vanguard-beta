//! Écrire un plugin de Vanguard en Rust.
//!
//! Un plugin est un programme que Vanguard lance (`vanguard plugins <nom>`) ; ce qu'il écrit sur sa sortie standard
//! est montré, et une ligne qui est un objet JSON `{"vanguard":1,"niveau":…,"categorie":…,"message":…}` devient un
//! constat, affiché comme ceux du bilan (jamais compté dans la note). Cette bibliothèque écrit ces lignes
//! exactement comme Vanguard les lit, dit la langue de l'interface, et lance un autre programme proprement : sans
//! shell, avec un délai et une sortie bornée.
//!
//! ```no_run
//! use vanguard_extension::{Constat, message};
//! message("Bonjour depuis un plugin en Rust.");
//! Constat::moyen("Salon", "Une prise inventée est ouverte.").envoyer();
//! Constat::ok("Salon", "Tout le reste va bien.").envoyer();
//! ```

// Pas d'`unsafe` hors du seul appel au système qui en demande un (`arreter`).
#![deny(unsafe_code)]

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Le niveau d'un constat : `Ok` (rien à signaler) puis du moins au plus grave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Niveau {
    Ok,
    Info,
    Moyen,
    Eleve,
    Critique,
}

impl Niveau {
    /// Le mot du protocole.
    #[must_use]
    pub fn mot(self) -> &'static str {
        match self {
            Niveau::Ok => "ok",
            Niveau::Info => "info",
            Niveau::Moyen => "moyen",
            Niveau::Eleve => "eleve",
            Niveau::Critique => "critique",
        }
    }
}

/// Un constat à envoyer à Vanguard. Vanguard le borne à l'affichage (catégorie 40 caractères, message 300, 100
/// constats par lancement) et retire les caractères qui piloteraient le terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constat {
    pub niveau: Niveau,
    pub categorie: String,
    pub message: String,
}

impl Constat {
    pub fn nouveau(niveau: Niveau, categorie: impl Into<String>, message: impl Into<String>) -> Constat {
        Constat {
            niveau,
            categorie: categorie.into(),
            message: message.into(),
        }
    }

    pub fn ok(categorie: impl Into<String>, message: impl Into<String>) -> Constat {
        Constat::nouveau(Niveau::Ok, categorie, message)
    }

    pub fn info(categorie: impl Into<String>, message: impl Into<String>) -> Constat {
        Constat::nouveau(Niveau::Info, categorie, message)
    }

    pub fn moyen(categorie: impl Into<String>, message: impl Into<String>) -> Constat {
        Constat::nouveau(Niveau::Moyen, categorie, message)
    }

    pub fn eleve(categorie: impl Into<String>, message: impl Into<String>) -> Constat {
        Constat::nouveau(Niveau::Eleve, categorie, message)
    }

    pub fn critique(categorie: impl Into<String>, message: impl Into<String>) -> Constat {
        Constat::nouveau(Niveau::Critique, categorie, message)
    }

    /// La ligne du protocole, sans saut de ligne final.
    #[must_use]
    pub fn json(&self) -> String {
        format!(
            "{{\"vanguard\":1,\"niveau\":\"{}\",\"categorie\":{},\"message\":{}}}",
            self.niveau.mot(),
            chaine_json(&self.categorie),
            chaine_json(&self.message)
        )
    }

    /// Écrit la ligne sur la sortie standard, d'un seul tenant (une ligne coupée ne serait plus un constat).
    pub fn envoyer(&self) {
        let mut sortie = std::io::stdout().lock();
        let _ = writeln!(sortie, "{}", self.json());
        let _ = sortie.flush();
    }
}

/// Une chaîne JSON entre guillemets : « " » et « \ » échappés, chaque caractère de contrôle aussi (un saut de ligne
/// gardé tel quel couperait la ligne du constat en deux), et les séparateurs U+2028 et U+2029.
#[must_use]
pub fn chaine_json(texte: &str) -> String {
    let mut s = String::with_capacity(texte.len() + 2);
    s.push('"');
    for c in texte.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(s, "\\u{:04x}", c as u32);
            }
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// Une ligne ordinaire, montrée telle quelle par Vanguard. Ses sauts de ligne en font plusieurs.
pub fn message(texte: &str) {
    let mut sortie = std::io::stdout().lock();
    let _ = writeln!(sortie, "{texte}");
    let _ = sortie.flush();
}

/// La langue de l'interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Langue {
    Francais,
    Anglais,
}

/// Comme Vanguard : `LC_ALL`, puis `LC_MESSAGES`, puis `LANG` (« fr_CA.UTF-8 » → français) ; sans langue connue, anglais.
/// Vanguard passe `LANG` à ses plugins.
#[must_use]
pub fn langue() -> Langue {
    langue_de(|v| std::env::var(v).ok())
}

fn langue_de(lire: impl Fn(&str) -> Option<String>) -> Langue {
    let code = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|v| lire(v))
        .find(|v| !v.is_empty())
        .and_then(|v| v.split(['_', '.', '@', '-']).next().map(str::to_ascii_lowercase));
    if code.as_deref() == Some("fr") {
        Langue::Francais
    } else {
        Langue::Anglais
    }
}

/// Le texte dans la langue de l'interface : `tr("Bonjour", "Hello")`.
#[must_use]
pub fn tr<'a>(fr: &'a str, en: &'a str) -> &'a str {
    if langue() == Langue::Francais { fr } else { en }
}

/// Les arguments donnés au plugin (ceux du manifeste, puis ceux tapés après `vanguard plugins <nom>`).
#[must_use]
pub fn arguments() -> Vec<String> {
    std::env::args().skip(1).collect()
}

/// Ce qu'un programme lancé par `lancer` a fait.
#[derive(Debug)]
pub struct Sortie {
    /// Code de retour ; `None` s'il a été arrêté (délai, borne) ou tué par un signal.
    pub code: Option<i32>,
    pub sortie: String,
    pub erreurs: String,
    /// Une sortie a passé la borne : il a été arrêté là.
    pub tronque: bool,
    /// Le délai est passé : il a été arrêté.
    pub delai: bool,
}

/// Ce qu'on garde de chaque sortie, au plus.
pub const SORTIE_MAX: usize = 1 << 20;

fn lire_borne(
    mut flux: impl Read + Send + 'static,
    plein: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> mpsc::Receiver<Vec<u8>> {
    let (envoi, reception) = mpsc::channel();
    std::thread::spawn(move || {
        let mut lu = Vec::new();
        let mut tampon = [0u8; 8192];
        loop {
            let n = match flux.read(&mut tampon) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let reste = SORTIE_MAX - lu.len();
            lu.extend_from_slice(&tampon[..n.min(reste)]);
            if n > reste {
                plein.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
        let _ = envoi.send(lu);
    });
    reception
}

/// Lance `programme` avec `arguments`, sans shell (chaque argument arrive tel quel, rien n'est interprété), l'entrée
/// fermée, et attend au plus `delai`. Chaque sortie est gardée jusqu'à `SORTIE_MAX` octets ; passé la borne ou le
/// délai, le programme est arrêté (sous Unix, avec tout son groupe de processus : ce qu'il a lancé aussi).
///
/// # Errors
///
/// Le programme ne démarre pas (introuvable, pas le droit de l'exécuter), ou son état ne se lit plus.
pub fn lancer(programme: impl AsRef<OsStr>, arguments: &[&str], delai: Duration) -> std::io::Result<Sortie> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut c = Command::new(programme);
    c.args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Son propre groupe : l'arrêter arrête aussi ses enfants.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    let mut enfant = c.spawn()?;
    let plein = Arc::new(AtomicBool::new(false));
    let manque = || std::io::Error::other("sortie non ouverte");
    let sortie = lire_borne(enfant.stdout.take().ok_or_else(manque)?, plein.clone());
    let erreurs = lire_borne(enfant.stderr.take().ok_or_else(manque)?, plein.clone());
    let limite = Instant::now() + delai;
    let (mut tronque, mut depasse) = (false, false);
    let code = loop {
        if let Some(statut) = enfant.try_wait()? {
            break statut.code();
        }
        let plein_ = plein.load(Ordering::Relaxed);
        if plein_ || Instant::now() >= limite {
            tronque = plein_;
            depasse = !plein_;
            arreter(&mut enfant);
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let texte = |r: mpsc::Receiver<Vec<u8>>| {
        r.recv_timeout(Duration::from_secs(2))
            .map(|o| String::from_utf8_lossy(&o).into_owned())
            .unwrap_or_default()
    };
    // Arrêté par SIGPIPE quand la lecture a cessé à la borne : tronqué aussi.
    tronque |= plein.load(Ordering::Relaxed);
    Ok(Sortie {
        code,
        sortie: texte(sortie),
        erreurs: texte(erreurs),
        tronque,
        delai: depasse,
    })
}

// FFI de libc : kill, pour arrêter tout le groupe de processus du programme lancé.
#[allow(unsafe_code)]
fn arreter(enfant: &mut std::process::Child) {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        if let Ok(groupe) = i32::try_from(enfant.id()) {
            // SAFETY: simple envoi de SIGKILL (9) au groupe de processus créé pour ce programme (numéro négatif).
            unsafe { kill(-groupe, 9) };
        }
    }
    let _ = enfant.kill();
    let _ = enfant.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_echappe_ce_qu_il_faut() {
        assert_eq!(chaine_json("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(chaine_json("l1\nl2\r\t"), r#""l1\nl2\r\t""#);
        assert_eq!(chaine_json("\u{1b}[2K\u{0}\u{7f}"), r#""\u001b[2K\u0000\u007f""#);
        assert_eq!(chaine_json("é ✔ \u{2028}"), "\"é ✔ \\u2028\"");
        let c = Constat::eleve("Réseau \"Salon\"", "Port\nouvert");
        assert_eq!(
            c.json(),
            r#"{"vanguard":1,"niveau":"eleve","categorie":"Réseau \"Salon\"","message":"Port\nouvert"}"#
        );
        assert!(!c.json().contains('\n'));
    }

    #[test]
    fn les_niveaux_du_protocole() {
        let mots: Vec<&str> = [
            Constat::ok("a", "b"),
            Constat::info("a", "b"),
            Constat::moyen("a", "b"),
            Constat::eleve("a", "b"),
            Constat::critique("a", "b"),
        ]
        .iter()
        .map(|c| c.niveau.mot())
        .collect();
        assert_eq!(mots, ["ok", "info", "moyen", "eleve", "critique"]);
    }

    #[test]
    fn langue_comme_vanguard() {
        let env = |paires: &'static [(&'static str, &'static str)]| {
            move |v: &str| paires.iter().find(|(k, _)| *k == v).map(|(_, x)| (*x).to_string())
        };
        assert_eq!(langue_de(env(&[("LANG", "fr_CA.UTF-8")])), Langue::Francais);
        assert_eq!(
            langue_de(env(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "fr_FR.UTF-8")])),
            Langue::Anglais
        );
        assert_eq!(langue_de(env(&[("LC_ALL", ""), ("LANG", "fr")])), Langue::Francais);
        assert_eq!(langue_de(env(&[])), Langue::Anglais);
    }

    #[cfg(unix)]
    #[test]
    fn lancer_sans_shell_avec_delai_et_borne() {
        // Sans shell : « ; » et « $(…) » arrivent tels quels.
        let s = lancer("echo", &["a;b", "$(id)"], Duration::from_secs(5)).unwrap();
        assert_eq!((s.code, s.sortie.as_str()), (Some(0), "a;b $(id)\n"));
        let debut = Instant::now();
        let s = lancer("sleep", &["30"], Duration::from_millis(300)).unwrap();
        assert!(s.delai && s.code.is_none() && debut.elapsed() < Duration::from_secs(5));
        let s = lancer("yes", &[], Duration::from_secs(30)).unwrap();
        assert!(s.tronque && s.sortie.len() <= SORTIE_MAX);
        assert!(lancer("/nexiste/pas", &[], Duration::from_secs(1)).is_err());
    }
}
