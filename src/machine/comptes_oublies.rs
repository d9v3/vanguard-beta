//! Comptes oubliés : un compte de l'ordinateur encore actif mais que personne n'utilise plus (l'ancien employé, le
//! compte créé pour un dépannage, celui d'un enfant parti). C'est une porte de plus, souvent avec un vieux mot de
//! passe. Vanguard cherche la dernière trace d'utilisation : la dernière connexion notée par le système (Windows,
//! lastlog2 ou lastlog sous Linux, l'historique utmpx sous macOS), et la date du dossier personnel (Linux, macOS :
//! une connexion graphique n'est pas toujours notée). Rien depuis six mois : une information, avec la façon de le
//! désactiver. Le compte qui lance Vanguard n'est jamais compté.

use super::{Constat, alerte};
use crate::risk::Niveau;
use crate::ui::affichable;
use crate::{tr, trf};

const CAT: &str = "Comptes";
/// Sans trace depuis plus longtemps, un compte est oublié.
const OUBLIE_JOURS: i64 = 180;

/// Un compte actif : son nom, et la dernière trace d'utilisation (`None` : aucune, jamais connecté).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Compte {
    nom: String,
    derniere: Option<chrono::NaiveDate>,
}

fn juger(comptes: &[Compte], aujourd_hui: chrono::NaiveDate) -> Vec<Constat> {
    comptes
        .iter()
        .filter_map(|c| {
            let nom = affichable(&c.nom);
            let message = match c.derniere {
                None => trf!(
                    "Le compte « {nom} » est actif mais n'a jamais servi : un compte oublié est une porte de plus, souvent avec un mot de passe faible.",
                    "The “{nom}” account is active but has never been used: a forgotten account is one more door, often with a weak password."
                ),
                Some(d) if (aujourd_hui - d).num_days() > OUBLIE_JOURS => trf!(
                    "Le compte « {nom} » est actif mais n'a pas servi depuis le {d} : un compte oublié est une porte de plus, souvent avec un vieux mot de passe.",
                    "The “{nom}” account is active but has not been used since {d}: a forgotten account is one more door, often with an old password."
                ),
                Some(_) => return None,
            };
            // Le compte par son nom tel que le système le donne : la date qui change ne fait pas un autre objet.
            Some(
                alerte(CAT, Niveau::Info, message)
                    .avec_objet(crate::modele::Objet::de("compte", &c.nom))
                    .manuel(desactiver(), &[]),
            )
        })
        .collect()
}

/// Comment désactiver un compte sans rien effacer, sur ce système.
fn desactiver() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Si personne ne s'en sert, le désactiver (ses fichiers restent) : Gestion de l'ordinateur › Utilisateurs locaux, ou « Disable-LocalUser -Name <nom> » en administrateur",
            "If nobody uses it, disable it (its files stay): Computer Management › Local Users, or “Disable-LocalUser -Name <name>” as administrator"
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Si personne ne s'en sert, le supprimer en gardant son dossier : Réglages Système › Utilisateurs et groupes",
            "If nobody uses it, delete it while keeping its folder: System Settings › Users & Groups"
        )
    } else {
        tr!(
            "Si personne ne s'en sert, le verrouiller (ses fichiers restent) : « sudo usermod --lock --expiredate 1 <nom> »",
            "If nobody uses it, lock it (its files stay): “sudo usermod --lock --expiredate 1 <name>”"
        )
    }
}

/// La date d'un fichier, en jour local.
#[cfg(unix)]
fn date_de(chemin: &std::path::Path) -> Option<chrono::NaiveDate> {
    let m = std::fs::metadata(chemin).ok()?.modified().ok()?;
    Some(chrono::DateTime::<chrono::Local>::from(m).date_naive())
}

/// Le compte qui lance Vanguard (sous sudo : celui qui l'a lancé).
#[cfg(unix)]
fn moi() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}

/// « dp  tty1   Sat Oct 17 22:51:53 -0400 2026 » ou « **Never logged in** » (lastlog2, lastlog) : la date.
#[cfg(any(target_os = "linux", test))]
fn lire_lastlog(ligne: &str) -> Option<chrono::NaiveDate> {
    let mots: Vec<&str> = ligne.split_whitespace().collect();
    let i = mots
        .iter()
        .position(|m| m.len() == 3 && ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(m))?;
    let texte = mots.get(i..i + 6)?.join(" ");
    chrono::DateTime::parse_from_str(&texte, "%a %b %e %H:%M:%S %z %Y")
        .ok()
        .map(|d| d.date_naive())
}

/// La date locale de secondes depuis 1970 (0 ou moins : jamais).
#[cfg(target_os = "linux")]
fn jour_de(secondes: i64) -> Option<chrono::NaiveDate> {
    (secondes > 0)
        .then(|| chrono::DateTime::from_timestamp(secondes, 0))
        .flatten()
        .map(|d| d.with_timezone(&chrono::Local).date_naive())
}

/// Les dernières connexions de lastlog2.db, lues par le lecteur SQLite maison : compte → jour. `Some(vide)` sans
/// base (le système ne s'en sert pas) ; `None` : base présente mais pas lisible seule (journal en attente, abîmée,
/// droits) : l'outil lastlog2 la relira.
#[cfg(target_os = "linux")]
fn lastlog2_natif() -> Option<std::collections::HashMap<String, chrono::NaiveDate>> {
    use crate::machine::linux::connexions;
    match connexions::base(std::path::Path::new(connexions::LASTLOG2)) {
        Err(connexions::PasLue::Absente) => Some(std::collections::HashMap::new()),
        Err(_) => None,
        Ok(octets) => Some(
            connexions::lastlog2(&octets)?
                .into_iter()
                .filter_map(|d| Some((d.compte, jour_de(d.secondes)?)))
                .collect(),
        ),
    }
}

/// La dernière connexion d'un compte : lastlog2.db puis /var/log/lastlog, lus par Vanguard (la plus récente des
/// deux, comme lastlog2 puis lastlog l'étaient) ; l'outil seulement pour une source qui ne se lit pas ici.
#[cfg(target_os = "linux")]
fn derniere_connexion(
    nom: &str,
    uid: u32,
    natif2: Option<&std::collections::HashMap<String, chrono::NaiveDate>>,
) -> Option<chrono::NaiveDate> {
    use crate::machine::linux::connexions;
    let outil = |outil: &str| {
        let r = crate::commande::lancer_en_anglais(std::process::Command::new(outil).args(["-u", nom]), 5)?;
        r.sortie.lines().skip(1).find_map(lire_lastlog)
    };
    let par_lastlog2 = match natif2 {
        Some(m) => m.get(nom).copied(),
        None => outil("lastlog2"),
    };
    let par_lastlog = match connexions::lastlog_de(std::path::Path::new(connexions::LASTLOG), uid) {
        Ok(e) => e.and_then(|(t, _, _)| jour_de(i64::from(t))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => outil("lastlog"),
    };
    par_lastlog2.max(par_lastlog)
}

#[cfg(target_os = "linux")]
pub fn constats() -> Vec<Constat> {
    let moi = moi();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let natif2 = lastlog2_natif();
    let comptes: Vec<Compte> = passwd
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            let (nom, uid, maison, shell) = (*c.first()?, c.get(2)?.parse::<u32>().ok()?, *c.get(5)?, *c.get(6)?);
            let humain = (1000..60000).contains(&uid) && !shell.ends_with("nologin") && !shell.ends_with("false");
            (humain && nom != moi).then(|| (nom.to_string(), uid, maison.to_string()))
        })
        .map(|(nom, uid, maison)| {
            let connexion = derniere_connexion(&nom, uid, natif2.as_ref());
            let dossier = date_de(std::path::Path::new(&maison));
            Compte {
                nom,
                derniere: connexion.max(dossier),
            }
        })
        .collect();
    juger(&comptes, chrono::Local::now().date_naive())
}

/// macOS : les comptes de session (UID à partir de 501, sans les comptes de service « _ »), lus dans la base des
/// comptes par `getpwent` (la même que `dscl . -list /Users`, sans lancer de programme) avec leur vrai dossier
/// personnel (NFSHomeDirectory, que `pw_dir` rend : pas toujours /Users/<nom>, un volume externe parfois). La
/// dernière trace : la session la plus récente que le système a notée (utmpx, ce que `last` lit), sinon la date du
/// dossier personnel.
#[cfg(target_os = "macos")]
pub fn constats() -> Vec<Constat> {
    let comptes = comptes_macos(&base_des_comptes(), &dernieres_sessions(), &moi(), date_de);
    juger(&comptes, chrono::Local::now().date_naive())
}

/// Les comptes de session parmi ceux de la base (nom, UID, dossier personnel) : UID à partir de 501 (ceux créés
/// dans Réglages Système), sans les comptes de service (« _ ») ni celui qui lance Vanguard. La dernière trace est
/// la plus récente de la dernière session et de la date du dossier. Un nom rendu deux fois par la base (deux
/// sources d'Open Directory) ne compte qu'une fois : la première.
#[cfg(any(target_os = "macos", test))]
fn comptes_macos(
    base: &[(String, u32, std::path::PathBuf)],
    sessions: &std::collections::HashMap<String, chrono::NaiveDate>,
    moi: &str,
    date_dossier: impl Fn(&std::path::Path) -> Option<chrono::NaiveDate>,
) -> Vec<Compte> {
    let mut vus = std::collections::HashSet::new();
    base.iter()
        .filter(|(nom, uid, _)| *uid >= 501 && !nom.starts_with('_') && nom != moi)
        .filter(|(nom, _, _)| vus.insert(nom.as_str()))
        .map(|(nom, _, maison)| Compte {
            nom: nom.clone(),
            derniere: sessions.get(nom).copied().max(date_dossier(maison)),
        })
        .collect()
}

/// La base des comptes (nom, UID, dossier personnel), une entrée par `getpwent` : sous macOS, elle vient d'Open
/// Directory, comme `dscl`. Bornée en entrées lues, celles sans nom comprises : une base en boucle ne ferait pas
/// tourner Vanguard sans fin.
#[cfg(target_os = "macos")]
fn base_des_comptes() -> Vec<(String, u32, std::path::PathBuf)> {
    const ENTREES_MAX: usize = 10_000;
    let mut comptes = Vec::new();
    // SAFETY : setpwent, getpwent et endpwent s'enchaînent dans ce seul fil, et rien d'autre dans le programme ne
    // parcourt la base des comptes ; la struct passwd rendue reste valable jusqu'à l'appel suivant et elle est lue
    // tout de suite ; pw_name et pw_dir sont des chaînes C terminées par un nul, ou nuls (vérifié avant la lecture).
    unsafe {
        libc::setpwent();
        for _ in 0..ENTREES_MAX {
            let p = libc::getpwent();
            if p.is_null() {
                break;
            }
            let (nom, uid, maison) = ((*p).pw_name, (*p).pw_uid, (*p).pw_dir);
            let Some(nom) = chaine_c(nom) else {
                continue;
            };
            let maison = chaine_c(maison).unwrap_or_default();
            comptes.push((nom, uid, std::path::PathBuf::from(maison)));
        }
        libc::endpwent();
    }
    comptes
}

/// Une chaîne C en `String` ; `None` : pointeur nul. L'appelant garantit que le pointeur, s'il n'est pas nul,
/// désigne une chaîne terminée par un nul, valable pendant l'appel.
#[cfg(target_os = "macos")]
unsafe fn chaine_c(p: *const libc::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY : non nul (vérifié), terminé par un nul et vivant pendant la lecture (garanti par l'appelant).
    Some(unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

// L'historique des sessions de macOS, celui que `last` lit : des extensions d'Apple à utmpx, dans libSystem, que le
// crate libc ne déclare pas.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn setutxent_wtmp(avant: libc::c_int);
    fn getutxent_wtmp() -> *mut libc::utmpx;
    fn endutxent_wtmp();
}

/// La dernière session de chaque compte, d'après l'historique (`getutxent_wtmp`) puis les sessions ouvertes en ce
/// moment (`getutxent`). Bornée en entrées lues : un historique démesuré n'est pas relu en entier.
#[cfg(target_os = "macos")]
fn dernieres_sessions() -> std::collections::HashMap<String, chrono::NaiveDate> {
    const ENTREES_MAX: usize = 100_000;
    let mut sessions = std::collections::HashMap::new();
    // SAFETY : chaque lecteur est ouvert, parcouru puis refermé dans ce seul fil ; l'entrée rendue reste valable
    // jusqu'à l'appel suivant, et elle est lue tout de suite (un pointeur non nul, vérifié, vers une struct utmpx
    // entière) ; ut_user est un tableau de taille fixe, lu jusqu'au premier nul ou à sa fin, jamais au-delà.
    unsafe {
        setutxent_wtmp(0);
        for _ in 0..ENTREES_MAX {
            let e = getutxent_wtmp();
            if e.is_null() {
                break;
            }
            noter_session(&mut sessions, &*e);
        }
        endutxent_wtmp();
        libc::setutxent();
        for _ in 0..ENTREES_MAX {
            let e = libc::getutxent();
            if e.is_null() {
                break;
            }
            noter_session(&mut sessions, &*e);
        }
        libc::endutxent();
    }
    sessions
}

/// Une session d'utilisateur (USER_PROCESS) datée note son jour pour ce compte ; le plus récent est gardé.
#[cfg(target_os = "macos")]
fn noter_session(sessions: &mut std::collections::HashMap<String, chrono::NaiveDate>, e: &libc::utmpx) {
    if e.ut_type != libc::USER_PROCESS {
        return;
    }
    let Some(jour) = jour_unix(e.ut_tv.tv_sec) else {
        return;
    };
    let nom = nom_utmpx(&e.ut_user);
    if nom.is_empty() {
        return;
    }
    let d = sessions.entry(nom).or_insert(jour);
    *d = (*d).max(jour);
}

/// Le nom d'une entrée utmpx : un tableau de taille fixe, pas forcément terminé par un nul.
#[cfg(any(target_os = "macos", all(test, unix)))]
fn nom_utmpx(champ: &[libc::c_char]) -> String {
    let octets: Vec<u8> = champ
        .iter()
        .map(|c| c.to_ne_bytes()[0])
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&octets).into_owned()
}

/// Le jour local d'un instant Unix (secondes) ; `None` : hors de ce que chrono représente.
#[cfg(any(target_os = "macos", all(test, unix)))]
fn jour_unix(secondes: i64) -> Option<chrono::NaiveDate> {
    Some(
        chrono::DateTime::from_timestamp(secondes, 0)?
            .with_timezone(&chrono::Local)
            .date_naive(),
    )
}

/// Windows : les comptes locaux actifs et leur dernière connexion, sauf les comptes intégrés (Administrateur, Invité,
/// DefaultAccount, WDAGUtilityAccount : déjà jugés à part ou sans session) et le compte en cours.
#[cfg(windows)]
pub fn constats() -> Vec<Constat> {
    // Lu avec les autres vérifications des comptes, en un seul lancement de PowerShell.
    let sortie = super::windows::comptes_locaux();
    let Some(lignes) = crate::commande::section(sortie.as_deref(), "CPT") else {
        return Vec::new();
    };
    let comptes: Vec<Compte> = lignes
        .iter()
        .filter_map(|l| {
            let (date, nom) = l.split_once('|')?;
            Some(Compte {
                nom: nom.trim().to_string(),
                derniere: chrono::NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d").ok(),
            })
        })
        .collect();
    juger(&comptes, chrono::Local::now().date_naive())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jour(a: i32, m: u32, j: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(a, m, j).unwrap()
    }

    #[test]
    fn comptes_oublies_seulement() {
        let comptes = [
            Compte {
                nom: "alice".into(),
                derniere: Some(jour(2026, 10, 1)),
            },
            Compte {
                nom: "ancien".into(),
                derniere: Some(jour(2025, 12, 1)),
            },
            Compte {
                nom: "depannage".into(),
                derniere: None,
            },
        ];
        let c = juger(&comptes, jour(2026, 10, 19));
        assert_eq!(c.len(), 2);
        assert!(c[0].message.contains("ancien") && c[0].message.contains("2025-12-01"));
        assert!(c[1].message.contains("jamais"));
        assert!(
            c.iter()
                .all(|x| x.probleme == Some(Niveau::Info) && !x.correctif.as_ref().unwrap().automatique)
        );
    }

    /// L'oracle : la dernière connexion de chaque compte de cet ordinateur, lue par Vanguard (lastlog2.db,
    /// /var/log/lastlog), contre lastlog2 -u puis lastlog -u comme avant. Rien de personnel dans le message.
    #[cfg(target_os = "linux")]
    #[test]
    fn derniere_connexion_comme_lastlog2() {
        if crate::commande::lancer(std::process::Command::new("lastlog2").arg("--help"), 5).is_none() {
            return crate::essais::saute("lastlog2 absent");
        }
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap();
        let natif2 = lastlog2_natif();
        let mut ecarts = 0;
        let mut vus = 0;
        for l in passwd.lines() {
            let c: Vec<&str> = l.split(':').collect();
            let (Some(nom), Some(Ok(uid))) = (c.first(), c.get(2).map(|u| u.parse::<u32>())) else {
                continue;
            };
            let outil = ["lastlog2", "lastlog"].iter().find_map(|outil| {
                let r = crate::commande::lancer_en_anglais(std::process::Command::new(outil).args(["-u", nom]), 5)?;
                r.sortie.lines().skip(1).find_map(lire_lastlog)
            });
            vus += 1;
            if derniere_connexion(nom, uid, natif2.as_ref()) != outil {
                ecarts += 1;
            }
        }
        assert_eq!(ecarts, 0, "{ecarts} comptes sur {vus} diffèrent de lastlog2");
    }

    #[test]
    fn dates_de_lastlog() {
        assert_eq!(
            lire_lastlog(
                "dp               tty1                                                Sat Oct 17 22:51:53 -0400 2026"
            ),
            Some(jour(2026, 10, 17))
        );
        assert_eq!(
            lire_lastlog("bob      pts/0    10.0.0.5   Mon Mar  2 09:05:01 +0100 2026"),
            Some(jour(2026, 3, 2))
        );
        assert_eq!(lire_lastlog("ancien                    **Never logged in**"), None);
    }

    /// macOS, sur une base inventée : les comptes de service et celui qui lance Vanguard sont écartés ; la dernière
    /// session l'emporte sur un dossier plus vieux, et un dossier hors de /Users (volume externe) est daté quand même.
    #[test]
    fn comptes_macos_sur_une_base_inventee() {
        let base = vec![
            ("root".to_string(), 0, std::path::PathBuf::from("/var/root")),
            ("_spotlight".to_string(), 89, std::path::PathBuf::from("/var/empty")),
            ("alice".to_string(), 501, std::path::PathBuf::from("/Users/alice")),
            ("bob".to_string(), 502, std::path::PathBuf::from("/Volumes/Externe/bob")),
            ("zoé".to_string(), 503, std::path::PathBuf::from("/Users/zoé")),
            // Rendu une seconde fois par la base : déjà compté.
            ("bob".to_string(), 502, std::path::PathBuf::from("/Users/bob")),
        ];
        let sessions = std::collections::HashMap::from([("alice".to_string(), jour(2026, 10, 18))]);
        let dossiers = |chemin: &std::path::Path| match chemin.to_str() {
            Some("/Users/alice") => Some(jour(2026, 3, 1)),
            Some("/Volumes/Externe/bob") => Some(jour(2026, 9, 9)),
            _ => None,
        };
        let comptes = comptes_macos(&base, &sessions, "alice", dossiers);
        assert_eq!(comptes.len(), 2);
        assert_eq!(
            comptes[0],
            Compte {
                nom: "bob".into(),
                derniere: Some(jour(2026, 9, 9))
            }
        );
        assert_eq!(
            comptes[1],
            Compte {
                nom: "zoé".into(),
                derniere: None
            }
        );
        let comptes = comptes_macos(&base, &sessions, "bob", dossiers);
        assert_eq!(
            comptes[0],
            Compte {
                nom: "alice".into(),
                derniere: Some(jour(2026, 10, 18))
            }
        );
    }

    /// Sous Unix seulement : le type `c_char` vient de libc, que Windows n'a pas.
    #[cfg(unix)]
    #[test]
    fn nom_et_jour_d_une_entree_utmpx() {
        let champ: Vec<libc::c_char> = b"alice\0xx".iter().map(|&b| libc::c_char::from_ne_bytes([b])).collect();
        assert_eq!(nom_utmpx(&champ), "alice");
        // Sans nul : tout le tableau, jamais au-delà.
        let plein: Vec<libc::c_char> = b"bob".iter().map(|&b| libc::c_char::from_ne_bytes([b])).collect();
        assert_eq!(nom_utmpx(&plein), "bob");
        assert_eq!(nom_utmpx(&[]), "");
        // 2026-10-17 12:00:00 UTC : le jour local, à l'heure de cet ordinateur.
        let j = jour_unix(1_792_238_400).unwrap();
        assert!((jour(2026, 10, 17) - j).num_days().abs() <= 1);
        assert_eq!(jour_unix(i64::MAX), None);
    }

    /// T4 : un compte oublié se reconnaît à son nom, pas à sa date ni à la langue.
    #[test]
    fn cles_sans_langue() {
        let comptes = [
            Compte {
                nom: "ancien".into(),
                derniere: Some(jour(2025, 12, 1)),
            },
            Compte {
                nom: "depannage".into(),
                derniere: None,
            },
        ];
        let cles = crate::machine::controler_regle("COM-CPT-002", || juger(&comptes, jour(2026, 10, 19)));
        assert_eq!(cles, ["COM-CPT-002|compte:ancien", "COM-CPT-002|compte:depannage"]);
    }
}
