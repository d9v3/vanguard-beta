//! Comptes oubliés : un compte de l'ordinateur encore actif mais que personne n'utilise plus (l'ancien employé, le
//! compte créé pour un dépannage, celui d'un enfant parti). C'est une porte de plus, souvent avec un vieux mot de
//! passe. Vanguard cherche la dernière trace d'utilisation : la dernière connexion notée par le système (Windows,
//! lastlog2 ou lastlog sous Linux), et la date du dossier personnel (Linux : une connexion graphique n'est pas toujours
//! notée). Rien depuis six mois : une information, avec la façon de le désactiver. Le compte qui lance Vanguard n'est
//! jamais compté.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

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
                Some(d) if aujourd_hui.signed_duration_since(d).num_days() > OUBLIE_JOURS => trf!(
                    "Le compte « {nom} » est actif mais n'a pas servi depuis le {d} : un compte oublié est une porte de plus, souvent avec un vieux mot de passe.",
                    "The “{nom}” account is active but has not been used since {d}: a forgotten account is one more door, often with an old password."
                ),
                Some(_) => return None,
            };
            // Le compte par son nom tel que le système le donne : la date qui change ne fait pas un autre objet.
            let constat = alerte(CAT, Niveau::Info, message)
                .avec_objet(crate::modele::Objet::de("compte", &c.nom))
                .manuel(desactiver(), &[]);
            // Linux : verrouillé par un geste de défense, réactivable ; le compte de la session en cours est rejugé
            // et averti par l'enfant root, qui le sait mieux que ce bilan.
            #[cfg(target_os = "linux")]
            let constat = super::defense::corriger(
                constat,
                trf!(
                    "Verrouiller le compte « {nom} » (il ne s'ouvre plus ; ses fichiers restent, réactivable)",
                    "Lock the “{nom}” account (it no longer opens; its files stay, can be re-enabled)"
                ),
                &super::defense::verrouiller([c.nom.as_str()]),
            );
            Some(constat)
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
    let texte = mots.get(i..i.saturating_add(6))?.join(" ");
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
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
        assert!(c.iter().all(|x| x.probleme == Some(Niveau::Info)));
        // Linux (D7a) : verrouillé par un geste de défense, défait par sa note ; ailleurs, à la main.
        for (x, nom) in c.iter().zip(["ancien", "depannage"]) {
            let k = x.correctif.as_ref().unwrap();
            #[cfg(target_os = "linux")]
            {
                use crate::machine::gestes_unix::{Defense, GesteUnix, analyser};
                assert!(k.automatique);
                let [ligne] = k.commandes.as_slice() else {
                    panic!("un geste attendu")
                };
                assert!(matches!(
                    analyser(ligne),
                    Some(GesteUnix::Defense(Defense::VerrouillerCompte(n), _)) if n.as_str() == nom
                ));
                assert!(matches!(k.defaire, crate::machine::Defaire::Gestes(ref g) if g.len() == 1));
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = nom;
                assert!(!k.automatique);
            }
        }
    }

    /// Un nom que le système n'admettrait pas (forgé dans /etc/passwd) : rien d'automatique, le conseil seul.
    #[cfg(target_os = "linux")]
    #[test]
    fn compte_oublie_au_nom_forge() {
        let comptes = [Compte {
            nom: "$(reboot)".into(),
            derniere: None,
        }];
        let c = juger(&comptes, jour(2026, 10, 19));
        assert!(!c[0].correctif.as_ref().unwrap().automatique);
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
