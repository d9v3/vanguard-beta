//! Reconnaître un réseau public sans rien envoyer, et le portail captif. Vanguard ne peut pas savoir à coup sûr
//! qu'un réseau est public : il lit ce que le système sait déjà (Wi-Fi ouvert ou sans mot de passe, catégorie
//! « Public » déjà choisie sous Windows, portail vu par le propre test de NetworkManager) et en tire une suggestion,
//! jamais un allumage. La page de connexion s'ouvre par l'adresse de la sonde du système lui-même, jamais par un
//! serveur de Vanguard ; sous Linux sans adresse configurée, rien n'est inventé : la personne ouvre un site en http.

use std::time::Duration;

use crate::langue::Reponse;
use crate::ui::*;

/// Ce que le système sait déjà du réseau connecté. `None` : pas lu.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Signaux {
    /// Force de la protection du Wi-Fi (`machine::wifi::force` : 0 ouvert, 1 sans mot de passe ou faible…).
    pub force: Option<u8>,
    /// Windows : la personne a déjà déclaré ce réseau « Public ».
    pub deja_public: bool,
    /// Un portail captif d'après le test du système (NetworkManager : « portal »).
    pub portail: Option<bool>,
}

/// La suggestion à montrer, ou `None` si rien ne fait penser à un réseau public.
pub(crate) fn suggestion(s: Signaux) -> Option<String> {
    let mut raisons = Vec::new();
    if s.force == Some(0) {
        raisons.push(tr!("ouvert, sans mot de passe", "open, without a password"));
    } else if s.force == Some(1) {
        raisons.push(tr!(
            "faiblement protégé ou sans mot de passe",
            "weakly protected or without a password"
        ));
    }
    if s.deja_public {
        raisons.push(tr!(
            "déclaré public sur cet ordinateur",
            "declared public on this computer"
        ));
    }
    if s.portail == Some(true) {
        raisons.push(tr!(
            "page de connexion (portail) signalée",
            "login page (portal) reported"
        ));
    }
    (!raisons.is_empty()).then(|| {
        trf!(
            "Ce réseau semble public ({}) : le mode est fait pour lui.",
            "This network looks public ({}): the mode is made for it.",
            raisons.join(", ")
        )
    })
}

/// L'adresse à ouvrir pour faire paraître la page de connexion : celle de la sonde du système.
// Même signature partout : sous Linux, l'adresse peut manquer.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn adresse() -> Option<String> {
    #[cfg(target_os = "linux")]
    return super::linux::lecture::uri_de_connectivite();
    #[cfg(windows)]
    return Some("http://www.msftconnecttest.com/redirect".to_string());
    #[cfg(target_os = "macos")]
    return Some("http://captive.apple.com".to_string());
}

/// Ouvre la page de connexion (après accord), puis attend que la personne s'y soit connectée, jusqu'à `fin` au plus :
/// `false` si l'échéance est passée avant.
pub(crate) fn ouvrir_et_attendre(fin: Option<std::time::Instant>) -> bool {
    match adresse() {
        Some(url) => {
            if demander(tr!(
                "  Ouvrir la page de connexion du réseau dans le navigateur ? [o/N] : ",
                "  Open the network's login page in the browser? [y/N]: "
            ))
            .oui()
            {
                trp!("  {}Page ouverte : {url}{}", "  {}Page opened: {url}{}", GRIS, RESET);
                crate::machine::ouvrir(&url);
            }
        }
        None => afficher_aligne(
            "  ",
            tr!(
                "Pour faire paraître la page de connexion, ouvrez dans le navigateur un site en « http:// » (pas https) : le réseau le détourne vers sa page.",
                "To bring up the login page, open a site starting with “http://” (not https) in the browser: the network redirects it to its page."
            ),
            2,
            "",
        ),
    }
    crate::selection::attendre_retour_avant(
        tr!(
            "  Entrée une fois connecté à la page… ",
            "  Enter once logged in on the page… "
        ),
        fin,
    )
}

/// Les noms de sites se résolvent-ils encore (par le DNS du système, en 8 secondes au plus) ? Une seule question,
/// celle que ferait n'importe quel navigateur.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn noms_resolus() -> bool {
    use std::net::ToSocketAddrs;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let ok = ("www.example.com", 443)
            .to_socket_addrs()
            .is_ok_and(|mut a| a.next().is_some());
        let _ = tx.send(ok);
    });
    rx.recv_timeout(Duration::from_secs(8)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestion_sans_rien_envoyer() {
        assert_eq!(suggestion(Signaux::default()), None);
        assert_eq!(
            suggestion(Signaux {
                force: Some(2),
                ..Signaux::default()
            }),
            None
        );
        let s = suggestion(Signaux {
            force: Some(0),
            deja_public: false,
            portail: Some(true),
        })
        .unwrap();
        assert!(
            s.contains(tr!("ouvert", "open")) && s.contains(tr!("portail", "portal")),
            "{s}"
        );
        assert!(
            suggestion(Signaux {
                deja_public: true,
                ..Signaux::default()
            })
            .is_some()
        );
    }
}
