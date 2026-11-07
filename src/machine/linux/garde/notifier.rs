//! sd_notify maison : READY=1 au démarrage, WATCHDOG=1 tant que le fil lecteur bat, STOPPING=1 à l'arrêt. Un datagramme
//! sur NOTIFY_SOCKET (un chemin, ou un nom abstrait qui commence par « @ ») ; sans cette variable (lancé à la main),
//! rien n'est envoyé.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::os::unix::net::{SocketAddr, UnixDatagram};

/// L'adresse lue dans NOTIFY_SOCKET.
pub(crate) fn adresse(valeur: &str) -> Option<SocketAddr> {
    if let Some(nom) = valeur.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        return SocketAddr::from_abstract_name(nom.as_bytes()).ok();
    }
    valeur
        .starts_with('/')
        .then(|| SocketAddr::from_pathname(valeur).ok())
        .flatten()
}

/// Le canal vers systemd.
pub(crate) struct Notifier {
    canal: Option<(UnixDatagram, SocketAddr)>,
}

impl Notifier {
    /// Depuis l'environnement (le garde ne lance aucun programme : la variable n'a pas à être retirée).
    pub(crate) fn depuis_environnement() -> Notifier {
        let canal = std::env::var("NOTIFY_SOCKET")
            .ok()
            .and_then(|v| adresse(&v))
            .and_then(|a| UnixDatagram::unbound().ok().map(|s| (s, a)));
        Notifier { canal }
    }

    pub(crate) fn envoyer(&self, message: &str) {
        if let Some((s, a)) = &self.canal {
            let _ = s.send_to_addr(message.as_bytes(), a);
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresse_abstraite_ou_chemin() {
        use std::os::linux::net::SocketAddrExt;
        let a = adresse("@/org/freedesktop/systemd1/notify/42").unwrap();
        assert_eq!(a.as_abstract_name(), Some(&b"/org/freedesktop/systemd1/notify/42"[..]));
        let c = adresse("/run/systemd/notify").unwrap();
        assert_eq!(c.as_pathname(), Some(std::path::Path::new("/run/systemd/notify")));
        assert!(adresse("relatif").is_none());
        assert!(adresse("").is_none());
    }

    /// Un vrai datagramme reçu, comme systemd le recevrait.
    #[test]
    fn le_message_arrive() {
        // Un nom abstrait, comme celui que systemd donne : le chemin d'un dossier jetable dépasse parfois les 108
        // octets d'une adresse de socket ; le numéro du processus et du fil le rend unique.
        let nom = format!(
            "@vanguard-essai-notifier-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        let a = adresse(&nom).unwrap();
        let recepteur = UnixDatagram::bind_addr(&a).unwrap();
        let n = Notifier {
            canal: Some((UnixDatagram::unbound().unwrap(), adresse(&nom).unwrap())),
        };
        n.envoyer("READY=1");
        let mut t = [0u8; 64];
        let lu = recepteur.recv(&mut t).unwrap();
        assert_eq!(&t[..lu], b"READY=1");
        Notifier { canal: None }.envoyer("WATCHDOG=1");
    }
}
