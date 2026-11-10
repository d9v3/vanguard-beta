//! Le résultat du type de NAT (`modele::resultat`) : le verdict de l'écran (ouvert, modéré, strict), le partage
//! d'adresse par le fournisseur et l'IPv6, sans l'écran. Versé au rapport (`examens/PRO-NAT-001.json`), au journal
//! des événements, et rendu par `--json`.
//!
//! Ce qui n'a pas pu se mesurer (mode hors ligne, aucun serveur qui répond, un seul serveur, UPnP de la box non lu)
//! est dit non vérifié, jamais compté bon. L'adresse publique n'est pas écrite : le rapport n'en a pas besoin.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::{Ipv6, Releve, TypeNat, adresse_partagee, juger};
use crate::machine::{alerte, impossible_par, ok, sans_objet};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-NAT-001";

const CAT: &str = "NAT";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'un test commencé à `debut` ; `None` : rien n'a été mesuré (mode hors ligne).
pub(super) fn resultat(r: Option<&Releve>, debut: Debut) -> Resultat {
    let mut constats = Vec::new();
    let mut non_verifies = Vec::new();
    let mut verifies = 0u32;
    let Some(r) = r else {
        let raison = tr!(
            "mode hors ligne (VANGUARD_HORS_LIGNE ou Paramètres) : aucun serveur n'est interrogé",
            "offline mode (VANGUARD_HORS_LIGNE or Settings): no server is asked"
        );
        constats.push(impossible_par(
            CAT,
            Raison::Refuse(raison.to_string()),
            trf!("Non vérifié : {raison}.", "Not checked: {raison}."),
        ));
        non_verifies.push(raison.to_string());
        return Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies });
    };
    let Some((mesure, publique)) = r.mesure.as_ref().and_then(|m| Some((m, m.vues.first()?.1.ip()))) else {
        let raison = tr!(
            "aucun serveur n'a répondu : pas d'Internet, ou l'UDP sortant est bloqué (pare-feu, réseau d'entreprise ou d'hôtel)",
            "no server answered: no Internet, or outgoing UDP is blocked (firewall, company or hotel network)"
        );
        constats.push(impossible_par(
            CAT,
            Raison::Echoue(raison.to_string()),
            trf!("Non vérifié : {raison}.", "Not checked: {raison}."),
        ));
        non_verifies.push(raison.to_string());
        return Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies });
    };
    let (upnp, etat_upnp) = r.upnp;
    if let Some((type_nat, pourquoi)) = juger(mesure, upnp) {
        let objet = Objet::de("mesure", "nat");
        let c = match type_nat {
            TypeNat::Ouvert => Some(ok(CAT, trf!("NAT ouvert : {pourquoi}", "Open NAT: {pourquoi}"))),
            TypeNat::Modere => Some(alerte(
                CAT,
                Niveau::Info,
                trf!(
                    "NAT modéré (PlayStation : type 2) : {pourquoi}",
                    "Moderate NAT (PlayStation: type 2): {pourquoi}"
                ),
            )),
            TypeNat::Strict => Some(alerte(
                CAT,
                Niveau::Moyen,
                trf!(
                    "NAT strict (PlayStation : type 3) : {pourquoi}",
                    "Strict NAT (PlayStation: type 3): {pourquoi}"
                ),
            )),
            TypeNat::Incertain => {
                constats.push(
                    impossible_par(
                        CAT,
                        Raison::Echoue(pourquoi.to_string()),
                        trf!(
                            "Type de NAT non vérifié : {pourquoi}",
                            "NAT type not checked: {pourquoi}"
                        ),
                    )
                    .avec_objet(objet.clone()),
                );
                non_verifies.push(pourquoi.to_string());
                None
            }
        };
        if let Some(c) = c {
            constats.push(c.avec_objet(objet));
            verifies = verifies.saturating_add(1);
        }
    }
    if upnp.is_none() {
        non_verifies.push(trf!("UPnP du routeur : {etat_upnp}", "Router UPnP: {etat_upnp}"));
    }
    match (r.box_internet, adresse_partagee(r.box_internet, publique)) {
        (_, Some(partage)) => {
            constats.push(alerte(CAT, Niveau::Moyen, partage).avec_objet(Objet::de("mesure", "partage")));
            verifies = verifies.saturating_add(1);
        }
        (Some(_), None) => {
            constats.push(
                ok(
                    CAT,
                    tr!(
                        "Ni double NAT, ni adresse partagée par le fournisseur (CGNAT).",
                        "Neither double NAT nor an address shared by the provider (CGNAT)."
                    ),
                )
                .avec_objet(Objet::de("mesure", "partage")),
            );
            verifies = verifies.saturating_add(1);
        }
        (None, None) => non_verifies.push(
            tr!(
                "double NAT et partage d'adresse (CGNAT) : le routeur n'a pas dit son adresse Internet (UPnP coupé ou non lu)",
                "double NAT and address sharing (CGNAT): the router did not tell its Internet address (UPnP off or not read)"
            )
            .to_string(),
        ),
    }
    let ipv6 = Objet::de("mesure", "ipv6");
    let c = match r.ipv6 {
        Ipv6::Absente => sans_objet(
            CAT,
            Absence::Inactif,
            tr!(
                "IPv6 : absente sur ce réseau. Les jeux passent par l'IPv4, et donc par le NAT.",
                "IPv6: absent on this network. Games go through IPv4, hence through the NAT."
            ),
        ),
        Ipv6::Directe => ok(
            CAT,
            tr!(
                "IPv6 : directe, sans NAT. Les jeux et les consoles qui s'en servent sont joignables, si le pare-feu du routeur les laisse passer.",
                "IPv6: direct, without NAT. Games and consoles that use it are reachable, if the router's firewall lets them through."
            ),
        ),
        Ipv6::Traduite => ok(
            CAT,
            tr!(
                "IPv6 : présente, mais traduite elle aussi (rare) : comme pour l'IPv4.",
                "IPv6: present, but translated as well (rare): same as IPv4."
            ),
        ),
        Ipv6::Injoignable => alerte(
            CAT,
            Niveau::Info,
            tr!(
                "IPv6 : une adresse, mais Internet ne répond pas par là (bloquée par le routeur ou le fournisseur).",
                "IPv6: an address, but the Internet does not answer that way (blocked by the router or the provider)."
            ),
        ),
    };
    constats.push(c.avec_objet(ipv6));
    Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies })
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::Mesure;
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    /// Une mesure aux adresses de la documentation : cet ordinateur derrière la box, les ports vus par serveur.
    fn releve(ports: &[u16], upnp: Option<bool>, box_internet: Option<Ipv4Addr>) -> Releve {
        Releve {
            mesure: Some(Mesure {
                locale: "192.168.1.20".parse().unwrap(),
                port_local: 50000,
                vues: ports
                    .iter()
                    .zip(["cloudflare", "google"])
                    .map(|(p, n)| (n, format!("203.0.113.7:{p}").parse().unwrap()))
                    .collect(),
            }),
            upnp: (upnp, "?"),
            box_internet,
            ipv6: Ipv6::Absente,
        }
    }

    #[test]
    fn hors_ligne_rien_ne_part() {
        let r = resultat(None, debut());
        assert_eq!(r.outil, ID);
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
        assert_eq!(r.constats[0].raison.as_deref(), Some("refuse"));
    }

    #[test]
    fn aucun_serveur_non_verifie() {
        let mut muet = releve(&[], None, None);
        let r = resultat(Some(&muet), debut());
        assert_eq!(r.verdict(), "non-verifie");
        muet.mesure = None;
        assert_eq!(resultat(Some(&muet), debut()).verdict(), "non-verifie");
    }

    /// Ouvert avec l'UPnP et la box qui dit une adresse publique : sain.
    #[test]
    fn ouvert_sain() {
        let r = resultat(
            Some(&releve(
                &[40000, 40000],
                Some(true),
                Some(Ipv4Addr::new(203, 0, 113, 7)),
            )),
            debut(),
        );
        assert_eq!(r.verdict(), "sain", "{:?}", r.couverture);
        assert_eq!(r.couverture.verifies, 2);
    }

    /// Strict : un problème moyen ; un seul serveur : non vérifié ; l'UPnP non lu et la box muette, des manques.
    #[test]
    fn strict_incertain_et_manques() {
        let strict = resultat(Some(&releve(&[40000, 40001], Some(false), None)), debut());
        assert_eq!(strict.verdict(), "probleme");
        assert_eq!(strict.constats[0].niveau, Some(Niveau::Moyen));
        assert_eq!(strict.couverture.non_verifies.len(), 1);
        let seul = resultat(Some(&releve(&[40000], None, None)), debut());
        assert_eq!(seul.verdict(), "non-verifie");
        assert_eq!(seul.couverture.verifies, 0);
        assert_eq!(seul.couverture.non_verifies.len(), 3);
    }

    /// Une adresse partagée (CGNAT, 100.64.0.0/10) ou privée (double NAT) se dit en problème moyen.
    #[test]
    fn partage_d_adresse() {
        for b in [Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::new(192, 168, 0, 2)] {
            let r = resultat(Some(&releve(&[40000, 40000], Some(true), Some(b))), debut());
            assert_eq!(r.verdict(), "probleme");
            assert!(r.constats.iter().any(|c| c.niveau == Some(Niveau::Moyen)));
        }
    }
}
