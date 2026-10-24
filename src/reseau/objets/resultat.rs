//! Le résultat de « Box et objets connectés » (`modele::resultat`) : le jugement du dernier scan gardé, sans
//! l'écran. Versé au rapport (`examens/PRO-OBJ-001.json`), au journal des événements, et rendu par `--json`.
//!
//! Rien n'est sondé : sans scan gardé, rien n'est vérifié, jamais sain. Le mot de passe d'origine n'est jamais
//! essayé (choix de l'utilisateur) : un appareil qui en a souvent un laisse ce point non vérifié, car rien ne
//! prouve qu'il a été changé.

use super::{Appareil, Genre, admin_en_clair, genre};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Objet, Raison};
use crate::reseau::date_fr;
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-OBJ-001";

const CAT: &str = "Appareils";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// L'objet d'un appareil : son adresse dans le réseau, ce que le carnet garde de lui sans langue.
fn objet(a: &Appareil) -> Objet {
    Objet::de("appareil", &a.ip.to_string())
}

/// Le résultat du carnet de ce réseau (`None` : aucun scan gardé) : un constat par appareil reconnu, un problème
/// pour une administration du routeur en HTTP seul, et ce qui n'a pas pu être vérifié.
pub(super) fn resultat(appareils: Option<&[Appareil]>, debut: Debut) -> Resultat {
    let Some(appareils) = appareils else {
        let pourquoi = tr!(
            "aucun scan gardé pour ce réseau : lancez d'abord « Scan du réseau » (vanguard appareils)",
            "no scan kept for this network: first run “Network scan” (vanguard devices)"
        );
        return Resultat::nouveau(
            ID,
            debut,
            &[impossible_par(CAT, Raison::Introuvable, pourquoi)],
            Couverture {
                verifies: 0,
                non_verifies: vec![pourquoi.to_string()],
            },
        );
    };
    let mut non_verifies = Vec::new();
    if appareils.is_empty() {
        non_verifies.push(
            tr!(
                "le dernier scan ne montre aucun autre appareil que cet ordinateur",
                "the last scan shows no device other than this computer"
            )
            .to_string(),
        );
    }
    let mut reconnus: Vec<(Genre, &Appareil)> = appareils.iter().filter_map(|a| Some((genre(a)?, a))).collect();
    reconnus.sort_by_key(|(g, a)| (*g, a.ip));
    let mut constats: Vec<Constat> = Vec::new();
    // Le carnet dit ce que le dernier scan a vu, pas ce qui est là maintenant : sa date suit le résultat.
    if let Some(jour) = appareils.iter().filter_map(|a| a.dernier_vu.as_deref()).max() {
        constats.push(ok(
            CAT,
            trf!(
                "D'après le dernier scan, du {} : rien n'est sondé ici, un appareil arrivé depuis n'y est pas.",
                "From the last scan, of {}: nothing is probed here, a device that arrived since is not in it.",
                date_fr(jour)
            ),
        ));
    }
    for (g, a) in &reconnus {
        let titre = if a.titre.is_empty() {
            tr!("appareil inconnu", "unknown device")
        } else {
            &a.titre
        };
        let c = if *g == Genre::Boite && admin_en_clair(a) {
            alerte(
                CAT,
                Niveau::Moyen,
                trf!(
                    "{} {} ({titre}) : sa page d'administration répond en HTTP et le scan n'a pas trouvé de HTTPS ; son mot de passe passe peut-être en clair sur le réseau.",
                    "{} {} ({titre}): its admin page answers over HTTP and the scan found no HTTPS; its password may travel in clear text on the network.",
                    g.nom(),
                    a.ip
                ),
            )
        } else {
            ok(CAT, format!("{} {} ({titre})", g.nom(), a.ip))
        };
        constats.push(c.avec_objet(objet(a)));
    }
    if reconnus.is_empty() && !appareils.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun objet connecté reconnu (caméra, imprimante, NAS, télé…), ni le routeur.",
                "No connected device recognized (camera, printer, NAS, TV…), nor the router."
            ),
        ));
    }
    let mut a_changer: Vec<Genre> = reconnus
        .iter()
        .map(|(g, _)| *g)
        .filter(|g| g.mot_de_passe_d_origine())
        .collect();
    a_changer.dedup();
    if !a_changer.is_empty() {
        let liste = a_changer.iter().map(|g| g.nom()).collect::<Vec<_>>().join(", ");
        non_verifies.push(trf!(
            "mot de passe d'origine ({liste}) : jamais essayé, par choix ; s'il n'a jamais été changé, changez-le dans leur application ou leur page web",
            "default password ({liste}): never tried, by choice; if it was never changed, change it in their app or web page"
        ));
    }
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            // Chaque appareil du carnet a été examiné (type, administration du routeur).
            verifies: u32::try_from(appareils.len()).unwrap_or(u32::MAX),
            non_verifies,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn appareil(dernier: u8, boite: bool, fabricant: Option<&str>, tcp: &[u16]) -> Appareil {
        Appareil {
            ip: Ipv4Addr::new(192, 168, 1, dernier),
            titre: "Salon".into(),
            boite,
            fabricant: fabricant.map(str::to_string),
            nom: None,
            tcp: tcp.to_vec(),
            annonces: Vec::new(),
            dernier_vu: Some("2026-10-20".into()),
        }
    }

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    #[test]
    fn sans_scan_rien_n_est_verifie() {
        let r = resultat(None, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
        assert_eq!(r.constats[0].raison.as_deref(), Some("introuvable"));
        assert_eq!(resultat(Some(&[]), debut()).verdict(), "non-verifie");
    }

    #[test]
    fn routeur_en_http_seul() {
        let appareils = [
            appareil(1, true, Some("Sagemcom Broadband SAS"), &[80]),
            appareil(30, false, Some("Nintendo Co.,Ltd"), &[]),
        ];
        let r = resultat(Some(&appareils), debut());
        assert_eq!(r.verdict(), "probleme");
        assert_eq!(r.pire(), Some(Niveau::Moyen));
        let probleme = r.constats.iter().find(|c| c.etat == "probleme").unwrap();
        assert_eq!(probleme.objet.as_deref(), Some("appareil:192.168.1.1"));
        // Le mot de passe d'origine du routeur n'est jamais essayé : non vérifié, dit.
        assert_eq!(r.couverture.non_verifies.len(), 1);
        assert_eq!(r.couverture.verifies, 2);
    }

    /// Une console et rien qui ait un mot de passe d'origine : tout ce qui devait l'être l'a été.
    #[test]
    fn sain_seulement_sans_manque() {
        let r = resultat(Some(&[appareil(30, false, Some("Nintendo Co.,Ltd"), &[])]), debut());
        assert_eq!(r.verdict(), "sain");
        let r = resultat(Some(&[appareil(1, true, None, &[443])]), debut());
        assert_eq!(
            r.verdict(),
            "non-verifie",
            "routeur : mot de passe d'origine non vérifié"
        );
    }
}
