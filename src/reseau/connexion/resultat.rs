//! Le résultat du test de connexion pour le jeu (`modele::resultat`) : chaque critère du verdict de l'écran (ping,
//! gigue, pertes, bufferbloat), les débits, la liaison avec le routeur et la comparaison aux habitudes, sans l'écran.
//! Versé au rapport (`examens/PRO-CNX-001.json`), au journal des événements, et rendu par `--json`. Ce qui n'a pas pu
//! se mesurer (pas d'Internet, mode hors ligne, aucun transfert abouti) est dit non vérifié, jamais compté bon.

use super::{Releve, liaison_instable, moins_bonne_que_d_habitude, note_bufferbloat};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-CNX-001";

const CAT: &str = "Connexion";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Un critère : bon, un simple fait ; sinon une alerte moyenne. Une connexion lente gêne le jeu, elle ne met pas
/// l'ordinateur en danger : le ✖ de l'écran ne dit pas une gravité.
fn critere(bon: bool, mesure: &str, message: String) -> Constat {
    let c = if bon {
        ok(CAT, message)
    } else {
        alerte(CAT, Niveau::Moyen, message)
    };
    c.avec_objet(Objet::de("mesure", mesure))
}

/// Le résultat d'un test commencé à `debut` ; `None` : rien n'a été mesuré (mode hors ligne).
pub(super) fn resultat(r: Option<&Releve>, debut: Debut) -> Resultat {
    let mut constats = Vec::new();
    let mut non_verifies = Vec::new();
    let mut verifies = 0u32;
    let repos_ms = r.and_then(|r| r.repos.internet.mediane());
    match (r, repos_ms) {
        (None, _) => {
            let raison = crate::tr!(
                "mode hors ligne (VANGUARD_HORS_LIGNE ou Paramètres) : la connexion n'est pas mesurée",
                "offline mode (VANGUARD_HORS_LIGNE or Settings): the connection is not measured"
            );
            constats.push(impossible_par(
                CAT,
                Raison::Refuse(raison.to_string()),
                crate::trf!("Non vérifié : {raison}.", "Not checked: {raison}."),
            ));
            non_verifies.push(raison.to_string());
        }
        (Some(_), None) | (Some(Releve { charge: None, .. }), _) => {
            let raison = crate::tr!("Internet ne répond pas", "Internet does not answer");
            constats.push(impossible_par(
                CAT,
                Raison::Echoue(raison.to_string()),
                crate::trf!("{raison} : test arrêté.", "{raison}: test stopped."),
            ));
            non_verifies.push(crate::trf!(
                "ping, gigue, pertes, débit et bufferbloat : {raison}",
                "ping, jitter, loss, speed and bufferbloat: {raison}"
            ));
        }
        (
            Some(
                r @ Releve {
                    charge: Some(charge), ..
                },
            ),
            Some(repos),
        ) => {
            let internet = &r.repos.internet;
            let (gigue, pertes) = (internet.gigue(), internet.pertes());
            constats.push(critere(
                repos < 60.0,
                "ping",
                crate::trf!("Ping : {repos:.0} ms.", "Ping: {repos:.0} ms."),
            ));
            constats.push(critere(
                gigue < 10.0,
                "gigue",
                crate::trf!("Gigue : {} ms.", "Jitter: {} ms.", crate::langue::decimal(gigue, 1)),
            ));
            constats.push(critere(
                pertes <= 1.0,
                "pertes",
                crate::trf!("Pertes : {pertes:.0} %.", "Loss: {pertes:.0}%."),
            ));
            verifies += 3;
            match charge.hausse(repos) {
                Some(h) => {
                    constats.push(critere(
                        h <= 30.0,
                        "bufferbloat",
                        crate::trf!(
                            "Bufferbloat : {} (+{h:.0} ms quand la connexion est occupée).",
                            "Bufferbloat: {} (+{h:.0} ms when the connection is busy).",
                            note_bufferbloat(h).0
                        ),
                    ));
                    verifies += 1;
                }
                None => non_verifies.push(
                    crate::tr!(
                        "bufferbloat : aucune mesure sous charge n'a abouti",
                        "bufferbloat: no measurement under load succeeded"
                    )
                    .to_string(),
                ),
            }
            for (debit, mesure, nom) in [
                (charge.debit_bas, "reception", crate::tr!("Réception", "Download")),
                (charge.debit_haut, "envoi", crate::tr!("Envoi", "Upload")),
            ] {
                match debit {
                    Some(d) => {
                        constats.push(critere(
                            true,
                            mesure,
                            crate::trf!("{nom} : {d:.0} Mbit/s.", "{nom}: {d:.0} Mbit/s."),
                        ));
                        verifies += 1;
                    }
                    None => non_verifies.push(crate::trf!(
                        "{nom} : aucun transfert n'a abouti",
                        "{nom}: no transfer succeeded"
                    )),
                }
            }
            match liaison_instable(r.repos.serie_box.as_ref(), internet) {
                Some(instable) => {
                    let message = if instable {
                        crate::tr!(
                            "La liaison avec le routeur est instable (souvent le Wi-Fi) : un câble Ethernet règle presque toujours ça.",
                            "The link to the router is unstable (often Wi-Fi): an Ethernet cable almost always fixes it."
                        )
                    } else {
                        crate::tr!(
                            "La liaison avec le routeur est stable.",
                            "The link to the router is stable."
                        )
                    };
                    constats.push(critere(!instable, "routeur", message.to_string()));
                    verifies += 1;
                }
                None => non_verifies.push(
                    crate::tr!(
                        "la liaison avec le routeur : il ne répond pas, ou plus lentement qu'Internet (pas mesurable)",
                        "the link to the router: it does not answer, or more slowly than the Internet (not measurable)"
                    )
                    .to_string(),
                ),
            }
            // Sans au moins trois tests sur ce réseau, rien à comparer : ce n'est pas un manque.
            if let Some(h) = &r.habituel {
                let moins_bonne = moins_bonne_que_d_habitude(h, repos, charge);
                let message = if moins_bonne {
                    crate::tr!(
                        "La connexion est nettement moins bonne que d'habitude sur ce réseau.",
                        "The connection is clearly worse than usual on this network."
                    )
                } else {
                    crate::tr!(
                        "La connexion est comme d'habitude sur ce réseau.",
                        "The connection is as usual on this network."
                    )
                };
                constats.push(critere(!moins_bonne, "habitudes", message.to_string()));
                verifies += 1;
            }
        }
    }
    Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies })
}

#[cfg(test)]
mod tests {
    use super::super::{Charge, Repos, Serie};
    use super::*;

    fn releve(internet: Vec<Option<f64>>, charge: Option<Charge>) -> Releve {
        Releve {
            repos: Repos {
                boite: None,
                serie_box: Some(Serie(vec![Some(1.0); 5])),
                internet: Serie(internet),
            },
            charge,
            habituel: None,
        }
    }

    fn charge(ms: f64) -> Charge {
        Charge {
            en_reception: Serie(vec![Some(ms); 5]),
            debit_bas: Some(300.0),
            en_envoi: Serie(vec![Some(ms); 5]),
            debit_haut: Some(40.0),
        }
    }

    #[test]
    fn resultat_d_un_test() {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        // Hors ligne, ou Internet muet : rien de vérifié, jamais sain.
        let r = resultat(None, debut);
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 0));
        let r = resultat(Some(&releve(vec![None; 20], None)), debut);
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 0));
        assert_eq!(r.constats[0].etat, "non-verifie");
        // Tout mesuré et bon : sain.
        let r = resultat(Some(&releve(vec![Some(12.0); 20], Some(charge(14.0)))), debut);
        assert_eq!((r.verdict(), r.couverture.verifies), ("sain", 7), "{:?}", r.couverture);
        // Pertes et bufferbloat : problème, et l'objet dit lequel.
        let mut perdu = vec![Some(12.0); 18];
        perdu.extend([None, None]);
        let r = resultat(Some(&releve(perdu, Some(charge(250.0)))), debut);
        assert_eq!(r.verdict(), "probleme");
        let objets: Vec<&str> = r
            .constats
            .iter()
            .filter(|c| c.etat == "probleme")
            .filter_map(|c| c.objet.as_deref())
            .collect();
        assert_eq!(objets, ["mesure:pertes", "mesure:bufferbloat"]);
        // Aucun transfert abouti : le débit manque, jamais compté bon.
        let mut sans_debit = charge(14.0);
        sans_debit.debit_haut = None;
        let r = resultat(Some(&releve(vec![Some(12.0); 20], Some(sans_debit))), debut);
        assert_eq!(r.verdict(), "non-verifie");
    }
}
