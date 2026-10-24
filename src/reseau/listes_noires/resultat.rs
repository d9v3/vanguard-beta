//! Le résultat de la recherche de l'adresse publique dans les listes noires (`modele::resultat`) : le jugement du
//! relevé, sans l'écran. Versé au rapport (`examens/PRO-LNO-001.json`), au journal des événements, et rendu par
//! `--json`. Sans accord, rien n'a été demandé : non vérifié, jamais « pas listée ».

use super::{LISTES, Releve, Verdict, sens};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::Objet;
use crate::modele::Raison;
use crate::modele::resultat::{Couverture, Resultat};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-LNO-001";

const CAT: &str = "Listes noires";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'un relevé commencé à `debut` : un constat par liste interrogée (pas listée, listée et pourquoi, ou
/// impossible à vérifier), ou un seul « non vérifié » quand rien n'a été envoyé. L'adresse publique n'y est pas
/// écrite : le résultat dit ce que les listes en pensent, pas qui elle est.
pub(super) fn resultat(r: &Releve, debut: Debut) -> Resultat {
    let rien = |raison: Raison, message: String| {
        Resultat::nouveau(
            ID,
            debut,
            &[impossible_par(CAT, raison, message.clone())],
            Couverture {
                verifies: 0,
                non_verifies: vec![message],
            },
        )
    };
    match r {
        Releve::SansAccord => rien(
            Raison::Refuse(crate::tr!("sans accord", "without consent").to_string()),
            crate::tr!(
                "Adresse publique pas cherchée dans les listes noires : rien n'est envoyé sans accord (relancez avec --internet pour le donner d'avance).",
                "Public address not looked up in the blocklists: nothing is sent without consent (run again with --internet to give it in advance)."
            )
            .to_string(),
        ),
        Releve::HorsLigne => rien(
            Raison::Refuse(crate::tr!("travail sans Internet", "working offline").to_string()),
            crate::tr!(
                "Adresse publique pas cherchée dans les listes noires : le travail sans Internet est demandé, rien n'a été envoyé.",
                "Public address not looked up in the blocklists: working offline is requested, nothing was sent."
            )
            .to_string(),
        ),
        Releve::SansAdresse => rien(
            Raison::Echoue(crate::tr!("adresse publique introuvable", "public address not found").to_string()),
            crate::tr!(
                "Adresse publique introuvable (pas d'Internet ?) : aucune liste n'a été interrogée.",
                "Public address not found (no Internet?): no list was queried."
            )
            .to_string(),
        ),
        Releve::Repondu(_, reponses) => {
            let mut verifies = 0;
            let constats: Vec<Constat> = LISTES
                .iter()
                .zip(reponses)
                .map(|(liste, reponse)| {
                    let nom = liste.nom;
                    let constat = match reponse {
                        Verdict::Absente => {
                            verifies += 1;
                            ok(CAT, crate::trf!("{nom} : pas listée.", "{nom}: not listed."))
                        }
                        Verdict::Listee(codes) => {
                            verifies += 1;
                            let (texte, niveau) = sens(liste.zone, codes);
                            let message = crate::trf!("{nom} : {texte}.", "{nom}: {texte}.");
                            match niveau {
                                Some(n) => alerte(CAT, n, message),
                                // La PBL : adresse résidentielle, normal.
                                None => ok(CAT, message),
                            }
                        }
                        Verdict::Impossible(raison) => impossible_par(
                            CAT,
                            Raison::Echoue(raison.clone()),
                            crate::trf!(
                                "{nom} : impossible à vérifier : {raison}.",
                                "{nom}: could not check: {raison}."
                            ),
                        ),
                    };
                    constat.avec_objet(Objet::de("liste", nom))
                })
                .collect();
            Resultat::nouveau(
                ID,
                debut,
                &constats,
                Couverture {
                    verifies,
                    non_verifies: Vec::new(),
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    #[test]
    fn rien_d_envoye_jamais_sain() {
        for r in [Releve::SansAccord, Releve::HorsLigne, Releve::SansAdresse] {
            let res = resultat(&r, debut());
            assert_eq!(res.verdict(), "non-verifie", "{r:?}");
            assert_eq!(res.couverture.verifies, 0);
        }
        let sans_accord = resultat(&Releve::SansAccord, debut());
        assert!(sans_accord.couverture.non_verifies[0].contains("--internet"));
    }

    #[test]
    fn listee_ou_non() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let toutes_absentes = Releve::Repondu(ip, (0..LISTES.len()).map(|_| Verdict::Absente).collect());
        let r = resultat(&toutes_absentes, debut());
        assert_eq!(r.verdict(), "sain");
        assert_eq!(r.couverture.verifies, 4);
        assert!(
            !crate::modele::resultat::json(&r).contains("203.0.113.7"),
            "l'adresse n'est pas écrite"
        );
        // DroneBL la liste ; SpamCop ne répond pas.
        let releve = Releve::Repondu(
            ip,
            vec![
                Verdict::Listee(vec![Ipv4Addr::new(127, 0, 0, 11)]),
                Verdict::Impossible("votre DNS n'a pas répondu".into()),
                Verdict::Listee(vec![Ipv4Addr::new(127, 0, 0, 17)]),
                Verdict::Absente,
            ],
        );
        let r = resultat(&releve, debut());
        assert_eq!(r.verdict(), "probleme");
        assert_eq!(r.couverture.verifies, 3);
        let listee: Vec<_> = r.constats.iter().filter(|c| c.etat == "probleme").collect();
        assert_eq!(listee.len(), 1, "la PBL seule n'est pas un problème");
        assert_eq!(listee[0].objet.as_deref(), Some("liste:DroneBL"));
        assert_eq!(r.constats[1].etat, "non-verifie");
    }
}
