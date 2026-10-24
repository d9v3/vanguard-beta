//! Le résultat de « Mon ordinateur est-il contrôlé ? » (`modele::resultat`) : le jugement du relevé, sans l'écran.
//! Versé au rapport (`examens/PRO-DIS-001.json`), au journal des événements, et rendu par `--json`. Les constats sont
//! ceux du bilan (un par logiciel trouvé, sa correction décrite, jamais lancée d'ici) ; ce qui n'a pas pu être lu
//! (programmes installés, démarrage, processus, dossiers) est dit non vérifié.

use chrono::NaiveDate;

use super::{CAT, Releve, juger};
use crate::machine::{Constat, impossible, ok};
use crate::modele::resultat::{Couverture, Resultat};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-DIS-001";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Ce qui n'a pas pu être lu, dans la langue du moment, et le nombre de sortes de traces lues.
fn couverture(r: &Releve) -> Couverture {
    let sortes = [
        (
            r.lu.installes,
            crate::tr!(
                "programmes installés : leur liste ne se lit pas",
                "installed programs: their list cannot be read"
            ),
        ),
        (
            r.lu.demarrage,
            crate::tr!(
                "lancements au démarrage : pas tous lisibles",
                "programs started at boot: not all readable"
            ),
        ),
        (
            r.lu.en_cours,
            crate::tr!(
                "programmes en cours : leur liste ne se lit pas",
                "running programs: their list cannot be read"
            ),
        ),
        (
            r.lu.fichiers,
            crate::tr!(
                "Téléchargements, Bureau et dossiers temporaires : pas tous lisibles",
                "Downloads, Desktop and temporary folders: not all readable"
            ),
        ),
    ];
    Couverture {
        verifies: u32::try_from(sortes.iter().filter(|(lu, _)| *lu).count()).unwrap_or(u32::MAX),
        non_verifies: sortes
            .iter()
            .filter(|(lu, _)| !*lu)
            .map(|(_, texte)| (*texte).to_string())
            .collect(),
    }
}

/// Le résultat d'un relevé commencé à `debut` (`None` : rien de lisible).
pub(super) fn resultat(r: Option<&Releve>, aujourd_hui: NaiveDate, debut: Debut) -> Resultat {
    let Some(r) = r else {
        return Resultat::nouveau(
            ID,
            debut,
            &[impossible(
                CAT,
                crate::tr!("programmes installés illisibles", "installed programs unreadable"),
            )],
            Couverture::default(),
        );
    };
    let couverture = couverture(r);
    let mut constats: Vec<Constat> = juger(&r.trouvailles, aujourd_hui);
    // Rien trouvé dans ce qui a pu être lu : le « rien trouvé » du bilan affirmerait aussi ce qui n'a pas été lu.
    if !couverture.non_verifies.is_empty() && constats.iter().all(|c| c.probleme.is_none()) {
        constats = vec![ok(
            CAT,
            crate::tr!(
                "Aucun logiciel de prise de contrôle à distance (AnyDesk, TeamViewer, RustDesk…) dans ce qui a pu être lu ; le reste n'est pas vérifié.",
                "No remote control tool (AnyDesk, TeamViewer, RustDesk…) in what could be read; the rest is not checked."
            ),
        )];
    }
    Resultat::nouveau(ID, debut, &constats, couverture)
}

#[cfg(test)]
mod tests {
    use super::super::{LOGICIELS, Lu, Trace, Trouvaille};
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    fn jour(t: &str) -> NaiveDate {
        NaiveDate::parse_from_str(t, "%Y-%m-%d").unwrap()
    }

    const TOUT_LU: Lu = Lu {
        installes: true,
        demarrage: true,
        en_cours: true,
        fichiers: true,
    };

    #[test]
    fn rien_de_lu_jamais_sain() {
        let aujourd_hui = jour("2026-10-24");
        let vide = Releve::default();
        let r = resultat(Some(&vide), aujourd_hui, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
        assert_eq!(r.couverture.non_verifies.len(), 4);
        assert_eq!(resultat(None, aujourd_hui, debut()).verdict(), "non-verifie");
        // Les processus seuls manquent : toujours pas « sain ».
        let sans_processus = Releve {
            lu: Lu {
                en_cours: false,
                ..TOUT_LU
            },
            ..Releve::default()
        };
        let r = resultat(Some(&sans_processus), aujourd_hui, debut());
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 3));
        let tout = Releve {
            lu: TOUT_LU,
            ..Releve::default()
        };
        assert_eq!(resultat(Some(&tout), aujourd_hui, debut()).verdict(), "sain");
    }

    #[test]
    fn anydesk_telecharge() {
        let anydesk = LOGICIELS.iter().position(|l| l.nom[0] == "AnyDesk").unwrap();
        let r = Releve {
            trouvailles: vec![Trouvaille {
                logiciel: anydesk,
                trace: Trace::Fichier,
                ou: "/home/alice/Téléchargements/AnyDesk.exe".into(),
                depuis: Some(jour("2026-10-20")),
                retrait: vec!["rm -f x".into()],
                arret: Vec::new(),
            }],
            lu: Lu {
                fichiers: true,
                ..Lu::default()
            },
        };
        let res = resultat(Some(&r), jour("2026-10-24"), debut());
        assert_eq!(res.verdict(), "probleme");
        assert_eq!(res.pire(), Some(crate::risk::Niveau::Eleve));
        assert_eq!(res.constats[0].objet.as_deref(), Some("logiciel:AnyDesk"));
        assert_eq!(res.couverture.non_verifies.len(), 3, "le reste reste dit non vérifié");
    }
}
