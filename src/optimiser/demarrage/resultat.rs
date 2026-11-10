//! Le résultat des programmes au démarrage (`modele::resultat`), pour `vanguard demarrage --json` : la liste que
//! montre l'écran à cocher, sans l'écran ni aucun retrait, versée au rapport (`examens/PRO-DEM-001.json`) et au
//! journal.
//!
//! Un programme qui se lance n'est pas un problème en soi : chacun est un constat sain, avec ce que l'écran en dit (à
//! garder, pare-feu, se lance, retiré par Vanguard). Seul un démarrage chargé (8 programmes ordinaires ou plus, le
//! seuil de la lenteur) se signale, pour information. Ce qui n'a pas pu être lu (dossier d'autostart illisible,
//! services du compte sans systemd, clé Run fermée, notes de Vanguard douteuses) est dit non vérifié : jamais une
//! liste incomplète comptée saine.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::machine::{Constat, alerte, ok};
use crate::modele::Objet;
use crate::modele::resultat::{Couverture, Resultat, nom_pour_cle, nom_sans_piege};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-DEM-001";

const CAT: &str = "Programmes au démarrage";

/// Au-delà, les programmes se résument en une ligne : la fenêtre n'a pas à en lister des centaines.
const PROGRAMMES_MONTRES: usize = 40;

/// À partir de là, le démarrage est chargé : le même seuil que la lenteur (`lenteur::juger`).
const CHARGE: usize = 8;

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Ce que l'écran dit d'un programme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Statut {
    /// À garder (sécurité, pilote, bureau…), avec la raison : jamais proposé.
    Garder(&'static str),
    /// Un pare-feu reconnu : le retirer serait une baisse.
    PareFeu,
    /// Un programme ordinaire qui se lance.
    SeLance,
    /// Retiré par Vanguard, remis d'un clic.
    Retire,
}

/// Un programme de la liste, tel que l'écran le montre. `identite` : ce qui le désigne dans les notes de Vanguard
/// (« demarrage:… » sans le préfixe).
pub(super) struct Entree<'a> {
    pub nom: &'a str,
    pub commande: &'a str,
    pub identite: &'a str,
    pub machine: bool,
    pub statut: Statut,
}

/// Le résultat d'après la liste lue et ce qui n'a pas pu l'être (`manques`).
pub(super) fn resultat(entrees: &[Entree], manques: Vec<String>, debut: Debut) -> Resultat {
    let mut constats: Vec<Constat> = entrees.iter().take(PROGRAMMES_MONTRES).map(constat).collect();
    let reste = entrees.len().saturating_sub(PROGRAMMES_MONTRES);
    if reste > 0 {
        constats.push(ok(
            CAT,
            trf!(
                "… et {} autre(s) programme(s) : la liste entière dans « vanguard demarrage ».",
                "… and {} other program(s): the whole list in “vanguard startup”.",
                reste
            ),
        ));
    }
    let ordinaires = entrees.iter().filter(|e| e.statut == Statut::SeLance).count();
    if ordinaires >= CHARGE {
        constats.push(alerte(
            CAT,
            Niveau::Info,
            trf!(
                "{} programmes ordinaires se lancent à l'ouverture de session : en retirer accélère le démarrage (ils restent installés).",
                "{} ordinary programs start at login: removing some speeds up startup (they stay installed).",
                ordinaires
            ),
        ));
    }
    if entrees.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun programme du compte ne se lance à l'ouverture de session.",
                "No program of this account starts at login."
            ),
        ));
    }
    // La liste a été lue (même en partie) : une vérification ; chaque manque la rend partielle.
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies: 1,
            non_verifies: manques,
        },
    )
}

/// Le constat d'un programme : sain, avec ce que l'écran en dit. Le nom et la commande viennent de qui a posé
/// l'entrée : montrés sans piège, et la clé (objet « demarrage:… ») échappée.
fn constat(e: &Entree) -> Constat {
    let statut = match e.statut {
        Statut::Garder(raison) => trf!("à garder ({})", "to keep ({})", raison),
        Statut::PareFeu => tr!(
            "pare-feu : le retirer baisserait la protection",
            "firewall: removing it would lower protection"
        )
        .to_string(),
        Statut::SeLance => tr!("se lance", "starts").to_string(),
        Statut::Retire => tr!("retiré par Vanguard", "removed by Vanguard").to_string(),
    };
    let mut texte = format!(
        "{} — {statut} · {}",
        nom_sans_piege(e.nom, 80),
        nom_sans_piege(e.commande, 160)
    );
    if e.machine {
        texte.push_str(tr!(" · tout l'ordinateur", " · whole machine"));
    }
    ok(CAT, texte).avec_objet(Objet::de("demarrage", &nom_pour_cle(e.identite)))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    /// Un programme inventé.
    fn entree(nom: &'static str, statut: Statut) -> Entree<'static> {
        Entree {
            nom,
            commande: "/opt/exemple/lanceur --discret",
            identite: nom,
            machine: false,
            statut,
        }
    }

    /// Des programmes trouvés, tout lu : un constat sain par programme, avec sa clé ; sain.
    #[test]
    fn programmes_trouves() {
        let l = [
            entree("Lecteur", Statut::SeLance),
            entree("Pilote", Statut::Garder("pilote")),
            entree("Messagerie", Statut::Retire),
        ];
        let r = resultat(&l, vec![], debut());
        assert_eq!(r.outil, ID);
        assert_eq!((r.couverture.verifies, r.verdict()), (1, "sain"));
        assert_eq!(r.constats.len(), 3);
        assert_eq!(r.constats[0].objet.as_deref(), Some("demarrage:Lecteur"));
        assert!(r.constats[1].message.contains("pilote"));
    }

    /// Aucun programme : une ligne saine qui le dit.
    #[test]
    fn aucun_programme() {
        let r = resultat(&[], vec![], debut());
        assert_eq!((r.constats.len(), r.verdict()), (1, "sain"));
    }

    /// Un dossier illisible ou des notes douteuses : partiel, jamais sain, même sans aucun programme.
    #[test]
    fn partiel_jamais_sain() {
        let r = resultat(&[], vec!["services du compte pas lus".into()], debut());
        assert_eq!((r.couverture.verifies, r.verdict()), (1, "non-verifie"));
        assert!(r.couverture.non_verifies[0].contains("services"));
    }

    /// Un démarrage chargé : une information, pas un problème grave ; plafonné, le reste résumé ; un nom piégé sort
    /// inoffensif, dans le texte comme dans la clé.
    #[test]
    fn charge_plafonne_et_sans_piege() {
        let noms: Vec<String> = (0..45).map(|i| format!("Programme{i}\u{202e}")).collect();
        let l: Vec<Entree> = noms
            .iter()
            .map(|n| Entree {
                nom: n,
                commande: "x\u{1b}[2Ky",
                identite: n,
                machine: true,
                statut: Statut::SeLance,
            })
            .collect();
        let r = resultat(&l, vec![], debut());
        assert_eq!(r.constats.len(), PROGRAMMES_MONTRES + 2);
        assert!(r.constats.iter().any(|c| c.message.contains(" 5 ")));
        assert_eq!(r.pire(), Some(Niveau::Info));
        assert!(
            r.constats
                .iter()
                .all(|c| !c.message.contains('\u{202e}') && !c.message.contains('\u{1b}'))
        );
        assert!(
            r.constats
                .iter()
                .filter_map(|c| c.objet.as_deref())
                .all(|o| !o.contains('\u{202e}'))
        );
    }
}
