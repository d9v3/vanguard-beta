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
use crate::modele::resultat::{Couverture, GesteEcrit, Resultat, nom_pour_cle, nom_sans_piege};
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
    // Rien de lu mais quelque chose de pas lu : la liste ne dit pas qu'aucun programme ne se lance (T-1).
    if entrees.is_empty() && manques.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun programme du compte ne se lance à l'ouverture de session.",
                "No program of this account starts at login."
            ),
        ));
    }
    // La liste a été lue (même en partie) : une vérification ; chaque manque la rend partielle.
    let mut r = Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies: 1,
            non_verifies: manques,
        },
    );
    // Les premiers constats sont ceux des programmes montrés, dans le même ordre : chacun reçoit son geste.
    for (c, e) in r.constats.iter_mut().zip(entrees.iter().take(PROGRAMMES_MONTRES)) {
        c.geste = geste(e);
    }
    r
}

/// L'objet d'un programme, tel que le constat l'écrit : « demarrage:<identité échappée> », le chemin d'une entrée
/// d'autostart montré « ~/… » sous le dossier personnel : son chemin absolu dit le nom du compte, et part au rapport,
/// au journal et vers la fenêtre (T-4, comme 27ae2490 du sous-lot B). L'empreinte, elle, reste celle de l'identité
/// entière (`empreinte`) : elle ne change pas d'une version à l'autre.
fn objet(identite: &str) -> Objet {
    let montree = match identite.split_once('|') {
        Some((sorte, chemin)) if chemin.starts_with('/') => format!("{sorte}|{}", chemin_montre(chemin)),
        _ => identite.to_string(),
    };
    Objet::de("demarrage", &nom_pour_cle(&montree))
}

/// « ~ » ou « ~/… » sous le dossier personnel, jamais son chemin absolu ; tel quel ailleurs.
fn chemin_montre(chemin: &str) -> String {
    let maison = crate::socle::maison();
    if !maison.is_absolute() || maison.parent().is_none() {
        return chemin.to_string();
    }
    match std::path::Path::new(chemin).strip_prefix(&maison).map(|r| r.to_str()) {
        Ok(Some("")) => "~".to_string(),
        Ok(Some(r)) => format!("~/{r}"),
        _ => chemin.to_string(),
    }
}

/// L'empreinte d'un programme : les 16 premiers octets du BLAKE3 de son objet tel que le constat l'écrit
/// (« demarrage:<identité échappée> »), en 32 chiffres hexadécimaux minuscules. C'est tout ce que la fenêtre renvoie
/// pour le désigner : ni nom ni chemin, qu'elle aurait pu se faire glisser. `None` : une identité vide, sans objet.
pub(super) fn empreinte(identite: &str) -> Option<String> {
    let objet = Objet::de("demarrage", &nom_pour_cle(identite));
    let texte = objet.texte().filter(|t| !t.is_empty())?;
    let h = blake3::hash(texte.as_bytes());
    Some(super::hex(h.as_bytes().get(..16)?))
}

/// Ce qu'un clic peut demander pour ce programme : le retirer s'il est ordinaire et se lance, le remettre si Vanguard
/// l'a retiré ; rien pour un programme à garder ni pour un pare-feu (le retirer serait une baisse, qui ne se choisit
/// pas d'un clic).
fn geste(e: &Entree) -> Option<GesteEcrit> {
    let sorte = match e.statut {
        Statut::SeLance => "retirer",
        Statut::Retire => "remettre",
        Statut::Garder(_) | Statut::PareFeu => return None,
    };
    Some(GesteEcrit {
        sorte: sorte.to_string(),
        empreinte: empreinte(e.identite)?,
        nom: nom_sans_piege(e.nom, 80),
        commande: nom_sans_piege(e.commande, 160),
        machine: e.machine,
    })
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
    ok(CAT, texte).avec_objet(objet(e.identite))
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

    /// T-4 : l'objet d'une entrée d'autostart du compte part en « ~/… », jamais avec le chemin du dossier personnel
    /// (qui dit le nom du compte) ; l'empreinte reste celle de l'identité entière ; un service ou un chemin hors du
    /// dossier personnel reste tel quel. Linux seulement : sous Windows, l'identité (« hkcu|Run|nom ») ne porte aucun
    /// chemin, et le dossier personnel (« C:\users\… ») n'y prend jamais la forme « /… » que l'essai bâtit.
    #[cfg(target_os = "linux")]
    #[test]
    fn l_objet_ne_dit_pas_le_dossier_personnel() {
        let maison = crate::socle::maison();
        let maison = maison.to_str().unwrap();
        let identite = format!("autostart|{maison}/.config/autostart/lecteur.desktop");
        let mut e = entree("Lecteur", Statut::SeLance);
        e.identite = &identite;
        let r = resultat(std::slice::from_ref(&e), vec![], debut());
        let o = r.constats[0].objet.clone().unwrap();
        assert!(!o.contains(maison), "{o}");
        assert!(o.contains("~/.config/autostart/lecteur.desktop"), "{o}");
        assert_eq!(
            r.constats[0].geste.as_ref().unwrap().empreinte,
            empreinte(&identite).unwrap()
        );
        for tel_quel in ["systemd|syncthing.service", "autostart|/etc/xdg/autostart/x.desktop"] {
            assert_eq!(
                objet(tel_quel).texte(),
                Objet::de("demarrage", &nom_pour_cle(tel_quel)).texte(),
                "{tel_quel}"
            );
        }
    }

    /// Le geste de chaque programme : retirer un programme ordinaire qui se lance, remettre ce que Vanguard a
    /// retiré, rien pour un programme à garder ni pour un pare-feu. L'empreinte est celle de l'objet écrit, en 32
    /// chiffres hexadécimaux minuscules ; le nom et la commande sortent sans piège.
    #[test]
    fn gestes_et_empreintes() {
        let mut piege = entree("Lecteur\u{202e}", Statut::SeLance);
        piege.commande = "x\u{1b}[2Ky";
        piege.machine = true;
        let l = [
            piege,
            entree("Pilote", Statut::Garder("pilote")),
            entree("Messagerie", Statut::Retire),
            entree("Murdefeu", Statut::PareFeu),
        ];
        let r = resultat(&l, vec![], debut());
        let gestes: Vec<Option<&str>> = r
            .constats
            .iter()
            .map(|c| c.geste.as_ref().map(|g| g.sorte.as_str()))
            .collect();
        assert_eq!(gestes, [Some("retirer"), None, Some("remettre"), None]);
        let g = r.constats[0].geste.as_ref().unwrap();
        assert!(g.machine);
        assert!(!g.nom.contains('\u{202e}') && !g.commande.contains('\u{1b}'));
        for c in &r.constats {
            if let (Some(g), Some(objet)) = (&c.geste, &c.objet) {
                assert_eq!(g.empreinte.len(), 32);
                assert!(g.empreinte.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
                let h = blake3::hash(objet.as_bytes());
                assert_eq!(g.empreinte, super::super::hex(&h.as_bytes()[..16]), "{objet}");
            }
        }
        // Deux programmes, deux empreintes.
        assert_ne!(empreinte("Lecteur"), empreinte("Lecteur "));
        assert_eq!(empreinte(""), None);
        // Au-delà des programmes montrés, la ligne qui résume n'a pas de geste.
        let noms: Vec<String> = (0..45).map(|i| format!("Programme{i}")).collect();
        let l: Vec<Entree> = noms
            .iter()
            .map(|n| Entree {
                nom: n,
                commande: "lecteur",
                identite: n,
                machine: false,
                statut: Statut::SeLance,
            })
            .collect();
        let r = resultat(&l, vec![], debut());
        assert_eq!(
            r.constats.iter().filter(|c| c.geste.is_some()).count(),
            PROGRAMMES_MONTRES
        );
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
