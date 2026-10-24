//! Le résultat du bilan de confidentialité (`modele::resultat`) : chaque application qui a un accès sensible, celles
//! lancées d'un dossier où un logiciel espion se cache souvent, et ce qui n'a pas pu être lu, sans l'écran. Versé au
//! rapport (`examens/PRO-ACC-001.json`), au journal des événements, et rendu par `--json`.

use super::{Acces, Bilan, PERMISSIONS, Permission, Remarque};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat, sans_piege};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-ACC-001";

const CAT: &str = "Confidentialité";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le code stable d'une permission, sans langue : il entre dans l'objet des constats.
fn code(p: Permission) -> &'static str {
    match p {
        Permission::Position => "position",
        Permission::Contacts => "contacts",
        Permission::Camera => "camera",
        Permission::Micro => "micro",
    }
}

/// La permission dans une liste (« position, caméra »).
fn nom(p: Permission) -> &'static str {
    match p {
        Permission::Position => crate::tr!("position", "location"),
        Permission::Contacts => crate::tr!("contacts", "contacts"),
        Permission::Camera => crate::tr!("caméra", "camera"),
        Permission::Micro => crate::tr!("micro", "microphone"),
    }
}

/// Ce à quoi l'on a accès, dans une phrase (« a accès à la caméra », « aux contacts »).
fn acces_a(p: Permission) -> &'static str {
    match p {
        Permission::Position => crate::tr!("à la position", "to the location"),
        Permission::Contacts => crate::tr!("aux contacts", "to the contacts"),
        Permission::Camera => crate::tr!("à la caméra", "to the camera"),
        Permission::Micro => crate::tr!("au micro", "to the microphone"),
    }
}

/// L'objet d'un accès : la permission et l'application, telle que le système la nomme. Le nom vient du registre, de
/// Flatpak, de Snap ou de TCC : ses caractères piégés deviennent « � », comme dans le message.
fn objet(a: &Acces) -> Objet {
    Objet::de(
        "acces",
        &format!("{}:{}", code(a.permission), sans_piege(&a.application, false)),
    )
}

/// Un accès : une alerte quand l'application a été lancée d'un dossier temporaire ou de Téléchargements (signalée
/// en rouge à l'écran), sinon un simple fait.
fn constat_d_acces(a: &Acces) -> Constat {
    let quand = if a.en_cours {
        Some(crate::tr!("en ce moment", "right now").to_string())
    } else {
        a.quand.clone()
    };
    let detail = match quand {
        Some(q) => format!("{} ; {q}", a.source),
        None => a.source.clone(),
    };
    let c = if crate::protection::camera::lieu_suspect(&a.application) {
        alerte(
            CAT,
            Niveau::Eleve,
            crate::trf!(
                "{} a accès {} ({detail}) et a été lancé depuis un dossier temporaire ou Téléchargements : un logiciel espion se cache souvent là. Faites vérifier le fichier avant tout.",
                "{} has access {} ({detail}) and was started from a temporary folder or Downloads: spyware often hides there. Have the file checked first.",
                a.application,
                acces_a(a.permission)
            ),
        )
    } else {
        ok(
            CAT,
            crate::trf!(
                "{} a accès {} ({detail}).",
                "{} has access {} ({detail}).",
                a.application,
                acces_a(a.permission)
            ),
        )
    };
    c.avec_objet(objet(a))
}

/// Le résultat d'un bilan commencé à `debut`. Une permission n'est comptée vérifiée que si rien de ce qui la touche
/// n'a échoué, et que le système liste tout ce qui peut s'en servir ; une lecture en échec se dit sous chaque
/// permission qu'elle touchait (`non_verifies`, une fois par texte, avec les permissions concernées).
pub(super) fn resultat(b: &Bilan, debut: Debut) -> Resultat {
    // Un manque, pour le résultat : une lecture en échec, ou ce que le système ne liste pas (affiché comme un fait).
    let manque = |r: &Remarque| !r.verifie || r.hors_liste;
    let touchee = |r: &Remarque, p: Permission| r.touchees.contains(&p);
    let verifiee = |p: Permission| !b.remarques.iter().any(|r| manque(r) && touchee(r, p));
    // Seul manque : ce qui n'est pas listé. Ce qui l'est a bien été lu.
    let listee = |p: Permission| !b.remarques.iter().any(|r| !r.verifie && touchee(r, p));
    // Les permissions d'une remarque, dans une phrase : « tout » quand elle les touche toutes.
    let quoi = |r: &Remarque| match r.permission {
        Some(p) => vec![nom(p)],
        None if r.touchees.len() == PERMISSIONS.len() => vec![crate::tr!("tout", "everything")],
        None => r.touchees.iter().map(|p| nom(*p)).collect(),
    };
    let mut constats: Vec<Constat> = b.acces.iter().map(constat_d_acces).collect();
    for r in &b.remarques {
        let c = if manque(r) {
            let quoi = quoi(r).join(", ");
            impossible_par(
                CAT,
                Raison::Illisible(r.texte.clone()),
                crate::trf!("Non vérifié ({quoi}) : {}", "Not checked ({quoi}): {}", r.texte),
            )
        } else {
            ok(CAT, r.texte.clone())
        };
        constats.push(match r.permission {
            Some(p) => c.avec_objet(Objet::de("permission", code(p))),
            None => c,
        });
    }
    for p in PERMISSIONS {
        let rien = !b.acces.iter().any(|a| a.permission == p) && !b.remarques.iter().any(|r| r.permission == Some(p));
        if !rien {
            continue;
        }
        let message = if verifiee(p) {
            crate::trf!("Aucune application n'a accès {}.", "No app has access {}.", acces_a(p))
        } else if listee(p) {
            // Ce qui est listé a été lu : le dire, sans conclure pour ce que le système ne montre pas.
            crate::trf!(
                "Aucune des applications que le système liste n'a accès {}.",
                "None of the apps the system lists has access {}.",
                acces_a(p)
            )
        } else {
            continue;
        };
        constats.push(ok(CAT, message).avec_objet(Objet::de("permission", code(p))));
    }
    // Un même échec touche souvent plusieurs permissions : une ligne par texte, les permissions réunies.
    let mut manques: Vec<(Vec<&'static str>, &str)> = Vec::new();
    for r in b.remarques.iter().filter(|r| manque(r)) {
        let touchees = quoi(r);
        match manques.iter_mut().find(|(_, t)| *t == r.texte) {
            Some((deja, _)) => deja.extend(touchees),
            None => manques.push((touchees, &r.texte)),
        }
    }
    let non_verifies = manques
        .into_iter()
        .map(|(touchees, texte)| crate::trf!("{} : {texte}", "{}: {texte}", touchees.join(", ")))
        .collect();
    let lues = PERMISSIONS.iter().filter(|p| verifiee(**p)).count();
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies: u32::try_from(lues).unwrap_or(u32::MAX),
            non_verifies,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acces(permission: Permission, application: &str) -> Acces {
        Acces {
            permission,
            application: application.into(),
            source: "programme classique".into(),
            quand: None,
            en_cours: false,
        }
    }

    #[test]
    fn resultat_d_un_bilan() {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        // Rien de lu (un système qui n'a rien rendu) : jamais sain.
        let mut b = Bilan::default();
        for p in PERMISSIONS {
            b.remarque(Some(p), false, "illisible");
        }
        let r = resultat(&b, debut);
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
        assert_eq!(
            r.couverture.non_verifies.len(),
            1,
            "un texte, les quatre permissions réunies"
        );
        // Tout lu, rien d'accordé : sain, une ligne par permission.
        let r = resultat(&Bilan::default(), debut);
        assert_eq!((r.verdict(), r.couverture.verifies), ("sain", 4));
        assert_eq!(r.constats.len(), 4);
        // Une application lancée de Téléchargements avec la caméra : problème, et son objet.
        let mut b = Bilan::default();
        b.acces
            .push(acces(Permission::Micro, r"C:\Program Files\Zoom\Zoom.exe"));
        b.acces
            .push(acces(Permission::Camera, r"C:\Users\alice\Downloads\outil.exe"));
        b.remarque(Some(Permission::Position), false, "illisible");
        let r = resultat(&b, debut);
        assert_eq!(r.verdict(), "probleme");
        assert_eq!(r.pire(), Some(Niveau::Eleve));
        assert_eq!(r.couverture.verifies, 3);
        let suspect = r.constats.iter().find(|c| c.etat == "probleme").unwrap();
        assert_eq!(
            suspect.objet.as_deref(),
            Some(r"acces:camera:C:\Users\alice\Downloads\outil.exe")
        );
        assert_eq!(
            r.constats.iter().filter(|c| c.etat == "sain").count(),
            2,
            "Zoom, et contacts : aucune"
        );
    }

    /// Ce que le système ne liste pas (programmes classiques sous Linux et Windows) : jamais « aucune application n'a
    /// accès », jamais compté vérifié ; ce qui est listé reste dit. Un journal WAL non lu (macOS) : non vérifié.
    #[test]
    fn ce_qui_n_est_pas_liste() {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let mut b = Bilan::default();
        b.hors_liste(
            &[Permission::Contacts, Permission::Camera, Permission::Micro],
            "ils peuvent tous se servir de la caméra",
        );
        let r = resultat(&b, debut);
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 1, "la position seule");
        assert_eq!(r.couverture.non_verifies.len(), 1, "{:?}", r.couverture.non_verifies);
        assert!(
            r.couverture.non_verifies[0].starts_with("contacts, caméra, micro : "),
            "{:?}",
            r.couverture.non_verifies
        );
        assert!(
            !r.constats
                .iter()
                .any(|c| c.message.starts_with("Aucune application n'a accès à la caméra")),
            "{:?}",
            r.constats
        );
        let camera = r
            .constats
            .iter()
            .find(|c| c.objet.as_deref() == Some("permission:camera"))
            .unwrap();
        assert_eq!(camera.etat, "sain");
        assert!(camera.message.contains("que le système liste"), "{}", camera.message);
        assert!(
            r.constats
                .iter()
                .any(|c| c.etat == "non-verifie" && c.message.contains("se servir")),
            "{:?}",
            r.constats
        );
        // Toutes coupées pour ces programmes (Windows) : un simple fait, tout vérifié.
        let mut b = Bilan::default();
        b.hors_liste(&[], "un programme jamais lancé y aurait accès");
        let r = resultat(&b, debut);
        assert_eq!((r.verdict(), r.couverture.verifies), ("sain", 4));
        // Un accès réel reste dit à côté du manque.
        let mut b = Bilan::default();
        b.acces.push(acces(Permission::Camera, "org.exemple.Visio"));
        b.hors_liste(&[Permission::Camera], "programmes classiques");
        let r = resultat(&b, debut);
        assert!(
            r.constats
                .iter()
                .any(|c| c.etat == "sain" && c.message.contains("Visio"))
        );
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 3));
        // macOS : le journal WAL non lu touche caméra, micro et contacts, pas la position.
        let mut b = Bilan::default();
        b.remarque_sur(
            &[Permission::Contacts, Permission::Camera, Permission::Micro],
            false,
            "journal WAL non lu",
        );
        let r = resultat(&b, debut);
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 1));
        assert_eq!(
            r.couverture.non_verifies,
            ["contacts, caméra, micro : journal WAL non lu"]
        );
        assert!(
            !r.constats
                .iter()
                .any(|c| c.message.contains("Aucune") && c.objet.as_deref() != Some("permission:position"))
        );
    }

    /// Windows : un programme classique peut se servir de ce qui n'est pas coupé pour lui sans être noté.
    #[test]
    fn programmes_classiques_de_windows() {
        let libre = crate::protection::camera::Consentement {
            global: Some("Allow".into()),
            hors_store: Some("Allow".into()),
            entrees: Vec::new(),
        };
        let mut coupe = libre.clone();
        coupe.hors_store = Some("Deny".into());
        let mut b = Bilan::default();
        assert!(super::super::juger_windows(
            Permission::Camera,
            Some(&libre),
            None,
            &mut b
        ));
        assert!(!super::super::juger_windows(
            Permission::Micro,
            Some(&coupe),
            None,
            &mut b
        ));
        assert!(!super::super::juger_windows(Permission::Contacts, None, None, &mut b));
    }

    /// Un nom d'application piégé n'arrive pas brut dans l'objet (le message l'est par `ConstatEcrit`).
    #[test]
    fn objet_sans_piege() {
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let mut b = Bilan::default();
        b.acces.push(acces(Permission::Micro, "outil\u{202e}exe.fdp"));
        let r = resultat(&b, debut);
        let o = r.constats[0].objet.as_deref().unwrap();
        assert!(!crate::ui::contient_un_piege(o), "{o:?}");
    }
}
