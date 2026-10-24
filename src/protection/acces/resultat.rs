//! Le résultat du bilan de confidentialité (`modele::resultat`) : chaque application qui a un accès sensible, celles
//! lancées d'un dossier où un logiciel espion se cache souvent, et ce qui n'a pas pu être lu, sans l'écran. Versé au
//! rapport (`examens/PRO-ACC-001.json`), au journal des événements, et rendu par `--json`.

use super::{Acces, Bilan, PERMISSIONS, Permission};
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
/// n'a échoué ; une lecture en échec se dit sous chaque permission qu'elle touchait (`non_verifies`, une fois par
/// texte, avec les permissions concernées).
pub(super) fn resultat(b: &Bilan, debut: Debut) -> Resultat {
    let general_manque = b.remarques.iter().any(|r| r.permission.is_none() && !r.verifie);
    let verifiee =
        |p: Permission| !general_manque && !b.remarques.iter().any(|r| r.permission == Some(p) && !r.verifie);
    let mut constats: Vec<Constat> = b.acces.iter().map(constat_d_acces).collect();
    for r in &b.remarques {
        let c = if r.verifie {
            ok(CAT, r.texte.clone())
        } else {
            let quoi = r.permission.map_or(crate::tr!("tout", "everything"), nom);
            impossible_par(
                CAT,
                Raison::Illisible(r.texte.clone()),
                crate::trf!("Non vérifié ({quoi}) : {}", "Not checked ({quoi}): {}", r.texte),
            )
        };
        constats.push(match r.permission {
            Some(p) => c.avec_objet(Objet::de("permission", code(p))),
            None => c,
        });
    }
    for p in PERMISSIONS {
        let rien = !b.acces.iter().any(|a| a.permission == p) && !b.remarques.iter().any(|r| r.permission == Some(p));
        if rien && verifiee(p) {
            constats.push(
                ok(
                    CAT,
                    crate::trf!("Aucune application n'a accès {}.", "No app has access {}.", acces_a(p)),
                )
                .avec_objet(Objet::de("permission", code(p))),
            );
        }
    }
    // Un même échec touche souvent plusieurs permissions : une ligne par texte, les permissions réunies.
    let mut manques: Vec<(Vec<&'static str>, &str)> = Vec::new();
    for r in b.remarques.iter().filter(|r| !r.verifie) {
        let touchee = r.permission.map_or(crate::tr!("tout", "everything"), nom);
        match manques.iter_mut().find(|(_, t)| *t == r.texte) {
            Some((touchees, _)) => touchees.push(touchee),
            None => manques.push((vec![touchee], &r.texte)),
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
