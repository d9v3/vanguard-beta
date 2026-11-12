//! La fenêtre (`vanguard-fenetre`) d'un programme que la mise à jour remplace : elle le suit, vérifiée contre
//! l'empreinte gravée dans le nouveau programme (`demarrage::empreinte_fenetre`), lui-même déjà vérifié (signature,
//! taille et empreinte de GitHub, ou la version de la clé). La fenêtre d'abord, puis le programme ; si le programme
//! ne se pose pas, l'ancienne fenêtre est remise. Même si ce retour échouait, rien de dangereux : un programme ne
//! lance jamais une fenêtre dont l'empreinte n'est pas la sienne (le menu à la place).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{Essai, Version, installer, lire_octets, mettre_en_place_sous};
use crate::demarrage::empreinte_fenetre::{self, Gravee};
use crate::demarrage::lancer_fenetre::{self, TAILLE_MAX};
use crate::tr;

/// La fenêtre posée à côté de `programme`, s'il y en a une, sous l'un des noms que le lancement cherche.
pub(super) fn a_cote(programme: &Path) -> Option<PathBuf> {
    lancer_fenetre::voisine(programme).filter(|p| std::fs::symlink_metadata(p).is_ok())
}

/// `fenetre` est-elle celle que grave `programme` ? Sinon, pourquoi pas.
fn juste(programme: &[u8], fenetre: &[u8]) -> Result<(), String> {
    match empreinte_fenetre::gravee(programme) {
        Some(Gravee::Empreinte(e)) if Sha256::digest(fenetre)[..] == e => Ok(()),
        Some(Gravee::Empreinte(_)) => Err(tr!(
            "la fenêtre reçue n'est pas celle du nouveau programme : rien n'est remplacé",
            "the received window is not the new program's: nothing is replaced"
        )
        .into()),
        Some(Gravee::Aucune) => Err(tr!(
            "le nouveau programme ne lance aucune fenêtre",
            "the new program launches no window"
        )
        .into()),
        None => Err(sans_marque()),
    }
}

fn sans_marque() -> String {
    tr!(
        "le nouveau programme ne dit pas quelle fenêtre il lance : rien n'est remplacé",
        "the new program does not say which window it launches: nothing is replaced"
    )
    .into()
}

/// `octets` à la place de `cible` (`installer`), et la fenêtre posée à côté remplacée par celle de la nouvelle
/// version, que `recevoir` donne (appelé seulement s'il en faut une). Tout ou rien : une fenêtre qui ne vient pas, ou
/// qui n'est pas celle gravée, et rien n'est remplacé. Un nouveau programme qui ne lance aucune fenêtre se pose seul :
/// celle d'ici reste, il ne la lancera pas.
pub(super) fn installer_avec_sa_fenetre(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    essai: Essai,
    recevoir: &mut dyn FnMut() -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    let Some(chemin) = a_cote(cible) else {
        return installer(octets, cible, attendue, essai);
    };
    match empreinte_fenetre::gravee(octets) {
        Some(Gravee::Aucune) => return installer(octets, cible, attendue, essai),
        // Rien n'est téléchargé pour un programme qui ne dit pas sa fenêtre : refusé tout de suite.
        None => return Err(sans_marque()),
        Some(Gravee::Empreinte(_)) => {}
    }
    let fenetre = recevoir()?;
    installer_avec(octets, cible, attendue, essai, &fenetre, &chemin)
}

/// La fenêtre posée à côté du programme `source` (la clé), si c'est bien celle que gravent ses `octets`. Sinon
/// `None` : la copie se fait sans elle (la surveillance en dépend), et une fenêtre déjà là ne sera pas lancée par un
/// programme qui ne la reconnaît pas.
pub(super) fn de_la_source(source: &Path, octets: &[u8]) -> Option<Vec<u8>> {
    let fenetre = lire_octets(&a_cote(source)?, TAILLE_MAX).ok()?;
    juste(octets, &fenetre).ok().map(|()| fenetre)
}

/// La fenêtre de la copie posée en `cible` : sous le nom que le lancement y cherche.
pub(super) fn pour(cible: &Path) -> Option<PathBuf> {
    lancer_fenetre::voisine(cible)
}

/// Ce qui était à `chemin` avant que la nouvelle fenêtre y soit posée, pour l'y remettre.
enum Avant {
    Absente,
    Lue(Vec<u8>),
    /// Là, mais illisible (droits, fichier spécial, démesurée) : elle ne pourra pas être remise.
    Illisible,
}

/// `octets` à la place de `cible`, `fenetre` posée à `chemin` d'abord, revérifiée ici contre l'empreinte gravée dans
/// `octets` (le seul endroit où cela se juge). Si le programme ne se pose pas, ce qui était à `chemin` y revient.
pub(super) fn installer_avec(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    essai: Essai,
    fenetre: &[u8],
    chemin: &Path,
) -> Result<(), String> {
    juste(octets, fenetre)?;
    let avant = match lire_octets(chemin, TAILLE_MAX) {
        Ok(o) => Avant::Lue(o),
        Err(_) if std::fs::symlink_metadata(chemin).is_err() => Avant::Absente,
        Err(_) => Avant::Illisible,
    };
    let changee = !matches!(&avant, Avant::Lue(o) if o == fenetre);
    if changee {
        poser(fenetre, chemin)?;
    }
    installer(octets, cible, attendue, essai).map_err(|e| {
        let remise = match &avant {
            _ if !changee => Ok(()),
            Avant::Lue(o) => poser(o, chemin),
            Avant::Absente => std::fs::remove_file(chemin).map_err(|e| e.to_string()),
            Avant::Illisible => Err(String::new()),
        };
        match remise {
            Ok(()) => e,
            Err(_) => format!(
                "{e}\n    {}",
                tr!(
                    "l'ancienne fenêtre n'a pas pu être remise : le menu s'ouvrira à sa place",
                    "the old window could not be put back: the menu will open instead"
                )
            ),
        }
    })
}

/// La copie de même version que la clé : seulement sa fenêtre, posée si celle d'ici n'est pas déjà la même.
pub(super) fn poser_si_autre(fenetre: &[u8], chemin: &Path) -> Result<(), String> {
    if lire_octets(chemin, TAILLE_MAX).ok().as_deref() == Some(fenetre) {
        return Ok(());
    }
    poser(fenetre, chemin)
}

/// `octets` à `chemin`, comme `installer` le fait pour le programme : à côté d'abord (créé neuf, jamais par un lien),
/// relu et comparé, puis renommé d'un coup ; rien ne traîne à côté en cas d'échec.
fn poser(octets: &[u8], chemin: &Path) -> Result<(), String> {
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| tr!("chemin sans nom de fichier", "path without a file name").to_string())?;
    let provisoire = chemin.with_file_name(format!("{nom}.nouveau"));
    let posee = (|| -> Result<(), String> {
        use std::io::Write;
        let _ = std::fs::remove_file(&provisoire);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&provisoire)
            .map_err(|e| e.to_string())?;
        f.write_all(octets)
            .and_then(|()| f.sync_all())
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        drop(f);
        if lire_octets(&provisoire, TAILLE_MAX).ok().as_deref() != Some(octets) {
            return Err(tr!("la copie relue ne correspond pas", "the copy read back does not match").into());
        }
        mettre_en_place_sous(&provisoire, chemin, &chemin.with_file_name(format!("{nom}.ancien")))
            .map_err(|e| e.to_string())
    })();
    if posee.is_err() {
        let _ = std::fs::remove_file(&provisoire);
    }
    posee
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demarrage::empreinte_fenetre::marque_d_essai;
    use crate::mise_a_jour::NOM;

    const V: Version = (0, 96, 0, 5);

    /// Un programme inventé de version 0.96.0+5, qui grave `marque` (ou aucune).
    fn programme(marque: Option<&[u8]>) -> Vec<u8> {
        [
            b"prog ".as_slice(),
            &super::super::entete(),
            b"0.96.0+5; ",
            marque.unwrap_or_default(),
        ]
        .concat()
    }

    fn lancant(fenetre: &[u8]) -> Vec<u8> {
        programme(Some(&marque_d_essai(&Sha256::digest(fenetre).into())))
    }

    const SANS_ESSAI: Essai = |_, _| Ok(());
    const ESSAI_RATE: Essai = |_, _| Err("ne démarre pas".into());

    fn dossier(nom: &str) -> PathBuf {
        let d = crate::socle::dossier_local().join(nom);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rien_a_cote(d: &Path) -> bool {
        std::fs::read_dir(d)
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".nouveau"))
    }

    /// GitHub : la fenêtre posée à côté du programme remplacé suit, vérifiée contre l'empreinte gravée dans le
    /// nouveau ; tout ou rien, et l'ancienne remise si le programme ne se pose pas.
    #[test]
    fn la_fenetre_suit_le_programme_de_github() {
        let d = dossier("essai-sa-fenetre-github");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        let remettre = || {
            std::fs::write(&cible, b"ancien programme").unwrap();
            std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        };
        let inchange = || {
            std::fs::read(&cible).unwrap() == b"ancien programme"
                && std::fs::read(&fenetre).unwrap() == b"ancienne fenetre"
        };
        let appels = std::cell::Cell::new(0);
        // La bonne fenêtre : les deux remplacés.
        remettre();
        let mut recevoir = || -> Result<Vec<u8>, String> {
            appels.set(appels.get() + 1);
            Ok(neuve.clone())
        };
        installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        assert!(rien_a_cote(&d));
        // Une autre fenêtre que celle gravée, ou aucune reçue : rien n'est remplacé.
        remettre();
        let mut autre = || -> Result<Vec<u8>, String> { Ok(b"fenetre plantee".to_vec()) };
        assert!(installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &mut autre).is_err());
        assert!(inchange());
        let mut panne = || -> Result<Vec<u8>, String> { Err("téléchargement interrompu".into()) };
        assert!(installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &mut panne).is_err());
        assert!(inchange());
        // Le programme ne se pose pas : l'ancienne fenêtre est remise.
        assert!(installer_avec_sa_fenetre(&nouveau, &cible, V, ESSAI_RATE, &mut recevoir).is_err());
        assert!(inchange());
        assert!(rien_a_cote(&d));
        // Un programme sans marque : refusé sans rien télécharger. Un qui ne lance aucune fenêtre : posé seul.
        let avant = appels.get();
        assert!(installer_avec_sa_fenetre(&programme(None), &cible, V, SANS_ESSAI, &mut recevoir).is_err());
        assert!(inchange());
        let sans_fenetre = programme(Some(&[&marque_d_essai(&[0; 32])[..17], b"AUCUNE;"].concat()));
        installer_avec_sa_fenetre(&sans_fenetre, &cible, V, SANS_ESSAI, &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), sans_fenetre);
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"ancienne fenetre");
        // Pas de fenêtre à côté : le programme seul, rien n'est téléchargé.
        std::fs::remove_file(&fenetre).unwrap();
        installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        assert_eq!(appels.get(), avant);
        // Posée sous le nom de la page de la version : c'est elle qui est remplacée.
        let page = d.join(lancer_fenetre::NOM_PAGE);
        std::fs::write(&page, b"ancienne fenetre").unwrap();
        installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&page).unwrap(), neuve);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La clé : la fenêtre posée à côté de son programme suit la copie si c'est la sienne ; sinon la copie se fait
    /// sans elle. Un programme qui ne se pose pas ne laisse pas une fenêtre neuve derrière lui.
    #[test]
    fn la_fenetre_de_la_cle_suit_la_copie() {
        let d = dossier("essai-sa-fenetre-cle");
        let source = d.join("cle").join(NOM);
        let cible = d.join("bin").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        std::fs::write(&source, lancant(&neuve)).unwrap();
        std::fs::write(pour(&source).unwrap(), &neuve).unwrap();
        let fenetre = pour(&cible).unwrap();
        // Rien ici : le programme et sa fenêtre posés. Mais pas si le programme ne démarre pas.
        assert!(super::super::poser_copie_dans(&source, &cible, ESSAI_RATE).is_err());
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        super::super::poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // La même copie, sa fenêtre effacée : remise.
        std::fs::remove_file(&fenetre).unwrap();
        super::super::poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // Une fenêtre changée sur la clé : la copie de même version garde la sienne, jamais celle de la clé.
        std::fs::write(pour(&source).unwrap(), b"fenetre plantee").unwrap();
        std::fs::remove_file(&fenetre).unwrap();
        super::super::poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        // Ni pour remplacer une copie plus ancienne : le programme est posé, sans elle.
        std::fs::write(
            &cible,
            [b"prog ".as_slice(), &super::super::entete(), b"0.95.0+1; "].concat(),
        )
        .unwrap();
        super::super::poser_copie_dans(&source, &cible, SANS_ESSAI).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        assert!(rien_a_cote(&d.join("bin")));
        let _ = std::fs::remove_dir_all(&d);
    }
}
