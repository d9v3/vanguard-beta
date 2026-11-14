//! La fenêtre (`vanguard-fenetre`) d'un programme que la mise à jour remplace : elle le suit, vérifiée contre
//! l'empreinte gravée dans le nouveau programme (`demarrage::empreinte_fenetre`), lui-même déjà vérifié (signature,
//! taille et empreinte de GitHub, ou la version de la clé). La fenêtre d'abord, puis le programme ; si le programme
//! ne se pose pas, l'ancienne fenêtre est remise. Même si ce retour échouait, rien de dangereux : un programme ne
//! lance jamais une fenêtre dont l'empreinte n'est pas la sienne (le menu à la place).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::TAILLE_MAX as TAILLE_PROGRAMME;
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
///
/// `vue` : la fenêtre que l'aperçu a montrée à côté de `cible` (C-7, relecture 0.96). Apparue, partie ou changée
/// depuis, rien n'est remplacé, le programme non plus : jamais une fenêtre remplacée sans avoir été montrée.
pub(super) fn installer_avec_sa_fenetre(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    essai: Essai,
    vue: &Vue,
    recevoir: &mut dyn FnMut() -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    vue.dite(a_cote(cible).as_deref())?;
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
    // Le téléchargement a pris du temps : une fenêtre a pu apparaître sous un autre nom que le lancement cherche.
    vue.dite(a_cote(cible).as_deref())?;
    installer_avec(octets, cible, attendue, essai, &fenetre, &chemin, vue)
}

/// La fenêtre telle que l'aperçu (ou la question du terminal) l'a montrée : le chemin que la mise à jour remplacera,
/// s'il y en a un, et ce qui y était (C-7, relecture 0.96). La pose la compare à ce qui y est maintenant ; sinon une
/// fenêtre apparue pendant le téléchargement était remplacée sans avoir été montrée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Vue {
    chemin: Option<PathBuf>,
    etat: Montree,
}

/// Ce qui était au chemin montré : rien, un fichier (son empreinte SHA-256), ou quelque chose d'illisible.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Montree {
    Absente,
    Empreinte([u8; 32]),
    Illisible,
}

impl Montree {
    fn de(avant: &Avant) -> Montree {
        match avant {
            Avant::Absente => Montree::Absente,
            Avant::Lue(o) => Montree::Empreinte(Sha256::digest(o).into()),
            Avant::Illisible => Montree::Illisible,
        }
    }
}

impl Vue {
    /// La fenêtre montrée à `chemin` (`None` : aucune ne sera touchée), relue maintenant.
    pub(super) fn de(chemin: Option<PathBuf>) -> Vue {
        let etat = chemin
            .as_deref()
            .map_or(Montree::Absente, |c| Montree::de(&Avant::de(c, TAILLE_MAX)));
        Vue { chemin, etat }
    }

    /// La fenêtre que la pose toucherait est-elle encore à ce chemin montré (ou aucune, si aucune n'a été montrée) ?
    pub(super) fn dite(&self, maintenant: Option<&Path>) -> Result<(), String> {
        if self.chemin.as_deref() == maintenant {
            Ok(())
        } else {
            Err(changee_depuis_l_apercu())
        }
    }

    /// Ce qui est à `chemin` juste avant la pose (`avant`) est-il ce qui a été montré ?
    fn meme_etat(&self, chemin: &Path, avant: &Avant) -> Result<(), String> {
        self.dite(Some(chemin))?;
        if self.etat == Montree::de(avant) {
            Ok(())
        } else {
            Err(changee_depuis_l_apercu())
        }
    }
}

fn changee_depuis_l_apercu() -> String {
    tr!(
        "la fenêtre à côté de ce programme a changé depuis ce qui a été montré (apparue, partie ou modifiée) : rien n'est remplacé ; relancez la mise à jour pour la voir",
        "the window next to this program changed since what was shown (appeared, gone or modified): nothing is replaced; run the update again to see it"
    )
    .into()
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

/// La fenêtre posée à `chemin` est-elle, relue maintenant, celle que grave `programme` ? Ce que dit la ligne de la
/// fenêtre après une mise à jour : jamais « à jour » sans l'avoir relue.
pub(super) fn posee_juste(programme: &[u8], chemin: &Path) -> Result<(), String> {
    juste(programme, &lire_octets(chemin, TAILLE_MAX)?)
}

/// Le reste d'une mise à jour faite pendant que la fenêtre de la copie `cible` tournait (Windows) : effacé. Encore
/// ouvert, il reste, et partira la fois suivante.
pub(super) fn effacer_l_ancienne(cible: &Path) {
    if let Some(nom) = pour(cible).and_then(|f| f.file_name().map(std::ffi::OsStr::to_os_string)) {
        let mut ancien = nom;
        ancien.push(".ancien");
        let _ = std::fs::remove_file(cible.with_file_name(ancien));
    }
}

/// Ce qui était à `chemin` avant que la nouvelle fenêtre y soit posée, pour l'y remettre.
enum Avant {
    Absente,
    Lue(Vec<u8>),
    /// Là, mais illisible (droits, fichier spécial, démesurée) : elle ne pourra pas être remise.
    Illisible,
}

impl Avant {
    /// Ce qui est à `chemin` maintenant (au plus `max` octets lus).
    fn de(chemin: &Path, max: u64) -> Avant {
        match lire_octets(chemin, max) {
            Ok(o) => Avant::Lue(o),
            Err(_) if std::fs::symlink_metadata(chemin).is_err() => Avant::Absente,
            Err(_) => Avant::Illisible,
        }
    }

    /// `chemin` est-il encore exactement ce qu'il était ? Illisible avant : on ne peut pas le dire, donc non.
    fn toujours_la(&self, chemin: &Path, max: u64) -> bool {
        match self {
            Avant::Absente => std::fs::symlink_metadata(chemin).is_err(),
            Avant::Lue(o) => lire_octets(chemin, max).is_ok_and(|l| l == *o),
            Avant::Illisible => false,
        }
    }
}

/// `octets` à la place de `cible`, `fenetre` posée à `chemin` d'abord, revérifiée ici contre l'empreinte gravée dans
/// `octets` (le seul endroit où cela se juge). Si le programme ne se pose pas, ce qui était à `chemin` y revient.
/// Tout ou rien : une fenêtre qui ne se pose pas arrête aussi le programme (GitHub, où l'aperçu les a montrés ensemble).
pub(super) fn installer_avec(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    essai: Essai,
    fenetre: &[u8],
    chemin: &Path,
    vue: &Vue,
) -> Result<(), String> {
    installer_avec_repli(octets, cible, attendue, essai, fenetre, chemin, Some(vue)).map(|_| ())
}

/// `installer_avec` pour la copie depuis la clé (C-4, relecture 0.96) : une fenêtre qui ne peut pas être posée (un
/// dossier à son nom…) n'arrête pas le programme, posé seul ; la raison est rendue pour être dite. La fenêtre d'avant
/// reste à côté de lui, refusée par l'empreinte qu'il grave : le menu.
pub(super) fn installer_avec_sinon_seul(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    essai: Essai,
    fenetre: &[u8],
    chemin: &Path,
) -> Result<Option<String>, String> {
    installer_avec_repli(octets, cible, attendue, essai, fenetre, chemin, None)
}

fn installer_avec_repli(
    octets: &[u8],
    cible: &Path,
    attendue: Version,
    essai: Essai,
    fenetre: &[u8],
    chemin: &Path,
    vue: Option<&Vue>,
) -> Result<Option<String>, String> {
    juste(octets, fenetre)?;
    let avant = Avant::de(chemin, TAILLE_MAX);
    // Avec un aperçu (`vue`) : ce qui est là doit être ce qu'il a montré, et tout ou rien. Sans (la copie depuis la
    // clé, C-4) : une fenêtre qui ne se pose pas laisse le programme se poser seul.
    let seul_sinon = match vue {
        Some(v) => {
            v.meme_etat(chemin, &avant)?;
            false
        }
        None => true,
    };
    // Le programme d'avant, relu après un échec (C-2) : l'ancienne fenêtre ne revient qu'à côté de lui.
    let programme_avant = Avant::de(cible, TAILLE_PROGRAMME);
    let changee = !matches!(&avant, Avant::Lue(o) if o == fenetre);
    if changee {
        match poser(fenetre, chemin) {
            Ok(()) => {}
            Err(e) if seul_sinon => {
                installer(octets, cible, attendue, essai)?;
                return Ok(Some(crate::trf!(
                    "la fenêtre n'a pas pu être posée à côté de la copie ({}) : le programme est posé seul, le raccourci ouvrira le menu",
                    "the window could not be placed next to the copy ({}): the program is placed alone, the shortcut will open the menu",
                    e
                )));
            }
            Err(e) => return Err(e),
        }
    }
    installer(octets, cible, attendue, essai).map(|()| None).map_err(|e| {
        if changee && !programme_avant.toujours_la(cible, TAILLE_PROGRAMME) {
            return format!(
                "{e}\n    {}",
                tr!(
                    "le programme n'est plus celui d'avant (changé pendant la mise à jour par un autre programme, ou illisible) : l'ancienne fenêtre n'est pas remise à côté de lui ; relancez la mise à jour",
                    "the program is no longer the previous one (changed during the update by another program, or unreadable): the old window is not put back next to it; run the update again"
                )
            );
        }
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
    poser_avec(octets, chemin, |_| ())
}

/// `poser`, avec ce qui se passe juste avant le renommage (`avant_renommage`, le chemin de la copie provisoire) : rien
/// en vrai ; un autre programme du compte, dans les essais.
///
/// La copie provisoire est tenue par son descripteur du début à la fin (C-1, relecture 0.96 ; la méthode de G-2 pour
/// le programme) : par son seul nom, un programme du compte pouvait l'échanger entre la relecture et le renommage, et
/// « fait » était dit sur une autre fenêtre. Relue par le descripteur ; après le renommage, la fenêtre posée doit
/// être ce même fichier, avec ces mêmes octets.
fn poser_avec(octets: &[u8], chemin: &Path, avant_renommage: impl FnOnce(&Path)) -> Result<(), String> {
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| tr!("chemin sans nom de fichier", "path without a file name").to_string())?;
    let provisoire = chemin.with_file_name(format!("{nom}.nouveau"));
    let posee = (|| -> Result<(), String> {
        let _ = std::fs::remove_file(&provisoire);
        let f = ecrire_provisoire(&provisoire, octets)?;
        if !meme_contenu(&f, octets)? {
            return Err(tr!("la copie relue ne correspond pas", "the copy read back does not match").into());
        }
        avant_renommage(&provisoire);
        mettre_en_place_sous(&provisoire, chemin, &chemin.with_file_name(format!("{nom}.ancien")))
            .map_err(|e| e.to_string())?;
        verifier_posee(&f, chemin, octets)
    })();
    if posee.is_err() {
        let _ = std::fs::remove_file(&provisoire);
    }
    posee
}

/// La copie provisoire créée neuve (O_EXCL : un lien posé à ce nom n'est jamais suivi, l'écriture échoue plutôt),
/// écrite, mise sur le disque, ses droits donnés par le descripteur. Sous Linux, rouverte en lecture seule par son
/// descripteur (`/proc/self/fd`, le même fichier même si le nom a changé) et le descripteur d'écriture fermé. Sous
/// Windows, rouverte en lecture par son nom, l'écriture refusée aux autres tant qu'elle est tenue (FILE_SHARE_READ |
/// FILE_SHARE_DELETE : sans le partage de suppression, le renommage échouerait) ; ce qui est ouvert est relu ensuite.
fn ecrire_provisoire(provisoire: &Path, octets: &[u8]) -> Result<std::fs::File, String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(provisoire)
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
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let lecture = std::fs::File::open(format!("/proc/self/fd/{}", f.as_raw_fd())).map_err(|e| {
            crate::trf!(
                "copie provisoire pas rouverte par son descripteur (/proc) : {}",
                "temporary copy not reopened through its descriptor (/proc): {}",
                e
            )
        })?;
        drop(f);
        Ok(lecture)
    }
    #[cfg(windows)]
    {
        drop(f);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1 | 4);
        options.open(provisoire).map_err(|e| e.to_string())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    Ok(f)
}

/// Le fichier ouvert `f` contient-il exactement `octets` ? Relu depuis le début, jamais plus d'un octet de trop.
fn meme_contenu(mut f: &std::fs::File, octets: &[u8]) -> Result<bool, String> {
    use std::io::{Read, Seek};
    f.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut lu = Vec::with_capacity(octets.len());
    let borne = u64::try_from(octets.len()).unwrap_or(u64::MAX).saturating_add(1);
    f.take(borne).read_to_end(&mut lu).map_err(|e| e.to_string())?;
    Ok(lu == octets)
}

/// Après le renommage : la fenêtre posée à `chemin` est-elle la copie écrite (`f`), avec les octets reçus ? Sous Unix,
/// ouverte sans suivre de lien, le même fichier (appareil et inode) que `f`, puis relue. Sous Windows, relue par une
/// poignée qui refuse l'écriture et la suppression aux autres le temps de la lecture (l'identité du fichier n'y est
/// pas comparée ; les octets, eux, le sont). Sinon, un échec qui le dit : jamais « fait » sur une autre fenêtre (que
/// `vanguard`, de toute façon, ne lancera pas : son empreinte n'est pas la gravée).
fn verifier_posee(f: &std::fs::File, chemin: &Path, octets: &[u8]) -> Result<(), String> {
    let changee = || -> String {
        tr!(
            "la fenêtre posée n'est pas celle qui a été reçue (changée pendant la mise à jour par un autre programme) : la mise à jour n'est pas faite, relancez-la",
            "the installed window is not the one that was received (changed during the update by another program): the update is not done, run it again"
        )
        .into()
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    // FILE_SHARE_READ seul.
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1);
    let posee = options.open(chemin).map_err(|_| changee())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (a, b) = (
            f.metadata().map_err(|e| e.to_string())?,
            posee.metadata().map_err(|e| e.to_string())?,
        );
        if !b.is_file() || a.dev() != b.dev() || a.ino() != b.ino() {
            return Err(changee());
        }
    }
    #[cfg(not(unix))]
    let _ = f;
    if meme_contenu(&posee, octets)? {
        Ok(())
    } else {
        Err(changee())
    }
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

    /// La fenêtre à côté de `cible` telle qu'un aperçu la montrerait maintenant.
    fn montree(cible: &Path) -> Vue {
        Vue::de(a_cote(cible))
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
        installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &montree(&cible), &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        assert!(rien_a_cote(&d));
        // Une autre fenêtre que celle gravée, ou aucune reçue : rien n'est remplacé.
        remettre();
        let mut autre = || -> Result<Vec<u8>, String> { Ok(b"fenetre plantee".to_vec()) };
        assert!(installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &montree(&cible), &mut autre).is_err());
        assert!(inchange());
        let mut panne = || -> Result<Vec<u8>, String> { Err("téléchargement interrompu".into()) };
        assert!(installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &montree(&cible), &mut panne).is_err());
        assert!(inchange());
        // Le programme ne se pose pas : l'ancienne fenêtre est remise.
        assert!(installer_avec_sa_fenetre(&nouveau, &cible, V, ESSAI_RATE, &montree(&cible), &mut recevoir).is_err());
        assert!(inchange());
        assert!(rien_a_cote(&d));
        // Un programme sans marque : refusé sans rien télécharger. Un qui ne lance aucune fenêtre : posé seul.
        let avant = appels.get();
        assert!(
            installer_avec_sa_fenetre(&programme(None), &cible, V, SANS_ESSAI, &montree(&cible), &mut recevoir)
                .is_err()
        );
        assert!(inchange());
        let sans_fenetre = programme(Some(&[&marque_d_essai(&[0; 32])[..17], b"AUCUNE;"].concat()));
        installer_avec_sa_fenetre(&sans_fenetre, &cible, V, SANS_ESSAI, &montree(&cible), &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), sans_fenetre);
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"ancienne fenetre");
        // Pas de fenêtre à côté : le programme seul, rien n'est téléchargé.
        std::fs::remove_file(&fenetre).unwrap();
        installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &montree(&cible), &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        assert_eq!(appels.get(), avant);
        // Posée sous le nom de la page de la version : c'est elle qui est remplacée.
        let page = d.join(lancer_fenetre::NOM_PAGE);
        std::fs::write(&page, b"ancienne fenetre").unwrap();
        installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &montree(&cible), &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&page).unwrap(), neuve);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-1 (relecture 0.96) : la fenêtre provisoire était relue puis renommée par son NOM ; un programme du compte
    /// qui l'échangeait entre les deux faisait poser sa fausse fenêtre, et la mise à jour disait « fait ». Tenue par
    /// son descripteur, la fenêtre posée doit être ce même fichier, avec ces octets : sinon un échec qui le dit.
    #[test]
    fn une_fenetre_provisoire_echangee_par_son_nom_n_est_jamais_dite_posee() {
        let d = dossier("essai-sa-fenetre-echange");
        let fenetre = pour(&d.join(NOM)).unwrap();
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        // Sous Windows, la provisoire tenue passe « en suppression » et son nom ne peut pas être réécrit : l'échange
        // échoue de lui-même. Sous Unix il réussit toujours, sinon l'essai ne prouverait rien.
        let substituee = std::cell::Cell::new(false);
        let echanger = |provisoire: &Path| {
            let fait = std::fs::remove_file(provisoire)
                .and_then(|()| std::fs::write(provisoire, b"FAUSSE FENETRE"))
                .is_ok();
            substituee.set(fait);
        };
        let r = poser_avec(b"fenetre 0.96", &fenetre, echanger);
        assert!(substituee.get() || cfg!(windows), "l'échange n'a pas eu lieu");
        if substituee.get() {
            assert!(r.is_err(), "« fait » sur une fenêtre échangée : {r:?}");
        }
        if r.is_ok() {
            assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre 0.96");
        }
        // Sans échange : posée.
        poser_avec(b"fenetre 0.96", &fenetre, |_| ()).unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre 0.96");
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-2 (relecture 0.96) : un échec après que le fichier du programme a changé remettait l'ancienne fenêtre à
    /// côté d'un programme inconnu, et disait seulement « pas faite ». Le programme d'avant est relu : changé, rien
    /// n'est remis, et c'est dit.
    #[test]
    fn un_programme_change_pendant_l_echec_n_est_pas_apparie_a_l_ancienne_fenetre() {
        const CHANGE_PUIS_RATE: Essai = |provisoire, _| {
            // Sous Linux, l'essai reçoit /proc/self/fd/N (lot-095) : son vrai chemin donne le dossier du programme.
            let vrai = std::fs::read_link(provisoire).unwrap_or_else(|_| provisoire.to_path_buf());
            std::fs::write(vrai.with_file_name(NOM), b"programme inconnu").unwrap();
            Err("ne démarre pas".into())
        };
        let d = dossier("essai-sa-fenetre-change");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        std::fs::write(&cible, b"ancien programme").unwrap();
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        let mut recevoir = || -> Result<Vec<u8>, String> { Ok(neuve.clone()) };
        let r = installer_avec_sa_fenetre(
            &lancant(&neuve),
            &cible,
            V,
            CHANGE_PUIS_RATE,
            &montree(&cible),
            &mut recevoir,
        );
        let e = r.expect_err("un échec");
        assert!(
            e.contains("n'est plus celui d'avant") || e.contains("no longer the previous"),
            "{e}"
        );
        assert_ne!(
            std::fs::read(&fenetre).unwrap(),
            b"ancienne fenetre",
            "remise à côté d'un inconnu"
        );
        assert!(rien_a_cote(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-7 (relecture 0.96) : la présence de la fenêtre était recalculée à la pose ; une fenêtre apparue pendant le
    /// téléchargement était remplacée sans avoir été montrée. Ce qui se pose est ce qui a été montré, sinon rien, le
    /// programme non plus, et c'est dit.
    #[test]
    fn une_fenetre_changee_depuis_l_apercu_n_est_jamais_remplacee() {
        let d = dossier("essai-sa-fenetre-apercu");
        let cible = d.join(NOM);
        let fenetre = pour(&cible).unwrap();
        let page = d.join(lancer_fenetre::NOM_PAGE);
        let neuve = b"fenetre 0.96".to_vec();
        let nouveau = lancant(&neuve);
        let dit = |r: Result<(), String>| {
            let e = r.expect_err("posé sans avoir été montré");
            assert!(
                e.contains("depuis ce qui a été montré") || e.contains("since what was shown"),
                "{e}"
            );
        };
        let programme_inchange = || std::fs::read(&cible).unwrap() == b"ancien programme";
        std::fs::write(&cible, b"ancien programme").unwrap();
        // GitHub. Aucune fenêtre montrée, une apparaît pendant le téléchargement du programme : rien, rien téléchargé.
        let appels = std::cell::Cell::new(0);
        let mut recevoir = || -> Result<Vec<u8>, String> {
            appels.set(appels.get() + 1);
            Ok(neuve.clone())
        };
        let aucune = montree(&cible);
        std::fs::write(&fenetre, b"fenetre apparue").unwrap();
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            SANS_ESSAI,
            &aucune,
            &mut recevoir,
        ));
        assert!(programme_inchange());
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre apparue");
        assert_eq!(appels.get(), 0);
        // Montrée, puis changée pendant le téléchargement de la nouvelle fenêtre.
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        let vue = montree(&cible);
        let mut changer = || -> Result<Vec<u8>, String> {
            std::fs::write(&fenetre, b"fenetre changee").unwrap();
            Ok(neuve.clone())
        };
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            SANS_ESSAI,
            &vue,
            &mut changer,
        ));
        assert!(programme_inchange());
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre changee");
        // Montrée, puis partie.
        let vue = montree(&cible);
        std::fs::remove_file(&fenetre).unwrap();
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            SANS_ESSAI,
            &vue,
            &mut recevoir,
        ));
        assert!(programme_inchange());
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        // Montrée sous le nom de la page ; une autre apparaît sous le premier nom pendant le téléchargement.
        std::fs::write(&page, b"ancienne fenetre").unwrap();
        let vue = montree(&cible);
        let mut apparait = || -> Result<Vec<u8>, String> {
            std::fs::write(&fenetre, b"fenetre apparue").unwrap();
            Ok(neuve.clone())
        };
        dit(installer_avec_sa_fenetre(
            &nouveau,
            &cible,
            V,
            SANS_ESSAI,
            &vue,
            &mut apparait,
        ));
        assert!(programme_inchange());
        assert_eq!(std::fs::read(&page).unwrap(), b"ancienne fenetre");
        assert_eq!(std::fs::read(&fenetre).unwrap(), b"fenetre apparue");
        std::fs::remove_file(&page).unwrap();
        // Rien n'a changé depuis l'aperçu : les deux posés.
        std::fs::write(&fenetre, b"ancienne fenetre").unwrap();
        let vue = montree(&cible);
        installer_avec_sa_fenetre(&nouveau, &cible, V, SANS_ESSAI, &vue, &mut recevoir).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), nouveau);
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // La clé (`installer_avec`) : la fenêtre d'ici changée, ou apparue, depuis la question.
        for (avant, apres) in [
            (Some(b"ancienne fenetre"), b"fenetre changee"),
            (None, b"fenetre apparue"),
        ] {
            std::fs::write(&cible, b"ancien programme").unwrap();
            match avant {
                Some(o) => std::fs::write(&fenetre, o).unwrap(),
                None => std::fs::remove_file(&fenetre).unwrap(),
            }
            let vue = Vue::de(Some(fenetre.clone()));
            std::fs::write(&fenetre, apres).unwrap();
            dit(installer_avec(&nouveau, &cible, V, SANS_ESSAI, &neuve, &fenetre, &vue));
            assert!(programme_inchange());
            assert_eq!(std::fs::read(&fenetre).unwrap(), apres);
        }
        assert!(rien_a_cote(&d));
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
        assert!(
            super::super::poser_copie_dans(
                &source,
                &cible,
                crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
                &super::super::tests::inconnue(),
                ESSAI_RATE
            )
            .is_err()
        );
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // La même copie, sa fenêtre effacée : remise.
        std::fs::remove_file(&fenetre).unwrap();
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&fenetre).unwrap(), neuve);
        // Une fenêtre changée sur la clé : la copie de même version garde la sienne, jamais celle de la clé.
        std::fs::write(pour(&source).unwrap(), b"fenetre plantee").unwrap();
        std::fs::remove_file(&fenetre).unwrap();
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            SANS_ESSAI,
        )
        .unwrap();
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        // Ni pour remplacer une copie plus ancienne : le programme est posé, sans elle.
        std::fs::write(
            &cible,
            [b"prog ".as_slice(), &super::super::entete(), b"0.95.0+1; "].concat(),
        )
        .unwrap();
        super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(std::fs::symlink_metadata(&fenetre).is_err());
        assert!(rien_a_cote(&d.join("bin")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La fenêtre non posée est dite. Sous Windows, un dossier à son nom ne bloque pas : `mettre_en_place_sous` le
    /// met de côté (`.ancien`, comme un programme en marche) et la fenêtre est posée ; elle doit alors l'être vraiment.
    fn dite_ou_posee_sous_windows(note: Option<String>, fenetre: &Path, neuve: &[u8]) -> bool {
        match note {
            Some(n) => n.contains("fenêtre") || n.contains("window"),
            None => cfg!(windows) && std::fs::read(fenetre).is_ok_and(|l| l == neuve),
        }
    }

    /// C-4 (relecture 0.96) : une chose impossible à remplacer au nom de la fenêtre (un dossier) bloquait la copie
    /// du PROGRAMME depuis la clé. Le programme est posé seul, et c'est dit ; la fenêtre d'avant reste, refusée par
    /// l'empreinte du nouveau programme (le menu).
    #[test]
    fn une_fenetre_impossible_a_poser_ne_bloque_pas_la_copie_de_la_cle() {
        let d = dossier("essai-sa-fenetre-cle-bloquee");
        let source = d.join("cle").join(NOM);
        let cible = d.join("bin").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(cible.parent().unwrap()).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        std::fs::write(&source, lancant(&neuve)).unwrap();
        std::fs::write(pour(&source).unwrap(), &neuve).unwrap();
        std::fs::write(
            &cible,
            [b"prog ".as_slice(), &super::super::entete(), b"0.95.0+1; "].concat(),
        )
        .unwrap();
        let fenetre = pour(&cible).unwrap();
        std::fs::create_dir(&fenetre).unwrap();
        let note = super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            SANS_ESSAI,
        )
        .unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(dite_ou_posee_sous_windows(note, &fenetre, &neuve), "rien n'est dit");
        // Un programme qui ne démarre pas : rien n'est posé, la fenêtre non plus.
        std::fs::write(
            &cible,
            [b"prog ".as_slice(), &super::super::entete(), b"0.95.0+1; "].concat(),
        )
        .unwrap();
        assert!(
            super::super::poser_copie_dans(
                &source,
                &cible,
                crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
                &super::super::tests::inconnue(),
                ESSAI_RATE
            )
            .is_err()
        );
        assert_ne!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        assert!(rien_a_cote(&d.join("bin")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C-5 (relecture 0.96) : la copie de même version dont la fenêtre ne peut pas être posée (ici, un dossier à son
    /// nom) répondait « fait » sans un mot. La copie reste faite, mais la raison est rendue pour être dite.
    #[test]
    fn une_fenetre_impossible_a_poser_a_cote_de_la_meme_copie_est_dite() {
        let d = dossier("essai-sa-fenetre-cle-dite");
        let source = d.join("cle").join(NOM);
        let cible = d.join("bin").join(NOM);
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        let neuve = b"fenetre 0.96".to_vec();
        std::fs::write(&source, lancant(&neuve)).unwrap();
        std::fs::write(pour(&source).unwrap(), &neuve).unwrap();
        assert_eq!(
            super::super::poser_copie_dans(
                &source,
                &cible,
                crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
                &super::super::tests::inconnue(),
                SANS_ESSAI
            )
            .unwrap(),
            None
        );
        let fenetre = pour(&cible).unwrap();
        std::fs::remove_file(&fenetre).unwrap();
        std::fs::create_dir(&fenetre).unwrap();
        let note = super::super::poser_copie_dans(
            &source,
            &cible,
            crate::programmes_poses::empreinte_de(&source).ok().as_deref(),
            &super::super::tests::inconnue(),
            SANS_ESSAI,
        )
        .unwrap();
        assert!(dite_ou_posee_sous_windows(note, &fenetre, &neuve), "rien n'est dit");
        assert_eq!(std::fs::read(&cible).unwrap(), std::fs::read(&source).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }
}
