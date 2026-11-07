//! Les ordres du garde, faits par l'assistant root (le mot de passe est l'accord) : poser, mettre à jour, régler,
//! mettre en pause, permettre une empreinte, retirer. Chaque ordre est validé par le parent (`ordres_ligne`), puis
//! rejugé ici (`juger_pose`) par l'élevé.
//!
//! La pose copie `/proc/self/exe` de l'assistant (l'image qui tourne déjà en root, à l'abri d'un remplacement du
//! fichier du compte) en root:root 0755 dans /opt/vanguard/garde : le garde ne lance jamais une copie que le
//! compte peut écrire. L'unité est activée par le bus système (le client maison), systemctl en secours.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::machine::gestes_unix::ActionUnite;
use crate::modele::Echec;
use crate::protection::blocage::ordres::Ordre;
use crate::protection::blocage::ordres::Resultat;
use crate::{tr, trf};

use super::{
    DOSSIER_ETAT, DOSSIER_PROGRAMME, DOSSIER_REGLAGES, FICHIER_UNITE, PERMISES_MAX, PROGRAMME, REGLAGES,
    REGLAGES_TAILLE_MAX, Reglages, UNITE, VANGUARD_MAX, VERSION_REGLAGES,
};

/// Le programme copié, au plus (Vanguard fait ~30 Mo).
const PROGRAMME_TAILLE_MAX: u64 = 512 << 20;

/// Rejuge une pose dans l'élevé : le compte existe et n'est pas root, son dossier des listes est à lui, sous son
/// dossier personnel, n'est pas un lien ; et le Vanguard qui demande tourne pour ce compte. `Some(raison)` : refusée.
pub(crate) fn juger_pose(compte: u32, dossier: &str, demandeur: Option<u32>) -> Option<String> {
    juger_pose_avec(
        compte,
        dossier,
        demandeur,
        crate::socle::personnel::dossier_personnel_de,
    )
}

fn juger_pose_avec(
    compte: u32,
    dossier: &str,
    demandeur: Option<u32>,
    personnel: impl Fn(u32) -> Option<std::path::PathBuf>,
) -> Option<String> {
    if compte == 0 {
        return Some(
            tr!(
                "le garde ne lit pas les listes de root",
                "the guard does not read root's lists"
            )
            .into(),
        );
    }
    let Some(maison) = personnel(compte) else {
        return Some(trf!("compte {} inconnu", "unknown account {}", compte));
    };
    let chemin = Path::new(dossier);
    if !chemin.is_absolute() || dossier.contains("/../") || dossier.ends_with("/..") || !chemin.starts_with(&maison) {
        return Some(trf!(
            "{} n'est pas dans le dossier personnel du compte",
            "{} is not in the account's home folder",
            crate::ui::affichable(dossier)
        ));
    }
    match std::fs::symlink_metadata(chemin) {
        Ok(m) if m.is_dir() && m.uid() == compte => {}
        Ok(_) => {
            return Some(trf!(
                "{} n'est pas un dossier du compte",
                "{} is not a folder of the account",
                crate::ui::affichable(dossier)
            ));
        }
        Err(e) => return Some(format!("{}: {e}", crate::ui::affichable(dossier))),
    }
    if let Some(pid) = demandeur {
        let reel = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| uid_reel(&s));
        if reel != Some(compte) {
            return Some(
                tr!(
                    "le garde se pose pour le compte qui le demande seulement",
                    "the guard is set up only for the account that asks"
                )
                .into(),
            );
        }
    }
    None
}

/// L'uid réel d'un /proc/<pid>/status.
fn uid_reel(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Fait un ordre du garde, en root.
pub(crate) fn faire_ordre(o: &Ordre) -> Resultat {
    if cfg!(test) {
        return Resultat::echec("aucune action réelle sous les essais");
    }
    if crate::socle::euid() != 0 {
        return Resultat::echec(tr!(
            "le garde se règle en administrateur seulement",
            "the guard is managed as administrator only"
        ));
    }
    let fait = match o {
        Ordre::GardePoser { compte, dossier } => poser(*compte, dossier),
        Ordre::GardeMettreAJour => mettre_a_jour(),
        Ordre::GardeRegler { refus } => regler(|r| {
            r.refus = *refus;
            Ok(())
        }),
        Ordre::GardePause { secondes } => regler(|r| {
            r.pause_jusqu_a = (*secondes > 0).then(|| super::maintenant().saturating_add(u64::from(*secondes)));
            Ok(())
        }),
        Ordre::GardePermettre { sha256 } => regler(|r| {
            let e = crate::protection::empreintes::hex(sha256);
            if !r.permises.contains(&e) {
                if r.permises.len() >= PERMISES_MAX {
                    return Err(Echec::refuse(
                        "garde/poser",
                        tr!(
                            "trop d'empreintes permises : retirez-en d'abord",
                            "too many allowed hashes: remove some first"
                        ),
                    ));
                }
                r.permises.push(e);
            }
            Ok(())
        }),
        Ordre::GardeRetirer => retirer(),
        _ => Err(Echec::refuse("garde/poser", "ordre étranger au garde")),
    };
    fait.map_or_else(
        |e| Resultat::echec(String::from(e)),
        |note| note.map_or_else(Resultat::ok, Resultat::ok_note),
    )
}

/// Les réglages en place, s'ils se lisent.
fn reglages_en_place() -> Option<Reglages> {
    let octets = crate::socle::lire_ordinaire(Path::new(REGLAGES), REGLAGES_TAILLE_MAX).ok()?;
    Reglages::lire(std::str::from_utf8(&octets).ok()?)
}

/// Un dossier à root, créé au besoin en 0755 : jamais un lien, jamais écrit par un autre.
fn dossier_root(chemin: &Path) -> Result<(), Echec> {
    if let Some(parent) = chemin.parent()
        && parent != Path::new("/")
        && std::fs::symlink_metadata(parent).is_err()
    {
        dossier_root(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o755).create(chemin) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Echec::ecriture("garde/poser", &e).detail(chemin.display().to_string())),
    }
    let m = std::fs::symlink_metadata(chemin)
        .map_err(|e| Echec::io("garde/poser", &e).detail(chemin.display().to_string()))?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(Echec::refuse(
            "garde/poser",
            trf!(
                "{} n'est pas un dossier à root seul : rien n'est posé",
                "{} is not a root-only folder: nothing is set up",
                chemin.display()
            ),
        ));
    }
    Ok(())
}

/// Écrit `contenu` dans `chemin` d'un coup (fichier temporaire à côté, puis renommage), avec ces droits.
fn ecrire_root(chemin: &Path, contenu: &[u8], mode: u32) -> Result<(), Echec> {
    let temporaire = chemin.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&temporaire);
    let ecrit = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporaire)?;
        f.write_all(contenu)?;
        // Le masque de création a pu retirer des droits : ceux voulus, exactement.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        std::fs::rename(&temporaire, chemin)
    })();
    if ecrit.is_err() {
        let _ = std::fs::remove_file(&temporaire);
    }
    ecrit.map_err(|e| Echec::ecriture("garde/poser", &e).detail(chemin.display().to_string()))
}

/// Copie l'image de ce processus (l'assistant root) en PROGRAMME, root:root 0755 ; rend son SHA-256.
fn installer_programme() -> Result<String, Echec> {
    dossier_root(Path::new(DOSSIER_PROGRAMME))?;
    let mut source =
        std::fs::File::open("/proc/self/exe").map_err(|e| Echec::io("garde/poser", &e).detail("/proc/self/exe"))?;
    let mut octets = Vec::new();
    (&mut source)
        .take(PROGRAMME_TAILLE_MAX)
        .read_to_end(&mut octets)
        .map_err(|e| Echec::io("garde/poser", &e).detail("/proc/self/exe"))?;
    let empreinte = crate::protection::empreintes::sha256_de(octets.as_slice())
        .ok_or_else(|| Echec::echoue("garde/poser", "/proc/self/exe illisible"))?;
    ecrire_root(Path::new(PROGRAMME), &octets, 0o755)?;
    Ok(crate::protection::empreintes::hex(&empreinte))
}

/// Ajoute l'empreinte d'un programme posé à celles de Vanguard (les dernières seulement).
fn garder_empreinte(r: &mut Reglages, empreinte: String) {
    r.vanguard.retain(|e| *e != empreinte);
    r.vanguard.push(empreinte);
    while r.vanguard.len() > VANGUARD_MAX {
        r.vanguard.remove(0);
    }
}

fn ecrire_reglages(r: &Reglages) -> Result<(), Echec> {
    dossier_root(Path::new(DOSSIER_REGLAGES))?;
    let texte = serde_json::to_string_pretty(r).map_err(|e| Echec::echoue("garde/poser", e.to_string()))?;
    ecrire_root(Path::new(REGLAGES), texte.as_bytes(), 0o644)
}

fn poser(compte: u32, dossier: &str) -> Result<Option<String>, Echec> {
    if !crate::machine::linux::dbus::systeme::systemd_present() {
        return Err(Echec::refuse(
            "garde/poser",
            tr!(
                "systemd n'est pas le gestionnaire de ce système : le garde ne peut pas y être posé",
                "systemd is not this system's manager: the guard cannot be set up"
            ),
        ));
    }
    let deja = Path::new(FICHIER_UNITE).exists();
    let avant = reglages_en_place();
    let empreinte = installer_programme()?;
    // Une nouvelle pose garde le mode et les empreintes permises choisis avec le mot de passe ; jamais de pause.
    let mut r = Reglages {
        version: VERSION_REGLAGES,
        compte,
        listes: dossier.to_string(),
        refus: avant.as_ref().is_some_and(|a| a.refus),
        pause_jusqu_a: None,
        permises: avant.as_ref().map(|a| a.permises.clone()).unwrap_or_default(),
        vanguard: avant.map(|a| a.vanguard).unwrap_or_default(),
    };
    garder_empreinte(&mut r, empreinte);
    ecrire_reglages(&r)?;
    ecrire_root(Path::new(FICHIER_UNITE), super::unite::texte().as_bytes(), 0o644)?;
    agir(ActionUnite::Activer, &["enable", "--now"])?;
    if deja {
        agir(ActionUnite::Redemarrer, &["try-restart"])?;
    }
    Ok(None)
}

fn mettre_a_jour() -> Result<Option<String>, Echec> {
    let Some(mut r) = reglages_en_place().filter(|_| Path::new(FICHIER_UNITE).exists()) else {
        return Err(Echec::refuse(
            "garde/poser",
            tr!("le garde n'est pas posé", "the guard is not set up"),
        ));
    };
    let empreinte = installer_programme()?;
    garder_empreinte(&mut r, empreinte);
    ecrire_reglages(&r)?;
    ecrire_root(Path::new(FICHIER_UNITE), super::unite::texte().as_bytes(), 0o644)?;
    agir(ActionUnite::ActiverSansDemarrer, &["enable"])?;
    agir(ActionUnite::Redemarrer, &["try-restart"])?;
    Ok(None)
}

/// Change les réglages ; le garde les relit de lui-même (leur date change).
fn regler(changer: impl FnOnce(&mut Reglages) -> Result<(), Echec>) -> Result<Option<String>, Echec> {
    let Some(mut r) = reglages_en_place() else {
        return Err(Echec::refuse(
            "garde/poser",
            tr!("le garde n'est pas posé", "the guard is not set up"),
        ));
    };
    changer(&mut r)?;
    ecrire_reglages(&r)?;
    Ok(None)
}

fn retirer() -> Result<Option<String>, Echec> {
    let mut notes = Vec::new();
    if Path::new(FICHIER_UNITE).exists() {
        agir(ActionUnite::Desactiver, &["disable", "--now"])?;
    }
    for f in [FICHIER_UNITE, PROGRAMME, REGLAGES] {
        match std::fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => notes.push(format!("{f}: {e}")),
        }
    }
    if let Err(e) = recharger() {
        notes.push(e.to_string());
    }
    match std::fs::remove_dir_all(DOSSIER_ETAT) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => notes.push(format!("{DOSSIER_ETAT}: {e}")),
    }
    // Les dossiers de Vanguard, s'ils sont vides (remove_dir refuse un dossier qui ne l'est pas).
    for d in [
        DOSSIER_PROGRAMME,
        "/opt/vanguard",
        DOSSIER_REGLAGES,
        "/var/lib/vanguard",
        "/run/vanguard/garde",
        "/run/vanguard",
    ] {
        let _ = std::fs::remove_dir(d);
    }
    if notes.is_empty() {
        Ok(None)
    } else {
        Err(Echec::echoue("garde/poser", notes.join(" ; ")))
    }
}

/// systemctl, par son chemin absolu.
fn systemctl() -> Option<&'static str> {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|c| Path::new(c).exists())
}

fn lancer_systemctl(arguments: &[&str]) -> Result<(), Echec> {
    let programme = systemctl().ok_or_else(|| Echec::echoue("garde/poser", "systemctl introuvable"))?;
    let mut c = std::process::Command::new(programme);
    c.args(arguments);
    if arguments.first().is_some_and(|a| *a != "daemon-reload") {
        c.arg(UNITE);
    }
    match crate::commande::lancer(&mut c, 60) {
        Some(r) if r.code == Some(0) => Ok(()),
        Some(r) => Err(Echec::echoue(
            "garde/poser",
            format!("systemctl {}: {}", arguments.join(" "), r.erreurs.trim()),
        )),
        None => Err(Echec::echoue(
            "garde/poser",
            format!("systemctl {} : pas de réponse", arguments.join(" ")),
        )),
    }
}

/// Une action sur l'unité : par le bus système, systemctl en secours.
fn agir(action: ActionUnite, secours: &[&str]) -> Result<(), Echec> {
    use crate::machine::linux::dbus::systeme;
    let par_le_bus = systeme::bus_pour_agir().and_then(|mut bus| systeme::agir_sur_unite(&mut bus, action, UNITE));
    match par_le_bus {
        Ok(()) => Ok(()),
        Err(e) => lancer_systemctl(secours).map_err(|s| Echec::echoue("garde/poser", format!("{e} ; {s}"))),
    }
}

/// Fait oublier à systemd l'unité retirée.
fn recharger() -> Result<(), Echec> {
    lancer_systemctl(&["daemon-reload"])
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_reel_lu_dans_status() {
        assert_eq!(
            uid_reel("Name:\tvanguard\nUid:\t1000\t0\t0\t0\nGid:\t1000\n"),
            Some(1000)
        );
        assert_eq!(uid_reel("Name:\tx\n"), None);
        assert_eq!(uid_reel("Uid:\tabc\n"), None);
    }

    #[test]
    fn pose_rejugee_par_l_eleve() {
        use std::os::unix::fs::MetadataExt;
        let d = crate::essais::Jetable::nouveau("garde-pose");
        let moi = std::fs::metadata(&*d).unwrap().uid();
        let maison = d.to_path_buf();
        let listes = d.join("listes");
        std::fs::create_dir(&listes).unwrap();
        let personnel = |uid: u32| (uid == moi).then(|| maison.clone());
        let juger =
            |compte: u32, dossier: &str, demandeur: Option<u32>| juger_pose_avec(compte, dossier, demandeur, personnel);
        let l = listes.to_str().unwrap();
        assert_eq!(juger(moi, l, None), None);
        assert_eq!(juger(moi, l, Some(std::process::id())), None);
        // Root, un compte inconnu, hors du dossier personnel, un chemin qui remonte, un lien, un fichier, rien.
        assert!(juger(0, l, None).is_some());
        assert!(juger(moi.wrapping_add(1), l, None).is_some());
        assert!(juger(moi, "/tmp", None).is_some());
        assert!(juger(moi, &format!("{l}/../.."), None).is_some());
        assert!(juger(moi, "listes", None).is_some());
        let lien = d.join("lien");
        std::os::unix::fs::symlink(&listes, &lien).unwrap();
        assert!(juger(moi, lien.to_str().unwrap(), None).is_some());
        let fichier = d.join("fichier");
        std::fs::write(&fichier, "").unwrap();
        assert!(juger(moi, fichier.to_str().unwrap(), None).is_some());
        assert!(juger(moi, d.join("absent").to_str().unwrap(), None).is_some());
        // Un demandeur d'un autre compte (init, root) ou disparu.
        if moi != 0 {
            assert!(juger(moi, l, Some(1)).is_some());
        }
        assert!(juger(moi, l, Some(u32::MAX)).is_some());
    }

    #[test]
    fn aucun_ordre_n_agit_sous_les_essais() {
        for o in [
            Ordre::GardeRetirer,
            Ordre::GardeMettreAJour,
            Ordre::GardeRegler { refus: true },
        ] {
            assert!(!faire_ordre(&o).reussi);
        }
    }

    #[test]
    fn empreintes_de_vanguard_bornees() {
        let mut r = Reglages::default();
        for i in 0..(VANGUARD_MAX + 2) {
            garder_empreinte(&mut r, format!("{i:064x}"));
        }
        garder_empreinte(&mut r, format!("{:064x}", VANGUARD_MAX + 1));
        assert_eq!(r.vanguard.len(), VANGUARD_MAX);
        assert_eq!(r.vanguard.last().unwrap(), &format!("{:064x}", VANGUARD_MAX + 1));
        assert_eq!(r.vanguard.first().unwrap(), &format!("{:064x}", 2));
    }
}
