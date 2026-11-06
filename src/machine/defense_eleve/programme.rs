//! Lot D7b : arrêter un programme suspect, rejugé par root (`chasse::juger_programme`, programme sans fichier). Ses
//! traces sont copiées D'ABORD (programme, ligne de commande, environnement, fichiers ouverts), dans
//! /var/lib/vanguard/traces, à root et fermé aux autres ; puis il est arrêté s'il est encore celui qui a été vu (même
//! naissance, même programme). Un fil du noyau n'est jamais touché : seul le conseil de réinstaller est donné.

use super::*;

/// Les traces des programmes arrêtés, à root, fermé aux autres.
pub(super) const TRACES: &str = "/var/lib/vanguard/traces";
/// `PF_KTHREAD` : un fil du noyau (linux/sched.h).
const FIL_DU_NOYAU: u64 = 0x0020_0000;
/// La taille la plus grande d'un fichier de /proc copié.
const PROC_MAX: usize = 4 * 1024 * 1024;
/// La taille la plus grande d'un programme copié ; au-delà, son empreinte seulement.
const PROGRAMME_MAX: usize = 64 * 1024 * 1024;
/// Les fichiers ouverts notés au plus.
const FD_MAX: usize = 1024;

/// De `/proc/<pid>/stat` : l'état (3e champ), les drapeaux (9e) et la naissance en tops d'horloge depuis le démarrage
/// (22e), lus après la dernière parenthèse : le nom, entre parenthèses, peut en contenir.
pub(crate) fn naissance_du_stat(stat: &str) -> Option<(char, u64, u64)> {
    let apres = stat.get(stat.rfind(')')? + 1..)?;
    let champs: Vec<&str> = apres.split_whitespace().collect();
    let etat = champs.first()?.chars().next()?;
    let drapeaux = champs.get(6)?.parse().ok()?;
    let debut = champs.get(19)?.parse().ok()?;
    Some((etat, drapeaux, debut))
}

fn dossier_traces(pid: u32, debut: u64) -> PathBuf {
    PathBuf::from(format!("{TRACES}/{pid}-{debut}"))
}

pub(super) fn juger_arret(pid: u32, debut: u64, a: &mut dyn Acces) -> Jugement {
    // Parti, ou un autre programme sur le même numéro : celui qui a été vu ne tourne plus.
    let Some(v) = a.processus(pid) else {
        return Ok(None);
    };
    if v.debut != debut || v.zombie {
        return Ok(None);
    }
    let nom = echappe(v.nom.as_bytes());
    if v.tgid != pid {
        return Err(refus(trf!(
            "le numéro {pid} est un fil d'un autre programme, pas un programme : rien n'est fait",
            "number {pid} is a thread of another program, not a program: nothing is done"
        )));
    }
    if v.noyau {
        return Err(refus(trf!(
            "{nom} ({pid}) est un fil du noyau : Vanguard n'y touche pas. Si le noyau lui-même est atteint (un module caché, par exemple), rien ne s'y nettoie de façon sûre : sauvegardez vos fichiers, puis réinstallez le système",
            "{nom} ({pid}) is a kernel thread: Vanguard does not touch it. If the kernel itself is compromised (a hidden module, for instance), nothing can be cleaned there safely: back up your files, then reinstall the system"
        )));
    }
    if let Some(g) = a.garde(pid, &v) {
        return Err(refus(trf!(
            "{nom} ({pid}) ne s'arrête pas : {g}. Rien n'est fait",
            "{nom} ({pid}) is not stopped: {g}. Nothing is done"
        )));
    }
    let Some(raison) = a.soupcon(pid, &v) else {
        return Err(refus(trf!(
            "relu en administrateur, {nom} ({pid}) n'a rien de suspect : rien n'est fait",
            "read again as administrator, {nom} ({pid}) has nothing suspicious: nothing is done"
        )));
    };
    let Some(exe) = v.exe.clone() else {
        return Err(refus(trf!(
            "le programme de {nom} ({pid}) ne se lit pas : rien n'est arrêté à l'aveugle",
            "the program of {nom} ({pid}) cannot be read: nothing is stopped blindly"
        )));
    };
    let montre = echappe(exe.as_bytes());
    let traces = lisible(&dossier_traces(pid, debut));
    let uid = v.uid;
    Ok(Some(Plan {
        texte: trf!(
            "Programme {nom} (numéro {pid}, compte {uid}) : {montre}\nSuspect : {raison}.\nSes traces (programme, ligne de commande, environnement, fichiers ouverts) sont copiées d'abord dans {traces}, lisible par root seulement (l'environnement peut contenir des mots de passe : effacez ce dossier une fois lu), puis il est arrêté. Ce qu'il faisait n'est pas défait : relancez le bilan ensuite.",
            "Program {nom} (number {pid}, account {uid}): {montre}\nSuspicious: {raison}.\nIts traces (program, command line, environment, open files) are copied first into {traces}, readable by root only (the environment may contain passwords: delete this folder once read), then it is stopped. What it did is not undone: run the check again afterwards."
        ),
        avertissement: None,
        non_annulable: true,
        seconde: None,
        champs: vec![
            ("pid".into(), pid.to_string().into_bytes()),
            ("debut".into(), debut.to_string().into_bytes()),
            ("exe".into(), exe.into_bytes()),
            ("nom".into(), v.nom.clone().into_bytes()),
            ("raison".into(), raison.into_bytes()),
        ],
        action: Action::Arreter(pid, v),
    }))
}

/// Les traces d'abord ; puis, s'il est encore celui qui a été vu, l'arrêt.
pub(super) fn arreter(pid: u32, v: &VueProcessus, a: &mut dyn Acces) -> Result<(), Echec> {
    let dossier = a.copier_traces(pid, v)?;
    if a.processus(pid).as_ref() != Some(v) {
        return Err(refus(trf!(
            "le programme {pid} a changé ou s'est arrêté pendant la copie de ses traces ({}) : rien n'est arrêté",
            "program {pid} changed or stopped while its traces were copied ({}): nothing is stopped",
            lisible(&dossier)
        )));
    }
    a.arreter(pid, v)
}

// ————— Le vrai ordinateur —————

fn champ_de_status<'a>(status: &'a str, nom: &str) -> Option<&'a str> {
    status.lines().find_map(|l| l.strip_prefix(nom)).map(str::trim)
}

pub(super) fn processus_reel(pid: u32) -> Option<VueProcessus> {
    let racine = PathBuf::from(format!("/proc/{pid}"));
    let (etat, drapeaux, debut) = naissance_du_stat(&std::fs::read_to_string(racine.join("stat")).ok()?)?;
    let status = std::fs::read_to_string(racine.join("status")).ok()?;
    let tgid = champ_de_status(&status, "Tgid:")?.parse().ok()?;
    let uid = champ_de_status(&status, "Uid:")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let nom = champ_de_status(&status, "Name:")?.to_string();
    let exe = std::fs::read_link(racine.join("exe"))
        .ok()
        .and_then(|l| l.to_str().map(str::to_string));
    Some(VueProcessus {
        debut,
        tgid,
        nom,
        exe,
        uid,
        noyau: drapeaux & FIL_DU_NOYAU != 0,
        zombie: matches!(etat, 'Z' | 'X'),
    })
}

/// Le soupçon relu par root : celui de la chasse (niveau moyen au moins), sinon celui d'un programme sans fichier.
pub(super) fn soupcon_reel(pid: u32, v: &VueProcessus) -> Option<String> {
    use crate::risk::Niveau;
    let p = crate::machine::chasse::en_marche_de(pid)?;
    if let Some(s) = crate::machine::chasse::juger_programme(&p, crate::machine::regles::Os::Linux)
        .filter(|s| s.niveau >= Niveau::Moyen)
    {
        return Some(match &s.extrait {
            Some(e) => format!("{} ({})", s.raison, echappe(e.as_bytes())),
            None => s.raison.to_string(),
        });
    }
    let lien = v.exe.as_deref()?;
    let chemin = lien.strip_suffix(" (deleted)").unwrap_or(lien);
    let remplace = Path::new(&format!("/proc/{pid}/root{chemin}")).exists();
    let montages = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    crate::machine::linux::dissimulation::juger_exe(lien, remplace, &montages)
        .filter(|j| j.niveau() >= Niveau::Moyen)
        .map(|j| j.raison().to_string())
}

/// Les gardes des arrêts : vital, programme du système, Vanguard lui-même, celui qui l'a demandé et leur lignée.
pub(super) fn garde_reelle(pid: u32, v: &VueProcessus, demandeur: Option<u32>) -> Option<String> {
    use crate::protection::blocage::{gardes, ordres};
    let Some((_, mut intouchables)) = crate::machine::chasse::en_marche() else {
        return Some(
            tr!(
                "la liste des programmes ne se lit pas, Vanguard ne peut pas vérifier ce qu'il arrêterait",
                "the list of programs cannot be read, Vanguard cannot check what it would stop"
            )
            .to_string(),
        );
    };
    for p in std::iter::once(std::process::id()).chain(demandeur) {
        intouchables.insert(p);
        intouchables.extend(ordres::ancetres(p));
    }
    let chemin = v.exe.as_deref().map(|e| e.strip_suffix(" (deleted)").unwrap_or(e));
    let fichier = chemin
        .and_then(|c| Path::new(c).file_name())
        .map(|n| n.to_string_lossy().into_owned());
    std::iter::once(v.nom.clone())
        .chain(fichier)
        .find_map(|nom| {
            gardes::processus_intouchable(pid, &nom, chemin, &intouchables, crate::machine::regles::Os::Linux)
        })
        .map(str::to_string)
}

/// Lit au plus `max` octets d'un fichier de /proc ; `Err` : `max` dépassé, ou illisible.
fn lire_borne(p: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let f = std::fs::File::open(p)?;
    let mut o = Vec::new();
    f.take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut o)?;
    if o.len() > max {
        return Err(std::io::Error::other(trf!(
            "plus de {max} octets",
            "more than {max} bytes"
        )));
    }
    Ok(o)
}

/// Le SHA-256 d'un fichier lu jusqu'au bout, par morceaux.
fn empreinte_lue(p: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut tampon = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut tampon) {
            Ok(0) => break,
            Ok(n) => h.update(tampon.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(gestes_unix::hex(&h.finalize()))
}

/// Crée le dossier `d` s'il manque, puis vérifie qu'il est à root et fermé (`ferme`).
fn dossier_de_traces(d: &Path, mode: u32, ferme: u32) -> Result<(), Echec> {
    use std::os::unix::fs::DirBuilderExt;
    if std::fs::symlink_metadata(d).is_err() {
        std::fs::DirBuilder::new()
            .mode(mode)
            .create(d)
            .map_err(|e| echoue(e.to_string()))?;
    }
    dossier_sur(d, ferme)
}

pub(super) fn copier_traces_reel(pid: u32, v: &VueProcessus, date: u64) -> Result<PathBuf, Echec> {
    use std::os::unix::fs::DirBuilderExt;
    essais_sans_ecriture()?;
    dossier_de_traces(Path::new(DOSSIER_VANGUARD), 0o755, 0o022)?;
    dossier_de_traces(Path::new(TRACES), 0o700, 0o077)?;
    let mut dossier = dossier_traces(pid, v.debut);
    if std::fs::symlink_metadata(&dossier).is_ok() {
        dossier = PathBuf::from(format!("{TRACES}/{pid}-{}-{date}", v.debut));
    }
    // Un dossier neuf (create échoue s'il existe) : rien n'y attendait déjà.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dossier)
        .map_err(|e| echoue(e.to_string()))?;
    dossier_sur(&dossier, 0o077)?;
    let racine = PathBuf::from(format!("/proc/{pid}"));
    let fichier = |nom: &str, contenu: &[u8]| {
        creer(
            &dossier.join(nom),
            contenu,
            Ecriture {
                mode: 0o600,
                uid: 0,
                gid: 0,
                avant: None,
            },
        )
    };
    let mut empreintes = String::new();
    for nom in [
        "cmdline",
        "environ",
        "status",
        "stat",
        "maps",
        "cgroup",
        "loginuid",
        "comm",
        "mountinfo",
    ] {
        match lire_borne(&racine.join(nom), PROC_MAX) {
            Ok(o) => {
                let _ = writeln!(empreintes, "{}  {nom}", gestes_unix::hex(&Sha256::digest(&o)));
                fichier(nom, &o)?;
            }
            Err(e) => {
                let _ = writeln!(empreintes, "-  {nom} ({e})");
            }
        }
    }
    // Le programme lui-même, lu par /proc : il se lit encore, effacé du disque ou en mémoire seulement.
    let exe = racine.join("exe");
    match lire_borne(&exe, PROGRAMME_MAX) {
        Ok(o) => {
            let _ = writeln!(empreintes, "{}  exe", gestes_unix::hex(&Sha256::digest(&o)));
            fichier("exe", &o)?;
        }
        Err(e) => match empreinte_lue(&exe) {
            Ok(h) => {
                let _ = writeln!(empreintes, "{h}  exe (pas copié : {e})");
            }
            Err(e) => {
                let _ = writeln!(empreintes, "-  exe ({e})");
            }
        },
    }
    let mut liens = String::new();
    for nom in ["exe", "cwd", "root"] {
        let l = std::fs::read_link(racine.join(nom));
        let _ = writeln!(liens, "{nom} -> {:?}", l.map_err(|e| e.to_string()));
    }
    if let Ok(fds) = std::fs::read_dir(racine.join("fd")) {
        let mut fds: Vec<(u32, PathBuf)> = fds
            .filter_map(|e| {
                let e = e.ok()?;
                let n = e.file_name().to_str()?.parse().ok()?;
                Some((n, std::fs::read_link(e.path()).ok()?))
            })
            .collect();
        fds.sort();
        for (n, l) in fds.iter().take(FD_MAX) {
            // Échappé : un nom de fichier qui porte un retour à la ligne n'invente pas de ligne dans la trace.
            let _ = writeln!(
                liens,
                "fd/{n} -> {}",
                gestes_unix::echappe(l.as_os_str().as_encoded_bytes())
            );
        }
    }
    fichier("liens.txt", liens.as_bytes())?;
    fichier("empreintes.txt", empreintes.as_bytes())?;
    Ok(dossier)
}

pub(super) fn arreter_reel(pid: u32, v: &VueProcessus) -> Result<(), Echec> {
    essais_sans_ecriture()?;
    let Some(exe) = v.exe.as_deref() else {
        return Err(refus(tr!(
            "programme illisible : rien n'est arrêté",
            "program unreadable: nothing is stopped"
        )));
    };
    crate::protection::blocage::arreter_confirme(pid, exe.strip_suffix(" (deleted)").unwrap_or(exe))
}

/// Crée un dossier de root (il ne doit pas exister), dans un dossier de root fermé aux autres.
pub(super) fn creer_dossier_reel(p: &Path, mode: u32) -> Result<(), Echec> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    essais_sans_ecriture()?;
    let parent = p.parent().ok_or_else(note_abimee)?;
    dossier_sur(parent, 0o022)?;
    std::fs::DirBuilder::new()
        .mode(mode)
        .create(p)
        .map_err(|e| echoue(e.to_string()))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).map_err(|e| echoue(e.to_string()))?;
    dossier_sur(p, 0o022)
}
