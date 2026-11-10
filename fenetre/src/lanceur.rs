//! Lancer `vanguard` avec une commande de la liste fermée (`commandes`), et rien d'autre : le programme voisin (le
//! fichier `vanguard` posé dans le même dossier que la fenêtre, jamais cherché dans le PATH ni désigné par une
//! variable), sans shell, avec ses arguments fixés dans le code, l'entrée fermée (il ne peut rien demander), ses
//! sorties lues en fond et bornées, un délai, et un arrêt qui tue tout son groupe (Linux).
//!
//! C'est l'équivalent, pour la fenêtre, de `commande::lancer` dans Vanguard : un enfant qui ne finit pas, qui écrit
//! sans fin ou qui garde ses sorties ouvertes ne bloque ni n'épuise la fenêtre.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::commandes::Commande;

/// La sortie (JSON) relue au plus : 16 Mio. Au-delà, l'enfant est arrêté et rien n'est montré.
pub const SORTIE_MAX: usize = 16 * 1024 * 1024;
/// Une ligne des erreurs gardée au plus (octets) ; le reste de la ligne est jeté.
const LIGNE_ERREUR_MAX: usize = 4096;
/// Lignes des erreurs relayées au plus par tâche.
const LIGNES_ERREUR_MAX: usize = 2000;
/// Après la fin de l'enfant, le temps laissé aux lecteurs pour finir (une sortie gardée ouverte par un petit-enfant).
const FIN_LECTURE: Duration = Duration::from_secs(2);
/// Entre la demande d'arrêt (SIGTERM) et l'arrêt forcé (SIGKILL).
const GRACE: Duration = Duration::from_millis(1500);
/// Le pas de la surveillance de l'enfant.
const PAS: Duration = Duration::from_millis(50);

/// Le programme `vanguard` voisin de la fenêtre.
#[derive(Clone, Debug)]
pub struct Programme(PathBuf);

impl Programme {
    /// `vanguard` (`vanguard.exe` sous Windows) dans le dossier de la fenêtre. Jamais le PATH, jamais une variable
    /// d'environnement : une fenêtre lancée d'un dossier piégé ne doit pas lancer un autre programme.
    pub fn voisin() -> Result<Programme, String> {
        let soi = std::env::current_exe().map_err(|e| e.to_string())?;
        let dossier = soi
            .parent()
            .ok_or_else(|| crate::tr!("dossier introuvable", "folder not found").to_string())?;
        #[cfg(unix)]
        let proprietaire = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&soi).map_err(|e| e.to_string())?.uid()
        };
        #[cfg(not(unix))]
        let proprietaire = 0;
        Programme::dans(dossier, proprietaire)
    }

    /// `proprietaire` : le compte à qui est la fenêtre elle-même (Linux) ; `vanguard` doit être à lui ou à root.
    fn dans(dossier: &Path, proprietaire: u32) -> Result<Programme, String> {
        let nom = if cfg!(windows) { "vanguard.exe" } else { "vanguard" };
        let chemin = dossier.join(nom);
        // symlink_metadata : un lien n'est pas suivi, il est refusé (pas un fichier ordinaire).
        let Ok(m) = std::fs::symlink_metadata(&chemin) else {
            return Err(crate::trf!(
                "« {} » est introuvable à côté de la fenêtre",
                "“{}” was not found next to the window",
                nom
            ));
        };
        match refus(&m, proprietaire) {
            None => Ok(Programme(chemin)),
            Some(raison) => Err(crate::trf!(
                "« {} » à côté de la fenêtre n'est pas lancé : {}",
                "“{}” next to the window is not started: {}",
                nom,
                raison
            )),
        }
    }
}

/// Pourquoi le `vanguard` voisin n'est pas lancé, s'il y a une raison : la même règle que Vanguard pour la fenêtre
/// (src/demarrage/lancer_fenetre.rs). Sous Linux, un vrai fichier (pas un lien), au compte de la fenêtre ou à root, que
/// ni le groupe ni les autres ne peuvent modifier : sinon un autre compte pourrait y mettre un faux `vanguard` dont
/// la fenêtre afficherait les « tout va bien ».
#[cfg(unix)]
fn refus(m: &std::fs::Metadata, proprietaire: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_file() {
        return Some(crate::tr!("pas un fichier ordinaire", "not a regular file"));
    }
    if m.uid() != proprietaire && m.uid() != 0 {
        return Some(crate::tr!("à un autre compte", "owned by another account"));
    }
    if m.mode() & 0o022 != 0 {
        return Some(crate::tr!(
            "modifiable par d'autres comptes",
            "writable by other accounts"
        ));
    }
    None
}

#[cfg(not(unix))]
fn refus(m: &std::fs::Metadata, _proprietaire: u32) -> Option<&'static str> {
    (!m.file_type().is_file()).then(|| crate::tr!("pas un fichier ordinaire", "not a regular file"))
}

/// Comment une tâche a fini.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issue {
    Terminee,
    /// Arrêtée à la demande (bouton Arrêter).
    Arretee,
    DelaiDepasse,
    /// La sortie dépassait `SORTIE_MAX` : arrêtée, rien de montré.
    TropLongue,
    /// Le programme n'a pas pu être lancé.
    Impossible(String),
}

/// La fin d'une tâche.
#[derive(Clone, Debug)]
pub struct Fin {
    pub commande: Commande,
    pub code: Option<i32>,
    pub sortie: Vec<u8>,
    pub issue: Issue,
    pub duree: Duration,
}

/// Ce qu'une tâche envoie à la fenêtre.
#[derive(Clone, Debug)]
pub enum Message {
    /// Une ligne écrite sur la sortie des erreurs (progression, avertissement), nettoyée.
    Ligne(String),
    Fin(Fin),
}

/// Une commande en cours.
pub struct Tache {
    pub commande: Commande,
    pub debut: Instant,
    arret: Arc<AtomicBool>,
    recu: mpsc::Receiver<Message>,
}

/// Réveille la fenêtre quand un message arrive (elle ne redessine pas sans cela).
pub type Reveil = Arc<dyn Fn() + Send + Sync>;

impl Tache {
    /// Lance `commande` en fond. Le résultat arrive par `recevoir`, toujours terminé par un `Message::Fin`.
    pub fn lancer(programme: &Programme, commande: Commande, anglais: bool, reveil: &Reveil) -> Tache {
        let arret = Arc::new(AtomicBool::new(false));
        let (envoi, recu) = mpsc::channel();
        let chemin = programme.0.clone();
        let a = Arc::clone(&arret);
        let lance = std::thread::Builder::new().name("vanguard-tache".into()).spawn({
            let envoi = envoi.clone();
            let reveil = Arc::clone(reveil);
            move || {
                let fin = surveiller(&chemin, commande, anglais, &a, &envoi, &reveil);
                let _ = envoi.send(Message::Fin(fin));
                reveil();
            }
        });
        if let Err(e) = lance {
            let _ = envoi.send(Message::Fin(Fin {
                commande,
                code: None,
                sortie: Vec::new(),
                issue: Issue::Impossible(e.to_string()),
                duree: Duration::ZERO,
            }));
            reveil();
        }
        Tache {
            commande,
            debut: Instant::now(),
            arret,
            recu,
        }
    }

    /// Demande l'arrêt : le groupe de l'enfant reçoit SIGTERM, puis SIGKILL après un court délai.
    pub fn arreter(&self) {
        self.arret.store(true, Ordering::Relaxed);
    }

    pub fn arret_demande(&self) -> bool {
        self.arret.load(Ordering::Relaxed)
    }

    /// Les messages arrivés depuis le dernier appel.
    pub fn recevoir(&self) -> Vec<Message> {
        self.recu.try_iter().collect()
    }
}

fn preparer(chemin: &Path, commande: Commande, anglais: bool) -> Command {
    let mut c = Command::new(chemin);
    c.args(commande.arguments())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Du texte simple : pas de couleurs ni de séquences de terminal (nettoyées de toute façon).
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .env("VANGUARD_LANG", if anglais { "en" } else { "fr" });
    if let Some(d) = chemin.parent() {
        c.current_dir(d);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Son propre groupe : Arrêter tue aussi ce que `vanguard` a lancé.
        c.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW : pas de console qui s'ouvre et se ferme à chaque commande.
        c.creation_flags(0x0800_0000);
    }
    c
}

fn surveiller(
    chemin: &Path,
    commande: Commande,
    anglais: bool,
    arret: &AtomicBool,
    envoi: &mpsc::Sender<Message>,
    reveil: &Reveil,
) -> Fin {
    let debut = Instant::now();
    let fin = |code, sortie, issue| Fin {
        commande,
        code,
        sortie,
        issue,
        duree: debut.elapsed(),
    };
    let mut enfant = match preparer(chemin, commande, anglais).spawn() {
        Ok(e) => e,
        Err(e) => {
            return fin(
                None,
                Vec::new(),
                Issue::Impossible(crate::nettoyage::nom(&e.to_string(), 200)),
            );
        }
    };
    let trop = Arc::new(AtomicBool::new(false));
    let (sortie_envoi, sortie_recu) = mpsc::channel();
    if let Some(s) = enfant.stdout.take() {
        let trop = Arc::clone(&trop);
        let _ = std::thread::Builder::new()
            .name("vanguard-sortie".into())
            .spawn(move || {
                let (octets, depasse) = lire_borne(s, SORTIE_MAX);
                if depasse {
                    trop.store(true, Ordering::Relaxed);
                }
                let _ = sortie_envoi.send(octets);
            });
    }
    if let Some(e) = enfant.stderr.take() {
        let envoi = envoi.clone();
        let reveil = Arc::clone(reveil);
        let _ = std::thread::Builder::new()
            .name("vanguard-erreurs".into())
            .spawn(move || {
                lire_lignes(e, LIGNE_ERREUR_MAX, LIGNES_ERREUR_MAX, |l| {
                    if !l.is_empty() {
                        let _ = envoi.send(Message::Ligne(l));
                        reveil();
                    }
                });
            });
    }
    let delai = commande.delai();
    let (code, issue) = loop {
        match enfant.try_wait() {
            Ok(Some(s)) => break (s.code(), Issue::Terminee),
            Ok(None) => {}
            Err(e) => {
                tuer(&mut enfant);
                break (None, Issue::Impossible(crate::nettoyage::nom(&e.to_string(), 200)));
            }
        }
        let issue = if arret.load(Ordering::Relaxed) {
            Some(Issue::Arretee)
        } else if trop.load(Ordering::Relaxed) {
            Some(Issue::TropLongue)
        } else if debut.elapsed() >= delai {
            Some(Issue::DelaiDepasse)
        } else {
            None
        };
        if let Some(i) = issue {
            tuer(&mut enfant);
            break (None, i);
        }
        std::thread::sleep(PAS);
    };
    // La sortie : ce que le lecteur a lu. Un petit-enfant qui la garderait ouverte est tué avec le groupe.
    let sortie = if let Ok(s) = sortie_recu.recv_timeout(FIN_LECTURE) {
        Some(s)
    } else {
        tuer_groupe(&enfant, true);
        sortie_recu.recv_timeout(FIN_LECTURE).ok()
    };
    let issue = if issue == Issue::Terminee && trop.load(Ordering::Relaxed) {
        Issue::TropLongue
    } else {
        issue
    };
    match (issue, sortie) {
        (Issue::Terminee, Some(s)) => fin(code, s, Issue::Terminee),
        (Issue::Terminee, None) => fin(
            code,
            Vec::new(),
            Issue::Impossible(crate::tr!("sortie jamais fermée", "output never closed").into()),
        ),
        (i, _) => fin(code, Vec::new(), i),
    }
}

/// Arrête l'enfant et attend sa fin : SIGTERM au groupe, puis SIGKILL après `GRACE` (Linux) ; sous Windows,
/// `TerminateProcess` sur `vanguard` seul (ses enfants éventuels ne sont pas tués : limite connue).
fn tuer(enfant: &mut Child) {
    tuer_groupe(enfant, false);
    let debut = Instant::now();
    while debut.elapsed() < GRACE {
        if matches!(enfant.try_wait(), Ok(Some(_))) {
            // Le meneur est parti ; ce qui reste du groupe part aussi.
            tuer_groupe(enfant, true);
            return;
        }
        std::thread::sleep(PAS);
    }
    tuer_groupe(enfant, true);
    let _ = enfant.kill();
    let _ = enfant.wait();
}

#[cfg(unix)]
fn tuer_groupe(enfant: &Child, force: bool) {
    let Ok(groupe) = i32::try_from(enfant.id()) else {
        return;
    };
    if groupe > 1 {
        signal::groupe(groupe, if force { libc::SIGKILL } else { libc::SIGTERM });
    }
}

#[cfg(not(unix))]
fn tuer_groupe(enfant: &Child, force: bool) {
    let _ = (enfant, force);
}

#[cfg(unix)]
mod signal {
    // raison : FFI de killpg (libc), pour arrêter tout le groupe de l'enfant, que std ne sait pas faire.
    #[allow(unsafe_code)]
    pub fn groupe(groupe: i32, sig: i32) {
        // SAFETY: killpg ne reçoit que deux entiers et ne touche aucune mémoire de ce programme ; le groupe est celui
        // de l'enfant (process_group(0) le crée avec son numéro), toujours > 1 (vérifié par l'appelant).
        let _ = unsafe { libc::killpg(groupe, sig) };
    }
}

/// Lit au plus `max` octets ; `true` si la source en avait plus (le reste n'est pas lu : l'enfant sera arrêté).
pub fn lire_borne(r: impl Read, max: usize) -> (Vec<u8>, bool) {
    let mut v = Vec::new();
    let limite = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let _ = r.take(limite).read_to_end(&mut v);
    if v.len() > max {
        v.truncate(max);
        (v, true)
    } else {
        (v, false)
    }
}

/// Lit des lignes, chacune coupée à `max_octets` (le reste de la ligne jeté) et nettoyée, `max_lignes` au plus ;
/// au-delà, la source est lue jusqu'au bout sans rien garder (l'enfant ne doit pas bloquer sur un tuyau plein).
pub fn lire_lignes(mut r: impl Read, max_octets: usize, max_lignes: usize, mut f: impl FnMut(String)) {
    let mut ligne: Vec<u8> = Vec::new();
    let mut lignes = 0usize;
    let mut bloc = [0u8; 8192];
    let mut rendre = |ligne: &mut Vec<u8>, lignes: &mut usize| {
        if *lignes < max_lignes {
            f(crate::nettoyage::ligne(&String::from_utf8_lossy(ligne)));
        }
        *lignes = lignes.saturating_add(1);
        ligne.clear();
    };
    loop {
        let n = match r.read(&mut bloc) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &o in bloc.get(..n).unwrap_or(&[]) {
            if o == b'\n' {
                rendre(&mut ligne, &mut lignes);
            } else if ligne.len() < max_octets {
                ligne.push(o);
            }
        }
    }
    if !ligne.is_empty() {
        rendre(&mut ligne, &mut lignes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_sortie_est_bornee() {
        assert_eq!(lire_borne(&b"abc"[..], 3), (b"abc".to_vec(), false));
        assert_eq!(lire_borne(&b"abcd"[..], 3), (b"abc".to_vec(), true));
        assert_eq!(lire_borne(&b""[..], 3), (Vec::new(), false));
    }

    #[test]
    fn les_lignes_sont_bornees_et_propres() {
        let mut vues = Vec::new();
        let source = format!("une\n{}\n\u{1b}[31mrouge\u{1b}[0m\r\nfin", "x".repeat(10_000));
        lire_lignes(source.as_bytes(), 10, 100, |l| vues.push(l));
        assert_eq!(vues, ["une", "xxxxxxxxxx", "rouge", "fin"]);
        let mut n = 0;
        lire_lignes("a\n".repeat(50).as_bytes(), 10, 5, |_| n += 1);
        assert_eq!(n, 5);
    }

    #[test]
    fn seul_le_voisin_est_lance() {
        let d = std::env::temp_dir().join(format!("vanguard-fenetre-essai-{}", std::process::id()));
        // Un dossier qui n'existe pas : rien, jamais le PATH.
        assert!(Programme::dans(&d, 0).is_err());
    }

    /// Un `vanguard` que d'autres comptes pourraient remplacer n'est pas lancé, ni un lien, ni celui d'un autre compte.
    #[cfg(unix)]
    #[test]
    fn un_vanguard_modifiable_par_d_autres_est_refuse() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("essais-fenetre")
            .join(format!("droits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("vanguard");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let moi = std::fs::metadata(&f).unwrap().uid();
        let droits = |mode| std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        droits(0o755);
        assert!(Programme::dans(&d, moi).is_ok());
        droits(0o775);
        assert!(Programme::dans(&d, moi).is_err());
        droits(0o757);
        assert!(Programme::dans(&d, moi).is_err());
        droits(0o755);
        if moi != 0 {
            assert!(Programme::dans(&d, moi.wrapping_add(1)).is_err());
        }
        std::fs::rename(&f, d.join("vrai")).unwrap();
        std::os::unix::fs::symlink(d.join("vrai"), &f).unwrap();
        assert!(Programme::dans(&d, moi).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un faux `vanguard` (un script) : la vraie suite lancée, attendue, arrêtée, sans rien toucher hors de target/.
    #[cfg(unix)]
    const FAUX: &str = r#"#!/bin/sh
# L'entrée est fermée : rien ne peut y être lu.
[ -z "$(cat)" ] || exit 9
case "$1 $2" in
"audit --json") echo "une ligne d'erreur" >&2; printf '{"score": 90, "fiable": true, "constats": [], "langue": "%s"}' "$VANGUARD_LANG" ;;
"protection --json") sleep 30 & echo $! > petit-enfant; sleep 30 ;;
"evenements --json") yes ;;
"diagnostic --json") sleep 30 & printf '{}' ;;
*) exit 7 ;;
esac
"#;

    #[cfg(unix)]
    fn attendre(t: &Tache) -> (Vec<String>, Fin) {
        let debut = Instant::now();
        let mut lignes = Vec::new();
        while debut.elapsed() < Duration::from_secs(20) {
            for m in t.recevoir() {
                match m {
                    Message::Ligne(l) => lignes.push(l),
                    Message::Fin(f) => return (lignes, f),
                }
            }
            std::thread::sleep(PAS);
        }
        panic!("la tâche n'a jamais fini");
    }

    /// Le processus existe-t-il encore (un zombie ne compte pas) ?
    #[cfg(unix)]
    fn vivant(pid: &str) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|s| s.rsplit_once(") ").is_some_and(|(_, r)| !r.starts_with('Z')))
    }

    /// Un seul essai pour les quatre cas : le script est écrit une fois avant tout lancement (sinon un autre essai
    /// qui lance un programme pendant l'écriture le rendrait « occupé », ETXTBSY).
    #[cfg(unix)]
    #[test]
    fn lance_attend_arrete_et_borne() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("essais-fenetre")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&d).unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let p = Programme::dans(&d, moi).unwrap();
        let rien: Reveil = Arc::new(|| {});

        // Terminée : la sortie entière, la ligne d'erreur à part, la langue passée.
        let (lignes, f) = attendre(&Tache::lancer(&p, Commande::Bilan, true, &rien));
        assert_eq!(f.issue, Issue::Terminee);
        assert_eq!(f.code, Some(0));
        assert!(String::from_utf8_lossy(&f.sortie).contains(r#""langue": "en""#));
        assert_eq!(lignes, ["une ligne d'erreur"]);

        // Arrêtée : le groupe entier part, le petit-enfant aussi.
        let t = Tache::lancer(&p, Commande::Protection, false, &rien);
        let debut = Instant::now();
        while !d.join("petit-enfant").exists() && debut.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(PAS);
        }
        t.arreter();
        let (_, f) = attendre(&t);
        assert_eq!(f.issue, Issue::Arretee);
        assert!(f.duree < Duration::from_secs(10));
        let pid = std::fs::read_to_string(d.join("petit-enfant")).unwrap();
        let pid = pid.trim();
        let debut = Instant::now();
        while vivant(pid) && debut.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(PAS);
        }
        assert!(!vivant(pid), "le petit-enfant {pid} vit encore");

        // Trop longue : arrêtée à SORTIE_MAX, rien de gardé.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::Evenements, false, &rien));
        assert_eq!(f.issue, Issue::TropLongue);
        assert_eq!(f.sortie, b"");

        // Un petit-enfant garde la sortie ouverte après la fin : il est tué, la sortie lue est rendue.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::Diagnostic, false, &rien));
        assert_eq!(f.issue, Issue::Terminee);
        assert_eq!(f.sortie, b"{}");

        // Une commande que le script ne connaît pas : son code de sortie est rendu tel quel.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::Lenteur, false, &rien));
        assert_eq!(f.code, Some(7));
        let _ = std::fs::remove_dir_all(&d);
    }
}
