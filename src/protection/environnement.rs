//! L'environnement dans lequel Vanguard démarre. Une bibliothèque injectée dans tous les programmes de la session
//! (LD_PRELOAD, LD_AUDIT, /etc/ld.so.preload sous Linux ; AppInit_DLLs sous Windows) tourne aussi dans Vanguard et peut
//! lui mentir : ce qu'il lit du système passe par elle. On le dit avant tout bilan, sur la sortie d'erreur (une sortie
//! JSON reste propre). LD_PRELOAD a des usages légitimes (GameMode, l'overlay Steam, libgtk3-nocsd, fakeroot) : une
//! bibliothèque d'un paquet du système, hors d'un dossier que l'utilisateur peut écrire, est une information ; le
//! reste, une alerte. /etc/ld.so.preload se lit comme le bilan et le fils root le lisent (`machine::prechargement`,
//! la lecture du chargeur de glibc, sur les octets) ; une lecture ratée se dit, elle ne compte jamais comme un fichier
//! sain.

use crate::risk::Niveau;
use crate::ui::*;

pub struct Avis {
    pub niveau: Niveau,
    pub texte: String,
}

/// Dossiers qu'un simple utilisateur, ou un programme lancé par lui, peut écrire : une bibliothèque qui en vient
/// n'offre aucune garantie. Un chemin relatif non plus.
#[cfg(any(target_os = "linux", test))]
fn dossier_modifiable(chemin: &str) -> bool {
    !chemin.starts_with('/')
        || [
            "/home/",
            "/root/",
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
            "/run/user/",
            "/mnt/",
            "/media/",
            "/run/media/",
        ]
        .iter()
        .any(|d| chemin.starts_with(d))
}

/// Dossiers où le système range ses bibliothèques : un nom nu (« libgamemodeauto.so.0 », ou « $LIB/… » comme
/// l'écrit GameMode) s'y résout.
#[cfg(any(target_os = "linux", test))]
const DOSSIERS_LIB: [&str; 7] = [
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib32",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib",
    "/lib64",
];

/// Juge une bibliothèque préchargée, son nom tel que le chargeur l'ouvre ; `du_systeme(chemin)` : le fichier existe et
/// vient d'un paquet du système. Le nom n'est pas rogné : « /usr/lib/x.so\r » est un autre fichier que celui du paquet
/// (relecture adverse du lot 096, C2 et C4).
#[cfg(any(target_os = "linux", test))]
fn juger_lib(lib: &str, du_systeme: &dyn Fn(&str) -> bool) -> Niveau {
    let nom = lib.rsplit('/').next().unwrap_or(lib);
    let nu = !lib.contains('/') || lib.starts_with("$LIB/") || lib.starts_with("${LIB}/");
    let chemin = if nu {
        match DOSSIERS_LIB
            .iter()
            .map(|d| format!("{d}/{nom}"))
            .find(|p| du_systeme(p))
        {
            Some(p) => p,
            None => return Niveau::Eleve,
        }
    } else {
        lib.to_string()
    };
    if !dossier_modifiable(&chemin) && du_systeme(&chemin) {
        Niveau::Info
    } else {
        Niveau::Eleve
    }
}

#[cfg(any(target_os = "linux", test))]
fn avis_variable(source: &str, valeur: &str, niveau: Niveau) -> Avis {
    let valeur = affichable(valeur);
    let texte = if niveau == Niveau::Info {
        trf!(
            "{source} = {valeur} : une bibliothèque du système est chargée dans tous les programmes de cette session (GameMode, overlay Steam…). Rien d'anormal, mais Vanguard tourne avec elle.",
            "{source} = {valeur}: a system library is loaded into every program of this session (GameMode, Steam overlay…). Nothing abnormal, but Vanguard runs with it."
        )
    } else {
        trf!(
            "{source} = {valeur} : une bibliothèque qui ne vient pas d'un paquet du système est injectée dans tous les programmes de cette session, Vanguard compris. Mes résultats peuvent être faussés. Cherchez qui pose cela (.bashrc, .profile, /etc/environment, /etc/ld.so.preload), ou relancez depuis une session propre.",
            "{source} = {valeur}: a library that does not come from a system package is injected into every program of this session, Vanguard included. My results may be tampered with. Find what sets it (.bashrc, .profile, /etc/environment, /etc/ld.so.preload), or restart from a clean session."
        )
    };
    Avis { niveau, texte }
}

#[cfg(target_os = "linux")]
fn avis() -> Vec<Avis> {
    use std::path::Path;
    let gestion = crate::machine::linux::Paquets::detecter();
    let du_systeme = |p: &str| Path::new(p).is_file() && gestion.is_some_and(|g| g.possede(Path::new(p)));
    let mut liste = Vec::new();
    for var in ["LD_PRELOAD", "LD_AUDIT"] {
        let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) else {
            continue;
        };
        let v = v.to_string_lossy().into_owned();
        let niveau = v
            .split([':', ' '])
            .filter(|l| !l.is_empty())
            .map(|l| juger_lib(l, &du_systeme))
            .max()
            .unwrap_or(Niveau::Info);
        liste.push(avis_variable(var, &v, niveau));
    }
    let lu = crate::machine::temoins::lire_borne(Path::new("/etc/ld.so.preload"), PRECHARGEMENT_MAX);
    liste.extend(avis_preload(lu.map(|lu| (lu.octets, lu.entier)), &du_systeme));
    liste
}

/// Au plus autant d'octets lus dans /etc/ld.so.preload, comme le bilan pour un fichier de configuration.
#[cfg(target_os = "linux")]
const PRECHARGEMENT_MAX: u64 = 32 * 1024 * 1024;

/// L'avis sur /etc/ld.so.preload, lu `lu` (ses octets, et s'ils sont le fichier entier) : chaque nom que le chargeur
/// y prend (`machine::prechargement`, la même lecture que le bilan et le fils root) est jugé tel quel. Un nom hors
/// UTF-8 ne vient d'aucun paquet connu : alerte. Pas de fichier : rien à dire. Illisible, ou lu en partie : « non
/// vérifié », jamais un silence (relecture adverse du lot 096, C4 : un seul octet hors UTF-8 taisait l'avis).
#[cfg(any(target_os = "linux", test))]
fn avis_preload(lu: std::io::Result<(Vec<u8>, bool)>, du_systeme: &dyn Fn(&str) -> bool) -> Option<Avis> {
    let source = "/etc/ld.so.preload";
    let (octets, entier) = match lu {
        Ok(lu) => lu,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            return Some(Avis {
                niveau: Niveau::Moyen,
                texte: trf!(
                    "{source} : illisible ({}). Ce fichier fait charger des bibliothèques dans tous les programmes, root compris, Vanguard aussi : je ne peux pas dire lesquelles, non vérifié. Sur un système sain, il est lisible par tous, ou absent.",
                    "{source}: unreadable ({}). This file makes libraries load into every program, root included, Vanguard too: I cannot tell which ones, not verified. On a healthy system, it is readable by everyone, or absent.",
                    affichable(&e.to_string())
                ),
            });
        }
    };
    let libs = crate::machine::prechargement::bibliotheques(&octets);
    let niveau = libs
        .iter()
        .map(|p| std::str::from_utf8(&p.nom).map_or(Niveau::Eleve, |nom| juger_lib(nom, du_systeme)))
        .max();
    let mut avis = niveau.map(|niveau| {
        let noms: Vec<String> = libs.iter().map(|p| String::from_utf8_lossy(&p.nom).into_owned()).collect();
        let mut a = avis_variable(source, &noms.join(" "), niveau);
        if libs.iter().any(|p| p.apres_un_diese) {
            a.texte.push(' ');
            a.texte.push_str(tr!(
                "Une ligne qui commence par « # » n'est pas toujours ignorée : le chargeur de glibc la lit dans certains cas, elle compte ici.",
                "A line that starts with \"#\" is not always ignored: the glibc loader reads it in some cases, so it counts here."
            ));
        }
        a
    });
    if !entier {
        let suite = tr!(
            "/etc/ld.so.preload est trop gros pour être lu en entier : la suite n'est pas vérifiée.",
            "/etc/ld.so.preload is too large to be read in full: the rest is not verified."
        );
        match avis.as_mut() {
            Some(a) => {
                a.niveau = a.niveau.max(Niveau::Moyen);
                a.texte.push(' ');
                a.texte.push_str(suite);
            }
            None => {
                avis = Some(Avis {
                    niveau: Niveau::Moyen,
                    texte: suite.to_string(),
                });
            }
        }
    }
    avis
}

/// Windows : AppInit_DLLs, chargées par le système dans chaque programme qui affiche une fenêtre (Vanguard, lancé dans
/// une console, en est). Vide sur un Windows normal ; les antivirus sérieux n'en ont plus besoin.
#[cfg(windows)]
fn avis() -> Vec<Avis> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let mut liste = Vec::new();
    for cle in [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ] {
        let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(cle) else {
            continue;
        };
        let charge: u32 = k.get_value("LoadAppInit_DLLs").unwrap_or(0);
        let dlls: String = k.get_value("AppInit_DLLs").unwrap_or_default();
        if charge == 1 && !dlls.trim().is_empty() {
            liste.push(Avis {
                niveau: Niveau::Eleve,
                texte: trf!(
                    "AppInit_DLLs = {} : Windows charge ces DLL dans chaque programme, Vanguard compris. Mes résultats peuvent être faussés. Un Windows sain n'en a aucune : regardez quel programme les a posées (clé {cle}).",
                    "AppInit_DLLs = {}: Windows loads these DLLs into every program, Vanguard included. My results may be tampered with. A healthy Windows has none: look at which program set them (key {cle}).",
                    affichable(dlls.trim())
                ),
            });
        }
    }
    liste
}

/// Les avis, lus une fois : l'affichage du démarrage et le choix de la fenêtre (`injection_alertee`) disent la même
/// chose.
fn avis_lus() -> &'static [Avis] {
    static AVIS: std::sync::OnceLock<Vec<Avis>> = std::sync::OnceLock::new();
    AVIS.get_or_init(avis)
}

/// Une bibliothèque injectée est signalée en alerte (pas une simple information) : la fenêtre de Vanguard, qui
/// charge les bibliothèques du système, ne s'ouvre pas (`demarrage::lancer_fenetre`).
pub(crate) fn injection_alertee() -> bool {
    avis_lus().iter().any(|a| a.niveau != Niveau::Info)
}

/// Au démarrage : chaque avis sur la sortie d'erreur, une information en gris, une alerte en couleur.
pub fn afficher() {
    for a in avis_lus() {
        let (marque, couleur) = if a.niveau == Niveau::Info {
            ("ℹ", GRIS)
        } else {
            ("⚠", couleur(a.niveau))
        };
        for (i, ligne) in envelopper(&a.texte, LARGEUR - 4).into_iter().enumerate() {
            if i == 0 {
                eprintln!("  {couleur}{marque}{RESET} {ligne}");
            } else {
                eprintln!("    {ligne}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bibliotheque_du_systeme_ou_pas() {
        let systeme = |p: &str| {
            p == "/usr/lib/libgamemodeauto.so.0"
                || p == "/usr/lib/libgtk3-nocsd.so.0"
                || p == "/home/alice/.steam/ubuntu12_32/gameoverlayrenderer.so"
        };
        // GameMode, écrit comme son lanceur le fait, et un chemin complet d'un paquet : information.
        assert_eq!(juger_lib("$LIB/libgamemodeauto.so.0", &systeme), Niveau::Info);
        assert_eq!(juger_lib("libgamemodeauto.so.0", &systeme), Niveau::Info);
        assert_eq!(juger_lib("/usr/lib/libgtk3-nocsd.so.0", &systeme), Niveau::Info);
        // Un fichier du dossier personnel, même connu : l'utilisateur (ou un programme à lui) peut le remplacer.
        assert_eq!(
            juger_lib("/home/alice/.steam/ubuntu12_32/gameoverlayrenderer.so", &systeme),
            Niveau::Eleve
        );
        // Hors paquet, dans /tmp, ou un nom nu que le système n'a pas : alerte.
        assert_eq!(juger_lib("/usr/lib/libinconnue.so", &systeme), Niveau::Eleve);
        assert_eq!(juger_lib("/tmp/libz.so", &systeme), Niveau::Eleve);
        assert_eq!(juger_lib("libz.so", &systeme), Niveau::Eleve);
        assert_eq!(juger_lib("./lib.so", &systeme), Niveau::Eleve);
        assert!(dossier_modifiable("/run/user/1000/x.so") && !dossier_modifiable("/usr/lib/x.so"));
        let a = avis_variable("LD_PRELOAD", "/tmp/libz.so", Niveau::Eleve);
        assert!(a.texte.contains("faussés"), "{}", a.texte);
    }

    /// Relecture adverse du lot 096, C4 : l'avis du démarrage lit /etc/ld.so.preload comme le bilan et le fils root
    /// (`machine::prechargement`, la lecture du chargeur de glibc), juge chaque nom tel qu'il est chargé, et ne se tait
    /// jamais sur une lecture ratée.
    #[test]
    fn preload_lu_comme_le_chargeur_au_demarrage() {
        use std::io::{Error, ErrorKind};
        let systeme = |p: &str| p == "/usr/lib/libgtk3-nocsd.so.0";
        let avis = |o: &[u8], entier: bool| avis_preload(Ok((o.to_vec(), entier)), &systeme);
        let niveau = |o: &[u8]| avis(o, true).map(|a| a.niveau);
        // Rien à charger : rien à dire.
        assert!(avis(b"", true).is_none());
        assert!(avis(b"# rien\n\n", true).is_none());
        assert!(avis_preload(Err(Error::from(ErrorKind::NotFound)), &systeme).is_none());
        // Une bibliothèque d'un paquet, avec une note en fin de ligne : une information, sans faux nom « # » ni « note ».
        let a = avis(b"/usr/lib/libgtk3-nocsd.so.0 # note\n", true);
        assert_eq!(a.as_ref().map(|a| a.niveau), Some(Niveau::Info));
        assert!(a.is_some_and(|a| !a.texte.contains("note")));
        // C1 : la deuxième ligne « # … » est chargée par le vrai chargeur (boucle de commentaires de glibc).
        let a = avis(
            b"# une note anodine assez longue pour couvrir la suite du fichier\n# /opt/x/evil.so\n",
            true,
        );
        assert_eq!(a.as_ref().map(|a| a.niveau), Some(Niveau::Eleve));
        assert!(a.is_some_and(|a| a.texte.contains("/opt/x/evil.so") && a.texte.contains("glibc")));
        // Coupé sur « : » comme le chargeur : le deuxième nom est jugé à part.
        assert_eq!(niveau(b"/usr/lib/libgtk3-nocsd.so.0:/tmp/x.so\n"), Some(Niveau::Eleve));
        // C2 : « …so.0\r » est un autre fichier que celui du paquet ; le « \r » se voit, rendu inoffensif.
        let a = avis(b"/usr/lib/libgtk3-nocsd.so.0\r\n", true);
        assert_eq!(a.as_ref().map(|a| a.niveau), Some(Niveau::Eleve));
        assert!(a.is_some_and(|a| a.texte.contains("libgtk3-nocsd.so.0\u{fffd}")));
        assert_eq!(juger_lib("/usr/lib/libgtk3-nocsd.so.0\r", &systeme), Niveau::Eleve);
        // Un octet hors UTF-8 ne rend plus l'avis muet ; le nom qui le porte ne peut venir d'aucun paquet connu.
        let a = avis(b"\xff/a.so\n/usr/lib/libgtk3-nocsd.so.0\n", true);
        assert_eq!(a.as_ref().map(|a| a.niveau), Some(Niveau::Eleve));
        assert!(a.is_some_and(|a| a.texte.contains("\u{fffd}/a.so")));
        // Illisible (droits, tube nommé) : « non vérifié », jamais un silence.
        let a = avis_preload(Err(Error::from(ErrorKind::PermissionDenied)), &systeme);
        assert_eq!(a.as_ref().map(|a| a.niveau), Some(Niveau::Moyen));
        assert!(a.is_some_and(|a| a.texte.contains("vérifié") || a.texte.contains("verified")));
        // Lu en partie : ce qui est lu est jugé, et la suite non lue est dite.
        let a = avis(b"/usr/lib/libgtk3-nocsd.so.0\n", false);
        assert_eq!(a.as_ref().map(|a| a.niveau), Some(Niveau::Moyen));
        assert!(a.is_some_and(|a| a.texte.contains("entier") || a.texte.contains("full")));
        assert_eq!(avis(b"# rien\n", false).map(|a| a.niveau), Some(Niveau::Moyen));
    }
}
