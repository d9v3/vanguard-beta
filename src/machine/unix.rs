//! Ce que Linux et macOS vérifient de la même façon : fichiers secrets lisibles par d'autres comptes, sudo sans mot de
//! passe, dossiers de commandes modifiables par d'autres comptes. Chaque système garde ses mots à lui (« la machine », « le Mac ») et ce qu'il vérifie en plus
//! (machine/linux/privileges.rs, machine/macos/privileges.rs).

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{Constat, alerte, ok, sortie};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Le chemin du programme `cmd` dans les dossiers de `path` (le PATH), comme `command -v` le trouve, sans lancer de
/// shell. Un nom avec une barre oblique est un chemin, pris tel quel. Le bit d'exécution compte : un fichier
/// ordinaire du même nom ne se lance pas.
pub(crate) fn chemin_dans(cmd: &str, path: &OsStr) -> Option<PathBuf> {
    let executable = |f: &Path| {
        f.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if cmd.is_empty() {
        return None;
    }
    if cmd.contains('/') {
        return executable(Path::new(cmd)).then(|| PathBuf::from(cmd));
    }
    // Une entrée vide du PATH veut dire le dossier courant pour le shell : on ne la suit pas, un programme posé là
    // par un tiers passerait pour installé.
    std::env::split_paths(path)
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join(cmd))
        .find(|f| executable(f))
}

/// Le programme `cmd` est-il dans le PATH, exécutable ?
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) fn present(cmd: &str) -> bool {
    chemin_dans(cmd, &std::env::var_os("PATH").unwrap_or_default()).is_some()
}

/// Fichiers qui contiennent des mots de passe ou des jetons d'accès, chemin relatif au dossier personnel.
const SECRETS: &[&str] = &[
    ".git-credentials",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".config/rclone/rclone.conf",
    ".gnupg",
];

/// Un secret est mal protégé si le groupe ou les autres comptes peuvent le lire (ou y entrer, pour un dossier).
pub(super) fn secret_expose(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Les fichiers secrets de `maison`, et le dossier personnel lui-même. `dossier_ouvert` : le texte de l'alerte quand
/// les autres comptes peuvent lire le dossier personnel (il nomme la machine ou le Mac).
pub(super) fn fichiers_secrets(maison: &Path, dossier_ouvert: &str) -> Vec<Constat> {
    let mut exposes = Vec::new();
    let mut commandes = Vec::new();
    let mut gestes = Vec::new();
    for nom in SECRETS {
        let chemin = maison.join(nom);
        // Droits du fichier lui-même, pas du lien : un lien symbolique (stow, chezmoi…) a toujours 777,
        // ce qui donnait une fausse alerte, jamais corrigée par le chmod.
        let Ok(meta) = std::fs::metadata(&chemin) else {
            continue;
        };
        if secret_expose(meta.permissions().mode()) {
            exposes.push(format!("~/{nom}"));
            commandes.push(format!("chmod {} ~/{nom}", if meta.is_dir() { "700" } else { "600" }));
            gestes.push(crate::optimiser::Geste::droits(&chemin));
        }
    }
    let mut constats = Vec::new();
    if !exposes.is_empty() {
        let cmds: Vec<&str> = commandes.iter().map(String::as_str).collect();
        constats.push(
            alerte(
                "Fichiers secrets",
                Niveau::Eleve,
                trf!(
                    "Lisible(s) par d'autres comptes : {} (mots de passe ou jetons d'accès).",
                    "Readable by other accounts: {} (passwords or access tokens).",
                    exposes.join(", ")
                ),
            )
            .corriger(
                tr!("Réserver ces fichiers à vous seul", "Restrict these files to you only"),
                &cmds,
            )
            .annulable(gestes),
        );
    }
    // Le dossier personnel lui-même (macOS le ferme d'origine, droits 750) : ouvert en lecture, il laisse voir tous tes
    // fichiers aux autres comptes.
    if std::fs::metadata(maison).is_ok_and(|m| m.permissions().mode() & 0o007 != 0) {
        constats.push(
            alerte("Fichiers secrets", Niveau::Info, dossier_ouvert)
                .corriger(
                    tr!(
                        "Fermer votre dossier personnel aux autres comptes",
                        "Close your home folder to the other accounts"
                    ),
                    &["chmod 750 ~"],
                )
                .annulable(vec![crate::optimiser::Geste::droits(maison)]),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            "Fichiers secrets",
            tr!(
                "Fichiers de mots de passe et de jetons protégés.",
                "Password and token files are protected."
            ),
        ));
    }
    constats
}

/// Règles « sudo sans mot de passe » : (règles qui donnent tout, règles limitées à des commandes précises).
pub(super) fn regles_nopasswd(liste: &str) -> (Vec<String>, usize) {
    let mut totales = Vec::new();
    let mut limitees = 0;
    for l in liste.lines().map(str::trim).filter(|l| l.contains("NOPASSWD:")) {
        let commandes = l.split_once("NOPASSWD:").map_or("", |(_, c)| c).trim();
        if commandes == "ALL" || commandes.starts_with("ALL,") {
            totales.push(l.to_string());
        } else {
            limitees += 1;
        }
    }
    (totales, limitees)
}

/// sudo sans mot de passe. `tout_permis` : le texte de l'alerte quand une règle donne toutes les commandes (il dit ce
/// que risque ce système).
/// Réglages par défaut de sudo qui valent pour ce compte (« Matching Defaults entries », première section de
/// `sudo -l`) : (sudo ne demande jamais le mot de passe, délai de mémorisation en minutes s'il est donné).
pub(super) fn defauts_sudo(liste: &str) -> (bool, Option<f64>) {
    let mut sans_mot_de_passe = false;
    let mut delai = None;
    let mut lignes = liste
        .lines()
        .skip_while(|l| !l.starts_with("Matching Defaults entries"));
    lignes.next();
    for ligne in lignes.take_while(|l| !l.trim().is_empty()) {
        // Une longue liste peut être coupée en fin de ligne après une virgule : elle est retirée.
        for reglage in ligne.split(", ").map(|r| r.trim().trim_end_matches(',')) {
            if reglage == "!authenticate" {
                sans_mot_de_passe = true;
            } else if reglage == "authenticate" {
                sans_mot_de_passe = false;
            } else if let Some(v) = reglage.strip_prefix("timestamp_timeout=") {
                delai = v.trim_matches('"').parse::<f64>().ok().or(delai);
            }
        }
    }
    (sans_mot_de_passe, delai)
}

pub(super) fn sudo_sans_mot_de_passe(tout_permis: &str) -> Vec<Constat> {
    // -n : jamais de demande de mot de passe. Sans règle NOPASSWD (ni sudo récent), la liste est refusée : rien à dire.
    let Some(liste) = sortie("sudo", &["-n", "-l"]) else {
        return Vec::new();
    };
    juger_sudo(&liste, tout_permis)
}

/// Le jugement de la sortie de `sudo -n -l` : séparé de sa lecture pour que le corpus de détection l'exerce.
pub(super) fn juger_sudo(liste: &str, tout_permis: &str) -> Vec<Constat> {
    let (totales, limitees) = regles_nopasswd(liste);
    let (jamais_demande, delai) = defauts_sudo(liste);
    let mut constats = Vec::new();
    if jamais_demande {
        constats.push(
            alerte(
                "Sudo",
                Niveau::Eleve,
                tr!(
                    "sudo ne demande jamais le mot de passe (« Defaults !authenticate ») : n'importe quel programme lancé par vous peut devenir root.",
                    "sudo never asks for the password (“Defaults !authenticate”): any program you run can become root."
                ),
            )
            .manuel(
                tr!(
                    "Retirer « !authenticate » des Defaults dans /etc/sudoers ou /etc/sudoers.d (toujours avec sudo visudo)",
                    "Remove “!authenticate” from the Defaults in /etc/sudoers or /etc/sudoers.d (always with sudo visudo)"
                ),
                &["sudo visudo"],
            ),
        );
    } else if let Some(minutes) = delai.filter(|&m| m < 0.0 || m > 60.0) {
        let message = if minutes < 0.0 {
            tr!(
                "sudo ne redemande jamais le mot de passe une fois tapé (« timestamp_timeout » négatif) : tout programme lancé ensuite dans ce terminal peut devenir root sans rien demander.",
                "sudo never asks for the password again once typed (negative “timestamp_timeout”): any program started later in that terminal can become root without asking."
            )
            .to_string()
        } else {
            trf!(
                "sudo garde le mot de passe {} minutes (« timestamp_timeout ») : un programme lancé pendant ce temps devient root sans rien demander.",
                "sudo keeps the password for {} minutes (“timestamp_timeout”): a program started during that time becomes root without asking.",
                minutes.round()
            )
        };
        constats.push(
            alerte("Sudo", if minutes < 0.0 { Niveau::Moyen } else { Niveau::Info }, message).manuel(
                tr!(
                    "Remettre le délai de sudo à 5 minutes, ou retirer « timestamp_timeout » (toujours avec sudo visudo)",
                    "Set sudo's delay back to 5 minutes, or remove “timestamp_timeout” (always with sudo visudo)"
                ),
                &["sudo visudo"],
            ),
        );
    }
    if !totales.is_empty() {
        constats.push(alerte("Sudo", Niveau::Eleve, tout_permis).manuel(
            tr!(
                "Retirer « NOPASSWD: » de cette règle dans /etc/sudoers.d (toujours avec sudo visudo, jamais à la main)",
                "Remove “NOPASSWD:” from this rule in /etc/sudoers.d (always with sudo visudo, never by hand)"
            ),
            &["sudo visudo"],
        ));
    } else if jamais_demande {
        // Déjà dit plus haut : pas de « demande toujours le mot de passe ».
    } else if limitees > 0 {
        constats.push(ok(
            "Sudo",
            trf!(
                "{limitees} règle(s) sudo sans mot de passe, limitée(s) à des commandes précises.",
                "{limitees} passwordless sudo rule(s), limited to specific commands."
            ),
        ));
    } else {
        constats.push(ok(
            "Sudo",
            tr!(
                "sudo demande toujours le mot de passe.",
                "sudo always asks for the password."
            ),
        ));
    }
    constats
}

// Lecture de sshd_config, la même sous Windows (OpenSSH de Microsoft) : `machine::sshd`.
pub(super) use super::sshd::{mots_de_passe_vides_sshd, partie_globale_sshd, valeur_sshd};

/// Configuration de sshd qui vaut pour toutes les connexions ; `None` si elle est réservée à root.
pub(super) fn configuration_sshd() -> Option<String> {
    // sshd garde la première valeur trouvée ; sur Arch, les fichiers .d sont inclus avant le reste.
    let mut fichiers: Vec<std::path::PathBuf> = std::fs::read_dir("/etc/ssh/sshd_config.d")
        .into_iter()
        .flatten()
        .flatten()
        .map(|f| f.path())
        .collect();
    fichiers.sort();
    fichiers.push("/etc/ssh/sshd_config".into());
    let mut conf = String::new();
    for f in &fichiers {
        match std::fs::read_to_string(f) {
            Ok(t) => conf += &partie_globale_sshd(&t),
            // Fedora et RHEL réservent la configuration à root : un fichier vide passerait pour les valeurs par
            // défaut (mot de passe permis), une fausse alerte.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(_) => {}
        }
    }
    Some(conf)
}

/// Serveur SSH du Mac (Remote Login) : ses mots de passe sont l'usage normal, pas une alerte. Seuls comptent un
/// compte sans mot de passe accepté et la connexion root. `None` : rien à dire.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn juger_sshd_mac(conf: &str) -> Option<Constat> {
    let ou = tr!(
        "dans /etc/ssh/sshd_config, puis couper et rallumer « Session à distance » (Réglages Système > Général > Partage)",
        "in /etc/ssh/sshd_config, then turn “Remote Login” off and on again (System Settings > General > Sharing)"
    );
    if mots_de_passe_vides_sshd(conf) {
        return Some(
            alerte(
                "SSH",
                Niveau::Critique,
                tr!(
                    "La session à distance accepte les comptes sans mot de passe : un tel compte s'ouvre depuis le réseau sans rien taper.",
                    "Remote Login accepts accounts without a password: such an account opens from the network without typing anything."
                ),
            )
            .manuel(trf!("Mettre « PermitEmptyPasswords no » {ou}", "Set “PermitEmptyPasswords no” {ou}"), &[]),
        );
    }
    (valeur_sshd(conf, "PermitRootLogin").as_deref() == Some("yes")).then(|| {
        alerte(
            "SSH",
            Niveau::Eleve,
            tr!(
                "La session à distance accepte une connexion en root : le compte qui a tous les droits s'ouvre depuis le réseau.",
                "Remote Login accepts root logins: the account with every right opens from the network."
            ),
        )
        .manuel(trf!("Mettre « PermitRootLogin no » {ou}", "Set “PermitRootLogin no” {ou}"), &[])
    })
}

/// Ports en écoute de `netstat -an -p tcp|udp` : « tcp4  0  0  *.22  *.*  LISTEN » → (adresse, port).
/// L'adresse et le port sont séparés par le dernier point (« 127.0.0.1.631 », « ::1.631 », « *.5900 »). Le netstat
/// des BSD, celui du Mac : ici pour que ses tests tournent aussi sous Linux.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn lire_netstat(sortie: &str, tcp: bool) -> Vec<(String, u16)> {
    sortie
        .lines()
        .filter(|l| {
            if tcp {
                l.contains("LISTEN")
            } else {
                l.starts_with("udp")
            }
        })
        .filter_map(|l| {
            let local = l.split_whitespace().nth(3)?;
            let (adresse, port) = local.rsplit_once('.')?;
            Some((adresse.to_string(), port.parse().ok()?))
        })
        .collect()
}

/// Un dossier de commandes tel qu'il est lu : son chemin réel, ses droits, son propriétaire, et si root y cherche ses
/// commandes.
pub(super) struct DossierDeCommandes {
    pub chemin: String,
    pub mode: u32,
    pub proprietaire: u32,
    pub de_root: bool,
}

/// Les dossiers de commandes modifiables par d'autres comptes. Quiconque peut écrire dans l'un d'eux y dépose un
/// programme du nom d'une vraie commande (« ls », « sudo ») : il tourne à la place de l'autre, avec les droits de qui
/// la tape, root compris après sudo. Un dossier ouvert à tous est fautif où qu'il soit ; un dossier de root qui
/// appartient à un autre compte que root l'est aussi. Le bit « sticky » (/tmp) n'y change rien : il empêche de
/// supprimer les fichiers des autres, pas d'en ajouter. Ailleurs, un dossier à un autre compte est voulu (Homebrew
/// sous Linux) : rien à dire. `proprietaire` : regarder aussi à qui sont les dossiers de root ; pas sous macOS, où
/// Homebrew prend /usr/local/bin à son compte sur les Mac Intel, et où sudo garde le PATH de la personne.
pub(super) fn juger_dossiers_de_commandes(dossiers: &[DossierDeCommandes], proprietaire: bool) -> Option<Constat> {
    let ouverts: Vec<&DossierDeCommandes> = dossiers.iter().filter(|d| d.mode & 0o002 != 0).collect();
    let a_d_autres: Vec<&DossierDeCommandes> = dossiers
        .iter()
        .filter(|d| proprietaire && d.de_root && d.proprietaire != 0 && d.mode & 0o002 == 0)
        .collect();
    if ouverts.is_empty() && a_d_autres.is_empty() {
        return None;
    }
    let niveau = if ouverts.iter().chain(&a_d_autres).any(|d| d.de_root) {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    let noms: Vec<&str> = ouverts.iter().chain(&a_d_autres).map(|d| d.chemin.as_str()).collect();
    let constat = alerte(
        "Privilèges",
        niveau,
        trf!(
            "D'autres comptes peuvent déposer des programmes dans {} : une fausse commande y prendrait la place de la vraie, avec vos droits, ou ceux de root après sudo.",
            "Other accounts can drop programs into {}: a fake command there would take the real one's place, with your rights, or root's after sudo.",
            noms.join(", ")
        ),
    );
    // Un dossier au bit « sticky » est un dossier temporaire (/tmp mis dans le PATH) : lui retirer l'écriture
    // casserait tous les programmes ; c'est de le sortir du PATH qu'il s'agit.
    let temporaires: Vec<&str> = ouverts
        .iter()
        .filter(|d| d.mode & 0o1000 != 0 && !d.de_root)
        .map(|d| d.chemin.as_str())
        .collect();
    if !temporaires.is_empty() {
        return Some(constat.manuel(
            trf!(
                "Sortir {} du PATH (fichier de démarrage du shell : ~/.bashrc, ~/.profile, /etc/profile.d) ; pour un autre dossier, sudo chmod o-w <dossier>",
                "Take {} out of PATH (shell startup file: ~/.bashrc, ~/.profile, /etc/profile.d); for another folder, sudo chmod o-w <folder>",
                temporaires.join(", ")
            ),
            &[],
        ));
    }
    Some(if a_d_autres.is_empty() {
        // Retirer l'écriture aux autres se défait exactement (chmod o+w) et ne gêne pas un dossier de commandes : rien
        // ne doit pouvoir y écrire sans en être propriétaire.
        let commandes: Vec<String> = ouverts
            .iter()
            .map(|d| format!("sudo chmod o-w {}", crate::commande::sh_chaine(&d.chemin)))
            .collect();
        constat.corriger(
            tr!(
                "Retirer l'écriture aux autres comptes (chmod o-w)",
                "Remove write access for other accounts (chmod o-w)"
            ),
            &commandes,
        )
    } else {
        // Rendre un dossier à root peut casser l'outil qui l'a pris : à décider soi-même.
        constat.manuel(
            tr!(
                "Rendre ces dossiers à root (sudo chown root:root <dossier> ; sudo chmod 755 <dossier>), après avoir vérifié quel outil les a changés",
                "Give these folders back to root (sudo chown root:root <folder>; sudo chmod 755 <folder>), after checking which tool changed them"
            ),
            &[],
        )
    })
}

/// Les dossiers de root (`racines`), puis ceux du PATH de la personne, sous leur chemin réel (« /bin » mène souvent à
/// « /usr/bin ») et sans doublon. Un dossier absent est sauté ; le dossier personnel aussi, qui est à la personne.
pub(super) fn dossiers_de_commandes(racines: &[&str], maison: &Path, proprietaire: bool) -> Option<Constat> {
    use std::os::unix::fs::MetadataExt;
    let maison = std::fs::canonicalize(maison).ok();
    let path = std::env::var("PATH").unwrap_or_default();
    let mut vus: Vec<DossierDeCommandes> = Vec::new();
    let candidats = racines
        .iter()
        .map(|d| (*d, true))
        .chain(path.split(':').filter(|d| d.starts_with('/')).map(|d| (d, false)));
    for (dossier, de_root) in candidats {
        let Ok(reel) = std::fs::canonicalize(dossier) else {
            continue;
        };
        if maison.as_ref().is_some_and(|m| reel.starts_with(m)) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&reel) else { continue };
        let chemin = reel.to_string_lossy().into_owned();
        match vus.iter_mut().find(|d| d.chemin == chemin) {
            Some(deja) => deja.de_root |= de_root,
            None => vus.push(DossierDeCommandes {
                chemin,
                mode: meta.mode(),
                proprietaire: meta.uid(),
                de_root,
            }),
        }
    }
    juger_dossiers_de_commandes(&vus, proprietaire)
}

#[cfg(test)]
mod tests_sshd {
    use super::*;

    #[test]
    fn serveur_ssh_du_mac() {
        // Mots de passe permis : l'usage normal de la session à distance, rien à dire.
        assert!(juger_sshd_mac("").is_none());
        assert!(juger_sshd_mac("PermitRootLogin prohibit-password\n").is_none());
        assert_eq!(
            juger_sshd_mac("PermitRootLogin yes\n").unwrap().probleme,
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger_sshd_mac("PermitEmptyPasswords yes\n").unwrap().probleme,
            Some(Niveau::Critique)
        );
        // Mots de passe coupés : un mot de passe vide ne sert à rien.
        let cles = "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords yes\n";
        assert!(juger_sshd_mac(cles).is_none());
    }
}

#[cfg(test)]
mod tests_dossiers_de_commandes {
    use super::*;

    #[test]
    fn dossiers_de_commandes_ouverts_a_d_autres() {
        let d = |chemin: &str, mode: u32, proprietaire: u32, de_root: bool| DossierDeCommandes {
            chemin: chemin.to_string(),
            mode: 0o40000 | mode,
            proprietaire,
            de_root,
        };
        let sains = [d("/usr/bin", 0o755, 0, true), d("/opt/outil/bin", 0o755, 1001, false)];
        assert!(juger_dossiers_de_commandes(&sains, true).is_none());
        // Ouvert à tous, même avec le bit sticky : corrigé par chmod o-w, le nom protégé.
        let ouvert = juger_dossiers_de_commandes(&[d("/usr/local/bin", 0o1777, 0, true)], true).unwrap();
        assert_eq!(ouvert.probleme, Some(Niveau::Eleve));
        assert_eq!(ouvert.correctif.unwrap().commandes, ["sudo chmod o-w '/usr/local/bin'"]);
        let a_moi = juger_dossiers_de_commandes(&[d("/opt/l'outil/bin", 0o777, 1000, false)], true).unwrap();
        assert_eq!(a_moi.probleme, Some(Niveau::Moyen));
        assert_eq!(
            a_moi.correctif.unwrap().commandes,
            ["sudo chmod o-w '/opt/l'\\''outil/bin'"]
        );
        // Un dossier de root à un autre compte : à décider soi-même.
        let pris = juger_dossiers_de_commandes(&[d("/usr/local/bin", 0o755, 1000, true)], true).unwrap();
        assert!(pris.probleme == Some(Niveau::Eleve) && !pris.correctif.unwrap().automatique);
        // /tmp dans le PATH : ouvert à tous mais temporaire, jamais chmod : à sortir du PATH.
        let tmp = juger_dossiers_de_commandes(&[d("/tmp", 0o1777, 0, false)], true).unwrap();
        assert!(!tmp.correctif.unwrap().automatique);
        // macOS : /usr/local/bin à la personne (Homebrew sur un Mac Intel), rien à dire.
        assert!(juger_dossiers_de_commandes(&[d("/usr/local/bin", 0o755, 501, true)], false).is_none());
    }
}

#[cfg(test)]
mod tests_netstat {
    use super::*;

    #[test]
    fn lecture_de_netstat() {
        let tcp = "Active Internet connections (including servers)\n\
                   Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
                   tcp4       0      0  *.22                   *.*                    LISTEN\n\
                   tcp4       0      0  127.0.0.1.631          *.*                    LISTEN\n\
                   tcp6       0      0  *.5900                 *.*                    LISTEN\n\
                   tcp4       0      0  10.0.0.20.51234        17.57.146.20.443       ESTABLISHED\n";
        assert_eq!(
            lire_netstat(tcp, true),
            [("*".into(), 22), ("127.0.0.1".into(), 631), ("*".into(), 5900)]
        );
        let udp = "udp4       0      0  *.5353                 *.*\nudp6       0      0  ::1.123  *.*\n";
        assert_eq!(lire_netstat(udp, false), [("*".into(), 5353), ("::1".into(), 123)]);
    }
}
