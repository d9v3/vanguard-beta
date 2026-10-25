//! Privilèges : fichiers secrets lisibles, groupes équivalents à root, sudo sans mot de passe, dossiers de commandes
//! modifiables par d'autres comptes, blocage des comptes et longueur des mots de passe (PAM). Fichiers secrets, sudo et
//! dossiers de commandes se vérifient comme sous macOS (machine/unix.rs).

use super::*;
#[cfg(test)]
use crate::machine::unix::{regles_nopasswd, secret_expose};

pub(super) fn fichiers_secrets() -> Vec<Constat> {
    super::super::unix::fichiers_secrets(
        Path::new(&home()),
        tr!(
            "Votre dossier personnel est lisible par les autres comptes de la machine.",
            "Your home folder is readable by the other accounts of the machine."
        ),
    )
}

/// Groupes qui donnent en pratique les droits root sans mot de passe.
pub(super) fn groupes_privilegies() -> Option<Constat> {
    let groupes = groupes_du_compte()?;
    let risques = groupes_a_risque(&groupes);
    Some(if risques.is_empty() {
        ok(
            "Groupes",
            tr!(
                "Aucun groupe qui donne les droits root sans mot de passe.",
                "No group gives root rights without a password."
            ),
        )
    } else {
        alerte(
            "Groupes",
            Niveau::Moyen,
            trf!(
                "Vous êtes dans le groupe {} : tout programme lancé par vous peut devenir root sans mot de passe (par un conteneur, une machine virtuelle ou le disque lui-même).", "You are in the {} group: any program you run can become root without a password (through a container, a virtual machine or the disk itself).",
                risques.join(", ")
            ),
        )
        .manuel(
            tr!("Si vous n'en avez pas besoin chaque jour, sortez du groupe (l'outil demandera alors sudo) ; sinon, gardez-le en connaissance de cause", "If you do not need it every day, leave the group (the tool will then ask for sudo); otherwise, keep it knowingly"),
            &[&format!("sudo gpasswd -d $USER {}", risques.first().copied().unwrap_or("docker"))],
        )
    })
}

/// Groupes de `id -nG` qui valent root : docker, lxd et incus-admin par un conteneur qui monte /, libvirt par une
/// machine virtuelle qui reçoit le disque de l'ordinateur, disk par la lecture et l'écriture directes du disque (donc
/// de /etc/shadow).
/// Les groupes du compte, séparés par des espaces comme `id -nG` les écrit : lus par getgroups et /etc/group.
/// Un groupe resté un numéro vient d'un annuaire (LDAP, sssd) que le programme, lié à musl, ne consulte pas :
/// seul `id` sait alors le nommer, et « docker » pourrait s'y cacher.
fn groupes_du_compte() -> Option<String> {
    natif::groupes()
        .filter(|g| !g.iter().any(|n| n.bytes().all(|o| o.is_ascii_digit())))
        .map(|g| g.join(" "))
        .or_else(|| sortie("id", &["-nG"]))
}

fn groupes_a_risque(groupes: &str) -> Vec<&str> {
    groupes
        .split_whitespace()
        .filter(|g| matches!(*g, "docker" | "lxd" | "incus-admin" | "libvirt" | "disk"))
        .collect()
}

pub(super) fn sudo_sans_mot_de_passe() -> Vec<Constat> {
    super::super::unix::sudo_sans_mot_de_passe(tout_permis())
}

/// Ce que risque ce système quand une règle sudo donne tout sans mot de passe.
pub(super) fn tout_permis() -> &'static str {
    tr!(
        "sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par vous peut devenir root.",
        "sudo without a password for ALL commands: any program you run can become root."
    )
}

/// Les dossiers où root cherche ses commandes : le `secure_path` de sudo des grandes distributions.
const DOSSIERS_DE_ROOT: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/snap/bin",
];

/// Sous Linux, un dossier de root qui appartient à un autre compte est fautif aussi.
pub(super) fn dossiers_de_commandes() -> Option<Constat> {
    crate::machine::unix::dossiers_de_commandes(DOSSIERS_DE_ROOT, Path::new(&home()), true)
}

/// Les fichiers de PAM où se règlent l'ouverture de session et les mots de passe : Arch et Fedora, puis Debian et
/// Ubuntu. Lisibles par tous.
const PAM: &[&str] = &[
    "/etc/pam.d/system-auth",
    "/etc/pam.d/password-auth",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-password",
];

/// La valeur d'un réglage « nom = valeur » d'un fichier de configuration (faillock.conf, pwquality.conf), la
/// dernière qui compte.
fn reglage(conf: &str, nom: &str) -> Option<u32> {
    conf.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.trim() == nom)
        .filter_map(|(_, v)| v.trim().parse().ok())
        .next_back()
}

/// L'option « nom=valeur » d'un module dans les lignes de PAM qui le chargent.
fn option_pam(lignes: &[&str], nom: &str) -> Option<u32> {
    lignes
        .iter()
        .flat_map(|l| l.split_whitespace())
        .filter_map(|mot| mot.strip_prefix(nom)?.strip_prefix('='))
        .filter_map(|v| v.parse().ok())
        .next_back()
}

/// Blocage des comptes après des mots de passe faux (pam_faillock, ou pam_tally2 sur les vieux systèmes), et longueur
/// minimale quand pam_pwquality vérifie les mots de passe. Des informations, sans correction automatique : PAM mal
/// réglé peut empêcher toute connexion, même celle de root. Les options de la ligne de PAM passent avant le fichier de
/// réglages ; sans l'un ni l'autre, les valeurs par défaut des modules (3 essais, 8 caractères). Sans pam_pwquality,
/// rien n'est dit de la longueur : elle n'est pas lue ailleurs.
pub(super) fn juger_pam(pam: &str, faillock: Option<&str>, pwquality: Option<&str>) -> Vec<Constat> {
    let actives: Vec<&str> = pam
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let charge = |module: &str| -> Vec<&str> { actives.iter().copied().filter(|l| l.contains(module)).collect() };
    let mut constats = Vec::new();
    let blocage = charge("pam_faillock.so");
    let essais = option_pam(&blocage, "deny")
        .or_else(|| faillock.and_then(|c| reglage(c, "deny")))
        .unwrap_or(3);
    if blocage.is_empty() && charge("pam_tally2.so").is_empty() {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Info,
                tr!(
                    "Aucun blocage après des mots de passe faux sur les comptes de cet ordinateur (pam_faillock n'est pas utilisé).",
                    "No lockout after wrong passwords on this computer's accounts (pam_faillock is not used)."
                ),
            )
            .manuel(
                tr!(
                    "L'activer avec l'outil de la distribution (Fedora : sudo authselect enable-feature with-faillock), une session root ouverte à côté pendant l'essai",
                    "Turn it on with the distribution's tool (Fedora: sudo authselect enable-feature with-faillock), with a root session open alongside while trying"
                ),
                &[],
            ),
        );
    } else if !blocage.is_empty() && essais == 0 {
        constats.push(alerte(
            "Comptes",
            Niveau::Info,
            tr!(
                "pam_faillock ne bloque jamais un compte (deny = 0) : les essais de mot de passe sont illimités.",
                "pam_faillock never locks an account (deny = 0): password attempts are unlimited."
            ),
        ));
    }
    let qualite = charge("pam_pwquality.so");
    if !qualite.is_empty() {
        let longueur = option_pam(&qualite, "minlen")
            .or_else(|| pwquality.and_then(|c| reglage(c, "minlen")))
            .unwrap_or(8);
        if longueur < 8 {
            constats.push(
                alerte(
                    "Comptes",
                    Niveau::Info,
                    trf!(
                        "Les mots de passe peuvent faire moins de 8 caractères (minimum : {longueur}).",
                        "Passwords can be shorter than 8 characters (minimum: {longueur})."
                    ),
                )
                .manuel(
                    tr!(
                        "Mettre « minlen = 8 » dans /etc/security/pwquality.conf (vaut au prochain changement de mot de passe)",
                        "Set “minlen = 8” in /etc/security/pwquality.conf (applies at the next password change)"
                    ),
                    &[],
                ),
            );
        }
    }
    constats
}

pub(super) fn pam() -> Vec<Constat> {
    let pam: String = PAM
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect::<Vec<_>>()
        .join("\n");
    if pam.is_empty() {
        return Vec::new();
    }
    juger_pam(
        &pam,
        std::fs::read_to_string("/etc/security/faillock.conf").ok().as_deref(),
        std::fs::read_to_string("/etc/security/pwquality.conf").ok().as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn droits_des_secrets() {
        assert!(!secret_expose(0o100_600));
        assert!(!secret_expose(0o40700));
        assert!(secret_expose(0o100_644));
        assert!(secret_expose(0o100_640));
    }

    #[test]
    fn blocage_et_longueur_d_apres_pam() {
        // Debian, Ubuntu : ni blocage ni pam_pwquality.
        let debian = "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n# auth required pam_faillock.so\n";
        let c = juger_pam(debian, None, None);
        assert_eq!(c.len(), 1);
        assert!(c[0].probleme == Some(Niveau::Info) && !c[0].correctif.as_ref().unwrap().automatique);
        // Arch : pam_faillock (3 essais par défaut), pam_pwquality absent.
        let arch = "auth required pam_faillock.so preauth\nauth [default=die] pam_faillock.so authfail\n";
        assert!(juger_pam(arch, None, None).is_empty());
        assert_eq!(juger_pam(arch, Some("# deny = 3\ndeny = 0\n"), None).len(), 1);
        // L'option de la ligne passe avant le fichier.
        let fedora =
            "auth required pam_faillock.so preauth deny=5\npassword requisite pam_pwquality.so local_users_only\n";
        assert!(juger_pam(fedora, Some("deny = 0\n"), None).is_empty());
        assert_eq!(juger_pam(fedora, None, Some("minlen = 6\n")).len(), 1);
        assert!(juger_pam(fedora, None, Some("# minlen = 6\n")).is_empty());
        let court = "auth required pam_faillock.so\npassword requisite pam_pwquality.so minlen=6\n";
        assert_eq!(juger_pam(court, None, Some("minlen = 12\n")).len(), 1);
    }

    #[test]
    fn groupes_qui_valent_root() {
        assert_eq!(
            groupes_a_risque("alice wheel libvirt kvm docker"),
            ["libvirt", "docker"]
        );
        assert_eq!(groupes_a_risque("alice wheel video audio kvm"), Vec::<&str>::new());
    }

    /// Sur cet ordinateur, les mêmes groupes que `id -nG`, quand il est là (l'ordre des groupes secondaires peut
    /// différer : seul compte ce qui y est).
    #[test]
    fn groupes_comme_id() {
        let Some(id) = crate::commande::lancer(Command::new("id").arg("-nG"), 5)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
        else {
            return crate::essais::saute("id absent");
        };
        let trier = |t: &str| {
            let mut v: Vec<String> = t.split_whitespace().map(str::to_string).collect();
            v.sort();
            v
        };
        assert_eq!(trier(&groupes_du_compte().unwrap()), trier(&id));
    }

    #[test]
    fn regles_sudo() {
        let omarchy = "User alice may run the following commands on portable:\n    (ALL) ALL\n    (root) NOPASSWD: /usr/bin/omarchy-dns Cloudflare, /usr/bin/omarchy-dns DHCP\n";
        assert_eq!(regles_nopasswd(omarchy), (vec![], 1));
        let tout = "    (ALL : ALL) NOPASSWD: ALL\n";
        assert_eq!(regles_nopasswd(tout).0.len(), 1);
    }

    #[test]
    fn reglages_par_defaut_de_sudo() {
        use crate::machine::unix::defauts_sudo;
        let liste = |defauts: &str| {
            format!(
                "Matching Defaults entries for alice on portable:\n    {defauts}\n\nRunas and Command-specific defaults for alice:\n    Defaults!/usr/bin/visudo env_keep+=\"SUDO_EDITOR EDITOR\"\n\nUser alice may run the following commands on portable:\n    (ALL) ALL\n"
            )
        };
        assert_eq!(
            defauts_sudo(&liste("secure_path=/usr/bin, passwd_tries=10")),
            (false, None)
        );
        assert_eq!(
            defauts_sudo(&liste("!authenticate, secure_path=/usr/bin")),
            (true, None)
        );
        assert_eq!(defauts_sudo(&liste("!authenticate, authenticate")), (false, None));
        assert_eq!(defauts_sudo(&liste("timestamp_timeout=-1")), (false, Some(-1.0)));
        assert_eq!(
            defauts_sudo(&liste("env_reset, timestamp_timeout=120")),
            (false, Some(120.0))
        );
        assert_eq!(defauts_sudo("    (ALL) ALL\n"), (false, None));
        // Liste coupée en fin de ligne après une virgule.
        let coupee = "Matching Defaults entries for alice on portable:\n    env_reset, timestamp_timeout=-1,\n    !authenticate\n\n";
        assert_eq!(defauts_sudo(coupee), (true, Some(-1.0)));
    }
}
