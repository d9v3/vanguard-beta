//! Audit de sécurité Linux (Arch/Omarchy), sans privilèges root.

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
pub(crate) mod dissimulation;
mod docker;
pub(crate) mod docker_api;
mod dpkg_verifier;
mod durcissement;
pub(crate) mod ecoute;
pub(crate) mod gvdb;
pub(crate) mod http_unix;
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
use maj::*;
use persistance::*;
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
    let racine = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
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
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .unwrap_or_default()
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
                Paquets::Apt => crate::commande::lancer_en_anglais(Command::new("dpkg").args(["-S", &*arg]), 30)
                    .filter(|r| r.code == Some(0))
                    .and_then(|r| paquet_dpkg(&r.sortie)),
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
            if let Some(r) = crate::commande::lancer_en_anglais(Command::new("pacman").arg("-Qo").args(fichiers), 60) {
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
            let programme = nomme
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
        Command::new("journalctl").args([
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
    let r = crate::commande::lancer(Command::new(cmd).args(args), secondes)?;
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

/// Le compte dont la session s'ouvre toute seule, et le fichier qui le dit, d'après les fichiers de GDM, SDDM et
/// LightDM donnés dans l'ordre où ils s'appliquent (le dernier l'emporte). `None` : personne.
fn ouverture_automatique_de(fichiers: &[(String, String)]) -> Option<(String, String)> {
    let mut trouve: Option<(String, String)> = None;
    for (chemin, texte) in fichiers {
        let compte = if chemin.contains("/gdm") {
            let daemon = |cle: &str| valeur_ini(texte, |s| s.eq_ignore_ascii_case("daemon"), cle);
            let oui = |cle: &str| daemon(cle).is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");
            let auto = oui("AutomaticLoginEnable").then(|| daemon("AutomaticLogin")).flatten();
            let minute = oui("TimedLoginEnable").then(|| daemon("TimedLogin")).flatten();
            Some(auto.or(minute).unwrap_or_default())
        } else if chemin.contains("sddm") {
            valeur_ini(texte, |s| s == "Autologin", "User")
        } else if chemin.contains("lightdm") {
            valeur_ini(
                texte,
                |s| s.starts_with("Seat") || s == "SeatDefaults",
                "autologin-user",
            )
        } else {
            None
        };
        match compte {
            Some(c) if !c.is_empty() => trouve = Some((c, chemin.clone())),
            Some(_) => trouve = None,
            None => {}
        }
    }
    trouve
}

/// Fichiers des gestionnaires de connexion, dans l'ordre où ils s'appliquent (le dernier l'emporte) : GDM
/// (custom.conf sur Ubuntu et Fedora, daemon.conf sur Debian) ; SDDM (réglages de la distribution sous /usr/lib, puis
/// /etc/sddm.conf.d, puis /etc/sddm.conf) ; LightDM (sous /usr/share, puis /etc/lightdm/lightdm.conf.d, puis
/// /etc/lightdm/lightdm.conf).
fn fichiers_de_connexion() -> Vec<(String, String)> {
    fn dossier(chemin: &str) -> Vec<std::path::PathBuf> {
        let mut dedans: Vec<std::path::PathBuf> = std::fs::read_dir(chemin)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "conf"))
            .collect();
        dedans.sort();
        dedans
    }
    let mut chemins: Vec<std::path::PathBuf> =
        ["/etc/gdm/custom.conf", "/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf"]
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
    chemins.extend(dossier("/usr/lib/sddm/sddm.conf.d"));
    chemins.extend(dossier("/etc/sddm.conf.d"));
    chemins.push("/etc/sddm.conf".into());
    chemins.extend(dossier("/usr/share/lightdm/lightdm.conf.d"));
    chemins.extend(dossier("/etc/lightdm/lightdm.conf.d"));
    chemins.push("/etc/lightdm/lightdm.conf".into());
    chemins
        .into_iter()
        .filter_map(|p| Some((p.to_string_lossy().into_owned(), std::fs::read_to_string(&p).ok()?)))
        .collect()
}

/// Session qui s'ouvre toute seule : sans disque chiffré, un ordinateur volé s'allume directement sur les fichiers.
/// Avec un disque chiffré (Omarchy), le mot de passe du disque protège : c'est dit, sans alerte.
fn ouverture_automatique() -> Option<Constat> {
    let fichiers = fichiers_de_connexion();
    let (compte, fichier) = ouverture_automatique_de(&fichiers)?;
    let gestes = gestes_d_ouverture(&fichiers, &fichier);
    Some(juger_ouverture_automatique(
        &compte,
        &fichier,
        racine_chiffree(),
        &gestes,
    ))
}

/// `gestes` : ceux qui coupent l'ouverture automatique (`gestes_d_ouverture`) ; vide, la correction reste à la main.
fn juger_ouverture_automatique(compte: &str, fichier: &str, chiffree: Option<bool>, gestes: &[Defense]) -> Constat {
    let compte = crate::ui::affichable(compte);
    if chiffree == Some(true) {
        return ok(
            "Comptes",
            trf!(
                "La session de « {compte} » s'ouvre toute seule, derrière le mot de passe du disque chiffré.",
                "“{compte}”'s session opens by itself, behind the encrypted disk's password."
            ),
        );
    }
    let constat = alerte(
        "Comptes",
        Niveau::Moyen,
        trf!(
            "La session de « {compte} » s'ouvre toute seule au démarrage, sans disque chiffré : un ordinateur volé s'allume directement sur vos fichiers.",
            "“{compte}”'s session opens by itself at startup, without an encrypted disk: a stolen computer boots straight into your files."
        ),
    )
    .manuel(
        trf!(
            "Couper l'ouverture automatique : réglages des utilisateurs du bureau (GNOME : Paramètres > Utilisateurs ; KDE : Écran de connexion), ou la ligne du compte dans {fichier}",
            "Turn off automatic login: the desktop's user settings (GNOME: Settings > Users; KDE: Login Screen), or the account's line in {fichier}"
        ),
        &[],
    );
    super::defense::corriger(
        constat,
        trf!(
            "Couper l'ouverture automatique (la ligne de {fichier} retirée ; le mot de passe sera demandé au prochain démarrage)",
            "Turn off automatic login (the line in {fichier} removed; the password will be asked at the next startup)"
        ),
        gestes,
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

/// La ligne de ce fichier du système (`gestes_unix::fichier_de_ligne_admis`) est-elle de celles qu'un geste de
/// défense retire : un préchargement (toute ligne de /etc/ld.so.preload, LD_PRELOAD, LD_AUDIT), une commande lancée
/// suspecte (`commande_suspecte`), ou l'ouverture automatique d'une session (`ouvre_une_session`) ? Revu par le fils
/// root avant de la retirer : seule une telle ligne part, jamais une autre que la liste lui aurait désignée.
pub(crate) fn ligne_suspecte(fichier: &str, ligne: &str) -> bool {
    if commentaire(ligne) {
        return false;
    }
    if fichier == "/etc/ld.so.preload" || ouvre_une_session(fichier, ligne) || definit_prechargement(ligne) {
        return true;
    }
    let cachee = |c: &str| {
        let programme = c
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|o| o == '"' || o == '\'');
        ["/home/", "/root/"].iter().any(|d| programme.starts_with(d)) && programme.contains("/.")
    };
    commande_suspecte(ligne, false).is_some()
        || commande_lancee(ligne).is_some_and(|c| commande_suspecte(&c, true).is_some() || cachee(&c))
}

/// La ligne ouvre-t-elle une session toute seule, d'après le gestionnaire de connexion du fichier (comme
/// `ouverture_automatique_de`) : GDM « AutomaticLoginEnable » ou « TimedLoginEnable » à vrai, SDDM « User= » d'un
/// compte, LightDM « autologin-user= » d'un compte.
pub(crate) fn ouvre_une_session(fichier: &str, ligne: &str) -> bool {
    let Some((cle, valeur)) = ligne.trim().split_once('=') else {
        return false;
    };
    let (cle, valeur) = (cle.trim(), valeur.trim());
    if fichier.contains("/gdm") {
        (cle.eq_ignore_ascii_case("AutomaticLoginEnable") || cle.eq_ignore_ascii_case("TimedLoginEnable"))
            && (valeur.eq_ignore_ascii_case("true") || valeur == "1")
    } else if fichier.contains("sddm") {
        cle.eq_ignore_ascii_case("User") && !valeur.is_empty()
    } else if fichier.contains("lightdm") {
        cle.eq_ignore_ascii_case("autologin-user") && !valeur.is_empty()
    } else {
        false
    }
}

/// Les gestes qui coupent l'ouverture automatique : retirer de `fichier` chaque ligne qui l'allume (lignes coupées
/// au seul « \n », comme les relit le fils root, qui en recalcule l'empreinte). Seulement si `fichier` est de ceux
/// qu'un geste a le droit de modifier, et si, ces lignes parties, plus aucun fichier n'ouvre de session : sinon un
/// réglage d'avant (sous /usr, dans un autre fichier) reprendrait la main sans rien dire, et la correction reste à
/// la main.
fn gestes_d_ouverture(fichiers: &[(String, String)], fichier: &str) -> Vec<Defense> {
    let Some((_, texte)) = fichiers.iter().rev().find(|(c, _)| c == fichier) else {
        return Vec::new();
    };
    let mut lignes: Vec<&str> = Vec::new();
    for l in texte.split('\n') {
        if !commentaire(l) && ouvre_une_session(fichier, l) && !lignes.contains(&l) {
            lignes.push(l);
        }
    }
    let Some(gestes) = lignes
        .iter()
        .map(|l| super::defense::retirer_ligne(fichier, l))
        .collect::<Option<Vec<Defense>>>()
    else {
        return Vec::new();
    };
    let apres: Vec<(String, String)> = fichiers
        .iter()
        .map(|(c, t)| {
            if c == fichier {
                let garde: Vec<&str> = t.split('\n').filter(|l| !lignes.contains(l)).collect();
                (c.clone(), garde.join("\n"))
            } else {
                (c.clone(), t.clone())
            }
        })
        .collect();
    if gestes.is_empty() || ouverture_automatique_de(&apres).is_some() {
        return Vec::new();
    }
    gestes
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
    let source = sortie("findmnt", &["-no", "SOURCE", "/"])?;
    // Btrfs affiche le sous-volume : « /dev/mapper/root[/@] ».
    let peripherique = source.trim().split('[').next()?.to_string();
    if !peripherique.starts_with("/dev/") {
        return None;
    }
    // -s : la chaîne inverse, du volume monté jusqu'au disque (lvm → crypt → part → disk).
    let chaine = sortie("lsblk", &["-nso", "TYPE", &peripherique])?;
    Some(chaine.lines().any(|l| l.trim() == "crypt"))
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
    let Ok(passwd) = std::fs::read_to_string("/etc/passwd") else {
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
        Command::new("nmcli").args([
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
        let ouvert =
            crate::commande::lancer_en_anglais(Command::new("nmcli").args(["-t", "connection", "show", &uuid]), 10)
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
            Some(lire("Timeout").and_then(|m| m.parse::<u64>().ok()).unwrap_or(5) * 60)
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
    let amd = std::fs::read_to_string("/proc/cpuinfo").is_ok_and(|c| c.contains("AuthenticAMD"));
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

    #[test]
    fn ouverture_de_session_automatique() {
        let f = |c: &str, t: &str| (c.to_string(), t.to_string());
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
        // Jugement : disque chiffré, sans alerte ; sinon moyen.
        assert!(
            juger_ouverture_automatique("alice", "x", Some(true), &[])
                .probleme
                .is_none()
        );
        assert_eq!(
            juger_ouverture_automatique("alice", "x", Some(false), &[]).probleme,
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger_ouverture_automatique("alice", "x", None, &[]).probleme,
            Some(Niveau::Moyen)
        );
        // Sans geste : à la main.
        let k = juger_ouverture_automatique("alice", "x", None, &[]).correctif.unwrap();
        assert!(!k.automatique);
    }

    /// D7a : l'ouverture automatique se coupe par un geste seulement si toutes ses lignes sont dans un fichier admis
    /// et que, parties, plus rien n'ouvre de session.
    #[test]
    fn ouverture_automatique_coupee_par_geste() {
        const AUCUN: [Defense; 0] = [];
        let f = |chemin: &str, texte: &str| (chemin.to_string(), texte.to_string());
        let empreinte = crate::machine::defense_eleve::empreinte_de_ligne;
        // SDDM d'Omarchy : la ligne du compte, telle quelle (fin « \r » comprise, comme la relit le fils root).
        let sddm = [f(
            "/etc/sddm.conf.d/autologin.conf",
            "[Autologin]\nUser=alice\r\nSession=omarchy.desktop\n",
        )];
        let g = gestes_d_ouverture(&sddm, "/etc/sddm.conf.d/autologin.conf");
        let [Defense::RetirerLigne(lue, fichier)] = g.as_slice() else {
            panic!("un geste attendu : {g:?}")
        };
        assert_eq!(*lue, empreinte(b"User=alice\r"));
        assert_eq!(fichier.octets(), b"/etc/sddm.conf.d/autologin.conf");
        let k = juger_ouverture_automatique("alice", "/etc/sddm.conf.d/autologin.conf", None, &g)
            .correctif
            .unwrap();
        assert!(k.automatique);
        assert!(matches!(k.defaire, crate::machine::Defaire::Gestes(ref v) if v.len() == 1));
        // GDM : les deux interrupteurs, deux gestes ; le compte nommé reste.
        let gdm = [f(
            "/etc/gdm3/custom.conf",
            "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\nTimedLoginEnable=true\nTimedLogin=bob\n",
        )];
        assert_eq!(gestes_d_ouverture(&gdm, "/etc/gdm3/custom.conf").len(), 2);
        // Un réglage de la distribution (sous /usr) reprendrait la main : rien d'automatique.
        let dessous = [
            f("/usr/lib/sddm/sddm.conf.d/auto.conf", "[Autologin]\nUser=alice\n"),
            f("/etc/sddm.conf", "[Autologin]\nUser=alice\n"),
        ];
        assert_eq!(gestes_d_ouverture(&dessous, "/etc/sddm.conf"), AUCUN);
        // Fichier hors de la liste admise : à la main.
        let ailleurs = [f("/usr/lib/sddm/sddm.conf.d/auto.conf", "[Autologin]\nUser=alice\n")];
        assert_eq!(
            gestes_d_ouverture(&ailleurs, "/usr/lib/sddm/sddm.conf.d/auto.conf"),
            AUCUN
        );
        // Un nom de fichier hostile n'est jamais admis.
        let hostile = [f("/etc/sddm.conf.d/a;rm -rf.conf", "[Autologin]\nUser=alice\n")];
        assert_eq!(gestes_d_ouverture(&hostile, "/etc/sddm.conf.d/a;rm -rf.conf"), AUCUN);
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
            let _ = ouverture_automatique_de(&[(chemin, t.clone())]);
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
