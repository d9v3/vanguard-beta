//! Réparations courantes, pour chaque système : réseau, navigation détournée, pare-feu, antivirus, fichiers
//! système, disque, place, mises à jour, heure.
//! Chaque réparation est montrée (pourquoi, durée, commandes) puis confirmée avant d'être lancée ; celles qui
//! modifient le système proposent d'abord un point de restauration.

use std::net::IpAddr;

use crate::machine;
use crate::ui::*;

pub struct Reparation {
    pub titre: &'static str,
    pub pourquoi: String,
    pub duree: &'static str,
    pub commandes: Vec<String>,
    /// Réparation refusée dans ce contexte (ex. : elle couperait la connexion à distance en cours).
    pub bloquee: Option<&'static str>,
    /// Rien à réparer : la vérification faite en ouvrant le menu n'a rien trouvé.
    pub inutile: Option<String>,
    /// Modifie le système : on propose un point de restauration avant (snapper, timeshift, Windows).
    pub restauration: bool,
    /// Un autre outil de Vanguard fait la réparation (Disque plein : Nettoyer), à la place des commandes.
    pub ouvrir: Option<fn()>,
}

fn rep(titre: &'static str, pourquoi: impl Into<String>, duree: &'static str, commandes: &[&str]) -> Reparation {
    Reparation {
        titre,
        pourquoi: pourquoi.into(),
        duree,
        commandes: commandes.iter().map(std::string::ToString::to_string).collect(),
        bloquee: None,
        inutile: None,
        restauration: false,
        ouvrir: None,
    }
}

/// Disque plein : l'outil Nettoyer, qui mesure ce que libère chaque élément et laisse choisir.
fn disque_plein() -> Reparation {
    let mut r = rep(
        tr!("Disque plein", "Disk full"),
        tr!(
            "Ouvre « Nettoyer le système » : la place que libère chaque élément (caches, fichiers temporaires, paquets, corbeille…), à cocher.",
            "Opens “Clean up the system”: the space each item frees (caches, temporary files, packages, trash…), to check."
        ),
        tr!("une minute", "one minute"),
        &[],
    );
    r.ouvrir = Some(crate::nettoyer::menu);
    r
}

impl Reparation {
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn avec_restauration(mut self) -> Self {
        self.restauration = true;
        self
    }
}

/// Une adresse vers laquelle le fichier hosts ne devrait jamais envoyer un nom : ni bouclage ni « 0.0.0.0 »
/// (listes de blocage), ni réseau local (NAS, imprimante nommés à la main), ni « fe00::0 ip6-localnet ». Il reste
/// les adresses d'Internet, selon la règle commune (`socle::adresses`) : une adresse d'exemple (203.0.113.x) y
/// compte, comme pour le blocage, au lieu d'être tue ici seulement.
fn publique(ip: IpAddr) -> bool {
    crate::socle::adresses::sur_internet(ip)
}

/// Lignes du fichier hosts qui envoient un nom vers une adresse d'Internet (adresse telle qu'écrite, noms).
/// Un malware s'en sert pour détourner une banque, un antivirus ou les mises à jour vers son serveur. Les noms,
/// écrits par lui, sont seulement montrés : rendus inoffensifs. L'adresse, qui sert aux commandes, en est une.
fn redirections(hosts: &str) -> Vec<(String, String)> {
    hosts
        .lines()
        .filter_map(|l| {
            let mut mots = l.split('#').next()?.split_whitespace();
            let ip = mots.next()?;
            // L'adresse d'abord : un fichier hosts de liste de blocage compte des millions de lignes « 0.0.0.0 nom »,
            // et l'ouverture du menu ne doit pas en assembler les noms un par un.
            if !ip.parse().is_ok_and(publique) {
                return None;
            }
            let noms = mots.collect::<Vec<_>>().join(" ");
            (!noms.is_empty()).then(|| (ip.to_string(), affichable(&noms)))
        })
        .collect()
}

/// Les adresses détournées, en expression régulière (« 1\.2\.3\.4|5\.6\.7\.8 »), pour sed et PowerShell.
fn motif_adresses(lignes: &[(String, String)]) -> String {
    let mut ips: Vec<String> = lignes.iter().map(|(ip, _)| ip.replace('.', r"\.")).collect();
    ips.sort();
    ips.dedup();
    ips.join("|")
}

/// Résumé lisible : « 1.2.3.4 → banque.fr, 5.6.7.8 → update.microsoft.com (et 3 autre(s)) ».
fn resume_redirections(lignes: &[(String, String)]) -> String {
    let textes: Vec<String> = lignes.iter().map(|(ip, noms)| format!("{ip} → {noms}")).collect();
    resume(&textes, 3, ", ")
}

/// Texte entre apostrophes pour bash ('…') ou PowerShell ('…').
#[cfg(unix)]
fn entre_apostrophes(t: &str) -> String {
    crate::commande::sh_chaine(t)
}
#[cfg(windows)]
fn entre_apostrophes(t: &str) -> String {
    crate::commande::ps_chaine(t)
}

/// Outil et commande du point de restauration, s'il y en a un de configuré.
#[cfg(target_os = "linux")]
pub(crate) fn point_restauration(titre: &str) -> Option<(&'static str, String)> {
    let description = entre_apostrophes(&trf!("Vanguard : avant « {titre} »", "Vanguard: before “{titre}”"));
    if present("snapper") && std::path::Path::new("/etc/snapper/configs/root").is_file() {
        Some((
            "snapper",
            format!("sudo snapper --config root create --cleanup-algorithm number --description {description}"),
        ))
    } else if present("timeshift") && std::path::Path::new("/etc/timeshift/timeshift.json").is_file() {
        Some((
            "timeshift",
            format!("sudo timeshift --create --scripted --comments {description}"),
        ))
    } else {
        None
    }
}

/// Code de sortie de la fenêtre administrateur quand la personne refuse de continuer sans point de restauration :
/// Vanguard le distingue d'un échec, pour dire pourquoi rien n'a changé.
#[cfg(windows)]
pub(crate) const SANS_POINT_ARRETE: i32 = 5;

/// Windows : la commande va dans la même fenêtre administrateur que la réparation (une seule demande).
/// Protection du système coupée sur C: : on le dit et on demande s'il faut continuer sans.
/// Windows ne crée qu'un point par 24 h : il l'écrit alors en avertissement, le plus récent sert.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sur Linux, où l'outil peut manquer
pub(crate) fn point_restauration(titre: &str) -> Option<(&'static str, String)> {
    // Le titre ne voyage plus : la correction native le fait par SRSetRestorePoint (eleve.rs), et le script
    // PowerShell, quand il reste nécessaire, reçoit la forme ci-dessous par `corrections::en_powershell`.
    let _ = titre;
    Some(("Windows", crate::machine::windows::corrections::POINT.to_string()))
}

/// La forme PowerShell du point de restauration, pour le script administrateur (liste mêlée à du PowerShell).
#[cfg(windows)]
pub(crate) fn point_restauration_powershell() -> String {
    let description = entre_apostrophes(tr!("Vanguard : avant une correction", "Vanguard: before a fix"));
    {
        trf!(
            "try {{ Checkpoint-Computer -Description {description} -RestorePointType MODIFY_SETTINGS }} \
             catch {{ Write-Host 'Point de restauration impossible (protection du système désactivée sur C: ?).' -ForegroundColor Red; \
             if ((Read-Host 'Continuer sans point de restauration ? [o/N]') -notin 'o', 'y') {{ exit {SANS_POINT_ARRETE} }} }}",
            "try {{ Checkpoint-Computer -Description {description} -RestorePointType MODIFY_SETTINGS }} \
             catch {{ Write-Host 'Restore point not possible (system protection turned off on C:?).' -ForegroundColor Red; \
             if ((Read-Host 'Continue without a restore point? [y/N]') -notin 'y', 'o') {{ exit {SANS_POINT_ARRETE} }} }}"
        )
    }
}

/// SID du compte de la personne (« S-1-5-21-… »). La fenêtre administrateur peut s'ouvrir sous un autre compte
/// (mot de passe d'un autre administrateur, cas courant quand on dépanne la famille) : son HKCU est alors celui de
/// cet autre compte, et un réglage de la personne doit s'écrire dans sa propre ruche, sous HKEY_USERS.
#[cfg(windows)]
pub(crate) fn sid_de_la_personne() -> Option<String> {
    crate::machine::windows::processus::sid()
}

/// Chemin PowerShell d'une clé du HKCU de la personne, pour la fenêtre administrateur. Sans SID, le HKCU de la
/// fenêtre : le bon quand la personne est elle-même administratrice.
#[cfg(windows)]
pub(crate) fn hkcu_de_la_personne(sid: Option<&str>, chemin: &str) -> String {
    match sid {
        Some(sid) => format!(r"Registry::HKEY_USERS\{sid}\{chemin}"),
        None => format!(r"HKCU:\{chemin}"),
    }
}

/// Connecté à cette machine à distance (SSH) : une réparation du réseau couperait la session.
#[cfg(unix)]
fn session_ssh() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some()
}

/// Relancer le réseau couperait une session SSH : la réparation est alors bloquée.
#[cfg(unix)]
fn sauf_en_ssh(r: &mut Reparation) {
    if session_ssh() {
        r.bloquee = Some(tr!(
            "vous êtes connecté par SSH : relancer le réseau couperait votre connexion",
            "you are connected over SSH: restarting the network would cut your connection"
        ));
    }
}

/// Ce que dit « Navigation détournée » des redirections trouvées dans le fichier hosts.
fn constat_hosts(detournees: &[(String, String)]) -> String {
    trf!("fichier hosts : {}", "hosts file: {}", resume_redirections(detournees))
}

/// « Navigation détournée », sur chaque système : `pourquoi` dit ce qu'elle fait et ce qui a été trouvé.
fn navigation_detournee(pourquoi: String, commandes: Vec<String>) -> Reparation {
    let titre = tr!(
        "Navigation détournée (proxy, fichier hosts)",
        "Hijacked browsing (proxy, hosts file)"
    );
    Reparation {
        commandes,
        ..rep(titre, pourquoi, tr!("quelques secondes", "a few seconds"), &[])
    }
}

/// « Navigation détournée » sous Linux et macOS : un point de restauration si le fichier hosts change, « rien à
/// faire » sans commande.
#[cfg(unix)]
fn finir_navigation(pourquoi: String, commandes: Vec<String>, hosts: bool) -> Reparation {
    let mut r = navigation_detournee(pourquoi, commandes);
    r.restauration = hosts;
    if r.commandes.is_empty() {
        r.inutile = Some(String::from(tr!(
            "ni redirection dans le fichier hosts, ni proxy imposé",
            "no redirection in the hosts file, no forced proxy"
        )));
    }
    r
}

#[cfg(target_os = "linux")]
use crate::machine::linux::natif::present_systeme as present;

/// Montre où sont définies les variables de proxy. -i : HTTP_PROXY et HTTPS_PROXY, en majuscules, comptent aussi
/// (lues plus bas dans les deux casses).
#[cfg(target_os = "linux")]
const TROUVER_PROXY: &str = "grep -insE '^[^#]*(https?|all|ftp)_proxy='";

/// Variables de proxy de l'environnement (`lire` en donne la valeur), en « nom=valeur ». La valeur vient d'un
/// fichier de démarrage que tout programme de la session peut écrire : montrée rendue inoffensive.
#[cfg(target_os = "linux")]
fn variables_proxy(lire: impl Fn(&str) -> Option<String>) -> Vec<String> {
    ["http_proxy", "https_proxy", "all_proxy", "ftp_proxy"]
        .iter()
        .filter_map(|v| {
            let valeur = lire(v).or_else(|| lire(&v.to_uppercase()))?;
            (!valeur.is_empty()).then(|| format!("{v}={}", affichable(&valeur)))
        })
        .collect()
}

/// Proxy imposé et redirections du fichier hosts : les deux façons classiques de détourner la navigation.
#[cfg(target_os = "linux")]
fn navigation() -> Reparation {
    let detournees = redirections(&std::fs::read_to_string("/etc/hosts").unwrap_or_default());
    let variables = variables_proxy(|v| std::env::var(v).ok());
    // Lu dans dconf et les schémas compilés ; gsettings en secours.
    let gnome = crate::machine::linux::dconf::gsettings_get("org.gnome.system.proxy", "mode")
        .or_else(|| {
            present("gsettings")
                .then(|| {
                    crate::commande::lancer(
                        std::process::Command::new("gsettings").args(["get", "org.gnome.system.proxy", "mode"]),
                        5,
                    )
                })
                .flatten()
                .map(|r| r.sortie)
        })
        .map(|s| s.trim().trim_matches('\'').to_string())
        .filter(|m| m == "manual" || m == "auto");

    let mut constats = Vec::new();
    let mut commandes = Vec::new();
    if !detournees.is_empty() {
        constats.push(constat_hosts(&detournees));
        commandes.push("sudo cp -p /etc/hosts /etc/hosts.vanguard-$(date +%Y%m%d-%H%M%S)".to_string());
        commandes.push(format!(
            "sudo sed -i -E 's/^([[:space:]]*({})[[:space:]])/# Vanguard : \\1/' /etc/hosts",
            motif_adresses(&detournees)
        ));
    }
    if let Some(mode) = &gnome {
        constats.push(trf!(
            "proxy du bureau en mode « {mode} »",
            "desktop proxy in “{mode}” mode"
        ));
        commandes.push("gsettings set org.gnome.system.proxy mode 'none'".to_string());
    }
    if !variables.is_empty() {
        // Définies dans un fichier de démarrage : on montre où, c'est à retirer à la main (peut être voulu).
        constats.push(trf!(
            "variables {} (à retirer à la main du fichier montré)",
            "{} variables (to remove by hand from the file shown)",
            variables.join(", ")
        ));
        commandes.push(
            format!("{TROUVER_PROXY} /etc/environment /etc/profile /etc/profile.d/* ~/.profile ~/.bashrc ~/.bash_profile ~/.zshrc ~/.config/environment.d/*; true"),
        );
    }
    finir_navigation(
        trf!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe le proxy imposé. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. Trouvé : {}.",
            "Comments out the hosts file lines that send a site to an Internet address (a copy is kept) and turns off the forced proxy. Block lists (0.0.0.0) and local network devices are left alone. Found: {}.",
            constats.join(" ; ")
        ),
        commandes,
        !detournees.is_empty(),
    )
}

/// ClamAV absent : où le menu propose de l'installer (Virus et logiciels espions › Analyse antivirus).
#[cfg(target_os = "linux")]
fn sans_clamav() -> &'static str {
    tr!(
        "ClamAV n'est pas installé : l'analyse antivirus (menu 6.1, rapide ou complète) propose de l'installer",
        "ClamAV is not installed: the antivirus scan (menu 6.1, quick or full) offers to install it"
    )
}

/// Signatures ClamAV : téléchargement immédiat, puis mise à jour automatique.
#[cfg(target_os = "linux")]
fn antivirus(systemd: bool) -> Reparation {
    let mut r = rep(
        tr!("Antivirus pas à jour", "Antivirus out of date"),
        "",
        tr!("une minute", "one minute"),
        &[],
    );
    if !present("clamscan") {
        r.inutile = Some(sans_clamav().into());
        return r;
    }
    let derniere = ["daily.cld", "daily.cvd"]
        .iter()
        .filter_map(|f| {
            std::fs::metadata(std::path::Path::new("/var/lib/clamav").join(f))
                .ok()?
                .modified()
                .ok()
        })
        .max()
        .and_then(|m| m.elapsed().ok())
        .map_or(tr!("jamais", "never").to_string(), |d| match d.as_secs() / 86_400 {
            0 => tr!("aujourd'hui", "today").to_string(),
            1 => tr!("hier", "yesterday").to_string(),
            n => trf!("il y a {n} jours", "{n} days ago"),
        });
    r.pourquoi = trf!(
        "Télécharge les dernières signatures de virus de ClamAV et active leur mise à jour automatique. Dernière mise à jour : {derniere}.",
        "Downloads the latest ClamAV virus signatures and turns on their automatic update. Last update: {derniere}."
    );
    if systemd {
        // Le service, s'il tourne, verrouille la base : on l'arrête le temps du téléchargement.
        r.commandes = vec![
            "sudo systemctl stop clamav-freshclam.service 2>/dev/null; sudo freshclam".into(),
            "if systemctl cat clamav-freshclam.service >/dev/null 2>&1; then sudo systemctl enable --now clamav-freshclam.service; fi".into(),
        ];
    } else {
        r.commandes = vec!["sudo freshclam".into()];
    }
    r
}

/// firewalld sur cette machine.
#[cfg(target_os = "linux")]
#[derive(Clone, Default)]
enum Firewalld {
    /// Pas installé, ou masqué (coupé exprès).
    #[default]
    Absent,
    Arrete,
    /// En service, avec sa zone par défaut si elle se lit.
    Actif(Option<String>),
}

/// ufw sur cette machine.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Default)]
enum Ufw {
    #[default]
    Absent,
    /// Installé, mais coupé ou réglé pour tout laisser entrer.
    Installe,
    /// Actif, et refuse les connexions entrantes.
    Protege,
}

/// La zone par défaut de firewalld (`firewall-cmd --get-default-zone`), lue dans sa configuration : celle de
/// l'administrateur, puis celle du paquet (firewalld 2 y met ses valeurs d'usine). `--set-default-zone` l'écrit
/// aussitôt, la zone en service est donc celle-là. `None` sans fichier ni clé lisibles : firewall-cmd, qui
/// demande au service, prend alors le relais.
#[cfg(target_os = "linux")]
fn zone_firewalld(racine: &std::path::Path) -> Option<String> {
    ["etc/firewalld/firewalld.conf", "usr/lib/firewalld/firewalld.conf"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(racine.join(f)).ok())
        .find_map(|t| {
            t.lines()
                .find_map(|l| l.trim().strip_prefix("DefaultZone=").map(str::trim))
                .filter(|z| !z.is_empty())
                .map(str::to_string)
        })
}

/// L'unité est-elle masquée par l'administrateur (`systemctl is-enabled` dit « masked ») : son nom dans
/// /etc/systemd/system est un lien vers /dev/null. Un masque posé pour ce démarrage seulement, dans /run, se dit
/// « masked-runtime » : il passe au prochain démarrage, la réparation reste proposée.
#[cfg(target_os = "linux")]
fn masquee_par_l_administrateur(racine: &std::path::Path, unite: &str) -> bool {
    std::fs::read_link(racine.join("etc/systemd/system").join(unite))
        .is_ok_and(|cible| cible == std::path::Path::new("/dev/null"))
}

/// Ce que la réparation du pare-feu Linux sait de la machine, lu à l'ouverture du menu.
#[cfg(target_os = "linux")]
#[derive(Clone, Default)]
struct EtatPareFeu {
    firewalld: Firewalld,
    ufw: Ufw,
    /// nftables ou iptables en service : des règles écrites à la main.
    autre: Option<&'static str>,
    gestion: Option<machine::linux::Paquets>,
    ssh: bool,
}

#[cfg(target_os = "linux")]
impl EtatPareFeu {
    fn lire(gestion: Option<machine::linux::Paquets>) -> Self {
        use crate::machine::linux::{politique_ufw, service_actif, ufw_actif};
        use std::process::Command;
        let firewalld = if service_actif("firewalld") {
            let zone = zone_firewalld(std::path::Path::new("/")).or_else(|| {
                crate::commande::lancer(Command::new("firewall-cmd").arg("--get-default-zone"), 10)
                    .map(|z| z.sortie.trim().to_string())
            });
            Firewalld::Actif(zone)
        } else if present("firewalld") && !masquee_par_l_administrateur(std::path::Path::new("/"), "firewalld.service")
        {
            Firewalld::Arrete
        } else {
            Firewalld::Absent
        };
        let politique = std::fs::read_to_string("/etc/default/ufw")
            .ok()
            .and_then(|t| politique_ufw(&t));
        let ufw = if ufw_actif() && politique.as_deref() != Some("ACCEPT") {
            Ufw::Protege
        } else if present("ufw") {
            Ufw::Installe
        } else {
            Ufw::Absent
        };
        EtatPareFeu {
            firewalld,
            ufw,
            autre: ["nftables", "iptables"].into_iter().find(|s| service_actif(s)),
            gestion,
            ssh: session_ssh(),
        }
    }
}

/// Pare-feu coupé ou qui laisse tout entrer : on garde celui qui est installé (firewalld), sinon ufw.
#[cfg(target_os = "linux")]
fn pare_feu(e: &EtatPareFeu) -> Reparation {
    let mut r = rep(
        tr!("Pare-feu coupé ou ouvert", "Firewall off or open"),
        "",
        tr!("quelques secondes", "a few seconds"),
        &[],
    );
    // Une règle de plus ou une zone changée peut couper la session SSH en cours : seulement depuis l'écran.
    let ssh = |r: &mut Reparation| {
        if e.ssh {
            r.bloquee = Some(tr!(
                "vous êtes connecté par SSH : changer le pare-feu pourrait couper votre connexion",
                "you are connected over SSH: changing the firewall could cut your connection"
            ));
        }
    };
    if let Firewalld::Actif(zone) = &e.firewalld {
        if zone.as_deref() == Some("trusted") {
            r.pourquoi = tr!("firewalld est actif mais en zone « trusted » : il laisse tout entrer. Passe la zone par défaut en « public ».", "firewalld is running but in the “trusted” zone: it lets everything in. Sets the default zone to “public”.").into();
            r.commandes = vec!["sudo firewall-cmd --set-default-zone=public".into()];
            ssh(&mut r);
        } else {
            r.inutile = Some(tr!("firewalld est actif", "firewalld is running").into());
        }
        return r;
    }
    if matches!(e.ufw, Ufw::Protege) {
        r.inutile = Some(String::from(tr!(
            "ufw est actif et refuse les connexions entrantes",
            "ufw is running and refuses incoming connections"
        )));
        return r;
    }
    if matches!(e.ufw, Ufw::Absent) {
        if let Some(autre) = e.autre {
            r.inutile = Some(trf!(
                "{autre} est actif : ses règles se gèrent à la main",
                "{autre} is running: its rules are managed by hand"
            ));
            return r;
        }
        // Installé mais arrêté (Fedora, openSUSE) : on le remet en route plutôt que d'en installer un second.
        if matches!(e.firewalld, Firewalld::Arrete) {
            r.pourquoi = tr!("firewalld est installé mais arrêté : le démarre avec sa zone par défaut et l'active au démarrage de l'ordinateur.", "firewalld is installed but stopped: starts it with its default zone and turns it on at boot.").into();
            r.commandes = vec![
                "sudo systemctl enable --now firewalld".into(),
                "sudo firewall-cmd --get-default-zone".into(),
            ];
            ssh(&mut r);
            return r;
        }
        let Some(g) = e.gestion else {
            r.inutile = Some(String::from(tr!(
                "aucun pare-feu, et gestionnaire de paquets non reconnu : installez ufw avec votre distribution",
                "no firewall, and package manager not recognized: install ufw with your distribution"
            )));
            return r;
        };
        r.commandes.push(g.installer("ufw"));
    }
    r.pourquoi = tr!("Active ufw et refuse par défaut les connexions entrantes (les sorties restent permises). Un service qui doit rester joignable depuis le réseau (partage, KDE Connect…) sera à autoriser : sudo ufw allow <port>.", "Turns ufw on and refuses incoming connections by default (outgoing stays allowed). A service that must stay reachable from the network (sharing, KDE Connect…) will need to be allowed: sudo ufw allow <port>.").into();
    r.commandes.extend(
        [
            "sudo ufw default deny incoming",
            "sudo ufw default allow outgoing",
            "sudo systemctl enable --now ufw",
            "sudo ufw --force enable",
            "sudo ufw status verbose",
        ]
        .map(String::from),
    );
    ssh(&mut r);
    r
}

/// Mises à jour en erreur : la réparation propre au gestionnaire de paquets (et au système atomique, s'il l'est).
#[cfg(target_os = "linux")]
fn paquets_casses(
    gestion: machine::linux::Paquets,
    atomique: Option<machine::linux::Atomique>,
    omarchy: bool,
) -> Reparation {
    use crate::machine::linux::{Atomique, Paquets};
    match gestion {
        // Système atomique : on ne répare pas l'image en place, on annule une opération restée bloquée puis on
        // repart d'une image propre (l'ancienne reste au menu de démarrage).
        Paquets::Dnf if atomique == Some(Atomique::RpmOstree) => rep(
            tr!("Mises à jour en erreur (rpm-ostree)", "Updates failing (rpm-ostree)"),
            tr!("Annule une opération restée bloquée, vide le cache, puis prépare l'image suivante. L'image actuelle reste au menu de démarrage en cas de problème.", "Cancels a stuck operation, clears the cache, then prepares the next image. The current image stays in the boot menu in case of trouble."),
            tr!("quelques minutes", "a few minutes"),
            &["sudo rpm-ostree cancel", "sudo rpm-ostree cleanup -m", "sudo rpm-ostree upgrade"],
        ),
        Paquets::Zypper if atomique == Some(Atomique::Transactionnel) => rep(
            tr!("Mises à jour en erreur (transactional-update)", "Updates failing (transactional-update)"),
            tr!("Prépare un nouvel instantané à jour, dépendances réparées. L'actuel reste au menu de démarrage en cas de problème.", "Prepares a new up-to-date snapshot with dependencies repaired. The current one stays in the boot menu in case of trouble."),
            tr!("quelques minutes", "a few minutes"),
            &["sudo transactional-update --non-interactive dup"],
        ),
        Paquets::Pacman => rep(
            tr!("Mises à jour en erreur (pacman)", "Updates failing (pacman)"),
            tr!("Débloque pacman après un arrêt brutal, renouvelle les clés de signature (erreurs « invalid or corrupted package »), puis met à jour.", "Unlocks pacman after a crash, renews the signing keys (“invalid or corrupted package” errors), then updates."),
            tr!("quelques minutes", "a few minutes"),
            &[
                // pamac (Manjaro) et PackageKit (Discover) travaillent sur la même base sans lancer pacman : effacer
                // leur verrou en pleine opération l'abîmerait.
                tr!("pgrep -x 'pacman|pamac-daemon|packagekitd' >/dev/null && echo 'un gestionnaire de paquets tourne déjà (pacman, pamac ou PackageKit) : attendez la fin' && exit 1; sudo rm -f /var/lib/pacman/db.lck", "pgrep -x 'pacman|pamac-daemon|packagekitd' >/dev/null && echo 'a package manager is already running (pacman, pamac or PackageKit): wait for it to finish' && exit 1; sudo rm -f /var/lib/pacman/db.lck"),
                // Les dérivées signent aussi leurs paquets avec leurs propres clés.
                "sudo pacman -Sy --needed --noconfirm archlinux-keyring $(pacman -Qq manjaro-keyring endeavouros-keyring cachyos-keyring omarchy-keyring 2>/dev/null)",
                // Sous Omarchy, sa mise à jour (instantané, migrations) plutôt qu'un pacman -Syu brut.
                if omarchy { "omarchy update" } else { "sudo pacman -Syu" },
            ],
        ).avec_restauration(),
        Paquets::Apt => rep(
            tr!("Mises à jour en erreur (apt)", "Updates failing (apt)"),
            tr!("Termine les installations interrompues et répare les dépendances cassées.", "Finishes interrupted installs and repairs broken dependencies."),
            tr!("quelques minutes", "a few minutes"),
            // Une étape en échec n'arrête pas les suivantes : ce sont elles qui réparent. La liste des paquets est
            // relue avant la réparation, qui sinon chercherait des versions disparues des dépôts.
            &["sudo dpkg --configure -a || true", "sudo apt-get update || true", "sudo apt-get -f install -y"],
        ).avec_restauration(),
        Paquets::Dnf => rep(
            tr!("Mises à jour en erreur (dnf)", "Updates failing (dnf)"),
            tr!("Vérifie la base des paquets et réaligne les paquets sur les versions de la distribution.", "Checks the package database and realigns packages with the distribution's versions."),
            tr!("quelques minutes", "a few minutes"),
            // « dnf check » sort en erreur quand il trouve un problème : c'est distro-sync qui le répare ensuite. Sans
            // -y : il peut rétrograder ou retirer des paquets, la liste se lit et se confirme d'abord.
            &["sudo dnf check || true", "sudo dnf distro-sync"],
        ).avec_restauration(),
        Paquets::Zypper => rep(
            tr!("Mises à jour en erreur (zypper)", "Updates failing (zypper)"),
            tr!("Vérifie et répare les dépendances des paquets installés.", "Checks and repairs the dependencies of installed packages."),
            tr!("quelques minutes", "a few minutes"),
            &["sudo zypper verify"],
        ),
    }
}

#[cfg(target_os = "linux")]
pub fn liste() -> Vec<Reparation> {
    use crate::machine::linux::{Paquets, atomique, service_actif};
    let gestion = Paquets::detecter();
    let atomique = atomique();
    // Sans systemd (conteneur, Alpine, Void…), les réparations qui passent par systemctl ou journalctl ne marchent pas.
    let systemd = std::path::Path::new("/run/systemd/system").is_dir();
    let mut l = Vec::new();

    let mut reseau = if service_actif("NetworkManager") {
        vec!["sudo systemctl restart NetworkManager"]
    } else if service_actif("systemd-networkd") {
        vec!["sudo systemctl restart systemd-networkd"]
    } else {
        vec![]
    };
    if service_actif("systemd-resolved") {
        reseau.push("sudo resolvectl flush-caches");
    }
    if !reseau.is_empty() {
        let mut r = rep(
            tr!("Internet ne marche plus", "Internet no longer works"),
            tr!(
                "Relance la gestion du réseau et vide le cache DNS (sites introuvables, Wi-Fi bloqué).",
                "Restarts network management and clears the DNS cache (sites not found, Wi-Fi stuck)."
            ),
            tr!("quelques secondes", "a few seconds"),
            &reseau,
        );
        sauf_en_ssh(&mut r);
        l.push(r);
    }
    l.push(navigation());
    l.push(antivirus(systemd));

    if let Some(g) = gestion {
        l.push(paquets_casses(g, atomique, machine::linux::omarchy()));
    }

    let installer_smart = gestion.map(|g| g.installer("smartmontools")).unwrap_or_default();
    let mut disque = vec![];
    if !present("smartctl") && !installer_smart.is_empty() {
        disque.push(installer_smart.as_str());
    }
    disque.push(
        // zram (mémoire compressée) et loop ne sont pas des disques physiques : pas de SMART.
        "for d in $(lsblk -dno NAME,TYPE | awk '$2==\"disk\" && $1 !~ /^(zram|loop)/{print $1}'); do echo \"== /dev/$d\"; sudo smartctl -H /dev/$d | tail -n +4; done",
    );
    // /proc/self/mountinfo, ce que findmnt lisait lui-même.
    let btrfs = machine::linux::natif::racine().is_some_and(|(_, genre)| genre == "btrfs");
    if btrfs {
        disque.push("sudo btrfs scrub start -B /");
    }
    l.push(rep(
        tr!("Disque : santé et erreurs", "Disk: health and errors"),
        if btrfs {
            tr!("Lit l'état SMART de chaque disque (usure, secteurs défectueux) et vérifie toutes les données du système (btrfs scrub).", "Reads the SMART state of each disk (wear, bad sectors) and checks all the system data (btrfs scrub).")
        } else {
            tr!("Lit l'état SMART de chaque disque (usure, secteurs défectueux). Pour réparer un ext4, démarrez sur la clé (SystemRescue).", "Reads the SMART state of each disk (wear, bad sectors). To repair ext4, boot from the USB key (SystemRescue).")
        },
        if btrfs { tr!("de quelques minutes à une heure", "from a few minutes to an hour") } else { tr!("quelques secondes", "a few seconds") },
        &disque,
    ));

    l.push(disque_plein());

    if !systemd {
        return l;
    }
    l.push(rep(
        tr!("Services en échec", "Failed services"),
        tr!("Montre les services qui ont planté, avec leurs dernières erreurs, puis remet leur compteur à zéro.", "Shows the services that crashed, with their latest errors, then resets their counter."),
        tr!("quelques secondes", "a few seconds"),
        &[
            "systemctl --failed --no-pager",
            "for s in $(systemctl --failed --no-legend --plain | awk '{print $1}'); do echo \"== $s\"; journalctl -u $s -n 5 --no-pager; done",
            "sudo systemctl reset-failed",
        ],
    ));

    l.push(pare_feu(&EtatPareFeu::lire(gestion)));

    l.push(rep(
        tr!("Heure fausse", "Wrong time"),
        tr!(
            "Réactive la synchronisation de l'heure (une heure fausse casse le HTTPS et les mises à jour).",
            "Turns time synchronization back on (a wrong time breaks HTTPS and updates)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            "sudo timedatectl set-ntp true",
            "timedatectl status | grep -E 'synchronized|NTP'",
        ],
    ));
    l
}

// ───────────────────────────── macOS ─────────────────────────────

/// Instantané local de Time Machine (APFS) : macOS le garde 24 heures, de quoi revenir en arrière si la
/// réparation tourne mal (Récupération > Restaurer depuis Time Machine).
#[cfg(target_os = "macos")]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux, où l'outil peut manquer
pub(crate) fn point_restauration(_titre: &str) -> Option<(&'static str, String)> {
    Some(("Time Machine", "tmutil localsnapshot".to_string()))
}

/// Services réseau actifs de macOS (« Wi-Fi », « Ethernet »…), pour networksetup : lus dans les réglages
/// (SCPreferences), `networksetup -listallnetworkservices` en secours.
#[cfg(target_os = "macos")]
fn services_reseau() -> Vec<String> {
    if let Some(services) = crate::machine::macos::config_reseau::services() {
        return services.into_iter().filter(|s| s.actif).map(|s| s.nom).collect();
    }
    crate::commande::lancer(
        std::process::Command::new("networksetup").arg("-listallnetworkservices"),
        10,
    )
    .map(|r| r.sortie)
    .unwrap_or_default()
    .lines()
    .skip(1)
    .filter(|l| !l.starts_with('*') && !l.trim().is_empty())
    .map(str::to_string)
    .collect()
}

/// Proxy imposé (`scutil --proxy` : « HTTPEnable : 1 ») et redirections du fichier hosts.
#[cfg(target_os = "macos")]
fn navigation_macos() -> Reparation {
    let detournees = redirections(&std::fs::read_to_string("/etc/hosts").unwrap_or_default());
    // Demandé à configd ; scutil en secours.
    let proxy = crate::machine::macos::config_reseau::proxy_comme_scutil()
        .or_else(|| crate::commande::lancer(std::process::Command::new("scutil").arg("--proxy"), 5).map(|r| r.sortie))
        .unwrap_or_default();
    let actifs: Vec<&str> = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"]
        .into_iter()
        .filter(|cle| {
            proxy
                .lines()
                .any(|l| l.trim().starts_with(cle) && l.trim().ends_with(": 1"))
        })
        .collect();
    let mut constats = Vec::new();
    let mut commandes = Vec::new();
    if !detournees.is_empty() {
        constats.push(constat_hosts(&detournees));
        commandes.push("sudo cp -p /etc/hosts /etc/hosts.vanguard-$(date +%Y%m%d-%H%M%S)".to_string());
        // sed de macOS : -i demande un suffixe (vide) ; puis vider le cache DNS pour que ça compte tout de suite.
        commandes.push(format!(
            "sudo sed -i '' -E 's/^([[:space:]]*({})[[:space:]])/# Vanguard : \\1/' /etc/hosts",
            motif_adresses(&detournees)
        ));
        commandes.push("sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder".to_string());
    }
    if !actifs.is_empty() {
        constats.push(trf!("proxy actif ({})", "proxy on ({})", actifs.join(", ")));
        for service in services_reseau() {
            let s = entre_apostrophes(&service);
            commandes.push(format!(
                "sudo networksetup -setwebproxystate {s} off; sudo networksetup -setsecurewebproxystate {s} off; \
                 sudo networksetup -setsocksfirewallproxystate {s} off; sudo networksetup -setautoproxystate {s} off"
            ));
        }
    }
    finir_navigation(
        trf!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe les proxys réglés dans le réseau. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. Trouvé : {}.",
            "Comments out the hosts file lines that send a site to an Internet address (a copy is kept) and turns off the proxies set in the network settings. Block lists (0.0.0.0) and local network devices are left alone. Found: {}.",
            constats.join(" ; ")
        ),
        commandes,
        !detournees.is_empty(),
    )
}

#[cfg(target_os = "macos")]
pub fn liste() -> Vec<Reparation> {
    const PARE_FEU: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    let mut l = Vec::new();

    // Réseau : cache DNS, nouvelle adresse (DHCP) et Wi-Fi coupé puis rallumé, sur chaque interface active.
    let mut r = rep(
        tr!("Internet ne marche plus", "Internet no longer works"),
        tr!(
            "Vide le cache DNS, redemande une adresse au routeur et relance le Wi-Fi (sites introuvables, Wi-Fi bloqué).",
            "Clears the DNS cache, asks the router for a new address and restarts Wi-Fi (sites not found, Wi-Fi stuck)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
            // Seulement les interfaces déjà en DHCP (getpacket) : une adresse réglée à la main ne doit pas y passer.
            // « ; true » : la boucle prend le code de la dernière interface, souvent sans DHCP, et arrêterait la suite.
            "for i in $(ifconfig -lu); do ipconfig getpacket $i >/dev/null 2>&1 && sudo ipconfig set $i DHCP; done; true",
            "W=$(networksetup -listallhardwareports | awk '/Wi-Fi/{getline; print $2}'); \
             [ -n \"$W\" ] && networksetup -setairportpower $W off && sleep 3 && networksetup -setairportpower $W on; true",
        ],
    );
    sauf_en_ssh(&mut r);
    l.push(r);
    l.push(navigation_macos());

    let actif = crate::commande::lancer(std::process::Command::new(PARE_FEU).arg("--getglobalstate"), 5)
        .is_some_and(|r| r.sortie.contains("enabled"));
    let mut feu = rep(
        tr!("Pare-feu coupé", "Firewall off"),
        tr!(
            "Active le pare-feu de macOS et son mode furtif (le Mac ne répond plus aux sondes du réseau).",
            "Turns on the macOS firewall and its stealth mode (the Mac no longer answers network probes)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            &format!("sudo {PARE_FEU} --setglobalstate on"),
            &format!("sudo {PARE_FEU} --setstealthmode on"),
        ],
    );
    if actif {
        feu.inutile = Some(tr!("le pare-feu est déjà actif", "the firewall is already on").into());
    }
    l.push(feu);

    // Antivirus : signatures ClamAV de Homebrew.
    let freshclam = machine::macos::homebrew()
        .map(|b| std::path::Path::new(b).with_file_name("freshclam"))
        .filter(|f| f.is_file());
    let mut av = rep(
        tr!("Antivirus pas à jour", "Antivirus out of date"),
        tr!(
            "Télécharge les dernières signatures de virus de ClamAV.",
            "Downloads the latest ClamAV virus signatures."
        ),
        tr!("une minute", "one minute"),
        &[],
    );
    match freshclam {
        Some(f) => {
            av.commandes = vec![crate::protection::antivirus::commande_freshclam(
                &f.display().to_string(),
            )];
        }
        None => {
            av.inutile = Some(String::from(tr!(
                "ClamAV n'est pas installé : l'analyse antivirus propose de l'installer",
                "ClamAV is not installed: the antivirus scan offers to install it"
            )));
        }
    }
    l.push(av);

    if let Some(brew) = machine::macos::homebrew() {
        l.push(rep(
            tr!("Homebrew en erreur", "Homebrew failing"),
            tr!(
                "Remet Homebrew dans un état propre (dépôts réalignés), puis montre ce qu'il reste à corriger.",
                "Puts Homebrew back in a clean state (repositories realigned), then shows what is left to fix."
            ),
            tr!("quelques minutes", "a few minutes"),
            &[
                &format!("{brew} update-reset"),
                &format!("{brew} update"),
                &format!("{brew} doctor; true"),
            ],
        ));
    }

    l.push(rep(
        tr!("Disque : santé et erreurs", "Disk: health and errors"),
        tr!(
            "Lit l'état SMART du disque interne et vérifie le volume du système (sans le démonter). Pour réparer, Utilitaire de disque > S.O.S. en mode de secours.",
            "Reads the SMART state of the internal disk and checks the system volume (without unmounting it). To repair, Disk Utility > First Aid in Recovery."
        ),
        tr!("quelques minutes", "a few minutes"),
        &[
            "diskutil info disk0 | grep -i smart",
            "diskutil verifyVolume /",
        ],
    ));
    l.push(disque_plein());

    l.push(rep(
        tr!("Heure fausse", "Wrong time"),
        tr!(
            "Réactive la mise à l'heure automatique et resynchronise tout de suite (une heure fausse casse le HTTPS et les mises à jour).",
            "Turns automatic time back on and syncs right away (a wrong time breaks HTTPS and updates)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &["sudo systemsetup -setusingnetworktime on", "sudo sntp -sS time.apple.com"],
    ));
    l
}

/// Ce que la réparation Windows doit savoir avant d'ouvrir le menu, lu dans le registre : proxy de l'utilisateur,
/// proxy WinHTTP (services, mises à jour), profils du pare-feu.
#[cfg(windows)]
#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct EtatWindows {
    proxy: String,
    pac: String,
    winhttp: String,
    parefeu_coupe: String,
    profils: u32,
}

#[cfg(windows)]
fn etat_windows() -> Option<EtatWindows> {
    etat_windows_natif().map(affichables).or_else(etat_windows_powershell)
}

/// Le même état sans PowerShell ; `None` si aucun profil du pare-feu ne se lit (l'appelant demande à PowerShell).
#[cfg(windows)]
fn etat_windows_natif() -> Option<EtatWindows> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let profils = machine::windows::profils_pare_feu();
    if profils.is_empty() {
        return None;
    }
    let internet = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .ok();
    let texte = |nom: &str| {
        internet
            .as_ref()
            .and_then(|c| c.get_value::<String, _>(nom).ok())
            .unwrap_or_default()
    };
    let actif = internet
        .as_ref()
        .and_then(|c| c.get_value::<u32, _>("ProxyEnable").ok())
        == Some(1);
    let winhttp = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections")
        .ok()
        .and_then(|c| c.get_raw_value("WinHttpSettings").ok())
        .map(|v| proxy_winhttp(&v.bytes))
        .unwrap_or_default();
    Some(EtatWindows {
        proxy: if actif { texte("ProxyServer") } else { String::new() },
        pac: texte("AutoConfigURL"),
        winhttp,
        parefeu_coupe: profils
            .iter()
            .filter(|(_, actif)| !actif)
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(", "),
        profils: u32::try_from(profils.len()).unwrap_or(0),
    })
}

/// Le proxy de WinHttpSettings : l'octet 8 vaut 1 pour « accès direct » ; sinon la longueur du proxy est à l'octet 12
/// et son nom (ASCII) suit à l'octet 16. Vide pour l'accès direct ; « configuré » quand le nom ne se lit pas.
#[cfg_attr(not(windows), allow(dead_code))]
fn proxy_winhttp(octets: &[u8]) -> String {
    if octets.len() < 16 || octets[8] == 1 {
        return String::new();
    }
    let n = i32::from_le_bytes([octets[12], octets[13], octets[14], octets[15]]);
    match usize::try_from(n)
        .ok()
        .filter(|&n| n > 0)
        .and_then(|n| octets.get(16..16 + n))
    {
        Some(nom) => nom
            .iter()
            .map(|&o| if o.is_ascii() { char::from(o) } else { '?' })
            .collect(),
        None => "configuré".into(),
    }
}

#[cfg(windows)]
fn etat_windows_powershell() -> Option<EtatWindows> {
    // WinHttpSettings : l'octet 8 vaut 1 pour « accès direct » ; sinon la longueur du proxy est à l'octet 12
    // et son nom suit à l'octet 16.
    let json = machine::windows::ps(
        r"$i = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
          $w = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -ErrorAction SilentlyContinue).WinHttpSettings
          $wp = ''
          if ($w -and $w.Length -ge 16 -and $w[8] -ne 1) { $n = [BitConverter]::ToInt32($w, 12); $wp = if ($n -gt 0 -and $w.Length -ge 16 + $n) { [Text.Encoding]::ASCII.GetString($w, 16, $n) } else { 'configuré' } }
          $profils = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
          [pscustomobject]@{
            proxy = if ($i.ProxyEnable -eq 1) { [string]$i.ProxyServer } else { '' }
            pac = [string]$i.AutoConfigURL
            winhttp = $wp
            parefeu_coupe = (@($profils | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name }) -join ', ')
            profils = $profils.Count
          } | ConvertTo-Json -Compress",
    )?;
    lire_etat_windows(&json)
}

/// La réponse d'`etat_windows`. Proxy et script de proxy viennent du registre, que tout programme de la session peut
/// écrire, et ne servent qu'à être montrés : rendus inoffensifs.
#[cfg(windows)]
fn lire_etat_windows(json: &str) -> Option<EtatWindows> {
    serde_json::from_str(json).ok().map(affichables)
}

#[cfg(windows)]
fn affichables(mut e: EtatWindows) -> EtatWindows {
    for t in [&mut e.proxy, &mut e.pac, &mut e.winhttp] {
        *t = affichable(t);
    }
    e
}

#[cfg(windows)]
fn navigation(etat: Option<&EtatWindows>) -> Reparation {
    const INTERNET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let hosts = std::path::Path::new(&racine).join(r"System32\drivers\etc\hosts");
    let detournees = redirections(&String::from_utf8_lossy(&std::fs::read(hosts).unwrap_or_default()));
    let mut constats = Vec::new();
    let mut commandes = Vec::new();
    if !detournees.is_empty() {
        constats.push(constat_hosts(&detournees));
        commandes.push(
            r#"$h = "$env:SystemRoot\System32\drivers\etc\hosts"; Copy-Item $h "$h.vanguard-$(Get-Date -Format yyyyMMdd-HHmmss)""#
                .to_string(),
        );
        // Réécrit en « Default » (ANSI), comme il a été lu : « ASCII » changerait en « ? » les lettres accentuées
        // des commentaires.
        commandes.push(format!(
            r#"$h = "$env:SystemRoot\System32\drivers\etc\hosts"; (Get-Content $h) | ForEach-Object {{ if ($_ -match '^\s*({})\s') {{ '# Vanguard : ' + $_ }} else {{ $_ }} }} | Set-Content $h -Encoding Default"#,
            motif_adresses(&detournees)
        ));
    }
    // Le proxy est un réglage de la personne : écrit dans sa ruche, même si la fenêtre administrateur est celle d'un
    // autre compte.
    if let Some(e) = etat {
        let reglages = if e.proxy.is_empty() && e.pac.is_empty() {
            String::new()
        } else {
            entre_apostrophes(&hkcu_de_la_personne(sid_de_la_personne().as_deref(), INTERNET))
        };
        if !e.proxy.is_empty() {
            constats.push(format!("proxy {}", e.proxy));
            commandes.push(format!(
                "Set-ItemProperty -LiteralPath {reglages} -Name ProxyEnable -Value 0"
            ));
        }
        if !e.pac.is_empty() {
            constats.push(trf!("script de proxy {}", "proxy script {}", e.pac));
            commandes.push(format!(
                "Remove-ItemProperty -LiteralPath {reglages} -Name AutoConfigURL"
            ));
        }
        if !e.winhttp.is_empty() {
            constats.push(trf!("proxy WinHTTP {}", "WinHTTP proxy {}", e.winhttp));
            commandes.push("netsh winhttp reset proxy".into());
        }
    }
    let mut r = navigation_detournee(
        trf!(
            "Met en commentaire les lignes du fichier hosts qui envoient un site vers une adresse d'Internet (une copie est gardée) et coupe le proxy imposé. Les listes de blocage (0.0.0.0) et les appareils du réseau local ne sont pas touchés. En entreprise, le proxy peut être voulu. Trouvé : {}.",
            "Comments out the hosts file lines that send a site to an Internet address (a copy is kept) and turns off the forced proxy. Block lists (0.0.0.0) and local network devices are left alone. In a company, the proxy may be intended. Found: {}.",
            constats.join(" ; ")
        ),
        commandes,
    );
    if r.commandes.is_empty() {
        r.inutile = Some(String::from(if etat.is_some() {
            tr!(
                "ni redirection dans le fichier hosts, ni proxy imposé",
                "no redirection in the hosts file, no forced proxy"
            )
        } else {
            tr!(
                "aucune redirection dans le fichier hosts (réglages du proxy non lus)",
                "no redirection in the hosts file (proxy settings not read)"
            )
        }));
    } else {
        r.commandes.push("ipconfig /flushdns".into());
        r.restauration = true;
    }
    r
}

#[cfg(windows)]
fn pare_feu(etat: Option<&EtatWindows>) -> Reparation {
    let mut r = rep(
        tr!("Pare-feu coupé", "Firewall off"),
        tr!(
            "Réactive le pare-feu Windows sur les trois profils (domaine, privé, public).",
            "Turns the Windows firewall back on for the three profiles (domain, private, public)."
        ),
        tr!("quelques secondes", "a few seconds"),
        &[
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            "Get-NetFirewallProfile | Format-Table Name, Enabled",
        ],
    );
    match etat {
        Some(e) if e.profils > 0 && e.parefeu_coupe.is_empty() => {
            r.inutile = Some(String::from(tr!(
                "le pare-feu Windows est actif sur tous les profils",
                "the Windows firewall is on for every profile"
            )));
        }
        Some(e) if e.profils > 0 => {
            r.pourquoi += &trf!(
                " Coupé pour : {}. Si un pare-feu tiers le remplace, ne rien faire.",
                " Off for: {}. If a third-party firewall replaces it, do nothing.",
                e.parefeu_coupe
            );
        }
        _ => r.pourquoi += tr!(" (état actuel non lu)", " (current state not read)"),
    }
    r
}

#[cfg(windows)]
pub fn liste() -> Vec<Reparation> {
    let etat = etat_windows();
    let etat = etat.as_ref();
    let a_distance = machine::windows::session_a_distance();
    let mut reseau = rep(
        tr!("Internet ne marche plus", "Internet no longer works"),
        tr!("Remet à zéro Winsock et la pile TCP/IP, vide le cache DNS, redemande une adresse. Un redémarrage termine la réparation. Une adresse IP fixe réglée à la main sera à remettre.", "Resets Winsock and the TCP/IP stack, clears the DNS cache, asks for a new address. A restart finishes the repair. A static IP address set by hand will have to be entered again."),
        tr!("une minute, puis redémarrer", "one minute, then restart"),
        &[
            "netsh winsock reset",
            "netsh int ip reset",
            "ipconfig /flushdns",
            "ipconfig /release",
            "ipconfig /renew",
        ],
    ).avec_restauration();
    if a_distance {
        reseau.bloquee = Some(tr!(
            "vous êtes connecté par le Bureau à distance : cette réparation couperait votre connexion",
            "you are connected over Remote Desktop: this repair would cut your connection"
        ));
    }
    vec![
        rep(
            tr!("Fichiers système abîmés", "Damaged system files"),
            tr!("Répare l'image de Windows (DISM) puis vérifie et remplace les fichiers système corrompus (SFC). À faire après un plantage ou un écran bleu.", "Repairs the Windows image (DISM), then checks and replaces corrupted system files (SFC). Do it after a crash or a blue screen."),
            tr!("15 à 45 minutes", "15 to 45 minutes"),
            &["DISM /Online /Cleanup-Image /RestoreHealth", "sfc /scannow"],
        ).avec_restauration(),
        rep(
            tr!("Disque : erreurs", "Disk: errors"),
            tr!("Analyse le disque C: sans le bloquer. Si des erreurs sont trouvées, la réparation se fait au redémarrage : chkdsk C: /f (C: ne peut pas être mis hors ligne pendant que Windows tourne).", "Scans disk C: without locking it. If errors are found, the repair happens at restart: chkdsk C: /f (C: cannot be taken offline while Windows is running)."),
            tr!("quelques minutes", "a few minutes"),
            &["Repair-Volume -DriveLetter C -Scan"],
        ),
        reseau,
        navigation(etat),
        pare_feu(etat),
        rep(
            tr!("Antivirus pas à jour", "Antivirus out of date"),
            tr!("Télécharge les dernières signatures de Microsoft Defender et affiche leur date.", "Downloads the latest Microsoft Defender signatures and shows their date."),
            tr!("une minute", "one minute"),
            &[
                "Update-MpSignature",
                "Get-MpComputerStatus | Format-List AntivirusSignatureLastUpdated, AntivirusSignatureVersion",
            ],
        ),
        rep(
            tr!("Windows Update bloqué", "Windows Update stuck"),
            tr!("Arrête les services de mise à jour, met de côté leurs caches (SoftwareDistribution, catroot2) et les relance.", "Stops the update services, sets their caches aside (SoftwareDistribution, catroot2) and restarts them."),
            tr!("une minute", "one minute"),
            &[
                "Stop-Service -Force wuauserv, bits, cryptsvc",
                "Rename-Item \"$env:SystemRoot\\SoftwareDistribution\" \"SoftwareDistribution.$(Get-Date -Format yyyyMMddHHmm)\"",
                "Rename-Item \"$env:SystemRoot\\System32\\catroot2\" \"catroot2.$(Get-Date -Format yyyyMMddHHmm)\"",
                "Start-Service wuauserv, bits, cryptsvc",
            ],
        ).avec_restauration(),
        disque_plein(),
        rep(
            tr!("Heure fausse", "Wrong time"),
            tr!("Resynchronise l'horloge (une heure fausse casse le HTTPS et Windows Update).", "Resynchronizes the clock (a wrong time breaks HTTPS and Windows Update)."),
            tr!("quelques secondes", "a few seconds"),
            // Service désactivé (par un outil d'« optimisation ») : remis comme à l'origine, sinon il ne démarre pas.
            &[
                "if ((Get-Service w32time).StartType -eq 'Disabled') { Set-Service w32time -StartupType Manual }",
                "Start-Service w32time",
                "w32tm /resync /force",
            ],
        ),
    ]
}

/// Menu des réparations : choisir, lire, confirmer.
pub fn menu() {
    use crate::selection::{Ligne, choisir};
    let reparations = liste();
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_titre(tr!("Réparer", "Repair"))),
    ];
    for (i, r) in reparations.iter().enumerate() {
        let note = if r.bloquee.is_some() {
            tr!("indisponible ici", "not available here")
        } else if r.inutile.is_some() {
            tr!("rien à faire", "nothing to do")
        } else {
            ""
        };
        lignes.push(Ligne::choix(&(i + 1).to_string(), r.titre, note));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let choix = choisir(
        &lignes,
        tr!(
            "Numéro de la réparation (Entrée pour revenir) : ",
            "Repair number (Enter to go back): "
        ),
        "1",
        tr!("revenir", "back"),
    )
    .unwrap_or_default();
    let Some(r) = choix
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| reparations.get(n))
    else {
        return;
    };
    lancer(r);
}

/// La réparation de ce titre, si ce système en a une : un parcours de dépannage la propose directement.
/// Seulement « Navigation détournée », pour le bilan : sans construire les autres réparations, dont certaines lancent
/// des commandes.
pub(crate) fn navigation_ici() -> Reparation {
    #[cfg(target_os = "linux")]
    {
        navigation()
    }
    #[cfg(target_os = "macos")]
    {
        navigation_macos()
    }
    #[cfg(windows)]
    {
        navigation(etat_windows().as_ref())
    }
}

pub fn par_titre(titre: &str) -> Option<Reparation> {
    liste().into_iter().find(|r| r.titre == titre)
}

/// Montre une réparation (pourquoi, durée, commandes), demande l'accord, puis la lance.
pub fn lancer(r: &Reparation) {
    if let Some(outil) = r.ouvrir {
        outil();
        return;
    }
    println!("\n  {GRAS}{}{RESET}", r.titre);
    if let Some(raison) = &r.inutile {
        trp!(
            "  {VERT}✔ Rien à faire : {raison}.{RESET}",
            "  {VERT}✔ Nothing to do: {raison}.{RESET}"
        );
        return;
    }
    println!("  {}", r.pourquoi);
    trp!("  {GRIS}Durée : {}{RESET}", "  {GRIS}Duration: {}{RESET}", r.duree);
    if let Some(raison) = r.bloquee {
        trp!(
            "\n  ✖ Pas maintenant : {raison}. Faites-la depuis l'écran de l'ordinateur.",
            "\n  ✖ Not now: {raison}. Do it from the computer's own screen."
        );
        return;
    }
    trp!("  Commandes :", "  Commands:");
    for c in &r.commandes {
        println!("    {GRIS}{}{RESET}", crate::ui::commande_affichable(c));
    }
    if !demander(tr!(
        "\n  Lancer cette réparation ? [o/N] : ",
        "\n  Run this repair? [y/N]: "
    ))
    .oui()
    {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut commandes = r.commandes.clone();
    // Point de restauration automatique avant une réparation qui modifie le système : on peut revenir en arrière.
    if r.restauration
        && let Some((outil, point)) = point_restauration(r.titre)
    {
        trp!(
            "  {GRIS}Point de restauration d'abord ({outil}).{RESET}",
            "  {GRIS}Restore point first ({outil}).{RESET}"
        );
        // Windows : dans la même fenêtre administrateur (une seule demande) ; elle demande quoi faire si ça échoue.
        #[cfg(windows)]
        commandes.insert(0, point);
        #[cfg(not(windows))]
        if !machine::appliquer(&[point])
            && !demander(tr!(
                "  ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ",
                "  ✖ Restore point not possible. Continue anyway? [y/N]: "
            ))
            .oui()
        {
            trp!("  Annulé.", "  Cancelled.");
            return;
        }
    }
    if machine::appliquer(&commandes) {
        trp!(
            "  {VERT}✔ Réparation terminée.{RESET}",
            "  {VERT}✔ Repair finished.{RESET}"
        );
    } else {
        trp!(
            "  ✖ Une étape a échoué : lisez le message ci-dessus.",
            "  ✖ A step failed: read the message above."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Refuser de continuer sans point de restauration sort avec un code à part, que Vanguard explique au lieu d'un
    /// « pas changé » sans raison.
    #[cfg(windows)]
    #[test]
    fn arret_sans_point_de_restauration_reconnu() {
        let (_, commande) = point_restauration("essai").unwrap();
        assert_eq!(commande, "vanguard:point-de-restauration");
        let commande = point_restauration_powershell();
        assert!(commande.contains(&format!("exit {SANS_POINT_ARRETE} }}")), "{commande}");
        assert!(!commande.contains("exit 1"), "{commande}");
    }

    #[test]
    fn chaque_reparation_est_complete() {
        let l = liste();
        assert!(l.len() >= 4);
        for r in &l {
            assert!(!r.titre.is_empty() && !r.duree.is_empty());
            if r.inutile.is_none() {
                assert!(!r.pourquoi.is_empty(), "{} n'explique rien", r.titre);
                assert!(
                    !r.commandes.is_empty() || r.ouvrir.is_some(),
                    "{} n'a pas de commande",
                    r.titre
                );
            }
        }
    }

    /// Une apostrophe ou une parenthèse oubliée ne se verrait qu'au lancement de la réparation, chez quelqu'un.
    #[cfg(unix)]
    #[test]
    fn les_commandes_sont_du_shell_valide() {
        for r in liste() {
            for c in &r.commandes {
                let valide = std::process::Command::new("bash")
                    .args(["-n", "-c", c])
                    .status()
                    .is_ok_and(|s| s.success());
                assert!(valide, "« {} » : {c}", r.titre);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pare_feu_selon_ce_qui_est_installe() {
        let base = EtatPareFeu {
            gestion: Some(machine::linux::Paquets::Dnf),
            ..EtatPareFeu::default()
        };
        // firewalld installé mais arrêté (Fedora, openSUSE) : relancé, pas doublé d'un ufw.
        let r = pare_feu(&EtatPareFeu {
            firewalld: Firewalld::Arrete,
            ..base.clone()
        });
        assert_eq!(r.commandes[0], "sudo systemctl enable --now firewalld");
        assert!(r.inutile.is_none() && r.bloquee.is_none() && !r.commandes.iter().any(|c| c.contains("ufw")));
        // Par SSH, ni firewalld démarré ni zone changée : la session pourrait tomber.
        let ssh = EtatPareFeu {
            ssh: true,
            ..base.clone()
        };
        assert!(
            pare_feu(&EtatPareFeu {
                firewalld: Firewalld::Arrete,
                ..ssh.clone()
            })
            .bloquee
            .is_some()
        );
        let r = pare_feu(&EtatPareFeu {
            firewalld: Firewalld::Actif(Some("trusted".into())),
            ..ssh.clone()
        });
        assert_eq!(r.commandes, ["sudo firewall-cmd --set-default-zone=public"]);
        assert!(r.bloquee.is_some());
        assert!(pare_feu(&ssh).bloquee.is_some());
        // Aucun pare-feu : ufw, installé depuis la distribution.
        let r = pare_feu(&base);
        assert!(r.commandes[0].contains("ufw") && r.commandes.iter().any(|c| c == "sudo ufw --force enable"));
        // Des règles écrites à la main, ou un pare-feu qui protège déjà : rien à faire.
        assert!(
            pare_feu(&EtatPareFeu {
                autre: Some("nftables"),
                ..base.clone()
            })
            .inutile
            .is_some()
        );
        assert!(
            pare_feu(&EtatPareFeu {
                firewalld: Firewalld::Actif(Some("public".into())),
                ..base.clone()
            })
            .inutile
            .is_some()
        );
    }

    /// Les commandes de chaque distribution, pas seulement celle de la machine de test.
    #[cfg(target_os = "linux")]
    #[test]
    fn reparations_des_paquets_pour_chaque_distribution() {
        use crate::machine::linux::{Atomique, Paquets};
        for g in [Paquets::Pacman, Paquets::Apt, Paquets::Dnf, Paquets::Zypper] {
            for atomique in [None, Some(Atomique::RpmOstree), Some(Atomique::Transactionnel)] {
                for omarchy in [false, true] {
                    let r = paquets_casses(g, atomique, omarchy);
                    for c in &r.commandes {
                        let valide = std::process::Command::new("bash")
                            .args(["-n", "-c", c])
                            .status()
                            .is_ok_and(|s| s.success());
                        assert!(valide, "« {} » : {c}", r.titre);
                        // Ce qui peut rétrograder ou retirer des paquets montre sa liste et se confirme.
                        assert!(!c.contains("distro-sync -y"), "{c}");
                    }
                }
            }
        }
    }

    /// Le renvoi suit la numérotation du menu principal : un groupe ajouté ou déplacé le rendrait faux.
    #[cfg(target_os = "linux")]
    #[test]
    fn renvoi_au_menu_de_l_antivirus() {
        let renvoi = crate::touche_de(crate::Action::Antivirus).expect("analyse antivirus absente du menu");
        assert!(
            sans_clamav().contains(&format!("menu {renvoi},")),
            "« {} » ne renvoie pas à {renvoi}",
            sans_clamav()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn variables_de_proxy_trouvees_dans_les_deux_casses() {
        let f = std::env::temp_dir().join(format!("vanguard-test-proxy-{}", std::process::id()));
        std::fs::write(
            &f,
            "export HTTPS_PROXY=http://10.0.0.1:3128\n# http_proxy=http://commentaire\nall_proxy=socks5://h\n",
        )
        .unwrap();
        let sortie = std::process::Command::new("bash")
            .args(["-c", &format!("{TROUVER_PROXY} {}", f.display())])
            .output()
            .unwrap();
        let lignes = String::from_utf8_lossy(&sortie.stdout).to_string();
        assert!(lignes.contains("1:export HTTPS_PROXY="), "{lignes}");
        assert!(
            lignes.contains("3:all_proxy=") && !lignes.contains("commentaire"),
            "{lignes}"
        );
        let _ = std::fs::remove_file(&f);
    }

    /// Un fichier hosts de liste de blocage : des centaines de milliers de lignes, une seule redirection.
    #[test]
    fn grand_fichier_hosts_de_liste_de_blocage() {
        use std::fmt::Write as _;
        let mut hosts = String::new();
        for i in 0..300_000 {
            let _ = writeln!(hosts, "0.0.0.0 pub{i}.exemple.com");
        }
        hosts.push_str("185.12.0.9 banque.fr\n");
        assert_eq!(
            redirections(&hosts),
            [("185.12.0.9".to_string(), "banque.fr".to_string())]
        );
    }

    #[test]
    fn redirections_du_fichier_hosts() {
        let hosts = "127.0.0.1 localhost\n::1 localhost ip6-localhost\nfe00::0 ip6-localnet\nff02::1 ip6-allnodes\n\
                     127.0.1.1 machine.local machine\n0.0.0.0 pub.exemple.com\n:: pistage.exemple.com\n\
                     192.168.1.20 nas # mon NAS\n100.101.2.3 tailscale-pc\n# 8.8.8.8 commentaire.exemple\n\
                     \t185.12.0.9\tbanque.fr   www.banque.fr\n2a00:1450::1 update.microsoft.com\n::ffff:93.184.216.34 mappee.com\n1.2.3.4\n";
        let r = redirections(hosts);
        assert_eq!(
            r,
            vec![
                ("185.12.0.9".to_string(), "banque.fr www.banque.fr".to_string()),
                ("2a00:1450::1".to_string(), "update.microsoft.com".to_string()),
                ("::ffff:93.184.216.34".to_string(), "mappee.com".to_string()),
            ]
        );
        assert_eq!(
            motif_adresses(&r),
            r"185\.12\.0\.9|2a00:1450::1|::ffff:93\.184\.216\.34"
        );
        assert!(resume_redirections(&r).starts_with("185.12.0.9 → banque.fr www.banque.fr, "));
    }

    /// Le fichier hosts s'écrit par qui détourne la navigation : un nom piégé arrive inoffensif dans ce qui est
    /// montré. L'adresse, qui sert à la commande, est déjà vérifiée (c'en est une).
    #[test]
    fn redirection_piegee() {
        let r = redirections("185.12.0.9 banque.fr\x1b]52;c;eA==\x07\u{202e}\x1b[2K\n");
        assert_eq!(
            r,
            [("185.12.0.9".to_string(), "banque.fr�]52;c;eA==���[2K".to_string())]
        );
        assert!(!crate::ui::contient_un_piege(&resume_redirections(&r)));
        assert_eq!(motif_adresses(&r), r"185\.12\.0\.9");
    }

    /// Une variable de proxy vient d'un fichier de démarrage que tout programme de la session peut écrire.
    #[cfg(target_os = "linux")]
    #[test]
    fn variable_de_proxy_piegee() {
        let v = variables_proxy(|n| {
            (n == "HTTPS_PROXY").then(|| "http://10.0.0.9:3128\x1b]52;c;eA==\x07\u{202e}".to_string())
        });
        assert_eq!(v, ["https_proxy=http://10.0.0.9:3128�]52;c;eA==��"]);
    }

    /// Proxy et script de proxy viennent du registre, que tout programme de la session peut écrire.
    #[cfg(windows)]
    #[test]
    fn proxy_windows_piege() {
        let json = serde_json::json!({
            "proxy": "10.0.0.9:3128\u{1b}]52;c;eA==\u{7}",
            "pac": "http://pac.exemple\u{1b}[2K\r\u{202e}/p.pac",
            "winhttp": "proxy\u{1b}[8m",
            "parefeu_coupe": "",
            "profils": 3
        })
        .to_string();
        let e = lire_etat_windows(&json).unwrap();
        assert_eq!(e.proxy, "10.0.0.9:3128�]52;c;eA==�");
        assert_eq!(e.pac, "http://pac.exemple�[2K��/p.pac");
        assert_eq!(e.winhttp, "proxy�[8m");
        assert_eq!(e.profils, 3);
    }

    #[test]
    fn proxy_de_winhttp() {
        let mut v = vec![0x28, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 14, 0, 0, 0];
        v.extend_from_slice(b"10.0.0.9:3128\xe9");
        assert_eq!(proxy_winhttp(&v), "10.0.0.9:3128?");
        let mut direct = v.clone();
        direct[8] = 1;
        assert_eq!(proxy_winhttp(&direct), "");
        assert_eq!(proxy_winhttp(&v[..20]), "configuré");
        assert_eq!(proxy_winhttp(&v[..10]), "");
        let mut negatif = v.clone();
        negatif[15] = 0x80;
        assert_eq!(proxy_winhttp(&negatif), "configuré");
    }

    /// Le vrai registre (Wine ici, la VM ensuite), sans PowerShell : le pare-feu de Wine n'a pas de profils, l'état se
    /// lit alors par PowerShell (absent ici) ; ailleurs, les trois profils.
    #[cfg(windows)]
    #[test]
    fn etat_lu_sans_powershell() {
        if let Some(e) = etat_windows_natif() {
            assert!(e.profils > 0);
        }
    }

    /// La zone par défaut de firewalld : celle de l'administrateur d'abord, puis celle du paquet ; une clé en
    /// commentaire ou vide ne compte pas ; sans fichier, rien n'est conclu (firewall-cmd prend le relais).
    #[cfg(target_os = "linux")]
    #[test]
    fn zone_de_firewalld_lue_dans_sa_configuration() {
        let d = std::env::temp_dir().join(format!("vanguard-reparer-firewalld-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(zone_firewalld(&d), None);
        let ecrire = |f: &str, t: &str| {
            let f = d.join(f);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, t).unwrap();
        };
        ecrire("usr/lib/firewalld/firewalld.conf", "# usine\nDefaultZone=public\n");
        assert_eq!(zone_firewalld(&d).as_deref(), Some("public"));
        ecrire(
            "etc/firewalld/firewalld.conf",
            "# DefaultZone=work\nDefaultZone=\nLogDenied=off\n",
        );
        assert_eq!(
            zone_firewalld(&d).as_deref(),
            Some("public"),
            "clé vide : celle du paquet"
        );
        ecrire("etc/firewalld/firewalld.conf", "  DefaultZone=trusted  \n");
        assert_eq!(zone_firewalld(&d).as_deref(), Some("trusted"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Masquée par l'administrateur : un lien vers /dev/null dans /etc/systemd/system, pas un autre lien, ni un masque
    /// de ce démarrage seulement (/run).
    #[cfg(target_os = "linux")]
    #[test]
    fn firewalld_masque() {
        use std::os::unix::fs::symlink;
        let d = std::env::temp_dir().join(format!("vanguard-reparer-masque-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for dossier in ["etc/systemd/system", "run/systemd/system"] {
            std::fs::create_dir_all(d.join(dossier)).unwrap();
        }
        assert!(!masquee_par_l_administrateur(&d, "firewalld.service"));
        symlink("/dev/null", d.join("run/systemd/system/firewalld.service")).unwrap();
        assert!(!masquee_par_l_administrateur(&d, "firewalld.service"));
        symlink(
            "/usr/lib/systemd/system/autre.service",
            d.join("etc/systemd/system/firewalld.service"),
        )
        .unwrap();
        assert!(!masquee_par_l_administrateur(&d, "firewalld.service"));
        std::fs::remove_file(d.join("etc/systemd/system/firewalld.service")).unwrap();
        symlink("/dev/null", d.join("etc/systemd/system/firewalld.service")).unwrap();
        assert!(masquee_par_l_administrateur(&d, "firewalld.service"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sur cet ordinateur, « masquée » se lit comme le dit `systemctl is-enabled`, et la zone comme `firewall-cmd`,
    /// quand ils répondent.
    #[cfg(target_os = "linux")]
    #[test]
    fn firewalld_comme_systemctl_et_firewall_cmd() {
        let racine = std::path::Path::new("/");
        let lancer = |cmd: &str, args: &[&str]| {
            crate::commande::lancer(std::process::Command::new(cmd).args(args), 10).map(|r| r.sortie.trim().to_string())
        };
        if let Some(etat) = lancer("systemctl", &["is-enabled", "firewalld.service"]).filter(|e| !e.is_empty()) {
            assert_eq!(
                masquee_par_l_administrateur(racine, "firewalld.service"),
                etat == "masked",
                "{etat}"
            );
        }
        if let (Some(zone), Some(natif)) = (
            lancer("firewall-cmd", &["--get-default-zone"]).filter(|z| !z.is_empty() && !z.contains(' ')),
            zone_firewalld(racine),
        ) {
            assert_eq!(natif, zone);
        }
    }
}
