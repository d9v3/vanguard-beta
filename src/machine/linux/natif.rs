//! Lectures natives de Linux, sans lancer de programme : le PATH, les unités systemd, les processus, les bases de
//! pacman, dpkg, Flatpak et Snap, les disques, la racine, les groupes du compte et deux constantes du système.
//!
//! Pourquoi : une commande externe peut manquer, changer de format ou de langue, ou être remplacée par un faux
//! dans le PATH ; le fichier qu'elle lit, lui, est là. Chaque fonction lit ses fichiers puis confie le texte à un
//! analyseur qui reçoit la racine en paramètre : les tests lui donnent une arborescence inventée. `None` veut dire
//! « non vérifié » (base absente, format inconnu), jamais « rien trouvé ».

// La recherche dans le PATH est commune à Linux et macOS (`machine::unix`).
use crate::machine::unix::chemin_dans;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::copier::sans_echappements;

/// La racine du vrai système ; les tests passent la leur.
const RACINE: &str = "/";

/// Un chemin absolu du système, rattaché à `racine` (`Path::join` d'un chemin absolu jetterait la racine).
fn sous(racine: &Path, chemin: &str) -> PathBuf {
    racine.join(chemin.trim_start_matches('/'))
}

// ---------------------------------------------------------------------------------------------------------------
// Programmes du PATH

/// Le programme `cmd` est-il là et exécutable, comme le dirait `command -v` ?
pub(crate) fn present(cmd: &str) -> bool {
    chemin(cmd).is_some()
}

/// Le chemin du programme `cmd`, le premier du PATH qui s'exécute (`None` : absent) : pour qui doit l'écrire en
/// entier, comme une unité systemd, qui ne cherche pas dans le PATH.
pub(crate) fn chemin(cmd: &str) -> Option<PathBuf> {
    chemin_dans(cmd, &std::env::var_os("PATH").unwrap_or_default())
}

/// Un nom avec une barre oblique est un chemin, pris tel quel, comme le fait le shell. Le bit d'exécution compte :
/// un fichier ordinaire du même nom dans le PATH ne se lance pas, et `command -v` l'ignore aussi.
#[cfg(test)]
fn present_dans(cmd: &str, path: &OsStr) -> bool {
    chemin_dans(cmd, path).is_some()
}

/// Les dossiers de programmes du système, ceux que le `secure_path` de sudo garde : pour décider d'une commande
/// lancée par sudo, le PATH du compte ne vaut rien (un `~/.local/bin/ufw` y passerait pour installé sans être celui
/// que sudo lancera).
const DOSSIERS_SYSTEME: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Le programme `cmd` est-il dans un dossier du système, et exécutable ? Les deux copies d'avant (réparer, nettoyer)
/// prenaient un dossier ou un fichier non exécutable du même nom pour le programme.
pub(crate) fn present_systeme(cmd: &str) -> bool {
    !cmd.contains('/') && chemin_dans(cmd, OsStr::new(DOSSIERS_SYSTEME)).is_some()
}

// ---------------------------------------------------------------------------------------------------------------
// Unités systemd

/// Les dossiers où l'administrateur et le démarrage en cours activent ou masquent des unités, du plus prioritaire
/// au moins prioritaire. Ceux de /usr/lib ne comptent pas : leurs liens viennent du paquet (unités « static »), et
/// `systemctl is-enabled` ne les dit pas activées.
fn dossiers_de_config(racine: &Path, utilisateur: bool) -> Vec<PathBuf> {
    if utilisateur {
        let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
        dossiers_utilisateur(racine, &crate::socle::maison(), xdg.as_deref(), uid())
    } else {
        vec![sous(racine, "/etc/systemd/system"), sous(racine, "/run/systemd/system")]
    }
}

/// Les dossiers de l'utilisateur. ~/.config/systemd/user vient toujours en premier : Vanguard y écrit ses unités,
/// et `systemd --user`, lancé par logind, n'hérite pas du XDG_CONFIG_HOME exporté par le profil du shell, il
/// garde ~/.config. Chercher seulement sous $XDG_CONFIG_HOME dirait désactivée une minuterie que systemctl dit
/// activée, et le passage de version la retirerait sans la remettre. $XDG_CONFIG_HOME s'ajoute s'il diffère :
/// un gestionnaire lancé avec cette variable y pose ses liens.
fn dossiers_utilisateur(racine: &Path, maison: &Path, xdg: Option<&Path>, uid: u32) -> Vec<PathBuf> {
    let mut dossiers = vec![sous(racine, &maison.join(".config/systemd/user").to_string_lossy())];
    if let Some(x) = xdg.filter(|x| x.is_absolute()) {
        let d = sous(racine, &x.join("systemd/user").to_string_lossy());
        if !dossiers.contains(&d) {
            dossiers.push(d);
        }
    }
    dossiers.extend([
        sous(racine, "/etc/systemd/user"),
        sous(racine, &format!("/run/user/{uid}/systemd/user")),
        sous(racine, "/run/systemd/user"),
    ]);
    dossiers
}

fn uid() -> u32 {
    crate::socle::uid()
}

/// Le nom complet d'une unité : `systemctl` ajoute « .service » quand il n'y a pas de suffixe, on fait pareil.
fn nom_complet(nom: &str) -> String {
    if nom.contains('.') {
        nom.to_string()
    } else {
        format!("{nom}.service")
    }
}

/// L'unité est-elle activée (`systemctl [--user] is-enabled`) ? `Some(false)` si elle est désactivée ou masquée,
/// `None` quand aucun dossier de systemd n'existe (pas de systemd : non vérifié).
pub(crate) fn unite_activee(nom: &str, utilisateur: bool) -> Option<bool> {
    unite_activee_dans(&dossiers_de_config(Path::new(RACINE), utilisateur), nom)
}

/// Activée = un lien à son nom dans un dossier « *.wants » ou « *.requires » (ce que `systemctl enable` pose).
/// Masquée = son fichier d'unité est un lien vers /dev/null dans un dossier plus prioritaire : elle ne démarre
/// plus, même si un ancien lien d'activation traîne. Pour un modèle (« getty@.service »), un lien vers une de
/// ses instances (« getty@tty1 », service de même suffixe) suffit, comme pour `systemctl`.
fn unite_activee_dans(dossiers: &[PathBuf], nom: &str) -> Option<bool> {
    let nom = nom_complet(nom);
    let existants: Vec<&PathBuf> = dossiers.iter().filter(|d| d.is_dir()).collect();
    if existants.is_empty() {
        return None;
    }
    let masquee = existants
        .iter()
        .any(|d| std::fs::read_link(d.join(&nom)).is_ok_and(|cible| cible == Path::new("/dev/null")));
    if masquee {
        return Some(false);
    }
    let modele = nom
        .split_once("@.")
        .map(|(debut, suffixe)| (format!("{debut}@"), format!(".{suffixe}")));
    let correspond = |lien: &OsStr| {
        let lien = lien.to_string_lossy();
        match &modele {
            Some((debut, fin)) => lien.starts_with(debut.as_str()) && lien.ends_with(fin.as_str()),
            None => lien == nom,
        }
    };
    let activee = existants.iter().any(|d| {
        std::fs::read_dir(d).into_iter().flatten().flatten().any(|w| {
            let n = w.file_name();
            let n = n.to_string_lossy();
            // Un alias (« Alias= » de [Install], tel dbus-org.freedesktop.nm-dispatcher.service) est un lien
            // d'un autre nom vers l'unité : `systemctl enable` le pose aussi, elle compte pour activée.
            let alias =
                n != nom.as_str() && std::fs::read_link(w.path()).is_ok_and(|c| c.file_name().is_some_and(correspond));
            alias
                || (n.ends_with(".wants") || n.ends_with(".requires"))
                    && std::fs::read_dir(w.path())
                        .into_iter()
                        .flatten()
                        .flatten()
                        .any(|l| correspond(&l.file_name()))
        })
    });
    Some(activee)
}

/// Les dossiers où systemd cherche les fichiers d'unités du système, dans son ordre (`systemd-analyze unit-paths`).
const DOSSIERS_UNITES: [&str; 9] = [
    "/etc/systemd/system",
    "/run/systemd/generator.early",
    "/run/systemd/system",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
    "/etc/systemd/system.control",
];

/// Le fichier de l'unité existe-t-il (ce que vérifiait `systemctl cat`) ?
pub(crate) fn unite_existe(nom: &str) -> bool {
    unite_existe_sous(Path::new(RACINE), nom)
}

/// Une instance (« getty@tty1 ») existe dès que son modèle (« getty@.service ») existe.
fn unite_existe_sous(racine: &Path, nom: &str) -> bool {
    let nom = nom_complet(nom);
    let modele = nom
        .split_once('@')
        .and_then(|(debut, reste)| Some(format!("{debut}@.{}", reste.rsplit_once('.')?.1)));
    DOSSIERS_UNITES.iter().any(|d| {
        let d = sous(racine, d);
        std::iter::once(&nom)
            .chain(modele.as_ref())
            .any(|n| d.join(n).symlink_metadata().is_ok())
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Processus

/// Un processus porte-t-il ce nom (`pgrep -x nom`) ?
pub(crate) fn processus_nomme(nom: &str) -> bool {
    processus_nomme_sous(Path::new(RACINE), nom)
}

/// Le noyau coupe le nom court (`/proc/<pid>/comm`) à 15 octets : un nom plus long se compare coupé, sinon il ne
/// serait jamais trouvé.
fn processus_nomme_sous(racine: &Path, nom: &str) -> bool {
    let mut fin = nom.len().min(15);
    while !nom.is_char_boundary(fin) {
        fin -= 1;
    }
    let cherche = &nom[..fin];
    if cherche.is_empty() {
        return false;
    }
    let proc = sous(racine, "/proc");
    crate::socle::processus::pids_dans(&proc)
        .unwrap_or_default()
        .into_iter()
        .any(|pid| {
            std::fs::read_to_string(proc.join(pid.to_string()).join("comm"))
                .is_ok_and(|c| c.trim_end_matches('\n') == cherche)
        })
}

/// Lesquels de ces services du système tournent (`systemctl is-active`) ? Un seul passage dans /proc pour toute
/// la liste. `None` : /proc ne montre pas les processus des autres comptes (option hidepid, ou pas de /proc), non
/// vérifié.
pub(crate) fn services_actifs(services: &[&str]) -> Option<Vec<bool>> {
    services_actifs_sous(Path::new(RACINE), services)
}

/// Un service tourne quand un processus est dans son groupe de contrôle, « `/system.slice/<nom>.service` », ce que
/// `/proc/<pid>/cgroup` dit à tous les comptes. Le nom du processus ne suffit pas : n'importe quel compte peut
/// appeler un programme « nextdns », un tunnel cloudflared lancé à la main ou dans un conteneur n'est pas le DNS
/// de la machine, ni le dnsmasq que libvirt ou NetworkManager lancent pour eux. Seul systemd, donc root, place
/// un processus dans system.slice ; un conteneur est sous « `/system.slice/docker-<id>.scope` », la session sous
/// user.slice. Le processus 1 doit se lire : sinon /proc cache les autres comptes et « aucun » serait faux.
fn services_actifs_sous(racine: &Path, services: &[&str]) -> Option<Vec<bool>> {
    let proc = sous(racine, "/proc");
    std::fs::read_to_string(proc.join("1/cgroup")).ok()?;
    let groupes: Vec<String> = services
        .iter()
        .map(|s| format!("/system.slice/{}", nom_complet(s)))
        .collect();
    let mut actifs = vec![false; services.len()];
    for pid in crate::socle::processus::pids_dans(&proc)? {
        let Ok(texte) = std::fs::read_to_string(proc.join(pid.to_string()).join("cgroup")) else {
            continue;
        };
        // Une ligne par hiérarchie, « 0::/chemin » (cgroup v2) ou « 1:name=systemd:/chemin » (v1) ; le chemin
        // commence par le groupe du service, suivi de rien ou d'un sous-groupe.
        for chemin in texte.lines().filter_map(|l| l.splitn(3, ':').nth(2)) {
            for (actif, g) in actifs.iter_mut().zip(&groupes) {
                if chemin
                    .strip_prefix(g.as_str())
                    .is_some_and(|reste| reste.is_empty() || reste.starts_with('/'))
                {
                    *actif = true;
                }
            }
        }
    }
    Some(actifs)
}

// ---------------------------------------------------------------------------------------------------------------
// pacman

const PACMAN_LOCAL: &str = "/var/lib/pacman/local";

/// Les champs d'un fichier « desc » de pacman : « %NOM% » puis une valeur par ligne jusqu'à la ligne vide.
pub(crate) fn champs_pacman(texte: &str) -> HashMap<String, Vec<String>> {
    let mut champs: HashMap<String, Vec<String>> = HashMap::new();
    let mut courant: Option<String> = None;
    for ligne in texte.lines() {
        let ligne = ligne.trim_end_matches('\r');
        if ligne.is_empty() {
            courant = None;
        } else if ligne.len() > 2 && ligne.starts_with('%') && ligne.ends_with('%') && courant.is_none() {
            let cle = ligne.trim_matches('%').to_string();
            champs.entry(cle.clone()).or_default();
            courant = Some(cle);
        } else if let Some(c) = &courant {
            champs.entry(c.clone()).or_default().push(ligne.to_string());
        }
    }
    champs
}

/// Le premier élément d'un champ.
fn premier<'a>(champs: &'a HashMap<String, Vec<String>>, cle: &str) -> Option<&'a str> {
    champs.get(cle)?.first().map(String::as_str)
}

/// Les dossiers de la base locale ; `None` si elle ne se lit pas (pas de pacman, ou base illisible).
fn dossiers_pacman(racine: &Path) -> Option<Vec<PathBuf>> {
    let mut d: Vec<PathBuf> = std::fs::read_dir(sous(racine, PACMAN_LOCAL))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    d.sort();
    Some(d)
}

/// Les paquets installés et leur version (`pacman -Q`).
pub(crate) fn paquets_pacman() -> Option<Vec<(String, String)>> {
    paquets_pacman_sous(Path::new(RACINE))
}

/// Le nom vient de « %NAME% » : le couper dans le nom du dossier se tromperait, un nom de paquet peut contenir des
/// tirets et des chiffres (« python-3to2-1.1.1-1 »).
fn paquets_pacman_sous(racine: &Path) -> Option<Vec<(String, String)>> {
    let mut paquets: Vec<(String, String)> = dossiers_pacman(racine)?
        .iter()
        .filter_map(|d| {
            let champs = champs_pacman(&std::fs::read_to_string(d.join("desc")).ok()?);
            Some((
                premier(&champs, "NAME")?.to_string(),
                premier(&champs, "VERSION")?.to_string(),
            ))
        })
        .collect();
    paquets.sort();
    Some(paquets)
}

/// Le dossier d'un paquet installé : seuls ceux qui commencent par « `<nom>-` » sont ouverts, puis le nom est vérifié
/// dans « desc » (« linux-6.1-1 » commence aussi par « linux- » pour le paquet « linux-firmware »).
fn dossier_pacman(racine: &Path, nom: &str) -> Option<(PathBuf, HashMap<String, Vec<String>>)> {
    let prefixe = format!("{nom}-");
    dossiers_pacman(racine)?.into_iter().find_map(|d| {
        if !d.file_name()?.to_string_lossy().starts_with(&prefixe) {
            return None;
        }
        let champs = champs_pacman(&std::fs::read_to_string(d.join("desc")).ok()?);
        (premier(&champs, "NAME")? == nom).then_some((d, champs))
    })
}

/// Les champs de « desc » d'un paquet installé (%SIZE%, %REASON%, %DEPENDS%, %PROVIDES%…), comme `pacman -Qi` ;
/// `None` s'il n'est pas installé ou si la base ne se lit pas.
pub(crate) fn desc_pacman(nom: &str) -> Option<HashMap<String, Vec<String>>> {
    dossier_pacman(Path::new(RACINE), nom).map(|(_, champs)| champs)
}

/// Le paquet propriétaire de chaque fichier (`pacman -Qo`) ; un fichier qu'aucun paquet n'a posé est absent de la
/// réponse. Les dossiers parents sont résolus comme le fait pacman (/bin est un lien vers usr/bin sur Arch).
pub(crate) fn proprietaire_pacman(fichiers: &[&Path]) -> Option<HashMap<PathBuf, String>> {
    let resolus: Vec<(PathBuf, PathBuf)> = fichiers.iter().map(|f| (f.to_path_buf(), parent_resolu(f))).collect();
    let trouves = proprietaire_pacman_sous(
        Path::new(RACINE),
        &resolus.iter().map(|(_, r)| r.as_path()).collect::<Vec<_>>(),
    )?;
    Some(
        resolus
            .into_iter()
            .filter_map(|(f, r)| Some((f, trouves.get(&r)?.clone())))
            .collect(),
    )
}

/// Le dossier parent résolu (liens suivis), le nom gardé : le fichier lui-même peut être un lien, posé tel quel par
/// le paquet.
fn parent_resolu(f: &Path) -> PathBuf {
    match (f.parent().and_then(|p| p.canonicalize().ok()), f.file_name()) {
        (Some(p), Some(n)) => p.join(n),
        _ => f.to_path_buf(),
    }
}

/// Un seul passage dans les listes « files » pour tous les fichiers demandés. Les chemins y sont écrits sans la
/// barre de tête ; les dossiers finissent par « / » et appartiennent à plusieurs paquets : ils ne comptent pas.
fn proprietaire_pacman_sous(racine: &Path, fichiers: &[&Path]) -> Option<HashMap<PathBuf, String>> {
    let cherches: HashMap<String, PathBuf> = fichiers
        .iter()
        .map(|f| (f.to_string_lossy().trim_start_matches('/').to_string(), f.to_path_buf()))
        .collect();
    let mut trouves = HashMap::new();
    for d in dossiers_pacman(racine)? {
        if trouves.len() == cherches.len() {
            break;
        }
        let Ok(liste) = std::fs::read_to_string(d.join("files")) else {
            continue;
        };
        let Some(nom) = std::fs::read_to_string(d.join("desc"))
            .ok()
            .and_then(|t| premier(&champs_pacman(&t), "NAME").map(str::to_string))
        else {
            continue;
        };
        for f in champs_pacman(&liste).get("FILES").into_iter().flatten() {
            if let Some(chemin) = cherches.get(f.as_str()) {
                trouves.entry(chemin.clone()).or_insert_with(|| nom.clone());
            }
        }
    }
    Some(trouves)
}

// ---------------------------------------------------------------------------------------------------------------
// dpkg

const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// Les paragraphes du fichier status de dpkg : des champs « Clé: valeur », séparés par une ligne vide ; une ligne
/// qui commence par une espace continue le champ d'avant (Description, Conffiles) et n'est pas gardée.
fn paragraphes_dpkg(texte: &str) -> Vec<HashMap<&str, &str>> {
    let mut tous = Vec::new();
    let mut courant = HashMap::new();
    for ligne in texte.lines().map(|l| l.trim_end_matches('\r')) {
        if ligne.trim().is_empty() {
            if !courant.is_empty() {
                tous.push(std::mem::take(&mut courant));
            }
        } else if !ligne.starts_with([' ', '\t'])
            && let Some((cle, valeur)) = ligne.split_once(':')
        {
            courant.insert(cle, valeur.trim());
        }
    }
    if !courant.is_empty() {
        tous.push(courant);
    }
    tous
}

/// État d'un paquet selon dpkg : installé quand le dernier mot de Status est « installed », qu'il soit voulu
/// (« install ok installed ») ou retenu (« hold ok installed »). Un paquet retiré dont la configuration reste
/// (« deinstall ok config-files ») est connu de dpkg, qui répond sans erreur à « dpkg -s » : il n'est pas
/// installé. La règle d'avant, ici, ne gardait que « install ok installed » : un openssh-server retenu n'avait pas
/// de version ; celle du menu Gaming comptait les paquets retenus. Une seule règle, celle de `dpkg-query`
/// (`${db:Status-Status}`).
pub(crate) fn installe_selon_dpkg(statut: &str) -> bool {
    statut.trim().ends_with(" installed")
}

/// Les paragraphes des paquets installés, `champ` gardé : (nom, champ), triés, sans doublon.
fn installes_dpkg_avec(status: &str, champ: &str) -> Vec<(String, String)> {
    let mut paquets: Vec<(String, String)> = paragraphes_dpkg(status)
        .into_iter()
        .filter(|p| p.get("Status").is_some_and(|s| installe_selon_dpkg(s)))
        .filter_map(|p| Some((p.get("Package")?.to_string(), p.get(champ)?.to_string())))
        .collect();
    paquets.sort();
    paquets.dedup();
    paquets
}

/// Les paquets installés et leur version, d'après le texte du fichier status.
pub(crate) fn paquets_dpkg_selon(status: &str) -> Vec<(String, String)> {
    installes_dpkg_avec(status, "Version")
}

/// Les paquets installés et leur architecture, d'après le texte du fichier status : « mesa-vulkan-drivers:i386 »
/// se demande par son architecture.
pub(crate) fn architectures_installees_selon(status: &str) -> Vec<(String, String)> {
    installes_dpkg_avec(status, "Architecture")
}

/// Les paquets installés selon dpkg, avec leur architecture : (nom, architecture). `None` sans base.
pub(crate) fn paquets_dpkg_installes() -> Option<Vec<(String, String)>> {
    Some(architectures_installees_selon(
        &std::fs::read_to_string(sous(Path::new(RACINE), DPKG_STATUS)).ok()?,
    ))
}

/// Les paquets installés (`dpkg-query -W`) ; `None` sans base dpkg.
pub(crate) fn paquets_dpkg() -> Option<Vec<(String, String)>> {
    paquets_dpkg_sous(Path::new(RACINE))
}

fn paquets_dpkg_sous(racine: &Path) -> Option<Vec<(String, String)>> {
    Some(paquets_dpkg_selon(
        &std::fs::read_to_string(sous(racine, DPKG_STATUS)).ok()?,
    ))
}

/// Les architectures connues de dpkg (/var/lib/dpkg/arch, une par ligne), la native comprise quand dpkg l'y a
/// écrite : pour savoir si i386 est activée, chercher « i386 » dans la liste suffit.
pub(crate) fn architectures_dpkg() -> Option<Vec<String>> {
    architectures_dpkg_sous(Path::new(RACINE))
}

fn architectures_dpkg_sous(racine: &Path) -> Option<Vec<String>> {
    let texte = std::fs::read_to_string(sous(racine, "/var/lib/dpkg/arch")).ok()?;
    Some(
        texte
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

// ---------------------------------------------------------------------------------------------------------------
// Flatpak

/// Les installations Flatpak : celle du système, puis celle du compte.
fn installations_flatpak(racine: &Path) -> Vec<PathBuf> {
    let maison = crate::socle::maison();
    let donnees = std::env::var_os("XDG_DATA_HOME").map_or_else(|| maison.join(".local/share"), PathBuf::from);
    vec![
        sous(racine, "/var/lib/flatpak"),
        sous(racine, &donnees.join("flatpak").to_string_lossy()),
    ]
}

/// Les applications installées (`flatpak list --app`), triées, sans doublon.
pub(crate) fn flatpak_apps() -> Vec<String> {
    flatpak_apps_dans(&installations_flatpak(Path::new(RACINE)))
}

/// Une application compte quand sa branche en service existe (`current/active`) : un dossier vide reste parfois
/// après une désinstallation interrompue.
fn flatpak_apps_dans(installations: &[PathBuf]) -> Vec<String> {
    let mut apps: Vec<String> = installations
        .iter()
        .flat_map(|i| std::fs::read_dir(i.join("app")).into_iter().flatten().flatten())
        .filter(|e| e.path().join("current/active").exists())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    apps.sort();
    apps.dedup();
    apps
}

/// Un fichier ordinaire lu jusqu'à `max` octets. Les fichiers que le compte peut poser (unités de
/// ~/.config/systemd, surcharges et applications Flatpak du compte) ne se lisent pas tels quels : un tube nommé
/// bloquerait la lecture pour toujours, un lien vers /dev/zero remplirait la mémoire. `None` pour tout ce qui
/// n'est pas un fichier ordinaire (le lien est suivi) ou ne se lit pas.
pub(crate) fn lire_borne(chemin: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    if !std::fs::metadata(chemin).is_ok_and(|m| m.is_file()) {
        return None;
    }
    let mut texte = String::new();
    std::fs::File::open(chemin)
        .ok()?
        .take(max)
        .read_to_string(&mut texte)
        .ok()?;
    Some(texte)
}

/// Le fichier « metadata » d'une application (ses permissions statiques, `[Context]`), celle du compte d'abord :
/// `flatpak run` prend la sienne quand l'application est installée deux fois.
pub(crate) fn flatpak_metadata(id: &str) -> Option<String> {
    flatpak_metadata_dans(&installations_flatpak(Path::new(RACINE)), id)
}

fn flatpak_metadata_dans(installations: &[PathBuf], id: &str) -> Option<String> {
    // Un identifiant avec une barre ou « .. » sortirait du dossier des applications.
    if id.is_empty() || id.contains('/') || id.contains("..") {
        return None;
    }
    installations
        .iter()
        .rev()
        // Quelques Ko d'habitude ; celui du compte se pose sans droits, d'où la borne.
        .find_map(|i| lire_borne(&i.join("app").join(id).join("current/active/metadata"), 1 << 20))
}

/// Les clés d'une section d'un fichier INI comme metadata (« `[Context]` » : sockets=…;devices=…), dans l'ordre.
pub(crate) fn section_ini<'a>(texte: &'a str, section: &str) -> Vec<(&'a str, &'a str)> {
    let entete = format!("[{section}]");
    let mut dedans = false;
    let mut cles = Vec::new();
    for ligne in texte.lines().map(str::trim) {
        if ligne.starts_with('[') {
            dedans = ligne == entete;
        } else if dedans
            && !ligne.starts_with('#')
            && let Some((cle, valeur)) = ligne.split_once('=')
        {
            cles.push((cle.trim(), valeur.trim()));
        }
    }
    cles
}

// ---------------------------------------------------------------------------------------------------------------
// Snap

/// Un snap installé : sa révision en service et toutes celles gardées sur le disque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snap {
    pub nom: String,
    /// La révision vers laquelle pointe le lien « current » ; `None` s'il manque (snap désactivé).
    pub courante: Option<String>,
    pub revisions: Vec<String>,
}

/// Les snaps installés (`snap list --all`) ; `None` sans snapd.
pub(crate) fn snaps() -> Option<Vec<Snap>> {
    snaps_sous(Path::new(RACINE))
}

/// Les révisions viennent des fichiers `/var/lib/snapd/snaps/<nom>_<révision>.snap` : un nom de snap n'a jamais de
/// « _ » (lettres, chiffres et tirets), le dernier sépare donc la révision. Le lien « current » est dans /snap
/// (ou /var/lib/snapd/snap sur Fedora et Arch, où /snap n'existe pas toujours).
fn snaps_sous(racine: &Path) -> Option<Vec<Snap>> {
    let fichiers = std::fs::read_dir(sous(racine, "/var/lib/snapd/snaps")).ok()?;
    let mut parnom: HashMap<String, Vec<String>> = HashMap::new();
    for f in fichiers.flatten() {
        let n = f.file_name();
        let Some((nom, revision)) = n.to_str().and_then(|n| n.strip_suffix(".snap")?.rsplit_once('_')) else {
            continue;
        };
        parnom.entry(nom.to_string()).or_default().push(revision.to_string());
    }
    let montages = [sous(racine, "/snap"), sous(racine, "/var/lib/snapd/snap")];
    let mut snaps: Vec<Snap> = parnom
        .into_iter()
        .map(|(nom, mut revisions)| {
            revisions.sort_by(|a, b| tri_revision(a).cmp(&tri_revision(b)));
            let courante = montages.iter().find_map(|m| {
                let cible = std::fs::read_link(m.join(&nom).join("current")).ok()?;
                Some(cible.file_name()?.to_string_lossy().into_owned())
            });
            Snap {
                nom,
                courante,
                revisions,
            }
        })
        .collect();
    snaps.sort_by(|a, b| a.nom.cmp(&b.nom));
    Some(snaps)
}

/// Les révisions sont des nombres (« x1 » pour un snap installé à la main) : triées comme des nombres, pas comme du
/// texte (« 10 » après « 9 »).
fn tri_revision(r: &str) -> (bool, u64, &str) {
    match r.parse::<u64>() {
        Ok(n) => (false, n, r),
        Err(_) => (true, 0, r),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Disques

/// Un périphérique bloc de /sys/block, ce que `lsblk -d` en montre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Disque {
    pub nom: String,
    pub octets: u64,
    pub rotatif: bool,
    pub amovible: bool,
    pub modele: String,
    pub serie: String,
    /// « nvme », « usb », « sata », « virtio », « mmc »… vide s'il ne se lit pas.
    pub bus: String,
    /// « disk », « rom » (lecteur optique), « loop » ou « dm » (périphérique virtuel de device-mapper).
    pub genre: String,
}

/// Les disques (`lsblk -dnb -o NAME,SIZE,ROTA,RM,MODEL,SERIAL,TRAN,TYPE`).
pub(crate) fn disques() -> Vec<Disque> {
    disques_sous(Path::new(RACINE))
}

/// La taille de /sys/block/*/size est toujours en secteurs de 512 octets, quelle que soit la taille réelle des
/// secteurs du disque.
fn disques_sous(racine: &Path) -> Vec<Disque> {
    let mut disques: Vec<Disque> = std::fs::read_dir(sous(racine, "/sys/block"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let nom = e.file_name().to_str()?.to_string();
            let d = e.path();
            let lire = |f: &str| {
                std::fs::read_to_string(d.join(f))
                    .map(|t| t.trim().to_string())
                    .unwrap_or_default()
            };
            let udev = proprietes_udev(
                &std::fs::read_to_string(sous(racine, &format!("/run/udev/data/b{}", lire("dev")))).unwrap_or_default(),
            );
            // L'ordre de lsblk : udev d'abord (ID_MODEL_ENC, puis ID_MODEL). Pour un disque SATA, device/model est le champ « product » de
            // l'INQUIRY SCSI que libata fabrique, coupé à 16 octets (« Samsung SSD 870 ») ; ata_id met dans
            // ID_MODEL_ENC le modèle ATA entier. sysfs ne sert que si udev ne dit rien.
            let modele = udev
                .get("ID_MODEL_ENC")
                .map(|m| espaces_normalises(&sans_echappements_x(m)))
                .filter(|m| !m.is_empty())
                // ID_MODEL tel quel, comme lsblk : pour un NVMe, udev y met le vrai nom (« WD_BLACK SN7100 »),
                // dont le « _ » fait partie.
                .or_else(|| udev.get("ID_MODEL").map(|m| espaces_normalises(m)))
                .filter(|m| !m.is_empty())
                .or_else(|| Some(lire("device/model")).filter(|m| !m.is_empty()))
                .unwrap_or_default();
            // NVMe donne sa série dans sysfs ; pour SATA et USB, seul udev la garde (lisible par tous).
            let serie = Some(lire("device/serial"))
                .filter(|s| !s.is_empty())
                .or_else(|| udev.get("ID_SERIAL_SHORT").cloned())
                .unwrap_or_default();
            let genre = if nom.starts_with("loop") {
                "loop"
            } else if nom.starts_with("dm-") {
                "dm"
            } else if lire("device/type") == "5" {
                // Type SCSI 5 : lecteur CD/DVD/Blu-ray.
                "rom"
            } else {
                "disk"
            };
            Some(Disque {
                octets: lire("size").parse::<u64>().ok()?.saturating_mul(512),
                rotatif: lire("queue/rotational") == "1",
                amovible: lire("removable") == "1",
                bus: bus(&d, &udev),
                genre: genre.into(),
                modele,
                serie,
                nom,
            })
        })
        .collect();
    disques.sort_by(|a, b| a.nom.cmp(&b.nom));
    disques
}

/// Le bus d'un disque : le sous-système de son parent (lien device/subsystem). Un disque USB s'y dit « scsi »
/// (USB passe par la couche SCSI) : le chemin réel de l'appareil traverse alors un contrôleur « usbN », qui le
/// trahit ; un disque SATA traverse « ataN ». udev en dernier recours (ID_BUS).
fn bus(bloc: &Path, udev: &HashMap<String, String>) -> String {
    let appareil = bloc.join("device");
    let sous_systeme = std::fs::read_link(appareil.join("subsystem"))
        .ok()
        .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let chemin = appareil.canonicalize().unwrap_or_default();
    let traverse = |prefixe: &str| {
        chemin.components().any(|c| {
            let c = c.as_os_str().to_string_lossy();
            c.strip_prefix(prefixe)
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|o| o.is_ascii_digit()))
        })
    };
    match sous_systeme.as_str() {
        "nvme" | "virtio" | "mmc" => sous_systeme,
        _ if traverse("usb") => "usb".into(),
        _ if traverse("ata") => "sata".into(),
        _ => udev.get("ID_BUS").cloned().unwrap_or_default(),
    }
}

/// « \xNN » remis en octet, comme le fait lsblk (udev écrit ainsi espaces et octets non imprimables) ; le
/// reste tel quel.
fn sans_echappements_x(texte: &str) -> String {
    let mut reste = texte.as_bytes();
    let mut sortie = Vec::with_capacity(reste.len());
    while let [premier, suite @ ..] = reste {
        if let [b'\\', b'x', h1, h2, apres @ ..] = reste
            && let Some(b) = std::str::from_utf8(&[*h1, *h2])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            sortie.push(b);
            reste = apres;
        } else {
            sortie.push(*premier);
            reste = suite;
        }
    }
    String::from_utf8_lossy(&sortie).into_owned()
}

/// Les espaces du début et de la fin retirés, ceux du milieu réduits à un : ID_MODEL_ENC garde le bourrage du
/// champ ATA (« Samsung\x20SSD\x20870\x20EVO\x201TB\x20\x20… »), que lsblk retire de la même façon.
fn espaces_normalises(texte: &str) -> String {
    texte.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Les propriétés d'un fichier /run/udev/data : lignes « E:CLÉ=valeur ».
fn proprietes_udev(texte: &str) -> HashMap<String, String> {
    texte
        .lines()
        .filter_map(|l| l.strip_prefix("E:")?.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Racine et chiffrement

/// La source et le type du système de fichiers monté sur / (`findmnt -no SOURCE,FSTYPE /`, sans le
/// « [/sous-volume] » que findmnt ajoute pour Btrfs).
pub(crate) fn racine() -> Option<(String, String)> {
    racine_selon(
        &std::fs::read_to_string("/proc/self/mountinfo").ok()?,
        Path::new(RACINE),
    )
}

/// D'après le texte de mountinfo : « id parent maj:min racine point options… - type source options ». Le dernier
/// montage sur / recouvre les précédents ; les chemins y sont écrits en octal (« \040 » pour l'espace).
///
/// Monté sans initramfs (root= donné au noyau, comme sur les machines virtuelles d'Ubuntu), la source est le nom
/// fictif « /dev/root », qui n'existe pas dans /dev : le chiffrement ne s'y lirait pas. Comme findmnt, on retrouve
/// alors le vrai périphérique par son numéro (maj:min) dans sysfs.
pub(crate) fn racine_selon(mountinfo: &str, racine: &Path) -> Option<(String, String)> {
    mountinfo.lines().rev().find_map(|l| {
        let (avant, apres) = l.split_once(" - ")?;
        let champs: Vec<&str> = avant.split(' ').collect();
        if *champs.get(4)? != "/" {
            return None;
        }
        let mut c = apres.split(' ');
        let genre = sans_echappements(c.next()?);
        let source = sans_echappements(c.next()?);
        let source = if source == "/dev/root" {
            peripherique_de(racine, champs.get(2)?).unwrap_or(source)
        } else {
            source
        };
        Some((source, genre))
    })
}

/// Le périphérique d'un numéro « maj:min », d'après le DEVNAME de son uevent dans sysfs (« /dev/sda1 »).
fn peripherique_de(racine: &Path, numero: &str) -> Option<String> {
    // Un numéro inattendu ne doit jamais faire lire ailleurs que sous /sys/dev/block.
    let (maj, min) = numero.split_once(':')?;
    if ![maj, min]
        .iter()
        .all(|n| !n.is_empty() && n.bytes().all(|o| o.is_ascii_digit()))
    {
        return None;
    }
    let uevent = lire_borne(&sous(racine, &format!("/sys/dev/block/{numero}/uevent")), 64 << 10)?;
    let nom = uevent.lines().find_map(|l| l.strip_prefix("DEVNAME="))?.trim();
    (!nom.is_empty() && !nom.contains("..")).then(|| format!("/dev/{nom}"))
}

/// Le périphérique `dev` (« /dev/mapper/root », « /dev/nvme0n1p2 ») est-il chiffré, lui ou un de ceux sur
/// lesquels il repose (`lsblk -s` montre un maillon « crypt ») ? `None` si le périphérique est inconnu de sysfs.
pub(crate) fn chiffre(dev: &str) -> Option<bool> {
    // /dev/mapper/<nom> est un lien vers /dev/dm-N : c'est sous ce nom-là que sysfs le connaît.
    let reel = Path::new(dev).canonicalize().ok()?;
    chiffre_sous(Path::new(RACINE), reel.file_name()?.to_str()?)
}

/// Un maillon dm-crypt : un dm dont l'identifiant (dm/uuid) commence par « CRYPT- » (LUKS1, LUKS2, plain). LVM
/// sur LUKS ou LUKS sur RAID : on remonte les « slaves » (les périphériques dessous) jusqu'en bas.
fn chiffre_sous(racine: &Path, nom: &str) -> Option<bool> {
    let bloc = sous(racine, "/sys/class/block").join(nom);
    if !bloc.exists() {
        return None;
    }
    Some(chiffre_en(&bloc, 0))
}

fn chiffre_en(bloc: &Path, profondeur: u8) -> bool {
    // Une boucle de liens ne doit pas faire tourner sans fin : aucune pile réelle n'a seize étages.
    if profondeur > 16 {
        return false;
    }
    if std::fs::read_to_string(bloc.join("dm/uuid")).is_ok_and(|u| u.starts_with("CRYPT-")) {
        return true;
    }
    std::fs::read_dir(bloc.join("slaves"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|s| chiffre_en(&s.path(), profondeur + 1))
}

// ---------------------------------------------------------------------------------------------------------------
// Groupes du compte

/// Les noms des groupes du compte (`id -nG`) : le groupe principal d'abord, puis les autres. Un groupe sans nom
/// (absent de /etc/group : le programme est lié à musl, qui ne consulte ni LDAP ni sssd) garde son numéro, comme
/// `id` le fait ; `None` si la liste ne se lit pas.
pub(crate) fn groupes() -> Option<Vec<String>> {
    // SAFETY: avec 0 et un pointeur nul, getgroups ne fait que compter, sans rien écrire.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut gids: Vec<libc::gid_t> = vec![0; usize::try_from(n).ok()?];
    // SAFETY: `gids` a exactement `n` places ; getgroups n'en écrit pas plus, et rend -1 si la liste a grandi.
    let n = unsafe { libc::getgroups(n, gids.as_mut_ptr()) };
    gids.truncate(usize::try_from(n).ok()?);
    // SAFETY: getegid ne peut pas échouer et ne touche à aucune mémoire du programme.
    let principal = unsafe { libc::getegid() };
    let mut vus = HashSet::new();
    Some(
        std::iter::once(principal)
            .chain(gids)
            .filter(|g| vus.insert(*g))
            .map(|g| nom_du_groupe(g).unwrap_or_else(|| g.to_string()))
            .collect(),
    )
}

/// Le nom d'un groupe par getgrgid_r, avec une mémoire qui grandit tant qu'elle est trop petite (ERANGE).
fn nom_du_groupe(gid: libc::gid_t) -> Option<String> {
    let mut taille = 1024usize;
    while taille <= 1 << 20 {
        let mut memoire = vec![0 as libc::c_char; taille];
        // SAFETY: `group` est une structure C de pointeurs et de nombres, valide à zéro.
        let mut groupe: libc::group = unsafe { std::mem::zeroed() };
        let mut resultat: *mut libc::group = std::ptr::null_mut();
        // SAFETY: `groupe`, `memoire` (de `taille` octets exactement) et `resultat` sont à nous et vivent
        // jusqu'à la fin de l'appel ; getgrgid_r n'écrit que dans ces bornes.
        let code = unsafe { libc::getgrgid_r(gid, &raw mut groupe, memoire.as_mut_ptr(), taille, &raw mut resultat) };
        if code == libc::ERANGE {
            taille *= 4;
            continue;
        }
        if code != 0 || resultat.is_null() || groupe.gr_name.is_null() {
            return None;
        }
        // SAFETY: gr_name pointe dans `memoire`, encore vivante, vers une chaîne terminée par un zéro.
        let nom = unsafe { std::ffi::CStr::from_ptr(groupe.gr_name) };
        return Some(nom.to_string_lossy().into_owned());
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------
// Constantes du système

/// Les tics d'horloge par seconde (`getconf CLK_TCK`), l'unité des temps de `/proc/<pid>/stat` ; 100 s'il ne se lit
/// pas, la valeur de tous les noyaux courants.
pub(crate) fn tics() -> u64 {
    // SAFETY: sysconf lit une constante du système, sans toucher à la mémoire du programme.
    u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
        .ok()
        .filter(|&t| t > 0)
        .unwrap_or(100)
}

/// La taille d'une page de mémoire (`getconf PAGESIZE`), l'unité de `/proc/<pid>/statm` ; 4096 s'il ne se lit pas.
pub(crate) fn taille_page() -> u64 {
    // SAFETY: sysconf lit une constante du système, sans toucher à la mémoire du programme.
    u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|&t| t > 0)
        .unwrap_or(4096)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// Une instance du modèle getty@.service, écrite par morceaux : son nom complet a la forme d'un courriel, que
    /// la vérification de confidentialité refuserait.
    fn instance(n: u8) -> String {
        format!("getty@tty{n}.{}", "service")
    }

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-natif-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ecrire(racine: &Path, chemin: &str, texte: &str) {
        let f = sous(racine, chemin);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, texte).unwrap();
    }

    /// La commande, en anglais, quand elle est là et réussit ; sinon le test s'arrête sans rien conclure.
    fn commande(programme: &str, args: &[&str]) -> Option<String> {
        if !present(programme) {
            return None;
        }
        crate::commande::lancer_en_anglais(std::process::Command::new(programme).args(args), 30)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    }

    #[test]
    fn present_suit_le_path_et_le_bit_d_execution() {
        let d = jetable("path");
        let (a, b) = (d.join("a"), d.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("outil"), "#!/bin/sh\n").unwrap();
        std::fs::write(b.join("texte"), "pas un programme").unwrap();
        std::fs::set_permissions(a.join("outil"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(b.join("texte"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = std::env::join_paths([&a, &b]).unwrap();
        assert!(present_dans("outil", &path));
        assert!(!present_dans("texte", &path), "non exécutable");
        assert!(!present_dans("absent", &path));
        assert!(!present_dans("", &path));
        // Un dossier du même nom n'est pas un programme.
        std::fs::create_dir_all(b.join("dossier")).unwrap();
        assert!(!present_dans("dossier", &path));
        // Un chemin se prend tel quel, sans le PATH.
        assert!(present_dans(&a.join("outil").to_string_lossy(), OsStr::new("")));
        assert!(!present_dans(&b.join("texte").to_string_lossy(), OsStr::new("")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les dossiers du système seulement, et jamais un chemin : `present_systeme` décide de commandes passées à sudo.
    #[test]
    fn present_systeme_sans_chemin() {
        assert!(present_systeme("sh"));
        assert!(!present_systeme("vanguard-introuvable") && !present_systeme(""));
        assert!(!present_systeme("/bin/sh") && !present_systeme("../bin/sh"));
    }

    #[test]
    fn unite_activee_par_les_liens() {
        let d = jetable("unites");
        let (etc, run) = (d.join("etc"), d.join("run"));
        assert_eq!(
            unite_activee_dans(&[etc.clone(), run.clone()], "sshd"),
            None,
            "aucun dossier"
        );
        std::fs::create_dir_all(etc.join("multi-user.target.wants")).unwrap();
        std::fs::create_dir_all(etc.join("sockets.target.requires")).unwrap();
        std::fs::create_dir_all(etc.join("getty.target.wants")).unwrap();
        let unite = d.join("sshd.service");
        std::fs::write(&unite, "[Unit]\n").unwrap();
        symlink(&unite, etc.join("multi-user.target.wants/sshd.service")).unwrap();
        symlink(&unite, etc.join("sockets.target.requires/cups.socket")).unwrap();
        symlink(&unite, etc.join("getty.target.wants").join(instance(1))).unwrap();
        // Activée par son seul alias.
        symlink(
            "/usr/lib/systemd/system/nm-dispatcher.service",
            etc.join("dbus-org.nm-dispatcher.service"),
        )
        .unwrap();
        let dossiers = [etc.clone(), run.clone()];
        // Sans suffixe, c'est un service, comme pour systemctl.
        assert_eq!(unite_activee_dans(&dossiers, "sshd"), Some(true));
        assert_eq!(unite_activee_dans(&dossiers, "sshd.service"), Some(true));
        assert_eq!(unite_activee_dans(&dossiers, "cups.socket"), Some(true));
        assert_eq!(unite_activee_dans(&dossiers, "cups.service"), Some(false));
        // Un modèle est activé par une de ses instances.
        assert_eq!(unite_activee_dans(&dossiers, "getty@.service"), Some(true));
        assert_eq!(unite_activee_dans(&dossiers, &instance(1)), Some(true));
        assert_eq!(unite_activee_dans(&dossiers, &instance(2)), Some(false));
        assert_eq!(unite_activee_dans(&dossiers, "absente.timer"), Some(false));
        assert_eq!(unite_activee_dans(&dossiers, "nm-dispatcher"), Some(true));
        // Masquée dans /run : plus activée, même avec son lien d'activation encore là.
        std::fs::create_dir_all(&run).unwrap();
        symlink("/dev/null", run.join("sshd.service")).unwrap();
        assert_eq!(unite_activee_dans(&dossiers, "sshd"), Some(false));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unite_existe_dans_les_dossiers_standards() {
        let d = jetable("existe");
        ecrire(&d, "/usr/lib/systemd/system/sshd.service", "[Unit]\n");
        ecrire(&d, "/lib/systemd/system/ancien.service", "[Unit]\n");
        ecrire(&d, "/usr/local/lib/systemd/system/maison.timer", "[Timer]\n");
        ecrire(&d, "/etc/systemd/system/getty@.service", "[Unit]\n");
        assert!(unite_existe_sous(&d, "sshd"));
        assert!(unite_existe_sous(&d, "ancien.service"));
        assert!(unite_existe_sous(&d, "maison.timer"));
        assert!(unite_existe_sous(&d, &instance(3)), "instance d'un modèle présent");
        assert!(!unite_existe_sous(&d, "maison.service"));
        assert!(!unite_existe_sous(&d, "absente.service"));
        // Une unité masquée a toujours son fichier (le lien vers /dev/null).
        std::fs::create_dir_all(sous(&d, "/etc/systemd/system")).unwrap();
        symlink("/dev/null", sous(&d, "/etc/systemd/system/masquee.service")).unwrap();
        assert!(unite_existe_sous(&d, "masquee.service"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn processus_par_le_nom_court() {
        let d = jetable("proc");
        ecrire(&d, "/proc/1/comm", "systemd\n");
        ecrire(&d, "/proc/412/comm", "hypridle\n");
        ecrire(&d, "/proc/977/comm", "un-nom-tres-lon\n");
        ecrire(&d, "/proc/self/comm", "imposteur\n");
        ecrire(&d, "/proc/sys/comm", "faux\n");
        assert!(processus_nomme_sous(&d, "hypridle"));
        assert!(processus_nomme_sous(&d, "systemd"));
        assert!(!processus_nomme_sous(&d, "hypr"), "nom exact, pas un début");
        assert!(
            processus_nomme_sous(&d, "un-nom-tres-long-coupe"),
            "coupé à 15 octets comme par le noyau"
        );
        assert!(
            !processus_nomme_sous(&d, "imposteur"),
            "seuls les dossiers numériques sont des processus"
        );
        assert!(!processus_nomme_sous(&d, ""));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn services_par_le_groupe_de_controle() {
        let d = jetable("services");
        let liste = ["nextdns", "cloudflared", "unbound", "dnsmasq", "AdGuardHome"];
        assert_eq!(services_actifs_sous(&d, &liste), None, "pas de /proc");
        ecrire(&d, "/proc/1/cgroup", "0::/init.scope\n");
        // Un compte quelconque nomme son programme « nextdns » : il reste dans sa session.
        ecrire(&d, "/proc/50/comm", "nextdns\n");
        ecrire(
            &d,
            "/proc/50/cgroup",
            "0::/user.slice/user-1000.slice/session-2.scope\n",
        );
        // Un tunnel dans un conteneur.
        ecrire(&d, "/proc/60/cgroup", "0::/system.slice/docker-ab12.scope\n");
        // Le dnsmasq de libvirt, dans le groupe de libvirtd.
        ecrire(&d, "/proc/70/cgroup", "0::/system.slice/libvirtd.service\n");
        // Un nom qui commence comme un service n'en est pas un.
        ecrire(&d, "/proc/80/cgroup", "0::/system.slice/unbound.serviceX\n");
        assert_eq!(services_actifs_sous(&d, &liste), Some(vec![false; 5]));
        // Le vrai service, en cgroup v1 avec un sous-groupe, et AdGuard Home en v2.
        ecrire(
            &d,
            "/proc/90/cgroup",
            "12:pids:/system.slice/unbound.service\n1:name=systemd:/system.slice/unbound.service/aide\n",
        );
        ecrire(&d, "/proc/91/cgroup", "0::/system.slice/AdGuardHome.service\n");
        ecrire(&d, "/proc/self/cgroup", "0::/system.slice/nextdns.service\n");
        assert_eq!(
            services_actifs_sous(&d, &liste),
            Some(vec![false, false, true, false, true]),
            "seuls les dossiers numériques sont des processus"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dossiers_de_l_utilisateur() {
        let r = Path::new("/r");
        let maison = Path::new("/home/a");
        let attendu = |milieu: &[&str]| {
            let mut v = vec![PathBuf::from("/r/home/a/.config/systemd/user")];
            v.extend(milieu.iter().map(PathBuf::from));
            v.extend(
                [
                    "/r/etc/systemd/user",
                    "/r/run/user/7/systemd/user",
                    "/r/run/systemd/user",
                ]
                .map(PathBuf::from),
            );
            v
        };
        assert_eq!(dossiers_utilisateur(r, maison, None, 7), attendu(&[]));
        // XDG_CONFIG_HOME du shell : ~/.config reste, là où Vanguard écrit et où systemd --user regarde.
        assert_eq!(
            dossiers_utilisateur(r, maison, Some(Path::new("/home/a/.xdg")), 7),
            attendu(&["/r/home/a/.xdg/systemd/user"])
        );
        assert_eq!(
            dossiers_utilisateur(r, maison, Some(Path::new("/home/a/.config")), 7),
            attendu(&[]),
            "sans doublon"
        );
        // Un chemin relatif est ignoré, comme le fait systemd.
        assert_eq!(dossiers_utilisateur(r, maison, Some(Path::new("rel")), 7), attendu(&[]));
    }

    /// Une base pacman inventée : un paquet par (dossier, nom, version, fichiers).
    fn base_pacman(racine: &Path, paquets: &[(&str, &str, &str, &[&str])]) {
        for (dossier, nom, version, fichiers) in paquets {
            let d = format!("{PACMAN_LOCAL}/{dossier}");
            ecrire(
                racine,
                &format!("{d}/desc"),
                &format!(
                    "%NAME%\n{nom}\n\n%VERSION%\n{version}\n\n%SIZE%\n1043228\n\n%REASON%\n1\n\n\
                     %DEPENDS%\nbash\nglibc>=2.40\n\n"
                ),
            );
            let liste = fichiers.join("\n");
            ecrire(
                racine,
                &format!("{d}/files"),
                &format!("%FILES%\n{liste}\n%BACKUP%\netc/x.conf\tabc\n"),
            );
        }
        ecrire(racine, &format!("{PACMAN_LOCAL}/ALPM_DB_VERSION"), "9\n");
    }

    #[test]
    fn pacman_lit_desc_et_files() {
        let d = jetable("pacman");
        assert_eq!(paquets_pacman_sous(&d), None, "pas de base : non vérifié");
        base_pacman(
            &d,
            &[
                (
                    "python-3to2-1.1.1-1",
                    "python-3to2",
                    "1.1.1-1",
                    &["usr/", "usr/bin/3to2"],
                ),
                (
                    "linux-6.17.1.arch1-1",
                    "linux",
                    "6.17.1.arch1-1",
                    &["usr/lib/modules/x/vmlinuz"],
                ),
                (
                    "linux-firmware-20261001-1",
                    "linux-firmware",
                    "20261001-1",
                    &["usr/", "usr/lib/firmware/a.bin"],
                ),
            ],
        );
        assert_eq!(
            paquets_pacman_sous(&d).unwrap(),
            [
                ("linux".to_string(), "6.17.1.arch1-1".to_string()),
                ("linux-firmware".into(), "20261001-1".into()),
                ("python-3to2".into(), "1.1.1-1".into()),
            ]
        );
        // « linux-firmware-… » commence aussi par « linux- » : le nom vient de desc.
        let (dossier, champs) = dossier_pacman(&d, "linux").unwrap();
        assert!(dossier.ends_with("linux-6.17.1.arch1-1"));
        assert_eq!(premier(&champs, "SIZE"), Some("1043228"));
        assert_eq!(premier(&champs, "REASON"), Some("1"));
        assert_eq!(champs["DEPENDS"], ["bash", "glibc>=2.40"]);
        assert!(dossier_pacman(&d, "python").is_none());
        let p = proprietaire_pacman_sous(
            &d,
            &[
                Path::new("/usr/bin/3to2"),
                Path::new("/usr/lib/firmware/a.bin"),
                Path::new("/usr"),
                Path::new("/etc/x.conf"),
                Path::new("/orphelin"),
            ],
        )
        .unwrap();
        assert_eq!(p.len(), 2, "{p:?}");
        assert_eq!(p[Path::new("/usr/bin/3to2")], "python-3to2");
        assert_eq!(p[Path::new("/usr/lib/firmware/a.bin")], "linux-firmware");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn champs_pacman_garde_les_listes_et_les_champs_vides() {
        let c = champs_pacman("%NAME%\nalice-outil\n\n%GROUPS%\n\n%DEPENDS%\na\nb\n\n%XDATA%\npkgtype=pkg\n");
        assert_eq!(premier(&c, "NAME"), Some("alice-outil"));
        assert_eq!(c["GROUPS"], Vec::<String>::new());
        assert_eq!(c["DEPENDS"], ["a", "b"]);
        assert_eq!(c["XDATA"], ["pkgtype=pkg"]);
    }

    const STATUS: &str = "Package: bash\nStatus: install ok installed\nPriority: required\nArchitecture: amd64\n\
        Version: 5.2.37-2\nDescription: GNU Bourne Again SHell\n Bash is an sh-compatible command language\n\
        \n\
        Package: ancien\nStatus: deinstall ok config-files\nVersion: 1.0-1\n\
        \n\
        Package: libc6\nStatus: install ok installed\nArchitecture: i386\nMulti-Arch: same\nVersion: 2.41-6\n\
        \n\
        Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: same\nVersion: 2.41-6\n\
        Conffiles:\n /etc/ld.so.conf.d/x86_64-linux-gnu.conf abc\n\
        \n\
        Package: demi\nStatus: install ok half-configured\nVersion: 3\n";

    #[test]
    fn paquet_retire_pas_compte_installe() {
        assert!(installe_selon_dpkg("install ok installed"));
        assert!(installe_selon_dpkg("hold ok installed\n"));
        assert!(!installe_selon_dpkg("deinstall ok config-files"));
        assert!(!installe_selon_dpkg("install ok half-installed"));
        assert!(!installe_selon_dpkg(""));
    }

    #[test]
    fn paquets_de_dpkg_avec_leur_architecture() {
        let status = "Package: steam-installer\nStatus: install ok installed\nArchitecture: amd64\n\
                      Description: jeux\n Status: deinstall ok config-files\n\n\
                      Package: libvulkan1\nStatus: hold ok installed\nArchitecture: i386\n\n\
                      Package: ancien\nStatus: deinstall ok config-files\nArchitecture: amd64\n";
        assert_eq!(
            architectures_installees_selon(status),
            [
                ("libvulkan1".to_string(), "i386".to_string()),
                ("steam-installer".to_string(), "amd64".to_string())
            ]
        );
        assert_eq!(architectures_installees_selon(""), Vec::<(String, String)>::new());
    }

    /// Un paquet retenu (« hold ») est installé : il a sa version.
    #[test]
    fn paquet_retenu_a_sa_version() {
        let status = "Package: openssh-server\nStatus: hold ok installed\nVersion: 1:9.6p1-3\n";
        assert_eq!(
            paquets_dpkg_selon(status),
            [("openssh-server".to_string(), "1:9.6p1-3".to_string())]
        );
    }

    #[test]
    fn dpkg_lit_status_et_arch() {
        assert_eq!(
            paquets_dpkg_selon(STATUS),
            [
                ("bash".to_string(), "5.2.37-2".to_string()),
                ("libc6".into(), "2.41-6".into())
            ]
        );
        let d = jetable("dpkg");
        assert_eq!(paquets_dpkg_sous(&d), None);
        assert_eq!(architectures_dpkg_sous(&d), None);
        ecrire(&d, DPKG_STATUS, STATUS);
        ecrire(&d, "/var/lib/dpkg/arch", "amd64\ni386\n");
        ecrire(&d, "/var/lib/dpkg/info/bash.md5sums", "abc  bin/bash\n");
        assert_eq!(paquets_dpkg_sous(&d).unwrap().len(), 2);
        assert_eq!(architectures_dpkg_sous(&d).unwrap(), ["amd64", "i386"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn flatpak_lit_les_dossiers_app() {
        let d = jetable("flatpak");
        let (systeme, compte) = (d.join("systeme"), d.join("compte"));
        let installations = [systeme.clone(), compte.clone()];
        assert_eq!(flatpak_apps_dans(&installations), Vec::<String>::new());
        let metadata = "[Application]\nname=org.exemple.Salon\n\n[Context]\nshared=network;ipc;\n\
                        sockets=x11;pulseaudio;\ndevices=all;\n# commentaire\n\n[Session Bus Policy]\na=talk\n";
        for (i, id) in [
            (&systeme, "org.exemple.Salon"),
            (&compte, "org.exemple.Salon"),
            (&compte, "com.alice.Notes"),
        ] {
            let actif = i.join("app").join(id).join("current/active");
            std::fs::create_dir_all(&actif).unwrap();
            std::fs::write(
                actif.join("metadata"),
                metadata.replace("x11", &i.file_name().unwrap().to_string_lossy()),
            )
            .unwrap();
        }
        // Désinstallation interrompue : le dossier reste, sans branche en service.
        std::fs::create_dir_all(systeme.join("app/org.exemple.Fantome")).unwrap();
        assert_eq!(
            flatpak_apps_dans(&installations),
            ["com.alice.Notes", "org.exemple.Salon"]
        );
        let m = flatpak_metadata_dans(&installations, "org.exemple.Salon").unwrap();
        assert!(m.contains("sockets=compte;"), "celle du compte d'abord : {m}");
        assert_eq!(
            section_ini(&m, "Context"),
            [
                ("shared", "network;ipc;"),
                ("sockets", "compte;pulseaudio;"),
                ("devices", "all;")
            ]
        );
        assert!(flatpak_metadata_dans(&installations, "org.exemple.Fantome").is_none());
        assert!(flatpak_metadata_dans(&installations, "../compte/app/com.alice.Notes").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn snaps_lit_les_revisions_et_current() {
        let d = jetable("snap");
        assert_eq!(snaps_sous(&d), None, "pas de snapd");
        for f in [
            "core22_1981.snap",
            "core22_2045.snap",
            "firefox_10.snap",
            "firefox_9.snap",
            "firefox_x1.snap",
        ] {
            ecrire(&d, &format!("/var/lib/snapd/snaps/{f}"), "");
        }
        ecrire(&d, "/var/lib/snapd/snaps/partial/rien", "");
        std::fs::create_dir_all(sous(&d, "/snap/firefox")).unwrap();
        symlink("10", sous(&d, "/snap/firefox/current")).unwrap();
        std::fs::create_dir_all(sous(&d, "/var/lib/snapd/snap/core22")).unwrap();
        symlink("2045", sous(&d, "/var/lib/snapd/snap/core22/current")).unwrap();
        assert_eq!(
            snaps_sous(&d).unwrap(),
            [
                Snap {
                    nom: "core22".into(),
                    courante: Some("2045".into()),
                    revisions: vec!["1981".into(), "2045".into()]
                },
                Snap {
                    nom: "firefox".into(),
                    courante: Some("10".into()),
                    revisions: vec!["9".into(), "10".into(), "x1".into()]
                },
            ]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn disques_lus_dans_sys_block() {
        let d = jetable("disques");
        // Un NVMe, une clé USB (SCSI sous un contrôleur usb2), un lecteur de DVD SATA, un dm et un loop.
        let appareils = [
            (
                "nvme0n1",
                "sys/devices/pci0000:00/0000:00:01.2/nvme/nvme0",
                "nvme",
                "259:0",
            ),
            (
                "sda",
                "sys/devices/pci0000:00/usb2/2-4/2-4:1.0/host6/target6:0:0/6:0:0:0",
                "scsi",
                "8:0",
            ),
            (
                "sr0",
                "sys/devices/pci0000:00/ata3/host2/target2:0:0/2:0:0:0",
                "scsi",
                "11:0",
            ),
            ("dm-0", "sys/devices/virtual/block/dm-0", "", "253:0"),
            ("loop0", "sys/devices/virtual/block/loop0", "", "7:0"),
        ];
        for (nom, appareil, sous_systeme, dev) in appareils {
            let a = d.join(appareil);
            std::fs::create_dir_all(&a).unwrap();
            if !sous_systeme.is_empty() {
                let s = d.join("sys/class").join(sous_systeme);
                std::fs::create_dir_all(&s).unwrap();
                symlink(&s, a.join("subsystem")).unwrap();
            }
            let b = sous(&d, &format!("/sys/block/{nom}"));
            std::fs::create_dir_all(b.join("queue")).unwrap();
            symlink(&a, b.join("device")).unwrap();
            std::fs::write(b.join("dev"), format!("{dev}\n")).unwrap();
        }
        let w = |chemin: &str, texte: &str| ecrire(&d, chemin, texte);
        w("/sys/block/nvme0n1/size", "3907029168\n");
        w("/sys/block/nvme0n1/queue/rotational", "0\n");
        w("/sys/block/nvme0n1/removable", "0\n");
        w(
            "/sys/block/nvme0n1/device/model",
            "Disque Salon 2TB                        \n",
        );
        w("/sys/block/nvme0n1/device/serial", "  SALON0001  \n");
        w("/sys/block/sda/size", "122880000\n");
        w("/sys/block/sda/queue/rotational", "1\n");
        w("/sys/block/sda/removable", "1\n");
        w("/sys/block/sda/device/model", "ProductCode     \n");
        w("/sys/block/sda/device/type", "0\n");
        w(
            "/run/udev/data/b8:0",
            "S:disk/by-id/usb-x\nE:ID_BUS=usb\nE:ID_SERIAL_SHORT=ALICE42\n",
        );
        // Un disque SATA : sysfs coupe le modèle à 16 octets, udev le garde entier (bourré d'espaces).
        let sata = d.join("sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0");
        std::fs::create_dir_all(&sata).unwrap();
        let bloc = sous(&d, "/sys/block/sdb");
        std::fs::create_dir_all(bloc.join("queue")).unwrap();
        symlink(&sata, bloc.join("device")).unwrap();
        w("/sys/block/sdb/dev", "8:16\n");
        w("/sys/block/sdb/size", "100\n");
        w("/sys/block/sdb/device/model", "Disque Essai 870\n");
        w(
            "/run/udev/data/b8:16",
            "E:ID_MODEL=Disque_Essai_870_EVO_1TB\n\
             E:ID_MODEL_ENC=Disque\\x20Essai\\x20870\\x20EVO\\x201TB\\x20\\x20\\x20\n",
        );
        w("/sys/block/sr0/size", "2097151\n");
        w("/sys/block/sr0/queue/rotational", "1\n");
        w("/sys/block/sr0/removable", "1\n");
        w("/sys/block/sr0/device/type", "5\n");
        w("/run/udev/data/b11:0", "E:ID_MODEL=Graveur_DVD  Essai \n");
        w("/sys/block/dm-0/size", "100\n");
        w("/sys/block/loop0/size", "0\n");
        let l = disques_sous(&d);
        assert_eq!(
            l.iter().map(|x| x.nom.as_str()).collect::<Vec<_>>(),
            ["dm-0", "loop0", "nvme0n1", "sda", "sdb", "sr0"]
        );
        assert_eq!(
            l[4].modele, "Disque Essai 870 EVO 1TB",
            "le modèle ATA entier, pas celui de sysfs"
        );
        let nvme = &l[2];
        assert_eq!(
            (
                nvme.octets,
                nvme.rotatif,
                nvme.amovible,
                nvme.bus.as_str(),
                nvme.genre.as_str()
            ),
            (3_907_029_168 * 512, false, false, "nvme", "disk")
        );
        assert_eq!(
            (nvme.modele.as_str(), nvme.serie.as_str()),
            ("Disque Salon 2TB", "SALON0001")
        );
        let cle = &l[3];
        assert_eq!(
            (cle.rotatif, cle.amovible, cle.bus.as_str(), cle.serie.as_str()),
            (true, true, "usb", "ALICE42")
        );
        assert_eq!(cle.modele, "ProductCode");
        let dvd = &l[5];
        assert_eq!(
            (dvd.genre.as_str(), dvd.bus.as_str(), dvd.modele.as_str()),
            ("rom", "sata", "Graveur_DVD Essai")
        );
        assert_eq!((l[0].genre.as_str(), l[0].bus.as_str()), ("dm", ""));
        assert_eq!(l[1].genre, "loop");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn racine_depuis_mountinfo() {
        let mountinfo = "22 1 0:21 / /proc rw,nosuid - proc proc rw\n\
            25 1 259:3 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n\
            26 25 0:30 / /mnt/Mes\\040disques rw - vfat /dev/sdb1 rw\n\
            31 1 253:0 /@ / rw,noatime shared:1 - btrfs /dev/mapper/racine\\040chiffr\\303\\251e rw,subvol=/@\n";
        let rien = Path::new("/nulle-part");
        assert_eq!(
            racine_selon(mountinfo, rien),
            Some(("/dev/mapper/racine chiffrée".to_string(), "btrfs".to_string())),
            "le dernier montage sur / l'emporte, échappements décodés"
        );
        assert_eq!(racine_selon("22 1 0:21 / /proc rw - proc proc rw\n", rien), None);
        assert_eq!(racine_selon("", rien), None);
    }

    /// « /dev/root » (noyau monté sans initramfs) : le vrai périphérique, retrouvé par son numéro, comme findmnt
    /// le montre ; sans sysfs qui le connaisse, le nom reste tel quel plutôt qu'inventé.
    #[test]
    fn racine_dev_root_par_son_numero() {
        let d = jetable("dev-root");
        ecrire(
            &d,
            "/sys/dev/block/8:1/uevent",
            "MAJOR=8\nMINOR=1\nDEVNAME=sda1\nDEVTYPE=partition\n",
        );
        let mountinfo = "25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/root rw\n";
        assert_eq!(
            racine_selon(mountinfo, &d),
            Some(("/dev/sda1".to_string(), "ext4".to_string()))
        );
        let inconnu = "25 1 8:9 / / rw,relatime shared:1 - ext4 /dev/root rw\n";
        assert_eq!(
            racine_selon(inconnu, &d),
            Some(("/dev/root".to_string(), "ext4".to_string()))
        );
        let piege = "25 1 ../../x / / rw - ext4 /dev/root rw\n";
        assert_eq!(
            racine_selon(piege, &d),
            Some(("/dev/root".to_string(), "ext4".to_string()))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn chiffre_remonte_les_slaves() {
        let d = jetable("crypt");
        let bloc = |nom: &str| sous(&d, &format!("/sys/class/block/{nom}"));
        // LVM (dm-1) sur LUKS (dm-0) sur une partition ; et une partition seule.
        for nom in ["nvme0n1p2", "nvme0n1p3", "dm-0", "dm-1"] {
            std::fs::create_dir_all(bloc(nom).join("slaves")).unwrap();
        }
        ecrire(
            &d,
            "/sys/class/block/dm-0/dm/uuid",
            "CRYPT-LUKS2-0123456789abcdef-racine\n",
        );
        ecrire(&d, "/sys/class/block/dm-1/dm/uuid", "LVM-abcdef\n");
        symlink(bloc("nvme0n1p2"), bloc("dm-0").join("slaves/nvme0n1p2")).unwrap();
        symlink(bloc("dm-0"), bloc("dm-1").join("slaves/dm-0")).unwrap();
        assert_eq!(chiffre_sous(&d, "dm-1"), Some(true));
        assert_eq!(chiffre_sous(&d, "dm-0"), Some(true));
        assert_eq!(chiffre_sous(&d, "nvme0n1p3"), Some(false));
        assert_eq!(chiffre_sous(&d, "sdz9"), None, "inconnu : non vérifié");
        // Une boucle de liens ne bloque pas.
        std::fs::create_dir_all(bloc("dm-2").join("slaves")).unwrap();
        symlink(bloc("dm-2"), bloc("dm-2").join("slaves/dm-2")).unwrap();
        assert_eq!(chiffre_sous(&d, "dm-2"), Some(false));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn groupes_et_constantes() {
        let g = groupes().unwrap();
        assert!(!g.is_empty() && g.iter().all(|n| !n.is_empty()));
        assert_eq!(g.len(), g.iter().collect::<HashSet<_>>().len(), "sans doublon");
        assert!(tics() > 0);
        assert!(taille_page() >= 4096 && taille_page().is_power_of_two());
    }

    // Tests « comme la commande » : sur cet ordinateur, la lecture native dit la même chose que l'outil, quand il
    // est là (sinon rien n'est conclu).

    #[test]
    fn comme_pacman_q() {
        // La liste entière : la même comparaison que l'autotest (machine::linux::croisees).
        crate::autotest::croisees::essayer("AUT-LNX-001");
        if commande("pacman", &["-V"]).is_none() {
            return crate::essais::saute("pacman absent");
        }
        // Le propriétaire de deux fichiers sûrs, et les champs d'un paquet.
        if let Some(sortie) = commande("pacman", &["-Qoq", "/usr/bin/pacman", "/etc/pacman.conf"]) {
            let p = proprietaire_pacman(&[Path::new("/usr/bin/pacman"), Path::new("/etc/pacman.conf")]).unwrap();
            let mut natif: Vec<&str> = vec![&p[Path::new("/usr/bin/pacman")], &p[Path::new("/etc/pacman.conf")]];
            let mut attendu: Vec<&str> = sortie.lines().collect();
            natif.sort_unstable();
            attendu.sort_unstable();
            assert_eq!(natif, attendu);
        }
        let desc = desc_pacman("pacman").unwrap();
        assert!(premier(&desc, "SIZE").is_some_and(|t| t.parse::<u64>().is_ok()));
    }

    #[test]
    fn comme_dpkg_query() {
        crate::autotest::croisees::essayer("AUT-LNX-002");
        if let Some(sortie) = commande("dpkg", &["--print-foreign-architectures"]) {
            let natif = architectures_dpkg().unwrap_or_default();
            for a in sortie.split_whitespace() {
                assert!(natif.iter().any(|n| n == a), "{a} absente de {natif:?}");
            }
        }
    }

    #[test]
    fn comme_lsblk() {
        let Some(sortie) = commande("lsblk", &["-dnbP", "-o", "NAME,SIZE,ROTA,RM,TYPE,TRAN,MODEL,SERIAL"]) else {
            return crate::essais::saute("lsblk absent");
        };
        let natifs = disques();
        for ligne in sortie.lines() {
            let champ = |cle: &str| {
                let debut = format!("{cle}=\"");
                let reste = &ligne[ligne.find(&debut)? + debut.len()..];
                Some(reste[..reste.find('"')?].to_string())
            };
            let (Some(nom), Some(genre)) = (champ("NAME"), champ("TYPE")) else {
                continue;
            };
            // lsblk donne un autre nom aux dm (crypt, lvm) : seuls disques et lecteurs se comparent.
            if genre != "disk" && genre != "rom" {
                continue;
            }
            let n = natifs
                .iter()
                .find(|d| d.nom == nom)
                .unwrap_or_else(|| panic!("{nom} absent : {natifs:?}"));
            assert_eq!(Some(n.octets.to_string()), champ("SIZE"), "{nom}");
            assert_eq!(champ("ROTA").as_deref() == Some("1"), n.rotatif, "{nom}");
            assert_eq!(champ("RM").as_deref() == Some("1"), n.amovible, "{nom}");
            assert_eq!(Some(n.genre.clone()), Some(genre), "{nom}");
            for (cle, natif) in [("TRAN", &n.bus), ("MODEL", &n.modele), ("SERIAL", &n.serie)] {
                // lsblk laisse vide ce qu'udev ne lui donne pas : on ne compare que ce qu'il sait.
                if let Some(v) = champ(cle).filter(|v| !v.is_empty()) {
                    assert_eq!(natif.trim(), v.trim(), "{nom} {cle}");
                }
            }
        }
    }

    #[test]
    fn comme_findmnt() {
        let Some(sortie) = commande("findmnt", &["-no", "SOURCE,FSTYPE", "/"]) else {
            return crate::essais::saute("findmnt absent");
        };
        let mut c = sortie.split_whitespace();
        let (Some(source), Some(genre)) = (c.next(), c.next()) else {
            return crate::essais::saute("findmnt illisible");
        };
        // findmnt ajoute « [/sous-volume] » à la source d'un Btrfs.
        let source = source.split('[').next().unwrap_or(source);
        let (s, g) = racine().unwrap();
        assert_eq!((s.as_str(), g.as_str()), (source, genre));
        // Et le chiffrement, comme le maillon « crypt » de lsblk.
        if let (Some(types), Some(natif)) = (commande("lsblk", &["-nso", "TYPE", &s]), chiffre(&s)) {
            assert_eq!(natif, types.lines().any(|t| t.trim() == "crypt"), "{types}");
        }
    }

    #[test]
    fn comme_id_ng() {
        crate::autotest::croisees::essayer("AUT-LNX-005");
        let Some(sortie) = commande("id", &["-nG"]) else {
            return crate::essais::saute("id absent");
        };
        assert_eq!(
            groupes().unwrap().first().map(String::as_str),
            sortie.split_whitespace().next(),
            "le principal d'abord"
        );
    }

    #[test]
    fn comme_systemctl_is_enabled() {
        crate::autotest::croisees::essayer("AUT-LNX-004");
        // La lecture croisée ne regarde pas si l'unité existe : le test, lui, confronte unite_existe au vrai
        // système, sans quoi seul un dossier inventé le vérifierait.
        if let Some(s) = commande(
            "systemctl",
            &[
                "list-unit-files",
                "--no-legend",
                "--plain",
                "--state=enabled,disabled,masked",
            ],
        ) {
            for u in s.lines().filter_map(|l| l.split_whitespace().next()) {
                assert!(unite_existe(u), "{u}");
            }
        }
    }

    #[test]
    fn comme_getconf() {
        if let Some(t) = commande("getconf", &["CLK_TCK"]) {
            assert_eq!(t.trim(), tics().to_string());
        }
        if let Some(t) = commande("getconf", &["PAGESIZE"]) {
            assert_eq!(t.trim(), taille_page().to_string());
        }
    }
    /// Un tube nommé, un lien vers /dev/zero ou un dossier ne se lisent pas ; un fichier trop long s'arrête à la
    /// borne. Sans la vérification, le tube bloquerait le test pour toujours.
    #[test]
    fn lecture_bornee_aux_fichiers_ordinaires() {
        let d = jetable("borne");
        std::fs::write(d.join("unite.service"), "[Install]\nDefaultInstance=tty1\n").unwrap();
        std::fs::write(d.join("long"), "x".repeat(5000)).unwrap();
        crate::essais::tube_nomme(&d.join("tube")).unwrap();
        symlink("/dev/zero", d.join("zero")).unwrap();
        symlink(d.join("unite.service"), d.join("lien.service")).unwrap();
        let depart = std::time::Instant::now();
        assert_eq!(
            lire_borne(&d.join("lien.service"), 1024).as_deref(),
            Some("[Install]\nDefaultInstance=tty1\n")
        );
        assert_eq!(lire_borne(&d.join("long"), 1024).map(|t| t.len()), Some(1024));
        for n in ["tube", "zero", "absent"] {
            assert_eq!(lire_borne(&d.join(n), 1024), None, "{n}");
        }
        assert_eq!(lire_borne(&d, 1024), None);
        assert!(depart.elapsed() < std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&d);
    }
}
