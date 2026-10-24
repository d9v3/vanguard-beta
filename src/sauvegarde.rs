//! Sauvegarde automatique guidée : la meilleure défense contre un disque qui lâche, un vol ou un rançongiciel, mise en
//! place avec l'outil du système, vers un disque externe, après accord, et annulable exactement. Linux : Déjà Dup s'il
//! est là (ses réglages gsettings, valeurs d'avant notées), sinon une minuterie systemd de l'utilisateur qui lance rsync
//! chaque jour vers le disque (et se tait quand il n'est pas branché) ; macOS : Time Machine (`tmutil`) ; Windows :
//! l'Historique des fichiers, que Vanguard vérifie au bilan et guide pas à pas (il se règle dans le Panneau de
//! configuration, rien ne se fait à sa place). Ce que Vanguard a posé est noté (sauvegarde.json) pour ne retirer que ça.
//! Jamais vers la clé VANGUARD ni le disque du système : la liste des disques de Copier mes fichiers les exclut.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::selection::{Ligne, choisir};
#[cfg(not(windows))]
use crate::socle::taille_lisible;
use crate::ui::*;

/// Le dossier posé sur le disque externe, un sous-dossier par ordinateur.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DOSSIER: &str = "Sauvegarde-Vanguard";
/// Les unités systemd posées par Vanguard (le nom contient « sauvegarde » : le bilan les reconnaît comme une vraie
/// sauvegarde).
pub(crate) const TIMER: &str = "vanguard-sauvegarde.timer";
pub(crate) const SERVICE: &str = "vanguard-sauvegarde.service";
/// L'heure du passage quotidien ; l'ordinateur éteint à cette heure-là, le passage se fait au prochain démarrage.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HEURE: &str = "12:00:00";

/// Ce que Vanguard a mis en place, pour l'annuler exactement.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MiseEnPlace {
    /// Linux : minuterie et service de systemd --user, avec l'empreinte de chaque fichier posé (un fichier modifié
    /// depuis n'est pas retiré).
    Systemd {
        date: String,
        destination: String,
        empreinte_timer: String,
        empreinte_service: String,
    },
    /// Linux : réglages de Déjà Dup, avec la valeur d'avant de chaque clé.
    DejaDup {
        date: String,
        destination: String,
        avant: Vec<(String, String)>,
    },
    /// macOS : destination ajoutée à Time Machine (son identifiant), et si Time Machine était déjà actif.
    TimeMachine {
        date: String,
        destination: String,
        identifiant: Option<String>,
        deja_actif: bool,
    },
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
struct Notes {
    #[serde(default)]
    mise_en_place: Option<MiseEnPlace>,
}

/// La note de ce qui a été mis en place, dans le dossier de données.
pub(crate) const NOTES: &str = "sauvegarde.json";

fn fichier_notes() -> PathBuf {
    crate::socle::dossier_local().join(NOTES)
}

fn charger_de(chemin: &Path) -> Notes {
    crate::socle::lire_texte_ordinaire(chemin, 16 << 20)
        .ok()
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_default()
}

/// Note ce qui vient d'être mis en place, pour pouvoir l'annuler ; dit si la note n'a pas pu s'écrire.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn noter(m: &MiseEnPlace) {
    if let Err(e) = ecrire_dans(
        &fichier_notes(),
        &Notes {
            mise_en_place: Some(m.clone()),
        },
    ) {
        mauvais(&trf!(
            "La note de ce qui a été mis en place n'a pas pu être écrite ({e}) : l'annulation devra se faire à la main.",
            "The note of what was set up could not be written ({e}): undoing will have to be done by hand."
        ));
    }
}

/// Les unités reprises sous le nouveau nom (`passage`) : leurs empreintes changent, la note suit pour que
/// « Annuler » les retire encore.
#[cfg(target_os = "linux")]
pub(crate) fn reprendre_note(timer: &str, service: &str) {
    let mut notes = charger_de(&fichier_notes());
    if let Some(MiseEnPlace::Systemd {
        empreinte_timer,
        empreinte_service,
        ..
    }) = notes.mise_en_place.as_mut()
    {
        *empreinte_timer = empreinte(timer);
        *empreinte_service = empreinte(service);
        let _ = ecrire_dans(&fichier_notes(), &notes);
    }
}

fn ecrire_dans(chemin: &Path, notes: &Notes) -> std::io::Result<()> {
    if let Some(parent) = chemin.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(chemin, serde_json::to_string_pretty(notes).unwrap_or_default())
}

#[cfg_attr(windows, allow(dead_code))]
fn aujourd_hui() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn empreinte(texte: &str) -> String {
    blake3::hash(texte.as_bytes()).to_hex().to_string()
}

/// Le nom de cet ordinateur, pour son dossier sur le disque ; « ordinateur » à défaut.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_machine() -> String {
    let brut = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default();
    let propre: String = brut
        .trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .take(40)
        .collect();
    if propre.is_empty() { "ordinateur".into() } else { propre }
}

// ───────────────────────────── Linux : systemd + rsync ─────────────────────────────

/// Un argument cité pour ExecStart= de systemd : entre guillemets, « \ » et « " » protégés, « % » doublé (systemd y
/// lit ses propres codes).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn citer_systemd(t: &str) -> String {
    format!(
        "\"{}\"",
        t.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%")
    )
}

/// Un chemin prêt pour une ligne d'unité systemd, `None` s'il contient un caractère de contrôle. Le chemin vient en
/// partie du nom du disque, que choisit qui l'a formaté : un saut de ligne y ajouterait à l'unité une ligne de son
/// choix (ExecStartPre=…), lancée chaque jour sous ce compte.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn chemin_systemd(p: &Path) -> Option<String> {
    let t = p.display().to_string();
    (!t.chars().any(char::is_control)).then(|| t.replace('%', "%%"))
}

/// Pourquoi les unités ne s'écrivent pas.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Refus {
    /// Un chemin contient un caractère de contrôle.
    Controle,
    /// L'identité du disque (UUID de son système de fichiers, findmnt pour la vérifier) ne se lit pas.
    Identite,
}

/// L'UUID tel qu'il peut entrer dans une ligne d'unité : lettres, chiffres et tirets seulement.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn uuid_valide(uuid: &str) -> bool {
    !uuid.is_empty() && uuid.len() <= 64 && uuid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// La ligne qui fait vérifier le disque à chaque passage. Le chemin de montage vient de l'étiquette du disque, que
/// choisit qui l'a formaté : sans elle, tout disque de même nom recevrait chaque jour la copie des dossiers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const VERIFICATION: &str = "ExecCondition=";

/// L'unité posée vérifie-t-elle l'identité du disque ? Celles d'avant la 0.78 ne regardaient que son chemin.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn verifie_le_disque(service: &str) -> bool {
    service
        .lines()
        .any(|l| l.starts_with(VERIFICATION) && l.contains(" --source UUID="))
}

/// Les deux fichiers d'unité : (timer, service). `racine` : le disque, dont le montage conditionne le passage ;
/// `destination` : le dossier de cet ordinateur dessus ; `sources` : les dossiers personnels copiés tels quels.
/// `findmnt` et `uuid` : chaque passage vérifie que le système de fichiers monté à `racine` est bien celui choisi ;
/// un autre disque au même endroit, et le passage est sauté sans erreur (code 1 de findmnt, `ExecCondition`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn unites(
    rsync: &Path,
    findmnt: Option<&Path>,
    uuid: Option<&str>,
    racine: &Path,
    destination: &Path,
    sources: &[PathBuf],
    fat: bool,
) -> Result<(String, String), Refus> {
    let (Some(findmnt), Some(uuid)) = (findmnt, uuid.filter(|u| uuid_valide(u))) else {
        return Err(Refus::Identite);
    };
    let tous = [rsync, findmnt, racine, destination]
        .into_iter()
        .chain(sources.iter().map(PathBuf::as_path));
    for p in tous {
        chemin_systemd(p).ok_or(Refus::Controle)?;
    }
    let timer = format!(
        "[Unit]\nDescription=Sauvegarde Vanguard, chaque jour\n\n[Timer]\nOnCalendar=*-*-* {HEURE}\nPersistent=true\nRandomizedDelaySec=10min\n\n[Install]\nWantedBy=timers.target\n"
    );
    // FAT et exFAT (presque toutes les clés USB) : ni liens symboliques, ni droits, ni propriétaires, et une heure à
    // 2 s près. « -a » y échouait sur chaque lien (rsync sort en erreur, chaque jour) et, sans tolérance sur l'heure,
    // tout serait recopié à chaque passage : fichiers et heures seulement, les liens laissés de côté.
    let options: &[&str] = if fat {
        &["-rt", "--modify-window=2"]
    } else {
        &["-a", "--no-specials", "--no-devices"]
    };
    let mut commande = vec![citer_systemd(&rsync.display().to_string())];
    commande.extend(options.iter().map(|o| (*o).to_string()));
    commande.extend([
        "--exclude=.cache".to_string(),
        "--exclude=node_modules".to_string(),
        "--exclude=.vanguard-copie-en-cours".to_string(),
    ]);
    commande.extend(sources.iter().map(|s| citer_systemd(&s.display().to_string())));
    commande.push(citer_systemd(&format!("{}/", destination.display())));
    let verification = format!(
        "{VERIFICATION}{} --source UUID={uuid} --mountpoint {}",
        citer_systemd(&findmnt.display().to_string()),
        citer_systemd(&racine.display().to_string())
    );
    let service = format!(
        "[Unit]\nDescription=Sauvegarde Vanguard vers {}\n# Disque débranché : rien ne se passe, sans erreur.\nConditionPathIsMountPoint={}\n\n[Service]\nType=oneshot\nNice=10\nIOSchedulingClass=idle\n# Un autre disque monté au même endroit (même nom) : passage sauté.\n{verification}\n# 24 : un fichier a disparu pendant la copie, normal pour un dossier en usage.\nSuccessExitStatus=24\nExecStart={}\n",
        chemin_systemd(destination).ok_or(Refus::Controle)?,
        chemin_systemd(racine).ok_or(Refus::Controle)?,
        commande.join(" ")
    );
    Ok((timer, service))
}

/// Le système de fichiers monté à `racine` (« vfat », « ext4 »…), d'après /proc/mounts.
#[cfg(target_os = "linux")]
fn systeme_de_fichiers(racine: &Path) -> Option<String> {
    systeme_de_fichiers_selon(&std::fs::read_to_string("/proc/mounts").ok()?, racine)
}

#[cfg(any(target_os = "linux", test))]
fn systeme_de_fichiers_selon(montages: &str, racine: &Path) -> Option<String> {
    montages.lines().find_map(|l| {
        let mut champs = l.split_whitespace();
        let (_, point, systeme) = (champs.next()?, champs.next()?, champs.next()?);
        (Path::new(&crate::copier::sans_echappements(point)) == racine).then(|| systeme.to_string())
    })
}

/// Un système de fichiers sans liens symboliques ni droits Unix, à l'heure près de 2 s : la famille FAT.
#[cfg(any(target_os = "linux", test))]
fn sans_liens(systeme: &str) -> bool {
    matches!(systeme, "vfat" | "msdos" | "exfat" | "fat" | "umsdos")
}

#[cfg(target_os = "linux")]
pub(crate) fn dossier_unites() -> PathBuf {
    let maison = crate::socle::maison();
    std::env::var_os("XDG_CONFIG_HOME")
        .map_or_else(|| maison.join(".config"), PathBuf::from)
        .join("systemd/user")
}

/// Le chemin d'un programme du PATH, écrit en entier dans l'unité systemd (qui ne cherche pas dans le PATH).
#[cfg(target_os = "linux")]
fn dans_le_path(commande: &str) -> Option<PathBuf> {
    crate::machine::linux::natif::chemin(commande)
}

/// Les clés de Déjà Dup que Vanguard règle : (schéma, clé, valeur voulue) ; la destination se construit à part.
#[cfg(target_os = "linux")]
fn cles_deja_dup(destination: &Path) -> Vec<(&'static str, &'static str, String)> {
    vec![
        ("org.gnome.DejaDup", "backend", "'local'".into()),
        (
            "org.gnome.DejaDup.Local",
            "folder",
            format!("'{}'", destination.display().to_string().replace('\'', "\\'")),
        ),
        ("org.gnome.DejaDup", "periodic", "true".into()),
        ("org.gnome.DejaDup", "periodic-period", "1".into()),
    ]
}

/// `gsettings set` : par l'écrivain de dconf (bus de la session), la valeur vérifiée contre le schéma puis relue ;
/// gsettings seulement quand ce chemin ne s'applique pas (schéma inconnu ici, valeur d'un autre type, pas de bus).
#[cfg(target_os = "linux")]
fn regler_gsettings(schema: &str, cle: &str, valeur: &str) -> bool {
    // Sous les essais, aucun réglage réel ne s'écrit, ni par dconf ni par gsettings.
    if cfg!(test) {
        return false;
    }
    match crate::machine::linux::dconf::gsettings_set(schema, cle, valeur) {
        Some(ecrit) => ecrit,
        None => crate::machine::sortie("gsettings", &["set", schema, cle, valeur]).is_some(),
    }
}

#[cfg(target_os = "linux")]
fn deja_dup_present() -> bool {
    dans_le_path("deja-dup").is_some()
        && schema_gsettings("org.gnome.DejaDup", Some("periodic")).unwrap_or_else(|| {
            crate::machine::sortie("gsettings", &["list-keys", "org.gnome.DejaDup"])
                .is_some_and(|t| t.contains("periodic"))
        })
}

/// Le schéma de réglages `schema` est-il installé, avec la clé `cle` quand elle est donnée (ce que disait
/// `gsettings list-keys`) ? Lu dans sa description XML (<schéma>.gschema.xml), que le paquet installe à côté de la
/// base compilée que lit gsettings. `None` si aucun fichier de ce nom n'est trouvé : la base compilée, au format
/// binaire, peut tout de même le connaître (un schéma rangé dans le fichier d'un autre) ; gsettings tranche alors.
#[cfg(target_os = "linux")]
pub(crate) fn schema_gsettings(schema: &str, cle: Option<&str>) -> Option<bool> {
    schema_gsettings_dans(&dossiers_de_schemas(), schema, cle)
}

/// Les dossiers où GLib cherche les schémas : GSETTINGS_SCHEMA_DIR, celui du compte, puis ceux de XDG_DATA_DIRS
/// (/usr/local/share et /usr/share par défaut ; Flatpak y ajoute les siens).
#[cfg(target_os = "linux")]
fn dossiers_de_schemas() -> Vec<PathBuf> {
    let maison = crate::socle::maison();
    let donnees = std::env::var_os("XDG_DATA_HOME").map_or_else(|| maison.join(".local/share"), PathBuf::from);
    let systeme = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    std::env::var_os("GSETTINGS_SCHEMA_DIR")
        .map(PathBuf::from)
        .into_iter()
        .chain(
            std::iter::once(donnees)
                .chain(systeme.split(':').filter(|d| !d.is_empty()).map(PathBuf::from))
                .map(|d| d.join("glib-2.0/schemas")),
        )
        .collect()
}

/// Un fichier peut décrire plusieurs schémas (« org.gnome.DejaDup » et « org.gnome.DejaDup.Local ») : la clé se
/// cherche dans l'élément du bon schéma, de son `id="…"` (guillemet compris : « …DejaDup.Local » n'est pas
/// « …DejaDup ») jusqu'à sa fermeture.
#[cfg(target_os = "linux")]
fn schema_gsettings_dans(dossiers: &[PathBuf], schema: &str, cle: Option<&str>) -> Option<bool> {
    let texte = dossiers
        .iter()
        .find_map(|d| std::fs::read_to_string(d.join(format!("{schema}.gschema.xml"))).ok())?;
    let debut = texte.find(&format!("id=\"{schema}\""))?;
    let element = &texte[debut..];
    let element = &element[..element.find("</schema>").unwrap_or(element.len())];
    Some(cle.is_none_or(|c| element.contains(&format!("name=\"{c}\""))))
}

// ───────────────────────────── macOS : Time Machine ─────────────────────────────

/// Les identifiants des destinations de `tmutil destinationinfo` (« ID : 1234-… »).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn identifiants_time_machine(texte: &str) -> Vec<String> {
    texte
        .lines()
        .filter_map(|l| {
            let (cle, valeur) = l.split_once(':')?;
            let id = valeur.trim();
            // Un identifiant de destination : des chiffres hexadécimaux et des tirets. Il repart plus tard dans une
            // commande lancée avec sudo : rien d'autre n'y passe.
            (cle.trim() == "ID" && !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
                .then(|| id.to_string())
        })
        .collect()
}

/// L'identifiant apparu après l'ajout : celui d'après qui n'était pas là avant.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn nouvel_identifiant(avant: &[String], apres: &[String]) -> Option<String> {
    apres.iter().find(|id| !avant.contains(id)).cloned()
}

// ───────────────────────────── Windows : Historique des fichiers ─────────────────────────────

/// Le nom du lecteur cible dans Config1.xml de l'Historique des fichiers (« <TargetName>… »).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn cible_historique(xml: &str) -> Option<String> {
    let debut = xml.find("<TargetName>")? + "<TargetName>".len();
    let fin = xml[debut..].find("</TargetName>")?;
    let nom = xml[debut..debut + fin].trim();
    (!nom.is_empty()).then(|| affichable(nom))
}

/// Âge en jours d'une date FILETIME (centaines de nanosecondes depuis 1601) par rapport à maintenant (secondes
/// Unix).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn age_filetime_jours(filetime: u64, maintenant_unix: u64) -> u64 {
    const ECART_1601_1970: u64 = 11_644_473_600;
    let secondes = (filetime / 10_000_000).saturating_sub(ECART_1601_1970);
    maintenant_unix.saturating_sub(secondes) / 86_400
}

/// Le constat « Sauvegardes » de Windows : l'Historique des fichiers configuré, et jusqu'à quand il a protégé.
#[cfg(windows)]
fn historique_des_fichiers() -> Constat {
    use crate::machine::{alerte, ok};
    use crate::risk::Niveau;
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default());
    let config = local.join("Microsoft\\Windows\\FileHistory\\Configuration\\Config1.xml");
    let cible = std::fs::read(&config)
        .ok()
        .map(|o| String::from_utf8_lossy(&o).into_owned())
        .and_then(|xml| cible_historique(&xml));
    let protege: Option<u64> = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\FileHistory")
        .ok()
        .and_then(|k| k.get_value::<u64, _>("ProtectedUpToTime").ok());
    let Some(cible) = cible else {
        return alerte(
            "Sauvegardes",
            Niveau::Moyen,
            tr!(
                "Aucune sauvegarde automatique : l'Historique des fichiers n'est pas configuré (la sauvegarde OneDrive de Windows n'est pas vérifiée ici).",
                "No automatic backup: File History is not set up (the Windows OneDrive backup is not checked here)."
            ),
        )
        .manuel(
            tr!(
                "Brancher un disque externe, puis Panneau de configuration > Historique des fichiers > Activer ; le pas à pas est dans le menu Données > Sauvegarde automatique",
                "Plug in an external disk, then Control Panel > File History > Turn on; the step by step is in the Data > Automatic backup menu"
            ),
            &["control.exe /name Microsoft.FileHistory"],
        );
    };
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    match protege.map(|p| age_filetime_jours(p, maintenant)) {
        Some(jours) if jours > 7 => alerte(
            "Sauvegardes",
            Niveau::Moyen,
            trf!(
                "Historique des fichiers vers « {cible} » : dernière sauvegarde il y a {jours} jours. Rebranchez le disque.",
                "File History to “{cible}”: last backup {jours} days ago. Plug the disk back in."
            ),
        ),
        Some(jours) => ok(
            "Sauvegardes",
            trf!(
                "Historique des fichiers vers « {cible} », dernière sauvegarde il y a {jours} jour(s).",
                "File History to “{cible}”, last backup {jours} day(s) ago."
            ),
        ),
        None => ok(
            "Sauvegardes",
            trf!(
                "Historique des fichiers configuré vers « {cible} » (pas encore de passage noté).",
                "File History set up to “{cible}” (no run recorded yet)."
            ),
        ),
    }
}

/// Au bilan : l'Historique des fichiers sous Windows ; sous Linux, la minuterie rsync posée par Vanguard lance-t-elle
/// encore un rsync qui existe (Linux et macOS ont déjà, ailleurs, leur vérification des sauvegardes).
pub fn constats() -> Vec<Constat> {
    #[cfg(windows)]
    {
        vec![historique_des_fichiers()]
    }
    #[cfg(target_os = "linux")]
    {
        rsync_disparu().into_iter().collect()
    }
    #[cfg(target_os = "macos")]
    {
        Vec::new()
    }
}

/// La minuterie rsync de Vanguard en place, mais rsync parti (paquet désinstallé) : elle échoue chaque jour en silence.
#[cfg(target_os = "linux")]
fn rsync_disparu() -> Option<Constat> {
    let Some(MiseEnPlace::Systemd { .. }) = charger_de(&fichier_notes()).mise_en_place else {
        return None;
    };
    let texte = std::fs::read_to_string(dossier_unites().join(SERVICE)).ok()?;
    let rsync = crate::reseau::surveillance::programme_d_une_unite(&texte)?;
    juger_rsync(&rsync, rsync.is_file())
}

#[cfg(any(target_os = "linux", test))]
fn juger_rsync(rsync: &Path, existe: bool) -> Option<Constat> {
    let montre = chemin_affichable(rsync);
    (!existe).then(|| {
        crate::machine::alerte(
            "Sauvegardes",
            crate::risk::Niveau::Moyen,
            trf!(
                "La sauvegarde automatique lance {montre}, qui n'existe plus : elle ne copie plus rien.",
                "The automatic backup starts {montre}, which no longer exists: it copies nothing any more."
            ),
        )
        .manuel(
            tr!(
                "Réinstaller rsync, ou l'annuler puis la remettre : « vanguard sauvegarde-auto »",
                "Reinstall rsync, or undo it and set it up again: “vanguard auto-backup”"
            ),
            &[],
        )
    })
}

/// Ce que Vanguard a mis en place, d'après la note du dossier de données `donnees`.
pub(crate) fn mise_en_place_de(donnees: &Path) -> Option<MiseEnPlace> {
    charger_de(&donnees.join(NOTES)).mise_en_place
}

/// Retire ce que Vanguard a mis en place, sans question (la désinstallation l'a montré et fait accepter), puis oublie
/// la note. Elle reste si une étape a échoué, pour réessayer, ou si une unité modifiée depuis sa pose est laissée en
/// place : sans elle, « vanguard sauvegarde-auto --annuler » ne la retrouverait plus. Rend si tout s'est bien passé,
/// et les unités laissées en place.
pub(crate) fn annuler_sans_question(m: &MiseEnPlace) -> (bool, Vec<PathBuf>) {
    let (ok, gardees) = annuler_mise_en_place(m);
    if ok && gardees.is_empty() {
        let _ = ecrire_dans(&fichier_notes(), &Notes::default());
    }
    (ok, gardees)
}

/// Le fichier d'horodatage de la minuterie (« stamp-vanguard-sauvegarde.timer »), comme pour la surveillance et
/// l'entretien : rend ce qui n'est pas parti.
#[cfg(target_os = "linux")]
fn retirer_horodatage() -> Vec<String> {
    crate::reseau::surveillance::retirer_horodatage(
        crate::reseau::surveillance::dossier_horodatages_maison().as_deref(),
        TIMER.trim_end_matches(".timer"),
    )
}

/// Les unités de la sauvegarde trouvées sans note (une note perdue) : retirées par leur nom exact, minuterie arrêtée.
/// Dit si systemctl n'a pas répondu.
pub(crate) fn retirer_sans_note(fichiers: &[PathBuf]) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    let arretee = crate::machine::linux::dbus::actions::utilisateur(
        crate::machine::linux::dbus::actions::Geste::Desactiver { maintenant: true },
        TIMER,
    );
    #[cfg(not(target_os = "linux"))]
    let arretee = false;
    let mut echecs = Vec::new();
    for f in fichiers {
        if let Err(e) = std::fs::remove_file(f)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            echecs.push(format!("{} ({e})", chemin_affichable(f)));
        }
    }
    #[cfg(target_os = "linux")]
    echecs.extend(retirer_horodatage());
    #[cfg(target_os = "linux")]
    let recharge =
        crate::machine::linux::dbus::actions::utilisateur(crate::machine::linux::dbus::actions::Geste::Recharger, "");
    #[cfg(not(target_os = "linux"))]
    let recharge = false;
    if !echecs.is_empty() {
        return Err(trf!("non retiré : {}", "not removed: {}", echecs.join(", ")));
    }
    if !(arretee && recharge) {
        return Err(tr!(
            "fichiers retirés, mais systemctl --user n'a pas répondu : la minuterie peut rester chargée jusqu'à la prochaine ouverture de session, où elle disparaît",
            "files removed, but systemctl --user did not answer: the timer may stay loaded until the next sign-in, where it goes away"
        )
        .to_string());
    }
    Ok(())
}

// ───────────────────────────── Le menu ─────────────────────────────

fn bon(texte: &str) {
    afficher_aligne(&format!("  {VERT}✔{RESET} "), texte, 4, "");
}

fn mauvais(texte: &str) {
    afficher_aligne(
        &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        texte,
        4,
        "",
    );
}

fn info(texte: &str) {
    afficher_aligne(
        &format!("  {}ℹ{RESET} ", couleur(crate::risk::Niveau::Info)),
        texte,
        4,
        "",
    );
}

/// Ce que Vanguard a mis en place, en une phrase.
fn decrire(m: &MiseEnPlace) -> String {
    match m {
        MiseEnPlace::Systemd { date, destination, .. } => trf!(
            "Mise en place par Vanguard le {date} : rsync chaque jour vers {destination} (minuterie {TIMER}).",
            "Set up by Vanguard on {date}: rsync every day to {destination} (timer {TIMER})."
        ),
        MiseEnPlace::DejaDup { date, destination, .. } => trf!(
            "Mise en place par Vanguard le {date} : Déjà Dup, chaque jour, vers {destination}.",
            "Set up by Vanguard on {date}: Déjà Dup, every day, to {destination}."
        ),
        MiseEnPlace::TimeMachine { date, destination, .. } => trf!(
            "Mise en place par Vanguard le {date} : Time Machine vers {destination}.",
            "Set up by Vanguard on {date}: Time Machine to {destination}."
        ),
    }
}

/// Le disque externe où sauvegarder, parmi ceux qui sont branchés.
#[cfg(not(windows))]
fn choisir_disque() -> Option<crate::copier::Disque> {
    let liste = crate::copier::disques();
    if liste.is_empty() {
        mauvais(tr!(
            "Aucun disque externe branché (la clé VANGUARD et le disque du système ne comptent pas). Branchez un disque assez grand pour vos fichiers, attendez qu'il apparaisse, puis recommencez.",
            "No external disk plugged in (the VANGUARD key and the system disk do not count). Plug in a disk large enough for your files, wait for it to appear, then start again."
        ));
        return None;
    }
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_section(tr!("VERS QUEL DISQUE", "TO WHICH DISK"))),
    ];
    for (i, d) in liste.iter().enumerate() {
        let place = trf!(
            "{} libres sur {}",
            "{} free out of {}",
            taille_lisible(d.libre),
            taille_lisible(d.total)
        );
        lignes.push(Ligne::choix(&(i + 1).to_string(), &d.nom, &place));
    }
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let choix = choisir(
        &lignes,
        tr!(
            "  Numéro du disque (Entrée pour revenir) : ",
            "  Disk number (Enter to go back): "
        ),
        "1",
        tr!("revenir", "back"),
    )?;
    let i = choix.trim().parse::<usize>().ok()?.checked_sub(1)?;
    liste.into_iter().nth(i)
}

/// Linux : met en place la minuterie rsync ou Déjà Dup vers le disque choisi.
#[cfg(target_os = "linux")]
fn mettre_en_place() -> Option<MiseEnPlace> {
    let sources: Vec<PathBuf> = crate::copier::sources().into_iter().map(|(_, c)| c).collect();
    if sources.is_empty() {
        mauvais(tr!(
            "Aucun dossier personnel trouvé (Documents, Images…) : rien à sauvegarder.",
            "No personal folder found (Documents, Pictures…): nothing to back up."
        ));
        return None;
    }
    let disque = choisir_disque()?;
    let destination = disque.racine.join(DOSSIER).join(nom_machine());
    let deja_dup = deja_dup_present();
    let rsync = dans_le_path("rsync");
    let outil = match (deja_dup, &rsync) {
        (false, None) => {
            mauvais(tr!(
                "Ni Déjà Dup ni rsync sur cet ordinateur : installez rsync (paquet « rsync ») ou Déjà Dup, puis recommencez.",
                "Neither Déjà Dup nor rsync on this computer: install rsync (“rsync” package) or Déjà Dup, then start again."
            ));
            return None;
        }
        (true, None) => 1,
        (false, Some(_)) => 2,
        (true, Some(_)) => {
            let lignes = vec![
                Ligne::Texte(String::new()),
                Ligne::Texte(ligne_section(tr!("AVEC QUEL OUTIL", "WITH WHICH TOOL"))),
                Ligne::choix(
                    "1",
                    tr!("Déjà Dup (outil du bureau)", "Déjà Dup (desktop tool)"),
                    tr!("chiffré, restauration graphique", "encrypted, graphical restore"),
                ),
                Ligne::choix(
                    "2",
                    tr!("rsync par systemd", "rsync via systemd"),
                    tr!("copie fidèle, lisible partout", "faithful copy, readable anywhere"),
                ),
                Ligne::choix("↵", tr!("Revenir", "Back"), ""),
                Ligne::Texte(String::new()),
            ];
            let choix = choisir(
                &lignes,
                tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
                "1",
                tr!("revenir", "back"),
            )?;
            match choix.trim() {
                "1" => 1,
                "2" => 2,
                _ => return None,
            }
        }
    };
    section(tr!("CE QUE VANGUARD VA FAIRE", "WHAT VANGUARD WILL DO"));
    afficher_aligne(
        "  ",
        &trf!(
            "Créer le dossier {} sur « {} » ({} libres).",
            "Create the folder {} on “{}” ({} free).",
            chemin_affichable(&destination),
            disque.nom,
            taille_lisible(disque.libre)
        ),
        2,
        "",
    );
    if outil == 1 {
        let cles = cles_deja_dup(&destination);
        afficher_aligne(
            "  ",
            tr!(
                "Régler Déjà Dup : destination locale = ce dossier, sauvegarde automatique chaque jour. Le reste (dossiers inclus, mot de passe de chiffrement) se choisit dans Déjà Dup au premier passage ; les valeurs d'avant sont notées pour annuler.",
                "Set Déjà Dup: local destination = this folder, automatic backup every day. The rest (folders included, encryption password) is chosen in Déjà Dup on the first run; the previous values are noted to undo."
            ),
            2,
            "",
        );
        for (schema, cle, valeur) in &cles {
            println!("    {GRIS}$ gsettings set {schema} {cle} {valeur}{RESET}");
        }
        if !demander(tr!("\n  Appliquer ? [o/N] : ", "\n  Apply? [y/N]: ")).oui() {
            return None;
        }
        if let Err(e) = std::fs::create_dir_all(&destination) {
            mauvais(&trf!(
                "Dossier impossible à créer : {e}",
                "Could not create the folder: {e}"
            ));
            return None;
        }
        let mut avant = Vec::new();
        for (schema, cle, valeur) in &cles {
            // Lue dans dconf et les schémas compilés, au format que `gsettings set` reprendra ; lui en secours.
            let ancienne = crate::machine::linux::dconf::gsettings_get(schema, cle)
                .or_else(|| crate::machine::sortie("gsettings", &["get", schema, cle]))
                .unwrap_or_default();
            avant.push((format!("{schema} {cle}"), ancienne.trim().to_string()));
            if !regler_gsettings(schema, cle, valeur) {
                mauvais(&trf!(
                    "gsettings set {schema} {cle} a échoué ; rien d'autre n'est changé.",
                    "gsettings set {schema} {cle} failed; nothing else is changed."
                ));
                return None;
            }
        }
        bon(tr!(
            "Déjà Dup réglé. Ouvrez-le une première fois (il demande les dossiers à inclure et un mot de passe de chiffrement) : « deja-dup ».",
            "Déjà Dup set. Open it once (it asks which folders to include and an encryption password): “deja-dup”."
        ));
        return Some(MiseEnPlace::DejaDup {
            date: aujourd_hui(),
            destination: destination.display().to_string(),
            avant,
        });
    }
    let rsync = rsync?;
    let fat = systeme_de_fichiers(&disque.racine).is_some_and(|s| sans_liens(&s));
    let uuid = crate::protection::manifeste::identifiant_volume(&disque.racine);
    let findmnt = dans_le_path("findmnt");
    let (timer, service) = match unites(
        &rsync,
        findmnt.as_deref(),
        uuid.as_deref(),
        &disque.racine,
        &destination,
        &sources,
        fat,
    ) {
        Ok(unites) => unites,
        Err(Refus::Controle) => {
            mauvais(tr!(
                "Le nom de ce disque ou d'un dossier contient un caractère de contrôle : rien n'est posé. Renommez le disque, puis recommencez.",
                "The name of this disk or of a folder contains a control character: nothing is set up. Rename the disk, then start again."
            ));
            return None;
        }
        Err(Refus::Identite) => {
            mauvais(tr!(
                "L'identité de ce disque (UUID de son système de fichiers) ne se lit pas : rien n'est posé. Sans elle, n'importe quel disque du même nom recevrait la copie de vos dossiers.",
                "This disk's identity (its file system UUID) cannot be read: nothing is set up. Without it, any disk with the same name would receive the copy of your folders."
            ));
            return None;
        }
    };
    let dossier = dossier_unites();
    afficher_aligne(
        "  ",
        &trf!(
            "Poser deux fichiers dans {} puis activer la minuterie : chaque jour à {}, rsync copie {} dans ce dossier (disque débranché : rien ne se passe ; ordinateur éteint : au prochain démarrage). Rien n'est effacé sur le disque : ce qui a disparu ici reste dans la sauvegarde.",
            "Put two files in {} then enable the timer: every day at {}, rsync copies {} into this folder (disk unplugged: nothing happens; computer off: at the next start). Nothing is deleted on the disk: what disappeared here stays in the backup.",
            chemin_affichable(&dossier),
            &HEURE[..5],
            sources
                .iter()
                .map(|s| chemin_affichable(s))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        2,
        "",
    );
    println!("\n  {GRIS}{SERVICE}{RESET}");
    for l in service.lines() {
        println!("    {GRIS}{l}{RESET}");
    }
    println!("  {GRIS}{TIMER}{RESET}");
    for l in timer.lines() {
        println!("    {GRIS}{l}{RESET}");
    }
    println!("    {GRIS}$ systemctl --user daemon-reload && systemctl --user enable --now {TIMER}{RESET}");
    if !demander(tr!("\n  Appliquer ? [o/N] : ", "\n  Apply? [y/N]: ")).oui() {
        return None;
    }
    let poser = || -> std::io::Result<()> {
        std::fs::create_dir_all(&destination)?;
        std::fs::create_dir_all(&dossier)?;
        std::fs::write(dossier.join(SERVICE), &service)?;
        std::fs::write(dossier.join(TIMER), &timer)
    };
    if let Err(e) = poser() {
        mauvais(&trf!(
            "Impossible de poser les fichiers : {e}",
            "Could not put the files: {e}"
        ));
        return None;
    }
    // Par le gestionnaire de l'utilisateur lui-même (D-Bus : EnableUnitFiles, Reload, StartUnit), sans shell ;
    // montré comme la commande qu'il remplace, et noté dans « Ce que Vanguard a changé ».
    let geste = format!("systemctl --user enable --now {TIMER}");
    println!("    {GRIS}$ {geste}{RESET}");
    let active = crate::machine::linux::dbus::actions::utilisateur(
        crate::machine::linux::dbus::actions::Geste::Activer { maintenant: true },
        TIMER,
    );
    crate::changements::noter(&[vec![geste]], &[active]);
    let mise_en_place = MiseEnPlace::Systemd {
        date: aujourd_hui(),
        destination: destination.display().to_string(),
        empreinte_timer: empreinte(&timer),
        empreinte_service: empreinte(&service),
    };
    // Noté tout de suite, avant toute autre question : une entrée fermée (Ctrl-D, terminal fermé) arrête Vanguard à
    // la question suivante, et la minuterie tournait alors chaque jour sans note, impossible à annuler par Vanguard.
    noter(&mise_en_place);
    if active {
        bon(&trf!(
            "Sauvegarde automatique active : chaque jour à {}, vers {}.",
            "Automatic backup on: every day at {}, to {}.",
            &HEURE[..5],
            chemin_affichable(&destination)
        ));
        if demander(tr!(
            "  Lancer la première sauvegarde maintenant, en arrière-plan ? [o/N] : ",
            "  Run the first backup now, in the background? [y/N]: "
        ))
        .oui()
        {
            if crate::machine::linux::dbus::actions::utilisateur(
                crate::machine::linux::dbus::actions::Geste::Demarrer { attendre: false },
                SERVICE,
            ) {
                info(&trf!(
                    "Première sauvegarde lancée. La suivre : journalctl --user -u {SERVICE} -f ; le bilan (catégorie Sauvegardes) dira la date du dernier passage.",
                    "First backup started. Follow it: journalctl --user -u {SERVICE} -f; the check (Backups category) will show the date of the last run."
                ));
            } else {
                mauvais(tr!("Le lancement a échoué.", "The start failed."));
            }
        }
    } else {
        mauvais(tr!(
            "La minuterie n'a pas pu être activée ; les fichiers sont posés, « Annuler » les retire.",
            "The timer could not be enabled; the files are in place, “Undo” removes them."
        ));
    }
    Some(mise_en_place)
}

/// macOS : ajoute le disque choisi aux destinations de Time Machine et l'active.
#[cfg(target_os = "macos")]
fn mettre_en_place() -> Option<MiseEnPlace> {
    let disque = choisir_disque()?;
    let avant = crate::machine::sortie("tmutil", &["destinationinfo"]).unwrap_or_default();
    let deja_actif = avant.contains("Name");
    let chemin = disque.racine.display().to_string();
    let commandes = vec![
        format!("sudo tmutil setdestination -a {}", crate::commande::sh_chaine(&chemin)),
        "sudo tmutil enable".to_string(),
    ];
    section(tr!("CE QUE VANGUARD VA FAIRE", "WHAT VANGUARD WILL DO"));
    afficher_aligne(
        "  ",
        &trf!(
            "Ajouter « {} » ({} libres) aux disques de Time Machine et l'activer : sauvegardes toutes les heures, tout le Mac, restauration dans le Finder ou à la réinstallation. Le mot de passe d'administrateur sera demandé.",
            "Add “{}” ({} free) to Time Machine's disks and turn it on: hourly backups, the whole Mac, restore from the Finder or at reinstall. The administrator password will be asked.",
            disque.nom,
            taille_lisible(disque.libre)
        ),
        2,
        "",
    );
    for c in &commandes {
        println!("    {GRIS}$ {c}{RESET}");
    }
    if !demander(tr!("\n  Appliquer ? [o/N] : ", "\n  Apply? [y/N]: ")).oui() {
        return None;
    }
    if !crate::machine::appliquer(&commandes) {
        mauvais(tr!(
            "tmutil a refusé ; rien n'est noté.",
            "tmutil refused; nothing is noted."
        ));
        return None;
    }
    let apres = crate::machine::sortie("tmutil", &["destinationinfo"]).unwrap_or_default();
    let identifiant = nouvel_identifiant(&identifiants_time_machine(&avant), &identifiants_time_machine(&apres));
    bon(&trf!(
        "Time Machine sauvegarde vers « {} ». Laissez le disque branché : la première sauvegarde prend du temps.",
        "Time Machine backs up to “{}”. Leave the disk plugged in: the first backup takes time.",
        disque.nom
    ));
    Some(MiseEnPlace::TimeMachine {
        date: aujourd_hui(),
        destination: chemin,
        identifiant,
        deja_actif,
    })
}

/// Windows : l'Historique des fichiers se règle dans le Panneau de configuration ; Vanguard guide et l'ouvre.
#[cfg(windows)]
fn mettre_en_place() -> Option<MiseEnPlace> {
    section(tr!("PAS À PAS", "STEP BY STEP"));
    for (i, etape) in [
        tr!(
            "Branchez un disque externe (ou une grosse clé) qui restera branché le plus souvent possible.",
            "Plug in an external disk (or a big USB stick) that will stay plugged in as often as possible."
        ),
        tr!(
            "Dans la fenêtre qui s'ouvre (Panneau de configuration > Historique des fichiers), choisissez « Sélectionner un lecteur », puis ce disque.",
            "In the window that opens (Control Panel > File History), choose “Select drive”, then that disk."
        ),
        tr!(
            "Cliquez sur « Activer ». Dans « Paramètres avancés », gardez « Toutes les heures » et « Conserver les versions : toujours ».",
            "Click “Turn on”. In “Advanced settings”, keep “Every hour” and “Keep saved versions: forever”."
        ),
        tr!(
            "Le bilan de Vanguard (catégorie Sauvegardes) dira ensuite la date de la dernière sauvegarde.",
            "Vanguard's check (Backups category) will then show the date of the last backup."
        ),
    ]
    .iter()
    .enumerate()
    {
        afficher_aligne(&format!("  {TOUCHE}{}{RESET} ", i + 1), etape, 4, "");
    }
    info(tr!(
        "Windows 11 n'a plus ce réglage dans Paramètres, seulement dans le Panneau de configuration. L'autre voie est la sauvegarde OneDrive (Paramètres > Comptes > Sauvegarde Windows), en ligne, limitée par l'espace OneDrive.",
        "Windows 11 no longer has this setting in Settings, only in the Control Panel. The other way is the OneDrive backup (Settings > Accounts > Windows backup), online, limited by the OneDrive space."
    ));
    if demander(tr!(
        "\n  Ouvrir l'Historique des fichiers ? [o/N] : ",
        "\n  Open File History? [y/N]: "
    ))
    .oui()
    {
        // Par son chemin entier dans System32 : un nom seul serait cherché d'abord dans le dossier courant, où un
        // faux control.exe posé à côté de Vanguard (clé USB, Téléchargements) se lancerait.
        crate::machine::ouvrir_avec(
            &crate::commande::systeme32("control").to_string_lossy(),
            "/name Microsoft.FileHistory",
        );
    }
    None
}

/// Retire exactement ce que Vanguard a mis en place. Rend si tout s'est bien passé, et les unités laissées en place
/// parce qu'elles ont été modifiées depuis leur pose (ce n'est plus seulement celle de Vanguard).
fn annuler_mise_en_place(m: &MiseEnPlace) -> (bool, Vec<PathBuf>) {
    match m {
        MiseEnPlace::Systemd {
            empreinte_timer,
            empreinte_service,
            ..
        } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (empreinte_timer, empreinte_service);
                (false, Vec::new())
            }
            #[cfg(target_os = "linux")]
            {
                let dossier = dossier_unites();
                let geste = format!("systemctl --user disable --now {TIMER}");
                println!("    {GRIS}$ {geste}{RESET}");
                let mut ok = crate::machine::linux::dbus::actions::utilisateur(
                    crate::machine::linux::dbus::actions::Geste::Desactiver { maintenant: true },
                    TIMER,
                );
                crate::changements::noter(&[vec![geste]], &[ok]);
                let mut gardees = Vec::new();
                for (nom, attendu) in [(TIMER, empreinte_timer), (SERVICE, empreinte_service)] {
                    let chemin = dossier.join(nom);
                    match std::fs::read_to_string(&chemin) {
                        Ok(t) if &empreinte(&t) == attendu => {
                            if std::fs::remove_file(&chemin).is_err() {
                                ok = false;
                            }
                        }
                        Ok(_) => {
                            info(&trf!(
                                "{} a été modifié depuis : laissé en place.",
                                "{} was modified since: left in place.",
                                chemin_affichable(&chemin)
                            ));
                            gardees.push(chemin);
                        }
                        Err(_) => {}
                    }
                }
                let _ = crate::machine::linux::dbus::actions::utilisateur(
                    crate::machine::linux::dbus::actions::Geste::Recharger,
                    "",
                );
                // Sa minuterie (Persistent=true) a un fichier d'horodatage que systemd ne retire jamais : il part avec
                // elle, et reste si elle reste.
                if !gardees.contains(&dossier.join(TIMER)) && !retirer_horodatage().is_empty() {
                    ok = false;
                }
                (ok, gardees)
            }
        }
        MiseEnPlace::DejaDup { avant, .. } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = avant;
                (false, Vec::new())
            }
            #[cfg(target_os = "linux")]
            {
                let mut ok = true;
                for (schema_cle, valeur) in avant {
                    let Some((schema, cle)) = schema_cle.split_once(' ') else {
                        continue;
                    };
                    println!("    {GRIS}$ gsettings set {schema} {cle} {valeur}{RESET}");
                    if !regler_gsettings(schema, cle, valeur) {
                        ok = false;
                    }
                }
                (ok, Vec::new())
            }
        }
        MiseEnPlace::TimeMachine {
            identifiant,
            deja_actif,
            ..
        } => {
            let mut commandes = Vec::new();
            // L'identifiant a été lu dans les notes, que n'importe quel programme du compte peut réécrire : vérifié de
            // nouveau avant de partir dans une commande lancée avec sudo.
            if let Some(id) = identifiant
                .as_deref()
                .filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
            {
                commandes.push(format!("sudo tmutil removedestination {id}"));
            }
            if !deja_actif {
                commandes.push("sudo tmutil disable".to_string());
            }
            (
                commandes.is_empty() || crate::machine::appliquer(&commandes),
                Vec::new(),
            )
        }
    }
}

/// « vanguard sauvegarde-auto --annuler » : retire ce que Vanguard a mis en place, après accord.
pub fn annuler() {
    let chemin = fichier_notes();
    let notes = charger_de(&chemin);
    let Some(m) = &notes.mise_en_place else {
        info(tr!(
            "Vanguard n'a rien mis en place à annuler.",
            "Vanguard set nothing up to undo."
        ));
        return;
    };
    info(&decrire(m));
    if !demander(tr!(
        "  Retirer cette sauvegarde automatique (les fichiers déjà sauvegardés restent sur le disque) ? [o/N] : ",
        "  Remove this automatic backup (the files already backed up stay on the disk)? [y/N]: "
    ))
    .oui()
    {
        return;
    }
    let (ok, gardees) = annuler_mise_en_place(m);
    if ok && !gardees.is_empty() {
        // Une unité de Vanguard reste : sa note aussi, sinon plus rien ne la retrouverait.
        mauvais(&trf!(
            "Retiré, sauf {} : modifié(s) depuis la pose, laissé(s) en place. Supprimez-les vous-même si vous n'en voulez plus ; la note est gardée.",
            "Removed, except {}: changed since they were placed, left in place. Delete them yourself if you no longer want them; the note is kept.",
            gardees
                .iter()
                .map(|p| chemin_affichable(p))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else if ok {
        let _ = ecrire_dans(&chemin, &Notes::default());
        bon(tr!(
            "Retiré. Les fichiers sauvegardés restent sur le disque externe.",
            "Removed. The backed-up files stay on the external disk."
        ));
    } else {
        mauvais(tr!(
            "Une étape a échoué : la note est gardée pour réessayer.",
            "A step failed: the note is kept to try again."
        ));
    }
}

/// Menu Données › Sauvegarde automatique.
pub fn menu() {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("SAUVEGARDE AUTOMATIQUE", "AUTOMATIC BACKUP")),
        &format!(
            "{GRIS}{}{RESET}",
            tr!("outil du système, disque externe", "system tool, external disk")
        ),
    );
    afficher_aligne(
        "  ",
        tr!(
            "Un disque qui lâche, un vol ou un rançongiciel emportent tout ce qui n'existe qu'ici. Vanguard met en place la sauvegarde avec l'outil du système, vers un disque externe, et peut la retirer exactement.",
            "A failing disk, a theft or ransomware takes everything that exists only here. Vanguard sets up the backup with the system's tool, to an external disk, and can remove it exactly."
        ),
        2,
        GRIS,
    );
    let chemin = fichier_notes();
    let notes = charger_de(&chemin);
    println!();
    match &notes.mise_en_place {
        Some(m) => {
            info(&decrire(m));
            #[cfg(target_os = "linux")]
            if matches!(m, MiseEnPlace::Systemd { .. })
                && std::fs::read_to_string(dossier_unites().join(SERVICE)).is_ok_and(|s| !verifie_le_disque(&s))
            {
                mauvais(tr!(
                    "Cette sauvegarde reconnaît son disque à son seul nom : un autre disque du même nom recevrait la copie de vos dossiers. Annulez-la, puis remettez-la en place : Vanguard vérifie maintenant l'identité du disque à chaque passage.",
                    "This backup recognizes its disk by name only: another disk with the same name would receive the copy of your folders. Undo it, then set it up again: Vanguard now checks the disk's identity at every run."
                ));
            }
        }
        None => info(tr!(
            "Vanguard n'a rien mis en place ici. Le bilan (catégorie Sauvegardes) dit si une sauvegarde existe déjà par ailleurs.",
            "Vanguard set nothing up here. The check (Backups category) says whether a backup already exists otherwise."
        )),
    }
    let mut lignes = vec![Ligne::Texte(String::new())];
    if notes.mise_en_place.is_none() {
        lignes.push(Ligne::choix(
            "1",
            tr!("Mettre en place", "Set up"),
            tr!(
                "montré, puis appliqué après accord",
                "shown, then applied after consent"
            ),
        ));
    } else {
        lignes.push(Ligne::choix(
            "2",
            tr!("Annuler ce que Vanguard a mis en place", "Undo what Vanguard set up"),
            tr!("les fichiers sauvegardés restent", "the backed-up files stay"),
        ));
    }
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let Some(choix) = choisir(
        &lignes,
        tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
        if notes.mise_en_place.is_none() { "1" } else { "2" },
        tr!("revenir", "back"),
    ) else {
        return;
    };
    match choix.trim() {
        "1" if notes.mise_en_place.is_none() => {
            if let Some(m) = mettre_en_place()
                && let Err(e) = ecrire_dans(&chemin, &Notes { mise_en_place: Some(m) })
            {
                mauvais(&trf!(
                    "La note de ce qui a été mis en place n'a pas pu être écrite ({e}) : l'annulation devra se faire à la main.",
                    "The note of what was set up could not be written ({e}): undoing will have to be done by hand."
                ));
            }
        }
        "2" if notes.mise_en_place.is_some() => annuler(),
        _ => {}
    }
}

// ───────────────────────────── Vérifier la sauvegarde ─────────────────────────────

/// Fichiers relus au plus dans la sauvegarde : répartis sur toute la liste, assez pour qu'un disque qui perd des
/// données se voie, assez peu pour finir en quelques secondes même sur un disque lent.
const A_RELIRE: usize = 20;
/// Au-delà, la liste de la sauvegarde s'arrête : l'échantillon reste réparti sur ce qui a été lu.
const LISTE_MAX: usize = 200_000;
/// Un fichier plus gros n'entre pas dans l'échantillon : relu deux fois (copie puis original), une image de
/// machine virtuelle de 40 Go prendrait une heure sur une clé lente, et « quelques secondes » ne tiendrait plus.
const TAILLE_RELUE_MAX: u64 = 1 << 30;

/// Les fichiers ordinaires trouvés dans la sauvegarde, et combien de gros fichiers ont été laissés de côté.
#[derive(Debug, Default, PartialEq, Eq)]
struct Liste {
    fichiers: Vec<PathBuf>,
    gros: usize,
}

/// Un fichier de la sauvegarde comparé à son original.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Comparaison {
    Identique,
    /// L'original a changé depuis la sauvegarde : la copie d'hier est juste, elle date d'hier.
    ModifieDepuis,
    /// Différent alors que l'original n'a pas changé : la sauvegarde est abîmée.
    Different,
    SansOriginal,
    Illisible,
}

/// La copie relue sur le disque (cache contourné, comme « Vérifier une copie ») puis comparée à l'original. rsync garde
/// sur la copie l'heure de modification de l'original : un contenu différent n'est une copie abîmée que si les deux
/// heures sont égales (c'est le « quick check » de rsync). Un original plus récent a changé depuis ; un original plus
/// ancien a été remplacé (restauration, archive extraite) : rsync reprendra l'un comme l'autre au prochain passage.
/// Deux secondes de marge : FAT et exFAT arrondissent l'heure.
fn comparer(copie: &Path, original: &Path) -> Comparaison {
    let Ok(relue) = crate::copier::empreinte_relue(copie) else {
        return Comparaison::Illisible;
    };
    let Ok(attendue) = empreinte_originale(original) else {
        return Comparaison::SansOriginal;
    };
    if relue == attendue {
        return Comparaison::Identique;
    }
    let heure = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let marge = std::time::Duration::from_secs(2);
    // Seul un original PLUS RÉCENT que sa copie est normal : on l'a retouché après la sauvegarde. Une copie plus
    // récente que son original, au contenu différent, a été réécrite sur le disque de sauvegarde : c'est ainsi
    // qu'apparaît un rançongiciel qui chiffre la sauvegarde. Dite abîmée, même si une ancienne version restaurée
    // depuis une archive donne le même signe : une vérification de trop coûte moins qu'une sauvegarde chiffrée
    // passée pour saine.
    match (heure(copie), heure(original)) {
        (Some(c), Some(o)) if o > c + marge => Comparaison::ModifieDepuis,
        _ => Comparaison::Different,
    }
}

/// L'empreinte de l'original, qui doit être un fichier ordinaire : depuis la sauvegarde, il a pu devenir un lien
/// vers /dev/zero ou un tube nommé, que `File::open` suivrait et lirait sans fin, écran figé. Le lien n'est pas
/// suivi (rsync ne copie pas sa cible sous ce nom), et l'ouverture est non bloquante, comme dans le bilan des
/// traces ; le descripteur ouvert est revérifié, pour qu'un échange entre les deux appels ne passe pas.
fn empreinte_originale(original: &Path) -> std::io::Result<blake3::Hash> {
    if !std::fs::symlink_metadata(original)?.is_file() {
        return Err(std::io::Error::other("pas un fichier ordinaire"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let fichier = options.open(original)?;
    if !fichier.metadata()?.is_file() {
        return Err(std::io::Error::other("pas un fichier ordinaire"));
    }
    Ok(blake3::Hasher::new().update_reader(fichier)?.finalize())
}

/// Les fichiers ordinaires de la sauvegarde, en chemins relatifs et triés, sans suivre les liens. La borne arrête
/// tout le parcours (pas seulement le dossier en cours) : sinon chaque dossier restant serait encore ouvert.
fn fichiers_de(dossier: &Path) -> Liste {
    let mut liste = Liste::default();
    let mut a_voir = vec![PathBuf::new()];
    'tout: while let Some(relatif) = a_voir.pop() {
        for e in std::fs::read_dir(dossier.join(&relatif))
            .into_iter()
            .flatten()
            .flatten()
        {
            let chemin = relatif.join(e.file_name());
            match std::fs::symlink_metadata(e.path()) {
                Ok(m) if m.is_dir() => a_voir.push(chemin),
                Ok(m) if m.is_file() && m.len() > TAILLE_RELUE_MAX => liste.gros += 1,
                Ok(m) if m.is_file() => liste.fichiers.push(chemin),
                _ => {}
            }
            if liste.fichiers.len() >= LISTE_MAX {
                break 'tout;
            }
        }
    }
    liste.fichiers.sort();
    liste
}

/// L'original d'un fichier de la sauvegarde : rsync copie chaque dossier sauvegardé sous son nom
/// (`disque/Documents`), et ce dossier peut être ailleurs que dans le dossier personnel (XDG_DOCUMENTS_DIR) : le
/// premier composant du chemin relatif désigne la source, comme dans « Vérifier une copie ».
fn original_de(relatif: &Path, sources: &[(String, PathBuf)]) -> Option<PathBuf> {
    let mut morceaux = relatif.components();
    let premier = morceaux.next()?.as_os_str().to_string_lossy().into_owned();
    let (_, source) = sources.iter().find(|(nom, _)| *nom == premier)?;
    Some(source.join(morceaux.as_path()))
}

/// La sauvegarde rsync de `destination` (un dossier par dossier sauvegardé : Documents, Images…) relue par
/// échantillon et comparée aux originaux, `sources` = (nom du dossier sur la sauvegarde, dossier d'origine) : chaque
/// fichier relu, avec son verdict, et le nombre de gros fichiers laissés de côté. Un dossier de la sauvegarde qui
/// ne correspond plus à aucune source reste sans original : rien n'est conclu sur lui.
fn relire_sauvegarde(destination: &Path, sources: &[(String, PathBuf)]) -> (Vec<(PathBuf, Comparaison)>, usize) {
    let liste = fichiers_de(destination);
    let relus = crate::copier::echantillon(&liste.fichiers, A_RELIRE)
        .into_iter()
        .map(|relatif| {
            let verdict = match original_de(relatif, sources) {
                Some(original) => comparer(&destination.join(relatif), &original),
                None => Comparaison::SansOriginal,
            };
            (relatif.clone(), verdict)
        })
        .collect();
    (relus, liste.gros)
}

/// Les dossiers sauvegardés par Vanguard (Documents, Images…), nommés comme rsync les pose sur la sauvegarde.
fn sources_actuelles() -> Vec<(String, PathBuf)> {
    crate::copier::sources()
        .into_iter()
        .filter_map(|(_, chemin)| {
            let nom = chemin.file_name()?.to_string_lossy().into_owned();
            Some((nom, chemin))
        })
        .collect()
}

/// « Vérifier ma sauvegarde » (menu Données, `vanguard verifier-sauvegarde`) : la sauvegarde que Vanguard a mise en
/// place est relue pour de vrai, quelques fichiers répartis sur toute la sauvegarde (toujours les mêmes d'un
/// passage à l'autre : l'échantillon est déterministe) comparés à leur original. Rien n'est écrit ni effacé.
pub fn verifier_sauvegarde() {
    println!();
    titre(tr!("Vérifier la sauvegarde automatique", "Check the automatic backup"));
    let mise_en_place = charger_de(&fichier_notes()).mise_en_place;
    let Some(MiseEnPlace::Systemd { destination, date, .. }) = mise_en_place else {
        let texte = match mise_en_place {
            Some(MiseEnPlace::DejaDup { .. }) => tr!(
                "Déjà Dup compresse et chiffre ses sauvegardes : Vanguard ne les relit pas. Pour l'essayer : Déjà Dup › Restaurer, un fichier vers un autre dossier, puis l'ouvrir. Non vérifié ici.",
                "Déjà Dup compresses and encrypts its backups: Vanguard does not read them back. To try it: Déjà Dup › Restore, one file to another folder, then open it. Not checked here."
            ),
            Some(MiseEnPlace::TimeMachine { .. }) => tr!(
                "Time Machine : « Entrer dans Time Machine » depuis le Finder, restaurer un fichier, puis l'ouvrir. Non vérifié ici.",
                "Time Machine: “Enter Time Machine” from the Finder, restore one file, then open it. Not checked here."
            ),
            _ if cfg!(windows) => tr!(
                "Historique des fichiers : Panneau de configuration › Historique des fichiers › Restaurer des fichiers personnels, un fichier vers un autre dossier. Non vérifié ici.",
                "File History: Control Panel › File History › Restore personal files, one file to another folder. Not checked here."
            ),
            _ => tr!(
                "Aucune sauvegarde mise en place par Vanguard sur cet ordinateur : Données et sauvegardes › Sauvegarde automatique. Une copie faite par « Copier mes fichiers » se vérifie avec « Une copie (un dossier) », sous « Vérifier une copie ou sauvegarde ».",
                "No backup set up by Vanguard on this computer: Data and backups › Automatic backup. A copy made by “Copy my files” is checked with “A copy (a folder)”, under “Check a copy or backup”."
            ),
        };
        info(texte);
        return;
    };
    let destination = PathBuf::from(destination);
    trp!(
        "  Sauvegarde rsync mise en place le {date} : {}",
        "  rsync backup set up on {date}: {}",
        chemin_affichable(&destination)
    );
    if !destination.is_dir() {
        mauvais(&trf!(
            "Sauvegarde introuvable (disque débranché ?) : rien n'a été vérifié.",
            "Backup not found (disk unplugged?): nothing was checked."
        ));
        return;
    }
    let (relus, gros) = relire_sauvegarde(&destination, &sources_actuelles());
    if relus.is_empty() && gros == 0 {
        mauvais(tr!(
            "La sauvegarde est vide : rsync n'y a encore rien copié (disque branché à midi ?). Rien n'a été vérifié.",
            "The backup is empty: rsync has not copied anything yet (disk plugged in at noon?). Nothing was checked."
        ));
        return;
    }
    let compte = |c: Comparaison| relus.iter().filter(|(_, v)| *v == c).count();
    let (identiques, modifies, differents, sans, illisibles) = (
        compte(Comparaison::Identique),
        compte(Comparaison::ModifieDepuis),
        compte(Comparaison::Different),
        compte(Comparaison::SansOriginal),
        compte(Comparaison::Illisible),
    );
    if identiques > 0 {
        bon(&trf!(
            "{identiques} fichier(s) relu(s) sur le disque de sauvegarde, identiques à leur original.",
            "{identiques} file(s) read back from the backup disk, identical to their original."
        ));
    }
    if modifies > 0 {
        info(&trf!(
            "{modifies} fichier(s) modifié(s) depuis la sauvegarde : normal, la prochaine les reprendra.",
            "{modifies} file(s) changed since the backup: normal, the next one will take them."
        ));
    }
    if sans > 0 {
        info(&trf!(
            "{sans} fichier(s) sans original à comparer (effacé depuis, ou hors du dossier personnel).",
            "{sans} file(s) with no original to compare (deleted since, or outside the home folder)."
        ));
    }
    if gros > 0 {
        info(&trf!(
            "{gros} gros fichier(s) (plus de 1 Gio) non relu(s) : trop longs à comparer.",
            "{gros} large file(s) (over 1 GiB) not read back: too long to compare."
        ));
    }
    for (relatif, verdict) in relus
        .iter()
        .filter(|(_, v)| matches!(v, Comparaison::Different | Comparaison::Illisible))
    {
        let pourquoi = if *verdict == Comparaison::Different {
            tr!(
                "différent de l'original, qui n'a pas changé",
                "different from the original, which has not changed"
            )
        } else {
            tr!("illisible sur le disque de sauvegarde", "unreadable on the backup disk")
        };
        mauvais(&format!("{} : {pourquoi}", chemin_affichable(relatif)));
    }
    println!();
    if differents + illisibles > 0 {
        mauvais(tr!(
            "La sauvegarde est abîmée : le disque perd peut-être des données. Vérifiez-le (Données et sauvegardes › Vérifier une clé USB ou un disque) et refaites une sauvegarde complète sur un autre disque.",
            "The backup is damaged: the disk may be losing data. Check it (Data and backups › Check a USB drive or a disk) and make a full backup to another disk."
        ));
    } else if identiques > 0 {
        bon(tr!(
            "La sauvegarde se relit : un fichier perdu s'y retrouverait. Rien n'a été écrit ni effacé.",
            "The backup reads back: a lost file would be found there. Nothing was written or deleted."
        ));
    } else {
        info(tr!(
            "Aucun fichier n'a pu être comparé : rien n'est conclu.",
            "No file could be compared: nothing is concluded."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le fichier d'horodatage que systemd pose pour la minuterie : « stamp- » + le nom de l'unité. Le retrait lui-même
    /// (surveillance::retirer_horodatage) est essayé sur un dossier jetable dans la surveillance ; ici, le nom.
    #[test]
    fn horodatage_de_la_sauvegarde_nomme() {
        assert_eq!(TIMER.trim_end_matches(".timer"), "vanguard-sauvegarde");
        assert_eq!(
            format!("stamp-{}.timer", TIMER.trim_end_matches(".timer")),
            "stamp-vanguard-sauvegarde.timer"
        );
    }

    /// Une sauvegarde rsync jouée dans un dossier jetable : copie identique, original modifié depuis (plus récent),
    /// copie abîmée (même heure, ou réécrite après la sauvegarde), fichier sans original.
    #[test]
    fn sauvegarde_relue_et_comparee() {
        let base = crate::socle::dossier_local().join("verifier-sauvegarde");
        let _ = std::fs::remove_dir_all(&base);
        let (maison, sauvegarde) = (base.join("maison"), base.join("disque"));
        for d in [maison.join("Documents"), sauvegarde.join("Documents")] {
            std::fs::create_dir_all(d).unwrap();
        }
        let ecrire = |racine: &Path, nom: &str, contenu: &str, il_y_a: u64| {
            let p = racine.join("Documents").join(nom);
            std::fs::write(&p, contenu).unwrap();
            let heure = std::time::SystemTime::now() - std::time::Duration::from_secs(il_y_a);
            std::fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(heure)
                .unwrap();
        };
        ecrire(&maison, "facture.pdf", "même contenu", 7200);
        ecrire(&sauvegarde, "facture.pdf", "même contenu", 7200);
        ecrire(&maison, "notes.txt", "écrit ce matin", 60);
        ecrire(&sauvegarde, "notes.txt", "écrit hier", 86_400);
        // Même heure, contenu différent : la seule preuve d'une copie abîmée.
        ecrire(&maison, "photo.jpg", "original", 86_400);
        ecrire(&sauvegarde, "photo.jpg", "abîmée", 86_400);
        ecrire(&sauvegarde, "efface.txt", "plus d'original", 86_400);
        // Copie réécrite après la sauvegarde, original inchangé et plus ancien : le signe d'un rançongiciel qui
        // chiffre la sauvegarde. Abîmée, même si une ancienne version restaurée donnerait le même signe.
        ecrire(&maison, "ancien.txt", "version d'archive", 172_800);
        ecrire(&sauvegarde, "ancien.txt", "chiffré par un rançongiciel", 86_400);
        // Les Documents peuvent être hors du dossier personnel : la source est nommée, pas devinée.
        let sources = vec![("Documents".to_string(), maison.join("Documents"))];
        let (mut relus, gros) = relire_sauvegarde(&sauvegarde, &sources);
        assert_eq!(gros, 0);
        relus.sort_by(|a, b| a.0.cmp(&b.0));
        let attendu = [
            ("ancien.txt", Comparaison::Different),
            ("efface.txt", Comparaison::SansOriginal),
            ("facture.pdf", Comparaison::Identique),
            ("notes.txt", Comparaison::ModifieDepuis),
            ("photo.jpg", Comparaison::Different),
        ];
        assert_eq!(relus.len(), attendu.len());
        for ((chemin, verdict), (nom, attendu)) in relus.iter().zip(attendu) {
            assert_eq!(chemin, &PathBuf::from("Documents").join(nom));
            assert_eq!(*verdict, attendu, "{nom}");
        }
        // Un dossier de la sauvegarde qui n'est plus une source : rien n'est conclu, jamais « abîmé ».
        assert!(
            relire_sauvegarde(&sauvegarde, &[])
                .0
                .iter()
                .all(|(_, v)| *v == Comparaison::SansOriginal)
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Un original qui n'est plus un fichier ordinaire (tube nommé, lien vers /dev/zero) n'est pas lu : il
    /// bloquerait ou lirait sans fin. Il est « sans original », jamais « abîmé ».
    #[cfg(unix)]
    #[test]
    fn original_qui_n_est_plus_un_fichier() {
        let base = crate::socle::dossier_local().join("verifier-sauvegarde-tube");
        let _ = std::fs::remove_dir_all(&base);
        let (maison, sauvegarde) = (base.join("maison"), base.join("disque"));
        for d in [maison.join("Documents"), sauvegarde.join("Documents")] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(sauvegarde.join("Documents/tube.txt"), "copie").unwrap();
        std::fs::write(sauvegarde.join("Documents/zero.txt"), "copie").unwrap();
        let tube = std::ffi::CString::new(maison.join("Documents/tube.txt").to_str().unwrap()).unwrap();
        // SAFETY : chemin C terminé par un zéro, vivant pendant l'appel ; mkfifo ne touche aucune mémoire du
        // programme.
        assert_eq!(unsafe { libc::mkfifo(tube.as_ptr(), 0o600) }, 0);
        std::os::unix::fs::symlink("/dev/zero", maison.join("Documents/zero.txt")).unwrap();
        let sources = vec![("Documents".to_string(), maison.join("Documents"))];
        let depart = std::time::Instant::now();
        let (relus, _) = relire_sauvegarde(&sauvegarde, &sources);
        assert!(depart.elapsed() < std::time::Duration::from_secs(3));
        assert_eq!(relus.len(), 2);
        assert!(relus.iter().all(|(_, v)| *v == Comparaison::SansOriginal));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// La borne arrête tout le parcours, et un gros fichier est compté sans entrer dans la liste.
    #[test]
    fn liste_bornee_et_gros_fichiers_comptes() {
        let base = crate::socle::dossier_local().join("verifier-sauvegarde-liste");
        let _ = std::fs::remove_dir_all(&base);
        for d in ["a", "b", "c"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
            for f in ["1", "2", "3"] {
                std::fs::write(base.join(d).join(f), "x").unwrap();
            }
        }
        // Un fichier creux : la taille déclarée compte, pas la place prise.
        let gros = std::fs::File::create(base.join("a/gros.img")).unwrap();
        gros.set_len(TAILLE_RELUE_MAX + 1).unwrap();
        drop(gros);
        let liste = fichiers_de(&base);
        assert_eq!(liste.fichiers.len(), 9);
        assert_eq!(liste.gros, 1);
        assert!(!liste.fichiers.iter().any(|f| f.ends_with("gros.img")));
        let _ = std::fs::remove_dir_all(&base);
    }

    fn findmnt() -> &'static Path {
        Path::new("/usr/bin/findmnt")
    }
    const UUID: Option<&str> = Some("1A2B-3C4D");

    #[test]
    fn sauvegarde_vers_une_cle_fat() {
        let montages = "/dev/sda1 /run/media/alice/EMTEC\\040D280C vfat rw,nosuid 0 0\n/dev/sdb1 /run/media/alice/Externe ext4 rw 0 0\n";
        assert_eq!(
            systeme_de_fichiers_selon(montages, Path::new("/run/media/alice/EMTEC D280C")).as_deref(),
            Some("vfat")
        );
        assert_eq!(
            systeme_de_fichiers_selon(montages, Path::new("/run/media/alice/Externe")).as_deref(),
            Some("ext4")
        );
        assert!(sans_liens("vfat") && sans_liens("exfat") && !sans_liens("ext4") && !sans_liens("ntfs3"));
        let regle = |fat| {
            unites(
                Path::new("/usr/bin/rsync"),
                Some(findmnt()),
                UUID,
                Path::new("/run/media/alice/Cle"),
                Path::new("/run/media/alice/Cle/Sauvegarde-Vanguard/pc"),
                &[PathBuf::from("/home/alice/Documents")],
                fat,
            )
            .unwrap()
            .1
        };
        // FAT : fichiers et heures (à 2 s près), sans liens ni droits ; sinon la copie complète.
        assert!(regle(true).contains("\"/usr/bin/rsync\" -rt --modify-window=2 --exclude=.cache"));
        assert!(regle(false).contains("\"/usr/bin/rsync\" -a --no-specials --no-devices --exclude=.cache"));
        // Un fichier disparu pendant la copie n'est pas un échec.
        assert!(regle(true).contains("SuccessExitStatus=24\n") && regle(false).contains("SuccessExitStatus=24\n"));
    }

    #[test]
    fn unites_systemd_bien_formees() {
        let (timer, service) = unites(
            Path::new("/usr/bin/rsync"),
            Some(findmnt()),
            UUID,
            Path::new("/run/media/alice/Externe"),
            Path::new("/run/media/alice/Externe/Sauvegarde-Vanguard/pc-alice"),
            &[
                PathBuf::from("/home/alice/Documents"),
                PathBuf::from("/home/alice/Mes \"images\""),
            ],
            false,
        )
        .unwrap();
        // Un nom de disque piégé (saut de ligne) : rien n'est écrit. Un « % » est doublé pour systemd.
        assert_eq!(
            unites(
                Path::new("/usr/bin/rsync"),
                Some(findmnt()),
                UUID,
                Path::new("/run/media/alice/X\nExecStartPre=/bin/touch /tmp/pirate"),
                Path::new("/run/media/alice/X\nExecStartPre=/bin/touch /tmp/pirate/Sauvegarde-Vanguard/pc"),
                &[PathBuf::from("/home/alice/Documents")],
                false,
            ),
            Err(Refus::Controle)
        );
        let (_, cent) = unites(
            Path::new("/usr/bin/rsync"),
            Some(findmnt()),
            UUID,
            Path::new("/run/media/alice/100%"),
            Path::new("/run/media/alice/100%/Sauvegarde-Vanguard/pc"),
            &[PathBuf::from("/home/alice/Documents")],
            false,
        )
        .unwrap();
        assert!(cent.contains("ConditionPathIsMountPoint=/run/media/alice/100%%\n"));
        assert!(cent.contains("\"/run/media/alice/100%%/Sauvegarde-Vanguard/pc/\""));
        assert!(timer.contains("OnCalendar=*-*-* 12:00:00") && timer.contains("Persistent=true"));
        assert!(timer.contains("WantedBy=timers.target"));
        assert!(service.contains("ConditionPathIsMountPoint=/run/media/alice/Externe"));
        assert!(service.contains("Type=oneshot"));
        let exec = service.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert!(exec.starts_with("ExecStart=\"/usr/bin/rsync\" -a --no-specials"));
        assert!(exec.contains("\"/home/alice/Documents\" \"/home/alice/Mes \\\"images\\\"\" "));
        assert!(exec.ends_with("\"/run/media/alice/Externe/Sauvegarde-Vanguard/pc-alice/\""));
        assert!(!exec.contains("--delete"));
        assert_eq!(citer_systemd(r"a\b"), "\"a\\\\b\"");
    }

    /// Le disque est reconnu à l'UUID de son système de fichiers, pas à son nom : un autre disque du même nom, monté
    /// au même endroit, fait sauter le passage. Sans identité lisible, rien n'est posé.
    #[test]
    fn le_disque_est_reconnu_a_son_uuid() {
        let poser = |findmnt: Option<&Path>, uuid: Option<&str>| {
            unites(
                Path::new("/usr/bin/rsync"),
                findmnt,
                uuid,
                Path::new("/run/media/alice/Mon disque"),
                Path::new("/run/media/alice/Mon disque/Sauvegarde-Vanguard/pc"),
                &[PathBuf::from("/home/alice/Documents")],
                false,
            )
        };
        let (_, service) = poser(Some(findmnt()), Some("0123abcd-4567-89ef-0123-456789abcdef")).unwrap();
        let verification = service.lines().find(|l| l.starts_with(VERIFICATION)).unwrap();
        assert_eq!(
            verification,
            "ExecCondition=\"/usr/bin/findmnt\" --source UUID=0123abcd-4567-89ef-0123-456789abcdef --mountpoint \"/run/media/alice/Mon disque\""
        );
        // La vérification passe avant la copie.
        assert!(service.find(VERIFICATION) < service.find("ExecStart="));
        assert!(verifie_le_disque(&service));
        // UUID illisible, absent ou qui sortirait de sa ligne ; findmnt introuvable : la mise en place est refusée.
        for uuid in [
            None,
            Some(""),
            Some("1A2B 3C4D"),
            Some("x\nExecStartPre=/bin/true"),
            Some("../../etc"),
        ] {
            assert_eq!(poser(Some(findmnt()), uuid), Err(Refus::Identite), "{uuid:?}");
        }
        assert_eq!(poser(None, UUID), Err(Refus::Identite));
        // Une unité posée avant la 0.78 (chemin seulement) est reconnue comme telle, pour le dire au menu.
        let ancienne = "[Unit]\nDescription=Sauvegarde Vanguard vers /run/media/alice/Externe/Sauvegarde-Vanguard/pc\nConditionPathIsMountPoint=/run/media/alice/Externe\n\n[Service]\nType=oneshot\nSuccessExitStatus=24\nExecStart=\"/usr/bin/rsync\" -a \"/home/alice/Documents\" \"/run/media/alice/Externe/Sauvegarde-Vanguard/pc/\"\n";
        assert!(!verifie_le_disque(ancienne));
    }

    /// La vérification de l'unité, faite pour de vrai par findmnt sur la racine de cet ordinateur : le bon UUID passe,
    /// un autre UUID ou un autre point de montage fait sauter le passage (code 1).
    #[cfg(target_os = "linux")]
    #[test]
    fn findmnt_tranche_comme_l_unite_l_attend() {
        let Some(findmnt) = dans_le_path("findmnt") else {
            return crate::essais::saute("findmnt absent");
        };
        let Some(uuid) = crate::protection::manifeste::identifiant_volume(Path::new("/")) else {
            return crate::essais::saute("identifiant du volume de / illisible");
        };
        let code = |uuid: &str, point: &str| {
            std::process::Command::new(&findmnt)
                .args(["--source", &format!("UUID={uuid}"), "--mountpoint", point])
                .output()
                .ok()
                .and_then(|s| s.status.code())
        };
        assert_eq!(code(&uuid, "/"), Some(0));
        assert_eq!(code("0000-0000", "/"), Some(1));
        assert_eq!(code(&uuid, "/nexiste/pas"), Some(1));
    }

    #[test]
    fn notes_ecrites_et_relues() {
        let f = std::env::temp_dir().join(format!("vanguard-sauvegarde-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&f);
        assert_eq!(charger_de(&f), Notes::default());
        let m = MiseEnPlace::Systemd {
            date: "2026-10-18".into(),
            destination: "/run/media/alice/Externe/Sauvegarde-Vanguard/pc".into(),
            empreinte_timer: empreinte("a"),
            empreinte_service: empreinte("b"),
        };
        ecrire_dans(
            &f,
            &Notes {
                mise_en_place: Some(m.clone()),
            },
        )
        .unwrap();
        assert_eq!(charger_de(&f).mise_en_place, Some(m.clone()));
        assert!(decrire(&m).contains("rsync") && decrire(&m).contains("2026-10-18"));
        let t = MiseEnPlace::TimeMachine {
            date: "2026-10-18".into(),
            destination: "/Volumes/Externe".into(),
            identifiant: Some("ABC".into()),
            deja_actif: false,
        };
        ecrire_dans(
            &f,
            &Notes {
                mise_en_place: Some(t.clone()),
            },
        )
        .unwrap();
        assert_eq!(charger_de(&f).mise_en_place, Some(t));
        // Un fichier abîmé : rien, jamais une erreur.
        std::fs::write(&f, "{abîmé").unwrap();
        assert_eq!(charger_de(&f), Notes::default());
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn destinations_de_time_machine() {
        let avant = "> Name          : Externe\n  Kind          : Local\n  Mount Point   : /Volumes/Externe\n  ID            : 1111-AAAA\n";
        let apres = format!(
            "{avant}====================================================\n> Name          : Neuf\n  Kind          : Local\n  ID            : 2222-BBBB\n"
        );
        assert_eq!(identifiants_time_machine(avant), ["1111-AAAA"]);
        assert_eq!(
            nouvel_identifiant(&identifiants_time_machine(avant), &identifiants_time_machine(&apres)),
            Some("2222-BBBB".into())
        );
        assert_eq!(nouvel_identifiant(&["a".into()], &["a".into()]), None);
        assert_eq!(identifiants_time_machine("tmutil: No destinations configured").len(), 0);
        assert_eq!(
            identifiants_time_machine("ID : 1A2B-3C4D\nID : x; rm -rf ~\nID : \n"),
            ["1A2B-3C4D"]
        );
    }

    #[test]
    fn historique_des_fichiers_de_windows() {
        let xml = "<?xml version=\"1.0\"?><DataProtectionUserConfig><Target><TargetName>Externe (E:)</TargetName><TargetUrl>E:\\</TargetUrl></Target></DataProtectionUserConfig>";
        assert_eq!(cible_historique(xml), Some("Externe (E:)".into()));
        assert_eq!(cible_historique("<x/>"), None);
        assert_eq!(cible_historique("<TargetName></TargetName>"), None);
        // 2026-10-18 00:00 UTC en FILETIME, vu trois jours plus tard.
        let unix_2026_10_18: u64 = 1_792_281_600;
        let filetime = (unix_2026_10_18 + 11_644_473_600) * 10_000_000;
        assert_eq!(age_filetime_jours(filetime, unix_2026_10_18 + 3 * 86_400), 3);
        assert_eq!(age_filetime_jours(filetime, unix_2026_10_18), 0);
        assert_eq!(age_filetime_jours(0, unix_2026_10_18), unix_2026_10_18 / 86_400);
    }

    /// La minuterie rsync de Vanguard qui lance un rsync parti : dit, avec la correction ; rsync là, rien à dire.
    #[test]
    fn rsync_parti_dit_au_bilan() {
        let c = juger_rsync(Path::new("/usr/bin/rsync"), false).expect("constat");
        assert_eq!(c.probleme, Some(crate::risk::Niveau::Moyen));
        assert!(c.message.contains("/usr/bin/rsync") && !c.correctif.unwrap().automatique);
        assert!(juger_rsync(Path::new("/usr/bin/rsync"), true).is_none());
    }

    #[test]
    fn nom_de_machine_propre() {
        let n = nom_machine();
        assert!(!n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '-'));
        assert!(constats().len() <= 1);
    }

    /// Un schéma décrit dans son fichier XML : la clé se cherche dans le bon schéma du fichier ; le premier dossier
    /// qui a le fichier l'emporte ; sans fichier, ou un fichier qui ne le décrit pas, rien n'est conclu.
    #[cfg(target_os = "linux")]
    #[test]
    fn schemas_de_reglages() {
        let d = std::env::temp_dir().join(format!("vanguard-sauvegarde-schemas-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (compte, systeme) = (d.join("compte"), d.join("systeme"));
        for dossier in [&compte, &systeme] {
            std::fs::create_dir_all(dossier).unwrap();
        }
        std::fs::write(
            systeme.join("org.exemple.Copie.gschema.xml"),
            "<schemalist>\n  <schema id=\"org.exemple.Copie\" path=\"/org/exemple/copie/\">\n    \
             <key name=\"periodic\" type=\"b\"><default>false</default></key>\n  </schema>\n  \
             <schema id=\"org.exemple.Copie.Local\">\n    <key name=\"folder\" type=\"s\"/>\n  </schema>\n\
             </schemalist>\n",
        )
        .unwrap();
        let dossiers = [compte.clone(), systeme.clone()];
        assert_eq!(
            schema_gsettings_dans(&dossiers, "org.exemple.Copie", Some("periodic")),
            Some(true)
        );
        assert_eq!(
            schema_gsettings_dans(&dossiers, "org.exemple.Copie", Some("folder")),
            Some(false)
        );
        assert_eq!(schema_gsettings_dans(&dossiers, "org.exemple.Copie", None), Some(true));
        assert_eq!(schema_gsettings_dans(&dossiers, "org.exemple.Autre", None), None);
        // Le dossier du compte passe avant celui du système.
        std::fs::write(
            compte.join("org.exemple.Copie.gschema.xml"),
            "<schemalist><schema id=\"org.exemple.Copie\"></schema></schemalist>",
        )
        .unwrap();
        assert_eq!(
            schema_gsettings_dans(&dossiers, "org.exemple.Copie", Some("periodic")),
            Some(false)
        );
        std::fs::write(compte.join("org.exemple.Vide.gschema.xml"), "<schemalist/>").unwrap();
        assert_eq!(schema_gsettings_dans(&dossiers, "org.exemple.Vide", None), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sur cet ordinateur, les clés que `gsettings list-keys` donne se trouvent dans le fichier du schéma, quand
    /// gsettings et le fichier sont là.
    #[cfg(target_os = "linux")]
    #[test]
    fn schemas_comme_gsettings() {
        for schema in ["org.gnome.desktop.privacy", "org.gnome.desktop.interface"] {
            let Some(cles) =
                crate::commande::lancer(std::process::Command::new("gsettings").args(["list-keys", schema]), 10)
                    .filter(|r| r.code == Some(0))
                    .map(|r| r.sortie)
            else {
                continue;
            };
            if schema_gsettings(schema, None).is_none() {
                continue;
            }
            for cle in cles.split_whitespace() {
                assert_eq!(schema_gsettings(schema, Some(cle)), Some(true), "{schema} {cle}");
            }
            assert_eq!(schema_gsettings(schema, Some("cle-qui-n-existe-pas")), Some(false));
        }
    }
}
