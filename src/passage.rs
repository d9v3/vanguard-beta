//! Passage de l'ancien nom à Vanguard. Le programme s'appelait autrement jusqu'à la 0.78 : ce qu'une version d'avant a
//! posé sur un ordinateur porte encore cet ancien nom (dossier des données, minuteries, tâches planifiées, raccourcis,
//! règles du pare-feu, dossiers sur les disques, fichiers posés par une correction). Ce module est le seul endroit du
//! code qui le connaît : au premier lancement, il reprend ce qui peut l'être, et il aide les autres modules à
//! reconnaître le reste, pour pouvoir encore l'annuler ou le retirer. Rien ne se perd, même sur un ordinateur oublié.
//! À retirer à la 1.0.

use std::path::{Path, PathBuf};

use crate::ui::*;

/// L'ancien nom d'un nom de Vanguard, dans la même casse : « vanguard-surveillance » → son équivalent d'avant.
pub(crate) fn ancien(nom: &str) -> String {
    nom.replace("VANGUARD", "GARDIEN")
        .replace("Vanguard", "Gardien")
        .replace("vanguard", "gardien")
}

/// Le nom et son ancien équivalent, pour reconnaître l'un ou l'autre.
pub(crate) fn les_deux(nom: &str) -> [String; 2] {
    [nom.to_string(), ancien(nom)]
}

/// Le nom et son ancien équivalent en liste PowerShell (« 'a','b' »), pour un paramètre qui accepte plusieurs noms.
#[cfg(any(windows, test))]
pub(crate) fn liste_ps(nom: &str) -> String {
    les_deux(nom)
        .iter()
        .map(|n| format!("'{}'", crate::commande::ps_texte(n)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Une variable d'environnement de Vanguard, ou à défaut son ancien nom : une clé HIBP ou une langue posée avant le
/// changement de nom continue de servir.
pub(crate) fn variable(nom: &str) -> Option<String> {
    std::env::var(nom).ok().or_else(|| std::env::var(ancien(nom)).ok())
}

/// Un fichier JSON de Vanguard (sauvegarde des données, manifeste de la clé) écrit sous l'ancien nom : son format et
/// ses champs reprennent le nouveau. Rien ne change pour un autre fichier.
pub(crate) fn reprendre_format(valeur: &mut serde_json::Value, format: &str) {
    let Some(objet) = valeur.as_object_mut() else {
        return;
    };
    if objet.get("format").and_then(|f| f.as_str()) != Some(ancien(format).as_str()) {
        return;
    }
    let a_renommer: Vec<String> = objet
        .keys()
        .filter(|k| k.contains(&ancien("vanguard")))
        .cloned()
        .collect();
    for cle in a_renommer {
        if let Some(v) = objet.remove(&cle) {
            objet.insert(cle.replace(&ancien("vanguard"), "vanguard"), v);
        }
    }
    objet.insert("format".into(), format.into());
}

/// Au lancement : si le dossier des données d'une version d'avant existe encore, tout ce qu'elle a posé passe à
/// Vanguard, une seule fois (le dossier déplacé, la question ne se repose plus). Jamais depuis un test : les vraies
/// données de l'ordinateur de développement ne doivent pas bouger.
pub(crate) fn au_lancement() {
    if cfg!(test) {
        return;
    }
    let nouveau = crate::socle::dossier_local();
    let vieux = nouveau.with_file_name(ancien("vanguard"));
    // Un dossier du même nom sans rien de la version d'avant est à une autre application : jamais repris.
    if !donnees_d_avant(&vieux) {
        return;
    }
    eprintln!(
        "{}",
        crate::tr!(
            "  Ce programme s'appelle maintenant Vanguard : reprise des données et des réglages de la version d'avant.",
            "  This program is now called Vanguard: taking over the data and settings of the previous version."
        )
    );
    if let Err(e) = deplacer_donnees(&vieux, &nouveau) {
        eprintln!(
            "{}",
            crate::trf!(
                "  ✖ Données non déplacées ({e}) : nouvel essai au prochain lancement.",
                "  ✖ Data not moved ({e}): another try at the next start."
            )
        );
        return;
    }
    let surveillance = retirer_minuterie(&ancien("vanguard-surveillance"));
    let entretien = retirer_minuterie(&ancien("vanguard-entretien"));
    #[cfg(target_os = "linux")]
    let sauvegarde = reprendre_sauvegarde();
    #[cfg(not(target_os = "linux"))]
    let sauvegarde = false;
    let raccourci = retirer_raccourci();
    // Le programme copié par la version d'avant pour ses minuteries (lancée depuis la clé) : remplacé ci-dessous.
    let _ = std::fs::remove_file(nouveau.join("bin").join(format!(
        "{}{}",
        ancien("vanguard"),
        std::env::consts::EXE_SUFFIX
    )));
    // Sans copie locale (elle a échoué et l'a dit), rien de ce qui la lancerait n'est repris.
    let exe = crate::reseau::surveillance::executable();
    let mut repris = Vec::new();
    if let Some(exe) = &exe
        && surveillance
        && crate::reseau::surveillance::reprendre(exe)
    {
        repris.push(crate::tr!("surveillance horaire", "hourly monitoring"));
    }
    if let Some(exe) = &exe
        && entretien
        && crate::entretien::reprendre(exe)
    {
        repris.push(crate::tr!("entretien du mois", "monthly check-up"));
    }
    if sauvegarde {
        repris.push(crate::tr!("sauvegarde automatique", "automatic backup"));
    }
    if let (Some(exe), Some(ou)) = (&exe, raccourci)
        && crate::raccourci::reprendre(exe, &ou)
    {
        repris.push(crate::tr!("raccourci", "shortcut"));
    }
    if !repris.is_empty() {
        eprintln!(
            "{}",
            crate::trf!(
                "  ✔ Repris sous le nom Vanguard : {}.",
                "  ✔ Taken over under the Vanguard name: {}.",
                repris.join(", ")
            )
        );
    }
}

/// Le dossier des données change de nom. Si Vanguard en a déjà un (lancé avant la reprise), ce qui n'y est pas encore
/// y passe, et le reste de l'ancien dossier y est gardé à part, jamais effacé.
fn deplacer_donnees(vieux: &Path, nouveau: &Path) -> std::io::Result<()> {
    if !nouveau.exists() {
        return std::fs::rename(vieux, nouveau);
    }
    for entree in std::fs::read_dir(vieux)?.flatten() {
        let cible = nouveau.join(entree.file_name());
        if !cible.exists() {
            std::fs::rename(entree.path(), cible)?;
        }
    }
    let reste = nouveau.join("reprise-version-d-avant");
    if std::fs::read_dir(vieux)?.next().is_none() {
        std::fs::remove_dir(vieux)
    } else if reste.exists() {
        std::fs::rename(
            vieux,
            reste.join(chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()),
        )
    } else {
        std::fs::rename(vieux, reste)
    }
}

/// Retire la minuterie, l'agent ou la tâche planifiée d'avant, de ce nom ; dit s'il était actif (il est alors recréé
/// sous le nouveau nom, avec le programme d'aujourd'hui).
fn retirer_minuterie(nom: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let dossier = dossier_systemd();
        if !dossier.join(format!("{nom}.timer")).exists() {
            return false;
        }
        let actif = crate::reseau::surveillance::minuterie_activee(&format!("{nom}.timer"));
        let _ = retirer_unites(nom, &dossier);
        actif
    }
    #[cfg(target_os = "macos")]
    {
        let agent = format!("com.{}", nom.replacen('-', ".", 1));
        let plist = crate::socle::maison().join(format!("Library/LaunchAgents/{agent}.plist"));
        if !plist.exists() {
            return false;
        }
        let domaine = crate::reseau::surveillance::domaine_launchd();
        let actif = crate::reseau::surveillance::reussit("launchctl", &["print", &format!("{domaine}/{agent}")]);
        let _ = crate::reseau::surveillance::reussit("launchctl", &["bootout", &domaine, &plist.display().to_string()]);
        let _ = std::fs::remove_file(&plist);
        actif
    }
    #[cfg(windows)]
    {
        // « gardien-surveillance » → la tâche « … - surveillance du reseau » (le nom lisible de la tâche).
        let tache = tache_windows(nom);
        // Absente pour le planificateur : rien à retirer, sans PowerShell.
        if crate::machine::windows::planificateur::etat(&[&tache])
            == Some(crate::machine::windows::planificateur::EtatTache::Absente)
        {
            return false;
        }
        let e = crate::commande::ps_texte(&tache);
        crate::machine::windows::ps(&format!(
            "$t = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {{ $_.TaskName -eq '{e}' }}; \
             if ($t) {{ if ($t.State -ne 'Disabled') {{ 'actif' }}; Unregister-ScheduledTask -TaskName '{e}' -Confirm:$false }}"
        ))
        .is_some_and(|s| s.trim() == "actif")
    }
}

/// Le nom lisible de la tâche planifiée Windows d'avant, d'après le nom court de la minuterie.
fn tache_windows(nom: &str) -> String {
    let (programme, quoi) = nom.split_once('-').unwrap_or((nom, ""));
    let lisible = match quoi {
        "surveillance" => "surveillance du reseau",
        "entretien" => "entretien du mois",
        autre => autre,
    };
    format!("{programme} - {lisible}")
}

#[cfg(target_os = "linux")]
fn dossier_systemd() -> PathBuf {
    crate::socle::maison().join(".config/systemd/user")
}

/// Sauvegarde automatique de Linux (minuterie rsync) : ses deux unités prennent le nouveau nom, avec le même contenu
/// (le même disque, le même dossier dessus : pas de nouvelle copie complète à côté de l'ancienne), et la note qui sert
/// à l'annuler suit. Dit si elle a été reprise.
#[cfg(target_os = "linux")]
fn reprendre_sauvegarde() -> bool {
    let dossier = dossier_systemd();
    let [timer, service] = ["vanguard-sauvegarde.timer", "vanguard-sauvegarde.service"];
    let (vieux_timer, vieux_service) = (dossier.join(ancien(timer)), dossier.join(ancien(service)));
    let (Ok(t), Ok(s)) = (
        std::fs::read_to_string(&vieux_timer),
        std::fs::read_to_string(&vieux_service),
    ) else {
        return false;
    };
    let actif = crate::reseau::surveillance::minuterie_activee(&ancien(timer));
    let (t, s) = (unite_sauvegarde(&t), unite_sauvegarde(&s));
    if std::fs::write(dossier.join(timer), &t).is_err() || std::fs::write(dossier.join(service), &s).is_err() {
        return false;
    }
    crate::reseau::surveillance::reussit("systemctl", &["--user", "disable", "--now", &ancien(timer)]);
    let _ = std::fs::remove_file(&vieux_timer);
    let _ = std::fs::remove_file(&vieux_service);
    crate::reseau::surveillance::reussit("systemctl", &["--user", "daemon-reload"]);
    if actif {
        crate::reseau::surveillance::reussit("systemctl", &["--user", "enable", "--now", timer]);
    }
    crate::sauvegarde::reprendre_note(&t, &s);
    true
}

/// Une unité de la sauvegarde d'avant, au nouveau nom : le nom du programme dans la description (le premier : la
/// suite est le chemin du disque) et le témoin des copies en cours exclu de la sauvegarde. Le dossier sur le disque
/// reste le même, la description continue de le dire tel qu'il est.
#[cfg(any(target_os = "linux", test))]
fn unite_sauvegarde(texte: &str) -> String {
    texte
        .lines()
        .map(|l| {
            if l.starts_with("Description=") {
                l.replacen(&ancien("Vanguard"), "Vanguard", 1)
            } else if l.starts_with("ExecStart=") {
                let temoin = ".vanguard-copie-en-cours";
                l.replace(&format!("--exclude={}", ancien(temoin)), &format!("--exclude={temoin}"))
            } else {
                l.to_string()
            }
        })
        .map(|l| l + "\n")
        .collect()
}

/// Le raccourci d'avant, s'il a été posé par la version d'avant : retiré ; rend l'endroit où poser le nouveau.
fn retirer_raccourci() -> Option<PathBuf> {
    let nouveau = crate::raccourci::chemin()?;
    let nom = nouveau.file_name()?.to_string_lossy().to_string();
    let vieux = nouveau.with_file_name(ancien(&nom));
    if !vieux.exists() || !raccourci_d_avant(&vieux) {
        return None;
    }
    std::fs::remove_file(&vieux).ok()?;
    // L'icône d'avant seulement si c'est bien la sienne : une icône du même nom venue d'ailleurs reste.
    if let Some(icone) = icone_d_avant(&nouveau) {
        let _ = std::fs::remove_file(icone);
    }
    (!nouveau.exists()).then_some(nouveau)
}

/// Ce raccourci a-t-il été posé par la version d'avant ? Un .desktop ou un .command porte sa marque ; un .lnk, qui ne
/// se lit pas comme du texte, doit viser son programme (le nom s'y trouve en octets simples ou en UTF-16) : l'ancien
/// nom est un mot courant, et un raccourci de ce nom vers un autre programme n'est pas à elle.
fn raccourci_d_avant(vieux: &Path) -> bool {
    let Ok(octets) = std::fs::read(vieux) else {
        return false;
    };
    if !vieux.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) {
        return String::from_utf8_lossy(&octets).contains(&ancien(crate::raccourci::MARQUE));
    }
    let bas: Vec<u8> = octets.iter().map(u8::to_ascii_lowercase).collect();
    let cible = format!("{}.exe", ancien("vanguard"));
    let large: Vec<u8> = cible.bytes().flat_map(|o| [o, 0]).collect();
    bas.windows(cible.len()).any(|f| f == cible.as_bytes()) || bas.windows(large.len()).any(|f| f == large.as_slice())
}

/// Ce dossier est-il celui des données de la version d'avant ? Il doit en garder un témoin (carnet, historique,
/// quarantaine, réglages, copie du programme) : un dossier du même nom venu d'une autre application n'est ni repris
/// ni proposé à l'effacement.
pub(crate) fn donnees_d_avant(vieux: &Path) -> bool {
    let programme = format!("bin/{}{}", ancien("vanguard"), std::env::consts::EXE_SUFFIX);
    // Le carnet chiffré a pu porter l'un ou l'autre nom.
    let chiffre = format!("appareils.json.{}", ancien("vanguard"));
    vieux.is_dir()
        && [
            "appareils.json",
            crate::chiffrement::CARNET_CHIFFRE,
            chiffre.as_str(),
            "historique.json",
            "quarantaine/quarantaine.json",
            "reglages.json",
            "parametres.json",
            programme.as_str(),
        ]
        .iter()
        .any(|t| std::fs::symlink_metadata(vieux.join(t)).is_ok())
}

/// L'icône posée par la version d'avant à côté du raccourci du menu des applications (Linux), si elle est là et
/// reconnue à son empreinte.
fn icone_d_avant(raccourci: &Path) -> Option<PathBuf> {
    let icone = crate::raccourci::icone(raccourci)?.with_file_name(format!("{}.png", ancien("vanguard")));
    let reconnue = std::fs::symlink_metadata(&icone).is_ok_and(|m| m.is_file())
        && std::fs::read(&icone).is_ok_and(|o| crate::raccourci::icone_de_vanguard(&o));
    reconnue.then_some(icone)
}

/// Ce qu'une version d'avant a laissé sur cet ordinateur, retrouvé par l'ancien nom pour la désinstallation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reste {
    /// Les unités systemd d'avant (« nom.timer », « nom.service »), dans ce dossier.
    Minuterie {
        nom: String,
        dossier: PathBuf,
    },
    /// Le plist d'un agent launchd d'avant.
    Agent(PathBuf),
    /// Une tâche du Planificateur d'avant, par son nom.
    Tache(String),
    Raccourci(PathBuf),
    Icone(PathBuf),
    /// La copie du programme d'avant dans bin/.
    Programme(PathBuf),
    /// L'ancien dossier des données, que `au_lancement` n'a pas pu déplacer.
    Donnees(PathBuf),
}

impl Reste {
    /// Ce que c'est, en quelques mots (26 colonnes au plus : la ligne à cocher les fait précéder de « Version d'avant : »).
    pub(crate) fn quoi(&self) -> String {
        let genre = |nom: &str| {
            if nom.ends_with("surveillance") {
                0
            } else if nom.ends_with("entretien") {
                1
            } else {
                2
            }
        };
        match self {
            Reste::Minuterie { nom, .. } => match genre(nom) {
                0 => tr!("minuterie de surveillance", "monitoring timer"),
                1 => tr!("minuterie d'entretien", "check-up timer"),
                _ => tr!("minuterie de sauvegarde", "backup timer"),
            },
            Reste::Agent(p) => match genre(&p.file_stem().unwrap_or_default().to_string_lossy()) {
                0 => tr!("agent de surveillance", "monitoring agent"),
                _ => tr!("agent d'entretien", "check-up agent"),
            },
            Reste::Tache(nom) if nom.ends_with("du mois") => tr!("tâche d'entretien", "check-up task"),
            Reste::Tache(_) => tr!("tâche de surveillance", "monitoring task"),
            Reste::Raccourci(_) => tr!("raccourci", "shortcut"),
            Reste::Icone(_) => tr!("icône", "icon"),
            Reste::Programme(_) => tr!("copie du programme", "program copy"),
            Reste::Donnees(_) => tr!("dossier de données", "data folder"),
        }
        .to_string()
    }

    /// Les fichiers ou le dossier qu'il touche (une tâche Windows n'en a pas).
    pub(crate) fn chemins(&self) -> Vec<PathBuf> {
        match self {
            Reste::Minuterie { nom, dossier } => ["timer", "service"]
                .iter()
                .map(|e| dossier.join(format!("{nom}.{e}")))
                .filter(|p| std::fs::symlink_metadata(p).is_ok())
                .collect(),
            Reste::Agent(p) | Reste::Raccourci(p) | Reste::Icone(p) | Reste::Programme(p) | Reste::Donnees(p) => {
                vec![p.clone()]
            }
            Reste::Tache(_) => Vec::new(),
        }
    }
}

/// Les tâches du Planificateur qu'une version d'avant posait, par leur nom.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn taches_d_avant() -> Vec<String> {
    ["vanguard-surveillance", "vanguard-entretien"]
        .iter()
        .map(|n| tache_windows(&ancien(n)))
        .collect()
}

/// Tout ce qu'une version d'avant a laissé dans les lieux `l`, sans rien retirer, avec le chemin à montrer. Les mêmes
/// règles que la reprise (`retirer_minuterie`, `tache_windows`, `retirer_raccourci`) : un nom exact, la marque d'avant
/// pour un raccourci, l'empreinte pour une icône. Ce que la version d'avant n'a pas posé n'y est jamais.
pub(crate) fn restes(l: &crate::desinstaller::Lieux) -> Vec<(Reste, PathBuf)> {
    let mut restes = Vec::new();
    for dossier in &l.unites {
        for quoi in ["surveillance", "entretien", "sauvegarde"] {
            let nom = ancien(&format!("vanguard-{quoi}"));
            let timer = dossier.join(format!("{nom}.timer"));
            let service = dossier.join(format!("{nom}.service"));
            if timer.exists() || service.exists() {
                let montre = if timer.exists() { timer } else { service };
                restes.push((
                    Reste::Minuterie {
                        nom,
                        dossier: dossier.clone(),
                    },
                    montre,
                ));
            }
        }
    }
    if let Some(agents) = &l.agents {
        for quoi in ["surveillance", "entretien"] {
            let plist = agents.join(format!("com.{}.{quoi}.plist", ancien("vanguard")));
            if plist.is_file() {
                restes.push((Reste::Agent(plist.clone()), plist));
            }
        }
    }
    for t in l.taches.iter().flatten() {
        if taches_d_avant().iter().any(|n| n.eq_ignore_ascii_case(&t.nom)) {
            restes.push((Reste::Tache(t.nom.clone()), PathBuf::from(&t.nom)));
        }
    }
    if let Some(nouveau) = &l.raccourci
        && let Some(nom) = nouveau.file_name()
    {
        let vieux = nouveau.with_file_name(ancien(&nom.to_string_lossy()));
        if vieux.is_file() && raccourci_d_avant(&vieux) {
            restes.push((Reste::Raccourci(vieux.clone()), vieux));
        }
        if let Some(icone) = icone_d_avant(nouveau) {
            restes.push((Reste::Icone(icone.clone()), icone));
        }
    }
    let programme = l
        .donnees
        .join("bin")
        .join(format!("{}{}", ancien("vanguard"), std::env::consts::EXE_SUFFIX));
    if std::fs::symlink_metadata(&programme).is_ok() {
        restes.push((Reste::Programme(programme.clone()), programme));
    }
    let vieux = l.donnees.with_file_name(ancien("vanguard"));
    if donnees_d_avant(&vieux) {
        restes.push((Reste::Donnees(vieux.clone()), vieux));
    }
    restes
}

/// Un dossier au nom de celui de la version d'avant, mais sans rien d'elle : à une autre application, jamais touché.
pub(crate) fn dossier_d_un_autre(l: &crate::desinstaller::Lieux) -> Option<PathBuf> {
    let vieux = l.donnees.with_file_name(ancien("vanguard"));
    (vieux.is_dir() && !donnees_d_avant(&vieux)).then_some(vieux)
}

/// Retire un reste d'une version d'avant, sans rien demander (la désinstallation l'a montré et fait accepter) ; rend
/// la raison d'un échec. Le dossier de données d'avant, lui, s'efface avec le reste des données
/// (`desinstaller::effacer_dossier`).
pub(crate) fn retirer_reste(r: &Reste) -> Result<(), String> {
    match r {
        Reste::Minuterie { nom, dossier } => retirer_unites(nom, dossier),
        Reste::Agent(plist) => {
            #[cfg(target_os = "macos")]
            {
                let domaine = crate::reseau::surveillance::domaine_launchd();
                let _ = crate::reseau::surveillance::reussit(
                    "launchctl",
                    &["bootout", &domaine, &plist.display().to_string()],
                );
            }
            std::fs::remove_file(plist).map_err(|e| e.to_string())
        }
        Reste::Tache(nom) => retirer_tache(nom),
        Reste::Raccourci(p) | Reste::Icone(p) | Reste::Programme(p) => {
            std::fs::remove_file(p).map_err(|e| e.to_string())
        }
        Reste::Donnees(d) => Err(trf!(
            "{} : un dossier s'efface avec les données",
            "{}: a folder is erased with the data",
            d.display()
        )),
    }
}

/// Les deux unités d'une minuterie d'avant : arrêtée, ses fichiers retirés, systemd rechargé. Dit si systemctl n'a
/// pas répondu, jamais compté comme fait.
fn retirer_unites(nom: &str, dossier: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    let arretee =
        crate::reseau::surveillance::reussit("systemctl", &["--user", "disable", "--now", &format!("{nom}.timer")]);
    #[cfg(not(target_os = "linux"))]
    let arretee = false;
    let mut echecs = Vec::new();
    for e in ["timer", "service"] {
        let f = dossier.join(format!("{nom}.{e}"));
        if std::fs::symlink_metadata(&f).is_ok()
            && let Err(x) = std::fs::remove_file(&f)
        {
            echecs.push(format!("{} ({x})", f.display()));
        }
    }
    #[cfg(target_os = "linux")]
    let recharge = crate::reseau::surveillance::reussit("systemctl", &["--user", "daemon-reload"]);
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

/// Une tâche du Planificateur d'avant : arrêtée (une passe en cours n'écrit plus rien), puis retirée.
fn retirer_tache(nom: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let e = crate::commande::ps_texte(nom);
        crate::machine::windows::ps(&format!(
            "Stop-ScheduledTask -TaskName '{e}' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '{e}' -Confirm:$false"
        ))
        .map(|_| ())
        .ok_or_else(|| tr!("PowerShell n'a pas pu retirer la tâche", "PowerShell could not remove the task").to_string())
    }
    #[cfg(not(windows))]
    Err(trf!(
        "« {nom} » : une tâche de Windows, pas de cet ordinateur",
        "“{nom}”: a Windows task, not of this computer"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancien_nom_dans_chaque_casse() {
        assert_eq!(ancien("Vanguard : bloquer *"), "Gardien : bloquer *");
        assert_eq!(ancien("VANGUARD_HIBP_CLE"), "GARDIEN_HIBP_CLE");
        assert_eq!(ancien(".vanguard-copie-en-cours"), ".gardien-copie-en-cours");
        assert_eq!(les_deux("Vanguard-copie-"), ["Vanguard-copie-", "Gardien-copie-"]);
        assert_eq!(
            liste_ps("Vanguard : bloquer *"),
            "'Vanguard : bloquer *','Gardien : bloquer *'"
        );
    }

    #[test]
    fn format_d_avant_repris() {
        let mut v: serde_json::Value =
            serde_json::from_str(r#"{"format":"gardien-sauvegarde","version_gardien":"0.77.0","base":{}}"#).unwrap();
        reprendre_format(&mut v, "vanguard-sauvegarde");
        assert_eq!(v["format"], "vanguard-sauvegarde");
        assert_eq!(v["version_vanguard"], "0.77.0");
        assert!(v.get("version_gardien").is_none());
        // Un autre fichier n'est pas touché.
        let mut autre: serde_json::Value = serde_json::from_str(r#"{"format":"autre","gardien":1}"#).unwrap();
        reprendre_format(&mut autre, "vanguard-sauvegarde");
        assert_eq!(autre["gardien"], 1);
    }

    #[test]
    fn taches_windows_d_avant() {
        assert_eq!(
            tache_windows("gardien-surveillance"),
            "gardien - surveillance du reseau"
        );
        assert_eq!(tache_windows("gardien-entretien"), "gardien - entretien du mois");
    }

    #[test]
    fn unites_de_sauvegarde_reprises() {
        let service = "[Unit]\nDescription=Sauvegarde Gardien vers /run/media/alice/Externe/Sauvegarde-Gardien/pc\n\
                       ConditionPathIsMountPoint=/run/media/alice/Externe\n\n[Service]\nType=oneshot\n\
                       ExecStart=\"/usr/bin/rsync\" -a --exclude=.cache --exclude=.gardien-copie-en-cours \"/home/alice/Documents\" \"/run/media/alice/Externe/Sauvegarde-Gardien/pc/\"\n";
        let repris = unite_sauvegarde(service);
        assert!(repris.contains("Description=Sauvegarde Vanguard vers /run/media/alice/Externe/Sauvegarde-Gardien/pc"));
        // Le dossier sur le disque ne bouge pas, seul le témoin exclu suit.
        assert!(repris.contains("--exclude=.vanguard-copie-en-cours \"/home/alice/Documents\" \"/run/media/alice/Externe/Sauvegarde-Gardien/pc/\""));
    }

    /// Les restes d'une version d'avant, dans un ordinateur jetable : reconnus à leur nom exact, à la marque d'avant
    /// pour un raccourci, à l'empreinte pour une icône ; le reste n'y est jamais.
    #[test]
    fn restes_d_une_version_d_avant() {
        let racine = crate::socle::dossier_local().join("passage-restes");
        let _ = std::fs::remove_dir_all(&racine);
        let l = crate::desinstaller::Lieux::jetable(&racine);
        let ecrire = |p: &Path, t: &[u8]| {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, t).unwrap();
        };
        let unites = &l.unites[0];
        ecrire(&unites.join("gardien-surveillance.timer"), b"[Timer]\n");
        ecrire(&unites.join("gardien-entretien.service"), b"[Service]\n");
        ecrire(&unites.join("gardien-autre.timer"), b"[Timer]\n");
        ecrire(&l.unites[1].join("gardien-sauvegarde.timer"), b"[Timer]\n");
        let agents = l.agents.clone().unwrap();
        ecrire(&agents.join("com.gardien.surveillance.plist"), b"<plist/>");
        let raccourci = l.raccourci.clone().unwrap();
        let vieux = raccourci.with_file_name("Gardien.desktop");
        ecrire(
            &vieux,
            format!("[Desktop Entry]\n{}\n", ancien(crate::raccourci::MARQUE)).as_bytes(),
        );
        let icone = crate::raccourci::icone(&raccourci)
            .unwrap()
            .with_file_name("gardien.png");
        ecrire(&icone, include_bytes!("../assets/icones/vanguard-128.png"));
        let bin = l
            .donnees
            .join("bin")
            .join(format!("gardien{}", std::env::consts::EXE_SUFFIX));
        ecrire(&bin, b"avant");
        let donnees = l.donnees.with_file_name("gardien");
        ecrire(&donnees.join("historique.json"), b"[]");
        let trouves: Vec<Reste> = restes(&l).into_iter().map(|(r, _)| r).collect();
        assert_eq!(
            trouves,
            [
                Reste::Minuterie {
                    nom: "gardien-surveillance".into(),
                    dossier: unites.clone()
                },
                Reste::Minuterie {
                    nom: "gardien-entretien".into(),
                    dossier: unites.clone()
                },
                Reste::Minuterie {
                    nom: "gardien-sauvegarde".into(),
                    dossier: l.unites[1].clone()
                },
                Reste::Agent(agents.join("com.gardien.surveillance.plist")),
                Reste::Raccourci(vieux.clone()),
                Reste::Icone(icone.clone()),
                Reste::Programme(bin),
                Reste::Donnees(donnees.clone()),
            ]
        );
        assert!(trouves.iter().all(|r| r.quoi().chars().count() <= 26));
        // Sans la marque d'avant, le raccourci n'est pas à elle ; une icône d'autres octets non plus.
        std::fs::write(&vieux, "[Desktop Entry]\nName=Gardien\n").unwrap();
        std::fs::write(&icone, "une autre icone").unwrap();
        let apres: Vec<Reste> = restes(&l).into_iter().map(|(r, _)| r).collect();
        assert!(
            !apres.iter().any(|r| matches!(r, Reste::Raccourci(_) | Reste::Icone(_))),
            "{apres:?}"
        );
        // Un dossier du même nom sans rien de la version d'avant : à une autre application, jamais proposé.
        std::fs::remove_file(donnees.join("historique.json")).unwrap();
        ecrire(&donnees.join("notes-d-une-autre-appli.txt"), b"x");
        assert!(!restes(&l).iter().any(|(r, _)| matches!(r, Reste::Donnees(_))));
        assert_eq!(dossier_d_un_autre(&l), Some(donnees.clone()));
        // Un .lnk au nom d'avant : seulement s'il vise le programme d'avant (en octets simples ou en UTF-16).
        let lnk = racine.join("Bureau").join("Gardien.lnk");
        ecrire(&lnk, b"L\0\0\0C:\\Program Files\\Autre\\autre.exe");
        assert!(!raccourci_d_avant(&lnk));
        ecrire(&lnk, b"L\0\0\0E:\\Windows\\GARDIEN.EXE");
        assert!(raccourci_d_avant(&lnk));
        let large: Vec<u8> = "C:\\x\\gardien.exe".bytes().flat_map(|o| [o, 0]).collect();
        ecrire(&lnk, &[b"L\0\0\0".as_slice(), &large].concat());
        assert!(raccourci_d_avant(&lnk));
        // Des tâches de Windows lues : celles d'avant seulement.
        let mut w = crate::desinstaller::Lieux::jetable(&racine.join("w"));
        w.taches = Some(
            [
                "gardien - surveillance du reseau",
                "vanguard - surveillance du reseau",
                "autre",
            ]
            .into_iter()
            .map(|nom| crate::desinstaller::TacheLue {
                nom: nom.into(),
                programme: String::new(),
                active: true,
            })
            .collect(),
        );
        assert_eq!(
            restes(&w).into_iter().map(|(r, _)| r).collect::<Vec<_>>(),
            [Reste::Tache("gardien - surveillance du reseau".into())]
        );
        let _ = std::fs::remove_dir_all(&racine);
    }

    #[test]
    fn donnees_d_avant_deplacees_sans_rien_perdre() {
        let base = crate::essais::temporaire().join(format!("vanguard-passage-{}", std::process::id()));
        let (vieux, nouveau) = (base.join("ancien"), base.join("nouveau"));
        std::fs::create_dir_all(vieux.join("quarantaine")).unwrap();
        std::fs::write(vieux.join("historique.json"), "avant").unwrap();
        std::fs::write(vieux.join("appareils.json"), "avant").unwrap();
        // Vanguard a déjà tourné une fois : son historique reste, celui d'avant est gardé à part.
        std::fs::create_dir_all(&nouveau).unwrap();
        std::fs::write(nouveau.join("historique.json"), "nouveau").unwrap();
        deplacer_donnees(&vieux, &nouveau).unwrap();
        assert!(!vieux.exists());
        assert_eq!(
            std::fs::read_to_string(nouveau.join("historique.json")).unwrap(),
            "nouveau"
        );
        assert_eq!(
            std::fs::read_to_string(nouveau.join("appareils.json")).unwrap(),
            "avant"
        );
        assert!(nouveau.join("quarantaine").is_dir());
        assert_eq!(
            std::fs::read_to_string(nouveau.join("reprise-version-d-avant/historique.json")).unwrap(),
            "avant"
        );
        // Sans dossier de Vanguard : simple changement de nom.
        let (vieux2, nouveau2) = (base.join("ancien2"), base.join("nouveau2"));
        std::fs::create_dir_all(&vieux2).unwrap();
        std::fs::write(vieux2.join("a"), "1").unwrap();
        deplacer_donnees(&vieux2, &nouveau2).unwrap();
        assert_eq!(std::fs::read_to_string(nouveau2.join("a")).unwrap(), "1");
        let _ = std::fs::remove_dir_all(base);
    }
}
