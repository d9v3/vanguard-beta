//! Retirer Vanguard de cet ordinateur : tout ce qu'il y a posé (surveillance horaire, entretien du mois, sauvegarde
//! automatique, veilleur, fichiers-pièges, raccourci et icône, copie du programme, restes d'une version d'avant,
//! dossier de données), retrouvé, montré avec ce qui sera fait, puis coché.
//!
//! Rien n'est tenu dans un registre de ce qui a été posé : tout est recalculé à partir de ce qui est trouvé, par des
//! noms exacts, une marque ou une empreinte. Un registre se perd, et un programme du compte peut le réécrire : il ne
//! doit jamais pouvoir faire effacer autre chose. Ce que Vanguard n'a pas posé, et la clé USB, ne sont jamais touchés.
//! Le dossier de données n'est jamais coché d'office et demande un second accord : il garde le carnet des appareils,
//! l'historique, l'apprentissage, la quarantaine (des fichiers peut-être à remettre) et de quoi défaire les
//! changements faits sur le système, que la désinstallation propose de défaire d'abord par leurs propres outils.
//! Sans droits d'administrateur.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::passage::{self, Reste};
use crate::reseau::surveillance::{self, Planifie};
use crate::sauvegarde::MiseEnPlace;
use crate::selection::{Case, Ligne, choisir, cocher};
use crate::ui::*;

/// Où chercher : les chemins de cet ordinateur, ou ceux d'un dossier jetable (tests).
pub(crate) struct Lieux {
    /// Le dossier de données de Vanguard (`crate::socle::dossier_local`).
    pub donnees: PathBuf,
    /// Les dossiers des unités systemd de l'utilisateur (Linux ; vide ailleurs) : celui de la surveillance et de
    /// l'entretien, puis celui de la sauvegarde s'il diffère (XDG_CONFIG_HOME).
    pub unites: Vec<PathBuf>,
    /// L'unité du veilleur (Linux ; `None` ailleurs), posée seulement par « vanguard veilleur on ».
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub veilleur: Option<PathBuf>,
    /// Le dossier des agents launchd (macOS).
    pub agents: Option<PathBuf>,
    /// Les tâches du Planificateur aux noms de Vanguard (Windows) ; `None` : le planificateur n'a pas pu être lu.
    pub taches: Option<Vec<TacheLue>>,
    /// Où va le raccourci sur ce système (`raccourci::chemin`).
    pub raccourci: Option<PathBuf>,
    /// Le programme en marche.
    pub programme: Option<PathBuf>,
    /// La clé VANGUARD branchée : jamais touchée.
    pub cle: Option<PathBuf>,
    /// Des sites dangereux bloqués par Vanguard dans le fichier hosts : les retirer demande l'administrateur.
    pub sites_bloques: bool,
}

/// Une tâche du Planificateur de Windows, lue.
pub(crate) struct TacheLue {
    pub nom: String,
    pub programme: String,
    pub active: bool,
}

impl Lieux {
    pub(crate) fn de_cet_ordinateur() -> Result<Lieux, String> {
        let donnees = crate::socle::dossier_local();
        // Sans HOME ni XDG_DATA_HOME (LOCALAPPDATA sous Windows), le dossier serait relatif : le dossier courant, qui
        // n'est pas celui de Vanguard. Rien n'est cherché, encore moins effacé.
        if !donnees.is_absolute() {
            return Err(tr!(
                "✖ Dossier de Vanguard inconnu (ni HOME ni XDG_DATA_HOME, ou LOCALAPPDATA) : rien n'est cherché.",
                "✖ Vanguard's folder is unknown (no HOME nor XDG_DATA_HOME, or LOCALAPPDATA): nothing is looked for."
            )
            .to_string());
        }
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut unites: Vec<PathBuf> = Vec::new();
        #[cfg(target_os = "linux")]
        {
            for d in [
                surveillance::dossier_unites_maison(),
                crate::sauvegarde::dossier_unites(),
            ] {
                if d.is_absolute() && !unites.contains(&d) {
                    unites.push(d);
                }
            }
        }
        #[cfg(target_os = "linux")]
        let veilleur = Some(crate::machine::linux::veilleur::fichier_unite()).filter(|p| p.is_absolute());
        #[cfg(not(target_os = "linux"))]
        let veilleur = None;
        #[cfg(target_os = "macos")]
        let agents = Some(crate::socle::maison().join("Library/LaunchAgents")).filter(|d| d.is_absolute());
        #[cfg(not(target_os = "macos"))]
        let agents = None;
        #[cfg(windows)]
        let taches = {
            let mut noms = vec![
                surveillance::TACHE_WINDOWS.to_string(),
                crate::entretien::TACHE_WINDOWS.to_string(),
            ];
            noms.extend(passage::taches_d_avant());
            let noms: Vec<&str> = noms.iter().map(String::as_str).collect();
            surveillance::definitions_windows(&noms).map(|lues| {
                lues.into_iter()
                    .map(|(nom, d)| TacheLue {
                        nom,
                        programme: d.programme,
                        active: d.active,
                    })
                    .collect()
            })
        };
        #[cfg(not(windows))]
        let taches = Some(Vec::new());
        #[cfg(unix)]
        let programme = crate::protection::cle::exe_d_origine();
        #[cfg(windows)]
        let programme = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok());
        Ok(Lieux {
            donnees,
            unites,
            veilleur,
            agents,
            taches,
            raccourci: crate::raccourci::chemin(),
            programme,
            cle: crate::reseau::cle_usb(),
            sites_bloques: crate::protection::sites_bloques::bloc_present(),
        })
    }

    /// Les lieux d'un ordinateur jetable, sous `racine` : la même disposition que sous Linux.
    #[cfg(test)]
    pub(crate) fn jetable(racine: &Path) -> Lieux {
        Lieux {
            donnees: racine.join("donnees/vanguard"),
            unites: vec![racine.join(".config/systemd/user"), racine.join("config/systemd/user")],
            veilleur: Some(racine.join(".config/systemd/user/vanguard-veilleur.service")),
            agents: Some(racine.join("Library/LaunchAgents")),
            taches: Some(Vec::new()),
            raccourci: Some(racine.join("donnees/applications/Vanguard.desktop")),
            programme: None,
            cle: Some(racine.join("cle")),
            sites_bloques: false,
        }
    }
}

/// Ce qu'est un élément trouvé ; l'ordre est celui de la liste et du retrait. Les données partent en dernier :
/// plusieurs retraits y écrivent avant (changements.jsonl, pieges.json, sauvegarde.json), et le veilleur, tant qu'il
/// tourne, y réécrit son état.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Genre {
    Surveillance,
    Entretien,
    Sauvegarde,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Veilleur,
    Avant,
    Pieges,
    Raccourci,
    Icone,
    Programme,
    DonneesAvant,
    Donnees,
}

/// Comment le retirer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Retrait {
    /// Avec ses fichiers trouvés (unités systemd dans chacun des dossiers, agent launchd) : tous sont retirés, pas
    /// seulement ceux du dossier où Vanguard les pose aujourd'hui.
    Surveillance(Vec<PathBuf>),
    Entretien(Vec<PathBuf>),
    /// La note de ce qui a été mis en place (`None` : unités trouvées par leur nom, sans note), et les unités trouvées.
    Sauvegarde(Option<MiseEnPlace>, Vec<PathBuf>),
    /// L'unité du veilleur, reconnue à sa marque : délégué au retrait de « vanguard veilleur off ».
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Veilleur(PathBuf),
    Pieges,
    /// Le raccourci (même absent) : `raccourci::retirer` retire aussi l'icône de Vanguard.
    Raccourci(PathBuf),
    /// Des copies du programme dans bin/.
    Fichiers(Vec<PathBuf>),
    /// Délégué à `passage` (ancien nom).
    Avant(Reste),
    Dossier(PathBuf),
}

/// Un élément de la liste : ce qu'on montre, ce qui est coché d'office, ce qui sera fait.
#[derive(Debug, Clone)]
pub(crate) struct Element {
    pub genre: Genre,
    pub texte: String,
    pub precision: String,
    pub detail: String,
    pub coche: bool,
    pub retrait: Retrait,
    /// Le programme que lance cette tâche ou ce raccourci : la copie de bin/ reste s'il est gardé.
    pub lance: Option<PathBuf>,
}

#[derive(Default)]
pub(crate) struct Recensement {
    pub elements: Vec<Element>,
    /// Ce qui reste à faire soi-même, avec la commande (Time Machine, programme en marche sous Windows…).
    pub a_faire: Vec<String>,
    /// Ce qui n'est pas à Vanguard ou pas à retirer d'ici (le programme sur la clé…) : gardé, dit.
    pub pas_a_lui: Vec<String>,
    /// Ce qui n'a pas pu être cherché : dit, jamais compté comme absent.
    pub non_verifie: Vec<String>,
}

/// Le même fichier ? Leurs formes canoniques d'abord (un lien, `\\?\` de Windows), à défaut les chemins tels quels.
fn meme(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Ce chemin est-il sur la clé ? Sa forme canonique, ou le chemin tel quel s'il n'existe plus.
fn sur_la_cle(p: &Path, cle: &Path) -> bool {
    let c = cle.canonicalize().unwrap_or_else(|_| cle.to_path_buf());
    p.canonicalize().is_ok_and(|q| q.starts_with(&c)) || p.starts_with(cle) || p.starts_with(&c)
}

/// La place prise par un dossier, sans suivre aucun lien.
fn taille(d: &Path) -> u64 {
    fn dans(d: &Path, profondeur: usize) -> u64 {
        if profondeur > 64 {
            return 0;
        }
        let Ok(entrees) = std::fs::read_dir(d) else {
            return 0;
        };
        entrees
            .flatten()
            .map(|e| match std::fs::symlink_metadata(e.path()) {
                Ok(m) if m.is_dir() => dans(&e.path(), profondeur + 1),
                Ok(m) if m.is_file() => m.len(),
                _ => 0,
            })
            .sum()
    }
    dans(d, 0)
}

/// Le programme d'un raccourci : la ligne Exec= d'un .desktop, la ligne exec d'un .command (citée pour sh) ; aucun
/// pour un .lnk, qui ne se lit pas comme du texte.
fn programme_du_raccourci(p: &Path) -> Option<PathBuf> {
    let texte = std::fs::read_to_string(p).ok()?;
    if let Some(v) = texte.lines().find_map(|l| l.strip_prefix("Exec=")) {
        return surveillance::premier_mot_cite(v);
    }
    let v = texte.lines().find_map(|l| l.strip_prefix("exec "))?;
    let mut mot = String::new();
    let mut car = v.trim_start().chars();
    while let Some(c) = car.next() {
        match c {
            '\'' => mot.extend(car.by_ref().take_while(|&c| c != '\'')),
            '\\' => mot.extend(car.next()),
            c if c.is_whitespace() => break,
            c => mot.push(c),
        }
    }
    (!mot.is_empty()).then(|| PathBuf::from(mot))
}

/// Le programme que lance un agent launchd.
#[cfg(any(target_os = "macos", test))]
fn programme_d_un_agent(p: &Path) -> Option<PathBuf> {
    surveillance::lire_plist(&std::fs::read(p).ok()?).map(|(programme, _)| programme)
}

#[cfg(not(any(target_os = "macos", test)))]
fn programme_d_un_agent(_: &Path) -> Option<PathBuf> {
    None
}

/// La surveillance ou l'entretien, s'ils sont planifiés quelque part dans les lieux : unités systemd, agent launchd,
/// tâche du Planificateur, chacun à son nom exact.
fn planifie(l: &Lieux, quoi: Planifie) -> Option<Element> {
    let (nom, agent, tache) = quoi.noms();
    let mut trouve: Vec<String> = Vec::new();
    let mut fichiers: Vec<PathBuf> = Vec::new();
    let mut lance: Option<PathBuf> = None;
    for d in &l.unites {
        let service = d.join(format!("{nom}.service"));
        let timer = d.join(format!("{nom}.timer"));
        if service.exists() || timer.exists() {
            trouve.push(chemin_affichable(if timer.exists() { &timer } else { &service }));
            fichiers.extend(
                [&timer, &service]
                    .into_iter()
                    .filter(|p| std::fs::symlink_metadata(p).is_ok())
                    .cloned(),
            );
            if lance.is_none() {
                lance = std::fs::read_to_string(&service)
                    .ok()
                    .and_then(|t| surveillance::programme_d_une_unite(&t));
            }
        }
    }
    if let Some(a) = &l.agents {
        let plist = a.join(format!("{agent}.plist"));
        if plist.is_file() {
            trouve.push(chemin_affichable(&plist));
            lance = lance.or_else(|| programme_d_un_agent(&plist));
            fichiers.push(plist);
        }
    }
    if let Some(t) = l.taches.iter().flatten().find(|t| t.nom.eq_ignore_ascii_case(tache)) {
        let etat = if t.active {
            ""
        } else {
            tr!(" (désactivée)", " (disabled)")
        };
        trouve.push(format!("« {} »{etat}", t.nom));
        lance = lance.or_else(|| Some(PathBuf::from(t.programme.trim().trim_matches('"'))));
    }
    if trouve.is_empty() {
        return None;
    }
    let lance_montre = lance
        .as_deref()
        .map_or_else(|| tr!("non lu", "not read").to_string(), chemin_affichable);
    let (genre, retrait, texte, precision, detail) = match quoi {
        Planifie::Surveillance => (
            Genre::Surveillance,
            Retrait::Surveillance(fichiers),
            tr!("Surveillance horaire", "Hourly monitoring"),
            tr!("désactivée puis retirée", "turned off, then removed"),
            trf!(
                "Arrêtée, puis retirée du planificateur : {}. Elle lance : {lance_montre}",
                "Stopped, then removed from the scheduler: {}. It starts: {lance_montre}",
                trouve.join(", ")
            ),
        ),
        Planifie::Entretien => (
            Genre::Entretien,
            Retrait::Entretien(fichiers),
            tr!("Entretien du mois", "Monthly check-up"),
            tr!("désactivé puis retiré", "turned off, then removed"),
            trf!(
                "Arrêté, puis retiré du planificateur : {}. Il lance : {lance_montre}",
                "Stopped, then removed from the scheduler: {}. It starts: {lance_montre}",
                trouve.join(", ")
            ),
        ),
    };
    Some(Element {
        genre,
        texte: texte.to_string(),
        precision: precision.to_string(),
        detail,
        coche: true,
        retrait,
        lance,
    })
}

/// La sauvegarde automatique : d'après sa note, ou ses unités trouvées par leur nom exact si la note manque.
fn sauvegarde(l: &Lieux, r: &mut Recensement) {
    use crate::sauvegarde::{SERVICE, TIMER};
    let unites: Vec<PathBuf> = l
        .unites
        .iter()
        .flat_map(|d| [d.join(TIMER), d.join(SERVICE)])
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect();
    let rsync = unites
        .iter()
        .filter(|p| p.ends_with(SERVICE))
        .find_map(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| surveillance::programme_d_une_unite(&t));
    let precision = tr!("retirée, vos copies restent", "removed, your copies stay").to_string();
    let montre: Vec<String> = unites.iter().map(|p| chemin_affichable(p)).collect();
    let rsync_texte = tr!("Sauvegarde automatique (rsync)", "Automatic backup (rsync)").to_string();
    // Une note qui ne peut pas être crue ne fait rien défaire (Time Machine, Déjà Dup) : c'est dit, avec quoi faire.
    if let Some(t) = crate::sauvegarde::note_douteuse_de(&l.donnees) {
        r.a_faire.push(t);
    }
    let element = match crate::sauvegarde::mise_en_place_de(&l.donnees) {
        Some(m @ MiseEnPlace::Systemd { .. }) => {
            let MiseEnPlace::Systemd { destination, .. } = &m else {
                return;
            };
            Element {
                genre: Genre::Sauvegarde,
                texte: rsync_texte,
                precision,
                detail: trf!(
                    "Minuterie arrêtée, ses unités retirées ({}) ; une unité modifiée depuis sa pose reste, et c'est dit. Les copies restent sur {destination}.",
                    "Timer stopped, its units removed ({}); a unit changed since it was placed stays, and this is said. The copies stay on {destination}.",
                    montre.join(", ")
                ),
                coche: true,
                lance: rsync,
                retrait: Retrait::Sauvegarde(Some(m), unites),
            }
        }
        Some(m @ MiseEnPlace::DejaDup { .. }) => {
            let MiseEnPlace::DejaDup { destination, .. } = &m else {
                return;
            };
            Element {
                genre: Genre::Sauvegarde,
                texte: tr!("Sauvegarde automatique (Déjà Dup)", "Automatic backup (Déjà Dup)").to_string(),
                precision,
                detail: trf!(
                    "Les réglages de Déjà Dup reprennent leur valeur d'avant (gsettings). Les copies restent sur {destination}.",
                    "Déjà Dup's settings get their earlier value back (gsettings). The copies stay on {destination}."
                ),
                coche: true,
                lance: None,
                retrait: Retrait::Sauvegarde(Some(m), Vec::new()),
            }
        }
        // Time Machine se défait avec sudo : jamais lancé d'ici, dit avec sa commande.
        Some(MiseEnPlace::TimeMachine { .. }) => {
            r.a_faire.push(tr!(
                "Time Machine : la destination ajoutée par Vanguard reste ; « vanguard sauvegarde-auto --annuler » la retire (mot de passe administrateur).",
                "Time Machine: the destination added by Vanguard stays; “vanguard auto-backup --undo” removes it (administrator password)."
            ).to_string());
            return;
        }
        None if !unites.is_empty() => Element {
            genre: Genre::Sauvegarde,
            texte: rsync_texte,
            precision,
            detail: trf!(
                "Sans note de sa mise en place : minuterie arrêtée, unités retirées par leur nom ({}).",
                "Without a note of its setup: timer stopped, units removed by their name ({}).",
                montre.join(", ")
            ),
            coche: true,
            lance: rsync,
            retrait: Retrait::Sauvegarde(None, unites),
        },
        None => return,
    };
    r.elements.push(element);
}

/// Le veilleur, si son unité est posée. Seule sa marque la dit de Vanguard : une unité du même nom sans elle est à
/// quelqu'un d'autre, gardée et pas même arrêtée ; une unité illisible n'est comptée ni comme la sienne ni comme
/// absente.
#[cfg(target_os = "linux")]
fn veilleur(p: &Path, r: &mut Recensement) {
    use crate::machine::linux::veilleur::{UNITE, notre_unite};
    if std::fs::symlink_metadata(p).is_err() {
        return;
    }
    match std::fs::read(p).map(|o| String::from_utf8_lossy(&o).into_owned()) {
        Ok(texte) if notre_unite(&texte) => {
            let lance = surveillance::programme_d_une_unite(&texte);
            let lance_montre = lance
                .as_deref()
                .map_or_else(|| tr!("non lu", "not read").to_string(), chemin_affichable);
            r.elements.push(Element {
                genre: Genre::Veilleur,
                texte: tr!("Veilleur (lancements, connexions)", "Watcher (launches, connections)").to_string(),
                precision: tr!("arrêté puis retiré", "stopped, then removed").to_string(),
                detail: trf!(
                    "Arrêté (systemctl --user disable --now {UNITE}), puis son unité retirée : {}. Il lance : {lance_montre}",
                    "Stopped (systemctl --user disable --now {UNITE}), then its unit removed: {}. It starts: {lance_montre}",
                    chemin_affichable(p)
                ),
                coche: true,
                lance,
                retrait: Retrait::Veilleur(p.to_path_buf()),
            });
        }
        Ok(_) => r.pas_a_lui.push(trf!(
            "Une unité {UNITE} ({}) n'a pas été posée par Vanguard : elle reste, et n'est pas arrêtée.",
            "A {UNITE} unit ({}) was not placed by Vanguard: it stays, and is not stopped.",
            chemin_affichable(p)
        )),
        Err(e) => r.non_verifie.push(trf!(
            "L'unité du veilleur ne se lit pas ({}, {e}) : rien ne dit qu'elle est de Vanguard, elle reste. « vanguard veilleur off » la retire si c'est la sienne.",
            "The watcher's unit cannot be read ({}, {e}): nothing says it is Vanguard's, it stays. “vanguard watcher off” removes it if it is its own.",
            chemin_affichable(p)
        )),
    }
}

/// Tout ce que Vanguard a posé dans les lieux `l`, sans rien changer : ne lit que des fichiers sous les chemins de
/// `l` et les tâches de `l.taches`. Dans l'ordre du retrait ; tout coché d'office, sauf les dossiers de données.
pub(crate) fn recenser(l: &Lieux) -> Recensement {
    let mut r = Recensement::default();
    if l.taches.is_none() {
        r.non_verifie.push(tr!(
            "Tâches planifiées non lues : la surveillance et l'entretien n'ont pas pu être cherchés (non vérifié). « vanguard surveillance off » et « vanguard entretien off » les retirent.",
            "Scheduled tasks not read: monitoring and the monthly check-up could not be looked for (not checked). “vanguard monitor off” and “vanguard maintenance off” remove them."
        ).to_string());
    }
    for quoi in [Planifie::Surveillance, Planifie::Entretien] {
        r.elements.extend(planifie(l, quoi));
    }
    // Le hosts est au système : jamais réécrit d'ici, sans droits ; dit avec sa commande, à lancer avant.
    if l.sites_bloques {
        r.a_faire.push(tr!(
            "Sites dangereux bloqués dans le fichier hosts : « vanguard sites-dangereux off » les retire (droits d'administrateur), avant de retirer Vanguard. Laissés, ils restent bloqués, sans autre effet.",
            "Dangerous sites blocked in the hosts file: “vanguard dangerous-sites off” removes them (administrator rights), before removing Vanguard. Left there, they stay blocked, with no other effect."
        ).to_string());
    }
    sauvegarde(l, &mut r);
    #[cfg(target_os = "linux")]
    if let Some(p) = &l.veilleur {
        veilleur(p, &mut r);
    }
    let (copies_d_avant, donnees_d_avant) = restes_d_avant(l, &mut r);
    pieges(l, &mut r);
    if let Some(p) = &l.raccourci {
        raccourci(l, p, &mut r);
    }
    copie_du_programme(l, copies_d_avant, &mut r);
    programme_en_marche(l, &mut r);
    dossiers_de_donnees(l, donnees_d_avant, &mut r);
    if let Some(cle) = l.cle.as_deref() {
        ecarter_la_cle(cle, &mut r);
    }
    r
}

/// Les restes d'une version d'avant. Rend à part la copie du programme d'avant (elle va avec bin/) et l'ancien
/// dossier de données (il va avec les données) ; les autres restes deviennent chacun un élément.
fn restes_d_avant(l: &Lieux, r: &mut Recensement) -> (Vec<PathBuf>, Option<PathBuf>) {
    let mut copies_d_avant = Vec::new();
    let mut donnees_d_avant = None;
    for (reste, montre) in passage::restes(l) {
        match reste {
            Reste::Programme(p) => copies_d_avant.push(p),
            Reste::Donnees(d) => donnees_d_avant = Some(d),
            reste => r.elements.push(Element {
                genre: Genre::Avant,
                texte: trf!("Version d'avant : {}", "Earlier version: {}", reste.quoi()),
                precision: tr!("reste d'une version d'avant", "left by an earlier version").to_string(),
                detail: trf!("Retire {}.", "Removes {}.", chemin_affichable(&montre)),
                coche: true,
                lance: None,
                retrait: Retrait::Avant(reste),
            }),
        }
    }
    (copies_d_avant, donnees_d_avant)
}

/// Les fichiers-pièges posés dans les dossiers de l'utilisateur : un élément s'il en reste au moins un.
fn pieges(l: &Lieux, r: &mut Recensement) {
    match crate::protection::pieges::nombre_dans(&l.donnees) {
        0 => {}
        n => r.elements.push(Element {
            genre: Genre::Pieges,
            texte: tr!(
                "Fichiers-pièges (Documents, Images, Bureau)",
                "Decoy files (Documents, Pictures, Desktop)"
            )
            .to_string(),
            precision: trf!("{n} retiré(s), sauf les modifiés", "{n} removed, except changed ones"),
            detail: tr!(
                "Les fichiers « !Vanguard » posés dans vos dossiers partent ; un fichier modifié ou renommé reste : c'est la preuve d'un passage.",
                "The “!Vanguard” files placed in your folders go; a changed or renamed one stays: it is the evidence of an attack."
            )
            .to_string(),
            coche: true,
            lance: None,
            retrait: Retrait::Pieges,
        }),
    }
}

/// Le raccourci `p` (Bureau ou menu des applications) : retiré s'il porte la marque de Vanguard, gardé et dit
/// sinon ; une icône de Vanguard restée sans son raccourci, reconnue à son empreinte, est retirée seule.
fn raccourci(l: &Lieux, p: &Path, r: &mut Recensement) {
    let present = std::fs::symlink_metadata(p).is_ok();
    let a_lui = present && crate::raccourci::de_vanguard(p);
    let icone = crate::raccourci::icone(p).filter(|i| {
        std::fs::symlink_metadata(i).is_ok_and(|m| m.is_file())
            && std::fs::read(i).is_ok_and(|o| crate::raccourci::icone_de_vanguard(&o))
    });
    let menu = p.extension().is_some_and(|e| e == "desktop");
    if a_lui {
        // Un .lnk ne se lit pas comme du texte : il vise la copie de bin/ que `raccourci::poser` lui donne
        // (`executable`). Au pire, cette copie est gardée sans nécessité, et c'est dit.
        let lance = programme_du_raccourci(p).or_else(|| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
                .then(|| l.donnees.join("bin").join(crate::mise_a_jour::NOM))
        });
        let avec = icone
            .as_deref()
            .map(|i| trf!(" et son icône {}", " and its icon {}", chemin_affichable(i)))
            .unwrap_or_default();
        r.elements.push(Element {
            genre: Genre::Raccourci,
            texte: if menu {
                tr!("Raccourci : menu des applications", "Shortcut: applications menu")
            } else {
                tr!("Raccourci sur le Bureau", "Shortcut on the Desktop")
            }
            .to_string(),
            precision: if icone.is_some() {
                tr!("retiré, avec son icône", "removed, with its icon")
            } else {
                tr!("retiré", "removed")
            }
            .to_string(),
            detail: trf!(
                "Efface {}{avec}. Il lance : {}",
                "Erases {}{avec}. It starts: {}",
                chemin_affichable(p),
                lance
                    .as_deref()
                    .map_or_else(|| tr!("non lu", "not read").to_string(), chemin_affichable)
            ),
            coche: true,
            lance,
            retrait: Retrait::Raccourci(p.to_path_buf()),
        });
    } else if present {
        // Le même nom, sans la marque : posé par quelqu'un d'autre, qui peut aussi se servir de l'icône.
        r.pas_a_lui.push(trf!(
            "Un raccourci au nom de Vanguard ({}) n'a pas été posé par Vanguard : il reste, avec son icône.",
            "A shortcut named Vanguard ({}) was not placed by Vanguard: it stays, with its icon.",
            chemin_affichable(p)
        ));
    } else if let Some(i) = &icone {
        r.elements.push(Element {
            genre: Genre::Icone,
            texte: tr!("Icône du menu des applications", "Applications menu icon").to_string(),
            precision: tr!("retirée (celle de Vanguard)", "removed (Vanguard's own)").to_string(),
            detail: trf!(
                "Efface {}, restée sans son raccourci : reconnue à son empreinte.",
                "Erases {}, left without its shortcut: recognised by its fingerprint.",
                chemin_affichable(i)
            ),
            coche: true,
            lance: None,
            retrait: Retrait::Raccourci(p.to_path_buf()),
        });
    }
}

/// La copie du programme : bin/vanguard, les restes d'une mise à jour, la copie d'avant (`copies_d_avant`) ; rien
/// d'autre de bin/. Sous Windows, la copie en marche est laissée et dite dans « à faire ».
fn copie_du_programme(l: &Lieux, copies_d_avant: Vec<PathBuf>, r: &mut Recensement) {
    let bin = l.donnees.join("bin");
    let nom = crate::mise_a_jour::NOM;
    let mut fichiers: Vec<PathBuf> = [nom.to_string(), format!("{nom}.ancien"), format!("{nom}.nouveau")]
        .iter()
        .map(|n| bin.join(n))
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect();
    fichiers.extend(copies_d_avant);
    // Windows n'efface pas un programme en marche : la copie qui tourne n'est pas essayée, et c'est dit.
    let en_marche = l.programme.as_deref();
    let tourne = |f: &Path| cfg!(windows) && en_marche.is_some_and(|p| meme(p, f));
    let garde = fichiers.iter().find(|f| tourne(f)).cloned();
    fichiers.retain(|f| !tourne(f));
    if let Some(g) = &garde {
        r.a_faire.push(trf!(
            "Ce programme est la copie de bin/ ({}) : Windows n'efface pas un programme en marche. Fermez Vanguard, puis supprimez le dossier {} ; ou lancez « vanguard desinstaller » depuis la clé, qui l'effacera.",
            "This program is the bin/ copy ({}): Windows does not erase a running program. Close Vanguard, then delete the folder {}; or run “vanguard uninstall” from the key, which will erase it.",
            chemin_affichable(g),
            chemin_affichable(&bin)
        ));
    }
    if fichiers.is_empty() {
        return;
    }
    let liste: Vec<String> = fichiers.iter().map(|f| chemin_affichable(f)).collect();
    // La copie en marche reste (dit dans « à faire ») : l'élément ne nomme que ce qui part vraiment.
    let (texte, precision) = if garde.is_some() {
        (
            tr!("Restes du programme (bin/)", "Program leftovers (bin/)"),
            tr!("effacés, sauf la copie en marche", "erased, except the running copy"),
        )
    } else {
        (
            tr!("Copie du programme (bin/)", "Program copy (bin/)"),
            tr!("effacée", "erased"),
        )
    };
    r.elements.push(Element {
        genre: Genre::Programme,
        texte: texte.to_string(),
        precision: precision.to_string(),
        detail: trf!(
            "Efface {} ; le dossier bin/ part s'il est vide ensuite, rien d'autre de bin/ n'est touché.",
            "Erases {}; the bin/ folder goes if it is empty afterwards, nothing else in bin/ is touched.",
            liste.join(", ")
        ),
        coche: true,
        lance: None,
        retrait: Retrait::Fichiers(fichiers),
    });
}

/// Le programme lancé, s'il n'est pas sous les données : celui de la clé ou un autre, jamais retiré, dit.
fn programme_en_marche(l: &Lieux, r: &mut Recensement) {
    let Some(p) = l.programme.as_deref() else {
        return;
    };
    let dans_les_donnees = p.starts_with(&l.donnees) || l.donnees.canonicalize().is_ok_and(|d| p.starts_with(d));
    if l.cle.as_deref().is_some_and(|c| sur_la_cle(p, c)) {
        r.pas_a_lui.push(trf!(
            "Le programme de la clé ({}) reste sur la clé : Vanguard n'efface jamais la clé.",
            "The key's program ({}) stays on the key: Vanguard never erases the key.",
            chemin_affichable(p)
        ));
    } else if !dans_les_donnees {
        r.pas_a_lui.push(trf!(
            "Le programme lancé ({}) n'a pas été posé par Vanguard : il reste. Supprimez-le vous-même si vous n'en voulez plus.",
            "The running program ({}) was not placed by Vanguard: it stays. Delete it yourself if you no longer want it.",
            chemin_affichable(p)
        ));
    }
}

/// Les dossiers de données, en dernier : l'ancien (`donnees_d_avant`, pas repris) puis l'actuel ; un dossier au
/// nom d'une version d'avant sans rien de Vanguard est gardé et dit.
fn dossiers_de_donnees(l: &Lieux, donnees_d_avant: Option<PathBuf>, r: &mut Recensement) {
    if let Some(d) = donnees_d_avant {
        r.elements.push(dossier_de_donnees(
            &d,
            Genre::DonneesAvant,
            &trf!(
                "L'ancien dossier de données ({}), qui n'a pas pu être repris : effacé seulement après une seconde question.",
                "The old data folder ({}), which could not be taken over: erased only after a second question.",
                chemin_affichable(&d)
            ),
            &mut r.pas_a_lui,
        ));
    }
    if let Some(d) = passage::dossier_d_un_autre(l) {
        r.pas_a_lui.push(trf!(
            "Un dossier porte le nom de celui d'une version d'avant ({}), mais rien de Vanguard n'y est : il reste.",
            "A folder has the name of an earlier version's one ({}), but nothing of Vanguard is in it: it stays.",
            chemin_affichable(&d)
        ));
    }
    if std::fs::symlink_metadata(&l.donnees).is_ok() {
        r.elements.push(dossier_de_donnees(
            &l.donnees,
            Genre::Donnees,
            &trf!(
                "Carnet des appareils, historique, apprentissage, quarantaine : {}. Effacé seulement après une seconde question.",
                "Device record, history, learning, quarantine: {}. Erased only after a second question.",
                chemin_affichable(&l.donnees)
            ),
            &mut r.pas_a_lui,
        ));
    }
}

/// La clé n'est jamais touchée, quoi qu'on ait trouvé : un élément dont un chemin mène à `cle` est écarté, et
/// c'est dit.
fn ecarter_la_cle(cle: &Path, r: &mut Recensement) {
    r.elements.retain(|e| {
        let sur = chemins(e).iter().any(|p| sur_la_cle(p, cle));
        if sur {
            r.pas_a_lui.push(trf!(
                "{} : sur la clé, jamais touché.",
                "{}: on the key, never touched.",
                e.texte
            ));
        }
        !sur
    });
}

/// La cible d'un dossier de données qui est un lien (déplacé sur un autre disque, un lien laissé à sa place) : seul
/// le lien part, jamais ce qu'il désigne.
fn lien_vers(d: &Path) -> Option<PathBuf> {
    std::fs::symlink_metadata(d)
        .is_ok_and(|m| m.is_symlink())
        .then(|| std::fs::read_link(d).unwrap_or_default())
}

/// L'élément d'un dossier de données, jamais coché d'office. Un lien est nommé comme tel, sans la taille de sa cible,
/// qui ne part pas : c'est dit dans `pas_a_lui`.
fn dossier_de_donnees(d: &Path, genre: Genre, detail: &str, pas_a_lui: &mut Vec<String>) -> Element {
    let avant = genre == Genre::DonneesAvant;
    let taille_ou_lien = match lien_vers(d) {
        Some(cible) => {
            pas_a_lui.push(trf!(
                "{} est un lien vers {} : coché, seul le lien part ; {} reste, avec tout ce qu'il contient (quarantaine comprise).",
                "{} is a link to {}: checked, only the link goes; {} stays, with everything in it (quarantine included).",
                chemin_affichable(d),
                chemin_affichable(&cible),
                chemin_affichable(&cible)
            ));
            tr!("lien", "link").to_string()
        }
        None => crate::socle::taille_lisible(taille(d)),
    };
    Element {
        genre,
        texte: if avant {
            trf!(
                "Ancien dossier de données ({taille_ou_lien})",
                "Old data folder ({taille_ou_lien})"
            )
        } else {
            trf!(
                "Dossier de données ({taille_ou_lien})",
                "Data folder ({taille_ou_lien})"
            )
        },
        precision: tr!("gardé, sauf si vous le cochez", "kept unless you check it").to_string(),
        detail: detail.to_string(),
        coche: false,
        lance: None,
        retrait: Retrait::Dossier(d.to_path_buf()),
    }
}

/// Les fichiers et dossiers qu'un élément touche.
fn chemins(e: &Element) -> Vec<PathBuf> {
    match &e.retrait {
        Retrait::Pieges => Vec::new(),
        Retrait::Surveillance(f) | Retrait::Entretien(f) | Retrait::Sauvegarde(_, f) | Retrait::Fichiers(f) => {
            f.clone()
        }
        Retrait::Raccourci(p) | Retrait::Dossier(p) | Retrait::Veilleur(p) => vec![p.clone()],
        Retrait::Avant(r) => r.chemins(),
    }
}

/// Les cases à cocher. Sans terminal, rien n'est coché au départ : `cocher` y valide sur une ligne vide les cases déjà
/// cochées, et une entrée redirigée vide accepterait tout. Les numéros sont alors à taper.
fn cases(e: &[Element], terminal: bool) -> Vec<Case> {
    e.iter()
        .map(|x| Case {
            texte: x.texte.clone(),
            precision: x.precision.clone(),
            detail: x.detail.clone(),
            cochee: terminal && x.coche,
            recommandee: x.coche,
            fixe: false,
        })
        .collect()
}

/// La copie du programme reste si un élément gardé la lance (une surveillance gardée lancerait un programme effacé) :
/// elle est décochée, et c'est dit.
fn garder_les_dependances(e: &[Element], etats: &mut [bool]) -> Vec<String> {
    let mut messages = Vec::new();
    for (i, garde_e) in e.iter().enumerate() {
        // Un état manquant compte comme coché : rien à garder pour lui.
        if etats.get(i).is_none_or(|&coche| coche) {
            continue;
        }
        let Some(lance) = &garde_e.lance else { continue };
        for (j, copie) in e.iter().enumerate() {
            if let Retrait::Fichiers(fichiers) = &copie.retrait
                && let Some(etat_copie) = etats.get_mut(j)
                && *etat_copie
                && fichiers.iter().any(|f| f == lance || meme(f, lance))
            {
                *etat_copie = false;
                messages.push(trf!(
                    "Copie du programme gardée : {}, que vous gardez, la lance.",
                    "Program copy kept: {}, which you keep, starts it.",
                    garde_e.texte
                ));
            }
        }
    }
    messages
}

/// Ce que des éléments gardés demandent encore dans le dossier `d`, qu'on efface : la copie du programme qu'ils
/// lancent (bin/ est dans le dossier de données), leurs propres fichiers, et, pour le dossier d'aujourd'hui
/// (`actuel`), leur note (le choix de la surveillance ou du veilleur, qui fait dire au bilan qu'il a disparu, et l'état
/// du veilleur ; la note de la sauvegarde et la liste des pièges, sans lesquelles ils ne se défont plus exactement).
/// Avec l'élément qui en a besoin.
fn gardes_dans(d: &Path, actuel: bool, e: &[Element], etats: &[bool]) -> Vec<(PathBuf, String)> {
    let mut gardes: Vec<(PathBuf, String)> = Vec::new();
    for (x, &coche) in e.iter().zip(etats) {
        if coche || matches!(x.genre, Genre::Donnees | Genre::DonneesAvant) {
            continue;
        }
        let mut besoins: Vec<PathBuf> = x.lance.iter().cloned().collect();
        besoins.extend(chemins(x));
        if actuel {
            // Une défense gardée garde aussi ce qui la juge : la note des défenses voulues, son programme posé et
            // leurs sceaux (oubliés des fichiers partis, `sceau::oublier_absents_dans`). Sans eux, le bilan la dirait
            // « non vérifiée », ou posée par une version d'avant.
            if matches!(x.genre, Genre::Surveillance | Genre::Entretien | Genre::Veilleur) {
                besoins.extend([
                    d.join(crate::voulues::FICHIER),
                    d.join(crate::programmes_poses::FICHIER),
                    d.join("sceaux.json"),
                ]);
            }
            match (&x.genre, &x.retrait) {
                (Genre::Surveillance, _) => besoins.push(d.join(surveillance::VOULUE)),
                (_, Retrait::Sauvegarde(Some(_), _)) => besoins.push(d.join(crate::sauvegarde::NOTES)),
                (Genre::Pieges, _) => besoins.push(d.join(crate::protection::pieges::LISTE)),
                // Le choix noté, sans quoi le bilan le dirait disparu, et l'état que le service réécrit.
                #[cfg(target_os = "linux")]
                (Genre::Veilleur, _) => {
                    use crate::machine::linux::veilleur::{ETAT, VOULU};
                    besoins.extend([d.join(VOULU), d.join(ETAT)]);
                }
                _ => {}
            }
        }
        for p in besoins {
            if std::fs::symlink_metadata(&p).is_ok()
                && surveillance::sous(&p, d)
                && !gardes.iter().any(|(q, _)| *q == p)
            {
                gardes.push((p, x.texte.clone()));
            }
        }
    }
    gardes
}

/// Efface le dossier `d` en entier, sans jamais suivre un lien ni une jonction (le lien lui-même part, pas ce qu'il
/// désigne). Sous Windows, la lecture seule est retirée d'abord (la quarantaine pose ses fichiers ainsi). `garder` :
/// le programme en marche (Windows ne l'efface pas), compté comme non effacé ; `aussi` : ce qu'un élément gardé
/// demande encore, gardé exprès (la personne l'a vu à la seconde question). Refusé pour un chemin relatif ou sur la
/// clé. Rend ce qui n'a pas pu partir, avec la raison.
pub(crate) fn effacer_dossier(
    d: &Path,
    garder: Option<&Path>,
    aussi: &[PathBuf],
    cle: Option<&Path>,
) -> Vec<(PathBuf, String)> {
    if !d.is_absolute() {
        return vec![(
            d.to_path_buf(),
            tr!("chemin relatif : refusé", "relative path: refused").to_string(),
        )];
    }
    if cle.is_some_and(|c| sur_la_cle(d, c)) {
        return vec![(
            d.to_path_buf(),
            tr!("sur la clé : jamais effacé", "on the key: never erased").to_string(),
        )];
    }
    let garder = garder.and_then(|g| g.canonicalize().ok());
    let aussi: Vec<PathBuf> = aussi.iter().filter_map(|a| a.canonicalize().ok()).collect();
    let mut restes = Vec::new();
    effacer(d, garder.as_deref(), &aussi, &mut restes, 0);
    restes
}

/// Efface `p` (un fichier, un lien ou un dossier) ; dit si quelque chose y est resté.
fn effacer(
    p: &Path,
    garder: Option<&Path>,
    aussi: &[PathBuf],
    restes: &mut Vec<(PathBuf, String)>,
    profondeur: usize,
) -> bool {
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            restes.push((p.to_path_buf(), e.to_string()));
            return false;
        }
    };
    if meta.is_symlink() {
        // Sous Windows, un lien vers un dossier (ou une jonction) se retire comme un dossier : sa cible reste.
        if std::fs::remove_file(p).is_ok() || std::fs::remove_dir(p).is_ok() {
            return true;
        }
        restes.push((p.to_path_buf(), tr!("lien non retiré", "link not removed").to_string()));
        return false;
    }
    if meta.is_dir() {
        if profondeur > 256 {
            restes.push((p.to_path_buf(), tr!("trop profond", "too deep").to_string()));
            return false;
        }
        let mut vide = true;
        match std::fs::read_dir(p) {
            Ok(entrees) => {
                for e in entrees.flatten() {
                    vide &= effacer(&e.path(), garder, aussi, restes, profondeur + 1);
                }
            }
            Err(e) => {
                restes.push((p.to_path_buf(), e.to_string()));
                return false;
            }
        }
        // Ce qui est resté dedans est déjà dit, ou gardé exprès : le dossier qui le contient ne s'ajoute pas à la liste.
        if !vide {
            return false;
        }
        return match std::fs::remove_dir(p) {
            Ok(()) => true,
            Err(e) => {
                restes.push((p.to_path_buf(), e.to_string()));
                false
            }
        };
    }
    if garder.is_some_and(|g| p.canonicalize().is_ok_and(|c| c == g)) {
        restes.push((
            p.to_path_buf(),
            tr!("programme en marche : gardé", "running program: kept").to_string(),
        ));
        return false;
    }
    if !aussi.is_empty() && p.canonicalize().is_ok_and(|c| aussi.contains(&c)) {
        return false;
    }
    #[cfg(windows)]
    {
        let mut droits = meta.permissions();
        if droits.readonly() {
            #[allow(clippy::permissions_set_readonly_false)] // il va être supprimé
            droits.set_readonly(false);
            let _ = std::fs::set_permissions(p, droits);
        }
    }
    match std::fs::remove_file(p) {
        Ok(()) => true,
        Err(e) => {
            restes.push((p.to_path_buf(), e.to_string()));
            false
        }
    }
}

/// Les changements faits sur le système que des outils de Vanguard savent défaire, et les corrections qui se défont à
/// la main.
struct Annulables {
    optimiser: usize,
    /// Les corrections du bilan qui se défont (leur valeur d'avant notée).
    bilan: usize,
    blocages: usize,
    jeux: usize,
    quarantaine: usize,
    a_la_main: Vec<(String, String)>,
}

impl Annulables {
    fn menu_vide(&self) -> bool {
        self.optimiser + self.bilan + self.blocages + self.jeux + self.quarantaine == 0
    }

    fn vide(&self) -> bool {
        self.menu_vide() && self.a_la_main.is_empty()
    }

    /// Ce qui se défait exactement grâce au dossier de données.
    fn a_defaire(&self) -> usize {
        self.optimiser + self.bilan + self.blocages + self.jeux
    }
}

fn annulables() -> Annulables {
    Annulables {
        optimiser: crate::optimiser::reglages_notes(),
        bilan: crate::optimiser::annulables::nombre(crate::optimiser::annulables::Origine::Bilan),
        blocages: crate::changements::blocages_en_place().len(),
        jeux: crate::gaming::reglages_notes(),
        quarantaine: crate::protection::quarantaine::nombre(),
        a_la_main: crate::changements::a_defaire_a_la_main(),
    }
}

/// Les changements faits sur le système : retirer Vanguard ne les défait pas. Leurs propres outils les défont d'abord,
/// si on veut ; ce qui reste est redit à la fin. `liste` : les montrer seulement.
fn defaire_d_abord(liste: bool) {
    let a = annulables();
    if a.vide() {
        return;
    }
    section(tr!("Changements faits sur le système", "Changes made to the system"));
    afficher_aligne(
        "  ",
        tr!(
            "Retirer Vanguard ne les défait pas : défaites d'abord ceux que vous ne voulez plus, avec leurs outils. Ce que vous gardez est redit à la fin.",
            "Removing Vanguard does not undo them: first undo those you no longer want, with their tools. What you keep is said again at the end."
        ),
        2,
        "",
    );
    if liste {
        for (texte, precision) in entrees_annulables(&a) {
            imprimer(&trf!("  • {texte} : {precision}", "  • {texte}: {precision}"));
        }
    } else if !a.menu_vide() {
        loop {
            let a = annulables();
            if a.menu_vide() {
                break;
            }
            let mut lignes = vec![Ligne::Texte(String::new())];
            for (i, (texte, precision)) in entrees_annulables(&a).into_iter().enumerate() {
                lignes.push(Ligne::choix(&(i + 1).to_string(), &texte, &precision));
            }
            lignes.push(Ligne::Texte(String::new()));
            lignes.push(Ligne::choix("↵", tr!("Continuer", "Continue"), ""));
            let Some(choix) = choisir(
                &lignes,
                tr!(
                    "\n  Numéro (Entrée pour continuer) : ",
                    "\n  Number (Enter to continue): "
                ),
                "↵",
                tr!("continuer", "continue"),
            ) else {
                // Échap ou ← continuent ici : la suite s'affiche, la pause du menu doit rester pour la lire.
                crate::ui::noter_retour(false);
                break;
            };
            let outils = outils_annulables(&a);
            let Some(outil) = choix
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|n| outils.get(n.checked_sub(1)?))
            else {
                break;
            };
            outil();
        }
    }
    let a = annulables();
    if !a.a_la_main.is_empty() {
        println!();
        afficher_aligne(
            "  ",
            &trf!(
                "« vanguard changements » montre les {} correction(s) faites ici : celles qui ne viennent ni d'Optimiser ni d'un blocage ne se défont pas toutes seules, chacune avec la commande inverse. Les dernières :",
                "“vanguard changes” shows the {} fix(es) made here: those that come neither from Optimize nor from a block do not undo themselves, each with the opposite command. The latest:",
                a.a_la_main.len()
            ),
            2,
            "",
        );
        for (date, commande) in a.a_la_main.iter().rev().take(5) {
            afficher_aligne(
                &format!("    {GRIS}{date}{RESET}  "),
                &commande_affichable(commande),
                22,
                GRIS,
            );
        }
    }
}

/// Les lignes du petit menu : (texte, précision), seulement celles qui ont de quoi défaire.
fn entrees_annulables(a: &Annulables) -> Vec<(String, String)> {
    let mut e = Vec::new();
    if a.optimiser > 0 {
        e.push((
            tr!("Réglages d'Optimiser", "Optimize settings").to_string(),
            trf!("{} réglage(s), annulables", "{} setting(s), undoable", a.optimiser),
        ));
    }
    if a.bilan > 0 {
        e.push((
            tr!("Corrections du bilan", "Check-up fixes").to_string(),
            trf!("{}, annulables une à une", "{}, undoable one by one", a.bilan),
        ));
    }
    if a.blocages > 0 {
        e.push((
            tr!("Blocages en place", "Blocks in place").to_string(),
            trf!("{}, annulables un à un", "{}, undoable one by one", a.blocages),
        ));
    }
    if a.jeux > 0 {
        e.push((
            tr!("Réglages pour jouer", "Gaming settings").to_string(),
            trf!("{} réglage(s), annulables", "{} setting(s), undoable", a.jeux),
        ));
    }
    if a.quarantaine > 0 {
        e.push((
            tr!("Quarantaine", "Quarantine").to_string(),
            trf!("{} fichier(s) à remettre ?", "{} file(s) to put back?", a.quarantaine),
        ));
    }
    e
}

/// Les outils qui défont, dans l'ordre de `entrees_annulables`.
fn outils_annulables(a: &Annulables) -> Vec<fn()> {
    let mut o: Vec<fn()> = Vec::new();
    if a.optimiser > 0 {
        o.push(crate::optimiser::tout_annuler);
    }
    if a.bilan > 0 {
        // « Ce que Vanguard a changé » : la liste, puis chaque correction à annuler.
        o.push(crate::changements::afficher);
    }
    if a.blocages > 0 {
        o.push(crate::protection::blocage::annuler);
    }
    if a.jeux > 0 {
        // Son choix 3 : « Remettre les réglages comme avant ».
        o.push(crate::gaming::menu);
    }
    if a.quarantaine > 0 {
        o.push(crate::protection::quarantaine::menu);
    }
    o
}

/// Ce qui a été fait, gardé, ce qui a échoué et ce qui reste à faire soi-même.
#[derive(Default)]
struct Bilan {
    retire: Vec<String>,
    garde: Vec<String>,
    echoue: Vec<(String, String)>,
    a_faire: Vec<String>,
    /// Ce qui n'a pas pu être cherché (le planificateur muet, la liste des pièges illisible) : peut-être encore là.
    non_verifie: Vec<String>,
}

/// Le texte du bilan. Un échec n'est jamais compté comme retiré, ni la fin dite « faite » s'il y en a un ; ce qui n'a
/// pas pu être cherché non plus : il peut encore tourner, ou rester dans les dossiers.
fn rediger_bilan(b: &Bilan) -> Vec<String> {
    let mut l = Vec::new();
    let mut partie = |titre: &str, lignes: Vec<String>| {
        if !lignes.is_empty() {
            l.push(String::new());
            l.push(ligne_section(titre));
            l.extend(lignes);
        }
    };
    partie(
        tr!("Retiré", "Removed"),
        b.retire.iter().map(|x| format!("  {VERT}✔{RESET} {x}")).collect(),
    );
    partie(
        tr!("Gardé", "Kept"),
        b.garde.iter().map(|x| format!("  • {x}")).collect(),
    );
    partie(
        tr!("Échoué", "Failed"),
        b.echoue
            .iter()
            .map(|(x, raison)| format!("  ✖ {x} : {raison}"))
            .collect(),
    );
    partie(
        tr!("Reste à faire vous-même", "Left for you to do"),
        b.a_faire.iter().map(|x| format!("  → {x}")).collect(),
    );
    partie(
        tr!("Non vérifié", "Not checked"),
        b.non_verifie.iter().map(|x| format!("  ? {x}")).collect(),
    );
    l.push(String::new());
    if b.echoue.is_empty() && b.non_verifie.is_empty() {
        l.push(trf!(
            "  {VERT}✔{RESET} Fait : rien d'autre de Vanguard ne reste ici, sauf ce qui est gardé ou à faire ci-dessus.",
            "  {VERT}✔{RESET} Done: nothing else of Vanguard stays here, except what is kept or left to do above."
        ));
    }
    if !b.echoue.is_empty() {
        l.push(trf!(
            "  ✖ {} élément(s) non retiré(s) : ils sont dits ci-dessus, avec quoi faire.",
            "  ✖ {} item(s) not removed: they are listed above, with what to do.",
            b.echoue.len()
        ));
    }
    if !b.non_verifie.is_empty() {
        l.push(trf!(
            "  ✖ {} point(s) non vérifié(s) : dit(s) ci-dessus ; ce qu'ils couvrent peut encore être là.",
            "  ✖ {} point(s) not checked: listed above; what they cover may still be there.",
            b.non_verifie.len()
        ));
    }
    l
}

/// Ce qu'il faut pour retirer : où sont le programme en marche et la clé, et ce qui s'accumule en route (un fichier
/// du dossier de données à garder pour un élément laissé en place, ce qui reste à faire soi-même).
struct Execution<'a> {
    donnees: &'a Path,
    en_marche: Option<&'a Path>,
    cle: Option<&'a Path>,
    gardes: Vec<(PathBuf, String)>,
    a_faire: Vec<String>,
    /// Posé quand le retrait du veilleur a échoué : les gardes, calculés avant, le supposaient retiré.
    veilleur_reste: Option<VeilleurReste>,
}

/// Un veilleur qui n'a pas pu être retiré (encore en marche, encore activé, unité restée) : à chaque battement il
/// réécrit son état, ce qui recrée le dossier de données, et il relancerait sa copie du programme en redémarrant.
/// Les deux restent donc.
struct VeilleurReste {
    /// Le programme qu'il lance ; `None` s'il n'a pas été lu, et alors toute copie du programme reste.
    lance: Option<PathBuf>,
}

/// Le résultat du retrait du veilleur, au bilan ; un échec est noté dans `x` pour les éléments qui suivent. Rien de
/// vu en marche (non vérifié) laisse continuer : rien ne montre qu'il recréerait quoi que ce soit.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn issue_du_veilleur(e: &Element, issue: Result<(), Echec>, x: &mut Execution) -> Result<String, Echec> {
    if let Err(Echec::Echoue(_)) = &issue {
        x.veilleur_reste = Some(VeilleurReste { lance: e.lance.clone() });
    }
    issue.map(|()| e.texte.clone())
}

/// Pourquoi un élément n'est pas compté comme retiré.
#[derive(Debug)]
enum Echec {
    /// Il reste, ou une étape a échoué.
    Echoue(String),
    /// Rien ne montre qu'il reste, mais le retrait n'a pas pu être constaté : jamais compté comme fait.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NonVerifie(String),
}

/// Retire un élément, sans rien demander (montré et accepté avant) ; rend ce qui est fait, ou pourquoi ce ne l'est pas.
fn retirer(e: &Element, x: &mut Execution) -> Result<String, Echec> {
    match &e.retrait {
        Retrait::Surveillance(trouves) => surveillance::retirer(trouves)
            .map(|()| e.texte.clone())
            .map_err(Echec::Echoue),
        Retrait::Entretien(trouves) => crate::entretien::retirer(trouves)
            .map(|()| e.texte.clone())
            .map_err(Echec::Echoue),
        Retrait::Sauvegarde(Some(m), _) => retirer_sauvegarde_notee(e, m, x),
        Retrait::Sauvegarde(None, fichiers) => crate::sauvegarde::retirer_sans_note(fichiers)
            .map(|()| e.texte.clone())
            .map_err(Echec::Echoue),
        // Le même retrait que « vanguard veilleur off » ; une unité devenue étrangère depuis la liste n'est pas
        // touchée.
        #[cfg(target_os = "linux")]
        Retrait::Veilleur(p) => {
            use crate::machine::linux::veilleur::{Retire, retirer_sans_question};
            let issue = match retirer_sans_question(p, false) {
                Retire::Fait => Ok(()),
                Retire::Echoue(raison) => Err(Echec::Echoue(raison)),
                Retire::NonVerifie(raison) => Err(Echec::NonVerifie(raison)),
            };
            issue_du_veilleur(e, issue, x)
        }
        #[cfg(not(target_os = "linux"))]
        Retrait::Veilleur(_) => Err(Echec::Echoue(
            tr!("le veilleur est de Linux seulement", "the watcher is Linux only").to_string(),
        )),
        Retrait::Pieges => retirer_pieges(e),
        Retrait::Raccourci(p) => retirer_raccourci(e, p),
        Retrait::Fichiers(fichiers) => retirer_fichiers(e, fichiers, x),
        // Un veilleur resté en marche réécrit son état à chaque battement : le dossier reviendrait aussitôt effacé,
        // et le bilan le dirait retiré. Rien n'y est touché.
        Retrait::Dossier(_) if e.genre == Genre::Donnees && x.veilleur_reste.is_some() => Err(Echec::Echoue(
            tr!(
                "gardé : le veilleur n'a pas pu être arrêté et le recréerait ; « vanguard veilleur off » puis réessayez",
                "kept: the watcher could not be stopped and would create it again; “vanguard watcher off” then try again"
            )
            .to_string(),
        )),
        Retrait::Avant(r) => passage::retirer_reste(r)
            .map(|()| e.texte.clone())
            .map_err(Echec::Echoue),
        Retrait::Dossier(d) => retirer_dossier(e, d, x),
    }
}

/// La sauvegarde automatique, défaite comme « vanguard sauvegarde-auto --annuler » : une unité modifiée depuis sa
/// pose reste, dite à faire soi-même, et sa note est gardée.
fn retirer_sauvegarde_notee(e: &Element, m: &MiseEnPlace, x: &mut Execution) -> Result<String, Echec> {
    let (ok, laissees) = crate::sauvegarde::annuler_sans_question(m);
    if !ok {
        return Err(Echec::Echoue(
            tr!(
                "une étape a échoué, sa note est gardée : « vanguard sauvegarde-auto --annuler » pour réessayer",
                "a step failed, its note is kept: “vanguard auto-backup --undo” to try again"
            )
            .to_string(),
        ));
    }
    // Une unité modifiée depuis sa pose reste, et sa note avec elle, même si le dossier de données part.
    for u in &laissees {
        x.a_faire.push(trf!(
            "{} : modifié depuis sa pose, laissé en place ; supprimez-le vous-même si vous n'en voulez plus. Sa note est gardée : « vanguard sauvegarde-auto --annuler » le retrouve.",
            "{}: changed since it was placed, left in place; delete it yourself if you no longer want it. Its note is kept: “vanguard auto-backup --undo” finds it.",
            chemin_affichable(u)
        ));
    }
    if !laissees.is_empty() {
        x.gardes
            .push((x.donnees.join(crate::sauvegarde::NOTES), e.texte.clone()));
    }
    Ok(trf!(
        "{} (vos copies restent sur le disque)",
        "{} (your copies stay on the disk)",
        e.texte
    ))
}

/// Les pièges : ce qui ne part pas est un échec ; ce qui reste exprès (pas reconnu, preuve d'un passage) est dit.
fn retirer_pieges(e: &Element) -> Result<String, Echec> {
    let (restes, gardes, douteuse) = crate::protection::pieges::retirer_sans_question();
    match (restes.as_slice(), gardes, douteuse) {
        ([premier, ..], _, _) => Err(Echec::Echoue(trf!(
            "{} non retiré(s), dont {}",
            "{} not removed, including {}",
            restes.len(),
            chemin_affichable(premier)
        ))),
        // Liste qui ne pouvait pas être crue : des « !Vanguard » pas reconnus, laissés, pas des preuves.
        (_, gardes, true) if !gardes.is_empty() => Ok(trf!(
            "{} ; pas reconnus, laissés (regardez-les vous-même) : {}",
            "{}; not recognized, left in place (look at them yourself): {}",
            e.texte,
            gardes
                .iter()
                .map(|p| chemin_affichable(p))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        (_, preuves, _) if !preuves.is_empty() => Ok(trf!(
            "{} ; gardés, preuve d'un passage : {}",
            "{}; kept, evidence of an attack: {}",
            e.texte,
            preuves
                .iter()
                .map(|p| chemin_affichable(p))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        _ => Ok(e.texte.clone()),
    }
}

/// Le raccourci et son icône ; une icône qui n'est pas celle de Vanguard reste, et c'est dit.
fn retirer_raccourci(e: &Element, p: &Path) -> Result<String, Echec> {
    let faits = crate::raccourci::retirer(p);
    let echecs: Vec<String> = faits
        .iter()
        .filter_map(|(f, x)| match x {
            crate::raccourci::Fait::Echec(raison) => Some(format!("{} ({raison})", chemin_affichable(f))),
            _ => None,
        })
        .collect();
    if !echecs.is_empty() {
        return Err(Echec::Echoue(echecs.join(", ")));
    }
    Ok(match faits.iter().find(|(_, x)| *x == crate::raccourci::Fait::Garde) {
        Some((i, _)) => trf!(
            "{} ; icône gardée ({}) : ce n'est pas celle de Vanguard",
            "{}; icon kept ({}): it is not Vanguard's",
            e.texte,
            chemin_affichable(i)
        ),
        None => e.texte.clone(),
    })
}

/// Des fichiers posés par Vanguard (la copie du programme), puis bin/ s'il est vide.
fn retirer_fichiers(e: &Element, fichiers: &[PathBuf], x: &Execution) -> Result<String, Echec> {
    // La copie que lance un veilleur resté en marche reste : redémarré, il lancerait un programme effacé.
    let (lancees, fichiers): (Vec<&PathBuf>, Vec<&PathBuf>) = fichiers.iter().partition(|f| match &x.veilleur_reste {
        None => false,
        Some(VeilleurReste { lance: Some(l) }) => *f == l || meme(f, l),
        Some(VeilleurReste { lance: None }) => e.genre == Genre::Programme,
    });
    let mut echecs = Vec::new();
    for f in &fichiers {
        if let Err(x) = std::fs::remove_file(f)
            && x.kind() != std::io::ErrorKind::NotFound
        {
            // Sous Windows, un programme en marche (une passe de la surveillance) ne s'efface pas.
            let raison = if cfg!(windows) {
                trf!(
                    "{x} ; la surveillance tourne peut-être encore, réessayez dans une minute",
                    "{x}; monitoring may still be running, try again in a minute"
                )
            } else {
                x.to_string()
            };
            echecs.push(format!("{} ({raison})", chemin_affichable(f)));
        }
    }
    // bin/ part s'il est vide ; ce que Vanguard n'y a pas mis le garde.
    if let Some(bin) = fichiers.first().and_then(|f| f.parent()) {
        let _ = std::fs::remove_dir(bin);
    }
    if let Some(l) = lancees.first() {
        echecs.push(trf!(
            "copie gardée ({}) : le veilleur n'a pas pu être arrêté et la lance ; « vanguard veilleur off » puis réessayez",
            "copy kept ({}): the watcher could not be stopped and starts it; “vanguard watcher off” then try again",
            chemin_affichable(l)
        ));
    }
    if echecs.is_empty() {
        Ok(e.texte.clone())
    } else {
        Err(Echec::Echoue(echecs.join(", ")))
    }
}

/// Un dossier de données, sauf ce que des éléments gardés y demandent encore.
fn retirer_dossier(e: &Element, d: &Path, x: &Execution) -> Result<String, Echec> {
    let lien = lien_vers(d);
    let gardes: Vec<&(PathBuf, String)> = x.gardes.iter().filter(|(p, _)| surveillance::sous(p, d)).collect();
    let fichiers: Vec<PathBuf> = gardes.iter().map(|(p, _)| p.clone()).collect();
    let restes = effacer_dossier(d, x.en_marche, &fichiers, x.cle);
    // Les sceaux gardés oublient ce qui est parti avec le dossier : effacé par la désinstallation, pas hors de
    // Vanguard.
    if !gardes.is_empty() {
        let _ = crate::sceau::oublier_absents_dans(d);
    }
    if let Some((p, raison)) = restes.first() {
        return Err(Echec::Echoue(trf!(
            "{} élément(s) non effacé(s), dont {} ({raison})",
            "{} item(s) not erased, including {} ({raison})",
            restes.len(),
            chemin_affichable(p)
        )));
    }
    if !gardes.is_empty() {
        let liste: Vec<String> = gardes
            .iter()
            .map(|(p, pour)| format!("{} ({pour})", chemin_affichable(p)))
            .collect();
        return Ok(trf!(
            "{} ; gardé, pour ce que vous gardez : {}",
            "{}; kept, for what you keep: {}",
            e.texte,
            liste.join(", ")
        ));
    }
    // Une passe déjà lancée a pu écrire de nouveau pendant l'effacement : un dossier revenu n'est pas retiré.
    if std::fs::symlink_metadata(d).is_ok() {
        return Err(Echec::Echoue(
            tr!(
                "revenu pendant l'effacement : une passe de Vanguard encore en cours y a écrit ; réessayez dans une minute",
                "back during the erasing: a Vanguard run still in progress wrote into it; try again in a minute"
            )
            .to_string(),
        ));
    }
    Ok(match lien {
        Some(cible) => trf!(
            "{} (le lien seul : {} reste)",
            "{} (the link only: {} stays)",
            e.texte,
            chemin_affichable(&cible)
        ),
        None => e.texte.clone(),
    })
}

/// Le second accord pour un dossier de données coché : ce qu'il garde (extensions, traces, quarantaine, de quoi
/// défaire les changements, le relevé des corrections), ce qui y reste pour un élément gardé (`gardes`), une
/// sauvegarde du carnet, puis la question. Le même chemin pour le dossier d'une version d'avant, qui peut lui aussi
/// garder une quarantaine. Rend la réponse.
fn accord_donnees(e: &Element, a: &Annulables, gardes: &[(PathBuf, String)]) -> bool {
    let Retrait::Dossier(d) = &e.retrait else {
        return false;
    };
    let avant = e.genre == Genre::DonneesAvant;
    let montre = chemin_affichable(d);
    println!();
    // Un lien : rien de ce qu'il désigne ne part, il n'y a rien d'autre à dire.
    if let Some(cible) = lien_vers(d) {
        afficher_aligne(
            "  ",
            &trf!(
                "{montre} est un lien vers {} : seul le lien part ; ce qu'il désigne reste, quarantaine comprise.",
                "{montre} is a link to {}: only the link goes; what it points to stays, quarantine included.",
                chemin_affichable(&cible)
            ),
            2,
            "",
        );
        return demander(tr!("  Retirer ce lien ? [o/N] : ", "  Remove this link? [y/N]: ")).oui();
    }
    let place = crate::socle::taille_lisible(taille(d));
    let dire = |texte: &str| afficher_aligne("  ", texte, 2, "");
    if avant {
        dire(&trf!(
            "Les données d'une version d'avant ({montre}, {place}) gardent son carnet des appareils et son historique.",
            "The data of an earlier version ({montre}, {place}) keeps its device record and its history."
        ));
    } else {
        dire(&trf!(
            "Le dossier de données ({montre}, {place}) garde le carnet des appareils, l'historique des bilans et ce que Vanguard a appris.",
            "The data folder ({montre}, {place}) keeps the device record, the check-up history and what Vanguard has learned."
        ));
    }
    let compter = |filtre: &dyn Fn(&std::fs::DirEntry) -> bool, dossier: &Path| {
        std::fs::read_dir(dossier).map_or(0, |l| l.flatten().filter(|x| filtre(x)).count())
    };
    let extensions = compter(&|x| x.path().is_dir(), &d.join("plugins"));
    let traces = compter(&|x| x.file_name().to_string_lossy().starts_with("traces-"), d);
    if extensions + traces > 0 {
        dire(&trf!(
            "Vos extensions ({extensions}) et les traces collectées ({traces}) y sont aussi.",
            "Your extensions ({extensions}) and the collected traces ({traces}) are there too."
        ));
    }
    let quarantaine = crate::protection::quarantaine::nombre_dans(&d.join("quarantaine"));
    if quarantaine > 0 && avant {
        // Le menu de la quarantaine ne remet que celle d'aujourd'hui : ces fichiers-là ne pourraient plus revenir.
        dire(&trf!(
            "Il garde {quarantaine} fichier(s) en quarantaine, qui ne se remettent pas d'ici : le dossier est gardé. Une détection peut se tromper : remettez d'abord ceux qui sont à vous (dans {}), puis effacez ce dossier vous-même.",
            "It holds {quarantaine} quarantined file(s), which cannot be put back from here: the folder is kept. A detection can be wrong: first put back those that are yours (in {}), then erase this folder yourself.",
            chemin_affichable(&d.join("quarantaine"))
        ));
        return false;
    }
    // Un brouillon de signalement peut être le seul écrit d'une faille pas encore soumise : dit avant. Après
    // le refus pour la quarantaine d'une version d'avant : là, le dossier est gardé et les brouillons avec lui.
    let brouillons = crate::signaler::nombre_dans(d);
    if brouillons > 0 {
        dire(&trf!(
            "{brouillons} brouillon(s) de signalement (signalements) seront effacés avec lui : copiez-les d'abord s'ils ne sont pas encore soumis.",
            "{brouillons} vulnerability report draft(s) (signalements) will be erased with it: copy them first if they are not submitted yet."
        ));
    }
    if quarantaine > 0 {
        dire(&trf!(
            "Il garde aussi {quarantaine} fichier(s) en quarantaine. Une détection peut se tromper : remettez d'abord ceux qui sont à vous, ou gardez le dossier.",
            "It also holds {quarantaine} quarantined file(s). A detection can be wrong: first put back those that are yours, or keep the folder."
        ));
        if demander(tr!(
            "  Ouvrir la quarantaine maintenant ? [o/N] : ",
            "  Open the quarantine now? [y/N]: "
        ))
        .oui()
        {
            crate::protection::quarantaine::menu();
        }
    }
    if !avant && a.a_defaire() > 0 {
        dire(&trf!(
            "Il garde aussi de quoi défaire {} changement(s) : effacé, Vanguard ne pourra plus les défaire.",
            "It also keeps what undoes {} change(s): erased, Vanguard can no longer undo them.",
            a.a_defaire()
        ));
    }
    let releve = d.join(crate::changements::RELEVE);
    if !avant && !a.a_la_main.is_empty() {
        dire(&trf!(
            "Il garde aussi le relevé des {} correction(s) faites ici ({}), le seul endroit où leurs commandes sont notées : effacé, il disparaît. Elles sont redites à la fin.",
            "It also keeps the record of the {} fix(es) made here ({}), the only place where their commands are written down: erased, it is gone. They are listed again at the end.",
            a.a_la_main.len(),
            crate::changements::RELEVE
        ));
        let dossier = crate::donnees::dossier_par_defaut();
        if demander(&trf!(
            "\n  Copier ce relevé dans {} ? [O/n] : ",
            "\n  Copy this record into {}? [Y/n]: ",
            chemin_affichable(&dossier)
        ))
        .chars()
        .next()
        .is_none_or(|c| matches!(c, 'o' | 'O' | 'y' | 'Y'))
        {
            match copier_releve(&releve, &dossier) {
                Ok(copie) => dire(&trf!(
                    "{VERT}✔{RESET} Relevé copié : {}",
                    "{VERT}✔{RESET} Record copied: {}",
                    chemin_affichable(&copie)
                )),
                Err(raison) => dire(&trf!("✖ Relevé non copié : {raison}", "✖ Record not copied: {raison}")),
            }
        }
    }
    if !gardes.is_empty() {
        dire(tr!(
            "Ce qui y reste, parce qu'un élément que vous gardez s'en sert :",
            "What stays in it, because an item you keep uses it:"
        ));
        for (p, pour) in gardes {
            afficher_aligne("    • ", &format!("{} ({pour})", chemin_affichable(p)), 6, "");
        }
    }
    if !avant
        && demander(tr!(
            "\n  Faire d'abord une sauvegarde du carnet des appareils (vanguard exporter) ? [O/n] : ",
            "\n  First back up the device record (vanguard export)? [Y/n]: "
        ))
        .chars()
        .next()
        .is_none_or(|c| matches!(c, 'o' | 'O' | 'y' | 'Y'))
    {
        crate::donnees::sauvegarder(None);
    }
    demander(if avant {
        tr!(
            "\n  Effacer aussi ce dossier pour de bon ? [o/N] : ",
            "\n  Erase this folder too, for good? [y/N]: "
        )
    } else {
        tr!(
            "\n  Effacer le dossier de données pour de bon ? [o/N] : ",
            "\n  Erase the data folder for good? [y/N]: "
        )
    })
    .oui()
}

/// Copie le relevé des corrections hors du dossier de données, sous un nom daté, sans jamais écraser un fichier déjà
/// là. Rend la copie.
fn copier_releve(releve: &Path, dossier: &Path) -> Result<PathBuf, String> {
    if !dossier.is_absolute() {
        return Err(tr!("dossier inconnu", "unknown folder").to_string());
    }
    // Un simple fichier, borné : un lien vers /dev/zero à sa place ne remplit pas le disque de la copie.
    let source = crate::socle::lire_ordinaire(releve, 64 << 20).map_err(|e| e.to_string())?;
    let date = chrono::Local::now().format("%Y-%m-%d");
    for n in 1..100 {
        let nom = if n == 1 {
            format!("vanguard-changements-{date}.jsonl")
        } else {
            format!("vanguard-changements-{date}-{n}.jsonl")
        };
        let copie = dossier.join(nom);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&copie) {
            Ok(mut f) => {
                use std::io::Write as _;
                return f.write_all(&source).map(|()| copie).map_err(|e| e.to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(tr!("trop de copies du même jour", "too many copies from the same day").to_string())
}

/// Ce qui reste des changements faits sur le système, pour la fin : avec la commande qui les défait, ou dit perdu si
/// le dossier de données (qui savait les défaire) est effacé.
fn changements_restants(a: &Annulables, donnees_effacees: bool) -> Vec<String> {
    let mut l = Vec::new();
    if donnees_effacees {
        if a.a_defaire() > 0 {
            l.push(trf!(
                "{} changement(s) faits par Vanguard restent sur le système, sans plus de quoi les défaire d'ici.",
                "{} change(s) made by Vanguard stay on the system, with nothing left here to undo them.",
                a.a_defaire()
            ));
        }
        // Leur relevé est parti avec les données : c'est la dernière fois qu'ils peuvent être lus.
        if !a.a_la_main.is_empty() {
            l.push(trf!(
                "{} correction(s) faites ici ne se défont pas toutes seules, et leur relevé est effacé. Les voici, chacune à défaire avec la commande inverse :",
                "{} fix(es) made here do not undo themselves, and their record is erased. Here they are, each to undo with the opposite command:",
                a.a_la_main.len()
            ));
            for (date, commande) in &a.a_la_main {
                l.push(format!("{date}  {}", commande_affichable(commande)));
            }
        }
        return l;
    }
    if a.optimiser > 0 {
        l.push(trf!(
            "{} réglage(s) d'Optimiser restent : menu Bloquer et réagir › Tout remettre comme avant.",
            "{} Optimize setting(s) stay: menu Block and respond › Put everything back.",
            a.optimiser
        ));
    }
    if a.blocages > 0 {
        l.push(trf!(
            "{} blocage(s) restent en place : « vanguard blocage annuler » les défait.",
            "{} block(s) stay in place: “vanguard blocking undo” undoes them.",
            a.blocages
        ));
    }
    if a.jeux > 0 {
        l.push(trf!(
            "{} réglage(s) pour jouer restent : menu Gaming › Remettre les réglages comme avant.",
            "{} gaming setting(s) stay: menu Gaming › Put the settings back as before.",
            a.jeux
        ));
    }
    if !a.a_la_main.is_empty() {
        l.push(trf!(
            "{} correction(s) notée(s) : « vanguard changements » les montre ; chacune se défait avec la commande inverse.",
            "{} fix(es) noted: “vanguard changes” shows them; each is undone with the opposite command.",
            a.a_la_main.len()
        ));
    }
    l
}

/// `vanguard desinstaller [--liste]` et le menu Données › Retirer Vanguard de cet ordinateur.
pub fn commande(liste: bool) {
    presenter(liste);
    let lieux = match Lieux::de_cet_ordinateur() {
        Ok(l) => l,
        Err(e) => {
            afficher_aligne("  ", &e, 4, "");
            return;
        }
    };
    let rec = recenser(&lieux);
    montrer_ce_qui_reste_hors_liste(&rec);
    if rec.elements.is_empty() {
        dire_qu_il_n_y_a_rien(&rec);
        return;
    }
    if liste {
        montrer_la_liste(&rec);
        return;
    }
    defaire_d_abord(false);
    // Défaire un changement a pu toucher au dossier de données (une note, la quarantaine) : la liste est refaite.
    let rec = recenser(&lieux);
    if rec.elements.is_empty() {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    let Some(mut etats) = cocher_ce_qui_part(&rec) else {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    };
    annoncer_le_retrait(&rec, &etats);
    let a = annulables();
    let gardes = confirmer_les_donnees(&rec, &mut etats, &a);
    if !etats.contains(&true) {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    if !demander(tr!(
        "\n  Retirer ce qui est coché ? [o/N] : ",
        "\n  Remove what is checked? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été retiré.", "  Nothing was removed.");
        return;
    }
    retirer_et_conclure(&lieux, &rec, &etats, gardes, &a);
}

/// Le titre, ce que fait la désinstallation, et le Wi-Fi public éteint d'abord s'il est allumé.
fn presenter(liste: bool) {
    titre(tr!(
        "Retirer Vanguard de cet ordinateur",
        "Remove Vanguard from this computer"
    ));
    afficher_aligne(
        "  ",
        tr!(
            "Vanguard cherche ce qu'il a posé sur cet ordinateur : il le retrouve, rien n'est noté d'avance. Rien n'est retiré sans votre accord ; la clé USB et ce que Vanguard n'a pas posé ne sont jamais touchés.",
            "Vanguard looks for what it placed on this computer: it finds it, nothing is recorded in advance. Nothing is removed without your consent; the USB key and what Vanguard did not place are never touched."
        ),
        2,
        "",
    );
    // Son état part avec le dossier de données : éteint d'abord, ses réglages reviennent comme avant.
    if !liste {
        crate::reseau::wifi_public::proposer_d_eteindre();
    }
}

/// Ce qui n'est pas à Vanguard, ce qui n'a pas pu être cherché, et la protection active qui part avec la surveillance.
fn montrer_ce_qui_reste_hors_liste(rec: &Recensement) {
    println!();
    for m in &rec.pas_a_lui {
        afficher_aligne("  • ", m, 4, "");
    }
    for m in &rec.non_verifie {
        afficher_aligne("  ? ", m, 4, "");
    }
    if crate::protection::blocage::protection_active() {
        afficher_aligne(
            "  • ",
            tr!(
                "La protection active tourne dans la surveillance horaire et s'arrête avec elle ; son réglage reste dans le dossier de données.",
                "Active protection runs inside the hourly monitoring and stops with it; its setting stays in the data folder."
            ),
            4,
            "",
        );
    }
}

/// Rien de Vanguard trouvé : le dire, sans compter comme absent ce qui n'a pas pu être cherché.
fn dire_qu_il_n_y_a_rien(rec: &Recensement) {
    let fin = if rec.non_verifie.is_empty() {
        tr!(
            "Vanguard n'a rien posé sur cet ordinateur, ou tout a déjà été retiré.",
            "Vanguard placed nothing on this computer, or everything was already removed."
        )
        .to_string()
    } else {
        trf!(
            "Rien de Vanguard n'a été trouvé, mais {} point(s) n'ont pas pu être cherchés (ci-dessus) : ce qu'ils couvrent peut encore être là.",
            "Nothing of Vanguard was found, but {} point(s) could not be looked for (above): what they cover may still be there.",
            rec.non_verifie.len()
        )
    };
    afficher_aligne("  ", &fin, 2, "");
    for x in &rec.a_faire {
        afficher_aligne("  → ", x, 4, "");
    }
}

/// « --liste » : ce que Vanguard a posé ici, ce qui serait coché d'office, sans rien retirer.
fn montrer_la_liste(rec: &Recensement) {
    section(tr!("Ce que Vanguard a posé ici", "What Vanguard placed here"));
    for (i, e) in rec.elements.iter().enumerate() {
        let coche = if e.coche {
            ""
        } else {
            tr!(" (pas coché d'office)", " (not checked by default)")
        };
        afficher_aligne(
            &format!("  {TOUCHE}{:>2}{RESET} ", i + 1),
            &format!("{}{coche}", e.texte),
            5,
            "",
        );
        afficher_aligne("     → ", &e.precision, 7, GRIS);
        afficher_aligne("       ", &e.detail, 7, GRIS);
    }
    defaire_d_abord(true);
    for x in &rec.a_faire {
        afficher_aligne("  → ", x, 4, "");
    }
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Rien n'a été retiré : « vanguard desinstaller » sans --liste propose de le faire.",
            "Nothing was removed: “vanguard uninstall” without --list offers to do it."
        ),
        2,
        "",
    );
}

/// La liste à cocher, puis ce que les éléments gardés retiennent ; `None` si rien ne doit partir.
fn cocher_ce_qui_part(rec: &Recensement) -> Option<Vec<bool>> {
    let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut entete = vec![
        String::new(),
        ligne_titre(tr!("Ce que Vanguard a posé ici", "What Vanguard placed here")),
    ];
    entete.extend(
        envelopper(
            tr!(
                "Cochez ce qui doit partir. Le dossier de données n'est pas coché : il garde vos données.",
                "Check what should go. The data folder is not checked: it keeps your data."
            ),
            LARGEUR - 2,
        )
        .into_iter()
        .map(|l| format!("  {GRIS}{l}{RESET}")),
    );
    entete.push(String::new());
    let mut etats = cocher(&entete, &cases(&rec.elements, terminal))?;
    for m in garder_les_dependances(&rec.elements, &mut etats) {
        afficher_aligne("  ", &m, 2, "");
    }
    etats.contains(&true).then_some(etats)
}

/// « Sera retiré : » et, pour chaque élément coché, ce qui lui arrivera.
fn annoncer_le_retrait(rec: &Recensement, etats: &[bool]) {
    println!();
    trp!("  Sera retiré :", "  Will be removed:");
    for (e, _) in rec.elements.iter().zip(etats).filter(|(_, c)| **c) {
        let action = if matches!(e.genre, Genre::Donnees | Genre::DonneesAvant) {
            tr!("effacé après une seconde question", "erased after a second question")
        } else {
            &e.precision
        };
        afficher_aligne("  • ", &format!("{} → {action}", e.texte), 4, "");
    }
}

/// La seconde question pour chaque dossier de données coché (décoché si elle est refusée) ; rend ce que des éléments
/// gardés y demandent encore, à garder à l'effacement.
fn confirmer_les_donnees(rec: &Recensement, etats: &mut [bool], a: &Annulables) -> Vec<(PathBuf, String)> {
    // Ce que des éléments gardés demandent encore dans les dossiers de données : vu à la seconde question, gardé à
    // l'effacement.
    let mut gardes: Vec<(PathBuf, String)> = Vec::new();
    for e in &rec.elements {
        if let (Genre::Donnees | Genre::DonneesAvant, Retrait::Dossier(d)) = (e.genre, &e.retrait) {
            gardes.extend(gardes_dans(d, e.genre == Genre::Donnees, &rec.elements, etats));
        }
    }
    // `etats` a une case par élément ; un élément sans case n'est pas coché, donc pas effacé.
    for (e, etat) in rec.elements.iter().zip(etats.iter_mut()) {
        if !*etat || !matches!(e.genre, Genre::Donnees | Genre::DonneesAvant) {
            continue;
        }
        let Retrait::Dossier(d) = &e.retrait else { continue };
        let les_siens: Vec<(PathBuf, String)> = gardes
            .iter()
            .filter(|(p, _)| surveillance::sous(p, d))
            .cloned()
            .collect();
        if !accord_donnees(e, a, &les_siens) {
            *etat = false;
            trp!("  Dossier de données gardé.", "  Data folder kept.");
        }
    }
    gardes
}

/// Retire ce qui est coché, montre le bilan, et ferme Vanguard si son dossier de données vient de partir.
fn retirer_et_conclure(
    lieux: &Lieux,
    rec: &Recensement,
    etats: &[bool],
    gardes: Vec<(PathBuf, String)>,
    a: &Annulables,
) {
    let mut x = Execution {
        donnees: &lieux.donnees,
        en_marche: if cfg!(windows) {
            lieux.programme.as_deref()
        } else {
            None
        },
        cle: lieux.cle.as_deref(),
        gardes,
        a_faire: Vec::new(),
        veilleur_reste: None,
    };
    let mut bilan = Bilan::default();
    let mut donnees_touchees = false;
    println!();
    for (e, &coche) in rec.elements.iter().zip(etats) {
        if !coche {
            bilan.garde.push(e.texte.clone());
            continue;
        }
        // Gardé à cause du veilleur, le dossier n'est pas touché : de quoi défaire les changements y reste.
        donnees_touchees |= e.genre == Genre::Donnees && x.veilleur_reste.is_none();
        match retirer(e, &mut x) {
            Ok(fait) => {
                afficher_aligne(&format!("  {VERT}✔{RESET} "), &e.texte, 4, "");
                bilan.retire.push(fait);
            }
            Err(Echec::Echoue(raison)) => {
                afficher_aligne("  ✖ ", &format!("{} : {raison}", e.texte), 4, "");
                bilan.echoue.push((e.texte.clone(), raison));
            }
            // Ni retiré ni échoué : la fin n'est pas dite « faite », le point est redit au bilan.
            Err(Echec::NonVerifie(raison)) => {
                let ligne = format!("{} : {raison}", e.texte);
                afficher_aligne("  ? ", &ligne, 4, "");
                bilan.non_verifie.push(ligne);
            }
        }
    }
    bilan.garde.extend(rec.pas_a_lui.iter().cloned());
    bilan.a_faire.extend(rec.a_faire.iter().cloned());
    bilan.a_faire.append(&mut x.a_faire);
    bilan.a_faire.extend(changements_restants(a, donnees_touchees));
    bilan.non_verifie.extend(rec.non_verifie.iter().cloned());
    for l in rediger_bilan(&bilan) {
        imprimer(&l);
    }
    if donnees_touchees {
        // Revenir au menu réécrirait des fichiers (état, journal) dans le dossier qu'on vient d'effacer.
        println!();
        trp!(
            "  Vanguard se ferme : rouvert, il recréerait son dossier de données.",
            "  Vanguard closes: reopened, it would create its data folder again."
        );
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn racine(nom: &str) -> PathBuf {
        let d = crate::socle::dossier_local().join(format!("desinstaller-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ecrire(p: &Path, texte: impl AsRef<[u8]>) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, texte).unwrap();
    }

    #[test]
    fn sites_bloques_dits_avec_leur_commande() {
        let mut l = Lieux::jetable(&racine("sites-bloques"));
        assert!(!recenser(&l).a_faire.iter().any(|x| x.contains("sites-dangereux off")));
        l.sites_bloques = true;
        assert!(recenser(&l).a_faire.iter().any(|x| x.contains("sites-dangereux off")));
    }

    /// Un ordinateur jetable où Vanguard, et une version d'avant, ont tout posé, avec à côté ce qui n'est pas à eux.
    fn ordinateur(nom: &str) -> (PathBuf, Lieux) {
        let r = racine(nom);
        let l = Lieux::jetable(&r);
        let unites = &l.unites[0];
        let bin = l.donnees.join("bin");
        let exe = bin.join(crate::mise_a_jour::NOM);
        let (service, timer) =
            surveillance::unites_systemd(&exe.display().to_string(), surveillance::Reglages::Aujourdhui);
        ecrire(&unites.join("vanguard-surveillance.service"), service);
        ecrire(&unites.join("vanguard-surveillance.timer"), timer);
        ecrire(&unites.join("vanguard-entretien.timer"), "[Timer]\n");
        ecrire(&l.unites[1].join(crate::sauvegarde::TIMER), "[Timer]\n");
        ecrire(
            &l.unites[1].join(crate::sauvegarde::SERVICE),
            "ExecStart=\"/usr/bin/rsync\" -a\n",
        );
        // Une version d'avant : sa minuterie et sa copie du programme.
        ecrire(
            &unites.join(format!("{}.timer", passage::ancien("vanguard-surveillance"))),
            "[Timer]\n",
        );
        ecrire(
            &bin.join(format!(
                "{}{}",
                passage::ancien("vanguard"),
                std::env::consts::EXE_SUFFIX
            )),
            "avant",
        );
        // Un agent launchd, le raccourci marqué et son icône.
        let agent = l
            .agents
            .as_ref()
            .unwrap()
            .join(format!("{}.plist", surveillance::AGENT_MACOS));
        ecrire(&agent, "<?xml version=\"1.0\"?><plist><dict></dict></plist>");
        let raccourci = l.raccourci.clone().unwrap();
        ecrire(
            &raccourci,
            format!(
                "[Desktop Entry]\nExec=\"{}\"\n{}\n",
                exe.display(),
                crate::raccourci::MARQUE
            ),
        );
        ecrire(
            &crate::raccourci::icone(&raccourci).unwrap(),
            include_bytes!("../assets/icones/vanguard-128.png"),
        );
        ecrire(&exe, "programme");
        ecrire(&bin.join(format!("{}.ancien", crate::mise_a_jour::NOM)), "programme");
        // Des données, une quarantaine, et l'ancien dossier de données.
        ecrire(&l.donnees.join("appareils.json"), "{}");
        ecrire(&l.donnees.join("quarantaine/x"), "x");
        ecrire(
            &l.donnees
                .with_file_name(passage::ancien("vanguard"))
                .join("historique.json"),
            "[]",
        );
        // Ce qui n'est pas à Vanguard : une autre minuterie, un autre .desktop, un fichier de bin/, une clé.
        ecrire(&unites.join("autre.timer"), "[Timer]\n");
        ecrire(
            &raccourci.with_file_name("Autre.desktop"),
            "[Desktop Entry]\nExec=autre\n",
        );
        ecrire(&bin.join("mon-outil"), "à moi");
        ecrire(&r.join("cle/vanguard"), "programme de la clé");
        (r, l)
    }

    fn genres(rec: &Recensement) -> Vec<Genre> {
        rec.elements.iter().map(|e| e.genre).collect()
    }

    #[test]
    fn recensement_d_un_ordinateur_jetable() {
        let (r, mut l) = ordinateur("recensement");
        let rec = recenser(&l);
        assert_eq!(
            genres(&rec),
            [
                Genre::Surveillance,
                Genre::Entretien,
                Genre::Sauvegarde,
                Genre::Avant,
                Genre::Raccourci,
                Genre::Programme,
                Genre::DonneesAvant,
                Genre::Donnees
            ]
        );
        let tout = format!("{:?}", rec.elements);
        for etranger in ["autre.timer", "Autre.desktop", "mon-outil", "cle/vanguard"] {
            assert!(!tout.contains(etranger), "{etranger} listé : {tout}");
        }
        // La surveillance lance la copie de bin/ ; le raccourci aussi ; l'icône part avec le raccourci.
        let exe = l.donnees.join("bin").join(crate::mise_a_jour::NOM);
        assert_eq!(rec.elements[0].lance.as_deref(), Some(exe.as_path()));
        assert_eq!(rec.elements[4].lance.as_deref(), Some(exe.as_path()));
        assert!(rec.elements[4].precision.contains("icône") || rec.elements[4].precision.contains("icon"));
        let Retrait::Fichiers(copies) = &rec.elements[5].retrait else {
            panic!("{:?}", rec.elements[5]);
        };
        assert_eq!(copies.len(), 3, "{copies:?}");
        assert!(matches!(
            &rec.elements[3].retrait,
            Retrait::Avant(Reste::Minuterie { .. })
        ));
        // Le programme en marche ailleurs : gardé, dit ; sur la clé : jamais touché, dit.
        l.programme = Some(r.join("ailleurs/vanguard"));
        assert!(recenser(&l).pas_a_lui.iter().any(|m| m.contains("ailleurs")));
        l.programme = Some(r.join("cle/vanguard"));
        let sur_la_cle = recenser(&l);
        assert!(
            sur_la_cle.pas_a_lui.iter().any(|m| m.contains("cle")),
            "{:?}",
            sur_la_cle.pas_a_lui
        );
        // Des données posées sur la clé (un dossier de données qui y mène) : écartées.
        l.donnees = r.join("cle/donnees/vanguard");
        std::fs::create_dir_all(&l.donnees).unwrap();
        assert!(!genres(&recenser(&l)).contains(&Genre::Donnees));
        // Des tâches de Windows lues : celle d'aujourd'hui, celle d'avant ; une autre est ignorée.
        let mut w = Lieux::jetable(&racine("taches"));
        w.taches = Some(
            [
                surveillance::TACHE_WINDOWS.to_string(),
                passage::taches_d_avant()[1].clone(),
                "Mise à jour de MonAppli".to_string(),
            ]
            .into_iter()
            .map(|nom| TacheLue {
                nom,
                programme: r"C:\Users\alice\AppData\Local\vanguard\bin\vanguard.exe".into(),
                active: true,
            })
            .collect(),
        );
        let rec = recenser(&w);
        assert_eq!(genres(&rec), [Genre::Surveillance, Genre::Avant]);
        assert!(!format!("{:?}", rec.elements).contains("MonAppli"));
        // Le planificateur non lu : dit, jamais compté comme absent.
        w.taches = None;
        assert_ne!(recenser(&w).non_verifie, Vec::<String>::new());
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn donnees_jamais_cochees_par_defaut() {
        let (r, l) = ordinateur("coches");
        let rec = recenser(&l);
        for e in &rec.elements {
            assert_eq!(
                e.coche,
                !matches!(e.genre, Genre::Donnees | Genre::DonneesAvant),
                "{e:?}"
            );
        }
        assert!(cases(&rec.elements, false).iter().all(|c| !c.cochee));
        let avec = cases(&rec.elements, true);
        assert_eq!(
            avec.iter().map(|c| c.cochee).collect::<Vec<_>>(),
            rec.elements.iter().map(|e| e.coche).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn copie_gardee_si_une_tache_gardee_la_lance() {
        let (r, l) = ordinateur("dependances");
        let rec = recenser(&l);
        let mut etats: Vec<bool> = rec.elements.iter().map(|e| e.coche).collect();
        // Tout ce qui est coché part : rien à garder.
        assert_eq!(garder_les_dependances(&rec.elements, &mut etats), Vec::<String>::new());
        // La surveillance gardée : la copie qu'elle lance reste, et c'est dit.
        etats[0] = false;
        let messages = garder_les_dependances(&rec.elements, &mut etats);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains(&rec.elements[0].texte));
        assert!(!etats[5]);
        let _ = std::fs::remove_dir_all(r);
    }

    #[cfg(unix)]
    #[test]
    fn effacer_sans_suivre_les_liens() {
        let r = racine("liens");
        let d = r.join("donnees");
        let dehors = r.join("dehors");
        ecrire(&dehors.join("garde.txt"), "à moi");
        ecrire(&d.join("a/b.txt"), "b");
        std::os::unix::fs::symlink(dehors.join("garde.txt"), d.join("lien-fichier")).unwrap();
        std::os::unix::fs::symlink(&dehors, d.join("a/lien-dossier")).unwrap();
        let en_marche = d.join("bin/vanguard");
        ecrire(&en_marche, "x");
        let restes = effacer_dossier(&d, Some(&en_marche), &[], None);
        // Les cibles des liens restent intactes ; le programme gardé reste, et c'est dit.
        assert_eq!(std::fs::read_to_string(dehors.join("garde.txt")).unwrap(), "à moi");
        assert!(en_marche.is_file());
        assert_eq!(restes.len(), 1, "{restes:?}");
        assert_eq!(restes[0].0, en_marche);
        assert!(!d.join("a").exists() && !d.join("lien-fichier").exists());
        // Sans rien à garder : tout part.
        assert_eq!(effacer_dossier(&d, None, &[], None), Vec::new());
        assert!(!d.exists());
        // Sur la clé, ou un chemin relatif : refusé, rien n'est touché.
        let cle = r.join("cle");
        ecrire(&cle.join("donnees/x"), "x");
        assert_eq!(effacer_dossier(&cle.join("donnees"), None, &[], Some(&cle)).len(), 1);
        assert!(cle.join("donnees/x").is_file());
        assert_eq!(effacer_dossier(Path::new("relatif"), None, &[], None).len(), 1);
        let _ = std::fs::remove_dir_all(r);
    }

    #[cfg(windows)]
    #[test]
    fn effacer_un_fichier_en_lecture_seule() {
        let r = racine("lecture-seule");
        let f = r.join("quarantaine/x.exe.vanguard-quarantaine");
        ecrire(&f, "x");
        let mut droits = std::fs::metadata(&f).unwrap().permissions();
        droits.set_readonly(true);
        std::fs::set_permissions(&f, droits).unwrap();
        assert_eq!(effacer_dossier(&r, None, &[], None), Vec::new());
        assert!(!r.exists());
    }

    #[test]
    fn un_echec_n_est_jamais_compte_comme_fait() {
        let b = Bilan {
            retire: vec!["Raccourci".into()],
            garde: vec!["Dossier de données".into()],
            echoue: vec![("Surveillance horaire".into(), "systemctl".into())],
            a_faire: vec!["vanguard blocage annuler".into()],
            non_verifie: Vec::new(),
        };
        let texte = rediger_bilan(&b).join("\n");
        let retire = texte.split(tr!("Gardé", "Kept")).next().unwrap();
        assert!(!retire.contains("Surveillance horaire"), "{texte}");
        assert!(texte.contains("✖ Surveillance horaire"), "{texte}");
        assert!(!texte.contains("Fait :") && !texte.contains("Done:"), "{texte}");
        assert!(texte.contains("1 "), "{texte}");
        let tout_bon = Bilan {
            echoue: Vec::new(),
            ..b
        };
        let texte = rediger_bilan(&tout_bon).join("\n");
        assert!(texte.contains("Fait :") || texte.contains("Done:"), "{texte}");
        // Le planificateur muet : rien n'a échoué, mais la fin n'est pas dite « faite » ; le point est redit.
        let muet = Bilan {
            non_verifie: vec!["Tâches planifiées non lues".into()],
            ..tout_bon
        };
        let texte = rediger_bilan(&muet).join("\n");
        assert!(!texte.contains("Fait :") && !texte.contains("Done:"), "{texte}");
        assert!(texte.contains("? Tâches planifiées non lues"), "{texte}");
        assert!(
            texte.contains("non vérifié") || texte.contains("not checked"),
            "{texte}"
        );
    }

    #[test]
    fn dossier_de_donnees_coche_garde_ce_que_demande_un_element_garde() {
        let (r, l) = ordinateur("dependances-dossier");
        ecrire(&l.donnees.join(surveillance::VOULUE), "");
        // La note scellée des défenses voulues, et un autre fichier scellé, qui part avec le dossier.
        crate::voulues::noter_dans(&l.donnees, crate::voulues::Defense::Surveillance, true, false).unwrap();
        crate::sceau::ecrire_dans(&l.donnees, crate::sceau::APPRIS, b"{}").unwrap();
        let rec = recenser(&l);
        let mut etats: Vec<bool> = rec.elements.iter().map(|e| e.coche).collect();
        // La surveillance gardée, le dossier de données coché.
        etats[0] = false;
        let i = rec.elements.iter().position(|e| e.genre == Genre::Donnees).unwrap();
        etats[i] = true;
        let _ = garder_les_dependances(&rec.elements, &mut etats);
        let gardes = gardes_dans(&l.donnees, true, &rec.elements, &etats);
        let exe = l.donnees.join("bin").join(crate::mise_a_jour::NOM);
        let voulue = l.donnees.join(surveillance::VOULUE);
        assert!(gardes.iter().any(|(p, _)| *p == exe), "{gardes:?}");
        assert!(gardes.iter().any(|(p, _)| *p == voulue), "{gardes:?}");
        assert!(gardes.iter().all(|(_, pour)| !pour.is_empty()));
        let mut x = Execution {
            donnees: &l.donnees,
            en_marche: None,
            cle: l.cle.as_deref(),
            gardes,
            a_faire: Vec::new(),
            veilleur_reste: None,
        };
        let fait = retirer(&rec.elements[i], &mut x).expect("effacé");
        // La note des défenses gardée avec ses sceaux, telle que Vanguard l'a écrite ; ce qui est parti n'est pas dit
        // effacé hors de Vanguard.
        assert!(matches!(
            crate::sceau::lire_dans(&l.donnees, crate::voulues::FICHIER),
            crate::sceau::Lecture::Intact(_)
        ));
        assert_eq!(
            crate::sceau::lire_dans(&l.donnees, crate::sceau::APPRIS),
            crate::sceau::Lecture::Absent
        );
        // bin/vanguard reste : la surveillance gardée le lance ; le reste des données part.
        assert!(exe.is_file() && voulue.is_file());
        assert!(!l.donnees.join("appareils.json").exists() && !l.donnees.join("quarantaine").exists());
        assert!(fait.contains("gardé") || fait.contains("kept"), "{fait}");
        // Sans rien de gardé : tout part, et le dossier est vérifié absent.
        x.gardes.clear();
        assert!(retirer(&rec.elements[i], &mut x).is_ok());
        assert!(!l.donnees.exists());
        let _ = std::fs::remove_dir_all(r);
    }

    /// L'unité du veilleur : celle de Vanguard (dans l'une ou l'autre langue) comptée, cochée, retirée avant le
    /// dossier de données, et ce qu'elle demande gardé si elle reste ; une unité du même nom sans la marque gardée,
    /// dite, jamais dans la liste.
    #[cfg(target_os = "linux")]
    #[test]
    fn veilleur_reconnu_a_sa_marque() {
        use crate::machine::linux::veilleur::{ETAT, VOULU, unite_d_essai};
        let r = racine("veilleur");
        let l = Lieux::jetable(&r);
        let unite = l.veilleur.clone().unwrap();
        let exe = l.donnees.join("bin").join(crate::mise_a_jour::NOM);
        ecrire(&exe, "programme");
        ecrire(&l.donnees.join(VOULU), "");
        ecrire(&l.donnees.join(ETAT), "{}");
        for anglais in [false, true] {
            ecrire(&unite, unite_d_essai(&exe.display().to_string(), anglais));
            let rec = recenser(&l);
            assert_eq!(
                genres(&rec),
                [Genre::Veilleur, Genre::Programme, Genre::Donnees],
                "{:?}",
                rec.elements
            );
            let v = &rec.elements[0];
            assert!(v.coche);
            assert_eq!(v.retrait, Retrait::Veilleur(unite.clone()));
            assert_eq!(v.lance.as_deref(), Some(exe.as_path()));
            assert!(largeur_affichee(&v.precision) <= 33 && largeur_affichee(&v.texte) <= 44);
            assert!(
                rec.pas_a_lui.is_empty() && rec.non_verifie.is_empty(),
                "{:?}",
                rec.pas_a_lui
            );
        }
        // Le veilleur gardé, le dossier de données coché : sa copie du programme, son choix et son état restent.
        let rec = recenser(&l);
        let mut etats = vec![false, true, true];
        let messages = garder_les_dependances(&rec.elements, &mut etats);
        assert_eq!(etats, [false, false, true], "{messages:?}");
        let gardes = gardes_dans(&l.donnees, true, &rec.elements, &etats);
        for p in [exe.clone(), l.donnees.join(VOULU), l.donnees.join(ETAT)] {
            assert!(gardes.iter().any(|(q, _)| *q == p), "{} : {gardes:?}", p.display());
        }
        // Le même nom sans la marque : quelqu'un d'autre l'a posée.
        ecrire(
            &unite,
            "[Unit]\nDescription=Mon veilleur\n[Service]\nExecStart=/usr/bin/mon-veilleur\n",
        );
        let rec = recenser(&l);
        assert!(!genres(&rec).contains(&Genre::Veilleur), "{:?}", rec.elements);
        assert!(!format!("{:?}", rec.elements).contains("mon-veilleur"));
        assert!(
            rec.pas_a_lui.iter().any(|m| m.contains("vanguard-veilleur.service")),
            "{:?}",
            rec.pas_a_lui
        );
        // La marque ailleurs qu'en première ligne ne suffit pas.
        ecrire(&unite, format!("[Unit]\n{}", unite_d_essai("/usr/bin/autre", false)));
        assert!(!genres(&recenser(&l)).contains(&Genre::Veilleur));
        // Absente : rien.
        std::fs::remove_file(&unite).unwrap();
        let rec = recenser(&l);
        assert!(!genres(&rec).contains(&Genre::Veilleur) && rec.pas_a_lui.is_empty());
        let _ = std::fs::remove_dir_all(r);
    }

    /// Un veilleur qui n'a pas pu être arrêté : la copie du programme qu'il lance et le dossier de données qu'il
    /// recréerait restent, et c'est dit en échec ; les autres copies partent. Seulement non vérifié, tout part.
    /// (`retirer_sans_question` lance systemctl : son issue est donnée à la main.)
    #[cfg(target_os = "linux")]
    #[test]
    fn veilleur_reste_garde_programme_et_donnees() {
        use crate::machine::linux::veilleur::unite_d_essai;
        let r = racine("veilleur-reste");
        let l = Lieux::jetable(&r);
        let exe = l.donnees.join("bin").join(crate::mise_a_jour::NOM);
        let autre = l.donnees.join("bin/vanguard-ancien");
        let poser = || {
            ecrire(&exe, "programme");
            ecrire(&autre, "copie d'avant");
            ecrire(&l.donnees.join("appareils.json"), "[]");
            ecrire(
                l.veilleur.as_ref().unwrap(),
                unite_d_essai(&exe.display().to_string(), false),
            );
        };
        poser();
        let rec = recenser(&l);
        assert_eq!(genres(&rec)[0], Genre::Veilleur, "{:?}", rec.elements);
        let veilleur = &rec.elements[0];
        let programme = Element {
            retrait: Retrait::Fichiers(vec![exe.clone(), autre.clone()]),
            ..rec
                .elements
                .iter()
                .find(|e| e.genre == Genre::Programme)
                .unwrap()
                .clone()
        };
        let donnees = rec.elements.iter().find(|e| e.genre == Genre::Donnees).unwrap();
        let execution = || Execution {
            donnees: &l.donnees,
            en_marche: None,
            cle: None,
            gardes: Vec::new(),
            a_faire: Vec::new(),
            veilleur_reste: None,
        };
        let echoue = || Err(Echec::Echoue("toujours en marche (processus 4242)".into()));
        // Toujours en marche : la copie qu'il lance et le dossier restent, l'autre copie part.
        let mut x = execution();
        assert!(matches!(
            issue_du_veilleur(veilleur, echoue(), &mut x),
            Err(Echec::Echoue(_))
        ));
        let Err(Echec::Echoue(raison)) = retirer(&programme, &mut x) else {
            panic!("copie lancée par le veilleur retirée");
        };
        assert!(
            raison.contains("veilleur off") || raison.contains("watcher off"),
            "{raison}"
        );
        assert!(exe.is_file() && !autre.exists());
        assert!(matches!(retirer(donnees, &mut x), Err(Echec::Echoue(_))));
        assert!(l.donnees.join("appareils.json").is_file());
        // Ce qu'il lance n'a pas été lu : toute copie du programme reste.
        poser();
        let mut x = execution();
        let sans_lance = Element {
            lance: None,
            ..veilleur.clone()
        };
        let _ = issue_du_veilleur(&sans_lance, echoue(), &mut x);
        assert!(retirer(&programme, &mut x).is_err());
        assert!(exe.is_file() && autre.is_file());
        // Rien vu en marche, l'arrêt seulement non confirmé : rien ne le recréerait, tout part.
        let mut x = execution();
        let issue = issue_du_veilleur(veilleur, Err(Echec::NonVerifie("pas de réponse".into())), &mut x);
        assert!(matches!(issue, Err(Echec::NonVerifie(_))) && x.veilleur_reste.is_none());
        assert!(retirer(&programme, &mut x).is_ok() && !exe.exists());
        assert!(retirer(donnees, &mut x).is_ok() && !l.donnees.exists());
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn ancien_dossier_avec_une_quarantaine_jamais_efface() {
        let r = racine("avant-quarantaine");
        let d = r.join("ancien");
        ecrire(&d.join("historique.json"), "[]");
        ecrire(&d.join("quarantaine/x.vanguard-quarantaine"), "x");
        ecrire(
            &d.join("quarantaine/journal.txt"),
            "2026-10-18 10:00:00\tTest\t/home/alice/x\tx.vanguard-quarantaine\n",
        );
        let mut pas_a_lui = Vec::new();
        let e = dossier_de_donnees(&d, Genre::DonneesAvant, "", &mut pas_a_lui);
        let a = Annulables {
            optimiser: 0,
            bilan: 0,
            blocages: 0,
            jeux: 0,
            quarantaine: 0,
            a_la_main: Vec::new(),
        };
        // Refusé avant toute question : ces fichiers ne se remettent pas d'ici.
        assert!(!accord_donnees(&e, &a, &[]));
        assert!(d.join("quarantaine/x.vanguard-quarantaine").is_file());
        let _ = std::fs::remove_dir_all(r);
    }

    #[cfg(unix)]
    #[test]
    fn dossier_de_donnees_qui_est_un_lien() {
        let r = racine("donnees-lien");
        let cible = r.join("autre-disque/vanguard");
        ecrire(&cible.join("appareils.json"), "{}");
        let mut l = Lieux::jetable(&r);
        std::fs::create_dir_all(l.donnees.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&cible, &l.donnees).unwrap();
        l.raccourci = None;
        let rec = recenser(&l);
        let e = rec.elements.iter().find(|e| e.genre == Genre::Donnees).unwrap();
        // Nommé comme un lien, sans la taille de sa cible ; dit que la cible reste.
        assert!(e.texte.contains("lien") || e.texte.contains("link"), "{}", e.texte);
        assert!(
            rec.pas_a_lui.iter().any(|m| m.contains("autre-disque")),
            "{:?}",
            rec.pas_a_lui
        );
        let mut x = Execution {
            donnees: &l.donnees,
            en_marche: None,
            cle: None,
            gardes: Vec::new(),
            a_faire: Vec::new(),
            veilleur_reste: None,
        };
        let fait = retirer(e, &mut x).unwrap();
        assert!(fait.contains("autre-disque"), "{fait}");
        assert!(std::fs::symlink_metadata(&l.donnees).is_err());
        assert!(cible.join("appareils.json").is_file());
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn corrections_redites_quand_leur_releve_part() {
        let a = Annulables {
            optimiser: 0,
            bilan: 0,
            blocages: 0,
            jeux: 0,
            quarantaine: 0,
            a_la_main: vec![
                ("2026-10-01 10:00".into(), "ufw enable".into()),
                ("2026-10-02 11:00".into(), "systemctl disable --now cups".into()),
            ],
        };
        let restes = changements_restants(&a, true).join("\n");
        assert!(restes.contains("ufw enable") && restes.contains("cups"), "{restes}");
        assert!(restes.contains("2026-10-02 11:00"), "{restes}");
        // Données gardées : le relevé est là, la commande qui le montre suffit.
        assert!(!changements_restants(&a, false).join("\n").contains("ufw enable"));
    }

    #[test]
    fn releve_copie_sans_rien_ecraser() {
        let r = racine("releve");
        let releve = r.join(crate::changements::RELEVE);
        ecrire(&releve, "{\"commande\":\"ufw enable\"}\n");
        let dest = r.join("maison");
        std::fs::create_dir_all(&dest).unwrap();
        let premiere = copier_releve(&releve, &dest).unwrap();
        let seconde = copier_releve(&releve, &dest).unwrap();
        assert_ne!(premiere, seconde);
        assert_eq!(
            std::fs::read_to_string(&premiere).unwrap(),
            std::fs::read_to_string(&releve).unwrap()
        );
        assert!(copier_releve(&releve, Path::new("relatif")).is_err());
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn precisions_accordees_et_programme_d_un_lnk() {
        let (r, mut l) = ordinateur("precisions");
        let rec = recenser(&l);
        // « Entretien du mois » est masculin.
        assert!(
            !rec.elements[1].precision.contains("retirée"),
            "{}",
            rec.elements[1].precision
        );
        // Les fichiers trouvés (les deux unités, l'agent launchd) vont avec la tâche, pour être tous retirés.
        let Retrait::Surveillance(f) = &rec.elements[0].retrait else {
            panic!("{:?}", rec.elements[0]);
        };
        assert_eq!(f.len(), 3, "{f:?}");
        // Un raccourci .lnk ne se lit pas : il vise la copie de bin/, qui reste s'il est gardé.
        let lnk = r.join("Bureau/Vanguard.lnk");
        ecrire(&lnk, b"L\0\0\0binaire");
        l.raccourci = Some(lnk);
        let rec = recenser(&l);
        let e = rec.elements.iter().find(|e| e.genre == Genre::Raccourci).unwrap();
        assert_eq!(e.lance, Some(l.donnees.join("bin").join(crate::mise_a_jour::NOM)));
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn copie_en_marche_nommee_d_apres_ce_qui_part() {
        let (r, mut l) = ordinateur("en-marche");
        l.programme = Some(l.donnees.join("bin").join(crate::mise_a_jour::NOM));
        let rec = recenser(&l);
        let e = rec.elements.iter().find(|e| e.genre == Genre::Programme).unwrap();
        if cfg!(windows) {
            // La copie en marche reste : l'élément dit « restes », jamais « copie effacée ».
            assert!(
                e.texte.contains("Restes") || e.texte.contains("leftovers"),
                "{}",
                e.texte
            );
            assert_ne!(rec.a_faire, Vec::<String>::new());
        } else {
            assert!(e.texte.contains("Copie") || e.texte.contains("copy"), "{}", e.texte);
        }
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn messages_dans_la_largeur() {
        let larges = crate::ui::textes_trop_larges(include_str!("desinstaller.rs"));
        assert_eq!(larges, Vec::<String>::new());
        let (r, l) = ordinateur("largeur");
        for e in recenser(&l).elements {
            assert!(largeur_affichee(&e.precision) <= 33, "{}", e.precision);
            assert!(largeur_affichee(&e.texte) <= 44, "{}", e.texte);
        }
        for (texte, precision) in entrees_annulables(&Annulables {
            optimiser: 120,
            bilan: 120,
            blocages: 120,
            jeux: 120,
            quarantaine: 120,
            a_la_main: Vec::new(),
        }) {
            assert!(largeur_affichee(&precision) <= 33 && largeur_affichee(&texte) <= 44);
        }
        let _ = std::fs::remove_dir_all(r);
    }
}
