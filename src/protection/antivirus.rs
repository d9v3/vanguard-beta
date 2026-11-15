//! Recherche de malwares avec le moteur de Vanguard (empreintes, YARA, base ClamAV installée, heuristiques), clamscan
//! en second avis facultatif sous Linux, Microsoft Defender sous Windows, et revue des programmes lancés au
//! démarrage, là où un malware cherche à se maintenir.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::path::PathBuf;
// Defender sous Windows ; sous Unix, clamscan part par `commande::par_le_systeme` (E-1, recontrôle 0.95).
#[cfg(any(windows, test))]
use std::process::Command;

use crate::risk::Niveau;
use crate::ui::*;

pub(crate) mod resultat;

#[cfg(unix)]
fn home() -> PathBuf {
    crate::socle::maison()
}

/// Ce qu'un moteur a conclu sur un fichier.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Examen {
    Sain,
    /// Rien trouvé, mais une source attendue manquait (base ClamAV absente ou écartée, empreintes de MalwareBazaar
    /// non chargées) : le « rien trouvé » est dit avec ce qui manquait, jamais comme un sain sans réserve.
    SainSousReserve(Vec<String>),
    /// Détections : nom de la menace ou de la famille.
    Trouve(Vec<String>),
    /// Des heuristiques seulement (moteur de Vanguard) : à regarder, jamais mis en quarantaine de lui-même. Un signe
    /// ne fait pas taire ce qui n'a pas pu être vérifié : `manques` (partie non lue, source attendue absente) et
    /// `reserves` (source facultative absente) restent dits à côté du « suspect ».
    Suspect {
        signes: Vec<String>,
        manques: Vec<String>,
        reserves: Vec<String>,
    },
    /// Pas pu analyser, avec la raison : jamais compté comme sain.
    Impossible(String),
}

impl Examen {
    /// Ce qu'un suspect n'a pas pu vérifier (manques puis réserves), en une phrase ; `None` s'il n'y en a pas ou si
    /// l'examen n'est pas un suspect. Partagé par l'écran, le courriel, les plugins et le résultat versé.
    pub(crate) fn non_verifie_du_suspect(&self) -> Option<String> {
        match self {
            Examen::Suspect { manques, reserves, .. } if !(manques.is_empty() && reserves.is_empty()) => {
                Some(manques.iter().chain(reserves).cloned().collect::<Vec<_>>().join(" ; "))
            }
            _ => None,
        }
    }

    /// La ligne à montrer pour ce moteur : (niveau, texte). Une détection est critique, un suspect moyen, une analyse
    /// impossible moyenne (rien n'est conclu).
    pub(crate) fn ligne(&self, moteur: &str) -> (Option<Niveau>, String) {
        match self {
            Examen::Sain => (None, trf!("{moteur} : rien trouvé.", "{moteur}: nothing found.")),
            Examen::SainSousReserve(reserves) => (
                None,
                trf!(
                    "{moteur} : rien trouvé (⚠ {}).",
                    "{moteur}: nothing found (⚠ {}).",
                    affichable(&reserves.join(" ; "))
                ),
            ),
            Examen::Trouve(noms) => (
                Some(Niveau::Critique),
                trf!("{moteur} : {}", "{moteur}: {}", affichable(&resume(noms, 3, ", "))),
            ),
            Examen::Suspect { signes, .. } => (
                Some(Niveau::Moyen),
                trf!(
                    "{moteur} : suspect, rien de connu ({}){}.",
                    "{moteur}: suspicious, nothing known ({}){}.",
                    affichable(&resume(signes, 2, " ; ")),
                    self.non_verifie_du_suspect()
                        .map(|n| trf!(" ; non vérifié : {}", "; not checked: {}", affichable(&n)))
                        .unwrap_or_default()
                ),
            ),
            // La raison peut porter un nom d'entrée d'archive, choisi par qui a fait le fichier : sans `affichable`,
            // ses séquences d'échappement effaceraient ou forgeraient les lignes de verdict à l'écran.
            Examen::Impossible(raison) => (
                Some(Niveau::Moyen),
                trf!(
                    "{moteur} : impossible à vérifier ({}).",
                    "{moteur}: could not check ({}).",
                    affichable(raison)
                ),
            ),
        }
    }
}

/// Ce que couvre une analyse.
pub enum Portee {
    /// Là où arrivent les menaces : téléchargements, bureau, démarrage automatique, /tmp récent.
    Rapide,
    /// Tout le dossier personnel.
    Complete,
    /// Une clé USB, un disque externe ou un dossier choisi.
    Dossier(PathBuf),
}

pub fn analyser(portee: Portee) {
    titre(match portee {
        Portee::Rapide => tr!("Analyse antivirus rapide", "Quick antivirus scan"),
        Portee::Complete => tr!("Analyse antivirus complète", "Full antivirus scan"),
        Portee::Dossier(_) => tr!(
            "Analyse antivirus d'une clé ou d'un dossier",
            "Antivirus scan of a drive or folder"
        ),
    });
    let portee = match portee {
        Portee::Dossier(d) => {
            let Ok(reel) = d.canonicalize() else {
                trp!("  ✖ Introuvable : {}", "  ✖ Not found: {}", chemin_affichable(&d));
                return;
            };
            Portee::Dossier(reel)
        }
        autre => autre,
    };
    // Linux : le moteur de Vanguard d'abord, ClamAV en second avis (ses signatures complètes, s'il est installé).
    #[cfg(unix)]
    {
        section(tr!("Moteur de Vanguard", "Vanguard engine"));
        crate::protection::yara::analyser_sans_titre(&portee, false);
        section(tr!("Second avis : ClamAV", "Second opinion: ClamAV"));
        clamav(&portee);
    }
    #[cfg(windows)]
    {
        let place = place_actuelle();
        if place == PlaceDuMoteur::SecondAvis {
            section(tr!("Microsoft Defender", "Microsoft Defender"));
            defender(&portee);
            section(tr!(
                "Second avis : moteur de Vanguard",
                "Second opinion: Vanguard engine"
            ));
            crate::protection::yara::analyser_sans_titre(&portee, false);
        } else {
            section(tr!("Moteur de Vanguard", "Vanguard engine"));
            for ligne in envelopper(place.ce_qui_manque(), LARGEUR - 4) {
                println!("  {GRIS}{ligne}{RESET}");
            }
            crate::protection::yara::analyser_sans_titre(&portee, false);
            section(tr!(
                "Second avis : Defender, à la demande",
                "Second opinion: Defender, on demand"
            ));
            defender(&portee);
        }
    }
    match &portee {
        // Une clé n'a pas de programmes de démarrage : on regarde plutôt les pièges des vers de clé USB.
        Portee::Dossier(d) => revue_cle(d),
        _ => demarrage(),
    }
}

/// `vanguard antivirus --json` : l'analyse rapide sans aucune question et sans rien changer (ni quarantaine, ni
/// téléchargement de signatures, ni Defender, qui retire de lui-même ce qu'il trouve) ; le résultat commun sur la
/// sortie, versé au rapport. Ce qui est trouvé est à isoler depuis le menu.
pub(crate) fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let mut r = crate::protection::yara::releve_rapide();
    #[cfg(unix)]
    ajouter_second_avis(&mut r, second_avis(&Portee::Rapide, false));
    #[cfg(windows)]
    {
        let place = place_actuelle();
        match place {
            PlaceDuMoteur::SecondAvis => {}
            PlaceDuMoteur::Principal => r.infos.push(place.ce_qui_manque().to_string()),
            PlaceDuMoteur::NonVerifie => r.manques.push(place.ce_qui_manque().to_string()),
        }
        r.manques.push(resultat::defender_pas_lance().to_string());
    }
    let (entrees, non_lus) = entrees_demarrage();
    resultat::ajouter_demarrage(&mut r, &entrees, &non_lus);
    let res = resultat::resultat(&r, debut);
    crate::modele::resultat::verser(&res);
    println!("{}", crate::modele::resultat::json(&res));
}

/// Le second avis de ClamAV dans le relevé : chaque fichier infecté (critique, à isoler depuis le menu) ; un avis
/// coupé ou clamscan absent est dit (il est facultatif) ; sans signatures, en échec ou avec des éléments illisibles,
/// il est non vérifié.
#[cfg(unix)]
fn ajouter_second_avis(r: &mut crate::protection::yara::resultat::Releve, avis: SecondAvis) {
    match avis {
        SecondAvis::NonLance(raison) if raison == raison_sans_signatures() => r.manques.push(tr!(
            "Second avis ClamAV non lancé : ses signatures manquent (à télécharger depuis le menu Antivirus et protection ; rien n'est téléchargé avec --json).",
            "ClamAV second opinion not run: its signatures are missing (download them from the Antivirus and protection menu; nothing is downloaded with --json)."
        ).to_string()),
        SecondAvis::NonLance(raison) => r.infos.push(trf!(
            "Second avis ClamAV non lancé : {raison}.",
            "ClamAV second opinion not run: {raison}."
        )),
        SecondAvis::PasDemarre => r.manques.push(tr!(
            "Second avis ClamAV : clamscan ne s'est pas lancé.",
            "ClamAV second opinion: clamscan did not start."
        ).to_string()),
        SecondAvis::Echoue(erreurs) => r.manques.push(trf!(
            "Second avis ClamAV : l'analyse a échoué, son résultat n'est pas fiable. {}",
            "ClamAV second opinion: the scan failed, its result is not reliable. {}",
            erreurs.join(" ; ")
        ).trim_end().to_string()),
        SecondAvis::Fait(bilan) => {
            if bilan.illisibles > 0 {
                r.manques.push(trf!(
                    "Second avis ClamAV : {} élément(s) illisible(s) sans droits root, non analysé(s).",
                    "ClamAV second opinion: {} item(s) unreadable without root rights, not scanned.",
                    bilan.illisibles
                ));
            }
            r.infos.push(trf!(
                "Second avis ClamAV : {} fichier(s) analysé(s).",
                "ClamAV second opinion: {} file(s) scanned.",
                bilan.analyses
            ));
            // Ni trouvaille (rien n'a confirmé l'infection), ni sain : non vérifié.
            r.manques.extend(bilan.non_verifies.iter().map(|(f, raison)| {
                trf!(
                    "Second avis ClamAV : {} signalé, non vérifié : {raison}.",
                    "ClamAV second opinion: {} reported, not verified: {raison}.",
                    affichable(f)
                )
            }));
            // Fichiers récents de /tmp que clamscan n'a pas reçus : dits, jamais comptés sains.
            r.manques.extend(bilan.non_analyses.iter().map(|(n, raison)| {
                trf!(
                    "Second avis ClamAV : {n} fichier(s) récent(s) de /tmp non analysé(s) : {raison}.",
                    "ClamAV second opinion: {n} recent file(s) in /tmp not scanned: {raison}."
                )
            }));
            if !bilan.lignes_inconnues.is_empty() {
                r.manques.push(trf!(
                    "Second avis ClamAV : lignes qu'aucun fichier n'explique ({}), sans doute un nom de fichier à saut de ligne : non vérifié.",
                    "ClamAV second opinion: lines that no file explains ({}), probably a file name with a line break: not verified.",
                    bilan.lignes_inconnues.join(", ")
                ));
            }
            r.trouves.extend(bilan.infectes.iter().map(|(f, menace)| {
                (
                    Niveau::Critique,
                    trf!(
                        "{} : {menace} (ClamAV). Ne l'ouvrez pas ; à isoler depuis le menu Antivirus et protection.",
                        "{}: {menace} (ClamAV). Do not open it; quarantine it from the Antivirus and protection menu.",
                        affichable(f)
                    ),
                )
            }));
        }
    }
}

/// La place du moteur de Vanguard face à Defender (P19), dans l'analyse antivirus de Windows.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlaceDuMoteur {
    /// Defender protège (ou un autre antivirus reconnu, Defender passif) : il analyse d'abord, Vanguard donne un
    /// second avis.
    SecondAvis,
    /// La protection en temps réel de Defender est coupée par le choix de la personne (Options de défense, noté) :
    /// Vanguard est le moteur principal, et ce qui manque est dit.
    Principal,
    /// Defender coupé sans choix noté, ou son état illisible : Vanguard analyse d'abord, sans rien conclure de
    /// Defender ; le bilan dit ce qui l'a coupé.
    NonVerifie,
}

impl PlaceDuMoteur {
    /// Ce qui ne protège plus quand le moteur de Vanguard est en premier : il analyse à la demande et à l'heure,
    /// il ne refuse rien avant le lancement, ne voit pas les scripts en mémoire (AMSI) et ne demande l'avis d'aucun
    /// nuage.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn ce_qui_manque(self) -> &'static str {
        match self {
            PlaceDuMoteur::SecondAvis => "",
            PlaceDuMoteur::Principal => tr!(
                "Defender est coupé par votre choix (Options de défense) : le moteur de Vanguard est le principal. Il ne remplace pas tout : rien n'est refusé avant le lancement, les scripts en mémoire (AMSI) ne sont pas vus, et aucun nuage n'est consulté. « Rallumer » remet Defender.",
                "Defender is turned off by your choice (Defense options): the Vanguard engine is the main one. It does not replace everything: nothing is refused before launch, in-memory scripts (AMSI) are not seen, and no cloud is consulted. “Turn back on” restores Defender."
            ),
            PlaceDuMoteur::NonVerifie => tr!(
                "La protection en temps réel de Defender est coupée sans choix noté, ou son état ne se lit pas : non vérifié, voir le bilan. Le moteur de Vanguard analyse d'abord ; il ne refuse rien avant le lancement, ne voit pas AMSI ni le nuage.",
                "Defender's real-time protection is off with no noted choice, or its state cannot be read: not verified, see the checkup. The Vanguard engine scans first; it refuses nothing before launch, sees neither AMSI nor the cloud."
            ),
        }
    }
}

/// La place du moteur de Vanguard face à Defender sur cet ordinateur, lue maintenant : l'analyse et l'écran de
/// l'antivirus.
#[cfg(windows)]
pub(crate) fn place_actuelle() -> PlaceDuMoteur {
    let (mode, temps_reel) = crate::machine::windows::defense_etat::defender_en_marche();
    let par_choix = crate::machine::choix_avant::note_de(
        &crate::machine::choix_avant::notes(),
        crate::machine::gestes::IdChoix::Defender(crate::machine::gestes::ReglageDefender::TempsReel),
    )
    .is_some();
    place_du_moteur(mode, temps_reel, par_choix)
}

/// P19 : Defender allumé (ou passif derrière un autre antivirus) → second avis ; temps réel coupé par le choix noté
/// de la personne → principal ; tout le reste (coupé sans choix, illisible) → non vérifié, jamais compté comme une
/// protection en place.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn place_du_moteur(
    mode: crate::options_defense::ModeDefender,
    temps_reel: Option<bool>,
    par_choix: bool,
) -> PlaceDuMoteur {
    use crate::options_defense::ModeDefender;
    match (mode, temps_reel) {
        (ModeDefender::Actif, Some(true)) | (ModeDefender::Passif | ModeDefender::BlocageEdr, _) => {
            PlaceDuMoteur::SecondAvis
        }
        (_, Some(false)) | (ModeDefender::Coupe, _) if par_choix => PlaceDuMoteur::Principal,
        _ => PlaceDuMoteur::NonVerifie,
    }
}

/// Menu : propose les clés et disques externes branchés, ou un chemin tapé à la main.
pub fn choisir() {
    let volumes = volumes_amovibles();
    titre(tr!("Antivirus : clé USB ou dossier", "Antivirus: USB drive or folder"));
    if volumes.is_empty() {
        trp!(
            "  {GRIS}Aucune clé ni disque externe monté.{RESET}",
            "  {GRIS}No USB drive or external disk mounted.{RESET}"
        );
    }
    for (i, (chemin, description)) in volumes.iter().enumerate() {
        println!(
            "  {TOUCHE}{}{RESET}  {}  {DISCRET}{description}{RESET}",
            i.saturating_add(1),
            chemin_affichable(chemin)
        );
    }
    let reponse = crate::selection::demander_ou_revenir(tr!(
        "\n  Numéro, ou chemin d'un dossier (Entrée pour revenir) : ",
        "\n  Number, or path of a folder (Enter to go back): "
    ));
    let reponse = reponse.trim();
    if reponse.is_empty() {
        return;
    }
    // Un numéro de la liste (compté depuis 1), sinon un chemin.
    let cible = match reponse
        .parse::<usize>()
        .ok()
        .and_then(|n| volumes.get(n.checked_sub(1)?))
    {
        Some((chemin, _)) => chemin.clone(),
        None => PathBuf::from(reponse.trim_matches(['"', '\''])),
    };
    analyser(Portee::Dossier(cible));
}

/// Clés et disques externes montés : (point de montage, description). Lu dans /proc/self/mountinfo et /sys, comme
/// lsblk le fait lui-même ; lsblk ne sert qu'en secours, quand mountinfo ne se lit pas.
#[cfg(target_os = "linux")]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    if let Ok(montages) = std::fs::read_to_string("/proc/self/mountinfo") {
        return volumes_amovibles_sous(std::path::Path::new("/"), &montages);
    }
    crate::commande::lancer(
        crate::commande::par_le_systeme("lsblk").args(["-Pno", "RM,HOTPLUG,LABEL,SIZE,MOUNTPOINT"]),
        10,
    )
    .map(|o| lire_lsblk(&o.sortie))
    .unwrap_or_default()
}

/// Un chemin absolu du système, rattaché à `racine` (les tests passent la leur).
#[cfg(target_os = "linux")]
fn sous(racine: &std::path::Path, chemin: &str) -> PathBuf {
    racine.join(chemin.trim_start_matches('/'))
}

/// Les volumes montés dont le disque est amovible ou branché à chaud. Chaque périphérique compte une fois, à son
/// premier montage entier (racine « / » du système de fichiers, pas un sous-volume Btrfs ni un montage lié) s'il y en
/// a un. Un volume chiffré ou LVM compte quand un des disques dessous est amovible : lsblk ne le disait pas, et une
/// clé chiffrée s'analyse aussi. Description : étiquette et taille, prête à montrer (l'étiquette vient de qui a
/// préparé la clé).
#[cfg(target_os = "linux")]
fn volumes_amovibles_sous(racine: &std::path::Path, mountinfo: &str) -> Vec<(PathBuf, String)> {
    let mut choisis: Vec<(String, PathBuf, bool)> = Vec::new();
    for l in mountinfo.lines() {
        let Some((avant, apres)) = l.split_once(" - ") else {
            continue;
        };
        let champs: Vec<&str> = avant.split(' ').collect();
        let (Some(dedans), Some(point)) = (champs.get(3), champs.get(4)) else {
            continue;
        };
        let Some(source) = apres.split(' ').nth(1).map(crate::copier::sans_echappements) else {
            continue;
        };
        if !source.starts_with("/dev/") {
            continue;
        }
        // /dev/mapper/<nom> et /dev/disk/by-* sont des liens : sysfs connaît le périphérique sous son nom réel.
        let reel = std::fs::canonicalize(sous(racine, &source)).unwrap_or_else(|_| PathBuf::from(&source));
        let Some(nom) = reel.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let entier = *dedans == "/";
        let point = PathBuf::from(crate::copier::sans_echappements(point));
        match choisis.iter_mut().find(|(n, _, _)| *n == nom) {
            Some(c) if entier && !c.2 => *c = (nom, point, true),
            Some(_) => {}
            None => choisis.push((nom, point, entier)),
        }
    }
    choisis
        .into_iter()
        .filter(|(nom, _, _)| bloc_amovible(racine, &sous(racine, "/sys/class/block").join(nom), 0))
        .map(|(nom, point, _)| {
            let octets = std::fs::read_to_string(sous(racine, "/sys/class/block").join(&nom).join("size"))
                .ok()
                .and_then(|t| t.trim().parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(512);
            let taille = taille_lsblk(octets);
            let description = match etiquette(racine, &nom) {
                Some(e) if !e.is_empty() => format!("{e} · {taille}"),
                _ => taille,
            };
            (point, affichable(&description))
        })
        .collect()
}

/// Un périphérique bloc (`/sys/class/block/<nom>`) est-il sur un disque amovible ? Une partition regarde son disque
/// (le dossier parent dans sysfs), un volume device-mapper les périphériques dessous (« slaves »).
#[cfg(target_os = "linux")]
fn bloc_amovible(racine: &std::path::Path, bloc: &std::path::Path, profondeur: u8) -> bool {
    // Une boucle de liens ne doit pas faire tourner sans fin : aucune pile réelle n'a seize étages.
    if profondeur > 16 {
        return false;
    }
    let Ok(reel) = std::fs::canonicalize(bloc) else {
        return false;
    };
    let disque = if reel.join("partition").exists() {
        match reel.parent() {
            Some(p) => p.to_path_buf(),
            None => return false,
        }
    } else {
        reel
    };
    let esclaves: Vec<PathBuf> = std::fs::read_dir(disque.join("slaves"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    if !esclaves.is_empty() {
        return esclaves
            .iter()
            .any(|e| bloc_amovible(racine, e, profondeur.saturating_add(1)));
    }
    std::fs::read_to_string(disque.join("removable")).is_ok_and(|r| r.trim() == "1")
        || branche_a_chaud(racine, &disque.join("device"))
}

/// Branché à chaud, comme le dit lsblk (HOTPLUG) : en remontant le chemin de l'appareil dans /sys/devices, le premier
/// attribut « removable » rencontré dit « removable » (un port USB, un lecteur de cartes) ; « fixed » arrête.
#[cfg(target_os = "linux")]
fn branche_a_chaud(racine: &std::path::Path, appareil: &std::path::Path) -> bool {
    let Ok(chemin) = std::fs::canonicalize(appareil) else {
        return false;
    };
    // Résolu lui aussi : `chemin` l'est, et une racine qui passe par un lien (un dossier de compilation lié vers un
    // autre disque) ne serait jamais son préfixe.
    let devices = std::fs::canonicalize(sous(racine, "/sys/devices")).unwrap_or_else(|_| sous(racine, "/sys/devices"));
    for d in chemin
        .ancestors()
        .take_while(|d| d.starts_with(&devices) && *d != devices)
    {
        match std::fs::read_to_string(d.join("removable")).as_deref().map(str::trim) {
            Ok("removable") => return true,
            Ok("fixed") => return false,
            _ => {}
        }
    }
    false
}

/// L'étiquette du système de fichiers, d'après les liens de /dev/disk/by-label (posés par udev, lisibles par tous).
/// udev y écrit en « \xHH » les octets qui ne vont pas dans un nom de fichier (l'espace : « MA\x20CLE »).
#[cfg(target_os = "linux")]
fn etiquette(racine: &std::path::Path, nom: &str) -> Option<String> {
    std::fs::read_dir(sous(racine, "/dev/disk/by-label"))
        .ok()?
        .flatten()
        .find(|e| {
            std::fs::read_link(e.path())
                .ok()
                .and_then(|c| c.file_name().map(|n| n == std::ffi::OsStr::new(nom)))
                .unwrap_or(false)
        })
        .map(|e| sans_hex(&e.file_name().to_string_lossy()))
}

/// « MA\x20CLE » → « MA CLE » : les octets écrits en hexadécimal, puis le texte relu en UTF-8.
#[cfg(any(target_os = "linux", test))]
fn sans_hex(t: &str) -> String {
    let o = t.as_bytes();
    let mut sortie = Vec::with_capacity(o.len());
    let mut i = 0;
    while let Some(&c) = o.get(i) {
        if c == b'\\'
            && o.get(i.saturating_add(1)) == Some(&b'x')
            && let Some(h) = t
                .get(i.saturating_add(2)..i.saturating_add(4))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            sortie.push(h);
            i = i.saturating_add(4);
        } else {
            sortie.push(c);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8_lossy(&sortie).into_owned()
}

/// Une taille écrite comme lsblk l'écrit : en puissances de 1024, une lettre (« 512B », « 47G », « 28,9G »), un
/// chiffre après la virgule quand il n'est pas nul, arrondi comme util-linux le fait.
#[cfg(any(unix, test))]
fn taille_lsblk(octets: u64) -> String {
    const LETTRES: [&str; 6] = ["K", "M", "G", "T", "P", "E"];
    if octets < 1024 {
        return format!("{octets}B");
    }
    // La plus grande unité (de 2^10 à 2^60) que la taille atteint ; K au moins, puisque `octets` ≥ 1024.
    let Some((exposant, lettre)) = (10..)
        .step_by(10)
        .zip(LETTRES)
        .take_while(|&(e, _)| e == 10 || octets >> e > 0)
        .last()
    else {
        return format!("{octets}B");
    };
    let mut entier = octets >> exposant;
    // Le reste en millièmes de l'unité (tronqués), puis arrondi au dixième.
    let reste = u128::from(octets & (1u64 << exposant).saturating_sub(1));
    let milliemes = u64::try_from((reste * 1000) >> exposant).unwrap_or(0);
    let mut dixiemes = milliemes.saturating_add(50) / 100;
    if dixiemes == 10 {
        entier = entier.saturating_add(1);
        dixiemes = 0;
    }
    if dixiemes == 0 {
        format!("{entier}{lettre}")
    } else {
        let virgule = if crate::langue::anglais() { '.' } else { ',' };
        format!("{entier}{virgule}{dixiemes}{lettre}")
    }
}

/// Lignes de `lsblk -P` : RM="1" HOTPLUG="1" LABEL="CLE" SIZE="28,9G" MOUNTPOINT="/run/media/alice/CLE". La
/// description est prête à montrer (l'étiquette vient de qui a préparé la clé) ; le point de montage reste tel quel,
/// pour l'analyse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_lsblk(texte: &str) -> Vec<(PathBuf, String)> {
    texte
        .lines()
        .filter_map(|l| {
            let champ = |nom: &str| {
                let debut = (l.find(&format!("{nom}=\""))?)
                    .saturating_add(nom.len())
                    .saturating_add(2);
                let fin = l[debut..].find('"')?.saturating_add(debut);
                // lsblk échappe les espaces et caractères spéciaux en \xHH.
                Some(l[debut..fin].replace("\\x20", " "))
            };
            let amovible = champ("RM").as_deref() == Some("1") || champ("HOTPLUG").as_deref() == Some("1");
            let point = champ("MOUNTPOINT").filter(|m| m.starts_with('/'))?;
            amovible.then(|| {
                let nom = champ("LABEL").filter(|n| !n.is_empty());
                let taille = champ("SIZE").unwrap_or_default();
                (
                    PathBuf::from(point),
                    affichable(&nom.map_or(taille.clone(), |n| format!("{n} · {taille}"))),
                )
            })
        })
        .collect()
}

#[cfg(windows)]
fn volumes_amovibles() -> Vec<(PathBuf, String)> {
    let lecteurs = crate::machine::windows::lecteurs::lecteurs();
    if !lecteurs.is_empty() {
        #[allow(clippy::cast_precision_loss)] // une taille en Go, montrée avec une décimale
        return lecteurs
            .into_iter()
            .filter(|l| l.amovible)
            .map(|l| {
                let taille =
                    crate::langue::decimal(crate::socle::nombres::flottant(l.total) / f64::from(1u32 << 30), 1);
                (l.racine, affichable(&format!("{} · {taille} Go", l.etiquette)))
            })
            .collect();
    }
    crate::machine::windows::ps(
        "Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | ForEach-Object { \
         \"$($_.DriveLetter)|$($_.FileSystemLabel)|$([math]::Round($_.Size / 1GB, 1))\" }",
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|l| {
        let mut c = l.trim().splitn(3, '|');
        let lettre = c.next().filter(|x| !x.is_empty())?;
        let nom = c.next().unwrap_or("");
        let taille = c.next().unwrap_or("");
        Some((
            PathBuf::from(format!("{lettre}:\\")),
            affichable(&format!("{nom} · {taille} Go")),
        ))
    })
    .collect()
}

/// Pièges classiques des vers de clé USB, à la racine : raccourci qui imite un dossier (le vrai est caché),
/// lanceur automatique, scripts. `entrees` = (nom, est un dossier).
fn signes_de_ver(entrees: &[(String, bool)]) -> Vec<(Niveau, String)> {
    // La clé de Vanguard a son autorun.inf et son lanceur : rien de suspect.
    if entrees
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(crate::reseau::TEMOIN_CLE))
    {
        return Vec::new();
    }
    let mut signes = Vec::new();
    let dossiers: Vec<String> = entrees
        .iter()
        .filter(|(_, d)| *d)
        .map(|(n, _)| n.to_lowercase())
        .collect();
    for (nom, dossier) in entrees.iter().filter(|(_, d)| !*d) {
        let bas = nom.to_lowercase();
        let (souche, extension) = bas.rsplit_once('.').unwrap_or((&bas, ""));
        if bas == "autorun.inf" {
            signes.push((Niveau::Moyen, trf!(
                "autorun.inf : Windows ne le lance plus tout seul, mais des vers s'en servent encore. À supprimer si vous ne l'avez pas mis.",
                "autorun.inf: Windows no longer runs it by itself, but worms still use it. Delete it if you did not put it there."
            )));
        } else if extension == "lnk" && (dossiers.iter().any(|d| d == souche) || entrees.len() <= 3) && !dossier {
            signes.push((Niveau::Eleve, trf!(
                "« {nom} » : un raccourci qui se fait passer pour un dossier, technique classique d'un ver de clé USB (le vrai dossier est caché, le raccourci lance le ver). N'ouvrez pas ce raccourci.",
                "“{nom}”: a shortcut posing as a folder, a classic USB worm trick (the real folder is hidden, the shortcut runs the worm). Do not open this shortcut."
            )));
        } else if ["vbs", "vbe", "js", "jse", "wsf", "wsh", "scr", "pif", "hta"].contains(&extension) {
            signes.push((Niveau::Eleve, trf!(
                "« {nom} » : script ou programme rarement légitime sur une clé. Ne le lancez pas sans savoir d'où il vient.",
                "“{nom}”: a script or program rarely legitimate on a drive. Do not run it without knowing where it comes from."
            )));
        }
    }
    signes
}

fn revue_cle(racine: &std::path::Path) {
    if !racine.is_dir() {
        return;
    }
    titre(tr!("Pièges de clé USB", "USB drive traps"));
    // Les noms, choisis par qui a rempli la clé, sont seulement montrés : lus prêts à montrer.
    let entrees: Vec<(String, bool)> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| (affichable(&e.file_name().to_string_lossy()), e.path().is_dir()))
        .collect();
    let signes = signes_de_ver(&entrees);
    if signes.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucun raccourci piégé, lanceur automatique ni script suspect à la racine.",
            "  {VERT}✔{RESET} No trapped shortcut, autorun or suspicious script at the root."
        );
    }
    for (n, s) in signes {
        println!("  {}●{RESET} {s}", couleur(n));
    }
}

// ───────────────────────────── Windows : Microsoft Defender ─────────────────────────────

/// Délai de MpCmdRun : jamais avant celui de Defender lui-même, qui arrête une analyse rapide ou personnalisée au
/// bout d'un jour et une complète au bout de sept (documentation de MpCmdRun, option -Timeout). Une analyse complète
/// normale, même de plusieurs heures, va donc au bout ; au-delà, MpCmdRun ne répond plus.
#[cfg(windows)]
const DELAI_MPCMDRUN: u64 = 8 * 24 * 3600;

/// MpCmdRun par un chemin que le compte ne peut pas détourner : la plateforme à jour de Defender, que HKLM nomme
/// (InstallLocation, sous ProgramData\Microsoft\Windows Defender\Platform, écrit par Defender lui-même), sinon la copie
/// de Program Files, dossier demandé à Windows (KnownFolder), jamais à la variable ProgramFiles qu'un `set` change
/// avant de lancer Vanguard. Sa sortie est crue : un faux MpCmdRun qui écrirait « found no threats » donnerait un
/// faux ✔.
#[cfg(windows)]
fn mpcmdrun() -> PathBuf {
    let dossiers = crate::machine::windows::environnement::dossiers();
    let installe: Option<String> = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows Defender")
        .and_then(|k| k.get_value("InstallLocation"))
        .ok();
    let plateforme = installe
        .zip(dossiers.program_data.as_deref().and_then(std::path::Path::to_str))
        .and_then(|(i, d)| plateforme_sure(&i, d))
        .map(|p| PathBuf::from(p).join("MpCmdRun.exe"))
        .filter(|p| p.is_file());
    plateforme.unwrap_or_else(|| match &dossiers.program_files {
        Some(d) => d.join(r"Windows Defender\MpCmdRun.exe"),
        // Repli jamais vu : le chemin par défaut sous le lecteur de Windows, comme le processus élevé.
        None => PathBuf::from(format!(
            r"{}\{}\MpCmdRun.exe",
            crate::commande::lecteur_systeme().unwrap_or("C:"),
            crate::machine::gestes::DOSSIER_DEFENDER
        )),
    })
}

/// Le dossier de plateforme lu dans HKLM, gardé seulement s'il est un dossier direct de
/// `<ProgramData>\Microsoft\Windows Defender\Platform` (« 4.18.24090.11-0 ») : ni « .. », ni autre endroit.
#[cfg(any(windows, test))]
fn plateforme_sure(installe: &str, program_data: &str) -> Option<String> {
    let installe = installe.trim().trim_end_matches('\\');
    let racine = format!(
        r"{}\Microsoft\Windows Defender\Platform\",
        program_data.trim().trim_end_matches('\\')
    );
    let version = installe
        .get(..racine.len())
        .filter(|debut| debut.eq_ignore_ascii_case(&racine))
        .and_then(|_| installe.get(racine.len()..))?;
    (!version.contains(['\\', '/']) && nom_sans_ambiguite(version)).then(|| installe.to_string())
}

/// Pendant une analyse qui peut durer une heure, une ligne par minute : MpCmdRun écrit son compte rendu dans un tube,
/// montré à la fin, et un écran figé invite au Ctrl+C.
#[cfg(windows)]
fn avec_progression<T>(travail: impl FnOnce() -> T) -> T {
    let (fin, attente) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|s| {
        // Refusé (dit par socle::fil) : l'analyse se fait sans le rappel des minutes.
        let _ = crate::socle::fil::dans(s, "progression", move || {
            let mut minutes = 0u64;
            // S'arrête quand `fin` est lâché (Disconnected), le travail fini.
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                attente.recv_timeout(std::time::Duration::from_secs(60))
            {
                minutes += 1;
                trp!(
                    "  {GRIS}… analyse en cours ({minutes} min){RESET}",
                    "  {GRIS}… scan in progress ({minutes} min){RESET}"
                );
            }
        });
        let resultat = travail();
        drop(fin);
        resultat
    })
}

#[cfg(windows)]
fn defender(portee: &Portee) {
    let mpcmd = mpcmdrun();
    if !mpcmd.is_file() {
        trp!(
            "  Defender introuvable (MpCmdRun absent) : rien n'a été analysé.",
            "  Defender not found (MpCmdRun missing): nothing was scanned."
        );
        return;
    }
    trp!(
        "  {GRIS}Moteur : Microsoft Defender. Cela peut prendre de quelques minutes à une heure (analyse complète) ; son compte rendu s'affiche à la fin…{RESET}",
        "  {GRIS}Engine: Microsoft Defender. This can take from a few minutes to an hour (full scan); its report shows at the end…{RESET}"
    );
    let mut commande = Command::new(&mpcmd);
    let cible = match portee {
        Portee::Rapide => {
            commande.args(["-Scan", "-ScanType", "1"]);
            None
        }
        Portee::Complete => {
            commande.args(["-Scan", "-ScanType", "2"]);
            None
        }
        // Analyse personnalisée d'un dossier ou d'une clé.
        Portee::Dossier(d) => {
            commande
                .args(["-Scan", "-ScanType", "3", "-File"])
                .arg(chemin_pour_mpcmdrun(d));
            Some((d.as_path(), true))
        }
    };
    let mut sondes = VraiDefender {
        mpcmd: &mpcmd,
        analyse: commande,
        delai: DELAI_MPCMDRUN,
        progression: true,
    };
    // La sortie est lue, pas seulement le code : MpCmdRun rend 0 aussi quand il a trouvé une menace et l'a retirée.
    let Some(analyse) = analyse_confirmee(&mut sondes, cible, &mut Memoire::default()) else {
        trp!(
            "  Defender n'a pas pu aller au bout de l'analyse (antivirus tiers actif ?).",
            "  Defender could not finish the scan (third-party antivirus active?)."
        );
        return;
    };
    // Son compte rendu, tel qu'il l'a écrit : le chemin y vient de qui a nommé le dossier, d'où `affichable`.
    for l in analyse.sortie.lines().filter(|l| !propre(l).is_empty()) {
        println!("  {GRIS}{}{RESET}", affichable(l.trim_end()));
    }
    let (verdict, detections) = (analyse.verdict, analyse.detections);
    let attention = |texte: &str| println!("  {}● {texte}{RESET}", couleur(Niveau::Moyen));
    match verdict {
        Verdict::Sain => trp!(
            "  {VERT}✔ Aucun malware trouvé.{RESET}",
            "  {VERT}✔ No malware found.{RESET}"
        ),
        Verdict::Menaces(noms) => montrer_menaces_defender(&noms, &detections),
        Verdict::Sautee => attention(tr!(
            "Defender a sauté ce qu'il devait analyser : exclu de l'analyse, ce qui est suspect si personne ne l'a voulu. Rien n'est garanti.",
            "Defender skipped what it had to scan: excluded from scanning, which is suspicious if nobody meant it. Nothing is guaranteed."
        )),
        Verdict::Exclue(exclusions) => {
            let liste = resume(&exclusions, 4, ", ");
            attention(&trf!(
                "Defender dit n'avoir rien trouvé, mais ses exclusions couvrent, en tout ou en partie, ce qu'il devait analyser : {liste}. Ce qui en relève n'a pas été regardé, ce qui est suspect si personne ne l'a voulu. Rien n'est garanti.",
                "Defender says it found nothing, but its exclusions cover, wholly or partly, what it had to scan: {liste}. Whatever falls under them was not looked at, which is suspicious if nobody meant it. Nothing is guaranteed."
            ));
        }
        Verdict::Inverifiable => {
            attention(tr!(
                "Defender dit n'avoir rien trouvé, mais Vanguard n'a pas pu lire ses exclusions ou ses détections pour le confirmer : rien ne garantit qu'il a tout regardé. Ses détections restent dans Sécurité Windows > Protection contre les virus et menaces > Historique de protection.",
                "Defender says it found nothing, but Vanguard could not read its exclusions or detections to confirm it: nothing guarantees it looked at everything. Its detections remain in Windows Security > Virus & threat protection > Protection history."
            ));
            if analyse.sans_droits {
                prevenir_sans_droits();
            }
            if analyse.cachees_a_l_admin {
                prevenir_cachees_a_l_admin();
            }
        }
        // Pas de « ✔ » sans la phrase de résultat : la sortie d'une analyse rapide ou complète n'est pas documentée.
        Verdict::Muette => trp!(
            "  Defender a fini (code 0, qui veut aussi dire « menace trouvée et retirée »), mais son compte rendu n'a pas été reconnu : rien n'est conclu. Ses détections restent dans Sécurité Windows > Protection contre les virus et menaces > Historique de protection.",
            "  Defender finished (code 0, which also means “threat found and removed”), but its report was not recognized: nothing is concluded. Its detections remain in Windows Security > Virus & threat protection > Protection history."
        ),
        Verdict::Echec => trp!(
            "  Defender n'a pas pu lancer l'analyse (antivirus tiers actif ?).",
            "  Defender could not start the scan (third-party antivirus active?)."
        ),
    }
}

/// Defender a trouvé des menaces (code 2, ou code 0 avec une menace retirée) : celles de CETTE analyse (détections
/// notées depuis son début, sous ce qu'elle regardait), jamais tout l'historique de Defender, puis la proposition de
/// les supprimer. `noms` : ceux de la sortie de MpCmdRun, montrés si Windows n'a rien noté de lisible.
#[cfg(windows)]
fn montrer_menaces_defender(noms: &[String], detections: &[Detection]) {
    // Jamais une liste vide sous une menace trouvée : les noms de MpCmdRun (déjà prêts à montrer), sinon une ligne.
    let lignes: Vec<(String, String)> = if !detections.is_empty() {
        detections
            .iter()
            .map(|d| {
                let fichiers: Vec<String> = d
                    .ressources
                    .iter()
                    .map(|r| affichable(chemin_de_ressource(r)))
                    .collect();
                (d.nom.clone(), resume(&fichiers, 3, ", "))
            })
            .collect()
    } else if !noms.is_empty() {
        noms.iter().map(|n| (n.clone(), String::new())).collect()
    } else {
        vec![(
            tr!(
                "menace signalée par Defender (voir son compte rendu ci-dessus)",
                "threat reported by Defender (see its report above)"
            )
            .to_string(),
            String::new(),
        )]
    };
    for (nom, fichiers) in lignes {
        println!("  {}✖ {nom}{RESET}  {fichiers}", couleur(Niveau::Critique));
    }
    trp!(
        "  Defender a normalement déjà mis ces fichiers en quarantaine.",
        "  Defender has normally already quarantined these files."
    );
    if demander(tr!(
        "  Supprimer définitivement les menaces détectées ? [o/N] : ",
        "  Permanently delete the detected threats? [y/N]: "
    ))
    .oui()
        // Par Vanguard administrateur, comme toute correction (une seule forme de demande d'administrateur),
        // sans note : rien à défaire.
        && crate::machine::appliquer_sans_noter(&[crate::machine::gestes::ligne_defender_menaces_retirer()]).0
    {
        // Réussi veut dire « plus aucune menace active, relu » : soit retirées, soit déjà toutes en quarantaine.
        // L'historique des détections montré plus haut peut n'en avoir aucune d'active : jamais « supprimées »
        // pour ce cas.
        trp!(
            "  {VERT}✔ Defender ne garde plus aucune menace active (relu).{RESET}",
            "  {VERT}✔ Defender no longer holds any active threat (read back).{RESET}"
        );
    }
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat de Defender, qui met lui-même en
/// quarantaine ce qu'il reconnaît.
#[cfg(windows)]
pub(crate) fn examiner(fichier: &std::path::Path) -> Examen {
    examiner_avec(fichier, &mut Memoire::default())
}

/// Un examinateur pour une série de fichiers (les pièces d'un courriel) : les exclusions lues une fois avant la
/// série puis réunies, et ce que Windows refuse de montrer retenu au lieu d'être redemandé à chaque pièce.
#[cfg(windows)]
pub(crate) fn examinateur() -> impl FnMut(&std::path::Path) -> Examen {
    let mut memoire = Memoire::default();
    move |fichier: &std::path::Path| examiner_avec(fichier, &mut memoire)
}

/// `examiner` avec ce qui a déjà été lu pour la même série (`memoire`).
#[cfg(windows)]
fn examiner_avec(fichier: &std::path::Path, memoire: &mut Memoire) -> Examen {
    let mpcmd = mpcmdrun();
    if !mpcmd.is_file() {
        return Examen::Impossible(raison_absent().into());
    }
    let mut analyse = Command::new(&mpcmd);
    analyse
        .args(["-Scan", "-ScanType", "3", "-File"])
        .arg(chemin_pour_mpcmdrun(fichier));
    let mut sondes = VraiDefender {
        mpcmd: &mpcmd,
        analyse,
        delai: 900,
        progression: false,
    };
    let Some(a) = analyse_confirmee(&mut sondes, Some((fichier, false)), memoire) else {
        return Examen::Impossible(raison_injoignable().into());
    };
    if a.sans_droits {
        prevenir_sans_droits();
    }
    if a.cachees_a_l_admin {
        prevenir_cachees_a_l_admin();
    }
    examen_de(a.verdict, &a.sortie, std::fs::symlink_metadata(fichier).is_ok())
}

/// Sans droits administrateur, dit une seule fois par lancement (pas à chaque pièce d'un courriel) pourquoi les
/// « rien trouvé » de Defender restent invérifiables, et comment avoir un verdict complet.
#[cfg(windows)]
fn prevenir_sans_droits() {
    static DIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !DIT.swap(true, std::sync::atomic::Ordering::Relaxed) {
        println!(
            "  {}● {}{RESET}",
            couleur(Niveau::Moyen),
            tr!(
                "Sans droits administrateur, Windows cache à Vanguard les exclusions de Defender (et parfois ses détections) : ses « rien trouvé » ne peuvent pas être confirmés et restent « impossibles à vérifier ». Pour un verdict complet, relancez Vanguard en administrateur (clic droit > Exécuter en tant qu'administrateur).",
                "Without administrator rights, Windows hides Defender's exclusions (and sometimes its detections) from Vanguard: its “nothing found” cannot be confirmed and stays “impossible to verify”. For a full verdict, run Vanguard as administrator (right-click > Run as administrator)."
            )
        );
    }
}

/// Les politiques de Defender qui cachent ses exclusions (HideExclusionsFromLocalAdmins, HideExclusionsFromLocalUsers,
/// propriétés de MSFT_MpPreference) : vraies seulement lues vraies, fausses si ce Windows ne les a pas. Ici et non
/// dans `machine::windows::exclusions`, qui les lit : les essais du double les jouent aussi sous Linux.
#[cfg(any(windows, test))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Politiques {
    /// Cachées même à un administrateur ; d'après Microsoft, elle cache aussi aux utilisateurs.
    pub(crate) aux_admins: bool,
    /// Cachées aux comptes sans droits administrateur.
    pub(crate) aux_utilisateurs: bool,
}

/// Windows cache les exclusions même à l'administrateur (une politique, sans doute : rien ne la nomme sûrement quand
/// elle est lue fausse ou absente, relecture des correctifs T10, 4e passe, BAS-2) : dit une seule fois par lancement pourquoi les « rien
/// trouvé » de Defender restent invérifiables et quoi vérifier. Pas de « relancez en administrateur » : rien n'y
/// changerait.
#[cfg(windows)]
fn prevenir_cachees_a_l_admin() {
    static DIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !DIT.swap(true, std::sync::atomic::Ordering::Relaxed) {
        println!(
            "  {}● {}{RESET}",
            couleur(Niveau::Moyen),
            tr!(
                "Windows cache les exclusions de Defender même à l'administrateur, sans doute par une politique (HideExclusionsFromLocalAdmins) : ses « rien trouvé » ne peuvent pas être confirmés. Une entreprise la pose parfois sur ses ordinateurs ; sur un ordinateur personnel, personne n'a de raison de le faire, et elle peut servir à cacher un dossier exclu par un programme malveillant. À vérifier : Paramètres > Comptes > Accès Professionnel ou Scolaire (l'ordinateur est-il géré par une organisation ?). Sinon, faites vérifier l'ordinateur.",
                "Windows hides Defender's exclusions even from the administrator, probably through a policy (HideExclusionsFromLocalAdmins): its “nothing found” cannot be confirmed. Companies sometimes set it on their computers; on a personal computer nobody has a reason to, and it can be used to hide a folder excluded by malware. To check: Settings > Accounts > Access work or school (is the computer managed by an organization?). If not, have the computer checked."
            )
        );
    }
}

/// Ce que Vanguard demande à Defender autour d'une analyse, dans l'ordre d'`analyse_confirmee` : sous Windows,
/// `VraiDefender` ; dans les essais, un double qui joue la séquence entière sans Windows.
#[cfg(any(windows, test))]
trait Sondes {
    /// Les exclusions de chemin et d'extension, telles que lues (« N/A: Must be an administrator… » sans droits
    /// administrateur), et les politiques qui les cachent, lues dans la même requête ; `None` si ni WMI ni
    /// PowerShell ne répondent.
    fn exclusions(&mut self) -> Option<([Vec<String>; 2], Politiques)>;
    /// `MpCmdRun -CheckExclusion -Path <cible>` (`exclusion_selon_mpcmdrun`) : le moteur lui-même, à cet instant.
    fn cible_exclue(&mut self, cible: &std::path::Path) -> Option<bool>;
    /// L'analyse : son code et sa sortie (erreurs comprises) ; `None` si MpCmdRun n'a pas pu aller au bout.
    fn analyser(&mut self) -> Option<(Option<i32>, String)>;
    /// Toutes les détections notées par Defender ; `None` si illisibles.
    fn detections(&mut self) -> Option<Vec<Detection>>;
    /// L'heure du début de l'analyse, en temps universel.
    fn maintenant(&self) -> chrono::NaiveDateTime;
    /// Vanguard a-t-il les droits administrateur ?
    fn eleve(&self) -> bool;
    /// Les variables d'environnement qu'une exclusion peut contenir, avec leurs valeurs (`variables_de_defender`).
    fn variables(&self) -> Vec<(&'static str, Vec<String>)>;
}

/// Defender pour de vrai : MpCmdRun (le chemin sûr de `mpcmdrun`), WMI ou PowerShell.
#[cfg(windows)]
struct VraiDefender<'a> {
    mpcmd: &'a std::path::Path,
    /// La commande d'analyse, prête.
    analyse: Command,
    delai: u64,
    /// Une ligne par minute pendant l'analyse (une analyse de dossier, pas un fichier).
    progression: bool,
}

#[cfg(windows)]
impl Sondes for VraiDefender<'_> {
    fn exclusions(&mut self) -> Option<([Vec<String>; 2], Politiques)> {
        crate::machine::windows::exclusions::lecture()
            .map(|([chemins, _, extensions], politiques)| ([chemins, extensions], politiques))
    }

    fn cible_exclue(&mut self, cible: &std::path::Path) -> Option<bool> {
        let r = crate::commande::lancer(
            Command::new(self.mpcmd)
                .args(["-CheckExclusion", "-Path"])
                .arg(chemin_pour_mpcmdrun(cible)),
            60,
        )?;
        exclusion_selon_mpcmdrun(r.code, &format!("{}\n{}", r.sortie, r.erreurs))
    }

    fn analyser(&mut self) -> Option<(Option<i32>, String)> {
        let (commande, delai) = (&mut self.analyse, self.delai);
        let r = if self.progression {
            avec_progression(|| crate::commande::lancer(commande, delai))
        } else {
            crate::commande::lancer(commande, delai)
        }?;
        // La même lecture partout : sortie et erreurs.
        Some((r.code, format!("{}\n{}", r.sortie, r.erreurs)))
    }

    fn detections(&mut self) -> Option<Vec<Detection>> {
        detections_de_defender()
    }

    fn maintenant(&self) -> chrono::NaiveDateTime {
        chrono::Utc::now().naive_utc()
    }

    fn eleve(&self) -> bool {
        crate::machine::windows::processus::eleve()
    }

    fn variables(&self) -> Vec<(&'static str, Vec<String>)> {
        let d = crate::machine::windows::environnement::dossiers();
        let texte = |p: Option<&'static PathBuf>| p.and_then(|p| p.to_str());
        variables_de_defender(&Racines {
            windows: d.windows.to_str().filter(|w| !w.is_empty()),
            program_files: texte(d.program_files.as_ref()),
            program_files_x86: texte(d.program_files_x86.as_ref()),
            communs: texte(d.fichiers_communs.as_ref()),
            program_data: texte(d.program_data.as_ref()),
            profil: texte(d.profil.as_ref()),
            appdata: texte(d.appdata.as_ref()),
            local: texte(d.appdata_local.as_ref()),
        })
    }
}

/// Ce qui ne se relit pas à chaque fichier d'une même série (les pièces d'un courriel) : les exclusions vues, et ce
/// que Windows refuse de montrer, qui ne change pas tant que Vanguard tourne.
#[cfg(any(windows, test))]
#[derive(Default)]
struct Memoire {
    /// Chemins et extensions exclus, réunis sur toutes les lectures : une exclusion vue avant une analyse puis retirée
    /// pendant couvre encore son résultat (Defender peut l'appliquer encore quelques secondes : passe 5 de l'essai
    /// T10).
    vues: [Vec<String>; 2],
    exclusions: Lecture,
    /// Cachées même à un administrateur (Vanguard élevé qui lit « N/A » ou des listes vides sous une politique, ou
    /// HideExclusionsFromLocalAdmins posée) : relancer en administrateur n'y changerait rien.
    cachees_a_l_admin: bool,
    /// Détections illisibles : pas relues.
    detections_illisibles: bool,
}

/// Où en est la lecture des exclusions d'une série.
#[cfg(any(windows, test))]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Lecture {
    #[default]
    PasEncore,
    Lues,
    /// Cachées : toujours sans droits administrateur ; élevé, « N/A » ou HideExclusionsFromLocalAdmins posée
    /// (`Memoire::lire`). Pas relues.
    Cachees,
    /// Illisibles (ni WMI ni PowerShell) : pas relues.
    Illisibles,
}

#[cfg(any(windows, test))]
impl Memoire {
    /// Lit les exclusions et les ajoute à celles déjà vues ; rien si Windows les a déjà refusées.
    fn lire(&mut self, sondes: &mut impl Sondes) {
        if matches!(self.exclusions, Lecture::Cachees | Lecture::Illisibles) {
            return;
        }
        let eleve = sondes.eleve();
        let Some((listes, politiques)) = sondes.exclusions() else {
            self.exclusions = Lecture::Illisibles;
            return;
        };
        // Sans élévation, toujours cachées, quoi qu'on lise : un Windows récent ne les montre jamais à un compte sans
        // droits, et son refus peut prendre une forme que rien ne reconnaît sûrement (listes vides ou nulles, « N/A »
        // traduit : « N/D : … » sur un Windows français ; relecture des correctifs T10, 4e passe, BAS-4). Élevé, la
        // politique des administrateurs (celle des utilisateurs laisse voir l'administrateur) peut les cacher sous une
        // autre forme que « N/A » (vides, nulles : Microsoft ne dit pas laquelle) : rien n'y prouve l'absence
        // d'exclusion.
        // Un refus se reconnaît à « N/A », ou, sans ce préfixe (traduit, autre forme), à une phrase : des espaces
        // dans un texte qui n'a rien d'un chemin (ni « \\ » ni « / »). Une extension n'a pas d'espace ; un tel texte
        // pris pour une exclusion pourrait donner un ✔ à tort pour un fichier (relecture des correctifs T10,
        // 5e passe, BAS-1).
        let refusees = listes.iter().flatten().any(|x| ressemble_a_un_refus(x));
        if !eleve || politiques.aux_admins || refusees {
            self.exclusions = Lecture::Cachees;
            self.cachees_a_l_admin = eleve || politiques.aux_admins;
            // Rien de cette lecture n'entre dans les vues : sous un refus, un texte n'est pas une exclusion (4e passe,
            // BAS-3). Celles vues à une lecture précédente restent : elles couvrent encore le résultat.
            return;
        }
        self.exclusions = Lecture::Lues;
        // Jamais un texte blanc : ni chemin ni extension (une extension blanche se lirait « *. » et couvrirait tout
        // fichier ; 4e passe, BAS-5).
        for (vues, liste) in self.vues.iter_mut().zip(listes) {
            for x in liste {
                if !x.trim().is_empty() && !vues.contains(&x) {
                    vues.push(x);
                }
            }
        }
    }

    /// Les exclusions vues, réunies, et si elles sont complètes (aucune lecture refusée ni échouée). Une lecture qui
    /// échoue ou se cache après une réussite n'efface pas ce qui a été vu : une exclusion vue avant l'analyse couvre
    /// encore son résultat.
    fn listes(&self) -> (&[Vec<String>; 2], bool) {
        (&self.vues, self.exclusions == Lecture::Lues)
    }
}

/// Un texte des listes d'exclusions qui est un refus de Windows et non une exclusion (voir `Memoire::lire`).
#[cfg(any(windows, test))]
fn ressemble_a_un_refus(x: &str) -> bool {
    let x = x.trim();
    x.starts_with("N/A") || (x.contains(char::is_whitespace) && !x.contains(['\\', '/']))
}

/// Une analyse confirmée auprès de Defender.
#[cfg(any(windows, test))]
struct Analyse {
    verdict: Verdict,
    /// Les détections de cette analyse, à montrer.
    detections: Vec<Detection>,
    /// Ce qu'a écrit MpCmdRun (sortie et erreurs).
    sortie: String,
    /// Invérifiable faute de droits administrateur : relancer Vanguard en administrateur donnerait un verdict.
    sans_droits: bool,
    /// Invérifiable parce qu'une politique cache les exclusions même à l'administrateur : relancer n'y changerait rien.
    cachees_a_l_admin: bool,
}

/// Une analyse de Defender, de bout en bout. Avant : les exclusions (une fois par série) et, pour une cible lisible,
/// `MpCmdRun -CheckExclusion` à cet instant. Puis l'analyse, lue par `lire_reponse`, et les détections notées depuis
/// son début. Un « sain » n'en reste un que confronté aux exclusions relues après l'analyse et réunies à celles d'avant
/// (une exclusion retirée juste avant l'analyse peut encore jouer, une autre peut être posée pendant), puis à
/// `confirmer`. `cible` : `(chemin, est un dossier)`, `None` pour une analyse rapide ou complète. `None` si MpCmdRun
/// n'a pas pu aller au bout.
#[cfg(any(windows, test))]
fn analyse_confirmee(
    sondes: &mut impl Sondes,
    cible: Option<(&std::path::Path, bool)>,
    memoire: &mut Memoire,
) -> Option<Analyse> {
    // Un chemin illisible en Unicode ne se compare pas : piégé, et toutes les détections de l'analyse comptent (fausse
    // alerte plutôt que silence).
    let texte = cible.and_then(|(c, _)| c.to_str());
    let piegee = cible.is_some() && texte.is_none_or(|t| t.chars().any(char::is_control));
    if memoire.exclusions == Lecture::PasEncore {
        memoire.lire(sondes);
    }
    // `-CheckExclusion` ne compte plus que pour « exclue » (`couverture`) ; inutile quand une exclusion déjà vue
    // couvre la cible : les vues ne font que grandir, un « sain » deviendra « exclue » de toute façon (seule la
    // cible ne s'ajoute pas à la liste montrée, sous l'exclusion qui la couvre). Un lancement de MpCmdRun de moins par
    // pièce d'un courriel sous un dossier exclu.
    let deja_couverte = !piegee
        && memoire.vues.iter().any(|v| !v.is_empty())
        && texte.zip(cible).is_some_and(|(t, (_, dossier))| {
            let [chemins, extensions] = &memoire.vues;
            !exclusions_qui_couvrent(t, dossier, chemins, extensions, &sondes.variables()).is_empty()
        });
    let verification = match cible {
        Some((c, _)) if !piegee && !deja_couverte => sondes.cible_exclue(c),
        _ => None,
    };
    let debut = sondes.maintenant();
    let (code, sortie) = sondes.analyser()?;
    let verdict = lire_reponse(code, &sortie);
    let detections = if memoire.detections_illisibles {
        None
    } else {
        let toutes = sondes.detections();
        memoire.detections_illisibles = toutes.is_none();
        toutes.and_then(|t| de_cette_analyse(t, debut, texte))
    };
    // Rien à confirmer : `confirmer` ne regarde les exclusions que pour un « sain » sans détection, d'une cible lisible
    // ou sans cible.
    let exclusions = if verdict != Verdict::Sain || piegee || detections.as_ref().is_some_and(|d| !d.is_empty()) {
        Some(Vec::new())
    } else {
        memoire.lire(sondes);
        let cible = cible.and_then(|(_, dossier)| texte.map(|t| (t, dossier)));
        couverture(cible, verification, memoire.listes(), &sondes.variables())
    };
    let verdict = confirmer(verdict, detections.as_deref(), exclusions, piegee);
    // Relancer en administrateur n'aide pas quand ni WMI ni PowerShell ne répondent (antivirus tiers), ni quand une
    // politique cache les exclusions même à l'administrateur (déjà élevé, ou HideExclusionsFromLocalAdmins).
    let inverifiable = verdict == Verdict::Inverifiable;
    let cachees = memoire.exclusions == Lecture::Cachees;
    let cachees_a_l_admin = inverifiable && cachees && memoire.cachees_a_l_admin;
    let sans_droits =
        inverifiable && !sondes.eleve() && memoire.exclusions != Lecture::Illisibles && !memoire.cachees_a_l_admin;
    Some(Analyse {
        verdict,
        detections: detections.unwrap_or_default(),
        sortie,
        sans_droits,
        cachees_a_l_admin,
    })
}

/// Les exclusions qui couvrent ce qu'une analyse devait regarder, prêtes à montrer ; `None` si rien ne permet de le
/// savoir. `listes` : les exclusions vues (`Memoire::listes`), et si elles sont complètes. Sans cible (analyse rapide
/// ou complète) : toute exclusion de chemin ou d'extension, qui en retire forcément une partie. Pour une cible : celles
/// de `exclusions_qui_couvrent`, et la cible elle-même quand MpCmdRun la dit exclue (`verification`). Listes
/// incomplètes (cachées ou illisibles à l'une des lectures) : ce qui a été vu et MpCmdRun peuvent prouver une
/// exclusion, jamais son absence.
#[cfg(any(windows, test))]
fn couverture(
    cible: Option<(&str, bool)>,
    verification: Option<bool>,
    (vues, completes): (&[Vec<String>; 2], bool),
    variables: &[(&str, Vec<String>)],
) -> Option<Vec<String>> {
    let [chemins, extensions] = vues;
    let Some((cible, dossier)) = cible else {
        let chemins = chemins
            .iter()
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .map(affichable);
        let extensions = extensions
            .iter()
            .filter(|e| !e.trim().is_empty())
            .map(|e| extension_montree(e));
        let toutes: Vec<String> = chemins.chain(extensions).collect();
        return (completes || !toutes.is_empty()).then_some(toutes);
    };
    let mut couvrent = exclusions_qui_couvrent(cible, dossier, chemins, extensions, variables);
    if verification == Some(true) {
        // Pas deux fois : une exclusion déjà montrée qui est la cible elle-même.
        let montree = sans_verbatim(cible).unwrap_or_else(|| cible.to_string());
        let c = pour_comparer(&montree);
        if !couvrent.iter().any(|x| pour_comparer(x) == c) {
            couvrent.insert(0, affichable(&montree));
        }
    }
    // Sans listes complètes, un « non exclue » de MpCmdRun ne suffit pas, même pour un fichier : rien ne prouve qu'il
    // tienne compte des extensions exclues (et pour un dossier, il ne voit ni ses sous-dossiers ni ses extensions
    // exclus). À rouvrir pour un fichier si l'essai en VM montre que `-CheckExclusion -Path C:\x\a.test` répond
    // « excluded » avec la seule exclusion d'extension `.test`.
    (completes || !couvrent.is_empty()).then_some(couvrent)
}

/// La réponse de `MpCmdRun -CheckExclusion -Path` (documentation de Microsoft) : « C:\x [\Device\…\x] is excluded.
/// Exit code is 0. » ou « … is not excluded. Exit code is 1. ». Seule la fin de la ligne compte : le chemin, devant,
/// vient de qui a nommé le fichier. Une ligne « excluded » suffit (prudence) ; « non exclue » demande que toutes les
/// lignes de résultat le disent et le code 1. `None` pour toute autre réponse (refus sans droits, plateforme d'avant
/// décembre 2021, format inconnu).
#[cfg(any(windows, test))]
fn exclusion_selon_mpcmdrun(code: Option<i32>, sortie: &str) -> Option<bool> {
    let resultats: Vec<bool> = sortie
        .lines()
        .map(propre)
        .filter_map(|l| {
            let l = l
                .strip_suffix(" Exit code is 0.")
                .or_else(|| l.strip_suffix(" Exit code is 1."))
                .unwrap_or(l)
                .trim_end();
            if l.ends_with(" is not excluded.") {
                Some(false)
            } else if l.ends_with(" is excluded.") {
                Some(true)
            } else {
                None
            }
        })
        .collect();
    if resultats.contains(&true) {
        Some(true)
    } else if !resultats.is_empty() && code == Some(1) {
        Some(false)
    } else {
        None
    }
}

/// Ce que dit une réponse de MpCmdRun, lue une seule fois pour l'analyse (`defender`) et pour un fichier (`examiner`).
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Une ligne de résultat, « found no threats. » (ou 0), avec le code 0, rien qui signale une menace, et (après
    /// `confirmer`) ni exclusion qui couvre la cible ni détection de Defender pendant l'analyse.
    Sain,
    /// Une menace, quel que soit le code : ses noms quand MpCmdRun les écrit ou que Defender les a notés (vide sinon).
    Menaces(Vec<String>),
    /// « Scanning <chemin> was skipped. » : exclu de Defender, rien d'analysé.
    Sautee,
    /// « Rien trouvé », mais des exclusions de Defender couvrent la cible (ou un parent, ou son extension) : elles,
    /// prêtes à montrer.
    Exclue(Vec<String>),
    /// « Rien trouvé », sans que les exclusions ou les détections de Defender aient pu être lues pour le confirmer.
    Inverifiable,
    /// Code 0 sans compte rendu reconnu : rien ne garantit que l'analyse a regardé quelque chose.
    Muette,
    /// Ni 0 ni 2 (ou arrêté), sans menace écrite : l'analyse n'a pas eu lieu.
    Echec,
}

/// Une ligne de MpCmdRun sans espaces autour ni BOM en tête (U+FEFF, que `trim` garde) : un BOM devant la première
/// ligne la ferait ignorer.
#[cfg(any(windows, test))]
fn propre(ligne: &str) -> &str {
    ligne.trim().trim_start_matches('\u{feff}').trim_start()
}

/// Fausse alerte plutôt que silence. MpCmdRun rend 0 pour « aucune menace » mais aussi pour « menace trouvée et
/// retirée » (sa documentation, et vu dans une machine virtuelle : « found 1 threats. », code 0), et 2 pour une menace
/// restée ou une erreur d'analyse : le code seul ne suffit pas. Une ligne « found N threats. » avec N > 0, ou une
/// ligne « Threat : … », est donc une menace quel que soit le code. Le code 0 ne vaut « sain » qu'avec une ligne de
/// résultat qui le dit et aucune ligne d'un format inconnu ; sans elle (sortie vide, ou dans un format inconnu), la
/// réponse est « muette », jamais saine. Le code 2 sans menace écrite reste une menace, sauf le fichier sauté (« was
/// skipped »), reconnu en fin de ligne. Ce « sain » n'est que la phrase de MpCmdRun : `confirmer` le confronte ensuite
/// aux exclusions et aux détections de Defender (la passe 5 de l'essai T10 a écrit « found no threats » sur un
/// dossier où EICAR était encore).
#[cfg(any(windows, test))]
fn lire_reponse(code: Option<i32>, sortie: &str) -> Verdict {
    let lignes: Vec<&str> = sortie.lines().map(propre).filter(|l| !l.is_empty()).collect();
    let noms = menaces_mpcmdrun(sortie);
    let comptes: Vec<u64> = lignes.iter().filter_map(|l| compte_de_menaces(l)).collect();
    // « b found 1 threats. » sans « Scanning » devant : la fin d'une ligne de résultat coupée par un saut de ligne dans
    // le nom de la cible. Une menace si son compte en dit une ; jamais une raison de dire « sain ».
    let orphelins: Vec<u64> = lignes.iter().filter_map(|l| compte_orphelin(l)).collect();
    if !noms.is_empty() || comptes.iter().chain(&orphelins).any(|&n| n > 0) {
        return Verdict::Menaces(noms);
    }
    // La phrase n'est reconnue qu'en fin de ligne, où Windows ne laisse finir aucun nom (ni point ni espace final) :
    // « facture was skipped.exe » n'en est pas une.
    let est_saut = |l: &str| l.starts_with("Scanning ") && l.ends_with(" was skipped.");
    let saute = lignes.iter().any(|l| est_saut(l));
    // Une ligne « Scanning … » qui n'est ni un compte lu ni un saut : un format inconnu, peut-être une menace.
    let inconnue = !orphelins.is_empty()
        || lignes
            .iter()
            .any(|l| l.starts_with("Scanning") && compte_de_menaces(l).is_none() && !est_saut(l));
    match code {
        Some(0 | 2) if saute => Verdict::Sautee,
        Some(0) if !comptes.is_empty() && !inconnue => Verdict::Sain,
        Some(0) => Verdict::Muette,
        Some(2) => Verdict::Menaces(Vec::new()),
        _ => Verdict::Echec,
    }
}

/// Le compte d'une ligne de résultat de MpCmdRun, « Scanning <chemin> found N threats. » (« found no threats. » :
/// 0 ; une analyse rapide ou complète l'écrit peut-être sans chemin) ; `None` pour toute autre ligne. Le chemin est
/// choisi par qui a nommé le fichier ou le dossier (« x found no threats ») : seule la fin de la ligne compte, écrite
/// par MpCmdRun après le nom. Un compte qui ne se lit pas (« found many threats. », nombre trop grand) vaut une
/// menace.
#[cfg(any(windows, test))]
fn compte_de_menaces(ligne: &str) -> Option<u64> {
    let reste = propre(ligne).strip_prefix("Scanning")?;
    if !reste.starts_with(' ') {
        return None;
    }
    let avant = reste
        .strip_suffix(" threats.")
        .or_else(|| reste.strip_suffix(" threat."))?;
    Some(match avant.rsplit_once(" found ").map(|(_, n)| n) {
        Some("no") => 0,
        Some(n) => n.parse().unwrap_or(1),
        None => 1,
    })
}

/// Le compte d'une ligne qui finit comme une ligne de résultat (« … found N threats. ») sans commencer par
/// « Scanning » ; `None` pour toute autre.
#[cfg(any(windows, test))]
fn compte_orphelin(ligne: &str) -> Option<u64> {
    let ligne = propre(ligne);
    if ligne.starts_with("Scanning") {
        return None;
    }
    let avant = ligne
        .strip_suffix(" threats.")
        .or_else(|| ligne.strip_suffix(" threat."))?;
    let (_, n) = avant.rsplit_once(" found ")?;
    Some(if n == "no" { 0 } else { n.parse().unwrap_or(1) })
}

/// Une détection de Defender (MSFT_MpThreatDetection), telle que lue.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Detection {
    /// Le nom de la menace (MSFT_MpThreat.ThreatName), prêt à montrer.
    nom: String,
    /// InitialDetectionTime et LastThreatStatusChangeTime, dates CIM (« 20261031154900.000000-240 »).
    dates: Vec<String>,
    /// Resources, tels que lus (« file:_C:\…\eicar.com ») : le chemin vient de qui a nommé le fichier.
    ressources: Vec<String>,
}

/// Une date CIM (« aaaammjjhhmmss.mmmmmm±UUU », décalage en minutes) en temps universel ; `None` si elle ne se lit
/// pas.
#[cfg(any(windows, test))]
fn date_cim(date: &str) -> Option<chrono::NaiveDateTime> {
    let date = date.trim();
    let locale = chrono::NaiveDateTime::parse_from_str(date.get(..14)?, "%Y%m%d%H%M%S").ok()?;
    let decalage: i64 = date.get(21..)?.parse().ok()?;
    locale.checked_sub_signed(chrono::Duration::minutes(decalage))
}

/// Le chemin d'une ressource de détection : « file:_C:\x\a.exe » → « C:\x\a.exe », « containerfile:_C:\x.zip->b.exe »
/// → « C:\x.zip » (un fichier dans une archive : l'archive). Seule une ressource d'archive est coupée à « -> » : un
/// chemin de fichier peut en contenir un (nom posé hors de Win32, par WSL ou l'API native). Inchangée sans préfixe.
#[cfg(any(windows, test))]
fn chemin_de_ressource(ressource: &str) -> &str {
    match ressource.split_once(":_") {
        Some((sorte, chemin)) if sorte.eq_ignore_ascii_case("containerfile") => {
            chemin.split("->").next().unwrap_or(chemin)
        }
        Some((sorte, chemin)) if !sorte.is_empty() && sorte.chars().all(|c| c.is_ascii_alphanumeric()) => chemin,
        _ => ressource,
    }
}

/// La ressource d'une détection est-elle `cible`, ou dedans ? Pour une archive, chaque coupe à un « -> » est essayée,
/// et le chemin entier : l'archive peut être dans un dossier dont le nom contient « -> ».
#[cfg(any(windows, test))]
fn ressource_sous_cible(ressource: &str, cible: &str) -> bool {
    if sous_cible(chemin_de_ressource(ressource), cible) {
        return true;
    }
    let Some((sorte, chemin)) = ressource.split_once(":_") else {
        return false;
    };
    sorte.eq_ignore_ascii_case("containerfile")
        && (sous_cible(chemin, cible)
            || chemin
                .match_indices("->")
                .any(|(i, _)| chemin.get(..i).is_some_and(|avant| sous_cible(avant, cible))))
}

/// Un chemin comparable à un autre, la même forme pour la cible et pour une exclusion : sans « \\?\ » (ni
/// « \\?\UNC\ »), « / » lus « \ », sans « \ » doublé ni final, « . » retirés et « .. » résolus (jamais sous la
/// racine : le lecteur, ou le serveur et le partage), en majuscules Unicode (NTFS compare par sa table de majuscules,
/// plus proche de `to_uppercase` que de `to_lowercase` : « İ »). Limites connues : un nom court 8.3 (PROGRA~1), un
/// lecteur réseau mappé et une jonction ou un lien ne se ramènent pas au chemin réel ; les résoudre demanderait
/// d'ouvrir le fichier. Pour comparer seulement : jamais pour agir sur un fichier.
#[cfg(any(windows, test))]
fn pour_comparer(chemin: &str) -> String {
    let c = chemin.trim().replace('/', "\\");
    let (tete, reste) = match c.strip_prefix(r"\\?\UNC\") {
        Some(reseau) => (r"\\", reseau),
        None => match c.strip_prefix(r"\\?\") {
            Some(local) => ("", local),
            None => c.strip_prefix(r"\\").map_or(("", c.as_str()), |reseau| (r"\\", reseau)),
        },
    };
    // Ce que « .. » ne peut pas retirer : le lecteur (« C: »), ou le serveur et le partage.
    let plancher = if tete.is_empty() { 1 } else { 2 };
    let mut parties: Vec<&str> = Vec::new();
    for partie in reste.split('\\') {
        match partie {
            "" | "." => {}
            ".." => {
                if parties.len() > plancher {
                    parties.pop();
                }
            }
            _ => parties.push(partie),
        }
    }
    format!("{tete}{}", parties.join("\\")).to_uppercase()
}

/// `chemin` est-il `cible`, ou dedans ? (Comparés par `pour_comparer`.)
#[cfg(any(windows, test))]
fn sous_cible(chemin: &str, cible: &str) -> bool {
    let (p, c) = (pour_comparer(chemin), pour_comparer(cible));
    !c.is_empty() && (p == c || p.starts_with(&format!("{c}\\")))
}

/// Les dossiers d'où Defender lit les variables d'une exclusion (`variables_de_defender`), tirés des dossiers connus
/// (`environnement::dossiers`, jamais de l'environnement du processus, que qui lance Vanguard choisit).
#[cfg(any(windows, test))]
#[derive(Default)]
struct Racines<'a> {
    windows: Option<&'a str>,
    program_files: Option<&'a str>,
    program_files_x86: Option<&'a str>,
    communs: Option<&'a str>,
    program_data: Option<&'a str>,
    /// Le profil du compte qui lance Vanguard.
    profil: Option<&'a str>,
    appdata: Option<&'a str>,
    local: Option<&'a str>,
}

/// Ce que valent les variables d'une exclusion pour Defender. Il tourne sous le compte SYSTEM et les développe là
/// (documentation de Microsoft) : %USERPROFILE%, %APPDATA%, %LOCALAPPDATA% désignent le profil de SYSTEM, %TEMP% et
/// %TMP% « C:\Windows\Temp ». Le dossier du compte qui lance Vanguard compte aussi, par prudence : une version qui les
/// développerait autrement ne doit pas faire passer une exclusion pour étrangère. Une variable absente d'ici
/// (%PUBLIC%, %CommonProgramFiles(x86)%, toute autre) est inconnue : elle couvre tout (`exclusions_qui_couvrent`).
#[cfg(any(windows, test))]
fn variables_de_defender(r: &Racines) -> Vec<(&'static str, Vec<String>)> {
    let net = |x: Option<&str>| {
        x.map(|x| x.trim_end_matches('\\').to_string())
            .filter(|x| !x.is_empty())
    };
    let windows = net(r.windows);
    let sous = |base: &Option<String>, s: &str| base.as_ref().map(|b| format!(r"{b}\{s}"));
    let systeme = sous(&windows, r"System32\config\systemprofile");
    let lecteur = windows
        .as_deref()
        .and_then(|w| w.get(..2))
        .filter(|l| l.ends_with(':'))
        .map(str::to_string);
    let temp = [sous(&windows, "Temp"), sous(&net(r.local), "Temp")];
    let toutes: [(&'static str, [Option<String>; 2]); 15] = [
        ("USERPROFILE", [systeme.clone(), net(r.profil)]),
        ("APPDATA", [sous(&systeme, r"AppData\Roaming"), net(r.appdata)]),
        ("LOCALAPPDATA", [sous(&systeme, r"AppData\Local"), net(r.local)]),
        ("TEMP", temp.clone()),
        ("TMP", temp),
        ("PROGRAMFILES", [net(r.program_files), None]),
        ("PROGRAMW6432", [net(r.program_files), None]),
        ("PROGRAMFILES(X86)", [net(r.program_files_x86), None]),
        ("COMMONPROGRAMFILES", [net(r.communs), None]),
        ("PROGRAMDATA", [net(r.program_data), None]),
        ("ALLUSERSPROFILE", [net(r.program_data), None]),
        ("SYSTEMROOT", [windows.clone(), None]),
        ("WINDIR", [windows, None]),
        ("SYSTEMDRIVE", [lecteur, None]),
        ("HOMEDRIVE", [None, None]),
    ];
    toutes
        .into_iter()
        .map(|(nom, valeurs)| {
            let mut v: Vec<String> = Vec::new();
            for x in valeurs.into_iter().flatten() {
                if !v.contains(&x) {
                    v.push(x);
                }
            }
            (nom, v)
        })
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

/// Les formes d'un chemin exclu une fois ses variables connues développées (`variables`, une forme par valeur
/// possible ; 64 au plus, au-delà la variable reste telle quelle), sans la condition d'une exclusion contextuelle
/// (« C:\x\:{PathType:folder} »). Une variable inconnue, ou un « % » seul, reste tel quel : son « % » arrête le début
/// fixe de l'exclusion, qui couvre alors tout ce qui commence pareil (prudence).
#[cfg(any(windows, test))]
fn formes_developpees(exclu: &str, variables: &[(&str, Vec<String>)]) -> Vec<String> {
    let exclu = exclu.find(":{").and_then(|i| exclu.get(..i)).unwrap_or(exclu);
    let mut formes = vec![String::new()];
    let mut reste = exclu;
    while let Some(i) = reste.find('%') {
        for f in &mut formes {
            f.push_str(reste.get(..i).unwrap_or_default());
        }
        let apres = reste.get(i.saturating_add(1)..).unwrap_or_default();
        let Some(j) = apres.find('%') else {
            reste = reste.get(i..).unwrap_or_default();
            break;
        };
        let nom = apres.get(..j).unwrap_or_default();
        let valeurs = variables
            .iter()
            .find(|(v, _)| v.eq_ignore_ascii_case(nom))
            .map(|(_, x)| x)
            .filter(|x| !x.is_empty() && x.len().saturating_mul(formes.len()) <= 64);
        formes = match valeurs {
            Some(valeurs) => formes
                .iter()
                .flat_map(|f| valeurs.iter().map(move |v| format!("{f}{v}")))
                .collect(),
            None => formes.into_iter().map(|f| format!("{f}%{nom}%")).collect(),
        };
        reste = apres.get(j.saturating_add(1)..).unwrap_or_default();
    }
    for f in &mut formes {
        f.push_str(reste);
    }
    formes
}

/// Les détections de cette analyse : notées depuis son début (`debut`, temps universel, deux secondes de marge pour
/// les secondes tronquées), sous la cible (toutes, sans cible : analyse rapide ou complète). Une détection sans
/// ressource compte (fausse alerte plutôt que silence). `None` si une détection qui compterait n'a aucune date
/// lisible : rien ne dit alors si elle est de cette analyse ou de l'historique.
#[cfg(any(windows, test))]
fn de_cette_analyse(
    toutes: Vec<Detection>,
    debut: chrono::NaiveDateTime,
    cible: Option<&str>,
) -> Option<Vec<Detection>> {
    let seuil = debut.checked_sub_signed(chrono::Duration::seconds(2))?;
    let mut gardees = Vec::new();
    for d in toutes {
        let concernee =
            cible.is_none_or(|c| d.ressources.is_empty() || d.ressources.iter().any(|r| ressource_sous_cible(r, c)));
        if !concernee {
            continue;
        }
        let dates: Vec<chrono::NaiveDateTime> = d.dates.iter().filter_map(|x| date_cim(x)).collect();
        if dates.is_empty() {
            return None;
        }
        if dates.iter().any(|x| *x >= seuil) {
            gardees.push(d);
        }
    }
    Some(gardees)
}

/// Les exclusions de Defender qui couvrent `cible`, prêtes à montrer telles qu'écrites : un chemin exclu égal à la
/// cible ou parent d'elle, et pour un dossier aussi un chemin exclu dedans et toute extension exclue (ses fichiers de
/// ce type ne sont pas regardés) ; pour un fichier, son extension. Exclusion et cible passent par la même
/// normalisation (`pour_comparer`), l'exclusion après le développement de ses variables connues (`variables` :
/// `formes_developpees`). Ce qui reste variable inconnue ou joker (% * ?) ne se compare pas exactement : l'exclusion
/// couvre dès que son début fixe est compatible avec la cible (prudence). Les exclusions de processus ne jouent pas
/// sur une analyse à la demande. Des listes cachées ne viennent jamais ici : rien d'une lecture cachée n'entre dans les
/// exclusions vues (`Memoire::lire`), seules lues par ses appelants (`couverture`, et `analyse_confirmee` avant
/// `-CheckExclusion`), et `couverture` dit seule si les listes sont complètes.
#[cfg(any(windows, test))]
fn exclusions_qui_couvrent(
    cible: &str,
    dossier: bool,
    chemins: &[String],
    extensions: &[String],
    variables: &[(&str, Vec<String>)],
) -> Vec<String> {
    let c = pour_comparer(cible);
    let mut couvrent = Vec::new();
    for exclu in chemins.iter().filter(|e| !e.trim().is_empty()) {
        let couvre = formes_developpees(exclu, variables).iter().any(|forme| {
            let e = pour_comparer(forme);
            // Rien de fixe (« \ », « / », « . » seuls) : Defender pourrait y lire la racine, donc tout (prudence).
            if e.is_empty() {
                return true;
            }
            match e.find(['%', '*', '?']) {
                Some(i) => {
                    let fixe = e.get(..i).unwrap_or_default();
                    c.starts_with(fixe) || (dossier && fixe.starts_with(c.as_str()))
                }
                // « C:\ » devient « C: » : parent de tout le lecteur.
                None => c == e || c.starts_with(&format!("{e}\\")) || (dossier && e.starts_with(&format!("{c}\\"))),
            }
        });
        if couvre {
            couvrent.push(affichable(exclu.trim()));
        }
    }
    let nom = c.rsplit('\\').next().unwrap_or_default();
    // Une extension blanche n'est pas une exclusion (`Memoire::lire` ne la garde pas) : écartée ici aussi, comme sans
    // cible (`couverture`). « * » ou « . » seuls, eux, couvrent tout fichier (prudence).
    for exclue in extensions.iter().filter(|e| !e.trim().is_empty()) {
        let e = exclue.trim().trim_start_matches(['*', '.']);
        let haute = e.to_uppercase();
        let couvre = dossier || e.is_empty() || nom.rsplit_once('.').is_some_and(|(_, x)| x == haute);
        if couvre {
            couvrent.push(extension_montree(exclue));
        }
    }
    couvrent
}

/// Une extension exclue, prête à montrer : « *.pdf » pour « pdf », « .pdf » ou « *.pdf ». Sans rien après les jokers
/// et les points (« * », « . »), telle qu'écrite : « *. » ne dirait rien.
#[cfg(any(windows, test))]
fn extension_montree(exclue: &str) -> String {
    let t = exclue.trim();
    match t.trim_start_matches(['*', '.']) {
        "" => affichable(t),
        e => format!("*.{}", affichable(e)),
    }
}

/// La phrase de MpCmdRun confrontée à ce que Defender a noté. Une détection de cette analyse est une menace, quoi
/// qu'ait écrit MpCmdRun (`detections` : `None` si illisibles). Un « sain » ne le reste que si la cible n'a rien
/// d'ambigu (`cible_piegee` : un caractère de contrôle, dont le saut de ligne qui découpe la ligne de résultat, ou un
/// nom illisible en Unicode), qu'aucune exclusion ne la couvre (`exclusions` : celles qui la couvrent, `None` si
/// rien ne permet de le savoir ; pour une analyse rapide ou complète, toutes les exclusions de chemin et d'extension :
/// `couverture`) et que les détections ont pu être lues.
#[cfg(any(windows, test))]
fn confirmer(
    verdict: Verdict,
    detections: Option<&[Detection]>,
    exclusions: Option<Vec<String>>,
    cible_piegee: bool,
) -> Verdict {
    if let Some(trouvees) = detections.filter(|d| !d.is_empty()) {
        let mut noms = match verdict {
            Verdict::Menaces(n) => n,
            _ => Vec::new(),
        };
        for d in trouvees {
            if !noms.contains(&d.nom) {
                noms.push(d.nom.clone());
            }
        }
        return Verdict::Menaces(noms);
    }
    if verdict != Verdict::Sain {
        return verdict;
    }
    if cible_piegee {
        return Verdict::Muette;
    }
    match exclusions {
        Some(e) if !e.is_empty() => Verdict::Exclue(e),
        Some(_) if detections.is_some() => Verdict::Sain,
        _ => Verdict::Inverifiable,
    }
}

/// Toutes les détections notées par Defender (MSFT_MpThreatDetection, la classe de Get-MpThreatDetection), avec le
/// nom de leur menace (MSFT_MpThreat) ; `None` si ni WMI ni PowerShell ne répondent. WMI d'abord, PowerShell en
/// secours.
#[cfg(windows)]
fn detections_de_defender() -> Option<Vec<Detection>> {
    use crate::machine::windows::wmi::{Valeur, requete};
    const ESPACE: &str = r"root\Microsoft\Windows\Defender";
    // Un tableau, ou une valeur seule ; une date CIM revient en texte.
    let textes = |v: Option<&Valeur>| -> Vec<String> { v.map(Valeur::textes).unwrap_or_default() };
    if let Some(lignes) = requete(
        ESPACE,
        "MSFT_MpThreatDetection",
        "",
        &[
            "ThreatID",
            "InitialDetectionTime",
            "LastThreatStatusChangeTime",
            "Resources",
        ],
    ) {
        let noms: std::collections::HashMap<i64, String> =
            requete(ESPACE, "MSFT_MpThreat", "", &["ThreatID", "ThreatName"])
                .unwrap_or_default()
                .iter()
                .filter_map(|m| Some((m.get("ThreatID")?.entier()?, m.get("ThreatName")?.texte()?.to_string())))
                .collect();
        return Some(
            lignes
                .iter()
                .map(|l| {
                    let id = l.get("ThreatID").and_then(Valeur::entier);
                    let mut dates = textes(l.get("InitialDetectionTime"));
                    dates.extend(textes(l.get("LastThreatStatusChangeTime")));
                    Detection {
                        nom: nom_de_menace(id.and_then(|i| noms.get(&i)).map(String::as_str), id),
                        dates,
                        ressources: textes(l.get("Resources")),
                    }
                })
                .collect(),
        );
    }
    // Les dates en temps universel, au format CIM, écrites sans la culture de la session (un calendrier bouddhiste
    // donnerait 2569).
    let json = crate::machine::windows::ps(
        "$n = @{}; Get-MpThreat | ForEach-Object { $n[[string]$_.ThreatID] = $_.ThreatName }; \
         ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-MpThreatDetection | ForEach-Object { @{ \
         i = [string]$_.ThreatID; n = [string]$n[[string]$_.ThreatID]; \
         d = @(@($_.InitialDetectionTime, $_.LastThreatStatusChangeTime) | Where-Object { $_ } | ForEach-Object { \
         $_.ToUniversalTime().ToString('yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture) + '.000000+000' }); \
         r = @($_.Resources) } })",
    )?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let chaines = |x: Option<&serde_json::Value>| -> Vec<String> {
        x.and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    Some(
        v.as_array()?
            .iter()
            .map(|d| {
                let id = d
                    .get("i")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|i| i.parse().ok());
                let nom = d.get("n").and_then(serde_json::Value::as_str);
                Detection {
                    nom: nom_de_menace(nom, id),
                    dates: chaines(d.get("d")),
                    ressources: chaines(d.get("r")),
                }
            })
            .collect(),
    )
}

/// Le nom d'une menace prêt à montrer ; son numéro, ou un nom générique, si Defender ne le donne pas.
#[cfg(windows)]
fn nom_de_menace(nom: Option<&str>, id: Option<i64>) -> String {
    match (nom.map(str::trim).filter(|n| !n.is_empty()), id) {
        (Some(n), _) => affichable(n),
        (None, Some(i)) => trf!("menace n° {i} de Defender", "Defender threat #{i}"),
        (None, None) => tr!("menace reconnue par Defender", "threat recognized by Defender").to_string(),
    }
}

/// La réponse de MpCmdRun lue seule, sans `confirmer` (les essais).
#[cfg(test)]
fn lire_mpcmdrun(code: Option<i32>, sortie: &str, encore_la: bool) -> Examen {
    examen_de(lire_reponse(code, sortie), sortie, encore_la)
}

/// Le verdict d'un seul fichier en `Examen`. Exclu de Defender : « impossible » (`raison_sautee`), jamais sain. Sauté
/// mais disparu : Defender l'a retiré. Une menace sans nom est dite avec la dernière ligne de MpCmdRun, et une réponse
/// muette ou invérifiable n'est jamais comptée comme saine.
#[cfg(any(windows, test))]
fn examen_de(verdict: Verdict, sortie: &str, encore_la: bool) -> Examen {
    match verdict {
        Verdict::Sain => Examen::Sain,
        Verdict::Menaces(noms) if !noms.is_empty() => Examen::Trouve(noms),
        Verdict::Exclue(_) => Examen::Impossible(raison_sautee().into()),
        Verdict::Sautee if encore_la => Examen::Impossible(raison_sautee().into()),
        Verdict::Menaces(_) | Verdict::Sautee => {
            let generique = tr!("menace reconnue par Defender", "threat recognized by Defender");
            Examen::Trouve(vec![match sortie.lines().map(propre).rfind(|l| !l.is_empty()) {
                // Le chemin du fichier y est, aussi long que Windows le permet : la ligne est coupée.
                Some(l) => {
                    let l = couper(&affichable(l), 160);
                    trf!("{generique} (MpCmdRun : « {l} »)", "{generique} (MpCmdRun: \"{l}\")")
                }
                None => generique.to_string(),
            }])
        }
        Verdict::Inverifiable => Examen::Impossible(
            tr!(
                "Defender dit n'avoir rien trouvé, mais ses exclusions ou ses détections n'ont pas pu être lues pour le confirmer",
                "Defender says it found nothing, but its exclusions or detections could not be read to confirm it"
            )
            .into(),
        ),
        Verdict::Muette => Examen::Impossible(
            tr!(
                "compte rendu de Defender non reconnu (son code 0 veut aussi dire « menace trouvée et retirée »)",
                "Defender's report not recognized (its code 0 also means “threat found and removed”)"
            )
            .into(),
        ),
        Verdict::Echec => Examen::Impossible(raison_echec().into()),
    }
}

/// Le chemin à donner à MpCmdRun : sans le préfixe « \\?\ » que `canonicalize` ajoute sous Windows, quand la forme
/// courte désigne sans doute possible le même fichier (la forme qu'on tape, la plus sûrement lue), inchangé sinon.
/// Le préfixe n'explique pas à lui seul le « found no threats » de la passe 5 de l'essai T10 : quelle que soit la
/// forme passée, un « sain » passe par `confirmer`.
#[cfg(windows)]
fn chemin_pour_mpcmdrun(chemin: &std::path::Path) -> PathBuf {
    chemin
        .to_str()
        .and_then(sans_verbatim)
        .map_or_else(|| chemin.to_path_buf(), PathBuf::from)
}

/// « \\?\C:\… » → « C:\… », « \\?\UNC\serveur\partage\… » → « \\serveur\partage\… », seulement quand la forme
/// courte désigne sans doute possible le même fichier. Sans « \\?\ », Windows réinterprète le chemin : point ou espace
/// final retiré, « . » et « .. » résolus, CON, NUL, COM1… pris pour des périphériques, longueur bornée (MAX_PATH).
/// « C:\x\dossier. », créé exprès par qui veut se cacher, deviendrait « C:\x\dossier », un autre dossier, sain. Dans
/// ces cas, et pour toute autre forme (« \\?\Volume{…}\ »), `None` : le chemin reste tel quel, et rien n'agit sur un
/// autre fichier à sa place.
#[cfg(any(windows, test))]
pub(crate) fn sans_verbatim(chemin: &str) -> Option<String> {
    // Au moins le serveur et le partage pour un chemin réseau ; un nom pour un lecteur.
    let (court, noms, minimum) = if let Some(reseau) = chemin.strip_prefix(r"\\?\UNC\") {
        (format!(r"\\{reseau}"), reseau, 2)
    } else {
        let local = chemin.strip_prefix(r"\\?\")?;
        let mut c = local.chars();
        let (Some(lettre), Some(':'), Some('\\')) = (c.next(), c.next(), c.next()) else {
            return None;
        };
        if !lettre.is_ascii_alphabetic() {
            return None;
        }
        // La racine du lecteur, « C:\ », n'a pas de nom après elle.
        let noms = c.as_str();
        if noms.is_empty() {
            return Some(local.to_string());
        }
        (local.to_string(), noms, 1)
    };
    let noms: Vec<&str> = noms.split('\\').collect();
    let sur = noms.len() >= minimum
        && noms.iter().all(|n| nom_sans_ambiguite(n))
        // MAX_PATH : 260 caractères UTF-16, le nul final compris.
        && court.encode_utf16().count() < 260;
    sur.then_some(court)
}

/// Un nom que Windows lit tel quel hors de « \\?\ » : ni vide, ni « . » ou « .. », sans point ni espace final, sans
/// caractère interdit, et pas un nom de périphérique (« CON », « nul.txt », « COM¹ »…), même suivi d'une extension.
#[cfg(any(windows, test))]
fn nom_sans_ambiguite(nom: &str) -> bool {
    const PERIPHERIQUES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    let souche = nom.split('.').next().unwrap_or_default().trim_end().to_uppercase();
    let numerote = ["COM", "LPT"].iter().any(|p| {
        souche.strip_prefix(p).is_some_and(|n| {
            matches!(
                n,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    !nom.is_empty()
        && !nom.ends_with(['.', ' '])
        && !nom.chars().any(|c| c < ' ' || "<>:\"/|?*".contains(c))
        && !PERIPHERIQUES.contains(&souche.as_str())
        && !numerote
}

/// La raison d'un fichier sauté ou exclu par Defender : propre à ce fichier (`vaut_pour_tous` la refuse, et
/// `pieces::moteurs` ne la reporte pas sur les pièces suivantes). Une exclusion qu'on n'a pas posée est elle-même un
/// signe.
#[cfg(any(windows, test))]
pub(crate) fn raison_sautee() -> &'static str {
    tr!(
        "Defender a sauté ce fichier : exclu de l'analyse, ce qui est suspect si personne ne l'a voulu",
        "Defender skipped this file: excluded from scanning, which is suspicious if nobody meant it"
    )
}

/// Noms des menaces dans la sortie de MpCmdRun : « Threat                  : Virus:DOS/EICAR_Test_File », prêts à
/// montrer.
#[cfg(any(windows, test))]
fn menaces_mpcmdrun(sortie: &str) -> Vec<String> {
    sortie
        .lines()
        .filter_map(|l| {
            // `propre` : la première ligne peut porter la marque d'ordre des octets (U+FEFF), que `trim` laisse.
            let (cle, valeur) = propre(l).split_once(':')?;
            (cle.trim() == "Threat").then(|| affichable(valeur.trim()))
        })
        .filter(|v| !v.is_empty())
        .collect()
}

/// Defender n'a pas pu analyser ce fichier (code de sortie 2 sans menace) : un autre antivirus a pris sa place
/// (Defender passif), il est cassé, ou ce seul fichier ne se lit pas (verrouillé, refusé). Propre au fichier :
/// `vaut_pour_tous` ne la reporte jamais.
#[cfg(any(windows, test))]
pub(crate) fn raison_echec() -> &'static str {
    tr!(
        "Defender n'a pas pu analyser (antivirus tiers actif ?)",
        "Defender could not scan (third-party antivirus active?)"
    )
}

/// MpCmdRun n'a pas pu aller au bout : lancement impossible ou délai dépassé (`commande::lancer` rend `None`), quel
/// que soit le fichier. Compilée partout pour `vaut_pour_tous`.
pub(crate) fn raison_injoignable() -> &'static str {
    tr!(
        "Defender n'a pas pu aller au bout (lancement impossible ou délai dépassé)",
        "Defender could not finish (could not start or timed out)"
    )
}

/// Le moteur manque.
#[cfg(windows)]
pub(crate) fn raison_absent() -> &'static str {
    tr!(
        "Defender introuvable (MpCmdRun absent)",
        "Defender not found (MpCmdRun missing)"
    )
}

/// Le second avis manque : clamscan n'est pas installé. Vanguard ne propose plus de l'installer (AV5, §7.5 de la
/// conception) : son moteur fait l'analyse, et lit lui-même la base de ClamAV si elle est là.
#[cfg(unix)]
pub(crate) fn raison_absent() -> &'static str {
    tr!(
        "clamscan non installé (second avis facultatif)",
        "clamscan not installed (optional second opinion)"
    )
}

/// Le second avis coupé par la personne (Paramètres › second-avis).
#[cfg(unix)]
pub(crate) fn raison_coupe() -> &'static str {
    tr!(
        "second avis ClamAV coupé dans les Paramètres",
        "ClamAV second opinion turned off in Settings"
    )
}

/// clamscan installé sans signatures, et leur téléchargement refusé ou impossible.
#[cfg(unix)]
pub(crate) fn raison_sans_signatures() -> &'static str {
    tr!("signatures de ClamAV absentes", "ClamAV signatures missing")
}

/// Une raison d'`Examen::Impossible` qui vaut pour tous les fichiers, que `pieces::moteurs` peut reporter sur les
/// pièces suivantes sans relancer le moteur : le moteur absent, ou (Windows) MpCmdRun qui ne se lance pas ou ne
/// finit pas dans le délai. Jamais une raison propre à un fichier (sauté, exclu, illisible, trop gros), ni un échec
/// d'analyse (code 2 : ce fichier-là peut être verrouillé), ni une réponse muette ou invérifiable : la pièce
/// suivante, elle, peut être lue ou détectée.
pub(crate) fn vaut_pour_tous(raison: &str) -> bool {
    #[cfg(unix)]
    if raison == raison_coupe() || raison == raison_sans_signatures() {
        return true;
    }
    raison == raison_absent() || (cfg!(windows) && raison == raison_injoignable())
}

/// Un seul fichier, pour « Vérifier un fichier téléchargé » : le résultat de ClamAV, sans rien déplacer.
/// Un examinateur pour une série de fichiers : ClamAV n'a rien à retenir d'un fichier à l'autre.
#[cfg(unix)]
pub(crate) fn examinateur() -> impl FnMut(&std::path::Path) -> Examen {
    examiner
}

#[cfg(unix)]
pub(crate) fn examiner(fichier: &std::path::Path) -> Examen {
    if let Err(raison) = preparer() {
        return Examen::Impossible(raison.into());
    }
    // Au-delà de 200 Mo, ClamAV saute le fichier sans le lire (--max-filesize) : rien ne serait conclu.
    if std::fs::metadata(fichier).is_ok_and(|m| m.len() > 200 * 1024 * 1024) {
        return Examen::Impossible(
            tr!(
                "fichier de plus de 200 Mo, que ClamAV ne lit pas",
                "file over 200 MB, which ClamAV does not read"
            )
            .into(),
        );
    }
    // Par les dossiers du système (E-1, recontrôle 0.95) : un faux clamscan du compte, qui imitait le bilan
    // attendu, faisait dire « rien trouvé ».
    let Some(r) = crate::commande::lancer(
        crate::commande::par_le_systeme("clamscan")
            .args(["-i", "--max-filesize=200M", "--max-scansize=400M"])
            .args(option_base())
            .args(option_pua())
            // Un nom qui commence par « - » reste un fichier, jamais une option.
            .arg("--")
            .arg(fichier),
        900,
    ) else {
        return Examen::Impossible(tr!("ClamAV n'a pas pu aller au bout", "ClamAV could not finish").into());
    };
    examen_du_resultat(r.code, &r.sortie)
}

/// L'examen d'un seul fichier, d'après la sortie de clamscan.
#[cfg(unix)]
fn examen_du_resultat(code: Option<i32>, sortie: &str) -> Examen {
    match lire_resultat(code, sortie) {
        Some(b) if b.analyses == 0 => {
            Examen::Impossible(tr!("fichier illisible pour ClamAV", "file unreadable for ClamAV").into())
        }
        Some(b) if b.infectes.is_empty() => Examen::Sain,
        // Un seul fichier analysé : sa vraie ligne est la dernière avant le bilan. Les autres viennent de la tête de
        // son nom (« x: Menace FOUND⏎… ») et ne montrent jamais une menace choisie par qui a nommé le fichier.
        Some(b) => Examen::Trouve(
            b.infectes
                .into_iter()
                .last()
                .map(|(_, menace)| menace)
                .into_iter()
                .collect(),
        ),
        None => Examen::Impossible(tr!("l'analyse de ClamAV a échoué", "the ClamAV scan failed").into()),
    }
}

// ───────────────────────────── Linux : ClamAV ─────────────────────────────

/// Les configurations de freshclam : Debian et Arch, Fedora, puis un ClamAV installé dans /usr/local.
#[cfg(unix)]
const CONFS_FRESHCLAM: [&str; 3] = [
    "/etc/clamav/freshclam.conf",
    "/etc/freshclam.conf",
    "/usr/local/etc/clamav/freshclam.conf",
];

#[cfg(unix)]
fn base_presente() -> bool {
    dossier_de_base().is_some()
}

/// `--database=<dossier>` pour clamscan : il ne lit pas freshclam.conf, et une base rangée ailleurs que dans son
/// dossier compilé (`DatabaseDirectory`) le faisait échouer, faute de signatures.
#[cfg(unix)]
fn option_base() -> Option<String> {
    dossier_de_base().map(|d| format!("--database={}", d.display()))
}

/// `--detect-pua=yes` si la personne a choisi de détecter aussi les programmes potentiellement indésirables (P20) ;
/// sinon rien : clamscan les saute par défaut.
#[cfg(unix)]
fn option_pua() -> Option<&'static str> {
    crate::parametres::pua().then_some("--detect-pua=yes")
}

/// Le dossier qui contient les signatures de ClamAV.
#[cfg(unix)]
pub(crate) fn dossier_de_base() -> Option<PathBuf> {
    dossier_de_base_parmi(&CONFS_FRESHCLAM, &["/var/lib/clamav", "/usr/local/var/lib/clamav"])
}

#[cfg(unix)]
fn dossier_de_base_parmi(confs: &[&str], fixes: &[&str]) -> Option<PathBuf> {
    // Le dossier choisi dans freshclam.conf d'abord : une base ailleurs faisait reproposer le téléchargement.
    confs
        .iter()
        .filter_map(|c| crate::socle::lire_texte_ordinaire(std::path::Path::new(c), 1 << 16).ok())
        .filter_map(|t| dossier_de_la_base(&t))
        .chain(fixes.iter().map(PathBuf::from))
        .find(|d| base_dans(d))
}

/// Le `DatabaseDirectory` d'une configuration de freshclam, s'il y en a un (la dernière ligne l'emporte).
#[cfg(unix)]
fn dossier_de_la_base(conf: &str) -> Option<PathBuf> {
    conf.lines()
        .rev()
        .find_map(|l| {
            let mut mots = l.split_whitespace();
            (mots.next()? == "DatabaseDirectory").then(|| mots.next()).flatten()
        })
        .map(|d| PathBuf::from(d.trim_matches('"')))
}

/// `dossier` contient-il des signatures (.cvd, .cld) ?
#[cfg(unix)]
fn base_dans(dossier: &std::path::Path) -> bool {
    std::fs::read_dir(dossier).is_ok_and(|d| {
        d.flatten().any(|f| {
            std::path::Path::new(&f.file_name())
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("cvd") || e.eq_ignore_ascii_case("cld"))
        })
    })
}

/// clamscan est-il installé ? Celui que `par_le_systeme` lancera, dans un dossier du système, jamais le PATH du compte
/// (E-1, recontrôle 0.95) : un ~/.local/bin/clamscan n'y passe ni pour installé, ni pour l'antivirus. Comme pour
/// freshclam, un ClamAV compilé dans /usr/local passe pour absent, ce qui se dit.
#[cfg(unix)]
pub(crate) fn clamscan_present() -> bool {
    crate::commande::outil_systeme("clamscan").is_some()
}

/// Le second avis peut-il tourner ? Coupé dans les Paramètres, ou clamscan absent : non, et pourquoi, sans rien
/// proposer d'installer (AV5 : ClamAV est facultatif). Installé sans signatures : leur premier téléchargement par
/// l'outil de ClamAV est proposé, la commande montrée avant la question qui l'accepte (la base sert aussi au moteur
/// de Vanguard).
#[cfg(unix)]
fn preparer() -> Result<(), &'static str> {
    preparer_selon(true)
}

/// `questions` faux (`--json`) : rien n'est demandé, montré ni téléchargé ; sans signatures, le second avis n'est
/// simplement pas lancé, et c'est dit.
#[cfg(unix)]
fn preparer_selon(questions: bool) -> Result<(), &'static str> {
    if !crate::parametres::second_avis_clamav() {
        return Err(raison_coupe());
    }
    if !clamscan_present() {
        return Err(raison_absent());
    }
    if !base_presente() {
        if !questions {
            return Err(raison_sans_signatures());
        }
        trp!(
            "  Les signatures de virus de ClamAV manquent (~300 Mo, une seule fois).",
            "  ClamAV's virus signatures are missing (~300 MB, only once)."
        );
        let (telechargement, service) = commandes_des_signatures();
        for c in std::iter::once(&telechargement).chain(&service) {
            println!("  {GRIS}{}{RESET}", crate::ui::commande_affichable(c));
        }
        // Le téléchargement passe par l'assistant élevé : pas sans accord.
        if !demander_ou_defaut(tr!(
            "  Les télécharger maintenant ? [o/N] : ",
            "  Download them now? [y/N]: "
        ))
        .oui()
        {
            return Err(raison_sans_signatures());
        }
        trp!(
            "  Téléchargement des signatures de virus…",
            "  Downloading the virus signatures…"
        );
        // Le téléchargement seul ne change rien à noter sous Linux ; le geste composé, qui arrête et redémarre un
        // service du système, est noté (sans changer son lancement au démarrage).
        #[cfg(target_os = "linux")]
        let ok = if telechargement == crate::machine::gestes_unix::GesteUnix::SignaturesClamav.ligne() {
            crate::machine::appliquer(&[telechargement])
        } else {
            crate::machine::appliquer_sans_noter(&[telechargement]).0
        } && service.is_none_or(|s| crate::machine::appliquer(&[s]));
        if !ok {
            return Err(raison_sans_signatures());
        }
    }
    Ok(())
}

/// Le geste du premier téléchargement des signatures, fait par l'assistant élevé sans shell (lot U3) ; rien après :
/// le lancement au démarrage de leur mise à jour automatique reste ce qu'il était.
#[cfg(target_os = "linux")]
fn commandes_des_signatures() -> (String, Option<String>) {
    use crate::machine::gestes_unix::{FRESHCLAM, GesteUnix};
    // Sur Debian/Ubuntu/Mint, le service tourne déjà et verrouille la base : le geste composé l'arrête le temps du
    // premier téléchargement, puis le relance. Sans systemd, freshclam seul.
    let systemd = std::path::Path::new("/run/systemd/system").is_dir();
    let geste = if systemd {
        GesteUnix::SignaturesClamav
    } else {
        GesteUnix::Programme(&FRESHCLAM)
    };
    (geste.ligne(), None)
}

/// Les endroits à risque du dossier personnel sous Linux : là où arrivent les menaces (téléchargements,
/// bureau, démarrage automatique, programmes de l'utilisateur). L'analyse rapide de l'antivirus et celle de YARA.
#[cfg(unix)]
pub(crate) const ENDROITS_A_RISQUE: [&str; 6] = [
    "Downloads",
    "Téléchargements",
    "Desktop",
    "Bureau",
    ".local/bin",
    ".config/autostart",
];

/// Ce que le second avis de ClamAV a donné, sans l'écran : l'analyse antivirus le montre et propose la quarantaine,
/// `vanguard antivirus --json` le rend tel quel.
#[cfg(unix)]
#[derive(Debug)]
enum SecondAvis {
    /// Pas lancé : coupé dans les Paramètres, clamscan absent, ou ses signatures absentes.
    NonLance(&'static str),
    /// clamscan ne s'est pas lancé.
    PasDemarre,
    /// L'analyse a échoué (résultat pas fiable) : ses lignes d'erreur, rendues affichables (au plus 5).
    Echoue(Vec<String>),
    /// L'analyse a eu lieu ; chaque fichier infecté n'y figure qu'une fois. En boîte : les fonctions qui lancent
    /// clamscan rendent leurs échecs dans ce type, qui serait sinon aussi gros qu'un bilan (`result_large_err`).
    Fait(Box<Bilan>),
}

/// Lance le second avis de ClamAV. `ecran` faux (`--json`) : aucune question, rien de montré, rien de téléchargé.
/// Seul reste le fichier de liste de /tmp, créé de façon exclusive puis effacé (clamscan y lit les fichiers récents).
#[cfg(unix)]
fn second_avis(portee: &Portee, ecran: bool) -> SecondAvis {
    if let Err(raison) = preparer_selon(ecran) {
        return SecondAvis::NonLance(raison);
    }
    let h = home();
    // Analyse rapide : là où arrivent les menaces (téléchargements, bureau, démarrage automatique, programmes de
    // l'utilisateur). Documents passe par l'analyse complète : des milliers de fichiers, rarement une porte d'entrée.
    let cibles: Vec<PathBuf> = match portee {
        Portee::Dossier(d) => vec![d.clone()],
        Portee::Complete => vec![h.clone()],
        Portee::Rapide => ENDROITS_A_RISQUE
            .iter()
            .map(|d| h.join(d))
            .filter(|p| p.exists())
            .collect(),
    };
    let cibles = sans_doublons(cibles);
    // /tmp : seulement les fichiers récents (7 jours), où atterrit un téléchargement en cours ou un script lancé ;
    // le reste peut peser des gigaoctets (caches de compilation, préfixes Wine) sans rien apprendre.
    let tmp = if matches!(portee, Portee::Rapide) {
        fichiers_recents(std::path::Path::new("/tmp"), 7, 5000)
    } else {
        Vec::new()
    };
    let lancement = preparer_lancement(cibles, tmp, &std::env::temp_dir());
    // Sans aucun chemin, clamscan analyserait le dossier courant : rien n'y est lancé.
    if lancement.liste.is_none() && lancement.arguments.is_empty() {
        if lancement.non_analyses.is_empty() {
            return SecondAvis::NonLance(tr!(
                "rien à analyser (aucun endroit à risque, aucun fichier récent dans /tmp)",
                "nothing to scan (no risky place, no recent file in /tmp)"
            ));
        }
        return SecondAvis::Fait(Box::new(Bilan {
            non_analyses: lancement.non_analyses,
            ..Bilan::default()
        }));
    }
    // Jeux, caches et préfixes Wine sont énormes et produisent des faux positifs (cracks, outils anti-triche).
    // Un dossier choisi est analysé en entier : seules les quarantaines restent à l'écart.
    let tout = [
        "Games",
        ".steam",
        ".local/share/Steam",
        ".cache",
        "Windows",
        ".cargo/registry",
        ".rustup",
        "target",
        "node_modules",
        // Dossiers privés des services systemd (root seul) : illisibles, ils feraient compter des erreurs.
        "systemd-private-[^/]*",
        // Quarantaine de Vanguard.
        ".local/share/vanguard/quarantaine",
        ".snapshots",
        ".Trash",
    ];
    let exclusions: &[&str] = if matches!(portee, Portee::Dossier(_)) {
        &[".local/share/vanguard/quarantaine"]
    } else {
        &tout
    };
    let mut decrites: Vec<String> = lancement
        .perimetre
        .cibles
        .iter()
        .map(|p| chemin_affichable(p))
        .collect();
    // Ne compte que ce que clamscan lira vraiment : ni une liste qui n'a pas pu s'écrire, ni ce qui reste à part.
    let n_tmp = lancement.perimetre.fichiers.len();
    if n_tmp > 0 {
        decrites.push(trf!(
            "/tmp ({n_tmp} fichier(s) de moins de 7 jours)",
            "/tmp ({n_tmp} file(s) under 7 days old)"
        ));
    }
    if ecran {
        trp!(
            "  {GRIS}Moteur : ClamAV. Analyse de : {}{RESET}",
            "  {GRIS}Engine: ClamAV. Scanning: {}{RESET}",
            decrites.join(", ")
        );
        trp!(
            "  {GRIS}Cela peut prendre de quelques secondes à plusieurs minutes…{RESET}",
            "  {GRIS}This can take from a few seconds to several minutes…{RESET}"
        );
    }
    // La seconde analyse des fichiers signalés recharge les signatures à chaque lancement : dite à l'écran seulement.
    let revu = analyser_et_revoir(&lancement, option_base().as_ref(), exclusions, |n| {
        if ecran {
            trp!(
                "  {GRIS}{n} fichier(s) signalé(s), analysé(s) à nouveau avant tout geste…{RESET}",
                "  {GRIS}{n} reported file(s), scanned again before anything is done…{RESET}"
            );
        }
    });
    match revu {
        Ok(bilan) => SecondAvis::Fait(Box::new(bilan)),
        Err(echec) => echec,
    }
}

/// Le second avis de ClamAV à l'écran, puis la quarantaine proposée pour ce qu'il a trouvé.
#[cfg(unix)]
fn clamav(portee: &Portee) {
    let bilan = match second_avis(portee, true) {
        SecondAvis::NonLance(raison) => {
            afficher_aligne(
                "  ",
                &trf!(
                    "Second avis non lancé : {raison}. Le moteur de Vanguard a fait l'analyse ci-dessus ; « vanguard parametres second-avis » le règle.",
                    "Second opinion not run: {raison}. The Vanguard engine did the scan above; “vanguard settings second-opinion” sets it."
                ),
                2,
                GRIS,
            );
            return;
        }
        SecondAvis::PasDemarre => {
            trp!("  Impossible de lancer clamscan.", "  Could not start clamscan.");
            return;
        }
        SecondAvis::Echoue(erreurs) => {
            trp!(
                "  {}✖ L'analyse a échoué : le résultat n'est pas fiable.{RESET}",
                "  {}✖ The scan failed: the result is not reliable.{RESET}",
                couleur(Niveau::Eleve)
            );
            for l in erreurs {
                println!("    {GRIS}{l}{RESET}");
            }
            return;
        }
        SecondAvis::Fait(bilan) => *bilan,
    };

    let illisibles = if bilan.illisibles > 0 {
        trf!(
            " ; {} élément(s) illisible(s) sans droits root, ignoré(s)",
            "; {} item(s) unreadable without root rights, skipped",
            bilan.illisibles
        )
    } else {
        String::new()
    };
    trp!(
        "  {GRIS}{} fichier(s) analysé(s){illisibles}.{RESET}",
        "  {GRIS}{} file(s) scanned{illisibles}.{RESET}",
        bilan.analyses
    );
    // Signalé sans être confirmé : montré, jamais compté sain, et aucun geste ne lui est proposé.
    for (f, raison) in &bilan.non_verifies {
        afficher_aligne(
            "  ",
            &trf!(
                "? Non vérifié : {} : signalé par l'analyse, mais {raison} ; rien n'y est fait.",
                "? Not verified: {}: reported by the scan, but {raison}; nothing is done to it.",
                affichable(f)
            ),
            4,
            couleur(Niveau::Moyen),
        );
    }
    if !bilan.lignes_inconnues.is_empty() {
        afficher_aligne(
            "  ",
            &trf!(
                "? Non vérifié : clamscan a écrit des lignes qu'aucun fichier n'explique ({}) : sans doute un nom de fichier à saut de ligne, que Vanguard ne peut pas désigner sans risque d'en viser un autre ; rien n'y est fait.",
                "? Not verified: clamscan wrote lines that no file explains ({}): probably a file name with a line break, which Vanguard cannot point to without risking another file; nothing is done to it.",
                bilan.lignes_inconnues.join(", ")
            ),
            4,
            couleur(Niveau::Moyen),
        );
    }
    for (n, raison) in &bilan.non_analyses {
        afficher_aligne(
            "  ",
            &trf!(
                "? Non analysé : {n} fichier(s) récent(s) de /tmp : {raison}.",
                "? Not scanned: {n} recent file(s) in /tmp: {raison}.",
            ),
            4,
            couleur(Niveau::Moyen),
        );
    }
    let infectes = bilan.infectes;
    if infectes.is_empty() {
        if bilan.non_verifies.is_empty() && bilan.lignes_inconnues.is_empty() && bilan.non_analyses.is_empty() {
            trp!(
                "  {VERT}✔ Aucun malware trouvé.{RESET}",
                "  {VERT}✔ No malware found.{RESET}"
            );
        } else {
            trp!(
                "  Aucun fichier confirmé infecté ; ce qui est signalé ci-dessus reste non vérifié.",
                "  No file confirmed infected; what is reported above remains unverified."
            );
        }
        return;
    }
    // Le chemin reste tel quel pour la quarantaine ; montré, il est rendu inoffensif.
    for (f, m) in &infectes {
        println!("  {}✖ {m}{RESET}  {}", couleur(Niveau::Critique), affichable(f));
    }
    trp!(
        "\n  {} fichier(s) suspect(s).",
        "\n  {} suspicious file(s).",
        infectes.len()
    );
    let rep = demander(tr!(
        "  [q]uarantaine (recommandé, réversible) / [s]upprimer / [r]ien : ",
        "  [q]uarantine (recommended, reversible) / [d]elete / [n]othing: "
    ))
    .to_lowercase();
    for (f, detection) in &infectes {
        let Some(resultat) = geste_clamav(&rep, f, detection, bilan.identites.get(f)) else {
            continue;
        };
        let f = affichable(f);
        match resultat {
            Ok(()) => println!("  {VERT}✔{RESET} {f}"),
            // sudo seulement pour un refus de droits : un fichier qui a changé depuis son examen ne se touche pas,
            // root ou non.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => trp!(
                "  ✖ {f} : {e} (fichier système ? relancer avec sudo)",
                "  ✖ {f}: {e} (system file? run again with sudo)"
            ),
            Err(e) => trp!("  ✖ {f} : {e}", "  ✖ {f}: {e}"),
        }
    }
    if !matches!(rep.as_str(), "q" | "s" | "d") {
        trp!(
            "  Rien n'a été fait : les fichiers restent à leur place.",
            "  Nothing was done: the files stay where they are."
        );
    }
    if rep == "q" {
        trp!(
            "  {GRIS}Quarantaine : {} ; un fichier se remet à sa place par le menu Virus et logiciels espions › Quarantaine.{RESET}",
            "  {GRIS}Quarantine: {}; a file goes back to its place through the menu Viruses and spyware › Quarantine.{RESET}",
            crate::protection::quarantaine::dossier().display()
        );
    }
}

/// Le geste choisi (« q », « s ») sur un fichier confirmé par sa seconde analyse ; `None` : rien à faire. Il ne vise que
/// l'inode revu (`identite`, PA-1) : entre l'examen et la réponse, un dossier du chemin changé en lien vers celui d'un
/// autre faisait isoler ou effacer le fichier de même nom qui s'y trouve.
#[cfg(unix)]
fn geste_clamav(
    rep: &str,
    f: &str,
    detection: &str,
    identite: Option<&crate::protection::quarantaine::Identite>,
) -> Option<std::io::Result<()>> {
    use crate::protection::quarantaine;
    if !matches!(rep, "q" | "s" | "d") {
        return None;
    }
    let chemin = std::path::Path::new(f);
    let change = || {
        std::io::Error::other(tr!(
            "le fichier a changé depuis son examen : rien n'y est fait",
            "the file changed since it was scanned: nothing is done to it"
        ))
    };
    // Sans identité relevée, rien ne dit que ce nom désigne le fichier revu.
    let Some(identite) = identite else {
        return Some(Err(change()));
    };
    Some(if rep == "q" {
        // Vu avant le relevé : un autre fichier sous ce nom n'est ni relevé ni noté. isoler_dans le relit ensuite.
        if !etat_de(chemin).is_ok_and(|e| e.identite.meme_fichier(identite)) {
            return Some(Err(change()));
        }
        // Le seul chemin vers la quarantaine : relevé d'abord, puis noté dans « Ce que Vanguard a changé ».
        let mut demande = quarantaine::demande_d_analyse(chemin, detection);
        demande.identite = Some(*identite);
        quarantaine::isoler(chemin, detection, demande).map(|_| ())
    } else {
        // Relevé et noté aussi : supprimé, le fichier n'a plus d'empreinte à chercher ni à comparer.
        quarantaine::supprimer_apres_analyse(chemin, detection, identite)
    })
}

/// Fichiers modifiés depuis moins de `jours` jours sous `dossier`, au plus `max` (les dossiers illisibles sont
/// sautés sans bruit).
#[cfg(unix)]
fn fichiers_recents(dossier: &std::path::Path, jours: u64, max: usize) -> Vec<PathBuf> {
    // Une date qui déborderait : la limite tombe en 1970, et tout passe pour récent (plus d'analyse, jamais moins).
    let limite = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(jours.saturating_mul(86_400)))
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut trouves = Vec::new();
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            if trouves.len() >= max {
                return trouves;
            }
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if m.is_file() && m.modified().is_ok_and(|t| t >= limite) {
                trouves.push(e.path());
            }
        }
    }
    trouves
}

/// Dossiers à analyser sans recouvrement : un ~/Desktop qui pointe vers ~/Bureau, ou un dossier contenu dans un
/// autre, faisait analyser deux fois les mêmes fichiers ; un fichier infecté était alors signalé deux fois et sa
/// seconde mise en quarantaine échouait (« fichier système ? »). Vu en test.
#[cfg(unix)]
fn sans_doublons(cibles: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut reels: Vec<PathBuf> = cibles.into_iter().map(|p| p.canonicalize().unwrap_or(p)).collect();
    // Trié, un dossier parent passe avant ce qu'il contient.
    reels.sort();
    reels.dedup();
    let mut garde: Vec<PathBuf> = Vec::new();
    for p in reels {
        if !garde.iter().any(|g| p.starts_with(g)) {
            garde.push(p);
        }
    }
    garde
}

/// Bilan d'une analyse ClamAV qui a vraiment eu lieu.
#[cfg(unix)]
#[derive(Debug, Default, PartialEq)]
struct Bilan {
    infectes: Vec<(String, String)>,
    /// Signalés, mais pas confirmés par une analyse d'eux seuls (`revoir_un_a_un`) : (chemin, raison). Rien n'y est
    /// fait, et ils ne comptent jamais pour sains.
    non_verifies: Vec<(String, &'static str)>,
    /// Lignes de clamscan qu'aucun fichier n'explique, rendues affichables : la tête d'un nom coupé par un saut de
    /// ligne. Le fichier en cause n'est pas désigné : non vérifié.
    lignes_inconnues: Vec<String>,
    analyses: u64,
    /// Fichiers illisibles sans droits root (ignorés) : ClamAV renvoie alors le code 2 même si tout s'est bien passé.
    illisibles: u64,
    /// L'inode de chaque fichier confirmé, relevé à sa seconde analyse : le geste ne vise que lui (PA-1).
    identites: std::collections::HashMap<String, crate::protection::quarantaine::Identite>,
    /// Fichiers récents de /tmp que clamscan n'a pas reçus : (nombre, pourquoi). Dits, jamais comptés sains.
    non_analyses: Vec<(u64, &'static str)>,
}

#[cfg(unix)]
impl Bilan {
    /// Le bilan d'un second lancement s'ajoute au premier : l'analyse est l'ensemble des deux.
    fn ajouter(&mut self, autre: Bilan) {
        self.infectes.extend(autre.infectes);
        self.lignes_inconnues.extend(autre.lignes_inconnues);
        self.analyses = self.analyses.saturating_add(autre.analyses);
        self.illisibles = self.illisibles.saturating_add(autre.illisibles);
    }
}

/// Résultat de clamscan, `None` si l'analyse n'a pas eu lieu (base absente, plantage…).
/// On se fie au bilan final plutôt qu'au code de retour : sur un Linux normal, quelques dossiers de /tmp
/// appartiennent à root, et ClamAV répond « erreur » (code 2) après avoir analysé tout le reste (vu en réel).
#[cfg(unix)]
fn lire_resultat(code: Option<i32>, sortie: &str) -> Option<Bilan> {
    // Le vrai bilan est écrit en dernier : un nom de fichier qui l'imite (sauts de ligne compris) passe avant lui.
    let (avant, apres) = sortie.rsplit_once(ENTETE_BILAN)?;
    let mut infectes = Vec::new();
    let mut lignes_inconnues = Vec::new();
    for l in avant.lines().filter(|l| !l.is_empty()) {
        match l.strip_suffix(" FOUND").and_then(|l| l.rsplit_once(": ")) {
            // Le chemin reste tel quel : c'est lui qu'on revoit, puis qu'on isole ou qu'on efface. La menace est
            // seulement montrée.
            Some((fichier, menace)) => infectes.push((fichier.to_string(), affichable(menace))),
            // Avec « -i », clamscan n'écrit rien d'autre avant le bilan (vu en réel, même pour un dossier
            // illisible) : une autre ligne est la tête d'un nom coupé par un saut de ligne.
            None => lignes_inconnues.push(affichable(l)),
        }
    }
    // Un fichier signalé après le bilan : la sortie n'a pas la forme connue, rien n'est conclu.
    if apres.lines().any(|l| l.ends_with(" FOUND")) {
        return None;
    }
    let champ = |nom: &str| {
        apres
            .lines()
            .find_map(|l| l.strip_prefix(nom)?.trim().parse::<u64>().ok())
    };
    let analyses = champ("Scanned files:")?;
    let annonces = champ("Infected files:")?;
    let illisibles = champ("Total errors:").unwrap_or(0);
    let lues = u64::try_from(infectes.len()).unwrap_or(u64::MAX);
    // Moins de lignes que de fichiers annoncés : un infecté manquerait, on ne sait pas quoi isoler. Plus de lignes :
    // un nom piégé (« x: y FOUND⏎z ») en ajoute de fausses, et jeter toute l'analyse cachait les vrais fichiers ;
    // chaque ligne est revue seule ensuite (`revoir_un_a_un`), les fausses y restent « non vérifié ».
    if !matches!(code, Some(0..=2)) || lues < annonces || (annonces == 0 && lues > 0) {
        return None;
    }
    Some(Bilan {
        infectes,
        lignes_inconnues,
        analyses,
        illisibles,
        ..Bilan::default()
    })
}

/// L'en-tête du bilan de clamscan, écrit après tous les fichiers.
#[cfg(unix)]
const ENTETE_BILAN: &str = "----------- SCAN SUMMARY -----------";

/// Une ligne de la liste `--file-list` tient-elle ce chemin tel quel ? La liste est jointe par « \n », et clamscan la
/// lit par morceaux de 1023 octets (vu avec 1.5.4 : 1022 octets lus, 1024 coupés) : un nom à caractère de contrôle
/// (saut de ligne surtout) ou trop long y serait coupé en deux, la moitié désignant un autre fichier ou dossier, et
/// le vrai ne serait jamais lu. Un nom qui n'est pas de l'UTF-8 y serait écrit changé (`display`).
#[cfg(unix)]
fn se_lit_dans_la_liste(f: &std::path::Path) -> bool {
    f.to_str()
        .is_some_and(|t| t.len() <= 1022 && !t.chars().any(char::is_control))
}

/// Au plus tant d'octets de chemins donnés en argument à un lancement de clamscan : loin de la limite du système
/// (`ARG_MAX`, 2 Mio ici), qu'un « Argument list too long » ferait échouer en entier.
#[cfg(unix)]
const OCTETS_EN_ARGUMENT: usize = 128 * 1024;

/// Au plus tant de fichiers de /tmp donnés à part : chacun signalé se revoit seul s'il a un saut de ligne (cinq
/// secondes environ), et /tmp est ouvert à tous les comptes.
#[cfg(unix)]
const TMP_A_PART: usize = 200;

/// Les fichiers récents de /tmp : ceux de la liste `--file-list`, ceux à donner en argument (bornés), et le nombre de
/// ceux qui restent, non analysés (dits).
#[cfg(unix)]
fn a_part_de_la_liste(fichiers: Vec<PathBuf>) -> (Vec<PathBuf>, Vec<PathBuf>, usize) {
    let (mut liste, mut a_part, mut laisses, mut octets) = (Vec::new(), Vec::new(), 0usize, 0usize);
    for f in fichiers {
        if se_lit_dans_la_liste(&f) {
            liste.push(f);
            continue;
        }
        let n = f.as_os_str().len().saturating_add(1);
        if a_part.len() < TMP_A_PART && octets.saturating_add(n) <= OCTETS_EN_ARGUMENT {
            octets = octets.saturating_add(n);
            a_part.push(f);
        } else {
            laisses = laisses.saturating_add(1);
        }
    }
    (liste, a_part, laisses)
}

/// Ce qui a été donné à clamscan : un chemin signalé hors de là (un nom piégé « `a⏎<autre chemin>` »,
/// un chemin relatif) n'a pas été demandé, et ne se propose jamais à un geste.
#[cfg(unix)]
#[derive(Debug, Default)]
struct Perimetre {
    /// Les dossiers (ou fichiers) analysés, sans doublons, tels que donnés à clamscan : canoniques (`sans_doublons`,
    /// `analyser`), donc clamscan écrit le vrai chemin de chaque fichier qu'il y lit.
    cibles: Vec<PathBuf>,
    /// Les fichiers de /tmp vraiment donnés à clamscan.
    fichiers: std::collections::HashSet<PathBuf>,
}

#[cfg(unix)]
impl Perimetre {
    fn contient(&self, chemin: &std::path::Path) -> bool {
        use std::path::Component;
        chemin.is_absolute()
            && chemin
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && (self.fichiers.contains(chemin) || self.cibles.iter().any(|c| chemin.starts_with(c)))
    }
}

/// La liste `--file-list`, effacée quand l'analyse est finie.
#[cfg(unix)]
#[derive(Debug)]
struct ListeEcrite(PathBuf);

#[cfg(unix)]
impl Drop for ListeEcrite {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Ce que le second avis donne à lire à clamscan.
#[cfg(unix)]
#[derive(Debug)]
struct Lancement {
    liste: Option<ListeEcrite>,
    /// Pour un lancement à part, sans `--file-list` : clamscan ignore tout chemin en argument dès qu'il a une liste.
    arguments: Vec<PathBuf>,
    perimetre: Perimetre,
    non_analyses: Vec<(u64, &'static str)>,
}

/// Répartit les cibles et les fichiers récents de /tmp entre la liste (écrite dans `dossier_liste`) et les arguments.
/// Avec `--file-list`, clamscan ignore tout chemin donné en argument (vu avec 1.5.4 : « Only scanning files from
/// --file-list ») : mêlés, Téléchargements et les autres endroits à risque n'étaient jamais lus dès qu'un fichier
/// récent était dans /tmp. Un dossier écrit dans la liste, lui, est bien parcouru (-r, --exclude-dir compris).
#[cfg(unix)]
fn preparer_lancement(cibles: Vec<PathBuf>, tmp: Vec<PathBuf>, dossier_liste: &std::path::Path) -> Lancement {
    let (tmp_liste, tmp_a_part, laisses) = a_part_de_la_liste(tmp);
    let (cibles_liste, mut arguments): (Vec<PathBuf>, Vec<PathBuf>) =
        cibles.iter().cloned().partition(|c| se_lit_dans_la_liste(c));
    let mut non_analyses = Vec::new();
    if laisses > 0 {
        non_analyses.push((
            u64::try_from(laisses).unwrap_or(u64::MAX),
            tr!(
                "trop nombreux à donner à part (noms à caractère de contrôle ou très longs, qui ne tiennent pas dans la liste de clamscan)",
                "too many to give separately (names with control characters or very long, which do not fit in the clamscan list)"
            ),
        ));
    }
    let lignes: Vec<&PathBuf> = cibles_liste.iter().chain(&tmp_liste).collect();
    let liste = if lignes.is_empty() {
        None
    } else {
        ecrire_liste(&lignes, dossier_liste)
    };
    let mut fichiers: std::collections::HashSet<PathBuf> = tmp_a_part.iter().cloned().collect();
    if liste.is_some() {
        fichiers.extend(tmp_liste);
    } else {
        // Pas de liste : les cibles passent en argument ; les fichiers de /tmp qui devaient y être ne sont pas
        // analysés, et c'est dit (avant, /tmp était sauté sans un mot).
        arguments.extend(cibles_liste);
        if !tmp_liste.is_empty() {
            non_analyses.push((
                u64::try_from(tmp_liste.len()).unwrap_or(u64::MAX),
                tr!(
                    "la liste à donner à clamscan n'a pas pu s'écrire",
                    "the list to give to clamscan could not be written"
                ),
            ));
        }
    }
    arguments.extend(tmp_a_part);
    Lancement {
        liste,
        arguments,
        perimetre: Perimetre { cibles, fichiers },
        non_analyses,
    }
}

/// La liste `--file-list`, créée de façon exclusive : jamais un fichier ou un lien posé d'avance par un autre compte
/// dans /tmp. `None` si elle n'a pas pu s'écrire.
#[cfg(unix)]
fn ecrire_liste(lignes: &[&PathBuf], dossier: &std::path::Path) -> Option<ListeEcrite> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let chemin = dossier.join(format!("vanguard-clamav-{}-{nanos}.txt", std::process::id()));
    // Chaque ligne a passé `se_lit_dans_la_liste` : de l'UTF-8 sans caractère de contrôle.
    let texte = lignes.iter().filter_map(|f| f.to_str()).collect::<Vec<_>>().join("\n");
    // Lisible par soi seul : elle nomme des fichiers du dossier personnel.
    let mut f =
        std::os::unix::fs::OpenOptionsExt::mode(std::fs::OpenOptions::new().write(true).create_new(true), 0o600)
            .open(&chemin)
            .ok()?;
    // Créée : effacée même si l'écriture échoue.
    let liste = ListeEcrite(chemin);
    std::io::Write::write_all(&mut f, texte.as_bytes()).ok()?;
    Some(liste)
}

/// Lance clamscan sur ce que `l` lui donne (la liste, puis les arguments, à part), et rend le bilan des deux, chaque
/// fichier infecté une seule fois.
#[cfg(unix)]
fn analyser_le_lancement(l: &Lancement, base: Option<&String>, exclusions: &[&str]) -> Result<Bilan, SecondAvis> {
    let commande = || {
        let mut cmd = crate::commande::par_le_systeme("clamscan");
        // Le bilan final (fichiers analysés, infectés, erreurs) sert à juger si l'analyse a vraiment eu lieu.
        cmd.args(["-r", "-i", "--max-filesize=200M", "--max-scansize=400M"]);
        cmd.args(base);
        cmd.args(option_pua());
        for e in exclusions {
            cmd.arg(format!("--exclude-dir={}", regex_echappe(e)));
        }
        cmd
    };
    let mut bilan = Bilan::default();
    if let Some(liste) = &l.liste {
        let mut option = std::ffi::OsString::from("--file-list=");
        option.push(&liste.0);
        bilan.ajouter(un_lancement(commande().arg(option))?);
    }
    if !l.arguments.is_empty() {
        // Un chemin qui commence par « - » reste un chemin, jamais une option.
        bilan.ajouter(un_lancement(commande().arg("--").args(&l.arguments))?);
    }
    // Un même fichier n'est proposé qu'une fois (sinon la 2e mise en quarantaine échoue).
    let mut vus = std::collections::HashSet::new();
    bilan.infectes.retain(|(f, _)| vus.insert(f.clone()));
    Ok(bilan)
}

/// Un lancement de clamscan et son bilan ; l'échec dit avec les lignes d'erreur de ClamAV.
#[cfg(unix)]
fn un_lancement(cmd: &mut std::process::Command) -> Result<Bilan, SecondAvis> {
    let Ok(sortie) = crate::coulisses::Suivie::output_suivi(cmd) else {
        return Err(SecondAvis::PasDemarre);
    };
    lire_resultat(sortie.status.code(), &String::from_utf8_lossy(&sortie.stdout)).ok_or_else(|| {
        // Les erreurs de ClamAV citent souvent un fichier, au nom choisi par n'importe qui.
        SecondAvis::Echoue(
            String::from_utf8_lossy(&sortie.stderr)
                .lines()
                .filter(|l| l.contains("ERROR"))
                .take(5)
                .map(affichable)
                .collect(),
        )
    })
}

/// L'analyse de `l`, puis chaque fichier signalé revu à part (`annoncer` reçoit leur nombre avant) : ce que le second
/// avis montre et rend.
#[cfg(unix)]
fn analyser_et_revoir(
    l: &Lancement,
    base: Option<&String>,
    exclusions: &[&str],
    annoncer: impl FnOnce(usize),
) -> Result<Bilan, SecondAvis> {
    let mut bilan = analyser_le_lancement(l, base, exclusions)?;
    if !bilan.infectes.is_empty() {
        annoncer(bilan.infectes.len());
    }
    revoir_un_a_un(&mut bilan, &l.perimetre, |lot| analyser_ensemble(lot, base));
    bilan.non_analyses.clone_from(&l.non_analyses);
    Ok(bilan)
}

/// Ce qu'on sait d'un fichier avant sa seconde analyse, relu après : le même inode, la même taille, les mêmes dates
/// (un fichier échangé puis remis change de ctime).
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Etat {
    identite: crate::protection::quarantaine::Identite,
    taille: u64,
    modifie: (i64, i64),
    change: (i64, i64),
}

/// L'état d'un fichier ordinaire qui est vraiment à `chemin`, lu sur un seul descripteur : ouvert sans suivre le
/// dernier nom (O_PATH|O_NOFOLLOW), l'inode est lu sur ce descripteur, puis le noyau dit où est ce fichier ouvert
/// (/proc/self/fd/N). Un chemin qui passe par un lien vers un dossier y montre un autre chemin : refusé, comme un
/// absent, un lien ou un dossier. L'état lu par lstat (qui suit le lien d'un dossier du milieu) puis le chemin jugé
/// par un autre appel laissaient un dossier échangé entre les deux faire garder l'inode du fichier d'un autre, ensuite
/// effacé ou isolé (PA-1, contrôle de la ronde 2).
#[cfg(unix)]
fn etat_de(chemin: &std::path::Path) -> Result<Etat, &'static str> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let absent = || {
        tr!(
            "absent, ou pas un fichier ordinaire (lien, dossier…)",
            "missing, or not a regular file (link, folder…)"
        )
    };
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(chemin)
        .map_err(|_| absent())?;
    let m = f.metadata().map_err(|_| absent())?;
    if !m.file_type().is_file() {
        return Err(absent());
    }
    // Les cibles sont canoniques et clamscan ne suit pas un lien trouvé en parcourant : un fichier qu'il a lu est à
    // son vrai chemin. Ailleurs, il vient d'ailleurs (un nom piégé, un dossier échangé entre-temps).
    if !std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).is_ok_and(|lieu| lieu == chemin) {
        return Err(tr!(
            "son chemin passe par un lien vers un dossier",
            "its path goes through a link to a folder"
        ));
    }
    Ok(Etat {
        identite: crate::protection::quarantaine::Identite::de(&m),
        taille: m.len(),
        modifie: (m.mtime(), m.mtime_nsec()),
        change: (m.ctime(), m.ctime_nsec()),
    })
}

/// Raison d'un fichier non vérifié : sa seconde analyse n'a pas pu aller au bout.
#[cfg(unix)]
fn pas_au_bout() -> &'static str {
    tr!(
        "son analyse à part n'a pas pu aller au bout",
        "scanning it on its own could not finish"
    )
}

/// Revoit à part les fichiers signalés, avant tout geste et avant le rapport (PA-1, relecture du 12 nov.). La
/// sortie de clamscan se lit par lignes, et un nom de fichier peut en contenir : « a⏎$HOME/.bashrc » infecté faisait
/// lire « $HOME/.bashrc: … FOUND », et la personne était invitée à isoler ou à effacer ce fichier-là. Ne reste
/// infecté qu'un fichier ordinaire (lu sans suivre un lien), dans ce qui a été donné à clamscan (`perimetre`), dont
/// la seconde analyse redit exactement « `<ce chemin>: … FOUND` », et qui n'a pas changé pendant ce temps ; son inode
/// est gardé pour le geste. Le reste passe dans `non_verifies`, avec sa raison : jamais compté sain, jamais proposé
/// à un geste. `analyser` reçoit des lots (un seul lancement de clamscan pour beaucoup de fichiers : il recharge ses
/// signatures à chaque fois, cinq secondes environ) ; un nom à saut de ligne est revu seul.
#[cfg(unix)]
fn revoir_un_a_un(
    bilan: &mut Bilan,
    perimetre: &Perimetre,
    mut analyser: impl FnMut(&[&std::path::Path]) -> Option<(Option<i32>, String)>,
) {
    let mut vus = std::collections::HashSet::new();
    let signales: Vec<String> = std::mem::take(&mut bilan.infectes)
        .into_iter()
        .map(|(f, _)| f)
        .filter(|f| vus.insert(f.clone()))
        .collect();
    let mut avant = std::collections::HashMap::new();
    let mut verdicts: std::collections::HashMap<String, Result<String, &'static str>> =
        std::collections::HashMap::new();
    for f in &signales {
        match etat_avant(f, perimetre) {
            Ok(etat) => {
                avant.insert(f.clone(), etat);
            }
            Err(raison) => {
                verdicts.insert(f.clone(), Err(raison));
            }
        }
    }
    let (seuls, par_lot): (Vec<&str>, Vec<&str>) = signales
        .iter()
        .map(String::as_str)
        .filter(|f| avant.contains_key(*f))
        .partition(|f| f.contains('\n'));
    // Un lancement par lot ou par fichier seul, plus `RELANCES` : au-delà, `None`, et le reste est « non vérifié ».
    let mut permis = en_lots(&par_lot)
        .len()
        .saturating_add(seuls.len())
        .saturating_add(RELANCES);
    let mut analyser = |lot: &[&std::path::Path]| {
        permis = permis.checked_sub(1)?;
        analyser(lot)
    };
    let le_meme = |f: &str| avant.get(f).is_some_and(|e| etat_de(std::path::Path::new(f)) == Ok(*e));
    for lot in en_lots(&par_lot) {
        for (f, v) in lot.iter().zip(verdicts_du_lot(&lot, &mut analyser, &le_meme)) {
            verdicts.insert((*f).to_string(), v);
        }
    }
    for f in seuls {
        verdicts.insert(f.to_string(), verdict_seul(f, &mut analyser));
    }
    for f in signales {
        let verdict = verdicts.remove(&f).unwrap_or(Err(pas_au_bout()));
        let etat = avant.get(&f).copied();
        // Relu après : un fichier échangé pendant l'analyse n'est pas celui qu'elle a vu.
        let verdict = verdict.and_then(|menace| match etat {
            Some(e) if etat_de(std::path::Path::new(&f)) == Ok(e) => Ok((menace, e)),
            _ => Err(change_pendant()),
        });
        match verdict {
            Ok((menace, e)) => {
                bilan.identites.insert(f.clone(), e.identite);
                bilan.infectes.push((f, menace));
            }
            Err(raison) => bilan.non_verifies.push((f, raison)),
        }
    }
}

/// L'état d'un fichier signalé avant sa seconde analyse, sinon pourquoi il reste non vérifié sans être relancé.
#[cfg(unix)]
fn etat_avant(fichier: &str, perimetre: &Perimetre) -> Result<Etat, &'static str> {
    let chemin = std::path::Path::new(fichier);
    if !perimetre.contient(chemin) {
        return Err(tr!(
            "hors de ce qui a été analysé (nom de fichier à saut de ligne ?)",
            "outside what was scanned (file name with a line break?)"
        ));
    }
    // Lu sans suivre un lien : clamscan, lui, le suivrait, et c'est la cible qui serait isolée ou effacée.
    etat_de(chemin)
}

/// Les chemins (sans saut de ligne) en lots d'au plus `OCTETS_EN_ARGUMENT` octets.
#[cfg(unix)]
fn en_lots<'a>(chemins: &[&'a str]) -> Vec<Vec<&'a str>> {
    let mut lots: Vec<Vec<&str>> = Vec::new();
    let mut octets = 0usize;
    for f in chemins {
        let n = f.len().saturating_add(1);
        match lots.last_mut() {
            Some(lot) if octets.saturating_add(n) <= OCTETS_EN_ARGUMENT => {
                octets = octets.saturating_add(n);
                lot.push(f);
            }
            _ => {
                octets = n;
                lots.push(vec![f]);
            }
        }
    }
    lots
}

/// Raison d'un fichier non vérifié : il n'est plus celui qui a été relevé avant sa seconde analyse.
#[cfg(unix)]
fn change_pendant() -> &'static str {
    tr!(
        "il a changé pendant son analyse à part",
        "it changed while it was scanned on its own"
    )
}

/// Le verdict de chaque fichier d'un lot, dans l'ordre, en un lancement si sa sortie a la forme exacte attendue.
/// Sinon, un fichier parti ou changé entre-temps (`le_meme` faux) n'écrit rien ou autre chose : il est écarté sans
/// être relancé, et le reste est revu en un lancement. Un autre compte qui efface ses fichiers de /tmp juste après
/// leur relevé ferait sinon couper le lot en deux jusqu'au fichier seul : un lancement de cinq secondes par fichier.
/// Si rien n'a changé, chaque moitié est revue à part.
#[cfg(unix)]
fn verdicts_du_lot(
    lot: &[&str],
    analyser: &mut impl FnMut(&[&std::path::Path]) -> Option<(Option<i32>, String)>,
    le_meme: &impl Fn(&str) -> bool,
) -> Vec<Result<String, &'static str>> {
    match lot {
        [] => Vec::new(),
        [seul] => vec![verdict_seul(seul, analyser)],
        _ => {
            let chemins: Vec<&std::path::Path> = lot.iter().map(std::path::Path::new).collect();
            let Some((code, sortie)) = analyser(&chemins) else {
                return lot.iter().map(|_| Err(pas_au_bout())).collect();
            };
            if let Some(v) = lire_le_lot(code, &sortie, lot) {
                return v;
            }
            let restes: Vec<bool> = lot.iter().map(|f| le_meme(f)).collect();
            if restes.contains(&false) {
                let gardes: Vec<&str> = lot.iter().zip(&restes).filter(|(_, r)| **r).map(|(f, _)| *f).collect();
                let mut v = verdicts_du_lot(&gardes, analyser, le_meme).into_iter();
                return restes
                    .iter()
                    .map(|r| {
                        if *r {
                            v.next().unwrap_or(Err(pas_au_bout()))
                        } else {
                            Err(change_pendant())
                        }
                    })
                    .collect();
            }
            let (a, b) = lot.split_at(lot.len() / 2);
            let mut v = verdicts_du_lot(a, analyser, le_meme);
            v.extend(verdicts_du_lot(b, analyser, le_meme));
            v
        }
    }
}

/// La sortie de « clamscan --no-summary -- f1 f2 … » : exactement une ligne par fichier, dans l'ordre des arguments
/// (vu avec 1.5.4), chacune « `<fi>: OK` », « `<fi>: <menace> FOUND` » ou une autre réponse sur ce fichier (« Empty
/// file », « Access denied »), qui ne conclut rien pour lui seul. Aucun chemin du lot n'a de saut de ligne : chaque
/// ligne se rattache sans doute possible à son fichier. Autre forme : `None`, rien n'est conclu.
#[cfg(unix)]
fn lire_le_lot(code: Option<i32>, sortie: &str, lot: &[&str]) -> Option<Vec<Result<String, &'static str>>> {
    if !matches!(code, Some(0..=2)) {
        return None;
    }
    let lignes: Vec<&str> = sortie.strip_suffix('\n')?.split('\n').collect();
    if lignes.len() != lot.len() {
        return None;
    }
    let mut trouve = false;
    let mut verdicts = Vec::with_capacity(lot.len());
    for (ligne, f) in lignes.iter().zip(lot) {
        let verdict = ligne.strip_prefix(f)?.strip_prefix(": ")?;
        if verdict == "OK" {
            verdicts.push(Err(pas_infecte()));
            continue;
        }
        let Some(menace) = verdict.strip_suffix(" FOUND") else {
            // « Empty file », « Access denied » (vus avec 1.5.4) : la ligne est bien la sienne, sans rien de net. Lui
            // seul reste non vérifié ; rejeter le lot le faisait couper en deux jusqu'au fichier seul, un lancement
            // par fichier piégé simplement posé.
            verdicts.push(Err(rien_de_net()));
            continue;
        };
        // Une menace vient des signatures : sans « : ». Autre chose ne se rattache pas sans doute.
        let menace = Some(menace).filter(|m| !m.is_empty() && !m.contains(": "))?;
        trouve = true;
        verdicts.push(Ok(affichable(menace)));
    }
    // Le code dit s'il y a eu une trouvaille (1, même avec un fichier illisible ; sinon 0, ou 2 pour un illisible) :
    // s'il contredit les lignes, rien n'est conclu.
    (trouve == (code == Some(1))).then_some(verdicts)
}

/// Raison d'un fichier non vérifié : analysé à part, il n'est pas trouvé infecté.
#[cfg(unix)]
fn pas_infecte() -> &'static str {
    tr!(
        "analysé à part, il n'est pas trouvé infecté (nom à saut de ligne, ou fichier changé depuis)",
        "scanned on its own, it is not found infected (name with a line break, or file changed since)"
    )
}

/// La menace que l'analyse de ce seul fichier redit, sinon pourquoi il reste non vérifié.
#[cfg(unix)]
fn verdict_seul(
    fichier: &str,
    analyser: &mut impl FnMut(&[&std::path::Path]) -> Option<(Option<i32>, String)>,
) -> Result<String, &'static str> {
    let Some((code, sortie)) = analyser(&[std::path::Path::new(fichier)]) else {
        return Err(pas_au_bout());
    };
    // Toute la sortie, d'un seul fichier : le chemin est connu en entier, saut de ligne compris, donc rien ne se lit
    // de travers ; la menace, elle, vient des signatures et tient sur une ligne.
    let verdict = sortie
        .strip_prefix(fichier)
        .and_then(|r| r.strip_prefix(": "))
        .and_then(|r| r.strip_suffix('\n'))
        .filter(|v| !v.contains('\n'));
    let menace = verdict.and_then(|v| v.strip_suffix(" FOUND")).filter(|m| !m.is_empty());
    match (code, menace, verdict) {
        (Some(1), Some(menace), _) => Ok(affichable(menace)),
        (Some(0), _, Some("OK")) => Err(pas_infecte()),
        _ => Err(rien_de_net()),
    }
}

/// Raison d'un fichier non vérifié : clamscan a parlé de lui sans dire ni « OK » ni une menace (fichier vide,
/// illisible, sortie inattendue).
#[cfg(unix)]
fn rien_de_net() -> &'static str {
    tr!(
        "son analyse à part n'a rien dit de net",
        "scanning it on its own gave no clear answer"
    )
}

/// Lancements de clamscan permis en plus d'un par lot pour revoir les fichiers signalés : une sortie d'une forme
/// inattendue fait couper un lot en deux, et des noms piégés posés feraient sinon un lancement de cinq secondes par
/// fichier. Au-delà, ce qui reste est « non vérifié ».
#[cfg(unix)]
const RELANCES: usize = 16;

/// clamscan sur ces seuls fichiers, avec les mêmes limites et options que l'analyse : (code, sortie). Sans « -i », un
/// fichier sain s'écrit « `<chemin>: OK` », jamais un silence ; sans bilan, la sortie ne parle que d'eux.
#[cfg(unix)]
fn analyser_ensemble(chemins: &[&std::path::Path], base: Option<&String>) -> Option<(Option<i32>, String)> {
    let r = crate::commande::lancer(
        crate::commande::par_le_systeme("clamscan")
            .args(["--no-summary", "--max-filesize=200M", "--max-scansize=400M"])
            .args(base)
            .args(option_pua())
            // Un nom qui commence par « - » reste un fichier, jamais une option.
            .arg("--")
            .args(chemins),
        900,
    )?;
    Some((r.code, r.sortie))
}

/// --exclude-dir attend une expression régulière : on échappe les points.
#[cfg(unix)]
fn regex_echappe(dossier: &str) -> String {
    // Le chemin du dossier n'a pas de « / » final : on accepte la fin de chaîne.
    format!("/{}(/|$)", dossier.replace('.', "\\."))
}

// ───────────────────────────── Démarrage automatique ─────────────────────────────

fn demarrage() {
    titre(tr!(
        "Programmes lancés au démarrage (à vérifier)",
        "Programs started at boot (to check)"
    ));
    let (entrees, non_lus) = entrees_demarrage();
    if !non_lus.is_empty() {
        let liste = non_lus.join(", ");
        afficher_aligne(
            "  ",
            &trf!(
                "Non vérifié : {liste} (illisible d'ici) ; la liste ci-dessous peut être incomplète.",
                "Not verified: {liste} (unreadable from here); the list below may be incomplete."
            ),
            2,
            GRIS,
        );
    }
    // « Rien de particulier » seulement quand tout a été lu : une source illisible ne passe pas pour vide.
    if entrees.is_empty() && non_lus.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Rien de particulier.",
            "  {VERT}✔{RESET} Nothing special."
        );
    }
    for e in entrees {
        println!("  • {e}");
    }
    trp!(
        "  {GRIS}Si vous ne reconnaissez pas une entrée, renseignez-vous avant de la supprimer.{RESET}",
        "  {GRIS}If you do not recognize an entry, look it up before deleting it.{RESET}"
    );
    afficher_aligne(
        "  ",
        tr!(
            "Pour qu'un programme ne se lance plus à l'ouverture de session, sans le désinstaller et de façon annulable : vanguard demarrage (ou Optimiser et installer › Programmes au démarrage).",
            "To stop a program from starting at login, without uninstalling it and in an undoable way: vanguard startup (or Optimize and install › Startup programs)."
        ),
        2,
        GRIS,
    );
}

/// Ce qui se lance au démarrage, sans l'écran : (entrées rendues affichables, sources non lues). L'analyse antivirus
/// le montre, `vanguard antivirus --json` le rend.
fn entrees_demarrage() -> (Vec<String>, Vec<String>) {
    // Chaque entrée est écrite par qui l'a posée (le programme qui veut se faire relancer) : montrée rendue inoffensive.
    let mut entrees: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let h = home();
        for d in [".config/autostart", ".config/systemd/user"] {
            for f in std::fs::read_dir(h.join(d)).into_iter().flatten().flatten() {
                if f.path().is_file() {
                    entrees.push(chemin_affichable(&f.path()));
                }
            }
        }
        if let Some(o) = crate::commande::lancer(crate::commande::par_le_systeme("crontab").arg("-l"), 10) {
            for l in o.sortie.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                let l = affichable(l);
                entrees.push(trf!("crontab : {l}", "crontab: {l}"));
            }
        }
        for f in std::fs::read_dir("/etc/systemd/system").into_iter().flatten().flatten() {
            let p = f.path();
            // Services ajoutés à la main (pas par un paquet) : endroit classique pour une persistance root.
            if p.extension().is_some_and(|e| e == "service") && p.is_file() && !p.is_symlink() {
                let possede = crate::machine::linux::Paquets::detecter().is_none_or(|g| g.possede(&p));
                if !possede {
                    entrees.push(trf!(
                        "{} (service système hors paquet)",
                        "{} (system service not from a package)",
                        chemin_affichable(&p)
                    ));
                }
            }
        }
    }

    // Windows : clés Run et RunOnce (winreg), dossiers Démarrage, tâches planifiées hors \Microsoft\ (ITaskService),
    // sans PowerShell ; Get-ScheduledTask seulement si le planificateur ne répond pas. Ce qui n'a pas été lu est dit.
    #[cfg(windows)]
    let non_lus = {
        let (lignes, mut non_lus) = demarrage_windows();
        entrees.extend(lignes);
        std::mem::take(&mut non_lus)
    };
    #[cfg(not(windows))]
    let non_lus: Vec<String> = Vec::new();
    (entrees, non_lus)
}

/// Ce qui se lance à l'ouverture de session sous Windows, lu sans PowerShell : (lignes à montrer, sources non lues).
/// Win32_StartupCommand lisait les mêmes clés et dossiers (en administrateur, aussi les clés Run des autres comptes
/// ouverts, qui manquent ici).
#[cfg(windows)]
fn demarrage_windows() -> (Vec<String>, Vec<String>) {
    let mut lignes = Vec::new();
    let (run, cles_non_lues) = crate::machine::windows::persistance::lignes_run();
    let mut non_lus: Vec<String> = cles_non_lues.iter().map(|c| (*c).to_string()).collect();
    for v in run {
        let nom = if v.nom.is_empty() {
            tr!("(par défaut)", "(default)").to_string()
        } else {
            affichable(&v.nom)
        };
        lignes.push(format!("{nom} — {}", affichable(&v.valeur)));
    }
    for (variable, sous_dossier) in [
        ("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        ("ProgramData", r"Microsoft\Windows\Start Menu\Programs\StartUp"),
    ] {
        let Some(base) = std::env::var_os(variable) else {
            non_lus.push(trf!(
                "dossier Démarrage (%{variable}% inconnu)",
                "Startup folder (%{variable}% unknown)"
            ));
            continue;
        };
        let dossier = std::path::PathBuf::from(base).join(sous_dossier);
        match std::fs::read_dir(&dossier) {
            Ok(fichiers) => {
                for f in fichiers.flatten() {
                    let nom = f.file_name().to_string_lossy().into_owned();
                    // desktop.ini : la mise en forme du dossier par l'Explorateur, rien qui se lance.
                    if !nom.eq_ignore_ascii_case("desktop.ini") {
                        lignes.push(trf!(
                            "{} (dossier Démarrage)",
                            "{} (Startup folder)",
                            chemin_affichable(&f.path())
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => non_lus.push(chemin_affichable(&dossier)),
        }
    }
    // Chaque tâche active, à programme ou à gestionnaire COM (une persistance connue, que Get-ScheduledTask montrait
    // aussi).
    if let Some(taches) = crate::machine::windows::planificateur::lancements() {
        for (nom, programme) in taches {
            lignes.push(trf!(
                "tâche planifiée : {} — {}",
                "scheduled task: {} — {}",
                affichable(&nom),
                affichable(&programme)
            ));
        }
    } else {
        let script = tr!(
            "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
             ForEach-Object { \"tâche planifiée : $($_.TaskName) — $($_.Actions.Execute)\" }",
            "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | \
             ForEach-Object { \"scheduled task: $($_.TaskName) — $($_.Actions.Execute)\" }"
        );
        match crate::machine::windows::ps(script) {
            Some(sortie) => lignes.extend(sortie.lines().filter(|l| !l.trim().is_empty()).map(affichable)),
            None => non_lus.push(tr!("tâches planifiées", "scheduled tasks").to_string()),
        }
    }
    (lignes, non_lus)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests_cle {
    use super::*;
    use std::path::Path;

    /// Un nom d'entrée d'archive piégé (effacement de ligne, couleur, cloche) ne passe jamais tel quel à l'écran,
    /// quelle que soit la branche du verdict qui le porte.
    #[test]
    fn ligne_du_verdict_sans_sequence_d_echappement() {
        let piege = "a.zip/\u{1b}[2K\r\u{1b}[32mrien\u{7}.7z".to_string();
        let examens = [
            Examen::Impossible(piege.clone()),
            Examen::Trouve(vec![piege.clone()]),
            Examen::SainSousReserve(vec![piege.clone()]),
            Examen::Suspect {
                signes: vec![piege.clone()],
                manques: vec![piege.clone()],
                reserves: vec![piege.clone()],
            },
        ];
        for examen in &examens {
            let (_, texte) = examen.ligne("Vanguard");
            assert!(
                !texte.chars().any(char::is_control),
                "séquence de contrôle à l'écran : {texte:?}"
            );
        }
    }

    /// P19 : le moteur de Vanguard n'est principal que si la personne a coupé Defender par son choix noté ; Defender
    /// allumé, ou passif derrière un autre antivirus, garde la première place ; un Defender coupé sans choix ou
    /// illisible n'est jamais compté comme une protection, et ce qui manque est dit (refus avant lancement, AMSI,
    /// nuage).
    #[test]
    fn place_du_moteur_selon_defender() {
        use crate::options_defense::ModeDefender as M;
        assert_eq!(place_du_moteur(M::Actif, Some(true), false), PlaceDuMoteur::SecondAvis);
        // Une note restée alors que Defender a été rallumé depuis : il protège, il reste premier.
        assert_eq!(place_du_moteur(M::Actif, Some(true), true), PlaceDuMoteur::SecondAvis);
        assert_eq!(
            place_du_moteur(M::Passif, Some(false), false),
            PlaceDuMoteur::SecondAvis
        );
        assert_eq!(place_du_moteur(M::BlocageEdr, None, false), PlaceDuMoteur::SecondAvis);
        assert_eq!(place_du_moteur(M::Actif, Some(false), true), PlaceDuMoteur::Principal);
        assert_eq!(place_du_moteur(M::Coupe, None, true), PlaceDuMoteur::Principal);
        // Coupé sans choix (un programme, un réglage d'ailleurs) ou illisible : non vérifié.
        assert_eq!(place_du_moteur(M::Actif, Some(false), false), PlaceDuMoteur::NonVerifie);
        assert_eq!(place_du_moteur(M::Coupe, Some(false), false), PlaceDuMoteur::NonVerifie);
        assert_eq!(place_du_moteur(M::Illisible, None, false), PlaceDuMoteur::NonVerifie);
        assert_eq!(place_du_moteur(M::Actif, None, false), PlaceDuMoteur::NonVerifie);
        assert_eq!(place_du_moteur(M::Illisible, None, true), PlaceDuMoteur::NonVerifie);
        for p in [PlaceDuMoteur::Principal, PlaceDuMoteur::NonVerifie] {
            let manque = p.ce_qui_manque();
            assert!(manque.contains("AMSI") && manque.contains("lancement"), "{manque}");
        }
        assert_eq!(PlaceDuMoteur::SecondAvis.ce_qui_manque(), "");
    }

    #[test]
    fn volumes_de_lsblk() {
        let texte = "RM=\"0\" HOTPLUG=\"0\" LABEL=\"\" SIZE=\"931,5G\" MOUNTPOINT=\"/\"\n\
                     RM=\"1\" HOTPLUG=\"1\" LABEL=\"\" SIZE=\"28,9G\" MOUNTPOINT=\"\"\n\
                     RM=\"1\" HOTPLUG=\"1\" LABEL=\"MA\\x20CLE\" SIZE=\"28,8G\" MOUNTPOINT=\"/run/media/alice/MA\\x20CLE\"\n\
                     RM=\"0\" HOTPLUG=\"1\" LABEL=\"\" SIZE=\"1T\" MOUNTPOINT=\"/run/media/alice/disque\"\n";
        let v = lire_lsblk(texte);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, PathBuf::from("/run/media/alice/MA CLE"));
        assert_eq!(v[0].1, "MA CLE · 28,8G");
        assert_eq!(v[1].1, "1T");
        // L'étiquette d'une clé USB est choisie par qui l'a préparée : piégée, elle arrive inoffensive.
        let piege = "RM=\"1\" HOTPLUG=\"1\" LABEL=\"CLE\x1b]52;c;eA==\x07\u{202e}\" SIZE=\"8G\" MOUNTPOINT=\"/run/media/alice/CLE\"\n";
        assert_eq!(lire_lsblk(piege)[0].1, "CLE�]52;c;eA==�� · 8G");
    }

    #[test]
    fn tailles_et_etiquettes_comme_lsblk() {
        assert_eq!(taille_lsblk(512), "512B");
        assert_eq!(taille_lsblk(47 << 30), "47G");
        assert_eq!(taille_lsblk(32 << 20), "32M");
        // 2,9 Gio + un peu : le dixième est arrondi, comme util-linux.
        let t = taille_lsblk((29 << 30) / 10 + 1);
        assert!(t == "2,9G" || t == "2.9G", "{t}");
        // 1023,96 Mio s'arrondit à 1024M, pas à « 1023,10M ».
        assert_eq!(taille_lsblk((1 << 30) - (40 << 10)), "1024M");
        assert_eq!(sans_hex("MA\\x20CLE"), "MA CLE");
        assert_eq!(sans_hex("caf\\xc3\\xa9\\x2"), "café\\x2");
    }

    /// Une arborescence inventée : une clé USB (amovible), un disque USB branché à chaud, le disque interne, un
    /// volume chiffré sur la clé, un sous-volume Btrfs monté avant le volume entier.
    #[cfg(target_os = "linux")]
    #[test]
    fn volumes_lus_dans_sys() {
        use std::os::unix::fs::symlink;
        let r = crate::essais::temporaire().join(format!("vanguard-antivirus-volumes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        let ecrire = |chemin: &str, texte: &str| {
            let f = sous(&r, chemin);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, texte).unwrap();
        };
        let usb = "/sys/devices/pci0/usb2/2-1";
        ecrire(&format!("{usb}/removable"), "removable\n");
        ecrire("/sys/devices/pci0/ata1/removable", "fixed\n");
        for (disque, appareil, amovible, parts) in [
            ("sdb", format!("{usb}/host6/block/sdb"), "1", 1),
            ("sdc", format!("{usb}/host7/block/sdc"), "0", 1),
            ("sda", "/sys/devices/pci0/ata1/host0/block/sda".to_string(), "0", 2),
        ] {
            ecrire(&format!("{appareil}/removable"), amovible);
            std::fs::create_dir_all(sous(&r, &format!("{appareil}/appareil"))).unwrap();
            symlink(
                sous(&r, &format!("{appareil}/appareil")),
                sous(&r, &format!("{appareil}/device")),
            )
            .unwrap();
            for p in 1..=parts {
                ecrire(&format!("{appareil}/{disque}{p}/partition"), &p.to_string());
                ecrire(&format!("{appareil}/{disque}{p}/size"), "61440000");
                ecrire(&format!("/dev/{disque}{p}"), "");
                std::fs::create_dir_all(sous(&r, "/sys/class/block")).unwrap();
                symlink(
                    sous(&r, &format!("{appareil}/{disque}{p}")),
                    sous(&r, &format!("/sys/class/block/{disque}{p}")),
                )
                .unwrap();
            }
        }
        // Le volume chiffré dm-0 repose sur sdb1 ; /dev/mapper/coffre pointe vers lui.
        ecrire("/sys/devices/virtual/block/dm-0/size", "2048");
        ecrire("/sys/devices/virtual/block/dm-0/removable", "0");
        std::fs::create_dir_all(sous(&r, "/sys/devices/virtual/block/dm-0/slaves")).unwrap();
        symlink(
            sous(&r, "/sys/class/block/sdb1"),
            sous(&r, "/sys/devices/virtual/block/dm-0/slaves/sdb1"),
        )
        .unwrap();
        symlink(
            sous(&r, "/sys/devices/virtual/block/dm-0"),
            sous(&r, "/sys/class/block/dm-0"),
        )
        .unwrap();
        ecrire("/dev/dm-0", "");
        std::fs::create_dir_all(sous(&r, "/dev/mapper")).unwrap();
        symlink("../dm-0", sous(&r, "/dev/mapper/coffre")).unwrap();
        std::fs::create_dir_all(sous(&r, "/dev/disk/by-label")).unwrap();
        symlink("../../sdb1", sous(&r, "/dev/disk/by-label/MA\\x20CLE")).unwrap();
        let mountinfo = "22 1 259:2 / / rw - ext4 /dev/sda2 rw\n\
                         30 22 8:17 /@donnees /run/media/alice/sous-volume rw - btrfs /dev/sdc1 rw\n\
                         31 22 8:17 / /run/media/alice/disque\\040USB rw - btrfs /dev/sdc1 rw\n\
                         32 22 8:17 / /run/media/alice/MA\\040CLE rw - vfat /dev/sdb1 rw\n\
                         33 22 254:0 / /run/media/alice/coffre rw - ext4 /dev/mapper/coffre rw\n\
                         34 22 0:5 / /proc rw - proc proc rw\n\
                         35 22 8:1 / /boot rw - vfat /dev/sda1 rw\n";
        let v = volumes_amovibles_sous(&r, mountinfo);
        let points: Vec<&std::path::Path> = v.iter().map(|(p, _)| p.as_path()).collect();
        assert_eq!(
            points,
            [
                std::path::Path::new("/run/media/alice/disque USB"),
                std::path::Path::new("/run/media/alice/MA CLE"),
                std::path::Path::new("/run/media/alice/coffre")
            ]
        );
        assert!(v[1].1.starts_with("MA CLE · 29"), "{}", v[1].1);
        assert_eq!(v[2].1, "1M");
        let _ = std::fs::remove_dir_all(&r);
    }

    /// Sur cet ordinateur, chaque volume amovible que lsblk montre se retrouve dans la lecture directe, avec la
    /// même étiquette ; en plus, seulement des volumes chiffrés ou LVM posés sur un disque amovible.
    #[cfg(target_os = "linux")]
    #[test]
    fn volumes_comme_lsblk() {
        let Some(r) = crate::commande::lancer(
            Command::new("lsblk").args(["-Pno", "RM,HOTPLUG,LABEL,SIZE,MOUNTPOINT"]),
            10,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("lsblk absent");
        };
        let Ok(montages) = std::fs::read_to_string("/proc/self/mountinfo") else {
            return crate::essais::saute("/proc/self/mountinfo illisible");
        };
        let lus = volumes_amovibles_sous(std::path::Path::new("/"), &montages);
        let dits = lire_lsblk(&r.sortie);
        for (point, nom) in &dits {
            let etiquette = |n: &str| n.rsplit_once(" · ").map(|(e, _)| e.to_string());
            let trouve = lus.iter().find(|(p, _)| p == point);
            assert!(trouve.is_some(), "{point:?} : {lus:?}");
            assert_eq!(etiquette(nom), etiquette(&trouve.unwrap().1), "{point:?}");
        }
        for (point, _) in &lus {
            let dm = montages.lines().any(|l| {
                l.contains(&format!(" {} ", point.display().to_string().replace(' ', "\\040")))
                    && (l.contains(" /dev/mapper/") || l.contains(" /dev/dm-"))
            });
            assert!(dm || dits.iter().any(|(p, _)| p == point), "{point:?} : {dits:?}");
        }
    }

    #[test]
    fn pieges_de_cle() {
        let e = |l: &[(&str, bool)]| l.iter().map(|(n, d)| ((*n).to_string(), *d)).collect::<Vec<_>>();
        // Ver de raccourcis : dossier caché + raccourci du même nom, autorun, script.
        let s = signes_de_ver(&e(&[
            ("Photos", true),
            ("Photos.lnk", false),
            ("autorun.inf", false),
            ("x.vbs", false),
            ("notes.txt", false),
        ]));
        assert_eq!(s.len(), 3);
        assert_eq!(s.iter().filter(|(n, _)| *n == Niveau::Eleve).count(), 2);
        // Clé normale.
        assert_eq!(
            signes_de_ver(&e(&[
                ("Photos", true),
                ("cv.pdf", false),
                ("jeu.lnk", false),
                ("a", false),
                ("b", false)
            ])),
            vec![]
        );
        // Clé Vanguard : son autorun et son lanceur sont attendus.
        assert_eq!(
            signes_de_ver(&e(&[("vanguard.cle", false), ("autorun.inf", false)])),
            vec![]
        );
    }

    #[test]
    fn menaces_de_defender() {
        let sortie = "Scan starting...\nScan finished.\nScanning C:\\Users\\alice\\Downloads\\x.exe found 1 threats.\n\n\
                      ----------------------------- Threat information ------------------------------\n\
                      Threat                  : Virus:DOS/EICAR_Test_File\n\
                      Resources               : 1 total\n";
        assert_eq!(menaces_mpcmdrun(sortie), ["Virus:DOS/EICAR_Test_File"]);
        assert_eq!(
            lire_mpcmdrun(Some(2), sortie, false),
            Examen::Trouve(vec!["Virus:DOS/EICAR_Test_File".into()])
        );
        // Nommée, la menace l'emporte même sur une phrase « skipped » ailleurs dans la sortie.
        assert!(matches!(
            lire_mpcmdrun(Some(2), &format!("{sortie}Scanning C:\\autre was skipped.\n"), true),
            Examen::Trouve(_)
        ));
        // Fichier exclu de Defender : code 2, rien d'analysé, ce n'est pas une menace (CI de GitHub).
        let saute = "Scan starting...\nScan finished.\n  Scanning C:\\Users\\alice\\notes.txt was skipped.  \n";
        assert!(matches!(lire_mpcmdrun(Some(2), saute, true), Examen::Impossible(r) if r == raison_sautee()));
        // La phrase dans le nom du fichier, ou une menace comptée sans être nommée : pas un saut.
        for piege in [
            "Scanning C:\\Users\\alice\\facture was skipped.exe found 1 threats.\n",
            "Scanning C:\\a was skipped. b.exe found 1 threats.\nScanning C:\\a was skipped.\n",
            "Scan finished. was skipped.\n",
        ] {
            assert!(
                matches!(lire_mpcmdrun(Some(2), piege, true), Examen::Trouve(_)),
                "{piege}"
            );
        }
        // La ligne citée a une borne, quel que soit le chemin.
        let long = format!("Scanning C:\\{} found 1 threats.\n", "a".repeat(5000));
        let Examen::Trouve(n) = lire_mpcmdrun(Some(2), &long, true) else {
            panic!("long")
        };
        assert!(n[0].chars().count() < 300, "{}", n[0].len());
        // Sauté mais le fichier a disparu : Defender l'a retiré, c'est une menace.
        assert!(matches!(lire_mpcmdrun(Some(2), saute, false), Examen::Trouve(_)));
        // Sortie inattendue : la menace est quand même dite, avec la dernière ligne de MpCmdRun pour comprendre.
        let Examen::Trouve(noms) = lire_mpcmdrun(Some(2), "Scan starting...\nAnalyse terminée\x1b[2K\n", true) else {
            panic!("code 2 sans nom")
        };
        assert_eq!(noms.len(), 1);
        assert!(noms[0].contains("Analyse terminée�[2K"), "{noms:?}");
        assert!(matches!(lire_mpcmdrun(Some(2), "", true), Examen::Trouve(n) if n.len() == 1));
        assert_eq!(menaces_mpcmdrun(""), Vec::<String>::new());
        // Code 0 sans ligne de résultat : rien ne dit que le fichier a été analysé, jamais sain.
        assert!(matches!(lire_mpcmdrun(Some(0), "", true), Examen::Impossible(_)));
        assert!(matches!(lire_mpcmdrun(Some(1), "", true), Examen::Impossible(_)));
        assert!(matches!(lire_mpcmdrun(None, "", true), Examen::Impossible(_)));
        assert_eq!(
            menaces_mpcmdrun("Threat                  : Trojan\x1b[2K\rFaux\u{202e}\n"),
            ["Trojan�[2K�Faux�"]
        );
    }

    /// Les sorties exactes de l'essai T10 (Windows 11, MpCmdRun dans une console : lignes en CRLF).
    const PASSE_6: &str = "Scan starting...\r\nScan finished.\r\n\
                           Scanning \\\\?\\C:\\Users\\Public\\vg-essai-eicar found 1 threats.\r\n";
    const PASSE_5: &str = "Scan starting...\r\nScan finished.\r\n\
                           Scanning \\\\?\\C:\\Users\\Public\\vg-essai-eicar found no threats.\r\n";

    #[test]
    fn passe_5_le_coche_seulement_avec_exclusions_et_detections_lues() {
        // Passe 5 : « found no threats », code 0, sur un dossier où EICAR était (une exclusion de Defender venait
        // d'être posée puis retirée sur lui). La phrase seule n'est qu'un « sain » à confirmer, jamais un ✔ ; la
        // séquence entière (exclusions lues avant et après l'analyse) est rejouée par
        // `passe_5_exclusion_lue_avant_l_analyse_puis_retiree`.
        assert_eq!(lire_reponse(Some(0), PASSE_5), Verdict::Sain);
        let cible = r"\\?\C:\Users\Public\vg-essai-eicar";
        let debut = date_cim("20261031194900.000000+000").unwrap();
        let eicar = Detection {
            nom: "Virus:DOS/EICAR_Test_File".into(),
            dates: vec!["20261031154905.123456-240".into()],
            ressources: vec![r"file:_C:\Users\Public\vg-essai-eicar\eicar.com".into()],
        };
        // Une détection notée pendant l'analyse, sous le dossier : menace, quoi qu'ait écrit MpCmdRun.
        let pendant = de_cette_analyse(vec![eicar.clone()], debut, Some(cible)).unwrap();
        assert_eq!(
            confirmer(lire_reponse(Some(0), PASSE_5), Some(&pendant), Some(vec![]), false),
            Verdict::Menaces(vec!["Virus:DOS/EICAR_Test_File".into()])
        );
        // Le dossier exclu (lui, un parent, ou tous les fichiers d'une extension) : pas de ✔, « rien n'est garanti ».
        let exclu = Some(exclusions_qui_couvrent(
            cible,
            true,
            &[r"C:\Users\Public\vg-essai-eicar".into()],
            &[],
            &[],
        ));
        assert_eq!(
            confirmer(lire_reponse(Some(0), PASSE_5), Some(&[]), exclu, false),
            Verdict::Exclue(vec![r"C:\Users\Public\vg-essai-eicar".into()])
        );
        // Exclusions cachées (sans droits administrateur) ou détections illisibles : pas de ✔ non plus.
        let cachees = couverture(Some((cible, true)), None, (&[vec![], vec![]], false), &[]);
        assert_eq!(
            confirmer(lire_reponse(Some(0), PASSE_5), Some(&[]), cachees, false),
            Verdict::Inverifiable
        );
        assert_eq!(
            confirmer(lire_reponse(Some(0), PASSE_5), None, Some(vec![]), false),
            Verdict::Inverifiable
        );
        // Un seul fichier : jamais « sain » dans ces cas, et l'exclusion vaut un fichier sauté.
        assert_eq!(
            examen_de(Verdict::Exclue(vec!["*.com".into()]), PASSE_5, true),
            Examen::Impossible(raison_sautee().into())
        );
        assert!(matches!(
            examen_de(Verdict::Inverifiable, PASSE_5, true),
            Examen::Impossible(_)
        ));
        // Seul « sain » qui le reste : exclusions lues, aucune ne couvre le dossier, aucune détection pendant
        // l'analyse (celle d'avant son début est de l'historique).
        let avant = Detection {
            dates: vec!["20261031150000.000000-240".into()],
            ..eicar
        };
        let rien = de_cette_analyse(vec![avant], debut, Some(cible)).unwrap();
        let aucune = exclusions_qui_couvrent(cible, true, &[r"D:\SteamLibrary".into()], &["vmdk".into()], &[]);
        assert_eq!(
            aucune,
            vec!["*.vmdk".to_string()],
            "toute extension exclue couvre un dossier"
        );
        let aucune = Some(exclusions_qui_couvrent(
            cible,
            true,
            &[r"D:\SteamLibrary".into()],
            &[],
            &[],
        ));
        assert_eq!(
            confirmer(lire_reponse(Some(0), PASSE_5), Some(&rien), aucune, false),
            Verdict::Sain
        );
    }

    #[test]
    fn reponse_de_mpcmdrun_lue_dans_la_sortie_pas_seulement_au_code() {
        // Passe 6 : menace trouvée et retirée, code 0. Ce n'est pas « aucun malware ».
        assert_eq!(lire_reponse(Some(0), PASSE_6), Verdict::Menaces(vec![]));
        assert_eq!(lire_reponse(Some(2), PASSE_6), Verdict::Menaces(vec![]));
        let Examen::Trouve(n) = lire_mpcmdrun(Some(0), PASSE_6, false) else {
            panic!("passe 6")
        };
        assert!(n[0].contains("found 1 threats."), "{n:?}");
        assert_eq!(
            lire_reponse(Some(0), "Scanning C:\\a found 0 threats.\r\n"),
            Verdict::Sain
        );
        // Une analyse rapide ou complète écrit peut-être la phrase sans chemin.
        assert_eq!(lire_reponse(Some(0), "Scanning found no threats.\r\n"), Verdict::Sain);
        assert_eq!(
            lire_reponse(Some(0), "Scanning found 3 threats.\r\n"),
            Verdict::Menaces(vec![])
        );
        // Des lignes « Threat : … » font une menace avec n'importe quel code, même sans compte.
        let nommee = "Scan finished.\r\nThreat                  : Virus:DOS/EICAR_Test_File\r\n";
        for code in [Some(0), Some(2), Some(1), None] {
            assert_eq!(
                lire_reponse(code, nommee),
                Verdict::Menaces(vec!["Virus:DOS/EICAR_Test_File".into()]),
                "{code:?}"
            );
        }
        // Le code 2 sans rien d'écrit reste une menace ; les autres codes, un échec.
        assert_eq!(lire_reponse(Some(2), PASSE_5), Verdict::Menaces(vec![]));
        assert_eq!(lire_reponse(Some(1), PASSE_5), Verdict::Echec);
        assert_eq!(lire_reponse(None, ""), Verdict::Echec);
    }

    #[test]
    fn code_0_sans_ligne_de_resultat_n_est_pas_sain() {
        for sortie in [
            "",
            "\r\n",
            "Scan starting...\r\nScan finished.\r\n",
            // Une sortie traduite, ou d'un format inconnu.
            "Analyse en cours...\r\nAnalyse terminée : aucune menace.\r\n",
            "Scanningfound no threats.\r\n",
        ] {
            assert_eq!(lire_reponse(Some(0), sortie), Verdict::Muette, "{sortie:?}");
            assert!(matches!(lire_mpcmdrun(Some(0), sortie, true), Examen::Impossible(r) if r != raison_sautee()));
        }
        // Le code 0 veut aussi dire « menace trouvée et retirée » : le texte ne dit jamais « aucune menace ».
        let Examen::Impossible(r) = lire_mpcmdrun(Some(0), "", true) else {
            panic!("muette")
        };
        assert!(!r.contains("aucune menace") && !r.contains("no threat"), "{r}");
        assert!(r.contains("non reconnu") || r.contains("not recognized"), "{r}");
    }

    #[test]
    fn ligne_de_resultat_coupee_ou_inconnue_jamais_saine() {
        // Relecture T10 (désaccord tranché) : un saut de ligne dans le nom de la cible coupe la ligne de résultat.
        // « Scanning C:\x\a found no threats.\nb found 1 threats. » : la menace est dans la fin orpheline.
        for (sortie, attendu) in [
            (
                "Scanning C:\\x\\a found no threats.\nb found 1 threats.\n",
                Verdict::Menaces(vec![]),
            ),
            (
                "Scanning C:\\x\\a found no threats.\nb found no threats.\n",
                Verdict::Muette,
            ),
            ("Scanning C:\\x\\a\nb found no threats.\n", Verdict::Muette),
            // Une ligne « Scanning … » d'un format inconnu, à côté d'un « rien » : pas sain.
            (
                "Scanning C:\\x is being processed.\r\nScanning C:\\x found no threats.\r\n",
                Verdict::Muette,
            ),
            // Un BOM en tête (sortie relayée par PowerShell) ne cache ni la menace ni le résultat.
            ("\u{feff}Scanning C:\\x found 1 threats.\r\n", Verdict::Menaces(vec![])),
            ("\u{feff}Scanning C:\\x found no threats.\r\n", Verdict::Sain),
            ("\u{feff}Scanning C:\\x was skipped.\r\n", Verdict::Sautee),
        ] {
            assert_eq!(lire_reponse(Some(0), sortie), attendu, "{sortie:?}");
        }
        assert_eq!(compte_orphelin("b found 2 threats."), Some(2));
        assert_eq!(compte_orphelin("Scanning C:\\b found 2 threats."), None);
        assert_eq!(compte_orphelin("Scan finished."), None);
        // Et même une ligne bien formée : une cible au nom piégé (caractère de contrôle) ne donne jamais le ✔.
        assert_eq!(confirmer(Verdict::Sain, Some(&[]), Some(vec![]), true), Verdict::Muette);
        // Ce qui n'est pas « sain » passe tel quel ; une menace garde ses noms, complétés par les détections.
        assert_eq!(confirmer(Verdict::Echec, None, None, true), Verdict::Echec);
        assert_eq!(confirmer(Verdict::Sautee, Some(&[]), None, false), Verdict::Sautee);
        let d = Detection {
            nom: "Trojan:Win32/Exemple".into(),
            dates: vec![],
            ressources: vec![],
        };
        assert_eq!(
            confirmer(Verdict::Menaces(vec!["A".into()]), Some(&[d.clone(), d]), None, false),
            Verdict::Menaces(vec!["A".into(), "Trojan:Win32/Exemple".into()])
        );
    }

    #[test]
    fn detections_de_cette_analyse_seulement() {
        assert_eq!(
            date_cim("20261031154900.123456-240"),
            date_cim("20261031194900.000000+000")
        );
        assert_eq!(
            date_cim("20261031154900.123456+060").map(|d| d.to_string()).as_deref(),
            Some("2026-10-31 14:49:00")
        );
        for faux in [
            "",
            "2026",
            "20261331154900.000000+000",
            "20261031154900.000000",
            "20261031154900.000000+abc",
        ] {
            assert_eq!(date_cim(faux), None, "{faux}");
        }
        assert_eq!(chemin_de_ressource(r"file:_C:\x\a.exe"), r"C:\x\a.exe");
        assert_eq!(chemin_de_ressource(r"containerfile:_C:\x\a.zip->b.exe"), r"C:\x\a.zip");
        assert_eq!(chemin_de_ressource(r"C:\x\a.exe"), r"C:\x\a.exe");
        assert!(sous_cible(r"C:\X\A.exe", r"\\?\c:\x\"));
        assert!(sous_cible(r"\\nas\p\a", r"\\?\UNC\nas\p"));
        assert!(!sous_cible(r"C:\xy\a.exe", r"C:\x"));
        assert!(!sous_cible(r"C:\x\a.exe", ""));
        // Relecture des correctifs T10, BAS-3 : seule une ressource d'archive est coupée à « -> ».
        assert_eq!(
            chemin_de_ressource(r"file:_C:\x->y\dir\eicar.com"),
            r"C:\x->y\dir\eicar.com"
        );
        assert_eq!(chemin_de_ressource(r"CONTAINERFILE:_C:\x\a.zip->b.exe"), r"C:\x\a.zip");
        assert!(ressource_sous_cible(r"file:_C:\x->y\dir\eicar.com", r"C:\x->y\dir"));
        assert!(ressource_sous_cible(r"containerfile:_C:\x->y\a.zip->b.exe", r"C:\x->y"));
        assert!(ressource_sous_cible(r"containerfile:_C:\x\a.zip->b.exe", r"C:\x"));
        assert!(!ressource_sous_cible(r"containerfile:_D:\x\a.zip->b.exe", r"C:\x"));
        assert!(!ressource_sous_cible(r"file:_C:\x->y\eicar.com", r"C:\x"));
        assert!(!ressource_sous_cible("process:_pid:42", r"C:\x"));
        let debut = date_cim("20261031194900.000000+000").unwrap();
        let det = |date: &str, ressource: &str| Detection {
            nom: ressource.into(),
            dates: if date.is_empty() { vec![] } else { vec![date.into()] },
            ressources: if ressource.is_empty() {
                vec![]
            } else {
                vec![ressource.into()]
            },
        };
        let toutes = vec![
            det("20261031194859.000000+000", r"file:_C:\x\pendant.exe"),
            det("20261031150000.000000+000", r"file:_C:\x\avant.exe"),
            det("20261031195000.000000+000", r"file:_D:\ailleurs.exe"),
            det("20261031195000.000000+000", ""),
        ];
        let noms = |v: Option<Vec<Detection>>| v.map(|v| v.into_iter().map(|d| d.nom).collect::<Vec<_>>());
        // Sous la cible et depuis le début (deux secondes de marge) ; sans ressource, gardée.
        assert_eq!(
            noms(de_cette_analyse(toutes.clone(), debut, Some(r"C:\x"))),
            Some(vec![r"file:_C:\x\pendant.exe".to_string(), String::new()])
        );
        // Analyse rapide ou complète : tout ce qui est de cette analyse.
        assert_eq!(
            noms(de_cette_analyse(toutes.clone(), debut, None)).map(|v| v.len()),
            Some(3)
        );
        // Une détection qui compterait, sans date lisible : rien à conclure.
        let mut sans_date = toutes;
        sans_date.push(det("", r"file:_C:\x\b.exe"));
        assert_eq!(de_cette_analyse(sans_date.clone(), debut, Some(r"C:\x")), None);
        assert!(de_cette_analyse(sans_date, debut, Some(r"E:\")).is_some_and(|v| v.len() == 1));
    }

    #[test]
    fn exclusions_qui_couvrent_la_cible() {
        let v = |l: &[&str]| l.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let c = |cible: &str, dossier: bool, chemins: &[&str], ext: &[&str]| {
            exclusions_qui_couvrent(cible, dossier, &v(chemins), &v(ext), &[])
        };
        // Relecture 2 des correctifs T10, BAS-9 : « \ », « / » ou « . » seuls, rien de fixe : tout (prudence).
        for exclu in ["\\", "/", " . "] {
            assert_eq!(c(r"C:\x\a.pdf", false, &[exclu], &[]), v(&[exclu.trim()]), "{exclu}");
        }
        // Elle-même, un parent, le lecteur entier ; « \\?\ » ou non, casse ou « \ » final (relecture T10, point 6).
        for exclu in [
            r"C:\Users\Public\vg-essai-eicar",
            r"c:\users\public\",
            r"C:\",
            "C:/Users",
        ] {
            assert_eq!(
                c(r"\\?\C:\Users\Public\vg-essai-eicar", true, &[exclu], &[]),
                v(&[exclu]),
                "{exclu}"
            );
        }
        // Un dossier exclu dedans couvre une partie du dossier analysé, pas un fichier voisin.
        assert_eq!(c(r"C:\x", true, &[r"C:\x\cache"], &[]), v(&[r"C:\x\cache"]));
        assert_eq!(c(r"C:\x\a.exe", false, &[r"C:\x\a.exe.d"], &[]), Vec::<String>::new());
        assert_eq!(c(r"C:\xy", true, &[r"C:\x"], &[]), Vec::<String>::new());
        // Variables inconnues et jokers : prudence, dès que le début fixe est compatible.
        assert_eq!(
            c(r"C:\Users\alice\AppData\Local\Temp\a.exe", false, &["%TEMP%"], &[]),
            v(&["%TEMP%"])
        );
        assert_eq!(
            c(r"C:\jeux\a.exe", false, &[r"C:\jeux\*.exe"], &[]),
            v(&[r"C:\jeux\*.exe"])
        );
        assert_eq!(c(r"D:\a.exe", false, &[r"C:\jeux\*"], &[]), Vec::<String>::new());
        // Extensions : celle du fichier ; toutes pour un dossier.
        assert_eq!(c(r"C:\x\facture.PDF", false, &[], &[".pdf", "exe"]), v(&["*.pdf"]));
        assert_eq!(c(r"C:\x\facture.exe", false, &[], &["pdf"]), Vec::<String>::new());
        assert_eq!(c(r"C:\x", true, &[], &["pdf"]), v(&["*.pdf"]));
        // Listes vides : rien ne couvre. Cachées : jamais ici (`Memoire::lire` ne garde pas « N/A »).
        assert_eq!(c(r"C:\x", true, &[""], &[]), Vec::<String>::new());
        // Un nom piégé est montré inoffensif.
        assert!(
            c(r"C:\x", true, &["C:\\x\x1b[2J"], &[])
                .iter()
                .all(|x| !x.contains('\x1b'))
        );
    }

    #[test]
    fn mpcmdrun_de_la_plateforme_et_raisons_reportees() {
        let pd = r"C:\ProgramData";
        assert_eq!(
            plateforme_sure(
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\",
                pd
            )
            .as_deref(),
            Some(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0")
        );
        assert!(plateforme_sure(r"c:\programdata\microsoft\windows defender\platform\4.18.1-0", pd).is_some());
        for faux in [
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\..",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\..\..\x",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform",
            r"C:\Users\alice\Platform\4.18.1-0",
            r"D:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0.",
            "",
        ] {
            assert_eq!(plateforme_sure(faux, pd), None, "{faux}");
        }
        // Seul ce qui vaut pour tous les fichiers est reporté sur les pièces suivantes d'un courriel.
        assert!(vaut_pour_tous(raison_absent()));
        // AV5 : le second avis coupé ou sans signatures vaut aussi pour toutes les pièces, sans reposer de question.
        #[cfg(unix)]
        {
            assert!(vaut_pour_tous(raison_coupe()));
            assert!(vaut_pour_tous(raison_sans_signatures()));
            assert!(!raison_absent().contains("refusée"), "{}", raison_absent());
        }
        assert!(!vaut_pour_tous(raison_sautee()));
        let Examen::Impossible(muette) = lire_mpcmdrun(Some(0), "", true) else {
            panic!("muette")
        };
        assert!(!vaut_pour_tous(&muette));
        let Examen::Impossible(inverifiable) = examen_de(Verdict::Inverifiable, "", true) else {
            panic!("invérifiable")
        };
        assert!(!vaut_pour_tous(&inverifiable));
        // Relecture des correctifs T10, MOYEN-C : un échec d'analyse (code 2) peut ne tenir qu'à ce fichier
        // (verrouillé) ; seul MpCmdRun qui ne se lance pas ou ne finit pas vaut pour tous, sous Windows.
        assert!(!vaut_pour_tous(raison_echec()));
        assert_eq!(vaut_pour_tous(raison_injoignable()), cfg!(windows));
    }

    /// Un Defender joué d'avance pour `analyse_confirmee` : les réponses successives aux lectures des exclusions (la
    /// dernière se répète), celle de `-CheckExclusion`, l'analyse et les détections, avec le compte des appels.
    struct Double {
        exclusions: Vec<Option<[Vec<String>; 2]>>,
        /// Les politiques rendues avec chaque lecture réussie.
        politiques: Politiques,
        lectures: usize,
        exclue: Option<bool>,
        verifications: usize,
        analyse: Option<(Option<i32>, String)>,
        detections: Option<Vec<Detection>>,
        lectures_detections: usize,
        eleve: bool,
        variables: Vec<(&'static str, Vec<String>)>,
    }

    impl Double {
        fn new(exclusions: &[Option<[&[&str]; 2]>]) -> Self {
            let liste = |l: &[&str]| l.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
            Double {
                exclusions: exclusions
                    .iter()
                    .map(|e| e.map(|[c, x]| [liste(c), liste(x)]))
                    .collect(),
                politiques: Politiques::default(),
                lectures: 0,
                exclue: None,
                verifications: 0,
                analyse: Some((Some(0), PASSE_5.into())),
                detections: Some(vec![]),
                lectures_detections: 0,
                eleve: true,
                variables: vec![],
            }
        }
    }

    impl Sondes for Double {
        fn exclusions(&mut self) -> Option<([Vec<String>; 2], Politiques)> {
            let r = self
                .exclusions
                .get(self.lectures)
                .or(self.exclusions.last())
                .cloned()
                .flatten();
            self.lectures += 1;
            r.map(|l| (l, self.politiques))
        }
        fn cible_exclue(&mut self, _: &std::path::Path) -> Option<bool> {
            self.verifications += 1;
            self.exclue
        }
        fn analyser(&mut self) -> Option<(Option<i32>, String)> {
            self.analyse.clone()
        }
        fn detections(&mut self) -> Option<Vec<Detection>> {
            self.lectures_detections += 1;
            self.detections.clone()
        }
        fn maintenant(&self) -> chrono::NaiveDateTime {
            date_cim("20261031194900.000000+000").unwrap()
        }
        fn eleve(&self) -> bool {
            self.eleve
        }
        fn variables(&self) -> Vec<(&'static str, Vec<String>)> {
            self.variables.clone()
        }
    }

    const DOSSIER_T10: &str = r"\\?\C:\Users\Public\vg-essai-eicar";
    const AUCUNE: &[&str] = &[];
    const CACHEES: &[&str] = &["N/A: Must be an administrator to view exclusions"];

    fn analyser_double(d: &mut Double, cible: Option<(&str, bool)>) -> Analyse {
        analyse_confirmee(
            d,
            cible.map(|(c, dossier)| (Path::new(c), dossier)),
            &mut Memoire::default(),
        )
        .unwrap()
    }

    #[test]
    fn passe_5_exclusion_lue_avant_l_analyse_puis_retiree() {
        // Relecture des correctifs T10, HAUT-1 : l'exclusion posée sur le dossier est vue avant l'analyse, retirée
        // pendant (relue vide après) ; Defender a pu l'appliquer encore : « found no threats », aucune détection,
        // et pourtant jamais ✔.
        let mut d = Double::new(&[
            Some([&[r"C:\Users\Public\vg-essai-eicar"], AUCUNE]),
            Some([AUCUNE, AUCUNE]),
        ]);
        d.exclue = Some(false);
        let a = analyser_double(&mut d, Some((DOSSIER_T10, true)));
        assert_eq!(
            a.verdict,
            Verdict::Exclue(vec![r"C:\Users\Public\vg-essai-eicar".into()])
        );
        // Relecture 3, BAS-6 : l'exclusion vue avant couvre déjà la cible, `-CheckExclusion` ne changerait rien.
        assert_eq!((d.lectures, d.verifications, d.lectures_detections), (2, 0, 1));
        // L'inverse : posée pendant l'analyse, vue seulement après.
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE]), Some([AUCUNE, &["com"]])]);
        let a = analyser_double(&mut d, Some((DOSSIER_T10, true)));
        assert_eq!(a.verdict, Verdict::Exclue(vec!["*.com".into()]));
        // Listes vides, mais le moteur dit la cible exclue à cet instant : pas de ✔, et la cible est montrée.
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
        d.exclue = Some(true);
        let a = analyser_double(&mut d, Some((DOSSIER_T10, true)));
        assert_eq!(
            a.verdict,
            Verdict::Exclue(vec![r"C:\Users\Public\vg-essai-eicar".into()])
        );
        // Relecture 2, BAS-4 : la cible exclue selon le moteur et déjà dans les listes n'est montrée qu'une fois.
        let mut d = Double::new(&[Some([&[r"c:\users\public\vg-essai-eicar\", r"C:\Users"], AUCUNE])]);
        d.exclue = Some(true);
        let a = analyser_double(&mut d, Some((DOSSIER_T10, true)));
        assert_eq!(
            a.verdict,
            Verdict::Exclue(vec![r"c:\users\public\vg-essai-eicar\".into(), r"C:\Users".into()])
        );
        // Tout lu, rien n'exclut, aucune détection : le seul ✔.
        let mut d = Double::new(&[Some([&[r"D:\SteamLibrary"], AUCUNE])]);
        d.exclue = Some(false);
        let a = analyser_double(&mut d, Some((DOSSIER_T10, true)));
        assert_eq!(a.verdict, Verdict::Sain);
        assert!(!a.sans_droits);
        assert_eq!(a.sortie, PASSE_5, "la sortie de MpCmdRun, à montrer");
        // Une détection notée pendant l'analyse, sous le dossier : menace, et les exclusions ne sont pas relues.
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
        d.detections = Some(vec![Detection {
            nom: "Virus:DOS/EICAR_Test_File".into(),
            dates: vec!["20261031154905.123456-240".into()],
            ressources: vec![r"file:_C:\Users\Public\vg-essai-eicar\eicar.com".into()],
        }]);
        let a = analyser_double(&mut d, Some((DOSSIER_T10, true)));
        assert_eq!(a.verdict, Verdict::Menaces(vec!["Virus:DOS/EICAR_Test_File".into()]));
        assert_eq!((d.lectures, a.detections.len()), (1, 1));
        // MpCmdRun qui ne va pas au bout : rien.
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
        d.analyse = None;
        assert!(analyse_confirmee(&mut d, Some((Path::new(DOSSIER_T10), true)), &mut Memoire::default()).is_none());
        // Un nom piégé (saut de ligne) : MpCmdRun n'est pas interrogé sur lui, et jamais ✔.
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
        let a = analyser_double(&mut d, Some(("C:\\x\nScanning C:\\y found no threats.", true)));
        assert_eq!((a.verdict, d.verifications), (Verdict::Muette, 0));
    }

    #[test]
    fn sans_droits_check_exclusion_seulement_pour_exclue() {
        // Relecture 2 des correctifs T10, MOYEN-B : listes cachées, détections lisibles. Un « non exclue » de
        // MpCmdRun ne suffit plus, même pour un fichier (rien ne prouve qu'il voie les extensions exclues) ; pour un
        // dossier, il ne voit ni un sous-dossier ni une extension exclus.
        let mut d = Double::new(&[Some([CACHEES, CACHEES])]);
        d.exclue = Some(false);
        d.eleve = false;
        let a = analyser_double(&mut d, Some((r"C:\x\facture.pdf", false)));
        assert_eq!(a.verdict, Verdict::Inverifiable);
        assert!(a.sans_droits);
        assert_eq!(d.lectures, 1, "cachées : pas relues après l'analyse");
        let a = analyser_double(&mut d, Some((r"C:\x", true)));
        assert_eq!(a.verdict, Verdict::Inverifiable);
        assert!(a.sans_droits);
        // MpCmdRun refuse aussi, ou répond autrement : invérifiable, faute de droits.
        let mut d = Double::new(&[Some([CACHEES, CACHEES])]);
        d.eleve = false;
        let a = analyser_double(&mut d, Some((r"C:\x\facture.pdf", false)));
        assert_eq!(a.verdict, Verdict::Inverifiable);
        assert!(a.sans_droits);
        // Exclue selon MpCmdRun : vrai même sans les listes, pour un dossier comme pour un fichier.
        d.exclue = Some(true);
        let a = analyser_double(&mut d, Some((r"C:\x", true)));
        assert_eq!(a.verdict, Verdict::Exclue(vec![r"C:\x".into()]));
        let a = analyser_double(&mut d, Some((r"\\?\C:\x\facture.pdf", false)));
        assert_eq!(a.verdict, Verdict::Exclue(vec![r"C:\x\facture.pdf".into()]));
        // Exclusions illisibles (ni WMI ni PowerShell) : invérifiable, mais pas faute de droits, élevé ou non
        // (relecture 2, BAS-6 : relancer en administrateur n'y changerait rien).
        for eleve in [true, false] {
            let mut d = Double::new(&[None]);
            d.exclue = Some(false);
            d.eleve = eleve;
            let a = analyser_double(&mut d, Some((r"C:\x\facture.pdf", false)));
            assert_eq!(a.verdict, Verdict::Inverifiable);
            assert!(!a.sans_droits);
        }
        // Cachées en administrateur (une politique les cache aux administrateurs) : pas faute de droits non plus.
        let mut d = Double::new(&[Some([CACHEES, AUCUNE])]);
        let a = analyser_double(&mut d, Some((r"C:\x", true)));
        assert_eq!(a.verdict, Verdict::Inverifiable);
        assert!(!a.sans_droits);
    }

    #[test]
    fn sans_droits_des_listes_vides_ne_prouvent_rien() {
        // Relecture 2 des correctifs T10, MOYEN-C : sans élévation, des listes lues vides (valeur absente ou nulle au
        // lieu de « N/A ») valent des listes cachées : pas de ✔, et pas relues.
        for cible in [(r"C:\x", true), (r"C:\x\facture.pdf", false)] {
            let mut d = Double::new(&[Some([AUCUNE, &[" "]])]);
            d.exclue = Some(false);
            d.eleve = false;
            let a = analyser_double(&mut d, Some(cible));
            assert_eq!(a.verdict, Verdict::Inverifiable);
            assert!(a.sans_droits);
            assert_eq!(d.lectures, 1);
        }
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
        d.eleve = false;
        assert_eq!(analyser_double(&mut d, None).verdict, Verdict::Inverifiable);
        // Les mêmes listes vides en administrateur : lues, le ✔ reste possible.
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
        d.exclue = Some(false);
        let a = analyser_double(&mut d, Some((r"C:\x", true)));
        assert_eq!((a.verdict, d.lectures), (Verdict::Sain, 2));
        // Sans élévation, des listes qui semblent se lire (Windows d'avant 2021, qui les montrait à tous) : cachées
        // quand même, donc invérifiable et plus ✔ (relecture des correctifs T10, 4e passe, BAS-4 : rien ne distingue
        // sûrement une liste d'un refus traduit). Relancer en administrateur donnerait un verdict.
        let mut d = Double::new(&[Some([&[r"D:\SteamLibrary"], AUCUNE])]);
        d.exclue = Some(false);
        d.eleve = false;
        let a = analyser_double(&mut d, Some((r"C:\x\facture.pdf", false)));
        assert_eq!(a.verdict, Verdict::Inverifiable);
        assert!(a.sans_droits && !a.cachees_a_l_admin);
        // 4e passe, BAS-4 et BAS-3 : le refus d'un Windows français, sans le préfixe « N/A », ne passe ni pour des
        // listes lues (pas de ✔) ni pour une exclusion (pas d'« exclue » qui montrerait sa phrase).
        let refus: &[&str] = &["N/D : Vous devez être administrateur pour voir les exclusions"];
        for cible in [Some((r"C:\x\facture.pdf", false)), Some((r"C:\x", true)), None] {
            let mut d = Double::new(&[Some([refus, refus])]);
            d.exclue = Some(false);
            d.eleve = false;
            let a = analyser_double(&mut d, cible);
            assert_eq!(a.verdict, Verdict::Inverifiable, "{cible:?}");
            assert!(a.sans_droits && !a.cachees_a_l_admin);
            assert_eq!(d.lectures, 1, "cachées : pas relues");
        }
        // 5e passe, BAS-1 : élevé, sans politique lue, un refus sans « N/A » ne compte ni pour des listes lues
        // ni pour une exclusion : jamais ✔ pour un fichier.
        let refus_en: &[&str] = &["Must be an administrator to view exclusions"];
        for cible in [Some((r"C:\x\facture.pdf", false)), Some((r"C:\x", true)), None] {
            let mut d = Double::new(&[Some([refus_en, refus_en])]);
            d.exclue = Some(false);
            let a = analyser_double(&mut d, cible);
            assert_eq!(a.verdict, Verdict::Inverifiable, "{cible:?}");
        }
        assert!(!ressemble_a_un_refus(r"C:\Program Files\Steam"));
        assert!(!ressemble_a_un_refus("%ProgramData%"));
        assert!(!ressemble_a_un_refus(".vmdk"));
        let mut d = Double::new(&[Some([refus, refus])]);
        d.eleve = false;
        let mut memoire = Memoire::default();
        memoire.lire(&mut d);
        assert_eq!(memoire.listes(), (&[vec![], vec![]], false));
    }

    #[test]
    fn analyse_rapide_ou_complete_et_exclusions() {
        // Relecture des correctifs T10, MOYEN-A : sans cible, toute exclusion de chemin ou d'extension retire une
        // partie de l'analyse ; MpCmdRun n'est pas interrogé (rien à lui nommer).
        let mut d = Double::new(&[Some([&[r"D:\SteamLibrary", ""], &[".vmdk"]])]);
        let a = analyser_double(&mut d, None);
        assert_eq!(
            a.verdict,
            Verdict::Exclue(vec![r"D:\SteamLibrary".into(), "*.vmdk".into()])
        );
        assert_eq!(d.verifications, 0);
        let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
        assert_eq!(analyser_double(&mut d, None).verdict, Verdict::Sain);
        // Une exclusion vue seulement avant l'analyse compte aussi.
        let mut d = Double::new(&[Some([&[r"C:\Outils"], AUCUNE]), Some([AUCUNE, AUCUNE])]);
        assert_eq!(
            analyser_double(&mut d, None).verdict,
            Verdict::Exclue(vec![r"C:\Outils".into()])
        );
        for illisibles in [Some([CACHEES, AUCUNE]), None] {
            let mut d = Double::new(&[illisibles]);
            assert_eq!(analyser_double(&mut d, None).verdict, Verdict::Inverifiable);
        }
    }

    #[test]
    fn memoire_d_une_serie_de_pieces() {
        // Relecture des correctifs T10, BAS-6 : pour les pièces d'un courriel, ce que Windows cache ou ne rend pas
        // n'est demandé qu'une fois.
        let mut d = Double::new(&[Some([CACHEES, CACHEES])]);
        d.detections = None;
        d.eleve = false;
        let mut memoire = Memoire::default();
        for piece in [r"C:\t\a.pdf", r"C:\t\b.pdf", r"C:\t\c.pdf"] {
            let a = analyse_confirmee(&mut d, Some((Path::new(piece), false)), &mut memoire).unwrap();
            assert_eq!(a.verdict, Verdict::Inverifiable);
            assert!(a.sans_droits);
        }
        assert_eq!((d.lectures, d.lectures_detections, d.verifications), (1, 1, 3));
        // Lisibles : les exclusions vues à la première pièce valent pour les suivantes (réunies), relues après
        // chaque analyse.
        let mut d = Double::new(&[Some([&[r"C:\t\a.pdf"], AUCUNE]), Some([AUCUNE, AUCUNE])]);
        d.exclue = Some(false);
        let mut memoire = Memoire::default();
        let a = analyse_confirmee(&mut d, Some((Path::new(r"C:\t\a.pdf"), false)), &mut memoire).unwrap();
        assert_eq!(a.verdict, Verdict::Exclue(vec![r"C:\t\a.pdf".into()]));
        let b = analyse_confirmee(&mut d, Some((Path::new(r"C:\t\b.pdf"), false)), &mut memoire).unwrap();
        assert_eq!(b.verdict, Verdict::Sain);
        assert_eq!(d.lectures, 3);
        // Relecture 2 des correctifs T10, MOYEN-A : la relecture d'après l'analyse échoue (illisible) ou se cache ;
        // l'exclusion vue avant compte encore, et celles d'après étant inconnues, une pièce qu'elle ne couvre pas
        // n'est jamais saine, même « non exclue » selon MpCmdRun.
        for apres in [None, Some([CACHEES, AUCUNE])] {
            let mut d = Double::new(&[Some([&[r"C:\t"], AUCUNE]), apres]);
            d.exclue = Some(false);
            let mut memoire = Memoire::default();
            let a = analyse_confirmee(&mut d, Some((Path::new(r"C:\t\a.pdf"), false)), &mut memoire).unwrap();
            assert_eq!(a.verdict, Verdict::Exclue(vec![r"C:\t".into()]));
            let b = analyse_confirmee(&mut d, Some((Path::new(r"D:\b.pdf"), false)), &mut memoire).unwrap();
            assert_eq!(b.verdict, Verdict::Inverifiable);
            assert!(!b.sans_droits, "administrateur : relancer n'y changerait rien");
            assert_eq!(
                b.cachees_a_l_admin,
                apres.is_some(),
                "illisibles : rien ne dit qu'une politique les cache"
            );
            let c = analyse_confirmee(&mut d, None, &mut memoire).unwrap();
            assert_eq!(c.verdict, Verdict::Exclue(vec![r"C:\t".into()]));
            assert_eq!(d.lectures, 2, "refusées ou illisibles : plus relues");
        }
    }

    #[test]
    fn politique_qui_cache_les_exclusions() {
        // Relecture des correctifs T10, 3e passe, MOYEN-1 : HideExclusionsFromLocalAdmins peut rendre des listes
        // vides plutôt que « N/A » ; en administrateur, vides, elles ne prouvent alors plus rien.
        let admins = Politiques {
            aux_admins: true,
            aux_utilisateurs: true,
        };
        let utilisateurs = Politiques {
            aux_admins: false,
            aux_utilisateurs: true,
        };
        for cible in [Some((DOSSIER_T10, true)), Some((r"C:\x\facture.pdf", false)), None] {
            let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
            d.exclue = Some(false);
            d.politiques = admins;
            let a = analyser_double(&mut d, cible);
            assert_eq!(a.verdict, Verdict::Inverifiable, "{cible:?}");
            // BAS-2 : la cause est dite, sans proposer de relancer en administrateur.
            assert!(a.cachees_a_l_admin && !a.sans_droits);
            assert_eq!(d.lectures, 1, "cachées : pas relues");
            // Politique fausse, ou absente (Windows plus ancien : fausse aussi) : lues, le ✔ reste possible.
            for p in [Politiques::default(), utilisateurs] {
                let mut d = Double::new(&[Some([AUCUNE, AUCUNE])]);
                d.exclue = Some(false);
                d.politiques = p;
                let a = analyser_double(&mut d, cible);
                assert_eq!(a.verdict, Verdict::Sain, "{cible:?}");
                assert!(!a.cachees_a_l_admin && !a.sans_droits);
            }
        }
        // 4e passe, BAS-3 : sous la politique, ce qui se lit n'entre pas dans les exclusions vues (un texte lu sous
        // un refus n'est pas une exclusion) ; invérifiable, et MpCmdRun peut encore prouver une exclusion.
        let mut d = Double::new(&[Some([&[r"C:\x"], AUCUNE])]);
        d.politiques = admins;
        let a = analyser_double(&mut d, Some((r"C:\x\facture.pdf", false)));
        assert_eq!(a.verdict, Verdict::Inverifiable);
        let a = analyser_double(&mut d, Some((r"D:\facture.pdf", false)));
        assert_eq!(a.verdict, Verdict::Inverifiable);
        d.exclue = Some(true);
        let a = analyser_double(&mut d, Some((r"C:\x\facture.pdf", false)));
        assert_eq!(a.verdict, Verdict::Exclue(vec![r"C:\x\facture.pdf".into()]));
        // Sans élévation, l'une ou l'autre cache (dans le doute). Celle des utilisateurs seule : relancer en
        // administrateur donnerait un verdict ; celle des administrateurs : non.
        for (p, relancer) in [(utilisateurs, true), (admins, false)] {
            let mut d = Double::new(&[Some([&[r"D:\SteamLibrary"], AUCUNE])]);
            d.exclue = Some(false);
            d.eleve = false;
            d.politiques = p;
            let a = analyser_double(&mut d, Some((r"C:\x\facture.pdf", false)));
            assert_eq!(a.verdict, Verdict::Inverifiable);
            assert_eq!((a.sans_droits, a.cachees_a_l_admin), (relancer, !relancer));
        }
        // « N/A » en administrateur : une politique aussi, sous l'autre forme.
        let mut d = Double::new(&[Some([CACHEES, CACHEES])]);
        let a = analyser_double(&mut d, None);
        assert_eq!(a.verdict, Verdict::Inverifiable);
        assert!(a.cachees_a_l_admin && !a.sans_droits);
        // BAS-5 : « N/A » n'entre jamais dans les exclusions vues ; 4e passe, BAS-3 : ce qui se lit à côté non plus.
        let mut d = Double::new(&[Some([CACHEES, &["pdf", " "]])]);
        let mut memoire = Memoire::default();
        memoire.lire(&mut d);
        assert_eq!(memoire.listes(), (&[vec![], vec![]], false));
    }

    #[test]
    fn extension_blanche() {
        // Relecture des correctifs T10, 4e passe, BAS-5 : une extension blanche n'est pas une exclusion, avec ou sans
        // cible (avant : « *. » pour une cible, ✔ sans cible), et n'entre pas dans les exclusions vues.
        let blanches: &[&str] = &["", "  "];
        let mut d = Double::new(&[Some([&["", " "], blanches])]);
        let mut memoire = Memoire::default();
        memoire.lire(&mut d);
        assert_eq!(memoire.listes(), (&[vec![], vec![]], true));
        for cible in [Some((r"C:\x\facture.pdf", false)), Some((r"C:\x", true)), None] {
            let mut d = Double::new(&[Some([AUCUNE, blanches])]);
            d.exclue = Some(false);
            assert_eq!(analyser_double(&mut d, cible).verdict, Verdict::Sain, "{cible:?}");
        }
        assert_eq!(
            exclusions_qui_couvrent(r"C:\x\a.pdf", false, &[], &[" ".into()], &[]),
            Vec::<String>::new()
        );
        // « * » ou « . » seuls couvrent tout fichier, montrés tels qu'écrits, jamais « *. » ; de même sans cible.
        let jokers = ["*".to_string(), " . ".to_string(), ".PDF".to_string()];
        assert_eq!(
            exclusions_qui_couvrent(r"C:\x\a.pdf", false, &[], &jokers, &[]),
            ["*", ".", "*.PDF"]
        );
        assert_eq!(
            couverture(None, None, (&[vec![], jokers.to_vec()], true), &[]),
            Some(vec!["*".into(), ".".into(), "*.PDF".into()])
        );
    }

    #[test]
    fn check_exclusion_seulement_s_il_peut_changer_le_verdict() {
        // Relecture des correctifs T10, 3e passe, BAS-6 : une pièce déjà couverte par une exclusion vue n'est pas
        // soumise à MpCmdRun (« exclue » de toute façon) ; les autres, si.
        let mut d = Double::new(&[Some([&[r"C:\t"], AUCUNE])]);
        d.exclue = Some(true);
        let mut memoire = Memoire::default();
        for piece in [r"C:\t\a.pdf", r"c:\T\b.pdf"] {
            let a = analyse_confirmee(&mut d, Some((Path::new(piece), false)), &mut memoire).unwrap();
            assert_eq!(a.verdict, Verdict::Exclue(vec![r"C:\t".into()]));
        }
        assert_eq!(d.verifications, 0);
        let a = analyse_confirmee(&mut d, Some((Path::new(r"D:\c.pdf"), false)), &mut memoire).unwrap();
        assert_eq!(a.verdict, Verdict::Exclue(vec![r"D:\c.pdf".into()]));
        assert_eq!(d.verifications, 1);
        // Relue illisible après l'analyse : vue avant, donc toujours couverte.
        let mut d = Double::new(&[Some([AUCUNE, &["pdf"]]), None]);
        let mut memoire = Memoire::default();
        let a = analyse_confirmee(&mut d, Some((Path::new(r"C:\t\a.pdf"), false)), &mut memoire).unwrap();
        assert_eq!((a.verdict, d.verifications), (Verdict::Exclue(vec!["*.pdf".into()]), 0));
        // Rien de vu qui couvre : demandée, même avec des listes cachées (« exclue » reste une preuve).
        let mut d = Double::new(&[Some([CACHEES, CACHEES])]);
        d.exclue = Some(true);
        let a = analyser_double(&mut d, Some((r"C:\t\a.pdf", false)));
        assert_eq!(
            (a.verdict, d.verifications),
            (Verdict::Exclue(vec![r"C:\t\a.pdf".into()]), 1)
        );
    }

    #[test]
    fn reponse_de_check_exclusion() {
        let oui = r"C:\Data\Test [\Device\HarddiskVolume1\Data\Test] is excluded. Exit code is 0.";
        let non = r"C:\Data\Test [\Device\HarddiskVolume1\Data\Test] is not excluded. Exit code is 1.";
        assert_eq!(exclusion_selon_mpcmdrun(Some(0), oui), Some(true));
        assert_eq!(exclusion_selon_mpcmdrun(None, oui), Some(true));
        assert_eq!(
            exclusion_selon_mpcmdrun(Some(0), &format!("\u{feff}{oui}\r\n")),
            Some(true)
        );
        assert_eq!(
            exclusion_selon_mpcmdrun(
                Some(0),
                r"C:\Data\Test [\Device\HarddiskVolume1\Data\Test] is excluded."
            ),
            Some(true)
        );
        assert_eq!(exclusion_selon_mpcmdrun(Some(1), non), Some(false));
        assert_eq!(
            exclusion_selon_mpcmdrun(Some(1), &format!("{non}\r\n\r\n")),
            Some(false)
        );
        // « Non exclue » demande le code 1 ; une ligne « exclue » l'emporte (prudence).
        assert_eq!(exclusion_selon_mpcmdrun(Some(0), non), None);
        assert_eq!(exclusion_selon_mpcmdrun(Some(1), &format!("{non}\n{oui}")), Some(true));
        // Seule la fin de la ligne compte : un nom qui contient « is excluded. » ne trompe pas.
        assert_eq!(
            exclusion_selon_mpcmdrun(
                Some(1),
                r"C:\a is excluded.\b [\Device\x] is not excluded. Exit code is 1."
            ),
            Some(false)
        );
        for autre in [
            "",
            "N/A: Must be an administrator to check exclusions",
            "CmdTool: Failed with hr = 0x80070005. Check C:\\Users\\alice\\AppData\\Local\\Temp\\MpCmdRun.log",
            "Usage: MpCmdRun.exe [command-specific-arguments]",
        ] {
            assert_eq!(exclusion_selon_mpcmdrun(Some(2), autre), None, "{autre}");
            assert_eq!(exclusion_selon_mpcmdrun(Some(1), autre), None, "{autre}");
        }
    }

    #[test]
    fn variables_des_exclusions() {
        // Relecture des correctifs T10, MOYEN-D : les variables connues développées, jamais par l'environnement du
        // processus.
        let variables = variables_de_defender(&Racines {
            windows: Some(r"C:\Windows"),
            program_files: Some(r"C:\Program Files\"),
            program_data: Some(r"C:\ProgramData"),
            profil: Some(r"C:\Users\alice"),
            local: Some(r"C:\Users\alice\AppData\Local"),
            ..Racines::default()
        });
        let valeurs = |nom: &str| variables.iter().find(|(v, _)| *v == nom).map(|(_, x)| x.clone());
        assert_eq!(
            valeurs("TEMP"),
            Some(vec![
                r"C:\Windows\Temp".into(),
                r"C:\Users\alice\AppData\Local\Temp".into()
            ])
        );
        assert_eq!(
            valeurs("USERPROFILE"),
            Some(vec![
                r"C:\Windows\System32\config\systemprofile".into(),
                r"C:\Users\alice".into()
            ])
        );
        assert_eq!(valeurs("PROGRAMFILES"), Some(vec![r"C:\Program Files".into()]));
        assert_eq!(valeurs("SYSTEMDRIVE"), Some(vec!["C:".into()]));
        assert_eq!(valeurs("PROGRAMFILES(X86)"), None, "absent : inconnue");
        assert_eq!(valeurs("PUBLIC"), None);
        assert_eq!(
            formes_developpees(r"%programfiles%\Steam\:{PathType:folder}", &variables),
            [r"C:\Program Files\Steam\"]
        );
        assert_eq!(formes_developpees(r"%TEMP%\x", &variables).len(), 2);
        assert_eq!(formes_developpees(r"%PUBLIC%\x", &variables), [r"%PUBLIC%\x"]);
        assert_eq!(formes_developpees(r"C:\100%\x", &variables), [r"C:\100%\x"]);
        let beaucoup = vec![("A", (0..10).map(|i| i.to_string()).collect::<Vec<_>>())];
        let formes = formes_developpees("%A%%A%%A%", &beaucoup);
        assert_eq!(formes.len(), 10);
        assert!(formes.iter().all(|f| f.ends_with("%A%%A%")));
        let c = |cible: &str, exclu: &str| exclusions_qui_couvrent(cible, false, &[exclu.to_string()], &[], &variables);
        // Développée : ne couvre plus « tout ce qui commence par rien ».
        assert_eq!(c(r"D:\Jeux\x.exe", r"%ProgramFiles%\Steam"), Vec::<String>::new());
        assert_eq!(
            c(r"C:\Program Files\Steam\x.exe", r"%ProgramFiles%\Steam"),
            [r"%ProgramFiles%\Steam"]
        );
        assert_eq!(c(r"C:\Windows\Temp\x.exe", r"%TEMP%"), ["%TEMP%"], "le TEMP de SYSTEM");
        assert_eq!(c(r"C:\Users\alice\AppData\Local\Temp\x.exe", r"%TEMP%").len(), 1);
        assert_eq!(c(r"D:\x.exe", r"%TEMP%"), Vec::<String>::new());
        // Inconnue : couvre, montrée telle quelle.
        assert_eq!(c(r"D:\Jeux\x.exe", r"%PUBLIC%\x"), [r"%PUBLIC%\x"]);
    }

    #[test]
    fn exclusion_et_cible_normalisees_pareil() {
        // Relecture des correctifs T10, BAS-2.
        assert_eq!(pour_comparer(r"C:\x\z\..\y"), pour_comparer(r"C:\x\y"));
        assert_eq!(pour_comparer(r"C:\x\\y\.\"), r"C:\X\Y");
        assert_eq!(pour_comparer(r"C:\..\..\x"), r"C:\X");
        assert_eq!(pour_comparer(r"\\?\UNC\nas\p\..\..\x"), r"\\NAS\P\X");
        assert_eq!(pour_comparer(r"\\nas\p\x"), pour_comparer(r"\\?\UNC\NAS\P\X\"));
        assert_eq!(pour_comparer(r"\\?\c:\"), "C:");
        // NTFS compare par sa table de majuscules : σ et ς sont tous deux Σ (`to_lowercase` les sépare).
        assert_eq!(pour_comparer("C:\\ΟΔΟΣ"), pour_comparer("C:\\οδοσ"));
        let c = |cible: &str, exclu: &str| exclusions_qui_couvrent(cible, false, &[exclu.to_string()], &[], &[]).len();
        assert_eq!(c(r"\\?\C:\x\y\a.exe", r"C:\x\z\..\y"), 1);
        assert_eq!(c(r"\\?\C:\x\y\a.exe", r"C:\x\\y"), 1);
        assert_eq!(c("C:\\οδοσ\\a.exe", "c:\\ΟΔΟΣ"), 1);
        assert_eq!(c(r"C:\x\y\a.exe", r"C:\x\y\..\..\z"), 0);
        // Extension : majuscules Unicode des deux côtés, montrée telle qu'écrite.
        assert_eq!(
            exclusions_qui_couvrent(r"C:\x\a.ΣΚ", false, &[], &[".σκ".into()], &[]),
            ["*.σκ"]
        );
        // Le BOM devant « Threat » (relecture BAS-1).
        assert_eq!(
            menaces_mpcmdrun("\u{feff}Threat : Trojan:Win32/X\r\n"),
            ["Trojan:Win32/X"]
        );
    }

    #[test]
    fn nom_de_dossier_piege_dans_la_ligne_de_resultat() {
        // Le nom vient de qui a créé le dossier : seule la fin de la ligne, écrite par MpCmdRun, compte.
        for (sortie, attendu) in [
            (
                "Scanning C:\\x found no threats found 1 threats.\r\n",
                Verdict::Menaces(vec![]),
            ),
            (
                "Scanning C:\\x found no threats.\r\nScanning C:\\y found 2 threats.\r\n",
                Verdict::Menaces(vec![]),
            ),
            ("Scanning C:\\found 1 threats found no threats.\r\n", Verdict::Sain),
            (
                "Scanning C:\\x found 99999999999999999999999 threats.\r\n",
                Verdict::Menaces(vec![]),
            ),
            ("Scanning C:\\x found many threats.\r\n", Verdict::Menaces(vec![])),
            // Une fausse ligne « rien » avant un saut : le saut l'emporte, rien n'est sain.
            (
                "Scanning C:\\x found no threats.\r\nScanning C:\\x was skipped.\r\n",
                Verdict::Sautee,
            ),
        ] {
            assert_eq!(lire_reponse(Some(0), sortie), attendu, "{sortie:?}");
        }
        assert_eq!(compte_de_menaces("  Scanning C:\\a found 1 threat.  "), Some(1));
        assert_eq!(compte_de_menaces("Scan finished."), None);
        assert_eq!(compte_de_menaces("Scanning C:\\a was skipped."), None);
    }

    #[test]
    fn fichier_saute_avec_le_code_0_ou_2() {
        let saute = "Scan starting...\r\nScan finished.\r\nScanning C:\\Users\\alice\\notes.txt was skipped.\r\n";
        for code in [Some(0), Some(2)] {
            assert_eq!(lire_reponse(code, saute), Verdict::Sautee);
            assert!(matches!(lire_mpcmdrun(code, saute, true), Examen::Impossible(r) if r == raison_sautee()));
            assert!(matches!(lire_mpcmdrun(code, saute, false), Examen::Trouve(_)));
        }
        // La phrase dans le nom du fichier n'est pas un saut.
        assert_eq!(
            lire_reponse(Some(0), "Scanning C:\\facture was skipped.exe found no threats.\r\n"),
            Verdict::Sain
        );
    }

    #[test]
    fn prefixe_etendu_retire_seulement_sans_ambiguite() {
        let s = |c: &str| sans_verbatim(c);
        assert_eq!(
            s(r"\\?\C:\Users\Public\vg-essai-eicar").as_deref(),
            Some(r"C:\Users\Public\vg-essai-eicar")
        );
        assert_eq!(s(r"\\?\d:\").as_deref(), Some(r"d:\"));
        assert_eq!(
            s(r"\\?\C:\Données\été 2026\a.b.txt").as_deref(),
            Some(r"C:\Données\été 2026\a.b.txt")
        );
        assert_eq!(s(r"\\?\UNC\nas\partage\x").as_deref(), Some(r"\\nas\partage\x"));
        assert_eq!(s(r"\\?\UNC\nas\partage").as_deref(), Some(r"\\nas\partage"));
        // Déjà court, ou une forme sans équivalent court : tel quel.
        for c in [
            r"C:\Users\alice",
            r"\\nas\partage",
            r"\\?\Volume{1234}\a",
            r"\\?\GLOBALROOT\Device\x",
            r"\\?\UNC\nas",
            r"\\?\UNC\",
            r"\\?\",
            r"\\?\C:",
            r"\\?\1:\x",
            r"\\.\C:\x",
        ] {
            assert_eq!(s(c), None, "{c}");
        }
        // Ce que Windows réinterpréterait sans « \\?\ » : un autre fichier, ou un périphérique.
        for c in [
            r"\\?\C:\x\dossier.",
            r"\\?\C:\x\dossier ",
            r"\\?\C:\x\..\y",
            r"\\?\C:\x\.\y",
            r"\\?\C:\x\\y",
            r"\\?\C:\x\",
            r"\\?\C:\x\CON",
            r"\\?\C:\x\nul.txt",
            r"\\?\C:\x\Aux .log",
            r"\\?\C:\x\com1",
            r"\\?\C:\x\LPT¹",
            r"\\?\C:\x\CONOUT$",
            r"\\?\C:\x\a:flux",
            r"\\?\C:\x\a*b",
            "\\\\?\\C:\\x\\a\u{1}b",
            r"\\?\UNC\nas\partage.\x",
        ] {
            assert_eq!(s(c), None, "{c}");
        }
        // Les noms qui ressemblent sans l'être restent courts.
        assert!(s(r"\\?\C:\x\CONSOLE\com10\nul2.txt\.config").is_some());
        // MAX_PATH : 259 caractères au plus, le nul final en plus.
        let long = |n: usize| format!(r"\\?\C:\{}", "a".repeat(n - 3));
        assert!(s(&long(259)).is_some());
        assert_eq!(s(&long(260)), None);
    }
}

#[allow(
    clippy::unwrap_used,
    clippy::as_conversions,
    reason = "essais : un échec y fait échouer l'essai, aides comprises"
)]
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn resultat_clamscan() {
        let bilan = |infectes: u64, erreurs: u64| {
            format!(
                "\n----------- SCAN SUMMARY -----------\nScanned files: 12683\nInfected files: {infectes}\nTotal errors: {erreurs}\n"
            )
        };
        // Cas réel : 0 infecté, 7 dossiers de /tmp illisibles, code 2 → analyse valable.
        let r = lire_resultat(Some(2), &bilan(0, 7)).unwrap();
        assert_eq!((r.infectes.len(), r.analyses, r.illisibles), (0, 12683, 7));
        let deux = format!(
            "/home/x/Téléchargements/eicar.com: Eicar-Test-Signature FOUND\n/tmp/a b.exe: Win.Trojan.Agent-123 FOUND\n{}",
            bilan(2, 0)
        );
        let r = lire_resultat(Some(1), &deux).unwrap();
        assert_eq!(
            r.infectes[1],
            ("/tmp/a b.exe".to_string(), "Win.Trojan.Agent-123".to_string())
        );
        // Pas de bilan (base absente, plantage) : jamais « aucun malware ».
        assert!(lire_resultat(Some(2), "ERROR: Can't open database").is_none());
        assert!(lire_resultat(None, &bilan(0, 0)).is_none());
        // Infectés annoncés mais lignes illisibles : pas fiable.
        assert!(lire_resultat(Some(1), &bilan(1, 0)).is_none());
    }

    /// PA-1 (relecture du 12 nov.) : clamscan écrit un nom de fichier tel quel, saut de ligne compris. Sortie réelle
    /// de clamscan 1.5.4 (chemins changés) pour « s/a⏎/maison/essai/leurre/bashrc » infecté : la moitié de nom
    /// « s/a » est signalée comme une ligne qu'aucun fichier n'explique, et un faux bilan glissé dans un nom ne
    /// remplace jamais le vrai, écrit en dernier.
    #[test]
    fn nom_a_saut_de_ligne_signale() {
        let sortie = "/maison/essai/s/b: Essai.Faux-1.UNOFFICIAL FOUND\n/maison/essai/s/a\n/maison/essai/leurre/bashrc: Essai.Faux-1.UNOFFICIAL FOUND\n\n----------- SCAN SUMMARY -----------\nKnown viruses: 1\nEngine version: 1.5.4\nScanned directories: 9\nScanned files: 2\nInfected files: 2\nTotal errors: 1\nData scanned: 58 B\n";
        let r = lire_resultat(Some(1), sortie).unwrap();
        assert_eq!(r.lignes_inconnues, vec!["/maison/essai/s/a".to_string()]);
        assert_eq!((r.infectes.len(), r.analyses, r.illisibles), (2, 2, 1));
        // Un nom piégé qui imite le bilan : le vrai bilan (le dernier) compte, ses lignes sont inconnues.
        let piege = "/m/x\n----------- SCAN SUMMARY -----------\nScanned files: 99\nInfected files: 0\nTotal errors: 0\n/m/y: Essai.Faux-1 FOUND\n\n----------- SCAN SUMMARY -----------\nScanned files: 3\nInfected files: 1\nTotal errors: 4\n";
        let r = lire_resultat(Some(1), piege).unwrap();
        assert_eq!((r.analyses, r.illisibles, r.infectes.len()), (3, 4, 1));
        assert_eq!(r.lignes_inconnues.len(), 5, "{:?}", r.lignes_inconnues);
        // Un « FOUND » après le dernier bilan : la sortie n'a pas la forme connue, rien n'est conclu.
        assert!(lire_resultat(Some(1), &format!("{piege}/m/z: Essai FOUND\n")).is_none());
        // Montrées, les lignes inconnues sont rendues inoffensives.
        let r = lire_resultat(
            Some(0),
            "/m/\u{1b}[2Ja\n\n----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\n",
        )
        .unwrap();
        assert!(!r.lignes_inconnues[0].contains('\u{1b}'), "{:?}", r.lignes_inconnues);
    }

    /// Un dossier jetable au chemin canonique : `target` est un lien, et un chemin qui passe par un lien vers un
    /// dossier n'est jamais confirmé (PA-1).
    fn jetable(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    /// Ce que rend un lancement de clamscan : son code de sortie et sa sortie standard.
    type Sortie = Option<(Option<i32>, String)>;

    /// Ce que clamscan répondrait pour un lot, d'après sa réponse pour chaque fichier seul : une ligne par fichier,
    /// dans l'ordre, rien pour un fichier muet, le pire code.
    fn faux_lot(lot: &[&std::path::Path], seul: &dyn Fn(&str) -> Sortie) -> Sortie {
        if let [p] = lot {
            return seul(p.to_str().unwrap());
        }
        let (mut code, mut sortie) = (0, String::new());
        for p in lot {
            if let Some((Some(c), s)) = seul(p.to_str().unwrap()) {
                code = code.max(c);
                sortie.push_str(&s);
            }
        }
        Some((Some(code), sortie))
    }

    fn perimetre(cibles: &[&std::path::Path]) -> Perimetre {
        Perimetre {
            cibles: cibles.iter().map(|c| c.to_path_buf()).collect(),
            fichiers: std::collections::HashSet::new(),
        }
    }

    fn signales(chemins: &[String]) -> Bilan {
        Bilan {
            infectes: chemins
                .iter()
                .map(|f| (f.clone(), "Essai.Faux-1".to_string()))
                .collect(),
            analyses: 10,
            ..Bilan::default()
        }
    }

    /// PA-1 : avant tout geste et avant le rapport, chaque fichier signalé est revu. Ne reste infecté qu'un fichier
    /// ordinaire, dans ce qui a été analysé, dont l'analyse redit « <ce chemin>: … FOUND » et qui n'a pas changé
    /// entre-temps ; le reste est « non vérifié », jamais sain, et un lien, un dossier, un absent ou un chemin venu
    /// d'ailleurs n'est même pas relancé.
    #[test]
    fn seconde_analyse_avant_tout_geste() {
        let d = jetable("vanguard-pa1");
        let c = d.join("c");
        std::fs::create_dir_all(c.join("dossier")).unwrap();
        std::fs::create_dir_all(d.join("hors")).unwrap();
        for nom in ["vrai", "leurre", "muet", "autre", "a\nb", "rate", "code2", "change"] {
            std::fs::write(c.join(nom), b"contenu invente").unwrap();
        }
        std::fs::write(d.join("hors/x"), b"contenu invente").unwrap();
        std::os::unix::fs::symlink(c.join("vrai"), c.join("lien")).unwrap();
        // Un lien vers un dossier hors de la cible : clamscan n'y descend pas, un chemin qui le traverse vient d'ailleurs.
        std::os::unix::fs::symlink(d.join("hors"), c.join("rep")).unwrap();
        let chemin = |nom: &str| c.join(nom).to_str().unwrap().to_string();
        let mut tous: Vec<String> = [
            "vrai", "leurre", "lien", "absent", "dossier", "muet", "autre", "a\nb", "rate", "code2", "change", "rep/x",
        ]
        .iter()
        .map(|n| chemin(n))
        .collect();
        // Hors de la cible, et un chemin relatif (« b » d'un nom « …/a⏎b ») : jamais relancés.
        tous.push(d.join("hors/x").to_str().unwrap().to_string());
        tous.push("c/vrai".to_string());
        let mut bilan = signales(&tous);
        let lances = std::cell::RefCell::new(Vec::new());
        let seul = |p: &str| -> Option<(Option<i32>, String)> {
            lances.borrow_mut().push(p.to_string());
            match p.rsplit('/').next().unwrap() {
                "vrai" | "a\nb" => Some((Some(1), format!("{p}: Essai.Faux-2 FOUND\n"))),
                // clamscan en erreur (code 2) : même une ligne « FOUND » ne conclut rien.
                "code2" => Some((Some(2), format!("{p}: Essai.Faux-1 FOUND\n"))),
                "leurre" => Some((Some(0), format!("{p}: OK\n"))),
                "autre" => Some((Some(1), format!("{}: Essai.Faux-1 FOUND\n", chemin("vrai")))),
                "rate" => Some((Some(1), format!("{p}: Essai.Faux-1 FOUND\n{p}: Essai.Faux-1 FOUND\n"))),
                "change" => {
                    // Le fichier est changé pendant son analyse : ce n'est plus celui qu'elle a vu.
                    let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
                    std::io::Write::write_all(&mut f, b"+").unwrap();
                    Some((Some(1), format!("{p}: Essai.Faux-1 FOUND\n")))
                }
                _ => None,
            }
        };
        revoir_un_a_un(&mut bilan, &perimetre(&[&c]), |lot| faux_lot(lot, &seul));
        // Une cible qui est elle-même un lien (« Téléchargements » ailleurs, /home sur Silverblue) : elle est donnée
        // à clamscan par son vrai chemin (`sans_doublons`), et ses fichiers se confirment.
        std::os::unix::fs::symlink(&c, d.join("cible-lien")).unwrap();
        let cibles = sans_doublons(vec![d.join("cible-lien")]);
        let par_le_lien = cibles[0].join("vrai").to_str().unwrap().to_string();
        let mut autre = signales(std::slice::from_ref(&par_le_lien));
        let reel = Perimetre {
            cibles,
            fichiers: std::collections::HashSet::new(),
        };
        revoir_un_a_un(&mut autre, &reel, |lot| faux_lot(lot, &seul));
        assert_eq!(autre.infectes.len(), 1, "{autre:?}");
        assert_eq!(
            bilan.infectes,
            vec![
                (chemin("vrai"), "Essai.Faux-2".to_string()),
                (chemin("a\nb"), "Essai.Faux-2".to_string())
            ]
        );
        // L'inode relevé à la seconde analyse, pour le geste.
        let m = std::fs::symlink_metadata(c.join("vrai")).unwrap();
        assert!(bilan.identites[&chemin("vrai")].meme_fichier(&crate::protection::quarantaine::Identite::de(&m)));
        assert_eq!(bilan.identites.len(), 2);
        let ecartes: Vec<&str> = bilan.non_verifies.iter().map(|(f, _)| f.as_str()).collect();
        let attendus: Vec<&str> = tous
            .iter()
            .map(String::as_str)
            .filter(|f| *f != chemin("vrai") && *f != chemin("a\nb"))
            .collect();
        assert_eq!(ecartes, attendus);
        assert!(bilan.non_verifies.iter().all(|(_, raison)| !raison.is_empty()));
        // Ni le lien, ni le dossier, ni l'absent, ni ce qui vient d'ailleurs ne sont relancés.
        for n in &tous[tous.len() - 3..] {
            assert!(!lances.borrow().contains(n), "{n:?}");
        }
        for n in ["lien", "absent", "dossier", "rep/x"] {
            assert!(!lances.borrow().contains(&chemin(n)), "{n}");
        }
        // Hors de la cible, ou relatif : dit comme tel, avant même d'être lu, et non comme un lien ou un absent.
        let raison = |f: &str| {
            bilan
                .non_verifies
                .iter()
                .find(|(g, _)| g == f)
                .map(|(_, r)| *r)
                .unwrap()
        };
        let hors = d.join("hors/x").to_str().unwrap().to_string();
        assert_eq!(raison(&hors), raison("c/vrai"));
        assert_ne!(raison(&hors), raison(&chemin("rep/x")));
        // Changé pendant un lot qui se lit bien : relu après, il n'est pas le fichier que clamscan a vu.
        let mut relu = signales(&[chemin("change"), chemin("vrai")]);
        revoir_un_a_un(&mut relu, &perimetre(&[&c]), |lot| faux_lot(lot, &seul));
        assert_eq!(relu.infectes, vec![(chemin("vrai"), "Essai.Faux-2".to_string())]);
        assert_eq!(
            relu.non_verifies.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
            vec![chemin("change")]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (A4 de la relecture) : clamscan recharge ses signatures à chaque lancement (cinq secondes environ) ;
    /// quarante fichiers signalés se revoient en un seul lancement, et un fichier qui ne répond pas ne fait revoir à
    /// part que la moitié qui le contient, jusqu'à lui seul.
    #[test]
    fn seconde_analyse_par_lots() {
        let d = jetable("vanguard-pa1-lots");
        let noms: Vec<String> = (0..40).map(|i| format!("f{i:02}")).collect();
        for n in &noms {
            std::fs::write(d.join(n), b"contenu invente").unwrap();
        }
        let tous: Vec<String> = noms.iter().map(|n| d.join(n).to_str().unwrap().to_string()).collect();
        let lancements = std::cell::Cell::new(0);
        let mut bilan = signales(&tous);
        revoir_un_a_un(&mut bilan, &perimetre(&[&d]), |lot| {
            lancements.set(lancements.get() + 1);
            faux_lot(lot, &|p| Some((Some(1), format!("{p}: Essai.Faux-1 FOUND\n"))))
        });
        assert_eq!((bilan.infectes.len(), lancements.get()), (40, 1));
        assert_eq!(bilan.infectes.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(), tous);
        // Huit fichiers, dont un muet : 1 lancement du lot, puis les moitiés (2 + 2 + 2), jamais un par fichier.
        let huit = &tous[..8];
        let muet = huit[5].clone();
        lancements.set(0);
        let mut bilan = signales(huit);
        revoir_un_a_un(&mut bilan, &perimetre(&[&d]), |lot| {
            lancements.set(lancements.get() + 1);
            faux_lot(lot, &|p| {
                (p != muet).then(|| (Some(1), format!("{p}: Essai.Faux-1 FOUND\n")))
            })
        });
        assert_eq!(bilan.infectes.len(), 7);
        assert_eq!(
            bilan.non_verifies.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
            vec![muet]
        );
        assert_eq!(lancements.get(), 7);
        // Une sortie à une ligne près de la forme attendue ne conclut rien : un nom de menace à « : », un préfixe
        // qui n'est pas le chemin, un code qui contredit les lignes.
        let lot = ["/m/a", "/m/b"];
        assert!(lire_le_lot(Some(1), "/m/a: OK\n/m/b: X FOUND\n", &lot).is_some());
        for (code, sortie) in [
            (Some(1), "/m/a: OK\n/m/b: x: y FOUND\n"),
            (Some(1), "/m/a: OK\n/m/bb: X FOUND\n"),
            (Some(0), "/m/a: OK\n/m/b: X FOUND\n"),
            (Some(1), "/m/a: OK\n/m/b: OK\n"),
            (Some(1), "/m/a: OK\n/m/b: X FOUND"),
            (Some(2), "/m/a: OK\n/m/b: X FOUND\n"),
            (Some(1), "/m/a: OK\n/m/b:  FOUND\n"),
        ] {
            assert!(lire_le_lot(code, sortie, &lot).is_none(), "{sortie:?}");
        }
        // Les lots restent sous la borne des arguments.
        let longs: Vec<String> = (0..300).map(|i| format!("/m/{}{i:03}", "x".repeat(1000))).collect();
        let longs: Vec<&str> = longs.iter().map(String::as_str).collect();
        let lots = en_lots(&longs);
        assert!(lots.len() > 1);
        assert!(
            lots.iter()
                .all(|l| l.iter().map(|f| f.len() + 1).sum::<usize>() <= OCTETS_EN_ARGUMENT)
        );
        assert_eq!(lots.concat(), longs);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (A4 de la relecture, cas hostile) : un autre compte efface ses fichiers de /tmp juste après leur relevé ;
    /// le lot n'a plus la forme attendue. Les fichiers partis sont écartés sans être relancés (« changé »), le reste
    /// est revu en un lancement : jamais un lancement de cinq secondes par fichier effacé.
    #[test]
    fn lot_aux_fichiers_effaces() {
        let d = jetable("vanguard-pa1-effaces");
        let tous: Vec<String> = (0..8)
            .map(|i| {
                let f = d.join(format!("f{i}"));
                std::fs::write(&f, b"contenu invente").unwrap();
                f.to_str().unwrap().to_string()
            })
            .collect();
        let lancements = std::cell::Cell::new(0);
        let seul = |p: &str| {
            std::path::Path::new(p)
                .exists()
                .then(|| (Some(1), format!("{p}: Essai.Faux-1 FOUND\n")))
        };
        let mut bilan = signales(&tous);
        revoir_un_a_un(&mut bilan, &perimetre(&[&d]), |lot| {
            if lancements.get() == 0 {
                for f in &tous[..3] {
                    std::fs::remove_file(f).unwrap();
                }
            }
            lancements.set(lancements.get() + 1);
            faux_lot(lot, &seul)
        });
        assert_eq!(lancements.get(), 2, "{bilan:?}");
        assert_eq!(
            bilan.infectes.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
            tous[3..]
        );
        assert_eq!(
            bilan.non_verifies.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
            tous[..3]
        );
        // Tous partis : un seul lancement, rien d'autre.
        lancements.set(0);
        let mut bilan = signales(&tous[3..]);
        revoir_un_a_un(&mut bilan, &perimetre(&[&d]), |lot| {
            for f in &tous[3..] {
                let _ = std::fs::remove_file(f);
            }
            lancements.set(lancements.get() + 1);
            faux_lot(lot, &seul)
        });
        assert_eq!(
            (lancements.get(), bilan.infectes.len(), bilan.non_verifies.len()),
            (1, 0, 5)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (A1 de la relecture) : entre la seconde analyse et la réponse, le dossier du fichier est changé en lien
    /// vers celui d'un autre, qui a un fichier de même nom. Isoler ou effacer ne vise que l'inode revu : l'autre
    /// fichier reste intact.
    #[test]
    fn geste_sur_le_fichier_revu_seulement() {
        let d = jetable("vanguard-pa1-course");
        std::fs::create_dir_all(d.join("tmp/e")).unwrap();
        std::fs::create_dir_all(d.join("victime")).unwrap();
        std::fs::write(d.join("tmp/e/bashrc"), b"contenu invente").unwrap();
        std::fs::write(d.join("victime/bashrc"), b"export ESSAI=1\n").unwrap();
        let p = d.join("tmp/e/bashrc").to_str().unwrap().to_string();
        let mut bilan = signales(std::slice::from_ref(&p));
        revoir_un_a_un(&mut bilan, &perimetre(&[&d.join("tmp")]), |lot| {
            faux_lot(lot, &|c| Some((Some(1), format!("{c}: Essai.Faux-1 FOUND\n"))))
        });
        assert_eq!(bilan.infectes.len(), 1);
        std::fs::rename(d.join("tmp/e"), d.join("tmp/e.cache")).unwrap();
        std::os::unix::fs::symlink(d.join("victime"), d.join("tmp/e")).unwrap();
        let (f, detection) = &bilan.infectes[0];
        for rep in ["s", "d", "q"] {
            let r = geste_clamav(rep, f, detection, bilan.identites.get(f));
            assert!(matches!(r, Some(Err(_))), "{rep} : {r:?}");
            assert_eq!(
                std::fs::read(d.join("victime/bashrc")).unwrap(),
                b"export ESSAI=1\n",
                "{rep}"
            );
            assert!(d.join("tmp/e.cache/bashrc").exists(), "{rep}");
        }
        // Sans inode relevé, rien n'est fait ; une autre réponse ne fait rien du tout.
        assert!(matches!(geste_clamav("s", f, detection, None), Some(Err(_))));
        assert!(geste_clamav("n", f, detection, bilan.identites.get(f)).is_none());
        // Le même fichier, à sa place : il est bien effacé.
        std::fs::remove_file(d.join("tmp/e")).unwrap();
        std::fs::rename(d.join("tmp/e.cache"), d.join("tmp/e")).unwrap();
        assert!(matches!(
            geste_clamav("s", f, detection, bilan.identites.get(f)),
            Some(Ok(()))
        ));
        assert!(!d.join("tmp/e/bashrc").exists());
        assert!(d.join("victime/bashrc").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (contrôle de la ronde 2, C1) : au relevé de l'état, un dossier du chemin est un lien vers celui d'un autre ;
    /// pendant la seconde analyse, le vrai dossier ; après, le lien de nouveau. Relevé par lstat puis jugé par un autre
    /// appel, c'est l'inode du fichier de l'autre qui était gardé, puis effacé ou isolé. Cible donnée : le fichier
    /// lui-même (aucun contrôle de lien avant), puis son dossier.
    #[test]
    fn identite_relevee_a_travers_un_lien() {
        let d = jetable("vanguard-pa1-lien-au-releve");
        std::fs::create_dir_all(d.join("tmp/e.vrai")).unwrap();
        std::fs::create_dir_all(d.join("victime")).unwrap();
        std::fs::write(d.join("tmp/e.vrai/bashrc"), b"contenu invente").unwrap();
        std::fs::write(d.join("victime/bashrc"), b"export ESSAI=1\n").unwrap();
        std::os::unix::fs::symlink(d.join("victime"), d.join("tmp/e")).unwrap();
        let f = d.join("tmp/e/bashrc");
        let p = f.to_str().unwrap().to_string();
        let echanger = |de: &str, vers: &str| std::fs::rename(d.join(de), d.join(vers)).unwrap();
        for cible in [f.clone(), d.join("tmp")] {
            let mut bilan = signales(std::slice::from_ref(&p));
            revoir_un_a_un(&mut bilan, &perimetre(&[&cible]), |lot| {
                echanger("tmp/e", "tmp/e.lien");
                echanger("tmp/e.vrai", "tmp/e");
                let r = faux_lot(lot, &|c| Some((Some(1), format!("{c}: Essai.Faux-1 FOUND\n"))));
                echanger("tmp/e", "tmp/e.vrai");
                echanger("tmp/e.lien", "tmp/e");
                r
            });
            for (g, detection) in &bilan.infectes {
                for rep in ["s", "q"] {
                    let _ = geste_clamav(rep, g, detection, bilan.identites.get(g));
                }
            }
            assert_eq!(
                std::fs::read(d.join("victime/bashrc")).ok().as_deref(),
                Some(&b"export ESSAI=1\n"[..]),
                "{cible:?}"
            );
            assert!(
                bilan.infectes.is_empty() && bilan.identites.is_empty(),
                "{cible:?} : {bilan:?}"
            );
            assert_eq!(bilan.non_verifies.len(), 1);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (contrôle de la ronde 2, C1, la course elle-même) : un autre fil échange sans arrêt le vrai dossier et un
    /// lien vers celui d'un autre. Aucun relevé ne porte l'inode du fichier de l'autre : l'état et le lieu se lisent
    /// sur un même descripteur. Lus par deux appels, l'essai du contrôle gagnait environ un tour sur trois.
    #[test]
    fn releve_pendant_un_echange_de_dossiers() {
        let d = jetable("vanguard-pa1-course-au-releve");
        std::fs::create_dir_all(d.join("tmp/e.v")).unwrap();
        std::fs::create_dir_all(d.join("victime")).unwrap();
        std::fs::write(d.join("tmp/e.v/bashrc"), b"contenu invente").unwrap();
        std::fs::write(d.join("victime/bashrc"), b"export ESSAI=1\n").unwrap();
        std::os::unix::fs::symlink(d.join("victime"), d.join("tmp/e")).unwrap();
        let victime =
            crate::protection::quarantaine::Identite::de(&std::fs::metadata(d.join("victime/bashrc")).unwrap());
        let p = d.join("tmp/e/bashrc").to_str().unwrap().to_string();
        let fin = std::sync::atomic::AtomicBool::new(false);
        let (vus, lien) = std::thread::scope(|s| {
            s.spawn(|| {
                let r = |de: &str, vers: &str| {
                    let _ = std::fs::rename(d.join(de), d.join(vers));
                };
                while !fin.load(std::sync::atomic::Ordering::Relaxed) {
                    r("tmp/e", "tmp/e.l");
                    r("tmp/e.v", "tmp/e");
                    r("tmp/e", "tmp/e.v");
                    r("tmp/e.l", "tmp/e");
                }
            });
            let (mut vus, mut lien) = (0u32, 0u32);
            let perimetre = perimetre(&[&d.join("tmp")]);
            for _ in 0..20_000 {
                match etat_avant(&p, &perimetre) {
                    Ok(e) if e.identite.meme_fichier(&victime) => vus += 1,
                    Err(r) if r.contains("lien") || r.contains("link") => lien += 1,
                    _ => {}
                }
            }
            fin.store(true, std::sync::atomic::Ordering::Relaxed);
            (vus, lien)
        });
        assert_eq!(vus, 0, "{lien} relevés à travers le lien refusés");
        // L'échange a bien eu lieu pendant les relevés.
        assert!(lien > 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (contrôle de la ronde 2, C2) : clamscan écrit aussi « <f>: Empty file » (fichier vide, code 0) et
    /// « <f>: Access denied » (illisible : code 2, ou 1 si un autre fichier est trouvé), vu avec 1.5.4. Seul ce fichier
    /// reste « non vérifié », le lot se lit en un lancement. Rejeter tout le lot le faisait couper en deux jusqu'au
    /// fichier seul : des noms piégés simplement posés (une archive décompressée) coûtaient un lancement chacun.
    #[test]
    fn lot_aux_lignes_ni_ok_ni_found() {
        let d = jetable("vanguard-pa1-vides");
        let tous: Vec<String> = (0..16)
            .map(|i| {
                let f = d.join(format!("f{i:02}"));
                std::fs::write(&f, b"x").unwrap();
                f.to_str().unwrap().to_string()
            })
            .collect();
        let lancements = std::cell::Cell::new(0);
        let mut bilan = signales(&tous);
        revoir_un_a_un(&mut bilan, &perimetre(&[&d]), |lot| {
            lancements.set(lancements.get() + 1);
            faux_lot(lot, &|p| Some((Some(0), format!("{p}: Empty file\n"))))
        });
        assert_eq!((bilan.infectes.len(), bilan.non_verifies.len()), (0, 16));
        assert_eq!(lancements.get(), 1);
        let (sans_droit, trouve, sain) = ("/t/a", "/t/b", "/t/c");
        assert_eq!(
            lire_le_lot(
                Some(1),
                "/t/a: Access denied\n/t/b: Essai.X FOUND\n/t/c: OK\n",
                &[sans_droit, trouve, sain]
            ),
            Some(vec![Err(rien_de_net()), Ok("Essai.X".to_string()), Err(pas_infecte())])
        );
        assert_eq!(
            lire_le_lot(Some(2), "/t/a: Access denied\n/t/c: OK\n", &[sans_droit, sain]),
            Some(vec![Err(rien_de_net()), Err(pas_infecte())])
        );
        // Une trouvaille donne le code 1 : avec le code 2, ou une menace qui ne vient pas des signatures, rien n'est
        // conclu, comme avant.
        assert_eq!(
            lire_le_lot(
                Some(2),
                "/t/a: Access denied\n/t/b: Essai.X FOUND\n",
                &[sans_droit, trouve]
            ),
            None
        );
        assert_eq!(
            lire_le_lot(
                Some(1),
                "/t/a: Empty file\n/t/b: x: Essai.X FOUND\n",
                &[sans_droit, trouve]
            ),
            None
        );
        assert_eq!(lire_le_lot(Some(0), "/t/b: Essai.X FOUND\n", &[trouve]), None);
        assert_eq!(lire_le_lot(Some(1), "/t/a: Empty file\n", &[sans_droit]), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (contrôle de la ronde 2, C2, toute la classe) : une sortie d'une forme encore inconnue fait couper un lot
    /// en deux, puis encore ; le nombre de lancements reste borné, et ce qui n'a pas été revu est « non vérifié ».
    #[test]
    fn relances_bornees() {
        let d = jetable("vanguard-pa1-relances");
        let tous: Vec<String> = (0..64)
            .map(|i| {
                let f = d.join(format!("f{i:02}"));
                std::fs::write(&f, b"x").unwrap();
                f.to_str().unwrap().to_string()
            })
            .collect();
        let n = std::cell::Cell::new(0usize);
        let mut bilan = signales(&tous);
        revoir_un_a_un(&mut bilan, &perimetre(&[&d]), |lot| {
            n.set(n.get() + 1);
            Some((Some(1), "forme inconnue\n".repeat(lot.len())))
        });
        assert!(n.get() <= 1 + RELANCES, "{} lancements", n.get());
        assert_eq!((bilan.infectes.len(), bilan.non_verifies.len()), (0, 64));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (A2 de la relecture) : un nom « x: y FOUND⏎z » ajoute une fausse ligne ; jeter toute l'analyse cachait
    /// les vrais fichiers. Plus de lignes que d'infectés annoncés se lit (chaque ligne est revue ensuite) ; moins, ou
    /// des lignes sans aucun infecté annoncé, ne conclut rien. L'examen d'un seul fichier ne montre que sa vraie
    /// menace, la dernière.
    #[test]
    fn fausse_ligne_found_dans_un_nom() {
        let resume =
            |n: u64| format!("\n----------- SCAN SUMMARY -----------\nScanned files: 2\nInfected files: {n}\n");
        let lignes = "/m/s/vrai.bin: Essai.Faux-1 FOUND\n/m/s/x: y FOUND\nz: Essai.Faux-1 FOUND\n";
        let r = lire_resultat(Some(1), &format!("{lignes}{}", resume(2))).unwrap();
        assert_eq!(r.infectes.len(), 3);
        assert!(r.infectes.iter().any(|(f, _)| f == "/m/s/vrai.bin"));
        assert!(lire_resultat(Some(1), &format!("{lignes}{}", resume(4))).is_none());
        assert!(lire_resultat(Some(0), &format!("{lignes}{}", resume(0))).is_none());
        let seul = format!("/m/x: Menace.Choisie FOUND\nz: Essai.Faux-1 FOUND\n{}", resume(1));
        assert_eq!(
            examen_du_resultat(Some(1), &seul),
            Examen::Trouve(vec!["Essai.Faux-1".to_string()])
        );
    }

    /// PA-1 : la liste --file-list est jointe par « \n » et lue par morceaux de 1023 octets ; un nom à caractère de
    /// contrôle ou trop long (il y serait coupé en deux), ou qui n'est pas de l'UTF-8 (il y serait changé), n'y entre
    /// pas : il est donné à part, en argument, dans une borne (A3, J8 et J9 de la relecture) ; au-delà, il est compté
    /// non analysé, jamais sain.
    #[test]
    fn nom_a_controle_hors_de_la_liste() {
        use std::os::unix::ffi::OsStringExt;
        let tient = PathBuf::from(format!("/tmp/{}", "b/".repeat(508) + "b"));
        let trop_long = PathBuf::from(format!("/tmp/{}", "a/".repeat(509)));
        assert_eq!((tient.as_os_str().len(), trop_long.as_os_str().len()), (1022, 1023));
        let fichiers = vec![
            PathBuf::from("/tmp/ordinaire"),
            PathBuf::from("/tmp/a\n/maison/essai/.bashrc"),
            PathBuf::from("/tmp/retour\r"),
            PathBuf::from("/tmp/accentué é"),
            PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/pas-utf8-\xff".to_vec())),
            tient.clone(),
            trop_long.clone(),
        ];
        let (liste, a_part, laisses) = a_part_de_la_liste(fichiers);
        assert_eq!(
            liste,
            vec![PathBuf::from("/tmp/ordinaire"), PathBuf::from("/tmp/accentué é"), tient]
        );
        assert_eq!(
            a_part,
            vec![
                PathBuf::from("/tmp/a\n/maison/essai/.bashrc"),
                PathBuf::from("/tmp/retour\r"),
                PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/pas-utf8-\xff".to_vec())),
                trop_long,
            ]
        );
        assert_eq!(laisses, 0);
        // Des milliers de noms piégés dans /tmp : jamais assez d'arguments pour faire échouer clamscan en entier.
        let pieges: Vec<PathBuf> = (0..5000)
            .map(|i| PathBuf::from(format!("/tmp/{}/{i:04}\u{1}", "d".repeat(500))))
            .collect();
        let (_, a_part, laisses) = a_part_de_la_liste(pieges.clone());
        let octets: usize = a_part.iter().map(|p| p.as_os_str().len() + 1).sum();
        assert!(octets <= OCTETS_EN_ARGUMENT && a_part.len() <= TMP_A_PART, "{octets}");
        assert_eq!(a_part.len() + laisses, 5000);
        let l = preparer_lancement(Vec::new(), pieges, std::path::Path::new("/nulle-part"));
        assert_eq!(
            l.non_analyses.iter().map(|(n, _)| *n).sum::<u64>(),
            5000 - a_part.len() as u64
        );
        assert_eq!(l.perimetre.fichiers.len(), a_part.len());
    }

    /// PA-1 (A11 de la relecture) : la liste n'a pas pu s'écrire. Les endroits à risque passent en argument, et les
    /// fichiers récents de /tmp qui devaient y être sont dits non analysés (avant, sautés sans un mot).
    #[test]
    fn liste_non_ecrite_dite() {
        let cibles = vec![
            PathBuf::from("/maison/essai/Téléchargements"),
            PathBuf::from("/maison/essai/Bureau"),
        ];
        let tmp = vec![
            PathBuf::from("/tmp/a"),
            PathBuf::from("/tmp/b"),
            PathBuf::from("/tmp/c\nd"),
        ];
        let d = jetable("vanguard-pa1-liste");
        let l = preparer_lancement(cibles.clone(), tmp.clone(), &d.join("absent"));
        assert!(l.liste.is_none());
        let mut attendus = cibles.clone();
        attendus.push(tmp[2].clone());
        assert_eq!(l.arguments, attendus);
        assert_eq!(l.non_analyses.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![2]);
        assert_eq!(l.perimetre.fichiers, std::iter::once(tmp[2].clone()).collect());
        // Écrite : tout y est sauf le nom à saut de ligne, et elle s'efface quand l'analyse est finie.
        let l = preparer_lancement(cibles, tmp, &d);
        let chemin = l.liste.as_ref().unwrap().0.clone();
        assert_eq!(
            std::fs::read_to_string(&chemin).unwrap(),
            "/maison/essai/Téléchargements\n/maison/essai/Bureau\n/tmp/a\n/tmp/b"
        );
        assert_eq!(l.arguments, vec![PathBuf::from("/tmp/c\nd")]);
        assert_eq!(l.non_analyses, []);
        assert_eq!(l.perimetre.fichiers.len(), 3);
        drop(l);
        assert!(!chemin.exists());
        let l = preparer_lancement(vec![PathBuf::from("/m")], Vec::new(), &d);
        let m = std::fs::metadata(&l.liste.as_ref().unwrap().0).unwrap();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777, 0o600);
        drop(l);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1, avec le vrai clamscan et une base jetable d'une seule empreinte (un contenu inventé, jamais une vraie
    /// signature) : le fichier piégé « s/a⏎<jetable>/leurre/bashrc » fait signaler le leurre ; revu, le leurre n'est
    /// pas confirmé, rien ne lui est proposé, et la moitié de nom est signalée.
    #[test]
    fn seconde_analyse_du_vrai_clamscan() {
        let Some(base) = base_jetable("vanguard-pa1-clam") else {
            crate::essais::saute("clamscan absent des dossiers du système");
            return;
        };
        let (d, base, contenu) = base;
        let leurre = d.join("leurre/bashrc");
        std::fs::create_dir_all(leurre.parent().unwrap()).unwrap();
        std::fs::write(&leurre, b"export ESSAI=1\n").unwrap();
        let piege = PathBuf::from(format!("{}/s/a\n{}", d.display(), leurre.display()));
        std::fs::create_dir_all(piege.parent().unwrap()).unwrap();
        std::fs::write(&piege, contenu).unwrap();
        std::fs::write(d.join("s/b"), contenu).unwrap();
        // Le leurre est dans ce qui est analysé : seule la seconde analyse l'écarte.
        let l = preparer_lancement(vec![d.join("s"), d.join("leurre")], Vec::new(), &d);
        let leurre = leurre.to_str().unwrap().to_string();
        // Sans seconde analyse, le leurre passe pour infecté : c'est le défaut.
        let brut = analyser_le_lancement(&l, Some(&base), &[]).unwrap();
        assert!(brut.infectes.iter().any(|(f, _)| *f == leurre), "{brut:?}");
        let bilan = analyser_et_revoir(&l, Some(&base), &[], |_| ()).unwrap();
        let b = d.join("s/b").to_str().unwrap().to_string();
        assert_eq!(bilan.infectes, vec![(b, "Essai.Faux-1.UNOFFICIAL".to_string())]);
        assert_eq!(
            bilan.non_verifies.iter().map(|(f, _)| f.as_str()).collect::<Vec<_>>(),
            vec![leurre.as_str()]
        );
        assert_eq!(bilan.lignes_inconnues, vec![format!("{}/s/a", d.display())]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (J1 et J2 de la relecture), avec le vrai clamscan : dès qu'il a une liste, clamscan ignore tout chemin
    /// en argument. Les endroits et fichiers de la liste, comme ceux donnés à part (nom à caractère de contrôle),
    /// sont tous analysés, et chaque infecté est confirmé.
    #[test]
    fn liste_et_arguments_tous_analyses() {
        let Some((d, base, contenu)) = base_jetable("vanguard-pa1-j1") else {
            crate::essais::saute("clamscan absent des dossiers du système");
            return;
        };
        let (c1, c2, t) = (d.join("c1"), d.join("c\u{1}2"), d.join("t"));
        for r in [&c1, &c2, &t] {
            std::fs::create_dir_all(r).unwrap();
        }
        let infectes = [c1.join("f1"), c2.join("f2"), t.join("ordinaire"), t.join("x\u{1}y")];
        for f in &infectes {
            std::fs::write(f, contenu).unwrap();
        }
        let l = preparer_lancement(vec![c1, c2.clone()], vec![infectes[2].clone(), infectes[3].clone()], &d);
        assert!(l.liste.is_some());
        assert_eq!(l.arguments, vec![c2, infectes[3].clone()]);
        let bilan = analyser_et_revoir(&l, Some(&base), &[], |_| ()).unwrap();
        let mut trouves: Vec<PathBuf> = bilan.infectes.iter().map(|(f, _)| PathBuf::from(f)).collect();
        trouves.sort();
        let mut attendus = infectes.to_vec();
        attendus.sort();
        assert_eq!(trouves, attendus, "{bilan:?}");
        assert!(bilan.non_verifies.is_empty() && bilan.analyses >= 4, "{bilan:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un dossier jetable et une base ClamAV d'une seule empreinte, celle d'un contenu inventé : (dossier, option
    /// « --database= », contenu). `None` sans clamscan dans les dossiers du système.
    fn base_jetable(nom: &str) -> Option<(PathBuf, String, &'static [u8])> {
        crate::commande::outil_systeme("clamscan")?;
        let d = jetable(nom);
        let contenu: &'static [u8] = b"contenu-invente-vanguard-pa1\n";
        std::fs::create_dir_all(d.join("base")).unwrap();
        std::fs::write(
            d.join("base/essai.hdb"),
            format!("{}:{}:Essai.Faux-1\n", md5_hex(contenu), contenu.len()),
        )
        .unwrap();
        let base = format!("--database={}", d.join("base").display());
        Some((d, base, contenu))
    }

    /// MD5 en hexadécimal, pour l'empreinte .hdb de la base jetable (format de ClamAV).
    fn md5_hex(octets: &[u8]) -> String {
        use md5::Digest;
        crate::socle::hachage::hexa(&md5::Md5::digest(octets))
    }

    #[test]
    fn dossiers_analyses_une_seule_fois() {
        let base = crate::essais::temporaire().join(format!("vanguard-cibles-{}", std::process::id()));
        let bureau = base.join("Bureau");
        std::fs::create_dir_all(bureau.join("sous")).unwrap();
        std::os::unix::fs::symlink(&bureau, base.join("Desktop")).unwrap();
        let reel = bureau.canonicalize().unwrap();
        // Desktop → Bureau, et un sous-dossier de Bureau : il ne reste que Bureau.
        assert_eq!(
            sans_doublons(vec![base.join("Desktop"), bureau.clone(), bureau.join("sous")]),
            vec![reel]
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn exclusions_en_expression_reguliere() {
        assert_eq!(regex_echappe(".steam"), "/\\.steam(/|$)");
    }

    /// E5-I1 (campagne 5) : le dossier des signatures choisi dans freshclam.conf est lu ; une ligne mise en
    /// commentaire ne compte pas, la dernière l'emporte.
    #[cfg(unix)]
    #[test]
    fn base_dans_le_dossier_de_freshclam_conf() {
        let d = crate::essais::temporaire().join(format!("vanguard-base-clamav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let conf = format!(
            "# DatabaseDirectory /var/lib/ailleurs\nDatabaseMirror database.clamav.net\nDatabaseDirectory /nulle/part\n  DatabaseDirectory \"{}\"\n",
            d.display()
        );
        assert_eq!(dossier_de_la_base(&conf), Some(d.clone()));
        assert_eq!(dossier_de_la_base("#DatabaseDirectory /x\nUpdateLogFile /y\n"), None);
        assert!(!base_dans(&d));
        std::fs::write(d.join("main.cvd"), b"").unwrap();
        assert!(base_dans(&d));
        // La configuration l'emporte sur un dossier fixe qui a aussi une base ; sans elle, le dossier fixe.
        let fixe = d.join("fixe");
        std::fs::create_dir(&fixe).unwrap();
        std::fs::write(fixe.join("daily.cld"), b"").unwrap();
        let chemin_conf = d.join("freshclam.conf");
        std::fs::write(&chemin_conf, &conf).unwrap();
        let (c, f) = (chemin_conf.to_str().unwrap(), fixe.to_str().unwrap());
        assert_eq!(dossier_de_base_parmi(&[c], &[f]), Some(d.clone()));
        assert_eq!(dossier_de_base_parmi(&["/nulle/part.conf"], &[f]), Some(fixe.clone()));
        assert_eq!(dossier_de_base_parmi(&[], &["/nulle/part"]), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Propriétés de la lecture de lsblk : rien ne plante, quelle que soit la sortie ; une clé amovible bien décrite
/// redonne son point de montage et son étiquette, rendue prête à montrer.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lsblk_sans_plantage(t in prop::collection::vec(prop_oneof![any::<String>(), "([A-Z]+=\"[ -~\u{1b}é]{0,12}\" ?){0,6}"], 0..8)) {
            for (point, nom) in lire_lsblk(&t.join("\n")) {
                prop_assert!(point.is_absolute());
                prop_assert!(!crate::ui::contient_un_piege(&nom));
            }
        }

        #[test]
        fn lsblk_redonne_ses_valeurs(etiquette in "[A-Za-z0-9_-]{1,11}", taille in "[0-9]{1,3}(,[0-9])?[GM]", amovible in prop_oneof![Just("RM=\"1\" HOTPLUG=\"0\""), Just("RM=\"0\" HOTPLUG=\"1\"")]) {
            let ligne = format!("{amovible} LABEL=\"{etiquette}\" SIZE=\"{taille}\" MOUNTPOINT=\"/run/media/alice/{etiquette}\"\n");
            let l = lire_lsblk(&ligne);
            prop_assert_eq!(l.len(), 1);
            prop_assert_eq!(&l[0].0, &PathBuf::from(format!("/run/media/alice/{etiquette}")));
            prop_assert_eq!(&l[0].1, &format!("{etiquette} · {taille}"));
            // Ni amovible ni branchée à chaud : pas une clé.
            prop_assert!(lire_lsblk(&ligne.replace("=\"1\"", "=\"0\"")).is_empty());
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(all(test, unix))]
mod tests_json {
    use super::*;
    use crate::protection::yara::resultat::Releve;

    fn lu() -> Releve {
        Releve {
            endroits: 3,
            fichiers: 40,
            ..Releve::default()
        }
    }

    fn verdict(r: &Releve) -> &'static str {
        resultat::resultat(r, (chrono::Utc::now(), std::time::Instant::now())).verdict()
    }

    /// Le second avis de ClamAV dans `--json` : trouvé → critique, à isoler depuis le menu ; rien trouvé en entier →
    /// sain ; coupé ou absent (facultatif) → dit, sans changer le verdict ; sans signatures, pas lancé, en échec ou
    /// avec des éléments illisibles → jamais sain.
    #[test]
    fn second_avis_trouve_rien_et_partiel() {
        let fait = |infectes: Vec<(String, String)>, illisibles| {
            SecondAvis::Fait(Box::new(Bilan {
                infectes,
                non_verifies: Vec::new(),
                lignes_inconnues: Vec::new(),
                analyses: 40,
                illisibles,
                ..Bilan::default()
            }))
        };
        let mut r = lu();
        ajouter_second_avis(&mut r, fait(Vec::new(), 0));
        assert_eq!(verdict(&r), "sain");
        for raison in [raison_coupe(), raison_absent()] {
            let mut r = lu();
            ajouter_second_avis(&mut r, SecondAvis::NonLance(raison));
            assert_eq!(verdict(&r), "sain", "{raison}");
            assert!(r.infos[0].contains(raison));
        }
        for avis in [
            SecondAvis::NonLance(raison_sans_signatures()),
            SecondAvis::PasDemarre,
            SecondAvis::Echoue(vec!["ERROR: essai".into()]),
            SecondAvis::Echoue(Vec::new()),
            fait(Vec::new(), 2),
        ] {
            let mut r = lu();
            ajouter_second_avis(&mut r, avis);
            assert_eq!(verdict(&r), "non-verifie", "{:?}", r.manques);
        }
        let mut r = lu();
        ajouter_second_avis(
            &mut r,
            fait(
                vec![(
                    "/maison/essai/eicar\u{202e}moc.txt".into(),
                    "Eicar-Test-Signature".into(),
                )],
                0,
            ),
        );
        let res = resultat::resultat(&r, (chrono::Utc::now(), std::time::Instant::now()));
        assert_eq!(res.verdict(), "probleme");
        assert_eq!(res.pire(), Some(Niveau::Critique));
        let json = crate::modele::resultat::json(&res);
        assert!(
            json.contains("à isoler depuis le menu") && !json.contains('\u{202e}'),
            "{json}"
        );
    }

    /// PA-1 : un fichier signalé que sa seconde analyse ne confirme pas, ou une moitié de nom coupé, n'est ni une
    /// trouvaille critique ni « sain » : « non vérifié », avec le chemin rendu inoffensif.
    #[test]
    fn second_avis_non_confirme_jamais_sain() {
        let avis = |non_verifies: Vec<(String, &'static str)>, lignes_inconnues: Vec<String>| {
            SecondAvis::Fait(Box::new(Bilan {
                infectes: Vec::new(),
                non_verifies,
                lignes_inconnues,
                analyses: 40,
                illisibles: 0,
                ..Bilan::default()
            }))
        };
        let mut r = lu();
        ajouter_second_avis(
            &mut r,
            avis(vec![("/maison/essai/.bash\u{1b}rc".into(), "pas confirmé")], Vec::new()),
        );
        assert_eq!(verdict(&r), "non-verifie", "{:?}", r.manques);
        assert_eq!(r.trouves.len(), 0, "{:?}", r.trouves);
        assert!(
            r.manques
                .iter()
                .any(|m| m.contains("/maison/essai/.bash") && m.contains("pas confirmé") && !m.contains('\u{1b}')),
            "{:?}",
            r.manques
        );
        let mut r = lu();
        ajouter_second_avis(&mut r, avis(Vec::new(), vec!["/maison/essai/s/a".into()]));
        assert_eq!(verdict(&r), "non-verifie", "{:?}", r.manques);
        assert!(
            r.manques.iter().any(|m| m.contains("/maison/essai/s/a")),
            "{:?}",
            r.manques
        );
        // Des fichiers récents de /tmp que clamscan n'a pas reçus (A11 de la relecture) : dits, jamais sains.
        let mut r = lu();
        ajouter_second_avis(
            &mut r,
            SecondAvis::Fait(Box::new(Bilan {
                analyses: 40,
                non_analyses: vec![(3, "liste non écrite")],
                ..Bilan::default()
            })),
        );
        assert_eq!(verdict(&r), "non-verifie", "{:?}", r.manques);
        assert!(
            r.manques
                .iter()
                .any(|m| m.contains('3') && m.contains("liste non écrite")),
            "{:?}",
            r.manques
        );
    }
}
