//! « Pourquoi c'est lent ? » : un instantané en deux mesures, à deux secondes d'écart. Ce qui occupe le processeur,
//! la mémoire et le disque, programme par programme ; le démarrage (sa durée, ce qui le retarde) ; les programmes
//! lancés à l'ouverture de session et leur poids. La mesure est en lecture seule : les conseils disent quel outil de
//! Vanguard règle quoi (Nettoyer, Optimiser, Mises à jour, programmes au démarrage à retirer ou remettre, après accord
//! et de façon annulable), et l'écran les ouvre.

use std::collections::HashMap;

use crate::risk::Niveau;
use crate::ui::*;

mod resultat;

/// Un programme (tous ses processus réunis : Firefox en compte une dizaine), tel que le script de Windows le donne.
#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct Programme {
    pub nom: String,
    /// Part de toute la machine (tous les cœurs), en %.
    pub processeur: f64,
    /// Mémoire vive occupée, en octets.
    pub memoire: u64,
    /// Lectures et écritures, en octets par seconde ; `None` : illisible (programme d'un autre compte).
    pub disque: Option<f64>,
}

/// Le dernier démarrage de l'ordinateur.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Demarrage {
    /// Durée totale, en secondes.
    pub total: f64,
    /// Les étapes (« micrologiciel 11,8 s · chargeur 8,1 s… »).
    pub etapes: String,
    /// Ce qui l'a le plus retardé : (nom, secondes).
    pub lents: Vec<(String, f64)>,
}

/// Un programme lancé à l'ouverture de session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuDemarrage {
    pub nom: String,
    /// Mémoire qu'il occupe en ce moment ; `None` : il ne tourne pas, ou on ne l'a pas retrouvé.
    pub poids: Option<u64>,
}

#[derive(Debug)]
pub struct Instantane {
    /// Processeur occupé, toute la machine, en %.
    pub processeur: Option<f64>,
    pub fils: usize,
    /// (totale, disponible), en octets.
    pub memoire: Option<(u64, u64)>,
    /// Mémoire d'échange (fichier ou partition) : (taille, utilisée).
    pub echange: Option<(u64, u64)>,
    /// Temps d'occupation du disque le plus chargé, en %.
    pub disque: Option<f64>,
    pub programmes: Vec<Programme>,
    /// `Err` : pourquoi la durée du démarrage n'a pas pu être lue.
    pub demarrage: Result<Demarrage, String>,
    pub au_demarrage: Vec<AuDemarrage>,
    /// Secondes depuis le démarrage.
    pub allume_depuis: Option<u64>,
    /// Disque du système : (libre, total).
    pub place: Option<(u64, u64)>,
}

impl Default for Instantane {
    fn default() -> Self {
        Instantane {
            processeur: None,
            fils: 1,
            memoire: None,
            echange: None,
            disque: None,
            programmes: Vec::new(),
            demarrage: Err(tr!("durée non mesurée", "duration not measured").into()),
            au_demarrage: Vec::new(),
            allume_depuis: None,
            place: None,
        }
    }
}

/// Les processus d'un même programme réunis, triés plus tard selon ce qu'on regarde. Par ici passent les programmes
/// des trois systèmes : chacun choisit son nom, rendu prêt à montrer (`affichable`).
fn reunir(processus: impl Iterator<Item = Programme>) -> Vec<Programme> {
    let mut par_nom: HashMap<String, Programme> = HashMap::new();
    for p in processus {
        let e = par_nom.entry(affichable(&p.nom)).or_default();
        e.processeur += p.processeur;
        e.memoire += p.memoire;
        e.disque = p.disque.map(|d| e.disque.unwrap_or(0.0) + d).or(e.disque);
    }
    par_nom.into_iter().map(|(nom, p)| Programme { nom, ..p }).collect()
}

/// Les programmes au démarrage, (nom, programme lancé), avec la mémoire qu'occupe ce programme en ce moment. Le nom,
/// écrit par qui a posé l'entrée, est rendu prêt à montrer.
fn avec_poids(programmes: &[Programme], liste: impl Iterator<Item = (String, String)>) -> Vec<AuDemarrage> {
    let mut par_nom: HashMap<String, u64> = HashMap::new();
    for p in programmes {
        *par_nom.entry(p.nom.to_lowercase()).or_default() += p.memoire;
    }
    let poids = |programme: &str| par_nom.get(&affichable(programme).to_lowercase()).copied();
    liste
        .map(|(nom, p)| AuDemarrage {
            poids: poids(&p),
            nom: affichable(&nom),
        })
        .collect()
}

/// Les instants du démarrage notés par systemd (propriétés du Manager, en microsecondes) : avant le noyau, le
/// micrologiciel et le chargeur se comptent à rebours depuis son départ ; après, l'initrd, le système et la fin depuis
/// son départ. Zéro : pas noté (pas d'EFI, pas d'initrd).
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct InstantsDemarrage {
    micrologiciel: u64,
    chargeur: u64,
    initrd: u64,
    espace_utilisateur: u64,
    fin: u64,
    /// Dans un conteneur, avant le système, ce sont les instants de l'hôte : seul le système compte.
    conteneur: bool,
}

/// La durée du démarrage et ses étapes (« micrologiciel 11,8 s · chargeur 8,1 s · noyau 15,2 s · système 5,6 s »),
/// calculées comme `systemd-analyze` ; `None` tant que le démarrage n'est pas fini.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[allow(clippy::cast_precision_loss)]
fn duree_demarrage(t: &InstantsDemarrage) -> Option<(f64, String)> {
    if t.fin == 0 {
        return None;
    }
    let secondes = |us: u64| us as f64 / 1e6;
    let mut etapes = Vec::new();
    let mut etape = |nom: &str, us: u64| etapes.push(format!("{nom} {}", secondes_lisibles(secondes(us))));
    let systeme = t.fin.saturating_sub(t.espace_utilisateur);
    if t.conteneur {
        etape(tr!("système", "userspace"), systeme);
        return Some((secondes(systeme), etapes.join(" · ")));
    }
    if t.micrologiciel > 0 {
        etape(
            tr!("micrologiciel", "firmware"),
            t.micrologiciel.saturating_sub(t.chargeur),
        );
    }
    if t.chargeur > 0 {
        etape(tr!("chargeur", "loader"), t.chargeur);
    }
    let noyau = if t.initrd > 0 { t.initrd } else { t.espace_utilisateur };
    if noyau > 0 {
        etape(tr!("noyau", "kernel"), noyau);
    }
    if t.initrd > 0 {
        etape("initrd", t.espace_utilisateur.saturating_sub(t.initrd));
    }
    etape(tr!("système", "userspace"), systeme);
    let total = if noyau > 0 { t.micrologiciel + t.fin } else { systeme };
    Some((secondes(total), etapes.join(" · ")))
}

/// Une unité vue par la chaîne critique : ses dépendances `After` et ses instants (microsecondes monotones) :
/// début (`InactiveExitTimestampMonotonic`), active (`ActiveEnterTimestampMonotonic`), retombée inactive
/// (`InactiveEnterTimestampMonotonic`).
#[derive(Debug, Default, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct UniteDemarrage {
    apres: Vec<String>,
    debut: u64,
    active: u64,
    inactive: u64,
}

/// Les unités du chemin critique du démarrage et le temps que chacune a pris à démarrer, les plus longues d'abord
/// (au plus 5, d'une demi-seconde au moins), comme `systemd-analyze critical-chain` : depuis `racine`, parmi les
/// dépendances `After` démarrées avant la fin du démarrage (`fin`), on suit celle devenue active en dernier (toutes
/// celles à égalité). `blame` mélangerait ce qui tourne après le démarrage (mise à jour de la base de locate, par
/// exemple) avec ce qui le retarde vraiment. `lire` donne une unité chargée par son nom (`Ok(None)` : pas chargée).
/// Une lecture qui échoue (`Err`) rend la liste vide : écarter l'unité ferait suivre une autre branche, et la liste
/// serait fausse. Le nom d'une unité de l'utilisateur est le sien : rendu prêt à montrer.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[allow(clippy::cast_precision_loss)]
fn chaine_critique(
    racine: &str,
    fin: u64,
    mut lire: impl FnMut(&str) -> Result<Option<UniteDemarrage>, String>,
) -> Vec<(String, f64)> {
    let mut connues: HashMap<String, Option<UniteDemarrage>> = HashMap::new();
    let illisible = std::cell::Cell::new(false);
    let mut unite = |nom: &str| {
        if let Some(u) = connues.get(nom) {
            return u.clone();
        }
        let u = lire(nom).unwrap_or_else(|_| {
            illisible.set(true);
            None
        });
        connues.insert(nom.to_string(), u.clone());
        u
    };
    // Une unité jamais démarrée (début nul) n'a pas de durée, comme pour systemd-analyze.
    let duree = |u: &UniteDemarrage| {
        let us = if u.debut == 0 {
            0
        } else if u.active >= u.debut {
            u.active - u.debut
        } else {
            u.inactive.saturating_sub(u.debut)
        };
        us as f64 / 1e6
    };
    let mut lents: HashMap<String, f64> = HashMap::new();
    if let Some(u) = unite(racine) {
        lents.insert(racine.to_string(), duree(&u));
    }
    let mut vues = std::collections::HashSet::from([racine.to_string()]);
    let mut a_suivre = vec![racine.to_string()];
    while let Some(nom) = a_suivre.pop() {
        let Some(u) = unite(&nom) else { continue };
        // Comme systemd-analyze : une unité jamais démarrée (début nul) ou active après la fin ne compte pas.
        let demarrees: Vec<(String, UniteDemarrage)> = u
            .apres
            .iter()
            .filter_map(|d| unite(d).map(|t| (d.clone(), t)))
            .filter(|(_, t)| t.debut > 0 && t.active > 0 && t.active <= fin)
            .collect();
        if illisible.get() {
            return Vec::new();
        }
        let Some(derniere) = demarrees.iter().map(|(_, t)| t.active).max() else {
            continue;
        };
        for (d, t) in demarrees.into_iter().filter(|(_, t)| t.active == derniere) {
            lents.insert(d.clone(), duree(&t));
            if vues.insert(d.clone()) {
                a_suivre.push(d);
            }
        }
    }
    if illisible.get() {
        return Vec::new();
    }
    let mut lents: Vec<(String, f64)> = lents
        .into_iter()
        .filter(|(_, s)| *s >= 0.5)
        .map(|(n, s)| (affichable(&n), s))
        .collect();
    lents.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    lents.truncate(5);
    lents
}

/// « 12,3 s », « 1 min 05 s ».
fn secondes_lisibles(s: f64) -> String {
    if s >= 60.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let s = s.round() as u64;
        return format!("{} min {:02} s", s / 60, s % 60);
    }
    format!("{} s", crate::langue::decimal(s, 1))
}

/// Un service de l'utilisateur lancé à l'ouverture de session : voulu par default.target (ou la session graphique). Un
/// service activé pour autre chose (au branchement d'une clé, par une minuterie, un chemin surveillé) ne l'est pas.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lance_a_l_ouverture(unite: &str) -> bool {
    let mut dans_install = false;
    unite.lines().map(str::trim).any(|l| {
        if l.starts_with('[') {
            dans_install = l == "[Install]";
            return false;
        }
        dans_install
            && l.split_once('=').is_some_and(|(cle, cibles)| {
                matches!(cle.trim(), "WantedBy" | "RequiredBy")
                    && cibles
                        .split_whitespace()
                        .any(|c| matches!(c, "default.target" | "graphical-session.target"))
            })
    })
}

/// Une entrée de démarrage automatique (fichier .desktop d'autostart) : (nom affiché, programme) si elle est active
/// pour ce bureau. `Hidden=true` ou `X-GNOME-Autostart-enabled=false` : désactivée ; `OnlyShowIn`/`NotShowIn` :
/// selon le bureau.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn entree_autostart(texte: &str, bureau: &str) -> Option<(String, String)> {
    let mut dans_entree = false;
    let mut champs: HashMap<&str, &str> = HashMap::new();
    for l in texte.lines().map(str::trim) {
        if l.starts_with('[') {
            dans_entree = l == "[Desktop Entry]";
        } else if dans_entree && let Some((cle, valeur)) = l.split_once('=') {
            champs.entry(cle.trim()).or_insert(valeur.trim());
        }
    }
    let vaut = |cle: &str, v: &str| champs.get(cle).is_some_and(|x| x.eq_ignore_ascii_case(v));
    // Les bureaux d'une liste (« GNOME;Unity; »), sans les vides : un nom vide de la session ne peut rien y trouver.
    let liste = |cle: &str| -> Vec<String> {
        let v = champs.get(cle).copied().unwrap_or_default().split(';');
        v.map(|b| b.trim().to_lowercase()).filter(|b| !b.is_empty()).collect()
    };
    let bureaux: Vec<String> = bureau.split(':').map(str::to_lowercase).collect();
    let ici = |l: Vec<String>| l.iter().any(|b| bureaux.contains(b));
    let seulement = liste("OnlyShowIn");
    if vaut("Hidden", "true")
        || vaut("X-GNOME-Autostart-enabled", "false")
        || (!seulement.is_empty() && !ici(seulement))
        || ici(liste("NotShowIn"))
    {
        return None;
    }
    // « env VAR=1 programme --option %u » → « programme ».
    let programme = champs
        .get("Exec")?
        .split_whitespace()
        .find(|m| *m != "env" && !m.contains('=') && !m.starts_with('-'))?
        .trim_matches('"');
    let programme = programme.rsplit('/').next().unwrap_or(programme).to_string();
    let nom = champs.get("Name").map_or(programme.clone(), ToString::to_string);
    Some((nom, programme))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outil {
    Nettoyer,
    Demarrage,
    Performance,
    MisesAJour,
}

/// Les conseils d'un instantané : (niveau d'alerte, texte, outil à proposer).
pub struct Conseil {
    pub grave: bool,
    pub texte: String,
    pub outil: Option<Outil>,
    /// Ce que mesure le conseil, sans langue (« processeur », « demarrage ») : l'objet de son constat (`resultat`).
    pub sujet: &'static str,
}

/// Programmes qui travaillent fort pendant un moment, puis se calment seuls : les nommer évite d'accuser l'ordinateur.
/// Une ligne par raison : débuts de leurs noms | en français | en anglais.
const PASSAGERS: &str = "\
msmpeng mpdefendercoreservice | l'antivirus de Windows analyse les fichiers | Windows' antivirus is scanning files
tiworker trustedinstaller | Windows installe des mises à jour | Windows is installing updates
searchindexer | Windows indexe les fichiers pour la recherche | Windows is indexing files for search
mdworker mds_stores | macOS indexe les fichiers pour Spotlight | macOS is indexing files for Spotlight
localsearch tracker-miner | le bureau indexe les fichiers pour la recherche | the desktop is indexing files for search
baloo_file | KDE indexe les fichiers pour la recherche | KDE is indexing files for search
packagekitd | les mises à jour se téléchargent | updates are downloading
plocate updatedb | la base de recherche des fichiers se refait | the file search database is being rebuilt";

fn passager(nom: &str) -> Option<&'static str> {
    let n = nom.to_lowercase();
    PASSAGERS.lines().find_map(|l| {
        let mut champs = l.split(" | ");
        let (cles, fr, en) = (champs.next()?, champs.next()?, champs.next()?);
        let trouve = cles.split_whitespace().any(|c| n.starts_with(c));
        trouve.then_some(if crate::langue::anglais() { en } else { fr })
    })
}

#[allow(clippy::cast_precision_loss)]
fn pourcent(n: u64, sur: u64) -> f64 {
    if sur == 0 { 0.0 } else { n as f64 * 100.0 / sur as f64 }
}

/// Ce qu'on peut conclure de l'instantané, le plus grave d'abord.
#[allow(clippy::cast_precision_loss)]
pub fn conseils(i: &Instantane) -> Vec<Conseil> {
    let mut c = Vec::new();
    let mut pousser = |grave, texte, outil, sujet| {
        c.push(Conseil {
            grave,
            texte,
            outil,
            sujet,
        });
    };
    let plus = |cle: fn(&Programme) -> f64| {
        i.programmes
            .iter()
            .max_by(|a, b| cle(a).total_cmp(&cle(b)))
            .filter(|p| cle(p) > 0.0)
    };
    if let Some(occupe) = i.processeur.filter(|&o| o >= 80.0) {
        let texte = match plus(|p| p.processeur) {
            Some(p) => match passager(&p.nom) {
                Some(raison) => trf!(
                    "Processeur occupé à {occupe:.0} %, surtout par {} : {raison}. Ça passe seul, en général en moins d'une heure.",
                    "Processor {occupe:.0}% busy, mostly by {}: {raison}. It passes by itself, usually within an hour.",
                    p.nom
                ),
                None => trf!(
                    "Processeur occupé à {occupe:.0} %, surtout par {} ({:.0} %). Le fermer s'il ne sert pas en ce moment.",
                    "Processor {occupe:.0}% busy, mostly by {} ({:.0}%). Close it if it is not in use right now.",
                    p.nom,
                    p.processeur
                ),
            },
            None => trf!("Processeur occupé à {occupe:.0} %.", "Processor {occupe:.0}% busy."),
        };
        pousser(true, texte, None, "processeur");
    }
    if let Some((total, dispo)) = i.memoire.filter(|&(t, d)| pourcent(d, t) < 10.0) {
        let texte = match plus(|p| p.memoire as f64) {
            Some(p) => trf!(
                "Mémoire presque pleine ({} libres sur {}) : l'ordinateur écrit sur le disque ce qui ne tient plus, d'où la lenteur. {} en occupe {} : le fermer, ou fermer des onglets.",
                "Memory almost full ({} free out of {}): the computer writes what no longer fits to the disk, hence the slowness. {} uses {}: close it, or close some tabs.",
                taille(dispo),
                taille(total),
                p.nom,
                taille(p.memoire)
            ),
            None => trf!(
                "Mémoire presque pleine ({} libres sur {}).",
                "Memory almost full ({} free out of {}).",
                taille(dispo),
                taille(total)
            ),
        };
        pousser(true, texte, Some(Outil::Demarrage), "memoire");
    }
    if let Some(occupe) = i.disque.filter(|&o| o >= 80.0) {
        let texte = match plus(|p| p.disque.unwrap_or(0.0)) {
            Some(p) => trf!(
                "Disque occupé {occupe:.0} % du temps, surtout par {} ({}/s){}.",
                "Disk busy {occupe:.0}% of the time, mostly by {} ({}/s){}.",
                p.nom,
                taille(debit(p)),
                passager(&p.nom).map(|r| format!(" : {r}")).unwrap_or_default()
            ),
            None => trf!(
                "Disque occupé {occupe:.0} % du temps : tout ce qui le lit ou l'écrit attend son tour.",
                "Disk busy {occupe:.0}% of the time: everything that reads or writes it waits its turn."
            ),
        };
        pousser(true, texte, None, "disque");
    }
    if let Some((libre, total)) = i.place.filter(|&(l, t)| pourcent(l, t) < 10.0) {
        let texte = trf!(
            "Disque du système presque plein ({} libres sur {}) : le système a besoin de place pour travailler.",
            "System disk almost full ({} free out of {}): the system needs room to work.",
            taille(libre),
            taille(total)
        );
        pousser(true, texte, Some(Outil::Nettoyer), "place");
    }
    if let Some(d) = i.demarrage.as_ref().ok().filter(|d| d.total >= 60.0) {
        let lents = retards(&d.lents[..d.lents.len().min(3)]);
        let texte = if lents.is_empty() {
            trf!("Démarrage long ({}).", "Slow startup ({}).", secondes_lisibles(d.total))
        } else {
            trf!(
                "Démarrage long ({}) ; ce qui le retarde le plus : {lents}.",
                "Slow startup ({}); what delays it most: {lents}.",
                secondes_lisibles(d.total)
            )
        };
        pousser(false, texte, Some(Outil::Performance), "demarrage");
    }
    if i.au_demarrage.len() >= 8 || i.au_demarrage.iter().filter_map(|p| p.poids).sum::<u64>() >= 1 << 30 {
        let texte = trf!(
            "{} programmes se lancent à l'ouverture de session : ceux dont vous n'avez pas besoin tout de suite peuvent attendre que vous les ouvriez.",
            "{} programs start when you log in: those you do not need right away can wait until you open them.",
            i.au_demarrage.len()
        );
        pousser(false, texte, Some(Outil::Demarrage), "au-demarrage");
    }
    // Windows surtout : des semaines sans redémarrer, et des mises à jour attendent, des fuites de mémoire s'accumulent.
    if i.allume_depuis.is_some_and(|s| s >= 14 * 86_400) {
        let texte = trf!(
            "Allumé depuis {} jours sans redémarrer : redémarrer libère la mémoire et termine les mises à jour en attente.",
            "On for {} days without a restart: restarting frees memory and finishes pending updates.",
            i.allume_depuis.unwrap_or(0) / 86_400
        );
        pousser(false, texte, Some(Outil::MisesAJour), "allume");
    }
    c
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn debit(p: &Programme) -> u64 {
    p.disque.unwrap_or(0.0).max(0.0) as u64
}

fn taille(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = octets as f64;
    if octets >= 1 << 30 {
        trf!("{} Go", "{} GB", crate::langue::decimal(f / f64::from(1u32 << 30), 1))
    } else if octets >= 1 << 20 {
        trf!("{:.0} Mo", "{:.0} MB", f / f64::from(1u32 << 20))
    } else {
        trf!("{:.0} ko", "{:.0} kB", f / 1024.0)
    }
}

/// « docker.service 4,5 s, … » : ce qui a retardé le démarrage.
fn retards(lents: &[(String, f64)]) -> String {
    let texte = |(n, s): &(String, f64)| format!("{n} {}", secondes_lisibles(*s));
    lents.iter().map(texte).collect::<Vec<_>>().join(", ")
}

/// Une barre de 10 cases (le `clamp` en garde 10 au plus), colorée selon la charge.
fn jauge(pct: f64) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let pleines = ((pct.clamp(0.0, 100.0) + 5.0) / 10.0) as usize;
    let c = match pct {
        p if p >= 80.0 => couleur(Niveau::Eleve),
        p if p >= 50.0 => couleur(Niveau::Moyen),
        _ => VERT,
    };
    format!("{c}{}{GRIS}{}{RESET}", "▰".repeat(pleines), "▱".repeat(10 - pleines))
}

fn ligne_mesure(libelle: &str, valeur: &str) {
    afficher_aligne(&format!("  {GRAS}{}{RESET} ", ajuster(libelle, 13)), valeur, 16, "");
}

/// Une mesure de « ce qui pèse le plus » : libellé, seuil, valeur d'un programme, et cette valeur en texte.
type Mesure = (&'static str, f64, fn(&Programme) -> f64, fn(&Programme) -> String);

#[allow(clippy::cast_precision_loss)]
fn afficher(i: &Instantane) {
    let processeur = tr!("Processeur", "Processor");
    let memoire = tr!("Mémoire", "Memory");
    let disque = tr!("Disque", "Disk");
    section(tr!("EN CE MOMENT", "RIGHT NOW"));
    let texte = match i.processeur {
        Some(p) => trf!("{} {p:.0} % ({} fils)", "{} {p:.0}% ({} threads)", jauge(p), i.fils),
        None => tr!("non mesuré", "not measured").into(),
    };
    ligne_mesure(processeur, &texte);
    if let Some((total, dispo)) = i.memoire {
        let utilise = pourcent(total.saturating_sub(dispo), total);
        let echange = match i.echange {
            Some((t, u)) if t > 0 && u >= 1 << 20 => trf!(", échange {} utilisés", ", swap {} used", taille(u)),
            _ => String::new(),
        };
        let texte = trf!(
            "{} {utilise:.0} % ({} libres sur {}){echange}",
            "{} {utilise:.0}% ({} free out of {}){echange}",
            jauge(utilise),
            taille(dispo),
            taille(total)
        );
        ligne_mesure(memoire, &texte);
    }
    let texte = match i.disque {
        Some(d) => trf!("{} occupé {d:.0} % du temps", "{} busy {d:.0}% of the time", jauge(d)),
        None => tr!("activité non mesurable ici", "activity not measurable here").into(),
    };
    ligne_mesure(disque, &texte);
    if let Some((libre, total)) = i.place {
        let texte = trf!(
            "{} libres sur {} (disque du système)",
            "{} free out of {} (system disk)",
            taille(libre),
            taille(total)
        );
        ligne_mesure(tr!("Place", "Space"), &texte);
    }

    section(tr!("CE QUI PÈSE LE PLUS", "WHAT WEIGHS THE MOST"));
    let rien = tr!("rien de notable", "nothing notable");
    // Les trois plus gros, au-dessus d'un seuil : un programme à « 0 % » n'est pas un suspect.
    #[rustfmt::skip] // une ligne par mesure, que rustfmt étalerait sur six
    let mesures: [Mesure; 3] = [
        (processeur, 1.0, |p| p.processeur, |p| trf!("{:.0} %", "{:.0}%", p.processeur)),
        (memoire, 100.0 * 1_048_576.0, |p| p.memoire as f64, |p| taille(p.memoire)),
        (disque, 1_048_576.0, |p| p.disque.unwrap_or(0.0), |p| format!("{}/s", taille(debit(p)))),
    ];
    for (libelle, seuil, cle, texte) in mesures {
        let mut tries: Vec<&Programme> = i.programmes.iter().filter(|p| cle(p) >= seuil).collect();
        tries.sort_by(|a, b| cle(b).total_cmp(&cle(a)));
        tries.truncate(3);
        let liste: Vec<String> = tries.iter().map(|p| format!("{} {}", p.nom, texte(p))).collect();
        let liste = liste.join(", ");
        ligne_mesure(libelle, if liste.is_empty() { rien } else { &liste });
    }

    section(tr!("DÉMARRAGE", "STARTUP"));
    let duree = tr!("Durée", "Duration");
    match &i.demarrage {
        Ok(d) => {
            let mut texte = secondes_lisibles(d.total);
            if !d.etapes.is_empty() {
                texte = format!("{texte} ({})", d.etapes);
            }
            ligne_mesure(duree, &texte);
            if !d.lents.is_empty() {
                ligne_mesure(tr!("Retardé par", "Delayed by"), &retards(&d.lents));
            }
        }
        Err(raison) => ligne_mesure(duree, &format!("{GRIS}{raison}{RESET}")),
    }
    if let Some(s) = i.allume_depuis {
        let (j, h) = (s / 86_400, s % 86_400 / 3600);
        let texte = if j > 0 {
            trf!("{j} j {h} h", "{j} d {h} h")
        } else {
            trf!("{h} h {:02}", "{h} h {:02}", s % 3600 / 60)
        };
        ligne_mesure(tr!("Allumé depuis", "On for"), &texte);
    }
    let a_l_ouverture = tr!("À l'ouverture", "At login");
    if i.au_demarrage.is_empty() {
        ligne_mesure(a_l_ouverture, tr!("aucun programme trouvé", "no program found"));
        return;
    }
    let mut liste: Vec<&AuDemarrage> = i.au_demarrage.iter().collect();
    liste.sort_by(|a, b| b.poids.cmp(&a.poids).then_with(|| a.nom.cmp(&b.nom)));
    let avec_taille = |p: &&AuDemarrage| match p.poids {
        Some(o) => format!("{} ({})", p.nom, taille(o)),
        None => p.nom.clone(),
    };
    let noms: Vec<String> = liste.iter().take(8).map(avec_taille).collect();
    let mut texte = noms.join(", ");
    let reste = liste.len().saturating_sub(8);
    if reste > 0 {
        texte += &trf!(" et {reste} autre(s)", " and {reste} more");
    }
    let texte = trf!("{} programme(s) : {texte}", "{} program(s): {texte}", liste.len());
    ligne_mesure(a_l_ouverture, &texte);
}

/// L'écran : l'en-tête, la mesure de deux secondes, puis ce qu'elle veut dire. Rend les conseils.
/// « Rien ne force » se conclut seulement sur une mesure : sans processeur ni mémoire mesurés, ce n'est pas sain,
/// c'est non vérifié.
fn mesure_complete(i: &Instantane) -> bool {
    i.processeur.is_some() && i.memoire.is_some()
}

fn mesurer() -> Vec<Conseil> {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("POURQUOI C'EST LENT ?", "WHY IS IT SLOW?")),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
    trp!(
        "  {DISCRET}Mesure pendant deux secondes : utilisez l'ordinateur comme d'habitude…{RESET}",
        "  {DISCRET}Measuring for two seconds: keep using the computer as usual…{RESET}"
    );
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let i = systeme::instantane();
    crate::modele::resultat::verser(&resultat::resultat(&i, debut));
    afficher(&i);
    let c = conseils(&i);
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    if c.is_empty() && !mesure_complete(&i) {
        let rien = tr!(
            "Mesure incomplète (processeur ou mémoire non mesurés) : rien n'est conclu, non vérifié.",
            "Incomplete measurement (processor or memory not measured): nothing concluded, not verified."
        );
        afficher_aligne(&format!("  {}⚠{RESET} ", couleur(Niveau::Moyen)), rien, 4, "");
    } else if c.is_empty() {
        let rien = tr!(
            "Rien ne force en ce moment : si c'est lent par moments, relancez la mesure à ce moment-là.",
            "Nothing is straining right now: if it is slow at times, run the measurement again at that moment."
        );
        afficher_aligne(&format!("  {VERT}✔{RESET} "), rien, 4, "");
    }
    let attention = format!("  {}⚠{RESET} ", couleur(Niveau::Moyen));
    for k in &c {
        let conseil = format!("  {} ", ampoule());
        afficher_aligne(if k.grave { &attention } else { &conseil }, &k.texte, 5, "");
    }
    c
}

/// « vanguard lenteur » : l'instantané et ses conseils.
pub fn commande() {
    mesurer();
}

/// `vanguard lenteur --json` : la même mesure de deux secondes que l'écran, jugée en résultat et versée comme lui.
/// Rien n'est demandé ni changé.
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let i = systeme::instantane();
    let r = resultat::resultat(&i, debut);
    crate::modele::resultat::verser(&r);
    println!("{}", crate::modele::resultat::json(&r));
}

/// L'outil au menu : l'instantané, ses conseils, puis l'outil qui règle ce qui a été trouvé.
pub fn menu() {
    loop {
        let c = mesurer();
        // Les choix s'écrivent sous la mesure, qui reste à l'écran (un menu au clavier redessinerait tout l'écran).
        section(tr!("ET MAINTENANT", "WHAT NEXT"));
        // Les outils des conseils, puis ceux toujours sous la main, même quand rien ne force.
        let proposes = c.iter().filter_map(|k| k.outil);
        let mut outils: Vec<Outil> = Vec::new();
        for o in proposes.chain([Outil::Demarrage, Outil::Nettoyer]) {
            if !outils.contains(&o) {
                outils.push(o);
            }
        }
        for (n, outil) in (1..).zip(&outils) {
            #[rustfmt::skip] // deux lignes par outil, que rustfmt étalerait sur quatre
            let (texte, precision) = match outil {
                Outil::Nettoyer => (tr!("Nettoyer le système", "Clean up the system"),
                    tr!("caches, temporaires, corbeille…", "caches, temp files, trash…")),
                Outil::Demarrage => (tr!("Programmes au démarrage", "Startup programs"),
                    tr!("les retirer ou les remettre", "remove or put back")),
                Outil::Performance => (tr!("Réglages de performance", "Performance settings"),
                    tr!("Optimiser, tout s'annule", "Optimize, all undoable")),
                Outil::MisesAJour => (tr!("Mises à jour", "Updates"),
                    tr!("système, programmes, pilotes", "system, programs, drivers")),
            };
            let texte = ajuster(texte, 34);
            println!("   {TOUCHE}{n}{RESET}  {texte}{DISCRET}{precision}{RESET}");
        }
        println!("   {TOUCHE}m{RESET}  {}", tr!("Mesurer de nouveau", "Measure again"));
        println!("   {TOUCHE}↵{RESET}  {}", tr!("Revenir", "Back"));
        let choix = crate::selection::demander_ou_revenir(tr!(
            "\n  Choix (Entrée pour revenir) : ",
            "\n  Choice (Enter to go back): "
        ));
        let choix = choix.to_lowercase();
        if choix == "m" {
            continue;
        }
        if let Some(n) = (1..=outils.len()).find(|n| n.to_string() == choix) {
            println!();
            match outils[n - 1] {
                Outil::Nettoyer => crate::nettoyer::menu(),
                Outil::Demarrage => crate::optimiser::programmes_au_demarrage(),
                #[cfg(not(target_os = "macos"))]
                Outil::Performance => crate::optimiser::menu(crate::optimiser::Categorie::Performance),
                #[cfg(target_os = "macos")]
                Outil::Performance => {}
                Outil::MisesAJour => crate::maj::executer(),
            }
        }
        return;
    }
}

// ───────────────────────────── Linux ─────────────────────────────

/// Le nom d'un processus : son programme (lien `/proc/<pid>/exe`, lisible pour nos propres processus), sauf quand ce
/// programme est un interpréteur ou un moteur partagé (python, electron…) : son nom court dit alors mieux qui il est.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_de_processus(exe: Option<&str>, comm: &str) -> String {
    const MOTEURS: &[&str] = &[
        "python", "perl", "ruby", "node", "electron", "java", "bash", "sh", "dash", "zsh", "lua",
    ];
    let fichier = exe.and_then(|e| e.rsplit('/').next());
    match fichier.map(|e| e.trim_end_matches(" (deleted)")) {
        Some(e) if !e.is_empty() && !MOTEURS.iter().any(|m| e.starts_with(m)) => e.to_string(),
        _ => comm.split('/').next().unwrap_or(comm).trim().to_string(),
    }
}

/// `/proc/<pid>/stat` : (temps processeur en tops d'horloge, mémoire résidente en pages). Le nom (2e champ) peut
/// contenir des espaces et des parenthèses : on repart de la dernière « ) ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_processus(texte: &str) -> Option<(u64, u64)> {
    let champs: Vec<&str> = texte.get(texte.rfind(')')? + 1..)?.split_whitespace().collect();
    // Après le nom : état (3e champ), …, utime (14e), stime (15e), …, rss (24e).
    let nombre = |i: usize| champs.get(i)?.parse::<u64>().ok();
    let (utime, stime, rss) = (nombre(11)?, nombre(12)?, nombre(21)?);
    Some((utime + stime, rss))
}

/// Première ligne de /proc/stat : (occupé, total) en tops d'horloge, toute la machine.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_processeur(texte: &str) -> Option<(u64, u64)> {
    let ligne = texte.strip_prefix("cpu ")?.lines().next()?;
    let valeurs: Vec<u64> = ligne.split_whitespace().filter_map(|v| v.parse().ok()).collect();
    // user nice system idle iowait irq softirq steal (guest est déjà compté dans user).
    let total: u64 = valeurs.iter().take(8).sum();
    let repos = valeurs.get(3)? + valeurs.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(repos), total))
}

/// /proc/diskstats : temps passé à servir des entrées-sorties (ms), par disque.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn occupation_disques(texte: &str, disques: &[String]) -> HashMap<String, u64> {
    let disque = |l: &str| {
        let c: Vec<&str> = l.split_whitespace().collect();
        let nom = (*c.get(2)?).to_string();
        disques.contains(&nom).then_some((nom, c.get(12)?.parse().ok()?))
    };
    texte.lines().filter_map(disque).collect()
}

#[cfg(target_os = "linux")]
mod systeme {
    use std::fs::{read_dir, read_to_string};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::machine::linux::dbus::{self, Bus, Valeur};
    use crate::machine::linux::natif;

    /// Durée entre les deux mesures : assez pour lisser un pic, assez courte pour qu'on attende sans s'impatienter.
    /// (Windows et macOS mesurent eux-mêmes sur deux secondes : PowerShell, top.)
    const ECART: Duration = Duration::from_secs(2);

    struct Echantillon {
        quand: Instant,
        processeur: Option<(u64, u64)>,
        /// pid → (nom, temps processeur, mémoire en pages, octets lus et écrits)
        processus: HashMap<u32, (String, u64, u64, Option<u64>)>,
        disques: HashMap<String, u64>,
    }

    /// Les disques entiers (pas les partitions), sans les disques virtuels.
    fn disques() -> Vec<String> {
        const VIRTUELS: [&str; 6] = ["loop", "ram", "zram", "dm-", "sr", "fd"];
        read_dir("/sys/block")
            .into_iter()
            .flatten()
            .flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .filter(|n| !VIRTUELS.iter().any(|p| n.starts_with(p)))
            .collect()
    }

    fn echantillon(disques: &[String]) -> Echantillon {
        let processus = crate::socle::processus::pids()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|n| {
                let pid = n;
                let (temps, pages) = stat_processus(&read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
                let comm = crate::socle::processus::nom_court(pid).unwrap_or_default();
                let exe = crate::socle::processus::programme(pid);
                let nom = nom_de_processus(exe.as_deref().and_then(Path::to_str), comm.trim());
                // Octets lus et écrits : illisibles pour les programmes d'un autre compte.
                let io = read_to_string(format!("/proc/{pid}/io")).unwrap_or_default();
                let lire = |cle: &str| io.lines().find_map(|l| l.strip_prefix(cle)?.trim().parse::<u64>().ok());
                let es = lire("read_bytes:").zip(lire("write_bytes:")).map(|(l, e)| l + e);
                Some((n, (nom, temps, pages, es)))
            })
            .collect();
        Echantillon {
            quand: Instant::now(),
            processeur: read_to_string("/proc/stat").ok().and_then(|t| stat_processeur(&t)),
            processus,
            disques: occupation_disques(&read_to_string("/proc/diskstats").unwrap_or_default(), disques),
        }
    }

    /// La durée du démarrage, demandée à systemd par le bus système (ce que calcule `systemd-analyze`), et ce qui l'a
    /// retardé (son `critical-chain`).
    pub(super) fn demarrage() -> Result<Demarrage, String> {
        let illisible = |e: String| trf!("durée illisible ({e})", "duration not readable ({e})");
        let mut bus = Bus::systeme().map_err(illisible)?;
        let mut instant = |nom: &str| {
            bus.propriete(dbus::SYSTEMD, dbus::CHEMIN_SYSTEMD, dbus::GESTIONNAIRE, nom)
                .map(|v| v.entier().unwrap_or(0))
        };
        let instants = InstantsDemarrage {
            micrologiciel: instant("FirmwareTimestampMonotonic").map_err(illisible)?,
            chargeur: instant("LoaderTimestampMonotonic").map_err(illisible)?,
            initrd: instant("InitRDTimestampMonotonic").map_err(illisible)?,
            espace_utilisateur: instant("UserspaceTimestampMonotonic").map_err(illisible)?,
            fin: instant("FinishTimestampMonotonic").map_err(illisible)?,
            // systemd y écrit le nom du gestionnaire de conteneurs quand il tourne dans l'un d'eux.
            conteneur: Path::new("/run/systemd/container").exists(),
        };
        let (total, etapes) = duree_demarrage(&instants).ok_or_else(|| {
            tr!(
                "durée illisible (démarrage pas encore fini)",
                "duration not readable (startup not finished yet)"
            )
            .to_string()
        })?;
        Ok(Demarrage {
            total,
            etapes,
            lents: unites_lentes(&mut bus, instants.fin),
        })
    }

    /// La chaîne critique, lue unité par unité sur le bus : chemins des unités chargées (ListUnits), puis les
    /// propriétés de chacune dont la chaîne a besoin. Une lecture qui échoue laisse la liste vide, pas fausse.
    fn unites_lentes(bus: &mut Bus, fin: u64) -> Vec<(String, f64)> {
        const RACINE: &str = "default.target";
        let Ok(mut chemins) = dbus::unites_chargees(bus) else {
            return Vec::new();
        };
        // default.target est un alias : ListUnits ne donne que le nom de l'unité qu'il désigne.
        let Some(racine) = bus
            .appeler(
                dbus::SYSTEMD,
                dbus::CHEMIN_SYSTEMD,
                dbus::GESTIONNAIRE,
                "GetUnit",
                "s",
                vec![Valeur::texte_de(RACINE)],
            )
            .ok()
            .and_then(|corps| corps.first().and_then(Valeur::texte).map(String::from))
        else {
            return Vec::new();
        };
        chemins.insert(RACINE.to_string(), racine);
        chaine_critique(RACINE, fin, |nom| {
            // Absente de ListUnits : pas chargée, ce n'est pas une erreur.
            let Some(chemin) = chemins.get(nom) else {
                return Ok(None);
            };
            let p = bus.proprietes(dbus::SYSTEMD, chemin, dbus::UNITE)?;
            let instant = |cle: &str| p.champ(cle).and_then(Valeur::entier).unwrap_or(0);
            Ok(Some(UniteDemarrage {
                apres: p.champ("After").map(Valeur::textes).unwrap_or_default(),
                debut: instant("InactiveExitTimestampMonotonic"),
                active: instant("ActiveEnterTimestampMonotonic"),
                inactive: instant("InactiveEnterTimestampMonotonic"),
            }))
        })
    }

    /// Les programmes lancés à l'ouverture de session, (nom, programme) : entrées d'autostart actives (celles de
    /// l'utilisateur remplacent celles du système au même nom) et services ajoutés par l'utilisateur
    /// (~/.config/systemd/user).
    fn au_demarrage() -> Vec<(String, String)> {
        let maison = crate::socle::maison();
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        let systeme = std::env::var("XDG_CONFIG_DIRS").unwrap_or_default();
        let systeme = if systeme.is_empty() { "/etc/xdg" } else { &systeme };
        let bureau = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let mut liste = Vec::new();
        // L'utilisateur d'abord : son entrée l'emporte sur celle du système au même nom, même désactivée.
        let mut vus: Vec<String> = Vec::new();
        for f in std::iter::once(config.join("autostart"))
            .chain(systeme.split(':').map(|d| Path::new(d).join("autostart")))
            .flat_map(|d| read_dir(d).into_iter().flatten().flatten())
        {
            let nom = f.file_name().to_string_lossy().into_owned();
            if Path::new(&nom).extension().is_some_and(|e| e == "desktop") && !vus.contains(&nom) {
                liste.extend(entree_autostart(&read_to_string(f.path()).unwrap_or_default(), &bureau));
                vus.push(nom);
            }
        }
        let activee = |u: &str| natif::unite_activee(u, true) == Some(true);
        for unite in services_actives(&config.join("systemd/user"), activee) {
            let nom = unite.trim_end_matches(".service").to_string();
            liste.push((nom.clone(), nom));
        }
        liste
    }

    /// Les services que l'utilisateur a ajoutés (`dossier` : ~/.config/systemd/user) et activés pour l'ouverture de
    /// session, triés. `activee` : un lien à son nom dans un dossier « *.wants » (ce que `systemctl --user
    /// list-unit-files --state=enabled` disait), lu par natif dans les dossiers de systemd sans le lancer.
    pub(super) fn services_actives(dossier: &Path, activee: impl Fn(&str) -> bool) -> Vec<String> {
        let mut unites: Vec<String> = read_dir(dossier)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|u| {
                let fichier = dossier.join(u);
                Path::new(u).extension().is_some_and(|e| e == "service")
                    && fichier.is_file()
                    && activee(u)
                    && lance_a_l_ouverture(&read_to_string(&fichier).unwrap_or_default())
            })
            .collect();
        unites.sort();
        unites
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn instantane() -> Instantane {
        let disques = disques();
        // sysconf, ce que getconf lisait lui-même.
        let horloge = natif::tics().max(1);
        let page = natif::taille_page();
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let a = echantillon(&disques);
        std::thread::sleep(ECART);
        let b = echantillon(&disques);
        let ecart_s = b.quand.duration_since(a.quand).as_secs_f64().max(0.001);
        let releves = a.processeur.zip(b.processeur).filter(|((_, ta), (_, tb))| tb > ta);
        let processeur = releves.map(|((oa, ta), (ob, tb))| ob.saturating_sub(oa) as f64 * 100.0 / (tb - ta) as f64);
        let programmes = reunir(b.processus.iter().map(|(pid, (nom, temps, pages, es))| {
            let avant = a.processus.get(pid);
            let tops = avant.map_or(0, |(_, t, ..)| temps.saturating_sub(*t));
            Programme {
                nom: nom.clone(),
                // Tops d'horloge → secondes de processeur, rapportées au temps écoulé et à tous les fils.
                processeur: tops as f64 / horloge as f64 / ecart_s / fils as f64 * 100.0,
                memoire: pages * page,
                disque: avant
                    .and_then(|(.., e)| *e)
                    .zip(*es)
                    .map(|(x, y)| y.saturating_sub(x) as f64 / ecart_s),
            }
        }));
        let disque = b
            .disques
            .iter()
            .filter_map(|(nom, ms)| Some(ms.saturating_sub(*a.disques.get(nom)?) as f64 / (ecart_s * 1000.0) * 100.0))
            .reduce(f64::max)
            .map(|d| d.min(100.0));
        let meminfo = read_to_string("/proc/meminfo").unwrap_or_default();
        let lire = |cle: &str| {
            meminfo
                .lines()
                .find_map(|l| l.strip_prefix(cle)?.split_whitespace().next()?.parse::<u64>().ok())
                .map(|ko| ko * 1024)
        };
        Instantane {
            processeur,
            fils,
            memoire: lire("MemTotal:").zip(lire("MemAvailable:")),
            echange: lire("SwapTotal:")
                .zip(lire("SwapFree:"))
                .map(|(t, l)| (t, t.saturating_sub(l))),
            disque,
            au_demarrage: avec_poids(&programmes, au_demarrage().into_iter()),
            programmes,
            demarrage: demarrage(),
            allume_depuis: read_to_string("/proc/uptime")
                .ok()
                .and_then(|t| t.split('.').next()?.parse().ok()),
            place: crate::socle::volume(Path::new("/")),
        }
    }
}

// ───────────────────────────── Windows ─────────────────────────────

/// Ce que lit le script PowerShell, en JSON.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct LectureWindows {
    processeur: Option<f64>,
    fils: usize,
    memoire: u64,
    disponible: u64,
    echange: u64,
    echange_utilise: u64,
    disque: Option<f64>,
    programmes: Vec<Programme>,
    demarrage_ms: Option<u64>,
    apres_ms: Option<u64>,
    demarrage_illisible: bool,
    lents: Vec<LentWindows>,
    au_demarrage: Vec<DemarrageWindows>,
    allume_s: Option<u64>,
    libre: u64,
    total: u64,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct LentWindows {
    nom: String,
    ms: u64,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct DemarrageWindows {
    nom: String,
    programme: String,
}

/// L'instantané d'après la lecture PowerShell (séparé pour être testé partout).
#[cfg_attr(not(windows), allow(dead_code))]
#[allow(clippy::cast_precision_loss)]
fn instantane_windows(l: LectureWindows) -> Instantane {
    let programmes = reunir(l.programmes.into_iter().map(|p| Programme {
        processeur: p.processeur.max(0.0),
        disque: p.disque.map(|d| d.max(0.0)),
        ..p
    }));
    let demarrage = match (l.demarrage_ms, l.demarrage_illisible) {
        (Some(ms), _) => {
            let mut lents: Vec<(String, f64)> = l
                .lents
                .into_iter()
                .filter(|x| !x.nom.trim().is_empty())
                .map(|x| (affichable(x.nom.trim()), x.ms as f64 / 1000.0))
                .collect();
            lents.sort_by(|a, b| b.1.total_cmp(&a.1));
            // Un même programme ralentit souvent plusieurs démarrages : une fois, avec son pire retard.
            let mut vus = std::collections::HashSet::new();
            lents.retain(|(nom, _)| vus.insert(nom.clone()));
            lents.truncate(5);
            let total = ms as f64 / 1000.0;
            let apres = l
                .apres_ms
                .filter(|&a| a > 0)
                .map(|a| secondes_lisibles(a as f64 / 1000.0));
            let etapes = apres
                .map(|a| trf!("dont {} après l'ouverture de session", "including {} after login", a))
                .unwrap_or_default();
            Ok(Demarrage { total, etapes, lents })
        }
        (None, true) => Err(tr!(
            "durée lisible seulement avec les droits d'administrateur",
            "duration readable only with administrator rights"
        )
        .into()),
        (None, false) => Err(tr!(
            "pas de mesure du dernier démarrage",
            "no measurement of the last startup"
        )
        .into()),
    };
    Instantane {
        processeur: l.processeur.map(|p| p.clamp(0.0, 100.0)),
        fils: l.fils.max(1),
        memoire: Some((l.memoire, l.disponible)).filter(|(t, _)| *t > 0),
        echange: Some((l.echange, l.echange_utilise)).filter(|(t, _)| *t > 0),
        disque: l.disque.map(|d| d.clamp(0.0, 100.0)),
        au_demarrage: avec_poids(&programmes, l.au_demarrage.into_iter().map(|d| (d.nom, d.programme))),
        programmes,
        demarrage,
        allume_depuis: l.allume_s,
        place: Some((l.libre, l.total)).filter(|(_, t)| *t > 0),
    }
}

#[cfg(windows)]
mod systeme {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use super::{DemarrageWindows, Instantane, LectureWindows, LentWindows, Programme, instantane_windows};
    use crate::machine::windows::wmi::{self, Ligne};

    const CIMV2: &str = r"root\cimv2";
    const PERFORMANCES: &str = "Microsoft-Windows-Diagnostics-Performance/Operational";

    /// Une lecture des compteurs bruts : le processeur (temps de repos), chaque disque (temps de repos), chaque
    /// processus (temps de processeur, octets lus et écrits, mémoire). Les mêmes classes que le script PowerShell.
    struct Releve {
        processeur: Option<Ligne>,
        disques: Vec<Ligne>,
        processus: Vec<Ligne>,
        quand: Instant,
    }

    fn releve() -> Option<Releve> {
        let processeur = wmi::requete(
            CIMV2,
            "Win32_PerfRawData_PerfOS_Processor",
            "Name='_Total'",
            &["PercentProcessorTime", "Timestamp_Sys100NS"],
        )
        .and_then(|l| l.into_iter().next());
        let disques = wmi::requete(
            CIMV2,
            "Win32_PerfRawData_PerfDisk_PhysicalDisk",
            "Name <> '_Total'",
            &["Name", "PercentIdleTime", "Timestamp_Sys100NS"],
        )
        .unwrap_or_default();
        // Sans les compteurs des processus (compteurs de performance coupés), PowerShell prend tout le relais.
        let processus = wmi::requete(
            CIMV2,
            "Win32_PerfRawData_PerfProc_Process",
            "Name <> '_Total'",
            &[
                "IDProcess",
                "Name",
                "PercentProcessorTime",
                "IODataBytesPersec",
                "WorkingSet",
            ],
        )?;
        Some(Releve {
            processeur,
            disques,
            processus,
            quand: Instant::now(),
        })
    }

    #[allow(clippy::cast_precision_loss)]
    fn nombre(l: &Ligne, champ: &str) -> Option<f64> {
        l[champ].entier().map(|n| n as f64)
    }

    /// Part occupée entre deux lectures d'un compteur de repos : 100 × (1 − repos / temps écoulé).
    fn occupe(avant: &Ligne, apres: &Ligne, repos: &str) -> Option<f64> {
        let ecoule = nombre(apres, "Timestamp_Sys100NS")? - nombre(avant, "Timestamp_Sys100NS")?;
        let libre = nombre(apres, repos)? - nombre(avant, repos)?;
        (ecoule > 0.0).then(|| 100.0 * (1.0 - libre / ecoule))
    }

    /// Le nom d'un processus comme Get-Process le donne : les compteurs numérotent les homonymes (« chrome#3 »).
    pub(super) fn nom_du_processus(instance: &str) -> &str {
        match instance.rsplit_once('#') {
            Some((nom, n)) if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) => nom,
            _ => instance,
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    fn programmes(avant: &Releve, apres: &Releve, ms: f64, fils: usize) -> Vec<Programme> {
        let par_pid = |r: &Releve| -> HashMap<i64, Ligne> {
            r.processus
                .iter()
                .filter_map(|l| Some((l["IDProcess"].entier()?, l.clone())))
                .collect()
        };
        let debut = par_pid(avant);
        apres
            .processus
            .iter()
            .filter_map(|l| {
                let pid = l["IDProcess"].entier()?;
                let d = debut.get(&pid);
                // Temps de processeur en centaines de nanosecondes, comme TotalProcessorTime.Ticks.
                let cpu = d
                    .and_then(|d| Some(nombre(l, "PercentProcessorTime")? - nombre(d, "PercentProcessorTime")?))
                    .map_or(0.0, |t| t / 10_000.0 / ms / fils as f64 * 100.0);
                let disque = d.and_then(|d| {
                    Some((nombre(l, "IODataBytesPersec")? - nombre(d, "IODataBytesPersec")?) / (ms / 1000.0))
                });
                Some(Programme {
                    nom: nom_du_processus(l["Name"].texte().unwrap_or_default()).to_string(),
                    processeur: cpu,
                    memoire: l["WorkingSet"].entier().map_or(0, |m| m.max(0) as u64),
                    disque,
                })
            })
            .collect()
    }

    /// Durée du dernier démarrage (événement 100) et ce qui l'a ralenti depuis trente jours (101, 102, 103, 106),
    /// comme le script : (durée, après l'ouverture de session, illisible, lents). Le journal ne s'ouvre qu'aux
    /// administrateurs : refusé sans élévation, c'est « illisible ».
    fn demarrage() -> (Option<u64>, Option<u64>, bool, Vec<LentWindows>) {
        use crate::machine::windows::evenements::parcourir_nommes;
        let fin = Instant::now() + Duration::from_secs(30);
        let champ = |v: &[(String, String)], nom: &str| v.iter().find(|(n, _)| n == nom).map(|(_, x)| x.clone());
        let Some(dernier) = parcourir_nommes(PERFORMANCES, "*[System[(EventID=100)]]", 1, fin, |_, _, v| {
            Some(format!(
                "{}|{}",
                champ(v, "BootTime")?,
                champ(v, "BootPostBootTime").unwrap_or_default()
            ))
        }) else {
            return (None, None, !crate::machine::windows::processus::eleve(), Vec::new());
        };
        let Some((total, apres)) = dernier.first().and_then(|l| l.split_once('|')) else {
            return (None, None, false, Vec::new());
        };
        let lents = parcourir_nommes(
            PERFORMANCES,
            "*[System[(EventID=101 or EventID=102 or EventID=103 or EventID=106) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]",
            50,
            fin,
            |_, _, v| {
                let nom = champ(v, "FriendlyName").filter(|n| !n.is_empty()).or_else(|| champ(v, "Name"))?;
                Some(format!("{}|{nom}", champ(v, "DegradationTime")?))
            },
        )
        .unwrap_or_default()
        .iter()
        .filter_map(|l| {
            let (ms, nom) = l.split_once('|')?;
            Some(LentWindows { nom: nom.to_string(), ms: ms.parse().ok()? })
        })
        .collect();
        (total.parse().ok(), apres.parse().ok(), false, lents)
    }

    /// Ce que StartupApproved dit d'une entrée : coupée dans le Gestionnaire des tâches si le premier octet est
    /// impair ; sans valeur, lancée.
    fn approuve(hklm: bool, sous: &str, nom: &str) -> bool {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let ruche = winreg::RegKey::predef(if hklm { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER });
        ruche
            .open_subkey(format!(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sous}"
            ))
            .and_then(|k| k.get_raw_value(nom))
            .ok()
            .and_then(|v| v.bytes.first().copied())
            .is_none_or(|octet| octet & 1 == 0)
    }

    /// Les programmes lancés à l'ouverture de session (Win32_StartupCommand), sans ceux qu'on a coupés.
    fn au_demarrage() -> Vec<DemarrageWindows> {
        let lignes = wmi::requete(
            CIMV2,
            "Win32_StartupCommand",
            "",
            &["Caption", "Command", "Location", "Name"],
        )
        .unwrap_or_default();
        lignes
            .iter()
            .filter_map(|s| {
                let texte = |c: &str| s[c].texte().unwrap_or_default().to_string();
                let lieu = texte("Location").to_ascii_lowercase();
                let sous = if lieu.contains("startup") {
                    "StartupFolder"
                } else if lieu.contains("wow6432node") {
                    "Run32"
                } else {
                    "Run"
                };
                let commande = texte("Command");
                let cle = if sous == "StartupFolder" {
                    commande.rsplit(['\\', '/']).next().unwrap_or_default().to_string()
                } else {
                    texte("Name")
                };
                if !approuve(lieu.starts_with("hklm"), sous, &cle) {
                    return None;
                }
                let c = commande.trim();
                let programme = match c.strip_prefix('"') {
                    Some(reste) => reste.split('"').next().unwrap_or_default(),
                    None => c.split_whitespace().next().unwrap_or_default(),
                };
                let programme = std::path::Path::new(programme)
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Some(DemarrageWindows {
                    nom: texte("Caption"),
                    programme,
                })
            })
            .collect()
    }

    /// Tout ce que lisait le script, sans PowerShell : WMI (compteurs bruts, système, fichier d'échange, programmes au
    /// démarrage), le journal des performances (wevtapi), le registre et le lecteur système. `None` sans les
    /// compteurs des processus, du processeur ou du système : PowerShell refait alors tout le relevé.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn lecture_directe() -> Option<LectureWindows> {
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let avant = releve()?;
        std::thread::sleep(Duration::from_secs(2));
        let apres = releve()?;
        let ms = apres
            .quand
            .duration_since(avant.quand)
            .as_secs_f64()
            .mul_add(1000.0, 0.0)
            .max(1.0);
        let processeur = avant
            .processeur
            .as_ref()
            .zip(apres.processeur.as_ref())
            .and_then(|(a, b)| occupe(a, b, "PercentProcessorTime"))?;
        let disque = apres
            .disques
            .iter()
            .filter_map(|d| {
                let nom = d["Name"].texte()?;
                let a = avant.disques.iter().find(|x| x["Name"].texte() == Some(nom))?;
                occupe(a, d, "PercentIdleTime")
            })
            .reduce(f64::max);
        let os = wmi::requete(
            CIMV2,
            "Win32_OperatingSystem",
            "",
            &["TotalVisibleMemorySize", "LastBootUpTime"],
        )
        .and_then(|l| l.into_iter().next())?;
        let disponible = wmi::requete(CIMV2, "Win32_PerfRawData_PerfOS_Memory", "", &["AvailableBytes"])
            .and_then(|l| l.first().and_then(|m| m["AvailableBytes"].entier()));
        let echange =
            wmi::requete(CIMV2, "Win32_PageFileUsage", "", &["AllocatedBaseSize", "CurrentUsage"]).unwrap_or_default();
        let somme = |champ: &str| -> u64 {
            echange
                .iter()
                .filter_map(|l| l[champ].entier())
                .map(|n| n.max(0) as u64)
                .sum::<u64>()
                * 1_048_576
        };
        let (demarrage_ms, apres_ms, demarrage_illisible, lents) = demarrage();
        let systeme = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let lecteur = crate::machine::windows::lecteurs::lecteur(std::path::Path::new(&format!("{systeme}\\")));
        let os = Some(os);
        Some(LectureWindows {
            processeur: Some(processeur),
            fils,
            memoire: os
                .as_ref()
                .and_then(|o| o["TotalVisibleMemorySize"].entier())
                .map_or(0, |k| k.max(0) as u64 * 1024),
            disponible: disponible.map_or(0, |d| d.max(0) as u64),
            echange: somme("AllocatedBaseSize"),
            echange_utilise: somme("CurrentUsage"),
            disque,
            programmes: programmes(&avant, &apres, ms, fils),
            demarrage_ms,
            apres_ms,
            demarrage_illisible,
            lents,
            au_demarrage: au_demarrage(),
            allume_s: os.as_ref().and_then(|o| {
                o["LastBootUpTime"]
                    .texte()
                    .and_then(|d| wmi::secondes_depuis(d, chrono::Utc::now()))
            }),
            libre: lecteur.as_ref().map_or(0, |l| l.libre),
            total: lecteur.as_ref().map_or(0, |l| l.total),
        })
    }

    pub fn instantane() -> Instantane {
        if let Some(l) = lecture_directe() {
            return instantane_windows(l);
        }
        // Secours : le même relevé par PowerShell.
        // Compteurs bruts lus deux fois, à deux secondes d'écart : les compteurs « mis en forme » de WMI ne sont justes
        // qu'à leur deuxième lecture, et leurs noms ne changent pas avec la langue de Windows (ceux de Get-Counter, si).
        let script = r#"
            $n = [Environment]::ProcessorCount
            function Cpu { Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue }
            function Disques { @(Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object Name -ne '_Total') }
            function Temps { $t = @{}; foreach ($p in Get-Process) { try { $t[$p.Id] = $p.TotalProcessorTime.Ticks } catch { } }; $t }
            function Es { $t = @{}; foreach ($p in Get-CimInstance Win32_PerfRawData_PerfProc_Process -ErrorAction SilentlyContinue) { $t[[int]$p.IDProcess] = [double]$p.IODataBytesPersec }; $t }
            $c0 = Cpu; $d0 = Disques; $t0 = Temps; $e0 = Es; $chrono = [Diagnostics.Stopwatch]::StartNew()
            Start-Sleep -Seconds 2
            $c1 = Cpu; $d1 = Disques; $t1 = Temps; $e1 = Es; $ms = [Math]::Max($chrono.Elapsed.TotalMilliseconds, 1)
            $processeur = $null
            if ($c1.Timestamp_Sys100NS -gt $c0.Timestamp_Sys100NS) {
              $processeur = 100 * (1 - ($c1.PercentProcessorTime - $c0.PercentProcessorTime) / ($c1.Timestamp_Sys100NS - $c0.Timestamp_Sys100NS)) }
            $disque = $null
            foreach ($d in $d1) { $avant = $d0 | Where-Object Name -eq $d.Name
              if ($avant -and $d.Timestamp_Sys100NS -gt $avant.Timestamp_Sys100NS) {
                $o = 100 * (1 - ($d.PercentIdleTime - $avant.PercentIdleTime) / ($d.Timestamp_Sys100NS - $avant.Timestamp_Sys100NS))
                if ($disque -eq $null -or $o -gt $disque) { $disque = $o } } }
            $programmes = foreach ($p in Get-Process) {
              $cpu = 0; if ($t0.ContainsKey($p.Id) -and $t1.ContainsKey($p.Id)) { $cpu = ($t1[$p.Id] - $t0[$p.Id]) / 10000 / $ms / $n * 100 }
              $es = $null; if ($e0.ContainsKey($p.Id) -and $e1.ContainsKey($p.Id)) { $es = ($e1[$p.Id] - $e0[$p.Id]) / ($ms / 1000) }
              @{ nom = $p.ProcessName; processeur = [double]$cpu; memoire = [uint64]$p.WorkingSet64; disque = $es } }
            $os = Get-CimInstance Win32_OperatingSystem
            $memoire = Get-CimInstance Win32_PerfRawData_PerfOS_Memory -ErrorAction SilentlyContinue
            $echange = @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)
            $demarrage = $null; $apres = $null; $illisible = $false; $lents = @()
            try {
              $e = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 1 -ErrorAction Stop
              $x = [xml]$e.ToXml(); $v = @{}; foreach ($d in $x.Event.EventData.Data) { $v[$d.Name] = $d.'#text' }
              $demarrage = [uint64]$v['BootTime']; $apres = [uint64]$v['BootPostBootTime']
              $lents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101, 102, 103, 106; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
                $x = [xml]$_.ToXml(); $v = @{}; foreach ($d in $x.Event.EventData.Data) { $v[$d.Name] = $d.'#text' }
                @{ nom = "$(if ($v['FriendlyName']) { $v['FriendlyName'] } else { $v['Name'] })"; ms = [uint64]$v['DegradationTime'] } })
            } catch [System.UnauthorizedAccessException] { $illisible = $true } catch { if ("$_" -match 'unauthorized|refusé|denied') { $illisible = $true } }
            function Approuve($ruche, $sous, $nom) {
              try { $v = (Get-ItemProperty -Path "$ruche\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sous" -Name $nom -ErrorAction Stop).$nom
                    return -not ($v[0] -band 1) } catch { return $true } }
            $au = foreach ($s in Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue) {
              $ruche = if ("$($s.Location)" -like 'HKLM*') { 'HKLM:' } else { 'HKCU:' }
              $sous = if ("$($s.Location)" -like '*Startup*') { 'StartupFolder' } elseif ("$($s.Location)" -like '*Wow6432Node*') { 'Run32' } else { 'Run' }
              $cle = if ($sous -eq 'StartupFolder') { Split-Path -Leaf "$($s.Command)" } else { "$($s.Name)" }
              if (Approuve $ruche $sous $cle) {
                $c = "$($s.Command)".Trim()
                $prog = if ($c.StartsWith('"')) { ($c -split '"')[1] } else { ($c -split '\s+')[0] }
                @{ nom = "$($s.Caption)"; programme = [IO.Path]::GetFileNameWithoutExtension($prog) } } }
            $lecteur = [IO.DriveInfo]::new($env:SystemDrive)
            [pscustomobject]@{
              processeur = $processeur; fils = $n; memoire = [uint64]($os.TotalVisibleMemorySize * 1024); disponible = [uint64]$memoire.AvailableBytes
              echange = [uint64](($echange | Measure-Object AllocatedBaseSize -Sum).Sum * 1MB)
              echange_utilise = [uint64](($echange | Measure-Object CurrentUsage -Sum).Sum * 1MB)
              disque = $disque; programmes = @($programmes)
              demarrage_ms = $demarrage; apres_ms = $apres; demarrage_illisible = $illisible; lents = @($lents)
              au_demarrage = @($au); allume_s = [uint64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
              libre = [uint64]$lecteur.AvailableFreeSpace; total = [uint64]$lecteur.TotalSize
            } | ConvertTo-Json -Compress -Depth 3"#;
        crate::machine::windows::ps(script)
            .and_then(|json| serde_json::from_str::<LectureWindows>(&json).ok())
            .map_or_else(Instantane::default, instantane_windows)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn noms_et_dates() {
            assert_eq!(nom_du_processus("chrome#3"), "chrome");
            assert_eq!(nom_du_processus("chrome"), "chrome");
            assert_eq!(nom_du_processus("C#"), "C#");
            assert_eq!(nom_du_processus("a#b"), "a#b");
        }

        /// Le relevé direct répond ou laisse la main à PowerShell ; jamais une valeur hors bornes.
        #[test]
        fn releve_reel() {
            if let Some(l) = lecture_directe() {
                assert!(l.fils >= 1);
                assert!(l.processeur.is_none_or(f64::is_finite));
                assert!(
                    l.programmes
                        .iter()
                        .all(|p| p.processeur.is_finite() && !p.nom.contains('#'))
                );
            }
        }
    }
}

// ───────────────────────────── macOS ─────────────────────────────

/// « 1234M », « 12K », « 1.2G », « 512B » (colonne MEM de top, parfois suivie de « + » ou « - ») → octets.
fn taille_top(texte: &str) -> Option<u64> {
    let t = texte.trim_end_matches(['+', '-']);
    let (nombre, unite) = t.split_at(t.len().checked_sub(1)?);
    let n: f64 = nombre.parse().ok()?;
    let facteur: f64 = match unite {
        "B" => 1.0,
        "K" => 1024.0,
        "M" => 1_048_576.0,
        "G" => 1_073_741_824.0,
        _ => return None,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some((n * facteur) as u64)
}

/// `top -l 2 -s 2 -n 20 -o cpu -stats pid,command,cpu,mem` : la seconde mesure seulement (la première compte depuis le
/// lancement de top). Rend (processeur occupé en %, programmes).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[allow(clippy::cast_precision_loss)]
fn lire_top(texte: &str, fils: usize) -> (Option<f64>, Vec<Programme>) {
    let derniere = texte.rsplit("Processes:").next().unwrap_or_default();
    let processeur = derniere.lines().find_map(|l| {
        let repos = l.strip_prefix("CPU usage:")?.split(',').find(|p| p.contains("idle"))?;
        Some(100.0 - repos.trim().split('%').next()?.trim().parse::<f64>().ok()?)
    });
    // Les lignes sous l'en-tête « PID COMMAND %CPU MEM », sans l'en-tête.
    let en_tete = |l: &&str| l.trim_start().starts_with("PID");
    let programmes = derniere
        .lines()
        .skip_while(|l| !en_tete(l))
        .filter(|l| !en_tete(l))
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let [_pid, nom @ .., cpu, mem] = mots.as_slice() else {
                return None;
            };
            let (Ok(cpu), Some(memoire)) = (cpu.parse::<f64>(), taille_top(mem)) else {
                return None;
            };
            Some(Programme {
                nom: nom.join(" "),
                // top compte 100 % par cœur : rapporté à toute la machine.
                processeur: cpu / fils.max(1) as f64,
                memoire,
                disque: None,
            })
        });
    (processeur, reunir(programmes))
}

#[cfg(target_os = "macos")]
mod systeme {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::commande::lancer;

    /// La sortie d'une commande qui a réussi (« sysctl -n hw.memsize »), vide sinon.
    fn sortie(commande: &str) -> String {
        let mut mots = commande.split(' ');
        lancer(Command::new(mots.next().unwrap_or_default()).args(mots), 30)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
            .unwrap_or_default()
    }

    pub fn instantane() -> Instantane {
        use crate::machine::macos::{demarrage, noyau, sysctl_nombre};
        let fils = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        // top reste l'outil qui fait foi pour le processeur de chaque programme : le noyau ne donne le temps de
        // processeur (PROC_PIDTASKINFO) que pour les processus du compte, et ceux de root disparaîtraient.
        let top = sortie("top -l 2 -s 2 -n 20 -o cpu -stats pid,command,cpu,mem");
        let (processeur, programmes) = lire_top(&top, fils);
        // Mémoire, échange et démarrage demandés au noyau (sysctlbyname), les outils en secours tant que l'oracle
        // de macos.yml n'a pas prouvé la lecture native.
        let total: Option<u64> =
            sysctl_nombre("hw.memsize").or_else(|| sortie("sysctl -n hw.memsize").trim().parse().ok());
        // La mémoire libre en %, celle que `memory_pressure` affiche (« System-wide memory free percentage: 63% »).
        let libre_pct: Option<u64> = sysctl_nombre("kern.memorystatus_level")
            .filter(|p| *p <= 100)
            .or_else(|| {
                sortie("memory_pressure")
                    .lines()
                    .find_map(|l| l.strip_prefix("System-wide memory free percentage:"))
                    .and_then(|v| v.trim().trim_end_matches('%').parse().ok())
            });
        let echange = noyau::echange().or_else(|| {
            // « total = 2048.00M  used = 1024.50M  free = 1023.50M  (encrypted) ».
            let echange = sortie("sysctl -n vm.swapusage");
            let valeur = |cle: &str| {
                let mo = echange.split(cle).nth(1)?.split_whitespace().next()?;
                mo.trim_end_matches('M').parse::<f64>().ok()
            };
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            valeur("total = ")
                .zip(valeur("used = "))
                .map(|(t, u)| ((t * 1_048_576.0) as u64, (u * 1_048_576.0) as u64))
        });
        let maintenant = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let allume_depuis = demarrage()
            .or_else(|| {
                sortie("sysctl -n kern.boottime")
                    .split_once("sec = ")
                    .and_then(|(_, r)| r.split(',').next()?.trim().parse::<u64>().ok())
            })
            .and_then(|s| maintenant.checked_sub(s));
        let maison = crate::socle::maison();
        // Agents lancés à l'ouverture de session par des programmes installés (pas ceux d'Apple).
        let dossiers = [maison, PathBuf::from("/")].map(|d| d.join("Library/LaunchAgents"));
        let au_demarrage = dossiers
            .iter()
            .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
            .filter_map(|f| {
                let nom = affichable(f.file_name().to_string_lossy().strip_suffix(".plist")?);
                (!nom.starts_with("com.apple.")).then_some(AuDemarrage { nom, poids: None })
            })
            .collect();
        let donnees = Path::new("/System/Volumes/Data");
        Instantane {
            processeur,
            fils,
            memoire: total.zip(libre_pct).map(|(t, p)| (t, t / 100 * p)),
            echange,
            disque: None,
            programmes,
            demarrage: Err(tr!(
                "macOS ne note pas la durée du démarrage",
                "macOS does not record the startup duration"
            )
            .into()),
            au_demarrage,
            allume_depuis,
            place: crate::socle::volume(if donnees.is_dir() { donnees } else { Path::new("/") }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seuls les services voulus par l'ouverture de session comptent ; un service déclenché au branchement d'une clé
    /// (WantedBy=…mount) ou par une minuterie, non.
    #[test]
    fn services_de_l_ouverture_de_session() {
        assert!(lance_a_l_ouverture(
            "[Unit]\nDescription=x\n[Service]\nExecStart=/usr/bin/x\n[Install]\nWantedBy=default.target\n"
        ));
        assert!(lance_a_l_ouverture(
            "[Install]\nWantedBy = graphical-session.target other.target\n"
        ));
        assert!(!lance_a_l_ouverture(
            "[Service]\nType=oneshot\n[Install]\nWantedBy=run-media-alice-VANGUARD.mount\n"
        ));
        assert!(!lance_a_l_ouverture("[Install]\nWantedBy=timers.target\n"));
        // Ailleurs que dans [Install], la même ligne ne compte pas.
        assert!(!lance_a_l_ouverture(
            "[Unit]\nWantedBy=default.target\n[Install]\nAlso=x.timer\n"
        ));
    }

    #[cfg(target_os = "linux")]
    /// « 1min 2.105s », « 835ms », « +1.186s » (durées écrites par systemd-analyze) → secondes : pour comparer à la
    /// commande.
    fn secondes_systemd(texte: &str) -> Option<f64> {
        let mut total = None;
        for morceau in texte.split_whitespace() {
            let morceau = morceau.trim_start_matches('+');
            let (nombre, unite) = morceau.split_at(morceau.find(|c: char| c.is_ascii_alphabetic())?);
            let n: f64 = nombre.parse().ok()?;
            let facteur = match unite {
                "h" => 3600.0,
                "min" => 60.0,
                "s" => 1.0,
                "ms" => 0.001,
                "us" | "µs" => 0.000_001,
                _ => return None,
            };
            total = Some(total.unwrap_or(0.0) + n * facteur);
        }
        total
    }

    #[cfg(target_os = "linux")]
    /// `systemd-analyze` : « Startup finished in 11.846s (firmware) + … = 40.673s » → (total, noms des étapes).
    fn duree_de_systemd_analyze(texte: &str) -> Option<(f64, Vec<String>)> {
        let ligne = texte.lines().find_map(|l| l.strip_prefix("Startup finished in "))?;
        let (etapes, total) = ligne.rsplit_once(" = ")?;
        let noms = etapes
            .split(" + ")
            .filter_map(|e| Some(e.split_once(" (")?.1.trim_end_matches(')').to_string()))
            .collect();
        Some((secondes_systemd(total.trim())?, noms))
    }

    #[cfg(target_os = "linux")]
    /// `systemd-analyze critical-chain` : (unité, « +durée ») de chaque ligne qui en a une.
    fn chaine_de_systemd_analyze(texte: &str) -> Vec<(String, f64)> {
        let unite = |l: &str| {
            let (nom, reste) = l.trim_start_matches(|c: char| !c.is_alphanumeric()).split_once(' ')?;
            Some((nom.to_string(), secondes_systemd(reste.split_once('+')?.1)?))
        };
        texte.lines().filter_map(unite).collect()
    }

    #[test]
    fn durees_du_demarrage() {
        // Les instants qui donnent « 11.846s (firmware) + 8.083s (loader) + 15.167s (kernel) + 5.575s (userspace) ».
        let mut t = InstantsDemarrage {
            micrologiciel: 19_929_000,
            chargeur: 8_083_000,
            initrd: 0,
            espace_utilisateur: 15_167_000,
            fin: 20_742_000,
            conteneur: false,
        };
        let (total, etapes) = duree_demarrage(&t).unwrap();
        assert!((total - 40.671).abs() < 1e-9);
        assert_eq!(
            etapes,
            "micrologiciel 11,8 s · chargeur 8,1 s · noyau 15,2 s · système 5,6 s"
        );
        // Avec un initrd : le noyau s'arrête à l'initrd, qui dure jusqu'au système.
        t.initrd = 4_000_000;
        assert_eq!(
            duree_demarrage(&t).unwrap().1,
            "micrologiciel 11,8 s · chargeur 8,1 s · noyau 4,0 s · initrd 11,2 s · système 5,6 s"
        );
        // Sans EFI (machine virtuelle, BIOS) : ni micrologiciel ni chargeur, le total part du noyau.
        let sans_efi = InstantsDemarrage {
            espace_utilisateur: 2_000_000,
            fin: 5_000_000,
            ..InstantsDemarrage::default()
        };
        assert_eq!(
            duree_demarrage(&sans_efi).unwrap(),
            (5.0, "noyau 2,0 s · système 3,0 s".to_string())
        );
        // Dans un conteneur, seul le système compte.
        let conteneur = InstantsDemarrage { conteneur: true, ..t };
        assert_eq!(
            duree_demarrage(&conteneur).unwrap(),
            (5.575, "système 5,6 s".to_string())
        );
        // Pas fini : rien.
        assert!(duree_demarrage(&InstantsDemarrage::default()).is_none());
    }

    fn unite(apres: &[&str], debut: u64, active: u64) -> UniteDemarrage {
        UniteDemarrage {
            apres: apres.iter().map(|a| (*a).to_string()).collect(),
            debut,
            active,
            inactive: 0,
        }
    }

    /// Le chemin critique d'un faux démarrage : on suit, à chaque étape, la dépendance devenue active en dernier ;
    /// ni ce qui a démarré après la fin, ni ce qui n'a jamais démarré, ni une unité non chargée.
    #[test]
    fn chemin_critique() {
        let s = 1_000_000;
        let graphe: HashMap<&str, UniteDemarrage> = HashMap::from([
            (
                "default.target",
                unite(
                    &["sddm.service", "locate.service", "absente.service", "x.service"],
                    0,
                    14 * s,
                ),
            ),
            (
                "sddm.service",
                unite(&["docker.service", "rapide.service"], 13 * s, 13 * s + 102_000),
            ),
            // Démarrée après la fin du démarrage : hors du chemin, même longue.
            ("locate.service", unite(&[], 15 * s, 60 * s)),
            // Jamais démarrée.
            ("x.service", unite(&[], 0, 0)),
            (
                "docker.service",
                unite(&["nm-wait-online.service", "basic.target"], 9 * s, 13 * s),
            ),
            ("rapide.service", unite(&["basic.target"], 3 * s, 4 * s)),
            ("nm-wait-online.service", unite(&["basic.target"], 2 * s, 8_810_000)),
            // Une boucle de dépendances ne fait pas tourner en rond.
            ("basic.target", unite(&["default.target"], 2 * s, 2 * s)),
        ]);
        let mut lus = Vec::new();
        let lents = chaine_critique("default.target", 20 * s, |nom| {
            lus.push(nom.to_string());
            Ok(graphe.get(nom).cloned())
        });
        assert_eq!(
            lents,
            [
                ("nm-wait-online.service".to_string(), 6.81),
                ("docker.service".to_string(), 4.0)
            ]
        );
        // Chaque unité n'est demandée qu'une fois au bus.
        let mut uniques = lus.clone();
        uniques.sort();
        uniques.dedup();
        assert_eq!(uniques.len(), lus.len());
        // Une unité relancée depuis (son début est après son activation) : sa durée va jusqu'à sa retombée.
        let relancee = UniteDemarrage {
            inactive: 7 * s,
            ..unite(&[], 6 * s, 3 * s)
        };
        let lents = chaine_critique("r", 10 * s, |nom| {
            Ok(match nom {
                "r" => Some(unite(&["e", "f"], 0, 5 * s)),
                "e" => Some(relancee.clone()),
                "f" => Some(unite(&[], s, 2 * s)),
                _ => None,
            })
        });
        assert_eq!(lents, [("e".to_string(), 1.0)]);
        // La lecture de la dépendance devenue active en dernier échoue (délai, erreur du bus) : la chaîne ne passe pas
        // par une autre branche, elle est vide. Même chose si l'échec vient plus bas dans la chaîne.
        for en_echec in ["docker.service", "nm-wait-online.service"] {
            let lents = chaine_critique("default.target", 20 * s, |nom| {
                if nom == en_echec {
                    return Err("le bus n'a pas répondu à temps".into());
                }
                Ok(graphe.get(nom).cloned())
            });
            assert!(lents.is_empty(), "{en_echec} : {lents:?}");
        }
    }

    /// Sur cet ordinateur, quand `systemd-analyze` répond : la durée lue sur le bus est la sienne, ses étapes aussi,
    /// et les unités lentes de son chemin critique sont celles trouvées ici.
    #[cfg(target_os = "linux")]
    #[test]
    fn demarrage_comme_systemd_analyze() {
        let commande = |args: &[&str]| {
            crate::commande::lancer(std::process::Command::new("systemd-analyze").args(args), 30)
                .filter(|r| r.code == Some(0))
                .map(|r| r.sortie)
        };
        let Some((total, noms)) = commande(&[]).as_deref().and_then(duree_de_systemd_analyze) else {
            return crate::essais::saute("systemd-analyze absent");
        };
        let d = systeme::demarrage().expect("systemd-analyze répond : le bus aussi");
        // systemd-analyze arrondit chaque étape à la milliseconde.
        assert!((d.total - total).abs() < 0.005, "{} contre {total}", d.total);
        assert_eq!(
            d.etapes.split(" · ").count(),
            noms.len(),
            "{} contre {noms:?}",
            d.etapes
        );
        let Some(chaine) = commande(&["critical-chain", "--no-pager"]) else {
            return crate::essais::saute("systemd-analyze critical-chain sans réponse (seconde moitié)");
        };
        let mut attendus: Vec<(String, f64)> = chaine_de_systemd_analyze(&chaine);
        attendus.sort_by(|a, b| b.1.total_cmp(&a.1));
        attendus.dedup_by(|a, b| a.0 == b.0);
        // Chaque unité lente d'un côté est de l'autre, sauf au bord : arrondi autour d'une demi-seconde, ou égalité
        // avec la cinquième.
        let plus_petite = d.lents.last().map_or(0.0, |l| l.1);
        for (nom, s) in &attendus {
            let au_bord = (*s - 0.5).abs() < 0.002 || (d.lents.len() == 5 && *s <= plus_petite + 0.002);
            assert!(
                *s < 0.5 || au_bord || d.lents.iter().any(|l| &l.0 == nom),
                "{nom} {s} absent de {:?}",
                d.lents
            );
        }
        for (nom, s) in &d.lents {
            let theirs = attendus.iter().find(|a| &a.0 == nom);
            assert!(
                theirs.is_some_and(|a| (a.1 - s).abs() < 0.002),
                "{nom} {s} : systemd-analyze dit {theirs:?}"
            );
        }
    }

    /// Un programme choisit son nom, un service ou une entrée de démarrage aussi : piégés, ils arrivent inoffensifs à
    /// l'écran et dans les conseils, sur les trois systèmes.
    #[test]
    fn noms_de_programmes_pieges() {
        let piege = "x\x1b]52;c;eA==\x07\x1b[2K\rfaux\u{202e}";
        let vu = "x�]52;c;eA==��[2K�faux�";
        let p = reunir(
            [Programme {
                nom: piege.into(),
                processeur: 90.0,
                memoire: 1 << 30,
                disque: None,
            }]
            .into_iter(),
        );
        assert_eq!(p[0].nom, vu);
        let service = format!("{piege}.service");
        let lents = chaine_critique("default.target", 20_000_000, |nom| {
            Ok(Some(if nom == "default.target" {
                unite(&[&service], 0, 10_000_000)
            } else {
                unite(&[], 1_000_000, 5_512_000)
            }))
        });
        assert_eq!(lents[0].0, format!("{vu}.service"));
        assert_eq!(
            avec_poids(&p, [(piege.to_string(), "x".to_string())].into_iter())[0].nom,
            vu
        );
        let l: LectureWindows = serde_json::from_str(
            r#"{"demarrage_ms":95000,"lents":[{"nom":"Lent\u001b[2K","ms":12000}],"programmes":[{"nom":"chrome\u001b]0;x\u0007","processeur":30,"memoire":1}]}"#,
        )
        .unwrap();
        let i = instantane_windows(l);
        assert_eq!(i.demarrage.as_ref().unwrap().lents[0].0, "Lent�[2K");
        assert_eq!(i.programmes[0].nom, "chrome�]0;x�");
    }

    #[test]
    fn compteurs_du_noyau() {
        // Un nom avec espaces et parenthèses ne décale pas les champs.
        let stat = "4321 (Isolated Web Co) S 1 4321 4321 0 -1 4194560 1000 0 0 0 250 50 0 0 20 0 30 0 100 2000000000 51200 18446744073709551615";
        assert_eq!(stat_processus(stat), Some((300, 51_200)));
        assert_eq!(stat_processus("1 (a) b) S 0"), None);
        assert_eq!(
            stat_processeur("cpu  615243 4461 358423 22585874 9347 49110 11212 0 21330 0\ncpu0 1 2 3 4\n"),
            Some((1_038_449, 23_633_670))
        );
        let disques = vec!["nvme0n1".to_string(), "sda".to_string()];
        let occupation = occupation_disques(
            " 259       0 nvme0n1 15653 7015 913108 2511 10334 5220 2294634 27465 0 2667 30239 0 0 0 0 129 263\n \
             259       1 nvme0n1p1 1 2 3 4 5 6 7 8 9 10 11 0 0 0 0 0 0\n",
            &disques,
        );
        assert_eq!(occupation.get("nvme0n1"), Some(&2667));
        assert!(!occupation.contains_key("nvme0n1p1"));
        assert_eq!(
            nom_de_processus(Some("/usr/lib/firefox/firefox"), "Isolated Web Co"),
            "firefox"
        );
        assert_eq!(
            nom_de_processus(Some("/usr/bin/python3.13"), "vanguard-outil"),
            "vanguard-outil"
        );
        assert_eq!(nom_de_processus(None, "kworker/u32:2"), "kworker");
    }

    #[test]
    fn entrees_au_demarrage() {
        let actif =
            "[Desktop Entry]\nType=Application\nName=Discord\nExec=env FOO=1 /usr/bin/discord --start-minimized\n";
        assert_eq!(
            entree_autostart(actif, "Hyprland"),
            Some(("Discord".to_string(), "discord".to_string()))
        );
        assert_eq!(entree_autostart(&format!("{actif}Hidden=true\n"), "Hyprland"), None);
        let gnome = "[Desktop Entry]\nName=Clavier\nExec=ibus-daemon\nOnlyShowIn=GNOME;Unity;\n";
        assert_eq!(entree_autostart(gnome, "Hyprland"), None);
        assert!(entree_autostart(gnome, "ubuntu:GNOME").is_some());
        let pas_kde = "[Desktop Entry]\nName=Outil\nExec=outil\nNotShowIn=KDE;\nX-GNOME-Autostart-enabled=true\n";
        assert!(entree_autostart(pas_kde, "GNOME").is_some() && entree_autostart(pas_kde, "KDE").is_none());
        // Une action d'un autre groupe ne remplace pas l'entrée principale.
        let actions =
            "[Desktop Entry]\nName=Appli\nExec=appli\n[Desktop Action Nouvelle]\nExec=appli --nouvelle\nHidden=true\n";
        assert_eq!(
            entree_autostart(actions, ""),
            Some(("Appli".to_string(), "appli".to_string()))
        );
    }

    #[test]
    fn lecture_de_top_sous_macos() {
        let top = "Processes: 1 total\nCPU usage: 50.0% user, 10.0% sys, 40.0% idle\nPID COMMAND %CPU MEM\n1 premier 99.0 1G\n\
                   Processes: 512 total, 3 running\nLoad Avg: 1.23\nCPU usage: 12.5% user, 6.25% sys, 81.25% idle\n\
                   PhysMem: 15G used (2048M wired), 1024M unused.\n\nPID    COMMAND          %CPU MEM\n\
                   123    WindowServer     12.0 512M\n456    Google Chrome He 8.0 1024M+\n789    Google Chrome He 4.0 512M\n";
        let (processeur, programmes) = lire_top(top, 4);
        assert_eq!(processeur, Some(18.75));
        let chrome = programmes.iter().find(|p| p.nom == "Google Chrome He").unwrap();
        assert!((chrome.processeur - 3.0).abs() < 1e-9 && chrome.memoire == 1536 << 20);
        assert_eq!(taille_top("12K"), Some(12 * 1024));
        assert_eq!(taille_top("x"), None);
    }

    #[test]
    fn lecture_windows() {
        let l: LectureWindows = serde_json::from_str(
            r#"{"processeur":92.5,"fils":8,"memoire":17179869184,"disponible":1073741824,"echange":4294967296,"echange_utilise":2147483648,
                "disque":12.0,"programmes":[{"nom":"chrome","processeur":30,"memoire":1073741824,"disque":1048576},
                {"nom":"chrome","processeur":10,"memoire":536870912,"disque":null},{"nom":"MsMpEng","processeur":60,"memoire":268435456}],
                "demarrage_ms":95000,"apres_ms":40000,"lents":[{"nom":"Programme d'essai","ms":12000},{"nom":"Programme d'essai","ms":9000}],
                "au_demarrage":[{"nom":"Discord","programme":"Discord"},{"nom":"Chrome","programme":"chrome"}],
                "allume_s":1728000,"libre":10737418240,"total":256060514304}"#,
        )
        .unwrap();
        let i = instantane_windows(l);
        let chrome = i.programmes.iter().find(|p| p.nom == "chrome").unwrap();
        assert!((chrome.processeur - 40.0).abs() < 1e-9);
        assert_eq!(chrome.memoire, 1_610_612_736);
        let d = i.demarrage.as_ref().unwrap();
        assert!((d.total - 95.0).abs() < 1e-9 && d.lents.len() == 1);
        assert_eq!(i.au_demarrage[1].poids, Some(1_610_612_736));
        // L'antivirus qui travaille est nommé comme passager ; mémoire presque pleine ; 20 jours sans redémarrer.
        let c = conseils(&i);
        assert!(c[0].texte.contains("l'antivirus de Windows"), "{}", c[0].texte);
        assert!(c.iter().any(|k| k.texte.contains("Mémoire presque pleine")));
        assert!(c.iter().any(|k| k.outil == Some(Outil::MisesAJour)));
        assert!(c.iter().any(|k| k.texte.contains("Démarrage long")));
        let illisible: LectureWindows = serde_json::from_str(r#"{"demarrage_illisible":true}"#).unwrap();
        assert!(
            instantane_windows(illisible)
                .demarrage
                .unwrap_err()
                .contains("administrateur")
        );
    }

    #[test]
    fn rien_a_signaler() {
        let i = Instantane {
            processeur: Some(12.0),
            fils: 8,
            memoire: Some((16 << 30, 9 << 30)),
            disque: Some(3.0),
            place: Some((200 << 30, 500 << 30)),
            demarrage: Ok(Demarrage {
                total: 20.0,
                ..Demarrage::default()
            }),
            allume_depuis: Some(3600),
            ..Instantane::default()
        };
        assert!(conseils(&i).is_empty());
        assert!(mesure_complete(&i));
        // Rien de mesuré : aucun conseil, mais jamais « rien ne force ».
        let vide = Instantane::default();
        assert!(conseils(&vide).is_empty() && !mesure_complete(&vide));
        assert!(!mesure_complete(&Instantane {
            processeur: Some(5.0),
            ..Instantane::default()
        }));
        assert_eq!(secondes_lisibles(75.4), "1 min 15 s");
        assert_eq!(secondes_lisibles(5.04), "5,0 s");
    }

    /// Les services ajoutés par l'utilisateur et activés pour l'ouverture de session : ni un service activé pour
    /// autre chose (une minuterie), ni un désactivé, ni un lien (dotfiles), ni ce qui n'est pas un service.
    #[cfg(target_os = "linux")]
    #[test]
    fn services_ajoutes_et_actives() {
        let d = std::env::temp_dir().join(format!("vanguard-lenteur-services-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let session = "[Service]\nExecStart=/usr/bin/essai\n[Install]\nWantedBy=default.target\n";
        for (nom, texte) in [
            ("synchro.service", session),
            ("agenda.service", session),
            ("eteint.service", session),
            ("minute.service", "[Install]\nWantedBy=timers.target\n"),
            ("synchro.timer", session),
        ] {
            std::fs::write(d.join(nom), texte).unwrap();
        }
        std::os::unix::fs::symlink(d.join("agenda.service"), d.join("lien.service")).unwrap();
        let activee = |u: &str| u != "eteint.service";
        let vus = systeme::services_actives(&d, activee);
        // Le lien vers un fichier ordinaire est un fichier pour is_file : il compte, comme pour systemctl.
        assert_eq!(vus, ["agenda.service", "lien.service", "synchro.service"]);
        assert_eq!(
            systeme::services_actives(&d.join("absent"), activee),
            Vec::<String>::new()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sur cet ordinateur, les services de ~/.config/systemd/user activés pour la session sont ceux que dit
    /// `systemctl --user list-unit-files`, quand il répond.
    #[cfg(target_os = "linux")]
    #[test]
    fn services_comme_systemctl() {
        let Some(r) = crate::commande::lancer(
            std::process::Command::new("systemctl").args([
                "--user",
                "list-unit-files",
                "--type=service",
                "--state=enabled",
                "--no-legend",
                "--no-pager",
            ]),
            20,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("systemctl absent");
        };
        let maison = crate::socle::maison();
        let config =
            std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), std::path::PathBuf::from);
        let dossier = config.join("systemd/user");
        let mut attendus: Vec<String> = r
            .sortie
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|u| {
                let f = dossier.join(u);
                f.is_file() && lance_a_l_ouverture(&std::fs::read_to_string(&f).unwrap_or_default())
            })
            .map(str::to_string)
            .collect();
        attendus.sort();
        let activee = |u: &str| crate::machine::linux::natif::unite_activee(u, true) == Some(true);
        assert_eq!(systeme::services_actives(&dossier, activee), attendus);
    }
}
