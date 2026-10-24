//! Lecture du journal de systemd (les fichiers `*.journal` de /var/log/journal et /run/log/journal), en lecture
//! seule, sans `journalctl`. Le format est celui de systemd (« Journal File Format », journal-def.h) : un en-tête, puis
//! des objets ; un champ (« PRIORITY=3 ») est un objet DATA rangé dans une table de hachage, et chaque DATA tient la
//! liste des entrées qui le portent. On cherche donc comme journalctl : le DATA voulu par son empreinte, puis ses
//! entrées, sans parcourir tout le fichier (les journaux d'un ordinateur pèsent souvent plusieurs Go).
//!
//! Les champs longs sont compressés : zstd (le décodeur de `super::zstd`), LZ4 (décodé ici, quelques lignes) ; xz,
//! l'ancien défaut, n'est pas lu. Tout ce qui ne se lit pas (droits, format plus récent, xz, fichier abîmé) rend
//! `None` : l'appelant garde journalctl en secours, et rien n'est compté comme sain sans avoir été lu.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// « LPKSHHRH » : la signature de l'en-tête.
const SIGNATURE: &[u8; 8] = b"LPKSHHRH";

// Drapeaux incompatibles de l'en-tête : un lecteur qui ne connaît pas l'un d'eux doit renoncer.
const XZ: u32 = 1;
const LZ4: u32 = 2;
const HACHAGE_A_CLE: u32 = 4;
const ZSTD: u32 = 8;
const COMPACT: u32 = 16;
const CONNUS: u32 = XZ | LZ4 | HACHAGE_A_CLE | ZSTD | COMPACT;

// Les sortes d'objets lues ici.
const DATA: u8 = 1;
const ENTREE: u8 = 3;
const TABLE_DATA: u8 = 4;
const TABLEAU: u8 = 6;

/// Au-delà, un champ est sauté (un vidage mémoire rangé dans le journal), plutôt que de remplir la mémoire.
const CHAMP_MAX: usize = 16 << 20;

/// Une entrée du journal : l'heure (microsecondes depuis 1970) et les champs demandés, dans l'ordre de l'entrée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entree {
    pub(crate) quand: u64,
    pub(crate) champs: Vec<(String, String)>,
}

impl Entree {
    /// La valeur d'un champ, s'il est là.
    pub(crate) fn champ(&self, nom: &str) -> Option<&str> {
        self.champs.iter().find(|(n, _)| n == nom).map(|(_, v)| v.as_str())
    }
}

/// Ce qu'on cherche : les entrées qui portent l'un des champs `un_de` (« _COMM=sshd »), depuis une heure ou d'un
/// démarrage, avec les seuls champs `champs`.
pub(crate) struct Requete<'a> {
    pub(crate) un_de: &'a [&'a str],
    pub(crate) depuis: Option<u64>,
    pub(crate) demarrage: Option<[u8; 16]>,
    pub(crate) champs: &'a [&'a str],
}

/// Les erreurs du démarrage en cours (priorité 0 à 3, ce que montre `journalctl -b -p err`), avec le nom sous lequel
/// chaque programme écrit. `None` : le journal ne se lit pas ici, journalctl prendra le relais.
pub(crate) fn erreurs_du_demarrage() -> Option<Vec<Entree>> {
    erreurs_avec(&["SYSLOG_IDENTIFIER", "_COMM"])
}

fn erreurs_avec(champs: &[&str]) -> Option<Vec<Entree>> {
    let demarrage = id_hexa(std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?.trim())?;
    // Pas de borne d'heure : au début du démarrage, l'horloge peut être fausse de plusieurs heures (une horloge
    // matérielle à l'heure locale, sous Windows en double démarrage), et journalctl -b garde ces entrées. Les
    // champs se trouvent par la table de hachage : lire aussi les fichiers d'avant ne coûte presque rien.
    chercher_dans_le_systeme(
        &Requete {
            un_de: &["PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3"],
            depuis: None,
            demarrage: Some(demarrage),
            champs,
        },
        false,
    )
}

/// Les messages que root a écrits sous le nom des programmes `programmes` (« _COMM=… ») les `secondes` dernières,
/// dans l'ordre du journal, comme `journalctl _COMM=a _UID=0 + _COMM=b _UID=0 --since -Ns -o cat`, dans les
/// journaux du système seulement. `_COMM` n'est que le nom du processus, que chacun choisit : un programme sans
/// droits nommé « sshd » écrivait de fausses attaques SSH (et un faux « mot de passe deviné ») dans son propre
/// journal, lu avec les autres. `_UID` est posé par journald lui-même, et sshd écrit ces lignes en root. `None` : le
/// journal ne se lit pas ici.
pub(crate) fn messages_de(programmes: &[&str], secondes: u64) -> Option<Vec<String>> {
    let un_de: Vec<String> = programmes.iter().map(|p| format!("_COMM={p}")).collect();
    let un_de: Vec<&str> = un_de.iter().map(String::as_str).collect();
    let depuis = maintenant().saturating_sub(secondes.saturating_mul(1_000_000));
    let entrees = chercher_dans_le_systeme(
        &Requete {
            un_de: &un_de,
            depuis: Some(depuis),
            demarrage: None,
            champs: &["MESSAGE", "_UID"],
        },
        true,
    )?;
    Some(de_root(entrees))
}

/// Les messages des entrées écrites par root (`_UID=0`, champ de confiance posé par journald) ; les autres, écrits
/// par n'importe quel compte sous le même nom de programme, sont écartés.
fn de_root(entrees: Vec<Entree>) -> Vec<String> {
    entrees
        .into_iter()
        .filter(|e| e.champ("_UID") == Some("0"))
        .filter_map(|e| e.champ("MESSAGE").map(str::to_string))
        .collect()
}

/// Les journaux du système seulement (« system.journal » et ses archives), sans ceux des comptes (« user-1000 ») :
/// ce qu'y écrit un programme sans droits n'a rien à faire dans ce que dit sshd.
fn du_systeme_seul(mut fichiers: Vec<PathBuf>) -> Vec<PathBuf> {
    fichiers.retain(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("system")));
    fichiers
}

fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Un identifiant de 128 bits écrit en hexadécimal, avec ou sans tirets (boot_id, machine-id).
fn id_hexa(texte: &str) -> Option<[u8; 16]> {
    let chiffres: Vec<u8> = texte.bytes().filter(|&c| c != b'-').collect();
    if chiffres.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (k, o) in id.iter_mut().enumerate() {
        *o = u8::from_str_radix(std::str::from_utf8(&chiffres[2 * k..2 * k + 2]).ok()?, 16).ok()?;
    }
    Some(id)
}

/// Les fichiers que lit `journalctl` sans option : ceux de cette machine, persistants et volatils, archivés compris
/// (`*.journal~` : un fichier mis de côté après un arrêt brutal). `None` si aucun journal du système n'est là, ou si
/// l'un d'eux ne s'ouvre pas : hors des groupes adm, wheel et systemd-journal, on ne verrait que son propre journal.
fn fichiers_du_systeme() -> Option<Vec<PathBuf>> {
    let machine = std::fs::read_to_string("/etc/machine-id").ok()?;
    fichiers_dans(
        &[Path::new("/var/log/journal"), Path::new("/run/log/journal")],
        machine.trim(),
    )
}

/// Les journaux de `machine` sous chaque racine. Un dossier absent (pas de journal persistant, ou pas encore de
/// volatil) ne compte pas ; un dossier là mais qui ne se liste pas (droits) rend `None` : lire le seul journal
/// volatil ferait dire « aucune erreur » d'une lecture partielle.
fn fichiers_dans(racines: &[&Path], machine: &str) -> Option<Vec<PathBuf>> {
    id_hexa(machine)?;
    let mut fichiers = Vec::new();
    for racine in racines {
        let dossier = match std::fs::read_dir(racine.join(machine)) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for e in dossier {
            let e = e.ok()?;
            let nom = e.file_name();
            let nom = nom.to_string_lossy();
            if nom.ends_with(".journal") || nom.ends_with(".journal~") {
                fichiers.push(e.path());
            }
        }
    }
    let systeme = |p: &PathBuf| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("system"));
    if !fichiers.iter().any(systeme) {
        return None;
    }
    fichiers.sort();
    Some(fichiers)
}

/// La requête sur les journaux du système. journald archive un fichier en le renommant (« system.journal » devient
/// « system@….journal ») : une rotation pendant la lecture ferait manquer l'archive. La liste est donc relue après ;
/// si elle a changé, la lecture recommence, et après trois essais, journalctl prend le relais.
/// `systeme_seul` : sans les journaux des comptes (`du_systeme_seul`).
fn chercher_dans_le_systeme(requete: &Requete, systeme_seul: bool) -> Option<Vec<Entree>> {
    let liste = || fichiers_du_systeme().map(|f| if systeme_seul { du_systeme_seul(f) } else { f });
    for _ in 0..3 {
        let fichiers = liste()?;
        let entrees = chercher(&fichiers, requete)?;
        if liste()? == fichiers {
            return Some(entrees);
        }
    }
    None
}

/// Les entrées de `fichiers` qui répondent à la requête, de la plus ancienne à la plus récente. Une entrée recopiée
/// dans deux fichiers (même suite de numéros, même numéro) ne compte qu'une fois, comme dans journalctl.
pub(crate) fn chercher(fichiers: &[PathBuf], requete: &Requete) -> Option<Vec<Entree>> {
    let mut vues: HashSet<([u8; 16], u64)> = HashSet::new();
    let mut toutes: Vec<(u64, u64, Entree)> = Vec::new();
    for chemin in fichiers {
        let fichier = match std::fs::File::open(chemin) {
            Ok(f) => f,
            // Archivé puis effacé entre la liste et l'ouverture (journald fait de la place) : plus rien à lire.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        let Ouvert::Pret(mut journal) = Journal::ouvrir(fichier)? else {
            continue;
        };
        for (numero, entree) in journal.chercher(requete)? {
            if vues.insert((journal.suite, numero)) {
                toutes.push((entree.quand, numero, entree));
            }
        }
    }
    toutes.sort_by_key(|(quand, numero, _)| (*quand, *numero));
    Some(toutes.into_iter().map(|(_, _, e)| e).collect())
}

/// Les champs qu'écrit `journalctl -o short-iso` : l'heure de la source, l'hôte, l'identifiant, le processus, le
/// message.
pub(crate) const CHAMPS_COURTS: &[&str] = &[
    "_SOURCE_REALTIME_TIMESTAMP",
    "_HOSTNAME",
    "SYSLOG_IDENTIFIER",
    "_COMM",
    "_PID",
    "SYSLOG_PID",
    "MESSAGE",
];

/// Une entrée écrite comme `journalctl -o short-iso` l'écrit (logs-show.c) : « 2026-10-24T06:36:34-04:00 hôte
/// identifiant[pid]: message ». L'heure est celle de la source (_SOURCE_REALTIME_TIMESTAMP), sinon celle de
/// l'entrée ; l'identifiant SYSLOG_IDENTIFIER, sinon _COMM ; le processus _PID, sinon SYSLOG_PID ; un message sur
/// plusieurs lignes continue sous le premier, décalé. `None` : une entrée sans MESSAGE, que journalctl ne montre pas
/// dans ce format. Les caractères de contrôle restent : l'appelant les neutralise.
pub(crate) fn ligne_courte(e: &Entree) -> Option<String> {
    let message = e.champ("MESSAGE")?;
    let quand = e
        .champ("_SOURCE_REALTIME_TIMESTAMP")
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(e.quand);
    let date = chrono::DateTime::from_timestamp(i64::try_from(quand / 1_000_000).ok()?, 0)?
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let mut debut = date;
    if let Some(h) = e.champ("_HOSTNAME") {
        debut.push(' ');
        debut.push_str(h);
    }
    debut.push(' ');
    debut.push_str(
        e.champ("SYSLOG_IDENTIFIER")
            .or_else(|| e.champ("_COMM"))
            .unwrap_or("unknown"),
    );
    if let Some(pid) = e.champ("_PID").or_else(|| e.champ("SYSLOG_PID")) {
        debut.push('[');
        debut.push_str(pid);
        debut.push(']');
    }
    debut.push_str(": ");
    let decalage = " ".repeat(debut.chars().count());
    let message = sans_ansi(message);
    let mut lignes = message.trim_end_matches('\n').split('\n');
    let mut texte = debut;
    texte.push_str(lignes.next().unwrap_or_default());
    for l in lignes {
        texte.push('\n');
        texte.push_str(&decalage);
        texte.push_str(l);
    }
    Some(texte)
}

/// Un message sans ses séquences de terminal (couleurs « ESC [ … m », titres « ESC ] … BEL »), que journalctl retire
/// à l'affichage sans couleurs.
fn sans_ansi(t: &str) -> String {
    let mut sortie = String::with_capacity(t.len());
    let mut c = t.chars().peekable();
    while let Some(x) = c.next() {
        if x != '\x1b' {
            sortie.push(x);
            continue;
        }
        match c.peek() {
            Some('[') => {
                c.next();
                // Paramètres et intermédiaires, puis l'octet final (de @ à ~).
                for y in c.by_ref() {
                    if ('@'..='~').contains(&y) {
                        break;
                    }
                }
            }
            Some(']') => {
                c.next();
                while let Some(y) = c.next() {
                    if y == '\x07' || (y == '\x1b' && c.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => sortie.push(x),
        }
    }
    sortie
}

/// Les entrées des journaux que `journalctl` lit sans option, qui portent l'un des champs `un_de`, depuis
/// `depuis` (µs depuis 1970), avec les champs `champs`, de la plus ancienne à la plus récente. `None` : le journal ne
/// se lit pas ici (droits, format, xz) : journalctl prendra le relais.
pub(crate) fn entrees(un_de: &[&str], depuis: u64, champs: &[&str]) -> Option<Vec<Entree>> {
    chercher_dans_le_systeme(
        &Requete {
            un_de,
            depuis: Some(depuis),
            demarrage: None,
            champs,
        },
        false,
    )
}

/// La plus ancienne entrée des journaux (µs depuis 1970), comme la première ligne de `journalctl --lines=+1` :
/// jusqu'où le journal remonte. `None` : illisible ici, ou aucune entrée.
pub(crate) fn plus_ancienne() -> Option<u64> {
    let mut min: Option<u64> = None;
    for chemin in fichiers_du_systeme()? {
        let fichier = match std::fs::File::open(&chemin) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        if let Ouvert::Pret(j) = Journal::ouvrir(fichier)?
            && j.premiere_heure != 0
        {
            min = Some(min.map_or(j.premiere_heure, |m| m.min(j.premiere_heure)));
        }
    }
    min
}

/// Ce que `tout_le_journal` a lu.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Parcours {
    /// Entrées écrites.
    pub(crate) entrees: usize,
    /// La lecture s'est arrêtée à la demande de l'appelant (sa borne) alors qu'il restait des entrées.
    pub(crate) coupe: bool,
}

/// Un fichier parcouru à l'envers : ses tableaux d'entrées restant à lire, et les cases du tableau en cours.
struct Recul {
    journal: Journal,
    tableaux: Vec<u64>,
    cases: Vec<u64>,
}

impl Recul {
    /// La position de l'entrée précédente ; `Ok(None)` : le fichier est fini ; `Err` : un tableau illisible.
    fn precedente(&mut self) -> Result<Option<u64>, ()> {
        loop {
            if let Some(e) = self.cases.pop() {
                return Ok(Some(e));
            }
            let Some(t) = self.tableaux.pop() else {
                return Ok(None);
            };
            self.cases = self.journal.cases_du_tableau(t).ok_or(())?;
        }
    }
}

/// Tout le journal depuis `depuis` (µs depuis 1970), du plus récent au plus ancien, comme `journalctl --since …
/// --reverse -o short-iso` : les fichiers que journalctl lit (`fichiers_du_systeme`), chacun parcouru à l'envers
/// par ses tableaux d'entrées, fusionnés par l'heure ; une entrée recopiée dans deux fichiers ne compte qu'une fois.
/// Chaque ligne passe à `ecrire`, qui rend faux pour arrêter (sa borne atteinte). `None` : le journal ne se lit pas
/// ici en entier (droits, format, xz, fichier abîmé) : journalctl prendra le relais, jamais une lecture partielle
/// prise pour complète.
pub(crate) fn tout_le_journal(depuis: u64, mut ecrire: impl FnMut(&str) -> bool) -> Option<Parcours> {
    let fichiers = fichiers_du_systeme()?;
    let mut reculs: Vec<Recul> = Vec::new();
    for chemin in &fichiers {
        let fichier = match std::fs::File::open(chemin) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        let Ouvert::Pret(mut journal) = Journal::ouvrir(fichier)? else {
            continue;
        };
        if journal.derniere_heure != 0 && journal.derniere_heure < depuis {
            continue;
        }
        let tableaux = journal.tableaux_des_entrees()?;
        reculs.push(Recul {
            journal,
            tableaux,
            cases: Vec::new(),
        });
    }
    parcourir(reculs, depuis, &mut ecrire)
}

fn parcourir(mut reculs: Vec<Recul>, depuis: u64, ecrire: &mut impl FnMut(&str) -> bool) -> Option<Parcours> {
    use std::collections::BinaryHeap;
    // (heure, numéro dans le fichier, fichier, position) de l'entrée la plus récente de chaque fichier.
    let mut tas: BinaryHeap<(u64, u64, usize, u64)> = BinaryHeap::new();
    let avancer = |reculs: &mut Vec<Recul>, i: usize, tas: &mut BinaryHeap<(u64, u64, usize, u64)>| -> Option<()> {
        if let Some(pos) = reculs[i].precedente().ok()? {
            let (numero, quand) = reculs[i].journal.en_tete(pos)?;
            tas.push((quand, numero, i, pos));
        }
        Some(())
    };
    for i in 0..reculs.len() {
        avancer(&mut reculs, i, &mut tas)?;
    }
    let mut vues: HashSet<([u8; 16], u64)> = HashSet::new();
    let mut caches: Vec<HashMap<u64, Champ>> = (0..reculs.len()).map(|_| HashMap::new()).collect();
    let mut parcours = Parcours::default();
    while let Some((quand, numero, i, pos)) = tas.pop() {
        if quand < depuis {
            // Le plus récent de ce fichier est plus ancien que la borne : il n'a plus rien à donner.
            continue;
        }
        if vues.insert((reculs[i].journal.suite, numero)) {
            let e = reculs[i].journal.entree(pos, CHAMPS_COURTS, &mut caches[i])?;
            if let Some(l) = ligne_courte(&e) {
                if !ecrire(&l) {
                    parcours.coupe = true;
                    return Some(parcours);
                }
                parcours.entrees += 1;
            }
        }
        avancer(&mut reculs, i, &mut tas)?;
    }
    Some(parcours)
}

/// Un fichier ouvert, lu par morceaux de 64 Kio gardés en mémoire (les objets voisins se lisent d'un coup).
///
/// Un budget borne ce que lit une requête : un fichier abîmé ou hostile (des objets qui se chevauchent, une chaîne
/// qui revient sur elle-même) pourrait sinon faire relire ses octets un nombre de fois qui croît avec sa taille.
/// Une requête sur un vrai journal lit chaque objet utile une ou deux fois : seize fois le fichier laisse de la
/// marge, et au-delà, la lecture renonce (`None`) et journalctl prend le relais.
struct Lecteur {
    fichier: std::fs::File,
    longueur: u64,
    morceaux: HashMap<u64, Vec<u8>>,
    lus: u64,
    budget: u64,
}

const MORCEAU: u64 = 64 << 10;

impl Lecteur {
    fn new(fichier: std::fs::File, longueur: u64) -> Self {
        Lecteur {
            fichier,
            longueur,
            morceaux: HashMap::new(),
            lus: 0,
            budget: longueur.saturating_mul(16).saturating_add(256 << 20),
        }
    }

    /// `n` octets de plus lus (ou décompressés) ; `None` quand le budget est épuisé.
    fn compter(&mut self, n: usize) -> Option<()> {
        self.lus = self.lus.saturating_add(n as u64);
        (self.lus <= self.budget).then_some(())
    }

    /// `n` octets à `pos`, ou `None` au-delà de la fin du fichier.
    fn lire(&mut self, pos: u64, n: usize) -> Option<Vec<u8>> {
        let fin = pos.checked_add(n as u64)?;
        if fin > self.longueur {
            return None;
        }
        self.compter(n)?;
        let mut sortie = Vec::with_capacity(n);
        let mut p = pos;
        while p < fin {
            let k = p / MORCEAU;
            if !self.morceaux.contains_key(&k) {
                // 32 Mio au plus en mémoire : au-delà, on repart de zéro plutôt que de tout garder.
                if self.morceaux.len() >= 512 {
                    self.morceaux.clear();
                }
                let taille = usize::try_from(MORCEAU.min(self.longueur - k * MORCEAU)).ok()?;
                let mut tampon = vec![0u8; taille];
                self.fichier.read_exact_at(&mut tampon, k * MORCEAU).ok()?;
                self.morceaux.insert(k, tampon);
            }
            let morceau = &self.morceaux[&k];
            let debut = usize::try_from(p - k * MORCEAU).ok()?;
            let jusqua = usize::try_from(fin.min((k + 1) * MORCEAU) - k * MORCEAU).ok()?;
            sortie.extend_from_slice(morceau.get(debut..jusqua)?);
            p = (k + 1) * MORCEAU;
        }
        Some(sortie)
    }
}

fn u64_a(o: &[u8], pos: usize) -> u64 {
    o.get(pos..pos + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn u32_a(o: &[u8], pos: usize) -> u32 {
    o.get(pos..pos + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// Un objet DATA lu : son empreinte, la taille de ce qu'il range (compressé ou non), le champ décompressé, et la
/// liste de ses entrées.
struct Donnee {
    empreinte: u64,
    longueur: u64,
    suivant_meme_case: u64,
    premiere_entree: u64,
    tableau: u64,
    nombre: u64,
    charge: Option<Vec<u8>>,
}

/// Un fichier qui s'ouvre : vide (créé, pas encore écrit), ou prêt à lire.
enum Ouvert {
    Vide,
    Pret(Journal),
}

/// Un champ d'une entrée : l'un de ceux qu'on veut (nom, valeur), ou un autre.
#[derive(Clone)]
enum Champ {
    Voulu(String, String),
    Autre,
}

/// Les drapeaux de compression d'un objet : xz, LZ4, zstd.
const COMPRESSE: u8 = 7;

/// Un fichier du journal, en-tête lu.
struct Journal {
    lecteur: Lecteur,
    drapeaux: u32,
    cle: [u8; 16],
    suite: [u8; 16],
    entete: u64,
    table: u64,
    cases: u64,
    derniere_heure: u64,
    /// La plus ancienne entrée du fichier (µs depuis 1970 ; 0 s'il n'en a pas).
    premiere_heure: u64,
    /// Le premier tableau de toutes les entrées du fichier (chaîné, dans l'ordre des numéros).
    tableau_entrees: u64,
}

impl Journal {
    /// L'en-tête lu ; `None` pour un format inconnu ou abîmé.
    fn ouvrir(fichier: std::fs::File) -> Option<Ouvert> {
        let longueur = fichier.metadata().ok()?.len();
        let mut lecteur = Lecteur::new(fichier, longueur);
        let Some(h) = lecteur.lire(0, 208) else {
            return Some(Ouvert::Vide);
        };
        if &h[..8] != SIGNATURE {
            return None;
        }
        let drapeaux = u32_a(&h, 12);
        if drapeaux & !CONNUS != 0 {
            return None;
        }
        let entete = u64_a(&h, 88);
        let table = u64_a(&h, 104);
        let cases = u64_a(&h, 112) / 16;
        if u64_a(&h, 152) == 0 {
            return Some(Ouvert::Vide);
        }
        if entete < 208 || cases == 0 || table < entete {
            return None;
        }
        let mut cle = [0u8; 16];
        cle.copy_from_slice(&h[24..40]);
        let mut suite = [0u8; 16];
        suite.copy_from_slice(&h[72..88]);
        let mut j = Journal {
            lecteur,
            drapeaux,
            cle,
            suite,
            entete,
            table,
            cases,
            derniere_heure: u64_a(&h, 192),
            premiere_heure: u64_a(&h, 184),
            tableau_entrees: u64_a(&h, 176),
        };
        // La table de hachage est bien là où l'en-tête la place (son objet la précède de 16 octets).
        j.objet(table.checked_sub(16)?, TABLE_DATA, 16)?;
        j.verifier_empreintes()?;
        Some(Ouvert::Pret(j))
    }

    fn compact(&self) -> bool {
        self.drapeaux & COMPACT != 0
    }

    /// L'empreinte d'un champ, comme journald la calcule.
    fn empreinte(&self, octets: &[u8]) -> u64 {
        if self.drapeaux & HACHAGE_A_CLE != 0 {
            siphash24(octets, &self.cle)
        } else {
            jenkins64(octets)
        }
    }

    /// Une empreinte mal calculée ne trouverait aucun champ, et « aucune erreur » serait faux : on la vérifie d'abord
    /// sur le premier DATA de la table (sa case, son empreinte rangée).
    fn verifier_empreintes(&mut self) -> Option<()> {
        for case in 0..self.cases.min(1 << 20) {
            let tete = u64_a(&self.lecteur.lire(self.table + case * 16, 8)?, 0);
            if tete == 0 {
                continue;
            }
            let d = self.donnee(tete, Some(CHAMP_MAX))?;
            // Trop long pour être lu (un vidage mémoire) : la case suivante fera l'essai.
            let Some(charge) = d.charge else {
                continue;
            };
            return (self.empreinte(&charge) == d.empreinte && d.empreinte % self.cases == case).then_some(());
        }
        None
    }

    /// L'en-tête d'un objet : sa sorte, ses drapeaux et sa taille, vérifiés contre le fichier.
    fn objet(&mut self, pos: u64, sorte: u8, minimum: u64) -> Option<(u8, u64)> {
        if pos < self.entete || !pos.is_multiple_of(8) {
            return None;
        }
        let o = self.lecteur.lire(pos, 16)?;
        let taille = u64_a(&o, 8);
        if o[0] != sorte || taille < minimum || pos.checked_add(taille)? > self.lecteur.longueur {
            return None;
        }
        Some((o[1], taille))
    }

    /// Un objet DATA ; avec `charge` (`Some(max)`), le champ lui-même, décompressé, s'il tient en `max` octets.
    /// `charge` vaut `None` pour un champ trop long (un vidage mémoire) ou qui ne se décompresse pas (abîmé) : à
    /// l'appelant de dire si ce champ-là pouvait compter.
    fn donnee(&mut self, pos: u64, charge: Option<usize>) -> Option<Donnee> {
        let debut = if self.compact() { 72 } else { 64 };
        let (drapeaux, taille) = self.objet(pos, DATA, debut)?;
        let o = self.lecteur.lire(pos, usize::try_from(debut).ok()?)?;
        let longueur = usize::try_from(taille - debut).ok()?;
        let compresse = drapeaux & COMPRESSE != 0;
        let charge = match charge.map(|m| m.min(CHAMP_MAX)) {
            Some(max) if longueur <= CHAMP_MAX && (compresse || longueur <= max) => {
                let brut = self.lecteur.lire(pos + debut, longueur)?;
                let lu = match drapeaux & COMPRESSE {
                    0 => Some(brut),
                    4 => super::zstd::decompresser(&brut, max),
                    2 => delz4(&brut, max),
                    // xz : rien ici ne le lit ; journalctl le fera.
                    _ => return None,
                };
                // Ce qui est décompressé compte dans le budget de lecture, comme ce qui est lu.
                if let Some(l) = &lu {
                    self.lecteur.compter(l.len())?;
                }
                lu
            }
            _ => None,
        };
        Some(Donnee {
            empreinte: u64_a(&o, 16),
            longueur: taille - debut,
            suivant_meme_case: u64_a(&o, 24),
            premiere_entree: u64_a(&o, 40),
            tableau: u64_a(&o, 48),
            nombre: u64_a(&o, 56),
            charge,
        })
    }

    /// Les entrées qui portent un champ exact (« PRIORITY=3 ») : son DATA trouvé par la table de hachage, puis la
    /// liste qu'il tient. Aucune s'il n'est pas dans ce fichier.
    fn entrees_du_champ(&mut self, champ: &[u8]) -> Option<Vec<u64>> {
        let h = self.empreinte(champ);
        let mut pos = u64_a(&self.lecteur.lire(self.table + (h % self.cases) * 16, 8)?, 0);
        // Une chaîne qui revient sur un maillon déjà vu (fichier abîmé ou hostile) rend None tout de suite ; et jamais
        // plus de maillons que d'objets possibles. Un maillon au-delà de la taille lue à l'ouverture a été écrit
        // depuis (le fichier en cours) : la chaîne s'arrête là.
        let mut vus: HashSet<u64> = HashSet::new();
        let mut pas = self.lecteur.longueur / 64;
        while pos != 0 && pos < self.lecteur.longueur {
            pas = pas.checked_sub(1)?;
            if !vus.insert(pos) {
                return None;
            }
            let entete = self.donnee(pos, None)?;
            // journald ne garde la forme compressée d'un champ que plus courte que lui (journal-file.c, compress_blob
            // dans size - 1 octets) : un DATA qui range plus que le champ n'est pas celui qu'on cherche, et sa charge
            // (jusqu'à 16 Mio) n'est ni lue ni décompressée.
            if entete.empreinte == h && entete.longueur <= champ.len() as u64 {
                let d = self.donnee(pos, Some(champ.len()))?;
                match d.charge.as_deref() {
                    Some(c) if c == champ => return self.entrees_de(&d),
                    Some(_) => {}
                    // Compressé, et illisible ou plus long que le champ une fois décompressé : la bonne empreinte,
                    // mais rien ne dit que ce n'est pas lui. Le dire « absent » ferait compter « aucune erreur ».
                    None => return None,
                }
            }
            pos = entete.suivant_meme_case;
        }
        Some(Vec::new())
    }

    /// Les positions des entrées d'un DATA : la première, puis la chaîne des tableaux.
    fn entrees_de(&mut self, d: &Donnee) -> Option<Vec<u64>> {
        // Ce qui est au-delà de la taille lue à l'ouverture a été écrit depuis, dans le fichier en cours : les
        // entrées, comme leurs tableaux, s'ajoutent toujours à la fin, la liste s'arrête donc là.
        let longueur = self.lecteur.longueur;
        let mut sortie = Vec::new();
        if d.nombre == 0 || d.premiere_entree == 0 || d.premiere_entree >= longueur {
            return Some(sortie);
        }
        sortie.push(d.premiere_entree);
        // Le nombre d'entrées vient du fichier : ce n'est pas lui qui borne la liste. Une entrée fait au moins
        // 64 octets, un DATA n'en tient donc jamais plus que longueur / 64 ; au-delà, ou si un tableau revient dans la
        // chaîne, le fichier est abîmé (ou hostile) et la liste grossirait sans fin.
        let plafond = usize::try_from(longueur / 64).unwrap_or(usize::MAX);
        let mut vus: HashSet<u64> = HashSet::new();
        let mut reste = d.nombre - 1;
        let mut tableau = d.tableau;
        let largeur: u64 = if self.compact() { 4 } else { 8 };
        let mut pas = self.lecteur.longueur / 24;
        while reste > 0 && tableau != 0 && tableau < longueur {
            pas = pas.checked_sub(1)?;
            if !vus.insert(tableau) {
                return None;
            }
            let (_, taille) = self.objet(tableau, TABLEAU, 24)?;
            let o = self.lecteur.lire(tableau, usize::try_from(taille).ok()?)?;
            for k in 0..(taille - 24) / largeur {
                if reste == 0 {
                    break;
                }
                let p = usize::try_from(24 + k * largeur).ok()?;
                let e = if largeur == 4 {
                    u64::from(u32_a(&o, p))
                } else {
                    u64_a(&o, p)
                };
                // Une case encore vide : le fichier en cours d'écriture s'arrête là.
                if e == 0 || e >= longueur {
                    return Some(sortie);
                }
                if sortie.len() >= plafond {
                    return None;
                }
                sortie.push(e);
                reste -= 1;
            }
            tableau = u64_a(&o, 16);
        }
        Some(sortie)
    }

    /// Les entrées de ce fichier qui répondent à la requête, avec leur numéro dans la suite du fichier.
    fn chercher(&mut self, r: &Requete) -> Option<Vec<(u64, Entree)>> {
        if r.depuis
            .is_some_and(|t| self.derniere_heure != 0 && self.derniere_heure < t)
        {
            return Some(Vec::new());
        }
        let mut positions: Vec<u64> = Vec::new();
        for champ in r.un_de {
            positions.extend(self.entrees_du_champ(champ.as_bytes())?);
        }
        positions.sort_unstable();
        positions.dedup();
        let mut champs: HashMap<u64, Champ> = HashMap::new();
        let mut sortie = Vec::new();
        for pos in positions {
            let (_, taille) = self.objet(pos, ENTREE, 64)?;
            let o = self.lecteur.lire(pos, usize::try_from(taille).ok()?)?;
            let numero = u64_a(&o, 16);
            let quand = u64_a(&o, 24);
            if r.depuis.is_some_and(|t| quand < t) || r.demarrage.is_some_and(|b| o[40..56] != b) {
                continue;
            }
            let largeur = if self.compact() { 4 } else { 16 };
            let mut lus = Vec::new();
            for k in 0..(o.len() - 64) / largeur {
                let p = 64 + k * largeur;
                let objet = if self.compact() {
                    u64::from(u32_a(&o, p))
                } else {
                    u64_a(&o, p)
                };
                // Un même champ revient dans beaucoup d'entrées (« SYSLOG_IDENTIFIER=kernel ») : lu une fois.
                let champ = if let Some(c) = champs.get(&objet) {
                    c.clone()
                } else {
                    let c = self.champ(objet, r.champs)?;
                    champs.insert(objet, c.clone());
                    c
                };
                if let Champ::Voulu(nom, valeur) = champ {
                    lus.push((nom, valeur));
                }
            }
            sortie.push((numero, Entree { quand, champs: lus }));
        }
        Some(sortie)
    }

    /// Le numéro et l'heure d'une entrée (sans ses champs).
    fn en_tete(&mut self, pos: u64) -> Option<(u64, u64)> {
        self.objet(pos, ENTREE, 64)?;
        let o = self.lecteur.lire(pos, 64)?;
        Some((u64_a(&o, 16), u64_a(&o, 24)))
    }

    /// Une entrée et ses champs voulus ; `cache` garde les champs déjà lus (un même champ revient dans beaucoup
    /// d'entrées), vidé au-delà de 100 000 pour borner la mémoire.
    fn entree(&mut self, pos: u64, voulus: &[&str], cache: &mut HashMap<u64, Champ>) -> Option<Entree> {
        let (_, taille) = self.objet(pos, ENTREE, 64)?;
        let o = self.lecteur.lire(pos, usize::try_from(taille).ok()?)?;
        let largeur = if self.compact() { 4 } else { 16 };
        let mut champs = Vec::new();
        for k in 0..(o.len() - 64) / largeur {
            let p = 64 + k * largeur;
            let objet = if self.compact() {
                u64::from(u32_a(&o, p))
            } else {
                u64_a(&o, p)
            };
            if cache.len() > 100_000 {
                cache.clear();
            }
            let champ = if let Some(c) = cache.get(&objet) {
                c.clone()
            } else {
                let c = self.champ(objet, voulus)?;
                cache.insert(objet, c.clone());
                c
            };
            if let Champ::Voulu(nom, valeur) = champ {
                champs.push((nom, valeur));
            }
        }
        Some(Entree {
            quand: u64_a(&o, 24),
            champs,
        })
    }

    /// Les tableaux de toutes les entrées, dans l'ordre de la chaîne. Une chaîne qui revient sur elle-même, ou plus
    /// longue que le fichier ne peut en tenir, rend `None`.
    fn tableaux_des_entrees(&mut self) -> Option<Vec<u64>> {
        let longueur = self.lecteur.longueur;
        let mut tableaux = Vec::new();
        let mut vus: HashSet<u64> = HashSet::new();
        let mut t = self.tableau_entrees;
        let mut pas = longueur / 24;
        while t != 0 && t < longueur {
            pas = pas.checked_sub(1)?;
            if !vus.insert(t) {
                return None;
            }
            self.objet(t, TABLEAU, 24)?;
            tableaux.push(t);
            t = u64_a(&self.lecteur.lire(t + 16, 8)?, 0);
        }
        Some(tableaux)
    }

    /// Les positions d'entrées d'un tableau, jusqu'à sa première case vide (le fichier en cours s'arrête là).
    fn cases_du_tableau(&mut self, tableau: u64) -> Option<Vec<u64>> {
        let longueur = self.lecteur.longueur;
        let (_, taille) = self.objet(tableau, TABLEAU, 24)?;
        let o = self.lecteur.lire(tableau, usize::try_from(taille).ok()?)?;
        let largeur: usize = if self.compact() { 4 } else { 8 };
        let mut cases = Vec::new();
        for k in 0..(o.len() - 24) / largeur {
            let p = 24 + k * largeur;
            let e = if largeur == 4 {
                u64::from(u32_a(&o, p))
            } else {
                u64_a(&o, p)
            };
            if e == 0 || e >= longueur {
                break;
            }
            cases.push(e);
        }
        Some(cases)
    }

    /// Le champ à `pos`, s'il fait partie de ceux qu'on veut : le début seul se lit d'abord, un champ long qui n'est
    /// pas compressé ne se lit en entier que s'il est voulu. `None` pour un champ voulu qui ne se lit pas, ou un champ
    /// compressé qui ne se décompresse pas (son nom ne se sait qu'après) : l'entrée compterait sans son message, et
    /// un échec SSH disparaîtrait du décompte au lieu de passer à journalctl.
    fn champ(&mut self, pos: u64, voulus: &[&str]) -> Option<Champ> {
        let debut = if self.compact() { 72 } else { 64 };
        let (drapeaux, taille) = self.objet(pos, DATA, debut)?;
        if drapeaux & COMPRESSE == 0 {
            let n = usize::try_from((taille - debut).min(64)).ok()?;
            let tete = self.lecteur.lire(pos + debut, n)?;
            let nom = tete.split(|&c| c == b'=').next().unwrap_or_default();
            if !voulus.iter().any(|v| v.as_bytes() == nom) || nom.len() == tete.len() {
                return Some(Champ::Autre);
            }
        }
        let charge = self.donnee(pos, Some(CHAMP_MAX))?.charge?;
        let Some(egal) = charge.iter().position(|&c| c == b'=') else {
            return Some(Champ::Autre);
        };
        let nom = String::from_utf8_lossy(&charge[..egal]).into_owned();
        if !voulus.contains(&nom.as_str()) {
            return Some(Champ::Autre);
        }
        let valeur = String::from_utf8_lossy(&charge[egal + 1..]).into_owned();
        Some(Champ::Voulu(nom, valeur))
    }
}

/// Un champ compressé en LZ4 par journald : la taille décompressée sur 8 octets, puis un bloc LZ4 (des séquences
/// « n littéraux, puis une copie de m octets pris d plus tôt », la dernière sans copie).
fn delz4(entree: &[u8], max: usize) -> Option<Vec<u8>> {
    let taille = usize::try_from(u64_a(entree, 0))
        .ok()
        .filter(|&t| t <= max && entree.len() >= 8)?;
    let mut s: Vec<u8> = Vec::with_capacity(taille);
    let mut i = 8;
    let longueur = |i: &mut usize, mut n: usize| -> Option<usize> {
        if n == 15 {
            loop {
                let o = *entree.get(*i)?;
                *i += 1;
                n = n.checked_add(usize::from(o))?;
                if o != 255 {
                    break;
                }
            }
        }
        Some(n)
    };
    loop {
        let jeton = *entree.get(i)?;
        i += 1;
        let litteraux = longueur(&mut i, usize::from(jeton >> 4))?;
        let fin = i.checked_add(litteraux)?;
        if s.len().checked_add(litteraux)? > taille {
            return None;
        }
        s.extend_from_slice(entree.get(i..fin)?);
        i = fin;
        if i == entree.len() {
            break;
        }
        let recul = usize::from(u16::from_le_bytes(entree.get(i..i + 2)?.try_into().ok()?));
        i += 2;
        let copie = longueur(&mut i, usize::from(jeton & 15))?.checked_add(4)?;
        if recul == 0 || recul > s.len() || s.len().checked_add(copie)? > taille {
            return None;
        }
        let depart = s.len() - recul;
        for k in 0..copie {
            let o = s[depart + k];
            s.push(o);
        }
    }
    (s.len() == taille).then_some(s)
}

/// SipHash-2-4, l'empreinte des fichiers récents (systemd 246 et après), avec l'identifiant du fichier pour clé.
fn siphash24(octets: &[u8], cle: &[u8; 16]) -> u64 {
    let k0 = u64_a(cle, 0);
    let k1 = u64_a(cle, 8);
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let tour = |v: &mut [u64; 4]| {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    };
    let (morceaux, reste) = octets.as_chunks::<8>();
    for m in morceaux {
        let m = u64::from_le_bytes(*m);
        v[3] ^= m;
        tour(&mut v);
        tour(&mut v);
        v[0] ^= m;
    }
    let mut dernier = (octets.len() as u64) << 56;
    for (k, &o) in reste.iter().enumerate() {
        dernier |= u64::from(o) << (8 * k);
    }
    v[3] ^= dernier;
    tour(&mut v);
    tour(&mut v);
    v[0] ^= dernier;
    v[2] ^= 0xff;
    for _ in 0..4 {
        tour(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// L'empreinte des fichiers plus anciens : lookup3 de Bob Jenkins (hashlittle2), les deux moitiés réunies.
fn jenkins64(octets: &[u8]) -> u64 {
    let (c, b) = hashlittle2(octets, 0, 0);
    (u64::from(c) << 32) | u64::from(b)
}

/// Le mélange de trois mots de lookup3 (« mix »).
fn melange(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c) ^ c.rotate_left(4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a) ^ a.rotate_left(6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b) ^ b.rotate_left(8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c) ^ c.rotate_left(16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a) ^ a.rotate_left(19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b) ^ b.rotate_left(4);
    *b = b.wrapping_add(*a);
}

/// hashlittle2 : `pc` et `pb` sont les graines (zéro pour journald), le résultat (c, b).
fn hashlittle2(octets: &[u8], pc: u32, pb: u32) -> (u32, u32) {
    // La longueur entre dans l'état sur 32 bits, comme dans lookup3.c.
    #[allow(clippy::cast_possible_truncation)]
    let depart = 0xdead_beef_u32.wrapping_add(octets.len() as u32).wrapping_add(pc);
    let (mut a, mut b, mut c) = (depart, depart, depart.wrapping_add(pb));
    let mot = |m: &[u8], k: usize| {
        let mut w = [0u8; 4];
        for (j, o) in m.iter().skip(4 * k).take(4).enumerate() {
            w[j] = *o;
        }
        u32::from_le_bytes(w)
    };
    let mut reste = octets;
    while reste.len() > 12 {
        a = a.wrapping_add(mot(reste, 0));
        b = b.wrapping_add(mot(reste, 1));
        c = c.wrapping_add(mot(reste, 2));
        melange(&mut a, &mut b, &mut c);
        reste = &reste[12..];
    }
    if reste.is_empty() {
        return (c, b);
    }
    a = a.wrapping_add(mot(reste, 0));
    b = b.wrapping_add(mot(reste, 1));
    c = c.wrapping_add(mot(reste, 2));
    c = (c ^ b).wrapping_sub(b.rotate_left(14));
    a = (a ^ c).wrapping_sub(c.rotate_left(11));
    b = (b ^ a).wrapping_sub(a.rotate_left(25));
    c = (c ^ b).wrapping_sub(b.rotate_left(16));
    a = (a ^ c).wrapping_sub(c.rotate_left(4));
    b = (b ^ a).wrapping_sub(a.rotate_left(14));
    c = (c ^ b).wrapping_sub(b.rotate_left(24));
    (c, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empreintes_des_vecteurs_connus() {
        // SipHash-2-4, clé 00…0f : le message vide et les 15 premiers octets (vecteurs de l'article de référence).
        let cle: [u8; 16] = std::array::from_fn(|k| u8::try_from(k).unwrap());
        assert_eq!(siphash24(b"", &cle), 0x726f_db47_dd0e_0e31);
        let message: Vec<u8> = (0..15).collect();
        assert_eq!(siphash24(&message, &cle), 0xa129_ca61_49be_45e5);
        // lookup3.c, le programme d'essai de son auteur.
        assert_eq!(hashlittle2(b"", 0, 0), (0xdead_beef, 0xdead_beef));
        assert_eq!(hashlittle2(b"", 0, 0xdead_beef), (0xbd5b_7dde, 0xdead_beef));
        assert_eq!(hashlittle2(b"", 0xdead_beef, 0xdead_beef), (0x9c09_3ccd, 0xbd5b_7dde));
        let phrase = b"Four score and seven years ago";
        assert_eq!(hashlittle2(phrase, 0, 0), (0x1777_0551, 0xce72_26e6));
        assert_eq!(hashlittle2(phrase, 0, 1), (0xe360_7cae, 0xbd37_1de4));
        assert_eq!(hashlittle2(phrase, 1, 0), (0xcd62_8161, 0x6cbe_a4b3));
        assert_eq!(jenkins64(b""), 0xdead_beef_dead_beef);
    }

    /// L'oracle du parcours complet : les 5 premiers Mo de `journalctl --since=-7d --reverse -o short-iso` contre
    /// le parcours de Vanguard, sur cet ordinateur. Les lignes d'avant le début des deux lectures (moins une marge)
    /// doivent être les mêmes, dans le même ordre ; rien de personnel dans les messages (des nombres).
    #[test]
    fn tout_le_journal_comme_journalctl() {
        let depart = maintenant();
        let depuis = depart - 7 * 86_400 * 1_000_000;
        let mut natives: Vec<String> = Vec::new();
        let mut octets = 0usize;
        let chrono = std::time::Instant::now();
        let Some(parcours) = tout_le_journal(depuis, |l| {
            octets += l.len() + 1;
            natives.push(l.to_string());
            octets < 5 << 20
        }) else {
            return crate::essais::saute("journal illisible ici");
        };
        let duree = chrono.elapsed();
        let Some(sortie) = crate::commande::lancer(
            std::process::Command::new("sh")
                .args([
                    "-c",
                    "journalctl --since=-7d --reverse --no-pager -o short-iso | head -c 5242880",
                ])
                .env("LC_ALL", "C.UTF-8"),
            120,
        ) else {
            return crate::essais::saute("journalctl absent");
        };
        // Seules les entrées : une ligne qui commence par une date (les suites de messages sur plusieurs lignes
        // commencent par des espaces).
        let entrees = |t: &[String]| -> Vec<String> {
            t.iter()
                .flat_map(|l| l.lines().map(String::from).collect::<Vec<_>>())
                .filter(|l| l.as_bytes().first().is_some_and(u8::is_ascii_digit))
                .collect()
        };
        let natives = entrees(&natives);
        let outil = entrees(&sortie.sortie.lines().map(String::from).collect::<Vec<_>>());
        // Les 10 dernières secondes avant le départ peuvent différer (des entrées écrites entre les deux lectures).
        let limite = chrono::DateTime::from_timestamp(i64::try_from((depart - 10_000_000) / 1_000_000).unwrap(), 0)
            .unwrap()
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        let anciennes = |v: &[String]| -> Vec<String> {
            v.iter()
                .filter(|l| l.get(..25).is_some_and(|d| d < limite.as_str()))
                .cloned()
                .collect()
        };
        let (a, b) = (anciennes(&natives), anciennes(&outil));
        let n = a.len().min(b.len()).saturating_sub(50);
        let differentes = a.iter().zip(&b).take(n).filter(|(x, y)| x != y).count();
        eprintln!(
            "parcours : {} entrées en {duree:?}, coupé {} ; comparées {n}, différentes {differentes}",
            parcours.entrees, parcours.coupe
        );
        assert!(n > 100, "trop peu à comparer : {n}");
        assert_eq!(differentes, 0);
    }

    #[test]
    fn lz4_de_journald() {
        // « salon salon salon » : 6 littéraux, puis une copie de 12 octets pris 6 plus tôt, puis rien.
        let mut bloc = 18u64.to_le_bytes().to_vec();
        bloc.extend([0x68]);
        bloc.extend(b"salon ");
        bloc.extend([6, 0, 0x00]);
        assert_eq!(delz4(&bloc, CHAMP_MAX).as_deref(), Some(&b"salon salon salon "[..]));
        // Taille annoncée fausse, recul vers avant le début, coupé.
        let mut faux = bloc.clone();
        faux[0] = 19;
        assert_eq!(delz4(&faux, CHAMP_MAX), None);
        let mut avant = bloc.clone();
        avant[15] = 7;
        assert_eq!(delz4(&avant, CHAMP_MAX), None);
        for n in 0..bloc.len() {
            assert_eq!(delz4(&bloc[..n], CHAMP_MAX), None);
        }
        // Plus long que la borne demandée : rien, sans rien écrire.
        assert_eq!(delz4(&bloc, 17), None);
    }

    /// Un fichier du journal écrit pour l'essai, comme journald l'écrirait : en-tête, table de hachage, puis les
    /// objets DATA, ENTRY et ENTRY_ARRAY, en mode compact ou non, empreinte à clé ou lookup3.
    struct Ecrivain {
        o: Vec<u8>,
        drapeaux: u32,
        cases: u64,
        donnees: HashMap<Vec<u8>, u64>,
        numero: u64,
        positions: Vec<u64>,
    }

    const CLE: [u8; 16] = *b"fichier-d-essai!";
    const DEMARRAGE: [u8; 16] = *b"demarrage-actuel";
    const AUTRE_DEMARRAGE: [u8; 16] = *b"demarrage-avant!";

    impl Ecrivain {
        fn new(drapeaux: u32) -> Self {
            let cases: u64 = 7;
            let mut o = vec![0u8; 272];
            o[..8].copy_from_slice(SIGNATURE);
            o[12..16].copy_from_slice(&drapeaux.to_le_bytes());
            o[24..40].copy_from_slice(&CLE);
            o[72..88].copy_from_slice(b"suite-de-numeros");
            o[88..96].copy_from_slice(&272u64.to_le_bytes());
            o[104..112].copy_from_slice(&(272u64 + 16).to_le_bytes());
            o[112..120].copy_from_slice(&(cases * 16).to_le_bytes());
            let mut e = Ecrivain {
                o,
                drapeaux,
                cases,
                donnees: HashMap::new(),
                numero: 0,
                positions: Vec::new(),
            };
            let mut table = vec![0u8; 16 + 16 * 7];
            table[0] = TABLE_DATA;
            e.objet(table);
            e
        }

        fn compact(&self) -> bool {
            self.drapeaux & COMPACT != 0
        }

        fn ecrire(&mut self, pos: u64, octets: &[u8]) {
            let p = usize::try_from(pos).unwrap();
            self.o[p..p + octets.len()].copy_from_slice(octets);
        }

        fn lire(&self, pos: u64) -> u64 {
            u64_a(&self.o, usize::try_from(pos).unwrap())
        }

        /// Ajoute un objet (sa taille écrite dans son en-tête), aligné sur 8 octets ; rend sa position.
        fn objet(&mut self, mut octets: Vec<u8>) -> u64 {
            let pos = self.o.len() as u64;
            let taille = octets.len() as u64;
            octets[8..16].copy_from_slice(&taille.to_le_bytes());
            self.o.extend(&octets);
            self.o.resize(self.o.len().div_ceil(8) * 8, 0);
            pos
        }

        fn empreinte(&self, champ: &[u8]) -> u64 {
            if self.drapeaux & HACHAGE_A_CLE != 0 {
                siphash24(champ, &CLE)
            } else {
                jenkins64(champ)
            }
        }

        /// Le DATA d'un champ, créé et rangé dans sa case s'il n'existe pas ; `compresse` : (drapeau, octets).
        fn donnee(&mut self, champ: &[u8], compresse: Option<(u8, Vec<u8>)>) -> u64 {
            if let Some(&pos) = self.donnees.get(champ) {
                return pos;
            }
            let h = self.empreinte(champ);
            let debut = if self.compact() { 72 } else { 64 };
            let mut d = vec![0u8; debut];
            d[0] = DATA;
            d[16..24].copy_from_slice(&h.to_le_bytes());
            match compresse {
                Some((drapeau, octets)) => {
                    d[1] = drapeau;
                    d.extend(octets);
                }
                None => d.extend(champ),
            }
            let pos = self.objet(d);
            // En tête de sa case, ou au bout de la chaîne.
            let case = 272 + 16 + (h % self.cases) * 16;
            if self.lire(case) == 0 {
                self.ecrire(case, &pos.to_le_bytes());
            } else {
                let mut p = self.lire(case);
                while self.lire(p + 24) != 0 {
                    p = self.lire(p + 24);
                }
                self.ecrire(p + 24, &pos.to_le_bytes());
            }
            self.donnees.insert(champ.to_vec(), pos);
            pos
        }

        /// Une entrée et ses champs ; chaque DATA la reçoit dans sa liste (la première en direct, les autres dans
        /// un tableau d'une case chacun, chaînés).
        fn entree(&mut self, quand: u64, demarrage: [u8; 16], champs: &[&[u8]]) {
            let positions: Vec<u64> = champs.iter().map(|c| self.donnee(c, None)).collect();
            self.entree_de(quand, demarrage, &positions);
        }

        fn entree_de(&mut self, quand: u64, demarrage: [u8; 16], positions: &[u64]) {
            self.numero += 1;
            let mut e = vec![0u8; 64];
            e[0] = ENTREE;
            e[16..24].copy_from_slice(&self.numero.to_le_bytes());
            e[24..32].copy_from_slice(&quand.to_le_bytes());
            e[40..56].copy_from_slice(&demarrage);
            for &p in positions {
                if self.compact() {
                    e.extend(&u32::try_from(p).unwrap().to_le_bytes());
                } else {
                    e.extend(&p.to_le_bytes());
                    e.extend(&0u64.to_le_bytes());
                }
            }
            let pos = self.objet(e);
            self.positions.push(pos);
            for &d in positions {
                let n = self.lire(d + 56);
                if n == 0 {
                    self.ecrire(d + 40, &pos.to_le_bytes());
                } else {
                    let mut t = vec![0u8; 24];
                    t[0] = TABLEAU;
                    if self.compact() {
                        t.extend(&u32::try_from(pos).unwrap().to_le_bytes());
                    } else {
                        t.extend(&pos.to_le_bytes());
                    }
                    let tableau = self.objet(t);
                    if self.lire(d + 48) == 0 {
                        self.ecrire(d + 48, &tableau.to_le_bytes());
                    } else {
                        let mut p = self.lire(d + 48);
                        while self.lire(p + 16) != 0 {
                            p = self.lire(p + 16);
                        }
                        self.ecrire(p + 16, &tableau.to_le_bytes());
                    }
                }
                self.ecrire(d + 56, &(n + 1).to_le_bytes());
            }
            let total = self.lire(152) + 1;
            self.ecrire(152, &total.to_le_bytes());
            self.ecrire(192, &quand.to_le_bytes());
        }

        /// Les tableaux de toutes les entrées (en-tête : premier tableau et plus ancienne heure), `par` entrées par
        /// tableau, chaînés comme journald les chaîne ; le dernier garde une case vide (le fichier en cours).
        fn tableaux_des_entrees(&mut self, par: usize) {
            let positions = self.positions.clone();
            let mut precedent: Option<u64> = None;
            for (k, morceau) in positions.chunks(par).enumerate() {
                let mut t = vec![0u8; 24];
                t[0] = TABLEAU;
                for &p in morceau {
                    if self.compact() {
                        t.extend(&u32::try_from(p).unwrap().to_le_bytes());
                    } else {
                        t.extend(&p.to_le_bytes());
                    }
                }
                if (k + 1) * par >= positions.len() {
                    t.extend(&[0u8; 8]);
                }
                let pos = self.objet(t);
                match precedent {
                    None => self.ecrire(176, &pos.to_le_bytes()),
                    Some(p) => self.ecrire(p + 16, &pos.to_le_bytes()),
                }
                precedent = Some(pos);
            }
            let premiere = self.lire(self.positions[0] + 24);
            self.ecrire(184, &premiere.to_le_bytes());
        }

        fn fichier(&self, dossier: &Path, nom: &str) -> PathBuf {
            let p = dossier.join(nom);
            std::fs::write(&p, &self.o).unwrap();
            p
        }
    }

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-journal-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Un journal inventé : des erreurs de deux démarrages, un message compressé en zstd, un autre en LZ4.
    fn journal_invente(drapeaux: u32) -> Ecrivain {
        let mut e = Ecrivain::new(drapeaux);
        e.entree(
            1_000,
            AUTRE_DEMARRAGE,
            &[b"PRIORITY=3", b"SYSLOG_IDENTIFIER=ancien", b"MESSAGE=avant"],
        );
        e.entree(
            2_000,
            DEMARRAGE,
            &[b"PRIORITY=6", b"_COMM=sshd", b"MESSAGE=Accepted publickey for alice"],
        );
        e.entree(
            3_000,
            DEMARRAGE,
            &[b"PRIORITY=3", b"_COMM=pipewire", b"MESSAGE=sans nom"],
        );
        e.entree(
            4_000,
            DEMARRAGE,
            &[b"PRIORITY=2", b"SYSLOG_IDENTIFIER=kernel", b"_COMM=kworker"],
        );
        // MESSAGE compressé en zstd (une trame à un bloc en clair) et en LZ4, pour sshd-session.
        let message = b"MESSAGE=Failed password for alice from 203.0.113.9 port 2222 ssh2";
        let mut zst = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, u8::try_from(message.len()).unwrap()];
        zst.extend(&(1 | (u32::try_from(message.len()).unwrap() << 3)).to_le_bytes()[..3]);
        zst.extend(message);
        let m1 = e.donnee(message, Some((4, zst)));
        let comm = e.donnee(b"_COMM=sshd-session", None);
        let p6 = e.donnee(b"PRIORITY=6", None);
        e.entree_de(5_000, DEMARRAGE, &[p6, comm, m1]);
        let invalide = b"MESSAGE=Invalid user zorglub from 203.0.113.10 port 4242";
        let mut lz4 = (invalide.len() as u64).to_le_bytes().to_vec();
        lz4.push(0xf0);
        lz4.push(u8::try_from(invalide.len() - 15).unwrap());
        lz4.extend(invalide);
        let m2 = e.donnee(invalide, Some((2, lz4)));
        e.entree_de(6_000, DEMARRAGE, &[p6, comm, m2]);
        e.entree(
            7_000,
            DEMARRAGE,
            &[b"PRIORITY=3", b"SYSLOG_IDENTIFIER=kernel", b"MESSAGE=encore"],
        );
        e
    }

    fn erreurs(fichiers: &[PathBuf]) -> Option<Vec<Entree>> {
        chercher(
            fichiers,
            &Requete {
                un_de: &["PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3"],
                depuis: None,
                demarrage: Some(DEMARRAGE),
                champs: &["SYSLOG_IDENTIFIER", "_COMM"],
            },
        )
    }

    fn sshd(fichiers: &[PathBuf], depuis: u64) -> Option<Vec<String>> {
        let entrees = chercher(
            fichiers,
            &Requete {
                un_de: &["_COMM=sshd", "_COMM=sshd-session"],
                depuis: Some(depuis),
                demarrage: None,
                champs: &["MESSAGE"],
            },
        )?;
        Some(
            entrees
                .iter()
                .filter_map(|e| e.champ("MESSAGE").map(str::to_string))
                .collect(),
        )
    }

    /// Le parcours complet à l'envers, fusionné entre deux fichiers, dédoublonné, écrit comme short-iso ; une
    /// borne qui coupe ; une chaîne de tableaux qui revient sur elle-même, refusée.
    #[test]
    fn parcours_a_l_envers_de_deux_fichiers() {
        let dossier = jetable("parcours");
        for drapeaux in [HACHAGE_A_CLE | COMPACT | ZSTD | LZ4, 0] {
            let mut a = journal_invente(drapeaux);
            a.tableaux_des_entrees(3);
            let fa = a.fichier(&dossier, "system.journal");
            let mut b = Ecrivain::new(drapeaux);
            // Une autre suite de numéros (un autre journald) : ses numéros 1 et 2 ne sont pas ceux de `a`.
            b.ecrire(72, b"autre-suite-num!");
            b.entree(
                2_500_000,
                DEMARRAGE,
                &[
                    b"_HOSTNAME=portable",
                    b"SYSLOG_IDENTIFIER=sudo",
                    b"_PID=7",
                    b"MESSAGE=alice : TTY=pts/0 ; COMMAND=/bin/ls",
                ],
            );
            b.entree(
                8_000_000,
                DEMARRAGE,
                &[b"_HOSTNAME=portable", b"_COMM=bash", b"MESSAGE=deux\nlignes"],
            );
            b.tableaux_des_entrees(1);
            let fb = b.fichier(&dossier, "user-1000.journal");
            let reculs: Vec<Recul> = [&fa, &fb]
                .iter()
                .map(|f| {
                    let mut journal = ouvert(f);
                    let tableaux = journal.tableaux_des_entrees().unwrap();
                    Recul {
                        journal,
                        tableaux,
                        cases: Vec::new(),
                    }
                })
                .collect();
            let mut lignes = Vec::new();
            let lu = parcourir(reculs, 2_000, &mut |l: &str| {
                lignes.push(l.to_string());
                true
            })
            .unwrap();
            // Du plus récent au plus ancien ; sans MESSAGE, pas de ligne ; avant 2 000 µs, rien.
            let fins: Vec<&str> = lignes.iter().map(|l| &l[26..]).collect();
            assert!(fins[0].starts_with("portable bash: deux\n"), "{fins:?}");
            assert!(fins[0].ends_with(&format!("{}lignes", " ".repeat(26 + "portable bash: ".len()))));
            assert_eq!(fins[1], "portable sudo[7]: alice : TTY=pts/0 ; COMMAND=/bin/ls");
            assert_eq!(
                fins.last().copied(),
                Some("sshd: Accepted publickey for alice"),
                "{fins:?}"
            );
            assert_eq!(
                lu,
                Parcours {
                    entrees: lignes.len(),
                    coupe: false
                }
            );
            assert_eq!(lignes.len(), 7, "{fins:?}");
            // Une borne : arrêt net, et dit.
            let mut journal = ouvert(&fa);
            let tableaux = journal.tableaux_des_entrees().unwrap();
            let lu = parcourir(
                vec![Recul {
                    journal,
                    tableaux,
                    cases: Vec::new(),
                }],
                0,
                &mut |_: &str| false,
            )
            .unwrap();
            assert_eq!(
                lu,
                Parcours {
                    entrees: 0,
                    coupe: true
                }
            );
            // Le dernier tableau renvoie au premier : refusé, jamais une boucle.
            let premier = a.lire(176);
            let mut t = premier;
            while a.lire(t + 16) != 0 {
                t = a.lire(t + 16);
            }
            a.ecrire(t + 16, &premier.to_le_bytes());
            let boucle = a.fichier(&dossier, "system.journal");
            assert!(ouvert(&boucle).tableaux_des_entrees().is_none());
        }
        assert_eq!(
            sans_ansi("\x1b[1;31mrouge\x1b[0m \x1b]0;titre\x07fin \x1b]8;;u\x1b\\x"),
            "rouge fin x"
        );
        assert_eq!(sans_ansi("\x1b"), "\x1b");
    }

    #[test]
    fn journal_invente_lu_dans_les_quatre_formats() {
        let d = jetable("formats");
        for drapeaux in [HACHAGE_A_CLE | COMPACT | ZSTD | LZ4, HACHAGE_A_CLE, COMPACT, 0] {
            let f = journal_invente(drapeaux).fichier(&d, "system.journal");
            let lues = erreurs(std::slice::from_ref(&f)).unwrap();
            let champs: Vec<Vec<(&str, &str)>> = lues
                .iter()
                .map(|e| e.champs.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect())
                .collect();
            assert_eq!(
                champs,
                [
                    vec![("_COMM", "pipewire")],
                    vec![("SYSLOG_IDENTIFIER", "kernel"), ("_COMM", "kworker")],
                    vec![("SYSLOG_IDENTIFIER", "kernel")],
                ],
                "drapeaux {drapeaux}"
            );
            assert_eq!(lues.iter().map(|e| e.quand).collect::<Vec<_>>(), [3_000, 4_000, 7_000]);
            assert_eq!(
                sshd(std::slice::from_ref(&f), 0).unwrap(),
                [
                    "Accepted publickey for alice",
                    "Failed password for alice from 203.0.113.9 port 2222 ssh2",
                    "Invalid user zorglub from 203.0.113.10 port 4242",
                ]
            );
            // Depuis une heure : les plus anciennes ne comptent plus ; après la dernière, le fichier est sauté.
            assert_eq!(sshd(std::slice::from_ref(&f), 5_500).unwrap().len(), 1);
            assert_eq!(sshd(std::slice::from_ref(&f), 8_000).unwrap(), Vec::<String>::new());
            // Le même fichier deux fois (une copie archivée) : chaque entrée une fois.
            let copie = d.join("archive-copie.journal~");
            std::fs::copy(&f, &copie).unwrap();
            assert_eq!(sshd(&[f.clone(), copie], 0).unwrap().len(), 3);
        }
    }

    /// Un programme sans droits copié sous le nom « sshd » écrit de fausses attaques dans son propre journal : seules
    /// les lignes que root a écrites (`_UID=0`, posé par journald) comptent, et le journal du compte n'est pas lu.
    #[test]
    fn sshd_de_confiance_seulement() {
        // Les archives de journald se nomment « system@… » : écrit ainsi, le garde-fou de confidentialité ne les
        // prend pas pour des adresses de courriel.
        const AROBASE: char = '@';
        let d = jetable("confiance");
        let mut e = Ecrivain::new(HACHAGE_A_CLE | COMPACT);
        e.entree(
            1_000,
            DEMARRAGE,
            &[
                b"_COMM=sshd",
                b"_UID=0",
                b"MESSAGE=Failed password for root from 203.0.113.9 port 4242 ssh2",
            ],
        );
        e.entree(
            2_000,
            DEMARRAGE,
            &[
                b"_COMM=sshd",
                b"_UID=1000",
                b"MESSAGE=Failed password for root from 198.51.100.7 port 1 ssh2",
            ],
        );
        e.entree(
            3_000,
            DEMARRAGE,
            &[
                b"_COMM=sshd-session",
                b"MESSAGE=Accepted password for alice from 198.51.100.7 port 2 ssh2",
            ],
        );
        let f = e.fichier(&d, "system.journal");
        let entrees = chercher(
            std::slice::from_ref(&f),
            &Requete {
                un_de: &["_COMM=sshd", "_COMM=sshd-session"],
                depuis: Some(0),
                demarrage: None,
                champs: &["MESSAGE", "_UID"],
            },
        )
        .unwrap();
        assert_eq!(entrees.len(), 3);
        assert_eq!(
            de_root(entrees),
            ["Failed password for root from 203.0.113.9 port 4242 ssh2"]
        );
        let tous = vec![
            d.join("system.journal"),
            d.join(format!("system{AROBASE}0001-0002.journal~")),
            d.join("user-1000.journal"),
            d.join(format!("user-1000{AROBASE}0003.journal")),
        ];
        assert_eq!(
            du_systeme_seul(tous),
            [
                d.join("system.journal"),
                d.join(format!("system{AROBASE}0001-0002.journal~"))
            ]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ce qui ne se lit pas rend `None` (journalctl prendra le relais), jamais une liste vide qui passerait pour
    /// « rien à signaler ».
    #[test]
    fn journal_illisible_ne_dit_pas_rien() {
        let d = jetable("illisible");
        let bon = journal_invente(HACHAGE_A_CLE | COMPACT);
        // Un drapeau inconnu (un format plus récent).
        let mut futur = Ecrivain::new(HACHAGE_A_CLE | 32);
        futur.entree(1, DEMARRAGE, &[b"PRIORITY=3"]);
        assert_eq!(erreurs(&[futur.fichier(&d, "futur.journal")]), None);
        // L'empreinte annoncée n'est pas celle qu'on calcule : on ne trouverait rien, à tort.
        let mut menteur = journal_invente(COMPACT);
        menteur.o[12] |= u8::try_from(HACHAGE_A_CLE).unwrap();
        assert_eq!(erreurs(&[menteur.fichier(&d, "menteur.journal")]), None);
        // Un champ compressé en xz.
        let mut xz = Ecrivain::new(HACHAGE_A_CLE | XZ);
        let m = xz.donnee(b"_COMM=sshd", Some((1, b"\xfd7zXZ\0".to_vec())));
        xz.entree_de(1, DEMARRAGE, &[m]);
        assert_eq!(sshd(&[xz.fichier(&d, "xz.journal")], 0), None);
        // Un MESSAGE en zstd ou en LZ4 abîmé, dans une entrée de sshd : l'entrée sans son message ferait disparaître
        // l'échec du décompte. Le nom d'un champ compressé ne se sait qu'après : même chercher d'autres champs renonce.
        for (drapeau, abime) in [
            (4, b"\x28\xb5\x2f\xfd\x20\x30abime".to_vec()),
            (2, b"\x30\0\0\0\0\0\0\0\xf0".to_vec()),
        ] {
            let mut j = Ecrivain::new(HACHAGE_A_CLE | ZSTD | LZ4);
            let comm = j.donnee(b"_COMM=sshd", None);
            let p3 = j.donnee(b"PRIORITY=3", None);
            let m = j.donnee(b"MESSAGE=Failed password for alice", Some((drapeau, abime)));
            j.entree_de(5_000, DEMARRAGE, &[p3, comm, m]);
            let f = j.fichier(&d, "abime.journal");
            assert_eq!(sshd(std::slice::from_ref(&f), 0), None, "drapeau {drapeau}");
            assert_eq!(erreurs(std::slice::from_ref(&f)), None, "drapeau {drapeau}");
        }
        // Pas un journal.
        std::fs::write(d.join("faux.journal"), vec![b'x'; 4096]).unwrap();
        assert_eq!(erreurs(&[d.join("faux.journal")]), None);
        // Un fichier qui a disparu entre la liste et la lecture ne compte pas ; un fichier vide non plus.
        std::fs::write(d.join("vide.journal"), b"").unwrap();
        let f = bon.fichier(&d, "system.journal");
        let lues = erreurs(&[d.join("parti.journal"), d.join("vide.journal"), f.clone()]).unwrap();
        assert_eq!(lues.len(), 3);
        // Le fichier en cours d'écriture, vu avant que la dernière entrée et son tableau n'y soient : les autres se
        // lisent, la liste s'arrête à la fin de ce qui est écrit.
        let derniere = *bon.positions.last().unwrap();
        std::fs::write(&f, &bon.o[..usize::try_from(derniere).unwrap()]).unwrap();
        let lues = erreurs(std::slice::from_ref(&f)).unwrap();
        assert_eq!(lues.iter().map(|e| e.quand).collect::<Vec<_>>(), [3_000, 4_000]);
        // Chaque octet changé, chaque coupure : jamais de panique.
        for i in 0..bon.o.len() {
            let mut abime = bon.o.clone();
            abime[i] ^= 0x41;
            std::fs::write(&f, &abime).unwrap();
            let _ = erreurs(std::slice::from_ref(&f));
            let _ = sshd(std::slice::from_ref(&f), 0);
            std::fs::write(&f, &bon.o[..i]).unwrap();
            let _ = erreurs(std::slice::from_ref(&f));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ouvre un journal d'essai déjà écrit.
    fn ouvert(chemin: &Path) -> Journal {
        match Journal::ouvrir(std::fs::File::open(chemin).unwrap()) {
            Some(Ouvert::Pret(j)) => j,
            _ => panic!("{} ne s'ouvre pas", chemin.display()),
        }
    }

    /// Une chaîne de tableaux qui revient sur elle-même, avec un nombre d'entrées démesuré venu du fichier : la
    /// lecture renonce sans empiler une position par tour (avant : environ 180 Mo pour un fichier de 66 Ko).
    #[test]
    fn tableaux_en_boucle_sans_remplir_la_memoire() {
        let d = jetable("tableaux");
        let mut e = journal_invente(HACHAGE_A_CLE);
        let p3 = e.donnees[&b"PRIORITY=3"[..]];
        let entree = e.positions[0];
        let pos = e.o.len() as u64;
        let mut tableau = vec![0u8; 24 + 8192 * 8];
        tableau[0] = TABLEAU;
        tableau[16..24].copy_from_slice(&pos.to_le_bytes());
        for k in 0..8192 {
            tableau[24 + k * 8..32 + k * 8].copy_from_slice(&entree.to_le_bytes());
        }
        assert_eq!(e.objet(tableau), pos);
        e.ecrire(p3 + 48, &pos.to_le_bytes());
        e.ecrire(p3 + 56, &u64::MAX.to_le_bytes());
        let f = e.fichier(&d, "system.journal");
        let mut j = ouvert(&f);
        assert_eq!(j.entrees_du_champ(b"PRIORITY=3"), None);
        assert!(j.lecteur.lus <= 2 * j.lecteur.longueur, "{} lus", j.lecteur.lus);
        // Deux tableaux qui se renvoient l'un à l'autre, sans case : la boucle se voit aussi.
        let mut e = journal_invente(HACHAGE_A_CLE);
        let p3 = e.donnees[&b"PRIORITY=3"[..]];
        let premier = e.o.len() as u64;
        let mut tableau = vec![0u8; 24];
        tableau[0] = TABLEAU;
        tableau[16..24].copy_from_slice(&(premier + 24).to_le_bytes());
        e.objet(tableau.clone());
        tableau[16..24].copy_from_slice(&premier.to_le_bytes());
        e.objet(tableau);
        e.ecrire(p3 + 48, &premier.to_le_bytes());
        e.ecrire(p3 + 56, &u64::MAX.to_le_bytes());
        assert_eq!(
            ouvert(&e.fichier(&d, "system.journal")).entrees_du_champ(b"PRIORITY=3"),
            None
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un DATA qui porte l'empreinte du champ cherché, une autre charge (longue) et lui-même pour suivant : la chaîne
    /// renonce au premier retour, sans relire la charge (avant : 4,8 s pour 4 Mio, la durée croissant au carré).
    #[test]
    fn chaine_de_hachage_en_boucle_sans_relire() {
        let d = jetable("chaine");
        let mut e = Ecrivain::new(HACHAGE_A_CLE);
        // Un champ honnête en tête de la même case : l'empreinte se vérifie à l'ouverture, sur lui.
        let case = e.empreinte(b"PRIORITY=3") % e.cases;
        let honnete = (0..100_000)
            .map(|k| format!("MESSAGE={k}"))
            .find(|c| e.empreinte(c.as_bytes()) % e.cases == case)
            .unwrap();
        e.entree(1_000, DEMARRAGE, &[honnete.as_bytes()]);
        let hostile = e.donnee(b"PRIORITY=3", Some((0, vec![b'x'; 256 << 10])));
        e.ecrire(hostile + 24, &hostile.to_le_bytes());
        let f = e.fichier(&d, "system.journal");
        let mut j = ouvert(&f);
        assert_eq!(j.entrees_du_champ(b"PRIORITY=3"), None);
        assert!(j.lecteur.lus < 4096, "{} lus", j.lecteur.lus);
        // Sans la boucle, le DATA trop long est sauté sans être lu, et le champ n'est pas là.
        e.ecrire(hostile + 24, &0u64.to_le_bytes());
        let f = e.fichier(&d, "system.journal");
        let mut j = ouvert(&f);
        assert_eq!(j.entrees_du_champ(b"PRIORITY=3"), Some(Vec::new()));
        assert!(j.lecteur.lus < 4096, "{} lus", j.lecteur.lus);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Des objets qui se chevauchent peuvent faire relire le fichier sans fin, quelle que soit la garde de chaque
    /// boucle : le budget de lecture arrête la requête, qui rend None.
    #[test]
    fn budget_de_lecture() {
        let d = jetable("budget");
        let f = journal_invente(HACHAGE_A_CLE).fichier(&d, "system.journal");
        let mut j = ouvert(&f);
        assert!(j.lecteur.lus < j.lecteur.longueur, "{} lus", j.lecteur.lus);
        j.lecteur.budget = j.lecteur.lus;
        assert_eq!(j.entrees_du_champ(b"PRIORITY=3"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un dossier du journal absent ne compte pas ; un dossier là mais qui ne se liste pas rend None (lire le seul
    /// journal volatil ferait dire « aucune erreur » d'une lecture partielle).
    #[test]
    fn dossier_du_journal_illisible() {
        let d = jetable("dossiers");
        let machine = "0123456789abcdef0123456789abcdef";
        let (persistant, volatil) = (d.join("var"), d.join("run"));
        std::fs::create_dir_all(volatil.join(machine)).unwrap();
        std::fs::write(volatil.join(machine).join("system.journal"), b"").unwrap();
        std::fs::write(volatil.join(machine).join("notes.txt"), b"").unwrap();
        let racines = [persistant.as_path(), volatil.as_path()];
        assert_eq!(
            fichiers_dans(&racines, machine),
            Some(vec![volatil.join(machine).join("system.journal")])
        );
        // Là, mais pas un dossier qui se liste (ENOTDIR ; des droits refusés donnent le même chemin, mais un essai
        // lancé en root, ou sous unshare -r, les passerait).
        std::fs::create_dir_all(&persistant).unwrap();
        std::fs::write(persistant.join(machine), b"").unwrap();
        assert_eq!(fichiers_dans(&racines, machine), None);
        // Un identifiant de machine qui n'en est pas un.
        assert_eq!(fichiers_dans(&racines, "../etc"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une entrée exportée : l'heure et les champs voulus.
    type Exportee = (u64, Vec<(String, String)>);

    /// Les entrées de `journalctl -o export`. Un champ qui n'est pas du texte sur une ligne s'écrit « NOM », un saut
    /// de ligne, sa taille sur 8 octets, puis ses octets.
    fn exportees(arguments: &[&str], champs: &[&str]) -> Option<Vec<Exportee>> {
        let sortie = std::process::Command::new("journalctl")
            .args(arguments)
            .args(["-q", "--no-pager", "-o", "export"])
            .env("LC_ALL", "C")
            .output()
            .ok()
            .filter(|s| s.status.success())?;
        let octets = sortie.stdout;
        let mut entrees = Vec::new();
        let mut actuelle: Option<Exportee> = None;
        let mut pos = 0;
        while pos < octets.len() {
            let fin = octets[pos..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(octets.len(), |k| pos + k);
            let ligne = &octets[pos..fin];
            pos = fin + 1;
            if ligne.is_empty() {
                entrees.extend(actuelle.take());
                continue;
            }
            let entree = actuelle.get_or_insert_with(|| (0, Vec::new()));
            let (nom, valeur) = if let Some(egal) = ligne.iter().position(|&c| c == b'=') {
                (&ligne[..egal], ligne[egal + 1..].to_vec())
            } else {
                let taille = usize::try_from(u64_a(&octets, pos)).ok()?;
                let valeur = octets.get(pos + 8..pos + 8 + taille)?.to_vec();
                pos += 8 + taille + 1;
                (ligne, valeur)
            };
            let nom = String::from_utf8_lossy(nom).into_owned();
            if nom == "__REALTIME_TIMESTAMP" {
                entree.0 = String::from_utf8_lossy(&valeur).parse().ok()?;
            } else if champs.contains(&nom.as_str()) {
                entree.1.push((nom, String::from_utf8_lossy(&valeur).into_owned()));
            }
        }
        entrees.extend(actuelle);
        Some(entrees)
    }

    /// `a` est-il contenu dans `b`, chaque élément compté autant de fois qu'il y paraît ?
    fn inclus<T: std::hash::Hash + Eq>(a: &[T], b: &[T]) -> bool {
        let mut comptes: HashMap<&T, usize> = HashMap::new();
        for x in b {
            *comptes.entry(x).or_default() += 1;
        }
        a.iter().all(|x| {
            comptes
                .get_mut(x)
                .and_then(|n| n.checked_sub(1).map(|r| *n = r))
                .is_some()
        })
    }

    /// Lu avant et après la lecture native : ce que journalctl voyait avant y est, et rien qui n'y soit après.
    fn comme_journalctl(arguments: &[&str], champs: &[&str], lire: impl Fn() -> Option<Vec<Entree>>) {
        let Some(avant) = exportees(arguments, champs) else {
            return;
        };
        let Some(lues) = lire() else {
            // Ne rien lire en Rust n'est permis que si le journal du système ne s'ouvre pas ici (hors des groupes
            // adm, wheel et systemd-journal) : sinon, une lecture qui rendrait toujours None (empreinte mal calculée,
            // décodeur cassé) passerait inaperçue, journalctl prenant la relève en silence.
            let ouverts = fichiers_du_systeme().is_some_and(|f| f.iter().all(|p| std::fs::File::open(p).is_ok()));
            assert!(
                !ouverts,
                "{arguments:?} : journalctl lit {} entrées, le journal du système s'ouvre, et la lecture en Rust rend None",
                avant.len()
            );
            return;
        };
        let apres = exportees(arguments, champs).unwrap();
        let lues: Vec<Exportee> = lues.into_iter().map(|e| (e.quand, e.champs)).collect();
        assert!(
            inclus(&avant, &lues),
            "{arguments:?} : {} avant, {} lues",
            avant.len(),
            lues.len()
        );
        assert!(
            inclus(&lues, &apres),
            "{arguments:?} : {} lues, {} après",
            lues.len(),
            apres.len()
        );
    }

    /// Sur cet ordinateur, quand le journal du système se lit : les erreurs du démarrage sont celles de
    /// `journalctl -b -p err`, avec les mêmes noms de programmes et les mêmes messages (ceux de plus de 512 octets
    /// sont compressés par journald).
    #[test]
    fn erreurs_comme_journalctl() {
        let champs = ["SYSLOG_IDENTIFIER", "_COMM", "MESSAGE"];
        let arguments = ["-b", "-p", "err", "--output-fields=SYSLOG_IDENTIFIER,_COMM,MESSAGE"];
        comme_journalctl(&arguments, &champs, || erreurs_avec(&champs));
    }

    /// Sur cet ordinateur : les messages de quelques programmes depuis une heure fixe sont ceux de journalctl,
    /// compressés ou non (ce qui essaie aussi la lecture de sshd, absent de la plupart des ordinateurs de bureau).
    #[test]
    fn messages_comme_journalctl() {
        let depuis = (maintenant() / 1_000_000 - 6 * 3600) * 1_000_000;
        let depuis_texte = format!("@{}", depuis / 1_000_000);
        for programmes in [&["sshd", "sshd-session"][..], &["systemd", "systemd-logind"]] {
            let mut arguments: Vec<String> = Vec::new();
            for (k, p) in programmes.iter().enumerate() {
                if k > 0 {
                    arguments.push("+".into());
                }
                arguments.push(format!("_COMM={p}"));
            }
            arguments.extend(["--since".into(), depuis_texte.clone(), "--output-fields=MESSAGE".into()]);
            let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let un_de: Vec<String> = programmes.iter().map(|p| format!("_COMM={p}")).collect();
            let un_de: Vec<&str> = un_de.iter().map(String::as_str).collect();
            comme_journalctl(&arguments, &["MESSAGE"], || {
                chercher_dans_le_systeme(
                    &Requete {
                        un_de: &un_de,
                        depuis: Some(depuis),
                        demarrage: None,
                        champs: &["MESSAGE"],
                    },
                    false,
                )
            });
        }
    }

    /// Sur cet ordinateur : chaque champ compressé des journaux lisibles se décompresse, et son empreinte est celle
    /// que journald a rangée (un octet faux la changerait).
    #[test]
    fn champs_compresses_du_systeme() {
        let Some(fichiers) = fichiers_du_systeme() else {
            return crate::essais::saute("aucun journal systemd lisible");
        };
        // Les journaux du système seulement : parcourir chaque objet de plusieurs Go de journaux d'utilisateur
        // prendrait trop de temps pour un essai.
        let systeme = fichiers
            .into_iter()
            .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("system")));
        for chemin in systeme {
            let Ok(f) = std::fs::File::open(&chemin) else { continue };
            let Some(Ouvert::Pret(mut j)) = Journal::ouvrir(f) else {
                continue;
            };
            // Chaque objet lu, une fois : bien plus qu'une requête, le budget ne vaut pas ici.
            j.lecteur.budget = u64::MAX;
            let entete = j.lecteur.lire(0, 208).unwrap();
            let dernier = u64_a(&entete, 136);
            let mut pos = j.entete;
            while pos != 0 && pos <= dernier {
                let Some(o) = j.lecteur.lire(pos, 16) else { break };
                let taille = u64_a(&o, 8);
                if taille == 0 {
                    break;
                }
                if o[0] == DATA && o[1] & 7 != 0 {
                    let d = j
                        .donnee(pos, Some(CHAMP_MAX))
                        .unwrap_or_else(|| panic!("{} : {pos}", chemin.display()));
                    let charge = d.charge.unwrap();
                    assert_eq!(j.empreinte(&charge), d.empreinte, "{} : {pos}", chemin.display());
                }
                pos += taille.div_ceil(8) * 8;
            }
        }
    }

    #[test]
    fn identifiants_en_hexadecimal() {
        let id = id_hexa("0123456789abcdef0123456789ABCDEF").unwrap();
        assert_eq!(id[0], 0x01);
        assert_eq!(id[15], 0xef);
        assert_eq!(
            id_hexa("01234567-89ab-cdef-0123-456789abcdef"),
            Some(std::array::from_fn(|k| id[k]))
        );
        assert_eq!(id_hexa("0123"), None);
        assert_eq!(id_hexa("zz23456789abcdef0123456789abcdef"), None);
    }
}
