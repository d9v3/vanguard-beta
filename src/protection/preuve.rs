//! La preuve relevée avant d'agir : avant d'arrêter un processus, de mettre un fichier en quarantaine ou de bloquer
//! une adresse, Vanguard note ce qui disparaîtra avec le geste (le programme, sa ligne de commande, son parent, son
//! compte, l'empreinte SHA-256 du fichier, les connexions en cours). C'est l'ordre que « Après une infection »
//! enseigne : les traces avant le nettoyage. Un blocage de nuit, fait tout seul, détruisait sinon la lignée et
//! l'empreinte du fichier isolé, qu'on ne pouvait plus chercher ni comparer.
//!
//! Le relevé ne retient jamais le geste : ce qui ne se lit pas (droits, processus déjà fini, connexions illisibles)
//! est noté « impossible (raison) », et le geste se fait quand même (défensif d'abord). La preuve est gardée avec le
//! blocage dans « Ce que Vanguard a changé » (changements.jsonl, sur cet ordinateur seulement), et les traces
//! d'incident la reprennent.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::trf;

/// Au-delà, un fichier n'est pas haché : le relevé ne doit pas retarder le geste de plusieurs secondes.
const TAILLE_MAX: u64 = 256 << 20;
/// Une ligne de commande se garde jusqu'à cette longueur, en caractères.
const LIGNE_MAX: usize = 4000;
/// Les connexions gardées au plus.
const CONNEXIONS_MAX: usize = 50;
/// Le temps laissé à WMI pour la ligne de commande et le parent, sous Windows : le relevé passe avant l'arrêt d'un
/// programme jugé certain, et un WMI lent ou figé (une panne connue, ou chargé par le programme hostile) ne doit pas
/// retarder l'arrêt des 30 secondes de son propre délai.
#[cfg_attr(not(windows), allow(dead_code))]
const DELAI_WMI: std::time::Duration = std::time::Duration::from_secs(3);

/// Ce qui a été relevé juste avant le geste.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Preuve {
    /// « AAAA-MM-JJ HH:MM:SS », heure de cet ordinateur.
    pub date: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processus: Option<Processus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fichier: Option<Fichier>,
    /// Les connexions du processus, ou vers l'adresse bloquée : « 203.0.113.7:443 (PID 4242, nom) ».
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connexions: Vec<String>,
    /// Ce qui n'a pas pu être relevé, et pourquoi, dans les deux langues.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impossible: Vec<String>,
}

/// Le processus tel qu'il était.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Processus {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub programme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ligne: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compte: Option<String>,
}

/// Le fichier tel qu'il était.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Fichier {
    pub chemin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taille: Option<u64>,
}

impl Preuve {
    fn nouvelle() -> Preuve {
        Preuve {
            date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            ..Preuve::default()
        }
    }

    /// Note ce qui n'a pas pu être relevé : « quoi : impossible (raison) », en français puis en anglais.
    fn impossible(&mut self, quoi: (&str, &str), raison: (&str, &str)) {
        self.impossible.push(format!(
            "{} : impossible ({}) / {}: not possible ({})",
            quoi.0, raison.0, quoi.1, raison.1
        ));
    }

    /// Le résumé d'une ligne, pour l'écran : l'empreinte et ce qui manque.
    pub(crate) fn resume(&self) -> String {
        let mut morceaux = Vec::new();
        if let Some(h) = self.fichier.as_ref().and_then(|f| f.sha256.as_deref()) {
            morceaux.push(format!("SHA-256 {h}"));
        }
        if let Some(p) = &self.processus {
            morceaux.push(trf!("PID {}", "PID {}", p.pid));
        }
        if !self.connexions.is_empty() {
            morceaux.push(trf!("{} connexion(s)", "{} connection(s)", self.connexions.len()));
        }
        if !self.impossible.is_empty() {
            morceaux.push(trf!(
                "{} élément(s) non relevé(s)",
                "{} item(s) not recorded",
                self.impossible.len()
            ));
        }
        morceaux.join(", ")
    }

    /// Le relevé en lignes de texte, pour les traces d'incident (une valeur par ligne, rendue inoffensive).
    pub(crate) fn lignes(&self) -> Vec<String> {
        let mut l = vec![format!("relevé/recorded {}", self.date)];
        if let Some(p) = &self.processus {
            l.push(format!(
                "PID {} ; parent {} ; compte/account {}",
                p.pid,
                p.parent.map_or_else(|| "?".to_string(), |x| x.to_string()),
                p.compte.as_deref().unwrap_or("?")
            ));
            if let Some(c) = &p.programme {
                l.push(format!("programme/program {c}"));
            }
            if let Some(c) = &p.ligne {
                l.push(format!("ligne/command line {c}"));
            }
        }
        if let Some(f) = &self.fichier {
            l.push(format!(
                "fichier/file {} ; SHA-256 {} ; {} octets/bytes",
                f.chemin,
                f.sha256.as_deref().unwrap_or("?"),
                f.taille.map_or_else(|| "?".to_string(), |t| t.to_string())
            ));
        }
        l.extend(self.connexions.iter().map(|c| format!("connexion/connection {c}")));
        l.extend(self.impossible.iter().cloned());
        l.into_iter().map(|x| crate::ui::affichable(&x)).collect()
    }
}

/// Ce qu'il faut relever avant un geste.
#[derive(Clone, Copy)]
pub(crate) enum Releve<'a> {
    /// Le programme à arrêter (`pid`) et le fichier à isoler.
    Programme {
        pid: Option<u32>,
        fichier: Option<&'a Path>,
    },
    /// Le processus à arrêter n'est plus celui de la détection : le fichier seul, et c'est dit.
    ProgrammeParti { fichier: Option<&'a Path> },
    /// Un fichier seul (quarantaine après une analyse, réglage réécrit, suppression).
    Fichier(&'a Path),
    /// Les connexions vers une adresse à bloquer.
    Adresse(IpAddr),
    /// Le geste n'efface aucune trace (un démarrage retiré se remet exactement, une liste de pilotes, un port
    /// fermé) : rien à relever, et c'est écrit ici, pas oublié.
    Rien,
}

/// Le jeton d'un relevé fait : la preuve (ou rien, quand le geste n'efface aucune trace) et l'événement qui la garde
/// dans le journal commun. Ses champs sont privés : seul `relever` en fabrique un, et noter un geste
/// (`changements::noter_blocage`, `quarantaine::isoler`) l'exige. Le compilateur impose ainsi le relevé avant le
/// geste, au lieu d'un commentaire qu'un nouvel appel pourrait ignorer.
pub(crate) struct PreuveFaite {
    preuve: Option<Preuve>,
    evenement: Option<String>,
}

impl PreuveFaite {
    pub(crate) fn preuve(&self) -> Option<&Preuve> {
        self.preuve.as_ref()
    }

    /// L'événement Preuve du journal, cause du geste.
    pub(crate) fn evenement(&self) -> Option<&str> {
        self.evenement.as_deref()
    }

    pub(crate) fn en_preuve(self) -> Option<Preuve> {
        self.preuve
    }
}

/// Relève ce que le geste va effacer, puis le note dans le journal des événements, relié à l'alerte qui parlait du
/// même objet (`cle`, ces dernières 24 heures). Ce qui ne se lit pas est dit « impossible (raison) » dans la preuve,
/// et le jeton est rendu quand même : on bloque (défensif d'abord), le rapport le dit.
pub(crate) fn relever(quoi: Releve<'_>, cle: &str, source: crate::modele::evenement::Source) -> PreuveFaite {
    use crate::modele::evenement::{Evenement, Genre};
    let preuve = match quoi {
        Releve::Programme { pid, fichier } => Some(relever_programme(pid, fichier)),
        Releve::ProgrammeParti { fichier } => Some(relever_programme_parti(fichier)),
        Releve::Fichier(f) => Some(relever_fichier(f)),
        Releve::Adresse(ip) => Some(relever_adresse(ip)),
        Releve::Rien => None,
    };
    let evenement = preuve.as_ref().and_then(|p| {
        let objet = crate::traces::vanguard::objet(cle);
        let alerte = crate::modele::journal::dernier(
            |e| {
                matches!(e.quoi, Genre::Alerte { .. })
                    && e.cle
                        .as_deref()
                        .is_some_and(|c| crate::traces::vanguard::objet(c) == objet)
            },
            chrono::Duration::hours(24),
        );
        crate::modele::journal::noter(
            Evenement::nouveau(source, Genre::Preuve { releve: p.clone() })
                .cle(Some(cle))
                .cause(alerte.as_deref()),
        )
    });
    PreuveFaite { preuve, evenement }
}

/// Le relevé d'un programme à arrêter (`pid`) et du fichier à isoler (`fichier`), juste avant le geste.
fn relever_programme(pid: Option<u32>, fichier: Option<&Path>) -> Preuve {
    let mut p = Preuve::nouvelle();
    if let Some(pid) = pid {
        p.processus = Some(processus(pid, &mut p));
        connexions_de(&mut p, |c| c.pid == Some(pid));
    }
    if let Some(f) = fichier {
        p.fichier = Some(fichier_releve(f, &mut p));
    }
    p
}

/// Le relevé quand le processus à arrêter n'est plus celui de la détection (fini, ou son numéro repris par un autre
/// programme) : le fichier seul, et c'est dit.
fn relever_programme_parti(fichier: Option<&Path>) -> Preuve {
    let mut p = relever_programme(None, fichier);
    p.impossible(
        ("processus", "process"),
        (
            "fini, ou son numéro repris par un autre programme",
            "ended, or its number reused by another program",
        ),
    );
    p
}

/// Le relevé d'un fichier seul (quarantaine demandée après une analyse, réglage réécrit).
fn relever_fichier(f: &Path) -> Preuve {
    let mut p = Preuve::nouvelle();
    p.fichier = Some(fichier_releve(f, &mut p));
    p
}

/// Le relevé des connexions vers une adresse, avant de la bloquer : quels programmes lui parlaient.
fn relever_adresse(ip: IpAddr) -> Preuve {
    let mut p = Preuve::nouvelle();
    let ip = ip.to_canonical();
    connexions_de(&mut p, |c| c.distante.to_canonical() == ip);
    p
}

fn fichier_releve(f: &Path, p: &mut Preuve) -> Fichier {
    use crate::traces::Empreinte;
    let quoi = ("empreinte SHA-256", "SHA-256 fingerprint");
    let taille = std::fs::metadata(f).ok().map(|m| m.len());
    let sha256 = match crate::traces::empreinte(f, TAILLE_MAX) {
        Empreinte::Sha256(h) => Some(h),
        Empreinte::Droits => {
            p.impossible(quoi, ("droits", "rights"));
            None
        }
        Empreinte::TropGros => {
            p.impossible(quoi, ("plus de 256 Mio", "over 256 MiB"));
            None
        }
        Empreinte::Aucune | Empreinte::Illisible | Empreinte::Delai => {
            p.impossible(quoi, ("fichier illisible ou disparu", "file unreadable or gone"));
            None
        }
    };
    Fichier {
        chemin: f.to_string_lossy().into_owned(),
        sha256,
        taille,
    }
}

/// Les connexions en cours qui répondent à `garder`, notées dans la preuve ; illisibles, c'est dit.
fn connexions_de(p: &mut Preuve, garder: impl Fn(&crate::protection::sortantes::ConnexionVue) -> bool) {
    let quoi = ("connexions", "connections");
    match crate::protection::sortantes::connexions_vues() {
        Some(liste) => {
            p.connexions = liste
                .iter()
                .filter(|c| garder(c))
                .take(CONNEXIONS_MAX)
                .map(|c| {
                    let proprietaire = match (c.pid, &c.programme) {
                        (Some(pid), Some(n)) => format!(" (PID {pid}, {n})"),
                        (Some(pid), None) => format!(" (PID {pid})"),
                        _ => String::new(),
                    };
                    format!("{}{proprietaire}", std::net::SocketAddr::new(c.distante, c.port))
                })
                .collect();
        }
        None => p.impossible(quoi, ("illisibles", "unreadable")),
    }
}

/// Coupe une ligne de commande trop longue (un script passé en argument peut faire des pages).
fn borner(ligne: &str) -> String {
    match ligne.char_indices().nth(LIGNE_MAX) {
        Some((i, _)) => format!("{}…", &ligne[..i]),
        None => ligne.to_string(),
    }
}

/// Le processus `pid`, tel qu'il se lit ; ce qui manque est noté dans `p`.
fn processus(pid: u32, p: &mut Preuve) -> Processus {
    let mut pr = Processus {
        pid,
        programme: crate::protection::blocage::chemin_du_processus(pid),
        ..Processus::default()
    };
    let sans_reponse = lire_processus(&mut pr);
    if pr.programme.is_none() {
        p.impossible(
            ("programme du processus", "process program"),
            ("droits, ou processus fini", "rights, or process ended"),
        );
    }
    if pr.ligne.is_none() {
        p.impossible(
            ("ligne de commande", "command line"),
            sans_reponse.unwrap_or(("droits, ou processus fini", "rights, or process ended")),
        );
    }
    pr
}

/// Le résultat de `lire`, s'il arrive dans le délai ; sinon `None`, et le fil qui lit est abandonné (il finira de
/// lui-même) : le geste n'attend pas.
#[cfg_attr(not(windows), allow(dead_code))]
fn en_moins_de<T: Send + 'static>(delai: std::time::Duration, lire: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (envoi, reception) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("vanguard-releve".into())
        .spawn(move || {
            let _ = envoi.send(lire());
        })
        .ok()?;
    reception.recv_timeout(delai).ok()
}

/// Linux : /proc, sans lancer de commande. Rend la raison d'un relevé resté sans réponse (jamais ici).
#[cfg(target_os = "linux")]
fn lire_processus(pr: &mut Processus) -> Option<(&'static str, &'static str)> {
    if let Ok(o) = std::fs::read(format!("/proc/{}/cmdline", pr.pid))
        && !o.is_empty()
    {
        let texte = String::from_utf8_lossy(&o);
        pr.ligne = Some(borner(texte.trim_end_matches('\0').replace('\0', " ").as_str()));
    }
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pr.pid)) {
        let champ = |nom: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(nom))
                .and_then(|r| r.split_whitespace().next())
                .and_then(|n| n.parse::<u32>().ok())
        };
        pr.parent = champ("PPid:");
        pr.compte =
            champ("Uid:").map(|uid| nom_du_compte(uid, &std::fs::read_to_string("/etc/passwd").unwrap_or_default()));
    }
    None
}

/// Le nom du compte d'après /etc/passwd, avec son numéro : « alice (1000) » ; le numéro seul s'il n'y est pas.
#[cfg(any(target_os = "linux", test))]
fn nom_du_compte(uid: u32, passwd: &str) -> String {
    let nom = passwd.lines().find_map(|l| {
        let c: Vec<&str> = l.split(':').collect();
        (c.get(2) == Some(&uid.to_string().as_str())).then(|| c[0].to_string())
    });
    nom.map_or_else(|| uid.to_string(), |n| format!("{n} ({uid})"))
}

/// macOS : ps, par son chemin complet (rien de posé plus tôt dans le PATH).
#[cfg(target_os = "macos")]
fn lire_processus(pr: &mut Processus) -> Option<(&'static str, &'static str)> {
    let r = crate::commande::lancer(
        std::process::Command::new("/bin/ps").args(["-o", "ppid=,user=,args=", "-p", &pr.pid.to_string()]),
        10,
    )?;
    let ligne = r.sortie.trim();
    let mut mots = ligne.splitn(3, char::is_whitespace).filter(|m| !m.is_empty());
    pr.parent = mots.next().and_then(|n| n.parse().ok());
    pr.compte = mots.next().map(str::to_string);
    pr.ligne = mots.next().map(|l| borner(l.trim()));
    None
}

/// Windows : Win32_Process par WMI, le compte lu dans le jeton du processus.
#[cfg(windows)]
fn lire_processus(pr: &mut Processus) -> Option<(&'static str, &'static str)> {
    let compte = crate::machine::windows::processus::compte_de(pr.pid);
    if !compte.is_empty() {
        pr.compte = Some(compte);
    }
    let condition = format!("ProcessId = {}", pr.pid);
    let Some(reponse) = en_moins_de(DELAI_WMI, move || {
        crate::machine::windows::wmi::requete(
            r"root\cimv2",
            "Win32_Process",
            &condition,
            &["ParentProcessId", "ExecutablePath", "CommandLine"],
        )
    }) else {
        return Some(("WMI sans réponse", "WMI not responding"));
    };
    let lignes = reponse?;
    let l = lignes.first()?;
    pr.parent = l["ParentProcessId"].entier().and_then(|n| u32::try_from(n).ok());
    pr.ligne = l["CommandLine"].texte().filter(|t| !t.is_empty()).map(borner);
    if pr.programme.is_none() {
        pr.programme = l["ExecutablePath"]
            .texte()
            .filter(|t| !t.is_empty())
            .map(str::to_string);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le relevé d'un processus de ce test et de son propre programme : la ligne, le parent, l'empreinte ; une
    /// relecture JSON garde tout, et un relevé d'une version d'avant (sans preuve) se relit.
    #[test]
    fn releve_d_un_processus_et_de_son_fichier() {
        let moi = std::process::id();
        // Le programme des tests dépasse la borne du hachage : un petit fichier inventé à sa place.
        let fichier = std::env::temp_dir().join(format!("vanguard-preuve-{moi}.sh"));
        std::fs::write(&fichier, b"#!/bin/sh\necho essai\n").unwrap();
        let p = relever_programme(Some(moi), Some(&fichier));
        let _ = std::fs::remove_file(&fichier);
        let f = p.fichier.as_ref().unwrap();
        assert_eq!(
            f.sha256.as_deref(),
            Some("127ff8f5f3ed1a49383df0b971875c685a63058db980668d87853631eff56e53"),
            "{p:?}"
        );
        assert_eq!(f.taille, Some(21));
        let pr = p.processus.as_ref().unwrap();
        assert_eq!(pr.pid, moi);
        #[cfg(target_os = "linux")]
        {
            assert!(
                pr.parent.is_some() && pr.ligne.is_some() && pr.compte.is_some(),
                "{pr:?}"
            );
            assert!(p.impossible.is_empty(), "{:?}", p.impossible);
        }
        let relu: Preuve = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(relu, p);
        assert!(p.lignes().iter().any(|l| l.starts_with("fichier/file ")));
    }

    /// Le relevé ne retient jamais le geste : un processus fini et un fichier disparu sont notés « impossible »,
    /// dans les deux langues, et le relevé est quand même rendu.
    #[test]
    fn ce_qui_ne_se_lit_pas_est_dit_impossible() {
        let fichier = std::env::temp_dir().join(format!("vanguard-preuve-absent-{}", std::process::id()));
        let p = relever_programme(Some(u32::MAX - 7), Some(&fichier));
        assert!(p.fichier.as_ref().is_some_and(|f| f.sha256.is_none()));
        assert!(p.impossible.len() >= 2, "{:?}", p.impossible);
        assert!(
            p.impossible
                .iter()
                .all(|l| l.contains("impossible (") && l.contains("not possible ("))
        );
        assert_ne!(p.resume(), "");
    }

    #[test]
    fn compte_lu_dans_passwd() {
        let passwd = "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        assert_eq!(nom_du_compte(1000, passwd), "alice (1000)");
        assert_eq!(nom_du_compte(1001, passwd), "1001");
    }

    #[test]
    fn ligne_bornee() {
        assert_eq!(borner("court"), "court");
        let longue = "é".repeat(LIGNE_MAX + 10);
        assert_eq!(borner(&longue).chars().count(), LIGNE_MAX + 1);
    }

    /// Le jeton ne se fabrique qu'ici : ses champs sont privés (le compilateur refuse `PreuveFaite { .. }` ailleurs),
    /// et aucun autre fichier n'en écrit un littéral ni n'appelle un constructeur qui le contournerait. Un test de
    /// compilation (`compile_fail`) ne tourne pas dans un programme ; la lecture des sources le remplace.
    #[test]
    fn jeton_fabrique_ici_seulement() {
        fn parcourir(d: &std::path::Path, trouves: &mut Vec<String>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    parcourir(&p, trouves);
                } else if p.extension().is_some_and(|x| x == "rs") && !p.ends_with("protection/preuve.rs") {
                    let texte = std::fs::read_to_string(&p).unwrap();
                    if texte.contains("PreuveFaite {") {
                        trouves.push(p.display().to_string());
                    }
                }
            }
        }
        let mut trouves = Vec::new();
        parcourir(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut trouves,
        );
        assert!(
            trouves.is_empty(),
            "PreuveFaite fabriqué hors de preuve.rs : {trouves:?}"
        );
        // Le relevé d'un geste qui n'efface rien rend un jeton sans preuve, sans rien noter.
        let j = relever(
            Releve::Rien,
            "demarrage:essai",
            crate::modele::evenement::Source::Blocage,
        );
        assert!(j.preuve().is_none() && j.evenement().is_none());
        // Un relevé fait est noté au journal, et le jeton le porte : le geste s'y reliera.
        let f = crate::socle::dossier_local().join(format!("essai-jeton-{}", std::process::id()));
        std::fs::create_dir_all(crate::socle::dossier_local()).unwrap();
        std::fs::write(&f, b"x").unwrap();
        let j = relever(
            Releve::Fichier(&f),
            "fichier:essai",
            crate::modele::evenement::Source::Analyse,
        );
        assert!(j.preuve().is_some_and(|p| p.fichier.is_some()));
        assert!(j.evenement().is_some());
        let _ = std::fs::remove_file(&f);
    }

    /// Une lecture qui ne répond pas (WMI figé) ne retient pas le geste au-delà du délai ; une lecture rapide rend
    /// son résultat.
    #[test]
    fn un_releve_sans_reponse_ne_retient_pas_le_geste() {
        let debut = std::time::Instant::now();
        let r = en_moins_de(std::time::Duration::from_millis(100), || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            1
        });
        assert_eq!(r, None);
        assert!(debut.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(en_moins_de(std::time::Duration::from_secs(5), || 2), Some(2));
    }
}
