//! Les règles `EVT-` changées en constats et en couverture (`modele::resultat`), et leurs deux points d'entrée : un
//! dossier de .evtx (Linux, macOS, Windows : journaux rapportés, `winevt\Logs` d'un disque monté) et l'ordinateur
//! vivant (Windows). Sans écran : la commande (`journaux_windows::commande`) et la chronologie
//! (`journaux_windows::chronologie`) le reprennent.
//!
//! Chaque règle rend ses trouvailles (une alerte par objet), puis, si elle n'a pas tout lu, un « non vérifié » qui
//! dit pourquoi ; « rien trouvé » seulement quand tout ce qu'elle cherche a été lu. Une alerte déclarée normale
//! (`protection::normales`, clé `evenements|<règle>|<objet>`) est tue, et comptée dans le constat de sa règle.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use super::jeu::{JOURNAUX, REGLES};
use super::moteur::{
    Audit, BornesMoteur, EtatJournal, Gravite, Jugement, Lecture, Manque, Moteur, Options, Reserve, StatJournal, Texte,
    Trouvaille,
};
use crate::journaux_windows::evenement::Filtre;
use crate::journaux_windows::evtx::Bilan;
use crate::journaux_windows::fichiers::{self, BilanFichier, BornesFichiers, ErreurFichier};
use crate::machine::{Constat, alerte, impossible_par, ok, sans_objet};
use crate::modele::resultat::{Couverture, Resultat, nom_sans_piege};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;

/// L'identifiant de l'analyse des journaux (`modele::registre::OUTILS`) : le résultat commun de ses règles.
pub(crate) const ID: &str = "PRO-EVT-001";

pub(crate) const CAT: &str = "Journaux d'événements";

/// D'où viennent les événements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    Dossier(PathBuf),
    Vivant,
}

/// Ce que l'analyse a donné : le jugement de chaque règle, ce que chaque journal a donné, et ce que la source n'a
/// pas pu lire du tout (fichiers au-delà des bornes, entrées illisibles), déjà dans la langue du moment.
#[derive(Debug, Clone)]
pub(crate) struct Analyse {
    pub source: Source,
    pub jugements: Vec<Jugement>,
    pub journaux: Vec<StatJournal>,
    pub etats: Vec<EtatJournal>,
    pub manques_source: Vec<String>,
}

pub(crate) fn texte(t: Texte) -> &'static str {
    if crate::langue::anglais() { t.1 } else { t.0 }
}

/// Une date de journal, à l'heure de l'ordinateur qui lit.
pub(crate) fn date(d: DateTime<Utc>) -> String {
    d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string()
}

// ---------------------------------------------------------------------------------------------------------------
// La source « dossier »
// ---------------------------------------------------------------------------------------------------------------

/// Le journal d'un fichier qui n'en a rien dit (vide, illisible) : d'après son nom (« Microsoft-Windows-PowerShell
/// %4Operational.evtx », ou ceux de `vanguard traces`).
fn journal_du_nom(chemin: &Path) -> Option<String> {
    let nom = chemin.file_stem()?.to_str()?;
    let bas = nom.to_ascii_lowercase();
    let traces = match bas.as_str() {
        "05-security" => Some("Security"),
        "05-system" => Some("System"),
        "05-powershell" => Some("Microsoft-Windows-PowerShell/Operational"),
        "05-defender" => Some("Microsoft-Windows-Windows Defender/Operational"),
        _ => None,
    };
    let journal = traces.map_or_else(|| nom.replace("%4", "/"), str::to_string);
    // Le nom donné par Windows à son journal, s'il est de ceux que lisent les règles (la casse du fichier peut
    // différer).
    Some(
        JOURNAUX
            .iter()
            .find(|j| j.eq_ignore_ascii_case(&journal))
            .map_or(journal, |j| (*j).to_string()),
    )
}

fn erreur_fichier(e: ErreurFichier) -> String {
    match e {
        ErreurFichier::Ouverture(k) => crate::trf!("ouverture impossible ({k})", "cannot open ({k})"),
        ErreurFichier::PasUnFichier => crate::tr!("pas un fichier ordinaire", "not a regular file").to_string(),
        ErreurFichier::PasUnEvtx => crate::tr!("pas un journal .evtx", "not an .evtx log").to_string(),
        ErreurFichier::Lecture(k) => crate::trf!("erreur de lecture ({k})", "read error ({k})"),
    }
}

/// Ce que la lecture d'un fichier n'a pas pu juger : vide quand elle est complète.
fn partiel(f: &BilanFichier, b: &Bilan) -> Vec<String> {
    let nom = f
        .chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut v: Vec<String> = Vec::new();
    let mut compte = |n: u64, fr: &str, en: &str| {
        if n > 0 {
            v.push(if crate::langue::anglais() {
                format!("{n} {en}")
            } else {
                format!("{n} {fr}")
            });
        }
    };
    compte(
        u64::from(b.en_tete_abime),
        "en-tête de fichier abîmé",
        "damaged file header",
    );
    compte(b.morceaux_illisibles, "morceaux illisibles", "unreadable chunks");
    compte(
        b.morceaux_non_verifies,
        "morceaux abîmés (CRC faux), relus sans preuve",
        "damaged chunks (bad CRC), read without proof",
    );
    compte(
        b.morceaux_hors_borne,
        "morceaux au-delà des bornes",
        "chunks beyond the limits",
    );
    compte(
        b.enregistrements_illisibles,
        "enregistrements illisibles",
        "unreadable records",
    );
    compte(
        b.enregistrements_hors_borne,
        "enregistrements au-delà des bornes",
        "records beyond the limits",
    );
    compte(
        b.enregistrements_absents,
        "enregistrements annoncés introuvables",
        "announced records not found",
    );
    compte(b.valeurs_inconnues, "valeurs illisibles", "unreadable values");
    compte(b.chaines_tronquees, "textes coupés", "truncated texts");
    compte(b.substitutions_manquantes, "valeurs manquantes", "missing values");
    compte(f.sans_date, "événements sans date", "events without a date");
    compte(f.sans_identifiant, "événements sans numéro", "events without an ID");
    if v.is_empty() {
        return v;
    }
    vec![crate::trf!("{nom} : {}", "{nom}: {}", v.join(", "))]
}

/// Les états des journaux d'un dossier lu, un par journal et par fichier.
fn etats_du_dossier(fichiers: &[BilanFichier]) -> Vec<EtatJournal> {
    let mut etats = Vec::new();
    for f in fichiers {
        let mut noms = f.journaux.clone();
        if noms.is_empty() {
            noms.extend(journal_du_nom(&f.chemin));
        }
        let lecture = match &f.lecture {
            Ok(b) => Lecture::Lu(partiel(f, b)),
            Err(e) => {
                let nom = f
                    .chemin
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Lecture::Illisible(crate::trf!("{nom} : {}", "{nom}: {}", erreur_fichier(*e)))
            }
        };
        let du_nom = journal_du_nom(&f.chemin);
        let seul = noms.len() <= 1;
        for (i, nom) in noms.iter().enumerate() {
            // Les suites d'un fichier : la sienne (portée par son premier journal) et celles d'origine, qui portent
            // leur journal.
            let suites = if i == 0 { f.suites.clone() } else { Vec::new() };
            etats.push(EtatJournal {
                nom: nom.clone(),
                lecture: lecture.clone(),
                active: None,
                // Le journal du fichier lui-même : seul dans son fichier, ou nommé par lui. Une archive
                // d'événements transférés ne porte que quelques-uns des événements de chacun.
                principal: seul || du_nom.as_deref().is_some_and(|d| d.eq_ignore_ascii_case(nom)),
                suites,
            });
        }
    }
    etats
}

/// Analyse un dossier de journaux .evtx. `Err` : le dossier lui-même ne se lit pas.
/// Le temps laissé au jugement d'un dossier : au-delà, les événements suivants sont lus sans être jugés, comptés, et
/// chaque règle est non vérifiée (un dossier forgé ne fige pas le menu).
const DELAI_DOSSIER: std::time::Duration = std::time::Duration::from_secs(600);

pub(crate) fn analyser_dossier(dossier: &Path, options: &Options) -> std::io::Result<Analyse> {
    analyser_dossier_borne(
        dossier,
        options,
        &BornesFichiers::default(),
        BornesMoteur::default(),
        std::time::Instant::now() + DELAI_DOSSIER,
    )
}

pub(crate) fn analyser_dossier_borne(
    dossier: &Path,
    options: &Options,
    bornes: &BornesFichiers,
    bornes_moteur: BornesMoteur,
    fin: std::time::Instant,
) -> std::io::Result<Analyse> {
    let mut moteur = Moteur::nouveau(REGLES, options.clone(), bornes_moteur);
    let filtre = Filtre {
        depuis: options.depuis,
        ..Filtre::default()
    };
    let mut hors_delai = 0u64;
    let bilan = fichiers::lire_dossier(dossier, &filtre, bornes, |e| {
        if std::time::Instant::now() < fin {
            moteur.recevoir(&e);
        } else {
            hors_delai += 1;
        }
    })?;
    let etats = etats_du_dossier(&bilan.fichiers);
    let mut manques_source = Vec::new();
    if bilan.hors_borne > 0 {
        manques_source.push(crate::trf!(
            "{} fichiers .evtx au-delà des bornes, pas lus",
            "{} .evtx files beyond the limits, not read",
            bilan.hors_borne
        ));
    }
    if hors_delai > 0 {
        manques_source.push(crate::trf!(
            "délai dépassé : {hors_delai} événements lus sans être jugés",
            "time limit exceeded: {hors_delai} events read without being judged"
        ));
    }
    if bilan.entrees_illisibles > 0 {
        manques_source.push(crate::trf!(
            "{} entrées du dossier illisibles",
            "{} unreadable folder entries",
            bilan.entrees_illisibles
        ));
    }
    let journaux = moteur.journaux();
    let mut jugements = moteur.conclure(&etats);
    for j in &mut jugements {
        for m in &manques_source {
            j.manques.push(Manque::Partiel(String::new(), m.clone()));
        }
    }
    Ok(Analyse {
        source: Source::Dossier(dossier.to_path_buf()),
        jugements,
        journaux,
        etats,
        manques_source,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// La source « vivante »
// ---------------------------------------------------------------------------------------------------------------

/// Ce qu'une lecture vivante n'a pas pu juger.
#[cfg(windows)]
fn partiel_vivant(b: &crate::journaux_windows::vivant::BilanVivant) -> Vec<String> {
    use crate::journaux_windows::vivant::RefusVivant;
    let mut v = Vec::new();
    if b.borne_atteinte {
        v.push(
            crate::tr!(
                "trop d'événements : les plus anciens ne sont pas lus",
                "too many events: the oldest are not read"
            )
            .to_string(),
        );
    }
    if b.delai {
        v.push(
            crate::tr!(
                "délai dépassé : les plus anciens ne sont pas lus",
                "time limit exceeded: the oldest are not read"
            )
            .to_string(),
        );
    }
    match b.interrompu {
        Some(RefusVivant::Droits) => {
            v.push(crate::tr!("lecture refusée en cours de route", "reading refused midway").to_string());
        }
        Some(_) => {
            v.push(crate::tr!("lecture interrompue", "reading interrupted").to_string());
        }
        None => {}
    }
    for (n, fr, en) in [
        (b.illisibles, "événements illisibles", "unreadable events"),
        (b.chaines_tronquees, "textes coupés", "truncated texts"),
        (b.sans_date, "événements sans date", "events without a date"),
        (b.sans_identifiant, "événements sans numéro", "events without an ID"),
        (
            b.hors_suites,
            "numéros d'événements sans suite jugée",
            "record numbers without a judged sequence",
        ),
        (
            b.trous_non_confirmes,
            "trous de numéros non revérifiés",
            "record number gaps not rechecked",
        ),
    ] {
        if n > 0 {
            v.push(if crate::langue::anglais() {
                format!("{n} {en}")
            } else {
                format!("{n} {fr}")
            });
        }
    }
    v
}

/// La date d'installation de Windows (InstallDate, secondes depuis 1970, en UTC ; celle que donne aussi
/// Win32_OperatingSystem), lisible sans droits d'administrateur. Une mise à jour de fonctionnalités la récrit : c'est
/// alors la date de cette mise à jour, qui ne crée aucun compte. Rien : illisible, ou nulle.
#[cfg(windows)]
fn date_d_installation() -> Option<DateTime<Utc>> {
    let cle = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()?;
    let secondes: u32 = cle.get_value("InstallDate").ok()?;
    (secondes > 0)
        .then(|| DateTime::from_timestamp(i64::from(secondes), 0))
        .flatten()
}

/// Analyse les journaux de cet ordinateur, jusqu'à `fin`. Sans droits d'administrateur, le journal de sécurité est
/// refusé : ses règles sont non vérifiées, et le disent.
#[cfg(windows)]
pub(crate) fn analyser_vivant(options: &Options, fin: std::time::Instant) -> Analyse {
    use crate::journaux_windows::vivant::{self, BornesVivant, RefusVivant};
    let mut options = options.clone();
    if options.defender_antivirus.is_none() {
        options.defender_antivirus = crate::machine::windows::defender_est_l_antivirus();
    }
    if options.installation.is_none() {
        options.installation = date_d_installation();
    }
    let mut moteur = Moteur::nouveau(REGLES, options.clone(), BornesMoteur::default());
    let mut etats = Vec::new();
    for journal in JOURNAUX {
        let filtre = Filtre {
            journaux: vec![(*journal).to_string()],
            depuis: options.depuis,
            ..Filtre::default()
        };
        let lu = vivant::lire_journal(journal, &filtre, &BornesVivant::default(), fin, |e| moteur.recevoir(&e));
        etats.push(match lu {
            Ok(b) => EtatJournal {
                nom: (*journal).to_string(),
                lecture: Lecture::Lu(partiel_vivant(&b)),
                active: b.active,
                principal: true,
                suites: b.suites,
            },
            Err(r) => EtatJournal {
                nom: (*journal).to_string(),
                lecture: match r {
                    RefusVivant::Droits => Lecture::Refuse,
                    RefusVivant::Absent => Lecture::Absent,
                    RefusVivant::Illisible(code) => Lecture::Illisible(match code {
                        Some(c) => crate::trf!("erreur {c} du service des journaux", "event log service error {c}"),
                        None => crate::tr!("refusé par le service des journaux", "refused by the event log service")
                            .to_string(),
                    }),
                },
                active: None,
                principal: true,
                suites: Vec::new(),
            },
        });
    }
    let journaux = moteur.journaux();
    let jugements = moteur.conclure(&etats);
    Analyse {
        source: Source::Vivant,
        jugements,
        journaux,
        etats,
        manques_source: Vec::new(),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Constats et couverture
// ---------------------------------------------------------------------------------------------------------------

/// La clé d'une alerte déclarée normale.
pub(crate) fn cle_normale(regle: &str, objet: &str) -> String {
    format!("evenements|{regle}|{objet}")
}

/// Une trouvaille qu'une alerte déclarée normale peut taire. Jamais une critique ; jamais non plus le regroupement
/// des blocs que PowerShell juge suspects sans motif reconnu (`jeu::bloc_de_script`) : une seule clé pour tous, la
/// déclarer normale tairait aussi les blocs à venir, d'une attaque que les motifs ne reconnaissent pas. Il ne fait
/// qu'une ligne d'information.
pub(crate) fn taisable(regle: &str, t: &Trouvaille) -> bool {
    t.gravite < Gravite::Critique && !(regle == "EVT-PSH-001" && t.objet.starts_with("avertissement|"))
}

pub(crate) fn niveau(g: Gravite) -> Niveau {
    match g {
        Gravite::Info => Niveau::Info,
        Gravite::Alerte => Niveau::Eleve,
        Gravite::Critique => Niveau::Critique,
    }
}

/// Un nom de journal tel qu'on le dit : un dossier le dit par son fichier.
fn journal_dit(source: &Source, journal: &str) -> String {
    match source {
        Source::Dossier(_) => {
            let fichier = journal.replace('/', "%4");
            crate::trf!("{journal} ({fichier}.evtx)", "{journal} ({fichier}.evtx)")
        }
        Source::Vivant => journal.to_string(),
    }
}

/// Un manque, dans la langue du moment, et sa raison typée.
pub(crate) fn manque(source: &Source, m: &Manque) -> (String, Raison) {
    let ill = |t: &str| Raison::Illisible(t.to_string());
    match m {
        Manque::Absent(j) => (
            match source {
                Source::Dossier(_) => crate::trf!(
                    "journal {} absent du dossier",
                    "log {} missing from the folder",
                    journal_dit(source, j)
                ),
                Source::Vivant => crate::trf!("journal {j} absent de cet ordinateur", "log {j} missing on this computer"),
            },
            Raison::Introuvable,
        ),
        Manque::Refuse(j) => (
            crate::trf!(
                "journal {j} réservé à l'administrateur",
                "log {j} restricted to administrators"
            ),
            Raison::Droits,
        ),
        Manque::Illisible(j, x) => {
            let t = crate::trf!("journal {j} illisible : {x}", "log {j} unreadable: {x}");
            (t.clone(), ill(&t))
        }
        Manque::Desactive(j) => {
            let t = crate::trf!(
                "journal {j} désactivé : il n'écrit plus rien, ce qui est lu est ancien",
                "log {j} disabled: it writes nothing anymore, what is read is old"
            );
            (t.clone(), Raison::Echoue(t))
        }
        Manque::Partiel(j, x) if j.is_empty() => (x.clone(), ill(x)),
        Manque::Partiel(j, x) => {
            let t = crate::trf!("journal {j} lu en partie ({x})", "log {j} partly read ({x})");
            (t.clone(), ill(&t))
        }
        Manque::Vide(j) => {
            let t = crate::trf!(
                "journal {j} lu mais vide sur la période : vidé, remplacé, ou son audit coupé",
                "log {j} read but empty over the period: cleared, replaced, or its auditing turned off"
            );
            (t.clone(), Raison::Echoue(t))
        }
        Manque::VideCalme(j) => {
            let t = crate::trf!(
                "journal {j} présent mais vide sur la période : rien n'y est vérifié (courant si rien ne s'est passé ; un journal vidé ressemble à cela)",
                "log {j} present but empty over the period: nothing in it is checked (common if nothing happened; a cleared log looks the same)"
            );
            (t.clone(), Raison::Echoue(t))
        }
        Manque::Muet { journal, depuis } => {
            let t = crate::trf!(
                "journal {journal} muet depuis le {} alors que d'autres écrivent encore : service des journaux bloqué ou audit coupé",
                "log {journal} silent since {} while others still write: event log service blocked or auditing turned off",
                date(*depuis)
            );
            (t.clone(), Raison::Echoue(t))
        }
        Manque::AuditReduit { journal } => {
            let t = crate::trf!(
                "{journal} : la politique d'audit de ces événements a été réduite pendant la période (4719)",
                "{journal}: the audit policy of these events was reduced during the period (4719)"
            );
            (t.clone(), Raison::Echoue(t))
        }
        Manque::NonVerifies { journal, nombre } => {
            let t = crate::trf!(
                "journal {journal} : {nombre} événements de morceaux abîmés, sans preuve que Windows les a écrits ainsi",
                "log {journal}: {nombre} events from damaged chunks, with no proof Windows wrote them that way"
            );
            (t.clone(), ill(&t))
        }
        Manque::NonAudite { journal, quoi } => {
            let q = texte(*quoi);
            let t = crate::trf!(
                "{journal} : rien ne prouve que Windows écrit ces événements ({q})",
                "{journal}: nothing proves Windows writes these events ({q})"
            );
            (t.clone(), Raison::Echoue(t))
        }
        Manque::ChampCoupe { journal, depuis, quoi } => {
            let q = texte(*quoi);
            let t = crate::trf!(
                "{journal} : plus rien ne prouve ces événements depuis le {} ({q})",
                "{journal}: nothing proves these events since {} ({q})",
                date(*depuis)
            );
            (t.clone(), Raison::Echoue(t))
        }
        Manque::PeriodeCourte { journal, debut } => (
            crate::trf!(
                "journal {journal} lu seulement depuis le {} : plus ancien écrasé, effacé, ou rien écrit",
                "log {journal} only read from {}: older events overwritten, cleared, or never written",
                date(*debut)
            ),
            Raison::Introuvable,
        ),
        Manque::Bornes(n) => {
            let t = crate::trf!(
                "{n} événements au-delà des bornes de l'analyse, pas jugés",
                "{n} events beyond the analysis limits, not judged"
            );
            (t.clone(), Raison::Refuse(t))
        }
        Manque::SansDate(n) => {
            let t = crate::trf!(
                "{n} événements sans date, que les rafales ne peuvent pas placer",
                "{n} events without a date, which bursts cannot place"
            );
            (t.clone(), ill(&t))
        }
        Manque::TrousIllisibles { journal, nombre } => {
            let t = crate::trf!(
                "{journal} : {nombre} numéros manquent là où la lecture a perdu quelque chose (non vérifiés)",
                "{journal}: {nombre} record numbers missing where reading lost something (not verified)"
            );
            (t.clone(), ill(&t))
        }
        Manque::SuiteNonProuvee { journal, nombre } => {
            let t = crate::trf!(
                "{journal} : {nombre} numéros ne tiennent qu'à des morceaux abîmés, la suite n'est pas une preuve",
                "{journal}: {nombre} record numbers rest only on damaged chunks, the sequence is no proof"
            );
            (t.clone(), ill(&t))
        }
        Manque::TrousAuDela { journal, nombre } => {
            let t = crate::trf!(
                "{journal} : {nombre} trous de numéros au-delà des bornes, pas jugés",
                "{journal}: {nombre} record number gaps beyond the limits, not judged"
            );
            (t.clone(), Raison::Refuse(t))
        }
        Manque::DefenderInconnu => (
            crate::tr!(
                "rien ne dit ici si Microsoft Defender est l'antivirus de l'ordinateur : une protection coupée peut venir d'un autre antivirus",
                "nothing here says whether Microsoft Defender is the computer's antivirus: a protection turned off may come from another antivirus"
            )
            .to_string(),
            Raison::Introuvable,
        ),
    }
}

/// Le texte d'une réserve.
pub(crate) fn reserve(r: Reserve) -> &'static str {
    match r {
        Reserve::MorceauAbime => crate::tr!(
            "vient d'un morceau abîmé du journal : un indice, pas une preuve",
            "comes from a damaged chunk of the log: a clue, not a proof"
        ),
        Reserve::CopieAChaud => crate::tr!(
            "fichier copié pendant que Windows écrivait : effacement possible, non concluant",
            "file copied while Windows was writing: possible clearing, not conclusive"
        ),
        Reserve::AvantExport => crate::tr!(
            "fichier exporté : rien ne prouve son origine, un export se fabrique",
            "exported file: nothing proves its origin, an export can be forged"
        ),
        Reserve::AutreAntivirus => crate::tr!(
            "un autre antivirus est inscrit, qui met Defender en retrait ; mais un faux antivirus inscrit fait de même",
            "another antivirus is registered, which puts Defender aside; but a fake registered antivirus does the same"
        ),
        Reserve::ArretInattendu => crate::tr!(
            "un arrêt inattendu au même moment l'explique",
            "an unexpected shutdown at the same time explains it"
        ),
        Reserve::MiseEnRoutePossible => crate::tr!(
            "fait par le compte de l'ordinateur, comme le fait la mise en route de Windows à l'installation ; la date d'installation n'est pas connue ici : si c'était à l'installation, rien d'anormal",
            "done by the computer account, as Windows setup does at installation; the installation date is not known here: if it was at installation, nothing is wrong"
        ),
    }
}

/// Ce que dit une trouvaille, sans ses dates : pourquoi, puis ses détails (compte, programme, adresse), venus du
/// journal et nettoyés (`nom_sans_piege` : ni séquence de terminal ni saut de ligne, coupés).
pub(crate) fn corps(t: &Trouvaille) -> String {
    let mut m = texte(t.pourquoi).to_string();
    let details: Vec<String> = t
        .details
        .iter()
        .map(|(l, v)| format!("{} {}", texte(l.textes()), nom_sans_piege(v, 160)))
        .collect();
    if !details.is_empty() {
        m.push_str(" : ");
        m.push_str(&details.join(", "));
    }
    m
}

/// Le message d'une trouvaille.
fn message(t: &Trouvaille) -> String {
    let mut m = corps(t);
    m.push_str(&match (t.premier, t.dernier) {
        (Some(p), Some(d)) if t.nombre > 1 => crate::trf!(
            " ({} fois, du {} au {})",
            " ({} times, from {} to {})",
            t.nombre,
            date(p),
            date(d)
        ),
        (Some(p), _) => crate::trf!(" (le {})", " (on {})", date(p)),
        _ if t.nombre > 1 => crate::trf!(" ({} fois)", " ({} times)", t.nombre),
        _ => String::new(),
    });
    if !t.ordinateur.is_empty() {
        m.push_str(&crate::trf!(
            " [ordinateur {}]",
            " [computer {}]",
            nom_sans_piege(&t.ordinateur, 64)
        ));
    }
    for r in &t.reserves {
        m.push_str(" — ");
        m.push_str(reserve(*r));
    }
    m
}

/// Ce que les journaux d'une règle ont donné : « Security : 2 261 événements du … au … ».
fn lu(j: &Jugement) -> String {
    let parts: Vec<String> = j
        .journaux
        .iter()
        .filter(|s| s.evenements > 0)
        .map(|s| match (s.premier, s.dernier) {
            (Some(p), Some(d)) => crate::trf!(
                "{} : {} événements du {} au {}",
                "{}: {} events from {} to {}",
                s.nom,
                s.evenements,
                date(p),
                date(d)
            ),
            _ => crate::trf!("{} : {} événements", "{}: {} events", s.nom, s.evenements),
        })
        .collect();
    parts.join(" ; ")
}

/// Les constats d'une analyse, et sa couverture. `est_normale` : l'alerte de cette clé est-elle déclarée normale ?
pub(crate) fn constats(a: &Analyse, est_normale: &dyn Fn(&str) -> bool) -> (Vec<Constat>, Couverture) {
    let (constats, _, couverture) = constats_dates(a, est_normale);
    (constats, couverture)
}

/// Comme `constats`, avec la date de chaque constat (celle du premier événement d'une alerte ; rien pour les autres),
/// dans le même ordre : le rapport remet les alertes dans l'ordre du temps.
fn constats_dates(
    a: &Analyse,
    est_normale: &dyn Fn(&str) -> bool,
) -> (Vec<Constat>, Vec<Option<DateTime<Utc>>>, Couverture) {
    let mut constats = Vec::new();
    let mut dates = Vec::new();
    let mut couverture = Couverture::default();
    for m in &a.manques_source {
        couverture.non_verifies.push(m.clone());
    }
    for j in &a.jugements {
        let r = j.regle;
        let mut tues = 0u64;
        for t in &j.trouvailles {
            // Une alerte critique ne se déclare jamais normale : elle revient toujours.
            if taisable(r.id, t) && est_normale(&cle_normale(r.id, &t.objet)) {
                tues += 1;
                continue;
            }
            let mut c = alerte(CAT, niveau(t.gravite), message(t)).avec_objet(Objet::de("evt", &t.objet));
            c.regle = r.id;
            constats.push(c);
            dates.push(t.premier);
        }
        if j.au_dela > 0 {
            let mut c = alerte(
                CAT,
                niveau(j.au_dela_pire.unwrap_or(Gravite::Alerte)),
                crate::trf!(
                    "{} : {} événements de plus à signaler, au-delà de ce qui est gardé",
                    "{}: {} more events to report, beyond what is kept",
                    r.id,
                    j.au_dela
                ),
            )
            .avec_objet(Objet::de("evt", "au-dela"));
            c.regle = r.id;
            constats.push(c);
            dates.push(None);
        }
        let sujet = texte(r.sujet);
        let mut c = if j.sans_objet && j.manques.is_empty() {
            sans_objet(
                CAT,
                Absence::Logiciel,
                crate::trf!(
                    "{sujet} : Microsoft Defender n'est pas l'antivirus de cet ordinateur.",
                    "{sujet}: Microsoft Defender is not this computer's antivirus."
                ),
            )
        } else if j.verifie() {
            let mut m = if j.trouvailles.len() as u64 > tues || j.au_dela > 0 {
                crate::trf!("{sujet} : lu en entier ({}).", "{sujet}: read in full ({}).", lu(j))
            } else {
                crate::trf!(
                    "{sujet} : rien trouvé dans ce qui a été lu ({}).",
                    "{sujet}: nothing found in what was read ({}).",
                    lu(j)
                )
            };
            if let Some(l) = r.limite {
                m.push(' ');
                m.push_str(&crate::trf!("Limite : {}.", "Limit: {}.", texte(l)));
            }
            // Un réglage prouvé par un champ du fichier lui-même : un fichier rapporté se fabrique.
            if matches!(a.source, Source::Dossier(_))
                && r.volets.iter().any(|v| matches!(v.audit, Audit::PreuveChamp { .. }))
            {
                m.push(' ');
                m.push_str(crate::tr!(
                    "Réserve : la preuve que ce réglage est allumé vient des fichiers lus, qui ne prouvent pas leur origine.",
                    "Caveat: the proof that this setting is on comes from the files read, which do not prove their origin."
                ));
            }
            if tues > 0 {
                m.push(' ');
                m.push_str(&crate::trf!(
                    "{tues} alertes déclarées normales, tues.",
                    "{tues} alerts declared normal, silenced."
                ));
            }
            couverture.verifies += 1;
            ok(CAT, m)
        } else {
            let textes: Vec<(String, Raison)> = j.manques.iter().map(|m| manque(&a.source, m)).collect();
            let mut liste: Vec<String> = Vec::new();
            for (t, _) in &textes {
                if !liste.contains(t) {
                    liste.push(t.clone());
                }
            }
            for t in &liste {
                couverture.non_verifies.push(format!("{} : {t}", r.id));
            }
            let raison = textes.into_iter().next().map_or(Raison::NonPrecisee, |(_, r)| r);
            let deja = if j.trouvailles.is_empty() {
                String::new()
            } else {
                crate::tr!(" (ses alertes restent)", " (its alerts stand)").to_string()
            };
            impossible_par(
                CAT,
                raison,
                crate::trf!(
                    "{sujet} : non vérifié{deja} — {}.",
                    "{sujet}: not verified{deja} — {}.",
                    liste.join(" ; ")
                ),
            )
        };
        c.regle = r.id;
        constats.push(c.avec_objet(Objet::de("evt", "couverture")));
        dates.push(None);
    }
    (constats, dates, couverture)
}

/// Les constats d'une analyse pour le bilan (WIN-JRN-003, un client du moteur parmi d'autres) : chaque alerte, son
/// identifiant `EVT-` devant (le bilan pose le sien sur tous ses constats) ; les règles vérifiées en un seul constat
/// sain ; les règles non vérifiées regroupées par ce qui leur a manqué (un journal de sécurité refusé en rend huit non
/// vérifiées d'un coup), chacune avec sa raison typée : jamais un sain pour ce qui n'a pas été lu.
pub(crate) fn constats_du_bilan(a: &Analyse, est_normale: &dyn Fn(&str) -> bool) -> Vec<Constat> {
    let (tous, _) = constats(a, est_normale);
    let couverture = Objet::de("evt", "couverture");
    let mut sortie: Vec<Constat> = tous
        .into_iter()
        .filter(|c| c.objet != couverture)
        .map(|mut c| {
            c.message = crate::trf!("{} : {}", "{}: {}", c.regle, c.message);
            c
        })
        .collect();
    let mut verifiees: Vec<&str> = Vec::new();
    let mut sans: Vec<&str> = Vec::new();
    // (ce qui a manqué, sa raison, les règles) : une entrée par manque identique.
    let mut non_verifiees: Vec<(String, Raison, Vec<String>)> = Vec::new();
    for c in &a.manques_source {
        non_verifiees.push((c.clone(), Raison::Illisible(c.clone()), Vec::new()));
    }
    for j in &a.jugements {
        let r = j.regle;
        if j.sans_objet && j.manques.is_empty() {
            sans.push(r.id);
            continue;
        }
        if j.verifie() {
            verifiees.push(r.id);
            continue;
        }
        let textes: Vec<(String, Raison)> = j.manques.iter().map(|m| manque(&a.source, m)).collect();
        let mut liste: Vec<String> = Vec::new();
        for (t, _) in &textes {
            if !liste.contains(t) {
                liste.push(t.clone());
            }
        }
        let cle = liste.join(" ; ");
        let raison = textes.into_iter().next().map_or(Raison::NonPrecisee, |(_, r)| r);
        let regle = format!("{} ({})", r.id, texte(r.sujet));
        match non_verifiees.iter_mut().find(|(c, x, _)| *c == cle && *x == raison) {
            Some((_, _, regles)) => regles.push(regle),
            None => non_verifiees.push((cle, raison, vec![regle])),
        }
    }
    if !verifiees.is_empty() {
        sortie.push(ok(
            CAT,
            crate::trf!(
                "Journaux d'événements lus en entier pour {} règle(s) : {}.",
                "Event logs read in full for {} rule(s): {}.",
                verifiees.len(),
                verifiees.join(", ")
            ),
        ));
    }
    if !sans.is_empty() {
        sortie.push(sans_objet(
            CAT,
            Absence::Logiciel,
            crate::trf!(
                "{} : Microsoft Defender n'est pas l'antivirus de cet ordinateur.",
                "{}: Microsoft Defender is not this computer's antivirus.",
                sans.join(", ")
            ),
        ));
    }
    for (manque, raison, regles) in non_verifiees {
        let message = if regles.is_empty() {
            crate::trf!("Non vérifié : {manque}.", "Not verified: {manque}.")
        } else {
            crate::trf!(
                "Non vérifié — {manque} : {}.",
                "Not verified — {manque}: {}.",
                regles.join(" ; ")
            )
        };
        sortie.push(impossible_par(CAT, raison, message));
    }
    sortie
}

/// Le résultat commun d'une analyse commencée à `debut`.
pub(crate) fn resultat(
    a: &Analyse,
    debut: (DateTime<Utc>, std::time::Instant),
    est_normale: &dyn Fn(&str) -> bool,
) -> Resultat {
    let (constats, dates, couverture) = constats_dates(a, est_normale);
    let mut r = Resultat::nouveau(ID, debut, &constats, couverture);
    for (c, d) in r.constats.iter_mut().zip(dates) {
        c.date = d.map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    r
}
