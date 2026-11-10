//! L'écran « État de l'antivirus » (menu Antivirus et protection › Analyse antivirus, et
//! `vanguard antivirus --etat`) : le moteur utilisé, les bases et leur date (MalwareBazaar, base ClamAV installée et
//! sa version, règles YARA), ce que le moteur ne lit pas, les choix du second avis et des PUA, et l'état du temps
//! réel des fichiers. Rien n'est lancé ni changé : des fichiers lus, les en-têtes des bases seuls. Le détail de ce que
//! la base ClamAV ne lit pas demande de la charger (quelques secondes) : demandé, jamais imposé.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::time::Duration;

use crate::protection::clamav::base::{self, Apercu, Base};
use crate::protection::clamav::commun::NonLu;
use crate::ui::*;

mod resultat;

/// Les copies de MalwareBazaar se rafraîchissent chaque semaine (liste complète) et chaque jour (récentes) : plus
/// vieilles, les logiciels malveillants des derniers jours n'y sont pas reconnus.
const SEMAINE: Duration = Duration::from_hours(7 * 24);
const JOUR: Duration = Duration::from_hours(24);

/// Le détail de la base ClamAV (ce qu'elle ne lit pas, par raison) : le charger demande quelques secondes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Detail {
    /// Ligne de commande sans `--detail` : rien de chargé.
    Non,
    /// `--detail` : chargé.
    Oui,
    /// Le menu : la question est posée, non par défaut.
    Demander,
}

/// Le second avis de ClamAV tel qu'il tournerait à la prochaine analyse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(unix),
    allow(
        dead_code,
        reason = "clamscan n'est lancé que sous Linux ; ses états restent pour les essais communs"
    )
)]
#[cfg_attr(unix, allow(dead_code, reason = "Defender n'est le second avis que sous Windows"))]
enum SecondAvis {
    Pret,
    Absent,
    Coupe,
    /// Windows : le second avis est Microsoft Defender, clamscan n'est pas lancé.
    Defender,
}

/// Ce que l'écran a relevé, lu une fois puis mis en mots par `lignes` (pure, essayée).
struct Releve {
    moteur: String,
    /// Windows : Defender coupé sans choix noté, ou son état illisible (`PlaceDuMoteur::NonVerifie`).
    manque_du_moteur: Option<String>,
    /// L'âge des copies gardées de MalwareBazaar : liste complète, récentes (48 heures).
    complete: Option<Duration>,
    recentes: Option<Duration>,
    /// La raison de la base ClamAV absente ou refusée, telle que le moteur la dirait.
    clamav: Result<Apercu, String>,
    yara: Result<(usize, usize), String>,
    commit_yara: Option<&'static str>,
    second_avis: SecondAvis,
    pua: bool,
    temps_reel: String,
}

/// L'écran entier.
pub(crate) fn montrer(detail: Detail) {
    titre(tr!("État de l'antivirus", "Antivirus status"));
    let r = relever();
    let a_une_base = r.clamav.is_ok();
    for (nom, lignes) in lignes(&r, chrono::Local::now()) {
        section(nom);
        for l in lignes {
            afficher_aligne("  ", &l, 4, "");
        }
    }
    if !a_une_base {
        return;
    }
    let charger = match detail {
        Detail::Non => false,
        Detail::Oui => true,
        Detail::Demander => {
            println!();
            demander_ou_defaut(tr!(
                "  Compter ce que la base ClamAV a d'écarté (environ 10 s) ? [o/N] : ",
                "  Count what the ClamAV database has skipped (about 10 s)? [y/N]: "
            ))
            .oui()
        }
    };
    if !charger {
        return;
    }
    section(tr!(
        "Base ClamAV : ce qui n'est pas appliqué",
        "ClamAV database: what is not applied"
    ));
    trp!(
        "  {GRIS}Lecture de la base ClamAV…{RESET}",
        "  {GRIS}Reading the ClamAV database…{RESET}"
    );
    let lignes = match crate::protection::moteur::base_a_la_demande() {
        Ok(b) => lignes_du_detail(b),
        Err(raison) => vec![trf!("Non vérifié : {raison}.", "Not verified: {raison}.")],
    };
    for l in lignes {
        afficher_aligne("  ", &l, 4, "");
    }
}

/// `vanguard antivirus --etat --json` : l'état en résultat commun, sans rien charger ni lancer (comme l'écran sans
/// `--detail`). Pas versé au rapport : `examens/PRO-ANV-001.json` garde la dernière analyse, et l'état l'écraserait :
/// un logiciel malveillant trouvé disparaîtrait du rapport.
pub(crate) fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = relever();
    let maintenant = chrono::Local::now();
    let section_des_bases = tr!("Bases et leur date", "Databases and their date");
    let notes = lignes(&r, maintenant)
        .into_iter()
        .filter(|(nom, _)| *nom != section_des_bases)
        .flat_map(|(nom, l)| l.into_iter().map(move |l| trf!("{nom} : {l}", "{nom}: {l}")))
        .collect();
    let etat = resultat::Etat {
        bases: bases(&r, maintenant),
        notes,
        manques: r.manque_du_moteur.into_iter().collect(),
    };
    println!("{}", crate::modele::resultat::json(&resultat::resultat(&etat, debut)));
}

fn relever() -> Releve {
    let cache = crate::socle::cache::age;
    let yara = crate::protection::yara::regles()
        .map(|r| (r.nombre(), r.refus().len()))
        .map_err(str::to_string);
    #[cfg(unix)]
    let second_avis = if !crate::parametres::second_avis_clamav() {
        SecondAvis::Coupe
    } else if crate::protection::antivirus::clamscan_present() {
        SecondAvis::Pret
    } else {
        SecondAvis::Absent
    };
    #[cfg(windows)]
    let second_avis = SecondAvis::Defender;
    #[cfg(unix)]
    let manque_du_moteur = None;
    #[cfg(windows)]
    let manque_du_moteur = {
        use crate::protection::antivirus::PlaceDuMoteur;
        let place = crate::protection::antivirus::place_actuelle();
        (place == PlaceDuMoteur::NonVerifie).then(|| place.ce_qui_manque().to_string())
    };
    Releve {
        moteur: moteur(),
        manque_du_moteur,
        complete: cache(("malwarebazaar", "complete.zip")),
        recentes: cache(("malwarebazaar", "recentes.txt")),
        clamav: base::en_tetes().map_err(|r| r.to_string()),
        yara,
        commit_yara: crate::protection::yara::commit_des_regles(),
        second_avis,
        pua: crate::parametres::pua(),
        temps_reel: temps_reel(),
    }
}

#[cfg(unix)]
fn moteur() -> String {
    tr!(
        "Le moteur de Vanguard fait les analyses à la demande : empreintes de MalwareBazaar, règles YARA, base ClamAV installée (lue par Vanguard, sans clamscan) et heuristiques. Le temps réel des fichiers tient en 128 Mio : règles YARA, heuristiques et empreintes récentes (48 heures) ; la base ClamAV sert aux analyses à la demande et à la passe horaire.",
        "The Vanguard engine runs on-demand scans: MalwareBazaar fingerprints, YARA rules, the installed ClamAV database (read by Vanguard, without clamscan) and heuristics. Real-time file scanning fits in 128 MiB: YARA rules, heuristics and recent fingerprints (48 hours); the ClamAV database serves on-demand scans and the hourly pass."
    )
    .to_string()
}

#[cfg(windows)]
fn moteur() -> String {
    use crate::protection::antivirus::PlaceDuMoteur;
    let place = crate::protection::antivirus::place_actuelle();
    let mut t = match place {
        PlaceDuMoteur::SecondAvis => tr!(
            "Microsoft Defender protège en temps réel et analyse d'abord ; le moteur de Vanguard (empreintes, règles YARA, base ClamAV installée, heuristiques) donne un second avis à chaque analyse.",
            "Microsoft Defender protects in real time and scans first; the Vanguard engine (fingerprints, YARA rules, installed ClamAV database, heuristics) gives a second opinion on each scan."
        )
        .to_string(),
        PlaceDuMoteur::Principal | PlaceDuMoteur::NonVerifie => tr!(
            "Le moteur de Vanguard analyse d'abord (empreintes, règles YARA, base ClamAV installée, heuristiques) ; Defender donne un second avis, à la demande.",
            "The Vanguard engine scans first (fingerprints, YARA rules, installed ClamAV database, heuristics); Defender gives a second opinion, on demand."
        )
        .to_string(),
    };
    let manque = place.ce_qui_manque();
    if !manque.is_empty() {
        t.push(' ');
        t.push_str(manque);
    }
    t
}

#[cfg(target_os = "linux")]
pub(crate) fn temps_reel() -> String {
    crate::machine::linux::veilleur::phrase_des_fichiers()
}

#[cfg(windows)]
pub(crate) fn temps_reel() -> String {
    tr!(
        "Temps réel des fichiers : celui de Microsoft Defender. Celui de Vanguard n'existe pas encore sous Windows.",
        "Real-time file scanning: Microsoft Defender's. Vanguard's does not exist on Windows yet."
    )
    .to_string()
}

/// La date d'une copie de `age`, vue `maintenant` (« 07/11/2026 »).
fn date_d_age(age: Duration, maintenant: chrono::DateTime<chrono::Local>) -> String {
    let age = chrono::Duration::from_std(age).unwrap_or(chrono::Duration::MAX);
    maintenant
        .checked_sub_signed(age)
        .map_or_else(|| "?".to_string(), |d| d.format("%d/%m/%Y").to_string())
}

/// Les lignes des bases, chacune avec son jugement : `true` quand la source est là, lisible, entière et à jour ;
/// `false` : le moteur analyse sans elle, ou sans sa part récente (non vérifié pour `--json`).
fn bases(r: &Releve, maintenant: chrono::DateTime<chrono::Local>) -> Vec<(bool, String)> {
    let mut bases = Vec::new();
    bases.push(match (r.complete, r.recentes) {
        (None, None) => (
            false,
            tr!(
                "MalwareBazaar : aucune copie gardée ; ses empreintes ne sont pas vérifiées. La clé abuse.ch (vanguard parametres abuse.ch) les fait télécharger.",
                "MalwareBazaar: no copy kept; its fingerprints are not checked. The abuse.ch key (vanguard settings abuse.ch) has them downloaded."
            )
            .to_string(),
        ),
        (c, rec) => {
            let date = |a: Option<Duration>| {
                a.map_or_else(
                    || tr!("aucune", "none").to_string(),
                    |a| date_d_age(a, maintenant),
                )
            };
            let a_jour = c.is_some_and(|a| a <= SEMAINE) && rec.is_some_and(|a| a <= JOUR);
            (
                a_jour,
                trf!(
                    "MalwareBazaar : liste complète du {}, récentes (48 heures) du {}.",
                    "MalwareBazaar: full list from {}, recent ones (48 hours) from {}.",
                    date(c),
                    date(rec)
                ),
            )
        }
    });
    match &r.clamav {
        Ok(a) => bases.push((
            !a.bases.is_empty() && a.bases.iter().all(|(_, e)| e.is_some()),
            base_clamav(a),
        )),
        Err(raison) => bases.push((
            false,
            trf!(
                "Base ClamAV : non lue ({raison}) ; le moteur analyse avec les empreintes, YARA et les heuristiques seulement.",
                "ClamAV database: not read ({raison}); the engine scans with fingerprints, YARA and heuristics only."
            ),
        )),
    }
    let commit = r
        .commit_yara
        .map(|c| trf!(", commit {c}", ", commit {c}"))
        .unwrap_or_default();
    bases.push(match r.yara {
        Ok((n, 0)) => (
            true,
            trf!(
                "Règles YARA : {n} de ReversingLabs{commit}, intégrées à Vanguard {} ; toutes appliquées.",
                "YARA rules: {n} from ReversingLabs{commit}, built into Vanguard {}; all applied.",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        Ok((n, refus)) => (
            false,
            trf!(
                "Règles YARA : {n} de ReversingLabs{commit}, intégrées à Vanguard {} ; {refus} refusée(s) par le moteur, non vérifiée(s).",
                "YARA rules: {n} from ReversingLabs{commit}, built into Vanguard {}; {refus} refused by the engine, not checked.",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        Err(ref e) => (
            false,
            trf!(
                "Règles YARA : inutilisables ({e}), non vérifiées.",
                "YARA rules: unusable ({e}), not checked."
            ),
        ),
    });
    bases
}

/// Les sections de l'écran et leurs lignes (à envelopper), d'après `r`, à la date `maintenant`.
fn lignes(r: &Releve, maintenant: chrono::DateTime<chrono::Local>) -> Vec<(&'static str, Vec<String>)> {
    let bases: Vec<String> = bases(r, maintenant).into_iter().map(|(_, l)| l).collect();
    let mut non_lus = vec![
        tr!(
            "Formats reconnus mais pas ouverts (7z, RAR, CAB, ISO, PDF, xz, zstd…) : le fichier est dit « non vérifié », jamais sain. clamscan, en second avis, ouvre 7z et RAR.",
            "Formats recognized but not opened (7z, RAR, CAB, ISO, PDF, xz, zstd…): the file is reported “not verified”, never clean. clamscan, as a second opinion, opens 7z and RAR."
        )
        .to_string(),
        // B5 : l'heuristique du programme sans signature ne regarde que la présence de la table Authenticode.
        tr!(
            "Signature des programmes Windows : signature présente, non vérifiée (ni sa chaîne ni le contenu du fichier). Une signature copiée d'un autre programme fait taire « programme sans signature ».",
            "Windows program signatures: signature present, not verified (neither its chain nor the file's content). A signature copied from another program silences “unsigned program”."
        )
        .to_string(),
    ];
    if let Ok(a) = &r.clamav {
        non_lus.extend(non_lus_de_l_apercu(a));
    }
    let second = match r.second_avis {
        SecondAvis::Pret => tr!(
            "Second avis ClamAV (clamscan) : oui, lancé après le moteur de Vanguard à chaque analyse.",
            "ClamAV second opinion (clamscan): yes, run after the Vanguard engine on each scan."
        ),
        SecondAvis::Absent => tr!(
            "Second avis ClamAV (clamscan) : oui, mais clamscan n'est pas installé. Facultatif : le moteur de Vanguard analyse sans lui.",
            "ClamAV second opinion (clamscan): yes, but clamscan is not installed. Optional: the Vanguard engine scans without it."
        ),
        SecondAvis::Coupe => tr!(
            "Second avis ClamAV (clamscan) : non, votre choix. Ce que clamscan lit de plus (bytecode, 7z, RAR) n'est pas vérifié.",
            "ClamAV second opinion (clamscan): no, your choice. What clamscan reads on top (bytecode, 7z, RAR) is not checked."
        ),
        SecondAvis::Defender => tr!(
            "Second avis : Microsoft Defender ; clamscan n'est pas lancé sous Windows.",
            "Second opinion: Microsoft Defender; clamscan is not run on Windows."
        ),
    };
    let pua = if r.pua {
        tr!(
            "Programmes indésirables (PUA) : signalés aux analyses à la demande, votre choix ; jamais mis en quarantaine tout seuls.",
            "Unwanted programs (PUA): reported by on-demand scans, your choice; never quarantined by themselves."
        )
    } else {
        tr!(
            "Programmes indésirables (PUA) : sautés, comme par défaut.",
            "Unwanted programs (PUA): skipped, as by default."
        )
    };
    let changer = tr!(
        "Les changer : vanguard parametres second-avis oui|non, vanguard parametres pua oui|non, ou le menu Paramètres.",
        "Change them: vanguard settings second-opinion yes|no, vanguard settings pua yes|no, or the Settings menu."
    );
    vec![
        (tr!("Moteur", "Engine"), vec![r.moteur.clone()]),
        (tr!("Bases et leur date", "Databases and their date"), bases),
        (
            tr!("Ce que le moteur ne lit pas", "What the engine does not read"),
            non_lus,
        ),
        (
            tr!("Vos choix", "Your choices"),
            vec![second.to_string(), pua.to_string(), changer.to_string()],
        ),
        (tr!("Temps réel", "Real time"), vec![r.temps_reel.clone()]),
    ]
}

/// La base ClamAV installée, d'après ses en-têtes : chaque .cvd et .cld, sa version et sa date ; les fichiers à part.
fn base_clamav(a: &Apercu) -> String {
    let bases: Vec<String> = a
        .bases
        .iter()
        .map(|(nom, e)| match e {
            Some(e) => trf!(
                "{} version {} du {}",
                "{} version {} from {}",
                affichable(nom),
                e.version,
                affichable(e.date.trim())
            ),
            None => trf!("{} (en-tête illisible)", "{} (unreadable header)", affichable(nom)),
        })
        .collect();
    let mut t = trf!(
        "Base ClamAV ({}) : {}.",
        "ClamAV database ({}): {}.",
        chemin_affichable(&a.dossier),
        if bases.is_empty() {
            tr!("aucun .cvd ni .cld", "no .cvd or .cld").to_string()
        } else {
            bases.join(", ")
        }
    );
    if !a.a_part.is_empty() {
        let noms: Vec<String> = a.a_part.iter().map(|n| affichable(n)).collect();
        t.push(' ');
        t.push_str(&trf!("À part : {}.", "Separate files: {}.", resume(&noms, 4, ", ")));
    }
    t
}

/// Ce que les en-têtes disent déjà de ce qui n'est pas lu : le bytecode (tout bytecode.cvd), les bases illisibles.
fn non_lus_de_l_apercu(a: &Apercu) -> Vec<String> {
    let mut t = Vec::new();
    let bytecode: u64 = a
        .bases
        .iter()
        .filter(|(nom, _)| nom.starts_with("bytecode."))
        .filter_map(|(_, e)| e.as_ref().map(|e| e.signatures))
        .max()
        .unwrap_or(0);
    if bytecode > 0 {
        t.push(trf!(
            "Bytecode ClamAV (.cbc) : {bytecode} programme(s) de bytecode.cvd, jamais lancés par Vanguard ; clamscan, en second avis, les lance.",
            "ClamAV bytecode (.cbc): {bytecode} program(s) from bytecode.cvd, never run by Vanguard; clamscan, as a second opinion, runs them."
        ));
    }
    let illisibles: Vec<String> = a
        .bases
        .iter()
        .filter(|(_, e)| e.is_none())
        .map(|(n, _)| affichable(n))
        .collect();
    if !illisibles.is_empty() {
        t.push(trf!(
            "Bases écartées : {} ({}), en-tête illisible.",
            "Skipped databases: {} ({}), unreadable header.",
            illisibles.len(),
            resume(&illisibles, 4, ", ")
        ));
    }
    t.push(
        tr!(
            "Les signatures écartées, comptées par raison : vanguard antivirus --etat --detail (lit toute la base, environ 10 secondes).",
            "Skipped signatures, counted by reason: vanguard antivirus --status --detail (reads the whole database, about 10 seconds)."
        )
        .to_string(),
    );
    t
}

/// Une raison de signature non appliquée, en quelques mots.
fn raison_non_lue(r: NonLu) -> &'static str {
    match r {
        NonLu::Pua => tr!(
            "programmes indésirables (PUA), sautés par choix",
            "unwanted programs (PUA), skipped by choice"
        ),
        NonLu::Ignoree => tr!("ignorées par la base elle-même", "ignored by the database itself"),
        NonLu::Niveau => tr!(
            "écrites pour une autre version de ClamAV",
            "written for another ClamAV version"
        ),
        // Compté en lignes de .cbc (un programme en fait plusieurs) : l'en-tête de bytecode.cvd compte les programmes.
        NonLu::Bytecode => tr!(
            "bytecode (.cbc, en lignes), jamais lancé",
            "bytecode (.cbc, in lines), never run"
        ),
        NonLu::Conteneurs => tr!(
            "métadonnées d'archives (.cdb, .zmd, .rmd)",
            "archive metadata (.cdb, .zmd, .rmd)"
        ),
        NonLu::AutreFormat => tr!(
            "icônes, certificats, imports, réglages",
            "icons, certificates, imports, settings"
        ),
        NonLu::Hameconnage => tr!(
            "hameçonnage : des adresses, pas des fichiers",
            "phishing: addresses, not files"
        ),
        NonLu::Yara => tr!(
            "règles YARA de la base (Vanguard a les siennes)",
            "YARA rules of the database (Vanguard has its own)"
        ),
        NonLu::Pcre => tr!("expressions rationnelles (PCRE)", "regular expressions (PCRE)"),
        NonLu::Forme => tr!("formes de signature non lues", "signature forms not read"),
        NonLu::Cible => tr!(
            "cibles préparées autrement (HTML, courriel…)",
            "targets prepared differently (HTML, mail…)"
        ),
        NonLu::Condition => tr!("conditions de cible non jugées", "target conditions not judged"),
        NonLu::Comptage => tr!("comptages d'occurrences", "occurrence counts"),
        NonLu::Bornes => tr!("refusées par les bornes du moteur", "refused by the engine's bounds"),
        NonLu::Illisible => tr!("lignes illisibles", "unreadable lines"),
        NonLu::Mode => tr!("laissées par ce mode", "left out by this mode"),
    }
}

/// Le détail de la base chargée : ce qui n'est pas appliqué, par raison, les approchées, les hors liste, les écartés.
fn lignes_du_detail(b: &Base) -> Vec<String> {
    let c = &b.signatures.comptes;
    let mut t = vec![trf!(
        "{} signature(s) non appliquée(s), hors celles que la base ignore, les PUA sautées et celles de ce mode :",
        "{} signature(s) not applied, besides those the database ignores, skipped PUA and those of this mode:",
        c.manquees()
    )];
    for (&raison, n) in &c.non_lues {
        t.push(format!("  · {} : {n}", raison_non_lue(raison)));
    }
    if c.approchees > 0 {
        t.push(trf!(
            "{} signature(s) appliquée(s) en partie : un saut sans fin borné, un écart plus grand échappe.",
            "{} signature(s) applied in part: an open-ended gap is bounded, a wider gap escapes.",
            c.approchees
        ));
    }
    if c.hors_liste > 0 {
        t.push(trf!(
            "{} membre(s) absent(s) de la liste de leur base : ni crus ni lus.",
            "{} member(s) missing from their database's list: neither trusted nor read.",
            c.hors_liste
        ));
    }
    for (nom, raison) in &b.ecartes {
        t.push(trf!(
            "Écarté : {} ({}).",
            "Skipped: {} ({}).",
            affichable(nom),
            affichable(raison)
        ));
    }
    t
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::clamav::cvd::EnTete;

    fn en_tete(version: u32, signatures: u64) -> EnTete {
        EnTete {
            date: "07 Nov 2026 06-24 +0000".into(),
            version,
            signatures,
            niveau: 90,
        }
    }

    fn releve(clamav: Result<Apercu, String>) -> Releve {
        Releve {
            moteur: "moteur".into(),
            manque_du_moteur: None,
            complete: Some(Duration::from_hours(48)),
            recentes: None,
            clamav,
            yara: Ok((308, 0)),
            commit_yara: Some("e0a0be54aa1e"),
            second_avis: SecondAvis::Absent,
            pua: false,
            temps_reel: "Temps réel des fichiers : arrêté.".into(),
        }
    }

    fn maintenant() -> chrono::DateTime<chrono::Local> {
        use chrono::TimeZone;
        chrono::Local.with_ymd_and_hms(2026, 11, 9, 12, 0, 0).unwrap()
    }

    fn tout(r: &Releve) -> String {
        lignes(r, maintenant())
            .into_iter()
            .flat_map(|(s, l)| std::iter::once(s.to_string()).chain(l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Les cinq parties demandées, les dates et versions des bases, le bytecode compté depuis son en-tête, une base
    /// illisible écartée, et un nom piégé de la base rendu affichable.
    #[test]
    fn ecran_complet_d_apres_les_en_tetes() {
        let a = Apercu {
            dossier: "/var/lib/clamav".into(),
            bases: vec![
                ("bytecode.cvd".into(), Some(en_tete(339, 99))),
                ("daily.cld".into(), Some(en_tete(27_812, 2_100_000))),
                ("main.cvd".into(), Some(en_tete(62, 3_300_000))),
                ("x\u{1b}[2J.cvd".into(), None),
            ],
            a_part: vec!["local.hdb".into()],
        };
        let t = tout(&releve(Ok(a)));
        for attendu in [
            "Moteur",
            "liste complète du 07/11/2026",
            "récentes (48 heures) du aucune",
            "main.cvd version 62 du 07 Nov 2026",
            "daily.cld version 27812",
            "À part : local.hdb",
            "308 de ReversingLabs, commit e0a0be54aa1e",
            "toutes appliquées",
            "7z, RAR",
            "99 programme(s) de bytecode.cvd",
            "Bases écartées : 1",
            "--detail",
            "clamscan n'est pas installé",
            "PUA) : sautés",
            "vanguard parametres pua",
            "Temps réel des fichiers : arrêté.",
            "signature présente, non vérifiée",
        ] {
            assert!(t.contains(attendu), "{attendu} manque dans :\n{t}");
        }
        assert!(!t.contains('\u{1b}'), "nom de base non rendu affichable");
    }

    /// Sans base, l'écran le dit et ce qui reste au moteur ; des règles YARA refusées ne passent pas pour appliquées.
    #[test]
    fn sans_base_et_regles_refusees() {
        let mut r = releve(Err("aucune base ClamAV sur l'ordinateur".into()));
        r.yara = Ok((308, 2));
        r.second_avis = SecondAvis::Coupe;
        r.pua = true;
        let t = tout(&r);
        assert!(t.contains("non lue (aucune base ClamAV sur l'ordinateur)"), "{t}");
        assert!(t.contains("empreintes, YARA et les heuristiques seulement"), "{t}");
        assert!(t.contains("2 refusée(s) par le moteur, non vérifiée(s)"), "{t}");
        assert!(!t.contains("toutes appliquées"), "{t}");
        assert!(t.contains("non, votre choix"), "{t}");
        assert!(t.contains("signalés aux analyses à la demande"), "{t}");
        assert!(!t.contains("bytecode.cvd"), "{t}");
    }

    /// Une base n'est vérifiée (`--json`) que là, lisible, entière et à jour : MalwareBazaar trop vieille (liste
    /// complète de plus d'une semaine, récentes de plus d'un jour), un en-tête ClamAV illisible, des règles refusées ou
    /// une base absente ne le sont jamais.
    #[test]
    fn bases_selon_leur_age() {
        let a_jour = |r: &Releve| bases(r, maintenant()).iter().map(|(v, _)| *v).collect::<Vec<_>>();
        let apercu = |lisible: bool| Apercu {
            dossier: "/var/lib/clamav".into(),
            bases: vec![
                ("main.cvd".into(), Some(en_tete(62, 3_300_000))),
                ("daily.cld".into(), lisible.then(|| en_tete(27_812, 2_100_000))),
            ],
            a_part: Vec::new(),
        };
        let mut r = releve(Ok(apercu(true)));
        r.recentes = Some(Duration::from_hours(2));
        assert_eq!(a_jour(&r), [true, true, true]);
        r.complete = Some(Duration::from_hours(24 * 8));
        assert!(!a_jour(&r)[0]);
        r.complete = Some(Duration::from_hours(48));
        r.recentes = Some(Duration::from_hours(30));
        assert!(!a_jour(&r)[0]);
        r.recentes = None;
        assert!(!a_jour(&r)[0]);
        let mut r = releve(Ok(apercu(false)));
        r.yara = Ok((308, 1));
        assert_eq!(a_jour(&r)[1..], [false, false]);
        let mut r = releve(Ok(Apercu {
            bases: Vec::new(),
            ..apercu(true)
        }));
        r.yara = Err("essai".into());
        assert_eq!(a_jour(&r)[1..], [false, false]);
        r.complete = None;
        assert!(!a_jour(&r)[0]);
        assert!(!a_jour(&releve(Err("aucune base".into())))[1]);
    }

    #[test]
    fn date_d_une_copie() {
        assert_eq!(date_d_age(Duration::from_secs(0), maintenant()), "09/11/2026");
        assert_eq!(date_d_age(Duration::from_hours(24 * 9), maintenant()), "31/10/2026");
        assert_eq!(date_d_age(Duration::MAX, maintenant()), "?");
    }

    /// Les textes affichés tels quels (non enveloppés) tiennent dans la largeur, et le détail compte chaque raison
    /// avec ses mots, sans laisser passer de nom de base piégé.
    #[test]
    fn largeur_et_detail() {
        assert_eq!(
            crate::ui::textes_trop_larges(include_str!("etat_antivirus.rs")),
            Vec::<String>::new()
        );
        for r in [NonLu::Bytecode, NonLu::Pcre, NonLu::Bornes, NonLu::Mode] {
            assert!(raison_non_lue(r).chars().count() <= 60, "{r:?}");
        }
    }
}
