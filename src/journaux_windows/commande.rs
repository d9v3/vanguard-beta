//! `vanguard journaux-windows [--dossier D] [--jours N] [--json]` : les règles `EVT-` sur les journaux de Windows,
//! d'un dossier de .evtx (sous tout système) ou de cet ordinateur (sous Windows), puis « Que s'est-il passé ? » :
//! le verdict de chaque règle, les alertes datées dans l'ordre du temps, la période que chaque journal a vraiment
//! couverte et ce qui est resté au-delà des bornes. Lecture seule : le résultat est versé (`examens/PRO-EVT-001.json`,
//! repris par le rapport, qui dit le dossier quand ce n'est pas cet ordinateur) ; les alertes de cet ordinateur vont au
//! journal des événements, d'où une alerte non critique peut être déclarée normale (« Ce que Vanguard a appris ») ;
//! rien n'est demandé.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use super::chronologie::{self, AlerteDatee, Chronologie, EtatPeriode};
use super::regles::moteur::{Gravite, Options};
use super::regles::resultat::{self, Analyse};
use crate::modele::resultat::{ConstatEcrit, Resultat};
use crate::risk::Niveau;
use crate::ui::*;
use crate::{tr, trf, trp};

/// Le nom de la commande, pour les messages (« vanguard journaux-windows --dossier … »).
pub(crate) const NOM: &str = "journaux-windows";

/// Le temps laissé à la lecture des journaux de cet ordinateur : au-delà, les plus anciens ne sont pas lus, et c'est
/// dit (non vérifié).
#[cfg(windows)]
const DELAI_VIVANT: std::time::Duration = std::time::Duration::from_secs(120);

/// Les alertes notées au journal des événements par passage, au plus (les plus récentes) : une analyse d'un dossier
/// d'attaque en trouve des centaines, et le journal n'est pas une copie du résultat.
const NOTEES_MAX: usize = 30;

/// Les alertes montrées dans la chronologie, au plus (les plus récentes) ; le JSON et le rapport ont le reste.
const MONTREES: usize = 60;

/// Pourquoi l'analyse n'a pas pu commencer.
enum Refus {
    /// Sans `--dossier`, hors de Windows : rien à lire ici.
    SansDossier,
    /// Le dossier ne se lit pas.
    Dossier(PathBuf, std::io::Error),
}

fn options(jours: u32) -> Options {
    Options {
        depuis: Some(Utc::now() - chrono::Duration::days(i64::from(jours))),
        defender_antivirus: None,
        installation: None,
    }
}

fn analyser(dossier: Option<&Path>, jours: u32) -> Result<Analyse, Refus> {
    let options = options(jours);
    match dossier {
        Some(d) => resultat::analyser_dossier(d, &options).map_err(|e| Refus::Dossier(d.to_path_buf(), e)),
        #[cfg(windows)]
        None => Ok(resultat::analyser_vivant(
            &options,
            std::time::Instant::now() + DELAI_VIVANT,
        )),
        #[cfg(not(windows))]
        None => Err(Refus::SansDossier),
    }
}

/// Pourquoi l'analyse n'a pas commencé, dans la langue du moment.
fn texte_refus(r: &Refus) -> String {
    match r {
        Refus::SansDossier => trf!(
            "  ✖ Sans --dossier, Vanguard lit les journaux du Windows en marche : ici, il n'y en a pas. Donnez-lui un dossier de journaux .evtx, par exemple Windows\\System32\\winevt\\Logs d'un disque de Windows monté depuis la clé de secours, ou le dossier laissé par « vanguard depanner traces » sous Windows :\n    vanguard {NOM} --dossier /run/media/alice/Windows/Windows/System32/winevt/Logs",
            "  ✖ Without --dossier, Vanguard reads the logs of the running Windows: there is none here. Give it a folder of .evtx logs, for example Windows\\System32\\winevt\\Logs of a Windows disk mounted from the rescue drive, or the folder left by “vanguard troubleshoot evidence” on Windows:\n    vanguard windows-logs --folder /run/media/alice/Windows/Windows/System32/winevt/Logs"
        ),
        Refus::Dossier(d, e) => trf!(
            "  ✖ Le dossier {} ne se lit pas ({e}) : rien n'a été analysé.",
            "  ✖ The folder {} cannot be read ({e}): nothing was analysed.",
            chemin_affichable(d)
        ),
    }
}

/// Dit pourquoi l'analyse n'a pas commencé, sur la sortie d'erreur (rien sur la sortie, même sous `--json`), et
/// quitte : 2 pour un appel à refaire autrement, 1 pour un dossier illisible.
fn refuser(r: &Refus) -> ! {
    eprintln!("{}", mettre_en_lignes(&texte_refus(r)));
    crate::machine::quitter(match r {
        Refus::SansDossier => 2,
        Refus::Dossier(..) => 1,
    });
}

/// La commande. `jours` : 1 et plus (clap refuse 0 et les nombres négatifs).
pub(crate) fn executer(dossier: Option<&Path>, jours: u32, json: bool) {
    if let Err(r) = lancer(dossier, jours, json) {
        refuser(&r);
    }
}

/// Les jours lus depuis le menu : ceux de la commande sans `--jours`.
const JOURS_DU_MENU: u32 = 7;

/// Menu Bloquer et réagir › Journaux de Windows : sous Windows, les journaux de cet ordinateur ; ailleurs, un dossier
/// de .evtx demandé (`winevt\Logs` d'un disque de Windows monté depuis la clé de secours, des journaux rapportés).
/// Rien ne quitte le menu : un dossier illisible est dit, et l'on revient.
pub(crate) fn menu() {
    let dossier = if cfg!(windows) {
        None
    } else {
        // Le cadre « Que s'est-il passé ? » vient avec l'analyse (`entete`) : ici, seulement ce qu'il faut donner.
        println!();
        afficher_aligne(
            "  ",
            tr!(
                "Il n'y a pas de Windows en marche ici : Vanguard lit un dossier de journaux .evtx, par exemple Windows\\System32\\winevt\\Logs d'un disque de Windows monté depuis la clé de secours, ou des journaux rapportés d'un autre ordinateur. Rien n'y est changé.",
                "There is no running Windows here: Vanguard reads a folder of .evtx logs, for example Windows\\System32\\winevt\\Logs of a Windows disk mounted from the rescue drive, or logs brought from another computer. Nothing in it is changed."
            ),
            2,
            GRIS,
        );
        let reponse = demander(tr!(
            "\n  Dossier des journaux (glissez-le ici, ou tapez son chemin ; Entrée pour revenir) : ",
            "\n  Log folder (drag it here, or type its path; Enter to go back): "
        ));
        let Some(d) = crate::protection::courriel_suspect::chemin_saisi(&reponse) else {
            noter_retour(true);
            return;
        };
        Some(d)
    };
    if let Err(r) = lancer(dossier.as_deref(), JOURS_DU_MENU, false) {
        println!("{}", mettre_en_lignes(&texte_refus(&r)));
    }
}

/// L'analyse, son versement et son écran (ou son JSON) ; `Err` : elle n'a pas pu commencer.
fn lancer(dossier: Option<&Path>, jours: u32, json: bool) -> Result<(), Refus> {
    let debut = (Utc::now(), std::time::Instant::now());
    if dossier.is_none() && !cfg!(windows) {
        return Err(Refus::SansDossier);
    }
    if !json {
        entete(dossier, jours);
    }
    let a = analyser(dossier, jours)?;
    let est_normale = |cle: &str| crate::protection::normales::est_normale(cle);
    let mut r = resultat::resultat(&a, debut, &est_normale);
    if let Some(d) = dossier {
        r.dossier = Some(crate::modele::resultat::nom_sans_piege(&d.to_string_lossy(), 300));
    }
    crate::modele::resultat::verser(&r);
    let c = chronologie::chronologie(&a, &est_normale);
    if dossier.is_none() {
        noter_alertes(&c);
    }
    if json {
        println!("{}", crate::modele::resultat::json(&r));
        return Ok(());
    }
    afficher(&a, &r, &c, options(jours).depuis.unwrap_or(debut.0));
    Ok(())
}

/// Les alertes de cet ordinateur au journal des événements, avec leur clé : « Ce que Vanguard a appris » les propose
/// à déclarer normales (jamais une critique). Seulement les datées, d'alerte ou critiques (pas une simple
/// information), les plus récentes. Le texte commence par la date UTC du premier événement : une alerte déjà notée
/// pour la même clé et le même premier événement ne l'est pas deux fois, quelles que soient la langue, l'heure
/// locale ou la période demandée. Celles d'un dossier ne sont jamais notées : elles ne parlent pas de cet ordinateur.
fn noter_alertes(c: &Chronologie) {
    use crate::modele::evenement::{Evenement, Source};
    let lu = crate::modele::journal::lire();
    // Seulement ce que la lecture garantit de Vanguard : une ligne posée d'avance par un autre programme, avec la clé
    // et la date d'une alerte à venir, en aurait sinon fait sauter la note. Au pire, une alerte est notée deux fois.
    let deja: std::collections::HashSet<(String, String)> = crate::modele::journal::alertes(lu.verifies())
        .filter_map(|(e, _, _, texte)| Some((e.cle.clone()?, texte.get(..20)?.to_string())))
        .collect();
    let mut datees: Vec<(&AlerteDatee, DateTime<Utc>)> = c
        .alertes
        .iter()
        .filter(|x| x.gravite > Gravite::Info)
        .filter_map(|x| Some((x, x.date?)))
        .collect();
    datees.sort_by_key(|(_, d)| *d);
    let debut = datees.len().saturating_sub(NOTEES_MAX);
    for (x, d) in datees.iter().skip(debut) {
        let utc = d.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        if deja.contains(&(x.cle.clone(), utc.clone())) {
            continue;
        }
        let titre = format!("{} : {}", x.regle, chronologie::gravite(x.gravite));
        let texte = format!("{utc} — {}", x.texte);
        let ev = Evenement::alerte(
            Source::Outil,
            crate::reseau::tableau::FAMILLE_EVENEMENTS,
            &titre,
            &texte,
        )
        .gravite(resultat::niveau(x.gravite))
        .cle(Some(&x.cle));
        crate::modele::journal::noter(ev);
    }
}

/// Les caractères d'un mot au plus, à l'écran : un chemin ou un nom de journal plus long serait coupé par le
/// terminal au milieu, et reprendrait au bord gauche.
const MOT_MAX: usize = 60;
/// Les caractères d'un texte au plus, à l'écran : le verdict d'une règle sur un dossier de cent journaux en fait
/// des milliers ; `--json` et le rapport l'ont en entier.
const TEXTE_ECRAN: usize = 700;

/// Un texte prêt pour `afficher_aligne` : les mots trop longs coupés en morceaux, le tout borné.
fn ecran(t: &str) -> String {
    let mut sortie = String::new();
    for (i, mot) in t.split_whitespace().enumerate() {
        if i > 0 {
            sortie.push(' ');
        }
        // Coupé de préférence juste après un séparateur (« / », « \\ », « - »…), pour que chaque morceau se lise.
        let lettres: Vec<char> = mot.chars().collect();
        let mut reste: &[char] = &lettres;
        // Plus long que `MOT_MAX` : la tête existe, et la coupe (au plus `MOT_MAX`) tombe dedans ; sinon le reste
        // est écrit tel quel juste après.
        while reste.len() > MOT_MAX {
            let Some((tete, _)) = reste.split_first_chunk::<MOT_MAX>() else {
                break;
            };
            let coupe = tete
                .iter()
                .rposition(|c| matches!(c, '/' | '\\' | '-' | '_' | '%' | '.' | ','))
                .filter(|i| *i >= MOT_MAX / 2)
                .map_or(MOT_MAX, |i| i + 1);
            let Some((morceau, suite)) = reste.split_at_checked(coupe) else {
                break;
            };
            sortie.extend(morceau);
            sortie.push(' ');
            reste = suite;
        }
        sortie.extend(reste);
    }
    match sortie.char_indices().nth(TEXTE_ECRAN) {
        Some((i, _)) => format!("{}… {}", &sortie[..i], tr!("(la suite : --json)", "(the rest: --json)")),
        None => sortie,
    }
}

/// Le décalage de l'heure locale d'aujourd'hui, dit en tête : les journaux sont en UTC. Une date d'un autre
/// décalage (l'heure d'hiver) porte le sien (`locale`).
fn fuseau() -> String {
    chrono::Local::now().format("UTC%:z").to_string()
}

fn entete(dossier: Option<&Path>, jours: u32) {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("QUE S'EST-IL PASSÉ ?", "WHAT HAPPENED?")),
        &format!("{GRIS}{}{RESET}", tr!("lecture seule", "read only")),
    );
    let source = match dossier {
        Some(d) => ecran(&trf!("Dossier : {}", "Folder: {}", chemin_affichable(d))),
        None => tr!("Les journaux de cet ordinateur", "This computer's logs").to_string(),
    };
    afficher_aligne("  ", &source, 2, GRIS);
    let depuis = chrono::Local::now() - chrono::Duration::days(i64::from(jours));
    afficher_aligne(
        "  ",
        &trf!(
            "Période demandée : les {jours} derniers jours, depuis le {} (heures de l'ordinateur qui lit, {} ; les journaux sont en UTC).",
            "Period asked: the last {jours} days, since {} (times of the computer reading, {}; the logs are in UTC).",
            depuis.format("%Y-%m-%d %H:%M"),
            fuseau()
        ),
        2,
        GRIS,
    );
    trp!(
        "  {DISCRET}Lecture des journaux…{RESET}",
        "  {DISCRET}Reading the logs…{RESET}"
    );
}

fn icone(n: Option<Niveau>) -> String {
    match n {
        Some(n) => format!("{}✖{RESET}", couleur(n)),
        None => format!("{VERT}✔{RESET}"),
    }
}

fn non_verifie() -> String {
    format!("{}?{RESET}", couleur(Niveau::Moyen))
}

/// Le verdict d'une règle, tiré de ses constats : problème si une alerte reste, puis non vérifié, puis sain.
fn verdict_regle<'a>(r: &'a Resultat, regle: &str) -> (String, usize, Option<&'a ConstatEcrit>) {
    let siens: Vec<&ConstatEcrit> = r.constats.iter().filter(|c| c.regle == regle).collect();
    let alertes = siens.iter().filter(|c| c.etat == "probleme").count();
    let pire = siens
        .iter()
        .filter(|c| c.etat == "probleme")
        .filter_map(|c| c.niveau)
        .max();
    let couverture = siens.iter().find(|c| c.etat != "probleme").copied();
    let marque = match (pire, couverture.map(|c| c.etat.as_str())) {
        (Some(n), _) => icone(Some(n)),
        (None, Some("sans-objet")) => format!("{GRIS}–{RESET}"),
        (None, Some("sain")) => icone(None),
        // Sans constat de couverture, rien ne dit que la règle a tout lu.
        (None, _) => non_verifie(),
    };
    (marque, alertes, couverture)
}

fn afficher(a: &Analyse, r: &Resultat, c: &Chronologie, depuis: DateTime<Utc>) {
    section(tr!("CE QUE DISENT LES RÈGLES", "WHAT THE RULES SAY"));
    for j in &a.jugements {
        let id = j.regle.id;
        let (marque, alertes, couverture) = verdict_regle(r, id);
        let mut texte = String::new();
        if alertes > 0 {
            texte.push_str(&trf!("{alertes} alerte(s). ", "{alertes} alert(s). "));
        }
        texte.push_str(couverture.map_or_else(
            || {
                tr!(
                    "non vérifié : aucun jugement rendu.",
                    "not verified: no judgement given."
                )
            },
            |c| c.message.as_str(),
        ));
        afficher_aligne(&format!("  {marque} {GRAS}{id}{RESET} "), &ecran(&texte), 4, "");
    }
    for m in &a.manques_source {
        afficher_aligne(&format!("  {} ", non_verifie()), &ecran(&affichable(m)), 4, GRIS);
    }

    section(&trf!(
        "CHRONOLOGIE (heures d'ici, {})",
        "TIMELINE (times here, {})",
        fuseau()
    ));
    chronologie_ecran(c, depuis);

    section(tr!("PÉRIODE LUE PAR JOURNAL", "PERIOD READ PER LOG"));
    periodes_ecran(a);

    if !c.au_dela.is_empty() {
        section(tr!("AU-DELÀ DES BORNES", "BEYOND THE LIMITS"));
        for b in &c.au_dela {
            let pire = b.pire.map_or_else(|| tr!("inconnue", "unknown"), chronologie::gravite);
            afficher_aligne(
                &format!("  {} ", non_verifie()),
                &trf!(
                    "{} : {} événements au-delà, pire gravité {pire} (pas montrés un à un).",
                    "{}: {} events beyond, worst severity {pire} (not shown one by one).",
                    b.regle,
                    b.evenements
                ),
                4,
                "",
            );
        }
    }

    section(tr!("EN RÉSUMÉ", "IN SHORT"));
    let problemes = r.constats.iter().filter(|c| c.etat == "probleme").count();
    let manques = r.couverture.non_verifies.len();
    match r.verdict() {
        "probleme" => {
            let mut t = trf!(
                "{problemes} alerte(s) à regarder, de la plus ancienne à la plus récente ci-dessus.",
                "{problemes} alert(s) to look at, oldest first above."
            );
            if manques > 0 {
                t.push(' ');
                t.push_str(&trf!(
                    "Et {manques} point(s) non vérifié(s) : ce qui n'a pas été lu peut cacher autre chose.",
                    "And {manques} point(s) not verified: what was not read may hide something else."
                ));
            }
            afficher_aligne(&format!("  {} ", icone(r.pire())), &t, 4, "");
        }
        "sain" => afficher_aligne(
            &format!("  {} ", icone(None)),
            tr!(
                "Rien trouvé : chaque règle a lu tout ce qu'elle cherche sur la période.",
                "Nothing found: each rule read everything it looks for over the period."
            ),
            4,
            "",
        ),
        _ => afficher_aligne(
            &format!("  {} ", non_verifie()),
            &trf!(
                "Pas tout vérifié ({manques} point(s)) : aucune alerte dans ce qui a été lu, mais ce n'est pas « rien vu ».",
                "Not everything checked ({manques} point(s)): no alert in what was read, but that is not “nothing seen”."
            ),
            4,
            "",
        ),
    }
    if c.tues > 0 {
        afficher_aligne(
            "  ",
            &trf!(
                "{} alerte(s) déclarée(s) normale(s), tue(s) (Vanguard › Ce que Vanguard a appris).",
                "{} alert(s) declared normal, silenced (Vanguard › What Vanguard learned).",
                c.tues
            ),
            2,
            GRIS,
        );
    }
    afficher_aligne(
        "  ",
        &trf!(
            "Le détail pour un script : vanguard {NOM} --json. Le rapport (vanguard rapport) reprend ce passage.",
            "Details for a script: vanguard windows-logs --json. The report (vanguard report) includes this run."
        ),
        2,
        GRIS,
    );
}

/// Une date à l'heure de l'ordinateur qui lit ; son décalage quand ce n'est pas celui d'aujourd'hui (dit en tête).
fn locale(d: DateTime<Utc>) -> String {
    use chrono::Offset as _;
    let l = d.with_timezone(&chrono::Local);
    if l.offset().fix() == chrono::Local::now().offset().fix() {
        l.format("%Y-%m-%d %H:%M").to_string()
    } else {
        l.format("%Y-%m-%d %H:%M (UTC%:z)").to_string()
    }
}

fn ligne_alerte(x: &AlerteDatee, depuis: DateTime<Utc>) {
    let n = resultat::niveau(x.gravite);
    let quand = x.date.map_or_else(|| tr!("sans date", "no date").to_string(), locale);
    let mut texte = format!("{} — {}", x.regle, x.texte);
    // Une règle des trous juge toute la suite des numéros du fichier : son premier événement peut précéder la période.
    if x.date.is_some_and(|d| d < depuis) {
        texte.push_str(tr!(" (avant la période demandée)", " (before the period asked)"));
    }
    afficher_aligne(
        &format!("  {} {GRAS}{quand}{RESET} ", icone(Some(n))),
        &ecran(&texte),
        4,
        "",
    );
    let mut ou = x.contexte.clone();
    if let Some(t) = x.technique {
        if !ou.is_empty() {
            ou.push_str(" · ");
        }
        ou.push_str(&trf!("ATT&CK {t}", "ATT&CK {t}"));
    }
    if !ou.is_empty() {
        afficher_aligne("    ", &ecran(&ou), 4, GRIS);
    }
}

fn chronologie_ecran(c: &Chronologie, depuis: DateTime<Utc>) {
    if c.alertes.is_empty() {
        afficher_aligne(
            "  ",
            tr!(
                "Aucune alerte dans ce qui a été lu (voir plus haut ce qui ne l'a pas été).",
                "No alert in what was read (see above for what was not)."
            ),
            2,
            GRIS,
        );
        return;
    }
    // Les plus récentes, si elles sont trop : ce qui vient de se passer compte le plus ; l'ordre reste celui du temps.
    let datees: Vec<&AlerteDatee> = c.alertes.iter().filter(|x| x.date.is_some()).collect();
    let sans: Vec<&AlerteDatee> = c.alertes.iter().filter(|x| x.date.is_none()).collect();
    let coupees = datees.len().saturating_sub(MONTREES);
    if coupees > 0 {
        afficher_aligne(
            "  ",
            &trf!(
                "{coupees} alerte(s) plus ancienne(s) non montrée(s) ici : --json les donne toutes.",
                "{coupees} older alert(s) not shown here: --json gives them all."
            ),
            2,
            GRIS,
        );
    }
    for x in datees.iter().skip(coupees) {
        ligne_alerte(x, depuis);
    }
    if !sans.is_empty() {
        afficher_aligne(
            "  ",
            &trf!(
                "{} alerte(s) sans date (événements sans date lisible) :",
                "{} alert(s) without a date (events without a readable date):",
                sans.len()
            ),
            2,
            GRIS,
        );
        for x in sans.iter().take(MONTREES / 4) {
            ligne_alerte(x, depuis);
        }
        let reste = sans.len().saturating_sub(MONTREES / 4);
        if reste > 0 {
            afficher_aligne(
                "  ",
                &trf!(
                    "{reste} de plus : --json les donne toutes.",
                    "{reste} more: --json gives them all."
                ),
                2,
                GRIS,
            );
        }
    }
}

fn periodes_ecran(a: &Analyse) {
    for p in chronologie::periodes(a) {
        let (marque, texte) = match &p.etat {
            EtatPeriode::Absent => (
                non_verifie(),
                match a.source {
                    resultat::Source::Dossier(_) => tr!("absent du dossier", "missing from the folder"),
                    resultat::Source::Vivant => tr!("absent de cet ordinateur", "missing on this computer"),
                }
                .to_string(),
            ),
            EtatPeriode::Refuse => (
                non_verifie(),
                tr!(
                    "réservé à l'administrateur : relancez Vanguard en administrateur",
                    "restricted to administrators: run Vanguard as administrator"
                )
                .to_string(),
            ),
            EtatPeriode::Illisible(x) => (non_verifie(), trf!("illisible : {x}", "unreadable: {x}")),
            EtatPeriode::Lu(manques) => {
                let mut t = match (p.premier, p.dernier) {
                    (Some(d), Some(f)) => trf!(
                        "{} événements, du {} au {}",
                        "{} events, from {} to {}",
                        p.evenements,
                        locale(d),
                        locale(f)
                    ),
                    _ => trf!(
                        "lu, aucun événement daté sur la période",
                        "read, no dated event over the period"
                    ),
                };
                if p.courte {
                    t.push_str(tr!(
                        " — plus court que demandé : le plus ancien est écrasé, effacé, ou rien n'a été écrit",
                        " — shorter than asked: older events overwritten, cleared, or never written"
                    ));
                }
                if !manques.is_empty() {
                    t.push_str(&trf!(" — lu en partie : {}", " — partly read: {}", manques.join(" ; ")));
                }
                // Vide, muet, désactivé, trous non vérifiés : lu sans erreur, mais pas sain.
                for r in &p.remarques {
                    t.push_str(" — ");
                    t.push_str(r);
                }
                let m = if p.courte || !manques.is_empty() || !p.remarques.is_empty() {
                    non_verifie()
                } else {
                    icone(None)
                };
                (m, t)
            }
        };
        afficher_aligne(
            &format!("  {marque} "),
            &ecran(&trf!("{} : {texte}", "{}: {texte}", p.journal)),
            4,
            "",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sans_dossier_hors_de_windows_refuse() {
        if cfg!(windows) {
            return crate::essais::saute("sous Windows, sans --dossier, ce sont les journaux de l'ordinateur");
        }
        assert!(matches!(analyser(None, 7), Err(Refus::SansDossier)));
    }

    #[test]
    fn dossier_absent_refuse() {
        let d = std::env::temp_dir().join(format!("vanguard-jw-absent-{}", std::process::id()));
        assert!(matches!(analyser(Some(&d), 7), Err(Refus::Dossier(..))));
    }

    /// Les alertes notées au journal : une seule fois par clé et premier événement, quelle que soit la langue ; ni
    /// une information ni une alerte sans date ; les plus récentes seulement.
    #[test]
    fn alertes_notees_une_fois() {
        let marque = format!("essai-notees-{}", std::process::id());
        let alerte = |i: i64, g: Gravite, date: bool| AlerteDatee {
            date: date.then(|| DateTime::from_timestamp(1_760_000_000 + i * 60, 0).unwrap()),
            dernier: None,
            regle: "EVT-SRV-001",
            technique: None,
            gravite: g,
            cle: format!("evenements|EVT-SRV-001|{marque}|{i}"),
            texte: format!("texte {i}"),
            contexte: String::new(),
        };
        let mut c = Chronologie::default();
        for i in 0..40 {
            c.alertes.push(alerte(i, Gravite::Alerte, true));
        }
        c.alertes.push(alerte(100, Gravite::Info, true));
        c.alertes.push(alerte(101, Gravite::Critique, false));
        let compter = || {
            let lu = crate::modele::journal::lire();
            crate::modele::journal::alertes(&lu.evenements)
                .filter(|(e, ..)| e.cle.as_deref().is_some_and(|k| k.contains(&marque)))
                .map(|(e, ..)| e.cle.clone().unwrap())
                .collect::<Vec<_>>()
        };
        noter_alertes(&c);
        let notees = compter();
        assert_eq!(notees.len(), NOTEES_MAX, "{notees:?}");
        assert!(
            notees
                .iter()
                .all(|k| !k.ends_with("|100") && !k.ends_with("|101") && !k.ends_with("|0"))
        );
        // Une autre langue : d'autres textes, mêmes clés et premiers événements.
        for a in &mut c.alertes {
            a.texte = format!("text {}", a.cle);
        }
        noter_alertes(&c);
        assert_eq!(compter().len(), NOTEES_MAX);
    }

    /// Un dossier vide n'est jamais sain : chaque règle dit son journal absent.
    #[test]
    fn dossier_vide_jamais_sain() {
        let d = std::env::temp_dir().join(format!("vanguard-jw-vide-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let Ok(a) = analyser(Some(&d), 7) else {
            panic!("dossier vide lisible")
        };
        let r = resultat::resultat(&a, (Utc::now(), std::time::Instant::now()), &|_| false);
        assert_eq!(r.verdict(), "non-verifie");
        for j in &a.jugements {
            let (marque, alertes, _) = verdict_regle(&r, j.regle.id);
            assert_eq!(alertes, 0);
            assert!(!marque.contains('✔'), "{}", j.regle.id);
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
