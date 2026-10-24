//! `vanguard signaler` (alias `disclose`) : préparer un signalement à un éditeur, sans jamais l'envoyer. L'assistant
//! trie d'abord (une faille déjà connue se corrige par une mise à jour, un logiciel malveillant n'est pas une faille
//! de l'éditeur), prépare ensuite un brouillon dans le format du programme choisi (MSRC, Google, Chrome, Mozilla,
//! Apple, GHSA, CERT/CC, CERT-FR, Vanguard), passé par le garde-fou de confidentialité, puis l'écrit dans un fichier
//! local et le montre en entier. La personne le relit, le copie et le soumet elle-même.
//!
//! Pourquoi rien ne part : un rapport mal relu coûte à la personne (Apple plafonne les envois et peut suspendre qui
//! envoie des rapports automatiques non validés), et un brouillon décrit une faille pas encore corrigée. Le module ne
//! contient aucun code réseau, ni presse-papier, ni `mailto` : un test le vérifie par une liste fermée des chemins
//! `crate::…` qu'il a le droit d'appeler (un appel indirect au réseau, comme le catalogue KEV qui se télécharge quand
//! sa copie a plus d'un jour, ne contient pas le mot « http »).
//!
//! L'affichage est ici ; le jugement (tri, brouillon, garde-fou, neutralisation Markdown) est dans les sous-modules,
//! purs et testés seuls.

mod brouillon;
mod garde;
mod markdown;
mod programmes;
mod tri;

use std::path::{Path, PathBuf};

use brouillon::{Brouillon, Contexte, Kev, Masque, Reponses};
use garde::Sorte;
use programmes::{Fiche, Langue, Programme};
use tri::{Sujet, Tri};

use crate::modele::Echec;
use crate::modele::evenement::{Evenement, Genre, Source};
use crate::modele::journal::{Lecture, Lu};
use crate::selection::Ligne;
use crate::tr;
use crate::trf;
use crate::trp;
use crate::ui::*;

/// Le sous-dossier des brouillons, dans le dossier de données de cet ordinateur (réservé au compte), jamais sur la
/// clé VANGUARD ni ailleurs : un dossier synchronisé (OneDrive, iCloud Drive) ferait sortir le brouillon de
/// l'ordinateur sans geste de la personne.
pub(crate) const DOSSIER: &str = "signalements";

/// Alertes et gestes proposés au choix, chacun au plus : les plus récents.
const PROPOSES: usize = 20;

/// Où envoyer soi-même un échantillon de logiciel malveillant (hors champ : seulement nommé).
const WDSI: &str = "https://www.microsoft.com/en-us/wdsi/filesubmission";
/// Où signaler soi-même un site d'hameçonnage (hors champ : seulement nommé).
const HAMECONNAGE: &str = "https://safebrowsing.google.com/safebrowsing/report_phish/";
/// Un incident vécu au Canada (le Centre canadien pour la cybersécurité n'a pas de canal public pour les failles).
const CCCS: &str = "https://www.cyber.gc.ca/fr/cyberincidents";

/// Les options de la commande.
pub(crate) struct Options {
    pub incident: Option<String>,
    pub outil: Option<String>,
    pub programme: Option<String>,
    pub langue: Option<String>,
    pub json: bool,
    pub effacer: bool,
}

/// `vanguard signaler [--incident ID] [--outil ID] [--programme NOM] [--langue fr|en] [--json] [--effacer]`.
pub(crate) fn commande(o: &Options) {
    if let Err(e) = lancer(o) {
        trp!("\n  ✖ {}", "\n  ✖ {}", affichable(&e.to_string()));
    }
}

/// Le menu : Protection › Préparer un signalement.
pub(crate) fn menu() {
    commande(&Options {
        incident: None,
        outil: None,
        programme: None,
        langue: None,
        json: false,
        effacer: false,
    });
}

fn lancer(o: &Options) -> Result<(), Echec> {
    if o.effacer {
        return effacer();
    }
    let programme = match o.programme.as_deref() {
        Some(p) => Some(Programme::lire(p).ok_or_else(|| {
            let ids: Vec<&str> = programmes::PROGRAMMES.iter().map(|f| f.id).collect();
            Echec::refuse(
                "signaler/programme",
                trf!(
                    "programme inconnu « {} » : {}",
                    "unknown program “{}”: {}",
                    affichable(p),
                    ids.join(", ")
                ),
            )
        })?),
        None => None,
    };
    let langue = match o.langue.as_deref() {
        Some(l) => Some(Langue::lire(l).ok_or_else(|| {
            Echec::refuse(
                "signaler/langue",
                trf!(
                    "langue inconnue « {} » : fr ou en",
                    "unknown language “{}”: fr or en",
                    affichable(l)
                ),
            )
        })?),
        None => None,
    };
    let lu = crate::modele::journal::lire();
    let sujet = match (o.incident.as_deref(), o.outil.as_deref()) {
        (Some(id), _) => sujet_incident(&lu, id)?,
        (None, Some(outil)) => sujet_examen(outil)?,
        (None, None) if o.json => Sujet::Rien,
        (None, None) => {
            titre(tr!(
                "PRÉPARER UN SIGNALEMENT À UN ÉDITEUR",
                "PREPARE A REPORT FOR A VENDOR"
            ));
            afficher_aligne(
                "  ",
                tr!(
                    "Vanguard prépare le texte. Il ne l'envoie jamais : c'est vous qui le relisez, le copiez et le soumettez.",
                    "Vanguard prepares the text. It never sends it: you read it, copy it and submit it yourself."
                ),
                2,
                GRIS,
            );
            match choisir_sujet(&lu) {
                Some(s) => s,
                None => return Ok(()),
            }
        }
    };
    if o.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&en_json(&lu, &sujet, programme, langue)).unwrap_or_default()
        );
        return Ok(());
    }
    interactif(&lu, &sujet, programme, langue)
}

/// Le fil d'un incident, depuis l'événement `id`.
fn sujet_incident(lu: &Lu, id: &str) -> Result<Sujet, Echec> {
    let Some(choisi) = lu.evenements.iter().find(|e| e.id == id) else {
        return Err(Echec::refuse(
            "signaler/incident",
            trf!(
                "aucun événement « {} » (vanguard evenements donne les identifiants)",
                "no event “{}” (vanguard events gives the identifiers)",
                affichable(id)
            ),
        ));
    };
    let fil = crate::modele::journal::incident(&lu.evenements, id)
        .into_iter()
        .cloned()
        .collect();
    Ok(Sujet::Incident {
        choisi: Box::new(choisi.clone()),
        fil,
        omis: 0,
    })
}

/// Le dernier examen d'un outil, relu par son sceau (un fichier falsifié ne fournit aucun constat).
fn sujet_examen(outil: &str) -> Result<Sujet, Echec> {
    let voulu = outil.trim().to_ascii_uppercase();
    crate::modele::resultat::derniers()
        .into_iter()
        .find(|r| r.outil == voulu)
        .map(|r| Sujet::Examen(Box::new(r)))
        .ok_or_else(|| {
            Echec::refuse(
                "signaler/outil",
                trf!(
                    "aucun examen gardé pour « {} » (outils qui en gardent un : {})",
                    "no kept examination for “{}” (tools that keep one: {})",
                    affichable(outil),
                    crate::modele::resultat::AVEC_RESULTAT.join(", ")
                ),
            )
        })
}

/// Les sujets proposés : les 20 dernières alertes et les 20 derniers gestes (les essais exclus), les derniers
/// examens, puis « rien de ce que Vanguard a vu ».
fn choisir_sujet(lu: &Lu) -> Option<Sujet> {
    let mut proposes: Vec<&Evenement> = crate::modele::journal::alertes(&lu.evenements)
        .map(|(e, ..)| e)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .take(PROPOSES)
        .collect();
    proposes.extend(
        lu.evenements
            .iter()
            .rev()
            .filter(|e| !e.essai && matches!(e.quoi, Genre::Action { .. }))
            .take(PROPOSES),
    );
    proposes.sort_by(|a, b| b.quand.cmp(&a.quand));
    let examens = crate::modele::resultat::derniers();
    let mut lignes: Vec<Ligne> = vec![Ligne::Texte(String::new())];
    if !matches!(lu.lecture, Lecture::Vide | Lecture::Intact) {
        lignes.push(Ligne::Texte(format!(
            "  {GRIS}{}{RESET}",
            tr!(
                "Journal non vérifié : ce qui en vient le dira.",
                "Log not verified: what comes from it will say so."
            )
        )));
    }
    for (i, e) in proposes.iter().enumerate() {
        let quand = e.date_locale().unwrap_or_else(|| e.quand.clone());
        let texte = match &e.quoi {
            Genre::Alerte { titre, .. } => titre.clone(),
            _ => e.resume(),
        };
        lignes.push(Ligne::choix(
            &(i + 1).to_string(),
            &crate::modele::resultat::nom_sans_piege(&format!("{} {texte}", quand.get(..10).unwrap_or(&quand)), 40),
            e.quoi.sorte(),
        ));
    }
    let base = proposes.len();
    for (j, r) in examens.iter().enumerate() {
        lignes.push(Ligne::choix(
            &(base + j + 1).to_string(),
            &trf!(
                "Examen {} du {}",
                "{} examination of {}",
                r.outil,
                r.debut.get(..10).unwrap_or("?")
            ),
            r.verdict(),
        ));
    }
    lignes.push(Ligne::choix(
        "0",
        tr!("Rien de ce que Vanguard a vu", "Nothing Vanguard saw"),
        tr!("je l'écris moi-même", "I write it myself"),
    ));
    lignes.push(Ligne::Texte(String::new()));
    let choix = crate::selection::choisir(
        &lignes,
        tr!("Que voulez-vous signaler ? ", "What do you want to report? "),
        "0",
        tr!("revenir", "back"),
    )?;
    let n: usize = choix.trim().parse().ok()?;
    if n == 0 {
        return Some(Sujet::Rien);
    }
    if let Some(e) = proposes.get(n - 1) {
        return sujet_incident(lu, &e.id).ok();
    }
    examens
        .into_iter()
        .nth(n - 1 - base)
        .map(|r| Sujet::Examen(Box::new(r)))
}

/// La question du tri, quand ce que Vanguard a vu ne suffit pas à classer.
fn question_nature() -> Option<Tri> {
    let natures = [
        (
            Tri::AEcrire,
            tr!("Un logiciel se comporte mal", "A program misbehaves"),
            tr!("une faille, à signaler", "a flaw, to report"),
        ),
        (
            Tri::Contournement,
            tr!("Une protection a été contournée", "A protection was bypassed"),
            tr!("AppLocker, dossiers protégés…", "AppLocker, protected folders…"),
        ),
        (
            Tri::DetectionRatee,
            tr!("L'antivirus n'a pas vu un fichier", "The antivirus missed a file"),
            tr!("un échantillon, pas une faille", "a sample, not a flaw"),
        ),
        (
            Tri::Malveillant,
            tr!("Un fichier ou programme malveillant", "A malicious file or program"),
            tr!("pas une faille de l'éditeur", "not a flaw of the vendor"),
        ),
        (
            Tri::Hameconnage,
            tr!("Un lien ou courriel d'hameçonnage", "A phishing link or email"),
            tr!("pas une faille de l'éditeur", "not a flaw of the vendor"),
        ),
        (
            Tri::Vanguard,
            tr!("Un problème dans Vanguard", "A problem in Vanguard"),
            tr!("son propre signalement privé", "its own private reporting"),
        ),
    ];
    let mut lignes = vec![Ligne::Texte(String::new())];
    for (i, (_, texte, precision)) in natures.iter().enumerate() {
        lignes.push(Ligne::choix(&(i + 1).to_string(), texte, precision));
    }
    lignes.push(Ligne::Texte(String::new()));
    println!("\n  {}", tr!("Qu'est-ce qui s'est passé ?", "What happened?"));
    let choix = crate::selection::choisir(&lignes, tr!("Choix : ", "Choice: "), "1", tr!("revenir", "back"))?;
    let n: usize = choix.trim().parse().ok()?;
    natures.into_iter().nth(n.checked_sub(1)?).map(|(t, ..)| t)
}

/// Le programme, parmi la liste fermée, ceux qui conviennent au produit et au système d'abord.
fn choisir_programme(produit: &str) -> Option<Programme> {
    let ordre = programmes::propose(produit, programmes::Plateforme::d_ici());
    let mut lignes = vec![Ligne::Texte(String::new())];
    for (i, p) in ordre.iter().enumerate() {
        let precision = if i == 0 { tr!("proposé", "suggested") } else { "" };
        lignes.push(Ligne::choix(&(i + 1).to_string(), p.fiche().nom, precision));
    }
    lignes.push(Ligne::Texte(String::new()));
    println!("\n  {}", tr!("À quel programme ?", "To which program?"));
    let choix = crate::selection::choisir(&lignes, tr!("Choix : ", "Choice: "), "1", tr!("revenir", "back"))?;
    let n: usize = choix.trim().parse().ok()?;
    ordre.get(n.checked_sub(1)?).copied()
}

/// Ce que dit le catalogue KEV de la CISA de ces CVE : sa copie gardée seule, sans rien demander à Internet (le
/// catalogue entier se télécharge quand sa copie a plus d'un jour : jamais d'ici).
fn kev(cves: &[String]) -> Kev {
    kev_selon(
        cves,
        crate::protection::kev::catalogue_selon(Some(tr!(
            "copie gardée absente : rien n'est téléchargé ici",
            "no kept copy: nothing is downloaded here"
        )))
        .map(|c| c.into_iter().map(|e| e.cve).collect()),
    )
}

/// Le jugement de `kev`, d'après les CVE du catalogue ou la raison pour laquelle il n'a pas pu être lu.
fn kev_selon(cves: &[String], catalogue: Result<Vec<String>, String>) -> Kev {
    // Sans CVE citée, rien n'a été cherché : un « absente du catalogue » serait un faux vert.
    if cves.is_empty() {
        return Kev::NonVerifie(tr!("aucune CVE citée", "no CVE cited").into());
    }
    match catalogue {
        Ok(catalogue) => Kev::Exploitees(cves.iter().filter(|c| catalogue.contains(c)).cloned().collect()),
        Err(raison) => Kev::NonVerifie(raison),
    }
}

/// Le contexte du système, et l'état du journal pour un incident.
fn contexte(lu: &Lu, sujet: &Sujet, kev: Option<Kev>) -> Contexte {
    Contexte {
        systeme: crate::journal::systeme().to_string(),
        journal: matches!(sujet, Sujet::Incident { .. }).then(|| lu.lecture.clone()),
        kev,
    }
}

/// Le brouillon assemblé avec le vrai masquage de cet ordinateur.
fn assembler(fiche: &'static Fiche, langue: Langue, sujet: &Sujet, r: &Reponses, ctx: &Contexte) -> Brouillon {
    let maisons = garde::maisons();
    let masque = Masque {
        maisons: &maisons,
        anonymiser: &crate::journal::anonymiser,
    };
    brouillon::assembler(fiche, langue, sujet, r, ctx, &masque)
}

/// Le texte final, s'il passe le contrôle : rien de ce que l'ordinateur sait de la personne n'y survit.
fn finaliser(b: &Brouillon, connues: &[(String, Sorte)]) -> Result<String, Vec<Sorte>> {
    let texte = brouillon::en_markdown(b);
    garde::controle_final(&texte, connues).map(|()| texte)
}

/// La phrase d'un refus du contrôle final : la sorte de donnée, jamais sa valeur.
fn refus(sortes: &[Sorte]) -> Echec {
    let noms: Vec<String> = sortes.iter().map(|s| s.nom()).collect();
    Echec::refuse(
        "signaler/controle",
        trf!(
            "Rien n'est écrit : un détail personnel ({}) restait dans le texte.",
            "Nothing written: a personal detail ({}) was still in the text.",
            noms.join(", ")
        ),
    )
}

/// `--json` : le tri, le brouillon et ce qui a été masqué, sans rien écrire ni noter (un script n'a pas relu le
/// texte, la personne si). Le brouillon n'est pas préparé pour ce que le tri écarte.
fn en_json(lu: &Lu, sujet: &Sujet, programme: Option<Programme>, langue: Option<Langue>) -> serde_json::Value {
    let tri = tri::trier(sujet);
    let programme = programme.unwrap_or_else(|| programmes::propose("", programmes::Plateforme::d_ici())[0]);
    let fiche = programme.fiche();
    let langue = langue.or(fiche.langue).unwrap_or_else(Langue::de_l_interface);
    let mut v = serde_json::json!({
        "etat_journal": lu.lecture.code(),
        "tri": tri,
        "programme": fiche.id,
        "langue": langue,
        "adresse": fiche.adresse,
        "ecrit": false,
    });
    if !matches!(tri, Tri::AEcrire | Tri::Vanguard | Tri::Contournement) {
        v["brouillon"] = serde_json::Value::Null;
        return v;
    }
    let b = assembler(fiche, langue, sujet, &Reponses::default(), &contexte(lu, sujet, None));
    v["incomplet"] = b.incomplet().into();
    v["manque"] = serde_json::json!(b.manque);
    v["masques"] = serde_json::json!(b.masques);
    match finaliser(&b, &garde::connues()) {
        Ok(texte) => v["brouillon"] = texte.into(),
        Err(sortes) => {
            v["brouillon"] = serde_json::Value::Null;
            v["refus"] = serde_json::json!(sortes);
        }
    }
    v
}

/// Une question à une ligne : la réponse, vide si la personne passe.
fn question(texte: &str) -> String {
    demander(&format!("\n  {texte}\n  › "))
}

/// Le parcours au clavier : le tri, le programme, les questions, le texte montré en entier, puis l'écriture après
/// accord.
fn interactif(lu: &Lu, sujet: &Sujet, programme: Option<Programme>, langue: Option<Langue>) -> Result<(), Echec> {
    if let Some(a) = avertissement_journal(&lu.lecture, sujet) {
        afficher_aligne("  ", a, 2, GRIS);
    }
    let mut tri = tri::trier(sujet);
    if tri == Tri::AEcrire {
        match question_nature() {
            Some(t) => tri = t,
            None => return Ok(()),
        }
    }
    let mut r = Reponses::default();
    let mut programme = programme;
    let mut kev_lu = None;
    println!();
    match &tri {
        Tri::FailleConnue(cves) => {
            let liste = if cves.is_empty() {
                tr!("logiciel pas à jour", "outdated software").to_string()
            } else {
                cves.join(", ")
            };
            afficher_aligne(
                "  ",
                &trf!(
                    "Cette faille est déjà connue ({}). Pas besoin de la signaler : une mise à jour la corrige.",
                    "This flaw is already known ({}). No need to report it: an update fixes it.",
                    liste
                ),
                2,
                "",
            );
            let k = kev(cves);
            match &k {
                Kev::Exploitees(dans) if !dans.is_empty() => afficher_aligne(
                    "  ",
                    &trf!(
                        "Exploitée selon le catalogue de la CISA : {}. Mettez à jour d'abord.",
                        "Exploited according to CISA's catalog: {}. Update first.",
                        dans.join(", ")
                    ),
                    2,
                    GRIS,
                ),
                Kev::Exploitees(_) => {}
                Kev::NonVerifie(raison) => afficher_aligne(
                    "  ",
                    &trf!(
                        "Catalogue de la CISA : non vérifié ({}).",
                        "CISA's catalog: not checked ({}).",
                        affichable(raison)
                    ),
                    2,
                    GRIS,
                ),
            }
            if !crate::langue::oui(&demander(tr!(
                "\n  La mise à jour ne la corrige pas ? Préparer quand même un brouillon (ce sera noté dedans) ? [o/N] : ",
                "\n  The update does not fix it? Prepare a draft anyway (it will be noted in it)? [y/N]: "
            ))) {
                return Ok(());
            }
            r.outre_connue = if cves.is_empty() {
                vec!["CVE ?".into()]
            } else {
                cves.clone()
            };
            kev_lu = Some(k);
        }
        Tri::Malveillant | Tri::DetectionRatee => {
            afficher_aligne(
                "  ",
                &trf!(
                    "Un logiciel malveillant ou une détection ratée n'est pas une faille de l'éditeur. Pour aider les antivirus, vous pouvez envoyer le fichier vous-même à {}. Vanguard ne prépare rien : un fichier envoyé peut contenir vos données, et il y est gardé longtemps.",
                    "Malware or a missed detection is not a flaw in the vendor's product. To help antivirus engines, you can send the file yourself to {}. Vanguard prepares nothing: a submitted file can hold your data, and it is kept there a long time.",
                    WDSI
                ),
                2,
                "",
            );
            afficher_aligne(
                "  ",
                &trf!("Un incident vécu au Canada : {}", "An incident in Canada: {}", CCCS),
                2,
                GRIS,
            );
            return Ok(());
        }
        Tri::Hameconnage => {
            afficher_aligne(
                "  ",
                &trf!(
                    "Un lien ou un courriel d'hameçonnage n'est pas une faille de l'éditeur. Vous pouvez signaler le site vous-même : {}",
                    "A phishing link or email is not a flaw in the vendor's product. You can report the site yourself: {}",
                    HAMECONNAGE
                ),
                2,
                "",
            );
            afficher_aligne(
                "  ",
                &trf!("Un incident vécu au Canada : {}", "An incident in Canada: {}", CCCS),
                2,
                GRIS,
            );
            return Ok(());
        }
        Tri::Contournement => {
            afficher_aligne(
                "  ",
                tr!(
                    "Microsoft ne corrige pas par défaut le contournement d'une protection « en profondeur » (AppLocker, accès contrôlé aux dossiers, Exploit Guard). Vous pouvez continuer : ce sera dit dans le brouillon.",
                    "Microsoft does not fix by default the bypass of a “defense-in-depth” protection (AppLocker, controlled folder access, Exploit Guard). You can go on: the draft will say so."
                ),
                2,
                GRIS,
            );
            r.contournement = true;
        }
        Tri::Vanguard => programme = Some(Programme::Vanguard),
        Tri::AEcrire => {}
    }

    r.produit = question(tr!(
        "Quel logiciel, et sa version ? (ex. Firefox 132.0)",
        "Which software, and its version? (e.g. Firefox 132.0)"
    ));
    let programme = match programme {
        Some(p) => p,
        None => match choisir_programme(&r.produit) {
            Some(p) => p,
            None => return Ok(()),
        },
    };
    let fiche = programme.fiche();
    let langue = langue.or(fiche.langue).unwrap_or_else(Langue::de_l_interface);
    afficher_aligne(
        "  ",
        tr!(
            "Une ligne par réponse ; Entrée pour passer. Vous pourrez compléter le fichier ensuite.",
            "One line per answer; Enter to skip. You can complete the file afterwards."
        ),
        2,
        GRIS,
    );
    r.fait = question(tr!(
        "Qu'avez-vous fait, étape par étape ?",
        "What did you do, step by step?"
    ));
    r.vu = question(tr!("Qu'est-ce qui s'est passé ?", "What happened?"));
    r.attendu = question(tr!("Qu'est-ce qui aurait dû se passer ?", "What should have happened?"));
    if fiche.champs.contains(&programmes::Champ::PreuveDeConcept) {
        r.preuve = question(tr!(
            "La preuve de concept : comment la refaire, en peu de mots ?",
            "The proof of concept: how to redo it, in a few words?"
        ));
    }
    if fiche.champs.contains(&programmes::Champ::Impact) {
        r.impact = question(tr!(
            "L'impact, si vous le connaissez (sinon Entrée) :",
            "The impact, if you know it (otherwise Enter):"
        ));
    }

    let b = assembler(fiche, langue, sujet, &r, &contexte(lu, sujet, kev_lu));
    let texte = finaliser(&b, &garde::connues()).map_err(|s| refus(&s))?;
    titre(tr!("BROUILLON", "DRAFT"));
    for l in texte.lines() {
        afficher_aligne("  ", &affichable(l), 2, "");
    }
    println!();
    afficher_aligne(
        "  ",
        &trf!(
            "Retiré avant d'écrire : {}. Relisez quand même : vous seul savez ce qui est personnel.",
            "Removed before writing: {}. Read it anyway: only you know what is personal.",
            b.masques.texte()
        ),
        2,
        GRIS,
    );
    if b.incomplet() {
        let manque: Vec<&str> = b.manque.iter().map(|c| c.titre(Langue::de_l_interface())).collect();
        afficher_aligne(
            "  ",
            &trf!(
                "INCOMPLET : ne le soumets pas tel quel. Il manque : {}.",
                "INCOMPLETE: do not submit it as is. Missing: {}.",
                manque.join(", ")
            ),
            2,
            couleur(crate::risk::Niveau::Moyen),
        );
    }
    let ecrire = demander(tr!(
        "\n  Écrire ce brouillon sur cet ordinateur ? [O/n] : ",
        "\n  Write this draft on this computer? [Y/n]: "
    ));
    if !ecrire.is_empty() && !crate::langue::oui(&ecrire) {
        trp!("  Rien n'est écrit.", "  Nothing written.");
        return Ok(());
    }
    let dossier = crate::socle::dossier_local();
    let chemin = ecrire_dans(
        &dossier,
        &nom_de_fichier(chrono::Local::now(), fiche),
        &texte,
        crate::socle::ecriture_sure(&dossier),
    )?;
    let ecrit = if fiche.compte_verifie() {
        trf!(
            "{VERT}✔{RESET} Brouillon écrit : {}. Soumettez-le sur {} (compte {} demandé).",
            "{VERT}✔{RESET} Draft written: {}. Submit it at {} ({} account required).",
            chemin_affichable(&chemin),
            fiche.adresse,
            if crate::langue::anglais() {
                fiche.compte.1
            } else {
                fiche.compte.0
            }
        )
    } else {
        // Le compte exigé par ce programme n'a pas été vérifié : il n'est pas annoncé comme une exigence.
        trf!(
            "{VERT}✔{RESET} Brouillon écrit : {}. Soumettez-le sur {} (compte demandé : non vérifié).",
            "{VERT}✔{RESET} Draft written: {}. Submit it at {} (account required: not checked).",
            chemin_affichable(&chemin),
            fiche.adresse
        )
    };
    afficher_aligne("  ", &ecrit, 2, "");
    if let Some(a) = programme.avertissement() {
        afficher_aligne("  ", a, 2, GRIS);
    }
    afficher_aligne(
        "  ",
        tr!(
            "Ne publie rien avant que l'éditeur ait publié son avis. Effacer les brouillons : vanguard signaler --effacer",
            "Do not publish anything before the vendor has published its advisory. Erase the drafts: vanguard disclose --effacer"
        ),
        2,
        GRIS,
    );
    crate::modele::journal::noter(geste(fiche, sujet));
    if crate::langue::oui(&demander(tr!(
        "\n  Ouvrir la page du programme dans le navigateur ? [o/N] : ",
        "\n  Open the program's page in the browser? [y/N]: "
    ))) {
        // Une adresse de la liste fermée seulement, jamais un texte assemblé : rien du brouillon ne part.
        crate::machine::ouvrir(fiche.adresse);
    }
    Ok(())
}

/// Le tri d'un incident vient du journal : quand sa chaîne n'est pas vérifiée, un « déjà connue » ou un « pas une
/// faille de l'éditeur » peut venir d'un événement forgé, et le tri peut s'arrêter sans brouillon qui le dirait.
fn avertissement_journal(lecture: &Lecture, sujet: &Sujet) -> Option<&'static str> {
    (matches!(sujet, Sujet::Incident { .. }) && !matches!(lecture, Lecture::Vide | Lecture::Intact)).then(|| {
        tr!(
            "Journal non vérifié : ce tri vient de lui, il peut être faux.",
            "Log not verified: this triage comes from it, it may be wrong."
        )
    })
}

/// L'événement du geste, pour le journal : le programme, la clé et la cause du sujet ; jamais le texte du rapport.
fn geste(fiche: &Fiche, sujet: &Sujet) -> Evenement {
    let (cle, cause) = match sujet {
        Sujet::Incident { choisi, .. } => (choisi.cle.clone(), Some(choisi.id.clone())),
        Sujet::Examen(r) => (Some(r.outil.clone()), None),
        Sujet::Rien => (None, None),
    };
    Evenement::action(
        Source::Utilisateur,
        &trf!("rapport préparé pour {}", "report prepared for {}", fiche.nom),
        true,
        &[],
    )
    .cle(cle.as_deref())
    .cause(cause.as_deref())
}

/// « 20261023-140509-msrc.md » : rien de ce nom ne vient de l'extérieur.
fn nom_de_fichier(maintenant: chrono::DateTime<chrono::Local>, fiche: &Fiche) -> String {
    format!("{}-{}.md", maintenant.format("%Y%m%d-%H%M%S"), fiche.id)
}

/// Écrit le brouillon dans `dossier/signalements/`, dossier réservé au compte (0700), fichier en 0600 (il décrit une
/// faille pas encore corrigée). Refusé quand l'écriture n'est pas sûre (root dans le dossier d'un compte, sudo -E),
/// ou quand `signalements` n'est pas un vrai dossier (un lien posé d'avance ferait écrire ailleurs). Un nom déjà pris
/// (deux brouillons dans la même seconde) prend un numéro : rien n'est jamais écrasé.
fn ecrire_dans(dossier: &Path, nom: &str, texte: &str, sure: bool) -> Result<PathBuf, Echec> {
    if !sure {
        return Err(Echec::refuse(
            "signaler/ecrire",
            tr!(
                "écriture refusée : Vanguard tourne en administrateur dans le dossier d'un compte",
                "writing refused: Vanguard runs as administrator in an account's folder"
            ),
        ));
    }
    let rep = dossier.join(DOSSIER);
    if let Ok(m) = std::fs::symlink_metadata(&rep)
        && !m.is_dir()
    {
        return Err(Echec::refuse(
            "signaler/ecrire",
            tr!(
                "« signalements » n'est pas un vrai dossier : rien n'est écrit",
                "“signalements” is not a real folder: nothing written"
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&rep)
            .map_err(|e| Echec::ecriture("signaler/dossier", &e))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&rep).map_err(|e| Echec::ecriture("signaler/dossier", &e))?;
    let base = nom.trim_end_matches(".md");
    let chemin = (1..100)
        .map(|n| {
            if n == 1 {
                rep.join(nom)
            } else {
                rep.join(format!("{base}-{n}.md"))
            }
        })
        .find(|c| std::fs::symlink_metadata(c).is_err())
        .ok_or_else(|| {
            Echec::refuse(
                "signaler/ecrire",
                tr!(
                    "trop de brouillons ce même instant",
                    "too many drafts at the same moment"
                ),
            )
        })?;
    crate::socle::ecrire_atomique(&chemin, texte).map_err(|e| Echec::ecriture("signaler/ecrire", &e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Echec::ecriture("signaler/droits", &e))?;
    }
    Ok(chemin)
}

/// Les brouillons de `dossier/signalements/` : seulement les simples fichiers `.md`, jamais un lien ni autre chose.
fn brouillons_dans(dossier: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dossier.join(DOSSIER))
        .map(|l| {
            l.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "md"))
                .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file()))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Le nombre de brouillons gardés dans un dossier de données : la désinstallation le dit avant de l'effacer (un
/// brouillon peut être le seul écrit d'une faille pas encore soumise).
pub(crate) fn nombre_dans(dossier: &Path) -> usize {
    brouillons_dans(dossier).len()
}

/// `--effacer` : les brouillons listés, puis effacés après accord.
fn effacer() -> Result<(), Echec> {
    let dossier = crate::socle::dossier_local();
    let liste = brouillons_dans(&dossier);
    if liste.is_empty() {
        trp!("  Aucun brouillon de signalement.", "  No report draft.");
        return Ok(());
    }
    for p in &liste {
        println!("  {}", chemin_affichable(p));
    }
    if !crate::langue::oui(&demander(&trf!(
        "\n  Effacer ces {} brouillon(s) ? [o/N] : ",
        "\n  Erase these {} draft(s)? [y/N]: ",
        liste.len()
    ))) {
        return Ok(());
    }
    let effaces = effacer_liste(&liste)?;
    trp!(
        "  {VERT}✔{RESET} {} brouillon(s) effacé(s).",
        "  {VERT}✔{RESET} {} draft(s) erased.",
        effaces
    );
    Ok(())
}

fn effacer_liste(liste: &[PathBuf]) -> Result<usize, Echec> {
    for p in liste {
        std::fs::remove_file(p).map_err(|e| Echec::ecriture("signaler/effacer", &e))?;
    }
    Ok(liste.len())
}

#[cfg(test)]
mod tests;
