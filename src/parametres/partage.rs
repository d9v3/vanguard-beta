//! Le partage avec l'auteur (A5) : l'interrupteur du relevé (`amelioration`) et de l'envoi (`envoi`), gardé dans
//! le fichier des paramètres (`partage` : « oui », « non », absent) et relu sur le disque avant chaque écriture du relevé et
//! avant chaque POST : un « non » donné ici arrête aussi un autre Vanguard déjà lancé.
//!
//! - **Phase 1** (aujourd'hui, `PHASE`) : en marche une fois l'avis montré (E8) ; « non » le coupe.
//! - **Phase 2** (L7g, avant la 1.0) : la question au lancement, sans valeur par défaut cachée (E11) ; un « oui » de
//!   la phase 1 ne vaut plus, la question est posée ; un « non » est gardé (E12).
//! - Écrit hors de Vanguard, un « oui » (ou un avis dit montré) ne vaut rien ; un « non », si (E9).
//! - « Non » efface le relevé, la file et l'identifiant d'installation ; rien de relevé jusqu'au jour d'un accord ne
//!   part jamais (`envoi::tenir`).
//! - « Non » est aussi marqué hors du fichier des paramètres (`MARQUE_NON`) : une version d'avant, qui réécrit ce
//!   fichier sans le partage, ne l'efface pas ; seul un « oui » donné dans Vanguard retire la marque.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::io::IsTerminal as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::{Fichier, PARAMETRES, charger_juge, fichier, modifier_dans};
use crate::selection::{Ligne, choisir_sans_defaut};
use crate::ui::*;

/// La phase du partage. La phase 2 (L7g) s'ouvre en changeant cette constante, au plus tard dans la dernière version
/// avant la 1.0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Un,
    #[cfg_attr(not(test), allow(dead_code))] // ouverte par L7g
    Deux,
}

pub(crate) const PHASE: Phase = Phase::Un;

impl Phase {
    fn numero(self) -> u8 {
        match self {
            Phase::Un => 1,
            Phase::Deux => 2,
        }
    }
}

/// Ce que la personne a choisi.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Choix {
    Oui,
    Non,
}

/// Une réponse à la question : « plus tard » (vide, fin de l'entrée, inconnue) n'en est pas une.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reponse {
    Oui,
    Non,
    Voir,
}

/// La réponse tapée (ou la touche choisie), dans l'une ou l'autre langue. Rien d'autre ne vaut : « peut-être », une
/// ligne vide ou « ↵ » ne disent ni oui ni non.
pub(crate) fn reponse_de(saisie: &str) -> Option<Reponse> {
    match saisie.trim().to_lowercase().as_str() {
        "1" | "oui" | "o" | "yes" | "y" => Some(Reponse::Oui),
        "2" | "non" | "n" | "no" => Some(Reponse::Non),
        "3" | "voir" | "v" | "see" | "view" | "s" => Some(Reponse::Voir),
        _ => None,
    }
}

fn date(texte: Option<&str>) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(texte?, "%Y-%m-%d").ok()
}

fn jour(d: NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

/// Le jour de l'accord que donne `f` en `phase`, s'il en donne un. Un jour du futur (horloge reculée, fichier forgé)
/// n'en est pas un : rien ne part tant que l'horloge ne l'a pas rattrapé.
fn accord_de(f: &Fichier, phase: Phase, aujourd_hui: NaiveDate) -> Option<NaiveDate> {
    let le = match (f.partage, phase) {
        // Un « oui » d'avant la question (phase 1) ne vaut pas la réponse à la question ; sans réponse en phase 2,
        // rien.
        (Some(Choix::Oui), Phase::Deux) if f.partage_phase.unwrap_or(1) < 2 => None,
        (Some(Choix::Oui), _) => date(f.partage_le.as_deref()),
        (None, Phase::Un) => date(f.avis_partage.as_deref()),
        (Some(Choix::Non), _) | (None, Phase::Deux) => None,
    }?;
    (le <= aujourd_hui).then_some(le)
}

/// L'accord gardé dans `dossier` : le fichier relu sous son sceau (un « oui » forgé n'y est déjà plus). Illisible,
/// ou un « non » marqué (`MARQUE_NON`) : aucun.
pub(crate) fn accord_dans(dossier: &Path, aujourd_hui: NaiveDate) -> Option<NaiveDate> {
    if marque_dans(dossier) {
        return None;
    }
    let (f, _) = charger_juge(&dossier.join(PARAMETRES)).ok()?;
    accord_de(&f, PHASE, aujourd_hui)
}

/// « Non » gardé dans `dossier` ? La marque du refus (`MARQUE_NON`), un fichier illisible, ou disparu après avoir été
/// scellé, comptent pour un « non » : au doute, rien n'est relevé.
pub(crate) fn refuse_dans(dossier: &Path) -> bool {
    marque_dans(dossier)
        || disparu(dossier)
        || charger_juge(&dossier.join(PARAMETRES)).map_or(true, |(f, _)| f.partage == Some(Choix::Non))
}

/// La marque d'un « non », à côté du fichier des paramètres et hors de lui. Une version d'avant le partage (0.89.0 et
/// plus ancienne) relit ce fichier et le réécrit sans les champs qu'elle ne connaît pas : le « non » partait avec eux,
/// et en phase 1 un partage sans réponse vaut accord une fois l'avis montré. Ce nom-là, aucune version d'avant ne le
/// lit, ne l'écrit ni ne l'efface ; « Non » (qui vide `amelioration/` et `envoi/`) non plus.
///
/// Elle ne dit jamais que « non » : sa seule présence, sous n'importe quelle forme (fichier, lien, dossier, contenu
/// quelconque), ou le doute sur elle (pas lisible), vaut refus, quoi que dise le fichier des paramètres, jusqu'à un
/// « oui » donné dans Vanguard, qui la retire. Absente, elle ne donne rien : le fichier des paramètres décide. Sans
/// sceau, donc : un « non » forgé est respecté, et un « oui » ne peut pas venir d'elle.
pub(crate) const MARQUE_NON: &str = "partage-non";

/// La marque est-elle là, ou ne peut-on pas savoir ? Seul « elle n'existe pas » dit non.
fn marque_dans(dossier: &Path) -> bool {
    !matches!(
        std::fs::symlink_metadata(dossier.join(MARQUE_NON)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// Pose la marque, sauf si quelque chose est déjà à sa place : cela vaut refus tel quel, et rien n'est suivi ni
/// remplacé.
fn poser_marque_dans(dossier: &Path, aujourd_hui: NaiveDate) -> std::io::Result<()> {
    let chemin = dossier.join(MARQUE_NON);
    match std::fs::symlink_metadata(&chemin) {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }
    if !crate::socle::ecriture_sure(dossier) {
        return Err(std::io::Error::other("dossier de Vanguard pas sûr"));
    }
    // Le contenu ne compte pas (seule la présence vaut) : il dit ce qu'est ce fichier à qui l'ouvre.
    crate::socle::ecrire_atomique(
        &chemin,
        format!(
            "Vanguard : « non » au partage avec l'auteur, le {}. / \"no\" to sharing with the author.\n",
            jour(aujourd_hui)
        ),
    )
}

/// Retire la marque sans rien suivre : un fichier ou un lien est retiré ; un dossier seulement s'il est vide (rien
/// n'est effacé dedans), sinon il reste, et le refus avec lui.
fn retirer_marque_dans(dossier: &Path) -> std::io::Result<()> {
    let chemin = dossier.join(MARQUE_NON);
    match std::fs::symlink_metadata(&chemin) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => std::fs::remove_dir(&chemin),
        // Un lien vers un dossier, sous Windows, ne se retire que par `remove_dir`, qui ne suit pas le lien (ailleurs,
        // il refuse un lien).
        Ok(_) => std::fs::remove_file(&chemin).or_else(|e| std::fs::remove_dir(&chemin).map_err(|_| e)),
    }
}

/// Enregistre `choix` dans `dossier` : le fichier des paramètres et la marque du « non ». « Non » : la marque d'abord
/// (dès qu'elle est là, le refus tient, même si le fichier ne s'écrit pas) ; « oui » : le fichier d'abord, la marque
/// retirée ensuite (jusque-là, le refus tient). Un « oui » qui lève la marque prend le jour d'aujourd'hui, même si le
/// fichier en gardait un plus ancien : rien de relevé avant ne part. Rend la première erreur.
///
/// Sans verrou, un « oui » et un « non » donnés en même temps (deux Vanguard ouverts) pourraient finir en « non » dans
/// le fichier sans marque, que la 0.89.0 oublierait : le « non » repose donc la marque après le fichier, et le « oui »
/// relit le fichier après l'avoir retirée. Quel que soit l'ordre, l'un des deux voit l'autre.
fn enregistrer_choix_dans(dossier: &Path, choix: Choix, aujourd_hui: NaiveDate) -> std::io::Result<()> {
    let chemin = dossier.join(PARAMETRES);
    match choix {
        Choix::Non => {
            let marque = poser_marque_dans(dossier, aujourd_hui);
            let fichier = ecrire_choix_dans(&chemin, choix, aujourd_hui);
            let encore = poser_marque_dans(dossier, aujourd_hui);
            marque.and(fichier).and(encore)
        }
        Choix::Oui => {
            ecrire_choix_garde(&chemin, choix, aujourd_hui, !marque_dans(dossier))?;
            retirer_marque_dans(dossier)?;
            garder_un_non_arrive(dossier, aujourd_hui)
        }
    }
}

/// Après un « oui » qui a retiré la marque : si le fichier ne dit plus « oui » (un « non » écrit entre-temps, ou un
/// doute), la marque revient et le « oui » n'est pas pris.
fn garder_un_non_arrive(dossier: &Path, aujourd_hui: NaiveDate) -> std::io::Result<()> {
    if !refuse_dans(dossier) {
        return Ok(());
    }
    poser_marque_dans(dossier, aujourd_hui)?;
    Err(std::io::Error::other(tr!(
        "un « non » donné en même temps l'emporte",
        "a “no” given at the same time wins"
    )))
}

/// Le fichier des paramètres a disparu après avoir été scellé, ou les sceaux ont été refaits sans lui : un « non »
/// a pu partir avec lui (effacé à la main, par un autre programme). Rien ne part ni ne se relève jusqu'à une
/// nouvelle réponse, qui le réécrit.
fn disparu(dossier: &Path) -> bool {
    matches!(
        crate::sceau::lire_sans_ecrire(dossier, PARAMETRES),
        crate::sceau::Lecture::Falsifie(None) | crate::sceau::Lecture::Inconnu
    )
}

/// Seulement des mots entiers : sans terminal, la ligne lue vient peut-être d'un script qui répondait à autre chose
/// (« 1 » pour le bilan, `yes |`), et un accord ne se donne pas ainsi.
fn reponse_en_mots(saisie: &str) -> Option<Reponse> {
    match saisie.trim().to_lowercase().as_str() {
        "oui" | "yes" => Some(Reponse::Oui),
        "non" | "no" => Some(Reponse::Non),
        "voir" | "see" | "view" => Some(Reponse::Voir),
        _ => None,
    }
}

/// Enregistre `choix` du jour `aujourd_hui`. Un « oui » déjà là, de cette phase, garde son jour.
fn ecrire_choix_dans(chemin: &Path, choix: Choix, aujourd_hui: NaiveDate) -> std::io::Result<()> {
    ecrire_choix_garde(chemin, choix, aujourd_hui, true)
}

/// `ecrire_choix_dans` ; sans `garder`, le jour est celui d'aujourd'hui même si le même choix était déjà là.
fn ecrire_choix_garde(chemin: &Path, choix: Choix, aujourd_hui: NaiveDate, garder: bool) -> std::io::Result<()> {
    modifier_dans(chemin, |f| {
        let deja = garder
            && f.partage == Some(choix)
            && f.partage_phase == Some(PHASE.numero())
            && date(f.partage_le.as_deref()).is_some_and(|d| d <= aujourd_hui);
        if deja {
            return false;
        }
        f.partage = Some(choix);
        f.partage_le = Some(jour(aujourd_hui));
        f.partage_phase = Some(PHASE.numero());
        true
    })
}

/// L'avis montré (phase 1), noté une fois.
fn noter_avis_dans(chemin: &Path, aujourd_hui: NaiveDate) -> std::io::Result<()> {
    modifier_dans(chemin, |f| {
        if f.avis_partage.is_some() {
            return false;
        }
        f.avis_partage = Some(jour(aujourd_hui));
        true
    })
}

fn aujourd_hui() -> NaiveDate {
    chrono::Local::now().date_naive()
}

fn envoi_coupe() -> bool {
    std::env::var("VANGUARD_ENVOI").is_ok_and(|v| v.trim() == "0")
}

/// « Non » donné dans ce processus : le relevé et l'envoi y restent arrêtés jusqu'au prochain lancement.
static COUPE_ICI: AtomicBool = AtomicBool::new(false);

// --- Ce qui se lit -----------------------------------------------------------------------------------------------

/// La valeur montrée dans Paramètres (33 caractères au plus avec la variable).
pub(crate) fn etat_court() -> String {
    let chemin = fichier();
    let dossier = chemin.parent().unwrap_or_else(|| Path::new("."));
    let mut texte = match charger_juge(&chemin) {
        _ if marque_dans(dossier) => tr!("non", "no").to_string(),
        Ok(_) if disparu(dossier) => tr!("fichier effacé : rien ne part", "file erased: nothing is sent").to_string(),
        Err(_) => tr!("illisible : rien ne part", "unreadable: nothing is sent").to_string(),
        Ok((f, _)) => match (f.partage, PHASE) {
            (Some(Choix::Non), _) => tr!("non", "no").to_string(),
            (Some(Choix::Oui), _) if accord_de(&f, PHASE, aujourd_hui()).is_some() => tr!("oui", "yes").to_string(),
            (Some(Choix::Oui), _) => tr!("oui, pas encore valable", "yes, not valid yet").to_string(),
            (None, Phase::Un) if f.avis_partage.is_some() => tr!("oui (avis montré)", "yes (notice shown)").to_string(),
            (None, _) => tr!("pas répondu", "no answer").to_string(),
        },
    };
    if envoi_coupe() {
        texte += tr!(" (VANGUARD_ENVOI=0 l'emporte)", " (VANGUARD_ENVOI=0 wins)");
    }
    texte
}

/// Ce que fait le réglage, sous la question et dans l'aide.
pub(crate) fn explication() -> &'static str {
    tr!(
        "Vanguard relève sur cet ordinateur ses erreurs, ses lenteurs, le résultat des corrections, les choix faits dans Vanguard, le matériel et le nom des logiciels, services et pilotes en cause ; jamais de mot de passe, de fichier, de site visité ni de texte tapé. Oui : ce relevé part à l'auteur une fois par jour, pour améliorer Vanguard (rien de ce qui a été relevé avant ce jour-là ne part). Non : il s'arrête, et ce qui a été relevé est effacé avec l'identifiant d'installation.",
        "Vanguard records on this computer its errors, slowdowns, the result of fixes, the choices made in Vanguard, the hardware and the name of the software, services and drivers involved; never a password, file, visited site or typed text. Yes: this record goes to the author once a day, to improve Vanguard (nothing recorded before that day is ever sent). No: it stops, and what was recorded is erased along with the installation identifier."
    )
}

fn dire_relais_absent() {
    if crate::envoi::RELAIS.is_none() {
        afficher_aligne(
            "  ",
            tr!(
                "Le relais de l'auteur n'est pas encore en service : rien ne part pour l'instant.",
                "The author's relay is not in service yet: nothing is sent for now."
            ),
            2,
            GRIS,
        );
    }
}

/// `vanguard parametres partage` : la valeur, ce qu'elle veut dire, les valeurs acceptées.
pub(crate) fn afficher() {
    trp!("  partage : {}", "  sharing: {}", etat_court());
    afficher_aligne("  ", explication(), 2, GRIS);
    dire_relais_absent();
    trp!(
        "  Valeurs : oui, non, voir (ce qui serait envoyé).",
        "  Values: yes, no, see (what would be sent)."
    );
}

/// Le lot en JSON, mis en retrait pour la lecture : des retours à la ligne et des espaces hors des chaînes, rien
/// d'autre ; chaque ligne passée par `affichable` (un texte relevé ne pilote pas le terminal).
fn en_retrait(octets: &[u8]) -> Vec<String> {
    let texte = String::from_utf8_lossy(octets);
    let mut lignes = Vec::new();
    let mut ligne = String::new();
    let mut profondeur = 0usize;
    let (mut dans_chaine, mut echappe) = (false, false);
    let couper = |ligne: &mut String, profondeur: usize, lignes: &mut Vec<String>| {
        lignes.push(affichable(&std::mem::take(ligne)));
        *ligne = "  ".repeat(profondeur.saturating_add(1));
    };
    ligne.push_str("  ");
    for c in texte.chars() {
        if dans_chaine {
            ligne.push(c);
            if echappe {
                echappe = false;
            } else if c == '\\' {
                echappe = true;
            } else if c == '"' {
                dans_chaine = false;
            }
            continue;
        }
        match c {
            '"' => {
                dans_chaine = true;
                ligne.push(c);
            }
            '{' | '[' => {
                ligne.push(c);
                profondeur = profondeur.saturating_add(1);
                couper(&mut ligne, profondeur, &mut lignes);
            }
            '}' | ']' => {
                profondeur = profondeur.saturating_sub(1);
                couper(&mut ligne, profondeur, &mut lignes);
                ligne.push(c);
            }
            ',' => {
                ligne.push(c);
                couper(&mut ligne, profondeur, &mut lignes);
            }
            ':' => ligne.push_str(": "),
            _ => ligne.push(c),
        }
    }
    lignes.push(affichable(&ligne));
    lignes.retain(|l| !l.trim().is_empty());
    lignes
}

/// « Voir ce qui serait envoyé » : le prochain lot, la file, le dernier envoi ; rien n'est écrit.
pub(crate) fn voir() {
    println!();
    println!("{}", ligne_titre(tr!("Ce qui serait envoyé", "What would be sent")));
    dire_relais_absent();
    if refuse_dans(&crate::socle::dossier_local()) {
        afficher_aligne(
            "  ",
            tr!(
                "Partage coupé : rien n'est gardé pour l'envoi. Les bilans, les réglages et les mesures de l'autodiagnostic restent sur cet ordinateur, à vous.",
                "Sharing off: nothing is kept for sending. Scans, settings and self-test measurements stay on this computer, yours."
            ),
            2,
            "",
        );
        return;
    }
    let a = crate::envoi::apercu();
    trp!("  En attente : {} lot(s).", "  Waiting: {} batch(es).", a.en_attente);
    let jamais = tr!("jamais", "never").to_string();
    trp!(
        "  Dernier envoi réussi : {}.",
        "  Last successful send: {}.",
        a.dernier_succes.unwrap_or(jamais)
    );
    if let Some(r) = a.dernier_echec {
        trp!(
            "  Dernier échec : {}.",
            "  Last failure: {}.",
            crate::envoi::raison_texte(r)
        );
    }
    let Some(lot) = a.lot else {
        trp!(
            "  Rien de relevé pour l'instant : aucun lot à montrer.",
            "  Nothing recorded yet: no batch to show."
        );
        return;
    };
    println!();
    if a.en_file {
        trp!("  Le prochain lot, en file :", "  The next batch, queued:");
    } else {
        trp!(
            "  Le lot du relevé le plus récent, refait pour voir :",
            "  The batch of the latest record, rebuilt to see it:"
        );
    }
    for l in en_retrait(&lot) {
        println!("{l}");
    }
    afficher_aligne(
        "  ",
        &trf!(
            "Mis en retrait pour la lecture : sans les retraits, ce sont ces {} octets qui partiraient.",
            "Indented for reading: without the indentation, these are the {} bytes that would be sent.",
            lot.len()
        ),
        2,
        GRIS,
    );
}

// --- Ce qui change -----------------------------------------------------------------------------------------------

fn dire_oui() -> bool {
    let dossier = crate::socle::dossier_local();
    if let Err(e) = enregistrer_choix_dans(&dossier, Choix::Oui, aujourd_hui()) {
        // Le fichier a pu prendre le « oui » sans que la marque parte : le refus tient, il faut le dire tel quel.
        if refuse_dans(&dossier) {
            trp!(
                "  ✖ « Oui » pas pris ({e}) : le « non » tient, rien n'est relevé ni envoyé.",
                "  ✖ “Yes” not taken ({e}): the “no” holds, nothing is recorded or sent."
            );
        } else {
            trp!("  ✖ Non enregistré ({e}).", "  ✖ Not saved ({e}).");
        }
        return false;
    }
    trp!(
        "  ✔ Partage avec l'auteur : oui. Rien de relevé avant ce jour ne part.",
        "  ✔ Sharing with the author: yes. Nothing recorded before today is sent."
    );
    if COUPE_ICI.load(Ordering::SeqCst) {
        trp!(
            "  Le relevé reprend au prochain lancement de Vanguard.",
            "  Recording resumes the next time Vanguard starts."
        );
    }
    if envoi_coupe() {
        trp!(
            "  VANGUARD_ENVOI=0 l'emporte : rien n'est relevé ni envoyé.",
            "  VANGUARD_ENVOI=0 wins: nothing is recorded or sent."
        );
    }
    dire_relais_absent();
    true
}

/// « Non » : enregistré d'abord (les autres Vanguard le lisent avant leur prochaine écriture), puis l'envoi de ce
/// processus arrêté et sa file vidée, puis le relevé arrêté et effacé, le verrou de l'agent tenu : aucun tour ne
/// réécrit un jour pendant l'effacement. Jamais appelé des essais : il arrêterait tout le processus d'essai.
fn dire_non() -> bool {
    let dossier = crate::socle::dossier_local();
    let enregistre = enregistrer_choix_dans(&dossier, Choix::Non, aujourd_hui());
    COUPE_ICI.store(true, Ordering::SeqCst);
    let envoi = crate::envoi::arreter_et_vider();
    let geste = crate::agent::geste_dans(&dossier);
    let releve = crate::amelioration::arreter_et_effacer();
    let tour_en_cours = geste.is_err();
    drop(geste);
    match &enregistre {
        Ok(()) => trp!(
            "  ✔ Partage avec l'auteur : non. Plus rien n'est relevé ni envoyé.",
            "  ✔ Sharing with the author: no. Nothing is recorded or sent anymore."
        ),
        // La marque ou le fichier tient : le « non » reste, mais pas aussi sûrement.
        Err(e) if refuse_dans(&dossier) => {
            trp!(
                "  ✔ Partage avec l'auteur : non. Plus rien n'est relevé ni envoyé.",
                "  ✔ Sharing with the author: no. Nothing is recorded or sent anymore."
            );
            trp!(
                "  ⚠ Pas tout enregistré ({e}) : refaites « non » dans un moment.",
                "  ⚠ Not everything saved ({e}): say “no” again in a moment."
            );
        }
        Err(e) => trp!(
            "  ✖ Non enregistré ({e}) : arrêté pour ce lancement seulement.",
            "  ✖ Not saved ({e}): stopped for this run only."
        ),
    }
    if let Some(raison) = crate::amelioration::pourquoi_pas_efface() {
        trp!(
            "  ⚠ Rien d'effacé ici : {raison}.",
            "  ⚠ Nothing erased here: {raison}."
        );
    } else if let Some(e) = envoi.err().or(releve.err()) {
        trp!(
            "  ⚠ Pas tout effacé ({e}) : refaites « non » dans un moment.",
            "  ⚠ Not everything erased ({e}): say “no” again in a moment."
        );
    } else {
        afficher_aligne(
            "  ",
            tr!(
                "Effacés : le relevé (amelioration/), la file de l'envoi (envoi/) et l'identifiant d'installation.",
                "Erased: the record (amelioration/), the sending queue (envoi/) and the installation identifier."
            ),
            2,
            "",
        );
        if tour_en_cours {
            trp!(
                "  Un tour de l'Agent était en cours : refaites « non » s'il reste.",
                "  An Agent round was running: say “no” again if anything is left."
            );
        }
    }
    enregistre.is_ok()
}

/// `vanguard parametres partage <valeur>`.
pub(crate) fn changer(saisie: &str) -> bool {
    match reponse_de(saisie) {
        Some(Reponse::Oui) => dire_oui(),
        Some(Reponse::Non) => dire_non(),
        Some(Reponse::Voir) => {
            voir();
            false
        }
        None => {
            trp!(
                "  ✖ Valeur inconnue : « {} ». Valeurs : oui, non, voir.",
                "  ✖ Unknown value: “{}”. Values: yes, no, see.",
                affichable(saisie)
            );
            false
        }
    }
}

/// Les lignes de la question : aucun des trois choix n'est pris d'avance ; « ↵ » (plus tard) ne change rien.
fn lignes_de_la_question(titre: &str) -> Vec<Ligne> {
    let mut lignes = vec![Ligne::Texte(String::new()), Ligne::Texte(ligne_titre(titre))];
    lignes.extend(
        envelopper(explication(), LARGEUR - 4)
            .into_iter()
            .map(|l| Ligne::Texte(format!("  {GRIS}{l}{RESET}"))),
    );
    lignes.push(Ligne::Texte(format!(
        "  {}",
        trf!("En ce moment : {}.", "Right now: {}.", etat_court())
    )));
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix(
        "1",
        tr!("Oui", "Yes"),
        tr!("une fois par jour", "once a day"),
    ));
    lignes.push(Ligne::choix(
        "2",
        tr!("Non", "No"),
        tr!("arrêter et effacer le relevé", "stop and erase the record"),
    ));
    lignes.push(Ligne::choix(
        "3",
        tr!("Voir ce qui serait envoyé", "See what would be sent"),
        "",
    ));
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix(
        "↵",
        tr!("Plus tard", "Later"),
        tr!("rien ne change", "nothing changes"),
    ));
    lignes
}

/// La question, reposée après « Voir » ; « plus tard », Échap, une ligne vide, une fin de lecture ou une réponse
/// inconnue ne changent rien. Rend la réponse donnée.
fn poser(titre: &str) -> Option<Reponse> {
    let par_tube = !std::io::stdin().is_terminal();
    let invite = if par_tube {
        tr!(
            "\n  Réponse : oui, non ou voir (Entrée : plus tard) : ",
            "\n  Answer: yes, no or see (Enter: later): "
        )
    } else {
        tr!(
            "\n  Choix : 1, 2 ou 3 (Entrée : plus tard) : ",
            "\n  Choice: 1, 2 or 3 (Enter: later): "
        )
    };
    loop {
        let lignes = lignes_de_la_question(titre);
        let saisie = choisir_sans_defaut(&lignes, invite, "↵", tr!("plus tard", "later"))?;
        // Entrée sur « Plus tard », au clavier.
        if saisie == "↵" {
            return None;
        }
        let lue = if par_tube {
            reponse_en_mots(&saisie)
        } else {
            reponse_de(&saisie)
        };
        let Some(reponse) = lue else {
            if reponse_de(&saisie).is_some() {
                trp!(
                    "  « {} » : sans terminal, répondez par un mot ; rien ne change.",
                    "  “{}”: without a terminal, answer with a word; nothing changes.",
                    affichable(&saisie)
                );
            } else {
                trp!(
                    "  « {} » : réponse inconnue ; rien ne change.",
                    "  “{}”: unknown answer; nothing changes.",
                    affichable(&saisie)
                );
            }
            return None;
        };
        match reponse {
            Reponse::Voir => {
                voir();
                if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
                    crate::selection::attendre_retour(tr!(
                        "\n  Entrée pour revenir à la question… ",
                        "\n  Enter to go back to the question… "
                    ));
                }
            }
            r @ (Reponse::Oui | Reponse::Non) => return Some(r),
        }
    }
}

/// Paramètres › Partage avec l'auteur.
pub(crate) fn menu() {
    match poser(tr!("Partager avec l'auteur ?", "Share with the author?")) {
        Some(Reponse::Oui) => {
            dire_oui();
        }
        Some(Reponse::Non) => {
            dire_non();
        }
        Some(Reponse::Voir) | None => {}
    }
}

// --- Au lancement --------------------------------------------------------------------------------------------------

/// Ce que le lancement à la main montre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuLancement {
    Rien,
    /// Phase 1 : l'avis, une fois, dans un terminal (E8).
    Avis,
    /// Phase 2 : la question, terminal ou non, jusqu'à une réponse (E11, E12) ; sans terminal, seuls les mots
    /// entiers y valent (`reponse_en_mots`).
    Question,
}

/// Rien tant que le relais n'est pas en service ou que ce processus ne relève pas : l'avis dirait une chose fausse.
/// Un fichier illisible ne montre rien (rien ne part non plus). Un fichier disparu (`disparu`) a peut-être emporté un
/// « non » : la question, dans un terminal, plutôt que l'avis, dont l'appui vaudrait accord.
fn au_lancement(f: Option<&Fichier>, phase: Phase, en_service: bool, terminal: bool, disparu: bool) -> AuLancement {
    let Some(f) = f.filter(|_| en_service) else {
        return AuLancement::Rien;
    };
    if disparu {
        return if terminal {
            AuLancement::Question
        } else {
            AuLancement::Rien
        };
    }
    match (phase, f.partage) {
        (Phase::Un, None) if f.avis_partage.is_none() && terminal => AuLancement::Avis,
        (_, Some(Choix::Non)) | (Phase::Un, _) => AuLancement::Rien,
        (Phase::Deux, Some(Choix::Oui)) if f.partage_phase.unwrap_or(1) >= 2 => AuLancement::Rien,
        (Phase::Deux, _) => AuLancement::Question,
    }
}

/// À l'ouverture du menu : l'avis (phase 1) ou la question (phase 2), quand il y a lieu.
pub(crate) fn au_menu() {
    let en_service = crate::envoi::RELAIS.is_some() && crate::amelioration::actif();
    let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let chemin = fichier();
    let dossier = chemin.parent().unwrap_or_else(|| Path::new("."));
    // Un « non » marqué : rien à montrer (sans fichier lu, `au_lancement` ne montre rien), ni l'avis, dont l'appui
    // vaudrait accord, ni la question.
    let lu = if marque_dans(dossier) {
        None
    } else {
        charger_juge(&chemin).ok().map(|(f, _)| f)
    };
    let parti = disparu(dossier);
    match au_lancement(lu.as_ref(), PHASE, en_service, terminal, parti) {
        AuLancement::Rien => {}
        AuLancement::Avis => {
            println!();
            println!(
                "{}",
                ligne_titre(tr!("Partage avec l'auteur", "Sharing with the author"))
            );
            afficher_aligne(
                "  ",
                tr!(
                    "Vanguard envoie à son auteur, une fois par jour, ses erreurs, lenteurs, résultats des corrections, choix faits dans Vanguard, matériel, et le nom des logiciels, services et pilotes en cause. Jamais de mot de passe, de fichier, de site visité ni de texte tapé. Voir : vanguard parametres partage voir. Couper : vanguard parametres partage non.",
                    "Vanguard sends its author, once a day, its errors, slowdowns, fix results, choices made in Vanguard, hardware, and the name of the software, services and drivers involved. Never a password, file, visited site or typed text. See: vanguard settings sharing see. Turn off: vanguard settings sharing no."
                ),
                2,
                "",
            );
            crate::selection::attendre_retour(tr!("\n  Entrée pour continuer… ", "\n  Enter to continue… "));
            // Noté après l'appui seulement : un programme fermé avant n'a pas vu l'avis.
            let _ = noter_avis_dans(&fichier(), aujourd_hui());
        }
        AuLancement::Question => menu(),
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn d(j: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, j).unwrap()
    }

    fn jetable(nom: &str) -> std::path::PathBuf {
        let dossier = crate::essais::temporaire().join(format!("vanguard-partage-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        dossier
    }

    fn avec(partage: Option<Choix>, le: Option<&str>, phase: Option<u8>, avis: Option<&str>) -> Fichier {
        Fichier {
            partage,
            partage_le: le.map(str::to_string),
            partage_phase: phase,
            avis_partage: avis.map(str::to_string),
            ..Fichier::default()
        }
    }

    /// La phase 2 s'ouvre par L7g, pas ici.
    #[test]
    fn la_phase_reste_la_premiere() {
        assert_eq!(PHASE, Phase::Un);
    }

    #[test]
    fn accord_selon_la_phase() {
        let aujourd_hui = d(10);
        // Phase 1 : l'avis montré suffit ; sans avis, rien.
        assert_eq!(accord_de(&Fichier::default(), Phase::Un, aujourd_hui), None);
        assert_eq!(
            accord_de(&avec(None, None, None, Some("2026-11-03")), Phase::Un, aujourd_hui),
            Some(d(3))
        );
        // « Non » l'emporte sur tout, avis compris.
        let non = avec(Some(Choix::Non), Some("2026-11-05"), Some(1), Some("2026-11-03"));
        assert_eq!(accord_de(&non, Phase::Un, aujourd_hui), None);
        assert_eq!(accord_de(&non, Phase::Deux, aujourd_hui), None);
        // « Oui » : son jour.
        let oui1 = avec(Some(Choix::Oui), Some("2026-11-04"), Some(1), None);
        assert_eq!(accord_de(&oui1, Phase::Un, aujourd_hui), Some(d(4)));
        // Phase 2 : ni l'avis ni un « oui » de la phase 1 ne valent.
        assert_eq!(
            accord_de(&avec(None, None, None, Some("2026-11-03")), Phase::Deux, aujourd_hui),
            None
        );
        assert_eq!(accord_de(&oui1, Phase::Deux, aujourd_hui), None);
        assert_eq!(
            accord_de(
                &avec(Some(Choix::Oui), Some("2026-11-04"), None, None),
                Phase::Deux,
                aujourd_hui
            ),
            None
        );
        let oui2 = avec(Some(Choix::Oui), Some("2026-11-06"), Some(2), None);
        assert_eq!(accord_de(&oui2, Phase::Deux, aujourd_hui), Some(d(6)));
        // Un jour du futur, ou illisible, n'est pas un accord.
        assert_eq!(
            accord_de(
                &avec(Some(Choix::Oui), Some("2026-11-11"), Some(1), None),
                Phase::Un,
                aujourd_hui
            ),
            None
        );
        assert_eq!(
            accord_de(
                &avec(Some(Choix::Oui), Some("demain"), Some(1), None),
                Phase::Un,
                aujourd_hui
            ),
            None
        );
        assert_eq!(
            accord_de(&avec(Some(Choix::Oui), None, Some(1), None), Phase::Un, aujourd_hui),
            None
        );
        assert_eq!(
            accord_de(&avec(None, None, None, Some("2027-01-01")), Phase::Un, aujourd_hui),
            None
        );
    }

    /// Une réponse vide, une fin de lecture, « peut-être » ou « ↵ » ne disent rien.
    #[test]
    fn seules_trois_reponses_valent() {
        for (s, r) in [
            ("1", Reponse::Oui),
            ("oui", Reponse::Oui),
            (" Yes ", Reponse::Oui),
            ("2", Reponse::Non),
            ("NON", Reponse::Non),
            ("no", Reponse::Non),
            ("3", Reponse::Voir),
            ("voir", Reponse::Voir),
            ("see", Reponse::Voir),
        ] {
            assert_eq!(reponse_de(s), Some(r), "{s}");
        }
        for s in ["", " ", "peut-être", "maybe", "↵", "4", "0", "oui non", "ouii"] {
            assert_eq!(reponse_de(s), None, "{s}");
            assert_eq!(reponse_en_mots(s), None, "{s}");
        }
        // Sans terminal, les mots entiers seulement.
        for s in ["1", "2", "3", "o", "y", "n", "v", "s"] {
            assert!(reponse_de(s).is_some() && reponse_en_mots(s).is_none(), "{s}");
        }
        for (s, r) in [(" OUI ", Reponse::Oui), ("no", Reponse::Non), ("voir", Reponse::Voir)] {
            assert_eq!(reponse_en_mots(s), Some(r), "{s}");
        }
    }

    /// Écrit hors de Vanguard : un « oui » ou un avis dit montré ne valent rien, un « non » est gardé. Écrit par
    /// Vanguard, ils valent.
    #[test]
    fn fichier_falsifie() {
        let dossier = jetable("falsifie");
        let chemin = dossier.join(PARAMETRES);
        // Jamais écrit : ni refus ni accord.
        assert!(!disparu(&dossier) && !refuse_dans(&dossier));
        for forge in [
            r#"{"partage":"oui","partage_le":"2026-11-01","partage_phase":2}"#,
            r#"{"avis_partage":"2026-11-01"}"#,
        ] {
            crate::sceau::ecrire_dans(&dossier, PARAMETRES, b"{}").unwrap();
            std::fs::write(&chemin, forge).unwrap();
            let (f, douteux) = charger_juge(&chemin).unwrap();
            assert!(douteux.is_some(), "{forge}");
            assert_eq!(accord_dans(&dossier, d(10)), None, "{forge}");
            assert_eq!(accord_de(&f, Phase::Deux, d(10)), None, "{forge}");
            assert!(!refuse_dans(&dossier), "{forge}");
        }
        crate::sceau::ecrire_dans(&dossier, PARAMETRES, b"{}").unwrap();
        std::fs::write(&chemin, r#"{"partage":"non","avis_partage":"2026-11-01"}"#).unwrap();
        assert!(refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), None);
        // Illisible : refusé, sans accord.
        crate::sceau::ecrire_dans(&dossier, PARAMETRES, b"{}").unwrap();
        std::fs::write(&chemin, "{pas du json").unwrap();
        assert!(refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), None);
        // Une valeur inconnue ne se lit pas : refusé aussi.
        crate::sceau::ecrire_dans(&dossier, PARAMETRES, br#"{"partage":"peut-etre"}"#).unwrap();
        assert!(refuse_dans(&dossier));
        // Écrit par Vanguard : vaut, et un « oui » redit garde son jour.
        let _ = std::fs::remove_file(&chemin);
        ecrire_choix_dans(&chemin, Choix::Oui, d(4)).unwrap();
        ecrire_choix_dans(&chemin, Choix::Oui, d(8)).unwrap();
        assert_eq!(accord_dans(&dossier, d(10)), Some(d(4)));
        assert!(!refuse_dans(&dossier));
        // « Non » puis « oui » : le jour du nouveau « oui ».
        ecrire_choix_dans(&chemin, Choix::Non, d(8)).unwrap();
        assert!(refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), None);
        ecrire_choix_dans(&chemin, Choix::Oui, d(9)).unwrap();
        assert_eq!(accord_dans(&dossier, d(10)), Some(d(9)));
        // Un « non » dont le fichier disparaît (effacé à la main, par un autre programme) : toujours refusé, sans
        // accord, jusqu'à une nouvelle réponse.
        ecrire_choix_dans(&chemin, Choix::Non, d(9)).unwrap();
        std::fs::remove_file(&chemin).unwrap();
        assert!(disparu(&dossier) && refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), None);
        ecrire_choix_dans(&chemin, Choix::Oui, d(9)).unwrap();
        assert!(!disparu(&dossier) && !refuse_dans(&dossier));
        // Les sceaux effacés avec lui : pareil.
        ecrire_choix_dans(&chemin, Choix::Non, d(9)).unwrap();
        std::fs::remove_file(&chemin).unwrap();
        let _ = std::fs::remove_file(dossier.join("sceaux.json"));
        assert!(
            refuse_dans(&dossier),
            "{:?}",
            crate::sceau::lire_sans_ecrire(&dossier, PARAMETRES)
        );
        // L'avis, noté une fois : son premier jour reste.
        let _ = std::fs::remove_file(&chemin);
        noter_avis_dans(&chemin, d(2)).unwrap();
        noter_avis_dans(&chemin, d(5)).unwrap();
        assert_eq!(accord_dans(&dossier, d(10)), Some(d(2)));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Une version d'avant (0.89.0) réécrit le fichier des paramètres, scellé, sans le partage : le « non » tient par
    /// sa marque, l'avis noté ou un « oui » dans le fichier n'y peuvent rien. Sans marque, rien ne change (phase 1).
    #[test]
    fn non_survit_a_une_version_plus_ancienne() {
        let dossier = jetable("ancienne");
        enregistrer_choix_dans(&dossier, Choix::Non, d(8)).unwrap();
        assert!(dossier.join(MARQUE_NON).is_file());
        for reecrit in [
            &br#"{"langue":"fr"}"#[..],
            br#"{"avis_partage":"2026-11-01"}"#,
            br#"{"partage":"oui","partage_le":"2026-11-01","partage_phase":1}"#,
        ] {
            crate::sceau::ecrire_dans(&dossier, PARAMETRES, reecrit).unwrap();
            let (f, douteux) = charger_juge(&dossier.join(PARAMETRES)).unwrap();
            assert!(douteux.is_none() && f.partage != Some(Choix::Non));
            assert!(refuse_dans(&dossier), "{}", String::from_utf8_lossy(reecrit));
            assert_eq!(
                accord_dans(&dossier, d(10)),
                None,
                "{}",
                String::from_utf8_lossy(reecrit)
            );
        }
        // « Oui » donné dans Vanguard : la marque part, l'accord vaut de ce jour.
        enregistrer_choix_dans(&dossier, Choix::Oui, d(9)).unwrap();
        assert!(!dossier.join(MARQUE_NON).exists() && !refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), Some(d(9)));
        // « Non » la repose.
        enregistrer_choix_dans(&dossier, Choix::Non, d(9)).unwrap();
        assert!(dossier.join(MARQUE_NON).is_file() && refuse_dans(&dossier));
        // Sans marque ni réponse : la phase 1 d'avant, inchangée (rien sans l'avis, accord dès l'avis montré).
        std::fs::remove_file(dossier.join(MARQUE_NON)).unwrap();
        crate::sceau::ecrire_dans(&dossier, PARAMETRES, br#"{"langue":"fr"}"#).unwrap();
        assert!(!refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), None);
        crate::sceau::ecrire_dans(&dossier, PARAMETRES, br#"{"avis_partage":"2026-11-01"}"#).unwrap();
        assert!(!refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), Some(d(1)));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Une marque posée hors de Vanguard, vide, illisible, dossier ou lien : refus, jamais un accord, même devant un
    /// « oui » scellé. Un « oui » la retire sans rien suivre ; un dossier plein reste, et le refus avec lui.
    #[test]
    fn marque_forgee_ou_douteuse() {
        let dossier = jetable("marque");
        let oui = br#"{"partage":"oui","partage_le":"2026-11-01","partage_phase":1}"#;
        let refuse = |quoi: &str| {
            crate::sceau::ecrire_dans(&dossier, PARAMETRES, oui).unwrap();
            assert!(refuse_dans(&dossier), "{quoi}");
            assert_eq!(accord_dans(&dossier, d(10)), None, "{quoi}");
        };
        let marque = dossier.join(MARQUE_NON);
        for contenu in [&b""[..], b"oui", b"{\"partage\":\"oui\"}", &[0xff, 0xfe, 0x00]] {
            std::fs::write(&marque, contenu).unwrap();
            refuse(&String::from_utf8_lossy(contenu));
            enregistrer_choix_dans(&dossier, Choix::Oui, d(9)).unwrap();
            assert!(!marque.exists() && accord_dans(&dossier, d(10)).is_some());
        }
        // Un dossier vide se retire ; plein, il reste, avec ce qu'il contient.
        std::fs::create_dir(&marque).unwrap();
        refuse("dossier vide");
        enregistrer_choix_dans(&dossier, Choix::Oui, d(9)).unwrap();
        assert!(!marque.exists());
        std::fs::create_dir(&marque).unwrap();
        std::fs::write(marque.join("a-moi.txt"), b"alice").unwrap();
        refuse("dossier plein");
        assert!(enregistrer_choix_dans(&dossier, Choix::Oui, d(9)).is_err());
        assert!(marque.join("a-moi.txt").exists());
        refuse("dossier plein, après « oui »");
        // « Non » ne remplace pas ce qui est déjà à la place de la marque.
        enregistrer_choix_dans(&dossier, Choix::Non, d(9)).unwrap();
        assert!(marque.join("a-moi.txt").exists() && refuse_dans(&dossier));
        std::fs::remove_dir_all(&marque).unwrap();
        // Au doute (on ne peut pas savoir si elle est là) : refus. Sous Windows, un chemin à travers un fichier se dit
        // « introuvable », comme une marque absente.
        std::fs::write(dossier.join("pas-un-dossier"), b"").unwrap();
        assert_eq!(accord_dans(&dossier.join("pas-un-dossier"), d(10)), None);
        #[cfg(unix)]
        assert!(marque_dans(&dossier.join("pas-un-dossier")));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un lien à la place de la marque vaut refus, cassé ou non ; « non » ne le suit pas, « oui » retire le lien et
    /// laisse ce qu'il désigne.
    #[cfg(unix)]
    #[test]
    fn marque_en_lien() {
        let dossier = jetable("marque-lien");
        let ailleurs = jetable("marque-ailleurs");
        let marque = dossier.join(MARQUE_NON);
        crate::sceau::ecrire_dans(
            &dossier,
            PARAMETRES,
            br#"{"partage":"oui","partage_le":"2026-11-01","partage_phase":1}"#,
        )
        .unwrap();
        for cible in [ailleurs.join("absent"), ailleurs.join("cible.txt"), ailleurs.clone()] {
            std::fs::write(ailleurs.join("cible.txt"), b"alice").unwrap();
            std::os::unix::fs::symlink(&cible, &marque).unwrap();
            assert!(refuse_dans(&dossier), "{}", cible.display());
            assert_eq!(accord_dans(&dossier, d(10)), None);
            enregistrer_choix_dans(&dossier, Choix::Non, d(9)).unwrap();
            assert_eq!(std::fs::read(ailleurs.join("cible.txt")).unwrap(), b"alice");
            assert!(!ailleurs.join("absent").exists());
            enregistrer_choix_dans(&dossier, Choix::Oui, d(9)).unwrap();
            assert!(
                std::fs::symlink_metadata(&marque).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                    && ailleurs.join("cible.txt").exists()
            );
        }
        let _ = std::fs::remove_dir_all(&dossier);
        let _ = std::fs::remove_dir_all(&ailleurs);
    }

    /// Un « oui » et un « non » en même temps : le « oui » a écrit le fichier, le « non » l'a récrit, puis le « oui »
    /// retire la marque. En relisant, il la repose et n'est pas pris ; sans « non » arrivé, rien ne change.
    #[test]
    fn oui_et_non_en_meme_temps() {
        let dossier = jetable("en-meme-temps");
        let marque = dossier.join(MARQUE_NON);
        ecrire_choix_dans(&dossier.join(PARAMETRES), Choix::Non, d(9)).unwrap();
        assert!(!marque_dans(&dossier));
        assert!(garder_un_non_arrive(&dossier, d(9)).is_err());
        assert!(marque.is_file() && refuse_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(10)), None);
        // Un « oui » seul, ensuite : pris, et rien n'est reposé.
        enregistrer_choix_dans(&dossier, Choix::Oui, d(10)).unwrap();
        assert!(!marque_dans(&dossier) && garder_un_non_arrive(&dossier, d(10)).is_ok());
        assert!(!marque_dans(&dossier));
        assert_eq!(accord_dans(&dossier, d(11)), Some(d(10)));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// « Non » efface le relevé, la file et l'identifiant ; rien d'autre : ni le fichier des paramètres, ni les mesures, ni
    /// un fichier qui n'est pas du relevé.
    #[test]
    fn non_efface_le_releve_et_la_file_seulement() {
        let dossier = jetable("efface");
        enregistrer_choix_dans(&dossier, Choix::Non, d(8)).unwrap();
        for (nom, octets) in [
            ("amelioration/jours/2026-11-07.json", &b"{}"[..]),
            ("amelioration/suivi.json", b"{}"),
            ("amelioration/materiel.json", b"{}"),
        ] {
            std::fs::create_dir_all(dossier.join(nom).parent().unwrap()).unwrap();
            crate::sceau::ecrire_dans(&dossier, nom, octets).unwrap();
        }
        std::fs::create_dir_all(dossier.join("envoi/file")).unwrap();
        std::fs::write(dossier.join("envoi/file/2026-11-07.json"), b"{}").unwrap();
        std::fs::write(
            dossier.join("envoi/etat.json"),
            br#"{"installation":{"id":"x","depuis":"2026-11-01"}}"#,
        )
        .unwrap();
        std::fs::write(dossier.join("amelioration/a-moi.txt"), b"alice").unwrap();
        std::fs::write(dossier.join("mesures.json"), b"{}").unwrap();
        std::fs::write(dossier.join("journal.jsonl"), b"").unwrap();
        crate::envoi::vider_dans(&dossier).unwrap();
        crate::amelioration::effacer_dans(&dossier).unwrap();
        assert!(!dossier.join("envoi").exists());
        assert!(!dossier.join("amelioration/jours").exists());
        assert!(!dossier.join("amelioration/suivi.json").exists());
        assert!(!dossier.join("amelioration/materiel.json").exists());
        assert!(dossier.join("amelioration/a-moi.txt").exists());
        assert!(dossier.join("mesures.json").exists());
        assert!(dossier.join("journal.jsonl").exists());
        assert!(refuse_dans(&dossier), "le « non » reste après l'effacement");
        assert!(
            dossier.join(MARQUE_NON).is_file(),
            "la marque du « non » reste après l'effacement"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un lien posé à la place de `amelioration/`, de `amelioration/jours/`, de `envoi/` ou de `envoi/file/` est
    /// retiré ou refusé, jamais suivi : les fichiers qu'il désigne, nommés comme ceux du relevé, restent.
    #[cfg(unix)]
    #[test]
    fn non_ne_suit_aucun_lien() {
        for lien in ["amelioration", "amelioration/jours", "envoi", "envoi/file"] {
            let dossier = jetable("lien");
            let ailleurs = jetable("ailleurs");
            for nom in ["2026-11-07.json", "suivi.json", "materiel.json", "etat.json"] {
                std::fs::write(ailleurs.join(nom), b"{}").unwrap();
            }
            let place = dossier.join(lien);
            std::fs::create_dir_all(place.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&ailleurs, &place).unwrap();
            let _ = crate::envoi::vider_dans(&dossier);
            let _ = crate::amelioration::effacer_dans(&dossier);
            crate::amelioration::purger_dans(&dossier, d(30) + chrono::Duration::days(400)).ok();
            for nom in ["2026-11-07.json", "suivi.json", "materiel.json", "etat.json"] {
                assert!(ailleurs.join(nom).exists(), "{lien} → {nom} effacé à travers le lien");
            }
            let _ = std::fs::remove_dir_all(&dossier);
            let _ = std::fs::remove_dir_all(&ailleurs);
        }
    }

    #[test]
    fn ce_que_montre_le_lancement() {
        let vide = Fichier::default();
        let avis = avec(None, None, None, Some("2026-11-01"));
        let non = avec(Some(Choix::Non), Some("2026-11-01"), Some(1), None);
        let oui1 = avec(Some(Choix::Oui), Some("2026-11-01"), Some(1), None);
        let oui2 = avec(Some(Choix::Oui), Some("2026-11-01"), Some(2), None);
        // Sans relais (aujourd'hui) ou sans relevé : rien.
        for phase in [Phase::Un, Phase::Deux] {
            assert_eq!(au_lancement(Some(&vide), phase, false, true, false), AuLancement::Rien);
            assert_eq!(au_lancement(None, phase, true, true, false), AuLancement::Rien);
            assert_eq!(au_lancement(Some(&non), phase, true, true, false), AuLancement::Rien);
        }
        assert_eq!(
            au_lancement(Some(&vide), Phase::Un, true, true, false),
            AuLancement::Avis
        );
        assert_eq!(
            au_lancement(Some(&vide), Phase::Un, true, false, false),
            AuLancement::Rien
        );
        assert_eq!(
            au_lancement(Some(&avis), Phase::Un, true, true, false),
            AuLancement::Rien
        );
        assert_eq!(
            au_lancement(Some(&oui1), Phase::Un, true, true, false),
            AuLancement::Rien
        );
        // Phase 2 : la question, même sans terminal, sauf « oui » déjà donné en phase 2.
        assert_eq!(
            au_lancement(Some(&vide), Phase::Deux, true, false, false),
            AuLancement::Question
        );
        assert_eq!(
            au_lancement(Some(&avis), Phase::Deux, true, true, false),
            AuLancement::Question
        );
        assert_eq!(
            au_lancement(Some(&oui1), Phase::Deux, true, true, false),
            AuLancement::Question
        );
        assert_eq!(
            au_lancement(Some(&oui2), Phase::Deux, true, true, false),
            AuLancement::Rien
        );
        // Fichier disparu : la question dans un terminal (jamais l'avis), rien sans lui.
        for phase in [Phase::Un, Phase::Deux] {
            assert_eq!(
                au_lancement(Some(&vide), phase, true, true, true),
                AuLancement::Question
            );
            assert_eq!(au_lancement(Some(&vide), phase, true, false, true), AuLancement::Rien);
            assert_eq!(au_lancement(Some(&vide), phase, false, true, true), AuLancement::Rien);
        }
    }

    /// Les retraits ne touchent que l'extérieur des chaînes : sans eux, ce sont les octets d'origine.
    #[test]
    fn retrait_sans_toucher_aux_chaines() {
        let brut = br#"{"a":[1,2],"b":"x, {y}: [z] \" ,","c":{"d":null}}"#;
        let lignes = en_retrait(brut);
        let recolle: String = lignes
            .iter()
            .map(|l| l.trim_start())
            .collect::<Vec<_>>()
            .join("")
            .replace(": ", ":");
        assert_eq!(recolle, String::from_utf8_lossy(brut).replace(": ", ":"));
        assert!(lignes.iter().any(|l| l.contains(r#""x, {y}: [z] \" ,""#)), "{lignes:?}");
    }

    #[test]
    fn textes_dans_la_largeur() {
        assert_eq!(
            crate::ui::textes_trop_larges(include_str!("partage.rs")),
            Vec::<String>::new()
        );
    }
}
