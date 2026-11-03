//! Les notes « avant » des choix de la personne (`vanguard:defender-choix`, `vanguard:defender-asr-choix`) et
//! « Rallumer » (`vanguard:rallumer`), faits par le processus élevé.
//!
//! Une baisse n'est faite que montrée, puis confirmée (`demander_baisse`), et seulement si sa note s'écrit d'abord :
//! la valeur d'avant, gardée sous HKLM `SOFTWARE\Vanguard\ChoixAvant` (que seuls les administrateurs écrivent), avec
//! son empreinte SHA-256. Sans note, rien n'est baissé (`echec note`) : une baisse sans moyen sûr de la rallumer
//! n'est pas faite. « Rallumer » remet la valeur d'avant d'une note valide si elle est au moins allumée, sinon la
//! valeur sûre (`gestes::cible_rallumer`) : une note forgée ou abîmée ne fait jamais rallumer plus faible.
//!
//! Le geste lui-même (`faire_choix`, `rallumer`) passe par un `Monde` : WMI et le registre sous Windows
//! (`defender_ecriture`), un faux monde dans les essais, si bien que chaque cas se vérifie sur tous les systèmes.

#[path = "choix_note.rs"]
mod note;

use crate::machine::gestes::{IdChoix, Montre, Sens, sens};
use crate::modele::Echec;
use crate::ui::{tr, trf, trp};
#[cfg(windows)]
pub(crate) use note::lire_valeur;
pub(crate) use note::{NOTE_MAX, Note, texte_valeur};

/// La clé des notes, sous HKLM (vue 64 bits).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const CLE: &str = r"SOFTWARE\Vanguard\ChoixAvant";
/// Le plus de valeurs que la clé peut garder : une note neuve au-delà est refusée (`echec note`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const VALEURS_MAX: usize = 256;
/// Ce que le processus élevé lit et écrit pour un choix : Defender et le registre sous Windows, un faux dans les
/// essais.
pub(crate) trait Monde {
    /// La valeur actuelle (`None` : illisible ; `Some(None)` : règle ASR absente de la liste).
    #[allow(clippy::option_option)] // None : illisible ; Some(None) : valeur absente
    fn lire(&mut self, id: IdChoix) -> Option<Option<i64>>;
    /// Écrit la valeur exacte ; `Err` : le refus, prêt à montrer.
    fn ecrire(&mut self, id: IdChoix, v: i64) -> Result<(), Echec>;
    /// Relit après l'écriture de `v` (le temps réel met un instant à changer : relu quelques fois).
    #[allow(clippy::option_option)] // None : illisible ; Some(None) : valeur absente
    fn relire(&mut self, id: IdChoix, v: i64) -> Option<Option<i64>>;
    /// Les octets de la note `nom`, s'il y en a une.
    fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>>;
    fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec>;
    fn effacer_note(&mut self, nom: &str);
    /// Une entrée du journal d'événements de Windows (source Vanguard) : une par baisse faite.
    fn journal(&mut self, texte: &str);
    /// Secondes depuis 1970 (UTC).
    fn maintenant(&self) -> u64;
    /// Pourquoi Windows a gardé la valeur (protection contre les falsifications, stratégie…).
    fn pourquoi_garde(&mut self) -> String;
}

/// Ce qu'un choix ou « Rallumer » a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Issue {
    /// Fait et relu ; `note` : une baisse, notée (« ok avant=… note=choix »).
    Fait { avant: String, note: bool },
    /// Déjà à la valeur : rien d'écrit.
    Rien(String),
    /// Rien de compté comme fait ; `avant` : la valeur lue, si elle l'a été.
    Echec { avant: Option<String>, raison: String },
    /// La note ne s'écrit pas : rien n'est baissé.
    EchecNote,
    /// Devenue une baisse depuis l'affichage sans avoir été montrée comme telle, ou une baisse dont la valeur relue
    /// n'est plus celle montrée : refusée, rien d'écrit.
    Change,
}

/// Une baisse refusée à l'écriture (plan §3.3) : Defender peut juger le geste suspect. Jamais de contournement.
pub(crate) fn defender_bloque() -> &'static str {
    tr!(
        "Defender a bloqué ce changement et l'a peut-être signalé comme une attaque. Vanguard ne cherche pas à le contourner.",
        "Defender blocked this change and may have reported it as an attack. Vanguard does not try to get around it."
    )
}

/// La valeur d'avant telle que le parent la note : « defender-pua=1 », « asr-…=absente ».
pub(crate) fn texte_avant(id: IdChoix, v: Option<i64>) -> String {
    format!("{}={}", id.texte(), texte_valeur(v))
}

fn illisible() -> Issue {
    Issue::Echec {
        avant: None,
        raison: tr!(
            "réglage de Defender illisible, rien d'écrit",
            "Defender setting unreadable, nothing written"
        )
        .to_string(),
    }
}

fn relue_illisible(avant: String) -> Issue {
    Issue::Echec {
        avant: Some(avant),
        raison: tr!(
            "réglage relu illisible après l'écriture : rien n'est compté comme fait",
            "setting unreadable after writing: nothing is counted as done"
        )
        .to_string(),
    }
}

fn changee_pendant(avant: String) -> Issue {
    Issue::Echec {
        avant: Some(avant),
        raison: tr!(
            "la valeur a changé pendant le geste : rien n'est compté comme fait",
            "the value changed during the step: nothing is counted as done"
        )
        .to_string(),
    }
}

/// La note valide de `id`, si elle existe.
pub(crate) fn note_valide(m: &mut impl Monde, id: IdChoix) -> Option<Note> {
    let nom = id.texte();
    m.lire_note(&nom).and_then(|o| Note::lire(&nom, &o))
}

/// La protection est revenue à la valeur notée ou plus haut (ou la note ne vaut rien) : la note n'a plus d'usage. Une
/// autre valeur du même rang la garde, comme la baisse qui l'a écrite.
fn effacer_si_remontee(m: &mut impl Monde, id: IdChoix, valeur: Option<i64>) {
    let nom = id.texte();
    let Some(octets) = m.lire_note(&nom) else {
        return;
    };
    match Note::lire(&nom, &octets) {
        Some(n) if valeur != n.avant && id.rang(valeur) <= id.rang(n.avant) => {}
        _ => m.effacer_note(&nom),
    }
}

/// Remet les octets d'avant de la note (ou l'efface s'il n'y en avait pas) : une baisse qui n'a pas eu lieu ne
/// laisse pas de note neuve.
fn remettre_note(m: &mut impl Monde, nom: &str, ancienne: Option<&[u8]>) {
    match ancienne {
        Some(o) => {
            let _ = m.ecrire_note(nom, o);
        }
        None => m.effacer_note(nom),
    }
}

/// Fait un choix exact : `cible`, la valeur visée ; `montre`, le sens et la valeur montrés à la personne avant son
/// accord. Le sens est rejugé ici, sur la valeur relue juste avant d'écrire : une baisse qui n'a pas été montrée comme
/// telle, ou dont la valeur relue n'est plus celle montrée (la note garderait une valeur que la personne n'a pas vue),
/// est refusée (`Change`). Une baisse écrit d'abord sa note (la valeur d'avant d'une note encore valide et au moins aussi
/// forte est gardée : deux baisses de suite rallument à la première valeur), la relit, puis écrit la valeur ; si la
/// note ne s'écrit pas, rien n'est baissé (`EchecNote`).
pub(crate) fn faire_choix(m: &mut impl Monde, id: IdChoix, cible: i64, montre: Option<Montre>) -> Issue {
    let Some(lue) = m.lire(id) else {
        return illisible();
    };
    let avant = texte_avant(id, lue);
    match sens(id, Some(lue), Some(cible)) {
        Sens::Rien => {
            effacer_si_remontee(m, id, lue);
            Issue::Rien(trf!(
                "déjà réglé ({avant}), rien d'écrit",
                "already set ({avant}), nothing written"
            ))
        }
        Sens::Baisse
            if montre
                != Some(Montre {
                    sens: Sens::Baisse,
                    lue: Some(lue),
                }) =>
        {
            Issue::Change
        }
        Sens::Baisse => {
            let nom = id.texte();
            let ancienne = m.lire_note(&nom);
            let gardee = ancienne
                .as_deref()
                .and_then(|o| Note::lire(&nom, o))
                .filter(|n| id.rang(n.avant) >= id.rang(lue));
            let note = Note {
                id: nom.clone(),
                avant: gardee.map_or(lue, |n| n.avant),
                posee: cible,
                date: m.maintenant(),
            }
            .octets();
            if note.len() > NOTE_MAX || m.ecrire_note(&nom, &note).is_err() {
                remettre_note(m, &nom, ancienne.as_deref());
                return Issue::EchecNote;
            }
            if m.lire_note(&nom).as_deref() != Some(note.as_slice()) {
                remettre_note(m, &nom, ancienne.as_deref());
                return Issue::EchecNote;
            }
            if let Err(e) = m.ecrire(id, cible) {
                remettre_note(m, &nom, ancienne.as_deref());
                return Issue::Echec {
                    avant: Some(avant),
                    raison: e.to_string(),
                };
            }
            match m.relire(id, cible) {
                Some(v) if v == Some(cible) => {
                    m.journal(&trf!(
                        "Vanguard : réglage baissé à la demande de la personne, confirmée dans la fenêtre administrateur : {nom}, {} -> {cible}. « Rallumer » dans Vanguard le remet.",
                        "Vanguard: setting lowered at the person's request, confirmed in the administrator window: {nom}, {} -> {cible}. “Turn back on” in Vanguard restores it.",
                        texte_valeur(lue)
                    ));
                    Issue::Fait { avant, note: true }
                }
                Some(v) if v == lue => {
                    remettre_note(m, &nom, ancienne.as_deref());
                    Issue::Echec {
                        avant: Some(avant),
                        raison: m.pourquoi_garde(),
                    }
                }
                // La valeur a bougé autrement : la note reste, pour que « Rallumer » sache où revenir.
                Some(_) => changee_pendant(avant),
                None => relue_illisible(avant),
            }
        }
        Sens::Renforce => {
            if let Err(e) = m.ecrire(id, cible) {
                return Issue::Echec {
                    avant: Some(avant),
                    raison: e.to_string(),
                };
            }
            match m.relire(id, cible) {
                Some(v) if v == Some(cible) => {
                    effacer_si_remontee(m, id, v);
                    Issue::Fait { avant, note: false }
                }
                Some(v) if v == lue => Issue::Echec {
                    avant: Some(avant),
                    raison: m.pourquoi_garde(),
                },
                Some(_) => changee_pendant(avant),
                None => relue_illisible(avant),
            }
        }
    }
}

/// Rallume ce qu'un choix a baissé : la cible vient de la note valide si elle est au moins allumée, sinon de la
/// valeur sûre (`gestes::cible_rallumer`). Déjà plus fort, ou déjà à cette valeur : rien d'écrit ; une autre valeur
/// du même rang (audit de tout pour audit des disques) est remise comme elle était. La note est effacée une fois la
/// protection revenue.
pub(crate) fn rallumer(m: &mut impl Monde, id: IdChoix) -> Issue {
    let note = note_valide(m, id);
    // Un élément de liste (exclusion, programme permis) n'est retiré que si Vanguard l'a posé ou noté : une
    // exclusion posée par quelqu'un d'autre passe par le bilan (`defender-exclusion-retirer`), jamais par ici.
    if id.element() && note.is_none() {
        return Issue::Echec {
            avant: None,
            raison: tr!(
                "pas posé par Vanguard (aucune note), rien d'écrit",
                "not set by Vanguard (no note), nothing written"
            )
            .to_string(),
        };
    }
    let cible = crate::machine::gestes::cible_rallumer(id, note.map(|n| n.avant));
    let Some(lue) = m.lire(id) else {
        return illisible();
    };
    let avant = texte_avant(id, lue);
    if id.rang(lue) > id.rang(Some(cible)) || lue == Some(cible) {
        m.effacer_note(&id.texte());
        return Issue::Rien(trf!(
            "déjà en marche ({avant}), rien d'écrit",
            "already on ({avant}), nothing written"
        ));
    }
    if let Err(e) = m.ecrire(id, cible) {
        return Issue::Echec {
            avant: Some(avant),
            raison: e.to_string(),
        };
    }
    match m.relire(id, cible) {
        Some(v) if v == Some(cible) || id.rang(v) > id.rang(Some(cible)) => {
            m.effacer_note(&id.texte());
            Issue::Fait { avant, note: false }
        }
        Some(v) if v == lue => Issue::Echec {
            avant: Some(avant),
            raison: m.pourquoi_garde(),
        },
        Some(_) => changee_pendant(avant),
        None => relue_illisible(avant),
    }
}

/// Le sens de « C'est moi » (`vanguard:choix-noter`) : une baisse, car la note fera dire au bilan « par votre
/// choix » au lieu d'une alerte. Il n'y a rien à noter si la valeur n'est pas baissée (`IdChoix::baissee` :
/// « toujours demander » des échantillons ne l'est pas), ou déjà notée telle quelle ; une valeur illisible reste une baisse (le processus élevé relit, puis refuse).
#[allow(clippy::option_option)] // None : illisible ; Some(None) : valeur absente
pub(crate) fn sens_noter(id: IdChoix, lue: Option<Option<i64>>, note: Option<&Note>) -> Sens {
    let Some(lue) = lue else {
        return Sens::Baisse;
    };
    let deja = matches!((note, lue), (Some(n), Some(v)) if n.posee == v);
    if lue.is_some() && id.baissee(lue) && !deja {
        Sens::Baisse
    } else {
        Sens::Rien
    }
}

/// « C'est moi » : note une protection déjà baissée, telle qu'elle a été montrée (`montre`, une baisse avec la valeur
/// relue), pour que le bilan la dise « par votre choix ». La note dit « avant : la valeur sûre » : « Rallumer » remet
/// donc la valeur sûre, jamais plus faible. Rien n'est écrit dans Defender.
pub(crate) fn noter(m: &mut impl Monde, id: IdChoix, montre: Option<Montre>) -> Issue {
    let Some(lue) = m.lire(id) else {
        return illisible();
    };
    let avant = texte_avant(id, lue);
    let note = note_valide(m, id);
    match sens_noter(id, Some(lue), note.as_ref()) {
        Sens::Rien | Sens::Renforce => {
            return Issue::Rien(trf!(
                "rien à noter ({avant}), rien d'écrit",
                "nothing to note ({avant}), nothing written"
            ));
        }
        Sens::Baisse => {}
    }
    if montre
        != Some(Montre {
            sens: Sens::Baisse,
            lue: Some(lue),
        })
    {
        return Issue::Change;
    }
    let Some(posee) = lue else {
        return Issue::Rien(trf!(
            "rien à noter ({avant}), rien d'écrit",
            "nothing to note ({avant}), nothing written"
        ));
    };
    let nom = id.texte();
    let ancienne = m.lire_note(&nom);
    let octets = Note {
        id: nom.clone(),
        avant: Some(id.sure()),
        posee,
        date: m.maintenant(),
    }
    .octets();
    if octets.len() > NOTE_MAX
        || m.ecrire_note(&nom, &octets).is_err()
        || m.lire_note(&nom).as_deref() != Some(&octets[..])
    {
        remettre_note(m, &nom, ancienne.as_deref());
        return Issue::EchecNote;
    }
    m.journal(&trf!(
        "Vanguard : protection baissée notée « par votre choix » à la demande de la personne, confirmée dans la fenêtre administrateur : {nom}={}. « Rallumer » dans Vanguard la remet.",
        "Vanguard: lowered protection noted as “your choice” at the person's request, confirmed in the administrator window: {nom}={}. “Turn back on” in Vanguard restores it.",
        texte_valeur(lue)
    ));
    Issue::Fait { avant, note: true }
}

/// Efface les notes devenues sans objet : la valeur relue est plus forte que celle que la note a posée (Windows ou
/// quelqu'un l'a rallumée depuis). Une valeur illisible garde la note. Appelé à chaque passage élevé.
pub(crate) fn nettoyer(m: &mut impl Monde, ids: impl IntoIterator<Item = IdChoix>) {
    for id in ids {
        let (Some(note), Some(lue)) = (note_valide(m, id), m.lire(id)) else {
            continue;
        };
        if id.rang(lue) > id.rang(Some(note.posee)) {
            m.effacer_note(&id.texte());
        }
    }
}

/// Ce que dit une note au bilan, relue avec la valeur actuelle (plan §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lecture {
    /// Encore à la valeur que la note a posée : « par votre choix le `date` ».
    ParChoix(u64),
    /// Plus fort que la valeur posée : rallumée depuis, par Windows ou par quelqu'un (note effacée au prochain
    /// passage élevé).
    Remontee,
    /// Ni l'un ni l'autre (illisible, ou une autre valeur aussi faible) : jugée comme sans note.
    Autre,
}

/// La lecture d'une note : `lue`, la valeur actuelle (`None` : illisible ; `Some(None)` : règle absente).
#[allow(clippy::option_option)] // None : illisible ; Some(None) : valeur absente
pub(crate) fn lecture_note(id: IdChoix, note: &Note, lue: Option<Option<i64>>) -> Lecture {
    match lue {
        Some(v) if v == Some(note.posee) => Lecture::ParChoix(note.date),
        Some(v) if id.rang(v) > id.rang(Some(note.posee)) => Lecture::Remontee,
        _ => Lecture::Autre,
    }
}

/// La note valide d'un réglage parmi celles lues (`notes`).
pub(crate) fn note_de(notes: &[(IdChoix, Option<Note>)], id: IdChoix) -> Option<&Note> {
    notes.iter().find(|(i, _)| *i == id).and_then(|(_, n)| n.as_ref())
}

/// Une date de note (secondes depuis 1970, UTC), à l'heure locale : « 2026-11-03 ».
pub(crate) fn date_note(secondes: u64) -> String {
    i64::try_from(secondes)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map_or_else(
            || "?".to_string(),
            |d| d.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string(),
        )
}

/// La commande « Rallumer » d'un réglage noté, proposée au bilan, jamais faite d'office.
pub(crate) fn commande_rallumer(id: IdChoix) -> String {
    format!("vanguard options-defense --rallumer {}", id.texte())
}

/// Le constat d'une protection baissée par la personne (plan §3.4) : une information, jamais saine ni dans « Tout
/// corriger » ; « Rallumer » proposé à part. `sujet` : ce qui est baissé, prêt à montrer (« Protection en temps réel :
/// coupée », une exclusion et son texte). « Si ce n'est pas vous » y est toujours : une note imitée par un programme
/// administrateur (R3) ne fait pas taire la coupure.
pub(crate) fn par_votre_choix(categorie: &'static str, id: IdChoix, sujet: &str, date: u64) -> crate::machine::Constat {
    let date = date_note(date);
    let protege = crate::options_defense::protege_encore(id);
    crate::machine::alerte(
        categorie,
        crate::risk::Niveau::Info,
        trf!(
            "{sujet}, par votre choix le {date}. {protege} Si ce n'est pas vous : Rallumer.",
            "{sujet}, by your choice on {date}. {protege} If it was not you: Turn back on."
        ),
    )
    .manuel(
        tr!(
            "Rallumer (Options de défense), si ce n'est pas vous qui l'avez baissée",
            "Turn back on (Defense options), if you did not lower it"
        ),
        &[&commande_rallumer(id)],
    )
}

/// Le constat d'une protection notée mais rallumée depuis (plan §3.4).
pub(crate) fn rallumee_depuis(categorie: &'static str, nom: &str) -> crate::machine::Constat {
    crate::machine::ok(
        categorie,
        trf!(
            "{nom} : rallumée depuis votre choix, par Windows ou par quelqu'un. La note sera effacée au prochain passage administrateur.",
            "{nom}: turned back on since your choice, by Windows or by someone. The note will be cleared at the next administrator pass."
        ),
    )
}

/// Le sujet d'un constat « par votre choix » : le nom du réglage et sa valeur notée (« Protection en temps réel :
/// coupée »).
pub(crate) fn sujet_note(id: IdChoix, note: &Note) -> String {
    format!(
        "{} : {}",
        crate::options_defense::nom_choix(id),
        crate::options_defense::texte_choix(id, Some(Some(note.posee)))
    )
}

/// Les constats des notes, pour les réglages que le bilan ne juge pas déjà ailleurs : `lire`, la valeur actuelle
/// d'un réglage. Une note abîmée, ou dont la valeur ne dit rien (`Lecture::Autre`), ne donne rien ici.
#[allow(clippy::option_option)] // None : illisible ; Some(None) : valeur absente
pub(crate) fn constats_des_notes(
    categorie: &'static str,
    notes: &[(IdChoix, Option<Note>)],
    mut lire: impl FnMut(IdChoix) -> Option<Option<i64>>,
) -> Vec<crate::machine::Constat> {
    notes
        .iter()
        .filter_map(|(id, n)| Some((*id, n.as_ref()?)))
        .filter_map(|(id, n)| match lecture_note(id, n, lire(id)) {
            Lecture::ParChoix(date) => Some(par_votre_choix(categorie, id, &sujet_note(id, n), date)),
            Lecture::Remontee => Some(rallumee_depuis(categorie, &crate::options_defense::nom_choix(id))),
            Lecture::Autre => None,
        })
        .collect()
}

/// La question d'une liste de baisses, posée une fois : seul un oui (« o », « oui », « y », « yes ») accepte ;
/// Entrée seule, « n », la fin de l'entrée ou toute autre réponse refusent. `console` : l'entrée est une vraie
/// console (`GetConsoleMode` réussit sur stdin) ; sinon rien n'est lu et la réponse vaut non, même si un « o »
/// attend dans un tube.
pub(crate) fn demander_baisse(console: bool, demander: impl FnOnce(&str) -> String) -> bool {
    if !console {
        trp!(
            "  L'entrée n'est pas une console : la réponse vaut non, rien n'est baissé.",
            "  The input is not a console: the answer is no, nothing is lowered."
        );
        return false;
    }
    let reponse = demander(tr!(
        "  Ces changements rendent votre PC MOINS protégé.\n  Les avez-vous demandés vous-même, dans Vanguard, à l'instant ? Si ce n'est pas vous, répondez N.\n  Faire ces changements ? [o/N] : ",
        "  These changes make your PC LESS protected.\n  Did you ask for them yourself, in Vanguard, just now? If it was not you, answer N.\n  Make these changes? [y/N]: "
    ));
    crate::langue::oui(&reponse)
}

// ------------------------------------------------------------------ registre (Windows)

#[cfg(windows)]
mod registre {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY};

    use super::{CLE, NOTE_MAX, VALEURS_MAX};
    use crate::modele::Echec;

    const CONTEXTE: &str = "choix_avant/note";

    fn cle(ecrire: bool) -> std::io::Result<RegKey> {
        let racine = RegKey::predef(HKEY_LOCAL_MACHINE);
        if ecrire {
            racine
                .create_subkey_with_flags(CLE, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY)
                .map(|(k, _)| k)
        } else {
            racine.open_subkey_with_flags(CLE, KEY_QUERY_VALUE | KEY_WOW64_64KEY)
        }
    }

    /// Les octets d'une note (REG_BINARY, bornés) ; `None` : absente, d'un autre type ou trop longue.
    pub(crate) fn lire(nom: &str) -> Option<Vec<u8>> {
        let v = cle(false).ok()?.get_raw_value(nom).ok()?;
        (v.vtype == REG_BINARY && v.bytes.len() <= NOTE_MAX).then(|| v.bytes.to_vec())
    }

    /// Écrit une note ; refusée si la clé garde déjà `VALEURS_MAX` valeurs et que celle-ci est neuve.
    pub(crate) fn ecrire(nom: &str, octets: &[u8]) -> Result<(), Echec> {
        let k = cle(true).map_err(|e| Echec::io(CONTEXTE, &e))?;
        let neuve = k.get_raw_value(nom).is_err();
        let compte = k.query_info().map_or(usize::MAX, |i| i.values as usize);
        if neuve && compte >= VALEURS_MAX {
            return Err(Echec::refuse(
                CONTEXTE,
                crate::ui::tr!("trop de notes", "too many notes"),
            ));
        }
        k.set_raw_value(
            nom,
            &winreg::RegValue {
                bytes: octets.to_vec().into(),
                vtype: REG_BINARY,
            },
        )
        .map_err(|e| Echec::io(CONTEXTE, &e))
    }

    pub(crate) fn effacer(nom: &str) {
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(CLE, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY)
        {
            let _ = k.delete_value(nom);
        }
    }

    /// Les noms et octets des notes, lisibles sans droits d'administrateur (pour « Tout remettre » et l'écran).
    pub(crate) fn toutes() -> Vec<(String, Vec<u8>)> {
        let Ok(k) = cle(false) else {
            return Vec::new();
        };
        k.enum_values()
            .flatten()
            .take(VALEURS_MAX)
            .filter(|(_, v)| v.vtype == REG_BINARY && v.bytes.len() <= NOTE_MAX)
            .map(|(n, v)| (n, v.bytes.to_vec()))
            .collect()
    }
}

#[cfg(windows)]
pub(crate) use registre::{ecrire as ecrire_brut, effacer as effacer_brut, lire as lire_brut};

/// Les notes de cet ordinateur, chacune avec son réglage : la note si elle se relit, `None` si elle est abîmée
/// (« Rallumer » vise alors la valeur sûre, mais le réglage reste à remettre) ; une valeur dont le nom n'est pas un
/// réglage des choix est ignorée. Vide ailleurs que sous Windows, ou sans note.
pub(crate) fn notes() -> Vec<(IdChoix, Option<Note>)> {
    #[cfg(windows)]
    {
        registre::toutes()
            .into_iter()
            .filter_map(|(nom, o)| Some((IdChoix::lire(&nom)?, Note::lire(&nom, &o))))
            .collect()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::gestes::{ASR_TOUTES, ReglageDefender};
    use note::{EMPREINTE, ENTETE};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    const PUA: IdChoix = IdChoix::Defender(ReglageDefender::Pua);
    const RTP: IdChoix = IdChoix::Defender(ReglageDefender::TempsReel);

    /// Un monde en mémoire : des valeurs, des notes, et des pannes à la demande.
    #[derive(Default)]
    #[allow(clippy::struct_excessive_bools)] // une panne par champ, chacune pour elle-même
    struct Faux {
        valeurs: HashMap<String, Option<i64>>,
        notes: HashMap<String, Vec<u8>>,
        illisible: bool,
        note_refusee: bool,
        /// La note s'écrit, mais se relit autre.
        note_alteree: bool,
        /// Windows garde la valeur sans erreur (protection contre les falsifications).
        garde: bool,
        ecriture_refusee: bool,
        ecritures: Vec<(String, i64)>,
        journal: Vec<String>,
    }

    impl Faux {
        fn avec(id: IdChoix, v: Option<i64>) -> Faux {
            let mut f = Faux::default();
            f.valeurs.insert(id.texte(), v);
            f
        }
        fn valeur(&self, id: IdChoix) -> Option<i64> {
            self.valeurs.get(&id.texte()).copied().flatten()
        }
    }

    impl Monde for Faux {
        fn lire(&mut self, id: IdChoix) -> Option<Option<i64>> {
            (!self.illisible).then(|| self.valeurs.get(&id.texte()).copied().flatten())
        }
        fn ecrire(&mut self, id: IdChoix, v: i64) -> Result<(), Echec> {
            if self.ecriture_refusee {
                return Err(Echec::refuse("essai", "refus"));
            }
            self.ecritures.push((id.texte(), v));
            if !self.garde {
                self.valeurs.insert(id.texte(), Some(v));
            }
            Ok(())
        }
        fn relire(&mut self, id: IdChoix, _: i64) -> Option<Option<i64>> {
            self.lire(id)
        }
        fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>> {
            self.notes.get(nom).cloned()
        }
        fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec> {
            if self.note_refusee {
                return Err(Echec::refuse("essai", "refus"));
            }
            let mut o = octets.to_vec();
            if self.note_alteree {
                o.push(0);
            }
            self.notes.insert(nom.to_string(), o);
            Ok(())
        }
        fn effacer_note(&mut self, nom: &str) {
            self.notes.remove(nom);
        }
        fn journal(&mut self, texte: &str) {
            self.journal.push(texte.to_string());
        }
        fn maintenant(&self) -> u64 {
            1_700_000_000
        }
        fn pourquoi_garde(&mut self) -> String {
            "gardée".into()
        }
    }

    fn note(id: IdChoix, avant: Option<i64>, posee: i64) -> Vec<u8> {
        Note {
            id: id.texte(),
            avant,
            posee,
            date: 1,
        }
        .octets()
    }

    /// Une baisse montrée avec la valeur que le faux monde a à cet instant, puis faite.
    fn baisser(m: &mut Faux, id: IdChoix, cible: i64) -> Issue {
        let lue = m.lire(id);
        faire_choix(
            m,
            id,
            cible,
            Some(Montre {
                sens: Sens::Baisse,
                lue,
            }),
        )
    }

    #[test]
    fn note_aller_retour() {
        for (id, avant) in [(PUA, Some(1)), (RTP, Some(0)), (IdChoix::Asr(ASR_TOUTES[0]), None)] {
            let n = Note {
                id: id.texte(),
                avant,
                posee: 0,
                date: 1_700_000_000,
            };
            assert_eq!(Note::lire(&id.texte(), &n.octets()), Some(n.clone()));
            // Copiée sous le nom d'un autre réglage : refusée.
            assert_eq!(Note::lire("defender-cloud", &n.octets()), None);
        }
    }

    /// Une note forgée, tronquée, d'une autre version, trop longue ou à l'empreinte fausse ne se lit pas : Rallumer
    /// vise alors la valeur sûre, jamais la valeur qu'elle porte.
    #[test]
    fn note_abimee_rallume_au_sur() {
        let bonne = note(PUA, Some(0), 0);
        let mut empreinte_fausse = bonne.clone();
        *empreinte_fausse.last_mut().unwrap() ^= 1;
        let tronquee = bonne[..bonne.len() - 1].to_vec();
        let mut version = bonne.clone();
        version[5] = 2;
        let n = version.len() - EMPREINTE;
        let e = Sha256::digest(&version[..n]);
        version[n..].copy_from_slice(&e);
        let mut longue = vec![0u8; NOTE_MAX + 1];
        longue[..ENTETE.len()].copy_from_slice(ENTETE);
        // Une note bien formée et bien signée, mais qui dit « avant = 0 » sous un faux champ « +0 ».
        let mut forgee = ENTETE.to_vec();
        for c in ["defender-pua", "+0", "0"] {
            forgee.extend_from_slice(&u16::try_from(c.len()).unwrap().to_le_bytes());
            forgee.extend_from_slice(c.as_bytes());
        }
        forgee.extend_from_slice(&1u64.to_le_bytes());
        let e = Sha256::digest(&forgee);
        forgee.extend_from_slice(&e);
        let mut suite = bonne.clone();
        suite.insert(suite.len() - EMPREINTE, b'x');
        for abimee in [empreinte_fausse, tronquee, version, longue, forgee, suite, Vec::new()] {
            assert_eq!(Note::lire("defender-pua", &abimee), None);
            let mut m = Faux::avec(PUA, Some(0));
            m.notes.insert(PUA.texte(), abimee);
            assert!(matches!(rallumer(&mut m, PUA), Issue::Fait { note: false, .. }));
            assert_eq!(m.valeur(PUA), Some(1), "valeur sûre : bloquer");
            assert!(m.notes.is_empty());
        }
        // Une note valide qui dit « coupée » : jamais remise, la valeur sûre à la place.
        let mut m = Faux::avec(RTP, Some(1));
        m.notes.insert(RTP.texte(), note(RTP, Some(1), 1));
        rallumer(&mut m, RTP);
        assert_eq!(m.valeur(RTP), Some(0));
        // Une note valide en audit : remise telle quelle (au moins allumée).
        let mut m = Faux::avec(PUA, Some(0));
        m.notes.insert(PUA.texte(), note(PUA, Some(2), 0));
        rallumer(&mut m, PUA);
        assert_eq!(m.valeur(PUA), Some(2));
    }

    /// Une baisse note d'abord, puis écrit, relit et le dit au journal de Windows ; la note garde la valeur d'avant.
    #[test]
    fn baisse_notee_puis_faite() {
        let mut m = Faux::avec(PUA, Some(1));
        let r = baisser(&mut m, PUA, 0);
        assert_eq!(
            r,
            Issue::Fait {
                avant: "defender-pua=1".into(),
                note: true
            }
        );
        assert_eq!(m.valeur(PUA), Some(0));
        let n = Note::lire("defender-pua", &m.notes["defender-pua"]).unwrap();
        assert_eq!((n.avant, n.posee), (Some(1), 0));
        assert_eq!(m.journal.len(), 1);
        // Une deuxième baisse (audit → coupée, après un audit choisi) garde la première valeur d'avant.
        let mut m = Faux::avec(PUA, Some(1));
        baisser(&mut m, PUA, 2);
        baisser(&mut m, PUA, 0);
        let n = Note::lire("defender-pua", &m.notes["defender-pua"]).unwrap();
        assert_eq!((n.avant, n.posee), (Some(1), 0));
        // Rallumer remet 1 et efface la note.
        assert!(matches!(rallumer(&mut m, PUA), Issue::Fait { .. }));
        assert_eq!(m.valeur(PUA), Some(1));
        assert!(m.notes.is_empty());
        // Déjà remonté : rien, la note effacée.
        m.notes.insert(PUA.texte(), note(PUA, Some(1), 0));
        assert!(matches!(rallumer(&mut m, PUA), Issue::Rien(_)));
        assert!(m.notes.is_empty() && m.ecritures.len() == 3);
    }

    /// La note ne s'écrit pas, ou se relit autre : `echec note`, aucun geste sur Defender, aucune note neuve.
    #[test]
    fn note_impossible_rien_baisse() {
        for alteree in [false, true] {
            let mut m = Faux::avec(RTP, Some(0));
            m.note_refusee = !alteree;
            m.note_alteree = alteree;
            assert_eq!(baisser(&mut m, RTP, 1), Issue::EchecNote);
            assert_eq!(m.ecritures, Vec::<(String, i64)>::new());
            assert_eq!(m.valeur(RTP), Some(0));
            assert!(m.notes.is_empty() && m.journal.is_empty());
        }
        // Une note d'avant déjà là est remise telle quelle.
        let mut m = Faux::avec(PUA, Some(2));
        let ancienne = note(PUA, Some(1), 2);
        m.notes.insert(PUA.texte(), ancienne.clone());
        m.note_alteree = true;
        assert_eq!(baisser(&mut m, PUA, 0), Issue::EchecNote);
        assert_eq!(m.ecritures, Vec::<(String, i64)>::new());
        assert_eq!(
            m.notes[&PUA.texte()].len(),
            ancienne.len() + 1,
            "remise par le même chemin d'écriture"
        );
    }

    /// Windows garde la valeur (protection contre les falsifications) : échec honnête, la note neuve retirée.
    #[test]
    fn baisse_gardee_par_windows() {
        let mut m = Faux::avec(RTP, Some(0));
        m.garde = true;
        let r = baisser(&mut m, RTP, 1);
        assert_eq!(
            r,
            Issue::Echec {
                avant: Some("defender-temps-reel=0".into()),
                raison: "gardée".into()
            }
        );
        assert!(m.notes.is_empty() && m.journal.is_empty());
        // Écriture refusée : de même.
        let mut m = Faux::avec(RTP, Some(0));
        m.ecriture_refusee = true;
        assert!(matches!(baisser(&mut m, RTP, 1), Issue::Echec { .. }));
        assert!(m.notes.is_empty());
        // Illisible : rien d'écrit.
        let mut m = Faux::avec(RTP, Some(0));
        m.illisible = true;
        assert!(matches!(baisser(&mut m, RTP, 1), Issue::Echec { avant: None, .. }));
        assert!(m.ecritures.is_empty() && m.notes.is_empty());
    }

    /// Rejugée juste avant d'écrire : une ligne montrée comme renforcement (ou « rien ») devenue une baisse est
    /// refusée, sans note ni geste.
    #[test]
    fn devenue_baisse_refusee() {
        for sens in [None, Some(Sens::Renforce), Some(Sens::Rien)] {
            let mut m = Faux::avec(PUA, Some(1));
            let montre = sens.map(|sens| Montre {
                sens,
                lue: Some(Some(1)),
            });
            assert_eq!(faire_choix(&mut m, PUA, 2, montre), Issue::Change);
            assert!(m.ecritures.is_empty() && m.notes.is_empty());
        }
        // Un renforcement se fait sans note, et efface une note dépassée.
        let mut m = Faux::avec(PUA, Some(0));
        m.notes.insert(PUA.texte(), note(PUA, Some(2), 0));
        assert!(matches!(
            faire_choix(
                &mut m,
                PUA,
                1,
                Some(Montre {
                    sens: Sens::Renforce,
                    lue: Some(Some(0))
                })
            ),
            Issue::Fait { note: false, .. }
        ));
        assert!(m.notes.is_empty());
        // Déjà là : rien.
        let mut m = Faux::avec(PUA, Some(1));
        assert!(matches!(baisser(&mut m, PUA, 1), Issue::Rien(_)));
        assert_eq!(m.ecritures, Vec::<(String, i64)>::new());
    }

    /// La valeur a bougé entre l'affichage et l'écriture (un autre outil, Defender lui-même) : la baisse est
    /// refusée, sans note ni geste, pour que la note ne garde jamais une valeur que la personne n'a pas vue.
    #[test]
    fn valeur_changee_depuis_l_affichage() {
        let vue = |lue| {
            Some(Montre {
                sens: Sens::Baisse,
                lue,
            })
        };
        // Montrée à 1 (bloque), relue à 2 (audit) au moment d'écrire : toujours une baisse vers 0, mais pas celle vue.
        let mut m = Faux::avec(PUA, Some(2));
        assert_eq!(faire_choix(&mut m, PUA, 0, vue(Some(Some(1)))), Issue::Change);
        assert!(m.ecritures.is_empty() && m.notes.is_empty() && m.journal.is_empty());
        // Montrée illisible, lisible au moment d'écrire : de même.
        assert_eq!(faire_choix(&mut m, PUA, 0, vue(None)), Issue::Change);
        // Règle absente montrée, présente relue : de même.
        let asr = IdChoix::Asr(ASR_TOUTES[0]);
        let mut m = Faux::avec(asr, Some(1));
        assert_eq!(faire_choix(&mut m, asr, 0, vue(Some(None))), Issue::Change);
        assert!(m.ecritures.is_empty() && m.notes.is_empty());
        // La valeur montrée est encore là : la baisse se fait.
        assert!(matches!(
            faire_choix(&mut m, asr, 0, vue(Some(Some(1)))),
            Issue::Fait { note: true, .. }
        ));
    }

    /// Une autre valeur du même rang (audit des disques → audit de tout) est une baisse : montrée, notée, et
    /// « Rallumer » remet la valeur d'avant.
    #[test]
    fn meme_rang_autre_valeur_notee() {
        let cfa = IdChoix::Defender(ReglageDefender::Cfa);
        let mut m = Faux::avec(cfa, Some(4));
        let renforce = Some(Montre {
            sens: Sens::Renforce,
            lue: Some(Some(4)),
        });
        assert_eq!(faire_choix(&mut m, cfa, 2, renforce), Issue::Change);
        assert_eq!(m.ecritures, Vec::<(String, i64)>::new());
        assert!(matches!(baisser(&mut m, cfa, 2), Issue::Fait { note: true, .. }));
        let n = Note::lire(&cfa.texte(), &m.notes[&cfa.texte()]).unwrap();
        assert_eq!((n.avant, n.posee), (Some(4), 2));
        // Redemander la même valeur ne fait rien et garde la note.
        assert!(matches!(baisser(&mut m, cfa, 2), Issue::Rien(_)));
        assert_eq!(m.notes.len(), 1);
        assert!(matches!(rallumer(&mut m, cfa), Issue::Fait { .. }));
        assert_eq!(m.valeur(cfa), Some(4));
        assert!(m.notes.is_empty());
        // Windows garde la valeur du même rang : « Rallumer » ne le compte pas comme fait.
        let mut m = Faux::avec(cfa, Some(2));
        m.notes.insert(cfa.texte(), note(cfa, Some(4), 2));
        m.garde = true;
        assert!(matches!(rallumer(&mut m, cfa), Issue::Echec { .. }));
        assert_eq!(m.notes.len(), 1);
    }

    /// La question n'accepte qu'un oui, dans une vraie console : Entrée, « n », la fin de l'entrée (réponse vide) ou
    /// une autre réponse refusent ; hors console, rien n'est même demandé.
    #[test]
    fn question_de_baisse() {
        for r in ["", "n", "N", "non", "no", "  ", "ok", "oui oui", "o n"] {
            assert!(!demander_baisse(true, |_| r.to_string()), "{r:?}");
        }
        for r in ["o", "O", "oui", "y", "yes", " o "] {
            assert!(demander_baisse(true, |_| r.to_string()), "{r:?}");
        }
        let mut demande = false;
        assert!(!demander_baisse(false, |_| {
            demande = true;
            "o".to_string()
        }));
        assert!(!demande);
        // La question elle-même : en majuscules « MOINS », défaut non.
        let mut question = String::new();
        demander_baisse(true, |q| {
            question = q.to_string();
            String::new()
        });
        assert!(question.contains("[o/N]") || question.contains("[y/N]"));
    }
}
