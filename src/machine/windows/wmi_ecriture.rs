//! Retirer un abonnement WMI permanent signalé par le bilan, et le recréer, par le processus élevé, sans PowerShell
//! (lot 3.5, passe c, R49). La ligne désigne le consumer (sa classe et son nom), le processus élevé juge : il relit
//! root\subscription (`wmi::Abonnements`, qui n'ouvre que cet espace de noms et ne touche qu'à ses quatre classes),
//! retrouve le consumer, ses liaisons (__FilterToConsumerBinding) et leurs filtres (__EventFilter), refuse tout
//! abonnement de Windows ou de Defender (`gestes::consumer_wmi_protege`), et le bilan refait sur une lecture complète
//! de cet instant (`portes::abonnement_signale`) doit proposer cette même ligne. Les propriétés des trois objets sont
//! notées dans `gestes::WMI_AVANT_CLE` (`gestes::NoteWmi`, bornée, versionnée, avec son empreinte) avant tout
//! changement, relues juste avant, puis la liaison, le consumer et le filtre qui ne sert à aucune autre liaison sont
//! supprimés (IWbemServices::DeleteInstance), et l'état réel est relu.
//!
//! La remise est coupée jusqu'à la passe 3.5d : le processus élevé refuse la ligne sans rien lire ni écrire, et la
//! note reste. En 3.5d, elle reviendra avec une confirmation dans la fenêtre administrateur, parce qu'une ligne
//! forgée par un programme du compte pourrait sinon recréer une persistance qui tourne en SYSTEM. Son code est gardé
//! (`remettre_apres_confirmation`) : il recrée les trois objets depuis la note seule (SpawnInstance, PutInstance sans
//! jamais écraser un objet présent), relit, et dit si un chemin d'objet a changé. Les références d'une liaison sont
//! celles des objets recréés, relues dans WMI, jamais un texte de la note.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use winreg::RegKey;
use winreg::enums::RegType::REG_BINARY;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};

use super::corrections::Resultat;
use super::wmi::{Abonnements, CLASSE_ABSENTE, Ligne, Parametre, Valeur};
use crate::machine::gestes::{
    self, AbonnementWmi, Acte, GenreWmi, LiaisonNotee, NoteWmi, ObjetNote, PROPRIETES_FILTRE, PROPRIETES_LIAISON,
    ValeurNotee,
};
use crate::ui::{tr, trf};

const FILTRE: &str = "__EventFilter";
const LIAISON: &str = "__FilterToConsumerBinding";
/// WBEM_E_NOT_FOUND : l'objet à supprimer n'est déjà plus là.
const ABSENT: i32 = 0x8004_1002_u32.cast_signed();
/// Le bilan refait lit cinq sections, chacune avec son propre délai : le geste entier en a plus.
const DELAI: Duration = Duration::from_secs(150);

fn refus(raison: String) -> Resultat {
    Resultat::echec(None, raison)
}

/// Une valeur lue par WMI, notée si son type est celui de la liste ; `None` sinon (jamais devinée).
fn notee(v: Option<&Valeur>, genre: GenreWmi) -> Option<ValeurNotee> {
    match (v.unwrap_or(&Valeur::Nul), genre) {
        (Valeur::Nul, _) => Some(ValeurNotee::Absente),
        (Valeur::Texte(t), GenreWmi::Texte) => {
            (t.len() <= gestes::NOTE_WMI_TEXTE_MAX).then(|| ValeurNotee::Texte(t.clone()))
        }
        (Valeur::Entier(n), GenreWmi::Entier) => Some(ValeurNotee::Entier(*n)),
        (Valeur::Booleen(b), GenreWmi::Booleen) => Some(ValeurNotee::Booleen(*b)),
        _ => None,
    }
}

/// Un objet lu, noté avec son chemin relatif et les propriétés de sa liste.
fn objet(l: &Ligne, proprietes: &[(&str, GenreWmi)]) -> Option<ObjetNote> {
    Some(ObjetNote {
        chemin: l.get("__RELPATH")?.texte()?.to_string(),
        valeurs: proprietes
            .iter()
            .map(|(n, g)| notee(l.get(*n), *g))
            .collect::<Option<Vec<_>>>()?,
    })
}

/// WMI compare les clés sans la casse : une référence « EVIL » vise l'objet « evil ». Comparer à l'identique
/// laisserait une liaison de côté et ferait croire un filtre libre alors qu'il sert encore.
fn meme_cle(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// Un nom tel que le bilan le lit (`portes::sur_une_ligne`) : sauts de ligne changés en une espace, bordures retirées.
fn lu_par_le_bilan(nom: &str) -> String {
    let mut sortie = String::with_capacity(nom.len());
    let mut saut = false;
    for c in nom.chars() {
        if matches!(c, '\r' | '\n') {
            if !saut {
                sortie.push(' ');
            }
            saut = true;
        } else {
            saut = false;
            sortie.push(c);
        }
    }
    sortie.trim().to_string()
}

fn nom_de(l: &Ligne) -> Option<&str> {
    l.get("Name")?.texte()
}

/// Les instances d'une classe ; une classe absente de ce Windows se lit comme vide.
fn instances(a: &Abonnements, classe: &str, champs: &[&str]) -> windows::core::Result<Vec<Ligne>> {
    match a.lire(classe, champs) {
        Err(e) if CLASSE_ABSENTE.contains(&e.code().0) => Ok(Vec::new()),
        r => r,
    }
}

fn champs(proprietes: &[(&'static str, GenreWmi)]) -> Vec<&'static str> {
    proprietes.iter().map(|(n, _)| *n).collect()
}

/// Ce qu'une lecture n'a pas permis de noter : dit tel quel, rien n'est écrit.
enum Illisible {
    Com(i32),
    Forme(String),
}

impl Illisible {
    fn resultat(self) -> Resultat {
        match self {
            Illisible::Com(code) => refus(trf!(
                "WMI refuse la lecture de root\\subscription ({code:#010x}) : rien d'écrit",
                "WMI refuses to read root\\subscription ({code:#010x}): nothing written"
            )),
            Illisible::Forme(r) => refus(r),
        }
    }
}

impl From<windows::core::Error> for Illisible {
    fn from(e: windows::core::Error) -> Self {
        Illisible::Com(e.code().0)
    }
}

/// Classe et nom d'une référence de liaison, seulement si elle vise root\subscription : relative
/// (`CommandLineEventConsumer.Name="x"`), ou préfixée de cet espace, avec ou sans serveur. Une référence vers un autre
/// espace de noms n'est pas un objet d'ici : elle est illisible pour le geste, qui refuse alors d'écrire.
fn reference_locale(chemin: &str) -> Option<(String, String)> {
    let avant_cle = chemin.split('"').next().unwrap_or_default();
    let relative = match avant_cle.rfind(':') {
        Some(i) => {
            let (espace, reste) = (chemin.get(..i)?, chemin.get(i.checked_add(1)?..)?);
            let espace = match espace.strip_prefix(r"\\") {
                Some(serveur) => serveur.split_once('\\')?.1,
                None => espace,
            };
            if !espace.eq_ignore_ascii_case(r"root\subscription") {
                return None;
            }
            reste
        }
        None => chemin,
    };
    if relative.starts_with('\\') {
        return None;
    }
    super::portes::reference(relative)
}

/// Les liaisons lues : (filtre, classe du consumer, nom du consumer, la ligne). Une référence illisible arrête tout :
/// sans elle, on ne saurait dire si un filtre sert encore à une autre liaison.
fn liaisons(a: &Abonnements) -> Result<Vec<(String, String, String, Ligne)>, Illisible> {
    let mut c = champs(&PROPRIETES_LIAISON);
    c.extend(["Filter", "Consumer"]);
    instances(a, LIAISON, &c)?
        .into_iter()
        .map(|l| {
            let filtre = l.get("Filter").and_then(Valeur::texte).and_then(reference_locale);
            let consumer = l.get("Consumer").and_then(Valeur::texte).and_then(reference_locale);
            match (filtre, consumer) {
                (Some((_, f)), Some((classe, nom))) => Ok((f, classe, nom, l)),
                _ => Err(Illisible::Forme(
                    tr!(
                        "une liaison de root\\subscription a une référence illisible : rien d'écrit (à retirer à la main)",
                        "a binding in root\\subscription has an unreadable reference: nothing written (remove by hand)"
                    )
                    .to_string(),
                )),
            }
        })
        .collect()
}

/// L'abonnement `w` tel qu'il est à cet instant, noté ; `Ok(None)` si son consumer n'existe pas.
fn lire_abonnement(a: &Abonnements, w: &AbonnementWmi) -> Result<Option<NoteWmi>, Illisible> {
    let classe = w.classe.classe();
    let proprietes = w.classe.proprietes();
    let consumers = instances(a, classe, &champs(proprietes))?;
    let mut trouves = consumers.iter().filter(|l| nom_de(l) == Some(w.nom.texte()));
    let forme = |r: &str| Illisible::Forme(r.to_string());
    let Some(lu) = trouves.next() else {
        // Le bilan lit chaque nom sur une ligne (espaces de bordure retirés, sauts de ligne changés en espace) : un
        // consumer dont seul le nom ainsi lu correspond existe bel et bien, il n'est pas « déjà retiré ».
        if consumers
            .iter()
            .filter_map(nom_de)
            .any(|n| lu_par_le_bilan(n) == w.nom.texte())
        {
            return Err(forme(tr!(
                "le vrai nom de ce consumer a des espaces en bordure ou des sauts de ligne : rien d'écrit (à retirer à la main)",
                "this consumer's real name has leading or trailing spaces or line breaks: nothing written (remove by hand)"
            )));
        }
        return Ok(None);
    };
    if trouves.next().is_some() {
        return Err(forme(tr!(
            "deux consumers portent ce nom : rien d'écrit",
            "two consumers have this name: nothing written"
        )));
    }
    let consumer = objet(lu, proprietes).ok_or_else(|| {
        forme(tr!(
            "propriété du consumer illisible ou trop longue pour être notée : rien d'écrit",
            "consumer property unreadable or too long to be noted: nothing written"
        ))
    })?;
    let liees = liaisons(a)?;
    let filtres = instances(a, FILTRE, &champs(&PROPRIETES_FILTRE))?;
    let a_nous = |c: &str, n: &str| c.eq_ignore_ascii_case(classe) && meme_cle(n, w.nom.texte());
    let mut notees = Vec::new();
    for (f, _, _, l) in liees.iter().filter(|(_, c, n, _)| a_nous(c, n)) {
        let Some(filtre) = filtres.iter().find(|x| nom_de(x).is_some_and(|x| meme_cle(x, f))) else {
            return Err(forme(tr!(
                "une liaison de ce consumer vise un filtre introuvable : rien d'écrit (à retirer à la main)",
                "a binding of this consumer points to a filter that cannot be found: nothing written (remove by hand)"
            )));
        };
        let partage = liees.iter().any(|(autre, c, n, _)| meme_cle(autre, f) && !a_nous(c, n));
        let (Some(filtre), Some(liaison)) = (objet(filtre, &PROPRIETES_FILTRE), objet(l, &PROPRIETES_LIAISON)) else {
            return Err(forme(tr!(
                "propriété d'un filtre ou d'une liaison illisible ou trop longue pour être notée : rien d'écrit",
                "property of a filter or binding unreadable or too long to be noted: nothing written"
            )));
        };
        notees.push(LiaisonNotee {
            filtre_retire: !partage && !gestes::abonnement_wmi_protege(f),
            filtre,
            liaison,
        });
    }
    if notees.len() > gestes::NOTE_WMI_LIAISONS_MAX {
        return Err(forme(tr!(
            "trop de liaisons pour ce consumer : rien d'écrit (à retirer à la main)",
            "too many bindings for this consumer: nothing written (remove by hand)"
        )));
    }
    Ok(Some(NoteWmi {
        classe: w.classe,
        consumer,
        liaisons: notees,
    }))
}

/// Ce que lance le consumer noté : son programme, sa ligne de commande, son fichier de script.
fn programmes(n: &NoteWmi) -> Vec<&str> {
    n.classe
        .proprietes()
        .iter()
        .zip(&n.consumer.valeurs)
        .filter(|((p, _), _)| matches!(*p, "ExecutablePath" | "CommandLineTemplate" | "ScriptFileName"))
        .filter_map(|(_, v)| match v {
            ValeurNotee::Texte(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

/// Le nom de la note : la ligne sans son verbe (la classe et le nom en hexadécimal), le même pour les deux sens.
fn nom_note(w: &AbonnementWmi) -> String {
    Acte::WmiAbonnementRemettre(w.clone())
        .ligne()
        .strip_prefix(gestes::WMI_ABONNEMENT_REMETTRE)
        .unwrap_or_default()
        .to_string()
}

fn notes(ecrire: bool) -> std::io::Result<RegKey> {
    let racine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let drapeaux = KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY;
    if ecrire {
        racine
            .create_subkey_with_flags(gestes::WMI_AVANT_CLE, drapeaux)
            .map(|(k, _)| k)
    } else {
        racine.open_subkey_with_flags(gestes::WMI_AVANT_CLE, drapeaux)
    }
}

fn ecrire_note(nom: &str, octets: Vec<u8>) -> std::io::Result<()> {
    notes(true).and_then(|k| {
        k.set_raw_value(
            nom,
            &winreg::RegValue {
                bytes: octets.into(),
                vtype: REG_BINARY,
            },
        )
    })
}

fn effacer_note(nom: &str) {
    if let Ok(k) = notes(false) {
        let _ = k.delete_value(nom);
    }
}

fn lire_note(nom: &str) -> Option<NoteWmi> {
    let v = notes(false).ok()?.get_raw_value(nom).ok()?;
    (v.vtype == REG_BINARY).then_some(())?;
    NoteWmi::lire(&v.bytes)
}

/// Dans un fil COM à lui ; si WMI ne répond pas à temps, rien n'est sûr : dit tel quel. Le fil n'est pas arrêté,
/// seulement abandonné : `abandon` levé, il n'écrit plus rien de neuf (vérifié avant la note, la première suppression
/// et la première création), mais un geste déjà commencé peut s'achever après le message.
fn dans_wmi(geste: impl FnOnce(&AtomicBool) -> Resultat + Send + 'static) -> Resultat {
    let abandon = Arc::new(AtomicBool::new(false));
    let vu_du_fil = Arc::clone(&abandon);
    super::wmi::com_delai(crate::compte_rendu::Contexte::Wmi, "abonnement WMI", DELAI, move || Ok(geste(&vu_du_fil))).unwrap_or_else(|| {
        abandon.store(true, Ordering::SeqCst);
        Resultat::echec(
            None,
            tr!(
                "WMI ne répond pas : l'état de l'abonnement est à relire (relancez le bilan) ; un retrait ou une remise déjà commencé peut s'achever après ce message",
                "WMI does not answer: the subscription's state must be read again (run the check again); a removal or restore already started may finish after this message"
            )
            .to_string(),
        )
    })
}

fn abandonne() -> Resultat {
    refus(
        tr!(
            "délai dépassé avant d'écrire : rien d'écrit",
            "time limit passed before writing: nothing written"
        )
        .to_string(),
    )
}

/// Ce qui reste de l'abonnement noté : le consumer, une liaison vers lui, un filtre que Vanguard devait retirer.
fn restes(a: &Abonnements, n: &NoteWmi, w: &AbonnementWmi) -> Result<Vec<String>, Illisible> {
    let mut restes = Vec::new();
    let classe = w.classe.classe();
    if instances(a, classe, &["Name"])?
        .iter()
        .any(|l| nom_de(l) == Some(w.nom.texte()))
    {
        restes.push(tr!("le consumer", "the consumer").to_string());
    }
    let liees = liaisons(a)?
        .iter()
        .filter(|(_, c, nom, _)| c.eq_ignore_ascii_case(classe) && meme_cle(nom, w.nom.texte()))
        .count();
    if liees > 0 {
        restes.push(trf!("{liees} liaison(s)", "{liees} binding(s)"));
    }
    let filtres = instances(a, FILTRE, &["Name"])?;
    for l in n.liaisons.iter().filter(|l| l.filtre_retire) {
        if filtres.iter().any(|f| nom_de(f) == l.filtre.nom()) {
            let f = crate::ui::affichable(l.filtre.nom().unwrap_or_default());
            restes.push(trf!("le filtre « {f} »", "the filter “{f}”"));
        }
    }
    Ok(restes)
}

fn decrire(n: &NoteWmi) -> String {
    let (l, f) = (n.liaisons.len(), n.liaisons.iter().filter(|l| l.filtre_retire).count());
    trf!(
        "abonnement WMI présent ({l} liaison(s), {f} filtre(s) propre(s) à lui)",
        "WMI subscription present ({l} binding(s), {f} filter(s) of its own)"
    )
}

/// Dans le processus élevé : retire l'abonnement `w` si et seulement si le bilan, refait ici sur une lecture complète,
/// le signale et propose cette même ligne.
pub(super) fn retirer(w: &AbonnementWmi) -> Resultat {
    let w = w.clone();
    dans_wmi(move |abandon| retirer_ici(&w, abandon))
}

fn retirer_ici(w: &AbonnementWmi, abandon: &AtomicBool) -> Resultat {
    let ligne = Acte::WmiAbonnementRetirer(w.clone()).ligne();
    let protege = tr!(
        "abonnement de Windows ou de Defender : Vanguard n'y touche jamais ; rien d'écrit",
        "Windows or Defender subscription: Vanguard never touches it; nothing written"
    );
    if gestes::abonnement_wmi_protege(w.nom.texte()) {
        return refus(protege.to_string());
    }
    let a = match Abonnements::ouvrir() {
        Ok(a) => a,
        Err(e) => return Illisible::from(e).resultat(),
    };
    let note = match lire_abonnement(&a, w) {
        Ok(Some(n)) => n,
        Ok(None) => {
            return Resultat::rien(
                tr!(
                    "l'abonnement n'existe plus : rien à retirer",
                    "the subscription no longer exists: nothing to remove"
                )
                .to_string(),
            );
        }
        Err(i) => return i.resultat(),
    };
    if gestes::consumer_wmi_protege(w.nom.texte(), &programmes(&note)) {
        return refus(protege.to_string());
    }
    if !super::portes::abonnement_signale(&ligne) {
        return refus(
            tr!(
                "le bilan refait ici ne signale pas cet abonnement : rien d'écrit",
                "the check run again here does not report this subscription: nothing written"
            )
            .to_string(),
        );
    }
    if !note.valide(w) {
        return refus(
            tr!(
                "un filtre de cet abonnement a un nom piégé (vide, trop long, avec un caractère de contrôle, ou en double) : rien d'écrit (à retirer à la main)",
                "a filter of this subscription has a trapped name (empty, too long, with a control character, or duplicated): nothing written (remove by hand)"
            )
            .to_string(),
        );
    }
    let Some(octets) = note.octets() else {
        return refus(
            tr!(
                "abonnement trop long pour être noté : rien d'écrit (à retirer à la main)",
                "subscription too long to be noted: nothing written (remove by hand)"
            )
            .to_string(),
        );
    };
    // Notée d'abord : sans note, pas de changement (la remise serait perdue).
    let nom_note = nom_note(w);
    if abandon.load(Ordering::SeqCst) {
        return abandonne();
    }
    if let Err(e) = ecrire_note(&nom_note, octets) {
        return refus(trf!(
            "les propriétés de l'abonnement ne se notent pas ({e}) : rien d'écrit",
            "the subscription's properties cannot be noted ({e}): nothing written"
        ));
    }
    // Relu juste avant : jamais un abonnement changé depuis le jugement.
    if !matches!(lire_abonnement(&a, w), Ok(Some(encore)) if encore == note) {
        effacer_note(&nom_note);
        return refus(
            tr!(
                "l'abonnement a changé entre la lecture et l'écriture ; rien d'écrit",
                "the subscription changed between reading and writing; nothing written"
            )
            .to_string(),
        );
    }
    let avant = decrire(&note);
    // La liaison d'abord (le consumer ne se déclenche plus), puis le consumer, puis les filtres propres à lui.
    let mut ordre: Vec<(&str, &str)> = note
        .liaisons
        .iter()
        .map(|l| (LIAISON, l.liaison.chemin.as_str()))
        .collect();
    ordre.push((w.classe.classe(), note.consumer.chemin.as_str()));
    ordre.extend(
        note.liaisons
            .iter()
            .filter(|l| l.filtre_retire)
            .map(|l| (FILTRE, l.filtre.chemin.as_str())),
    );
    if abandon.load(Ordering::SeqCst) {
        effacer_note(&nom_note);
        return abandonne();
    }
    let mut refuse = None;
    for (classe, chemin) in ordre {
        match a.supprimer(classe, chemin) {
            Ok(()) => {}
            Err(e) if e.code().0 == ABSENT => {}
            Err(e) => {
                refuse = Some(e.code().0);
                break;
            }
        }
    }
    match restes(&a, &note, w) {
        Ok(r) if r.is_empty() => Resultat::fait(avant),
        Ok(r) => {
            let r = r.join(", ");
            let pourquoi = refuse.map_or_else(String::new, |c| format!(" ({c:#010x})"));
            Resultat::echec(
                Some(avant),
                trf!(
                    "retrait incomplet{pourquoi} : il reste {r} ; la note est gardée",
                    "incomplete removal{pourquoi}: {r} remain(s); the note is kept"
                ),
            )
        }
        Err(_) => Resultat::echec(
            Some(avant),
            tr!(
                "l'abonnement n'a pas pu être relu après le retrait : état inconnu, à relire (relancez le bilan) ; la note est gardée",
                "the subscription could not be read again after removal: state unknown, check again (run the check again); the note is kept"
            )
            .to_string(),
        ),
    }
}

/// Les propriétés d'un objet noté, prêtes pour `Abonnements::creer` ; une valeur absente n'est pas posée (WMI garde
/// sa valeur par défaut). Un entier hors de 32 bits est refusé : aucune propriété notée n'en a de plus grand.
fn parametres(o: &ObjetNote, proprietes: &[(&'static str, GenreWmi)]) -> Option<Vec<(&'static str, Parametre)>> {
    let mut p = Vec::new();
    for ((nom, _), v) in proprietes.iter().zip(&o.valeurs) {
        match v {
            ValeurNotee::Absente => {}
            ValeurNotee::Texte(t) => p.push((*nom, Parametre::Texte(t.clone()))),
            ValeurNotee::Booleen(b) => p.push((*nom, Parametre::Booleen(*b))),
            ValeurNotee::Entier(n) => {
                let n = i32::try_from(*n)
                    .ok()
                    .or_else(|| u32::try_from(*n).ok().map(u32::cast_signed))?;
                p.push((*nom, Parametre::Entier(n)));
            }
        }
    }
    Some(p)
}

/// Les valeurs relues correspondent-elles à celles de la note ? Une valeur notée absente ne compte pas : WMI y met
/// sa valeur par défaut.
fn memes_valeurs(notees: &ObjetNote, relues: &ObjetNote) -> bool {
    notees
        .valeurs
        .iter()
        .zip(&relues.valeurs)
        .all(|(n, r)| *n == ValeurNotee::Absente || n == r)
}

/// Retire ce que la remise a créé, après un échec : le consumer recréé, toute liaison qui le vise (une liaison
/// pendante d'avant comprise, qui ne pouvait viser que ce nom absent), et les filtres créés par elle seule ; jamais un
/// filtre qui était là avant.
fn defaire_creation(a: &Abonnements, w: &AbonnementWmi, filtres_crees: &[String]) {
    let classe = w.classe.classe();
    if let Ok(liees) = liaisons(a) {
        for (_, c, n, l) in &liees {
            if c.eq_ignore_ascii_case(classe)
                && meme_cle(n, w.nom.texte())
                && let Some(chemin) = l.get("__RELPATH").and_then(Valeur::texte)
            {
                let _ = a.supprimer(LIAISON, chemin);
            }
        }
    }
    let supprimer_nomme = |classe: &str, nom: &str| {
        if let Ok(lus) = instances(a, classe, &["Name"]) {
            for l in lus.iter().filter(|l| nom_de(l) == Some(nom)) {
                if let Some(chemin) = l.get("__RELPATH").and_then(Valeur::texte) {
                    let _ = a.supprimer(classe, chemin);
                }
            }
        }
    };
    supprimer_nomme(classe, w.nom.texte());
    for f in filtres_crees {
        supprimer_nomme(FILTRE, f);
    }
}

/// Dans le processus élevé : la remise est coupée jusqu'à la passe 3.5d (elle reviendra avec une confirmation dans la
/// fenêtre administrateur). Refusée sans rien lire ni écrire : ni WMI, ni le registre, et la note reste.
pub(super) fn remettre(_w: &AbonnementWmi) -> Resultat {
    refus(
        tr!(
            "la remise d'un abonnement WMI viendra dans une version suivante, avec une confirmation dans la fenêtre administrateur : rien n'est changé, et la note de Vanguard est gardée",
            "putting back a WMI subscription will come in a later version, with a confirmation in the administrator window: nothing is changed, and Vanguard's note is kept"
        )
        .to_string(),
    )
}

/// Passe 3.5d, une fois la confirmation demandée dans la fenêtre administrateur : recrée l'abonnement `w` depuis la
/// note que `retirer` a écrite, seulement si aucun consumer de ce nom n'existe et que chaque filtre est dans l'état
/// noté ; la note est effacée après relecture.
// Gardé pour la passe 3.5d : personne ne l'appelle d'ici là (`remettre` refuse).
#[allow(dead_code)]
fn remettre_apres_confirmation(w: &AbonnementWmi) -> Resultat {
    let w = w.clone();
    dans_wmi(move |abandon| remettre_ici(&w, abandon))
}

fn remettre_ici(w: &AbonnementWmi, abandon: &AtomicBool) -> Resultat {
    let nom_note = nom_note(w);
    let Some(note) = lire_note(&nom_note).filter(|n| n.valide(w)) else {
        return refus(
            tr!(
                "aucune note valide de Vanguard pour cet abonnement (absente, altérée ou d'un autre abonnement) : rien d'écrit",
                "no valid Vanguard note for this subscription (missing, altered or for another subscription): nothing written"
            )
            .to_string(),
        );
    };
    if gestes::consumer_wmi_protege(w.nom.texte(), &programmes(&note)) {
        return refus(
            tr!(
                "abonnement de Windows ou de Defender : Vanguard n'y touche jamais ; rien d'écrit",
                "Windows or Defender subscription: Vanguard never touches it; nothing written"
            )
            .to_string(),
        );
    }
    let Some(params_consumer) = parametres(&note.consumer, w.classe.proprietes()) else {
        return refus(tr!("note invalide : rien d'écrit", "invalid note: nothing written").to_string());
    };
    let a = match Abonnements::ouvrir() {
        Ok(a) => a,
        Err(e) => return Illisible::from(e).resultat(),
    };
    match lire_abonnement(&a, w) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return refus(
                tr!(
                    "un consumer de ce nom existe déjà : rien d'écrit (jamais par-dessus)",
                    "a consumer with this name already exists: nothing written (never over it)"
                )
                .to_string(),
            );
        }
        Err(i) => return i.resultat(),
    }
    let filtres = match instances(&a, FILTRE, &champs(&PROPRIETES_FILTRE)) {
        Ok(f) => f,
        Err(e) => return Illisible::from(e).resultat(),
    };
    // Chaque filtre : à recréer s'il a été retiré (sauf s'il est revenu tel quel), à retrouver s'il était resté.
    let mut a_creer = Vec::new();
    for l in &note.liaisons {
        let nom = l.filtre.nom().unwrap_or_default();
        let present = filtres
            .iter()
            .find(|f| nom_de(f) == Some(nom))
            .map(|f| objet(f, &PROPRIETES_FILTRE));
        match (l.filtre_retire, present) {
            (true, None) => match parametres(&l.filtre, &PROPRIETES_FILTRE) {
                Some(p) => a_creer.push((nom.to_string(), p)),
                None => return refus(tr!("note invalide : rien d'écrit", "invalid note: nothing written").to_string()),
            },
            (true, Some(Some(lu))) if memes_valeurs(&l.filtre, &lu) => {}
            (false, Some(_)) => {}
            (true, Some(_)) => {
                let nom = crate::ui::affichable(nom);
                return refus(trf!(
                    "un autre filtre « {nom} » existe déjà : rien d'écrit (jamais par-dessus)",
                    "another filter “{nom}” already exists: nothing written (never over it)"
                ));
            }
            (false, None) => {
                let nom = crate::ui::affichable(nom);
                return refus(trf!(
                    "le filtre « {nom} », resté en place au retrait, n'existe plus : rien d'écrit",
                    "the filter “{nom}”, left in place at removal, no longer exists: nothing written"
                ));
            }
        }
    }
    let mut filtres_crees = Vec::new();
    let echec = |a: &Abonnements, filtres_crees: &[String], code: Option<i32>| {
        defaire_creation(a, w, filtres_crees);
        refus(match code {
            Some(code) => trf!(
                "WMI refuse la création ({code:#010x}) : ce que Vanguard venait de créer est retiré ; la note est gardée",
                "WMI refuses the creation ({code:#010x}): what Vanguard had just created is removed; the note is kept"
            ),
            None => tr!(
                "un objet créé ne se retrouve pas à la relecture : ce que Vanguard venait de créer est retiré ; la note est gardée",
                "a created object cannot be found when read back: what Vanguard had just created is removed; the note is kept"
            )
            .to_string(),
        })
    };
    if abandon.load(Ordering::SeqCst) {
        return abandonne();
    }
    for (nom, p) in &a_creer {
        if let Err(e) = a.creer(FILTRE, p) {
            return echec(&a, &filtres_crees, Some(e.code().0));
        }
        filtres_crees.push(nom.clone());
    }
    if let Err(e) = a.creer(w.classe.classe(), &params_consumer) {
        return echec(&a, &filtres_crees, Some(e.code().0));
    }
    // Les références d'une liaison : les chemins relus du filtre et du consumer, tels que WMI les écrit.
    let chemin_de = |classe: &str, nom: &str| -> Option<String> {
        instances(&a, classe, &["Name"])
            .ok()?
            .iter()
            .find(|l| nom_de(l).is_some_and(|n| meme_cle(n, nom)))
            .and_then(|l| l.get("__RELPATH")?.texte().map(str::to_string))
    };
    let Some(chemin_consumer) = chemin_de(w.classe.classe(), w.nom.texte()) else {
        return echec(&a, &filtres_crees, None);
    };
    for l in &note.liaisons {
        let nom = l.filtre.nom().unwrap_or_default();
        let (Some(chemin_filtre), Some(mut p)) = (chemin_de(FILTRE, nom), parametres(&l.liaison, &PROPRIETES_LIAISON))
        else {
            return echec(&a, &filtres_crees, None);
        };
        p.push(("Filter", Parametre::Texte(chemin_filtre)));
        p.push(("Consumer", Parametre::Texte(chemin_consumer.clone())));
        if let Err(e) = a.creer(LIAISON, &p) {
            return echec(&a, &filtres_crees, Some(e.code().0));
        }
    }
    let avant = tr!("abonnement WMI absent", "WMI subscription absent").to_string();
    let Ok(Some(relu)) = lire_abonnement(&a, w) else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "l'abonnement recréé n'a pas pu être relu : état inconnu, à relire (relancez le bilan) ; la note est gardée",
                "the recreated subscription could not be read again: state unknown, check again (run the check again); the note is kept"
            )
            .to_string(),
        );
    };
    // Chaque objet noté doit se relire avec ses valeurs ; un chemin d'objet changé se dit.
    let mut differents = Vec::new();
    let mut fideles = memes_valeurs(&note.consumer, &relu.consumer) && relu.liaisons.len() == note.liaisons.len();
    if relu.consumer.chemin != note.consumer.chemin {
        differents.push(relu.consumer.chemin.clone());
    }
    for l in &note.liaisons {
        match relu.liaisons.iter().find(|r| r.filtre.nom() == l.filtre.nom()) {
            Some(r) => {
                fideles &= memes_valeurs(&l.filtre, &r.filtre) && memes_valeurs(&l.liaison, &r.liaison);
                for (n, r) in [(&l.filtre, &r.filtre), (&l.liaison, &r.liaison)] {
                    if n.chemin != r.chemin {
                        differents.push(r.chemin.clone());
                    }
                }
            }
            None => fideles = false,
        }
    }
    if !fideles {
        return Resultat::echec(
            Some(avant),
            tr!(
                "abonnement recréé, mais relu avec des propriétés différentes de la note : à vérifier ; la note est gardée",
                "subscription recreated, but read back with properties different from the note: check it; the note is kept"
            )
            .to_string(),
        );
    }
    effacer_note(&nom_note);
    let raison = if differents.is_empty() {
        tr!(
            "recréé et relu ; chemins d'objet identiques",
            "recreated and read back; same object paths"
        )
        .to_string()
    } else {
        let d = crate::ui::affichable(&differents.join(" ; "));
        trf!(
            "recréé et relu ; chemin d'objet différent de celui d'avant : {d}",
            "recreated and read back; object path different from before: {d}"
        )
    };
    Resultat {
        reussi: true,
        rien: false,
        avant: Some(avant),
        raison,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_de_root_subscription_seulement() {
        let attendu = Some(("CommandLineEventConsumer".to_string(), "Mise a jour".to_string()));
        for chemin in [
            r#"CommandLineEventConsumer.Name="Mise a jour""#,
            r#"\\.\root\subscription:CommandLineEventConsumer.Name="Mise a jour""#,
            r#"\\PC-SALON\ROOT\Subscription:CommandLineEventConsumer.Name="Mise a jour""#,
            r#"root\subscription:CommandLineEventConsumer.Name="Mise a jour""#,
        ] {
            assert_eq!(reference_locale(chemin), attendu, "{chemin}");
        }
        // Un deux-points dans le nom ne passe pas pour un espace de noms.
        assert_eq!(
            reference_locale(r#"__EventFilter.Name="a:b""#),
            Some(("__EventFilter".to_string(), "a:b".to_string()))
        );
        for chemin in [
            r#"\\.\root\cimv2:CommandLineEventConsumer.Name="x""#,
            r#"root\default:CommandLineEventConsumer.Name="x""#,
            r#"root\subscription:\\.\root\cimv2:CommandLineEventConsumer.Name="x""#,
            r#"\\.:CommandLineEventConsumer.Name="x""#,
            "",
        ] {
            assert_eq!(reference_locale(chemin), None, "{chemin}");
        }
    }

    #[test]
    fn noms_lus_par_le_bilan() {
        assert_eq!(lu_par_le_bilan(" Updater "), "Updater");
        assert_eq!(lu_par_le_bilan("Upda\r\ndater"), "Upda dater");
        assert_eq!(lu_par_le_bilan("Updater"), "Updater");
    }

    /// La remise est coupée jusqu'à la passe 3.5d : une ligne « remettre » bien formée, passée par l'aiguillage du
    /// processus élevé, est refusée, et la note valide de cet abonnement reste octet pour octet (rien d'écrit, rien
    /// d'effacé). Sans note, refusée de même, et aucune note n'apparaît.
    #[test]
    fn remise_refusee_note_gardee() {
        use crate::machine::gestes::{ClasseConsumer, NomConsumer, PROPRIETES_COMMANDE};
        let w = AbonnementWmi {
            classe: ClasseConsumer::Commande,
            nom: NomConsumer::nouveau("VanguardEssaiRemise").unwrap(),
        };
        let ligne = Acte::WmiAbonnementRemettre(w.clone()).ligne();
        let acte = gestes::analyser_acte(&ligne).expect("ligne bien formée");
        assert!(matches!(&acte, Acte::WmiAbonnementRemettre(x) if *x == w), "{ligne}");
        let t = |s: &str| ValeurNotee::Texte(s.to_string());
        let mut consumer = vec![ValeurNotee::Absente; PROPRIETES_COMMANDE.len()];
        consumer[0] = t("VanguardEssaiRemise");
        consumer[2] = t(r"cmd.exe /c C:\Users\Public\x.bat");
        let note = NoteWmi {
            classe: ClasseConsumer::Commande,
            consumer: ObjetNote {
                chemin: "CommandLineEventConsumer.Name=\"VanguardEssaiRemise\"".to_string(),
                valeurs: consumer,
            },
            liaisons: vec![LiaisonNotee {
                filtre_retire: true,
                filtre: ObjetNote {
                    chemin: "__EventFilter.Name=\"VanguardEssaiRemiseF\"".to_string(),
                    valeurs: vec![
                        t("VanguardEssaiRemiseF"),
                        t("SELECT * FROM __InstanceModificationEvent WITHIN 60"),
                        t("WQL"),
                        t(r"root\cimv2"),
                        ValeurNotee::Absente,
                    ],
                },
                liaison: ObjetNote {
                    chemin: String::new(),
                    valeurs: vec![ValeurNotee::Absente; PROPRIETES_LIAISON.len()],
                },
            }],
        };
        assert!(note.valide(&w));
        let octets = note.octets().unwrap();
        let nom = nom_note(&w);
        let relue = || notes(false).ok().and_then(|k| k.get_raw_value(&nom).ok());
        let faire = || super::super::services_ecriture::faire(&acte, &Ok(String::new()));
        let refusee = |r: &Resultat| !r.reussi && !r.rien && r.avant.is_none() && r.raison.contains("note");
        effacer_note(&nom);
        let r = faire();
        assert!(refusee(&r), "{}", r.raison);
        assert!(relue().is_none(), "aucune note écrite");
        if ecrire_note(&nom, octets.clone()).is_err() {
            return crate::essais::saute("registre de la machine non inscriptible");
        }
        let r = faire();
        let reste = relue();
        effacer_note(&nom);
        assert!(refusee(&r), "{}", r.raison);
        let reste = reste.expect("note gardée");
        assert_eq!((reste.vtype, &reste.bytes[..]), (REG_BINARY, &octets[..]));
    }

    /// Fonctions de la remise gardée pour la passe 3.5d (`remettre_apres_confirmation`), essayées seules d'ici là.
    #[test]
    fn valeurs_notees_et_recreees() {
        assert_eq!(notee(None, GenreWmi::Texte), Some(ValeurNotee::Absente));
        assert_eq!(
            notee(Some(&Valeur::Entier(5)), GenreWmi::Entier),
            Some(ValeurNotee::Entier(5))
        );
        // Jamais devinée : un type inattendu, un texte trop long refusent la note entière.
        assert_eq!(notee(Some(&Valeur::Texte("5".into())), GenreWmi::Entier), None);
        assert_eq!(notee(Some(&Valeur::Booleen(true)), GenreWmi::Texte), None);
        let long = Valeur::Texte("a".repeat(gestes::NOTE_WMI_TEXTE_MAX + 1));
        assert_eq!(notee(Some(&long), GenreWmi::Texte), None);
        let objet = ObjetNote {
            chemin: String::new(),
            valeurs: vec![
                ValeurNotee::Booleen(true),
                ValeurNotee::Absente,
                ValeurNotee::Absente,
                ValeurNotee::Entier(i64::from(u32::MAX)),
            ],
        };
        let p = parametres(&objet, &PROPRIETES_LIAISON).unwrap();
        assert_eq!(p.len(), 2);
        assert!(matches!(p[1], ("DeliveryQoS", Parametre::Entier(-1))));
        let mut trop = objet.clone();
        trop.valeurs[3] = ValeurNotee::Entier(i64::from(u32::MAX) + 1);
        assert!(parametres(&trop, &PROPRIETES_LIAISON).is_none());
        // Une valeur notée absente ne compte pas à la relecture ; une autre, oui.
        let mut relu = objet.clone();
        relu.valeurs[1] = ValeurNotee::Booleen(false);
        assert!(memes_valeurs(&objet, &relu));
        relu.valeurs[0] = ValeurNotee::Booleen(false);
        assert!(!memes_valeurs(&objet, &relu));
    }
}
