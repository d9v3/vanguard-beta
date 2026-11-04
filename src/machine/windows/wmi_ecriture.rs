//! Retirer un abonnement WMI permanent signalé par le bilan, et le recréer, par le processus élevé, sans PowerShell
//! (lot 3.5, passe c, R49). La ligne désigne le consumer (sa classe et son nom), le processus élevé juge : il relit
//! root\subscription (`wmi::Abonnements`, qui n'ouvre que cet espace de noms et ne touche qu'à ses quatre classes),
//! retrouve le consumer, ses liaisons (__FilterToConsumerBinding) et leurs filtres (__EventFilter), refuse un
//! abonnement qui lance le vrai programme de Windows ou de Defender (`protege::protege` : à sa place et signé par
//! Microsoft), et le bilan refait sur une lecture complète de cet instant (`portes::abonnement_signale`) doit proposer
//! cette même ligne. Les propriétés des trois objets sont notées dans `gestes::WMI_AVANT_CLE` (`gestes::NoteWmi`,
//! bornée, versionnée, avec son empreinte) avant tout changement, relues juste avant, puis la liaison, le consumer et
//! le filtre qui ne sert à aucune autre liaison sont supprimés (IWbemServices::DeleteInstance), et l'état réel est relu.
//!
//! Ce qu'un refus de prudence arrêtait se demande dans la console élevée, non par défaut (D6d) : un nom de Windows ou
//! de Defender qui n'est pas le vrai ; un retrait que Vanguard ne pourra pas défaire (vrai nom piégé, montré échappé ;
//! référence de liaison illisible : les filtres restent tous ; filtre introuvable ; note trop longue ou refusée ;
//! au-delà de 16 liaisons notées). La question est posée hors du fil COM, puis tout est relu et doit être identique.
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
use super::protege::Protege;
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

/// Un nom tel que le bilan le désigne (`portes::sur_une_ligne`, puis `gestes::nom_designe`) : sauts de ligne changés
/// en une espace, bordures retirées, guillemets et barre oblique inverse changés en « _ ».
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
    gestes::nom_designe(sortie.trim())
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

/// Une liaison de root\subscription telle que lue : ses deux références (`None` : illisible, ou hors de cet espace de
/// noms) et la ligne.
struct LiaisonBrute {
    filtre: Option<String>,
    consumer: Option<(String, String)>,
    ligne: Ligne,
}

fn liaisons(a: &Abonnements) -> windows::core::Result<Vec<LiaisonBrute>> {
    let mut c = champs(&PROPRIETES_LIAISON);
    c.extend(["Filter", "Consumer"]);
    Ok(instances(a, LIAISON, &c)?
        .into_iter()
        .map(|l| LiaisonBrute {
            filtre: l
                .get("Filter")
                .and_then(Valeur::texte)
                .and_then(reference_locale)
                .map(|(_, f)| f),
            consumer: l.get("Consumer").and_then(Valeur::texte).and_then(reference_locale),
            ligne: l,
        })
        .collect())
}

fn vise(b: &LiaisonBrute, classe: &str, nom: &str) -> bool {
    b.consumer
        .as_ref()
        .is_some_and(|(c, n)| c.eq_ignore_ascii_case(classe) && meme_cle(n, nom))
}

/// Une liaison du consumer : son chemin, le filtre visé (nom et chemin) s'il se retrouve, s'il peut partir avec le
/// consumer (il ne sert à rien d'autre, n'a pas un nom de Windows ou de Defender, et toutes les liaisons se lisent),
/// et sa note (`None` : filtre introuvable, ou une propriété qui ne se note pas).
#[derive(Clone, Debug, PartialEq, Eq)]
struct LiaisonLue {
    chemin: String,
    filtre: Option<(String, String)>,
    filtre_libre: bool,
    notee: Option<LiaisonNotee>,
}

/// L'abonnement tel qu'il est à cet instant : tout ce que le retrait touche, et ce que la question a montré (deux
/// lectures égales : rien n'a changé pendant la question).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Lecture {
    /// Le vrai nom du consumer, tel que WMI le garde.
    exact: String,
    chemin: String,
    /// Les propriétés du consumer, si elles se notent.
    consumer: Option<ObjetNote>,
    /// Ce qu'il lance (programme, ligne de commande, fichier de script), lu tel quel.
    programmes: Vec<String>,
    liaisons: Vec<LiaisonLue>,
    /// Une liaison de root\subscription a une référence illisible : on ne sait pas si un filtre sert encore ailleurs,
    /// tous restent.
    reference_illisible: bool,
}

/// L'abonnement `w` tel qu'il est à cet instant ; `Ok(None)` si aucun consumer ne porte ce nom. Le nom de la ligne est
/// celui que le bilan lit (`lu_par_le_bilan`) : un seul consumer doit s'y lire, sinon on ne saurait lequel retirer.
fn lire(a: &Abonnements, w: &AbonnementWmi) -> Result<Option<Lecture>, Illisible> {
    let consumers = instances(a, w.classe.classe(), &champs(w.classe.proprietes()))?;
    let toutes = liaisons(a)?;
    let filtres = instances(a, FILTRE, &champs(&PROPRIETES_FILTRE))?;
    lire_selon(&consumers, &toutes, &filtres, w)
}

/// `lire`, les trois classes lues données (pur, pour les tests).
fn lire_selon(
    consumers: &[Ligne],
    toutes: &[LiaisonBrute],
    filtres: &[Ligne],
    w: &AbonnementWmi,
) -> Result<Option<Lecture>, Illisible> {
    let classe = w.classe.classe();
    let proprietes = w.classe.proprietes();
    let mut trouves = consumers
        .iter()
        .filter(|l| nom_de(l).is_some_and(|n| n == w.nom.texte() || lu_par_le_bilan(n) == w.nom.texte()));
    let forme = |r: &str| Illisible::Forme(r.to_string());
    let Some(lu) = trouves.next() else {
        return Ok(None);
    };
    if trouves.next().is_some() {
        return Err(forme(tr!(
            "deux consumers portent ce nom (ou le même nom, une fois lu sur une ligne) : rien d'écrit",
            "two consumers have this name (or the same name, once read on one line): nothing written"
        )));
    }
    let exact = nom_de(lu).unwrap_or_default().to_string();
    let chemin_de = |l: &Ligne| l.get("__RELPATH").and_then(Valeur::texte).map(str::to_string);
    let sans_chemin = || {
        forme(tr!(
            "un objet de l'abonnement n'a pas de chemin lisible : rien d'écrit",
            "an object of the subscription has no readable path: nothing written"
        ))
    };
    let chemin = chemin_de(lu).ok_or_else(sans_chemin)?;
    let programmes = proprietes
        .iter()
        .filter(|(p, _)| matches!(*p, "ExecutablePath" | "CommandLineTemplate" | "ScriptFileName"))
        .filter_map(|(p, _)| lu.get(*p).and_then(Valeur::texte))
        .filter(|t| !t.trim().is_empty())
        .map(str::to_string)
        .collect();
    let reference_illisible = toutes.iter().any(|b| b.filtre.is_none() || b.consumer.is_none());
    let mut lues = Vec::new();
    for b in toutes.iter().filter(|b| vise(b, classe, &exact)) {
        let chemin = chemin_de(&b.ligne).ok_or_else(sans_chemin)?;
        let filtre = b
            .filtre
            .as_ref()
            .and_then(|f| filtres.iter().find(|x| nom_de(x).is_some_and(|x| meme_cle(x, f))));
        let Some(filtre) = filtre else {
            lues.push(LiaisonLue {
                chemin,
                filtre: None,
                filtre_libre: false,
                notee: None,
            });
            continue;
        };
        let nom_filtre = nom_de(filtre).unwrap_or_default().to_string();
        // Partagé : une autre liaison le vise, dont le consumer n'est pas celui-ci (ou illisible).
        let partage = toutes.iter().any(|autre| {
            autre.filtre.as_ref().is_some_and(|f| meme_cle(f, &nom_filtre)) && !vise(autre, classe, &exact)
        });
        let filtre_libre = !partage && !reference_illisible && !gestes::abonnement_wmi_protege(&nom_filtre);
        let notee = match (objet(filtre, &PROPRIETES_FILTRE), objet(&b.ligne, &PROPRIETES_LIAISON)) {
            (Some(f), Some(l)) => Some(LiaisonNotee {
                filtre_retire: filtre_libre,
                filtre: f,
                liaison: l,
            }),
            _ => None,
        };
        lues.push(LiaisonLue {
            chemin,
            filtre: Some((nom_filtre, chemin_de(filtre).ok_or_else(sans_chemin)?)),
            filtre_libre,
            notee,
        });
    }
    Ok(Some(Lecture {
        exact,
        chemin,
        consumer: objet(lu, proprietes),
        programmes,
        liaisons: lues,
        reference_illisible,
    }))
}

/// La note de cette lecture, et ce qui empêchera Vanguard de remettre l'abonnement tel quel (pur). Au-delà de
/// `NOTE_WMI_LIAISONS_MAX` liaisons, seules les premières sont notées ; pour toute autre raison, aucune note.
fn note_et_manques(l: &Lecture, w: &AbonnementWmi) -> (Option<NoteWmi>, Vec<String>) {
    let mut manques = Vec::new();
    if l.exact != w.nom.texte() {
        manques.push(trf!(
            "son vrai nom est {}, que la note ne garde pas",
            "its real name is {}, which the note does not keep",
            super::protege::echappe_exact(&l.exact, NOM_MONTRE_MAX)
        ));
    }
    if l.reference_illisible {
        manques.push(
            tr!(
                "une liaison de root\\subscription a une référence illisible : les liaisons de ce consumer et le consumer partiraient, tous les filtres resteraient",
                "a binding in root\\subscription has an unreadable reference: this consumer's bindings and the consumer would go, every filter would stay"
            )
            .to_string(),
        );
    }
    if l.liaisons.iter().any(|x| x.filtre.is_none()) {
        manques.push(
            tr!(
                "une liaison de ce consumer vise un filtre introuvable",
                "a binding of this consumer points to a filter that cannot be found"
            )
            .to_string(),
        );
    }
    let notees: Option<Vec<LiaisonNotee>> = l.liaisons.iter().map(|x| x.notee.clone()).collect();
    if l.consumer.is_none() || (notees.is_none() && l.liaisons.iter().all(|x| x.filtre.is_some())) {
        manques.push(
            tr!(
                "une propriété est illisible ou trop longue pour être notée",
                "a property is unreadable or too long to be noted"
            )
            .to_string(),
        );
    }
    let (Some(consumer), Some(mut notees), true) = (l.consumer.clone(), notees, manques.is_empty()) else {
        return (None, manques);
    };
    let n = notees.len();
    if n > gestes::NOTE_WMI_LIAISONS_MAX {
        let max = gestes::NOTE_WMI_LIAISONS_MAX;
        notees.truncate(max);
        manques.push(trf!(
            "{n} liaisons : non annulable au-delà des {max} notées",
            "{n} bindings: not undoable beyond the {max} noted"
        ));
    }
    let note = NoteWmi {
        classe: w.classe,
        consumer,
        liaisons: notees,
    };
    if !note.valide(w) {
        manques.push(
            tr!(
                "un filtre a un nom piégé (vide, trop long, avec un caractère de contrôle, ou en double) que la note ne garde pas",
                "a filter has a trapped name (empty, too long, with a control character, or duplicated) that the note does not keep"
            )
            .to_string(),
        );
        return (None, manques);
    }
    if note.octets().is_none() {
        manques.push(
            tr!(
                "l'abonnement est trop long pour être noté",
                "the subscription is too long to be noted"
            )
            .to_string(),
        );
        return (None, manques);
    }
    (Some(note), manques)
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

/// Dans un fil COM à lui ; si WMI ne répond pas à temps, rien n'est sûr : `None`. Le fil n'est pas arrêté, seulement
/// abandonné : `abandon` levé, il n'écrit plus rien de neuf (vérifié avant la note, la première suppression et la
/// première création), mais un geste déjà commencé peut s'achever après le message.
fn dans_wmi_selon<T: Send + 'static>(geste: impl FnOnce(&AtomicBool) -> T + Send + 'static) -> Option<T> {
    let abandon = Arc::new(AtomicBool::new(false));
    let vu_du_fil = Arc::clone(&abandon);
    let r = super::wmi::com_delai(crate::compte_rendu::Contexte::Wmi, "abonnement WMI", DELAI, move || {
        Ok(geste(&vu_du_fil))
    });
    if r.is_none() {
        abandon.store(true, Ordering::SeqCst);
    }
    r
}

fn dans_wmi(geste: impl FnOnce(&AtomicBool) -> Resultat + Send + 'static) -> Resultat {
    dans_wmi_selon(geste).unwrap_or_else(muet)
}

/// WMI n'a pas répondu à temps.
fn muet() -> Resultat {
    Resultat::echec(
        None,
        tr!(
            "WMI ne répond pas : l'état de l'abonnement est à relire (relancez le bilan) ; un retrait ou une remise déjà commencé peut s'achever après ce message",
            "WMI does not answer: the subscription's state must be read again (run the check again); a removal or restore already started may finish after this message"
        )
        .to_string(),
    )
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

/// Ce qui reste de l'abonnement lu : le consumer, une liaison vers lui, un filtre que Vanguard devait retirer.
fn restes(a: &Abonnements, l: &Lecture, w: &AbonnementWmi) -> Result<Vec<String>, Illisible> {
    let mut restes = Vec::new();
    let classe = w.classe.classe();
    if instances(a, classe, &["Name"])?
        .iter()
        .any(|x| nom_de(x) == Some(l.exact.as_str()))
    {
        restes.push(tr!("le consumer", "the consumer").to_string());
    }
    let liees = liaisons(a)?.iter().filter(|b| vise(b, classe, &l.exact)).count();
    if liees > 0 {
        restes.push(trf!("{liees} liaison(s)", "{liees} binding(s)"));
    }
    let filtres = instances(a, FILTRE, &["Name"])?;
    for (nom, _) in l
        .liaisons
        .iter()
        .filter(|x| x.filtre_libre)
        .filter_map(|x| x.filtre.as_ref())
    {
        if filtres.iter().any(|f| nom_de(f) == Some(nom.as_str())) {
            let f = crate::ui::affichable(nom);
            restes.push(trf!("le filtre « {f} »", "the filter “{f}”"));
        }
    }
    Ok(restes)
}

fn decrire(l: &Lecture) -> String {
    let (n, f) = (l.liaisons.len(), l.liaisons.iter().filter(|x| x.filtre_libre).count());
    trf!(
        "abonnement WMI présent ({n} liaison(s), {f} filtre(s) propre(s) à lui)",
        "WMI subscription present ({n} binding(s), {f} filter(s) of its own)"
    )
}

/// Le plus de caractères montrés d'un nom échappé.
const NOM_MONTRE_MAX: usize = 300;

/// Ce que la console élevée demande avant de retirer. Posée hors du fil COM (son délai court pendant qu'on lit la
/// question), puis le geste est refait de zéro : l'abonnement relu doit être celui que la personne a vu
/// (`Accords::vu`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Question {
    /// Un nom de Windows ou de Defender, ou un programme qui en porte le nom, sans être le vrai.
    NomSeul { nom: String, programme: String },
    /// Le retrait ne pourra pas être défait par Vanguard (tout ou partie) : les raisons.
    SansNote { raisons: Vec<String> },
}

/// Les oui déjà donnés, et l'abonnement vu à la première question.
#[derive(Clone, Debug, Default)]
struct Accords {
    nom_seul: bool,
    /// Les raisons acceptées d'un retrait non annulable.
    sans_note: Vec<String>,
    vu: Option<Lecture>,
}

/// Une étape du geste : fini, ou une question à poser hors du fil COM (avec l'abonnement lu).
enum Etape {
    Fini(Resultat),
    Demander(Question, Box<Lecture>),
}

/// Le jugement avant d'écrire, pur : le vrai programme de Windows ou de Defender refusé ; le bilan refait doit
/// proposer la ligne ; un nom seul demandé ; un retrait non annulable demandé. `Ok` : la note à écrire, s'il y en a une.
fn juger(
    l: &Lecture,
    w: &AbonnementWmi,
    jugements: &[(Protege, &str)],
    signale: bool,
    accords: &Accords,
) -> Result<Option<NoteWmi>, Etape> {
    if jugements.iter().any(|(j, _)| *j == Protege::Vrai) {
        return Err(Etape::Fini(refus(
            tr!(
                "l'abonnement lance le vrai programme de Sécurité Windows ou de Defender (à sa place, signé par Microsoft) : Vanguard n'y touche jamais ; rien d'écrit",
                "the subscription starts the real Windows Security or Defender program (in its place, signed by Microsoft): Vanguard never touches it; nothing written"
            )
            .to_string(),
        )));
    }
    if !signale {
        return Err(Etape::Fini(refus(
            tr!(
                "le bilan refait ici ne signale pas cet abonnement : rien d'écrit",
                "the check run again here does not report this subscription: nothing written"
            )
            .to_string(),
        )));
    }
    let nom_seul = jugements.iter().find(|(j, _)| *j == Protege::NomSeul).map(|(_, p)| *p);
    if !accords.nom_seul && (nom_seul.is_some() || gestes::abonnement_wmi_protege(&l.exact)) {
        return Err(Etape::Demander(
            Question::NomSeul {
                nom: l.exact.clone(),
                programme: nom_seul.unwrap_or_default().to_string(),
            },
            Box::new(l.clone()),
        ));
    }
    let (note, manques) = note_et_manques(l, w);
    if !manques.iter().all(|m| accords.sans_note.contains(m)) {
        return Err(Etape::Demander(
            Question::SansNote { raisons: manques },
            Box::new(l.clone()),
        ));
    }
    Ok(note)
}

/// Ce que la console dit avant de demander, pour un nom de Windows ou de Defender qui n'est pas le vrai.
fn texte_nom_seul(nom: &str, programme: &str) -> String {
    let nom = super::protege::echappe_exact(nom, NOM_MONTRE_MAX);
    if programme.is_empty() {
        trf!(
            "  Le consumer {nom} porte le nom d'un abonnement de Windows ou de Defender mais n'est pas lui : ceux de Windows écrivent au journal (NTEventLogEventConsumer), celui-ci lance une commande ou un script. Un vrai n'est jamais retiré.",
            "  The consumer {nom} bears the name of a Windows or Defender subscription but is not it: Windows' own write to the event log (NTEventLogEventConsumer), this one runs a command or a script. A real one is never removed."
        )
    } else {
        super::protege::texte_nom_seul(&nom, programme)
    }
}

fn texte_sans_note(raisons: &[String]) -> String {
    let r = crate::ui::affichable(&raisons.join(tr!(" ; ", "; ")));
    trf!(
        "  Vanguard ne pourra pas remettre cet abonnement tel qu'il était : {r}.",
        "  Vanguard will not be able to put this subscription back as it was: {r}."
    )
}

/// Dans le processus élevé : retire l'abonnement `w` si et seulement si le bilan, refait ici sur une lecture complète,
/// le signale et propose cette même ligne ; une question posée dans la console élevée (non par défaut) pour un nom
/// seul ou un retrait non annulable.
pub(super) fn retirer(w: &AbonnementWmi) -> Resultat {
    let mut accords = Accords::default();
    // Trois questions au plus (nom seul, sans note, note refusée par le registre) : la quatrième étape finit.
    for _ in 0..4 {
        let (abonnement, a) = (w.clone(), accords.clone());
        let Some(etape) = dans_wmi_selon(move |abandon| retirer_ici(&abonnement, &a, abandon)) else {
            return muet();
        };
        let (question, lue) = match etape {
            Etape::Fini(r) => return r,
            Etape::Demander(q, l) => (q, l),
        };
        let oui = match &question {
            Question::NomSeul { nom, programme } => {
                super::protege::accord(&texte_nom_seul(nom, programme), super::protege::question_quand_meme())
            }
            Question::SansNote { raisons } => {
                super::protege::accord(&texte_sans_note(raisons), super::protege::question_non_annulable())
            }
        };
        if !oui {
            return refus(super::protege::non_confirme());
        }
        match question {
            Question::NomSeul { .. } => accords.nom_seul = true,
            Question::SansNote { raisons } => accords.sans_note = raisons,
        }
        accords.vu.get_or_insert(*lue);
    }
    refus(tr!("geste inachevé : rien d'écrit", "unfinished action: nothing written").to_string())
}

/// Ce qui se supprime, dans l'ordre : les liaisons d'abord (le consumer ne se déclenche plus), puis le consumer, puis
/// les filtres propres à lui ; jamais un filtre partagé, protégé, ou quand une liaison se lit mal.
fn ordre<'a>(l: &'a Lecture, w: &AbonnementWmi) -> Vec<(&'static str, &'a str)> {
    let mut ordre: Vec<(&str, &str)> = l.liaisons.iter().map(|x| (LIAISON, x.chemin.as_str())).collect();
    ordre.push((w.classe.classe(), l.chemin.as_str()));
    ordre.extend(
        l.liaisons
            .iter()
            .filter(|x| x.filtre_libre)
            .filter_map(|x| x.filtre.as_ref())
            .map(|(_, chemin)| (FILTRE, chemin.as_str())),
    );
    ordre
}

fn retirer_ici(w: &AbonnementWmi, accords: &Accords, abandon: &AtomicBool) -> Etape {
    let fini = Etape::Fini;
    let ligne = Acte::WmiAbonnementRetirer(w.clone()).ligne();
    let a = match Abonnements::ouvrir() {
        Ok(a) => a,
        Err(e) => return fini(Illisible::from(e).resultat()),
    };
    let lue = match lire(&a, w) {
        Ok(Some(l)) => l,
        Ok(None) => {
            return fini(Resultat::rien(
                tr!(
                    "l'abonnement n'existe plus : rien à retirer",
                    "the subscription no longer exists: nothing to remove"
                )
                .to_string(),
            ));
        }
        Err(i) => return fini(i.resultat()),
    };
    if accords.vu.as_ref().is_some_and(|v| *v != lue) {
        return fini(refus(
            tr!(
                "l'abonnement a changé pendant la question ; rien d'écrit",
                "the subscription changed during the question; nothing written"
            )
            .to_string(),
        ));
    }
    let programmes: Vec<String> = lue
        .programmes
        .iter()
        .map(|p| match w.classe {
            gestes::ClasseConsumer::Commande => crate::commande::decouper_commande(p).0,
            gestes::ClasseConsumer::Script => p.clone(),
        })
        .collect();
    let mut jugements: Vec<(Protege, &str)> = programmes
        .iter()
        .map(|p| (super::protege::protege(&lue.exact, p), p.as_str()))
        .collect();
    jugements.push((super::protege::protege(&lue.exact, ""), ""));
    let signale = super::portes::abonnement_signale(&ligne);
    let note = match juger(&lue, w, &jugements, signale, accords) {
        Ok(n) => n,
        Err(etape) => return etape,
    };
    // Notée d'abord : sans note, pas de changement, sauf accord « non annulable ».
    let nom_note = nom_note(w);
    if abandon.load(Ordering::SeqCst) {
        return fini(abandonne());
    }
    let notee = if let Some(octets) = note.and_then(|n| n.octets()) {
        match ecrire_note(&nom_note, octets) {
            Ok(()) => true,
            Err(e) => {
                let mut raisons = note_et_manques(&lue, w).1;
                raisons.push(trf!(
                    "les propriétés de l'abonnement ne se notent pas ({e})",
                    "the subscription's properties cannot be noted ({e})"
                ));
                if accords.sans_note != raisons {
                    return Etape::Demander(Question::SansNote { raisons }, Box::new(lue));
                }
                false
            }
        }
    } else {
        false
    };
    // Relu juste avant : jamais un abonnement changé depuis le jugement.
    if !matches!(lire(&a, w), Ok(Some(encore)) if encore == lue) {
        if notee {
            effacer_note(&nom_note);
        }
        return fini(refus(
            tr!(
                "l'abonnement a changé entre la lecture et l'écriture ; rien d'écrit",
                "the subscription changed between reading and writing; nothing written"
            )
            .to_string(),
        ));
    }
    let mut avant = decrire(&lue);
    if !notee {
        avant.push_str(tr!(" ; sans note, non annulable", " ; no note, not undoable"));
    }
    let ordre = ordre(&lue, w);
    if abandon.load(Ordering::SeqCst) {
        if notee {
            effacer_note(&nom_note);
        }
        return fini(abandonne());
    }
    // Sans note, une note plus ancienne sous ce nom remettrait un autre abonnement : effacée ici seulement, relu
    // identique et le retrait qui suit (jamais un « rien d'écrit » qui aurait effacé une note).
    if !notee {
        effacer_note(&nom_note);
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
    let garde = if notee {
        tr!("la note est gardée", "the note is kept")
    } else {
        tr!("sans note", "no note")
    };
    fini(match restes(&a, &lue, w) {
        Ok(r) if r.is_empty() => Resultat::fait(avant),
        Ok(r) => {
            let r = r.join(", ");
            let pourquoi = refuse.map_or_else(String::new, |c| format!(" ({c:#010x})"));
            Resultat::echec(
                Some(avant),
                trf!(
                    "retrait incomplet{pourquoi} : il reste {r} ; {garde}",
                    "incomplete removal{pourquoi}: {r} remain(s); {garde}"
                ),
            )
        }
        Err(_) => Resultat::echec(
            Some(avant),
            trf!(
                "l'abonnement n'a pas pu être relu après le retrait : état inconnu, à relire (relancez le bilan) ; {garde}",
                "the subscription could not be read again after removal: state unknown, check again (run the check again); {garde}"
            ),
        ),
    })
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
        for b in &liees {
            if vise(b, classe, w.nom.texte())
                && let Some(chemin) = b.ligne.get("__RELPATH").and_then(Valeur::texte)
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
    // Passe 3.5d : un nom seul demandera, comme au retrait ; d'ici là, tout ce qui porte le nom de Defender est refusé.
    let nom = note.consumer.nom().unwrap_or_default();
    if gestes::abonnement_wmi_protege(nom)
        || programmes(&note)
            .iter()
            .any(|p| super::protege::protege(nom, p) != Protege::Non)
    {
        return refus(
            tr!(
                "abonnement qui porte le nom de Windows ou de Defender : rien d'écrit",
                "subscription bearing the name of Windows or Defender: nothing written"
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
    match lire(&a, w) {
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
    let Some(relu) = lire(&a, w).ok().flatten().and_then(|l| note_et_manques(&l, w).0) else {
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

    fn ligne(champs: &[(&str, &str)]) -> Ligne {
        champs
            .iter()
            .map(|(n, v)| ((*n).to_string(), Valeur::Texte((*v).to_string())))
            .collect()
    }

    fn consumer(nom: &str) -> Ligne {
        ligne(&[
            ("Name", nom),
            ("CommandLineTemplate", r"C:\Users\alice\AppData\Roaming\maj.exe -q"),
            (
                "__RELPATH",
                &format!("CommandLineEventConsumer.Name=\"{}\"", nom_designe_essai(nom)),
            ),
        ])
    }

    fn nom_designe_essai(nom: &str) -> String {
        nom.replace(['\r', '\n'], "")
    }

    fn filtre(nom: &str) -> Ligne {
        ligne(&[
            ("Name", nom),
            ("Query", "SELECT * FROM __InstanceModificationEvent WITHIN 60"),
            ("QueryLanguage", "WQL"),
            ("EventNamespace", r"root\cimv2"),
            ("__RELPATH", &format!("__EventFilter.Name=\"{nom}\"")),
        ])
    }

    fn liaison(i: usize, filtre: Option<&str>, consumer: Option<&str>) -> LiaisonBrute {
        LiaisonBrute {
            filtre: filtre.map(str::to_string),
            consumer: consumer.map(|n| ("CommandLineEventConsumer".to_string(), n.to_string())),
            ligne: ligne(&[("__RELPATH", &format!("__FilterToConsumerBinding.n{i}"))]),
        }
    }

    fn abonnement(nom: &str) -> AbonnementWmi {
        AbonnementWmi {
            classe: gestes::ClasseConsumer::Commande,
            nom: gestes::NomConsumer::nouveau(nom).unwrap(),
        }
    }

    fn lu(consumers: &[Ligne], toutes: &[LiaisonBrute], filtres: &[Ligne], w: &AbonnementWmi) -> Lecture {
        match lire_selon(consumers, toutes, filtres, w) {
            Ok(Some(l)) => l,
            _ => panic!("lecture"),
        }
    }

    fn question(e: Result<Option<NoteWmi>, Etape>) -> Question {
        match e {
            Err(Etape::Demander(q, _)) => q,
            Err(Etape::Fini(r)) => panic!("fini : {}", r.raison),
            Ok(_) => panic!("aucune question"),
        }
    }

    fn refuse(e: Result<Option<NoteWmi>, Etape>) -> String {
        match e {
            Err(Etape::Fini(r)) if !r.reussi && r.avant.is_none() => r.raison,
            _ => panic!("pas un refus"),
        }
    }

    /// Le vrai programme de Defender (à sa place, signé) est refusé sans question, même après un oui au nom seul ; un
    /// nom de Windows ou de Defender qui n'est pas lui se demande (le jugement du lieu et de la signature est dans
    /// `protege`) ; un abonnement que le bilan refait ne signale pas est refusé.
    #[test]
    fn wmi_seul_le_vrai_est_refuse() {
        let w = abonnement("Windows Defender Update");
        let l = lu(
            &[consumer("Windows Defender Update")],
            &[liaison(0, Some("F"), Some("Windows Defender Update"))],
            &[filtre("F")],
            &w,
        );
        let faux = [(Protege::NomSeul, r"C:\Users\alice\AppData\Roaming\maj.exe")];
        let q = question(juger(&l, &w, &faux, true, &Accords::default()));
        assert!(
            matches!(&q, Question::NomSeul { nom, .. } if nom == "Windows Defender Update"),
            "{q:?}"
        );
        let oui = Accords {
            nom_seul: true,
            ..Accords::default()
        };
        assert!(matches!(juger(&l, &w, &faux, true, &oui), Ok(Some(_))));
        let vrai = [(Protege::Vrai, r"C:\Program Files\Windows Defender\MpCmdRun.exe")];
        assert!(refuse(juger(&l, &w, &vrai, true, &oui)).contains("Microsoft"));
        assert!(refuse(juger(&l, &w, &[(Protege::Non, "")], false, &oui)).contains("bilan"));
        // Un nom de Windows sur un consumer de commande : jamais le vrai (ceux de Windows écrivent au journal).
        let w = abonnement("SCM Event Log Consumer");
        let l = lu(&[consumer("SCM Event Log Consumer")], &[], &[], &w);
        let q = question(juger(&l, &w, &[(Protege::Non, "")], true, &Accords::default()));
        assert!(
            matches!(&q, Question::NomSeul { programme, .. } if programme.is_empty()),
            "{q:?}"
        );
        assert!(texte_nom_seul("SCM Event Log Consumer", "").contains("NTEventLogEventConsumer"));
    }

    /// Une liaison de root\subscription à la référence illisible : les liaisons de ce consumer et le consumer partent,
    /// tous les filtres restent ; non annulable, demandé ; accepté, aucune note.
    #[test]
    fn wmi_reference_illisible_garde_les_filtres() {
        let w = abonnement("Updater");
        let toutes = [
            liaison(0, Some("F1"), Some("Updater")),
            liaison(1, Some("F2"), None),
            liaison(2, None, Some("Autre")),
        ];
        let l = lu(&[consumer("Updater")], &toutes, &[filtre("F1"), filtre("F2")], &w);
        assert!(l.reference_illisible);
        let o = ordre(&l, &w);
        assert!(o.iter().all(|(c, _)| *c != FILTRE), "{o:?}");
        assert_eq!(
            o,
            [
                (LIAISON, "__FilterToConsumerBinding.n0"),
                ("CommandLineEventConsumer", "CommandLineEventConsumer.Name=\"Updater\"")
            ]
        );
        let Question::SansNote { raisons } = question(juger(&l, &w, &[(Protege::Non, "")], true, &Accords::default()))
        else {
            panic!("sans note");
        };
        assert!(raisons.iter().any(|r| r.contains("illisible")), "{raisons:?}");
        let oui = Accords {
            sans_note: raisons,
            ..Accords::default()
        };
        assert!(matches!(juger(&l, &w, &[(Protege::Non, "")], true, &oui), Ok(None)));
        // Sans référence illisible, le filtre propre part ; un filtre partagé avec un autre consumer reste.
        let toutes = [
            liaison(0, Some("F1"), Some("Updater")),
            liaison(1, Some("F2"), Some("Updater")),
            liaison(2, Some("F2"), Some("Autre")),
        ];
        let l = lu(&[consumer("Updater")], &toutes, &[filtre("F1"), filtre("F2")], &w);
        let filtres: Vec<&str> = ordre(&l, &w)
            .into_iter()
            .filter(|(c, _)| *c == FILTRE)
            .map(|(_, p)| p)
            .collect();
        assert_eq!(filtres, ["__EventFilter.Name=\"F1\""]);
        assert!(
            matches!(juger(&l, &w, &[(Protege::Non, "")], true, &Accords::default()), Ok(Some(n)) if n.liaisons.len() == 2)
        );
    }

    /// Un filtre introuvable : demandé, sans note. Plus de 16 liaisons : « non annulable au-delà des 16 notées »,
    /// demandé, les 16 premières notées, toutes retirées.
    #[test]
    fn wmi_filtre_introuvable_et_liaisons_au_dela_de_la_note() {
        let w = abonnement("Updater");
        let l = lu(
            &[consumer("Updater")],
            &[liaison(0, Some("Parti"), Some("Updater"))],
            &[],
            &w,
        );
        let (note, manques) = note_et_manques(&l, &w);
        assert!(
            note.is_none() && manques.iter().any(|m| m.contains("introuvable")),
            "{manques:?}"
        );
        assert!(matches!(
            question(juger(&l, &w, &[(Protege::Non, "")], true, &Accords::default())),
            Question::SansNote { .. }
        ));
        let n = gestes::NOTE_WMI_LIAISONS_MAX + 1;
        let noms: Vec<String> = (0..n).map(|i| format!("F{i}")).collect();
        let toutes: Vec<LiaisonBrute> = noms
            .iter()
            .enumerate()
            .map(|(i, f)| liaison(i, Some(f), Some("Updater")))
            .collect();
        let filtres: Vec<Ligne> = noms.iter().map(|f| filtre(f)).collect();
        let l = lu(&[consumer("Updater")], &toutes, &filtres, &w);
        let (note, manques) = note_et_manques(&l, &w);
        assert_eq!(note.map(|n| n.liaisons.len()), Some(gestes::NOTE_WMI_LIAISONS_MAX));
        assert!(
            manques.len() == 1 && (manques[0].contains("au-delà des 16") || manques[0].contains("beyond the 16")),
            "{manques:?}"
        );
        assert_eq!(ordre(&l, &w).iter().filter(|(c, _)| *c == LIAISON).count(), n);
        let oui = Accords {
            sans_note: manques,
            ..Accords::default()
        };
        assert!(matches!(juger(&l, &w, &[(Protege::Non, "")], true, &oui), Ok(Some(_))));
    }

    /// Un vrai nom piégé (espaces de bordure, saut de ligne, guillemet) : la ligne porte le nom tel que le bilan le
    /// lit ; le processus élevé retrouve le seul consumer qui s'y lit, montre son vrai nom échappé et demande, sans
    /// note. Deux consumers qui se lisent de même : refusé.
    #[test]
    fn wmi_vrai_nom_piege_montre_echappe() {
        for (vrai, designe) in [(" Upda\r\nter ", "Upda ter"), ("a\"b", "a_b"), ("x\\y'z", "x_y_z")] {
            let w = abonnement(designe);
            let l = lu(&[consumer(vrai)], &[], &[], &w);
            assert_eq!(l.exact, vrai);
            let (note, manques) = note_et_manques(&l, &w);
            assert!(note.is_none());
            let montre = &manques[0];
            assert!(
                montre.contains(&super::super::protege::echappe_exact(vrai, NOM_MONTRE_MAX)),
                "{montre}"
            );
            assert!(!montre.chars().any(char::is_control), "{montre:?}");
            let Question::SansNote { raisons } =
                question(juger(&l, &w, &[(Protege::Non, "")], true, &Accords::default()))
            else {
                panic!("sans note");
            };
            assert!(!texte_sans_note(&raisons).chars().any(char::is_control));
        }
        let w = abonnement("a_b");
        assert!(lire_selon(&[consumer("a_b"), consumer("a\"b")], &[], &[], &w).is_err());
        assert!(matches!(lire_selon(&[consumer("autre")], &[], &[], &w), Ok(None)));
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
