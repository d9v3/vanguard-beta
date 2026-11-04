//! Désactiver une tâche planifiée signalée par le bilan, par le processus élevé, sans PowerShell (lot 3.5, passe b,
//! R47) : le planificateur de Windows (ITaskService, COM), IRegisteredTask::put_Enabled. La ligne désigne, le
//! processus élevé juge : la tâche est relue ici, jamais sous \Microsoft\ (les tâches de Windows et de Defender), son
//! chemin doit être exactement celui de la ligne, aucun de ses programmes n'est le vrai programme de Windows ou de
//! Defender (`protege::protege` ; un nom seul se demande), et le bilan refait sur ses lignes
//! (`planificateur::lignes_tache`, `persistance::tache_signalee`) doit proposer cette même ligne. Son XML est noté
//! dans `gestes::TACHE_AVANT_CLE` avant le changement, relu juste avant, puis celui d'après : la réactivation n'a lieu
//! que si la tâche est restée telle que Vanguard l'a laissée. Une définition qui ne se note pas : désactivée (jamais
//! supprimée) seulement après une question « non annulable par Vanguard ». Les questions se posent hors du fil du
//! planificateur, puis tout est relu.

use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{IRegisteredTask, ITaskService, TASK_STATE_DISABLED, TaskScheduler};
use windows::Win32::System::Variant::VARIANT;
use windows::core::BSTR;
use winreg::RegKey;
use winreg::enums::RegType::REG_BINARY;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};

use super::corrections::Resultat;
use super::protege::Protege;
use crate::machine::gestes::{self, Acte, CheminTache};
use crate::ui::{tr, trf};

/// Le XML d'une tâche tient en quelques kilo-octets ; au-delà, refusé plutôt que noté dans le registre.
const XML_MAX: usize = 256 * 1024;

fn refus(raison: String) -> Resultat {
    Resultat::echec(None, raison)
}

/// La note : le nombre d'unités UTF-16 du XML d'avant (4 octets, petit-boutiste), le XML d'avant, puis celui d'après
/// (vide tant que le changement n'est pas fait), en UTF-16 petit-boutiste.
fn note(avant: &str, apres: &str) -> Option<Vec<u8>> {
    let a: Vec<u16> = avant.encode_utf16().collect();
    let mut n = u32::try_from(a.len()).ok()?.to_le_bytes().to_vec();
    n.extend(
        a.iter()
            .chain(apres.encode_utf16().collect::<Vec<_>>().iter())
            .flat_map(|u| u.to_le_bytes()),
    );
    Some(n)
}

fn lire_note(n: &[u8]) -> Option<(String, String)> {
    let (longueur, reste) = n.split_first_chunk::<4>()?;
    let (unites, reste) = reste.as_chunks::<2>();
    if !reste.is_empty() {
        return None;
    }
    let mots: Vec<u16> = unites.iter().map(|p| u16::from_le_bytes(*p)).collect();
    let (avant, apres) = mots.split_at_checked(usize::try_from(u32::from_le_bytes(*longueur)).ok()?)?;
    Some((String::from_utf16(avant).ok()?, String::from_utf16(apres).ok()?))
}

/// Le nom de la note : le chemin en hexadécimal (la ligne sans son verbe), le même pour les deux sens.
fn nom_note(t: &CheminTache) -> String {
    Acte::TacheReactiver(t.clone())
        .ligne()
        .strip_prefix(gestes::TACHE_REACTIVER)
        .unwrap_or_default()
        .to_string()
}

/// Le dossier (« \ » ou « \A\B ») et le nom d'un chemin de tâche.
fn dossier_et_nom(chemin: &str) -> Option<(String, String)> {
    let (dossier, nom) = chemin.rsplit_once('\\')?;
    let dossier = if dossier.is_empty() { "\\" } else { dossier };
    Some((dossier.to_string(), nom.to_string()))
}

/// Le préfixe des lignes du bilan : le dossier terminé par « \ », comme `planificateur::taches`.
fn prefixe(dossier: &str) -> String {
    if dossier.ends_with('\\') {
        dossier.to_string()
    } else {
        format!("{dossier}\\")
    }
}

/// Ce que le processus élevé lit d'une tâche, dans l'appartement COM.
struct Lue {
    chemin: String,
    active: bool,
    xml: String,
    lignes: Vec<String>,
}

/// Ouvre le planificateur et la tâche ; `Ok(None)` si elle (ou son dossier) n'existe pas.
// FFI de COM (crate windows) : ITaskService.
#[allow(unsafe_code)]
fn ouvrir(dossier: &str, nom: &str) -> windows::core::Result<Option<IRegisteredTask>> {
    // Fichier ou dossier introuvable (HRESULT_FROM_WIN32 de ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND).
    const ABSENTE: [u32; 2] = [0x8007_0002, 0x8007_0003];
    // SAFETY: COM est initialisé dans ce fil (par `wmi::com`) ; TaskScheduler est la classe du planificateur.
    let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }?;
    let vide = VARIANT::default();
    // SAFETY: VARIANT vides = cet ordinateur, le compte qui lance.
    unsafe { service.Connect(&vide, &vide, &vide, &vide) }?;
    // SAFETY: service connecté ; chemins BSTR valides pendant les appels.
    let tache = unsafe {
        service
            .GetFolder(&BSTR::from(dossier))
            .and_then(|d| d.GetTask(&BSTR::from(nom)))
    };
    match tache {
        Ok(t) => Ok(Some(t)),
        #[allow(clippy::cast_sign_loss)]
        Err(e) if ABSENTE.contains(&(e.code().0 as u32)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Relit la tâche : son chemin, si elle est active, son XML et ses lignes du bilan.
// FFI de COM (crate windows) : IRegisteredTask.
#[allow(unsafe_code)]
fn lire(t: &IRegisteredTask, dossier: &str) -> windows::core::Result<Lue> {
    // SAFETY: tâche vivante rendue par le planificateur, le temps de cet appel.
    unsafe {
        Ok(Lue {
            chemin: t.Path()?.to_string(),
            active: t.Enabled()? == VARIANT_TRUE && t.State()? != TASK_STATE_DISABLED,
            xml: t.Xml()?.to_string(),
            lignes: super::planificateur::lignes_tache(t, &prefixe(dossier))?,
        })
    }
}

/// Active ou désactive la tâche.
// FFI de COM (crate windows) : IRegisteredTask::put_Enabled.
#[allow(unsafe_code)]
fn activer(t: &IRegisteredTask, oui: bool) -> windows::core::Result<()> {
    // SAFETY: tâche vivante rendue par le planificateur ; VARIANT_BOOL passé par valeur.
    unsafe { t.SetEnabled(if oui { VARIANT_TRUE } else { VARIANT_FALSE }) }
}

/// La tâche ouverte puis relue ; `Ok(None)` si elle n'existe pas.
fn relire(dossier: &str, nom: &str) -> windows::core::Result<Option<(IRegisteredTask, Lue)>> {
    match ouvrir(dossier, nom)? {
        Some(t) => {
            let l = lire(&t, dossier)?;
            Ok(Some((t, l)))
        }
        None => Ok(None),
    }
}

fn erreur_com(e: &windows::core::Error) -> Resultat {
    let code = e.code().0;
    refus(trf!(
        "le planificateur refuse ({code:#010x}) : rien d'écrit",
        "the Task Scheduler refuses ({code:#010x}): nothing written"
    ))
}

fn notes(ecrire: bool) -> std::io::Result<RegKey> {
    let racine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let drapeaux = KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY;
    if ecrire {
        racine
            .create_subkey_with_flags(gestes::TACHE_AVANT_CLE, drapeaux)
            .map(|(k, _)| k)
    } else {
        racine.open_subkey_with_flags(gestes::TACHE_AVANT_CLE, drapeaux)
    }
}

fn ecrire_note(nom: &str, avant: &str, apres: &str) -> std::io::Result<()> {
    let n = note(avant, apres).ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    notes(true).and_then(|k| {
        k.set_raw_value(
            nom,
            &winreg::RegValue {
                bytes: n.into(),
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

/// Le planificateur, dans un appartement COM à lui ; s'il ne répond pas à temps, rien n'est sûr : dit tel quel.
fn dans_le_planificateur(geste: impl FnOnce() -> Resultat + Send + 'static) -> Resultat {
    dans_le_planificateur_selon(geste).unwrap_or_else(muet)
}

fn dans_le_planificateur_selon<T: Send + 'static>(geste: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    super::wmi::com(
        crate::compte_rendu::Contexte::TachesPlanifiees,
        "ITaskService",
        move || Ok(geste()),
    )
}

fn muet() -> Resultat {
    Resultat::echec(
        None,
        tr!(
            "le planificateur de tâches ne répond pas : l'état de la tâche est à relire (relancez le bilan)",
            "the Task Scheduler does not answer: the task's state must be read again (run the check again)"
        )
        .to_string(),
    )
}

/// Ce que la console demande avant de désactiver. Posée hors du fil du planificateur (son délai court pendant qu'on
/// lit la question), puis le geste est refait de zéro, la tâche relue : la définition doit être celle que la
/// personne a vue (`Accords::xml`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Question {
    /// Un programme qui porte le nom de Defender sans être lui.
    NomSeul { nom: String, programme: String },
    /// La définition ne se note pas (trop longue, registre refusé) : désactivée sans note, non réactivable par Vanguard.
    SansNote { raison: String },
}

/// Les oui déjà donnés, et la définition vue à la première question.
#[derive(Clone, Debug, Default)]
struct Accords {
    nom_seul: bool,
    sans_note: bool,
    xml: Option<String>,
}

/// Une étape du geste : fini, ou une question à poser hors du planificateur (avec la définition lue).
enum Etape {
    Fini(Resultat),
    Demander(Question, String),
}

/// Avant la désactivation : noter la définition, ou demander de s'en passer (pur, pour les tests). Une définition
/// au-delà de `XML_MAX` ne se note pas ; un refus du registre non plus (`noter` le tente).
#[derive(Debug, PartialEq, Eq)]
enum Noter {
    /// Notée : la réactivation exacte reste possible.
    Fait,
    /// Sans note, accordé « non annulable ».
    Passer,
    Demander(String),
}

fn noter_ou_demander(taille: usize, sans_note_accorde: bool, noter: impl FnOnce() -> std::io::Result<()>) -> Noter {
    if sans_note_accorde {
        return Noter::Passer;
    }
    if taille > XML_MAX {
        return Noter::Demander(trf!(
            "définition de {taille} octets, au-delà des {XML_MAX} que la note garde",
            "definition of {taille} bytes, beyond the {XML_MAX} the note keeps"
        ));
    }
    match noter() {
        Ok(()) => Noter::Fait,
        Err(e) => Noter::Demander(e.to_string()),
    }
}

/// Ce que la console dit avant de demander une désactivation sans note.
fn texte_sans_note(raison: &str) -> String {
    trf!(
        "  La définition de la tâche ne se note pas ({raison}). La tâche serait désactivée (jamais supprimée), mais Vanguard ne pourra pas la réactiver : à faire dans le Planificateur de tâches si besoin.",
        "  The task's definition cannot be noted ({raison}). The task would be disabled (never deleted), but Vanguard will not be able to re-enable it: to do in Task Scheduler if needed."
    )
}

/// Dans le processus élevé : désactive la tâche `t` si et seulement si le bilan, refait ici sur la tâche relue, la
/// signale et propose cette même ligne.
pub(super) fn desactiver(t: &CheminTache) -> Resultat {
    let mut accords = Accords::default();
    // Deux questions au plus (nom seul, sans note) : la troisième étape finit toujours.
    for _ in 0..3 {
        let (tache, a) = (t.clone(), accords.clone());
        let Some(etape) = dans_le_planificateur_selon(move || desactiver_ici(&tache, &a)) else {
            return muet();
        };
        let (question, xml) = match etape {
            Etape::Fini(r) => return r,
            Etape::Demander(q, xml) => (q, xml),
        };
        let oui = match &question {
            Question::NomSeul { nom, programme } => super::protege::accord(
                &super::protege::texte_nom_seul(nom, programme),
                super::protege::question_quand_meme(),
            ),
            Question::SansNote { raison } => super::protege::accord(
                &texte_sans_note(&crate::ui::affichable(raison)),
                super::protege::question_non_annulable(),
            ),
        };
        if !oui {
            return refus(super::protege::non_confirme());
        }
        match question {
            Question::NomSeul { .. } => accords.nom_seul = true,
            Question::SansNote { .. } => accords.sans_note = true,
        }
        accords.xml.get_or_insert(xml);
    }
    refus(tr!("geste inachevé : rien d'écrit", "unfinished action: nothing written").to_string())
}

fn desactiver_ici(t: &CheminTache, accords: &Accords) -> Etape {
    let fini = Etape::Fini;
    let ligne = Acte::TacheDesactiver(t.clone()).ligne();
    let Some((dossier, nom)) = dossier_et_nom(t.texte()) else {
        return fini(refus(
            tr!("ligne mal formée : rien d'écrit", "malformed line: nothing written").to_string(),
        ));
    };
    if !super::planificateur::hors_windows(&dossier) {
        return fini(refus(
            tr!(
                "tâche de Windows (sous \\Microsoft\\) : Vanguard n'y touche jamais ; rien d'écrit",
                "Windows task (under \\Microsoft\\): Vanguard never touches it; nothing written"
            )
            .to_string(),
        ));
    }
    let (_, lue) = match relire(&dossier, &nom) {
        Ok(Some(x)) => x,
        Ok(None) => {
            return fini(Resultat::rien(
                tr!(
                    "la tâche n'existe plus : rien à désactiver",
                    "the task no longer exists: nothing to disable"
                )
                .to_string(),
            ));
        }
        Err(e) => return fini(erreur_com(&e)),
    };
    if lue.chemin != t.texte() {
        return fini(refus(
            tr!(
                "la tâche trouvée n'a pas exactement le chemin de la ligne : rien d'écrit",
                "the task found does not have exactly the path in the line: nothing written"
            )
            .to_string(),
        ));
    }
    if !lue.active {
        return fini(Resultat::rien(
            tr!(
                "la tâche est déjà désactivée : rien à faire",
                "the task is already disabled: nothing to do"
            )
            .to_string(),
        ));
    }
    // La définition vue à la première question : jamais une tâche changée depuis.
    if accords.xml.as_ref().is_some_and(|x| *x != lue.xml) {
        return fini(refus(
            tr!(
                "la tâche a changé pendant la question ; rien d'écrit",
                "the task changed during the question; nothing written"
            )
            .to_string(),
        ));
    }
    let programmes: Vec<String> = lue
        .lignes
        .iter()
        .map(|l| l.split('|').nth(2).unwrap_or_default().to_string())
        .collect();
    let jugements: Vec<(Protege, &String)> = programmes
        .iter()
        .map(|p| (super::protege::protege(&nom, p), p))
        .collect();
    if jugements.iter().any(|(j, _)| *j == Protege::Vrai) {
        return fini(refus(
            tr!(
                "la tâche lance le vrai programme de Sécurité Windows ou de Defender (signé par Microsoft) : Vanguard n'y touche jamais ; rien d'écrit",
                "the task starts the real Windows Security or Defender program (signed by Microsoft): Vanguard never touches it; nothing written"
            )
            .to_string(),
        ));
    }
    if !super::persistance::tache_signalee(&lue.lignes, &ligne) {
        return fini(refus(
            tr!(
                "le bilan refait ici ne signale pas cette tâche : rien d'écrit",
                "the check run again here does not report this task: nothing written"
            )
            .to_string(),
        ));
    }
    if !accords.nom_seul
        && let Some((_, programme)) = jugements.iter().find(|(j, _)| *j == Protege::NomSeul)
    {
        return Etape::Demander(
            Question::NomSeul {
                nom: nom.clone(),
                programme: (*programme).clone(),
            },
            lue.xml,
        );
    }
    // Notée d'abord : sans note, pas de changement, sauf accord « non annulable » (la réactivation exacte serait
    // perdue).
    let nom_note = nom_note(t);
    let notee = match noter_ou_demander(lue.xml.len(), accords.sans_note, || {
        ecrire_note(&nom_note, &lue.xml, "")
    }) {
        Noter::Fait => true,
        Noter::Passer => {
            // Une note plus ancienne sous ce nom réactiverait sur une autre définition : effacée.
            effacer_note(&nom_note);
            false
        }
        Noter::Demander(raison) => return Etape::Demander(Question::SansNote { raison }, lue.xml),
    };
    let effacer = || {
        if notee {
            effacer_note(&nom_note);
        }
    };
    // Relue juste avant par une nouvelle demande au planificateur (pas l'objet déjà lu, qui pourrait garder un état
    // en cache) : jamais une tâche changée depuis le jugement ; c'est cet objet relu qui est désactivé.
    let tache = match relire(&dossier, &nom) {
        Ok(Some((encore, l))) if l.xml == lue.xml && l.active && l.chemin == lue.chemin => encore,
        _ => {
            effacer();
            return fini(refus(
                tr!(
                    "la tâche a changé entre la lecture et l'écriture ; rien d'écrit",
                    "the task changed between reading and writing; nothing written"
                )
                .to_string(),
            ));
        }
    };
    let avant = if notee {
        tr!("active", "enabled").to_string()
    } else {
        tr!(
            "active ; sans note, non annulable par Vanguard, accepté",
            "enabled; no note, not undoable by Vanguard, accepted"
        )
        .to_string()
    };
    if let Err(e) = activer(&tache, false) {
        effacer();
        return fini(erreur_com(&e));
    }
    let apres = match relire(&dossier, &nom) {
        Ok(Some((_, l))) if !l.active && l.chemin == lue.chemin => l,
        Ok(Some((_, l))) if l.active && l.chemin == lue.chemin => {
            effacer();
            return fini(refus(
                tr!(
                    "la tâche relue est toujours active : rien n'a changé",
                    "the task read again is still enabled: nothing changed"
                )
                .to_string(),
            ));
        }
        _ => {
            return fini(Resultat::echec(
                Some(avant),
                tr!(
                    "la tâche n'a pas pu être relue après le changement : état inconnu, à relire dans le Planificateur de tâches ; la note est gardée",
                    "the task could not be read again after the change: state unknown, check it in Task Scheduler; the note is kept"
                )
                .to_string(),
            ));
        }
    };
    if notee && let Err(e) = ecrire_note(&nom_note, &lue.xml, &apres.xml) {
        return fini(Resultat::echec(
            Some(avant),
            trf!(
                "tâche désactivée, mais sa définition d'après ne se note pas ({e}) : la réactiver par Vanguard sera refusé (à faire dans le Planificateur de tâches)",
                "task disabled, but its new definition cannot be noted ({e}): re-enabling it through Vanguard will be refused (do it in Task Scheduler)"
            ),
        ));
    }
    fini(Resultat::fait(avant))
}

/// Dans le processus élevé : réactive la tâche `t` que `desactiver` a désactivée, seulement si sa définition est
/// encore exactement celle que Vanguard a laissée ; la note est effacée après relecture.
pub(super) fn reactiver(t: &CheminTache) -> Resultat {
    let t = t.clone();
    dans_le_planificateur(move || reactiver_ici(&t))
}

fn reactiver_ici(t: &CheminTache) -> Resultat {
    let Some((dossier, nom)) = dossier_et_nom(t.texte()) else {
        return refus(tr!("ligne mal formée : rien d'écrit", "malformed line: nothing written").to_string());
    };
    let nom_note = nom_note(t);
    let notee = notes(false)
        .ok()
        .and_then(|k| k.get_raw_value(&nom_note).ok())
        .filter(|n| n.vtype == REG_BINARY)
        .and_then(|n| lire_note(&n.bytes))
        .filter(|(_, apres)| !apres.is_empty());
    let Some((_, apres)) = notee else {
        return refus(
            tr!(
                "aucune définition notée par Vanguard pour cette tâche : rien d'écrit",
                "no definition noted by Vanguard for this task: nothing written"
            )
            .to_string(),
        );
    };
    if !super::planificateur::hors_windows(&dossier) {
        return refus(
            tr!(
                "tâche de Windows (sous \\Microsoft\\) : Vanguard n'y touche jamais ; rien d'écrit",
                "Windows task (under \\Microsoft\\): Vanguard never touches it; nothing written"
            )
            .to_string(),
        );
    }
    let (tache, lue) = match relire(&dossier, &nom) {
        Ok(Some(x)) => x,
        Ok(None) => {
            return refus(
                tr!(
                    "la tâche n'existe plus : rien à réactiver (Vanguard ne la recrée pas)",
                    "the task no longer exists: nothing to re-enable (Vanguard does not recreate it)"
                )
                .to_string(),
            );
        }
        Err(e) => return erreur_com(&e),
    };
    if lue.chemin != t.texte() {
        return refus(
            tr!(
                "la tâche trouvée n'a pas exactement le chemin de la ligne : rien d'écrit",
                "the task found does not have exactly the path in the line: nothing written"
            )
            .to_string(),
        );
    }
    if lue.active {
        effacer_note(&nom_note);
        return Resultat::rien(
            tr!(
                "la tâche est déjà active : rien à faire",
                "the task is already enabled: nothing to do"
            )
            .to_string(),
        );
    }
    if lue.xml != apres {
        return refus(
            tr!(
                "la tâche a changé depuis que Vanguard l'a désactivée : rien d'écrit (à réactiver dans le Planificateur de tâches si vous la reconnaissez)",
                "the task changed since Vanguard disabled it: nothing written (re-enable it in Task Scheduler if you recognize it)"
            )
            .to_string(),
        );
    }
    let avant = tr!("désactivée", "disabled").to_string();
    if let Err(e) = activer(&tache, true) {
        return erreur_com(&e);
    }
    match relire(&dossier, &nom) {
        Ok(Some((_, l))) if l.active => {
            effacer_note(&nom_note);
            Resultat::fait(avant)
        }
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "la tâche relue n'est pas active ; la note est gardée",
                "the task read again is not enabled; the note is kept"
            )
            .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_note_garde_les_deux_definitions() {
        let (avant, apres) = ("<Task>é</Task>", "<Task><Enabled>false</Enabled></Task>");
        assert_eq!(
            lire_note(&note(avant, apres).unwrap()),
            Some((avant.into(), apres.into()))
        );
        assert_eq!(
            lire_note(&note(avant, "").unwrap()),
            Some((avant.into(), String::new()))
        );
        // Trop courte, longueur au-delà, octet impair : refusées.
        assert_eq!(lire_note(&[1, 0]), None);
        assert_eq!(lire_note(&[9, 0, 0, 0, b'a', 0]), None);
        assert_eq!(lire_note(&[0, 0, 0, 0, b'a']), None);
    }

    /// D6d : une définition plus grande que la note, ou une note refusée, demande « non annulable » (Non par défaut,
    /// `protege::accord`) ; acceptée, la tâche est désactivée sans note, jamais supprimée : ce module n'a aucun
    /// appel qui supprime une tâche.
    #[test]
    fn sans_note_la_tache_se_desactive_sans_etre_supprimee() {
        assert!(matches!(
            noter_ou_demander(XML_MAX + 1, false, || Ok(())),
            Noter::Demander(_)
        ));
        assert_eq!(noter_ou_demander(XML_MAX, false, || Ok(())), Noter::Fait);
        assert_eq!(
            noter_ou_demander(10, false, || Err(std::io::Error::other("refusé"))),
            Noter::Demander("refusé".into())
        );
        // Accordé : aucune note tentée.
        assert_eq!(
            noter_ou_demander(XML_MAX + 1, true, || panic!("pas de note")),
            Noter::Passer
        );
        // Le nom de l'appel coupé en deux ici, pour que ce test ne se trouve pas lui-même.
        let source = include_str!("taches_ecriture.rs");
        assert!(!source.contains(&format!("{}{}", "Delete", "Task")));
    }

    /// Une tâche sous \Microsoft\ reste refusée, même au nom de Defender, quelle que soit la casse ; une tâche au nom
    /// de Defender ailleurs se juge (`protege`), refusée seulement si c'est le vrai programme.
    #[test]
    fn tache_sous_microsoft_refusee() {
        use super::super::planificateur::hors_windows;
        for d in [r"\Microsoft", r"\MICROSOFT\Windows\Windows Defender", r"\microsoft\x"] {
            assert!(!hors_windows(d), "{d}");
        }
        for d in ["\\", r"\Windows Defender", r"\MicrosoftEdgeUpdate", r"\vg-essai"] {
            assert!(hors_windows(d), "{d}");
        }
    }

    #[test]
    fn dossier_nom_et_prefixe() {
        assert_eq!(dossier_et_nom(r"\Maj"), Some(("\\".into(), "Maj".into())));
        assert_eq!(dossier_et_nom(r"\A\B\Maj"), Some((r"\A\B".into(), "Maj".into())));
        assert_eq!(prefixe("\\"), "\\");
        assert_eq!(prefixe(r"\A\B"), r"\A\B\");
    }
}
