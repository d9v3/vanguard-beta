//! Désactiver une tâche planifiée signalée par le bilan, par le processus élevé, sans PowerShell (lot 3.5, passe b,
//! R47) : le planificateur de Windows (ITaskService, COM), IRegisteredTask::put_Enabled. La ligne désigne, le
//! processus élevé juge : la tâche est relue ici, jamais sous \Microsoft\ (les tâches de Windows et de Defender), son
//! chemin doit être exactement celui de la ligne, aucun de ses programmes n'est de Windows ou de Defender
//! (`gestes::run_protege`), et le bilan refait sur ses lignes (`planificateur::lignes_tache`,
//! `persistance::tache_signalee`) doit proposer cette même ligne. Son XML est noté dans `gestes::TACHE_AVANT_CLE`
//! avant le changement, relu juste avant, puis celui d'après : la réactivation n'a lieu que si la tâche est restée
//! telle que Vanguard l'a laissée.

use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{IRegisteredTask, ITaskService, TASK_STATE_DISABLED, TaskScheduler};
use windows::Win32::System::Variant::VARIANT;
use windows::core::BSTR;
use winreg::RegKey;
use winreg::enums::RegType::REG_BINARY;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};

use super::corrections::Resultat;
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
    super::wmi::com("Tâche planifiée", "ITaskService", move || Ok(geste())).unwrap_or_else(|| {
        Resultat::echec(
            None,
            tr!(
                "le planificateur de tâches ne répond pas : l'état de la tâche est à relire (relancez le bilan)",
                "the Task Scheduler does not answer: the task's state must be read again (run the check again)"
            )
            .to_string(),
        )
    })
}

/// Dans le processus élevé : désactive la tâche `t` si et seulement si le bilan, refait ici sur la tâche relue, la
/// signale et propose cette même ligne.
pub(super) fn desactiver(t: &CheminTache) -> Resultat {
    let t = t.clone();
    dans_le_planificateur(move || desactiver_ici(&t))
}

fn desactiver_ici(t: &CheminTache) -> Resultat {
    let ligne = Acte::TacheDesactiver(t.clone()).ligne();
    let Some((dossier, nom)) = dossier_et_nom(t.texte()) else {
        return refus(tr!("ligne mal formée : rien d'écrit", "malformed line: nothing written").to_string());
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
            return Resultat::rien(
                tr!(
                    "la tâche n'existe plus : rien à désactiver",
                    "the task no longer exists: nothing to disable"
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
    if !lue.active {
        return Resultat::rien(
            tr!(
                "la tâche est déjà désactivée : rien à faire",
                "the task is already disabled: nothing to do"
            )
            .to_string(),
        );
    }
    let protege = lue.lignes.iter().any(|l| {
        let programme = l.split('|').nth(2).unwrap_or_default();
        gestes::run_protege(&nom, programme)
    });
    if protege {
        return refus(
            tr!(
                "la tâche lance un programme de Sécurité Windows ou de Defender : Vanguard n'y touche jamais ; rien d'écrit",
                "the task starts a Windows Security or Defender program: Vanguard never touches it; nothing written"
            )
            .to_string(),
        );
    }
    if !super::persistance::tache_signalee(&lue.lignes, &ligne) {
        return refus(
            tr!(
                "le bilan refait ici ne signale pas cette tâche : rien d'écrit",
                "the check run again here does not report this task: nothing written"
            )
            .to_string(),
        );
    }
    if lue.xml.len() > XML_MAX {
        return refus(
            tr!(
                "définition de la tâche trop longue pour être notée : rien d'écrit",
                "task definition too long to be noted: nothing written"
            )
            .to_string(),
        );
    }
    // Notée d'abord : sans note, pas de changement (la réactivation exacte serait perdue).
    let nom_note = nom_note(t);
    if let Err(e) = ecrire_note(&nom_note, &lue.xml, "") {
        return refus(trf!(
            "la définition d'avant ne se note pas ({e}) : rien d'écrit",
            "the previous definition cannot be noted ({e}): nothing written"
        ));
    }
    // Relue juste avant : jamais une tâche changée depuis le jugement.
    if !lire(&tache, &dossier).is_ok_and(|encore| encore.xml == lue.xml && encore.active) {
        effacer_note(&nom_note);
        return refus(
            tr!(
                "la tâche a changé entre la lecture et l'écriture ; rien d'écrit",
                "the task changed between reading and writing; nothing written"
            )
            .to_string(),
        );
    }
    let avant = tr!("active", "enabled").to_string();
    if let Err(e) = activer(&tache, false) {
        effacer_note(&nom_note);
        return erreur_com(&e);
    }
    let apres = match relire(&dossier, &nom) {
        Ok(Some((_, l))) if !l.active && l.chemin == lue.chemin => l,
        _ => {
            return Resultat::echec(
                Some(avant),
                tr!(
                    "la tâche relue n'est pas désactivée ; la note est gardée",
                    "the task read again is not disabled; the note is kept"
                )
                .to_string(),
            );
        }
    };
    if let Err(e) = ecrire_note(&nom_note, &lue.xml, &apres.xml) {
        return Resultat::echec(
            Some(avant),
            trf!(
                "tâche désactivée, mais sa définition d'après ne se note pas ({e}) : la réactiver par Vanguard sera refusé (à faire dans le Planificateur de tâches)",
                "task disabled, but its new definition cannot be noted ({e}): re-enabling it through Vanguard will be refused (do it in Task Scheduler)"
            ),
        );
    }
    Resultat::fait(avant)
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

    #[test]
    fn dossier_nom_et_prefixe() {
        assert_eq!(dossier_et_nom(r"\Maj"), Some(("\\".into(), "Maj".into())));
        assert_eq!(dossier_et_nom(r"\A\B\Maj"), Some((r"\A\B".into(), "Maj".into())));
        assert_eq!(prefixe("\\"), "\\");
        assert_eq!(prefixe(r"\A\B"), r"\A\B\");
    }
}
