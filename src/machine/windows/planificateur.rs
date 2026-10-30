//! Les tâches planifiées lues par le planificateur de Windows lui-même (ITaskService, COM), au lieu de
//! Get-ScheduledTask : quelques millisecondes là où PowerShell prend une à plusieurs secondes.

use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{
    IComHandlerAction, IExecAction, IRegisteredTask, ITaskFolder, ITaskService, TASK_ACTION_COM_HANDLER,
    TASK_ACTION_EXEC, TASK_ACTION_TYPE, TASK_ENUM_HIDDEN, TASK_STATE_DISABLED, TASK_TRIGGER_LOGON, TASK_TRIGGER_TYPE2,
    TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

use super::wmi;
use crate::reseau::surveillance::Definition;

/// Plus de dossiers qu'un vrai planificateur n'en a : au-delà, la lecture est refusée plutôt que laissée à moitié.
const DOSSIERS_MAX: usize = 10_000;

/// Les tâches qui ne sont pas désactivées, hors \Microsoft\ (celles de Windows), cachées comprises : une ligne
/// « dossier|nom|programme|arguments » par action qui lance un programme, comme la section TCH du script
/// PowerShell (le dossier finit par « \ », comme TaskPath). `None` si le planificateur ne répond pas ou refuse une
/// lecture : PowerShell prend le relais, jamais une liste partielle qui passerait pour saine. Même chose sans le
/// dossier \Microsoft, que tout Windows a : un planificateur qui ne le montre pas ne montre rien (celui de Wine rend
/// des listes vides sans erreur, GetTasks n'y étant qu'une ébauche).
pub(super) fn taches() -> Option<Vec<String>> {
    wmi::com("Tâches planifiées", "ITaskService", lire)
}

fn hors_windows(dossier: &str) -> bool {
    let bas = dossier.to_ascii_lowercase();
    bas != r"\microsoft" && !bas.starts_with(r"\microsoft\")
}

fn lire() -> windows::core::Result<Vec<String>> {
    // SAFETY: COM est initialisé dans ce fil (par `wmi::com`) ; TaskScheduler est la classe du planificateur.
    let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }?;
    let vide = VARIANT::default();
    // SAFETY: VARIANT vides = cet ordinateur, le compte qui lance.
    unsafe { service.Connect(&vide, &vide, &vide, &vide) }?;
    // SAFETY: service connecté ; chemin BSTR valide pendant l'appel.
    let racine = unsafe { service.GetFolder(&BSTR::from(r"\")) }?;
    let mut lignes = Vec::new();
    let mut a_lire: Vec<ITaskFolder> = vec![racine];
    let mut lus = 0;
    let mut dossier_de_windows = false;
    while let Some(dossier) = a_lire.pop() {
        lus += 1;
        if lus > DOSSIERS_MAX {
            return Err(windows::core::Error::empty());
        }
        // SAFETY: dossier est une interface vivante rendue par le planificateur.
        let chemin = unsafe { dossier.Path() }?.to_string();
        if !hors_windows(&chemin) {
            dossier_de_windows = true;
            continue;
        }
        let prefixe = if chemin.ends_with('\\') {
            chemin
        } else {
            format!("{chemin}\\")
        };
        // SAFETY: dossier vivant ; les collections sont indexées de 1 à Count, bornes lues avant chaque accès.
        unsafe {
            let taches = dossier.GetTasks(TASK_ENUM_HIDDEN.0)?;
            for i in 1..=taches.Count()? {
                let tache = taches.get_Item(&wmi::variant_entier(i))?;
                if tache.State()? == TASK_STATE_DISABLED {
                    continue;
                }
                let nom = tache.Name()?;
                let actions = tache.Definition()?.Actions()?;
                let mut nombre = 0;
                actions.Count(&raw mut nombre)?;
                for j in 1..=nombre {
                    let action = actions.get_Item(j)?;
                    let mut genre = TASK_ACTION_TYPE::default();
                    action.Type(&raw mut genre)?;
                    if genre != TASK_ACTION_EXEC {
                        continue;
                    }
                    let lancement: IExecAction = action.cast()?;
                    let (mut programme, mut arguments) = (BSTR::new(), BSTR::new());
                    lancement.Path(&raw mut programme)?;
                    lancement.Arguments(&raw mut arguments)?;
                    // Comme le `Where-Object { $_.Execute }` du script : une action sans programme ne lance rien.
                    if !programme.is_empty() {
                        lignes.push(format!("{prefixe}|{nom}|{programme}|{arguments}"));
                    }
                }
            }
            let sous = dossier.GetFolders(0)?;
            for i in 1..=sous.Count()? {
                a_lire.push(sous.get_Item(&wmi::variant_entier(i))?);
            }
        }
    }
    if !dossier_de_windows {
        return Err(windows::core::Error::empty());
    }
    Ok(lignes)
}

/// Ce que lance chaque tâche active hors \Microsoft\, pour la liste du menu antivirus : (nom, programme), ou
/// (nom, « COM {CLSID} ») pour une action à gestionnaire COM, persistance connue sans programme à montrer. Une tâche
/// sans action de ces deux genres (courriel, message, abandonnés depuis Windows 8) est montrée sans rien. `None` :
/// comme `taches`.
pub(crate) fn lancements() -> Option<Vec<(String, String)>> {
    wmi::com("Tâches planifiées", "ITaskService", || {
        let mut lignes = Vec::new();
        parcourir(|tache| {
            // SAFETY: tâche vivante rendue par le planificateur, le temps de cet appel ; ses actions sont indexées de
            // 1 à Count, lu avant.
            unsafe {
                if tache.State()? == TASK_STATE_DISABLED {
                    return Ok(());
                }
                let nom = tache.Name()?.to_string();
                let actions = tache.Definition()?.Actions()?;
                let mut nombre = 0;
                actions.Count(&raw mut nombre)?;
                let mut vues = 0;
                for j in 1..=nombre {
                    let action = actions.get_Item(j)?;
                    let mut genre = TASK_ACTION_TYPE::default();
                    action.Type(&raw mut genre)?;
                    let quoi = if genre == TASK_ACTION_EXEC {
                        let lancement: IExecAction = action.cast()?;
                        let mut programme = BSTR::new();
                        lancement.Path(&raw mut programme)?;
                        programme.to_string()
                    } else if genre == TASK_ACTION_COM_HANDLER {
                        let gestionnaire: IComHandlerAction = action.cast()?;
                        let mut classe = BSTR::new();
                        gestionnaire.ClassId(&raw mut classe)?;
                        format!("COM {classe}")
                    } else {
                        continue;
                    };
                    vues += 1;
                    lignes.push((nom.clone(), quoi));
                }
                if vues == 0 {
                    lignes.push((nom, String::new()));
                }
            }
            Ok(())
        })?;
        Ok(lignes)
    })
}

/// L'état des tâches nommées `noms`, où qu'elles soient hors \Microsoft\ (celles de Vanguard sont à la racine),
/// comme `Get-ScheduledTask | Where-Object TaskName -in …` : active si l'une n'est pas désactivée. `None` si le planificateur
/// ne répond pas ou ne montre pas le dossier \Microsoft (Wine) : PowerShell prend le relais.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum EtatTache {
    Absente,
    Desactivee,
    Active,
}

pub(crate) fn etat(noms: &[&str]) -> Option<EtatTache> {
    let noms: Vec<String> = noms.iter().map(|n| n.to_lowercase()).collect();
    wmi::com("Tâches planifiées", "ITaskService", move || {
        let mut trouve = EtatTache::Absente;
        parcourir(|tache| {
            // SAFETY: tâche vivante rendue par le planificateur, le temps de cet appel.
            let (nom, active) = unsafe { (tache.Name()?.to_string(), tache.State()? != TASK_STATE_DISABLED) };
            if noms.contains(&nom.to_lowercase()) {
                if active {
                    trouve = EtatTache::Active;
                } else if trouve == EtatTache::Absente {
                    trouve = EtatTache::Desactivee;
                }
            }
            Ok(())
        })?;
        Ok(trouve)
    })
}

/// Les tâches nommées `noms`, où qu'elles soient hors \Microsoft\, désactivées comprises : ce qu'elles lancent et
/// leurs réglages de rattrapage (`surveillance::Definition`). `None` si le planificateur ne répond pas ou ne montre
/// pas le dossier \Microsoft (Wine) : PowerShell prend le relais.
pub(crate) fn definitions(noms: &[&str]) -> Option<Vec<(String, Definition)>> {
    let noms: Vec<String> = noms.iter().map(|n| n.to_lowercase()).collect();
    wmi::com("Tâches planifiées", "ITaskService", move || {
        let mut trouvees = Vec::new();
        parcourir(|tache| {
            // SAFETY: tâche vivante rendue par le planificateur, le temps de cet appel.
            let nom = unsafe { tache.Name() }?.to_string();
            if noms.contains(&nom.to_lowercase()) {
                trouvees.push((nom, definition(tache)?));
            }
            Ok(())
        })?;
        Ok(trouvees)
    })
}

/// Le XML de la tâche nommée `nom` (hors \Microsoft\), tel que le planificateur la garde : ce que Vanguard a posé,
/// déclencheurs, réglages et actions compris (`programmes_poses` en scelle l'empreinte). `None` si le planificateur ne
/// répond pas ou si elle n'existe pas : jamais une lecture partielle.
pub(crate) fn xml(nom: &str) -> Option<String> {
    let nom = nom.to_lowercase();
    wmi::com("Tâches planifiées", "ITaskService", move || {
        let mut trouve = None;
        parcourir(|tache| {
            // SAFETY: tâche vivante rendue par le planificateur, le temps de cet appel.
            if unsafe { tache.Name() }?.to_string().to_lowercase() == nom {
                // SAFETY: la même tâche vivante.
                trouve = Some(unsafe { tache.Xml() }?.to_string());
            }
            Ok(())
        })?;
        Ok(trouve)
    })
    .flatten()
}

/// Ce que lance une tâche (sa première action qui lance un programme), si elle part dès que possible après un
/// passage manqué, si elle a un déclencheur à l'ouverture de session, et si elle est active.
fn definition(tache: &IRegisteredTask) -> windows::core::Result<Definition> {
    // SAFETY: tâche vivante ; chaque sortie est une variable locale valide pendant l'appel ; les collections sont
    // indexées de 1 à Count, bornes lues avant chaque accès.
    unsafe {
        let active = tache.State()? != TASK_STATE_DISABLED;
        let def = tache.Definition()?;
        let mut des_que_possible = VARIANT_BOOL::default();
        def.Settings()?.StartWhenAvailable(&raw mut des_que_possible)?;
        let declencheurs = def.Triggers()?;
        let mut nombre = 0;
        declencheurs.Count(&raw mut nombre)?;
        let mut a_l_ouverture = false;
        for i in 1..=nombre {
            let mut genre = TASK_TRIGGER_TYPE2::default();
            declencheurs.get_Item(i)?.Type(&raw mut genre)?;
            a_l_ouverture |= genre == TASK_TRIGGER_LOGON;
        }
        let actions = def.Actions()?;
        let mut nombre = 0;
        actions.Count(&raw mut nombre)?;
        let mut programme = String::new();
        for j in 1..=nombre {
            let action = actions.get_Item(j)?;
            let mut genre = TASK_ACTION_TYPE::default();
            action.Type(&raw mut genre)?;
            if genre == TASK_ACTION_EXEC {
                let lancement: IExecAction = action.cast()?;
                let mut chemin = BSTR::new();
                lancement.Path(&raw mut chemin)?;
                programme = chemin.to_string();
                break;
            }
        }
        Ok(Definition {
            programme,
            des_que_possible: des_que_possible.as_bool(),
            a_l_ouverture,
            active,
        })
    }
}

/// Chaque tâche hors \Microsoft\, cachées et désactivées comprises, donnée à `voir` ; une erreur de `voir` ou du
/// planificateur arrête tout. Erreur aussi sans le dossier \Microsoft (voir `taches`).
fn parcourir(mut voir: impl FnMut(&IRegisteredTask) -> windows::core::Result<()>) -> windows::core::Result<()> {
    // SAFETY: COM est initialisé dans ce fil (par `wmi::com`) ; TaskScheduler est la classe du planificateur.
    let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }?;
    let vide = VARIANT::default();
    // SAFETY: VARIANT vides = cet ordinateur, le compte qui lance.
    unsafe { service.Connect(&vide, &vide, &vide, &vide) }?;
    // SAFETY: service connecté ; chemin BSTR valide pendant l'appel.
    let racine = unsafe { service.GetFolder(&BSTR::from(r"\")) }?;
    let mut a_lire: Vec<ITaskFolder> = vec![racine];
    let mut lus = 0;
    let mut dossier_de_windows = false;
    while let Some(dossier) = a_lire.pop() {
        lus += 1;
        if lus > DOSSIERS_MAX {
            return Err(windows::core::Error::empty());
        }
        // SAFETY: dossier est une interface vivante rendue par le planificateur.
        if !hors_windows(&unsafe { dossier.Path() }?.to_string()) {
            dossier_de_windows = true;
            continue;
        }
        // SAFETY: dossier vivant ; les collections sont indexées de 1 à Count, bornes lues avant chaque accès.
        unsafe {
            let taches = dossier.GetTasks(TASK_ENUM_HIDDEN.0)?;
            for i in 1..=taches.Count()? {
                voir(&taches.get_Item(&wmi::variant_entier(i))?)?;
            }
            let sous = dossier.GetFolders(0)?;
            for i in 1..=sous.Count()? {
                a_lire.push(sous.get_Item(&wmi::variant_entier(i))?);
            }
        }
    }
    if !dossier_de_windows {
        return Err(windows::core::Error::empty());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dossiers_de_windows_ecartes() {
        assert!(hors_windows(r"\"));
        assert!(hors_windows(r"\Mozilla"));
        assert!(hors_windows(r"\MicrosoftEdgeUpdate"));
        assert!(!hors_windows(r"\Microsoft"));
        assert!(!hors_windows(r"\microsoft\Windows\Defrag"));
    }

    /// Sous Wine, sans dossier \Microsoft (GetTasks n'y est qu'une ébauche) : aucune réponse plutôt qu'une liste
    /// vide. Ailleurs (vrai Windows de la CI), des lignes à quatre champs.
    #[test]
    fn lecture_reelle() {
        let wine = std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file();
        let lu = taches();
        assert!(!wine || lu.is_none(), "{lu:?}");
        if let Some(lignes) = lu {
            assert!(lignes.iter().all(|l| l.splitn(4, '|').count() == 4));
        }
    }

    /// Même règle pour ce que lancent les tâches : sous Wine, pas de réponse ; ailleurs, une tâche qui n'existe pas
    /// n'est pas rendue.
    #[test]
    fn definitions_reelles() {
        let wine = std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file();
        let lu = definitions(&["vanguard - tâche qui n'existe pas"]);
        assert!(
            if wine {
                lu.is_none()
            } else {
                lu.as_ref().is_none_or(Vec::is_empty)
            },
            "{lu:?}"
        );
    }

    /// Même règle pour l'état d'une tâche : sous Wine, pas de réponse ; ailleurs, une tâche qui n'existe pas est absente.
    #[test]
    fn etat_reel() {
        let wine = std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file();
        let lu = etat(&["vanguard - tâche qui n'existe pas"]);
        assert!(
            if wine {
                lu.is_none()
            } else {
                lu.is_none_or(|e| e == EtatTache::Absente)
            },
            "{lu:?}"
        );
    }
}
