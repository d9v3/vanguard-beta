//! L'état d'un service Windows, lu auprès du gestionnaire de services (advapi32) sans PowerShell : ce que
//! `(Get-Service <nom>).Status` donnait, avec les mêmes mots.

use std::ffi::c_void;

#[repr(C)]
#[derive(Default)]
struct EtatDuService {
    sorte: u32,
    etat: u32,
    acceptes: u32,
    code: u32,
    code_du_service: u32,
    etape: u32,
    attente: u32,
}

/// La forme de QUERY_SERVICE_CONFIGW ; les textes sont rangés dans le même tampon, après elle.
#[repr(C)]
struct ConfigDuService {
    sorte: u32,
    demarrage: u32,
    erreurs: u32,
    programme: *const u16,
    groupe: *const u16,
    etiquette: u32,
    dependances: *const u16,
    compte: *const u16,
    nom_affiche: *const u16,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, base: *const u16, acces: u32) -> *mut c_void;
    fn OpenServiceW(gestionnaire: *mut c_void, nom: *const u16, acces: u32) -> *mut c_void;
    fn QueryServiceStatus(service: *mut c_void, etat: *mut EtatDuService) -> i32;
    fn QueryServiceConfigW(service: *mut c_void, config: *mut c_void, taille: u32, besoin: *mut u32) -> i32;
    fn CloseServiceHandle(objet: *mut c_void) -> i32;
}

/// Ce qu'un service répond.
#[derive(Debug, PartialEq)]
pub(crate) enum Service {
    /// Son état, dans les mots de Get-Service (« Running », « Stopped »…).
    Etat(&'static str),
    /// Le service n'existe pas sur cette machine.
    Absent,
}

/// L'état du service ; `None` si le gestionnaire de services ne répond pas (l'appelant ne conclut pas).
pub(crate) fn etat(nom: &str) -> Option<Service> {
    const CONNEXION: u32 = 0x1;
    const LIRE_L_ETAT: u32 = 0x4;
    const INTROUVABLE: i32 = 1060;
    let large: Vec<u16> = nom.encode_utf16().chain([0]).collect();
    // SAFETY : le nom est terminé par un zéro et vit pendant l'appel ; chaque poignée obtenue (nulle : refus, vérifié)
    // est fermée une seule fois ; la structure a la forme de SERVICE_STATUS (sept u32).
    unsafe {
        let gestionnaire = OpenSCManagerW(std::ptr::null(), std::ptr::null(), CONNEXION);
        if gestionnaire.is_null() {
            return None;
        }
        let service = OpenServiceW(gestionnaire, large.as_ptr(), LIRE_L_ETAT);
        let reponse = if service.is_null() {
            (std::io::Error::last_os_error().raw_os_error() == Some(INTROUVABLE)).then_some(Service::Absent)
        } else {
            let mut e = EtatDuService::default();
            let lu = QueryServiceStatus(service, &raw mut e) != 0;
            CloseServiceHandle(service);
            lu.then(|| Service::Etat(mot(e.etat)))
        };
        CloseServiceHandle(gestionnaire);
        reponse
    }
}

/// Le mot de Get-Service pour un état de SERVICE_STATUS.
fn mot(etat: u32) -> &'static str {
    match etat {
        1 => "Stopped",
        2 => "StartPending",
        3 => "StopPending",
        4 => "Running",
        5 => "ContinuePending",
        6 => "PausePending",
        7 => "Paused",
        _ => "Unknown",
    }
}

/// Comme `"$((Get-Service <nom>).Status)"` : le mot de l'état, vide si le service n'existe pas.
pub(crate) fn statut(nom: &str) -> Option<&'static str> {
    Some(match etat(nom)? {
        Service::Etat(m) => m,
        Service::Absent => "",
    })
}

/// Ce que le gestionnaire de services dit de la configuration d'un service : sa sorte, son démarrage (le nombre du
/// registre), son programme et son compte.
struct Config {
    sorte: u32,
    demarrage: u32,
    programme: String,
    compte: String,
}

/// La configuration d'un service auprès du gestionnaire de services ; `None` s'il ne répond pas ou refuse.
fn config(nom: &str) -> Option<Config> {
    const CONNEXION: u32 = 0x1;
    const LIRE_LA_CONFIG: u32 = 0x1;
    let large: Vec<u16> = nom.encode_utf16().chain([0]).collect();
    // SAFETY : le nom est terminé par un zéro et vit pendant l'appel ; chaque poignée obtenue (nulle : refus, vérifié)
    // est fermée une seule fois, après la lecture.
    unsafe {
        let gestionnaire = OpenSCManagerW(std::ptr::null(), std::ptr::null(), CONNEXION);
        if gestionnaire.is_null() {
            return None;
        }
        let service = OpenServiceW(gestionnaire, large.as_ptr(), LIRE_LA_CONFIG);
        let config = if service.is_null() {
            None
        } else {
            let config = lire_config(service);
            CloseServiceHandle(service);
            config
        };
        CloseServiceHandle(gestionnaire);
        config
    }
}

/// QueryServiceConfigW sur une poignée ouverte avec SERVICE_QUERY_CONFIG.
///
/// # Safety
/// `service` doit être une poignée de service valide, ouverte avec ce droit.
unsafe fn lire_config(service: *mut c_void) -> Option<Config> {
    // La documentation borne le tampon à 8 Ko ; au-delà, la réponse n'est pas crue.
    const TAMPON_MAX: usize = 64 * 1024;
    let mut besoin = 0u32;
    // SAFETY : premier appel sans tampon (taille 0), qui ne rend que la taille nécessaire dans `besoin`.
    unsafe { QueryServiceConfigW(service, std::ptr::null_mut(), 0, &raw mut besoin) };
    let besoin = usize::try_from(besoin).ok()?;
    if besoin < size_of::<ConfigDuService>() || besoin > TAMPON_MAX {
        return None;
    }
    // Des u64 : le tampon est aligné pour la structure et ses pointeurs.
    let mut tampon = vec![0u64; besoin.div_ceil(8)];
    let octets = tampon.len() * 8;
    let mut rendu = 0u32;
    // SAFETY : le tampon fait `octets` octets, la taille annoncée, et vit pendant l'appel.
    if unsafe {
        QueryServiceConfigW(
            service,
            tampon.as_mut_ptr().cast(),
            u32::try_from(octets).ok()?,
            &raw mut rendu,
        )
    } == 0
    {
        return None;
    }
    let debut = tampon.as_ptr() as usize;
    let fin = debut + octets;
    // SAFETY : l'appel a réussi, le tampon (aligné sur 8, vérifié plus grand que la structure) commence par elle.
    let c = unsafe { &*tampon.as_ptr().cast::<ConfigDuService>() };
    // Un texte de la réponse : son pointeur doit tomber dans le tampon, aligné, et la lecture s'arrête au premier
    // zéro ou à la fin du tampon, jamais au-delà.
    let texte = |p: *const u16| -> String {
        let a = p as usize;
        if p.is_null() || a < debut || a >= fin || !a.is_multiple_of(2) {
            return String::new();
        }
        // SAFETY : [a, fin) est dans le tampon (borne vérifiée juste au-dessus), aligné sur 2, initialisé.
        let mots = unsafe { std::slice::from_raw_parts(p, (fin - a) / 2) };
        // Jusqu'au premier zéro, ou tout le reste du tampon s'il n'y en a pas.
        String::from_utf16_lossy(mots.split(|&m| m == 0).next().unwrap_or(mots))
    };
    Some(Config {
        sorte: c.sorte,
        demarrage: c.demarrage,
        programme: texte(c.programme),
        compte: texte(c.compte),
    })
}

/// Le mot de Win32_Service pour la valeur Start du registre.
fn mot_demarrage(start: u32) -> &'static str {
    match start {
        0 => "Boot",
        1 => "System",
        2 => "Auto",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}

/// Un service Win32 inscrit dans le registre, avec ce que Win32_Service en montrait.
pub(crate) struct Inscrit {
    pub nom: String,
    /// Dans les mots de Win32_Service (« Running », « Stopped », « Start Pending »…) ; vide s'il ne se lit pas.
    pub etat: &'static str,
    /// « Boot », « System », « Auto », « Manual », « Disabled ».
    pub demarrage: &'static str,
    /// Le compte du service (ObjectName : « LocalSystem », « NT AUTHORITY\LocalService »…).
    pub compte: String,
    /// La ligne lancée (ImagePath), telle qu'inscrite.
    pub programme: String,
}

/// Les services Win32 (ni pilotes ni systèmes de fichiers) inscrits sous `HKLM\SYSTEM\CurrentControlSet\Services`,
/// avec leur état ; `None` si la clé ne s'ouvre pas.
pub(crate) fn inscrits() -> Option<Vec<Inscrit>> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    const SERVICE_WIN32: u32 = 0x30;
    let services = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(crate::machine::windows::CLE_SERVICES)
        .ok()?;
    Some(
        services
            .enum_keys()
            .flatten()
            .filter_map(|nom| {
                let etat = match etat(&nom) {
                    Some(Service::Etat(m)) => mot_wmi(m),
                    _ => "",
                };
                let Ok(cle) = services.open_subkey(&nom) else {
                    // Clé refusée en lecture (un moyen connu de se cacher de regedit) : le gestionnaire de services,
                    // qui la lit pour Win32_Service, répond encore. Sinon le nom seul : sauté en silence, le service
                    // caché, celui qu'on cherche, manquait aux traces sans que rien ne le dise.
                    return match config(&nom) {
                        Some(c) if c.sorte & SERVICE_WIN32 == 0 => None,
                        Some(c) => Some(Inscrit {
                            etat,
                            demarrage: mot_demarrage(c.demarrage),
                            compte: c.compte,
                            programme: c.programme,
                            nom,
                        }),
                        None => Some(Inscrit {
                            etat,
                            demarrage: "Unknown",
                            compte: String::new(),
                            programme: String::new(),
                            nom,
                        }),
                    };
                };
                if cle.get_value::<u32, _>("Type").ok()? & SERVICE_WIN32 == 0 {
                    return None;
                }
                let texte = |v: &str| cle.get_value::<String, _>(v).unwrap_or_default();
                let demarrage = mot_demarrage(cle.get_value::<u32, _>("Start").unwrap_or(u32::MAX));
                Some(Inscrit {
                    etat,
                    demarrage,
                    compte: texte("ObjectName"),
                    programme: texte("ImagePath"),
                    nom,
                })
            })
            .collect(),
    )
}

/// Le mot de Win32_Service pour celui de Get-Service (« StartPending » → « Start Pending »).
fn mot_wmi(mot: &'static str) -> &'static str {
    match mot {
        "StartPending" => "Start Pending",
        "StopPending" => "Stop Pending",
        "ContinuePending" => "Continue Pending",
        "PausePending" => "Pause Pending",
        autre => autre,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mots_de_get_service() {
        assert_eq!(mot(4), "Running");
        assert_eq!(mot(1), "Stopped");
        assert_eq!(mot(0), "Unknown");
    }

    /// Le vrai gestionnaire de services (Wine ici, la VM ensuite) : un service inventé est absent, et la réponse pour
    /// un vrai service est un mot de Get-Service.
    #[test]
    fn services_lus_par_windows() {
        if let Some(e) = etat("VanguardServiceInexistant") {
            assert_eq!(e, Service::Absent);
        }
        let _ = statut("Spooler");
        let inscrits = inscrits().expect("clé des services");
        assert!(inscrits.iter().all(|s| !s.nom.is_empty()));
        // La configuration par le gestionnaire (secours d'une clé refusée) dit la même chose que le registre.
        assert!(config("VanguardServiceInexistant").is_none());
        if let Some(s) = inscrits.first()
            && let Some(c) = config(&s.nom)
        {
            assert!(c.sorte & 0x30 != 0);
            assert_eq!(mot_demarrage(c.demarrage), s.demarrage, "{}", s.nom);
        }
        assert_eq!(mot_demarrage(2), "Auto");
        assert_eq!(mot_demarrage(9), "Unknown");
        assert_eq!(mot_wmi("StartPending"), "Start Pending");
    }
}
