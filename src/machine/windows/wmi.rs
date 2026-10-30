//! WMI sans PowerShell : une requête WQL lue directement par COM. Chaque lancement de PowerShell coûte près d'une
//! demi-seconde (plusieurs secondes sur un ordinateur lent) ; la même lecture par COM, quelques millisecondes.
//! Chaque requête tourne dans son propre fil : son appartement COM ne gêne pas celui de l'appelant, et un fournisseur
//! WMI bloqué (Defender suspendu…) ne fige pas l'audit, comme le délai de `ps()`.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT, COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, SAFEARRAY,
};
use windows::Win32::System::Ole::{SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::Variant::{
    VARENUM, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_ARRAY, VT_BOOL, VT_BSTR, VT_BYREF, VT_I1, VT_I2, VT_I4,
    VT_I8, VT_INT, VT_UI1, VT_UI2, VT_UI4, VT_UI8, VT_UINT, VariantClear,
};
use windows::Win32::System::Wmi::{
    IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE, WBEM_INFINITE,
    WbemLocator,
};
use windows::core::{BSTR, HSTRING, IUnknown, Interface};

/// Constantes de rpcdce.h (authentification Windows, sans autorisation), ici pour ne pas tirer tout Win32_System_Rpc.
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;

/// Le délai de `ps()` est de 60 s ; ici la moitié, puisque PowerShell prend le relais si COM ne répond pas.
const DELAI: Duration = Duration::from_secs(30);

/// Plus d'éléments qu'aucune liste lue par Vanguard n'en a : une liste plus longue est tronquée, pas parcourue.
const ELEMENTS_MAX: i32 = 4096;

/// Une valeur lue par WMI. Les entiers de 64 bits arrivent en texte (c'est ainsi que WMI les donne) : `entier()`
/// les relit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Valeur {
    Nul,
    Booleen(bool),
    Entier(i64),
    Texte(String),
    Liste(Vec<Valeur>),
}

impl Valeur {
    pub(crate) fn entier(&self) -> Option<i64> {
        match self {
            Valeur::Entier(n) => Some(*n),
            Valeur::Texte(t) => t.trim().parse().ok(),
            _ => None,
        }
    }

    pub(crate) fn texte(&self) -> Option<&str> {
        match self {
            Valeur::Texte(t) => Some(t),
            _ => None,
        }
    }

    /// La valeur en JSON, comme ConvertTo-Json la rendrait : pour garder les lectures qui jugeaient le JSON de
    /// PowerShell.
    pub(crate) fn json(&self) -> serde_json::Value {
        match self {
            Valeur::Nul => serde_json::Value::Null,
            Valeur::Booleen(b) => (*b).into(),
            Valeur::Entier(n) => (*n).into(),
            Valeur::Texte(t) => t.as_str().into(),
            Valeur::Liste(l) => l.iter().map(Valeur::json).collect(),
        }
    }

    pub(crate) fn liste(&self) -> &[Valeur] {
        match self {
            Valeur::Liste(l) => l,
            _ => &[],
        }
    }
}

/// Une instance : ses champs demandés, `Valeur::Nul` pour un champ que la classe n'a pas (version de Windows plus
/// ancienne).
pub(crate) type Ligne = HashMap<String, Valeur>;

/// Les `champs` de chaque instance de `classe` dans l'espace de noms `espace` (`root\cimv2`…), filtrées par
/// `condition` (WQL, après WHERE ; vide : toutes). `None` : WMI absent ou en panne, espace ou classe inconnus (Wine,
/// édition de Windows sans ce composant), délai dépassé ; l'appelant passe alors par PowerShell ou dit « non
/// vérifié ». Une liste vide est une vraie réponse, aucune instance : la classe a été trouvée.
pub(crate) fn requete(espace: &str, classe: &str, condition: &str, champs: &[&str]) -> Option<Vec<Ligne>> {
    match interroger(espace, classe, condition, champs)? {
        Reponse::Lignes(lignes) => Some(lignes),
        Reponse::ClasseAbsente => None,
    }
}

/// Ce que WMI a répondu, quand une classe absente se distingue d'un échec (un refus, une panne).
pub(crate) enum Reponse {
    Lignes(Vec<Ligne>),
    /// La classe n'existe pas dans cet espace de noms (pas inscrite sur ce Windows).
    ClasseAbsente,
}

/// Comme `requete`, avec « classe absente » à part ; `None` : tout autre échec (refus, espace inconnu, délai).
pub(crate) fn interroger(espace: &str, classe: &str, condition: &str, champs: &[&str]) -> Option<Reponse> {
    /// WBEM_E_NOT_FOUND et WBEM_E_INVALID_CLASS.
    const ABSENTE: [i32; 2] = [0x8004_1002_u32.cast_signed(), 0x8004_1010_u32.cast_signed()];
    // Tous les champs (`*`), lus ensuite un par un : un champ que cette version de Windows n'a pas devient
    // `Valeur::Nul`, au lieu de faire échouer toute la requête.
    let wql = if condition.is_empty() {
        format!("SELECT * FROM {classe}")
    } else {
        format!("SELECT * FROM {classe} WHERE {condition}")
    };
    let (espace, classe) = (espace.to_string(), classe.to_string());
    let champs: Vec<String> = champs.iter().map(|c| (*c).to_string()).collect();
    let debut: String = wql.chars().take(240).collect();
    com("WMI", &debut, move || {
        match dans_ce_fil(&espace, &classe, &wql, &champs) {
            Ok(lignes) => Ok(Reponse::Lignes(lignes)),
            Err(e) if ABSENTE.contains(&e.code().0) => Ok(Reponse::ClasseAbsente),
            Err(e) => Err(e),
        }
    })
}

/// Une lecture par COM dans un fil à elle, avec son propre appartement (multithread), arrêtée d'attendre après le
/// délai. `None` si elle échoue (composant absent : rien au journal, PowerShell ou « non vérifié » suivent) ou ne
/// répond pas à temps (noté au journal sous `nom`, avec `quoi`). Le fil d'une lecture bloquée est abandonné, pas tué :
/// COM ne sait pas interrompre un appel en cours.
pub(crate) fn com<T: Send + 'static>(
    nom: &str,
    quoi: &str,
    lecture: impl FnOnce() -> windows::core::Result<T> + Send + 'static,
) -> Option<T> {
    com_delai(nom, quoi, DELAI, lecture)
}

/// Comme `com`, avec un délai choisi : la recherche de Windows Update peut prendre deux ou trois minutes.
pub(crate) fn com_delai<T: Send + 'static>(
    nom: &str,
    quoi: &str,
    delai: Duration,
    lecture: impl FnOnce() -> windows::core::Result<T> + Send + 'static,
) -> Option<T> {
    dans_un_appartement(nom, quoi, delai, COINIT_MULTITHREADED, lecture)
}

/// Comme `com`, dans un appartement à fil unique (STA), celui de PowerShell 5.1 : les objets de l'Explorateur
/// (propriétés d'un volume) sont écrits pour lui.
pub(crate) fn com_sta<T: Send + 'static>(
    nom: &str,
    quoi: &str,
    lecture: impl FnOnce() -> windows::core::Result<T> + Send + 'static,
) -> Option<T> {
    dans_un_appartement(nom, quoi, DELAI, COINIT_APARTMENTTHREADED, lecture)
}

fn dans_un_appartement<T: Send + 'static>(
    nom: &str,
    quoi: &str,
    delai: Duration,
    appartement: COINIT,
    lecture: impl FnOnce() -> windows::core::Result<T> + Send + 'static,
) -> Option<T> {
    if let Some(resultat) = dans_un_fil(delai, appartement, lecture) {
        resultat.ok()
    } else {
        crate::journal::erreur(nom, &format!("délai de {} s dépassé\n{quoi}", delai.as_secs()));
        None
    }
}

/// La lecture dans son fil et son appartement ; `None` si elle n'a pas répondu dans le délai. Une erreur ne sort du
/// fil que par son code : une `windows::core::Error` garde l'IErrorInfo du fil (GetErrorInfo, un objet COM), et la
/// libérer ailleurs, l'appartement fermé et la DLL qui l'a créée peut-être déchargée, plantait Vanguard sur un vrai
/// Windows (violation d'accès, 0xC0000005, au hasard des règles lancées en parallèle). `map_err` la détruit avant
/// `Appartement`, dans son appartement.
fn dans_un_fil<T: Send + 'static>(
    delai: Duration,
    appartement: COINIT,
    lecture: impl FnOnce() -> windows::core::Result<T> + Send + 'static,
) -> Option<Result<T, windows::core::HRESULT>> {
    let (envoi, reception) = mpsc::channel();
    std::thread::Builder::new()
        .name("com".into())
        .spawn(move || {
            // SAFETY: fil créé pour cette seule lecture ; l'appartement est rendu par `Appartement` à la sortie.
            let resultat = unsafe { CoInitializeEx(None, appartement) }
                .ok()
                .map_err(|e| e.code())
                .and_then(|()| {
                    let _appartement = Appartement;
                    lecture().map_err(|e| e.code())
                });
            let _ = envoi.send(resultat);
        })
        .ok()?;
    reception.recv_timeout(delai).ok()
}

/// Secondes depuis une date CIM (« 20261020075504.500000-240 », décalage en minutes) ; `None` si illisible.
pub(crate) fn secondes_depuis(date_cim: &str, maintenant: chrono::DateTime<chrono::Utc>) -> Option<u64> {
    let locale = chrono::NaiveDateTime::parse_from_str(date_cim.get(..14)?, "%Y%m%d%H%M%S").ok()?;
    let decalage: i64 = date_cim.get(21..)?.parse().ok()?;
    let utc = locale - chrono::Duration::minutes(decalage);
    u64::try_from((maintenant.naive_utc() - utc).num_seconds()).ok()
}

/// Un entier dans un VARIANT, pour les collections COM qui s'indexent ainsi (`get_Item`, à partir de 1).
pub(crate) fn variant_entier(n: i32) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: std::mem::ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_I4,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { lVal: n },
            }),
        },
    }
}

/// Rend l'appartement COM du fil à sa fin, quel que soit le chemin de sortie.
struct Appartement;

impl Drop for Appartement {
    fn drop(&mut self) {
        // SAFETY: créé seulement après un CoInitializeEx réussi dans ce même fil.
        unsafe { CoUninitialize() };
    }
}

/// Droits d'appel sur un mandataire vers le service WMI : se faire passer pour l'utilisateur (impersonate), comme
/// Get-CimInstance. L'échec est sans suite : un objet sans mandataire (le WMI de Wine, dans le processus) n'en a pas
/// besoin, et un vrai refus se voit à la requête.
///
/// Les droits se règlent interface par interface : c'est le pointeur de `T` lui-même qui est passé, jamais celui de
/// son IUnknown (obtenu par `cast`), qui laissait IWbemServices au niveau par défaut (identify). Sur un vrai Windows,
/// les fournisseurs qui se font passer pour l'appelant (Win32_OperatingSystem, Win32_Process,
/// Win32_QuickFixEngineering, compteurs Win32_PerfRawData_*) échouaient alors ; Wine, sans mandataire, ne le montre pas.
fn droits_d_appel<T: Interface>(objet: &T) {
    let brut = objet.as_raw();
    // SAFETY: `brut` est le pointeur vivant de `objet`, emprunté le temps de l'appel ; toute interface COM commence
    // par IUnknown. Les autres paramètres sont des constantes ou nuls.
    let Some(objet) = (unsafe { IUnknown::from_raw_borrowed(&brut) }) else {
        return;
    };
    // SAFETY: voir plus haut.
    let _ = unsafe {
        CoSetProxyBlanket(
            objet,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    };
}

fn dans_ce_fil(espace: &str, classe: &str, wql: &str, champs: &[String]) -> windows::core::Result<Vec<Ligne>> {
    // SAFETY: COM est initialisé dans ce fil (par `com`) ; WbemLocator est la classe du localisateur WMI de Windows.
    let localisateur: IWbemLocator = unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }?;
    let vide = BSTR::new();
    // SAFETY: chaînes BSTR valides pendant l'appel ; utilisateur et mot de passe vides = le compte qui lance.
    let services = unsafe { localisateur.ConnectServer(&BSTR::from(espace), &vide, &vide, &vide, 0, &vide, None) }?;
    droits_d_appel(&services);
    // SAFETY: services est vivant ; requête et langage sont des BSTR valides pendant l'appel.
    let instances = unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(wql),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    }?;
    droits_d_appel(&instances);
    let noms: Vec<HSTRING> = champs.iter().map(|c| HSTRING::from(c.as_str())).collect();
    let mut lignes = Vec::new();
    loop {
        let mut objets = [None];
        let mut rendus = 0u32;
        // SAFETY: un emplacement pour un objet, `rendus` dit combien ont été écrits.
        unsafe { instances.Next(WBEM_INFINITE, &mut objets, &raw mut rendus) }.ok()?;
        let Some(objet) = objets[0].take().filter(|_| rendus == 1) else {
            break;
        };
        let mut ligne = Ligne::new();
        for (champ, nom) in champs.iter().zip(&noms) {
            let mut v = VARIANT::default();
            // SAFETY: objet est vivant, `nom` une chaîne terminée par un zéro, `v` un VARIANT vide qui reçoit la copie.
            let valeur = match unsafe { objet.Get(nom, 0, &raw mut v, None, None) } {
                // SAFETY: `v` vient d'être rempli par Get.
                Ok(()) => unsafe { lire(&v) },
                Err(_) => Valeur::Nul,
            };
            // SAFETY: `v` est à nous (copie rendue par Get, ou vide) ; VariantClear libère ce qu'il porte.
            let _ = unsafe { VariantClear(&raw mut v) };
            ligne.insert(champ.clone(), valeur);
        }
        lignes.push(ligne);
    }
    if lignes.is_empty() {
        // Le WMI de Wine répond à une classe inconnue par une liste vide, sans erreur : sans cette preuve que la
        // classe existe, « aucune instance » pourrait passer pour sain. L'emplacement de retour est exigé par Wine.
        let mut definition = None;
        // SAFETY: services est vivant ; le chemin est un BSTR valide pendant l'appel ; `definition` reçoit l'objet.
        unsafe {
            services.GetObject(
                &BSTR::from(classe),
                WBEM_GENERIC_FLAG_TYPE(0),
                None,
                Some(&raw mut definition),
                None,
            )
        }?;
    }
    Ok(lignes)
}

/// Le membre de l'union que désigne `vt`, et lui seul.
///
/// # Safety
/// `v` est un VARIANT initialisé dont `vt` décrit le contenu (rempli par COM).
unsafe fn lire(v: &VARIANT) -> Valeur {
    // SAFETY: le VARIANT est initialisé (contrat de la fonction) ; on lit son en-tête puis le membre de `vt`.
    unsafe {
        let interne = &v.Anonymous.Anonymous;
        let vt = interne.vt;
        let u = &interne.Anonymous;
        // Par référence, le membre est un pointeur (pparray, plVal…) : jamais lu comme la valeur elle-même.
        if vt.0 & VT_BYREF.0 != 0 {
            return Valeur::Nul;
        }
        if vt.0 & VT_ARRAY.0 != 0 {
            return lire_liste(u.parray, VARENUM(vt.0 & !VT_ARRAY.0));
        }
        match vt {
            VT_BOOL => Valeur::Booleen(u.boolVal.as_bool()),
            VT_BSTR => Valeur::Texte(u.bstrVal.to_string()),
            VT_I1 => Valeur::Entier(i64::from(u.cVal)),
            VT_UI1 => Valeur::Entier(i64::from(u.bVal)),
            VT_I2 => Valeur::Entier(i64::from(u.iVal)),
            VT_UI2 => Valeur::Entier(i64::from(u.uiVal)),
            VT_I4 => Valeur::Entier(i64::from(u.lVal)),
            VT_UI4 => Valeur::Entier(i64::from(u.ulVal)),
            VT_INT => Valeur::Entier(i64::from(u.intVal)),
            VT_UINT => Valeur::Entier(i64::from(u.uintVal)),
            VT_I8 => Valeur::Entier(u.llVal),
            VT_UI8 => i64::try_from(u.ullVal).map_or(Valeur::Nul, Valeur::Entier),
            // Vide, nul, ou un type que Vanguard ne lit pas (date, objet) : sans valeur, jamais deviné.
            _ => Valeur::Nul,
        }
    }
}

/// Un élément d'une liste à une dimension, copié par SafeArrayGetElement. La taille d'un élément est vérifiée
/// AVANT la copie : SafeArrayGetElement en écrit `cbElements` octets dans la destination.
///
/// # Safety
/// `liste` pointe sur un SAFEARRAY vivant à une dimension, `T` est le type de ses éléments.
unsafe fn element<T: Default>(liste: *const SAFEARRAY, i: i32) -> Option<T> {
    // SAFETY: `liste` est non nul et vivant (contrat de la fonction).
    if usize::try_from(unsafe { (*liste).cbElements }).ok()? != size_of::<T>() {
        return None;
    }
    let mut x = T::default();
    // SAFETY: un seul indice pour une dimension ; la destination a exactement la taille d'un élément.
    unsafe { SafeArrayGetElement(liste, &raw const i, (&raw mut x).cast()) }.ok()?;
    Some(x)
}

/// # Safety
/// `liste` est nul ou pointe sur un SAFEARRAY vivant dont les éléments sont du type `vt`.
unsafe fn lire_liste(liste: *const SAFEARRAY, vt: VARENUM) -> Valeur {
    // SAFETY: pointeur vérifié non nul avant chaque lecture ; dimensions et bornes demandées à Windows.
    unsafe {
        if liste.is_null() || SafeArrayGetDim(liste) != 1 {
            return Valeur::Nul;
        }
        let (Ok(bas), Ok(haut)) = (SafeArrayGetLBound(liste, 1), SafeArrayGetUBound(liste, 1)) else {
            return Valeur::Nul;
        };
        let haut = haut.min(bas.saturating_add(ELEMENTS_MAX - 1));
        let mut valeurs = Vec::new();
        for i in bas..=haut {
            let v = match vt {
                VT_BSTR => element::<BSTR>(liste, i).map(|b| Valeur::Texte(b.to_string())),
                VT_BOOL => element::<VARIANT_BOOL>(liste, i).map(|b| Valeur::Booleen(b.as_bool())),
                VT_I1 => element::<i8>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_UI1 => element::<u8>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_I2 => element::<i16>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_UI2 => element::<u16>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_I4 | VT_INT => element::<i32>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_UI4 | VT_UINT => element::<u32>(liste, i).map(|n| Valeur::Entier(n.into())),
                VT_I8 => element::<i64>(liste, i).map(Valeur::Entier),
                _ => None,
            };
            valeurs.push(v.unwrap_or(Valeur::Nul));
        }
        Valeur::Liste(valeurs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valeurs_relues() {
        assert_eq!(Valeur::Texte(" 18446744 ".into()).entier(), Some(18_446_744));
        assert_eq!(Valeur::Entier(3).entier(), Some(3));
        assert_eq!(Valeur::Nul.entier(), None);
        assert_eq!(Valeur::Texte("a".into()).texte(), Some("a"));
        assert_eq!(Valeur::Nul.json(), serde_json::Value::Null);
        assert_eq!(
            Valeur::Liste(vec![Valeur::Entier(1), Valeur::Booleen(false)]).json(),
            serde_json::json!([1, false])
        );
        assert_eq!(Valeur::Nul.liste(), []);
        assert_eq!(Valeur::Liste(vec![Valeur::Entier(2)]).liste(), &[Valeur::Entier(2)]);
    }

    /// Une erreur COM avec sa description (IErrorInfo posée par SetErrorInfo, comme le fait WMI) : captée par
    /// `windows::core::Error` dans le fil, elle n'en sort que par son code, et le fil appelant n'en hérite pas.
    #[test]
    fn erreur_rendue_sans_son_objet_com() {
        use windows::Win32::Foundation::E_FAIL;
        use windows::Win32::System::Com::{GetErrorInfo, IErrorInfo, SetErrorInfo};
        use windows::Win32::System::Ole::CreateErrorInfo;
        let r = dans_un_fil(DELAI, COINIT_MULTITHREADED, || -> windows::core::Result<()> {
            // SAFETY: COM est initialisé dans ce fil ; l'objet créé est rendu à COM par SetErrorInfo.
            unsafe {
                let createur = CreateErrorInfo()?;
                createur.SetDescription(windows::core::w!("erreur d'essai"))?;
                SetErrorInfo(0, &createur.cast::<IErrorInfo>()?)?;
            }
            let erreur = windows::core::Error::from(E_FAIL);
            // La preuve que l'objet COM a bien été capté, puis libéré ici, dans son appartement.
            assert_eq!(erreur.message(), "erreur d'essai");
            Err(erreur)
        });
        assert_eq!(r, Some(Err(E_FAIL)));
        // SAFETY: simple lecture de l'IErrorInfo de ce fil.
        assert!(unsafe { GetErrorInfo(0) }.is_err());
    }

    #[test]
    fn dates_cim() {
        let maintenant = chrono::DateTime::parse_from_rfc3339("2026-10-20T16:00:00Z")
            .unwrap()
            .to_utc();
        // 07:55:04 à UTC−4 = 11:55:04 UTC : 4 h 4 min 56 s plus tôt.
        assert_eq!(secondes_depuis("20261020075504.500000-240", maintenant), Some(14_696));
        assert_eq!(secondes_depuis("20261020160000.000000+000", maintenant), Some(0));
        assert_eq!(secondes_depuis("pas une date", maintenant), None);
        assert_eq!(secondes_depuis("20261021000000.000000+000", maintenant), None);
    }

    /// Le WMI de Wine connaît Win32_OperatingSystem : la requête aboutit sans PowerShell, comme sous Windows.
    #[test]
    fn requete_reelle() {
        let lignes = requete(
            r"root\cimv2",
            "Win32_OperatingSystem",
            "",
            &["Caption", "ChampQuiNExistePas"],
        )
        .expect("WMI répond");
        assert_eq!(lignes.len(), 1);
        assert!(matches!(&lignes[0]["Caption"], Valeur::Texte(t) if !t.is_empty()));
        assert_eq!(lignes[0]["ChampQuiNExistePas"], Valeur::Nul);
    }

    /// Une classe inconnue n'est pas une liste vide : c'est « illisible », pour que l'appelant ne conclue pas.
    #[test]
    fn classe_inconnue() {
        assert!(requete(r"root\cimv2", "Classe_Qui_N_Existe_Pas", "", &["Name"]).is_none());
        assert!(matches!(
            interroger(r"root\cimv2", "Classe_Qui_N_Existe_Pas", "", &["Name"]),
            Some(Reponse::ClasseAbsente)
        ));
        assert!(interroger(r"root\EspaceQuiNExistePas", "Win32_OperatingSystem", "", &["Name"]).is_none());
        assert!(requete(r"root\EspaceQuiNExistePas", "Win32_OperatingSystem", "", &["Name"]).is_none());
        // Une classe connue sans instance qui réponde : une vraie liste vide.
        assert_eq!(
            requete(
                r"root\cimv2",
                "Win32_OperatingSystem",
                "Caption = 'Pas un nom de Windows'",
                &["Caption"]
            ),
            Some(Vec::new())
        );
    }
}
