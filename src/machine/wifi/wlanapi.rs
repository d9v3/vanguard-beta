//! Les bornes Wi-Fi et les réseaux enregistrés de Windows, lus par l'API WLAN (wlanapi.dll) sans netsh ni
//! PowerShell : WlanEnumInterfaces, WlanQueryInterface (le réseau connecté et son émetteur), WlanGetNetworkBssList
//! (les éléments d'information bruts de chaque borne : chiffrement, WPS, BSSID), WlanGetProfileList et WlanGetProfile
//! (les profils qui se reconnectent seuls, sans jamais demander leur clé). La bibliothèque est chargée à la demande :
//! absente, incomplète ou sous Wine (où ces fonctions sont des coquilles qui plantent), c'est « non vérifié ». Ce que
//! Windows rend est copié d'un bloc puis lu octet par octet, chaque borne testée avant la lecture ; les lecteurs sont
//! purs et testés sur des blocs fabriqués selon wlanapi.h.

#[cfg(any(windows, test))]
use super::elements::{self, mac_texte};
#[cfg(any(windows, test))]
use super::profils::ProfilEnregistre;
#[cfg(any(windows, test))]
use super::{Balise, Bande, Borne, Connexion, canal_de_frequence};
#[cfg(any(windows, test))]
use crate::ui::affichable;
#[cfg(any(windows, test))]
use std::mem::{offset_of, size_of};

/// DOT11_SSID (wlantypes.h).
#[cfg(any(windows, test))]
#[repr(C)]
struct Dot11Ssid {
    longueur: u32,
    ssid: [u8; 32],
}

/// WLAN_INTERFACE_INFO (wlanapi.h).
#[cfg(any(windows, test))]
#[repr(C)]
struct WlanInterfaceInfo {
    guid: [u8; 16],
    description: [u16; 256],
    etat: u32,
}

/// WLAN_RATE_SET.
#[cfg(any(windows, test))]
#[repr(C)]
struct WlanRateSet {
    longueur: u32,
    debits: [u16; 126],
}

/// WLAN_BSS_ENTRY : une borne, et où trouver ses éléments d'information (décalage depuis le début de l'entrée).
#[cfg(any(windows, test))]
#[repr(C)]
struct WlanBssEntry {
    ssid: Dot11Ssid,
    phy_id: u32,
    bssid: [u8; 6],
    genre_bss: u32,
    phy: u32,
    rssi: i32,
    qualite: u32,
    dans_domaine: u8,
    periode_balise: u16,
    horodatage: u64,
    horodatage_hote: u64,
    capacites: u16,
    frequence_centrale_khz: u32,
    debits: WlanRateSet,
    decalage_elements: u32,
    taille_elements: u32,
}

/// WLAN_PROFILE_INFO.
#[cfg(any(windows, test))]
#[repr(C)]
struct WlanProfileInfo {
    nom: [u16; 256],
    drapeaux: u32,
}

/// WLAN_ASSOCIATION_ATTRIBUTES.
#[cfg(any(windows, test))]
#[repr(C)]
struct WlanAssociationAttributes {
    ssid: Dot11Ssid,
    genre_bss: u32,
    bssid: [u8; 6],
    phy: u32,
    phy_index: u32,
    qualite: u32,
    reception: u32,
    emission: u32,
}

/// WLAN_SECURITY_ATTRIBUTES.
#[cfg(any(windows, test))]
#[repr(C)]
struct WlanSecurityAttributes {
    securise: i32,
    onex: i32,
    authentification: u32,
    chiffrement: u32,
}

/// WLAN_CONNECTION_ATTRIBUTES, rendue par WlanQueryInterface (wlan_intf_opcode_current_connection).
#[cfg(any(windows, test))]
#[repr(C)]
struct WlanConnectionAttributes {
    etat: u32,
    mode: u32,
    profil: [u16; 256],
    association: WlanAssociationAttributes,
    securite: WlanSecurityAttributes,
}

/// Les listes (WLAN_INTERFACE_INFO_LIST, WLAN_BSS_LIST, WLAN_PROFILE_INFO_LIST) : deux u32 d'en-tête, puis les
/// éléments.
#[cfg(any(windows, test))]
const ENTETE_LISTE: usize = 8;
/// WLAN_INTERFACE_STATE : wlan_interface_state_connected.
#[cfg(any(windows, test))]
const INTERFACE_CONNECTEE: u32 = 1;
/// Interfaces, profils et bornes lus au plus.
#[cfg(any(windows, test))]
const ELEMENTS_MAX: usize = 256;

/// Une interface Wi-Fi de Windows.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
struct Interface {
    guid: [u8; 16],
    connectee: bool,
}

#[cfg(any(windows, test))]
fn u16_a(octets: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*octets.get(pos..pos + 2)?.first_chunk::<2>()?))
}

#[cfg(any(windows, test))]
fn u32_a(octets: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*octets.get(pos..pos + 4)?.first_chunk::<4>()?))
}

/// Un texte UTF-16 terminé par un zéro, dans un champ de `n` caractères, prêt à montrer.
#[cfg(any(windows, test))]
fn texte_large(octets: &[u8], pos: usize, n: usize) -> Option<String> {
    let champ = octets.get(pos..pos + 2 * n)?;
    let mots: Vec<u16> = champ
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        // Jusqu'au zéro final, s'il y en a un.
        .take_while(|&m| m != 0)
        .collect();
    Some(affichable(&String::from_utf16_lossy(&mots)))
}

/// Un DOT11_SSID : sa longueur (32 au plus) et ses octets, prêt à montrer ; vide s'il est caché.
#[cfg(any(windows, test))]
fn ssid_a(octets: &[u8], pos: usize) -> Option<String> {
    let longueur = usize::try_from(u32_a(octets, pos)?).ok()?.min(32);
    let nom = octets.get(pos + 4..pos + 4 + longueur)?;
    if nom.iter().all(|&o| o == 0) {
        return Some(String::new());
    }
    Some(affichable(&String::from_utf8_lossy(nom)))
}

/// Le nombre d'éléments d'une liste, borné.
#[cfg(any(windows, test))]
fn compte(octets: &[u8], pos: usize) -> usize {
    u32_a(octets, pos)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0)
        .min(ELEMENTS_MAX)
}

/// Les interfaces d'un WLAN_INTERFACE_INFO_LIST copié.
#[cfg(any(windows, test))]
fn interfaces_de(octets: &[u8]) -> Vec<Interface> {
    (0..compte(octets, 0))
        .filter_map(|i| {
            let base = ENTETE_LISTE + i * size_of::<WlanInterfaceInfo>();
            let guid = octets.get(base..base + 16)?;
            let etat = u32_a(octets, base + offset_of!(WlanInterfaceInfo, etat))?;
            Some(Interface {
                guid: <[u8; 16]>::try_from(guid).ok()?,
                connectee: etat == INTERFACE_CONNECTEE,
            })
        })
        .collect()
}

/// Les bornes d'un WLAN_BSS_LIST copié : chaque entrée, puis ses éléments d'information, bornés au bloc.
#[cfg(any(windows, test))]
fn balises_de(octets: &[u8]) -> Vec<Balise> {
    (0..compte(octets, 4))
        .filter_map(|i| {
            let base = ENTETE_LISTE + i * size_of::<WlanBssEntry>();
            let ssid = ssid_a(octets, base + offset_of!(WlanBssEntry, ssid))?;
            let bssid = mac_texte(
                octets.get(base + offset_of!(WlanBssEntry, bssid)..base + offset_of!(WlanBssEntry, bssid) + 6)?,
            );
            let qualite = u32_a(octets, base + offset_of!(WlanBssEntry, qualite))?;
            let capacites = u16_a(octets, base + offset_of!(WlanBssEntry, capacites))?;
            let khz = u32_a(octets, base + offset_of!(WlanBssEntry, frequence_centrale_khz))?;
            let decalage = usize::try_from(u32_a(octets, base + offset_of!(WlanBssEntry, decalage_elements))?).ok()?;
            let taille = usize::try_from(u32_a(octets, base + offset_of!(WlanBssEntry, taille_elements))?).ok()?;
            // Les éléments suivent l'entrée dans le même bloc ; hors du bloc, ils ne sont pas lus (borne sans
            // protection connue, qu'on ne compte pas saine : ni RSN ni WPA la fait passer pour ouverte, ce que le
            // bit « Privacy » corrige en WEP au pire).
            let ies = base
                .checked_add(decalage)
                .and_then(|d| octets.get(d..d.checked_add(taille)?))
                .unwrap_or(&[]);
            let lus = elements::lire(ies, capacites);
            let mhz = khz / 1000;
            Some(Balise {
                borne: Borne {
                    ssid: if lus.ssid.is_empty() { ssid } else { lus.ssid },
                    bssid,
                    bande: Bande::de_frequence(mhz)?,
                    canal: canal_de_frequence(mhz)?,
                    signal: u8::try_from(qualite.min(100)).ok(),
                    actif: false,
                },
                protection: lus.protection,
                wps: lus.wps,
            })
        })
        .collect()
}

/// Le réseau connecté, d'après une WLAN_CONNECTION_ATTRIBUTES copiée ; `None` si l'interface n'est pas connectée.
#[cfg(any(windows, test))]
fn connexion_de(octets: &[u8]) -> Option<Connexion> {
    if u32_a(octets, offset_of!(WlanConnectionAttributes, etat))? != INTERFACE_CONNECTEE {
        return None;
    }
    let association = offset_of!(WlanConnectionAttributes, association);
    let ssid = ssid_a(octets, association + offset_of!(WlanAssociationAttributes, ssid))?;
    let debut = association + offset_of!(WlanAssociationAttributes, bssid);
    let qualite = u32_a(octets, association + offset_of!(WlanAssociationAttributes, qualite));
    let securite = offset_of!(WlanConnectionAttributes, securite);
    let champ = |decalage| u32_a(octets, securite + decalage);
    // Un bloc coupé avant la protection : rien de deviné, la balise la dira.
    let negociee = match (
        champ(offset_of!(WlanSecurityAttributes, authentification)),
        champ(offset_of!(WlanSecurityAttributes, chiffrement)),
    ) {
        (Some(a), Some(c)) => protection_negociee(a, c),
        _ => "",
    };
    Some(Connexion {
        ssid,
        bssid: mac_texte(octets.get(debut..debut + 6)?),
        qualite: qualite.and_then(|q| u8::try_from(q.min(100)).ok()),
        securite: negociee.to_string(),
        ..Connexion::default()
    })
}

/// La protection négociée (DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGORITHM), nommée comme `Protection::libelle` ; vide
/// si inconnue. Une borne WPA2/WPA3 annonce les deux dans sa balise, mais une carte sans WPA3 s'y connecte en WPA2.
#[cfg(any(windows, test))]
fn protection_negociee(authentification: u32, chiffrement: u32) -> &'static str {
    match authentification {
        // Système ouvert avec une clé WEP (WEP40, WEP104, WEP) : chiffré quand même.
        1 if matches!(chiffrement, 0x01 | 0x05 | 0x101) => "WEP",
        1 => crate::tr!("ouvert", "open"),
        2 => "WEP",
        3 => "WPA-Enterprise",
        4 => "WPA",
        6 => "WPA2-Enterprise",
        7 => "WPA2",
        8 | 11 => "WPA3-Enterprise",
        9 => "WPA3",
        10 => "OWE",
        _ => "",
    }
}

/// La bande d'après le seul canal, quand il n'y en a qu'une possible : les canaux 1, 5, 9 et 13 sont aussi des canaux
/// de 6 GHz, et Windows ne dit pas la fréquence de la connexion sans la liste des bornes.
#[cfg(any(windows, test))]
fn bande_sans_ambiguite(canal: u16) -> Option<Bande> {
    (![1, 5, 9, 13].contains(&canal))
        .then(|| Bande::de_canal(canal))
        .flatten()
}

/// Les noms des profils d'un WLAN_PROFILE_INFO_LIST copié.
#[cfg(any(windows, test))]
fn profils_de(octets: &[u8]) -> Vec<String> {
    (0..compte(octets, 0))
        .filter_map(|i| texte_large(octets, ENTETE_LISTE + i * size_of::<WlanProfileInfo>(), 256))
        .filter(|n| !n.is_empty())
        .collect()
}

/// Le contenu de la première balise `<nom>` d'un XML de profil, sans espaces autour.
#[cfg(any(windows, test))]
fn balise_xml<'a>(xml: &'a str, nom: &str) -> Option<&'a str> {
    let debut = xml.find(&format!("<{nom}>"))? + nom.len() + 2;
    let fin = xml[debut..].find(&format!("</{nom}>"))?;
    Some(xml[debut..debut + fin].trim())
}

/// Un profil Wi-Fi de Windows (le XML de WlanGetProfile) : son nom, s'il se reconnecte seul (`connectionMode`
/// « auto »), s'il est ouvert (authentification « open » et chiffrement « none » ; WEP et OWE ne sont pas ouverts).
/// La clé, chiffrée dans le XML, n'est jamais lue.
#[cfg(any(windows, test))]
pub(crate) fn profil_xml(xml: &str) -> Option<ProfilEnregistre> {
    let nom = affichable(balise_xml(xml, "name")?);
    if nom.is_empty() {
        return None;
    }
    let minuscules = |b: &str| balise_xml(xml, b).map(str::to_ascii_lowercase);
    let automatique = minuscules("connectionMode").as_deref() == Some("auto");
    let ouvert =
        minuscules("authentication").as_deref() == Some("open") && minuscules("encryption").as_deref() == Some("none");
    // Un nom qui porte un guillemet ou un retour casserait la commande montrée : ces caractères n'y entrent pas.
    let sur: String = nom.chars().filter(|c| !matches!(c, '"' | '\n' | '\r')).collect();
    Some(ProfilEnregistre {
        commande: format!("netsh wlan set profileparameter name=\"{sur}\" connectionmode=manual"),
        commande_sure: false,
        nom,
        automatique,
        ouvert,
    })
}

#[cfg(windows)]
mod natif {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    use super::{
        Balise, Connexion, ELEMENTS_MAX, ProfilEnregistre, balises_de, connexion_de, interfaces_de, profil_xml,
        profils_de,
    };
    use crate::machine::wifi::Lecture;
    use crate::tr;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(nom: *const u16, fichier: *mut c_void, drapeaux: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, nom: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }

    type Ouvrir = unsafe extern "system" fn(u32, *mut c_void, *mut u32, *mut *mut c_void) -> u32;
    type Fermer = unsafe extern "system" fn(*mut c_void, *mut c_void) -> u32;
    type Enumerer = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> u32;
    type Interroger = unsafe extern "system" fn(
        *mut c_void,
        *const u8,
        u32,
        *mut c_void,
        *mut u32,
        *mut *mut c_void,
        *mut u32,
    ) -> u32;
    type ListeBss = unsafe extern "system" fn(
        *mut c_void,
        *const u8,
        *const c_void,
        u32,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> u32;
    type ListeProfils = unsafe extern "system" fn(*mut c_void, *const u8, *mut c_void, *mut *mut c_void) -> u32;
    type Profil = unsafe extern "system" fn(
        *mut c_void,
        *const u8,
        *const u16,
        *mut c_void,
        *mut *mut u16,
        *mut u32,
        *mut u32,
    ) -> u32;
    type Liberer = unsafe extern "system" fn(*mut c_void);

    /// Au-delà, ce n'est plus une liste de bornes.
    const TAILLE_MAX: usize = 4 << 20;
    /// wlan_intf_opcode_current_connection.
    const CONNEXION_COURANTE: u32 = 7;
    /// wlan_intf_opcode_channel_number.
    const NUMERO_DE_CANAL: u32 = 8;
    /// dot11_BSS_type_any.
    const TOUT_GENRE_BSS: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;

    /// Les fonctions de wlanapi.dll, chargées à la demande.
    struct Api {
        module: *mut c_void,
        ouvrir: Ouvrir,
        fermer: Fermer,
        enumerer: Enumerer,
        interroger: Interroger,
        liste_bss: ListeBss,
        liste_profils: ListeProfils,
        profil: Profil,
        liberer: Liberer,
    }

    impl Drop for Api {
        fn drop(&mut self) {
            // SAFETY: le module vient de LoadLibraryExW et n'est libéré qu'ici, une fois ; plus aucun pointeur de
            // fonction n'est appelé après.
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }

    /// Wine installe ses propres programmes dans system32 ; wineboot.exe n'existe pas sur un vrai Windows. Ses
    /// fonctions WLAN sont des coquilles qui lèvent une exception : on ne les appelle pas.
    fn sous_wine() -> bool {
        let systeme = std::env::var_os("SystemRoot").map_or_else(|| "C:\\windows".into(), std::path::PathBuf::from);
        systeme.join("system32").join("wineboot.exe").is_file()
    }

    impl Api {
        /// `None` : la bibliothèque manque ou n'a pas toutes les fonctions (Windows Server sans la fonction WLAN).
        fn charger() -> Option<Api> {
            /// LOAD_LIBRARY_SEARCH_SYSTEM32.
            const CHERCHER_DANS_SYSTEM32: u32 = 0x800;
            let nom: Vec<u16> = "wlanapi.dll\0".encode_utf16().collect();
            // Seulement depuis System32 : wlanapi.dll n'est pas une « KnownDLL », et un LoadLibraryW par son seul nom
            // la chercherait d'abord dans le dossier de vanguard.exe (clé USB, Téléchargements), où n'importe qui peut
            // poser une fausse DLL qui s'exécuterait dans Vanguard.
            // SAFETY: le nom est terminé par un zéro ; chaque nom de fonction aussi ; aucun fichier n'est passé
            // (pointeur nul permis). Un pointeur nul est vérifié avant d'être converti ; les signatures sont celles
            // de wlanapi.h. Le module est libéré par Drop.
            unsafe {
                let module = LoadLibraryExW(nom.as_ptr(), std::ptr::null_mut(), CHERCHER_DANS_SYSTEM32);
                if module.is_null() {
                    return None;
                }
                let fonction = |nom: &[u8]| {
                    let p = GetProcAddress(module, nom.as_ptr());
                    (!p.is_null()).then_some(p)
                };
                let charge = (|| {
                    Some(Api {
                        module,
                        ouvrir: std::mem::transmute::<*mut c_void, Ouvrir>(fonction(b"WlanOpenHandle\0")?),
                        fermer: std::mem::transmute::<*mut c_void, Fermer>(fonction(b"WlanCloseHandle\0")?),
                        enumerer: std::mem::transmute::<*mut c_void, Enumerer>(fonction(b"WlanEnumInterfaces\0")?),
                        interroger: std::mem::transmute::<*mut c_void, Interroger>(fonction(b"WlanQueryInterface\0")?),
                        liste_bss: std::mem::transmute::<*mut c_void, ListeBss>(fonction(b"WlanGetNetworkBssList\0")?),
                        liste_profils: std::mem::transmute::<*mut c_void, ListeProfils>(fonction(
                            b"WlanGetProfileList\0",
                        )?),
                        profil: std::mem::transmute::<*mut c_void, Profil>(fonction(b"WlanGetProfile\0")?),
                        liberer: std::mem::transmute::<*mut c_void, Liberer>(fonction(b"WlanFreeMemory\0")?),
                    })
                })();
                if charge.is_none() {
                    FreeLibrary(module);
                }
                charge
            }
        }
    }

    /// Une session ouverte avec le service WLAN : la poignée est refermée une seule fois, à la fin.
    struct Session {
        api: Api,
        poignee: *mut c_void,
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // SAFETY: la poignée vient de WlanOpenHandle (non nulle, vérifié) et n'est refermée qu'ici.
            unsafe {
                (self.api.fermer)(self.poignee, null_mut());
            }
        }
    }

    impl Session {
        fn ouvrir() -> Result<Session, &'static str> {
            if sous_wine() {
                return Err(tr!(
                    "API Wi-Fi de Windows absente sous Wine",
                    "Windows Wi-Fi API missing under Wine"
                ));
            }
            let Some(api) = Api::charger() else {
                return Err(tr!(
                    "wlanapi.dll absente ou incomplète",
                    "wlanapi.dll missing or incomplete"
                ));
            };
            let (mut version, mut poignee) = (0u32, null_mut());
            // SAFETY: WlanOpenHandle écrit la version négociée et la poignée dans deux variables à nous.
            let code = unsafe { (api.ouvrir)(2, null_mut(), &raw mut version, &raw mut poignee) };
            if code != 0 || poignee.is_null() {
                return Err(tr!(
                    "le service WLAN de Windows est arrêté",
                    "the Windows WLAN service is stopped"
                ));
            }
            Ok(Session { api, poignee })
        }

        /// Copie un bloc rendu par l'API (`n` octets) puis le libère. SAFETY exigée de l'appelant : `bloc` vient
        /// d'une fonction WLAN qui a réussi et couvre au moins `n` octets.
        unsafe fn prendre(&self, bloc: *mut c_void, n: usize) -> Vec<u8> {
            // SAFETY: voir ci-dessus ; le bloc n'est libéré qu'ici, une fois, par la fonction de l'API.
            unsafe {
                let copie = std::slice::from_raw_parts(bloc.cast::<u8>(), n).to_vec();
                (self.api.liberer)(bloc);
                copie
            }
        }

        /// Une liste à en-tête (nombre, index) : copiée sur l'en-tête et ses éléments, bornés.
        /// SAFETY exigée de l'appelant : `bloc` vient d'une fonction WLAN qui a réussi et rend une liste à en-tête
        /// (8 octets) suivie d'éléments de `taille_element` octets.
        unsafe fn prendre_liste(&self, bloc: *mut c_void, taille_element: usize) -> Vec<u8> {
            // SAFETY: l'API garantit l'en-tête et `n` éléments entiers dans le bloc.
            unsafe {
                let n = usize::try_from(std::ptr::read_unaligned(bloc.cast::<u32>()))
                    .unwrap_or(0)
                    .min(ELEMENTS_MAX);
                self.prendre(bloc, 8 + n * taille_element)
            }
        }

        fn interfaces(&self) -> Vec<super::Interface> {
            let mut liste = null_mut();
            // SAFETY: WlanEnumInterfaces rend une WLAN_INTERFACE_INFO_LIST (vérifiée non nulle) que `prendre_liste`
            // copie et libère.
            unsafe {
                if (self.api.enumerer)(self.poignee, null_mut(), &raw mut liste) != 0 || liste.is_null() {
                    return Vec::new();
                }
                interfaces_de(&self.prendre_liste(liste, std::mem::size_of::<super::WlanInterfaceInfo>()))
            }
        }

        /// Le réseau connecté d'une interface ; `Err` : le code de Windows (ERROR_ACCESS_DENIED sans l'autorisation
        /// de localisation, depuis Windows 11 24H2).
        fn connexion(&self, guid: &[u8; 16]) -> Result<Option<Connexion>, u32> {
            let (mut taille, mut donnees, mut genre) = (0u32, null_mut(), 0u32);
            // SAFETY: WlanQueryInterface écrit la taille et le bloc (vérifié non nul) ; copié sur `taille` octets,
            // au plus la structure attendue, puis libéré.
            let connexion = unsafe {
                let code = (self.api.interroger)(
                    self.poignee,
                    guid.as_ptr(),
                    CONNEXION_COURANTE,
                    null_mut(),
                    &raw mut taille,
                    &raw mut donnees,
                    &raw mut genre,
                );
                if code != 0 || donnees.is_null() {
                    return if code == 0 { Ok(None) } else { Err(code) };
                }
                let n = usize::try_from(taille)
                    .unwrap_or(0)
                    .min(std::mem::size_of::<super::WlanConnectionAttributes>());
                connexion_de(&self.prendre(donnees, n))
            };
            Ok(connexion.map(|c| Connexion {
                canal: self.canal(guid),
                ..c
            }))
        }

        /// Le canal de la connexion (wlan_intf_opcode_channel_number, un ULONG).
        fn canal(&self, guid: &[u8; 16]) -> Option<u16> {
            let (mut taille, mut donnees, mut genre) = (0u32, null_mut(), 0u32);
            // SAFETY: comme `connexion` ; le bloc n'est lu que s'il couvre les 4 octets d'un ULONG.
            unsafe {
                let code = (self.api.interroger)(
                    self.poignee,
                    guid.as_ptr(),
                    NUMERO_DE_CANAL,
                    null_mut(),
                    &raw mut taille,
                    &raw mut donnees,
                    &raw mut genre,
                );
                if code != 0 || donnees.is_null() {
                    return None;
                }
                let n = usize::try_from(taille).unwrap_or(0).min(4);
                let octets = self.prendre(donnees, n);
                super::u32_a(&octets, 0)
                    .and_then(|c| u16::try_from(c).ok())
                    .filter(|&c| c > 0)
            }
        }

        /// Les bornes d'une interface ; `Err` si Windows refuse (sans l'autorisation de localisation, depuis
        /// Windows 11 24H2).
        fn balises(&self, guid: &[u8; 16]) -> Result<Vec<Balise>, u32> {
            let mut liste = null_mut();
            // SAFETY: WlanGetNetworkBssList rend une WLAN_BSS_LIST (vérifiée non nulle) dont le premier u32 est la
            // taille totale du bloc : copié sur cette taille, bornée, puis libéré.
            unsafe {
                let code = (self.api.liste_bss)(
                    self.poignee,
                    guid.as_ptr(),
                    null(),
                    TOUT_GENRE_BSS,
                    0,
                    null_mut(),
                    &raw mut liste,
                );
                if code != 0 || liste.is_null() {
                    return Err(code);
                }
                let total = usize::try_from(std::ptr::read_unaligned(liste.cast::<u32>())).unwrap_or(8);
                Ok(balises_de(&self.prendre(liste, total.clamp(8, TAILLE_MAX))))
            }
        }

        fn profils(&self, guid: &[u8; 16]) -> Vec<ProfilEnregistre> {
            let mut liste = null_mut();
            // SAFETY: WlanGetProfileList rend une WLAN_PROFILE_INFO_LIST (vérifiée non nulle), copiée et libérée ;
            // WlanGetProfile rend un texte UTF-16 terminé par un zéro (vérifié non nul), lu jusqu'au zéro, au plus
            // 64 Ki caractères, puis libéré. Le nom passé est terminé par un zéro.
            unsafe {
                if (self.api.liste_profils)(self.poignee, guid.as_ptr(), null_mut(), &raw mut liste) != 0
                    || liste.is_null()
                {
                    return Vec::new();
                }
                let noms = profils_de(&self.prendre_liste(liste, std::mem::size_of::<super::WlanProfileInfo>()));
                noms.iter()
                    .take(64)
                    .filter_map(|nom| {
                        let large: Vec<u16> = nom.encode_utf16().chain(std::iter::once(0)).collect();
                        let (mut xml, mut drapeaux, mut acces) = (null_mut::<u16>(), 0u32, 0u32);
                        let code = (self.api.profil)(
                            self.poignee,
                            guid.as_ptr(),
                            large.as_ptr(),
                            null_mut(),
                            &raw mut xml,
                            &raw mut drapeaux,
                            &raw mut acces,
                        );
                        if code != 0 || xml.is_null() {
                            return None;
                        }
                        let mut mots = Vec::new();
                        while mots.len() < 65_536 {
                            let m = std::ptr::read_unaligned(xml.add(mots.len()));
                            if m == 0 {
                                break;
                            }
                            mots.push(m);
                        }
                        (self.api.liberer)(xml.cast());
                        profil_xml(&String::from_utf16_lossy(&mots))
                    })
                    .collect()
            }
        }
    }

    /// Les bornes que Windows a entendues et le réseau connecté. `Err` : pas de Wi-Fi, service arrêté, API absente.
    pub(crate) fn lire() -> Result<Lecture, &'static str> {
        let session = Session::ouvrir()?;
        let interfaces = session.interfaces();
        if interfaces.is_empty() {
            return Err(pas_de_carte());
        }
        let mut lecture = Lecture::default();
        let mut refus = false;
        for i in &interfaces {
            if i.connectee && lecture.connexion.is_none() {
                match session.connexion(&i.guid) {
                    Ok(c) => lecture.connexion = c,
                    Err(ERROR_ACCESS_DENIED) => refus = true,
                    Err(_) => {}
                }
            }
            match session.balises(&i.guid) {
                Ok(bornes) => {
                    for b in bornes {
                        if !lecture
                            .balises
                            .iter()
                            .any(|d| d.borne.bssid == b.borne.bssid && d.borne.canal == b.borne.canal)
                        {
                            lecture.balises.push(b);
                        }
                    }
                }
                Err(ERROR_ACCESS_DENIED) => refus = true,
                Err(_) => {}
            }
        }
        if let Some(c) = &mut lecture.connexion {
            for b in &mut lecture.balises {
                b.borne.actif = !c.bssid.is_empty() && b.borne.bssid == c.bssid;
            }
            // La bande de la borne de la connexion ; sans elle, d'après le canal, sauf un canal que le 6 GHz réutilise.
            c.bande = lecture
                .balises
                .iter()
                .find(|b| b.borne.actif)
                .map(|b| b.borne.bande)
                .or_else(|| c.canal.and_then(super::bande_sans_ambiguite));
        }
        // Windows 11 24H2 ne liste les réseaux qu'avec l'autorisation de localisation.
        if refus || (lecture.balises.is_empty() && interfaces.iter().any(|i| i.connectee)) {
            lecture.note = Some(tr!(
                "Windows ne montre les réseaux Wi-Fi qu'avec la localisation : Paramètres > Confidentialité et sécurité > Localisation, autoriser les applications de bureau",
                "Windows shows Wi-Fi networks only with location access: Settings > Privacy & security > Location, allow desktop apps"
            ));
        }
        Ok(lecture)
    }

    /// Les cartes Wi-Fi de cet ordinateur, connectée ou non chacune : WlanEnumInterfaces ne demande pas la
    /// localisation, là où netsh (Windows 11 24H2) cache le réseau connecté sans elle. Le bilan y distingue « pas de
    /// carte » ou « pas connecté » (sans objet) d'un réseau qu'il ne voit pas (non vérifié). `Err` : API absente.
    pub(crate) fn cartes() -> Result<Vec<bool>, &'static str> {
        Ok(Session::ouvrir()?.interfaces().iter().map(|i| i.connectee).collect())
    }

    fn pas_de_carte() -> &'static str {
        tr!(
            "pas de carte Wi-Fi sur cet ordinateur",
            "no Wi-Fi card on this computer"
        )
    }

    /// Le réseau connecté seul, sans la liste des bornes : son nom, sa qualité, son canal. `Ok(None)` : pas
    /// connecté ; `Err` : pas de Wi-Fi, service arrêté, API absente, ou Windows refuse sans la localisation.
    pub(crate) fn connexion() -> Result<Option<Connexion>, &'static str> {
        let session = Session::ouvrir()?;
        let interfaces = session.interfaces();
        if interfaces.is_empty() {
            return Err(pas_de_carte());
        }
        let mut erreur = None;
        for i in interfaces.iter().filter(|i| i.connectee) {
            match session.connexion(&i.guid) {
                Ok(Some(c)) => {
                    // La bande de la borne de la connexion dans la liste, quand Windows la donne ; sinon d'après le
                    // canal, sauf s'il est aussi un canal de 6 GHz.
                    let bande = session
                        .balises(&i.guid)
                        .ok()
                        .and_then(|b| b.into_iter().find(|b| !c.bssid.is_empty() && b.borne.bssid == c.bssid))
                        .map(|b| b.borne.bande)
                        .or_else(|| c.canal.and_then(super::bande_sans_ambiguite));
                    return Ok(Some(Connexion { bande, ..c }));
                }
                Err(ERROR_ACCESS_DENIED) => {
                    return Err(tr!(
                        "Windows ne dit le réseau connecté qu'avec la localisation",
                        "Windows tells the connected network only with location access"
                    ));
                }
                Ok(None) => {}
                // Une carte connectée qui ne se lit pas : « pas connecté » ne serait pas prouvé.
                Err(_) => {
                    erreur.get_or_insert(tr!(
                        "Windows ne dit pas le réseau connecté",
                        "Windows does not tell the connected network"
                    ));
                }
            }
        }
        erreur.map_or(Ok(None), Err)
    }

    /// Les profils Wi-Fi enregistrés de toutes les cartes. `Err` : API absente ou service arrêté.
    pub(crate) fn profils() -> Result<Vec<ProfilEnregistre>, &'static str> {
        let session = Session::ouvrir()?;
        let mut tous = Vec::new();
        for i in session.interfaces() {
            for p in session.profils(&i.guid) {
                if !tous.iter().any(|t: &ProfilEnregistre| t.nom == p.nom) {
                    tous.push(p);
                }
            }
        }
        Ok(tous)
    }
}

#[cfg(windows)]
pub(crate) use natif::{cartes, connexion, lire, profils};

#[cfg(test)]
mod tests {
    use super::super::elements::fabrique;
    use super::*;

    /// Les structures ont la taille et les décalages de wlanapi.h : un champ de trop ou de moins décalerait tout.
    #[test]
    fn structures_au_format_de_windows() {
        assert_eq!(size_of::<Dot11Ssid>(), 36);
        assert_eq!(size_of::<WlanInterfaceInfo>(), 532);
        assert_eq!(offset_of!(WlanInterfaceInfo, etat), 528);
        assert_eq!(size_of::<WlanBssEntry>(), 360);
        assert_eq!(offset_of!(WlanBssEntry, bssid), 40);
        assert_eq!(offset_of!(WlanBssEntry, rssi), 56);
        assert_eq!(offset_of!(WlanBssEntry, qualite), 60);
        assert_eq!(offset_of!(WlanBssEntry, horodatage), 72);
        assert_eq!(offset_of!(WlanBssEntry, capacites), 88);
        assert_eq!(offset_of!(WlanBssEntry, frequence_centrale_khz), 92);
        assert_eq!(offset_of!(WlanBssEntry, debits), 96);
        assert_eq!(offset_of!(WlanBssEntry, decalage_elements), 352);
        assert_eq!(offset_of!(WlanBssEntry, taille_elements), 356);
        assert_eq!(size_of::<WlanProfileInfo>(), 516);
        assert_eq!(size_of::<WlanAssociationAttributes>(), 68);
        assert_eq!(offset_of!(WlanAssociationAttributes, bssid), 40);
        assert_eq!(size_of::<WlanSecurityAttributes>(), 16);
        assert_eq!(size_of::<WlanConnectionAttributes>(), 604);
        assert_eq!(offset_of!(WlanConnectionAttributes, association), 520);
        // La qualité et la protection de la connexion, lues à ces places dans le bloc copié.
        let association = offset_of!(WlanConnectionAttributes, association);
        assert_eq!(association + offset_of!(WlanAssociationAttributes, qualite), 576);
        let securite = offset_of!(WlanConnectionAttributes, securite);
        assert_eq!(securite + offset_of!(WlanSecurityAttributes, securise), 588);
        assert_eq!(securite + offset_of!(WlanSecurityAttributes, authentification), 596);
        assert_eq!(securite + offset_of!(WlanSecurityAttributes, chiffrement), 600);
    }

    /// Le canal seul ne donne une bande que s'il n'est pas aussi un canal de 6 GHz.
    #[test]
    fn bande_d_apres_le_canal() {
        assert_eq!(bande_sans_ambiguite(6), Some(Bande::G24));
        assert_eq!(bande_sans_ambiguite(36), Some(Bande::G5));
        for canal in [1, 5, 9, 13] {
            assert_eq!(bande_sans_ambiguite(canal), None, "{canal}");
        }
        assert_eq!(bande_sans_ambiguite(0), None);
    }

    fn liste(n: u32, elements: &[Vec<u8>]) -> Vec<u8> {
        let mut l = n.to_le_bytes().to_vec();
        l.extend_from_slice(&0u32.to_le_bytes());
        for e in elements {
            l.extend_from_slice(e);
        }
        l
    }

    fn texte_utf16(t: &str, n: usize) -> Vec<u8> {
        let mut mots: Vec<u16> = t.encode_utf16().collect();
        mots.resize(n, 0);
        mots.iter().flat_map(|m| m.to_le_bytes()).collect()
    }

    fn dot11_ssid(nom: &str) -> Vec<u8> {
        let mut s = u32::try_from(nom.len()).unwrap().to_le_bytes().to_vec();
        s.extend_from_slice(nom.as_bytes());
        s.resize(36, 0);
        s
    }

    fn interface(guid: u8, etat: u32) -> Vec<u8> {
        let mut i = vec![guid; 16];
        i.extend(texte_utf16("Intel(R) Wi-Fi 6", 256));
        i.extend_from_slice(&etat.to_le_bytes());
        i
    }

    /// Une WLAN_BSS_ENTRY sans ses éléments (placés par `liste_bss`).
    fn entree(nom: &str, bssid: [u8; 6], khz: u32, qualite: u32, capacites: u16) -> Vec<u8> {
        let mut e = vec![0u8; 360];
        e[..36].copy_from_slice(&dot11_ssid(nom));
        e[40..46].copy_from_slice(&bssid);
        e[56..60].copy_from_slice(&(-60i32).to_le_bytes());
        e[60..64].copy_from_slice(&qualite.to_le_bytes());
        e[88..90].copy_from_slice(&capacites.to_le_bytes());
        e[92..96].copy_from_slice(&khz.to_le_bytes());
        e
    }

    /// Une WLAN_BSS_LIST comme Windows l'écrit : l'en-tête (taille totale, nombre), les entrées à la suite, puis
    /// les éléments de chacune, désignés par leur décalage depuis le début de leur entrée.
    fn liste_bss(entrees: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut bloc = vec![0u8; 8];
        let mut elements = Vec::new();
        let fin_entrees = 8 + 360 * entrees.len();
        for (i, (e, ies)) in entrees.iter().enumerate() {
            let mut e = e.clone();
            let base = 8 + 360 * i;
            let position = fin_entrees + elements.len();
            e[352..356].copy_from_slice(&u32::try_from(position - base).unwrap().to_le_bytes());
            e[356..360].copy_from_slice(&u32::try_from(ies.len()).unwrap().to_le_bytes());
            bloc.extend_from_slice(&e);
            elements.extend_from_slice(ies);
        }
        bloc.extend(elements);
        let total = u32::try_from(bloc.len()).unwrap();
        bloc[0..4].copy_from_slice(&total.to_le_bytes());
        bloc[4..8].copy_from_slice(&u32::try_from(entrees.len()).unwrap().to_le_bytes());
        bloc
    }

    #[test]
    fn interfaces_lues() {
        let octets = liste(2, &[interface(1, 1), interface(2, 4)]);
        assert_eq!(
            interfaces_de(&octets),
            [
                Interface {
                    guid: [1; 16],
                    connectee: true
                },
                Interface {
                    guid: [2; 16],
                    connectee: false
                }
            ]
        );
        // Un nombre qui dépasse le bloc : seules les interfaces entières sont lues.
        assert_eq!(interfaces_de(&liste(5, &[interface(1, 1)])).len(), 1);
        assert_eq!(interfaces_de(&[]), [] as [Interface; 0]);
    }

    #[test]
    fn bornes_lues_avec_leurs_elements() {
        let bloc = liste_bss(&[
            (
                entree("Salon", [2, 0, 0, 0xAA, 0xBB, 1], 5_180_000, 80, 0x0411),
                fabrique::box_ordinaire("Salon"),
            ),
            (
                entree("Voisin", [2, 0, 0, 0xAA, 0xBB, 2], 2_437_000, 150, 0x0411),
                [fabrique::ssid("Voisin"), fabrique::rsn(2, &[2, 4], &[2], 0)].concat(),
            ),
            (
                entree("Café", [2, 0, 0, 0xAA, 0xBB, 3], 2_412_000, 10, 0x0401),
                Vec::new(),
            ),
        ]);
        let b = balises_de(&bloc);
        assert_eq!(b.len(), 3);
        assert_eq!(b[0].borne.ssid, "Salon");
        assert_eq!(b[0].borne.bssid, "02:00:00:aa:bb:01");
        assert_eq!(
            (b[0].borne.bande, b[0].borne.canal, b[0].borne.signal),
            (Bande::G5, 36, Some(80))
        );
        assert!(b[0].protection.rsn && b[0].protection.aes && !b[0].borne.actif);
        assert_eq!(b[0].wps.map(|w| w.etat), Some(2));
        assert!(b[1].protection.tkip && b[1].wps.is_none());
        assert_eq!((b[1].borne.canal, b[1].borne.signal), (6, Some(100)));
        // Sans éléments : le nom de l'entrée, la protection d'après les capacités (ouvert ici).
        assert_eq!(b[2].borne.ssid, "Café");
        assert_eq!(b[2].protection.force(), 0);
        // Un décalage hors du bloc : le nom de l'entrée, et le bit « Privacy » seul dit WEP.
        let mut bloc = liste_bss(&[(
            entree("Vieux", [2, 0, 0, 0xAA, 0xBB, 2], 2_437_000, 150, 0x0011),
            Vec::new(),
        )]);
        bloc[8 + 352..8 + 356].copy_from_slice(&4_000_000u32.to_le_bytes());
        bloc[8 + 356..8 + 360].copy_from_slice(&10u32.to_le_bytes());
        let b = balises_de(&bloc);
        assert_eq!(b[0].borne.ssid, "Vieux");
        assert_eq!(b[0].protection.libelle(), "WEP");
        assert_eq!(b[0].borne.canal, 6);
        // Une fréquence inconnue : pas de borne ; un nom caché : vide ; un nom piégé : inoffensif.
        let hors_bande = liste_bss(&[(entree("X", [2, 0, 0, 0xAA, 0xBB, 3], 900_000, 10, 0), Vec::new())]);
        assert_eq!(balises_de(&hors_bande), [] as [Balise; 0]);
        let cache = liste_bss(&[(entree("\0\0\0", [2, 0, 0, 0xAA, 0xBB, 3], 2_412_000, 10, 0), Vec::new())]);
        assert_eq!(balises_de(&cache)[0].borne.ssid, "");
        let piege = liste_bss(&[(
            entree("Salon\x1b[2K", [2, 0, 0, 0xAA, 0xBB, 3], 2_412_000, 10, 0),
            Vec::new(),
        )]);
        assert_eq!(balises_de(&piege)[0].borne.ssid, "Salon�[2K");
    }

    #[test]
    fn connexion_et_profils_lus() {
        let mut c = vec![0u8; 604];
        c[0..4].copy_from_slice(&1u32.to_le_bytes());
        c[520..556].copy_from_slice(&dot11_ssid("Salon"));
        c[560..566].copy_from_slice(&[2, 0, 0, 0xAA, 0xBB, 1]);
        c[576..580].copy_from_slice(&72u32.to_le_bytes());
        c[588..592].copy_from_slice(&1u32.to_le_bytes());
        c[596..600].copy_from_slice(&7u32.to_le_bytes());
        c[600..604].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            connexion_de(&c),
            Some(Connexion {
                ssid: "Salon".into(),
                bssid: "02:00:00:aa:bb:01".into(),
                qualite: Some(72),
                securite: "WPA2".into(),
                ..Connexion::default()
            })
        );
        // Connectée en WPA2 (RSNA_PSK, CCMP) à une borne qui annonce aussi WPA3 : WPA2.
        assert_eq!(super::super::force(protection_negociee(9, 4)), 3);
        assert_eq!(protection_negociee(1, 0x101), "WEP");
        assert_eq!(super::super::force(protection_negociee(1, 0)), 0);
        assert_eq!(protection_negociee(5, 0), "");
        // Une qualité démesurée est bornée ; un bloc coupé avant la protection garde le nom, sans protection.
        c[576..580].copy_from_slice(&500u32.to_le_bytes());
        assert_eq!(connexion_de(&c).and_then(|c| c.qualite), Some(100));
        assert_eq!(connexion_de(&c[..598]).map(|c| c.securite), Some(String::new()));
        c[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(connexion_de(&c), None);
        assert_eq!(connexion_de(&c[..100]), None);
        let mut p1 = texte_utf16("Salon", 256);
        p1.extend_from_slice(&0u32.to_le_bytes());
        let mut p2 = texte_utf16("Café\x1b[2K", 256);
        p2.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(profils_de(&liste(2, &[p1, p2])), ["Salon", "Café�[2K"]);
    }

    #[test]
    fn profil_xml_lu() {
        let xml = |mode: &str, auth: &str, chiffrement: &str| {
            format!(
                "<?xml version=\"1.0\"?>\r\n<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\r\n\t<name>Café du coin</name>\r\n\t<SSIDConfig>\r\n\t\t<SSID>\r\n\t\t\t<hex>43616665</hex>\r\n\t\t\t<name>Cafe</name>\r\n\t\t</SSID>\r\n\t</SSIDConfig>\r\n\t<connectionType>ESS</connectionType>\r\n\t<connectionMode>{mode}</connectionMode>\r\n\t<MSM>\r\n\t\t<security>\r\n\t\t\t<authEncryption>\r\n\t\t\t\t<authentication>{auth}</authentication>\r\n\t\t\t\t<encryption>{chiffrement}</encryption>\r\n\t\t\t\t<useOneX>false</useOneX>\r\n\t\t\t</authEncryption>\r\n\t\t\t<sharedKey><keyType>passPhrase</keyType><protected>true</protected><keyMaterial>AQAAANCM</keyMaterial></sharedKey>\r\n\t\t</security>\r\n\t</MSM>\r\n</WLANProfile>"
            )
        };
        let p = profil_xml(&xml("auto", "open", "none")).unwrap();
        assert_eq!(p.nom, "Café du coin");
        assert!(p.automatique && p.ouvert && !p.commande_sure);
        assert_eq!(
            p.commande,
            "netsh wlan set profileparameter name=\"Café du coin\" connectionmode=manual"
        );
        assert!(!p.commande.contains("AQAAANCM"));
        let p = profil_xml(&xml("manual", "open", "none")).unwrap();
        assert!(!p.automatique && p.ouvert);
        assert!(!profil_xml(&xml("auto", "WPA2PSK", "AES")).unwrap().ouvert);
        assert!(!profil_xml(&xml("auto", "open", "WEP")).unwrap().ouvert);
        assert!(!profil_xml(&xml("auto", "OWE", "AES")).unwrap().ouvert);
        assert_eq!(profil_xml("<WLANProfile></WLANProfile>"), None);
        assert_eq!(profil_xml("<WLANProfile><name> </name></WLANProfile>"), None);
        // Un nom piégé n'entre ni dans le message ni dans la commande montrée.
        let p = profil_xml("<name>Gare\" & del \x1b[2K\n*</name><connectionMode>auto</connectionMode>").unwrap();
        assert!(!crate::ui::contient_un_piege(&p.nom));
        assert_eq!(p.commande.matches('"').count(), 2);
        assert!(!p.commande.contains('\n'));
    }

    #[test]
    fn blocs_abimes_sans_plantage() {
        let bloc = liste_bss(&[(
            entree("Salon", [2, 0, 0, 0xAA, 0xBB, 1], 5_180_000, 80, 0x0411),
            fabrique::box_ordinaire("Salon"),
        )]);
        for n in 0..bloc.len() {
            let _ = balises_de(&bloc[..n]);
            let _ = interfaces_de(&bloc[..n]);
            let _ = profils_de(&bloc[..n]);
            let _ = connexion_de(&bloc[..n]);
        }
        // Un nombre d'éléments démesuré ne lit que ce que le bloc contient.
        assert_eq!(balises_de(&liste(u32::MAX, &[])), [] as [Balise; 0]);
    }

    /// Sous Wine, l'API n'est pas appelée (ses fonctions sont des coquilles) : « non vérifié », sans planter. Sur un
    /// vrai Windows, ce qui est lu se tient.
    #[cfg(windows)]
    #[test]
    fn lecture_native_sous_wine() {
        match lire() {
            Ok(l) => {
                for b in &l.balises {
                    assert_eq!(b.borne.bssid.len(), 17);
                    assert!(!crate::ui::contient_un_piege(&b.borne.ssid));
                }
            }
            Err(raison) => assert_ne!(raison, ""),
        }
        if let Ok(p) = profils() {
            assert!(p.iter().all(|p| !crate::ui::contient_un_piege(&p.nom)));
        }
    }
}
