//! Les réseaux Wi-Fi enregistrés sur cet ordinateur, ceux auxquels il se reconnecte tout seul, lus dans les fichiers
//! du système sans lancer nmcli, iwctl ni networksetup : NetworkManager (`/etc/NetworkManager/system-connections`,
//! un fichier clé par connexion, plus ceux de `/run` et `/usr/lib` : netplan, profils fournis), iwd (`/var/lib/iwd`, un fichier par réseau, nommé d'après lui), macOS
//! (`com.apple.wifi.known-networks.plist`). Ces fichiers n'appartiennent qu'à l'administrateur : sans ses droits,
//! c'est « non vérifié », et le bilan de la machine garde sa lecture par nmcli. Windows lit les siens par l'API WLAN
//! (wlanapi.rs). Les lecteurs sont purs ; seuls `lire_linux` et `lire_macos` touchent le disque.

use crate::ui::affichable;

/// Un réseau enregistré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfilEnregistre {
    pub nom: String,
    /// Se reconnecte tout seul.
    pub automatique: bool,
    /// Sans aucune protection (ni WPA, ni WEP, ni OWE).
    pub ouvert: bool,
    /// La commande qui coupe la reconnexion automatique, à montrer ou à lancer.
    pub commande: String,
    /// La commande peut être lancée telle quelle : ce qu'elle reprend du profil a une forme sûre (un UUID). Sinon,
    /// elle est montrée, à lancer soi-même.
    pub commande_sure: bool,
}

/// Fichiers lus au plus par dossier (et réseaux connus d'un Mac).
#[cfg(any(target_os = "linux", target_os = "macos", test))]
const FICHIERS_MAX: usize = 200;
/// Taille lue au plus par fichier.
#[cfg(target_os = "linux")]
const TAILLE_MAX: u64 = 64 * 1024;

/// Les paires clé = valeur d'un fichier INI (fichier clé de NetworkManager, réglages d'iwd), avec leur section :
/// (section, clé, valeur), sans commentaires ni espaces autour.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ini(texte: &str) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut paires = Vec::new();
    for ligne in texte.lines().map(str::trim) {
        if ligne.is_empty() || ligne.starts_with('#') || ligne.starts_with(';') {
            continue;
        }
        if let Some(nom) = ligne.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = nom.trim().to_string();
        } else if let Some((cle, valeur)) = ligne.split_once('=') {
            paires.push((section.clone(), cle.trim().to_string(), valeur.trim().to_string()));
        }
    }
    paires
}

/// La valeur d'une clé d'une section.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn valeur<'a>(paires: &'a [(String, String, String)], section: &str, cle: &str) -> Option<&'a str> {
    paires
        .iter()
        .find(|(s, c, _)| s == section && c == cle)
        .map(|(_, _, v)| v.as_str())
}

/// Un fichier clé de NetworkManager : une connexion Wi-Fi (`type=wifi`), son nom (`id`), son UUID, `autoconnect`
/// (vrai par défaut), et sa protection : sans section `[wifi-security]` ou sans `key-mgmt`, le réseau est ouvert
/// (« none » est du WEP, « owe » du Wi-Fi ouvert chiffré : pas ouverts). `None` : pas une connexion Wi-Fi, ou un UUID
/// qui n'a pas sa forme (il entre dans une commande).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn nm_keyfile(texte: &str) -> Option<ProfilEnregistre> {
    let paires = ini(texte);
    if !matches!(valeur(&paires, "connection", "type"), Some("wifi" | "802-11-wireless")) {
        return None;
    }
    let uuid = valeur(&paires, "connection", "uuid")?;
    if uuid.len() != 36 || !uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return None;
    }
    let nom = valeur(&paires, "connection", "id")
        .or_else(|| valeur(&paires, "wifi", "ssid"))
        .map(affichable)
        .filter(|n| !n.is_empty())?;
    let automatique = !matches!(valeur(&paires, "connection", "autoconnect"), Some("false" | "no" | "0"));
    let ouvert = valeur(&paires, "wifi-security", "key-mgmt").is_none_or(str::is_empty);
    Some(ProfilEnregistre {
        nom,
        automatique,
        ouvert,
        commande: format!("nmcli connection modify {uuid} connection.autoconnect no"),
        commande_sure: true,
    })
}

/// Le nom d'un réseau d'après le nom de son fichier iwd : tel quel quand il ne contient que des lettres, chiffres,
/// espaces, « _ » et « - » ; sinon « = » suivi de ses octets en hexadécimal.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nom_iwd(base: &str) -> Option<String> {
    let nom = match base.strip_prefix('=') {
        Some(hex) => {
            let octets: Option<Vec<u8>> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
                .collect();
            String::from_utf8_lossy(&octets?).into_owned()
        }
        None => base.to_string(),
    };
    Some(affichable(&nom)).filter(|n| !n.is_empty())
}

/// Un réseau d'iwd : le fichier `<nom>.open`, `.psk` ou `.8021x` dit sa protection ; `[Settings] AutoConnect=false`
/// coupe la reconnexion. `None` : pas un fichier de réseau.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn iwd(nom_fichier: &str, texte: &str) -> Option<ProfilEnregistre> {
    let (base, extension) = nom_fichier.rsplit_once('.')?;
    if !matches!(extension, "open" | "psk" | "8021x") {
        return None;
    }
    let nom = nom_iwd(base)?;
    let paires = ini(texte);
    let automatique = !matches!(
        valeur(&paires, "Settings", "AutoConnect")
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("false" | "no" | "0")
    );
    let sur: String = nom.chars().filter(|c| !matches!(c, '"' | '\n' | '\r')).collect();
    Some(ProfilEnregistre {
        nom,
        automatique,
        ouvert: extension == "open",
        commande: format!("iwctl known-networks \"{sur}\" set-property AutoConnect no"),
        commande_sure: false,
    })
}

/// Les réseaux connus d'un Mac, dans `com.apple.wifi.known-networks.plist` (macOS 11 et après : une entrée
/// « wifi.network.ssid.<nom> » par réseau, `SecurityType` « Open » pour un réseau ouvert, `AutoJoinDisabled` quand la
/// reconnexion est coupée) ou l'ancien `com.apple.airport.preferences.plist` (dictionnaire `KnownNetworks`,
/// `SSIDString`, `SecurityType`, `Disabled`). Les deux clés de reconnexion sont tolérées : absentes, le Mac rejoint
/// le réseau tout seul.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn connus_macos(plist: &crate::plist::Valeur) -> Vec<ProfilEnregistre> {
    use crate::plist::Valeur;
    let entrees: Vec<(&str, &Valeur)> = match plist {
        Valeur::Dico(paires) => match plist.cle("KnownNetworks") {
            Some(Valeur::Dico(anciens)) => anciens.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            _ => paires
                .iter()
                .filter(|(k, _)| k.starts_with("wifi.network.ssid."))
                .map(|(k, v)| (k.as_str(), v))
                .collect(),
        },
        _ => Vec::new(),
    };
    let booleen = |v: &Valeur, cle: &str| match v.cle(cle) {
        Some(Valeur::Booleen(b)) => Some(*b),
        Some(Valeur::Entier(n)) => Some(*n != 0),
        _ => None,
    };
    entrees
        .into_iter()
        .take(FICHIERS_MAX)
        .filter_map(|(cle, v)| {
            let nom = match (v.cle("SSIDString").and_then(Valeur::texte), v.cle("SSID")) {
                (Some(t), _) => t.to_string(),
                (None, Some(Valeur::Donnees(octets))) => String::from_utf8_lossy(octets).into_owned(),
                (None, Some(Valeur::Texte(t))) => t.clone(),
                _ => cle.strip_prefix("wifi.network.ssid.").unwrap_or(cle).to_string(),
            };
            let nom = affichable(&nom);
            if nom.is_empty() {
                return None;
            }
            let securite = v.cle("SecurityType").and_then(Valeur::texte).unwrap_or("");
            let ouvert = securite.eq_ignore_ascii_case("open") || securite.eq_ignore_ascii_case("none");
            let coupee = booleen(v, "AutoJoinDisabled") == Some(true)
                || booleen(v, "AutoJoin") == Some(false)
                || booleen(v, "Disabled") == Some(true);
            let sur: String = nom.chars().filter(|c| !matches!(c, '"' | '\n' | '\r')).collect();
            Some(ProfilEnregistre {
                nom,
                automatique: !coupee,
                ouvert,
                commande: format!("networksetup -removepreferredwirelessnetwork en0 \"{sur}\""),
                commande_sure: false,
            })
        })
        .collect()
}

/// Les fichiers ordinaires d'un dossier, lus jusqu'à la taille bornée : (nom, contenu). `Err` : dossier ou un de ses
/// fichiers interdit.
#[cfg(target_os = "linux")]
fn fichiers(dossier: &str) -> std::io::Result<Vec<(String, String)>> {
    use std::io::Read;
    let mut liste = Vec::new();
    let entrees: Vec<std::fs::DirEntry> = std::fs::read_dir(dossier)?.flatten().take(FICHIERS_MAX + 1).collect();
    // Plus de fichiers que la borne : pas une liste partielle prise pour complète (le bilan passe alors par D-Bus).
    if entrees.len() > FICHIERS_MAX {
        return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
    }
    for entree in entrees {
        let chemin = entree.path();
        if !chemin.is_file() {
            continue;
        }
        let fichier = match std::fs::File::open(&chemin) {
            Ok(f) => f,
            // Dossier lisible (0755 sur certaines distributions) mais fichiers en 0600 : les sauter rendrait une liste
            // vide, donc un faux « aucun réseau ouvert ». Même cas qu'un dossier interdit : le bilan passe par nmcli.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Err(e),
            Err(_) => continue,
        };
        let mut texte = String::new();
        if fichier.take(TAILLE_MAX).read_to_string(&mut texte).is_ok() {
            liste.push((entree.file_name().to_string_lossy().into_owned(), texte));
        }
    }
    Ok(liste)
}

/// Les réseaux enregistrés par NetworkManager et iwd. `Err` : ni l'un ni l'autre ne se lit (il faut
/// l'administrateur), avec la raison.
#[cfg(target_os = "linux")]
pub(crate) fn lire_linux() -> Result<Vec<ProfilEnregistre>, &'static str> {
    let nm = fichiers("/etc/NetworkManager/system-connections");
    let iwd_dossier = fichiers("/var/lib/iwd");
    let run = fichiers("/run/NetworkManager/system-connections");
    let usr = fichiers("/usr/lib/NetworkManager/system-connections");
    // Un dossier qui a plus de profils que la borne : rien n'est conclu d'ici (le bilan passe par D-Bus, qui le dit).
    if [&nm, &iwd_dossier, &run, &usr]
        .iter()
        .any(|r| r.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::FileTooLarge))
    {
        return Err(crate::tr!(
            "trop de profils enregistrés pour les lire tous",
            "too many saved profiles to read them all"
        ));
    }
    if nm.is_err() && iwd_dossier.is_err() {
        return Err(crate::tr!(
            "lisibles seulement en administrateur (NetworkManager, iwd) ; le bilan les lit par nmcli",
            "readable only as administrator (NetworkManager, iwd); the check-up reads them through nmcli"
        ));
    }
    // Les réseaux enregistrés par NetworkManager. /etc et iwd décident seuls si les profils se lisent : ils sont
    // réservés à l'administrateur. /run (netplan, profils en mémoire) et /usr/lib (profils fournis) peuvent se lister
    // sans lui, ou manquer : ils s'ajoutent sans rien décider. Sans eux, un /etc vide en administrateur rendait
    // « aucun réseau ouvert » sur un Ubuntu à netplan, sans passer par nmcli, qui les voit.
    let mut profils: Vec<ProfilEnregistre> = nm
        .into_iter()
        .flatten()
        .chain(run.unwrap_or_default())
        .chain(usr.unwrap_or_default())
        .filter_map(|(_, texte)| nm_keyfile(&texte))
        .collect();
    profils.extend(
        iwd_dossier
            .into_iter()
            .flatten()
            .filter_map(|(nom, texte)| iwd(&nom, &texte)),
    );
    Ok(profils)
}

/// Les réseaux connus du Mac. `Err` : le fichier est réservé à l'administrateur.
#[cfg(target_os = "macos")]
pub(crate) fn lire_macos() -> Result<Vec<ProfilEnregistre>, &'static str> {
    let chemins = [
        "/Library/Preferences/com.apple.wifi.known-networks.plist",
        "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
    ];
    let mut profils = Vec::new();
    let (mut interdit, mut illisible) = (false, false);
    for chemin in chemins {
        match crate::plist::lire_fichier(std::path::Path::new(chemin)) {
            Ok(crate::plist::Lu::Plist(plist)) => profils.extend(connus_macos(&plist)),
            // Trop gros, hostile ou d'un format inconnu : rien à en tirer, et rien à confier à plutil.
            Ok(_) => illisible = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => interdit = true,
        }
    }
    if profils.is_empty() && interdit {
        return Err(crate::tr!(
            "lisibles seulement en administrateur (sudo)",
            "readable only as administrator (sudo)"
        ));
    }
    if profils.is_empty() && illisible {
        return Err(crate::tr!(
            "fichier des réseaux connus illisible",
            "known networks file unreadable"
        ));
    }
    Ok(profils)
}

#[cfg(test)]
mod tests {
    /// Plus de profils dans un dossier que la borne : pas une liste partielle prise pour complète.
    #[cfg(target_os = "linux")]
    #[test]
    fn dossier_de_profils_trop_plein() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        for n in 0..=super::FICHIERS_MAX {
            std::fs::write(d.join(format!("p{n}.nmconnection")), b"[connection]\n").unwrap();
        }
        let e = super::fichiers(&d.to_string_lossy()).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::FileTooLarge);
        std::fs::remove_file(d.join("p0.nmconnection")).unwrap();
        assert_eq!(
            super::fichiers(&d.to_string_lossy()).unwrap().len(),
            super::FICHIERS_MAX
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    use super::*;
    use crate::plist::Valeur;

    #[test]
    fn fichier_cle_de_networkmanager() {
        let ouvert = "[connection]\nid=Café du coin\nuuid=5c6a2e2a-1b1b-4c4c-8d8d-9e9e9e9e9e9e\ntype=wifi\n\n[wifi]\nmode=infrastructure\nssid=Café du coin\n\n[ipv4]\nmethod=auto\n";
        let p = nm_keyfile(ouvert).unwrap();
        assert_eq!(p.nom, "Café du coin");
        assert!(p.automatique && p.ouvert && p.commande_sure);
        assert_eq!(
            p.commande,
            "nmcli connection modify 5c6a2e2a-1b1b-4c4c-8d8d-9e9e9e9e9e9e connection.autoconnect no"
        );
        let protege = "[connection]\nid=Salon\nuuid=5c6a2e2a-1b1b-4c4c-8d8d-9e9e9e9e9e9e\ntype=wifi\nautoconnect=false\n[wifi-security]\nkey-mgmt=wpa-psk\npsk=secret\n";
        let p = nm_keyfile(protege).unwrap();
        assert!(!p.automatique && !p.ouvert);
        assert!(!p.commande.contains("secret"));
        // WEP et OWE ne sont pas ouverts ; une clé vide, si.
        let wep = protege.replace("key-mgmt=wpa-psk", "key-mgmt=none");
        assert!(!nm_keyfile(&wep).unwrap().ouvert);
        let vide = protege.replace("key-mgmt=wpa-psk", "key-mgmt=");
        assert!(nm_keyfile(&vide).unwrap().ouvert);
        // Pas du Wi-Fi, UUID qui n'a pas sa forme, nom manquant : rien.
        assert!(nm_keyfile(&ouvert.replace("type=wifi", "type=ethernet")).is_none());
        assert!(nm_keyfile(&ouvert.replace("9e9e9e9e9e9e", "9e9e9e9e9e9e; rm -rf")).is_none());
        assert!(
            nm_keyfile(
                &ouvert
                    .replace("id=Café du coin\n", "")
                    .replace("ssid=Café du coin\n", "")
            )
            .is_none()
        );
        // Un nom piégé arrive inoffensif.
        let piege = ouvert.replace("id=Café du coin", "id=Gare\x1b[2K");
        assert_eq!(nm_keyfile(&piege).unwrap().nom, "Gare�[2K");
    }

    #[test]
    fn reseaux_d_iwd() {
        let p = iwd("Hotel Wifi.open", "[Settings]\nAutoConnect=true\n").unwrap();
        assert_eq!(p.nom, "Hotel Wifi");
        assert!(p.automatique && p.ouvert && !p.commande_sure);
        assert_eq!(
            p.commande,
            "iwctl known-networks \"Hotel Wifi\" set-property AutoConnect no"
        );
        let p = iwd(
            "Salon.psk",
            "[Security]\nPassphrase=secret\n[Settings]\nAutoConnect=false\n",
        )
        .unwrap();
        assert!(!p.automatique && !p.ouvert);
        assert!(!p.commande.contains("secret"));
        // Un nom encodé en hexadécimal (« Café »), un fichier qui n'est pas un réseau, un nom vide.
        assert_eq!(iwd("=436166c3a9.open", "").unwrap().nom, "Café");
        assert!(iwd("Salon.psk.bak", "").is_none());
        assert!(iwd("main.conf", "").is_none());
        assert!(iwd("=zz.open", "").is_none());
        assert!(iwd(".open", "").is_none());
        // Un guillemet dans le nom n'entre pas dans la commande montrée.
        let p = iwd("=476172652220616d7020646f22.open", "").unwrap();
        assert_eq!(p.nom, "Gare\" amp do\"");
        assert_eq!(p.commande.matches('"').count(), 2);
    }

    fn reseau(cle: &str, nom: Option<&str>, securite: &str, extras: &[(&str, Valeur)]) -> (String, Valeur) {
        let mut d = vec![("SecurityType".to_string(), Valeur::Texte(securite.into()))];
        if let Some(n) = nom {
            d.push(("SSID".into(), Valeur::Donnees(n.as_bytes().to_vec())));
        }
        for (k, v) in extras {
            d.push(((*k).to_string(), v.clone()));
        }
        (cle.to_string(), Valeur::Dico(d))
    }

    #[test]
    fn reseaux_connus_du_mac() {
        let plist = Valeur::Dico(vec![
            reseau("wifi.network.ssid.Salon", Some("Salon"), "WPA2 Personal", &[]),
            reseau("wifi.network.ssid.Aéroport", Some("Aéroport"), "Open", &[]),
            reseau(
                "wifi.network.ssid.Hôtel",
                Some("Hôtel"),
                "Open",
                &[("AutoJoinDisabled", Valeur::Booleen(true))],
            ),
            reseau(
                "wifi.network.ssid.Gare",
                None,
                "Open",
                &[("AutoJoin", Valeur::Booleen(false))],
            ),
            ("Version".into(), Valeur::Entier(1)),
        ]);
        let p = connus_macos(&plist);
        assert_eq!(p.len(), 4);
        assert!(!p[0].ouvert && p[0].automatique);
        assert!(p[1].ouvert && p[1].automatique);
        assert_eq!(
            p[1].commande,
            "networksetup -removepreferredwirelessnetwork en0 \"Aéroport\""
        );
        assert!(p[2].ouvert && !p[2].automatique);
        assert_eq!(p[3].nom, "Gare");
        assert!(!p[3].automatique);
        // L'ancien format.
        let ancien = Valeur::Dico(vec![(
            "KnownNetworks".into(),
            Valeur::Dico(vec![(
                "wifi.ssid.<53616c6f6e>".into(),
                Valeur::Dico(vec![
                    ("SSIDString".into(), Valeur::Texte("Café\x1b[2K".into())),
                    ("SecurityType".into(), Valeur::Texte("Open".into())),
                    ("Disabled".into(), Valeur::Booleen(false)),
                ]),
            )]),
        )]);
        let p = connus_macos(&ancien);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].nom, "Café�[2K");
        assert!(p[0].ouvert && p[0].automatique);
        assert_eq!(connus_macos(&Valeur::Texte("rien".into())), [] as [ProfilEnregistre; 0]);
    }

    #[test]
    fn ini_tolerant() {
        let paires = ini("# commentaire\n[Settings]\n AutoConnect = false \nsans_egal\n[]\nx=1\n");
        assert_eq!(valeur(&paires, "Settings", "AutoConnect"), Some("false"));
        assert_eq!(valeur(&paires, "", "x"), Some("1"));
        assert_eq!(valeur(&paires, "Settings", "x"), None);
    }

    /// Un dossier qui se liste mais dont un fichier est interdit : refusé comme un dossier interdit, pas une liste
    /// vide qui dirait « aucun réseau ouvert ». Sans objet en administrateur, qui lit tout.
    #[cfg(target_os = "linux")]
    #[test]
    fn fichier_interdit_dans_un_dossier_lisible() {
        use std::os::unix::fs::PermissionsExt;
        if crate::socle::euid() == 0 {
            return;
        }
        let dossier = std::env::temp_dir().join(format!("vanguard-profils-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::write(dossier.join("Salon.nmconnection"), "[wifi]\nssid=Salon\n").unwrap();
        let nom = dossier.to_string_lossy().into_owned();
        assert_eq!(fichiers(&nom).unwrap().len(), 1);
        let cafe = dossier.join("Café.nmconnection");
        std::fs::write(&cafe, "[wifi]\nssid=Café\n").unwrap();
        std::fs::set_permissions(&cafe, std::fs::Permissions::from_mode(0o000)).unwrap();
        let lu = fichiers(&nom);
        std::fs::set_permissions(&cafe, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _ = std::fs::remove_dir_all(&dossier);
        assert!(lu.is_err());
    }

    /// La vraie lecture : sans droits, la raison ; avec, des profils aux noms inoffensifs. Rien n'est affiché.
    #[cfg(target_os = "linux")]
    #[test]
    fn lecture_reelle_linux() {
        match lire_linux() {
            Ok(p) => assert!(p.iter().all(|p| !crate::ui::contient_un_piege(&p.nom))),
            Err(raison) => assert_ne!(raison, ""),
        }
    }
}
