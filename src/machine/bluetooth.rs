//! Bluetooth : un ordinateur visible en permanence (tout appareil à portée le voit et peut demander à s'appairer), et
//! les appareils appairés depuis peu. Un appareil appairé (clavier, casque) peut parler à l'ordinateur sans rien
//! demander : un clavier Bluetooth appairé par quelqu'un d'autre tape ce qu'il veut. Vanguard note ici la date où il voit
//! chaque appareil pour la première fois (bluetooth.json, jamais sur la clé) et signale ceux de la dernière semaine ;
//! ceux qui étaient là au premier passage sont connus d'avant. Sans adaptateur Bluetooth, rien n'est dit.

use std::collections::BTreeMap;

use chrono::NaiveDate;

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::ui::{affichable, resume};
use crate::{tr, trf};

const CAT: &str = "Bluetooth";
/// Un appareil vu pour la première fois depuis moins longtemps que ça est « appairé depuis peu ».
const RECENT_JOURS: i64 = 7;

/// Un appareil appairé : son adresse (« AA:BB:CC:DD:EE:FF ») et le nom qu'il se donne.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Appareil {
    adresse: String,
    nom: String,
}

/// Ce que le système dit de son Bluetooth.
#[derive(Debug, Default, PartialEq, Eq)]
struct Etat {
    allume: bool,
    /// Visible sans limite de temps (Linux) ; Windows et macOS ne le sont que réglages ouverts.
    visible_toujours: bool,
    appareils: Vec<Appareil>,
}

/// Les appareils déjà vus : adresse → date de la première fois (« AAAA-MM-JJ »), vide pour ceux du premier passage.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq, Eq)]
struct Vus {
    vus: BTreeMap<String, String>,
}

fn fichier() -> std::path::PathBuf {
    crate::socle::dossier_local().join("bluetooth.json")
}

/// « aa-bb-cc-dd-ee-ff », « aabbccddeeff » → « AA:BB:CC:DD:EE:FF » ; `None` si ce n'est pas une adresse.
fn adresse(texte: &str) -> Option<String> {
    let hex: String = texte.chars().filter(char::is_ascii_hexdigit).collect();
    let separateurs = texte.chars().filter(|c| matches!(c, ':' | '-')).count();
    if hex.len() != 12 || !(separateurs == 0 || separateurs == 5) || texte.trim().len() != 12 + separateurs {
        return None;
    }
    let octets: Vec<String> = hex
        .as_bytes()
        .chunks(2)
        .map(|o| String::from_utf8_lossy(o).to_uppercase())
        .collect();
    Some(octets.join(":"))
}

pub fn constats() -> Vec<Constat> {
    let Some(etat) = lire() else {
        return Vec::new();
    };
    let avant: Option<Vus> = std::fs::read_to_string(fichier())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    let aujourd_hui = chrono::Local::now().date_naive();
    let (constats, apres) = juger(&etat, avant.as_ref(), aujourd_hui);
    if avant.as_ref() != Some(&apres)
        && let Ok(texte) = serde_json::to_string_pretty(&apres)
    {
        let _ = std::fs::create_dir_all(crate::socle::dossier_local());
        let _ = crate::socle::ecrire_atomique(&fichier(), texte);
    }
    constats
}

/// Les constats, et la liste des appareils vus à garder. `avant` vaut `None` au premier passage : tout ce qui est là
/// est connu d'avant.
fn juger(etat: &Etat, avant: Option<&Vus>, aujourd_hui: NaiveDate) -> (Vec<Constat>, Vus) {
    let mut vus = avant.map(|v| v.vus.clone()).unwrap_or_default();
    for a in &etat.appareils {
        let date = if avant.is_some() {
            aujourd_hui.format("%Y-%m-%d").to_string()
        } else {
            String::new()
        };
        vus.entry(a.adresse.clone()).or_insert(date);
    }
    let recents: Vec<&Appareil> = etat
        .appareils
        .iter()
        .filter(|a| {
            vus.get(&a.adresse)
                .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                .is_some_and(|d| (aujourd_hui - d).num_days() < RECENT_JOURS)
        })
        .collect();
    let mut constats = Vec::new();
    if etat.allume && etat.visible_toujours {
        constats.push(
            alerte(
                CAT,
                Niveau::Moyen,
                tr!(
                    "L'ordinateur est visible en Bluetooth en permanence : tout appareil à portée le voit et peut demander à s'appairer.",
                    "The computer is visible over Bluetooth all the time: any device in range sees it and can ask to pair."
                ),
            )
            .corriger(
                tr!(
                    "Le rendre invisible (il le redevient le temps d'un appairage, depuis les réglages Bluetooth)",
                    "Make it invisible (it becomes visible again while pairing, from the Bluetooth settings)"
                ),
                &["bluetoothctl discoverable off"],
            ),
        );
    }
    for a in &recents {
        let nom = affichable(&a.nom);
        // Sous Linux, la commande qui le retire ; l'adresse a été vérifiée (`adresse`) : rien d'autre ne s'y glisse.
        let retirer = format!("bluetoothctl remove {}", a.adresse);
        let commandes: &[&str] = if cfg!(target_os = "linux") {
            &[retirer.as_str()]
        } else {
            &[]
        };
        constats.push(
            alerte(
                CAT,
                Niveau::Moyen,
                trf!(
                    "Appareil Bluetooth appairé depuis peu : « {nom} » ({}). Si ce n'est pas le vôtre (un clavier appairé par quelqu'un d'autre tape ce qu'il veut), retirez-le.",
                    "Bluetooth device paired recently: “{nom}” ({}). If it is not yours (a keyboard paired by someone else types whatever it wants), remove it.",
                    a.adresse
                ),
            )
            .manuel(retrait(), commandes),
        );
    }
    if constats.is_empty() {
        let noms: Vec<String> = etat.appareils.iter().map(|a| affichable(&a.nom)).collect();
        let appareils = if noms.is_empty() {
            tr!("aucun appareil appairé", "no paired device").to_string()
        } else {
            trf!("appairés : {}", "paired: {}", resume(&noms, 4, ", "))
        };
        constats.push(ok(
            CAT,
            if etat.allume {
                trf!(
                    "Bluetooth allumé, ordinateur invisible ; {appareils}, aucun nouveau cette semaine.",
                    "Bluetooth on, computer invisible; {appareils}, none new this week."
                )
            } else {
                trf!("Bluetooth éteint ; {appareils}.", "Bluetooth off; {appareils}.")
            },
        ));
    }
    (constats, Vus { vus })
}

/// Comment retirer un appareil appairé, sur ce système.
fn retrait() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Paramètres › Bluetooth et appareils › Appareils : « Supprimer l'appareil »",
            "Settings › Bluetooth & devices › Devices: “Remove device”"
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Réglages Système › Bluetooth : (i) à côté de l'appareil › « Oublier cet appareil »",
            "System Settings › Bluetooth: (i) next to the device › “Forget This Device”"
        )
    } else {
        tr!(
            "Le retirer des réglages Bluetooth, ou avec la commande ci-dessous",
            "Remove it from the Bluetooth settings, or with the command below"
        )
    }
}

// ───────────────────────────── Lectures ─────────────────────────────

#[cfg(target_os = "linux")]
fn lire() -> Option<Etat> {
    // Aucun adaptateur : rien à dire (sans quoi bluetoothctl attendrait un service qui n'existe pas).
    let adaptateur = std::fs::read_dir("/sys/class/bluetooth")
        .ok()?
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("hci"));
    if !adaptateur {
        return None;
    }
    // Compte remappé dans un espace de noms d'utilisateur (`unshare -r`, conteneur sans droits) : le bus système y
    // refuse l'authentification, et bluetoothctl 5.87 ne vérifie pas sa connexion et s'arrête net (SIGABRT, un
    // vidage mémoire à chaque fois : plus de cent en une journée, venus de l'étape sans Internet des tests). Rien à
    // lire de toute façon.
    if std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|m| !identite(&m)) {
        return None;
    }
    let lancer = |args: &[&str]| {
        crate::commande::lancer_en_anglais(std::process::Command::new("bluetoothctl").args(args), 5).map(|r| r.sortie)
    };
    let show = lancer(&["show"])?;
    let mut etat = lire_show(&show)?;
    // « paired-devices » a disparu de bluez 5.66 au profit de « devices Paired ».
    let appareils = lancer(&["devices", "Paired"])
        .filter(|s| !s.contains("Invalid command"))
        .or_else(|| lancer(&["paired-devices"]))
        .unwrap_or_default();
    etat.appareils = lire_appareils(&appareils);
    Some(etat)
}

/// `/proc/self/uid_map` sans remappage : une seule plage « 0 0 4294967295 », le compte vu tel qu'il est.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn identite(uid_map: &str) -> bool {
    let plages: Vec<Vec<&str>> = uid_map.lines().map(|l| l.split_whitespace().collect()).collect();
    plages == [vec!["0", "0", "4294967295"]]
}

/// « bluetoothctl show » : Powered, Discoverable et DiscoverableTimeout (« 0x00000000 (0) » : sans limite).
#[cfg(any(target_os = "linux", test))]
fn lire_show(texte: &str) -> Option<Etat> {
    if !texte.lines().any(|l| l.starts_with("Controller ")) {
        return None;
    }
    let valeur = |cle: &str| {
        texte
            .lines()
            .find_map(|l| l.trim().strip_prefix(cle)?.strip_prefix(':').map(str::trim))
    };
    let oui = |cle: &str| valeur(cle) == Some("yes");
    let sans_limite = valeur("DiscoverableTimeout").is_some_and(|v| v.starts_with("0x00000000") || v == "0");
    Some(Etat {
        allume: oui("Powered"),
        visible_toujours: oui("Discoverable") && sans_limite,
        appareils: Vec::new(),
    })
}

/// « Device AA:BB:CC:DD:EE:FF Nom » par ligne.
#[cfg(any(target_os = "linux", test))]
fn lire_appareils(texte: &str) -> Vec<Appareil> {
    texte
        .lines()
        .filter_map(|l| {
            let reste = l.trim().strip_prefix("Device ")?;
            let (mac, nom) = reste.split_once(' ').unwrap_or((reste, ""));
            Some(Appareil {
                adresse: adresse(mac)?,
                nom: nom.trim().to_string(),
            })
        })
        .collect()
}

/// Windows : les appareils appairés sont dans le registre (une sous-clé par adresse, le nom en UTF-8 terminé par un
/// zéro). Lisible sans droits administrateur. Visible seulement réglages Bluetooth ouverts : jamais « toujours ».
#[cfg(windows)]
fn lire() -> Option<Etat> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let parametres = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters")
        .ok()?;
    let appareils = parametres
        .open_subkey("Devices")
        .map(|d| {
            d.enum_keys()
                .flatten()
                .filter_map(|cle| {
                    let nom = d
                        .open_subkey(&cle)
                        .and_then(|k| k.get_raw_value("Name"))
                        .map(|v| nom_utf8(&v.bytes))
                        .unwrap_or_default();
                    Some(Appareil {
                        adresse: adresse(&cle)?,
                        nom,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Etat {
        allume: true,
        visible_toujours: false,
        appareils,
    })
}

/// Le nom d'un appareil tel que Windows le garde : UTF-8, terminé par un zéro.
#[cfg(any(windows, test))]
fn nom_utf8(octets: &[u8]) -> String {
    let fin = octets.iter().position(|&o| o == 0).unwrap_or(octets.len());
    String::from_utf8_lossy(&octets[..fin]).trim().to_string()
}

#[cfg(target_os = "macos")]
fn lire() -> Option<Etat> {
    let r = crate::commande::lancer(
        std::process::Command::new("system_profiler").args(["-json", "SPBluetoothDataType"]),
        20,
    )?;
    lire_profil(&r.sortie)
}

/// `system_profiler -json SPBluetoothDataType` : l'état du contrôleur, et les appareils appairés, connectés ou non
/// (macOS 12 et plus récents).
#[cfg(any(target_os = "macos", test))]
fn lire_profil(json: &str) -> Option<Etat> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let bloc = v.get("SPBluetoothDataType")?.get(0)?;
    let controleur = bloc.get("controller_properties")?;
    let allume = controleur.get("controller_state").and_then(|s| s.as_str()) == Some("attrib_on");
    let mut appareils = Vec::new();
    for liste in ["device_connected", "device_not_connected"] {
        for entree in bloc.get(liste).and_then(|l| l.as_array()).into_iter().flatten() {
            let Some(objet) = entree.as_object() else { continue };
            for (nom, proprietes) in objet {
                if let Some(a) = proprietes
                    .get("device_address")
                    .and_then(|a| a.as_str())
                    .and_then(adresse)
                {
                    appareils.push(Appareil {
                        adresse: a,
                        nom: nom.clone(),
                    });
                }
            }
        }
    }
    Some(Etat {
        allume,
        visible_toujours: false,
        appareils,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jour(j: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, j).unwrap()
    }

    fn appareil(mac: &str, nom: &str) -> Appareil {
        Appareil {
            adresse: mac.into(),
            nom: nom.into(),
        }
    }

    #[test]
    fn adresses() {
        assert_eq!(adresse("a4:c1:38:0b:1e:22").as_deref(), Some("A4:C1:38:0B:1E:22"));
        assert_eq!(adresse("a4c1380b1e22").as_deref(), Some("A4:C1:38:0B:1E:22"));
        assert_eq!(adresse("A4-C1-38-0B-1E-22").as_deref(), Some("A4:C1:38:0B:1E:22"));
        assert_eq!(adresse("a4:c1:38"), None);
        assert_eq!(adresse("zz:c1:38:0b:1e:22"), None);
        assert_eq!(adresse("../../a4c1380b1e22"), None);
    }

    #[test]
    fn compte_remappe_reconnu() {
        assert!(identite("         0          0 4294967295\n"));
        // unshare -r : root mappé sur le compte 1000 ; conteneur sans droits : une plage décalée.
        assert!(!identite("         0       1000          1\n"));
        assert!(!identite("0 100000 65536\n"));
        assert!(!identite(""));
    }

    #[test]
    fn lectures_de_bluetoothctl() {
        let show = "Controller 00:1A:7D:DA:71:13 (public)\n\tName: salon\n\tPowered: yes\n\tDiscoverable: yes\n\
                    \tDiscoverableTimeout: 0x00000000 (0)\n\tPairable: yes\n";
        let e = lire_show(show).unwrap();
        assert!(e.allume && e.visible_toujours);
        // Visible trois minutes (appairage en cours) : pas « toujours ».
        let e = lire_show(&show.replace("0x00000000 (0)", "0x000000b4 (180)")).unwrap();
        assert!(e.allume && !e.visible_toujours);
        assert_eq!(lire_show("No default controller available\n"), None);
        let appareils = lire_appareils(
            "Device 98:7B:F3:11:22:33 Casque Salon\nDevice C8:3F:26:44:55:66 Xbox Wireless Controller\nautre\n",
        );
        assert_eq!(
            appareils,
            [
                appareil("98:7B:F3:11:22:33", "Casque Salon"),
                appareil("C8:3F:26:44:55:66", "Xbox Wireless Controller")
            ]
        );
        assert_eq!(nom_utf8(b"Clavier \xc3\xa9t\xc3\xa9\0\0\x12"), "Clavier été");
    }

    #[test]
    fn lecture_de_system_profiler() {
        let json = r#"{"SPBluetoothDataType":[{"controller_properties":{"controller_state":"attrib_on",
            "controller_discoverable":"attrib_off"},
            "device_connected":[{"AirPods d'Alice":{"device_address":"F4:65:A6:11:22:33"}}],
            "device_not_connected":[{"Magic Keyboard":{"device_address":"04-4B-ED-44-55-66"}},{"Sans adresse":{}}]}]}"#;
        let e = lire_profil(json).unwrap();
        assert!(e.allume && !e.visible_toujours);
        assert_eq!(
            e.appareils,
            [
                appareil("F4:65:A6:11:22:33", "AirPods d'Alice"),
                appareil("04:4B:ED:44:55:66", "Magic Keyboard")
            ]
        );
        assert_eq!(lire_profil(r#"{"SPBluetoothDataType":[{}]}"#), None);
    }

    #[test]
    fn appareils_nouveaux_signales_une_semaine() {
        let casque = appareil("98:7B:F3:11:22:33", "Casque Salon");
        let clavier = appareil("C8:3F:26:44:55:66", "Clavier\x1b[2K");
        let etat = Etat {
            allume: true,
            visible_toujours: false,
            appareils: vec![casque.clone()],
        };
        // Premier passage : le casque est connu d'avant, rien à signaler.
        let (c, vus) = juger(&etat, None, jour(10));
        assert_eq!(c.len(), 1);
        assert!(c[0].probleme.is_none(), "{}", c[0].message);
        assert_eq!(vus.vus.get("98:7B:F3:11:22:33").map(String::as_str), Some(""));
        // Un clavier apparaît : signalé, nom rendu inoffensif, pendant une semaine.
        let etat = Etat {
            appareils: vec![casque, clavier],
            ..etat
        };
        let (c, vus) = juger(&etat, Some(&vus), jour(12));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert!(c[0].message.contains("Clavier�[2K") && c[0].message.contains("C8:3F:26:44:55:66"));
        assert!(!c[0].correctif.as_ref().unwrap().automatique);
        let (c, _) = juger(&etat, Some(&vus), jour(18));
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        let (c, _) = juger(&etat, Some(&vus), jour(19));
        assert!(c[0].probleme.is_none());
    }

    #[test]
    fn visible_en_permanence() {
        let etat = Etat {
            allume: true,
            visible_toujours: true,
            appareils: Vec::new(),
        };
        let (c, _) = juger(&etat, Some(&Vus::default()), jour(10));
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert!(c[0].correctif.as_ref().unwrap().automatique);
        // Éteint : visible ou non, personne ne le voit.
        let (c, _) = juger(&Etat { allume: false, ..etat }, None, jour(10));
        assert!(c[0].probleme.is_none() && c[0].message.contains("éteint"));
    }
}
