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

/// Un adaptateur allumé et visible sans limite de temps (Linux) : son objet chez BlueZ (« /org/bluez/hci0 ») et le
/// nom à montrer (« hci0 (salon) »).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Visible {
    chemin: String,
    nom: String,
}

/// Ce que le système dit de son Bluetooth.
#[derive(Debug, Default, PartialEq, Eq)]
struct Etat {
    /// Au moins un adaptateur est allumé.
    allume: bool,
    /// Les adaptateurs allumés et visibles sans limite de temps (Linux) ; Windows et macOS ne le sont que réglages
    /// ouverts.
    visibles: Vec<Visible>,
    /// Les adaptateurs vus en tout : avec un seul, c'est celui que `bluetoothctl` règle sans qu'on le nomme.
    adaptateurs: usize,
    appareils: Vec<Appareil>,
}

/// Les appareils déjà vus : adresse → date de la première fois (« AAAA-MM-JJ »), vide pour ceux du premier passage.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq, Eq)]
struct Vus {
    vus: BTreeMap<String, String>,
}

/// Les appareils déjà vus, scellés (`sceau::deja_vus`).
const VUS: &str = crate::sceau::BLUETOOTH;

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
    let etat = match lire_etat() {
        None => return Vec::new(),
        Some(Ok(e)) => e,
        Some(Err(raison)) => return vec![super::impossible(CAT, &raison)],
    };
    // Effacés, changés hors de Vanguard ou illisibles : une liste vide (chacun est redit), jamais un premier passage.
    let (avant, douteux): (Option<Vus>, bool) = match crate::sceau::deja_vus(VUS) {
        Ok(None) => (None, false),
        Ok(Some(o)) => serde_json::from_slice(&o).map_or((Some(Vus::default()), true), |v| (Some(v), false)),
        Err(()) => (Some(Vus::default()), true),
    };
    let aujourd_hui = chrono::Local::now().date_naive();
    let (mut constats, apres) = juger(&etat, avant.as_ref(), aujourd_hui);
    if douteux {
        // Les alertes d'appareils « appairés depuis peu », reconnues à leur adresse.
        for c in constats
            .iter_mut()
            .filter(|c| c.probleme.is_some() && etat.appareils.iter().any(|a| c.message.contains(&a.adresse)))
        {
            c.message += crate::sceau::redit();
        }
    }
    if avant.as_ref() != Some(&apres)
        && let Ok(texte) = serde_json::to_string_pretty(&apres)
    {
        let _ = crate::sceau::ecrire(VUS, texte);
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
    if !etat.visibles.is_empty() {
        let noms: Vec<String> = etat.visibles.iter().map(|v| affichable(&v.nom)).collect();
        let noms = noms.join(", ");
        // Un seul adaptateur : celui que bluetoothctl règle. Plusieurs : chacun par son objet chez BlueZ, que
        // `lire_objets` n'a gardé que de la forme /org/bluez/hciN (rien d'autre ne se glisse dans la commande).
        let commandes: Vec<String> = if etat.adaptateurs <= 1 {
            vec!["bluetoothctl discoverable off".into()]
        } else {
            etat.visibles
                .iter()
                .filter(|v| !v.chemin.is_empty())
                .map(|v| {
                    format!(
                        "busctl set-property org.bluez {} org.bluez.Adapter1 Discoverable b false",
                        v.chemin
                    )
                })
                .collect()
        };
        constats.push(
            alerte(
                CAT,
                Niveau::Moyen,
                trf!(
                    "L'ordinateur est visible en Bluetooth en permanence ({noms}) : tout appareil à portée le voit et peut demander à s'appairer.",
                    "The computer is visible over Bluetooth all the time ({noms}): any device in range sees it and can ask to pair."
                ),
            )
            .corriger(
                tr!(
                    "Le rendre invisible (il le redevient le temps d'un appairage, depuis les réglages Bluetooth)",
                    "Make it invisible (it becomes visible again while pairing, from the Bluetooth settings)"
                ),
                &commandes,
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

/// L'état lu ; `None` : rien à dire (pas d'adaptateur, service Bluetooth arrêté) ; `Err` : la lecture a échoué, ce
/// qui se dit « impossible à vérifier », jamais « invisible ».
#[cfg(not(target_os = "linux"))]
fn lire_etat() -> Option<Result<Etat, String>> {
    lire().map(Ok)
}

#[cfg(target_os = "linux")]
fn lire_etat() -> Option<Result<Etat, String>> {
    use crate::machine::linux::dbus;
    // Aucun adaptateur : rien à dire.
    let adaptateur = std::fs::read_dir("/sys/class/bluetooth")
        .ok()?
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("hci"));
    if !adaptateur {
        return None;
    }
    // Compte remappé dans un espace de noms d'utilisateur (`unshare -r`, conteneur sans droits) : le bus système y
    // refuse l'authentification. Rien à lire, comme du temps de bluetoothctl (qui s'y arrêtait net, SIGABRT).
    if std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|m| !identite(&m)) {
        return None;
    }
    // GetManagedObjects de BlueZ : tous les adaptateurs (bluetoothctl show ne voyait que celui par défaut) et tous
    // les appareils, en une réponse typée.
    let objets = dbus::Bus::systeme().and_then(|mut bus| bus.objets("org.bluez", "/"));
    match objets {
        // bluetoothd arrêté ou absent : comme bluetoothctl (« No default controller available »), rien à dire.
        Err(e) if dbus::service_absent(&e) => None,
        Err(e) => Some(Err(e)),
        Ok(objets) => lire_objets(&objets).map(Ok),
    }
}

/// `/proc/self/uid_map` sans remappage : une seule plage « 0 0 4294967295 », le compte vu tel qu'il est.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn identite(uid_map: &str) -> bool {
    let plages: Vec<Vec<&str>> = uid_map.lines().map(|l| l.split_whitespace().collect()).collect();
    plages == [vec!["0", "0", "4294967295"]]
}

/// Les objets de BlueZ (chemin → interfaces → propriétés) : chaque `org.bluez.Adapter1` jugé à part (allumé, visible,
/// sans limite de temps : DiscoverableTimeout à 0), et les `org.bluez.Device1` appairés (Paired), comme
/// « bluetoothctl devices Paired ». `None` : aucun adaptateur chez BlueZ (rien à dire).
#[cfg(target_os = "linux")]
fn lire_objets(objets: &[(String, crate::machine::linux::dbus::Valeur)]) -> Option<Etat> {
    let mut etat = Etat::default();
    for (chemin, interfaces) in objets {
        if let Some(a) = interfaces.champ("org.bluez.Adapter1") {
            etat.adaptateurs += 1;
            let oui = |cle: &str| a.champ(cle).and_then(super::linux::dbus::Valeur::booleen) == Some(true);
            let allume = oui("Powered");
            etat.allume |= allume;
            let sans_limite = a
                .champ("DiscoverableTimeout")
                .and_then(super::linux::dbus::Valeur::entier)
                == Some(0);
            // Seul un objet de la forme /org/bluez/hciN finit dans la commande de correction.
            let nom_hci = chemin.strip_prefix("/org/bluez/").filter(|n| {
                n.strip_prefix("hci")
                    .is_some_and(|c| !c.is_empty() && c.bytes().all(|o| o.is_ascii_digit()))
            });
            if allume && oui("Discoverable") && sans_limite {
                let alias = a
                    .champ("Alias")
                    .or_else(|| a.champ("Name"))
                    .and_then(|v| v.texte())
                    .unwrap_or_default();
                let hci = nom_hci.unwrap_or(chemin);
                etat.visibles.push(Visible {
                    chemin: if nom_hci.is_some() {
                        chemin.clone()
                    } else {
                        String::new()
                    },
                    nom: if alias.is_empty() {
                        hci.to_string()
                    } else {
                        format!("{hci} ({alias})")
                    },
                });
            }
        }
        if let Some(d) = interfaces.champ("org.bluez.Device1")
            && d.champ("Paired").and_then(super::linux::dbus::Valeur::booleen) == Some(true)
            && let Some(mac) = d.champ("Address").and_then(|v| v.texte()).and_then(adresse)
        {
            let nom = d
                .champ("Alias")
                .or_else(|| d.champ("Name"))
                .and_then(|v| v.texte())
                .unwrap_or_default();
            etat.appareils.push(Appareil {
                adresse: mac,
                nom: nom.trim().to_string(),
            });
        }
    }
    (etat.adaptateurs > 0).then_some(etat)
}

/// « bluetoothctl show » (Powered, Discoverable, DiscoverableTimeout « 0x00000000 (0) » : sans limite) : l'oracle de
/// l'essai qui compare la lecture par BlueZ à l'outil.
#[cfg(all(test, target_os = "linux"))]
fn lire_show(texte: &str) -> Option<(bool, bool)> {
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
    Some((oui("Powered"), oui("Powered") && oui("Discoverable") && sans_limite))
}

/// « Device AA:BB:CC:DD:EE:FF Nom » par ligne (bluetoothctl devices Paired), pour le même essai.
#[cfg(all(test, target_os = "linux"))]
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
        adaptateurs: 1,
        appareils,
        ..Etat::default()
    })
}

/// Le nom d'un appareil tel que Windows le garde : UTF-8, terminé par un zéro.
#[cfg(any(windows, test))]
fn nom_utf8(octets: &[u8]) -> String {
    // Jusqu'au premier zéro, s'il y en a un.
    let nom: Vec<u8> = octets.iter().copied().take_while(|&o| o != 0).collect();
    String::from_utf8_lossy(&nom).trim().to_string()
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
        adaptateurs: 1,
        appareils,
        ..Etat::default()
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
        assert_eq!(nom_utf8(b"Clavier \xc3\xa9t\xc3\xa9\0\0\x12"), "Clavier été");
    }

    #[test]
    fn compte_remappe_reconnu() {
        assert!(identite("         0          0 4294967295\n"));
        // unshare -r : root mappé sur le compte 1000 ; conteneur sans droits : une plage décalée.
        assert!(!identite("         0       1000          1\n"));
        assert!(!identite("0 100000 65536\n"));
        assert!(!identite(""));
    }

    #[cfg(target_os = "linux")]
    fn adaptateur(powered: bool, visible: bool, delai: u32, alias: &str) -> crate::machine::linux::dbus::Valeur {
        use crate::machine::linux::dbus::Valeur as V;
        let p = |k: &str, v: V| (V::texte_de(k), V::Variante(String::new(), Box::new(v)));
        V::Dictionnaire(vec![(
            V::texte_de("org.bluez.Adapter1"),
            V::Dictionnaire(vec![
                p("Powered", V::Booleen(powered)),
                p("Discoverable", V::Booleen(visible)),
                p("DiscoverableTimeout", V::U32(delai)),
                p("Alias", V::texte_de(alias)),
            ]),
        )])
    }

    #[cfg(target_os = "linux")]
    fn appareil_bluez(mac: &str, nom: &str, paired: bool) -> crate::machine::linux::dbus::Valeur {
        use crate::machine::linux::dbus::Valeur as V;
        let p = |k: &str, v: V| (V::texte_de(k), V::Variante(String::new(), Box::new(v)));
        V::Dictionnaire(vec![(
            V::texte_de("org.bluez.Device1"),
            V::Dictionnaire(vec![
                p("Address", V::texte_de(mac)),
                p("Alias", V::texte_de(nom)),
                p("Paired", V::Booleen(paired)),
            ]),
        )])
    }

    /// Réponses de GetManagedObjects fabriquées : chaque adaptateur jugé à part et nommé, les appareils appairés
    /// seulement, une adresse invalide ou un chemin étrange jamais repris dans une commande.
    #[cfg(target_os = "linux")]
    #[test]
    fn lectures_de_bluez() {
        let o = |c: &str, v| (c.to_string(), v);
        let objets = vec![
            o(
                "/org/bluez",
                crate::machine::linux::dbus::Valeur::Dictionnaire(Vec::new()),
            ),
            o("/org/bluez/hci0", adaptateur(true, false, 0, "salon")),
            o("/org/bluez/hci1", adaptateur(true, true, 0, "cle")),
            o(
                "/org/bluez/hci0/dev_98_7B_F3_11_22_33",
                appareil_bluez("98:7B:F3:11:22:33", "Casque Salon", true),
            ),
            o(
                "/org/bluez/hci0/dev_C8_3F_26_44_55_66",
                appareil_bluez("C8:3F:26:44:55:66", "Inconnu", false),
            ),
            o("/org/bluez/hci0/dev_x", appareil_bluez("pas une adresse", "x", true)),
        ];
        let e = lire_objets(&objets).unwrap();
        assert!(e.allume);
        assert_eq!(e.adaptateurs, 2);
        assert_eq!(
            e.visibles,
            [Visible {
                chemin: "/org/bluez/hci1".into(),
                nom: "hci1 (cle)".into()
            }]
        );
        assert_eq!(e.appareils, [appareil("98:7B:F3:11:22:33", "Casque Salon")]);
        // Deux adaptateurs : la correction vise celui qui est visible, par son objet.
        let (c, _) = juger(&e, Some(&Vus::default()), jour(10));
        let k = c[0].correctif.as_ref().unwrap();
        assert_eq!(
            k.commandes,
            ["busctl set-property org.bluez /org/bluez/hci1 org.bluez.Adapter1 Discoverable b false"]
        );
        assert!(c[0].message.contains("hci1 (cle)"), "{}", c[0].message);
        // Visible trois minutes (appairage en cours) : pas « toujours ». Éteint : personne ne le voit.
        for a in [adaptateur(true, true, 180, ""), adaptateur(false, true, 0, "")] {
            let e = lire_objets(&[o("/org/bluez/hci0", a)]).unwrap();
            assert!(e.visibles.is_empty(), "{e:?}");
        }
        // Un chemin d'adaptateur hors de la forme hciN : nommé, mais jamais dans une commande.
        let mut e = lire_objets(&[
            o("/org/bluez/hci0", adaptateur(true, true, 0, "")),
            o("/org/bluez/hci0;reboot", adaptateur(true, true, 0, "")),
        ])
        .unwrap();
        assert_eq!(e.visibles[1].chemin, "");
        e.appareils.clear();
        let (c, _) = juger(&e, Some(&Vus::default()), jour(10));
        let k = c[0].correctif.as_ref().unwrap();
        assert!(k.commandes.iter().all(|c| !c.contains("reboot")), "{:?}", k.commandes);
        // Aucun adaptateur chez BlueZ : rien à dire. Pas de réponse : rien non plus, jamais « invisible ».
        assert_eq!(lire_objets(&objets[..1]), None);
        assert_eq!(lire_objets(&[]), None);
        assert_eq!(lire_show("No default controller available\n"), None);
    }

    /// L'oracle : la lecture par BlueZ contre bluetoothctl, sur cette machine. bluetoothctl ne voit que l'adaptateur
    /// par défaut : la comparaison ne vaut qu'avec un seul. Rien de personnel n'est écrit (des nombres seulement).
    #[cfg(target_os = "linux")]
    #[test]
    fn bluez_comme_bluetoothctl() {
        let Some(Ok(natif)) = lire_etat() else {
            return crate::essais::saute("pas d'adaptateur Bluetooth ni de BlueZ joignable");
        };
        if natif.adaptateurs != 1 {
            return crate::essais::saute("plusieurs adaptateurs : bluetoothctl n'en voit qu'un");
        }
        let lancer = |args: &[&str]| {
            crate::commande::lancer_en_anglais(std::process::Command::new("bluetoothctl").args(args), 5)
                .map(|r| r.sortie)
        };
        let Some((allume, visible)) = lancer(&["show"]).as_deref().and_then(lire_show) else {
            return crate::essais::saute("bluetoothctl absent ou muet");
        };
        assert_eq!((natif.allume, !natif.visibles.is_empty()), (allume, visible));
        let mut outil: Vec<String> = lire_appareils(&lancer(&["devices", "Paired"]).unwrap_or_default())
            .into_iter()
            .map(|a| a.adresse)
            .collect();
        let mut lus: Vec<String> = natif.appareils.into_iter().map(|a| a.adresse).collect();
        outil.sort();
        lus.sort();
        assert!(
            outil == lus,
            "appareils appairés : {} par BlueZ, {} par bluetoothctl",
            lus.len(),
            outil.len()
        );
    }

    #[test]
    fn lecture_de_system_profiler() {
        let json = r#"{"SPBluetoothDataType":[{"controller_properties":{"controller_state":"attrib_on",
            "controller_discoverable":"attrib_off"},
            "device_connected":[{"AirPods d'Alice":{"device_address":"F4:65:A6:11:22:33"}}],
            "device_not_connected":[{"Magic Keyboard":{"device_address":"04-4B-ED-44-55-66"}},{"Sans adresse":{}}]}]}"#;
        let e = lire_profil(json).unwrap();
        assert!(e.allume && e.visibles.is_empty());
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
            adaptateurs: 1,
            appareils: vec![casque.clone()],
            ..Etat::default()
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
            adaptateurs: 1,
            visibles: vec![Visible {
                chemin: "/org/bluez/hci0".into(),
                nom: "hci0".into(),
            }],
            appareils: Vec::new(),
        };
        let (c, _) = juger(&etat, Some(&Vus::default()), jour(10));
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert!(c[0].correctif.as_ref().unwrap().automatique);
        assert_eq!(
            c[0].correctif.as_ref().unwrap().commandes,
            ["bluetoothctl discoverable off"]
        );
        // Éteint : visible ou non, personne ne le voit.
        let (c, _) = juger(
            &Etat {
                allume: false,
                visibles: Vec::new(),
                ..etat
            },
            None,
            jour(10),
        );
        assert!(c[0].probleme.is_none() && c[0].message.contains("éteint"));
    }
}
