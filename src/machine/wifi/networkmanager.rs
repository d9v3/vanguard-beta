//! Les bornes Wi-Fi que NetworkManager tient à jour, lues sur le bus système en un seul appel de lecture
//! (GetManagedObjects), sans lancer nmcli : la même liste que `nmcli dev wifi list --rescan no`. NetworkManager garde
//! les bornes de ses dernières recherches, là où le noyau les oublie après 30 s ; aucune recherche n'est demandée
//! d'ici (RequestScan agit sur la carte et n'est pas une lecture permise par le client D-Bus). L'âge de la dernière
//! recherche (LastScan) dit si la liste des voisins suffit à conclure. La lecture des objets est pure, testée sur des
//! valeurs fabriquées.

use super::elements::{Protection, mac_normalisee};
use super::{Balise, Bande, Borne, Connexion, Lecture, Voisins, canal_de_frequence};
use crate::machine::linux::dbus::{Bus, Valeur, service_absent};
use crate::ui::affichable;

const NM: &str = "org.freedesktop.NetworkManager";
const APPAREIL: &str = "org.freedesktop.NetworkManager.Device";
const SANS_FIL: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const POINT_D_ACCES: &str = "org.freedesktop.NetworkManager.AccessPoint";
/// NM_DEVICE_TYPE_WIFI.
const APPAREIL_WIFI: u64 = 2;

// NM80211ApFlags et NM80211ApSecurityFlags (nm-dbus-interface.h).
const AP_CHIFFRE: u64 = 0x1;
const SEC_TKIP: u64 = 0x4 | 0x40;
const SEC_AES: u64 = 0x8 | 0x80;
const SEC_WEP: u64 = 0x1 | 0x2 | 0x10 | 0x20;
const SEC_PSK: u64 = 0x100;
const SEC_ENTREPRISE: u64 = 0x200;
const SEC_SAE: u64 = 0x400;
const SEC_OWE: u64 = 0x800 | 0x1000;
const SEC_SUITE_B: u64 = 0x2000;

/// Ce que NetworkManager sait du Wi-Fi. `Ok(None)` : il n'est pas sur le bus, ou ne gère aucune carte Wi-Fi ;
/// `Err` : le bus refuse ou répond mal.
pub(crate) fn lire() -> Result<Option<Lecture>, crate::modele::raison::Echec> {
    use crate::modele::raison::Echec;
    let mut bus = Bus::systeme().map_err(|e| Echec::echoue("wifi/networkmanager", e))?;
    let objets = match bus.objets(NM, "/org/freedesktop") {
        Ok(o) => o,
        Err(e) if service_absent(&e) => return Ok(None),
        Err(e) => return Err(Echec::echoue("wifi/networkmanager", e)),
    };
    Ok(maintenant_ms().and_then(|t| lecture_des_objets(&objets, t)))
}

/// L'horloge de LastScan : CLOCK_BOOTTIME, en millisecondes (elle avance aussi pendant la veille).
fn maintenant_ms() -> Option<u64> {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime écrit dans une structure à nous, vivante pendant l'appel ; l'horloge existe depuis
    // Linux 2.6.39, et un échec est vérifié avant de lire.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut t) } != 0 {
        return None;
    }
    let s = u64::try_from(t.tv_sec).ok()?;
    let ns = u64::try_from(t.tv_nsec).ok()?;
    Some(s.saturating_mul(1000).saturating_add(ns / 1_000_000))
}

fn entier(proprietes: Option<&Valeur>, nom: &str) -> u64 {
    proprietes
        .and_then(|p| p.champ(nom))
        .and_then(Valeur::entier)
        .unwrap_or(0)
}

/// La protection d'une borne d'après ses drapeaux, comme `elements::lire` la tire des balises. Les trames de gestion
/// protégées et WPS n'y sont pas : COM-WIF-002 garde la lecture du noyau pour WPS.
fn protection(drapeaux: u64, wpa: u64, rsn: u64) -> Protection {
    let tout = wpa | rsn;
    let a = |m: u64| tout & m != 0;
    Protection {
        chiffree: drapeaux & AP_CHIFFRE != 0,
        rsn: rsn != 0,
        wpa: wpa != 0,
        tkip: a(SEC_TKIP),
        aes: a(SEC_AES),
        wep: a(SEC_WEP),
        psk: a(SEC_PSK),
        sae: a(SEC_SAE),
        entreprise: a(SEC_ENTREPRISE),
        suite_b: a(SEC_SUITE_B),
        owe: a(SEC_OWE),
        pmf: false,
        pmf_exigee: false,
    }
}

/// Une borne d'après les propriétés de son objet AccessPoint ; `None` hors des bandes connues.
fn balise(proprietes: &Valeur, actif: bool) -> Option<Balise> {
    let mhz = u32::try_from(entier(Some(proprietes), "Frequency")).ok()?;
    let octets: Vec<u8> = proprietes
        .champ("Ssid")
        .map(Valeur::elements)
        .unwrap_or_default()
        .iter()
        .filter_map(|o| u8::try_from(o.entier()?).ok())
        .collect();
    let ssid = if octets.iter().all(|&o| o == 0) {
        String::new()
    } else {
        affichable(&String::from_utf8_lossy(&octets))
    };
    let bssid = proprietes
        .champ("HwAddress")
        .and_then(Valeur::texte)
        .and_then(mac_normalisee)
        .unwrap_or_default();
    // Une force absente ou d'un autre type n'est pas « 0 % » : inconnue.
    let signal = proprietes
        .champ("Strength")
        .and_then(Valeur::entier)
        .and_then(|s| u8::try_from(s.min(100)).ok());
    Some(Balise {
        borne: Borne {
            ssid,
            bssid,
            bande: Bande::de_frequence(mhz)?,
            canal: canal_de_frequence(mhz)?,
            signal,
            actif,
        },
        protection: protection(
            entier(Some(proprietes), "Flags"),
            entier(Some(proprietes), "WpaFlags"),
            entier(Some(proprietes), "RsnFlags"),
        ),
        wps: None,
    })
}

/// LastScan d'une carte (x) : `None` pour -1, jamais cherché.
fn derniere_recherche(sans_fil: &Valeur) -> Option<u64> {
    match sans_fil.champ("LastScan")? {
        Valeur::I64(n) => u64::try_from(*n).ok(),
        v => v.entier(),
    }
}

/// La lecture d'après les objets de NetworkManager (chemin, interfaces et leurs propriétés) ; `None` : aucune carte
/// Wi-Fi gérée. `maintenant_ms` : l'horloge de LastScan.
fn lecture_des_objets(objets: &[(String, Valeur)], maintenant_ms: u64) -> Option<Lecture> {
    let cartes: Vec<&Valeur> = objets
        .iter()
        .filter(|(_, interfaces)| entier(interfaces.champ(APPAREIL), "DeviceType") == APPAREIL_WIFI)
        .filter_map(|(_, interfaces)| interfaces.champ(SANS_FIL))
        .collect();
    if cartes.is_empty() {
        return None;
    }
    let point = |chemin: &str| {
        objets
            .iter()
            .find(|(c, _)| c == chemin)
            .and_then(|(_, interfaces)| interfaces.champ(POINT_D_ACCES))
    };
    let mut lecture = Lecture::default();
    for carte in &cartes {
        let active = carte.champ("ActiveAccessPoint").and_then(Valeur::texte).unwrap_or("/");
        for chemin in carte.champ("AccessPoints").map(Valeur::textes).unwrap_or_default() {
            let Some(b) = point(&chemin).and_then(|p| balise(p, chemin == active)) else {
                continue;
            };
            if lecture.connexion.is_none() && b.borne.actif {
                lecture.connexion = Some(Connexion {
                    ssid: b.borne.ssid.clone(),
                    bssid: b.borne.bssid.clone(),
                    qualite: b.borne.signal,
                    canal: Some(b.borne.canal),
                    bande: Some(b.borne.bande),
                    // NetworkManager ne dit pas la protection négociée : celle de la borne.
                    securite: String::new(),
                });
            }
            if !lecture
                .balises
                .iter()
                .any(|d| d.borne.bssid == b.borne.bssid && d.borne.canal == b.borne.canal)
            {
                lecture.balises.push(b);
            }
        }
    }
    // Une carte associée dont la borne manque à la liste (fréquence hors des bandes connues, objet absent) : le réseau
    // connecté n'est pas lu, et « pas connecté » serait faux. Le noyau, qui le dit avec l'interface, prend la main.
    let associee = cartes.iter().any(|c| {
        c.champ("ActiveAccessPoint")
            .and_then(Valeur::texte)
            .is_some_and(|a| a != "/")
    });
    if associee && lecture.connexion.is_none() {
        return None;
    }
    // La recherche la plus récente des cartes dit l'âge de la liste.
    lecture.voisins = match cartes.iter().filter_map(|c| derniere_recherche(c)).max() {
        Some(t) => Voisins::selon_age(maintenant_ms.saturating_sub(t) / 1000),
        None => Voisins::JamaisCherches,
    };
    Some(lecture)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Valeur {
        Valeur::texte_de(s)
    }

    fn v(signature: &str, valeur: Valeur) -> Valeur {
        Valeur::Variante(signature.into(), Box::new(valeur))
    }

    /// Un dictionnaire `a{sv}`.
    fn proprietes(paires: Vec<(&str, Valeur)>) -> Valeur {
        Valeur::Dictionnaire(paires.into_iter().map(|(k, val)| (t(k), val)).collect())
    }

    /// Un objet de GetManagedObjects : son chemin, et ses interfaces avec leurs propriétés (`a{sa{sv}}`).
    fn objet(chemin: &str, interfaces: Vec<(&str, Valeur)>) -> (String, Valeur) {
        (
            chemin.into(),
            Valeur::Dictionnaire(interfaces.into_iter().map(|(k, val)| (t(k), val)).collect()),
        )
    }

    fn point(chemin: &str, ssid: &str, mac: &str, mhz: u32, force: u8, drapeaux: (u32, u32, u32)) -> (String, Valeur) {
        let octets = ssid.bytes().map(Valeur::Octet).collect();
        objet(
            chemin,
            vec![(
                POINT_D_ACCES,
                proprietes(vec![
                    ("Ssid", v("ay", Valeur::Tableau(octets))),
                    ("HwAddress", v("s", t(mac))),
                    ("Frequency", v("u", Valeur::U32(mhz))),
                    ("Strength", v("y", Valeur::Octet(force))),
                    ("Flags", v("u", Valeur::U32(drapeaux.0))),
                    ("WpaFlags", v("u", Valeur::U32(drapeaux.1))),
                    ("RsnFlags", v("u", Valeur::U32(drapeaux.2))),
                ]),
            )],
        )
    }

    fn carte(points: &[&str], active: &str, derniere: i64) -> (String, Valeur) {
        objet(
            "/org/freedesktop/NetworkManager/Devices/3",
            vec![
                (APPAREIL, proprietes(vec![("DeviceType", v("u", Valeur::U32(2)))])),
                (
                    SANS_FIL,
                    proprietes(vec![
                        (
                            "AccessPoints",
                            v("ao", Valeur::Tableau(points.iter().map(|p| t(p)).collect())),
                        ),
                        ("ActiveAccessPoint", v("o", t(active))),
                        ("LastScan", v("x", Valeur::I64(derniere))),
                    ]),
                ),
            ],
        )
    }

    const AP1: &str = "/org/freedesktop/NetworkManager/AccessPoint/1";
    const AP2: &str = "/org/freedesktop/NetworkManager/AccessPoint/2";

    fn objets(derniere: i64) -> Vec<(String, Valeur)> {
        vec![
            objet(
                "/org/freedesktop/NetworkManager/Devices/1",
                vec![(APPAREIL, proprietes(vec![("DeviceType", v("u", Valeur::U32(1)))]))],
            ),
            carte(&[AP1, AP2], AP1, derniere),
            // WPA2 en AES avec mot de passe ; un voisin ouvert du même nom.
            point(AP1, "Salon", "02:00:00:AA:BB:01", 5180, 72, (1, 0, 0x188)),
            point(AP2, "Salon", "02:00:00:AA:BB:02", 2437, 40, (0, 0, 0)),
        ]
    }

    #[test]
    fn bornes_connexion_et_age_de_la_liste() {
        let maintenant: u64 = 1_000_000_000;
        let il_y_a = |ms: u64| i64::try_from(maintenant - ms).unwrap();
        let l = lecture_des_objets(&objets(il_y_a(230_000)), maintenant).unwrap();
        assert_eq!(l.balises.len(), 2);
        let a = &l.balises[0];
        assert_eq!(
            (a.borne.ssid.as_str(), a.borne.bssid.as_str()),
            ("Salon", "02:00:00:aa:bb:01")
        );
        assert_eq!(
            (a.borne.bande, a.borne.canal, a.borne.signal, a.borne.actif),
            (Bande::G5, 36, Some(72), true)
        );
        assert_eq!(a.protection.libelle(), "WPA2");
        assert!(a.protection.aes && !a.protection.tkip && a.wps.is_none());
        assert_eq!(l.balises[1].protection.force(), 0);
        assert_eq!(
            l.connexion,
            Some(Connexion {
                ssid: "Salon".into(),
                bssid: "02:00:00:aa:bb:01".into(),
                qualite: Some(72),
                canal: Some(36),
                bande: Some(Bande::G5),
                securite: String::new(),
            })
        );
        assert_eq!(l.voisins, Voisins::Recents);
        // Le jumeau ouvert se voit dans le bilan.
        let c = super::super::bilan(&l, &[]);
        assert_eq!(c.len(), 2);
        // Une liste de 20 min, puis jamais cherché : non vérifiés.
        let l = lecture_des_objets(&objets(il_y_a(1_200_000)), maintenant).unwrap();
        assert_eq!(l.voisins, Voisins::Anciens { minutes: 20 });
        let l = lecture_des_objets(&objets(-1), maintenant).unwrap();
        assert_eq!(l.voisins, Voisins::JamaisCherches);
        assert!(l.reserve_voisins().is_some());
        // Sans carte Wi-Fi : rien à lire.
        assert_eq!(lecture_des_objets(&objets(0)[..1], maintenant), None);
        assert_eq!(lecture_des_objets(&[], maintenant), None);
    }

    #[test]
    fn noms_caches_pieges_et_valeurs_abimees() {
        let mut o = objets(0);
        o[2] = point(AP1, "", "pas une adresse", 5180, 250, (0, 0, 0));
        o[3] = point(AP2, "Salon\x1b[2K", "02:00:00:aa:bb:02", 900, 40, (0, 0, 0));
        let l = lecture_des_objets(&o, 0).unwrap();
        // Hors bande : écartée ; nom vide ; adresse illisible : vide ; force bornée.
        assert_eq!(l.balises.len(), 1);
        assert_eq!(
            (l.balises[0].borne.ssid.as_str(), l.balises[0].borne.bssid.as_str()),
            ("", "")
        );
        assert_eq!(l.balises[0].borne.signal, Some(100));
        o[3] = point(AP2, "Salon\x1b[2K", "02:00:00:aa:bb:02", 2412, 40, (0, 0, 0));
        let l = lecture_des_objets(&o, 0).unwrap();
        assert!(!crate::ui::contient_un_piege(&l.balises[1].borne.ssid));
        // Des propriétés d'un autre type que prévu ne font rien planter.
        let abime = vec![
            carte(&[AP1], AP1, 0),
            objet(
                AP1,
                vec![(POINT_D_ACCES, proprietes(vec![("Frequency", v("s", t("x")))]))],
            ),
        ];
        // La borne de la connexion illisible : la carte est associée, mais le réseau connecté ne se lit pas ; le
        // noyau prend la main plutôt qu'un « pas connecté ».
        assert_eq!(lecture_des_objets(&abime, 0), None);
        let abime_libre = vec![carte(&[AP1], "/", 0), abime[1].clone()];
        assert_eq!(lecture_des_objets(&abime_libre, 0).map(|l| l.balises.len()), Some(0));
    }

    #[test]
    fn protections_selon_les_drapeaux() {
        for ((drapeaux, wpa, rsn), attendu) in [
            ((0, 0, 0), "ouvert"),
            ((1, 0, 0), "WEP"),
            ((1, 0x144, 0), "WPA"),
            ((1, 0x144, 0x188), "WPA/WPA2"),
            ((1, 0, 0x188), "WPA2"),
            ((1, 0, 0x588), "WPA2/WPA3"),
            ((1, 0, 0x488), "WPA3"),
            ((1, 0, 0x288), "WPA2-Enterprise"),
            ((1, 0, 0x2288), "WPA3-Enterprise"),
            ((1, 0, 0x888), "OWE"),
        ] {
            let p = protection(drapeaux, wpa, rsn);
            let attendu = if attendu == "ouvert" { tr_ouvert() } else { attendu };
            assert_eq!(p.libelle(), attendu, "{drapeaux:#x} {wpa:#x} {rsn:#x}");
        }
        assert!(protection(1, 0x144, 0x188).tkip);
        assert!(protection(1, 0x11, 0).wep);
    }

    fn tr_ouvert() -> &'static str {
        crate::tr!("ouvert", "open")
    }

    /// Le vrai bus : NetworkManager voit les mêmes bornes que nmcli, et la même active. Rien n'est affiché, sauf des
    /// nombres en cas d'écart ; sauté sans NetworkManager, sans bus (`unshare -rn`) ou sans nmcli.
    #[test]
    fn memes_bornes_que_nmcli() {
        let Ok(Some(l)) = lire() else {
            return crate::essais::saute("NetworkManager absent du bus");
        };
        let Some(r) = crate::commande::lancer_en_anglais(
            std::process::Command::new("nmcli").args([
                "-t",
                "-f",
                "BSSID,ACTIVE",
                "dev",
                "wifi",
                "list",
                "--rescan",
                "no",
            ]),
            20,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("nmcli absent");
        };
        // « 02\:00\:00\:AA\:BB\:01:yes » : les « : » de l'adresse sont échappés.
        let mut nmcli: Vec<(String, bool)> = r
            .sortie
            .lines()
            .filter_map(|ligne| {
                let ligne = ligne.replace("\\:", "-");
                let (mac, actif) = ligne.rsplit_once(':')?;
                Some((mac.replace('-', ":").to_ascii_lowercase(), actif == "yes"))
            })
            .collect();
        let mut natif: Vec<(String, bool)> = l
            .balises
            .iter()
            .map(|b| (b.borne.bssid.clone(), b.borne.actif))
            .collect();
        nmcli.sort();
        nmcli.dedup();
        natif.sort();
        natif.dedup();
        // nmcli rafraîchit sa liste au même moment : une borne apparue entre les deux lectures se tolère.
        let communs = natif.iter().filter(|b| nmcli.contains(b)).count();
        assert!(
            communs + 2 >= natif.len().max(nmcli.len()),
            "natif {} bornes, nmcli {}, communes {communs}",
            natif.len(),
            nmcli.len()
        );
        assert_eq!(
            natif.iter().filter(|b| b.1).count(),
            nmcli.iter().filter(|b| b.1).count(),
            "bornes actives"
        );
        // Comparées sans être montrées : ce sont les adresses des bornes de la maison.
        assert!(
            natif.iter().find(|b| b.1).map(|b| &b.0) == nmcli.iter().find(|b| b.1).map(|b| &b.0),
            "borne active différente"
        );
    }
}
