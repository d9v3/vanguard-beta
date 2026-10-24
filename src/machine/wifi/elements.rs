//! Les éléments d'information des balises 802.11 : ce qu'une borne annonce d'elle-même à qui écoute, décodé octet
//! par octet depuis ce que le noyau (nl80211) ou Windows (wlanapi) ont gardé du dernier balayage. On y lit les
//! chiffrements acceptés (élément RSN pour WPA2 et WPA3, élément WPA de 2003) et WPS, qui ne se voit que là : ni
//! nmcli ni netsh ne le disent. Lecture seule, sur des octets choisis par la borne d'en face : chaque longueur est
//! vérifiée, un élément tronqué arrête la lecture sans rien casser.

use crate::tr;
use crate::ui::affichable;

/// Identifiants des éléments (IEEE 802.11-2020, tableau 9-92).
const ELEMENT_SSID: u8 = 0;
const ELEMENT_RSN: u8 = 48;
const ELEMENT_FABRICANT: u8 = 221;
/// L'OUI de Microsoft porte l'élément WPA (type 1) et l'élément WPS (type 4).
const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xF2];
/// L'OUI de l'IEEE 802.11 porte les suites de chiffrement et d'authentification de RSN.
const OUI_80211: [u8; 3] = [0x00, 0x0F, 0xAC];
/// Bit « Privacy » du champ des capacités : la borne chiffre.
const CAPACITE_CHIFFREE: u16 = 0x0010;
/// Attributs de WPS (Wi-Fi Simple Configuration 2.0, tableau 28), en gros-boutiste.
const WPS_ETAT: u16 = 0x1044;
const WPS_VERROUILLE: u16 = 0x1057;
const WPS_REGISTRAIRE: u16 = 0x1041;
const WPS_METHODES: u16 = 0x1008;
/// Méthodes de configuration WPS qui passent par un code PIN : étiquette, écran, clavier, écrans virtuel et
/// physique.
const METHODES_PIN: u16 = 0x0004 | 0x0008 | 0x0100 | 0x2000 | 0x4000;
/// Méthodes par bouton : poussoir, poussoir virtuel, poussoir physique.
const METHODES_BOUTON: u16 = 0x0080 | 0x0200 | 0x0400;
/// Suites lues au plus par liste : une borne n'en annonce que quelques-unes.
const SUITES_MAX: u16 = 16;

/// Ce qu'une borne annonce de son chiffrement : des drapeaux indépendants, lus tels quels dans ses balises (une
/// borne annonce souvent plusieurs suites à la fois), d'où autant de booléens.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Protection {
    /// Le bit « Privacy » des capacités : la borne chiffre ; sans élément RSN ni WPA, c'est du WEP.
    pub chiffree: bool,
    /// Un élément RSN : WPA2 ou WPA3.
    pub rsn: bool,
    /// L'élément WPA de 2003 (première version).
    pub wpa: bool,
    /// TKIP accepté, en chiffrement de paire ou de groupe.
    pub tkip: bool,
    /// CCMP ou GCMP (AES) accepté.
    pub aes: bool,
    /// WEP annoncé comme suite de chiffrement (réseaux mixtes WEP/WPA d'autrefois).
    pub wep: bool,
    /// Mot de passe partagé (PSK).
    pub psk: bool,
    /// SAE : WPA3-Personal.
    pub sae: bool,
    /// 802.1X : entreprise.
    pub entreprise: bool,
    /// Suite B 802.1X : WPA3-Enterprise.
    pub suite_b: bool,
    /// OWE : chiffré sans mot de passe (« Enhanced Open »).
    pub owe: bool,
    /// Trames de gestion protégées (802.11w) possibles.
    pub pmf: bool,
    /// Trames de gestion protégées exigées.
    pub pmf_exigee: bool,
}

impl Protection {
    /// Le nom que les systèmes donnent à cette protection, tel que `wifi::force` et `wifi::securite` le lisent :
    /// « WPA3 », « WPA2/WPA3 », « WPA2 », « WPA/WPA2 », « WPA2-Enterprise », « WPA », « WEP », « OWE », « ouvert ».
    pub(crate) fn libelle(self) -> &'static str {
        match self {
            p if p.suite_b => "WPA3-Enterprise",
            p if p.entreprise && p.rsn => "WPA2-Enterprise",
            p if p.entreprise => "WPA-Enterprise",
            p if p.owe && !p.psk && !p.sae => "OWE",
            p if p.sae && !p.psk => "WPA3",
            p if p.sae => "WPA2/WPA3",
            p if p.rsn && p.wpa => "WPA/WPA2",
            p if p.rsn => "WPA2",
            p if p.wpa => "WPA",
            p if p.chiffree => "WEP",
            _ => tr!("ouvert", "open"),
        }
    }

    /// Force sur l'échelle de `wifi::force` : 0 ouverte (ni RSN, ni WPA, ni le bit « Privacy »), 1 faible, 2 WPA2,
    /// 3 WPA3 ou entreprise.
    pub(crate) fn force(self) -> u8 {
        super::force(self.libelle())
    }
}

/// Ce que la borne annonce de WPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Wps {
    /// « Wi-Fi Protected Setup State » : 2 configuré (le plus courant), 1 pas encore configuré.
    pub etat: u8,
    /// « AP Setup Locked » : la borne a verrouillé la méthode PIN après trop d'essais.
    pub verrouille: bool,
    /// « Selected Registrar » : un enregistrement est en cours (bouton pressé, deux minutes).
    pub registraire: bool,
    /// « Config Methods », quand la borne les dit (réponse de sondage plutôt que balise).
    pub methodes: Option<u16>,
}

impl Wps {
    /// La méthode PIN est-elle offerte ? `None` : la borne ne dit pas ses méthodes.
    pub(crate) fn pin(self) -> Option<bool> {
        self.methodes.map(|m| m & METHODES_PIN != 0)
    }

    /// Le bouton est offert.
    pub(crate) fn bouton(self) -> bool {
        self.methodes.is_some_and(|m| m & METHODES_BOUTON != 0)
    }
}

/// Ce que les éléments d'une balise disent de la borne.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Elements {
    /// Vide si le réseau est caché.
    pub ssid: String,
    pub protection: Protection,
    pub wps: Option<Wps>,
}

/// Les éléments d'une balise, un par un : (identifiant, contenu). Un élément tronqué arrête la lecture.
fn elements(ies: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let id = *ies.get(pos)?;
        let longueur = usize::from(*ies.get(pos + 1)?);
        let corps = ies.get(pos + 2..pos + 2 + longueur)?;
        pos += 2 + longueur;
        Some((id, corps))
    })
}

/// Un curseur sur le contenu d'un élément : chaque lecture vérifie qu'il reste assez d'octets.
struct Curseur<'a> {
    octets: &'a [u8],
    pos: usize,
}

impl Curseur<'_> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.octets.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn u16_le(&mut self) -> Option<u16> {
        let o = self.octets.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes([o[0], o[1]]))
    }

    fn u16_be(&mut self) -> Option<u16> {
        let o = self.octets.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_be_bytes([o[0], o[1]]))
    }

    /// Une suite de chiffrement ou d'authentification : son OUI (3 octets) et son type.
    fn suite(&mut self) -> Option<([u8; 3], u8)> {
        let o = self.octets.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(([o[0], o[1], o[2]], o[3]))
    }

    fn sauter(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n).filter(|p| *p <= self.octets.len())?;
        Some(())
    }
}

/// Note une suite de chiffrement (RSN : OUI de l'IEEE ; WPA : OUI de Microsoft, mêmes numéros pour WEP, TKIP et
/// CCMP).
fn chiffrement(suite: ([u8; 3], u8), oui: [u8; 3], p: &mut Protection) {
    if suite.0 != oui {
        return;
    }
    match suite.1 {
        1 | 5 => p.wep = true,
        2 => p.tkip = true,
        4 | 8..=10 => p.aes = true,
        _ => {}
    }
}

/// Note une suite d'authentification (AKM).
fn authentification(suite: ([u8; 3], u8), oui: [u8; 3], p: &mut Protection) {
    if suite.0 != oui {
        return;
    }
    match suite.1 {
        1 | 3 | 5 => p.entreprise = true,
        2 | 4 | 6 | 19 | 20 => p.psk = true,
        8 | 9 | 24 | 25 => p.sae = true,
        11..=13 => p.suite_b = true,
        18 => p.owe = true,
        _ => {}
    }
}

/// L'élément RSN (WPA2, WPA3) : version, suite de groupe, suites de paire, suites d'authentification, capacités.
/// L'élément WPA de 2003 a la même forme, sans capacités, derrière l'OUI de Microsoft.
fn lire_suites(corps: &[u8], oui: [u8; 3], p: &mut Protection) -> Option<()> {
    let mut c = Curseur { octets: corps, pos: 0 };
    c.u16_le()?;
    chiffrement(c.suite()?, oui, p);
    let n = c.u16_le()?.min(SUITES_MAX);
    for _ in 0..n {
        chiffrement(c.suite()?, oui, p);
    }
    let n = c.u16_le()?.min(SUITES_MAX);
    for _ in 0..n {
        authentification(c.suite()?, oui, p);
    }
    if oui == OUI_80211 {
        let capacites = c.u16_le()?;
        p.pmf_exigee = capacites & 0x0040 != 0;
        p.pmf = capacites & 0x0080 != 0;
    }
    Some(())
}

/// L'élément WPS : des attributs (type, longueur, valeur) en gros-boutiste ; un attribut tronqué arrête la lecture.
fn lire_wps(corps: &[u8], w: &mut Wps) {
    let mut c = Curseur { octets: corps, pos: 0 };
    while let (Some(genre), Some(longueur)) = (c.u16_be(), c.u16_be()) {
        let debut = c.pos;
        match (genre, longueur) {
            (WPS_ETAT, 1) => w.etat = c.u8().unwrap_or(0),
            (WPS_VERROUILLE, 1) => w.verrouille = c.u8().is_some_and(|v| v != 0),
            (WPS_REGISTRAIRE, 1) => w.registraire = c.u8().is_some_and(|v| v != 0),
            (WPS_METHODES, 2) => w.methodes = c.u16_be(),
            _ => {}
        }
        c.pos = debut;
        if c.sauter(usize::from(longueur)).is_none() {
            return;
        }
    }
}

/// Lit les éléments d'une balise ; `capacites` est le champ des capacités de la trame (bit « Privacy »). macOS ne
/// donne pas ses balises (CoreWLAN) : rien ne l'appelle là-bas.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn lire(ies: &[u8], capacites: u16) -> Elements {
    let mut e = Elements {
        protection: Protection {
            chiffree: capacites & CAPACITE_CHIFFREE != 0,
            ..Protection::default()
        },
        ..Elements::default()
    };
    // Un élément WPS de plus de 255 octets est coupé en plusieurs éléments à la suite : recollés avant lecture.
    let mut wps: Option<Vec<u8>> = None;
    for (id, corps) in elements(ies) {
        match id {
            ELEMENT_SSID if e.ssid.is_empty() => {
                // Un réseau caché annonce un nom vide, ou rempli de zéros.
                if corps.iter().any(|&o| o != 0) {
                    e.ssid = affichable(&String::from_utf8_lossy(corps));
                }
            }
            ELEMENT_RSN => {
                e.protection.rsn = true;
                lire_suites(corps, OUI_80211, &mut e.protection);
            }
            ELEMENT_FABRICANT if corps.starts_with(&OUI_MICROSOFT) => match corps.get(3) {
                Some(1) => {
                    e.protection.wpa = true;
                    lire_suites(&corps[4..], OUI_MICROSOFT, &mut e.protection);
                }
                Some(4) => wps.get_or_insert_with(Vec::new).extend_from_slice(&corps[4..]),
                _ => {}
            },
            _ => {}
        }
    }
    if let Some(octets) = wps {
        let mut w = Wps::default();
        lire_wps(&octets, &mut w);
        e.wps = Some(w);
    }
    e
}

/// Une adresse MAC en texte, « aa:bb:cc:dd:ee:ff » ; vide si ce n'en est pas une.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn mac_texte(octets: &[u8]) -> String {
    if octets.len() != 6 {
        return String::new();
    }
    octets.iter().map(|o| format!("{o:02x}")).collect::<Vec<_>>().join(":")
}

/// Une adresse MAC écrite par un outil (« AA:BB:…», « aa-bb-… »), normalisée en minuscules avec des deux-points ;
/// `None` si ce n'en est pas une. Sert à NetworkManager, qui l'écrit en majuscules.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn mac_normalisee(texte: &str) -> Option<String> {
    let parties: Vec<u8> = texte
        .trim()
        .split([':', '-'])
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    (parties.len() == 6).then(|| mac_texte(&parties))
}

/// Fabrique des éléments d'information pour les tests des lecteurs (ici, nl80211, wlanapi, audit).
#[cfg(test)]
pub(crate) mod fabrique {
    use super::{ELEMENT_FABRICANT, ELEMENT_RSN, ELEMENT_SSID, OUI_80211, OUI_MICROSOFT};

    /// Un élément : identifiant, longueur, contenu.
    pub(crate) fn element(id: u8, corps: &[u8]) -> Vec<u8> {
        let mut e = vec![id, u8::try_from(corps.len()).expect("élément de 255 octets au plus")];
        e.extend_from_slice(corps);
        e
    }

    pub(crate) fn ssid(nom: &str) -> Vec<u8> {
        element(ELEMENT_SSID, nom.as_bytes())
    }

    fn suites(oui: [u8; 3], groupe: u8, paires: &[u8], akm: &[u8]) -> Vec<u8> {
        let mut c = vec![1, 0];
        c.extend_from_slice(&oui);
        c.push(groupe);
        let liste = |types: &[u8]| {
            let mut l = u16::try_from(types.len()).unwrap().to_le_bytes().to_vec();
            for t in types {
                l.extend_from_slice(&oui);
                l.push(*t);
            }
            l
        };
        c.extend(liste(paires));
        c.extend(liste(akm));
        c
    }

    /// Un élément RSN : chiffrement de groupe, chiffrements de paire, authentifications, capacités.
    pub(crate) fn rsn(groupe: u8, paires: &[u8], akm: &[u8], capacites: u16) -> Vec<u8> {
        let mut c = suites(OUI_80211, groupe, paires, akm);
        c.extend_from_slice(&capacites.to_le_bytes());
        element(ELEMENT_RSN, &c)
    }

    /// L'élément WPA de 2003.
    pub(crate) fn wpa(groupe: u8, paires: &[u8], akm: &[u8]) -> Vec<u8> {
        let mut c = OUI_MICROSOFT.to_vec();
        c.push(1);
        c.extend(suites(OUI_MICROSOFT, groupe, paires, akm));
        element(ELEMENT_FABRICANT, &c)
    }

    /// Un élément WPS avec ses attributs (type, valeur).
    pub(crate) fn wps(attributs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut c = OUI_MICROSOFT.to_vec();
        c.push(4);
        for (genre, valeur) in attributs {
            c.extend_from_slice(&genre.to_be_bytes());
            c.extend_from_slice(&u16::try_from(valeur.len()).unwrap().to_be_bytes());
            c.extend_from_slice(valeur);
        }
        element(ELEMENT_FABRICANT, &c)
    }

    /// Les balises d'une box WPA2-AES ordinaire avec WPS configuré (PIN par écran et bouton).
    pub(crate) fn box_ordinaire(nom: &str) -> Vec<u8> {
        [
            ssid(nom),
            rsn(4, &[4], &[2], 0x0080),
            wps(&[(0x1044, &[2]), (0x1008, &0x2088u16.to_be_bytes())]),
        ]
        .concat()
    }
}

#[cfg(test)]
mod tests {
    use super::fabrique::*;
    use super::*;

    #[test]
    fn wpa2_aes_avec_wps() {
        let e = lire(&box_ordinaire("Salon"), 0x0411);
        assert_eq!(e.ssid, "Salon");
        let p = e.protection;
        assert!(p.chiffree && p.rsn && p.aes && p.psk && p.pmf && !p.tkip && !p.wpa && !p.sae && !p.pmf_exigee);
        assert_eq!(p.libelle(), "WPA2");
        assert_eq!(p.force(), 2);
        let w = e.wps.expect("WPS");
        assert_eq!(w.etat, 2);
        assert_eq!(w.pin(), Some(true));
        assert!(w.bouton() && !w.verrouille && !w.registraire);
    }

    #[test]
    fn tkip_mixte_et_wpa_de_2003() {
        // WPA2 avec TKIP accepté en groupe et en paire, à côté de CCMP : le cas « mixte » des box.
        let ies = [ssid("Salon"), rsn(2, &[2, 4], &[2], 0)].concat();
        let p = lire(&ies, 0x0010).protection;
        assert!(p.tkip && p.aes && p.rsn);
        assert_eq!(p.libelle(), "WPA2");
        // L'élément WPA seul : première version, TKIP.
        let ies = [ssid("Salon"), wpa(2, &[2], &[2])].concat();
        let p = lire(&ies, 0x0010).protection;
        assert!(p.wpa && p.tkip && !p.rsn && !p.aes);
        assert_eq!(p.libelle(), "WPA");
        assert_eq!(p.force(), 1);
        // Les deux éléments : WPA/WPA2.
        let ies = [wpa(2, &[2], &[2]), rsn(2, &[4], &[2], 0)].concat();
        assert_eq!(lire(&ies, 0x0010).protection.libelle(), "WPA/WPA2");
    }

    #[test]
    fn wpa3_entreprise_owe_wep_et_ouvert() {
        assert_eq!(lire(&rsn(4, &[4], &[8], 0x00C0), 0x10).protection.libelle(), "WPA3");
        let mixte = lire(&rsn(4, &[4], &[2, 8], 0x0080), 0x10).protection;
        assert_eq!(mixte.libelle(), "WPA2/WPA3");
        assert_eq!(mixte.force(), 3);
        assert!(lire(&rsn(4, &[4], &[8], 0x00C0), 0x10).protection.pmf_exigee);
        assert_eq!(
            lire(&rsn(4, &[4], &[1], 0), 0x10).protection.libelle(),
            "WPA2-Enterprise"
        );
        assert_eq!(
            lire(&rsn(9, &[9], &[12], 0), 0x10).protection.libelle(),
            "WPA3-Enterprise"
        );
        assert_eq!(lire(&wpa(2, &[2], &[1]), 0x10).protection.libelle(), "WPA-Enterprise");
        let owe = lire(&rsn(4, &[4], &[18], 0x00C0), 0x10).protection;
        assert_eq!(owe.libelle(), "OWE");
        assert_eq!(owe.force(), 1);
        // Chiffrée sans RSN ni WPA : WEP.
        let wep = lire(&ssid("Vieux"), 0x0010).protection;
        assert_eq!(wep.libelle(), "WEP");
        assert_eq!(wep.force(), 1);
        // Ni chiffrement ni élément : ouvert.
        let ouvert = lire(&ssid("Café"), 0x0001).protection;
        assert_eq!(ouvert.force(), 0);
        assert_eq!(ouvert.libelle(), tr!("ouvert", "open"));
    }

    #[test]
    fn wps_verrouille_bouton_seul_et_sans_methodes() {
        let w = lire(
            &wps(&[(0x1044, &[2]), (0x1057, &[1]), (0x1008, &0x0080u16.to_be_bytes())]),
            0,
        )
        .wps
        .unwrap();
        assert!(w.verrouille);
        assert_eq!(w.pin(), Some(false));
        assert!(w.bouton());
        // Dans une balise, les méthodes manquent souvent : on ne conclut rien sur le PIN.
        let w = lire(&wps(&[(0x104A, &[0x10]), (0x1044, &[1]), (0x1041, &[1])]), 0)
            .wps
            .unwrap();
        assert_eq!((w.etat, w.pin(), w.bouton(), w.registraire), (1, None, false, true));
        // Un élément WPS coupé en deux (plus de 255 octets en tout) se recolle.
        let (a, b) = (wps(&[(0x1044, &[2])]), wps(&[(0x1008, &0x0004u16.to_be_bytes())]));
        let w = lire(&[a, b].concat(), 0).wps.unwrap();
        assert_eq!((w.etat, w.pin()), (2, Some(true)));
        // Sans élément WPS : rien.
        assert_eq!(lire(&box_ordinaire("Salon")[..7], 0).wps, None);
    }

    #[test]
    fn noms_caches_et_pieges() {
        assert_eq!(lire(&element(0, &[0, 0, 0, 0]), 0).ssid, "");
        assert_eq!(lire(&element(0, &[]), 0).ssid, "");
        let e = lire(&ssid("Salon\x1b[2K\rFaux"), 0);
        assert_eq!(e.ssid, "Salon�[2K�Faux");
        assert!(!crate::ui::contient_un_piege(&e.ssid));
        // Des octets qui ne sont pas de l'UTF-8 : lisibles quand même.
        assert_eq!(lire(&element(0, &[0x53, 0xFF, 0x61]), 0).ssid, "S�a");
        // Le premier nom gagne ; un second élément SSID n'écrase rien.
        assert_eq!(lire(&[ssid("Un"), ssid("Deux")].concat(), 0).ssid, "Un");
    }

    #[test]
    fn elements_tronques_sans_plantage() {
        let complet = box_ordinaire("Salon");
        for n in 0..complet.len() {
            let e = lire(&complet[..n], 0x0010);
            assert!(!crate::ui::contient_un_piege(&e.ssid));
        }
        // Un RSN qui annonce 60 000 suites de paire n'en fait lire que 16, puis s'arrête proprement.
        let mut gros = vec![1, 0, 0, 0x0F, 0xAC, 4, 0x60, 0xEA];
        gros.extend(std::iter::repeat_n([0, 0x0F, 0xAC, 2], 40).flatten());
        let p = lire(&element(48, &gros), 0x10).protection;
        assert!(p.rsn && p.tkip && p.aes && !p.psk);
        // Un attribut WPS dont la longueur dépasse le contenu arrête la lecture : l'état lu avant reste.
        let mut corps = OUI_MICROSOFT.to_vec();
        corps.extend_from_slice(&[4, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x08, 0x00, 0x02, 0x20]);
        let tronque = element(ELEMENT_FABRICANT, &corps);
        assert_eq!(lire(&tronque, 0).wps.map(|w| (w.etat, w.methodes)), Some((2, None)));
        // Une méthode annoncée sur un octet au lieu de deux n'est pas lue.
        let courte = wps(&[(0x1044, &[2]), (0x1008, &[0x20])]);
        assert_eq!(lire(&courte, 0).wps.map(|w| (w.etat, w.methodes)), Some((2, None)));
    }

    #[test]
    fn adresses_mac() {
        assert_eq!(mac_texte(&[2, 0, 0, 0xAA, 0xBB, 1]), "02:00:00:aa:bb:01");
        assert_eq!(mac_texte(&[1, 2, 3]), "");
        assert_eq!(
            mac_normalisee("02:00:00:AA:BB:01").as_deref(),
            Some("02:00:00:aa:bb:01")
        );
        assert_eq!(
            mac_normalisee(" 02-00-00-aa-bb-01 ").as_deref(),
            Some("02:00:00:aa:bb:01")
        );
        assert_eq!(mac_normalisee("02:00:00:aa:bb"), None);
        assert_eq!(mac_normalisee("zz:00:00:aa:bb:01"), None);
        assert_eq!(mac_normalisee(""), None);
    }
}

/// Quoi qu'annonce la borne d'en face, le lecteur ne plante pas, et un nom lu ne pilote jamais le terminal.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lecture_sans_plantage(ies in prop::collection::vec(any::<u8>(), 0..300), capacites in any::<u16>()) {
            let e = lire(&ies, capacites);
            prop_assert!(!crate::ui::contient_un_piege(&e.ssid));
            prop_assert!(e.ssid.chars().count() <= 255);
            prop_assert!(e.protection.force() <= 3);
        }

        #[test]
        fn elements_fabriques_relus(nom in "[a-zA-Z0-9 éà_-]{1,32}", paires in prop::collection::vec(1u8..=10, 1..4),
                                    akm in prop::collection::vec(1u8..=25, 1..4), methodes in any::<u16>()) {
            let ies = [
                super::fabrique::ssid(&nom),
                super::fabrique::rsn(4, &paires, &akm, 0),
                super::fabrique::wps(&[(0x1044, &[2]), (0x1008, &methodes.to_be_bytes())]),
            ].concat();
            let e = lire(&ies, 0x0010);
            prop_assert_eq!(&e.ssid, &nom);
            prop_assert!(e.protection.rsn && e.protection.chiffree);
            prop_assert_eq!(e.protection.tkip, paires.contains(&2));
            prop_assert_eq!(e.protection.psk, akm.iter().any(|a| matches!(a, 2 | 4 | 6 | 19 | 20)));
            let w = e.wps.unwrap();
            prop_assert_eq!(w.methodes, Some(methodes));
            prop_assert_eq!(w.pin(), Some(methodes & METHODES_PIN != 0));
        }
    }
}
