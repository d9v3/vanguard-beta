//! NetworkManager lu par le client D-Bus maison (org.freedesktop.NetworkManager) au lieu de `nmcli connection
//! show` : les profils enregistrés (Settings.ListConnections, puis GetSettings de chacun, sans les secrets, que
//! GetSecrets seul rendrait et qui n'est pas permis), les connexions actives et leurs cartes. Les fichiers des profils
//! (/etc/NetworkManager/system-connections) sont réservés à root : D-Bus est le seul chemin sans droits.
//!
//! NetworkManager absent ou arrêté : l'erreur ServiceUnknown remonte (`dbus::service_absent`), jamais « aucun
//! profil ».

use std::net::{Ipv4Addr, Ipv6Addr};

use super::dbus::{Bus, Valeur};

const NM: &str = "org.freedesktop.NetworkManager";
const CHEMIN_NM: &str = "/org/freedesktop/NetworkManager";
const CHEMIN_REGLAGES: &str = "/org/freedesktop/NetworkManager/Settings";
/// Profils lus au plus : nmcli n'en regardait que 40 ; une machine en a rarement plus de quelques dizaines.
const PROFILS_MAX: usize = 1000;

/// Un profil enregistré : ses réglages par section (`a{sa{sv}}`).
pub(crate) struct Profil(pub Valeur);

impl Profil {
    fn section(&self, nom: &str) -> Option<&Valeur> {
        self.0.champ(nom)
    }

    fn valeur(&self, section: &str, cle: &str) -> Option<&Valeur> {
        self.section(section)?.champ(cle)
    }

    pub(crate) fn uuid(&self) -> Option<&str> {
        self.valeur("connection", "uuid")?.texte()
    }

    pub(crate) fn nom(&self) -> &str {
        self.valeur("connection", "id")
            .and_then(Valeur::texte)
            .unwrap_or_default()
    }

    pub(crate) fn genre(&self) -> &str {
        self.valeur("connection", "type")
            .and_then(Valeur::texte)
            .unwrap_or_default()
    }

    /// Se reconnecte tout seul : la clé absente vaut « oui » (défaut de NetworkManager, comme nmcli l'affiche).
    pub(crate) fn automatique(&self) -> bool {
        self.valeur("connection", "autoconnect")
            .and_then(Valeur::booleen)
            .unwrap_or(true)
    }

    /// Un Wi-Fi ouvert, comme `wifi_ouvert` le jugeait d'après nmcli : pas de section de sécurité, ou une gestion de
    /// clé vide. « none » est du WEP, « owe » du Wi-Fi ouvert chiffré : pas ouverts.
    pub(crate) fn ouvert(&self) -> bool {
        self.valeur("802-11-wireless-security", "key-mgmt")
            .and_then(Valeur::texte)
            .is_none_or(|v| v.trim().is_empty())
    }

    /// Une propriété « section.clé » écrite comme `nmcli -t -e no -g` l'écrit : booléens en yes/no, listes jointes
    /// par des virgules, serveurs DNS en texte (« dns-data » d'abord, sinon « dns » : `au` en ordre réseau pour
    /// l'IPv4, `aay` pour l'IPv6). Une clé absente prend la valeur par défaut de NetworkManager pour les clés que
    /// Vanguard lit ; une autre clé absente : `None`.
    pub(crate) fn propriete(&self, nom: &str) -> Option<String> {
        let (section, cle) = nom.split_once('.')?;
        if cle == "dns" {
            if let Some(d) = self.valeur(section, "dns-data") {
                return Some(d.textes().join(","));
            }
            return Some(match self.valeur(section, "dns") {
                None => String::new(),
                Some(v) if section == "ipv4" => v
                    .elements()
                    .iter()
                    .filter_map(|n| match n.nue() {
                        // L'adresse en ordre réseau dans un entier de la machine : ses octets en mémoire, tels quels.
                        Valeur::U32(n) => Some(Ipv4Addr::from(n.to_ne_bytes()).to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(","),
                Some(v) => v
                    .elements()
                    .iter()
                    .filter_map(|a| {
                        let o: Vec<u8> = a
                            .elements()
                            .iter()
                            .filter_map(|o| match o {
                                Valeur::Octet(o) => Some(*o),
                                _ => None,
                            })
                            .collect();
                        Some(Ipv6Addr::from(<[u8; 16]>::try_from(o.as_slice()).ok()?).to_string())
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            });
        }
        match self.valeur(section, cle) {
            Some(v) => match v.nue() {
                Valeur::Booleen(b) => Some(if *b { "yes" } else { "no" }.to_string()),
                Valeur::Texte(t) => Some(t.clone()),
                Valeur::Tableau(_) => Some(v.textes().join(",")),
                autre => autre.entier().map(|n| n.to_string()),
            },
            None => match cle {
                "ignore-auto-dns" => Some("no".into()),
                "method" if section == "ipv4" || section == "ipv6" => Some("auto".into()),
                _ => None,
            },
        }
    }
}

/// Tous les profils enregistrés (au plus `PROFILS_MAX`), sur le bus système.
pub(crate) fn profils(bus: &mut Bus) -> Result<Vec<Profil>, String> {
    let liste = bus.appeler(
        NM,
        CHEMIN_REGLAGES,
        "org.freedesktop.NetworkManager.Settings",
        "ListConnections",
        "",
        Vec::new(),
    )?;
    let chemins = liste.first().map(Valeur::textes).unwrap_or_default();
    let mut profils = Vec::new();
    for chemin in chemins.iter().take(PROFILS_MAX) {
        let r = bus.appeler(
            NM,
            chemin,
            "org.freedesktop.NetworkManager.Settings.Connection",
            "GetSettings",
            "",
            Vec::new(),
        );
        match r {
            Ok(corps) => profils.extend(corps.into_iter().next().map(Profil)),
            // Un profil retiré entre la liste et sa lecture : rien à garder. Le reste est une vraie erreur.
            Err(e)
                if e.starts_with("org.freedesktop.DBus.Error.UnknownMethod ")
                    || e.starts_with("org.freedesktop.DBus.Error.UnknownObject ") => {}
            Err(e) => return Err(e),
        }
    }
    Ok(profils)
}

/// Le profil de cet UUID.
pub(crate) fn profil(bus: &mut Bus, uuid: &str) -> Result<Option<Profil>, String> {
    Ok(profils(bus)?.into_iter().find(|p| p.uuid() == Some(uuid)))
}

/// Les connexions actives : (UUID, noms des cartes), comme `nmcli -t -f UUID,DEVICE connection show --active`.
pub(crate) fn actives(bus: &mut Bus) -> Result<Vec<(String, Vec<String>)>, String> {
    let chemins = bus.propriete(NM, CHEMIN_NM, NM, "ActiveConnections")?.textes();
    let mut actives = Vec::new();
    for chemin in chemins.iter().take(PROFILS_MAX) {
        let Ok(p) = bus.proprietes(NM, chemin, "org.freedesktop.NetworkManager.Connection.Active") else {
            // Désactivée entre la liste et sa lecture.
            continue;
        };
        let Some(uuid) = p.champ("Uuid").and_then(Valeur::texte).map(String::from) else {
            continue;
        };
        let mut cartes = Vec::new();
        for appareil in p.champ("Devices").map(Valeur::textes).unwrap_or_default() {
            if let Ok(nom) = bus.propriete(NM, &appareil, "org.freedesktop.NetworkManager.Device", "Interface")
                && let Some(n) = nom.texte()
            {
                cartes.push(n.to_string());
            }
        }
        actives.push((uuid, cartes));
    }
    Ok(actives)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn p(k: &str, v: Valeur) -> (Valeur, Valeur) {
        (Valeur::texte_de(k), Valeur::Variante(String::new(), Box::new(v)))
    }

    fn section(nom: &str, cles: Vec<(Valeur, Valeur)>) -> (Valeur, Valeur) {
        (Valeur::texte_de(nom), Valeur::Dictionnaire(cles))
    }

    /// Un profil Wi-Fi fabriqué (réseau « Salon »), `securite` : la gestion de clé, ou pas de section.
    pub(crate) fn profil_wifi(uuid: &str, securite: Option<&str>, auto: Option<bool>) -> Profil {
        let mut connexion = vec![
            p("id", Valeur::texte_de("Salon")),
            p("uuid", Valeur::texte_de(uuid)),
            p("type", Valeur::texte_de("802-11-wireless")),
        ];
        if let Some(a) = auto {
            connexion.push(p("autoconnect", Valeur::Booleen(a)));
        }
        let mut sections = vec![section("connection", connexion)];
        if let Some(k) = securite {
            sections.push(section(
                "802-11-wireless-security",
                vec![p("key-mgmt", Valeur::texte_de(k))],
            ));
        }
        Profil(Valeur::Dictionnaire(sections))
    }

    #[test]
    fn wifi_ouvert_et_automatique() {
        let u = "0f3e6c3a-4b8e-4a52-9b1e-2a6c7d8e9f01";
        assert!(profil_wifi(u, None, None).ouvert());
        assert!(profil_wifi(u, Some(""), None).ouvert());
        assert!(!profil_wifi(u, Some("wpa-psk"), None).ouvert());
        assert!(!profil_wifi(u, Some("none"), None).ouvert(), "WEP");
        assert!(!profil_wifi(u, Some("owe"), None).ouvert());
        // Clé absente : se reconnecte seul, défaut de NetworkManager.
        assert!(profil_wifi(u, None, None).automatique());
        assert!(!profil_wifi(u, None, Some(false)).automatique());
        let w = profil_wifi(u, None, None);
        assert_eq!((w.uuid(), w.nom(), w.genre()), (Some(u), "Salon", "802-11-wireless"));
    }

    /// Les propriétés comme nmcli -g les écrit : DNS en texte depuis « dns » (au, aay) ou « dns-data » (as),
    /// booléens en yes/no, défauts pour les clés absentes.
    #[test]
    fn proprietes_comme_nmcli() {
        let v4 = |a: [u8; 4]| Valeur::U32(u32::from_ne_bytes(a));
        let mut v6 = vec![
            Valeur::Octet(0x20),
            Valeur::Octet(0x01),
            Valeur::Octet(0x0d),
            Valeur::Octet(0xb8),
        ];
        v6.extend((0..11).map(|_| Valeur::Octet(0)));
        v6.push(Valeur::Octet(1));
        let ancien = Profil(Valeur::Dictionnaire(vec![
            section(
                "ipv4",
                vec![
                    p("dns", Valeur::Tableau(vec![v4([1, 1, 1, 1]), v4([9, 9, 9, 9])])),
                    p("ignore-auto-dns", Valeur::Booleen(true)),
                    p("method", Valeur::texte_de("auto")),
                ],
            ),
            section("ipv6", vec![p("dns", Valeur::Tableau(vec![Valeur::Tableau(v6)]))]),
        ]));
        assert_eq!(ancien.propriete("ipv4.dns").as_deref(), Some("1.1.1.1,9.9.9.9"));
        assert_eq!(ancien.propriete("ipv4.ignore-auto-dns").as_deref(), Some("yes"));
        assert_eq!(ancien.propriete("ipv6.dns").as_deref(), Some("2001:db8::1"));
        assert_eq!(ancien.propriete("ipv6.ignore-auto-dns").as_deref(), Some("no"));
        assert_eq!(ancien.propriete("ipv6.method").as_deref(), Some("auto"));
        assert_eq!(ancien.propriete("ipv4.inconnue"), None);
        assert_eq!(ancien.propriete("sans-point"), None);
        let recent = Profil(Valeur::Dictionnaire(vec![section(
            "ipv4",
            vec![
                p("dns", Valeur::Tableau(vec![v4([1, 1, 1, 1])])),
                p(
                    "dns-data",
                    Valeur::Tableau(vec![
                        Valeur::texte_de("1.1.1.1#cloudflare-dns.com"),
                        Valeur::texte_de("8.8.8.8"),
                    ]),
                ),
            ],
        )]));
        assert_eq!(
            recent.propriete("ipv4.dns").as_deref(),
            Some("1.1.1.1#cloudflare-dns.com,8.8.8.8")
        );
        // Aucune section DNS : liste vide, comme nmcli.
        assert_eq!(
            Profil(Valeur::Dictionnaire(Vec::new()))
                .propriete("ipv6.dns")
                .as_deref(),
            Some("")
        );
    }

    /// L'oracle : les profils lus par D-Bus contre nmcli, sur cet ordinateur (des nombres seulement en cas d'écart).
    #[test]
    fn profils_comme_nmcli() {
        let natifs = match Bus::systeme().and_then(|mut b| profils(&mut b)) {
            Ok(p) => p,
            Err(e) => return crate::essais::saute(&format!("NetworkManager injoignable ({e})")),
        };
        let Some(r) = crate::commande::lancer_en_anglais(
            std::process::Command::new("nmcli").args([
                "-t",
                "-e",
                "no",
                "-f",
                "UUID,TYPE,AUTOCONNECT",
                "connection",
                "show",
            ]),
            15,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("nmcli absent");
        };
        let mut outil: Vec<String> = r.sortie.lines().map(str::to_string).collect();
        let mut lus: Vec<String> = natifs
            .iter()
            .map(|p| {
                format!(
                    "{}:{}:{}",
                    p.uuid().unwrap_or_default(),
                    p.genre(),
                    if p.automatique() { "yes" } else { "no" }
                )
            })
            .collect();
        outil.sort();
        lus.sort();
        assert!(
            outil == lus,
            "profils : {} par D-Bus, {} par nmcli",
            lus.len(),
            outil.len()
        );
        // Le DNS et la méthode de chaque profil, comme nmcli -g.
        for p in natifs.iter().take(10) {
            let uuid = p.uuid().unwrap_or_default();
            for cle in [
                "ipv4.dns",
                "ipv4.ignore-auto-dns",
                "ipv6.dns",
                "ipv6.ignore-auto-dns",
                "ipv6.method",
            ] {
                let Some(r) = crate::commande::lancer(
                    std::process::Command::new("nmcli").args(["-t", "-e", "no", "-g", cle, "connection", "show", uuid]),
                    10,
                )
                .filter(|r| r.code == Some(0)) else {
                    continue;
                };
                let norme = |t: &str| {
                    t.split([',', ' ', ';'])
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let lu = p.propriete(cle).unwrap_or_default();
                assert!(norme(&lu) == norme(r.sortie.trim()), "{cle} diffère de nmcli");
            }
        }
        // Les connexions actives et leurs cartes.
        let actives = Bus::systeme().and_then(|mut b| actives(&mut b)).unwrap();
        let r = crate::commande::lancer(
            std::process::Command::new("nmcli").args([
                "-t",
                "-e",
                "no",
                "-f",
                "UUID,DEVICE",
                "connection",
                "show",
                "--active",
            ]),
            10,
        )
        .unwrap();
        let mut outil: Vec<String> = r.sortie.lines().map(str::to_string).collect();
        let mut actives_lues: Vec<String> = actives.iter().map(|(u, c)| format!("{u}:{}", c.join(","))).collect();
        outil.sort();
        actives_lues.sort();
        assert!(
            outil == actives_lues,
            "actives : {} par D-Bus, {} par nmcli",
            actives_lues.len(),
            outil.len()
        );
    }
}
