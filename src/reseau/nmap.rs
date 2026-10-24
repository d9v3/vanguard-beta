//! Les versions des services d'un appareil, par nmap quand il est installé : au scan approfondi d'un appareil
//! (« vanguard appareils <ip> -p tous »), seulement sur les ports TCP que Vanguard y a déjà trouvés ouverts, et seulement
//! sur le réseau local. nmap -sV interroge chaque service pour reconnaître le logiciel et sa version : un service
//! ancien se repère ainsi. Ce que les appareils répondent est neutralisé avant d'être montré (`ui::affichable`).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::process::Command;

use serde::Deserialize;

/// La sortie XML de nmap (-oX -), réduite à ce qui sert.
#[derive(Debug, Deserialize)]
struct Rapport {
    #[serde(rename = "host", default)]
    hotes: Vec<Hote>,
}

#[derive(Debug, Deserialize)]
struct Hote {
    #[serde(rename = "address", default)]
    adresses: Vec<Adresse>,
    ports: Option<Ports>,
}

#[derive(Debug, Deserialize)]
struct Adresse {
    #[serde(rename = "@addr")]
    adresse: String,
    #[serde(rename = "@addrtype")]
    sorte: String,
}

#[derive(Debug, Deserialize)]
struct Ports {
    #[serde(rename = "port", default)]
    ports: Vec<Port>,
}

#[derive(Debug, Deserialize)]
struct Port {
    #[serde(rename = "@protocol")]
    protocole: String,
    #[serde(rename = "@portid")]
    numero: u16,
    state: Etat,
    service: Option<Service>,
}

#[derive(Debug, Deserialize)]
struct Etat {
    #[serde(rename = "@state")]
    etat: String,
}

#[derive(Debug, Deserialize)]
struct Service {
    #[serde(rename = "@name")]
    nom: String,
    #[serde(rename = "@product")]
    produit: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    precision: Option<String>,
}

/// nmap est-il installé ?
pub fn disponible() -> bool {
    chemin().is_some()
}

/// nmap trouvé dans le PATH, lancé par ce chemin : par son seul nom, Windows chercherait d'abord un nmap.exe posé à
/// côté de Vanguard ou dans le dossier courant.
fn chemin() -> Option<std::path::PathBuf> {
    let nom = if cfg!(windows) { "nmap.exe" } else { "nmap" };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(nom))
        .find(|p| p.is_absolute() && p.is_file())
}

/// Une adresse du réseau local (privée, lien local ou cette machine) : nmap n'est jamais lancé vers Internet. Le
/// réseau partagé du fournisseur (100.64.0.0/10) en est exclu exprès, à la différence de `socle::adresses::du_reseau` :
/// ce sont les box d'autres abonnés.
pub fn locale(ip: Ipv4Addr) -> bool {
    use crate::socle::adresses::{Portee, portee};
    matches!(portee(std::net::IpAddr::V4(ip)), Portee::Locale | Portee::Machine)
}

/// Les services reconnus dans la sortie XML de nmap, pour cette adresse : port TCP ouvert → « logiciel version
/// (précision) », ou le nom du service quand nmap ne sait pas mieux. Neutralisés pour l'écran.
pub fn lire(xml: &str, ip: Ipv4Addr) -> BTreeMap<u16, String> {
    let Ok(rapport) = quick_xml::de::from_str::<Rapport>(xml) else {
        return BTreeMap::new();
    };
    let voulue = ip.to_string();
    rapport
        .hotes
        .into_iter()
        .filter(|h| h.adresses.iter().any(|a| a.sorte == "ipv4" && a.adresse == voulue))
        .flat_map(|h| h.ports.map(|p| p.ports).unwrap_or_default())
        .filter(|p| p.protocole == "tcp" && p.state.etat == "open")
        .filter_map(|p| {
            let s = p.service?;
            let morceaux: Vec<String> = [s.produit, s.version]
                .into_iter()
                .flatten()
                .filter(|m| !m.trim().is_empty())
                .collect();
            let mut texte = if morceaux.is_empty() { s.nom } else { morceaux.join(" ") };
            if let Some(precision) = s.precision.filter(|x| !x.trim().is_empty()) {
                texte = format!("{texte} ({precision})");
            }
            let texte = crate::ui::affichable(texte.trim());
            (!texte.is_empty()).then_some((p.numero, texte))
        })
        .collect()
}

/// Les versions des services de `ports` sur `ip`, par nmap -sV. Vide si nmap manque, si l'adresse n'est pas locale, s'il
/// n'y a rien à interroger ou si nmap échoue : Vanguard garde alors ce qu'il a lu lui-même. Les arguments ne passent
/// par aucun shell ; « -- » termine les options avant l'adresse, et l'adresse est une vraie adresse IPv4.
pub fn versions(ip: Ipv4Addr, ports: &[u16]) -> BTreeMap<u16, String> {
    let Some(nmap) = chemin().filter(|_| !ports.is_empty() && locale(ip)) else {
        return BTreeMap::new();
    };
    let liste = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    // Une minute, plus cinq secondes par port : -sV attend la réponse de chaque service.
    let delai = 60 + 5 * u64::try_from(ports.len()).unwrap_or(u64::MAX).min(48);
    crate::commande::lancer(
        Command::new(nmap).args([
            "-sV",
            "-T4",
            "-Pn",
            "-n",
            "--open",
            "-p",
            &liste,
            "-oX",
            "-",
            "--",
            &ip.to_string(),
        ]),
        delai,
    )
    .filter(|r| r.code == Some(0))
    .map(|r| lire(&r.sortie, ip))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La forme de la sortie de « nmap -sV -oX - » (raccourcie), avec un service piégé.
    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80,443 -oX - -- 192.168.1.20" start="1760000000" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="3" services="22,80,443"/>
<verbose level="0"/>
<host starttime="1760000000" endtime="1760000010"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.168.1.20" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Exemple"/>
<hostnames></hostnames>
<ports><extraports state="closed" count="1"><extrareasons reason="conn-refused" count="1"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="nginx" version="1.24.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http-proxy" product="Pi&#xe8;ge&#x1b;[2K" method="probed" conf="10"/></port>
<port protocol="tcp" portid="9999"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="abyss" method="table" conf="3"/></port>
</ports>
<times srtt="200" rttvar="100" to="100000"/>
</host>
<runstats><finished time="1760000010" timestr="x" elapsed="10.00" summary="x" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>"#;

    #[test]
    fn versions_lues_dans_le_xml_de_nmap() {
        let ip: Ipv4Addr = "192.168.1.20".parse().unwrap();
        let v = lire(XML, ip);
        assert_eq!(
            v.get(&22).map(String::as_str),
            Some("OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)")
        );
        assert_eq!(v.get(&80).map(String::as_str), Some("nginx 1.24.0"));
        // Le nom seul quand nmap ne connaît pas le logiciel.
        assert_eq!(v.get(&9999).map(String::as_str), Some("abyss"));
        // Ce qu'un appareil répond ne pilote pas le terminal.
        assert!(!v[&8080].contains('\x1b'), "{}", v[&8080]);
        // Une autre adresse, ou un XML illisible : rien.
        assert!(lire(XML, "192.168.1.21".parse().unwrap()).is_empty());
        assert!(lire("<html>", ip).is_empty());
    }

    #[test]
    fn jamais_vers_internet() {
        assert!(locale("192.168.1.20".parse().unwrap()) && locale("10.0.0.1".parse().unwrap()));
        assert!(locale("169.254.3.4".parse().unwrap()) && locale("127.0.0.1".parse().unwrap()));
        assert!(!locale("1.1.1.1".parse().unwrap()) && !locale("8.8.8.8".parse().unwrap()));
        assert!(versions("8.8.8.8".parse().unwrap(), &[443]).is_empty());
        assert!(versions("192.168.1.20".parse().unwrap(), &[]).is_empty());
    }
}
