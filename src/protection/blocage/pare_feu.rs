//! Les règles de pare-feu du blocage, système par système : ce qui les pose et ce qui les retire exactement. Les
//! commandes sont construites ici, en fonctions pures (testées), puis lancées par `machine::appliquer_sans_noter`.
//! Linux : ufw s'il est actif, sinon une table nftables à Vanguard (`inet vanguard`) ; Windows : le Pare-feu Windows ;
//! macOS : une ancre de pf (`com.apple/vanguard`, que le pf.conf d'Apple lit déjà). Sinon : « non disponible ».

use std::net::IpAddr;

use crate::commande::sh_chaine;
use crate::{tr, trf};

/// Le pare-feu par lequel Vanguard bloque sur cet ordinateur. Noté avec un blocage (`changements::Inverse`) : la
/// règle inverse en est refaite à l'annulation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PareFeu {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Ufw,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Nftables,
    #[cfg_attr(not(windows), allow(dead_code))]
    Windows,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Pf,
}

impl PareFeu {
    pub(crate) fn nom(self) -> &'static str {
        match self {
            PareFeu::Ufw => "ufw",
            PareFeu::Nftables => "nftables",
            PareFeu::Windows => tr!("le Pare-feu Windows", "the Windows Firewall"),
            PareFeu::Pf => "pf",
        }
    }
}

/// Une règle : ce qui la pose, ce qui la retire, et sa limite s'il y en a une.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Regle {
    pub poser: Vec<String>,
    pub retirer: Vec<String>,
    /// Ce que la règle ne fait pas, à dire avant (« jusqu'au redémarrage »).
    pub limite: Option<&'static str>,
}

/// Le nom de la règle sortante de Windows vers une adresse.
fn nom_windows(ip: IpAddr) -> String {
    format!("Vanguard : bloquer vers {ip}")
}

/// Les lignes qui posent la table de Vanguard dans nftables : ses ensembles d'adresses et de ports, ses deux chaînes
/// (sortie, entrée sauf la boucle locale) et leurs règles. Vidées puis reposées à chaque fois : la même table, jamais
/// une règle en double.
const TABLE_NFT: [&str; 11] = [
    "add table inet vanguard",
    "add set inet vanguard sortie4 { type ipv4_addr; }",
    "add set inet vanguard sortie6 { type ipv6_addr; }",
    "add set inet vanguard ports { type inet_service; }",
    "add chain inet vanguard sortie { type filter hook output priority 0; policy accept; }",
    "add chain inet vanguard entree { type filter hook input priority 0; policy accept; }",
    "flush chain inet vanguard sortie",
    "flush chain inet vanguard entree",
    "add rule inet vanguard sortie ip daddr @sortie4 drop",
    "add rule inet vanguard sortie ip6 daddr @sortie6 drop",
    "add rule inet vanguard entree iifname != \"lo\" tcp dport @ports drop",
];

/// La table de Vanguard, puis un élément, en une seule transaction de nft (tout ou rien).
fn nft_avec(element: &str) -> String {
    let lot = TABLE_NFT
        .iter()
        .copied()
        .chain([element])
        .map(sh_chaine)
        .collect::<Vec<_>>()
        .join(" ");
    format!("printf '%s\\n' {lot} | sudo nft -f -")
}

/// Retire un élément d'un ensemble de la table ; s'il n'y a plus de table (redémarrage), il n'y a rien à retirer.
fn nft_sans(ensemble: &str, valeur: &str) -> String {
    let ensemble = sh_chaine(ensemble);
    let element = sh_chaine(&format!("{{ {valeur} }}"));
    format!(
        "sudo nft delete element inet vanguard {ensemble} {element} || ! sudo nft list table inet vanguard >/dev/null 2>&1"
    )
}

fn jusqu_au_redemarrage() -> &'static str {
    tr!(
        "la règle tient jusqu'au redémarrage de l'ordinateur",
        "the rule lasts until the computer restarts"
    )
}

/// La règle sortante vers une adresse. La connexion déjà ouverte est coupée là où le système le permet (ss -K sous
/// Linux, pfctl -k sous macOS) ; sinon, seules les nouvelles sont bloquées, et c'est dit.
pub(crate) fn sortante(pf: PareFeu, ip: IpAddr) -> Regle {
    let ip = ip.to_canonical();
    // Entre apostrophes : rien n'y est interprété par bash (un « [ » d'IPv6 serait sinon un motif de fichiers).
    let adresse = sh_chaine(&ip.to_string());
    let couper_linux = format!("sudo ss -K dst {adresse} >/dev/null 2>&1 || true");
    match pf {
        PareFeu::Ufw => Regle {
            poser: vec![format!("sudo ufw prepend deny out to {adresse}"), couper_linux],
            retirer: vec![format!("sudo ufw delete deny out to {adresse}")],
            limite: None,
        },
        PareFeu::Nftables => {
            let ensemble = if ip.is_ipv4() { "sortie4" } else { "sortie6" };
            Regle {
                poser: vec![
                    nft_avec(&format!("add element inet vanguard {ensemble} {{ {ip} }}")),
                    couper_linux,
                ],
                retirer: vec![nft_sans(ensemble, &ip.to_string())],
                limite: Some(jusqu_au_redemarrage()),
            }
        }
        PareFeu::Windows => {
            let nom = nom_windows(ip);
            Regle {
                poser: vec![format!(
                    "if (-not (Get-NetFirewallRule -DisplayName '{nom}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName '{nom}' -Direction Outbound -RemoteAddress {ip} -Action Block | Out-Null }}"
                )],
                retirer: vec![format!(
                    "Get-NetFirewallRule -DisplayName '{nom}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
                )],
                limite: Some(tr!(
                    "une connexion déjà ouverte peut durer jusqu'à sa fin ; les nouvelles sont bloquées",
                    "a connection already open may last until it ends; new ones are blocked"
                )),
            }
        }
        // pfctl fait foi (outil gardé, §4) : pf n'a pas d'interface publique (ioctl sur /dev/pf, en-têtes privés). Le
        // shell autour (grep, printf) est à retirer avec l'assistant élevé du lot du blocage (n°3) : arguments et
        // entrée passés en Rust, résultat contrôlé en Rust.
        PareFeu::Pf => Regle {
            poser: vec![
                // Les règles de l'ancre seulement si elles n'y sont pas : les recharger viderait la table.
                "sudo pfctl -a com.apple/vanguard -s rules 2>/dev/null | grep -q vanguard || printf '%s\\n' 'table <vanguard> persist' 'block drop out quick to <vanguard>' | sudo pfctl -a com.apple/vanguard -f -".to_string(),
                format!("sudo pfctl -a com.apple/vanguard -t vanguard -T add {adresse}"),
                format!("sudo pfctl -k 0.0.0.0/0 -k {adresse} >/dev/null 2>&1 || true"),
                "sudo pfctl -E >/dev/null 2>&1; sudo pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'".to_string(),
            ],
            retirer: vec![format!("sudo pfctl -a com.apple/vanguard -t vanguard -T delete {adresse}")],
            limite: Some(jusqu_au_redemarrage()),
        },
    }
}

/// La règle qui ferme un port TCP en entrée, sauf depuis cet ordinateur. Sous Windows, la règle porte le nom que le
/// bilan reconnaît déjà (« Vanguard : bloquer <port> »). `None` : pas de règle entrante ici (pf).
pub(crate) fn entrante(pf: PareFeu, port: u16) -> Option<Regle> {
    match pf {
        PareFeu::Ufw => {
            let regle = sh_chaine(&format!("{port}/tcp"));
            // En tête des règles : ajoutée à la fin, une autorisation déjà là pour ce port passerait avant elle.
            Some(Regle {
                poser: vec![format!("sudo ufw prepend deny {regle}")],
                retirer: vec![format!("sudo ufw delete deny {regle}")],
                limite: None,
            })
        }
        PareFeu::Nftables => Some(Regle {
            poser: vec![nft_avec(&format!("add element inet vanguard ports {{ {port} }}"))],
            retirer: vec![nft_sans("ports", &port.to_string())],
            limite: Some(jusqu_au_redemarrage()),
        }),
        PareFeu::Windows => {
            let nom = format!("Vanguard : bloquer {port}");
            Some(Regle {
                poser: vec![format!(
                    "if (-not (Get-NetFirewallRule -DisplayName '{nom}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName '{nom}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block | Out-Null }}"
                )],
                retirer: vec![format!(
                    "Get-NetFirewallRule -DisplayName '{nom}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
                )],
                limite: None,
            })
        }
        PareFeu::Pf => None,
    }
}

/// La destination d'une règle d'ufw (« 11434/tcp », « 8000:9000/tcp », « 80,443/tcp », « Anywhere ») vise-t-elle ce
/// port TCP ?
fn vise_le_port(destination: &str, port: u16) -> bool {
    let d = destination.trim_end_matches(" (v6)").trim();
    if d.eq_ignore_ascii_case("anywhere") {
        return true;
    }
    let (ports, proto) = d.split_once('/').unwrap_or((d, "tcp"));
    if !proto.eq_ignore_ascii_case("tcp") {
        return false;
    }
    ports.split(',').any(|p| match p.split_once(':') {
        Some((a, b)) => a.parse::<u16>().is_ok_and(|a| a <= port) && b.parse::<u16>().is_ok_and(|b| port <= b),
        None => p.parse::<u16>() == Ok(port),
    })
}

/// D'après `ufw status`, ce port TCP est-il refusé en entrée avant toute autorisation, en IPv4 comme en IPv6 ? Les
/// règles se lisent dans l'ordre où ufw les applique ; la première qui vise le port décide.
pub(crate) fn refuse_en_premier(status: &str, port: u16) -> bool {
    let mut decision: [Option<bool>; 2] = [None, None];
    let actions = ["ALLOW", "DENY", "REJECT", "LIMIT"];
    for l in status.lines().skip_while(|l| !l.trim_start().starts_with("--")).skip(1) {
        let mots: Vec<&str> = l.split_whitespace().collect();
        let Some(i) = mots.iter().position(|m| actions.contains(m)) else {
            continue;
        };
        // « ALLOW OUT » : une règle de sortie ne dit rien de l'entrée.
        if mots.get(i + 1) == Some(&"OUT") {
            continue;
        }
        let destination = mots[..i].join(" ");
        if !vise_le_port(&destination, port) {
            continue;
        }
        let famille = usize::from(l.contains("(v6)"));
        decision[famille].get_or_insert(matches!(mots[i], "DENY" | "REJECT"));
    }
    decision[0] == Some(true) && decision[1] != Some(false)
}

/// ufw refuse-t-il ce port avant toute autorisation, sur cet ordinateur ? Lu par `ufw status` (root, ou sudo sans
/// redemander le mot de passe, juste donné pour la règle). `None` : pas lisible.
pub(crate) fn ufw_refuse_en_premier(port: u16) -> Option<bool> {
    let r = crate::commande::lancer(&mut ufw_status()?, 15).filter(|r| r.code == Some(0))?;
    Some(refuse_en_premier(&r.sortie, port))
}

/// `ufw status`, en root ou par sudo sans redemander le mot de passe.
#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Windows, où il n'y a rien à lancer
fn ufw_status() -> Option<std::process::Command> {
    let mut c = if super::gestes::administrateur() {
        std::process::Command::new("ufw")
    } else {
        let mut c = std::process::Command::new("sudo");
        c.args(["-n", "ufw"]);
        c
    };
    c.arg("status").env("LC_ALL", "C");
    Some(c)
}

/// ufw n'existe pas sous Windows : rien n'est lancé, surtout pas un ufw.exe posé à côté de Vanguard.
#[cfg(not(unix))]
fn ufw_status() -> Option<std::process::Command> {
    None
}

/// Ni ufw actif ni nftables. Pas « absent » : ufw peut être installé mais coupé ; la phrase seule le dit
/// (`Introuvable` montre son détail tel quel).
#[cfg(target_os = "linux")]
fn sans_pare_feu_linux() -> crate::modele::Echec {
    crate::modele::Echec::new("blocage/pare-feu", crate::modele::Raison::Introuvable).detail(tr!(
        "non disponible : ni ufw actif ni nftables sur cet ordinateur",
        "not available: neither an active ufw nor nftables on this computer"
    ))
}

/// Le pare-feu par lequel bloquer ici ; `Err` : pourquoi il n'y en a pas (« non disponible »).
#[cfg_attr(windows, allow(clippy::unnecessary_wraps))] // même signature que sous Linux et macOS, où il peut manquer
pub(crate) fn detecter() -> Result<PareFeu, crate::modele::Echec> {
    #[cfg(target_os = "macos")]
    use crate::modele::{Echec, Raison};
    #[cfg(target_os = "macos")]
    const OU: &str = "blocage/pare-feu";
    #[cfg(target_os = "linux")]
    {
        if crate::machine::linux::ufw_actif() {
            return Ok(PareFeu::Ufw);
        }
        let nft = ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"]
            .iter()
            .any(|c| std::path::Path::new(c).exists());
        if nft {
            return Ok(PareFeu::Nftables);
        }
        Err(sans_pare_feu_linux())
    }
    #[cfg(windows)]
    {
        Ok(PareFeu::Windows)
    }
    #[cfg(target_os = "macos")]
    {
        if std::path::Path::new("/sbin/pfctl").exists() {
            Ok(PareFeu::Pf)
        } else {
            Err(Echec::new(OU, Raison::Absente("/sbin/pfctl".into())))
        }
    }
}

/// La phrase d'une règle posée, à montrer avant l'accord.
pub(crate) fn decrire_sortante(pf: PareFeu, ip: IpAddr) -> String {
    trf!(
        "Règle sortante dans {} : plus rien ne part vers {}",
        "Outbound rule in {}: nothing goes to {} any more",
        pf.nom(),
        ip.to_canonical()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ufw installé mais coupé, sans nftables : jamais « « ufw, nftables » absent », la phrase d'avant revient.
    #[cfg(target_os = "linux")]
    #[test]
    fn sans_pare_feu_dit_non_disponible() {
        let e = sans_pare_feu_linux();
        assert_eq!(e.code(), "introuvable");
        assert_eq!(
            e.to_string(),
            "non disponible : ni ufw actif ni nftables sur cet ordinateur"
        );
    }

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    /// Chaque règle posée a son inverse exact, et vise la bonne adresse.
    #[test]
    fn regles_sortantes_et_leur_inverse() {
        let r = sortante(PareFeu::Ufw, ip("203.0.113.7"));
        assert_eq!(r.poser[0], "sudo ufw prepend deny out to '203.0.113.7'");
        assert_eq!(r.retirer, ["sudo ufw delete deny out to '203.0.113.7'"]);
        assert!(r.poser[1].contains("ss -K dst '203.0.113.7'"));
        // Une adresse IPv4 vue en IPv6 est bloquée sous sa forme IPv4, celle du trafic réel.
        assert_eq!(sortante(PareFeu::Ufw, ip("::ffff:203.0.113.7")), r);

        let n = sortante(PareFeu::Nftables, ip("2001:db8::7"));
        assert!(n.poser[0].starts_with("printf '%s\\n' 'add table inet vanguard'"));
        assert!(n.poser[0].ends_with("'add element inet vanguard sortie6 { 2001:db8::7 }' | sudo nft -f -"));
        assert!(n.poser[0].contains("'flush chain inet vanguard sortie'"));
        assert_eq!(
            n.retirer,
            [
                "sudo nft delete element inet vanguard 'sortie6' '{ 2001:db8::7 }' || ! sudo nft list table inet vanguard >/dev/null 2>&1"
            ]
        );
        assert!(n.limite.is_some());

        let w = sortante(PareFeu::Windows, ip("203.0.113.7"));
        assert!(w.poser[0].contains(
            "New-NetFirewallRule -DisplayName 'Vanguard : bloquer vers 203.0.113.7' -Direction Outbound -RemoteAddress 203.0.113.7 -Action Block"
        ));
        assert_eq!(
            w.retirer,
            [
                "Get-NetFirewallRule -DisplayName 'Vanguard : bloquer vers 203.0.113.7' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
            ]
        );

        let p = sortante(PareFeu::Pf, ip("203.0.113.7"));
        assert!(
            p.poser
                .iter()
                .any(|c| c == "sudo pfctl -a com.apple/vanguard -t vanguard -T add '203.0.113.7'")
        );
        assert_eq!(
            p.retirer,
            ["sudo pfctl -a com.apple/vanguard -t vanguard -T delete '203.0.113.7'"]
        );
    }

    /// Défaut de la relecture : un refus ajouté après une autorisation du même port ne ferme rien. Le port n'est dit
    /// fermé que si ufw le refuse avant toute autorisation.
    #[test]
    fn refus_d_ufw_avant_toute_autorisation() {
        let entete = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n";
        let refus_d_abord = format!(
            "{entete}11434/tcp                  DENY IN     Anywhere\n11434/tcp                  ALLOW IN    192.168.1.0/24\n22/tcp                     ALLOW IN    Anywhere\n11434/tcp (v6)             DENY IN     Anywhere (v6)\n"
        );
        assert!(refuse_en_premier(&refus_d_abord, 11434));
        let apres = format!(
            "{entete}11000:12000/tcp            ALLOW IN    Anywhere\n11434/tcp                  DENY IN     Anywhere\n"
        );
        assert!(!refuse_en_premier(&apres, 11434));
        let v6_ouvert = format!(
            "{entete}11434/tcp                  DENY        Anywhere\n11434/tcp (v6)             ALLOW       Anywhere (v6)\n11434/tcp (v6)             DENY        Anywhere (v6)\n"
        );
        assert!(!refuse_en_premier(&v6_ouvert, 11434));
        // Une autorisation de tout depuis une adresse passe aussi avant.
        let depuis = format!(
            "{entete}Anywhere                   ALLOW IN    192.168.1.20\n11434/tcp                  DENY IN     Anywhere\n"
        );
        assert!(!refuse_en_premier(&depuis, 11434));
        // Les règles de sortie et des autres ports ne comptent pas ; aucune règle pour ce port : pas fermé.
        let autres = format!(
            "{entete}Anywhere                   ALLOW OUT   Anywhere on wg0\n80,443/tcp                 ALLOW IN    Anywhere\n11434/tcp                  DENY IN     Anywhere\n"
        );
        assert!(refuse_en_premier(&autres, 11434));
        assert!(!refuse_en_premier(entete, 11434));
        assert!(!refuse_en_premier("Status: inactive\n", 11434));
    }

    #[test]
    fn regles_entrantes_et_leur_inverse() {
        let u = entrante(PareFeu::Ufw, 11434).unwrap();
        assert_eq!(u.poser, ["sudo ufw prepend deny '11434/tcp'"]);
        assert_eq!(u.retirer, ["sudo ufw delete deny '11434/tcp'"]);
        let n = entrante(PareFeu::Nftables, 7860).unwrap();
        assert!(n.poser[0].contains("'add rule inet vanguard entree iifname != \"lo\" tcp dport @ports drop'"));
        assert!(n.poser[0].contains("'add element inet vanguard ports { 7860 }'"));
        assert!(n.retirer[0].starts_with("sudo nft delete element inet vanguard 'ports' '{ 7860 }'"));
        let w = entrante(PareFeu::Windows, 8188).unwrap();
        // Le nom que le bilan reconnaît (« Ports en écoute ») : le port n'y est plus compté comme ouvert.
        assert!(
            w.poser[0]
                .contains("-DisplayName 'Vanguard : bloquer 8188' -Direction Inbound -Protocol TCP -LocalPort 8188")
        );
        #[cfg(windows)]
        assert_eq!(
            crate::machine::windows::ecoute::port_bloque(
                "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=8188|Name=Vanguard : bloquer 8188|"
            ),
            Some(8188)
        );
        assert_eq!(entrante(PareFeu::Pf, 11434), None);
    }
}
