//! Isoler l'ordinateur du réseau (Défense R4), et le lever. Deux ordres fermés de la liste du blocage
//! (`Ordre::Isoler { garder }`, `Ordre::LeverIsolement`), validés avant l'élévation et rejugés par l'élevé :
//!
//! - **la session à distance en cours n'est jamais coupée** : ses connexions sont lues AVANT la moindre règle,
//!   montrées, portées par l'ordre (`garder`), puis relues par l'élevé, qui refuse si une session en cours n'y est
//!   pas, si les connexions ne se lisent pas, ou si un tunnel (VPN) est monté pendant une session (la session
//!   passerait par lui, et ses paquets chiffrés partiraient vers une adresse que rien ne garde). Chaque session est
//!   gardée par sa connexion TCP exacte (adresse, port distant, port local), dans son sens : rien d'autre vers cette
//!   adresse, ni une connexion que ce PC ouvrirait vers elle ;
//! - restent permis : la boucle locale, DHCP, le DNS du résolveur en place (port 53), et les serveurs de Vanguard
//!   (mises à jour, listes de menaces) en HTTPS (TCP 443) seulement, par les adresses qu'ils ont au moment d'isoler
//!   (P2) ;
//! - Linux : une table nf_tables à lui (`machine::linux::nftables::isolement`), remise au démarrage par sa propre
//!   unité (`machine::linux::isolement`) ; sans systemd, « jusqu'au redémarrage » ;
//! - Windows : des règles Block explicites, les exceptions écrites en plages et en ports complémentaires (une règle
//!   Block n'a pas d'exception), plus « bloquer toutes les connexions entrantes » quand aucune session n'est en
//!   cours ; les valeurs d'avant notées dans les règles mêmes, remises exactement à la levée ;
//! - la levée retire ce qui porte la marque de Vanguard (la table, les règles par leur nom), même sans l'état noté.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::net::IpAddr;

use crate::modele::Echec;
use crate::protection::blocage::gardes::Sessions;
use crate::protection::blocage::ordres::GARDER_MAX;
use crate::protection::blocage::ordres::Resultat;
pub(crate) use crate::protection::blocage::ordres::SessionGardee;
use crate::{tr, trf};

/// Ce que l'isolement laisse passer, en plus de la boucle locale et de DHCP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Permis {
    /// Les sessions à distance en cours : chacune par sa connexion TCP exacte, dans son sens, et rien d'autre.
    pub garder: Vec<SessionGardee>,
    /// Les serveurs de Vanguard, résolus au moment d'isoler : HTTPS (TCP 443) ouvert par ce PC, rien d'autre.
    pub serveurs: Vec<IpAddr>,
    /// Le résolveur en place : le port 53 seulement.
    pub dns: Vec<IpAddr>,
}

/// Les serveurs de Vanguard gardés pendant l'isolement (P2) : ses mises à jour et ses listes de menaces, rien d'autre
/// (ni les fuites de mots de passe, ni les versions des logiciels, ni le relais d'envoi). Tous dans `http::HOTES`.
pub(crate) const HOTES_DE_VANGUARD: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "raw.githubusercontent.com",
    "feodotracker.abuse.ch",
    "mb-api.abuse.ch",
    "threatfox-api.abuse.ch",
    "urlhaus-api.abuse.ch",
    "www.cisa.gov",
    "www.loldrivers.io",
];

/// Au plus autant d'adresses de serveurs (un nom en rend parfois une dizaine).
pub(crate) const SERVEURS_MAX: usize = 64;
/// Au plus autant de serveurs DNS.
pub(crate) const DNS_MAX: usize = 8;
/// Le contexte des échecs de l'isolement, celui du pare-feu du blocage (`compte_rendu::champs::CONTEXTES_ECHEC`).
const OU: &str = "blocage/pare-feu";
/// Le temps laissé aux noms des serveurs pour se résoudre, tous ensemble.
const RESOLUTION: std::time::Duration = std::time::Duration::from_secs(10);

/// Une adresse qu'un isolement peut garder : ni non spécifiée, ni multidiffusion, ni boucle locale (déjà permise),
/// sous sa forme canonique (une IPv4 écrite en IPv6 redevient une IPv4).
fn gardable(ip: IpAddr) -> Option<IpAddr> {
    let ip = ip.to_canonical();
    (!ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()).then_some(ip)
}

/// Une liste d'adresses gardables, triée, sans doublon.
fn trier(adresses: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = adresses.into_iter().filter_map(gardable).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Des sessions à garder, triées, sans doublon, l'adresse sous sa forme canonique ; sans celles de la boucle locale
/// (déjà permise) ni une adresse qui n'est pas celle d'un hôte.
fn trier_sessions(sessions: impl IntoIterator<Item = SessionGardee>) -> Vec<SessionGardee> {
    let mut v: Vec<SessionGardee> = sessions
        .into_iter()
        .filter_map(|s| {
            Some(SessionGardee {
                distante: gardable(s.distante)?,
                ..s
            })
        })
        .filter(|s| s.port_distant != 0 && s.port_local != 0)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Une session écrite pour la personne : « 192.0.2.7:51234 → 22 ».
pub(crate) fn session_texte(s: &SessionGardee) -> String {
    format!(
        "{} → {}",
        std::net::SocketAddr::new(s.distante, s.port_distant),
        s.port_local
    )
}

/// Les sessions à garder d'après les sessions à distance en cours (`Sessions::isolables`) : `Err` si elles ne se
/// lisent pas (rien n'est isolé sans les connaître) ou s'il y en a trop.
pub(crate) fn garder_pour(sessions: Option<&Sessions>) -> Result<Vec<SessionGardee>, Echec> {
    let Some(s) = sessions else {
        return Err(Echec::refuse(
            OU,
            tr!(
                "les connexions en cours ne se lisent pas : une session à distance pourrait être coupée, rien n'est isolé",
                "the current connections cannot be read: a remote session could be cut, nothing is isolated"
            ),
        ));
    };
    let garder = trier_sessions(s.isolables.iter().copied());
    if garder.len() > GARDER_MAX {
        return Err(Echec::refuse(
            OU,
            trf!(
                "{} sessions à distance en cours (au plus {GARDER_MAX}) : rien n'est isolé",
                "{} remote sessions in progress (at most {GARDER_MAX}): nothing is isolated",
                garder.len()
            ),
        ));
    }
    Ok(garder)
}

/// Le jugement de l'isolement, avant l'élévation puis par l'élevé, sur ce qu'il relit lui-même : `None` s'il peut
/// se faire. `tunnels` : les tunnels montés (`None` : illisibles).
pub(crate) fn juger(
    garder: &[SessionGardee],
    sessions: Option<&Sessions>,
    tunnels: Option<&[String]>,
) -> Option<String> {
    let Some(s) = sessions else {
        return Some(
            tr!(
                "les connexions en cours ne se lisent pas : une session à distance pourrait être coupée, rien n'est isolé",
                "the current connections cannot be read: a remote session could be cut, nothing is isolated"
            )
            .to_string(),
        );
    };
    let en_cours = trier_sessions(s.isolables.iter().copied());
    if let Some(manque) = en_cours.iter().find(|x| !garder.contains(x)) {
        let manque = session_texte(manque);
        return Some(trf!(
            "une session à distance ({manque}) est en cours sans avoir été montrée : rien n'est isolé (relancez pour la voir)",
            "a remote session ({manque}) is in progress without having been shown: nothing is isolated (start again to see it)"
        ));
    }
    if !en_cours.is_empty() {
        match tunnels {
            None => {
                return Some(
                    tr!(
                        "les cartes réseau ne se lisent pas : la session à distance passe peut-être par un tunnel, rien n'est isolé",
                        "the network adapters cannot be read: the remote session may go through a tunnel, nothing is isolated"
                    )
                    .to_string(),
                );
            }
            Some(t) if !t.is_empty() => {
                return Some(trf!(
                    "un tunnel est monté ({}) pendant une session à distance : elle passe peut-être par lui, et l'isoler la couperait. Rien n'est isolé",
                    "a tunnel is up ({}) during a remote session: it may go through it, and isolating would cut it. Nothing is isolated",
                    t.join(", ")
                ));
            }
            Some(_) => {}
        }
    }
    None
}

/// Une interface de Linux est-elle un tunnel ? Sa sorte (`/sys/class/net/<nom>/type`) : PPP (512), IPIP (768), IPv6
/// dans IPv4 (769, 776), GRE (778, 823), « sans en-tête » (65534 : WireGuard, tun) ; ou `tun_flags` (tun et tap).
#[cfg(any(target_os = "linux", test))]
fn tunnel_linux(sorte: u32, tun: bool) -> bool {
    tun || matches!(sorte, 512 | 768 | 769 | 776 | 778 | 823 | 65534)
}

/// Les tunnels montés, par leur nom ; `None` si les cartes ne se lisent pas.
#[cfg(target_os = "linux")]
pub(crate) fn tunnels() -> Option<Vec<String>> {
    let mut v = Vec::new();
    for entree in std::fs::read_dir("/sys/class/net").ok()? {
        let entree = entree.ok()?;
        let nom = entree.file_name().to_string_lossy().into_owned();
        if nom == "lo" {
            continue;
        }
        let d = entree.path();
        let sorte: u32 = std::fs::read_to_string(d.join("type")).ok()?.trim().parse().ok()?;
        let tun = d.join("tun_flags").exists();
        // IFF_UP (bit 0) des drapeaux de l'interface.
        let drapeaux = std::fs::read_to_string(d.join("flags")).ok()?;
        let drapeaux = u32::from_str_radix(drapeaux.trim().trim_start_matches("0x"), 16).ok()?;
        if drapeaux & 1 != 0 && tunnel_linux(sorte, tun) {
            v.push(nom);
        }
    }
    v.sort();
    Some(v)
}

/// Les tunnels montés (PPP 23, virtuelle 53 : WireGuard, OpenVPN, Tailscale ; tunnel 131), par leur numéro ; `None`
/// si les cartes ne se lisent pas.
#[cfg(windows)]
pub(crate) fn tunnels() -> Option<Vec<String>> {
    Some(
        crate::machine::windows::cartes::cartes()?
            .into_iter()
            .filter(|c| c.active && !c.cachee && matches!(c.sorte, 23 | 53 | 131))
            .map(|c| trf!("carte {}", "adapter {}", c.index))
            .collect(),
    )
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn tunnels() -> Option<Vec<String>> {
    None
}

/// Les adresses des serveurs de Vanguard, résolues maintenant (`SERVEURS_MAX` au plus) : un nom qui ne se résout pas
/// dans le délai est laissé (il n'est alors pas gardé).
pub(crate) fn resoudre_serveurs() -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    let (envoi, reception) = std::sync::mpsc::channel();
    for hote in HOTES_DE_VANGUARD {
        let envoi = envoi.clone();
        let _ = std::thread::Builder::new().name("isolement-dns".into()).spawn(move || {
            let adresses: Vec<IpAddr> = (*hote, 443)
                .to_socket_addrs()
                .map(|a| a.map(|s| s.ip()).collect())
                .unwrap_or_default();
            let _ = envoi.send(adresses);
        });
    }
    drop(envoi);
    let fin = std::time::Instant::now().checked_add(RESOLUTION);
    let mut toutes = Vec::new();
    for _ in HOTES_DE_VANGUARD {
        let reste = fin.map_or(std::time::Duration::ZERO, |f| {
            f.saturating_duration_since(std::time::Instant::now())
        });
        match reception.recv_timeout(reste) {
            Ok(a) => toutes.extend(a),
            Err(_) => break,
        }
    }
    let mut v = trier(toutes);
    v.truncate(SERVEURS_MAX);
    v
}

/// Les serveurs DNS en place (`DNS_MAX` au plus), sans la boucle locale (déjà permise).
pub(crate) fn dns_en_place() -> Vec<IpAddr> {
    let mut v = trier(
        crate::machine::dns::actuel()
            .map(|a| a.serveurs.into_iter().map(|(ip, _)| ip).collect::<Vec<_>>())
            .unwrap_or_default(),
    );
    v.truncate(DNS_MAX);
    v
}

/// Une liste d'adresses écrite « a,b,c » (vide : « - »).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn liste_texte(adresses: &[IpAddr]) -> String {
    if adresses.is_empty() {
        return "-".into();
    }
    adresses.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

/// Les sessions gardées écrites comme dans l'ordre (`ordres_ligne::garder_de`), « - » sans session.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn sessions_texte(sessions: &[SessionGardee]) -> String {
    if sessions.is_empty() {
        return "-".into();
    }
    sessions.iter().map(SessionGardee::texte).collect::<Vec<_>>().join(",")
}

/// L'inverse de `sessions_texte` : `None` hors de la forme de l'ordre, ou pour une adresse non gardable.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn sessions_de(texte: &str) -> Option<Vec<SessionGardee>> {
    if texte == "-" {
        return Some(Vec::new());
    }
    let v = crate::protection::blocage::ordres::garder_de(texte)?;
    v.iter().all(|s| gardable(s.distante) == Some(s.distante)).then_some(v)
}

/// L'inverse de `liste_texte`, borné : `None` si une adresse ne se lit pas ou s'il y en a plus que `max`.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn liste_de(texte: &str, max: usize) -> Option<Vec<IpAddr>> {
    if texte == "-" {
        return Some(Vec::new());
    }
    let v: Vec<IpAddr> = texte.split(',').map(|a| a.parse().ok()).collect::<Option<_>>()?;
    (v.len() <= max && v.iter().all(|ip| gardable(*ip) == Some(*ip))).then_some(v)
}

/// L'état noté d'un isolement (Linux) : depuis quand, et ce qu'il permet. Écrit par l'élevé dans un dossier à root,
/// relu par l'unité au démarrage pour remettre la même table.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Etat {
    /// Secondes depuis 1970.
    pub depuis: i64,
    pub permis: Permis,
}

/// La première ligne de l'état : sa forme.
#[cfg(any(target_os = "linux", test))]
const ENTETE_ETAT: &str = "vanguard-isolement 2";

/// L'état écrit, ligne à ligne.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn etat_texte(e: &Etat) -> String {
    format!(
        "{ENTETE_ETAT}\ndepuis {}\ngarder {}\nserveurs {}\ndns {}\n",
        e.depuis,
        sessions_texte(&e.permis.garder),
        liste_texte(&e.permis.serveurs),
        liste_texte(&e.permis.dns)
    )
}

/// L'état relu ; `None` s'il n'a pas exactement sa forme.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn lire_etat(texte: &str) -> Option<Etat> {
    let mut lignes = texte.lines();
    if lignes.next()? != ENTETE_ETAT {
        return None;
    }
    let mut champ = |nom: &str| lignes.next()?.strip_prefix(nom)?.strip_prefix(' ').map(str::to_string);
    let depuis = champ("depuis")?.parse().ok()?;
    let garder = sessions_de(&champ("garder")?)?;
    let serveurs = liste_de(&champ("serveurs")?, SERVEURS_MAX)?;
    let dns = liste_de(&champ("dns")?, DNS_MAX)?;
    if lignes.next().is_some() {
        return None;
    }
    Some(Etat {
        depuis,
        permis: Permis { garder, serveurs, dns },
    })
}

/// Une adresse en nombre, avec sa famille (`false` : IPv4).
#[cfg(any(windows, test))]
fn en_nombre(ip: IpAddr) -> (bool, u128) {
    match ip.to_canonical() {
        IpAddr::V4(v) => (false, u128::from(u32::from(v))),
        IpAddr::V6(v) => (true, u128::from(v)),
    }
}

/// Le nombre redevenu adresse.
#[cfg(any(windows, test))]
fn en_adresse(v6: bool, n: u128) -> Option<IpAddr> {
    if v6 {
        Some(IpAddr::V6(std::net::Ipv6Addr::from(n)))
    } else {
        u32::try_from(n).ok().map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n)))
    }
}

/// Le complément de plages (bornes incluses) dans 0..=`max` : ce qui n'est dans aucune d'elles. Les plages
/// renversées ou hors de 0..=`max` sont ignorées ; elles peuvent se chevaucher.
#[cfg(any(windows, test))]
pub(crate) fn complement(gardees: &[(u128, u128)], max: u128) -> Vec<(u128, u128)> {
    let mut g: Vec<(u128, u128)> = gardees.iter().copied().filter(|(a, b)| a <= b && *b <= max).collect();
    g.sort_unstable();
    let mut v = Vec::new();
    // Le début de ce qui n'est pas encore couvert ; `None` : tout l'est jusqu'à `max`.
    let mut debut = Some(0u128);
    for (a, b) in g {
        let Some(d) = debut else { break };
        if a > d
            && let Some(fin) = a.checked_sub(1)
        {
            v.push((d, fin));
        }
        if b >= d {
            debut = b.checked_add(1).filter(|n| *n <= max);
        }
    }
    if let Some(d) = debut {
        v.push((d, max));
    }
    v
}

/// Une plage d'adresses (bornes incluses) d'une même famille.
#[cfg(any(windows, test))]
pub(crate) type Plage = (IpAddr, IpAddr);

/// Les plages à bloquer : tout sauf `gardees`, IPv4 et IPv6 chacune de son côté.
#[cfg(test)]
pub(crate) fn plages_bloquees(gardees: &[Plage]) -> Vec<Plage> {
    let mut v = Vec::new();
    for (v6, max) in [(false, u128::from(u32::MAX)), (true, u128::MAX)] {
        let famille: Vec<(u128, u128)> = gardees
            .iter()
            .filter_map(|(a, b)| {
                let (fa, na) = en_nombre(*a);
                let (fb, nb) = en_nombre(*b);
                (fa == v6 && fb == v6).then_some((na, nb))
            })
            .collect();
        for (a, b) in complement(&famille, max) {
            if let (Some(a), Some(b)) = (en_adresse(v6, a), en_adresse(v6, b)) {
                v.push((a, b));
            }
        }
    }
    v
}

/// RemoteAddresses d'une règle : « a-b » par plage, « a » pour une seule adresse, séparées par des virgules.
#[cfg(any(windows, test))]
pub(crate) fn adresses_distantes(plages: &[Plage]) -> String {
    plages
        .iter()
        .map(|(a, b)| if a == b { a.to_string() } else { format!("{a}-{b}") })
        .collect::<Vec<_>>()
        .join(",")
}

/// Une plage écrite « a/n » (préfixe), bornes incluses.
#[cfg(any(windows, test))]
fn prefixe(reseau: &str, longueur: u32) -> Option<Plage> {
    let ip: IpAddr = reseau.parse().ok()?;
    let (v6, n) = en_nombre(ip);
    let bits = if v6 { 128u32 } else { 32 };
    let hote = bits.checked_sub(longueur)?;
    let masque = if hote >= 128 {
        u128::MAX
    } else {
        1u128.checked_shl(hote)?.checked_sub(1)?
    };
    Some((en_adresse(v6, n & !masque)?, en_adresse(v6, n | masque)?))
}

/// La boucle locale : jamais bloquée par les règles de l'isolement de Windows.
#[cfg(any(windows, test))]
fn boucle_locale() -> Vec<Plage> {
    [("127.0.0.0", 8), ("::1", 128)]
        .into_iter()
        .filter_map(|(r, l)| prefixe(r, l))
        .collect()
}

/// Le lien local et ce qui sert à obtenir une adresse : l'adresse non spécifiée et la diffusion (DHCP), le lien local
/// et la multidiffusion locale d'IPv6 (découverte des voisins, DHCPv6). Seuls DHCP (UDP) et ICMPv6 y passent.
#[cfg(any(windows, test))]
pub(crate) fn lien_local() -> Vec<Plage> {
    [
        ("0.0.0.0", 32),
        ("255.255.255.255", 32),
        ("::", 128),
        ("fe80::", 10),
        ("ff02::", 16),
    ]
    .into_iter()
    .filter_map(|(r, l)| prefixe(r, l))
    .collect()
}

/// Les ports distants de DHCP en UDP (v4 : 67-68 ; v6 : 546-547).
#[cfg(any(windows, test))]
pub(crate) const PORTS_DHCP: [u16; 4] = [67, 68, 546, 547];

/// Le port du DNS, en UDP et en TCP.
#[cfg(any(windows, test))]
const PORT_DNS: u16 = 53;

/// Le port des serveurs de Vanguard (HTTPS, TCP seulement).
#[cfg(any(windows, test))]
const PORT_HTTPS: u16 = 443;

/// Ce qui est permis vers une adresse, sous Windows. Tout le reste vers elle est bloqué, sauf les protocoles autres
/// que TCP, UDP et ICMP, qu'une règle Block ne sait pas viser un à un sans en écrire des centaines (limite dite).
#[cfg(any(windows, test))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Permission {
    /// La boucle locale : rien n'est bloqué.
    tout: bool,
    /// Les connexions TCP exactes des sessions gardées : (port local, port distant).
    tcp_paires: Vec<(u16, u16)>,
    /// Les ports distants TCP permis depuis tout port local (DNS, serveurs de Vanguard).
    tcp_distants: Vec<u16>,
    /// Les ports distants UDP permis (DNS, DHCP).
    udp_distants: Vec<u16>,
    /// ICMPv6 (découverte des voisins sur le lien local ; « paquet trop grand » et voisins d'une session gardée).
    icmp6: bool,
}

#[cfg(any(windows, test))]
impl Permission {
    /// L'union de deux permissions, en listes triées sans doublon.
    fn avec(&self, autre: &Permission) -> Permission {
        let joindre = |a: &[u16], b: &[u16]| {
            let mut v: Vec<u16> = a.iter().chain(b).copied().collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let mut paires: Vec<(u16, u16)> = self.tcp_paires.iter().chain(&autre.tcp_paires).copied().collect();
        paires.sort_unstable();
        paires.dedup();
        Permission {
            tout: self.tout || autre.tout,
            tcp_paires: paires,
            tcp_distants: joindre(&self.tcp_distants, &autre.tcp_distants),
            udp_distants: joindre(&self.udp_distants, &autre.udp_distants),
            icmp6: self.icmp6 || autre.icmp6,
        }
    }
}

/// Le protocole d'une règle de l'isolement de Windows.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtocoleWindows {
    Tout,
    Tcp,
    Udp,
    Icmp4,
    Icmp6,
}

#[cfg(any(windows, test))]
impl ProtocoleWindows {
    /// Le numéro du protocole pour INetFwRule (256 : tous).
    pub(crate) fn numero(self) -> i32 {
        match self {
            ProtocoleWindows::Tout => 256,
            ProtocoleWindows::Tcp => 6,
            ProtocoleWindows::Udp => 17,
            ProtocoleWindows::Icmp4 => 1,
            ProtocoleWindows::Icmp6 => 58,
        }
    }

    fn texte(self) -> &'static str {
        match self {
            ProtocoleWindows::Tout => "*",
            ProtocoleWindows::Tcp => "TCP",
            ProtocoleWindows::Udp => "UDP",
            ProtocoleWindows::Icmp4 => "ICMPv4",
            ProtocoleWindows::Icmp6 => "ICMPv6",
        }
    }
}

/// Une règle Block de l'isolement de Windows : son nom (marqué de `PREFIXE_WINDOWS` et de sa génération), son sens,
/// son protocole, ses adresses distantes (jamais vides), et ses ports (`None` : tous).
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegleWindows {
    pub nom: String,
    pub entree: bool,
    pub protocole: ProtocoleWindows,
    pub distantes: String,
    pub ports_locaux: Option<String>,
    pub ports_distants: Option<String>,
}

/// Le début du nom de chaque règle de l'isolement de Windows : la marque que la levée retire. Suivi d'une espace et
/// de la lettre de la génération (« a » ou « b ») : refaire l'isolement pose la génération suivante avant de retirer
/// l'autre, jamais un trou entre les deux.
#[cfg(any(windows, test))]
pub(crate) const PREFIXE_WINDOWS: &str = "Vanguard : isolement";

/// La génération d'une règle de l'isolement d'après son nom : `Some('a')`, `Some('b')`, ou `Some('?')` pour une
/// règle marquée d'une autre forme (une version d'avant) ; `None` hors de la marque.
#[cfg(any(windows, test))]
pub(crate) fn generation(nom: &str) -> Option<char> {
    let reste = nom.strip_prefix(PREFIXE_WINDOWS)?;
    match reste.strip_prefix(' ').and_then(|r| r.chars().next()) {
        Some(g @ ('a' | 'b')) => Some(g),
        _ => Some('?'),
    }
}

/// La génération à poser après celles en place : « b » si une règle « a » est là, sinon « a ».
#[cfg(any(windows, test))]
pub(crate) fn generation_suivante<'a>(noms: impl IntoIterator<Item = &'a str>) -> char {
    if noms.into_iter().any(|n| generation(n) == Some('a')) {
        'b'
    } else {
        'a'
    }
}

/// Les ports de 1 à 65535 hors de ceux-ci, écrits « a-b,c » ; `None` s'il n'en reste aucun.
#[cfg(any(windows, test))]
pub(crate) fn ports_hors(permis: &[u16]) -> Option<String> {
    let trous: Vec<(u128, u128)> = permis.iter().map(|p| (u128::from(*p), u128::from(*p))).collect();
    let v: Vec<String> = complement(&trous, u128::from(u16::MAX))
        .into_iter()
        .filter_map(|(a, b)| {
            let (a, b) = (u16::try_from(a.max(1)).ok()?, u16::try_from(b).ok()?);
            (a >= 1 && a <= b).then(|| if a == b { a.to_string() } else { format!("{a}-{b}") })
        })
        .collect();
    (!v.is_empty()).then(|| v.join(","))
}

/// Les règles de l'isolement de Windows, génération `generation` : l'espace des adresses est coupé en morceaux d'une
/// même permission (sessions gardées, serveurs, DNS, serveurs DHCP, lien local, boucle locale, rien), puis chaque
/// groupe reçoit les règles Block de ce qui ne lui est pas permis, dans les deux sens :
///
/// - rien de permis : tout bloqué (une règle, tout protocole) ;
/// - TCP : les ports hors de ceux permis (pour une session, hors de sa connexion exacte : port local, port distant) ;
/// - UDP : les ports distants hors du DNS (53) et de DHCP (67-68, 546-547) quand ils sont permis ;
/// - ICMPv4 toujours, ICMPv6 hors du lien local et des sessions gardées.
///
/// `None` si une règle n'aurait pas d'adresse (elle viserait tout).
#[cfg(any(windows, test))]
pub(crate) fn regles_windows(permis: &Permis, dhcp: &[IpAddr], generation: char) -> Option<Vec<RegleWindows>> {
    let seule = |ip: &IpAddr| (ip.to_canonical(), ip.to_canonical());
    let mut faits: Vec<(Plage, Permission)> = Vec::new();
    for (de, a) in [
        ("0.0.0.0", "255.255.255.255"),
        ("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ] {
        faits.push(((de.parse().ok()?, a.parse().ok()?), Permission::default()));
    }
    for p in boucle_locale() {
        faits.push((
            p,
            Permission {
                tout: true,
                ..Permission::default()
            },
        ));
    }
    let dhcp_permis = Permission {
        udp_distants: PORTS_DHCP.to_vec(),
        ..Permission::default()
    };
    for p in lien_local() {
        faits.push((
            p,
            Permission {
                icmp6: true,
                ..dhcp_permis.clone()
            },
        ));
    }
    for ip in dhcp {
        faits.push((seule(ip), dhcp_permis.clone()));
    }
    for g in &permis.garder {
        faits.push((
            seule(&g.distante),
            Permission {
                tcp_paires: vec![(g.port_local, g.port_distant)],
                icmp6: true,
                ..Permission::default()
            },
        ));
    }
    for ip in &permis.serveurs {
        faits.push((
            seule(ip),
            Permission {
                tcp_distants: vec![PORT_HTTPS],
                ..Permission::default()
            },
        ));
    }
    for ip in &permis.dns {
        faits.push((
            seule(ip),
            Permission {
                tcp_distants: vec![PORT_DNS],
                udp_distants: vec![PORT_DNS],
                ..Permission::default()
            },
        ));
    }
    // Les morceaux d'une même permission, chaque famille de son côté, regroupés par permission.
    let mut groupes: Vec<(Permission, Vec<Plage>)> = Vec::new();
    for (v6, max) in [(false, u128::from(u32::MAX)), (true, u128::MAX)] {
        let famille: Vec<((u128, u128), &Permission)> = faits
            .iter()
            .filter_map(|((a, b), p)| {
                let (fa, na) = en_nombre(*a);
                let (fb, nb) = en_nombre(*b);
                (fa == v6 && fb == v6 && na <= nb).then_some(((na, nb), p))
            })
            .collect();
        let mut bornes: Vec<u128> = vec![0];
        for ((a, b), _) in &famille {
            bornes.push(*a);
            if let Some(n) = b.checked_add(1).filter(|n| *n <= max) {
                bornes.push(n);
            }
        }
        bornes.sort_unstable();
        bornes.dedup();
        for (i, debut) in bornes.iter().enumerate() {
            let fin = match bornes.get(i.checked_add(1)?) {
                Some(n) => n.checked_sub(1)?,
                None => max,
            };
            let ici = famille
                .iter()
                .filter(|((a, b), _)| a <= debut && debut <= b)
                .fold(Permission::default(), |acc, (_, p)| acc.avec(p));
            let plage = (en_adresse(v6, *debut)?, en_adresse(v6, fin)?);
            match groupes.iter_mut().find(|(p, _)| *p == ici) {
                Some((_, plages)) => plages.push(plage),
                None => groupes.push((ici, vec![plage])),
            }
        }
    }
    let mut v = Vec::new();
    for (p, plages) in &groupes {
        if p.tout {
            continue;
        }
        let toutes = adresses_distantes(plages);
        let famille = |v6: bool| {
            adresses_distantes(
                &plages
                    .iter()
                    .copied()
                    .filter(|(a, _)| a.is_ipv6() == v6)
                    .collect::<Vec<_>>(),
            )
        };
        // (protocole, adresses, ports locaux, ports distants) ; `None` en ports : tous.
        let mut bloquer: Vec<(ProtocoleWindows, String, Option<String>, Option<String>)> = Vec::new();
        if *p == Permission::default() {
            bloquer.push((ProtocoleWindows::Tout, toutes.clone(), None, None));
        } else {
            // TCP : hors des ports locaux des sessions, tout port distant hors de ceux permis à tous ; puis, pour
            // chaque port local d'une session, les ports distants hors de ceux de ses sessions.
            let mut locaux: Vec<u16> = p.tcp_paires.iter().map(|(l, _)| *l).collect();
            locaux.dedup();
            if let Some(distants) = ports_hors(&p.tcp_distants) {
                if locaux.is_empty() {
                    bloquer.push((ProtocoleWindows::Tcp, toutes.clone(), None, Some(distants)));
                } else if let Some(hors) = ports_hors(&locaux) {
                    bloquer.push((ProtocoleWindows::Tcp, toutes.clone(), Some(hors), Some(distants)));
                }
            }
            for l in &locaux {
                let mut ouverts: Vec<u16> = p.tcp_paires.iter().filter(|(x, _)| x == l).map(|(_, d)| *d).collect();
                ouverts.extend(&p.tcp_distants);
                if let Some(distants) = ports_hors(&ouverts) {
                    bloquer.push((
                        ProtocoleWindows::Tcp,
                        toutes.clone(),
                        Some(l.to_string()),
                        Some(distants),
                    ));
                }
            }
            if let Some(distants) = ports_hors(&p.udp_distants) {
                bloquer.push((ProtocoleWindows::Udp, toutes.clone(), None, Some(distants)));
            }
            bloquer.push((ProtocoleWindows::Icmp4, famille(false), None, None));
            if !p.icmp6 {
                bloquer.push((ProtocoleWindows::Icmp6, famille(true), None, None));
            }
        }
        for (protocole, distantes, locaux, distants) in bloquer {
            // Une famille absente de ce groupe : pas de règle (sans adresse, elle viserait tout).
            if distantes.is_empty() && matches!(protocole, ProtocoleWindows::Icmp4 | ProtocoleWindows::Icmp6) {
                continue;
            }
            for entree in [false, true] {
                let n = v.len();
                v.push(RegleWindows {
                    nom: format!(
                        "{PREFIXE_WINDOWS} {generation}{n:03} ({}, {})",
                        if entree {
                            tr!("entrée", "inbound")
                        } else {
                            tr!("sortie", "outbound")
                        },
                        protocole.texte()
                    ),
                    entree,
                    protocole,
                    distantes: distantes.clone(),
                    ports_locaux: locaux.clone(),
                    ports_distants: distants.clone(),
                });
            }
        }
    }
    (!v.is_empty() && v.iter().all(|r| !r.distantes.is_empty())).then_some(v)
}

/// Les profils du Pare-feu Windows (domaine, privé, public), par leur bit, et leur lettre dans `Avant`.
#[cfg(any(windows, test))]
pub(crate) const PROFILS: [(i32, char); 3] = [(1, 'd'), (2, 'p'), (4, 'u')];

/// Les valeurs d'avant de chaque profil : (pare-feu en marche, toutes les entrées bloquées), dans l'ordre de
/// `PROFILS`. Notées dans la description de la règle de sortie, remises exactement à la levée.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Avant(pub [(bool, bool); 3]);

#[cfg(any(windows, test))]
impl Avant {
    /// « avant:d=1,0;p=1,0;u=1,1 ».
    pub(crate) fn texte(self) -> String {
        let un = |b: bool| if b { '1' } else { '0' };
        let profils: Vec<String> = PROFILS
            .iter()
            .zip(self.0)
            .map(|((_, l), (marche, entrees))| format!("{l}={},{}", un(marche), un(entrees)))
            .collect();
        format!("avant:{}", profils.join(";"))
    }

    /// Relu dans une description : `None` si la marque n'y est pas exactement.
    pub(crate) fn lire(description: &str) -> Option<Avant> {
        let reste = &description[description.find("avant:")?.checked_add(6)?..];
        let mot = reste.split_whitespace().next()?;
        let bit = |c: &str| match c {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        };
        let parts: Vec<&str> = mot.split(';').collect();
        if parts.len() != PROFILS.len() {
            return None;
        }
        let mut v = [(false, false); 3];
        for ((case, (_, lettre)), part) in v.iter_mut().zip(PROFILS).zip(parts) {
            let (l, valeurs) = part.split_once('=')?;
            let (m, e) = valeurs.split_once(',')?;
            if l.chars().ne([lettre]) {
                return None;
            }
            *case = (bit(m)?, bit(e)?);
        }
        Some(Avant(v))
    }
}

/// Ce que fait l'élevé pour isoler : il refuse hors de root (ou des essais), relit les sessions et rejuge, résout les
/// serveurs, lit le DNS, puis pose.
pub(crate) fn isoler_ici(garder: &[SessionGardee]) -> Resultat {
    if cfg!(test) {
        return Resultat::echec("essais : jamais d'isolement réel");
    }
    #[cfg(unix)]
    if crate::socle::euid() != 0 {
        return Resultat::echec(tr!(
            "l'isolement demande les droits d'administrateur",
            "isolation requires administrator rights"
        ));
    }
    let sessions = crate::protection::blocage::gardes::sessions_a_distance();
    if let Some(raison) = juger(garder, sessions.as_ref(), tunnels().as_deref()) {
        return Resultat::echec(raison);
    }
    let permis = Permis {
        garder: trier_sessions(garder.iter().copied()),
        serveurs: resoudre_serveurs(),
        dns: dns_en_place(),
    };
    #[cfg(target_os = "linux")]
    {
        crate::machine::linux::isolement::isoler(&permis)
    }
    #[cfg(windows)]
    {
        // Les sessions gardées (au moins celles en cours, relues et jugées) : « bloquer toutes les connexions
        // entrantes » n'est posé que sans aucune.
        let n = permis.garder.len();
        crate::machine::windows::isolement::isoler(&permis, n)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = permis;
        Resultat::echec(tr!("ordre d'un autre système", "order from another system"))
    }
}

/// Ce que fait l'élevé pour lever l'isolement : ce qui porte la marque de Vanguard, sans dépendre de l'état noté.
pub(crate) fn lever_ici() -> Resultat {
    if cfg!(test) {
        return Resultat::echec("essais : jamais de levée réelle");
    }
    #[cfg(target_os = "linux")]
    {
        crate::machine::linux::isolement::lever()
    }
    #[cfg(windows)]
    {
        crate::machine::windows::isolement::lever()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Resultat::echec(tr!("ordre d'un autre système", "order from another system"))
    }
}

/// L'isolement est-il en place ? `Some(depuis)` (secondes depuis 1970, 0 si inconnu) ; `None` sinon ou illisible.
/// Sous Linux, l'état noté (lisible par tous, dans un dossier à root) ; sous Windows, les règles par leur nom.
pub(crate) fn en_place() -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        crate::machine::linux::isolement::notee().map(|e| e.depuis)
    }
    #[cfg(windows)]
    {
        crate::machine::windows::isolement::en_place().then_some(0)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

/// Le bandeau de chaque lancement tant que dure l'isolement.
pub(crate) fn banniere() -> Option<String> {
    let depuis = en_place()?;
    let quand = chrono::DateTime::from_timestamp(depuis, 0)
        .filter(|_| depuis > 0)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format(tr!(" depuis le %Y-%m-%d à %H:%M", " since %Y-%m-%d at %H:%M"))
                .to_string()
        })
        .unwrap_or_default();
    Some(trf!(
        "Cet ordinateur est isolé du réseau par Vanguard{quand} : seuls la connexion gardée de la session à distance (aucune nouvelle), le DNS et les serveurs de Vanguard en HTTPS passent. Pour le lever : « vanguard blocage annuler ».",
        "This computer is isolated from the network by Vanguard{quand}: only the kept connection of the remote session (no new one), DNS and Vanguard's servers over HTTPS get through. To lift it: “vanguard blocking undo”."
    ))
}

/// Ce que l'élevé a répondu : la précision notée (« `<ligne> (<précision>)` »), ou la raison d'un échec.
fn reponse(ligne: &str, notes: &[String]) -> String {
    notes
        .iter()
        .find_map(|n| n.strip_prefix(ligne)?.trim().strip_prefix('(')?.strip_suffix(')'))
        .map_or_else(
            // Sans précision, la note n'est que la ligne de l'ordre : rien à dire de plus (essai QEMU de R4, qui
            // montrait « Isolement levé (vanguard:lever-isolement) »).
            || {
                notes
                    .iter()
                    .filter(|n| n.trim() != ligne)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ; ")
            },
            crate::protection::blocage::ordres::note_lisible,
        )
}

/// Ce qui est dit avant de demander l'accord d'isoler : ce qui passe, et ce que coûte l'isolement (il tient après un
/// redémarrage, la connexion gardée est figée, un état perdu ne garde plus rien), puis la sortie de secours.
pub(crate) fn avant_l_accord() -> [&'static str; 3] {
    [
        tr!(
            "Tout le reste est coupé, en entrée et en sortie : navigateur, partages, autres ordinateurs du réseau. Restent la boucle locale, DHCP, le DNS en place (port 53) et les serveurs de Vanguard en HTTPS (mises à jour, listes de menaces ; ces adresses sont souvent partagées avec d'autres sites par leur hébergeur).",
            "Everything else is cut, in and out: browser, shares, other computers on the network. What remains: loopback, DHCP, the current DNS (port 53) and Vanguard's servers over HTTPS (updates, threat lists; their host often shares these addresses with other sites)."
        ),
        tr!(
            "L'isolement tient après un redémarrage. Chaque session gardée l'est par sa connexion exacte d'aujourd'hui, figée : si elle se coupe, ou après un redémarrage, elle ne peut pas revenir (une nouvelle connexion, même depuis la même adresse, est refusée) ; une session dont l'adresse change (adresse dynamique) est refusée elle aussi. Sous Linux, si l'état noté de l'isolement est perdu ou abîmé, le redémarrage isole sans plus aucune exception, session comprise.",
            "The isolation holds after a restart. Each kept session is kept by its exact connection of today, frozen: if it drops, or after a restart, it cannot come back (a new connection, even from the same address, is refused); a session whose address changes (dynamic address) is refused as well. On Linux, if the recorded isolation state is lost or damaged, the restart isolates with no exception at all, session included."
        ),
        tr!(
            "Pour le lever : « vanguard blocage annuler ». Sortie de secours, depuis la console de l'ordinateur (écran et clavier) ou la clé de secours : « vanguard blocage lever-isolement » ; sous Linux, en dernier recours, en root : « nft delete table inet vanguard_isolement » puis « systemctl disable vanguard-isolement.service » ; sous Windows : les règles « Vanguard : isolement » du Pare-feu Windows (wf.msc).",
            "To lift it: “vanguard blocking undo”. Emergency exit, from the computer's console (screen and keyboard) or the rescue key: “vanguard blocking lift-isolation”; on Linux, as a last resort, as root: “nft delete table inet vanguard_isolement” then “systemctl disable vanguard-isolement.service”; on Windows: the “Vanguard : isolement” rules of the Windows Firewall (wf.msc)."
        ),
    ]
}

/// Confie un ordre de l'isolement à l'élévation (toujours : il faut les droits d'administrateur), le note au journal,
/// et rend la précision de l'élevé, ou pourquoi rien n'a été fait.
fn confier(
    o: &crate::protection::blocage::ordres::Ordre,
    source: crate::modele::evenement::Source,
    cle: Option<&str>,
) -> Result<String, Echec> {
    let ligne = o.ligne();
    let (faits, notes) = crate::machine::appliquer_chacune_sans_noter(&[vec![ligne.clone()]]);
    let notes = notes.into_iter().next().unwrap_or_default();
    let reussi = faits.first().copied().unwrap_or(false);
    crate::modele::journal::noter(
        crate::modele::evenement::Evenement::action(source, &o.texte(), reussi, std::slice::from_ref(&ligne)).cle(cle),
    );
    let precision = reponse(&ligne, &notes);
    if reussi {
        Ok(precision)
    } else if precision.is_empty() {
        Err(Echec::refuse(
            OU,
            tr!("refusé ou droits non accordés", "refused or rights not granted"),
        ))
    } else {
        Err(Echec::echoue(OU, precision))
    }
}

/// L'ordre d'isoler pour les sessions en cours, jugé ici avant l'élévation (l'élevé le rejuge) ; `Err` dit pourquoi
/// rien ne sera demandé.
pub(crate) fn ordre_maintenant() -> Result<crate::protection::blocage::ordres::Ordre, Echec> {
    let sessions = crate::protection::blocage::gardes::sessions_a_distance();
    let garder = garder_pour(sessions.as_ref())?;
    if let Some(raison) = juger(&garder, sessions.as_ref(), tunnels().as_deref()) {
        return Err(Echec::refuse(OU, raison));
    }
    Ok(crate::protection::blocage::ordres::Ordre::Isoler { garder })
}

/// Pur : `NoNewPrivs` d'un `/proc/<pid>/status`. Posé (le service du veilleur : `NoNewPrivileges=yes`), aucun
/// programme setuid (pkexec, sudo) ne donne de droits à ce processus ni à ce qu'il lance. Illisible : supposé posé
/// (rien n'est tenté à l'aveugle).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn sans_nouveaux_droits(status: &str) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NoNewPrivs:"))
        .is_none_or(|v| v.trim() != "0")
}

/// Isole sans question (la réponse au rançongiciel, R5) : l'ordre est jugé ici (les sessions en cours gardées, refusé
/// si l'une ne se reconnaît pas), puis demandé à l'élévation, montrée par le système (la fenêtre de mot de passe) ;
/// l'élevé le rejuge. Un processus qui ne peut pas gagner de droits (le service durci du veilleur) ne demande rien :
/// c'est dit, avec la commande qui le fait. `Ok` : la précision de l'élevé ; `Err` : pourquoi ce n'est pas fait.
#[cfg(target_os = "linux")]
pub(crate) fn isoler_sans_question(cle: Option<&str>) -> Result<String, Echec> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    if sans_nouveaux_droits(&status) {
        return Err(Echec::refuse(
            OU,
            tr!(
                "le veilleur tourne sans pouvoir demander les droits d'administrateur (service durci) : « vanguard blocage isoler » le fait",
                "the watcher runs without being able to ask for administrator rights (hardened service): “vanguard blocking isolate” does it"
            ),
        ));
    }
    let o = ordre_maintenant()?;
    confier(&o, crate::modele::evenement::Source::Blocage, cle)
}

/// `vanguard blocage isoler` : ce qui sera fait (les sessions gardées), montré, confirmé, puis demandé à l'élévation.
pub fn isoler_avec_accord() {
    use crate::ui::*;
    titre(tr!(
        "Isoler l'ordinateur du réseau",
        "Isolate the computer from the network"
    ));
    let o = match ordre_maintenant() {
        Ok(o) => o,
        Err(raison) => {
            afficher_aligne("  ✖ ", &raison.to_string(), 4, "");
            return;
        }
    };
    println!();
    afficher_aligne("  ", &o.texte(), 2, GRAS);
    for t in avant_l_accord() {
        afficher_aligne("    ", t, 4, GRIS);
    }
    if !demander(tr!("\n  Isoler maintenant ? [o/N] : ", "\n  Isolate now? [y/N]: ")).oui() {
        trp!("  Rien n'a été fait.", "  Nothing was done.");
        return;
    }
    match confier(&o, crate::modele::evenement::Source::Utilisateur, None) {
        Ok(p) if p.is_empty() => trp!("  {VERT}✔{RESET} Isolé.", "  {VERT}✔{RESET} Isolated."),
        Ok(p) => trp!("  {VERT}✔{RESET} Isolé ({p}).", "  {VERT}✔{RESET} Isolated ({p})."),
        Err(e) => afficher_aligne("  ✖ ", &e.to_string(), 4, ""),
    }
}

/// La levée : confirmée, puis demandée à l'élévation. `true` si elle a été faite.
pub(crate) fn lever_avec_accord() -> bool {
    use crate::ui::*;
    let o = crate::protection::blocage::ordres::Ordre::LeverIsolement;
    println!();
    afficher_aligne("  ", &o.texte(), 2, GRAS);
    if !demander(tr!(
        "\n  Lever l'isolement ? [o/N] : ",
        "\n  Lift the isolation? [y/N]: "
    ))
    .oui()
    {
        trp!("  Rien n'a été fait.", "  Nothing was done.");
        return false;
    }
    match confier(&o, crate::modele::evenement::Source::Utilisateur, None) {
        Ok(p) if p.is_empty() => {
            trp!("  {VERT}✔{RESET} Isolement levé.", "  {VERT}✔{RESET} Isolation lifted.");
            true
        }
        Ok(p) => {
            trp!(
                "  {VERT}✔{RESET} Isolement levé ({p}).",
                "  {VERT}✔{RESET} Isolation lifted ({p})."
            );
            true
        }
        Err(e) => {
            afficher_aligne("  ✖ ", &e.to_string(), 4, "");
            false
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn reponse_sans_la_ligne_brute() {
        let l = "vanguard:lever-isolement";
        assert_eq!(reponse(l, &[l.to_string()]), "");
        assert_eq!(reponse(l, &[format!("{l} (table absente)")]), "table absente");
        assert_eq!(reponse(l, &[l.to_string(), "autre chose".to_string()]), "autre chose");
        assert_eq!(reponse(l, &[]), "");
    }

    /// Une session gardée : « adresse », port distant, port local.
    fn sg(a: &str, distant: u16, local: u16) -> SessionGardee {
        SessionGardee {
            distante: ip(a),
            port_distant: distant,
            port_local: local,
        }
    }

    fn sessions(v: &[SessionGardee]) -> Sessions {
        Sessions {
            sessions: v.iter().map(|s| s.distante).collect(),
            isolables: v.to_vec(),
            ..Sessions::default()
        }
    }

    #[test]
    fn garder_trie_et_canonique() {
        let s = sessions(&[
            sg("198.51.100.20", 51234, 22),
            sg("::ffff:192.0.2.7", 50000, 3389),
            sg("198.51.100.20", 51234, 22),
            sg("198.51.100.20", 51235, 22),
            sg("127.0.0.1", 40000, 22),
        ]);
        assert_eq!(
            garder_pour(Some(&s)).unwrap(),
            vec![
                sg("192.0.2.7", 50000, 3389),
                sg("198.51.100.20", 51234, 22),
                sg("198.51.100.20", 51235, 22)
            ]
        );
        assert!(garder_pour(None).is_err());
        let trop: Vec<SessionGardee> = (1..=17).map(|i| sg(&format!("192.0.2.{i}"), 50000, 22)).collect();
        assert!(garder_pour(Some(&sessions(&trop))).is_err());
        // L'ordre construit se relit tel quel (validation de ordres_ligne).
        let o = crate::protection::blocage::ordres::Ordre::Isoler {
            garder: garder_pour(Some(&s)).unwrap(),
        };
        assert_eq!(crate::protection::blocage::ordres::analyser(&o.ligne()), Some(o));
    }

    #[test]
    fn jugement_de_l_isolement() {
        let s = sessions(&[sg("198.51.100.20", 51234, 22)]);
        let garder = [sg("198.51.100.20", 51234, 22)];
        assert_eq!(juger(&garder, Some(&s), Some(&[])), None);
        // Connexions illisibles : refusé.
        assert!(juger(&garder, None, Some(&[])).is_some());
        // Une session non montrée : refusé, même depuis une adresse gardée par une autre connexion.
        assert!(juger(&[], Some(&s), Some(&[])).is_some());
        assert!(juger(&[sg("198.51.100.20", 51235, 22)], Some(&s), Some(&[])).is_some());
        // Un tunnel pendant une session, ou des cartes illisibles : refusé.
        assert!(juger(&garder, Some(&s), Some(&["wg0".to_string()])).is_some());
        assert!(juger(&garder, Some(&s), None).is_some());
        // Sans session, un tunnel ne gêne rien.
        assert_eq!(juger(&[], Some(&Sessions::default()), Some(&["wg0".to_string()])), None);
        assert_eq!(juger(&[], Some(&Sessions::default()), None), None);
        // Garder plus que les sessions (une session finie entre-temps) : permis.
        assert_eq!(
            juger(&[sg("192.0.2.9", 50000, 22)], Some(&Sessions::default()), Some(&[])),
            None
        );
    }

    /// M4 : avant l'accord, la personne apprend que l'isolement tient après un redémarrage, que la connexion gardée
    /// est figée, qu'un état abîmé ne garde plus rien, et la sortie de secours.
    #[test]
    fn le_cout_est_dit_avant_l_accord() {
        let fr = avant_l_accord().join(" ");
        for mot in [
            "redémarrage",
            "figée",
            "abîmé",
            "secours",
            "vanguard blocage lever-isolement",
            "nft delete table inet vanguard_isolement",
            "HTTPS",
        ] {
            assert!(fr.contains(mot), "{mot}");
        }
    }

    #[test]
    fn tunnels_de_linux() {
        assert!(tunnel_linux(65534, false));
        assert!(tunnel_linux(1, true));
        assert!(tunnel_linux(512, false));
        assert!(!tunnel_linux(1, false));
        assert!(!tunnel_linux(772, false));
    }

    #[test]
    fn hotes_gardes_dans_la_liste_fermee() {
        for h in HOTES_DE_VANGUARD {
            assert!(crate::http::HOTES.contains(h), "{h}");
        }
    }

    /// R5 : le service durci du veilleur (`NoNewPrivileges=yes`) ne demande pas d'élévation ; illisible : supposé.
    #[test]
    fn sans_nouveaux_droits_lu_du_status() {
        assert!(sans_nouveaux_droits("Name:\tvanguard\nNoNewPrivs:\t1\nSeccomp:\t2\n"));
        assert!(!sans_nouveaux_droits("Name:\tvanguard\nNoNewPrivs:\t0\nSeccomp:\t0\n"));
        assert!(sans_nouveaux_droits(""));
        assert!(sans_nouveaux_droits("NoNewPrivs:\tx\n"));
    }

    #[test]
    fn etat_aller_retour() {
        let e = Etat {
            depuis: 1_700_000_000,
            permis: Permis {
                garder: vec![sg("198.51.100.20", 51234, 22), sg("2001:db8::7", 50000, 3389)],
                serveurs: vec![ip("192.0.2.1"), ip("2001:db8::1")],
                dns: Vec::new(),
            },
        };
        let t = etat_texte(&e);
        assert_eq!(lire_etat(&t), Some(e.clone()));
        assert!(t.contains("dns -\n"));
        assert!(
            t.contains("garder 198.51.100.20:51234>22,[2001:db8::7]:50000>3389\n"),
            "{t}"
        );
        // Toute autre forme : refusée (dont l'état d'avant, qui gardait des adresses seules).
        assert_eq!(
            lire_etat(&t.replace("vanguard-isolement 2", "vanguard-isolement 1")),
            None
        );
        assert_eq!(lire_etat(&format!("{t}x\n")), None);
        assert_eq!(lire_etat(&t.replace("198.51.100.20:51234>22", "198.51.100.20")), None);
        assert_eq!(
            lire_etat(&t.replace("198.51.100.20:51234>22", "198.51.100.20:0>22")),
            None
        );
        assert_eq!(
            lire_etat(&t.replace("198.51.100.20:51234>22", "127.0.0.1:51234>22")),
            None
        );
        // Sans session : « - ».
        let sans = Etat {
            permis: Permis {
                garder: Vec::new(),
                ..e.permis.clone()
            },
            ..e.clone()
        };
        assert!(etat_texte(&sans).contains("garder -\n"));
        assert_eq!(lire_etat(&etat_texte(&sans)), Some(sans));
        assert_eq!(lire_etat(&t.replace("depuis 1700000000", "depuis x")), None);
        assert_eq!(lire_etat(""), None);
    }

    #[test]
    fn complement_exact() {
        assert_eq!(complement(&[], 9), vec![(0, 9)]);
        assert_eq!(complement(&[(0, 9)], 9), vec![]);
        assert_eq!(complement(&[(3, 4), (4, 6), (9, 9)], 9), vec![(0, 2), (7, 8)]);
        assert_eq!(complement(&[(0, 0)], 9), vec![(1, 9)]);
        assert_eq!(complement(&[(5, 2), (2, 20)], 9), vec![(0, 9)]);
        assert_eq!(complement(&[(0, u128::MAX)], u128::MAX), vec![]);
        assert_eq!(complement(&[(1, 1)], u128::MAX), vec![(0, 0), (2, u128::MAX)]);
    }

    #[test]
    fn plages_ecrites() {
        let p = plages_bloquees(&[(ip("192.0.2.7"), ip("192.0.2.7"))]);
        let t = adresses_distantes(&p);
        assert!(t.starts_with("0.0.0.0-192.0.2.6,192.0.2.8-255.255.255.255,::-"), "{t}");
        assert_eq!(
            prefixe("fe80::", 10),
            Some((ip("fe80::"), ip("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))
        );
        assert_eq!(prefixe("127.0.0.0", 8), Some((ip("127.0.0.0"), ip("127.255.255.255"))));
        assert_eq!(prefixe("0.0.0.0", 32), Some((ip("0.0.0.0"), ip("0.0.0.0"))));
    }

    #[test]
    fn regles_de_windows() {
        let permis = Permis {
            garder: vec![sg("198.51.100.20", 51234, 22)],
            serveurs: vec![ip("192.0.2.1")],
            dns: vec![ip("192.168.1.1"), ip("198.51.100.20")],
        };
        let r = regles_windows(&permis, &[ip("192.168.1.1")], 'a').unwrap();
        // Chaque règle : marquée, génération « a », dans les deux sens, jamais sans adresse.
        assert!(
            r.iter()
                .all(|x| x.nom.starts_with("Vanguard : isolement a") && !x.distantes.is_empty())
        );
        assert_eq!(r.iter().filter(|x| x.entree).count() * 2, r.len());
        let noms: std::collections::BTreeSet<&str> = r.iter().map(|x| x.nom.as_str()).collect();
        assert_eq!(noms.len(), r.len());
        // La session (aussi DNS ici) : TCP hors du port local 22 sauf 53 ; sur 22, hors de 51234 et 53.
        let tcp_session: Vec<(&Option<String>, &Option<String>)> = r
            .iter()
            .filter(|x| !x.entree && x.protocole == ProtocoleWindows::Tcp && x.distantes == "198.51.100.20")
            .map(|x| (&x.ports_locaux, &x.ports_distants))
            .collect();
        assert_eq!(
            tcp_session,
            vec![
                (&Some("1-21,23-65535".into()), &Some("1-52,54-65535".into())),
                (&Some("22".into()), &Some("1-52,54-51233,51235-65535".into()))
            ]
        );
        // Le serveur : TCP hors de 443, et UDP tout entier.
        let serveur: Vec<(ProtocoleWindows, &Option<String>)> = r
            .iter()
            .filter(|x| !x.entree && x.distantes == "192.0.2.1")
            .map(|x| (x.protocole, &x.ports_distants))
            .collect();
        assert_eq!(
            serveur,
            vec![
                (ProtocoleWindows::Tcp, &Some("1-442,444-65535".into())),
                (ProtocoleWindows::Udp, &Some("1-65535".into())),
                (ProtocoleWindows::Icmp4, &None)
            ]
        );
        // B1 : le DNS (aussi serveur DHCP) : UDP hors de 53 et de DHCP, pas tout UDP.
        assert!(r.iter().any(|x| x.distantes == "192.168.1.1"
            && x.protocole == ProtocoleWindows::Udp
            && x.ports_distants.as_deref() == Some("1-52,54-66,69-545,548-65535")));
        assert_eq!(generation("Vanguard : isolement a003 (sortie, TCP)"), Some('a'));
        assert_eq!(generation("Vanguard : isolement (sortie)"), Some('?'));
        assert_eq!(generation("Vanguard : blocage"), None);
        assert_eq!(generation_suivante(["Vanguard : isolement a000 (sortie, *)"]), 'b');
        assert_eq!(generation_suivante(["Vanguard : isolement b000 (sortie, *)"]), 'a');
        assert_eq!(generation_suivante(["Vanguard : isolement (sortie)"]), 'a');
        assert_eq!(
            [
                ProtocoleWindows::Tout,
                ProtocoleWindows::Tcp,
                ProtocoleWindows::Udp,
                ProtocoleWindows::Icmp4,
                ProtocoleWindows::Icmp6
            ]
            .map(ProtocoleWindows::numero),
            [256, 6, 17, 1, 58]
        );
        assert_eq!(ports_hors(&[]), Some("1-65535".into()));
        assert_eq!(ports_hors(&[1, 65535]), Some("2-65534".into()));
        assert_eq!(ports_hors(&(1..=65535).collect::<Vec<u16>>()), None);
    }

    #[test]
    fn avant_aller_retour() {
        let a = Avant([(true, false), (false, false), (true, true)]);
        assert_eq!(a.texte(), "avant:d=1,0;p=0,0;u=1,1");
        let d = format!("Posée par l'isolement de Vanguard. {}", a.texte());
        assert_eq!(Avant::lire(&d), Some(a));
        assert_eq!(Avant::lire("rien"), None);
        assert_eq!(Avant::lire("avant:d=1,0;p=0,0"), None);
        assert_eq!(Avant::lire("avant:d=1,0;u=0,0;p=1,1"), None);
        assert_eq!(Avant::lire("avant:d=1,2;p=0,0;u=1,1"), None);
    }

    /// Une adresse est-elle dans une des plages ?
    fn couverte(plages: &[Plage], x: IpAddr) -> bool {
        let (fx, nx) = en_nombre(x);
        plages.iter().any(|(a, b)| {
            let (fa, na) = en_nombre(*a);
            let (_, nb) = en_nombre(*b);
            fa == fx && na <= nx && nx <= nb
        })
    }

    /// Un paquet vu par le simulateur : sens, protocole, adresse distante, port local, port distant.
    #[derive(Clone, Copy, Debug)]
    struct Paquet {
        entree: bool,
        protocole: ProtocoleWindows,
        distante: IpAddr,
        local: u16,
        distant: u16,
    }

    /// Des ports écrits « a-b,c » contiennent-ils celui-ci ? (`None` : tous.)
    fn dans_ports(ports: Option<&str>, p: u16) -> bool {
        ports.is_none_or(|t| {
            t.split(',').any(|x| match x.split_once('-') {
                Some((a, b)) => a.parse::<u16>().unwrap() <= p && p <= b.parse::<u16>().unwrap(),
                None => x.parse::<u16>().unwrap() == p,
            })
        })
    }

    /// Des adresses écrites « a-b,c » (la forme de RemoteAddresses), relues.
    fn plages_lues(t: &str) -> Vec<Plage> {
        t.split(',')
            .map(|p| match p.split_once('-') {
                Some((a, b)) if a.parse::<IpAddr>().is_ok() => (ip(a), ip(b)),
                _ => (ip(p), ip(p)),
            })
            .collect()
    }

    /// Le Pare-feu Windows simulé : une règle Block qui vise le paquet le bloque (aucune règle Allow n'y peut rien).
    fn bloque(r: &[RegleWindows], x: Paquet) -> bool {
        r.iter().any(|g| {
            g.entree == x.entree
                && (g.protocole == ProtocoleWindows::Tout || g.protocole == x.protocole)
                && couverte(&plages_lues(&g.distantes), x.distante.to_canonical())
                && dans_ports(g.ports_locaux.as_deref(), x.local)
                && dans_ports(g.ports_distants.as_deref(), x.distant)
        })
    }

    /// Ce qui doit passer, écrit d'après la règle et non d'après le code : la boucle locale ; la connexion exacte de
    /// chaque session ; les serveurs en TCP 443 ; le DNS en 53 ; DHCP vers les serveurs DHCP et le lien local ;
    /// ICMPv6 sur le lien local et vers une session. Rien d'autre.
    fn attendu(permis: &Permis, dhcp: &[IpAddr], x: Paquet) -> bool {
        let a = x.distante.to_canonical();
        let parmi = |v: &[IpAddr]| v.iter().any(|y| y.to_canonical() == a);
        if couverte(&boucle_locale(), a) {
            return true;
        }
        let lien = couverte(&lien_local(), a);
        match x.protocole {
            ProtocoleWindows::Tcp => {
                permis
                    .garder
                    .iter()
                    .any(|g| g.distante == a && g.port_local == x.local && g.port_distant == x.distant)
                    || (parmi(&permis.serveurs) && x.distant == 443)
                    || (parmi(&permis.dns) && x.distant == 53)
            }
            ProtocoleWindows::Udp => {
                (parmi(&permis.dns) && x.distant == 53) || ((parmi(dhcp) || lien) && PORTS_DHCP.contains(&x.distant))
            }
            ProtocoleWindows::Icmp6 => lien || permis.garder.iter().any(|g| g.distante == a),
            ProtocoleWindows::Icmp4 | ProtocoleWindows::Tout => false,
        }
    }

    fn adresse() -> impl Strategy<Value = IpAddr> {
        prop_oneof![
            any::<u32>().prop_map(|n| IpAddr::V4(n.into())),
            any::<u128>().prop_map(|n| IpAddr::V6(n.into())),
            // Près des bords et des plages toujours permises.
            (0u32..4).prop_map(|n| IpAddr::V4(n.into())),
            (0u128..4).prop_map(|n| IpAddr::V6((u128::MAX - n).into())),
            any::<u16>().prop_map(|n| IpAddr::V6((0xfe80u128 << 112 | u128::from(n)).into())),
        ]
    }

    fn session_au_hasard() -> impl Strategy<Value = SessionGardee> {
        (adresse(), prop_oneof![Just(22u16), Just(3389), 1u16..], 1u16..).prop_filter_map("gardable", |(a, l, d)| {
            Some(SessionGardee {
                distante: gardable(a)?,
                port_distant: d,
                port_local: l,
            })
        })
    }

    proptest! {
        /// M1, M3, B1 : sous Windows, la connexion exacte de chaque session passe dans les deux sens ; tout le reste
        /// est bloqué ou permis exactement comme le dit `attendu` (rien d'autre vers l'adresse d'une session, les
        /// serveurs en TCP 443 seulement, le DNS et DHCP par leurs ports seulement).
        #[test]
        fn windows_exactement_ce_qui_est_permis(
            garder in proptest::collection::vec(session_au_hasard(), 0..4),
            serveurs in proptest::collection::vec(adresse(), 0..4),
            dns in proptest::collection::vec(adresse(), 0..3),
            dhcp in proptest::collection::vec(adresse(), 0..3),
            vers in 0usize..6,
            autre in adresse(),
            protocole in prop_oneof![
                Just(ProtocoleWindows::Tcp),
                Just(ProtocoleWindows::Udp),
                Just(ProtocoleWindows::Icmp4),
                Just(ProtocoleWindows::Icmp6),
            ],
            entree in any::<bool>(),
            ports in prop_oneof![(1u16.., 1u16..), (Just(22u16), 1u16..), (1u16.., prop_oneof![Just(53u16), Just(443), Just(67), Just(547)])],
            exact in any::<bool>(),
        ) {
            let permis = Permis { garder: garder.clone(), serveurs: serveurs.clone(), dns: dns.clone() };
            let r = regles_windows(&permis, &dhcp, 'a').unwrap();
            prop_assert!(r.iter().all(|g| !g.distantes.is_empty()));
            // Chaque session : sa connexion exacte n'est jamais bloquée, ni en entrée ni en sortie.
            for g in &garder {
                for entree in [false, true] {
                    let x = Paquet { entree, protocole: ProtocoleWindows::Tcp, distante: g.distante, local: g.port_local, distant: g.port_distant };
                    prop_assert!(!bloque(&r, x), "session {g:?} bloquée");
                }
            }
            // Un paquet vers une adresse connue (session, serveur, DNS, DHCP) ou au hasard.
            let connues: Vec<IpAddr> = garder.iter().map(|g| g.distante).chain(serveurs).chain(dns).chain(dhcp.clone()).collect();
            let distante = connues.get(vers).copied().unwrap_or(autre);
            let (mut local, mut distant) = ports;
            if exact && let Some(g) = garder.iter().find(|g| g.distante == distante.to_canonical()) {
                (local, distant) = (g.port_local, g.port_distant);
            }
            // ICMPv4 ne va qu'à une IPv4, ICMPv6 qu'à une IPv6.
            let v6 = distante.to_canonical().is_ipv6();
            prop_assume!(match protocole {
                ProtocoleWindows::Icmp4 => !v6,
                ProtocoleWindows::Icmp6 => v6,
                _ => true,
            });
            let x = Paquet { entree, protocole, distante, local, distant };
            prop_assert_eq!(bloque(&r, x), !attendu(&permis, &dhcp, x), "{:?}", x);
        }
    }
}
