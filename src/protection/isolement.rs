//! Isoler l'ordinateur du réseau (Défense R4), et le lever. Deux ordres fermés de la liste du blocage
//! (`Ordre::Isoler { garder }`, `Ordre::LeverIsolement`), validés avant l'élévation et rejugés par l'élevé :
//!
//! - **la session à distance en cours n'est jamais coupée** : ses adresses sont lues AVANT la moindre règle, montrées,
//!   portées par l'ordre (`garder`), puis relues par l'élevé, qui refuse si une session en cours n'y est pas, si les
//!   connexions ne se lisent pas, ou si un tunnel (VPN) est monté pendant une session (la session passerait par lui,
//!   et ses paquets chiffrés partiraient vers une adresse que rien ne garde) ;
//! - restent permis : la boucle locale, DHCP, le DNS du résolveur en place (port 53), et les serveurs de Vanguard
//!   (mises à jour, listes de menaces), par les adresses qu'ils ont au moment d'isoler (P2) ;
//! - Linux : une table nf_tables à lui (`machine::linux::nftables::isolement`), remise au démarrage par sa propre
//!   unité (`machine::linux::isolement`) ; sans systemd, « jusqu'au redémarrage » ;
//! - Windows : des règles Block explicites, les exceptions écrites en plages complémentaires (une règle Block n'a pas
//!   d'exception), plus « bloquer toutes les connexions entrantes » quand aucune session n'est en cours ; les valeurs
//!   d'avant notées dans la règle même, remises exactement à la levée ;
//! - la levée retire ce qui porte la marque de Vanguard (la table, les règles par leur nom), même sans l'état noté.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::net::IpAddr;

use crate::modele::Echec;
use crate::protection::blocage::gardes::Sessions;
use crate::protection::blocage::ordres::GARDER_MAX;
use crate::protection::blocage::ordres::Resultat;
use crate::{tr, trf};

/// Ce que l'isolement laisse passer, en plus de la boucle locale et de DHCP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Permis {
    /// Les sessions à distance en cours : tout échange avec elles.
    pub garder: Vec<IpAddr>,
    /// Les serveurs de Vanguard, résolus au moment d'isoler : tout échange avec eux.
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
/// Le temps laissé aux noms des serveurs pour se résoudre, tous ensemble.
/// Le contexte des échecs de l'isolement, celui du pare-feu du blocage (`compte_rendu::champs::CONTEXTES_ECHEC`).
const OU: &str = "blocage/pare-feu";

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

/// Les adresses à garder d'après les sessions à distance en cours : `Err` si elles ne se lisent pas (rien n'est
/// isolé sans les connaître) ou s'il y en a trop.
pub(crate) fn garder_pour(sessions: Option<&Sessions>) -> Result<Vec<IpAddr>, Echec> {
    let Some(s) = sessions else {
        return Err(Echec::refuse(
            OU,
            tr!(
                "les connexions en cours ne se lisent pas : une session à distance pourrait être coupée, rien n'est isolé",
                "the current connections cannot be read: a remote session could be cut, nothing is isolated"
            ),
        ));
    };
    let garder = trier(s.sessions.iter().copied());
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
pub(crate) fn juger(garder: &[IpAddr], sessions: Option<&Sessions>, tunnels: Option<&[String]>) -> Option<String> {
    let Some(s) = sessions else {
        return Some(
            tr!(
                "les connexions en cours ne se lisent pas : une session à distance pourrait être coupée, rien n'est isolé",
                "the current connections cannot be read: a remote session could be cut, nothing is isolated"
            )
            .to_string(),
        );
    };
    let en_cours = trier(s.sessions.iter().copied());
    if let Some(ip) = en_cours.iter().find(|ip| !garder.contains(ip)) {
        return Some(trf!(
            "une session à distance depuis {ip} est en cours sans avoir été montrée : rien n'est isolé (relancez pour la voir)",
            "a remote session from {ip} is in progress without having been shown: nothing is isolated (start again to see it)"
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
const ENTETE_ETAT: &str = "vanguard-isolement 1";

/// L'état écrit, ligne à ligne.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn etat_texte(e: &Etat) -> String {
    format!(
        "{ENTETE_ETAT}\ndepuis {}\ngarder {}\nserveurs {}\ndns {}\n",
        e.depuis,
        liste_texte(&e.permis.garder),
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
    let garder = liste_de(&champ("garder")?, GARDER_MAX)?;
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
#[cfg(any(windows, test))]
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

/// Ce qui n'est jamais bloqué par les règles de l'isolement de Windows, en plus de ce qu'il garde : l'adresse non
/// spécifiée (DHCP), la boucle locale, la diffusion (DHCP), le lien local et la multidiffusion locale d'IPv6 (découverte
/// des voisins, DHCPv6). Le lien local ne reste ouvert qu'hors TCP (`TCP_LOCAL`).
#[cfg(any(windows, test))]
pub(crate) fn toujours_permises() -> Vec<Plage> {
    [
        ("0.0.0.0", 32),
        ("127.0.0.0", 8),
        ("255.255.255.255", 32),
        ("::", 128),
        ("::1", 128),
        ("fe80::", 10),
        ("ff02::", 16),
    ]
    .into_iter()
    .filter_map(|(r, l)| prefixe(r, l))
    .collect()
}

/// Une règle de l'isolement de Windows : son nom, son sens, ses adresses distantes, et si elle ne vise que TCP (hors
/// du port distant 53).
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegleWindows {
    pub nom: &'static str,
    pub entree: bool,
    pub distantes: String,
    pub tcp: bool,
}

/// Le nom de chaque règle de l'isolement de Windows : la marque que la levée retire.
#[cfg(any(windows, test))]
pub(crate) const NOMS_WINDOWS: [&str; 4] = [
    "Vanguard : isolement (sortie)",
    "Vanguard : isolement (entrée)",
    "Vanguard : isolement, TCP local (sortie)",
    "Vanguard : isolement, TCP local (entrée)",
];

/// Les ports distants de TCP local bloqués : tous sauf 53 (DNS en TCP).
#[cfg(windows)]
pub(crate) const TCP_LOCAL_PORTS: &str = "1-52,54-65535";

/// Les règles de l'isolement de Windows : tout bloquer sauf ce qui est gardé (sessions, serveurs), le DNS, les
/// serveurs DHCP et `toujours_permises` ; puis TCP vers le lien local, le DNS et les serveurs DHCP (sauf le port 53),
/// jamais vers une adresse gardée. `None` si une liste est vide (une règle sans adresse viserait tout).
#[cfg(any(windows, test))]
pub(crate) fn regles_windows(permis: &Permis, dhcp: &[IpAddr]) -> Option<Vec<RegleWindows>> {
    let seule = |ip: &IpAddr| (ip.to_canonical(), ip.to_canonical());
    let gardees: Vec<IpAddr> = permis
        .garder
        .iter()
        .chain(&permis.serveurs)
        .map(IpAddr::to_canonical)
        .collect();
    let mut exceptions: Vec<Plage> = gardees.iter().map(seule).collect();
    exceptions.extend(permis.dns.iter().chain(dhcp).map(seule));
    exceptions.extend(toujours_permises());
    let tout = adresses_distantes(&plages_bloquees(&exceptions));
    // TCP local : le lien local d'IPv6, le DNS et les serveurs DHCP, moins ce qui est gardé.
    let mut locales: Vec<Plage> = permis
        .dns
        .iter()
        .chain(dhcp)
        .filter(|ip| !gardees.contains(&ip.to_canonical()))
        .map(seule)
        .collect();
    locales.extend(prefixe("fe80::", 10));
    // Réunies (le complément du complément), sans double ni chevauchement.
    let locales = plages_bloquees(&plages_bloquees(&locales));
    let locales = adresses_distantes(&soustraire(&locales, &gardees));
    if tout.is_empty() || locales.is_empty() {
        return None;
    }
    Some(
        NOMS_WINDOWS
            .iter()
            .enumerate()
            .map(|(i, nom)| RegleWindows {
                nom,
                entree: i % 2 == 1,
                distantes: if i < 2 { tout.clone() } else { locales.clone() },
                tcp: i >= 2,
            })
            .collect(),
    )
}

/// Les plages moins ces adresses (une plage qui en contient une est coupée autour d'elle).
#[cfg(any(windows, test))]
fn soustraire(plages: &[Plage], adresses: &[IpAddr]) -> Vec<Plage> {
    let mut v = Vec::new();
    for (a, b) in plages {
        let (v6, na) = en_nombre(*a);
        let (_, nb) = en_nombre(*b);
        let trous: Vec<(u128, u128)> = adresses
            .iter()
            .map(|ip| en_nombre(*ip))
            .filter(|(f, n)| *f == v6 && *n >= na && *n <= nb)
            .map(|(_, n)| (n, n))
            .collect();
        // Le complément des trous, ramené à la plage.
        for (x, y) in complement(&trous, nb) {
            let (x, y) = (x.max(na), y);
            if x <= y
                && let (Some(x), Some(y)) = (en_adresse(v6, x), en_adresse(v6, y))
            {
                v.push((x, y));
            }
        }
    }
    v
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
pub(crate) fn isoler_ici(garder: &[IpAddr]) -> Resultat {
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
        garder: trier(garder.iter().copied()),
        serveurs: resoudre_serveurs(),
        dns: dns_en_place(),
    };
    #[cfg(target_os = "linux")]
    {
        crate::machine::linux::isolement::isoler(&permis)
    }
    #[cfg(windows)]
    {
        let n = sessions.map_or(0, |s| s.sessions.len());
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
        "Cet ordinateur est isolé du réseau par Vanguard{quand} : seuls la session à distance gardée, le DNS et les serveurs de Vanguard passent. Pour le lever : « vanguard blocage annuler ».",
        "This computer is isolated from the network by Vanguard{quand}: only the kept remote session, DNS and Vanguard's servers get through. To lift it: “vanguard blocking undo”."
    ))
}

/// Ce que l'élevé a répondu : la précision notée (« <ligne> (<précision>) »), ou la raison d'un échec.
fn reponse(ligne: &str, notes: &[String]) -> String {
    notes
        .iter()
        .find_map(|n| n.strip_prefix(ligne)?.trim().strip_prefix('(')?.strip_suffix(')'))
        .map_or_else(|| notes.join(" ; "), crate::protection::blocage::ordres::note_lisible)
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
    afficher_aligne(
        "    ",
        tr!(
            "Tout le reste est coupé, en entrée et en sortie : navigateur, partages, autres ordinateurs du réseau. Restent la boucle locale, DHCP, le DNS en place et les serveurs de Vanguard (mises à jour, listes de menaces). Se lève par « vanguard blocage annuler ».",
            "Everything else is cut, in and out: browser, shares, other computers on the network. What remains: loopback, DHCP, the current DNS and Vanguard's servers (updates, threat lists). Lifted with “vanguard blocking undo”."
        ),
        4,
        GRIS,
    );
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

    fn sessions(v: &[&str]) -> Sessions {
        Sessions {
            sessions: v.iter().map(|s| ip(s)).collect(),
            ..Sessions::default()
        }
    }

    #[test]
    fn garder_trie_et_canonique() {
        let s = sessions(&["198.51.100.20", "::ffff:192.0.2.7", "198.51.100.20", "127.0.0.1"]);
        assert_eq!(
            garder_pour(Some(&s)).unwrap(),
            vec![ip("192.0.2.7"), ip("198.51.100.20")]
        );
        assert!(garder_pour(None).is_err());
        let trop: Vec<String> = (1..=17).map(|i| format!("192.0.2.{i}")).collect();
        let trop: Vec<&str> = trop.iter().map(String::as_str).collect();
        assert!(garder_pour(Some(&sessions(&trop))).is_err());
        // L'ordre construit se relit tel quel (validation de ordres_ligne).
        let o = crate::protection::blocage::ordres::Ordre::Isoler {
            garder: garder_pour(Some(&s)).unwrap(),
        };
        assert_eq!(crate::protection::blocage::ordres::analyser(&o.ligne()), Some(o));
    }

    #[test]
    fn jugement_de_l_isolement() {
        let s = sessions(&["198.51.100.20"]);
        let garder = [ip("198.51.100.20")];
        assert_eq!(juger(&garder, Some(&s), Some(&[])), None);
        // Connexions illisibles : refusé.
        assert!(juger(&garder, None, Some(&[])).is_some());
        // Une session non montrée : refusé.
        assert!(juger(&[], Some(&s), Some(&[])).is_some());
        // Un tunnel pendant une session, ou des cartes illisibles : refusé.
        assert!(juger(&garder, Some(&s), Some(&["wg0".to_string()])).is_some());
        assert!(juger(&garder, Some(&s), None).is_some());
        // Sans session, un tunnel ne gêne rien.
        assert_eq!(juger(&[], Some(&Sessions::default()), Some(&["wg0".to_string()])), None);
        assert_eq!(juger(&[], Some(&Sessions::default()), None), None);
        // Garder plus que les sessions (une session finie entre-temps) : permis.
        assert_eq!(juger(&[ip("192.0.2.9")], Some(&Sessions::default()), Some(&[])), None);
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
                garder: vec![ip("198.51.100.20")],
                serveurs: vec![ip("192.0.2.1"), ip("2001:db8::1")],
                dns: Vec::new(),
            },
        };
        let t = etat_texte(&e);
        assert_eq!(lire_etat(&t), Some(e.clone()));
        assert!(t.contains("dns -\n"));
        // Toute autre forme : refusée.
        assert_eq!(
            lire_etat(&t.replace("vanguard-isolement 1", "vanguard-isolement 2")),
            None
        );
        assert_eq!(lire_etat(&format!("{t}x\n")), None);
        assert_eq!(lire_etat(&t.replace("198.51.100.20", "198.51.100.20,0.0.0.0")), None);
        assert_eq!(lire_etat(&t.replace("198.51.100.20", "127.0.0.1")), None);
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
            garder: vec![ip("198.51.100.20")],
            serveurs: vec![ip("192.0.2.1")],
            dns: vec![ip("192.168.1.1"), ip("198.51.100.20")],
        };
        let r = regles_windows(&permis, &[ip("192.168.1.1")]).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(r.iter().map(|x| x.nom).collect::<Vec<_>>(), NOMS_WINDOWS);
        assert!(!r[0].entree && r[1].entree && !r[2].entree && r[3].entree);
        assert!(!r[0].tcp && r[2].tcp);
        // TCP local : le DNS non gardé et le lien local, jamais la session (aussi DNS ici).
        assert_eq!(
            r[2].distantes,
            "192.168.1.1,fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        );
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

    proptest! {
        /// Aucune adresse gardée (session, serveur) n'est couverte par une règle Block ; toute autre adresse publique
        /// l'est par la règle de tout.
        #[test]
        fn rien_de_garde_n_est_bloque(
            garder in proptest::collection::vec(adresse(), 0..6),
            serveurs in proptest::collection::vec(adresse(), 0..6),
            dns in proptest::collection::vec(adresse(), 0..3),
            dhcp in proptest::collection::vec(adresse(), 0..3),
            autre in adresse(),
        ) {
            let permis = Permis { garder: garder.clone(), serveurs: serveurs.clone(), dns: dns.clone() };
            let r = regles_windows(&permis, &dhcp).unwrap();
            let lire = |t: &str| -> Vec<Plage> {
                t.split(',').map(|p| match p.split_once('-') {
                    Some((a, b)) if a.parse::<IpAddr>().is_ok() => (ip(a), ip(b)),
                    _ => (ip(p), ip(p)),
                }).collect()
            };
            for regle in &r {
                let plages = lire(&regle.distantes);
                for g in garder.iter().chain(&serveurs) {
                    prop_assert!(!couverte(&plages, g.to_canonical()), "{} couvre {g}", regle.nom);
                }
                if !regle.tcp {
                    for d in dns.iter().chain(&dhcp) {
                        prop_assert!(!couverte(&plages, d.to_canonical()));
                    }
                }
            }
            let autre = autre.to_canonical();
            let gardee = garder.iter().chain(&serveurs).chain(&dns).chain(&dhcp).any(|g| g.to_canonical() == autre)
                || couverte(&toujours_permises(), autre);
            prop_assert_eq!(couverte(&lire(&r[0].distantes), autre), !gardee);
        }
    }
}
