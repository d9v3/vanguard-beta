//! Ce que le noyau de macOS (XNU) rend en octets, lu sans le noyau sous la main : les structures de libproc
//! (sys/proc_info.h), la table de routage (net/route.h, sysctl NET_RT_DUMP et NET_RT_FLAGS), les arguments d'un
//! processus (sysctl KERN_PROCARGS2), l'échange (vm.swapusage), la protection de l'intégrité (sys/csr.h). Compilé
//! sous macOS et dans les tests de tous les systèmes : ces lectures sont pures, et se testent ici sur des octets fixes.
//!
//! Les structures sont écrites à la main d'après les en-têtes publiés par Apple (github.com/apple-oss-distributions/xnu),
//! avec des types de taille fixe : leur disposition est la même sur Apple Silicon et Intel (deux systèmes 64 bits à
//! alignement naturel) et sous Linux, où les assertions de compilation la vérifient aussi. Une réponse du noyau d'une
//! autre taille que celle de la structure est refusée (`None`), jamais lue à moitié : une version de macOS qui
//! changerait la disposition se verrait refusée, pas mal lue.

// Les noms des champs sont ceux des en-têtes de XNU, préfixes compris : on les retrouve en les cherchant.
#![allow(clippy::struct_field_names)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ───────────────────────────── sys/proc_info.h ─────────────────────────────

/// `struct proc_fileinfo` : l'en-tête commun des réponses de proc_pidfdinfo.
#[repr(C)]
#[allow(dead_code)] // seulement pour sa disposition
pub(crate) struct ProcFileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct vinfo_stat`.
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_temps: [i64; 8],
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

/// `struct sockbuf_info`.
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

/// `struct in_sockinfo` : les deux unions d'adresses (`in4in6_addr` ou `in6_addr`, 16 octets) en tableaux.
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct InSockinfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: [u32; 4],
    insi_laddr: [u32; 4],
    insi_v4: u8,
    insi_v6: InV6,
}

/// Le `struct { … } insi_v6` d'in_sockinfo.
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct InV6 {
    in6_hlim: u8,
    in6_cksum: i32,
    in6_ifindex: u16,
    in6_hops: i16,
}

/// `struct tcp_sockinfo`.
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct TcpSockinfo {
    tcpsi_ini: InSockinfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

/// `struct socket_info`. L'union `soi_proto` fait la taille de son plus grand membre, `un_sockinfo` (deux pointeurs
/// opaques et deux adresses de SOCK_MAXADDRLEN = 255 octets : 526, arrondis à 528 par l'alignement de 8).
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct SocketInfo {
    soi_stat: VinfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: [u64; 66],
}

/// `struct socket_fdinfo` : ce que rend proc_pidfdinfo(PROC_PIDFDSOCKETINFO).
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct SocketFdinfo {
    pfi: ProcFileinfo,
    psi: SocketInfo,
}

/// `struct proc_bsdshortinfo` : ce que rend proc_pidinfo(PROC_PIDT_SHORTBSDINFO), lisible pour les processus de tous
/// les comptes (le noyau ne demande pas le même compte pour cette sorte-là).
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct ProcBsdShortinfo {
    pbsi_pid: u32,
    pbsi_ppid: u32,
    pbsi_pgid: u32,
    pbsi_status: u32,
    pbsi_comm: [u8; 16],
    pbsi_flags: u32,
    pbsi_uid: u32,
    pbsi_gid: u32,
    pbsi_ruid: u32,
    pbsi_rgid: u32,
    pbsi_svuid: u32,
    pbsi_svgid: u32,
    pbsi_rfu: u32,
}

/// `struct xsw_usage` (sys/sysctl.h) : ce que rend vm.swapusage.
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct XswUsage {
    xsu_total: u64,
    xsu_avail: u64,
    xsu_used: u64,
    xsu_pagesize: u32,
    xsu_encrypted: i32,
}

/// `struct rt_msghdr` (net/route.h), suivi de `struct rt_metrics` (14 entiers de 32 bits).
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct RtMsghdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: i32,
    rtm_inits: u32,
    rtm_rmx: [u32; 14],
}

// Tailles et décalages d'après les en-têtes de XNU, vérifiés à la compilation (sur toutes les cibles : les types sont
// de taille fixe). Un écart ici est une structure mal recopiée, pas une version de macOS.
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<ProcFileinfo>() == 24);
    assert!(size_of::<VinfoStat>() == 136);
    assert!(size_of::<SockbufInfo>() == 24);
    assert!(size_of::<InSockinfo>() == 80);
    assert!(offset_of!(InSockinfo, insi_vflag) == 24);
    assert!(offset_of!(InSockinfo, insi_faddr) == 32);
    assert!(offset_of!(InSockinfo, insi_laddr) == 48);
    assert!(offset_of!(InSockinfo, insi_v6) == 68);
    assert!(size_of::<TcpSockinfo>() == 120);
    assert!(offset_of!(TcpSockinfo, tcpsi_state) == 80);
    assert!(size_of::<SocketInfo>() == 768);
    assert!(offset_of!(SocketInfo, soi_type) == 152);
    assert!(offset_of!(SocketInfo, soi_protocol) == 156);
    assert!(offset_of!(SocketInfo, soi_family) == 160);
    assert!(offset_of!(SocketInfo, soi_rcv) == 184);
    assert!(offset_of!(SocketInfo, soi_kind) == 232);
    assert!(offset_of!(SocketInfo, soi_proto) == 240);
    assert!(size_of::<SocketFdinfo>() == 792);
    assert!(offset_of!(SocketFdinfo, psi) == 24);
    assert!(size_of::<ProcBsdShortinfo>() == 64);
    assert!(offset_of!(ProcBsdShortinfo, pbsi_comm) == 16);
    assert!(offset_of!(ProcBsdShortinfo, pbsi_uid) == 36);
    assert!(offset_of!(ProcBsdShortinfo, pbsi_ruid) == 44);
    assert!(size_of::<XswUsage>() == 32);
    assert!(size_of::<RtMsghdr>() == 92);
    assert!(offset_of!(RtMsghdr, rtm_flags) == 8);
    assert!(offset_of!(RtMsghdr, rtm_addrs) == 12);
};

/// PROC_PIDFDSOCKETINFO (sys/proc_info.h), absent de libc.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PROC_PIDFDSOCKETINFO: i32 = 3;
/// PROC_PIDT_SHORTBSDINFO (sys/proc_info.h).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const PROC_PIDT_SHORTBSDINFO: i32 = 13;

/// Familles d'adresses de macOS (sys/socket.h) : AF_INET6 vaut 30, pas 10 comme sous Linux.
const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;
const AF_LINK: u8 = 18;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;
/// `soi_kind` : SOCKINFO_IN (UDP et autres prises IP), SOCKINFO_TCP.
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
/// `insi_vflag`.
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
/// `tcpsi_state` : TSI_S_LISTEN, TSI_S_ESTABLISHED.
pub(crate) const TSI_S_LISTEN: i32 = 1;
pub(crate) const TSI_S_ESTABLISHED: i32 = 4;

/// Le nom d'un état TCP (`tcpsi_state`), comme netstat et lsof l'écrivent.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn nom_etat_tcp(etat: i32) -> &'static str {
    const NOMS: [&str; 11] = [
        "CLOSED",
        "LISTEN",
        "SYN_SENT",
        "SYN_RECEIVED",
        "ESTABLISHED",
        "CLOSE_WAIT",
        "FIN_WAIT_1",
        "CLOSING",
        "LAST_ACK",
        "FIN_WAIT_2",
        "TIME_WAIT",
    ];
    usize::try_from(etat)
        .ok()
        .and_then(|i| NOMS.get(i))
        .copied()
        .unwrap_or("?")
}

fn octets<const N: usize>(o: &[u8], debut: usize) -> Option<[u8; N]> {
    o.get(debut..debut.checked_add(N)?)?.try_into().ok()
}

fn i32_ne(o: &[u8], debut: usize) -> Option<i32> {
    octets::<4>(o, debut).map(i32::from_ne_bytes)
}

fn u32_ne(o: &[u8], debut: usize) -> Option<u32> {
    octets::<4>(o, debut).map(u32::from_ne_bytes)
}

fn u16_ne(o: &[u8], debut: usize) -> Option<u16> {
    octets::<2>(o, debut).map(u16::from_ne_bytes)
}

fn u64_ne(o: &[u8], debut: usize) -> Option<u64> {
    octets::<8>(o, debut).map(u64::from_ne_bytes)
}

/// Une prise réseau IP d'un processus, lue dans sa `socket_fdinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PriseNoyau {
    pub tcp: bool,
    /// `tcpsi_state` (TSI_S_*) ; -1 pour une prise UDP, qui n'a pas d'état.
    pub etat: i32,
    pub locale: IpAddr,
    pub port_local: u16,
    pub distante: IpAddr,
    pub port_distant: u16,
}

/// Une adresse d'in_sockinfo (16 octets de l'union) : IPv4 dans ses 4 derniers octets (`in4in6_addr`, une prise
/// IPv6 qui sert aussi IPv4 garde INI_IPV4), IPv6 sinon. Les octets sont dans l'ordre du réseau.
fn adresse_insi(o: &[u8], debut: usize, vflag: u8) -> Option<IpAddr> {
    let a: [u8; 16] = octets(o, debut)?;
    if vflag & INI_IPV4 != 0 {
        Some(IpAddr::V4(Ipv4Addr::new(a[12], a[13], a[14], a[15])))
    } else if vflag & INI_IPV6 != 0 {
        Some(IpAddr::V6(Ipv6Addr::from(a)))
    } else {
        None
    }
}

/// Un port d'in_sockinfo : un `int` qui porte l'`u_short` du noyau, dans l'ordre du réseau (comme lsof, ntohs).
fn port_insi(o: &[u8], debut: usize) -> Option<u16> {
    let brut = u32_ne(o, debut)?;
    let court = u16::try_from(brut & 0xffff).ok()?;
    Some(u16::from_be(court))
}

/// La prise IP (TCP ou UDP) d'une réponse de proc_pidfdinfo(PROC_PIDFDSOCKETINFO). `None` : réponse d'une autre
/// taille que `socket_fdinfo`, prise d'une autre famille (Unix, noyau…), ou sans adresse lisible.
pub(crate) fn lire_socket_fdinfo(o: &[u8]) -> Option<PriseNoyau> {
    use std::mem::{offset_of, size_of};
    if o.len() != size_of::<SocketFdinfo>() {
        return None;
    }
    let psi = offset_of!(SocketFdinfo, psi);
    let famille = i32_ne(o, psi + offset_of!(SocketInfo, soi_family))?;
    if famille != AF_INET && famille != AF_INET6 {
        return None;
    }
    let protocole = i32_ne(o, psi + offset_of!(SocketInfo, soi_protocol))?;
    let sorte = i32_ne(o, psi + offset_of!(SocketInfo, soi_kind))?;
    let tcp = match (sorte, protocole) {
        (SOCKINFO_TCP, IPPROTO_TCP) => true,
        (SOCKINFO_IN, IPPROTO_UDP) => false,
        _ => return None,
    };
    // in_sockinfo est en tête de l'union, et aussi en tête de tcp_sockinfo.
    let ini = psi + offset_of!(SocketInfo, soi_proto);
    let vflag = *o.get(ini + offset_of!(InSockinfo, insi_vflag))?;
    let etat = if tcp {
        i32_ne(o, ini + offset_of!(TcpSockinfo, tcpsi_state))?
    } else {
        -1
    };
    Some(PriseNoyau {
        tcp,
        etat,
        locale: adresse_insi(o, ini + offset_of!(InSockinfo, insi_laddr), vflag)?,
        port_local: port_insi(o, ini + offset_of!(InSockinfo, insi_lport))?,
        distante: adresse_insi(o, ini + offset_of!(InSockinfo, insi_faddr), vflag)?,
        port_distant: port_insi(o, ini + offset_of!(InSockinfo, insi_fport))?,
    })
}

/// Ce que tout compte peut lire d'un processus (`proc_bsdshortinfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Court {
    pub pid: u32,
    pub ppid: u32,
    /// Le compte effectif (`pbsi_uid`) et le compte réel (`pbsi_ruid`, celui qui a lancé le programme).
    pub uid: u32,
    pub ruid: u32,
    /// Le nom court du noyau (p_comm, 16 octets au plus), choisi par le programme : à rendre inoffensif.
    pub comm: String,
}

/// Le texte d'un tableau de caractères C : jusqu'au premier nul, ou tout le tableau.
fn texte_c(o: &[u8]) -> String {
    let fin = o.iter().position(|&c| c == 0).unwrap_or(o.len());
    String::from_utf8_lossy(&o[..fin]).into_owned()
}

/// Une réponse de proc_pidinfo(PROC_PIDT_SHORTBSDINFO) ; `None` d'une autre taille, ou d'un autre processus que
/// celui demandé (un numéro réutilisé entre deux appels ne doit pas mêler deux processus).
pub(crate) fn lire_shortbsdinfo(o: &[u8], pid: u32) -> Option<Court> {
    use std::mem::{offset_of, size_of};
    if o.len() != size_of::<ProcBsdShortinfo>() {
        return None;
    }
    let lu = u32_ne(o, offset_of!(ProcBsdShortinfo, pbsi_pid))?;
    if lu != pid {
        return None;
    }
    let comm = offset_of!(ProcBsdShortinfo, pbsi_comm);
    Some(Court {
        pid,
        ppid: u32_ne(o, offset_of!(ProcBsdShortinfo, pbsi_ppid))?,
        uid: u32_ne(o, offset_of!(ProcBsdShortinfo, pbsi_uid))?,
        ruid: u32_ne(o, offset_of!(ProcBsdShortinfo, pbsi_ruid))?,
        comm: texte_c(o.get(comm..comm + 16)?),
    })
}

/// `sizeof(struct kinfo_proc)` sur macOS 64 bits (sys/sysctl.h : `extern_proc` puis `eproc`).
pub(crate) const TAILLE_KINFO_PROC: usize = 648;
/// Décalage de `p_pid` dans `extern_proc` : l'union `p_un` (16), deux pointeurs (16), `p_flag` (4), `p_stat` (1,
/// puis 3 octets d'alignement).
const KINFO_P_PID: usize = 40;

/// L'heure de démarrage d'un processus (secondes depuis 1970, microsecondes), dans la `kinfo_proc` que rend sysctl
/// {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid} : `p_starttime`, une `struct timeval` en tête d'`extern_proc`. Seul ce
/// champ est lu ; la taille et le numéro du processus (`p_pid`) gardent d'une réponse d'une autre forme.
pub(crate) fn debut_kinfo(o: &[u8], pid: u32) -> Option<(i64, u32)> {
    if o.len() != TAILLE_KINFO_PROC || u32_ne(o, KINFO_P_PID)? != pid {
        return None;
    }
    let secondes = i64::from_ne_bytes(octets(o, 0)?);
    let micro = u32_ne(o, 8)?;
    (secondes > 0 && micro < 1_000_000).then_some((secondes, micro))
}

/// Les arguments d'un processus, d'après sysctl KERN_PROCARGS2 : le nombre d'arguments (un `int`), le chemin du
/// programme lancé, des nuls de remplissage, puis les arguments, chacun fini par un nul (l'environnement suit, il
/// n'est pas lu : il peut porter des secrets). Rend (chemin, arguments). `None` : réponse trop courte ou qui annonce
/// plus d'arguments qu'elle n'en contient.
pub(crate) fn lire_procargs2(o: &[u8]) -> Option<(String, Vec<String>)> {
    let nombre = usize::try_from(i32_ne(o, 0)?).ok()?;
    if nombre > 100_000 {
        return None;
    }
    let reste = o.get(4..)?;
    let fin_chemin = reste.iter().position(|&c| c == 0)?;
    let chemin = String::from_utf8_lossy(&reste[..fin_chemin]).into_owned();
    let mut i = fin_chemin;
    while reste.get(i) == Some(&0) {
        i += 1;
    }
    let mut args = Vec::with_capacity(nombre.min(256));
    for _ in 0..nombre {
        let morceau = reste.get(i..)?;
        let longueur = morceau.iter().position(|&c| c == 0)?;
        args.push(String::from_utf8_lossy(&morceau[..longueur]).into_owned());
        i += longueur + 1;
    }
    Some((chemin, args))
}

/// (total, utilisé) en octets, d'après vm.swapusage (`struct xsw_usage`) ; `None` d'une autre taille.
pub(crate) fn lire_xsw_usage(o: &[u8]) -> Option<(u64, u64)> {
    use std::mem::{offset_of, size_of};
    if o.len() != size_of::<XswUsage>() {
        return None;
    }
    let total = u64_ne(o, offset_of!(XswUsage, xsu_total))?;
    let utilise = u64_ne(o, offset_of!(XswUsage, xsu_used))?;
    (utilise <= total).then_some((total, utilise))
}

// ───────────────────────────── net/route.h ─────────────────────────────

pub(crate) const RTF_UP: i32 = 0x1;
pub(crate) const RTF_GATEWAY: i32 = 0x2;
pub(crate) const RTF_LLINFO: i32 = 0x400;
pub(crate) const RTF_IFSCOPE: i32 = 0x0100_0000;
const RTM_VERSION: u8 = 5;
const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
const RTAX_MAX: usize = 8;

/// Une adresse d'un message de routage (`struct sockaddr` et ses variantes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdresseRoute {
    Ip(IpAddr),
    /// `sockaddr_dl` : l'interface (son numéro et son nom) et son adresse matérielle, vide si le noyau la tait.
    Lien {
        index: u16,
        nom: String,
        mac: Vec<u8>,
    },
    Autre,
}

impl std::fmt::Display for AdresseRoute {
    /// Comme `netstat -rn` : l'adresse IP, ou « link#4 » / l'adresse matérielle d'une interface.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AdresseRoute::Ip(ip) => write!(f, "{ip}"),
            AdresseRoute::Lien { index, mac, .. } if mac.is_empty() => write!(f, "link#{index}"),
            AdresseRoute::Lien { mac, .. } => {
                let t: Vec<String> = mac.iter().map(|o| format!("{o:x}")).collect();
                write!(f, "{}", t.join(":"))
            }
            AdresseRoute::Autre => write!(f, "?"),
        }
    }
}

/// Une route de la table, telle que la donne NET_RT_DUMP (ou NET_RT_FLAGS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    pub drapeaux: i32,
    pub index: u16,
    pub destination: Option<AdresseRoute>,
    pub passerelle: Option<AdresseRoute>,
    /// Le masque, absent pour une route d'hôte. Le noyau l'écrit tronqué après son dernier octet non nul (un masque
    /// nul tient en un `sa_len` de 0) : les octets manquants valent 0.
    pub masque: Option<IpAddr>,
}

/// Une `sockaddr` d'un message de routage : AF_INET, AF_INET6, AF_LINK ; sinon `Autre`. `famille_dst` sert au masque,
/// dont le noyau ne remplit pas toujours la famille.
fn adresse_route(sa: &[u8], famille_dst: Option<u8>) -> AdresseRoute {
    let famille = sa.get(1).copied().filter(|&f| f != 0).or(famille_dst);
    // Les octets à partir de `debut`, complétés de zéros jusqu'à `n` (masque tronqué).
    let complet = |debut: usize, n: usize| -> Vec<u8> {
        let mut v: Vec<u8> = sa.get(debut..).unwrap_or_default().iter().copied().take(n).collect();
        v.resize(n, 0);
        v
    };
    match famille.map(i32::from) {
        Some(AF_INET) => {
            let a = complet(4, 4);
            AdresseRoute::Ip(IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])))
        }
        Some(AF_INET6) => {
            let a: [u8; 16] = complet(8, 16).try_into().unwrap_or([0; 16]);
            AdresseRoute::Ip(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ if famille == Some(AF_LINK) => {
            // sdl_len, sdl_family, sdl_index (2), sdl_type, sdl_nlen, sdl_alen, sdl_slen, puis le nom et l'adresse.
            let index = u16_ne(sa, 2).unwrap_or(0);
            let nlen = usize::from(sa.get(5).copied().unwrap_or(0));
            let alen = usize::from(sa.get(6).copied().unwrap_or(0));
            let donnees = sa.get(8..).unwrap_or_default();
            let nom = donnees
                .get(..nlen)
                .map(|n| String::from_utf8_lossy(n).into_owned())
                .unwrap_or_default();
            let mac = donnees.get(nlen..nlen + alen).map(<[u8]>::to_vec).unwrap_or_default();
            AdresseRoute::Lien { index, nom, mac }
        }
        _ => AdresseRoute::Autre,
    }
}

/// La taille occupée par une `sockaddr` dans un message de routage : sa longueur arrondie à 4 octets, 4 pour une
/// longueur nulle (ROUNDUP32 de bsd/net/rtsock.c, sur Intel comme sur Apple Silicon).
fn place_sockaddr(longueur: usize) -> usize {
    if longueur == 0 { 4 } else { (longueur + 3) & !3 }
}

/// Les routes d'une réponse de sysctl {CTL_NET, PF_ROUTE, 0, famille, NET_RT_DUMP ou NET_RT_FLAGS, …} : une suite de
/// `rt_msghdr`, chacun suivi des adresses que `rtm_addrs` annonce. Un message de longueur impossible arrête la
/// lecture (la suite ne se recale pas) ; un message d'une autre version est sauté.
pub(crate) fn lire_routes(o: &[u8]) -> Vec<Route> {
    use std::mem::{offset_of, size_of};
    let entete = size_of::<RtMsghdr>();
    let mut routes = Vec::new();
    let mut debut = 0usize;
    while routes.len() < 100_000 {
        let Some(longueur) = u16_ne(o, debut).map(usize::from) else {
            break;
        };
        let Some(message) = o.get(debut..debut.saturating_add(longueur)) else {
            break;
        };
        if longueur < entete {
            break;
        }
        debut += longueur;
        if message.get(offset_of!(RtMsghdr, rtm_version)) != Some(&RTM_VERSION) {
            continue;
        }
        let drapeaux = i32_ne(message, offset_of!(RtMsghdr, rtm_flags)).unwrap_or(0);
        let index = u16_ne(message, offset_of!(RtMsghdr, rtm_index)).unwrap_or(0);
        let presentes = i32_ne(message, offset_of!(RtMsghdr, rtm_addrs)).unwrap_or(0);
        let mut adresses: [Option<&[u8]>; RTAX_MAX] = [None; RTAX_MAX];
        let mut i = entete;
        for (rang, place) in adresses.iter_mut().enumerate() {
            if presentes & (1 << rang) == 0 {
                continue;
            }
            let Some(&sa_len) = message.get(i) else {
                break;
            };
            let sa_len = usize::from(sa_len);
            *place = Some(message.get(i..(i + sa_len).min(message.len())).unwrap_or_default());
            i += place_sockaddr(sa_len);
        }
        let famille_dst = adresses[RTAX_DST].and_then(|d| d.get(1).copied());
        routes.push(Route {
            drapeaux,
            index,
            destination: adresses[RTAX_DST].map(|sa| adresse_route(sa, None)),
            passerelle: adresses[RTAX_GATEWAY].map(|sa| adresse_route(sa, None)),
            masque: adresses[RTAX_NETMASK].and_then(|sa| match adresse_route(sa, famille_dst) {
                AdresseRoute::Ip(ip) => Some(ip),
                _ => None,
            }),
        });
    }
    routes
}

/// La passerelle par défaut en IPv4, ce que dit `route -n get default` : la route 0.0.0.0/0 vers une passerelle, active,
/// et non attachée à une seule interface (RTF_IFSCOPE : les routes par défaut de secours de chaque interface).
pub(crate) fn passerelle_par_defaut(routes: &[Route]) -> Option<Ipv4Addr> {
    routes.iter().find_map(|r| {
        let voulus = RTF_UP | RTF_GATEWAY;
        if r.drapeaux & voulus != voulus || r.drapeaux & RTF_IFSCOPE != 0 {
            return None;
        }
        let Some(AdresseRoute::Ip(IpAddr::V4(dst))) = r.destination else {
            return None;
        };
        let masque_nul = r.masque.is_none_or(|m| m == IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        match &r.passerelle {
            Some(AdresseRoute::Ip(IpAddr::V4(p))) if dst.is_unspecified() && masque_nul => Some(*p),
            _ => None,
        }
    })
}

/// Un voisin du réseau local (table ARP) : son adresse IPv4, son adresse matérielle, le numéro de son interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Voisin {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub index: u16,
}

/// Les voisins d'une réponse NET_RT_FLAGS / RTF_LLINFO, ceux qu'affiche `arp -an` : une route d'hôte IPv4 dont la
/// passerelle est une adresse matérielle de 6 octets. Une entrée incomplète (sans adresse) n'en est pas un.
pub(crate) fn voisins(routes: &[Route]) -> Vec<Voisin> {
    routes
        .iter()
        .filter(|r| r.drapeaux & RTF_LLINFO != 0)
        .filter_map(|r| {
            let Some(AdresseRoute::Ip(IpAddr::V4(ip))) = r.destination else {
                return None;
            };
            let Some(AdresseRoute::Lien { index, mac, .. }) = &r.passerelle else {
                return None;
            };
            Some(Voisin {
                ip,
                mac: mac.as_slice().try_into().ok()?,
                index: *index,
            })
        })
        .collect()
}

// ───────────────────────────── sys/csr.h ─────────────────────────────

/// Les drapeaux de la configuration de SIP (CSR_ALLOW_*), dans l'ordre de sys/csr.h, et ce que chacun relâche.
pub(crate) const DRAPEAUX_CSR: [(u32, &str); 13] = [
    (1 << 0, "CSR_ALLOW_UNTRUSTED_KEXTS"),
    (1 << 1, "CSR_ALLOW_UNRESTRICTED_FS"),
    (1 << 2, "CSR_ALLOW_TASK_FOR_PID"),
    (1 << 3, "CSR_ALLOW_KERNEL_DEBUGGER"),
    (1 << 4, "CSR_ALLOW_APPLE_INTERNAL"),
    (1 << 5, "CSR_ALLOW_UNRESTRICTED_DTRACE"),
    (1 << 6, "CSR_ALLOW_UNRESTRICTED_NVRAM"),
    (1 << 7, "CSR_ALLOW_DEVICE_CONFIGURATION"),
    (1 << 8, "CSR_ALLOW_ANY_RECOVERY_OS"),
    (1 << 9, "CSR_ALLOW_UNAPPROVED_KEXTS"),
    (1 << 10, "CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE"),
    (1 << 11, "CSR_ALLOW_UNAUTHENTICATED_ROOT"),
    (1 << 12, "CSR_ALLOW_RESEARCH_GUESTS"),
];

/// L'état de SIP d'après csr_get_active_config : actif quand aucun drapeau n'est posé (la configuration d'origine,
/// `csrutil enable`). Tout drapeau, même inconnu de cette liste, le réduit : une exception faite par `csrutil enable
/// --without …` (« Custom Configuration ») n'est pas un SIP entier. Rend les noms des drapeaux posés (un bit inconnu
/// se dit par sa valeur).
pub(crate) fn drapeaux_sip(config: u32) -> Vec<String> {
    let mut noms: Vec<String> = DRAPEAUX_CSR
        .iter()
        .filter(|(bit, _)| config & bit != 0)
        .map(|(_, nom)| (*nom).to_string())
        .collect();
    let connus = DRAPEAUX_CSR.iter().fold(0u32, |acc, (bit, _)| acc | bit);
    if config & !connus != 0 {
        noms.push(format!("0x{:x}", config & !connus));
    }
    noms
}

// ───────────────────────────── diskutil -plist, ioreg -a ─────────────────────────────

/// Un entier positif d'une plist.
fn entier(v: Option<&crate::plist::Valeur>) -> Option<u64> {
    match v? {
        crate::plist::Valeur::Entier(n) => u64::try_from(*n).ok(),
        _ => None,
    }
}

/// Les disques entiers de `diskutil list -plist internal physical` (« WholeDisks »), ceux dont le nom est bien
/// « disk » suivi de chiffres : ils repartent en argument de diskutil.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn disques_entiers(liste: &crate::plist::Valeur) -> Vec<String> {
    liste
        .cle("WholeDisks")
        .and_then(crate::plist::Valeur::tableau)
        .unwrap_or_default()
        .iter()
        .filter_map(crate::plist::Valeur::texte)
        .filter(|n| {
            n.strip_prefix("disk")
                .is_some_and(|c| !c.is_empty() && c.bytes().all(|o| o.is_ascii_digit()))
        })
        .take(64)
        .map(str::to_string)
        .collect()
}

/// Ce que `diskutil info -plist <disque>` dit d'un disque.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct InfoDisque {
    /// Octets (« TotalSize », sinon « Size »).
    pub taille: Option<u64>,
    /// « SolidState » ; `None` : non dit.
    pub ssd: Option<bool>,
    /// « MediaName », choisi par le fabricant du disque : à rendre inoffensif avant de le montrer.
    pub modele: Option<String>,
    /// « SMARTStatus » (« Verified », « Failing », « Not Supported »).
    pub smart: Option<String>,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn info_disque(v: &crate::plist::Valeur) -> InfoDisque {
    use crate::plist::Valeur;
    let texte = |cle: &str| {
        v.cle(cle)
            .and_then(Valeur::texte)
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    };
    InfoDisque {
        taille: entier(v.cle("TotalSize")).or_else(|| entier(v.cle("Size"))),
        ssd: match v.cle("SolidState") {
            Some(Valeur::Booleen(b)) => Some(*b),
            _ => None,
        },
        modele: texte("MediaName"),
        smart: texte("SMARTStatus"),
    }
}

/// La santé de la batterie en % d'après `ioreg -a -rn AppleSmartBattery` (une liste de dictionnaires) : capacité
/// maximale actuelle / capacité d'origine. « AppleRawMaxCapacity » sur Apple Silicon (où « MaxCapacity » est déjà un
/// pourcentage), « MaxCapacity » en mAh sur Intel.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn sante_batterie(v: &crate::plist::Valeur) -> Option<u64> {
    let batterie = match v.tableau() {
        Some(liste) => liste.iter().find(|b| b.cle("DesignCapacity").is_some())?,
        None => v,
    };
    let origine = entier(batterie.cle("DesignCapacity")).filter(|c| *c > 0)?;
    let actuelle = entier(batterie.cle("AppleRawMaxCapacity"))
        .or_else(|| entier(batterie.cle("MaxCapacity")).filter(|c| *c > 100))?;
    Some((actuelle.saturating_mul(100) / origine).min(100))
}

/// L'identifiant de l'ordinateur (gethostuuid, 16 octets) écrit comme ioreg écrit IOPlatformUUID : en majuscules,
/// 8-4-4-4-12. L'empreinte de la machine (SHA-1 de ce texte) en dépend : la clé reconnaît l'ordinateur par elle.
#[cfg_attr(not(test), allow(dead_code))] // l'oracle de macos.yml seulement, tant que ioreg fait foi
pub(crate) fn uuid_comme_ioreg(o: &[u8; 16]) -> String {
    use std::fmt::Write;
    let h = o.iter().fold(String::with_capacity(32), |mut h, b| {
        let _ = write!(h, "{b:02X}");
        h
    });
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    /// Une socket_fdinfo fabriquée : les champs posés aux décalages écrits en clair (relus dans sys/proc_info.h),
    /// pas à ceux de offset_of! : une structure mal recopiée ne se vérifierait pas elle-même.
    fn prise(famille: i32, protocole: i32, sorte: i32, vflag: u8, etat: i32) -> Vec<u8> {
        let mut o = vec![0u8; 792];
        o[184..188].copy_from_slice(&famille.to_ne_bytes()); // 24 + soi_family (160)
        o[180..184].copy_from_slice(&protocole.to_ne_bytes()); // 24 + soi_protocol (156)
        o[256..260].copy_from_slice(&sorte.to_ne_bytes()); // 24 + soi_kind (232)
        let ini = 264; // 24 + soi_proto (240)
        o[ini..ini + 4].copy_from_slice(&u32::from(443u16.to_be()).to_ne_bytes()); // insi_fport
        o[ini + 4..ini + 8].copy_from_slice(&u32::from(52_000u16.to_be()).to_ne_bytes()); // insi_lport
        o[ini + 24] = vflag;
        if vflag & INI_IPV4 != 0 {
            o[ini + 32 + 12..ini + 48].copy_from_slice(&[192, 0, 2, 7]); // insi_faddr.ina_46.i46a_addr4
            o[ini + 48 + 12..ini + 64].copy_from_slice(&[192, 168, 1, 20]); // insi_laddr
        } else {
            o[ini + 32..ini + 48].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
            o[ini + 48..ini + 64].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        }
        o[ini + 80..ini + 84].copy_from_slice(&etat.to_ne_bytes()); // tcpsi_state
        o
    }

    #[test]
    fn decalages_ecrits_a_la_main() {
        assert_eq!(offset_of!(SocketFdinfo, psi) + offset_of!(SocketInfo, soi_family), 184);
        assert_eq!(offset_of!(SocketFdinfo, psi) + offset_of!(SocketInfo, soi_kind), 256);
        assert_eq!(offset_of!(SocketFdinfo, psi) + offset_of!(SocketInfo, soi_proto), 264);
        assert_eq!(size_of::<SocketFdinfo>(), 792);
    }

    #[test]
    fn prise_tcp_ipv4_et_ipv6() {
        let p = lire_socket_fdinfo(&prise(AF_INET, IPPROTO_TCP, SOCKINFO_TCP, INI_IPV4, TSI_S_ESTABLISHED)).unwrap();
        assert!(p.tcp);
        assert_eq!(p.etat, TSI_S_ESTABLISHED);
        assert_eq!(p.locale, "192.168.1.20".parse::<IpAddr>().unwrap());
        assert_eq!((p.port_local, p.port_distant), (52_000, 443));
        assert_eq!(p.distante, "192.0.2.7".parse::<IpAddr>().unwrap());
        // Une prise IPv6 qui sert aussi IPv4 (INI_IPV4) se lit en IPv4.
        let p = lire_socket_fdinfo(&prise(AF_INET6, IPPROTO_TCP, SOCKINFO_TCP, INI_IPV4, TSI_S_LISTEN)).unwrap();
        assert!(p.distante.is_ipv4());
        let p = lire_socket_fdinfo(&prise(AF_INET6, IPPROTO_TCP, SOCKINFO_TCP, INI_IPV6, TSI_S_LISTEN)).unwrap();
        assert_eq!(p.locale, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(p.distante, "2001:db8::7".parse::<IpAddr>().unwrap());
        // UDP : pas d'état.
        let p = lire_socket_fdinfo(&prise(AF_INET, IPPROTO_UDP, SOCKINFO_IN, INI_IPV4, 99)).unwrap();
        assert!(!p.tcp && p.etat == -1);
    }

    /// Ce qui n'est pas une prise IP lisible, ou une réponse d'une autre taille : rien, jamais une prise inventée.
    #[test]
    fn noms_des_etats_tcp() {
        assert_eq!(nom_etat_tcp(TSI_S_LISTEN), "LISTEN");
        assert_eq!(nom_etat_tcp(TSI_S_ESTABLISHED), "ESTABLISHED");
        assert_eq!(nom_etat_tcp(10), "TIME_WAIT");
        assert_eq!(nom_etat_tcp(-1), "?");
        assert_eq!(nom_etat_tcp(11), "?");
    }

    #[test]
    fn prises_refusees() {
        assert_eq!(lire_socket_fdinfo(&prise(1, 0, 3, 0, 0)), None); // AF_UNIX
        assert_eq!(
            lire_socket_fdinfo(&prise(AF_INET, IPPROTO_TCP, SOCKINFO_TCP, 0, 1)),
            None
        );
        assert_eq!(
            lire_socket_fdinfo(&prise(AF_INET, IPPROTO_UDP, SOCKINFO_TCP, INI_IPV4, 1)),
            None
        );
        let mut courte = prise(AF_INET, IPPROTO_TCP, SOCKINFO_TCP, INI_IPV4, 1);
        courte.pop();
        assert_eq!(lire_socket_fdinfo(&courte), None);
        assert_eq!(lire_socket_fdinfo(&[]), None);
        let mut longue = prise(AF_INET, IPPROTO_TCP, SOCKINFO_TCP, INI_IPV4, 1);
        longue.push(0);
        assert_eq!(lire_socket_fdinfo(&longue), None);
    }

    #[test]
    fn info_courte_du_processus() {
        let mut o = vec![0u8; 64];
        o[0..4].copy_from_slice(&4242u32.to_ne_bytes());
        o[4..8].copy_from_slice(&1u32.to_ne_bytes());
        o[16..28].copy_from_slice(b"llama-server");
        o[36..40].copy_from_slice(&501u32.to_ne_bytes());
        o[44..48].copy_from_slice(&502u32.to_ne_bytes());
        let c = lire_shortbsdinfo(&o, 4242).unwrap();
        assert_eq!((c.ppid, c.uid, c.ruid, c.comm.as_str()), (1, 501, 502, "llama-server"));
        // Un autre processus que celui demandé, ou une autre taille : refusé.
        assert_eq!(lire_shortbsdinfo(&o, 4243), None);
        assert_eq!(lire_shortbsdinfo(&o[..63], 4242), None);
        // 16 caractères sans nul : tout le tableau, pas au-delà.
        o[16..32].copy_from_slice(b"AppleFileServerX");
        assert_eq!(lire_shortbsdinfo(&o, 4242).unwrap().comm, "AppleFileServerX");
    }

    #[test]
    fn debut_dans_kinfo_proc() {
        let mut o = vec![0u8; TAILLE_KINFO_PROC];
        o[0..8].copy_from_slice(&1_761_300_000i64.to_ne_bytes());
        o[8..12].copy_from_slice(&250_000u32.to_ne_bytes());
        o[40..44].copy_from_slice(&77u32.to_ne_bytes());
        assert_eq!(debut_kinfo(&o, 77), Some((1_761_300_000, 250_000)));
        assert_eq!(debut_kinfo(&o, 78), None);
        assert_eq!(debut_kinfo(&o[..600], 77), None);
    }

    #[test]
    fn arguments_procargs2() {
        let mut o = 3i32.to_ne_bytes().to_vec();
        o.extend_from_slice(b"/usr/bin/ssh\0\0\0\0ssh\0-p\x002222\0HOME=/Users/alice\0");
        let (chemin, args) = lire_procargs2(&o).unwrap();
        assert_eq!(chemin, "/usr/bin/ssh");
        assert_eq!(args, ["ssh", "-p", "2222"]);
        // Plus d'arguments annoncés que présents, nombre négatif, réponse vide : rien.
        let mut menteur = 9i32.to_ne_bytes().to_vec();
        menteur.extend_from_slice(b"/bin/x\0x\0");
        assert_eq!(lire_procargs2(&menteur), None);
        assert_eq!(lire_procargs2(&(-1i32).to_ne_bytes()), None);
        assert_eq!(lire_procargs2(&[]), None);
        // Aucun argument : le chemin seul.
        let mut seul = 0i32.to_ne_bytes().to_vec();
        seul.extend_from_slice(b"/bin/y\0");
        assert_eq!(lire_procargs2(&seul), Some(("/bin/y".into(), Vec::new())));
    }

    #[test]
    fn echange_xsw_usage() {
        let mut o = vec![0u8; 32];
        o[0..8].copy_from_slice(&(2u64 << 30).to_ne_bytes());
        o[16..24].copy_from_slice(&(1u64 << 30).to_ne_bytes());
        assert_eq!(lire_xsw_usage(&o), Some((2 << 30, 1 << 30)));
        assert_eq!(lire_xsw_usage(&o[..31]), None);
        // Plus d'utilisé que de total : une réponse impossible.
        o[16..24].copy_from_slice(&(3u64 << 30).to_ne_bytes());
        assert_eq!(lire_xsw_usage(&o), None);
    }

    /// Un message de routage : en-tête de 92 octets puis les sockaddr annoncées, chacune arrondie à 4.
    fn message(drapeaux: i32, index: u16, adresses: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let mut o = vec![0u8; 92];
        o[2] = RTM_VERSION;
        o[4..6].copy_from_slice(&index.to_ne_bytes());
        o[8..12].copy_from_slice(&drapeaux.to_ne_bytes());
        let mut presentes = 0i32;
        for (rang, sa) in adresses {
            presentes |= 1 << rang;
            let mut sa = sa.clone();
            sa.resize(place_sockaddr(sa.len()), 0);
            o.extend_from_slice(&sa);
        }
        o[12..16].copy_from_slice(&presentes.to_ne_bytes());
        let longueur = u16::try_from(o.len()).unwrap();
        o[0..2].copy_from_slice(&longueur.to_ne_bytes());
        o
    }

    fn sin(a: [u8; 4]) -> Vec<u8> {
        let mut s = vec![16, 2, 0, 0];
        s.extend_from_slice(&a);
        s.extend_from_slice(&[0; 8]);
        s
    }

    fn sdl(index: u16, nom: &[u8], mac: &[u8]) -> Vec<u8> {
        let mut s = vec![0, AF_LINK];
        s.extend_from_slice(&index.to_ne_bytes());
        s.extend_from_slice(&[6, u8::try_from(nom.len()).unwrap(), u8::try_from(mac.len()).unwrap(), 0]);
        s.extend_from_slice(nom);
        s.extend_from_slice(mac);
        s.resize(s.len().max(20), 0);
        s[0] = u8::try_from(s.len()).unwrap();
        s
    }

    #[test]
    fn table_de_routage() {
        let mut o = Vec::new();
        // Une route par défaut attachée à en1 seulement (RTF_IFSCOPE) : pas la passerelle de l'ordinateur.
        o.extend(message(
            RTF_UP | RTF_GATEWAY | RTF_IFSCOPE,
            5,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sin([10, 0, 0, 1])),
                (RTAX_NETMASK, vec![0, 0, 0, 0]),
            ],
        ));
        // La route par défaut, masque nul écrit en sa_len 0 (4 octets occupés).
        o.extend(message(
            RTF_UP | RTF_GATEWAY,
            4,
            &[
                (RTAX_DST, sin([0; 4])),
                (RTAX_GATEWAY, sin([192, 168, 1, 1])),
                (RTAX_NETMASK, vec![0, 0, 0, 0]),
            ],
        ));
        // Un voisin : route d'hôte vers une adresse matérielle.
        o.extend(message(
            RTF_UP | RTF_LLINFO,
            4,
            &[
                (RTAX_DST, sin([192, 168, 1, 1])),
                (RTAX_GATEWAY, sdl(4, b"en0", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])),
            ],
        ));
        // Une entrée incomplète, sans adresse matérielle.
        o.extend(message(
            RTF_UP | RTF_LLINFO,
            4,
            &[(RTAX_DST, sin([192, 168, 1, 9])), (RTAX_GATEWAY, sdl(4, b"en0", &[]))],
        ));
        let routes = lire_routes(&o);
        assert_eq!(routes.len(), 4);
        assert_eq!(passerelle_par_defaut(&routes), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(
            routes[2].passerelle,
            Some(AdresseRoute::Lien {
                index: 4,
                nom: "en0".into(),
                mac: vec![0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]
            })
        );
        assert_eq!(routes[1].index, 4);
        assert_eq!(routes[2].passerelle.as_ref().unwrap().to_string(), "0:1a:2b:3c:4d:5e");
        assert_eq!(routes[3].passerelle.as_ref().unwrap().to_string(), "link#4");
        let v = voisins(&routes);
        assert_eq!(v.len(), 1);
        assert_eq!(
            (v[0].ip, v[0].mac[5], v[0].index),
            (Ipv4Addr::new(192, 168, 1, 1), 0x5e, 4)
        );
    }

    /// Des octets hostiles : longueur nulle ou trop grande, adresses annoncées absentes, autre version. Jamais de
    /// panique, jamais une route inventée.
    #[test]
    fn table_de_routage_hostile() {
        assert_eq!(lire_routes(&[]), Vec::new());
        assert_eq!(lire_routes(&[0, 0, 5, 0]), Vec::new());
        let mut m = message(RTF_UP | RTF_GATEWAY, 1, &[(RTAX_DST, sin([0; 4]))]);
        m[12..16].copy_from_slice(&0xffi32.to_ne_bytes()); // huit adresses annoncées, une seule présente
        let r = lire_routes(&m);
        assert_eq!(r.len(), 1);
        assert_eq!(passerelle_par_defaut(&r), None);
        let mut trop_long = message(RTF_UP, 1, &[]);
        trop_long[0..2].copy_from_slice(&500u16.to_ne_bytes());
        assert_eq!(lire_routes(&trop_long), Vec::new());
        let mut autre = message(
            RTF_UP | RTF_GATEWAY,
            1,
            &[(RTAX_DST, sin([0; 4])), (RTAX_GATEWAY, sin([1, 2, 3, 4]))],
        );
        autre[2] = 4;
        assert_eq!(lire_routes(&autre), Vec::new());
        // Des octets au hasard, de toutes les longueurs : rien ne tombe.
        let mut graine = 0x2545_f491_u32;
        for n in 0..400 {
            let o: Vec<u8> = (0..n)
                .map(|_| {
                    graine ^= graine << 13;
                    graine ^= graine >> 17;
                    graine ^= graine << 5;
                    graine.to_le_bytes()[0]
                })
                .collect();
            let _ = lire_routes(&o);
            let _ = lire_procargs2(&o);
            let _ = lire_socket_fdinfo(&o);
        }
    }

    #[test]
    fn sip_et_ses_drapeaux() {
        assert_eq!(drapeaux_sip(0), Vec::<String>::new());
        assert_eq!(drapeaux_sip(0x7f).len(), 7); // csrutil disable : CSR_DISABLE_FLAGS
        assert_eq!(drapeaux_sip(1 << 9), ["CSR_ALLOW_UNAPPROVED_KEXTS"]);
        assert_eq!(drapeaux_sip(1 << 20), ["0x100000"]);
    }

    #[test]
    fn disques_et_batterie_en_plist() {
        let liste = crate::plist::lire(
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>WholeDisks</key><array>
            <string>disk0</string><string>disk; rm</string><string>disk</string><string>disk12</string></array></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(disques_entiers(&liste), ["disk0", "disk12"]);
        let info = crate::plist::lire(
            br#"<plist version="1.0"><dict><key>MediaName</key><string>APPLE SSD AP0512Z</string>
            <key>SMARTStatus</key><string>Verified</string><key>SolidState</key><true/>
            <key>TotalSize</key><integer>500277790720</integer></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(
            info_disque(&info),
            InfoDisque {
                taille: Some(500_277_790_720),
                ssd: Some(true),
                modele: Some("APPLE SSD AP0512Z".into()),
                smart: Some("Verified".into())
            }
        );
        let silicon = crate::plist::lire(
            br#"<plist version="1.0"><array><dict><key>DesignCapacity</key><integer>4382</integer>
            <key>MaxCapacity</key><integer>100</integer><key>AppleRawMaxCapacity</key><integer>3943</integer></dict></array></plist>"#,
        )
        .unwrap();
        assert_eq!(sante_batterie(&silicon), Some(89));
        let intel = crate::plist::lire(
            br#"<plist version="1.0"><array><dict><key>DesignCapacity</key><integer>5000</integer>
            <key>MaxCapacity</key><integer>4500</integer></dict></array></plist>"#,
        )
        .unwrap();
        assert_eq!(sante_batterie(&intel), Some(90));
        // Sans batterie (un Mac de bureau) : rien.
        assert_eq!(
            sante_batterie(&crate::plist::lire(br#"<plist version="1.0"><array/></plist>"#).unwrap()),
            None
        );
    }

    #[test]
    fn uuid_ecrit_comme_ioreg() {
        let o = [
            0x56, 0x4d, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7,
        ];
        assert_eq!(uuid_comme_ioreg(&o), "564D0A1B-2C3D-4E5F-6071-8293A4B5C6D7");
    }
}
