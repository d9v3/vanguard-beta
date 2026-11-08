//! L'isolement de l'ordinateur (Défense R4) dans nf_tables : une table à lui, `inet vanguard_isolement`, distincte de
//! celle du blocage, posée et retirée par netlink comme elle (sans nft ni shell). Ses trois chaînes jettent tout ce
//! qu'elles ne permettent pas : une table d'un autre outil qui accepte ne la contourne pas (un paquet doit passer
//! toutes les chaînes de son crochet), et rien n'est retiré à celles des autres.
//!
//! ```text
//! table inet vanguard_isolement {
//!     chain entree { type filter hook input priority 0; policy drop;
//!         iifname "lo" accept
//!         ip saddr <gardée> accept            ip6 saddr <gardée> accept     (sessions, serveurs de Vanguard)
//!         ip saddr <dns> udp|tcp sport 53 accept                            (le résolveur en place)
//!         udp sport 67 udp dport 68 accept    udp sport 547 udp dport 546 accept      (DHCP)
//!         icmpv6 type 133-136 accept                                        (découverte des voisins)
//!         icmp type 3 code 4 accept           icmpv6 type 2 accept           (taille des paquets) }
//!     chain sortie { type filter hook output priority 0; policy drop;
//!         oifname "lo" accept   ip daddr <gardée> accept   ip daddr <dns> udp|tcp dport 53 accept
//!         udp sport 68 udp dport 67 accept    udp sport 546 udp dport 547 accept   icmpv6 type 133-136 accept }
//!     chain transit { type filter hook forward priority 0; policy drop; }
//! }
//! ```
//!
//! Posée en un seul lot (créée, supprimée, recréée : jamais un instant sans elle quand elle était déjà là, jamais une
//! règle en double), puis relue : chaque chaîne doit avoir ses règles. Le retrait supprime la table par son nom, et
//! rien d'autre : il ne dépend d'aucune note.

use std::net::IpAddr;

use super::{
    Attributs, CROCHET_ENTREE, CROCHET_SORTIE, NETLINK_NETFILTER, NF_ACCEPT, NF_DROP, NFPROTO_IPV4, NFPROTO_IPV6,
    NFT_CMP_EQ, NFT_META_IIFNAME, NFT_META_L4PROTO, NFT_META_NFPROTO, NFT_MSG_GETRULE, NFT_MSG_GETTABLE,
    NFT_MSG_NEWCHAIN, NFT_MSG_NEWRULE, NFT_MSG_NEWTABLE, NFT_PAYLOAD_NETWORK_HEADER, NFT_PAYLOAD_TRANSPORT_HEADER,
    NFT_REG_VERDICT, NFTA_CHAIN_HOOK, NFTA_CHAIN_NAME, NFTA_CHAIN_POLICY, NFTA_CHAIN_TABLE, NFTA_CHAIN_TYPE,
    NFTA_DATA_VERDICT, NFTA_HOOK_HOOKNUM, NFTA_HOOK_PRIORITY, NFTA_IMMEDIATE_DATA, NFTA_IMMEDIATE_DREG,
    NFTA_RULE_CHAIN, NFTA_RULE_EXPRESSIONS, NFTA_RULE_TABLE, NFTA_TABLE_FLAGS, NFTA_TABLE_NAME, NFTA_VERDICT_CODE, OU,
    Prise, attributs, cmp, expression, genre, lot, meta, netlink, nft, payload, premier_numero, recus, refus,
};
use crate::modele::Echec;
use crate::protection::isolement::Permis;
use crate::tr;

/// Le nom de la table : la marque de Vanguard, ce que le retrait vise et rien d'autre.
pub(crate) const TABLE_ISOLEMENT: &str = "vanguard_isolement";

const NFT_MSG_DELTABLE: u16 = 2;
/// Le crochet du transit (ce que l'ordinateur route pour d'autres : conteneurs, machines virtuelles).
const CROCHET_TRANSIT: u32 = 2;
/// meta oifname.
const NFT_META_OIFNAME: u32 = 7;

/// Les trois chaînes : (nom, crochet).
const CHAINES: [(&str, u32); 3] = [
    ("entree", CROCHET_ENTREE),
    ("sortie", CROCHET_SORTIE),
    ("transit", CROCHET_TRANSIT),
];

fn accepter(a: &mut Attributs) {
    expression(a, "immediate", |d| {
        d.be32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        d.imbrique(NFTA_IMMEDIATE_DATA, |v| {
            v.imbrique(NFTA_DATA_VERDICT, |c| c.be32(NFTA_VERDICT_CODE, NF_ACCEPT));
        });
    });
}

/// Un nom d'interface comparé sur IFNAMSIZ (16) octets, bourré de zéros.
fn nom_d_interface(nom: &[u8]) -> [u8; 16] {
    let mut n = [0u8; 16];
    if let Some(debut) = n.get_mut(..nom.len()) {
        debut.copy_from_slice(nom);
    }
    n
}

/// « `ip saddr|daddr <adresse>` » (ou ip6) : la famille, puis l'adresse à sa place dans l'en-tête.
fn adresse(a: &mut Attributs, ip: IpAddr, source: bool) {
    meta(a, NFT_META_NFPROTO);
    match ip {
        IpAddr::V4(v4) => {
            cmp(a, NFT_CMP_EQ, &[NFPROTO_IPV4]);
            payload(a, NFT_PAYLOAD_NETWORK_HEADER, if source { 12 } else { 16 }, 4);
            cmp(a, NFT_CMP_EQ, &v4.octets());
        }
        IpAddr::V6(v6) => {
            cmp(a, NFT_CMP_EQ, &[NFPROTO_IPV6]);
            payload(a, NFT_PAYLOAD_NETWORK_HEADER, if source { 8 } else { 24 }, 16);
            cmp(a, NFT_CMP_EQ, &v6.octets());
        }
    }
}

fn protocole(a: &mut Attributs, l4: u8) {
    meta(a, NFT_META_L4PROTO);
    cmp(a, NFT_CMP_EQ, &[l4]);
}

/// « sport N » ou « dport N » de l'en-tête UDP ou TCP (les deux au même endroit).
fn port(a: &mut Attributs, numero: u16, source: bool) {
    payload(a, NFT_PAYLOAD_TRANSPORT_HEADER, if source { 0 } else { 2 }, 2);
    cmp(a, NFT_CMP_EQ, &numero.to_be_bytes());
}

fn regle(f: impl FnOnce(&mut Attributs)) -> Attributs {
    let mut r = Attributs::default();
    f(&mut r);
    accepter(&mut r);
    r
}

/// Les règles de l'isolement, chaîne par chaîne, dans l'ordre où elles sont posées. Le transit n'en a aucune.
pub(crate) fn regles(permis: &Permis) -> Vec<(&'static str, Attributs)> {
    let mut v = Vec::new();
    for (chaine, entree) in [("entree", true), ("sortie", false)] {
        let lo = nom_d_interface(b"lo");
        v.push((
            chaine,
            regle(|r| {
                meta(r, if entree { NFT_META_IIFNAME } else { NFT_META_OIFNAME });
                cmp(r, NFT_CMP_EQ, &lo);
            }),
        ));
        // Les sessions gardées et les serveurs de Vanguard : tout échange avec eux.
        for ip in permis.garder.iter().chain(&permis.serveurs) {
            v.push((chaine, regle(|r| adresse(r, *ip, entree))));
        }
        // Le résolveur en place : le port 53 seulement, en UDP et en TCP.
        for ip in &permis.dns {
            for l4 in [17, 6] {
                v.push((
                    chaine,
                    regle(|r| {
                        adresse(r, *ip, entree);
                        protocole(r, l4);
                        port(r, 53, entree);
                    }),
                ));
            }
        }
        // DHCP (v4 : client 68, serveur 67 ; v6 : client 546, serveur 547).
        for (client, serveur) in [(68u16, 67u16), (546, 547)] {
            v.push((
                chaine,
                regle(|r| {
                    protocole(r, 17);
                    let (source, destination) = if entree { (serveur, client) } else { (client, serveur) };
                    port(r, source, true);
                    port(r, destination, false);
                }),
            ));
        }
        // La découverte des voisins d'IPv6 (sollicitation et annonce de routeur, de voisin) : sans elle, plus
        // d'adresse ni de passerelle IPv6, la session gardée comprise.
        for genre_icmp in 133u8..=136 {
            v.push((
                chaine,
                regle(|r| {
                    protocole(r, 58);
                    payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 1);
                    cmp(r, NFT_CMP_EQ, &[genre_icmp]);
                }),
            ));
        }
    }
    // La taille des paquets sur le chemin (« fragmentation nécessaire », « paquet trop grand ») : sans elle, une
    // session gardée peut se figer sur un lien à MTU réduite.
    v.push((
        "entree",
        regle(|r| {
            meta(r, NFT_META_NFPROTO);
            cmp(r, NFT_CMP_EQ, &[NFPROTO_IPV4]);
            protocole(r, 1);
            payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2);
            cmp(r, NFT_CMP_EQ, &[3, 4]);
        }),
    ));
    v.push((
        "entree",
        regle(|r| {
            protocole(r, 58);
            payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 1);
            cmp(r, NFT_CMP_EQ, &[2]);
        }),
    ));
    v
}

/// Le nombre de règles attendu dans chaque chaîne.
pub(crate) fn attendues(permis: &Permis) -> Vec<(&'static str, usize)> {
    let r = regles(permis);
    CHAINES
        .iter()
        .map(|(c, _)| (*c, r.iter().filter(|(chaine, _)| chaine == c).count()))
        .collect()
}

/// Le lot qui pose l'isolement : la table créée si elle manque, supprimée, recréée avec ses chaînes et ses règles.
/// Tout ou rien, en une seule transaction du noyau.
pub(crate) fn lot_isoler(premier: u32, permis: &Permis) -> (Vec<u8>, Vec<u32>) {
    let creer = super::NLM_F_REQUEST | super::NLM_F_CREATE | super::NLM_F_ACK;
    let table = |a: &mut Attributs| {
        a.texte(NFTA_TABLE_NAME, TABLE_ISOLEMENT);
        a.be32(NFTA_TABLE_FLAGS, 0);
    };
    let mut messages: Vec<Box<dyn FnOnce(u32) -> Vec<u8>>> = vec![
        Box::new(move |n| nft(NFT_MSG_NEWTABLE, creer, n, table)),
        Box::new(move |n| {
            nft(NFT_MSG_DELTABLE, super::NLM_F_REQUEST | super::NLM_F_ACK, n, |a| {
                a.texte(NFTA_TABLE_NAME, TABLE_ISOLEMENT);
            })
        }),
        Box::new(move |n| nft(NFT_MSG_NEWTABLE, creer, n, table)),
    ];
    for (chaine, crochet) in CHAINES {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_NEWCHAIN, creer, n, |a| {
                a.texte(NFTA_CHAIN_TABLE, TABLE_ISOLEMENT);
                a.texte(NFTA_CHAIN_NAME, chaine);
                a.be32(NFTA_CHAIN_POLICY, NF_DROP);
                a.texte(NFTA_CHAIN_TYPE, "filter");
                a.imbrique(NFTA_CHAIN_HOOK, |h| {
                    h.be32(NFTA_HOOK_HOOKNUM, crochet);
                    h.be32(NFTA_HOOK_PRIORITY, 0);
                });
            })
        }));
    }
    for (chaine, expressions) in regles(permis) {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_NEWRULE, creer | super::NLM_F_APPEND, n, |a| {
                a.texte(NFTA_RULE_TABLE, TABLE_ISOLEMENT);
                a.texte(NFTA_RULE_CHAIN, chaine);
                a.imbrique(NFTA_RULE_EXPRESSIONS, |x| x.0.extend_from_slice(&expressions.0));
            })
        }));
    }
    lot(premier, messages)
}

/// Le lot qui supprime la table de l'isolement, et elle seule.
pub(crate) fn lot_lever(premier: u32) -> (Vec<u8>, Vec<u32>) {
    lot(
        premier,
        vec![Box::new(move |n| {
            nft(NFT_MSG_DELTABLE, super::NLM_F_REQUEST | super::NLM_F_ACK, n, |a| {
                a.texte(NFTA_TABLE_NAME, TABLE_ISOLEMENT);
            })
        })],
    )
}

fn ouvrir() -> Result<Prise, Echec> {
    Prise::ouvrir(NETLINK_NETFILTER).map_err(|e| refus(e.raw_os_error().map_or(-libc::EIO, i32::saturating_neg)))
}

/// Les règles relues de chaque chaîne de la table de l'isolement.
fn relire(prise: &Prise) -> Result<Vec<(&'static str, usize)>, Echec> {
    let mut lues = Vec::new();
    for (chaine, _) in CHAINES {
        let demande = nft(
            NFT_MSG_GETRULE,
            super::NLM_F_REQUEST | super::NLM_F_DUMP,
            premier_numero(),
            |a| {
                a.texte(NFTA_RULE_TABLE, TABLE_ISOLEMENT);
                a.texte(NFTA_RULE_CHAIN, chaine);
            },
        );
        let octets = match prise.lister(&demande) {
            Ok(o) => o,
            Err(c) if c == -libc::ENOENT => Vec::new(),
            Err(c) => return Err(refus(c)),
        };
        lues.push((chaine, compter(&octets, chaine)));
    }
    Ok(lues)
}

/// Les règles de cette chaîne de la table de l'isolement, dans une réponse de nf_tables.
fn compter(octets: &[u8], chaine: &str) -> usize {
    let mut table = TABLE_ISOLEMENT.as_bytes().to_vec();
    table.push(0);
    recus(octets)
        .filter(|r| r.genre == genre(NFT_MSG_NEWRULE))
        .filter_map(|r| r.corps.get(4..))
        .filter(|corps| {
            attributs(corps).any(|(g, d)| g == NFTA_RULE_TABLE && d == table.as_slice())
                && attributs(corps)
                    .any(|(g, d)| g == NFTA_RULE_CHAIN && d.strip_suffix(b"\0") == Some(chaine.as_bytes()))
        })
        .count()
}

/// Pose l'isolement, puis le relit : chaque chaîne doit avoir toutes ses règles. Relu autrement, la table est
/// supprimée aussitôt (rien de compté comme isolé qui ne le serait qu'à moitié) et c'est dit.
pub(crate) fn isoler(permis: &Permis) -> Result<(), Echec> {
    let prise = ouvrir()?;
    let (octets, attendus) = lot_isoler(premier_numero(), permis);
    prise
        .envoyer_et_attendre(&octets, &attendus)
        .map_err(|(code, _)| refus(code))?;
    match relire(&prise) {
        Ok(lues) if lues == attendues(permis) => Ok(()),
        lu => {
            let (octets, attendus) = lot_lever(premier_numero());
            let _ = prise.envoyer_et_attendre(&octets, &attendus);
            Err(lu.err().unwrap_or_else(|| {
                Echec::echoue(
                    OU,
                    tr!(
                        "les règles de l'isolement relues ne sont pas celles posées : rien n'est compté comme isolé",
                        "the isolation rules read back are not those set: nothing is counted as isolated"
                    ),
                )
            }))
        }
    }
}

/// Supprime la table de l'isolement par son nom. `Ok(false)` : elle n'y était plus (redémarrage sans le service,
/// « nft flush ruleset »).
pub(crate) fn lever() -> Result<bool, Echec> {
    let prise = ouvrir()?;
    let (octets, attendus) = lot_lever(premier_numero());
    match prise.envoyer_et_attendre(&octets, &attendus) {
        Ok(()) => {}
        Err((code, _)) if code == -libc::ENOENT => return Ok(false),
        Err((code, _)) => return Err(refus(code)),
    }
    if presente_par(&prise)? {
        return Err(Echec::echoue(
            OU,
            tr!(
                "la table de l'isolement est toujours là après sa suppression",
                "the isolation table is still there after its removal"
            ),
        ));
    }
    Ok(true)
}

fn presente_par(prise: &Prise) -> Result<bool, Echec> {
    let demande = nft(
        NFT_MSG_GETTABLE,
        super::NLM_F_REQUEST | super::NLM_F_ACK,
        premier_numero(),
        |a| {
            a.texte(NFTA_TABLE_NAME, TABLE_ISOLEMENT);
        },
    );
    prise.envoyer(&demande).map_err(|e| Echec::io(OU, &e))?;
    loop {
        let morceau = prise.recevoir(true).map_err(|e| Echec::io(OU, &e))?;
        for r in recus(&morceau) {
            if r.genre == genre(NFT_MSG_NEWTABLE) {
                return Ok(true);
            }
            match netlink::erreur(&r) {
                Some((0, _)) => return Ok(true),
                Some((c, _)) if c == -libc::ENOENT => return Ok(false),
                Some((c, _)) => return Err(refus(c)),
                None => {}
            }
        }
    }
}

/// La table de l'isolement est-elle en place ? Il faut CAP_NET_ADMIN pour la lire : `Err` sans lui (essais).
#[cfg(test)]
pub(crate) fn presente() -> Result<bool, Echec> {
    presente_par(&ouvrir()?)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn permis() -> Permis {
        Permis {
            garder: vec!["192.0.2.7".parse().unwrap(), "2001:db8::7".parse().unwrap()],
            serveurs: vec!["198.51.100.20".parse().unwrap()],
            dns: vec!["192.0.2.53".parse().unwrap()],
        }
    }

    #[test]
    fn chaque_chaine_a_ses_regles() {
        // Entrée : lo, 3 adresses, 2 DNS, 2 DHCP, 4 voisins, 2 tailles ; sortie : de même sans les tailles.
        assert_eq!(
            attendues(&permis()),
            vec![("entree", 14), ("sortie", 12), ("transit", 0)]
        );
        assert_eq!(
            attendues(&Permis::default()),
            vec![("entree", 9), ("sortie", 7), ("transit", 0)]
        );
    }

    #[test]
    fn le_lot_ne_vise_que_la_table_de_l_isolement() {
        let (octets, numeros) = lot_isoler(10, &permis());
        // Début, 3 messages de table, 3 chaînes, 26 règles, fin : tous avec accusé sauf début et fin.
        assert_eq!(numeros.len(), 3 + 3 + 26);
        let messages: Vec<_> = recus(&octets).collect();
        assert_eq!(messages.len(), numeros.len() + 2);
        for m in &messages[1..messages.len() - 1] {
            let corps = m.corps.get(4..).unwrap();
            let noms: Vec<&[u8]> = attributs(corps).filter(|(g, _)| *g == 1).map(|(_, d)| d).collect();
            assert_eq!(noms, vec![b"vanguard_isolement\0".as_slice()], "{:?}", m.genre);
        }
        // Le deuxième message supprime la table : le lot remplace, il n'ajoute jamais en double.
        assert_eq!(messages[2].genre, genre(NFT_MSG_DELTABLE));
        let (octets, numeros) = lot_lever(5);
        assert_eq!(numeros, vec![6]);
        let messages: Vec<_> = recus(&octets).collect();
        assert_eq!(messages[1].genre, genre(NFT_MSG_DELTABLE));
    }

    #[test]
    fn les_noms_d_interface_sont_bourres() {
        assert_eq!(&nom_d_interface(b"lo")[..3], b"lo\0");
        assert_eq!(nom_d_interface(b"lo").len(), 16);
    }

    /// L'essai pour de vrai, dans un espace de noms réseau et utilisateur à part : une carte factice, une table d'un
    /// autre outil ; isolé, l'envoi vers une adresse quelconque est refusé, vers une adresse gardée il part ; levé, la
    /// liste des règles est celle d'avant, à l'octet près. Lancé par `isolement_dans_un_espace_a_part`, jamais seul.
    #[test]
    #[ignore = "lancé dans un espace de noms à part par isolement_dans_un_espace_a_part"]
    fn isolement_dedans_l_espace_a_part() {
        use std::net::UdpSocket;
        use std::process::Command;
        let ip = |args: &[&str]| assert!(Command::new("ip").args(args).status().is_ok_and(|s| s.success()));
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "add", "f0", "type", "dummy"]);
        ip(&["addr", "add", "192.0.2.1/24", "dev", "f0"]);
        ip(&["link", "set", "f0", "up"]);
        let nft = ["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"]
            .into_iter()
            .find(|c| std::path::Path::new(c).exists());
        let liste = || {
            nft.map(|n| {
                String::from_utf8_lossy(&Command::new(n).args(["list", "ruleset"]).output().unwrap().stdout)
                    .into_owned()
            })
        };
        if let Some(n) = nft {
            assert!(
                Command::new(n)
                    .args(["add", "table", "inet", "autre"])
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new(n)
                    .args([
                        "add",
                        "chain",
                        "inet",
                        "autre",
                        "s",
                        "{ type filter hook output priority 0; policy accept; }"
                    ])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let avant = liste();
        let envoyer = |vers: &str| {
            let s = UdpSocket::bind("0.0.0.0:0").unwrap();
            s.send_to(b"x", (vers.parse::<IpAddr>().unwrap(), 9)).is_ok()
        };
        assert!(envoyer("192.0.2.9"), "avant l'isolement, le paquet part");
        assert!(!presente().unwrap());
        let p = Permis {
            garder: vec!["192.0.2.7".parse().unwrap()],
            serveurs: Vec::new(),
            dns: vec!["192.0.2.53".parse().unwrap()],
        };
        isoler(&p).unwrap();
        // Deux fois : remplacée, jamais doublée.
        isoler(&p).unwrap();
        assert!(presente().unwrap());
        assert!(
            !envoyer("192.0.2.9"),
            "isolé : l'envoi vers une autre adresse est refusé"
        );
        assert!(envoyer("192.0.2.7"), "isolé : la session gardée passe");
        assert!(envoyer("127.0.0.1"), "isolé : la boucle locale passe");
        if let Some(texte) = liste() {
            for attendu in [
                "table inet autre",
                "table inet vanguard_isolement",
                "type filter hook input priority filter; policy drop;",
                "type filter hook output priority filter; policy drop;",
                "type filter hook forward priority filter; policy drop;",
                "ip daddr 192.0.2.7 accept",
                "ip saddr 192.0.2.7 accept",
                "udp dport 53 accept",
            ] {
                assert!(texte.contains(attendu), "« {attendu} » manque :\n{texte}");
            }
        }
        assert!(lever().unwrap());
        assert!(!lever().unwrap(), "déjà levé : rien à retirer, sans erreur");
        assert!(envoyer("192.0.2.9"), "levé : le paquet repart");
        assert_eq!(liste(), avant, "levé : les règles sont celles d'avant");
    }

    #[test]
    fn isolement_dans_un_espace_a_part() {
        let Ok(moi) = std::env::current_exe() else {
            return crate::essais::saute("programme de test introuvable");
        };
        let essai = std::process::Command::new("unshare").args(["-rn", "true"]).status();
        if !essai.is_ok_and(|s| s.success()) {
            return crate::essais::saute("pas d'espace de noms utilisateur ici (unshare -rn)");
        }
        let factice = std::process::Command::new("unshare")
            .args(["-rn", "ip", "link", "add", "f0", "type", "dummy"])
            .status();
        if !factice.is_ok_and(|s| s.success()) {
            return crate::essais::saute("pas de carte factice dans un espace de noms ici (ip, module dummy)");
        }
        let sortie = std::process::Command::new("unshare")
            .arg("-rn")
            .arg(moi)
            .args([
                "--ignored",
                "--exact",
                "machine::linux::nftables::isolement::tests::isolement_dedans_l_espace_a_part",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout);
        assert!(
            sortie.status.success() && texte.contains("1 passed"),
            "{texte}\n{}",
            String::from_utf8_lossy(&sortie.stderr)
        );
    }
}
