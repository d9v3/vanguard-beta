//! La table de Vanguard dans nf_tables (`inet vanguard`), posée et retirée par netlink, sans nft, sans shell et sans
//! bibliothèque (libnftnl est en C sous GPL-2.0, rustables sous GPL-3.0 : refusés pour garder la double licence).
//! La même table que celle que posaient les versions d'avant par « nft -f » : mêmes ensembles, mêmes chaînes, mêmes
//! règles, si bien qu'un blocage noté par elles se retire ici.
//!
//! ```text
//! table inet vanguard {
//!     set sortie4 { type ipv4_addr; }   set sortie6 { type ipv6_addr; }   set ports { type inet_service; }
//!     chain sortie { type filter hook output priority 0; policy accept;
//!         ip daddr @sortie4 drop ; ip6 daddr @sortie6 drop }
//!     chain entree { type filter hook input priority 0; policy accept;
//!         iifname != "lo" tcp dport @ports drop }
//! }
//! ```
//!
//! La coupure du réseau d'un programme (Défense R3) ajoute, au premier usage seulement, un ensemble de cgroups et deux
//! chaînes à elle : le processus coupé est mis par systemd dans un scope à lui sous `vanguard.slice`, et toute prise
//! née dans ce scope est jetée, en sortie comme en entrée.
//!
//! ```text
//!     set coupes { type cgroupsv2; }
//!     chain coupe-sortie { type filter hook output priority 0; policy accept;
//!         socket cgroupv2 level 2 @coupes drop }
//!     chain coupe-entree { type filter hook input priority 0; policy accept;
//!         socket cgroupv2 level 2 @coupes drop }
//! ```
//!
//! Chaînes à part : le blocage d'adresses et de ports garde ses chaînes et ses règles tels quels (un noyau d'avant
//! 5.13, qui ne connaît pas « socket cgroupv2 », ne le casse pas), et un cgroup qui n'existe plus ne correspond à
//! rien (son numéro n'est pas repris avant le redémarrage).
//!
//! Le protocole : NETLINK_NETFILTER, sous-système NFTABLES (linux/netfilter/nfnetlink.h, nf_tables.h). Les
//! changements partent en un lot (NFNL_MSG_BATCH_BEGIN … END) que le noyau applique tout entier ou pas du tout ; chaque
//! message demande son accusé. Les messages reprennent octet par octet ce que nft 1.1 envoie pour la même table
//! (`nft --debug=mnl`), ce que vérifient les tests ; un essai dans un espace de noms réseau à part (`unshare -rn`)
//! pose la table pour de vrai, la relit avec nft et vérifie qu'un paquet vers une adresse bloquée est refusé.
//! Seule la table « vanguard » de la famille inet est visée : chaque message la nomme, et le vidage d'une chaîne
//! nomme la chaîne.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::net::IpAddr;

use crate::modele::Echec;
use crate::{tr, trf};

/// Le contexte des échecs de ce module.
const OU: &str = "blocage/nf_tables";

use super::netlink::{
    self, Attributs, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REQUEST, Prise, attributs, recus,
};

pub(crate) const TABLE: &str = "vanguard";

/// L'isolement de l'ordinateur (Défense R4) : sa table à lui, posée avec les aides de ce module.
pub(crate) mod isolement;

const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

// enum nf_tables_msg_types.
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DELRULE: u16 = 8;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_GETSETELEM: u16 = 13;
const NFT_MSG_DELSETELEM: u16 = 14;

const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
/// NF_INET_LOCAL_IN et NF_INET_LOCAL_OUT (linux/netfilter.h).
const CROCHET_ENTREE: u32 = 1;
const CROCHET_SORTIE: u32 = 3;
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

// Attributs (enum nft_*_attributes).
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_LOOKUP_SET: u16 = 1;
const NFTA_LOOKUP_SREG: u16 = 2;
const NFTA_LOOKUP_SET_ID: u16 = 4;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_USERDATA: u16 = 13;
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_SET_ELEM_LIST_SET_ID: u16 = 4;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SOCKET_KEY: u16 = 1;
const NFTA_SOCKET_DREG: u16 = 2;
const NFTA_SOCKET_LEVEL: u16 = 3;
const NFT_SOCKET_CGROUPV2: u32 = 3;

const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

/// Les données d'utilisateur que nft attache à ces ensembles (ordre des octets de la clé : réseau), gardées pour que
/// « nft list » les montre comme les siens.
const DONNEES_D_ENSEMBLE: [u8; 16] = [0, 4, 2, 0, 0, 0, 3, 8, 0, 4, 4, 0, 0, 0, 1, 0];
/// Celles de l'ensemble des cgroups : le même, l'ordre des octets étant celui de la machine (1).
const DONNEES_DES_COUPES: [u8; 16] = [0, 4, 1, 0, 0, 0, 3, 8, 0, 4, 4, 0, 0, 0, 1, 0];

/// Les chaînes de la coupure, et leur crochet.
const CHAINES_DE_COUPE: [(&str, u32); 2] = [("coupe-sortie", CROCHET_SORTIE), ("coupe-entree", CROCHET_ENTREE)];

/// Le niveau des scopes de coupure sous la racine des cgroups : `vanguard.slice` (1), puis `coupe-….scope` (2).
pub(crate) const NIVEAU_DES_COUPES: u32 = 2;

/// Les ensembles de la table : les trois du blocage, et celui de la coupure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ensemble {
    Sortie4,
    Sortie6,
    Ports,
    Coupes,
}

impl Ensemble {
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Ensemble::Sortie4 => "sortie4",
            Ensemble::Sortie6 => "sortie6",
            Ensemble::Ports => "ports",
            Ensemble::Coupes => "coupes",
        }
    }
    /// Le type de nft (ipv4_addr = 7, ipv6_addr = 8, inet_service = 13, cgroupsv2 = 46) et la longueur de la clé.
    fn cle(self) -> (u32, u32) {
        match self {
            Ensemble::Sortie4 => (7, 4),
            Ensemble::Sortie6 => (8, 16),
            Ensemble::Ports => (13, 2),
            Ensemble::Coupes => (46, 8),
        }
    }
    fn donnees(self) -> [u8; 16] {
        match self {
            Ensemble::Coupes => DONNEES_DES_COUPES,
            _ => DONNEES_D_ENSEMBLE,
        }
    }
    /// Son numéro dans le lot : une règle du même lot s'y réfère par lui (NFTA_LOOKUP_SET_ID).
    fn id(self) -> u32 {
        match self {
            Ensemble::Sortie4 => 1,
            Ensemble::Sortie6 => 2,
            Ensemble::Ports => 3,
            Ensemble::Coupes => 4,
        }
    }
}

/// Ce qui entre dans un ensemble : une adresse bloquée en sortie, un port TCP fermé en entrée, ou le numéro du cgroup
/// (celui de son dossier dans /sys/fs/cgroup) d'un scope de coupure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Element {
    Adresse(IpAddr),
    Port(u16),
    Cgroupe(u64),
}

impl Element {
    pub(crate) fn ensemble(self) -> Ensemble {
        match self {
            Element::Adresse(ip) if ip.to_canonical().is_ipv4() => Ensemble::Sortie4,
            Element::Adresse(_) => Ensemble::Sortie6,
            Element::Port(_) => Ensemble::Ports,
            Element::Cgroupe(_) => Ensemble::Coupes,
        }
    }
    /// La clé telle que le noyau la compare : l'adresse ou le port dans l'ordre du réseau, le numéro du cgroup dans
    /// celui de la machine (le noyau le compare à `cgroup_id()`, un u64 en mémoire).
    fn octets(self) -> Vec<u8> {
        match self {
            Element::Adresse(ip) => match ip.to_canonical() {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            },
            Element::Port(p) => p.to_be_bytes().to_vec(),
            Element::Cgroupe(id) => id.to_ne_bytes().to_vec(),
        }
    }
}

/// Le type netlink d'un message de nf_tables.
fn genre(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

/// L'en-tête de nfnetlink (nfgenmsg) : famille, version 0, puis res_id dans l'ordre du réseau.
fn nfgen(famille: u8, res_id: u16) -> Attributs {
    let mut a = Attributs(vec![famille, 0]);
    a.0.extend_from_slice(&res_id.to_be_bytes());
    a
}

/// Un message de nf_tables sur la famille inet, ses attributs écrits par `f`.
fn nft(msg: u16, drapeaux: u16, sequence: u32, f: impl FnOnce(&mut Attributs)) -> Vec<u8> {
    let mut a = nfgen(NFPROTO_INET, 0);
    f(&mut a);
    netlink::message(genre(msg), drapeaux, sequence, &a.0)
}

/// Une expression d'une règle : son nom, puis ses données.
fn expression(a: &mut Attributs, nom: &str, donnees: impl FnOnce(&mut Attributs)) {
    a.imbrique(NFTA_LIST_ELEM, |e| {
        e.texte(NFTA_EXPR_NAME, nom);
        e.imbrique(NFTA_EXPR_DATA, donnees);
    });
}

fn meta(a: &mut Attributs, cle: u32) {
    expression(a, "meta", |d| {
        d.be32(NFTA_META_KEY, cle);
        d.be32(NFTA_META_DREG, NFT_REG_1);
    });
}

fn cmp(a: &mut Attributs, op: u32, valeur: &[u8]) {
    expression(a, "cmp", |d| {
        d.be32(NFTA_CMP_SREG, NFT_REG_1);
        d.be32(NFTA_CMP_OP, op);
        d.imbrique(NFTA_CMP_DATA, |v| v.brut(NFTA_DATA_VALUE, valeur));
    });
}

fn payload(a: &mut Attributs, base: u32, decalage: u32, longueur: u32) {
    expression(a, "payload", |d| {
        d.be32(NFTA_PAYLOAD_DREG, NFT_REG_1);
        d.be32(NFTA_PAYLOAD_BASE, base);
        d.be32(NFTA_PAYLOAD_OFFSET, decalage);
        d.be32(NFTA_PAYLOAD_LEN, longueur);
    });
}

fn lookup(a: &mut Attributs, e: Ensemble) {
    expression(a, "lookup", |d| {
        d.be32(NFTA_LOOKUP_SREG, NFT_REG_1);
        d.texte(NFTA_LOOKUP_SET, e.nom());
        d.be32(NFTA_LOOKUP_SET_ID, e.id());
    });
}

fn jeter(a: &mut Attributs) {
    expression(a, "immediate", |d| {
        d.be32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        d.imbrique(NFTA_IMMEDIATE_DATA, |v| {
            v.imbrique(NFTA_DATA_VERDICT, |c| c.be32(NFTA_VERDICT_CODE, NF_DROP));
        });
    });
}

/// « socket cgroupv2 level N » : le numéro du cgroup, ancêtre au niveau N de celui où la prise est née, dans le
/// registre 1. Une prise sans cgroup connu (paquet sans prise locale) ne correspond pas : la règle ne jette rien.
fn socket_cgroupe(a: &mut Attributs, niveau: u32) {
    expression(a, "socket", |d| {
        d.be32(NFTA_SOCKET_KEY, NFT_SOCKET_CGROUPV2);
        d.be32(NFTA_SOCKET_DREG, NFT_REG_1);
        d.be32(NFTA_SOCKET_LEVEL, niveau);
    });
}

/// La règle d'une chaîne de coupure : « socket cgroupv2 level N @coupes drop ».
fn regle_de_coupe(niveau: u32) -> Attributs {
    let mut r = Attributs::default();
    socket_cgroupe(&mut r, niveau);
    lookup(&mut r, Ensemble::Coupes);
    jeter(&mut r);
    r
}

/// Les trois règles : (chaîne, expressions).
fn regles() -> [(&'static str, Attributs); 3] {
    let mut v4 = Attributs::default();
    meta(&mut v4, NFT_META_NFPROTO);
    cmp(&mut v4, NFT_CMP_EQ, &[NFPROTO_IPV4]);
    // L'adresse de destination : 4 octets à 16 octets du début de l'en-tête IPv4.
    payload(&mut v4, NFT_PAYLOAD_NETWORK_HEADER, 16, 4);
    lookup(&mut v4, Ensemble::Sortie4);
    jeter(&mut v4);
    let mut v6 = Attributs::default();
    meta(&mut v6, NFT_META_NFPROTO);
    cmp(&mut v6, NFT_CMP_EQ, &[NFPROTO_IPV6]);
    // 16 octets à 24 octets du début de l'en-tête IPv6.
    payload(&mut v6, NFT_PAYLOAD_NETWORK_HEADER, 24, 16);
    lookup(&mut v6, Ensemble::Sortie6);
    jeter(&mut v6);
    let mut ports = Attributs::default();
    meta(&mut ports, NFT_META_IIFNAME);
    // Un nom d'interface se compare sur IFNAMSIZ (16) octets, bourré de zéros.
    let mut lo = [0u8; 16];
    lo[..2].copy_from_slice(b"lo");
    cmp(&mut ports, NFT_CMP_NEQ, &lo);
    meta(&mut ports, NFT_META_L4PROTO);
    cmp(&mut ports, NFT_CMP_EQ, &[6]);
    // Le port de destination : 2 octets à 2 octets du début de l'en-tête TCP.
    payload(&mut ports, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2);
    lookup(&mut ports, Ensemble::Ports);
    jeter(&mut ports);
    [("sortie", v4), ("sortie", v6), ("entree", ports)]
}

fn element_liste(a: &mut Attributs, element: Element) {
    let e = element.ensemble();
    a.texte(NFTA_SET_ELEM_LIST_TABLE, TABLE);
    a.texte(NFTA_SET_ELEM_LIST_SET, e.nom());
    a.be32(NFTA_SET_ELEM_LIST_SET_ID, e.id());
    a.imbrique(NFTA_SET_ELEM_LIST_ELEMENTS, |l| {
        l.imbrique(NFTA_LIST_ELEM, |el| {
            el.imbrique(NFTA_SET_ELEM_KEY, |k| k.brut(NFTA_DATA_VALUE, &element.octets()));
        });
    });
}

/// Un lot : le début, les messages (numérotés à partir de `premier`), la fin. Rend les octets et les numéros des
/// messages qui demandent un accusé.
fn lot(premier: u32, messages: Vec<Box<dyn FnOnce(u32) -> Vec<u8>>>) -> (Vec<u8>, Vec<u32>) {
    let res_id = NFNL_SUBSYS_NFTABLES;
    let mut octets = netlink::message(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        premier,
        &nfgen(NFPROTO_UNSPEC, res_id).0,
    );
    let mut numeros = Vec::new();
    let mut n = premier;
    for m in messages {
        // Numéros de séquence netlink : ils font le tour, c'est leur sens.
        n = n.wrapping_add(1);
        octets.extend(m(n));
        numeros.push(n);
    }
    octets.extend(netlink::message(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        n.wrapping_add(1),
        &nfgen(NFPROTO_UNSPEC, res_id).0,
    ));
    (octets, numeros)
}

/// Le lot qui pose la table (ensembles, chaînes, règles vidées puis remises : jamais une règle en double), puis
/// l'élément. Tout ou rien.
pub(crate) fn lot_poser(premier: u32, element: Element) -> (Vec<u8>, Vec<u32>) {
    let creer = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    let mut messages: Vec<Box<dyn FnOnce(u32) -> Vec<u8>>> = vec![Box::new(move |n| {
        nft(NFT_MSG_NEWTABLE, creer, n, |a| {
            a.texte(NFTA_TABLE_NAME, TABLE);
            a.be32(NFTA_TABLE_FLAGS, 0);
        })
    })];
    for e in [Ensemble::Sortie4, Ensemble::Sortie6, Ensemble::Ports] {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_NEWSET, creer, n, |a| {
                let (genre_cle, longueur) = e.cle();
                a.texte(NFTA_SET_TABLE, TABLE);
                a.texte(NFTA_SET_NAME, e.nom());
                a.be32(NFTA_SET_FLAGS, 0);
                a.be32(NFTA_SET_KEY_TYPE, genre_cle);
                a.be32(NFTA_SET_KEY_LEN, longueur);
                a.be32(NFTA_SET_ID, e.id());
                a.brut(NFTA_SET_USERDATA, &e.donnees());
            })
        }));
    }
    for (chaine, crochet) in [("sortie", CROCHET_SORTIE), ("entree", CROCHET_ENTREE)] {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_NEWCHAIN, creer, n, |a| {
                a.texte(NFTA_CHAIN_TABLE, TABLE);
                a.texte(NFTA_CHAIN_NAME, chaine);
                a.be32(NFTA_CHAIN_POLICY, NF_ACCEPT);
                a.texte(NFTA_CHAIN_TYPE, "filter");
                a.imbrique(NFTA_CHAIN_HOOK, |h| {
                    h.be32(NFTA_HOOK_HOOKNUM, crochet);
                    h.be32(NFTA_HOOK_PRIORITY, 0);
                });
            })
        }));
    }
    // « flush chain » : sans numéro de règle, le noyau retire toutes celles de la chaîne nommée, et d'elle seule.
    for chaine in ["sortie", "entree"] {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_DELRULE, NLM_F_REQUEST | NLM_F_ACK, n, |a| {
                a.texte(NFTA_RULE_TABLE, TABLE);
                a.texte(NFTA_RULE_CHAIN, chaine);
            })
        }));
    }
    for (chaine, expressions) in regles() {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_NEWRULE, creer | NLM_F_APPEND, n, |a| {
                a.texte(NFTA_RULE_TABLE, TABLE);
                a.texte(NFTA_RULE_CHAIN, chaine);
                a.imbrique(NFTA_RULE_EXPRESSIONS, |x| x.0.extend_from_slice(&expressions.0));
            })
        }));
    }
    messages.push(Box::new(move |n| {
        nft(NFT_MSG_NEWSETELEM, creer, n, |a| element_liste(a, element))
    }));
    lot(premier, messages)
}

/// Le lot qui retire un élément, et lui seul.
pub(crate) fn lot_retirer(premier: u32, element: Element) -> (Vec<u8>, Vec<u32>) {
    lot(
        premier,
        vec![Box::new(move |n| {
            nft(NFT_MSG_DELSETELEM, NLM_F_REQUEST | NLM_F_ACK, n, |a| {
                element_liste(a, element);
            })
        })],
    )
}

/// Le lot qui pose la coupure (la table, l'ensemble des cgroups, ses deux chaînes vidées puis remises) et ce cgroup.
/// Il ne touche ni aux ensembles ni aux chaînes du blocage. `niveau` : celui du scope sous la racine des cgroups
/// (`NIVEAU_DES_COUPES`, autre seulement dans l'essai, où le scope est plus bas).
pub(crate) fn lot_couper(premier: u32, cgroupe: u64, niveau: u32) -> (Vec<u8>, Vec<u32>) {
    let creer = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    let e = Ensemble::Coupes;
    let mut messages: Vec<Box<dyn FnOnce(u32) -> Vec<u8>>> = vec![
        Box::new(move |n| {
            nft(NFT_MSG_NEWTABLE, creer, n, |a| {
                a.texte(NFTA_TABLE_NAME, TABLE);
                a.be32(NFTA_TABLE_FLAGS, 0);
            })
        }),
        Box::new(move |n| {
            nft(NFT_MSG_NEWSET, creer, n, |a| {
                let (genre_cle, longueur) = e.cle();
                a.texte(NFTA_SET_TABLE, TABLE);
                a.texte(NFTA_SET_NAME, e.nom());
                a.be32(NFTA_SET_FLAGS, 0);
                a.be32(NFTA_SET_KEY_TYPE, genre_cle);
                a.be32(NFTA_SET_KEY_LEN, longueur);
                a.be32(NFTA_SET_ID, e.id());
                a.brut(NFTA_SET_USERDATA, &e.donnees());
            })
        }),
    ];
    for (chaine, crochet) in CHAINES_DE_COUPE {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_NEWCHAIN, creer, n, |a| {
                a.texte(NFTA_CHAIN_TABLE, TABLE);
                a.texte(NFTA_CHAIN_NAME, chaine);
                a.be32(NFTA_CHAIN_POLICY, NF_ACCEPT);
                a.texte(NFTA_CHAIN_TYPE, "filter");
                a.imbrique(NFTA_CHAIN_HOOK, |h| {
                    h.be32(NFTA_HOOK_HOOKNUM, crochet);
                    h.be32(NFTA_HOOK_PRIORITY, 0);
                });
            })
        }));
    }
    for (chaine, _) in CHAINES_DE_COUPE {
        messages.push(Box::new(move |n| {
            nft(NFT_MSG_DELRULE, NLM_F_REQUEST | NLM_F_ACK, n, |a| {
                a.texte(NFTA_RULE_TABLE, TABLE);
                a.texte(NFTA_RULE_CHAIN, chaine);
            })
        }));
    }
    for (chaine, _) in CHAINES_DE_COUPE {
        messages.push(Box::new(move |n| {
            let expressions = regle_de_coupe(niveau);
            nft(NFT_MSG_NEWRULE, creer | NLM_F_APPEND, n, |a| {
                a.texte(NFTA_RULE_TABLE, TABLE);
                a.texte(NFTA_RULE_CHAIN, chaine);
                a.imbrique(NFTA_RULE_EXPRESSIONS, |x| x.0.extend_from_slice(&expressions.0));
            })
        }));
    }
    messages.push(Box::new(move |n| {
        nft(NFT_MSG_NEWSETELEM, creer, n, |a| {
            element_liste(a, Element::Cgroupe(cgroupe));
        })
    }));
    lot(premier, messages)
}

/// Les numéros de messages : partis de l'heure, pour ne pas reprendre ceux d'une prise précédente.
fn premier_numero() -> u32 {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| d.subsec_nanos() | 1);
    s & 0x0fff_ffff
}

/// Pourquoi le noyau a refusé, en clair.
fn refus(code: i32) -> Echec {
    Echec::echoue(OU, refus_texte(code))
}

fn refus_texte(code: i32) -> String {
    match code.saturating_neg() {
        libc::EPERM => tr!(
            "nf_tables refuse : droits d'administrateur manquants (CAP_NET_ADMIN)",
            "nf_tables refuses: administrator rights missing (CAP_NET_ADMIN)"
        )
        .to_string(),
        libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT => {
            tr!("nf_tables absent de ce noyau", "nf_tables missing from this kernel").to_string()
        }
        _ => trf!(
            "nf_tables refuse : {}",
            "nf_tables refuses: {}",
            netlink::texte_errno(code)
        ),
    }
}

/// Pose la table de Vanguard et cet élément, puis relit la table : l'élément doit y être, et les trois règles à
/// leur place. `Err` : pourquoi rien n'est bloqué (le lot n'est jamais appliqué à moitié).
pub(crate) fn poser(element: Element) -> Result<(), Echec> {
    let prise = Prise::ouvrir(NETLINK_NETFILTER)
        .map_err(|e| refus(e.raw_os_error().map_or(-libc::EIO, i32::saturating_neg)))?;
    let (octets, attendus) = lot_poser(premier_numero(), element);
    prise
        .envoyer_et_attendre(&octets, &attendus)
        .map_err(|(code, _)| refus(code))?;
    let probleme = match relire(&prise) {
        Err(e) => Some(e.to_string()),
        Ok(relue) if !relue.elements.contains(&element) => Some(
            tr!(
                "la table relue ne contient pas l'élément posé : rien n'est compté comme bloqué",
                "the table read back does not hold the element added: nothing is counted as blocked"
            )
            .to_string(),
        ),
        Ok(relue) if relue.regles != [("sortie".to_string(), 2), ("entree".to_string(), 1)] => Some(
            tr!(
                "les règles de la table relue ne sont pas celles de Vanguard : rien n'est compté comme bloqué",
                "the rules of the table read back are not Vanguard's: nothing is counted as blocked"
            )
            .to_string(),
        ),
        Ok(_) => None,
    };
    let Some(probleme) = probleme else {
        return Ok(());
    };
    // Compté en échec, donc sans note pour l'annuler : l'élément posé est retiré aussitôt, pour ne pas laisser un
    // blocage que rien ne défait.
    let (octets, attendus) = lot_retirer(premier_numero(), element);
    let _ = prise.envoyer_et_attendre(&octets, &attendus);
    Err(Echec::echoue(OU, probleme))
}

/// Ce que donne le retrait d'un élément.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Retrait {
    Retire,
    /// Plus de table (l'ordinateur a redémarré) : il n'y a rien à retirer.
    SansTable,
    /// La table est là, sans cet élément : déjà retiré.
    DejaAbsent,
}

/// Retire cet élément de la table de Vanguard, et rien d'autre.
pub(crate) fn retirer(element: Element) -> Result<Retrait, Echec> {
    let prise = Prise::ouvrir(NETLINK_NETFILTER)
        .map_err(|e| refus(e.raw_os_error().map_or(-libc::EIO, i32::saturating_neg)))?;
    let (octets, attendus) = lot_retirer(premier_numero(), element);
    match prise.envoyer_et_attendre(&octets, &attendus) {
        Ok(()) => {}
        Err((code, _)) if code == -libc::ENOENT => {
            return Ok(if table_existe(&prise)? {
                Retrait::DejaAbsent
            } else {
                Retrait::SansTable
            });
        }
        Err((code, _)) => return Err(refus(code)),
    }
    // Relu : l'élément ne doit plus y être.
    if relire(&prise)?.elements.contains(&element) {
        return Err(Echec::echoue(
            OU,
            tr!(
                "l'élément est toujours dans la table relue",
                "the element is still in the table read back"
            ),
        ));
    }
    Ok(Retrait::Retire)
}

fn table_existe(prise: &Prise) -> Result<bool, Echec> {
    let n = premier_numero();
    let demande = nft(NFT_MSG_GETTABLE, NLM_F_REQUEST | NLM_F_ACK, n, |a| {
        a.texte(NFTA_TABLE_NAME, TABLE);
    });
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

/// La table relue : les éléments de ses ensembles, et le nombre de règles de chaque chaîne (celles de la coupure à
/// part : elles n'existent qu'après une première coupure).
#[derive(Debug, Default)]
pub(crate) struct Relue {
    pub elements: Vec<Element>,
    pub regles: Vec<(String, usize)>,
    pub regles_de_coupe: Vec<(String, usize)>,
}

/// Relit la table. Un ensemble ou une chaîne absents (ENOENT) sont lus vides : le blocage et la coupure posent chacun
/// les leurs, si bien que l'un peut exister sans l'autre ; ce qui doit y être est vérifié par l'appelant.
fn relire(prise: &Prise) -> Result<Relue, Echec> {
    let lister = |demande: &[u8]| match prise.lister(demande) {
        Ok(reponse) => Ok(reponse),
        Err(c) if c == -libc::ENOENT => Ok(Vec::new()),
        Err(c) => Err(refus(c)),
    };
    let mut relue = Relue::default();
    for e in [Ensemble::Sortie4, Ensemble::Sortie6, Ensemble::Ports, Ensemble::Coupes] {
        let demande = nft(NFT_MSG_GETSETELEM, NLM_F_REQUEST | NLM_F_DUMP, premier_numero(), |a| {
            a.texte(NFTA_SET_ELEM_LIST_TABLE, TABLE);
            a.texte(NFTA_SET_ELEM_LIST_SET, e.nom());
        });
        relue.elements.extend(lire_elements(&lister(&demande)?, e));
    }
    let chaines = ["sortie", "entree"]
        .into_iter()
        .map(|c| (c, false))
        .chain(CHAINES_DE_COUPE.iter().map(|(c, _)| (*c, true)));
    for (chaine, de_coupe) in chaines {
        let demande = nft(NFT_MSG_GETRULE, NLM_F_REQUEST | NLM_F_DUMP, premier_numero(), |a| {
            a.texte(NFTA_RULE_TABLE, TABLE);
            a.texte(NFTA_RULE_CHAIN, chaine);
        });
        let n = compter_regles(&lister(&demande)?, chaine);
        if de_coupe {
            relue.regles_de_coupe.push((chaine.to_string(), n));
        } else {
            relue.regles.push((chaine.to_string(), n));
        }
    }
    Ok(relue)
}

/// Pourquoi la coupure est refusée : un noyau qui ne connaît pas l'expression (avant 5.13, ou sans nft_socket) le dit
/// par ENOENT ou EOPNOTSUPP, puisque la table, l'ensemble et les chaînes sont créés dans le même lot.
fn refus_de_coupe(code: i32) -> Echec {
    match code.saturating_neg() {
        libc::ENOENT | libc::EOPNOTSUPP => Echec::echoue(
            OU,
            trf!(
                "ce noyau ne filtre pas par cgroup (« socket cgroupv2 » : Linux 5.13 ou plus, module nft_socket) : {}",
                "this kernel cannot filter by cgroup (\"socket cgroupv2\": Linux 5.13 or later, nft_socket module): {}",
                netlink::texte_errno(code)
            ),
        ),
        _ => refus(code),
    }
}

/// Coupe le réseau des prises nées dans ce cgroup (le scope du processus coupé), puis relit : le cgroup doit être
/// dans l'ensemble et chaque chaîne de coupure avoir sa règle. `Err` : rien n'est coupé (le cgroup est retiré si la
/// relecture échoue).
pub(crate) fn couper_cgroupe(cgroupe: u64, niveau: u32) -> Result<(), Echec> {
    let prise = Prise::ouvrir(NETLINK_NETFILTER)
        .map_err(|e| refus(e.raw_os_error().map_or(-libc::EIO, i32::saturating_neg)))?;
    let (octets, attendus) = lot_couper(premier_numero(), cgroupe, niveau);
    prise
        .envoyer_et_attendre(&octets, &attendus)
        .map_err(|(code, _)| refus_de_coupe(code))?;
    let element = Element::Cgroupe(cgroupe);
    let regles_voulues: Vec<(String, usize)> = CHAINES_DE_COUPE.iter().map(|(c, _)| ((*c).to_string(), 1)).collect();
    let probleme = match relire(&prise) {
        Err(e) => Some(e.to_string()),
        Ok(relue) if !relue.elements.contains(&element) => Some(
            tr!(
                "la table relue ne contient pas le cgroup coupé : rien n'est compté comme coupé",
                "the table read back does not hold the cut cgroup: nothing is counted as cut"
            )
            .to_string(),
        ),
        Ok(relue) if relue.regles_de_coupe != regles_voulues => Some(
            tr!(
                "les règles de coupure relues ne sont pas celles de Vanguard : rien n'est compté comme coupé",
                "the cut rules read back are not Vanguard's: nothing is counted as cut"
            )
            .to_string(),
        ),
        Ok(_) => None,
    };
    let Some(probleme) = probleme else {
        return Ok(());
    };
    let (octets, attendus) = lot_retirer(premier_numero(), element);
    let _ = prise.envoyer_et_attendre(&octets, &attendus);
    Err(Echec::echoue(OU, probleme))
}

/// Les cgroups de l'ensemble des coupures (vide sans table ou sans ensemble).
pub(crate) fn cgroupes_coupes() -> Result<Vec<u64>, Echec> {
    let prise = Prise::ouvrir(NETLINK_NETFILTER)
        .map_err(|e| refus(e.raw_os_error().map_or(-libc::EIO, i32::saturating_neg)))?;
    let demande = nft(NFT_MSG_GETSETELEM, NLM_F_REQUEST | NLM_F_DUMP, premier_numero(), |a| {
        a.texte(NFTA_SET_ELEM_LIST_TABLE, TABLE);
        a.texte(NFTA_SET_ELEM_LIST_SET, Ensemble::Coupes.nom());
    });
    let reponse = match prise.lister(&demande) {
        Ok(r) => r,
        Err(c) if c == -libc::ENOENT => return Ok(Vec::new()),
        Err(c) => return Err(refus(c)),
    };
    Ok(lire_elements(&reponse, Ensemble::Coupes)
        .into_iter()
        .filter_map(|e| match e {
            Element::Cgroupe(id) => Some(id),
            _ => None,
        })
        .collect())
}

/// Les éléments des messages NEWSETELEM d'une liste (après nfgenmsg : TABLE, SET, ELEMENTS { ELEM { KEY { VALUE } } }).
pub(crate) fn lire_elements(octets: &[u8], e: Ensemble) -> Vec<Element> {
    let mut trouves = Vec::new();
    for r in recus(octets).filter(|r| r.genre == genre(NFT_MSG_NEWSETELEM)) {
        let Some(corps) = r.corps.get(4..) else { continue };
        let meme_table = attributs(corps).any(|(g, d)| g == NFTA_SET_ELEM_LIST_TABLE && d == b"vanguard\0");
        let meme_ensemble = attributs(corps)
            .any(|(g, d)| g == NFTA_SET_ELEM_LIST_SET && d.strip_suffix(b"\0") == Some(e.nom().as_bytes()));
        if !meme_table || !meme_ensemble {
            continue;
        }
        for (_, liste) in attributs(corps).filter(|(g, _)| *g == NFTA_SET_ELEM_LIST_ELEMENTS) {
            for (_, elem) in attributs(liste).filter(|(g, _)| *g == NFTA_LIST_ELEM) {
                for (_, cle) in attributs(elem).filter(|(g, _)| *g == NFTA_SET_ELEM_KEY) {
                    for (_, v) in attributs(cle).filter(|(g, _)| *g == NFTA_DATA_VALUE) {
                        let element = match (e, v.len()) {
                            (Ensemble::Sortie4, 4) => <[u8; 4]>::try_from(v).ok().map(|o| Element::Adresse(o.into())),
                            (Ensemble::Sortie6, 16) => <[u8; 16]>::try_from(v).ok().map(|o| Element::Adresse(o.into())),
                            (Ensemble::Ports, 2) => <[u8; 2]>::try_from(v)
                                .ok()
                                .map(|o| Element::Port(u16::from_be_bytes(o))),
                            (Ensemble::Coupes, 8) => <[u8; 8]>::try_from(v)
                                .ok()
                                .map(|o| Element::Cgroupe(u64::from_ne_bytes(o))),
                            _ => None,
                        };
                        trouves.extend(element);
                    }
                }
            }
        }
    }
    trouves
}

/// Les règles NEWRULE de cette chaîne de la table de Vanguard dans une liste.
fn compter_regles(octets: &[u8], chaine: &str) -> usize {
    recus(octets)
        .filter(|r| r.genre == genre(NFT_MSG_NEWRULE))
        .filter_map(|r| r.corps.get(4..))
        .filter(|corps| {
            attributs(corps).any(|(g, d)| g == NFTA_RULE_TABLE && d == b"vanguard\0")
                && attributs(corps)
                    .any(|(g, d)| g == NFTA_RULE_CHAIN && d.strip_suffix(b"\0") == Some(chaine.as_bytes()))
        })
        .count()
}

/// nf_tables est-il dans ce noyau : chargé, intégré, ou livré comme module (chargé au premier message) ? Lu sans
/// droits, à la place de « le programme nft est-il installé ».
pub(crate) fn present() -> bool {
    if std::path::Path::new("/sys/module/nf_tables").exists() {
        return true;
    }
    let Some(version) = version_du_noyau() else {
        return false;
    };
    let dossier = std::path::Path::new("/lib/modules").join(version);
    let lire = |nom: &str| std::fs::read_to_string(dossier.join(nom)).unwrap_or_default();
    module_liste(&lire("modules.builtin")) || module_liste(&lire("modules.dep"))
}

/// Une liste de modules (modules.builtin, modules.dep) cite-t-elle nf_tables.ko (compressé ou non) ?
fn module_liste(texte: &str) -> bool {
    texte.lines().any(|l| {
        let fichier = l.split(':').next().unwrap_or("");
        let nom = fichier.rsplit('/').next().unwrap_or("");
        nom == "nf_tables.ko" || nom.strip_prefix("nf_tables.ko.").is_some()
    })
}

// FFI de libc : uname (version du noyau).
#[allow(unsafe_code)]
fn version_du_noyau() -> Option<String> {
    // SAFETY: utsname est une structure de tableaux d'octets, remplie par uname ; zéro est une valeur valide.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `u` est à nous, vivant pendant l'appel.
    if unsafe { libc::uname(&raw mut u) } != 0 {
        return None;
    }
    let octets: Vec<u8> = u
        .release
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| c.cast_unsigned())
        .collect();
    let v = String::from_utf8(octets).ok()?;
    // Un nom de dossier, jamais un chemin.
    (!v.is_empty() && !v.contains('/') && v != "..").then_some(v)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::linux::netlink::Recu;

    fn hex(t: &str) -> Vec<u8> {
        (0..t.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Les corps (après l'en-tête netlink) des messages que nft 1.1.7 envoie pour la même table et le même élément,
    /// relevés par « unshare -rn nft --debug=mnl -f lot.nft » (lot.nft : les onze lignes que posaient les versions
    /// d'avant, plus « add element inet vanguard sortie4 { 203.0.113.7 } »). Le message de la table de nft porte en
    /// plus des données d'utilisateur (NFTA_TABLE_USERDATA), sans effet sur le filtrage : Vanguard ne les met pas.
    const NFT_TABLE: &str = "010000000d00010076616e6775617264000000000800020000000000";
    const NFT_ENSEMBLES: [&str; 3] = [
        "010000000d00010076616e6775617264000000000c000200736f72746965340008000300000000000800040000000007080005000000000408000a000000000114000d0000040200000003080004040000000100",
        "010000000d00010076616e6775617264000000000c000200736f72746965360008000300000000000800040000000008080005000000001008000a000000000214000d0000040200000003080004040000000100",
        "010000000d00010076616e6775617264000000000a000200706f7274730000000800030000000000080004000000000d080005000000000208000a000000000314000d0000040200000003080004040000000100",
    ];
    const NFT_CHAINES: [&str; 2] = [
        "010000000d00010076616e6775617264000000000b000300736f72746965000008000500000000010b00070066696c74657200001400048008000100000000030800020000000000",
        "010000000d00010076616e6775617264000000000b000300656e74726565000008000500000000010b00070066696c74657200001400048008000100000000010800020000000000",
    ];
    const NFT_VIDAGES: [&str; 2] = [
        "010000000d00010076616e6775617264000000000b000200736f727469650000",
        "010000000d00010076616e6775617264000000000b000200656e747265650000",
    ];
    const NFT_REGLES: [&str; 3] = [
        "010000000d00010076616e6775617264000000000b000200736f727469650000e800048024000180090001006d6574610000000014000280080002000000000f08000100000000012c00018008000100636d700020000280080001000000000108000200000000000c0003800500010002000000340001800c0001007061796c6f616400240002800800010000000001080002000000000108000300000000100800040000000004300001800b0001006c6f6f6b757000002000028008000200000000010c000100736f7274696534000800040000000001300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c0002800800010000000000",
        "010000000d00010076616e6775617264000000000b000200736f727469650000e800048024000180090001006d6574610000000014000280080002000000000f08000100000000012c00018008000100636d700020000280080001000000000108000200000000000c000380050001000a000000340001800c0001007061796c6f616400240002800800010000000001080002000000000108000300000000180800040000000010300001800b0001006c6f6f6b757000002000028008000200000000010c000100736f7274696536000800040000000002300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c0002800800010000000000",
        "010000000d00010076616e6775617264000000000b000200656e7472656500004401048024000180090001006d6574610000000014000280080002000000000608000100000000013800018008000100636d70002c0002800800010000000001080002000000000118000380140001006c6f000000000000000000000000000024000180090001006d6574610000000014000280080002000000001008000100000000012c00018008000100636d700020000280080001000000000108000200000000000c0003800500010006000000340001800c0001007061796c6f616400240002800800010000000001080002000000000208000300000000020800040000000002300001800b0001006c6f6f6b757000002000028008000200000000010a000100706f7274730000000800040000000003300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c0002800800010000000000",
    ];
    const NFT_ELEMENT: &str = "010000000d00010076616e6775617264000000000c000200736f727469653400080004000000000114000380100001800c00018008000100cb007107";

    /// Le lot de Vanguard, message par message, contre celui de nft : mêmes types, mêmes corps à l'octet près (la
    /// table sans les données d'utilisateur de nft), et les drapeaux de création, d'ajout et d'accusé.
    #[test]
    fn le_lot_est_celui_de_nft_octet_par_octet() {
        let (octets, attendus) = lot_poser(100, Element::Adresse("203.0.113.7".parse().unwrap()));
        let messages: Vec<Recu<'_>> = recus(&octets).collect();
        assert_eq!(messages.len(), 14);
        assert_eq!(attendus, (101..=112).collect::<Vec<_>>());
        // Début et fin de lot : AF_UNSPEC, res_id = NFNL_SUBSYS_NFTABLES dans l'ordre du réseau.
        assert_eq!((messages[0].genre, messages[0].corps), (16, &[0u8, 0, 0, 10][..]));
        assert_eq!((messages[13].genre, messages[13].corps), (17, &[0u8, 0, 0, 10][..]));
        let attendu: Vec<(u16, Vec<u8>)> = std::iter::once((2560, hex(NFT_TABLE)))
            .chain(NFT_ENSEMBLES.iter().map(|h| (2569, hex(h))))
            .chain(NFT_CHAINES.iter().map(|h| (2563, hex(h))))
            .chain(NFT_VIDAGES.iter().map(|h| (2568, hex(h))))
            .chain(NFT_REGLES.iter().map(|h| (2566, hex(h))))
            .chain(std::iter::once((2572, hex(NFT_ELEMENT))))
            .collect();
        for (i, (g, corps)) in attendu.iter().enumerate() {
            let m = &messages[i + 1];
            assert_eq!(m.genre, *g, "message {i}");
            assert_eq!(m.corps, &corps[..], "message {i} (type {g})");
        }
        // Les drapeaux, relus dans l'en-tête de chaque message.
        let drapeaux = |m: usize| {
            let debut = recus(&octets)
                .take(m)
                .map(|r| (r.corps.len() + 16).next_multiple_of(4))
                .sum::<usize>();
            u16::from_ne_bytes([octets[debut + 6], octets[debut + 7]])
        };
        let creer = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
        assert_eq!(drapeaux(0), NLM_F_REQUEST);
        for m in 1..=6 {
            assert_eq!(drapeaux(m), creer, "message {m}");
        }
        assert_eq!(drapeaux(7), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(drapeaux(8), NLM_F_REQUEST | NLM_F_ACK);
        for m in 9..=11 {
            assert_eq!(drapeaux(m), creer | NLM_F_APPEND, "message {m}");
        }
        assert_eq!(drapeaux(12), creer);
    }

    /// Chaque message du lot nomme la famille inet et la table « vanguard » ; le vidage nomme toujours sa chaîne :
    /// rien d'autre ne peut être vidé.
    #[test]
    fn seule_la_table_de_vanguard_est_visee() {
        for element in [Element::Port(11434), Element::Adresse("2001:db8::7".parse().unwrap())] {
            for (octets, _) in [lot_poser(1, element), lot_retirer(1, element)] {
                for r in recus(&octets).filter(|r| r.genre >> 8 == NFNL_SUBSYS_NFTABLES) {
                    assert_eq!(r.corps[0], NFPROTO_INET);
                    let corps = &r.corps[4..];
                    // Le premier attribut est toujours le nom de la table (TABLE = 1 partout, NAME pour la table).
                    let (g, d) = attributs(corps).next().unwrap();
                    assert_eq!((g, d), (1, &b"vanguard\0"[..]));
                    if r.genre == genre(NFT_MSG_DELRULE) {
                        assert!(attributs(corps).any(|(g, _)| g == NFTA_RULE_CHAIN));
                    }
                }
            }
        }
        // Le retrait ne contient qu'un DELSETELEM entre le début et la fin du lot.
        let (octets, attendus) = lot_retirer(7, Element::Port(7860));
        let genres: Vec<u16> = recus(&octets).map(|r| r.genre).collect();
        assert_eq!(genres, [16, genre(NFT_MSG_DELSETELEM), 17]);
        assert_eq!(attendus, [8]);
    }

    /// Les corps des messages de nft 1.1.7 pour la coupure (« unshare -rn nft --debug=mnl -f coupe.nft » : la table,
    /// « add set inet vanguard coupes { type cgroupsv2; } », les deux chaînes, leur vidage, « add rule … socket cgroupv2
    /// level 2 @coupes drop » dans chacune, puis l'élément, cgroup 5924). nft numérote son ensemble 1, Vanguard 4 :
    /// seuls ces numéros (NFTA_SET_ID, NFTA_LOOKUP_SET_ID, NFTA_SET_ELEM_LIST_SET_ID) diffèrent, remplacés ici.
    const NFT_COUPE_ENSEMBLE: &str = "010000000d00010076616e6775617264000000000b000200636f7570657300000800030000000000080004000000002e080005000000000808000a000000000114000d0000040100000003080004040000000100";
    const NFT_COUPE_CHAINES: [&str; 2] = [
        "010000000d00010076616e67756172640000000011000300636f7570652d736f727469650000000008000500000000010b00070066696c74657200001400048008000100000000030800020000000000",
        "010000000d00010076616e67756172640000000011000300636f7570652d656e747265650000000008000500000000010b00070066696c74657200001400048008000100000000010800020000000000",
    ];
    const NFT_COUPE_VIDAGES: [&str; 2] = [
        "010000000d00010076616e67756172640000000011000200636f7570652d736f7274696500000000",
        "010000000d00010076616e67756172640000000011000200636f7570652d656e7472656500000000",
    ];
    const NFT_COUPE_REGLE_SORTIE: &str = "010000000d00010076616e67756172640000000011000200636f7570652d736f7274696500000000900004802c0001800b000100736f636b657400001c000280080001000000000308000200000000010800030000000002300001800b0001006c6f6f6b757000002000028008000200000000010b000100636f7570657300000800040000000001300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c0002800800010000000000";
    const NFT_COUPE_ELEMENT: &str = "010000000d00010076616e6775617264000000000b000200636f75706573000008000400000000011800038014000180100001800c0001002417000000000000";

    /// Remplace le numéro d'ensemble de nft (1) par celui de Vanguard (4) dans l'attribut qui le porte.
    fn numero_4(h: &str, attribut: &str) -> String {
        let avant = format!("{attribut}00000001");
        assert_eq!(h.matches(&avant).count(), 1, "{attribut} dans {h}");
        h.replace(&avant, &format!("{attribut}00000004"))
    }

    /// Le lot de la coupure, message par message, contre celui de nft, à l'octet près ; ses drapeaux.
    #[test]
    fn la_coupure_est_celle_de_nft_octet_par_octet() {
        // Le cgroup 5924, dans l'ordre des octets de la machine (celui de l'ordinateur où nft a écrit l'essai).
        if cfg!(target_endian = "big") {
            return crate::essais::saute("relevé de nft fait sur une machine petit-boutiste");
        }
        let (octets, attendus) = lot_couper(200, 5924, 2);
        let messages: Vec<Recu<'_>> = recus(&octets).collect();
        assert_eq!(messages.len(), 11);
        assert_eq!(attendus, (201..=209).collect::<Vec<_>>());
        assert_eq!((messages[0].genre, messages[0].corps), (16, &[0u8, 0, 0, 10][..]));
        assert_eq!((messages[10].genre, messages[10].corps), (17, &[0u8, 0, 0, 10][..]));
        let regle_entree = NFT_COUPE_REGLE_SORTIE.replace(
            "11000200636f7570652d736f7274696500000000",
            "11000200636f7570652d656e7472656500000000",
        );
        let attendu: Vec<(u16, String)> = vec![
            (2560, NFT_TABLE.to_string()),
            (2569, numero_4(NFT_COUPE_ENSEMBLE, "08000a00")),
            (2563, NFT_COUPE_CHAINES[0].to_string()),
            (2563, NFT_COUPE_CHAINES[1].to_string()),
            (2568, NFT_COUPE_VIDAGES[0].to_string()),
            (2568, NFT_COUPE_VIDAGES[1].to_string()),
            (2566, numero_4(NFT_COUPE_REGLE_SORTIE, "08000400")),
            (2566, numero_4(&regle_entree, "08000400")),
            (2572, numero_4(NFT_COUPE_ELEMENT, "08000400")),
        ];
        for (i, (g, corps)) in attendu.iter().enumerate() {
            let m = &messages[i + 1];
            assert_eq!(m.genre, *g, "message {i}");
            assert_eq!(m.corps, &hex(corps)[..], "message {i} (type {g})");
        }
        let drapeaux = |m: usize| {
            let debut = recus(&octets)
                .take(m)
                .map(|r| (r.corps.len() + 16).next_multiple_of(4))
                .sum::<usize>();
            u16::from_ne_bytes([octets[debut + 6], octets[debut + 7]])
        };
        let creer = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
        for m in 1..=4 {
            assert_eq!(drapeaux(m), creer, "message {m}");
        }
        assert_eq!(drapeaux(5), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(drapeaux(6), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(drapeaux(7), creer | NLM_F_APPEND);
        assert_eq!(drapeaux(8), creer | NLM_F_APPEND);
        assert_eq!(drapeaux(9), creer);
        // L'expression seule : « socket », clé CGROUPV2 (3), registre 1, niveau voulu.
        let mut x = Attributs::default();
        socket_cgroupe(&mut x, 7);
        assert_eq!(
            x.0,
            hex("2c0001800b000100736f636b657400001c000280080001000000000308000200000000010800030000000007")
        );
    }

    /// La coupure ne vise que la table « vanguard », ne vide que ses deux chaînes, et ne touche ni aux ensembles ni
    /// aux chaînes du blocage ; son retrait est un DELSETELEM de l'ensemble « coupes », seul.
    #[test]
    fn la_coupure_ne_touche_que_ses_chaines() {
        let (octets, _) = lot_couper(1, u64::MAX, NIVEAU_DES_COUPES);
        for r in recus(&octets).filter(|r| r.genre >> 8 == NFNL_SUBSYS_NFTABLES) {
            assert_eq!(r.corps[0], NFPROTO_INET);
            let corps = &r.corps[4..];
            assert_eq!(attributs(corps).next().unwrap(), (1, &b"vanguard\0"[..]));
            for (g, d) in attributs(corps) {
                let nom = d.strip_suffix(b"\0").unwrap_or(d);
                let nomme = match r.genre & 0xff {
                    m if m == NFT_MSG_NEWCHAIN => g == NFTA_CHAIN_NAME,
                    m if m == NFT_MSG_NEWRULE || m == NFT_MSG_DELRULE => g == NFTA_RULE_CHAIN,
                    m if m == NFT_MSG_NEWSET => g == NFTA_SET_NAME,
                    m if m == NFT_MSG_NEWSETELEM => g == NFTA_SET_ELEM_LIST_SET,
                    _ => false,
                };
                if nomme {
                    assert!(
                        [&b"coupe-sortie"[..], b"coupe-entree", b"coupes"].contains(&nom),
                        "{:?}",
                        String::from_utf8_lossy(nom)
                    );
                }
            }
        }
        let (octets, _) = lot_retirer(1, Element::Cgroupe(42));
        let m: Vec<Recu<'_>> = recus(&octets).collect();
        assert_eq!(m.len(), 3);
        assert_eq!(m[1].genre, genre(NFT_MSG_DELSETELEM));
        assert!(attributs(&m[1].corps[4..]).any(|(g, d)| g == NFTA_SET_ELEM_LIST_SET && d == b"coupes\0"));
        // Relu : le cgroup revient tel qu'il est parti.
        let mut p = nfgen(NFPROTO_INET, 0);
        element_liste(&mut p, Element::Cgroupe(0x0102_0304_0506_0708));
        let m = netlink::message(genre(NFT_MSG_NEWSETELEM), 2, 1, &p.0);
        assert_eq!(
            lire_elements(&m, Ensemble::Coupes),
            [Element::Cgroupe(0x0102_0304_0506_0708)]
        );
        assert_eq!(lire_elements(&m, Ensemble::Ports), []);
    }

    #[test]
    fn elements_relus() {
        // Le message NEWSETELEM de nft, tel que le noyau le renvoie dans une liste.
        let m = netlink::message(genre(NFT_MSG_NEWSETELEM), 2, 1, &hex(NFT_ELEMENT));
        assert_eq!(
            lire_elements(&m, Ensemble::Sortie4),
            [Element::Adresse("203.0.113.7".parse().unwrap())]
        );
        assert_eq!(lire_elements(&m, Ensemble::Ports), []);
        let mut p = nfgen(NFPROTO_INET, 0);
        element_liste(&mut p, Element::Port(7860));
        let m = netlink::message(genre(NFT_MSG_NEWSETELEM), 2, 1, &p.0);
        assert_eq!(lire_elements(&m, Ensemble::Ports), [Element::Port(7860)]);
        // Une adresse IPv4 vue en IPv6 va dans sortie4, sous sa forme IPv4.
        assert_eq!(
            Element::Adresse("::ffff:203.0.113.7".parse().unwrap()).ensemble(),
            Ensemble::Sortie4
        );
        assert_eq!(
            Element::Adresse("::ffff:203.0.113.7".parse().unwrap()).octets(),
            [203, 0, 113, 7]
        );
    }

    #[test]
    fn modules_du_noyau() {
        assert!(module_liste(
            "kernel/net/netfilter/nf_tables.ko.zst: kernel/net/netfilter/nfnetlink.ko.zst\n"
        ));
        assert!(module_liste("kernel/net/netfilter/nf_tables.ko\n"));
        assert!(!module_liste(
            "kernel/net/netfilter/nf_tables_set.ko: x\nkernel/net/netfilter/nft_ct.ko:\n"
        ));
    }

    /// L'essai pour de vrai, dans un espace de noms réseau et utilisateur à part (`unshare -rn`, sans root : la table
    /// n'existe que là, et disparaît avec lui). Lancé par `nftables_dans_un_espace_a_part`, jamais seul.
    #[test]
    #[ignore = "lancé dans un espace de noms à part par nftables_dans_un_espace_a_part"]
    fn dedans_l_espace_a_part() {
        use std::net::UdpSocket;
        // Rien que la boucle locale, montée : le paquet vers 127.0.0.2 passe par le crochet de sortie.
        assert!(
            std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .is_ok_and(|s| s.success())
        );
        let nft = ["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"]
            .into_iter()
            .find(|c| std::path::Path::new(c).exists());
        // Une table d'un autre outil, qui doit rester intacte.
        if let Some(nft) = nft {
            assert!(
                std::process::Command::new(nft)
                    .args(["add", "table", "inet", "autre"])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let cible: IpAddr = "127.0.0.2".parse().unwrap();
        let envoyer = || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.send_to(b"x", (cible, 9)).is_ok()
        };
        assert!(envoyer(), "avant le blocage, le paquet part");
        poser(Element::Adresse(cible)).unwrap();
        poser(Element::Port(7860)).unwrap();
        // Deux fois la même : toujours trois règles, un seul élément.
        poser(Element::Adresse(cible)).unwrap();
        assert!(
            !envoyer(),
            "bloquée : l'envoi vers l'adresse est refusé par la règle de sortie"
        );
        if let Some(nft) = nft {
            let liste = std::process::Command::new(nft)
                .args(["list", "ruleset"])
                .output()
                .unwrap();
            let texte = String::from_utf8_lossy(&liste.stdout);
            for attendu in [
                "table inet autre",
                "set sortie4",
                "type ipv4_addr",
                "elements = { 127.0.0.2 }",
                "type inet_service",
                "elements = { 7860 }",
                "type filter hook output priority filter; policy accept;",
                "ip daddr @sortie4 drop",
                "ip6 daddr @sortie6 drop",
                "type filter hook input priority filter; policy accept;",
                "iifname != \"lo\" tcp dport @ports drop",
            ] {
                assert!(texte.contains(attendu), "« {attendu} » manque :\n{texte}");
            }
            assert_eq!(texte.matches("drop").count(), 3, "{texte}");
        }
        assert_eq!(retirer(Element::Adresse(cible)).unwrap(), Retrait::Retire);
        assert!(envoyer(), "retirée : le paquet repart");
        assert_eq!(retirer(Element::Adresse(cible)).unwrap(), Retrait::DejaAbsent);
        assert_eq!(retirer(Element::Port(7860)).unwrap(), Retrait::Retire);
        if let Some(nft) = nft {
            // La table de l'autre outil est toujours là ; la nôtre se supprime, puis le retrait dit « plus de table ».
            let liste = std::process::Command::new(nft)
                .args(["list", "tables"])
                .output()
                .unwrap();
            assert!(String::from_utf8_lossy(&liste.stdout).contains("table inet autre"));
            assert!(
                std::process::Command::new(nft)
                    .args(["delete", "table", "inet", "vanguard"])
                    .status()
                    .unwrap()
                    .success()
            );
            assert_eq!(retirer(Element::Port(7860)).unwrap(), Retrait::SansTable);
        }
    }

    /// Le dossier de cgroup de ce processus et son niveau sous la racine, s'il est à nous (délégué par systemd à la
    /// session : on peut y créer un sous-dossier). Sinon `None`.
    fn cgroupe_delegue() -> Option<(std::path::PathBuf, u32)> {
        let texte = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let relatif = texte
            .lines()
            .find_map(|l| l.strip_prefix("0::"))?
            .trim_start_matches('/');
        if relatif.is_empty() {
            return None;
        }
        let dossier = std::path::Path::new("/sys/fs/cgroup").join(relatif);
        let essai = dossier.join(format!("vg-essai-delegue-{}", std::process::id()));
        std::fs::create_dir(&essai).ok()?;
        let _ = std::fs::remove_dir(&essai);
        let niveau = u32::try_from(relatif.split('/').count()).ok()?;
        Some((dossier, niveau))
    }

    /// La coupure pour de vrai, dans un espace de noms réseau à part. Le scope de systemd y est remplacé par un
    /// sous-cgroup du cgroup délégué de l'essai (créé puis retiré ; le processus coupé y est mis par l'essai, ce que
    /// Vanguard ne fait jamais : il le demande à systemd). Lancé par `coupure_dans_un_espace_a_part`, jamais seul.
    #[test]
    #[ignore = "lancé dans un espace de noms à part par coupure_dans_un_espace_a_part"]
    fn coupure_dedans_l_espace_a_part() {
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};
        assert!(
            std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .is_ok_and(|s| s.success())
        );
        let (parent, niveau_parent) = cgroupe_delegue().expect("cgroup délégué (vérifié avant le lancement)");
        let dossier = parent.join(format!("vg-essai-coupe-{}", std::process::id()));
        std::fs::create_dir(&dossier).unwrap();
        let id = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&dossier).unwrap());
        let niveau = niveau_parent + 1;
        let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ecoute.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in ecoute.incoming() {
                drop(c);
            }
        });
        // Un processus mis dans le sous-cgroup, qui ouvre une connexion ; « passe » s'il y arrive en 4 s.
        let essayer = || {
            let mut enfant = std::process::Command::new("bash")
                .args([
                    "-c",
                    &format!("echo $$ > \"$DEST\" && exec 3<>/dev/tcp/127.0.0.1/{port} && echo passe"),
                ])
                .env("DEST", dossier.join("cgroup.procs"))
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let debut = Instant::now();
            while enfant.try_wait().unwrap().is_none() && debut.elapsed() < Duration::from_secs(4) {
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = enfant.kill();
            let sortie = enfant.wait_with_output().unwrap();
            String::from_utf8_lossy(&sortie.stdout).contains("passe")
        };
        let voisin = || TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(4)).is_ok();
        assert!(essayer(), "avant la coupure, le processus passe");
        assert_eq!(cgroupes_coupes().unwrap(), Vec::<u64>::new());
        couper_cgroupe(id, niveau).unwrap();
        // Deux fois : toujours une règle par chaîne, un seul élément.
        couper_cgroupe(id, niveau).unwrap();
        assert_eq!(cgroupes_coupes().unwrap(), [id]);
        assert!(!essayer(), "coupé : le processus du sous-cgroup ne passe plus");
        assert!(voisin(), "son voisin (l'essai, hors du sous-cgroup) passe");
        let nft = ["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"]
            .into_iter()
            .find(|c| std::path::Path::new(c).exists());
        if let Some(nft) = nft {
            let liste = std::process::Command::new(nft)
                .args(["list", "ruleset"])
                .output()
                .unwrap();
            let texte = String::from_utf8_lossy(&liste.stdout);
            for attendu in [
                "set coupes",
                "type cgroupsv2",
                "chain coupe-sortie",
                "chain coupe-entree",
                &format!("socket cgroupv2 level {niveau} @coupes drop"),
            ] {
                assert!(texte.contains(attendu), "« {attendu} » manque :\n{texte}");
            }
            assert_eq!(texte.matches("drop").count(), 2, "{texte}");
        }
        assert_eq!(retirer(Element::Cgroupe(id)).unwrap(), Retrait::Retire);
        assert!(essayer(), "rendu : le processus repasse");
        assert_eq!(retirer(Element::Cgroupe(id)).unwrap(), Retrait::DejaAbsent);
        // Les processus de l'essai sont finis : le sous-cgroup se retire.
        let debut = Instant::now();
        while std::fs::remove_dir(&dossier).is_err() && debut.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!dossier.exists());
    }

    /// La coupure d'un cgroup, éprouvée par de vraies connexions dans un espace de noms réseau à part. Sautée sans
    /// espaces de noms utilisateur, sans cgroup délégué (CI), sans bash ou sans « ip ».
    #[test]
    fn coupure_dans_un_espace_a_part() {
        let Ok(moi) = std::env::current_exe() else {
            return crate::essais::saute("programme de test introuvable");
        };
        let essai = std::process::Command::new("unshare").args(["-rn", "true"]).status();
        if !essai.is_ok_and(|s| s.success()) {
            return crate::essais::saute("pas d'espace de noms utilisateur ici (unshare -rn)");
        }
        if !std::path::Path::new("/usr/bin/ip").exists() && !std::path::Path::new("/usr/sbin/ip").exists() {
            return crate::essais::saute("« ip » absent : la boucle locale ne se monte pas");
        }
        if !std::path::Path::new("/usr/bin/bash").exists() && !std::path::Path::new("/bin/bash").exists() {
            return crate::essais::saute("bash absent");
        }
        if cgroupe_delegue().is_none() {
            return crate::essais::saute("pas de cgroup délégué à l'essai (cgroup v2 de la session)");
        }
        let sortie = std::process::Command::new("unshare")
            .arg("-rn")
            .arg(moi)
            .args([
                "--ignored",
                "--exact",
                "machine::linux::nftables::tests::coupure_dedans_l_espace_a_part",
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

    /// La table posée par netlink, relue par nft et éprouvée par un vrai paquet, dans un espace de noms réseau à
    /// part : rien ne touche le pare-feu de cet ordinateur. Sauté sans espaces de noms utilisateur (CI d'Ubuntu, qui
    /// les restreint) ou sans « ip ».
    #[test]
    fn nftables_dans_un_espace_a_part() {
        let Ok(moi) = std::env::current_exe() else {
            return crate::essais::saute("programme de test introuvable");
        };
        let essai = std::process::Command::new("unshare").args(["-rn", "true"]).status();
        if !essai.is_ok_and(|s| s.success()) {
            return crate::essais::saute("pas d'espace de noms utilisateur ici (unshare -rn)");
        }
        if !std::path::Path::new("/usr/bin/ip").exists() && !std::path::Path::new("/usr/sbin/ip").exists() {
            return crate::essais::saute("« ip » absent : la boucle locale ne se monte pas");
        }
        let sortie = std::process::Command::new("unshare")
            .arg("-rn")
            .arg(moi)
            .args([
                "--ignored",
                "--exact",
                "machine::linux::nftables::tests::dedans_l_espace_a_part",
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
