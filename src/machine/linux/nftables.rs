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
//! Le protocole : NETLINK_NETFILTER, sous-système NFTABLES (linux/netfilter/nfnetlink.h, nf_tables.h). Les
//! changements partent en un lot (NFNL_MSG_BATCH_BEGIN … END) que le noyau applique tout entier ou pas du tout ; chaque
//! message demande son accusé. Les messages reprennent octet par octet ce que nft 1.1 envoie pour la même table
//! (`nft --debug=mnl`), ce que vérifient les tests ; un essai dans un espace de noms réseau à part (`unshare -rn`)
//! pose la table pour de vrai, la relit avec nft et vérifie qu'un paquet vers une adresse bloquée est refusé.
//! Seule la table « vanguard » de la famille inet est visée : chaque message la nomme, et le vidage d'une chaîne
//! nomme la chaîne.

use std::net::IpAddr;

use crate::modele::Echec;
use crate::{tr, trf};

/// Le contexte des échecs de ce module.
const OU: &str = "blocage/nf_tables";

use super::netlink::{
    self, Attributs, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REQUEST, Prise, attributs, recus,
};

pub(crate) const TABLE: &str = "vanguard";

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

/// Les trois ensembles de la table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ensemble {
    Sortie4,
    Sortie6,
    Ports,
}

impl Ensemble {
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Ensemble::Sortie4 => "sortie4",
            Ensemble::Sortie6 => "sortie6",
            Ensemble::Ports => "ports",
        }
    }
    /// Le type de nft (ipv4_addr = 7, ipv6_addr = 8, inet_service = 13) et la longueur de la clé.
    fn cle(self) -> (u32, u32) {
        match self {
            Ensemble::Sortie4 => (7, 4),
            Ensemble::Sortie6 => (8, 16),
            Ensemble::Ports => (13, 2),
        }
    }
    /// Son numéro dans le lot : une règle du même lot s'y réfère par lui (NFTA_LOOKUP_SET_ID).
    fn id(self) -> u32 {
        match self {
            Ensemble::Sortie4 => 1,
            Ensemble::Sortie6 => 2,
            Ensemble::Ports => 3,
        }
    }
}

/// Ce qui entre dans un ensemble : une adresse bloquée en sortie, ou un port TCP fermé en entrée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Element {
    Adresse(IpAddr),
    Port(u16),
}

impl Element {
    pub(crate) fn ensemble(self) -> Ensemble {
        match self {
            Element::Adresse(ip) if ip.to_canonical().is_ipv4() => Ensemble::Sortie4,
            Element::Adresse(_) => Ensemble::Sortie6,
            Element::Port(_) => Ensemble::Ports,
        }
    }
    /// La clé telle que le noyau la compare : l'adresse ou le port dans l'ordre du réseau.
    fn octets(self) -> Vec<u8> {
        match self {
            Element::Adresse(ip) => match ip.to_canonical() {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            },
            Element::Port(p) => p.to_be_bytes().to_vec(),
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
        n += 1;
        octets.extend(m(n));
        numeros.push(n);
    }
    octets.extend(netlink::message(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        n + 1,
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
                a.brut(NFTA_SET_USERDATA, &DONNEES_D_ENSEMBLE);
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
    let prise = Prise::ouvrir(NETLINK_NETFILTER).map_err(|e| refus(e.raw_os_error().map_or(-libc::EIO, |c| -c)))?;
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
    let prise = Prise::ouvrir(NETLINK_NETFILTER).map_err(|e| refus(e.raw_os_error().map_or(-libc::EIO, |c| -c)))?;
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

/// La table relue : les éléments de ses trois ensembles, et le nombre de règles de chaque chaîne.
#[derive(Debug, Default)]
pub(crate) struct Relue {
    pub elements: Vec<Element>,
    pub regles: Vec<(String, usize)>,
}

fn relire(prise: &Prise) -> Result<Relue, Echec> {
    let mut relue = Relue::default();
    for e in [Ensemble::Sortie4, Ensemble::Sortie6, Ensemble::Ports] {
        let demande = nft(NFT_MSG_GETSETELEM, NLM_F_REQUEST | NLM_F_DUMP, premier_numero(), |a| {
            a.texte(NFTA_SET_ELEM_LIST_TABLE, TABLE);
            a.texte(NFTA_SET_ELEM_LIST_SET, e.nom());
        });
        let reponse = prise.lister(&demande).map_err(refus)?;
        relue.elements.extend(lire_elements(&reponse, e));
    }
    for chaine in ["sortie", "entree"] {
        let demande = nft(NFT_MSG_GETRULE, NLM_F_REQUEST | NLM_F_DUMP, premier_numero(), |a| {
            a.texte(NFTA_RULE_TABLE, TABLE);
            a.texte(NFTA_RULE_CHAIN, chaine);
        });
        let reponse = prise.lister(&demande).map_err(refus)?;
        relue
            .regles
            .push((chaine.to_string(), compter_regles(&reponse, chaine)));
    }
    Ok(relue)
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
                            (Ensemble::Ports, 2) => Some(Element::Port(u16::from_be_bytes([v[0], v[1]]))),
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

fn version_du_noyau() -> Option<String> {
    // SAFETY : utsname est une structure de tableaux d'octets, remplie par uname ; zéro est une valeur valide.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY : `u` est à nous, vivant pendant l'appel.
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
