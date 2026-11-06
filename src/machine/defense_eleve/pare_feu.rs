//! Lot D7c : le pare-feu de Linux (ufw, firewalld, nftables) coupé ou rallumé sur le choix de la personne, depuis
//! les Options de défense, jamais depuis une correction du bilan. Couper est une BAISSE : la question le dit (« MOINS
//! protégé »), la note d'« avant » porte l'identifiant fixe du pare-feu (`PareFeu::note`), Défaire ou Rallumer la
//! remet. Rallumer sans note est un renforcement, non annulable. Rien ne vient de la ligne du parent que le nom du
//! pare-feu : l'état est relu ici, par root.
//!
//! nftables, défini avant le code (rapport du lot) : il n'est « le » pare-feu que si ni ufw ni firewalld ne tiennent
//! les règles. Couper retire, en une seule transaction, chaque table qui n'est pas à Vanguard (`inet vanguard` du
//! blocage, `inet vanguard_public` du mode Wi-Fi public, jamais touchées : donc jamais `flush ruleset`), après les
//! avoir sauvegardées dans la note et vérifié que la sauvegarde se relit (`nft -c -f`) ; nftables.service, s'il était
//! lancé au démarrage, n'y est plus, sans être arrêté (son arrêt vide toutes les règles, celles de Vanguard
//! comprises). Remettre recharge la sauvegarde, vérifiée d'abord, d'un bloc.

use super::*;
use crate::machine::gestes_unix::PareFeu;

const UFW_CONF: &str = "/etc/ufw/ufw.conf";
const UFW_CONF_MAX: usize = 64 * 1024;
pub(super) const FIREWALLD: &str = "firewalld.service";
pub(super) const NFTABLES: &str = "nftables.service";
/// Le fichier où une sauvegarde de nftables passe le temps de la vérifier et de la charger : dans le dossier des notes
/// (à root, fermé aux autres), sous un nom qu'aucune note ne prend (elles n'ont que 16 chiffres hexadécimaux).
pub(super) const FICHIER_NFT: &str = "/var/lib/vanguard/avant/pare-feu.nft";
/// Les tables de Vanguard : jamais sauvegardées, jamais retirées (`protection::blocage::pare_feu`,
/// `reseau::wifi_public::linux::TABLE`).
pub(super) const TABLES_VANGUARD: [(&str, &str); 2] = [("inet", "vanguard"), ("inet", "vanguard_public")];
const FAMILLES: [&str; 6] = ["ip", "ip6", "inet", "arp", "bridge", "netdev"];
const NOM_TABLE_MAX: usize = 64;
const TABLES_MAX: usize = 64;
/// Les règles ajoutées d'ufw montrées dans la question, au plus.
const REGLES_MONTREES: usize = 20;
const TCP_MAX: usize = 4 * 1024 * 1024;

// ————— Ce qui est relu —————

/// ufw : `ENABLED=` de /etc/ufw/ufw.conf (allumé au démarrage), et `ufw status` (allumé maintenant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EtatUfw {
    pub(super) enabled: bool,
    pub(super) actif: bool,
}

/// La valeur de `ENABLED=` (la dernière, comme ufw la lit) ; `None` : absente, ou ni yes ni no.
pub(super) fn ufw_enabled(t: &str) -> Option<bool> {
    let mut v = None;
    for l in t.lines() {
        let l = l.trim();
        if let Some(x) = l.strip_prefix("ENABLED=") {
            let x = x.trim().trim_matches(['"', '\'']);
            v = Some(match x.to_ascii_lowercase().as_str() {
                "yes" => true,
                "no" => false,
                _ => return None,
            });
        }
    }
    v
}

/// La première ligne de `ufw status` : « Status: active » ou « Status: inactive », et rien d'autre.
pub(super) fn ufw_statut(t: &str) -> Option<bool> {
    match t.lines().next()?.trim() {
        "Status: active" => Some(true),
        "Status: inactive" => Some(false),
        _ => None,
    }
}

/// L'état d'ufw ; `None` : il n'est pas installé (ni ufw.conf, ni l'outil).
fn etat_ufw(a: &mut dyn Acces) -> Result<Option<EtatUfw>, Echec> {
    let conf = Path::new(UFW_CONF);
    let conf_la = a.fiche(conf).is_some();
    if !conf_la && !a.outil("ufw") {
        return Ok(None);
    }
    let illisible = || {
        refus(tr!(
            "l'état d'ufw ne se lit pas (/etc/ufw/ufw.conf, ufw status) : rien n'est fait",
            "ufw's state cannot be read (/etc/ufw/ufw.conf, ufw status): nothing is done"
        ))
    };
    let texte = a.lire(conf, UFW_CONF_MAX).ok_or_else(illisible)?;
    let enabled = ufw_enabled(&String::from_utf8_lossy(&texte)).ok_or_else(illisible)?;
    let r = lancer_ok(a, "ufw", &[os("status")])?;
    let actif = ufw_statut(&r.sortie).ok_or_else(illisible)?;
    Ok(Some(EtatUfw { enabled, actif }))
}

/// L'état d'une unité (fichier, activité) ; `None` : sans systemd, ou pas installée.
fn etat_unite(nom: &str, s: &mut dyn Services) -> Result<Option<(String, String)>, Echec> {
    if !s.systemd() || !s.fichier_sur(nom)? {
        return Ok(None);
    }
    let etat = s.etat_du_fichier(nom)?.unwrap_or_default();
    let activite = s.etat_d_activite(nom)?.unwrap_or_default();
    Ok(Some((etat, activite)))
}

fn unite_allumee(e: &(String, String)) -> bool {
    lance_au_demarrage(&e.0) || tourne(&e.1)
}

/// Un nom de table que nft écrit tel quel et que Vanguard repasse sans risque : lettres, chiffres, « _ », « . »,
/// « - », jamais en tête un chiffre, un « - » ou un « . ».
pub(super) fn nom_de_table(n: &str) -> bool {
    let o = n.as_bytes();
    o.len() <= NOM_TABLE_MAX
        && o.first().is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        && o.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// Les tables d'une liste `table <famille> <nom>`, une par ligne ; toute autre forme : `None` (rien n'est fait).
pub(super) fn tables_de(t: &str) -> Option<Vec<(String, String)>> {
    let mut v = Vec::new();
    for l in t.lines() {
        if l.is_empty() {
            continue;
        }
        let mots: Vec<&str> = l.split(' ').collect();
        let ["table", f, n] = mots.as_slice() else {
            return None;
        };
        if !FAMILLES.contains(f) || !nom_de_table(n) || v.len() >= TABLES_MAX {
            return None;
        }
        v.push(((*f).to_string(), (*n).to_string()));
    }
    Some(v)
}

pub(super) fn de_vanguard(t: &(String, String)) -> bool {
    TABLES_VANGUARD.iter().any(|(f, n)| t.0 == *f && t.1 == *n)
}

/// Toutes les tables de nftables, relues par root.
fn lire_tables(a: &mut dyn Acces) -> Result<Vec<(String, String)>, Echec> {
    if !a.outil("nft") {
        return Err(refus(tr!(
            "nft n'est pas installé dans les dossiers du système : rien n'est fait",
            "nft is not installed in the system folders: nothing is done"
        )));
    }
    let r = lancer_ok(a, "nft", &[os("list"), os("tables")])?;
    tables_de(&r.sortie).ok_or_else(|| {
        refus(tr!(
            "la liste des tables de nftables a une forme que Vanguard ne relit pas : rien n'est fait",
            "the list of nftables tables has a form Vanguard does not read: nothing is done"
        ))
    })
}

fn liste_lisible(tables: &[(String, String)]) -> String {
    tables
        .iter()
        .map(|(f, n)| format!("{f} {n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Une table relue (`nft -s list table`, sans compteurs : rien n'y bouge pendant la question), jugée : une table tenue
/// par un programme qui tourne (`flags owner`) ou celle d'iptables (Docker, libvirt, fail2ban…) n'est jamais retirée.
pub(super) fn juger_table(f: &str, n: &str, r: &Sortie) -> Result<(), Echec> {
    let vu = format!("{f} {n}");
    // D'abord iptables. nft écrit son avertissement (« # Warning: table … is managed by iptables-nft ») sur la sortie
    // d'erreur, et seulement quand la table a des expressions d'iptables (`xt`) ; une table d'iptables-nft aux règles
    // simples (une adresse refusée) n'a aucune marque (essai QEMU de D7c, Arch, iptables 1.8.13, nft 1.1.7) : elle se
    // reconnaît à sa forme, un nom de table et une chaîne de base d'iptables.
    if r.sortie.contains("iptables-nft") || r.erreurs.contains("iptables-nft") || forme_iptables(f, n, &r.sortie) {
        return Err(refus(trf!(
            "la table {vu} est (ou a la forme de) celle d'iptables (Docker, libvirt, fail2ban…) : Vanguard ne la retire pas",
            "the table {vu} is (or looks like) iptables' (Docker, libvirt, fail2ban…): Vanguard does not remove it"
        )));
    }
    if r.sortie.lines().find(|l| !l.starts_with('#')).map(str::trim_end) != Some(&format!("table {f} {n} {{")) {
        return Err(refus(trf!(
            "la table {vu} de nftables a une forme que Vanguard ne relit pas : rien n'est fait",
            "the nftables table {vu} has a form Vanguard does not read: nothing is done"
        )));
    }
    let tenue = r.sortie.lines().any(|l| {
        l.trim()
            .strip_prefix("flags ")
            .is_some_and(|x| x.split([',', ' ']).any(|m| m == "owner" || m == "persist"))
    });
    if tenue {
        return Err(refus(trf!(
            "la table {vu} appartient à un programme qui tourne (flags owner) : Vanguard ne la retire pas. Arrêtez ce programme d'abord",
            "the table {vu} belongs to a running program (flags owner): Vanguard does not remove it. Stop that program first"
        )));
    }
    Ok(())
}

/// Une table à la forme de celles d'iptables-nft, ebtables ou arptables : son nom est celui d'une table d'iptables, et
/// elle a une chaîne au nom d'une chaîne de base d'iptables (en majuscules). Une table écrite à la main sur ce modèle
/// est refusée aussi, par prudence (rien n'est fait, et le message le dit).
pub(super) fn forme_iptables(f: &str, n: &str, liste: &str) -> bool {
    const TABLES: [&str; 6] = ["filter", "nat", "mangle", "raw", "security", "broute"];
    const CHAINES: [&str; 6] = ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING", "BROUTING"];
    matches!(f, "ip" | "ip6" | "arp" | "bridge")
        && TABLES.contains(&n)
        && liste.lines().any(|l| {
            l.trim()
                .strip_prefix("chain ")
                .and_then(|c| c.strip_suffix(" {"))
                .is_some_and(|c| CHAINES.contains(&c))
        })
}

/// La sauvegarde des tables : pour chacune, `add table`, `delete table`, puis sa liste ; rechargée d'un bloc, elle les
/// remet telles qu'elles étaient.
fn sauvegarde(a: &mut dyn Acces, tables: &[(String, String)]) -> Result<String, Echec> {
    let mut s = String::new();
    for (f, n) in tables {
        let r = lancer_ok(a, "nft", &[os("-s"), os("list"), os("table"), os(f), os(n)])?;
        juger_table(f, n, &r)?;
        let _ = writeln!(s, "add table {f} {n}\ndelete table {f} {n}");
        s.push_str(&r.sortie);
        if !s.ends_with('\n') {
            s.push('\n');
        }
    }
    if s.len() > VALEUR_MAX {
        return Err(refus(tr!(
            "les règles de nftables sont trop grandes pour tenir dans la note d'« avant » : rien n'est fait",
            "the nftables rules are too large to fit in the \"before\" note: nothing is done"
        )));
    }
    Ok(s)
}

/// Une session SSH est-elle peut-être ouverte sur cet ordinateur ? Vrai aussi quand on ne peut pas dire le contraire :
/// la lignée de Vanguard illisible ou dans sshd, les sessions illisibles, une session distante, une connexion TCP
/// établie sur le port 22, ou une connexion entrante venue d'ailleurs sur un port en écoute (sshd sur un autre port).
pub(super) fn ssh_peut_etre_ouvert(a: &dyn Acces, s: &mut dyn Services) -> bool {
    let lignee = s.groupes_de_la_lignee();
    if lignee.is_empty() || lignee.iter().any(|g| systeme::groupe_ssh(g)) {
        return true;
    }
    let Some(sessions) = s.sessions() else {
        return true;
    };
    if sessions
        .iter()
        .any(|v| v.distante || v.service.starts_with("ssh") || v.service.contains("dropbear"))
    {
        return true;
    }
    ["/proc/net/tcp", "/proc/net/tcp6"].iter().any(|p| {
        a.lire(Path::new(p), TCP_MAX)
            .is_none_or(|o| tcp_ssh_etabli(&String::from_utf8_lossy(&o)))
    })
}

/// Dans /proc/net/tcp ou tcp6 : une connexion établie (état 01) dont le port local est 22 (0016), ou dont le port local
/// est aussi en écoute (état 0A : une connexion entrante, pas une sortante) et l'adresse distante n'est pas la boucle
/// locale. sshd peut écouter sur un autre port que 22 (relecture de D7c) ; une autre connexion entrante (VNC, Bureau à
/// distance) avertit aussi, par prudence.
pub(super) fn tcp_ssh_etabli(t: &str) -> bool {
    let lignes: Vec<Vec<&str>> = t.lines().skip(1).map(|l| l.split_whitespace().collect()).collect();
    let port = |adresse: &str| adresse.rsplit(':').next().map(str::to_ascii_uppercase);
    let ecoute: std::collections::HashSet<String> = lignes
        .iter()
        .filter(|m| m.get(3) == Some(&"0A"))
        .filter_map(|m| port(m.get(1)?))
        .collect();
    lignes.iter().any(|m| {
        let (Some(local), Some(distante), Some(&"01")) = (m.get(1), m.get(2), m.get(3)) else {
            return false;
        };
        let Some(p) = port(local) else {
            return false;
        };
        p == "0016" || (ecoute.contains(&p) && !boucle_locale(distante.split(':').next().unwrap_or("")))
    })
}

/// Une adresse de /proc/net/tcp (127.0.0.0/8, octets à l'envers) ou tcp6 (::1, ou 127.x.x.x vue en IPv6) en hexadécimal.
fn boucle_locale(hex: &str) -> bool {
    let h = hex.to_ascii_uppercase();
    match h.len() {
        8 => h.ends_with("7F"),
        32 => {
            h == "00000000000000000000000001000000" || (h.starts_with("0000000000000000FFFF0000") && h.ends_with("7F"))
        }
        _ => false,
    }
}

fn avertissement_ssh(a: &dyn Acces, s: &mut dyn Services, quoi: &str) -> Option<String> {
    ssh_peut_etre_ouvert(a, s).then(|| {
        trf!(
            "une session SSH (ou une autre connexion venue d'ailleurs) est peut-être ouverte sur cet ordinateur (ou Vanguard ne peut pas dire le contraire). {quoi} Si vous êtes connecté de loin, répondez non et faites-le depuis l'écran de l'ordinateur.",
            "an SSH session (or another connection from elsewhere) may be open on this computer (or Vanguard cannot tell otherwise). {quoi} If you are connected from afar, answer no and do it from the computer's own screen."
        )
    })
}

fn regles_remises() -> &'static str {
    tr!(
        "Les règles remises peuvent refuser les nouvelles connexions SSH, ou couper celle en cours.",
        "The rules put back may refuse new SSH connections, or cut the current one."
    )
}

// ————— Textes de la question —————

/// La question de baisse (plan §2.0) : la ligne « allumé → COUPÉ », ce qui a été relu, ce qui protège encore, puis
/// la phrase qui demande si c'est bien la personne.
fn texte_baisse(p: PareFeu, details: &str) -> String {
    let nom = p.mot();
    let mut t = trf!("Pare-feu {nom} : allumé → COUPÉ.", "{nom} firewall: on → OFF.");
    if !details.is_empty() {
        t.push('\n');
        t.push_str(details);
    }
    t.push('\n');
    t.push_str(tr!(
        "Ce qui protège encore : le routeur de votre réseau, les programmes qui n'écoutent pas le réseau, et les blocages de Vanguard (ses propres tables, qui restent). Défaire, ou Rallumer dans les Options de défense, le remet comme avant.",
        "What still protects: your network's router, the programs that do not listen on the network, and Vanguard's blocks (its own tables, which stay). Undo, or Turn back on in the Defense options, puts it back as before."
    ));
    t.push('\n');
    t.push_str(tr!(
        "Ces changements rendent votre ordinateur MOINS protégé.\nLes avez-vous demandés vous-même, dans Vanguard, à l'instant ? Si ce n'est pas vous, répondez N.",
        "These changes make your computer LESS protected.\nDid you ask for them yourself, in Vanguard, just now? If it was not you, answer N."
    ));
    t
}

fn pas_recoupe() -> &'static str {
    tr!(
        "Vanguard ne le recoupera pas de lui-même ; pour le recouper : Options de défense.",
        "Vanguard will not turn it off again by itself; to turn it off again: Defense options."
    )
}

fn pas_installe(p: PareFeu) -> Echec {
    let nom = p.mot();
    refus(trf!(
        "{nom} n'est pas installé : rien n'est fait",
        "{nom} is not installed: nothing is done"
    ))
}

/// Deux pare-feu à la fois se marchent dessus (chacun réécrit les règles de l'autre) : allumer `p` est refusé tant
/// qu'un autre est allumé. Pour nftables, ufw ou firewalld allumé veut dire que c'est lui qui tient les règles.
fn autre_allume(p: PareFeu, a: &mut dyn Acces, s: &mut dyn Services) -> Result<(), Echec> {
    let deux = |autre: &str| {
        refus(trf!(
            "{autre} est allumé : deux pare-feu à la fois se marchent dessus. Rien n'est fait ; coupez d'abord {autre}, ou gardez-le",
            "{autre} is on: two firewalls at once get in each other's way. Nothing is done; turn {autre} off first, or keep it"
        ))
    };
    if p != PareFeu::Ufw && etat_ufw(a)?.is_some_and(|e| e.enabled || e.actif) {
        return Err(deux("ufw"));
    }
    if p != PareFeu::Firewalld && etat_unite(FIREWALLD, s)?.is_some_and(|e| unite_allumee(&e)) {
        return Err(deux("firewalld"));
    }
    Ok(())
}

// ————— Couper —————

pub(super) fn juger_couper(p: PareFeu, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    match p {
        PareFeu::Ufw => couper_ufw(a),
        PareFeu::Firewalld => couper_firewalld(s),
        PareFeu::Nftables => couper_nftables(a, s),
    }
}

fn couper_ufw(a: &mut dyn Acces) -> Jugement {
    let e = etat_ufw(a)?.ok_or_else(|| pas_installe(PareFeu::Ufw))?;
    match (e.enabled, e.actif) {
        (false, false) => return Ok(None),
        (true, true) => {}
        _ => {
            return Err(refus(tr!(
                "ufw est à moitié allumé (au démarrage seulement, ou maintenant seulement) : Vanguard ne saurait pas le remettre exactement. Rien n'est fait",
                "ufw is half on (at startup only, or right now only): Vanguard could not put it back exactly. Nothing is done"
            )));
        }
    }
    Ok(Some(Plan {
        texte: texte_baisse(
            PareFeu::Ufw,
            tr!(
                "ufw : allumé au démarrage (ENABLED=yes) et maintenant (Status: active) ; `ufw disable` le coupe, ses règles restent écrites.",
                "ufw: on at startup (ENABLED=yes) and now (Status: active); `ufw disable` turns it off, its rules stay written."
            ),
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: vec![
            ("enabled".into(), b"yes".to_vec()),
            ("actif".into(), b"active".to_vec()),
        ],
        action: Action::Outils(vec![("ufw", vec![os("disable")])]),
    }))
}

fn couper_firewalld(s: &mut dyn Services) -> Jugement {
    let e = etat_unite(FIREWALLD, s)?.ok_or_else(|| pas_installe(PareFeu::Firewalld))?;
    if !unite_allumee(&e) {
        return Ok(None);
    }
    let (etat_vu, activite_vue) = (echappe(e.0.as_bytes()), echappe(e.1.as_bytes()));
    Ok(Some(Plan {
        texte: texte_baisse(
            PareFeu::Firewalld,
            &trf!(
                "firewalld.service : {etat_vu}, {activite_vue} ; il est arrêté et n'est plus lancé au démarrage.",
                "firewalld.service: {etat_vu}, {activite_vue}; it is stopped and no longer started at startup."
            ),
        ),
        avertissement: None,
        non_annulable: false,
        seconde: None,
        champs: vec![("etat".into(), e.0.into_bytes()), ("activite".into(), e.1.into_bytes())],
        action: Action::UniteSysteme(ActionUnite::Desactiver, FIREWALLD),
    }))
}

/// Les tables de la personne (hors de Vanguard), après avoir vérifié que ni ufw ni firewalld ne tiennent les règles.
fn tables_de_la_personne(a: &mut dyn Acces, s: &mut dyn Services) -> Result<Vec<(String, String)>, Echec> {
    autre_allume(PareFeu::Nftables, a, s)?;
    let tables = lire_tables(a)?;
    if tables.iter().any(|(f, n)| f == "inet" && n == "firewalld") {
        return Err(refus(tr!(
            "la table de firewalld est là : c'est lui qui tient les règles. Rien n'est fait ; passez par firewalld",
            "firewalld's table is there: it holds the rules. Nothing is done; go through firewalld"
        )));
    }
    Ok(tables.into_iter().filter(|t| !de_vanguard(t)).collect())
}

fn script_de_retrait(tables: &[(String, String)]) -> String {
    tables.iter().fold(String::new(), |mut s, (f, n)| {
        let _ = writeln!(s, "delete table {f} {n}");
        s
    })
}

fn couper_nftables(a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let tables = tables_de_la_personne(a, s)?;
    let service = etat_unite(NFTABLES, s)?;
    let lance = service.as_ref().is_some_and(|e| lance_au_demarrage(&e.0));
    if tables.is_empty() && !lance {
        return Ok(None);
    }
    let sauve = sauvegarde(a, &tables)?;
    let mut actions = Vec::new();
    if !tables.is_empty() {
        actions.push(Action::Nft {
            contenu: sauve.clone().into_bytes(),
            appliquer: false,
        });
        actions.push(Action::Nft {
            contenu: script_de_retrait(&tables).into_bytes(),
            appliquer: true,
        });
    }
    if lance {
        actions.push(Action::UniteSysteme(ActionUnite::DesactiverSansArreter, NFTABLES));
    }
    let mut details = if tables.is_empty() {
        tr!(
            "nftables : aucune table à vous ; seul son lancement au démarrage est retiré.",
            "nftables: no table of yours; only its start at startup is removed."
        )
        .to_string()
    } else {
        let liste = liste_lisible(&tables);
        trf!(
            "Tables retirées, d'un bloc (gardées dans la note, vérifiées par nft -c) : {liste}.",
            "Tables removed, all at once (kept in the note, checked by nft -c): {liste}."
        )
    };
    if lance {
        details.push('\n');
        details.push_str(tr!(
            "nftables.service n'est plus lancé au démarrage ; il n'est pas arrêté (son arrêt viderait aussi les tables de Vanguard).",
            "nftables.service is no longer started at startup; it is not stopped (stopping it would also empty Vanguard's tables)."
        ));
    }
    let nat = tables.iter().any(|(_, n)| n.contains("nat"))
        || ["masquerade", "snat ", "dnat "].iter().any(|m| sauve.contains(m));
    if nat {
        details.push('\n');
        details.push_str(tr!(
            "Ces règles font de la traduction d'adresses (NAT) : elle sert souvent à Docker, à libvirt ou au partage de connexion. Les machines qui passent par elles perdent le réseau.",
            "These rules do address translation (NAT): it is often used by Docker, libvirt or connection sharing. The machines that go through them lose the network."
        ));
    }
    Ok(Some(Plan {
        texte: texte_baisse(PareFeu::Nftables, &details),
        avertissement: avertissement_ssh(
            a,
            s,
            tr!(
                "Retirer ces tables peut couper une connexion qui passe par elles (une redirection de port, un partage de connexion).",
                "Removing these tables may cut a connection going through them (a port forward, a shared connection)."
            ),
        ),
        non_annulable: false,
        seconde: None,
        champs: vec![
            ("tables".into(), tables_en_lignes(&tables).into_bytes()),
            ("sauvegarde".into(), sauve.into_bytes()),
            ("service".into(), service.map(|e| e.0).unwrap_or_default().into_bytes()),
        ],
        action: Action::Suite(actions),
    }))
}

fn tables_en_lignes(tables: &[(String, String)]) -> String {
    tables.iter().fold(String::new(), |mut s, (f, n)| {
        let _ = writeln!(s, "table {f} {n}");
        s
    })
}

/// Une sauvegarde de nftables passée par un fichier de root (0600) : vérifiée par `nft -c -f`, puis chargée si
/// `appliquer`, d'un bloc ; le fichier est retiré dans tous les cas. Un fichier resté là d'une fois d'avant est retiré
/// d'abord. Vérification refusée : rien n'est changé.
pub(super) fn nft_fichier(contenu: &[u8], appliquer: bool, a: &mut dyn Acces) -> Result<(), Echec> {
    let p = Path::new(FICHIER_NFT);
    if a.fiche(p).is_some() {
        a.retirer(p)?;
    }
    a.ecrire(
        p,
        contenu,
        Ecriture {
            mode: 0o600,
            uid: 0,
            gid: 0,
            avant: None,
        },
    )?;
    let fait = verifier_puis_charger(appliquer, a);
    let _ = a.retirer(p);
    fait
}

fn verifier_puis_charger(appliquer: bool, a: &mut dyn Acces) -> Result<(), Echec> {
    if let Err(e) = lancer_ok(a, "nft", &[os("-c"), os("-f"), os(FICHIER_NFT)]) {
        return Err(refus(trf!(
            "les règles de nftables ne se reliraient pas ({e}) : rien n'est changé",
            "the nftables rules would not load again ({e}): nothing is changed"
        )));
    }
    if appliquer {
        lancer_ok(a, "nft", &[os("-f"), os(FICHIER_NFT)])?;
    }
    Ok(())
}

// ————— Remettre (Défaire, ou Rallumer quand la note existe) —————

pub(super) fn remettre(p: PareFeu, note: &Note, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    match p {
        PareFeu::Ufw => remettre_ufw(note, a, s),
        PareFeu::Firewalld => remettre_firewalld(note, a, s),
        PareFeu::Nftables => remettre_nftables(note, a, s),
    }
}

fn remettre_ufw(note: &Note, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    if note.texte("enabled") != Some("yes") || note.texte("actif") != Some("active") {
        return Err(note_abimee());
    }
    let e = etat_ufw(a)?.ok_or_else(|| pas_installe(PareFeu::Ufw))?;
    if e.enabled && e.actif {
        return Ok(None);
    }
    autre_allume(PareFeu::Ufw, a, s)?;
    Ok(Some(Plan {
        texte: tr!(
            "Pare-feu ufw : COUPÉ → rallumé (ufw --force enable), au démarrage aussi.",
            "ufw firewall: OFF → back on (ufw --force enable), at startup too."
        )
        .to_string(),
        avertissement: avertissement_ssh(a, s, regles_remises()),
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Outils(vec![("ufw", vec![os("--force"), os("enable")])]),
    }))
}

/// Ce qui manque pour revenir à l'état d'avant d'une unité : `None` s'il est déjà au moins aussi allumé.
fn manque(lance_avant: bool, tourne_avant: bool, e: &(String, String)) -> Option<ActionUnite> {
    let (lance, en_marche) = (lance_au_demarrage(&e.0), tourne(&e.1));
    match (lance_avant && !lance, tourne_avant && !en_marche) {
        (true, true) => Some(ActionUnite::Activer),
        (true, false) => Some(ActionUnite::ActiverSansDemarrer),
        (false, true) => Some(ActionUnite::Demarrer),
        (false, false) => None,
    }
}

fn remettre_firewalld(note: &Note, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let (etat0, activite0) = (
        note.texte("etat").ok_or_else(note_abimee)?,
        note.texte("activite").ok_or_else(note_abimee)?,
    );
    if !s.systemd() {
        return Err(refus(sans_systemd()));
    }
    let e = etat_unite(FIREWALLD, s)?.ok_or_else(|| pas_installe(PareFeu::Firewalld))?;
    let Some(action) = manque(lance_au_demarrage(etat0), tourne(activite0), &e) else {
        return Ok(None);
    };
    autre_allume(PareFeu::Firewalld, a, s)?;
    Ok(Some(Plan {
        texte: tr!(
            "Pare-feu firewalld : COUPÉ → remis comme avant.",
            "firewalld firewall: OFF → put back as before."
        )
        .to_string(),
        avertissement: if action == ActionUnite::ActiverSansDemarrer {
            None
        } else {
            avertissement_ssh(a, s, regles_remises())
        },
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::UniteSysteme(action, FIREWALLD),
    }))
}

fn remettre_nftables(note: &Note, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let tables0 = note.texte("tables").and_then(tables_de).ok_or_else(note_abimee)?;
    let sauve = note.champ("sauvegarde").ok_or_else(note_abimee)?;
    let service0 = note.texte("service").ok_or_else(note_abimee)?;
    if tables0.iter().any(de_vanguard) || tables0.is_empty() != sauve.is_empty() {
        return Err(note_abimee());
    }
    let tables = tables_de_la_personne(a, s)?;
    let la = tables0.iter().filter(|t| tables.contains(t)).count();
    if la > 0 && la < tables0.len() {
        return Err(change_depuis(tr!("les tables de nftables", "the nftables tables")));
    }
    let remettre_tables = la == 0 && !tables0.is_empty();
    let service = etat_unite(NFTABLES, s)?;
    let relancer = lance_au_demarrage(service0) && !service.as_ref().is_some_and(|e| lance_au_demarrage(&e.0));
    if !remettre_tables && !relancer {
        return Ok(None);
    }
    if relancer && service.is_none() {
        return Err(refus(tr!(
            "nftables.service n'est plus là (ou systemd manque) : rien n'est remis",
            "nftables.service is no longer there (or systemd is missing): nothing is put back"
        )));
    }
    let mut actions = Vec::new();
    let mut texte = Vec::new();
    if remettre_tables {
        actions.push(Action::Nft {
            contenu: sauve.to_vec(),
            appliquer: true,
        });
        let liste = liste_lisible(&tables0);
        texte.push(trf!(
            "Pare-feu nftables : COUPÉ → tables remises, d'un bloc, après vérification (nft -c) : {liste}.",
            "nftables firewall: OFF → tables put back, all at once, after checking (nft -c): {liste}."
        ));
    }
    if relancer {
        actions.push(Action::UniteSysteme(ActionUnite::ActiverSansDemarrer, NFTABLES));
        texte.push(
            tr!(
                "nftables.service est de nouveau lancé au démarrage (sans être relancé maintenant).",
                "nftables.service is started at startup again (without being restarted now)."
            )
            .to_string(),
        );
    }
    Ok(Some(Plan {
        texte: texte.join("\n"),
        avertissement: if remettre_tables {
            avertissement_ssh(a, s, regles_remises())
        } else {
            None
        },
        non_annulable: false,
        seconde: None,
        champs: Vec::new(),
        action: Action::Suite(actions),
    }))
}

/// La note d'une coupure de `p` trouvée là au moment d'en faire une : `Ok(true)` si elle est périmée (le pare-feu a
/// été rallumé hors de Vanguard, il est déjà comme avant la coupure : elle peut être retirée), `Ok(false)` s'il est
/// encore coupé par ce choix.
pub(super) fn note_perimee(p: PareFeu, octets: &[u8], a: &mut dyn Acces, s: &mut dyn Services) -> Result<bool, Echec> {
    let id = p.note();
    let note = Note::lire(id.as_str(), octets).ok_or_else(note_abimee)?;
    if note.geste != GesteUnix::Defense(Defense::CouperPareFeu(p), id).ligne() {
        return Err(note_abimee());
    }
    Ok(remettre(p, &note, a, s)?.is_none())
}

// ————— Rallumer (sans note : renforcement, non annulable) —————

pub(super) fn juger_rallumer(p: PareFeu, a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    if a.note_lire(p.note())?.is_some() {
        return Err(refus(tr!(
            "ce pare-feu est coupé par votre choix, noté : Rallumer passe par cette note (Options de défense), pour le remettre exactement comme avant. Rien n'est fait",
            "this firewall is off by your choice, noted: Turn back on goes through that note (Defense options), to put it back exactly as before. Nothing is done"
        )));
    }
    match p {
        PareFeu::Ufw => rallumer_ufw(a, s),
        PareFeu::Firewalld => rallumer_firewalld(a, s),
        PareFeu::Nftables => rallumer_nftables(a, s),
    }
}

/// Les règles ajoutées d'ufw (`ufw show added`), échappées, `REGLES_MONTREES` au plus ; et si l'une semble ouvrir SSH.
fn regles_ufw(a: &mut dyn Acces) -> (String, bool) {
    let Some(r) = a
        .lancer("ufw", &[os("show"), os("added")])
        .filter(|r| r.code == Some(0))
    else {
        return (String::new(), false);
    };
    let regles: Vec<&str> = r.sortie.lines().skip(1).filter(|l| !l.trim().is_empty()).collect();
    let ssh = regles.iter().any(|l| {
        l.contains("allow")
            && l.split([' ', '/'])
                .any(|m| m == "22" || m.eq_ignore_ascii_case("openssh") || m == "ssh")
    });
    let mut t: Vec<String> = regles
        .iter()
        .take(REGLES_MONTREES)
        .map(|l| format!("  {}", echappe(l.as_bytes())))
        .collect();
    if regles.len() > REGLES_MONTREES {
        t.push(format!("  … (+{})", regles.len().saturating_sub(REGLES_MONTREES)));
    }
    (t.join("\n"), ssh)
}

fn rallumer_ufw(a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let e = etat_ufw(a)?.ok_or_else(|| pas_installe(PareFeu::Ufw))?;
    if e.enabled && e.actif {
        return Ok(None);
    }
    autre_allume(PareFeu::Ufw, a, s)?;
    let (regles, ssh_ouvert) = regles_ufw(a);
    let mut texte = tr!(
        "Pare-feu ufw : coupé → ALLUMÉ (ufw --force enable), au démarrage aussi.",
        "ufw firewall: off → ON (ufw --force enable), at startup too."
    )
    .to_string();
    if regles.is_empty() {
        texte.push('\n');
        texte.push_str(tr!(
            "Aucune règle ajoutée : tout ce qui entre est refusé, sauf ce qui répond à vos propres connexions.",
            "No added rule: everything coming in is refused, except replies to your own connections."
        ));
    } else {
        texte.push('\n');
        texte.push_str(tr!("Règles ajoutées d'ufw :", "ufw's added rules:"));
        texte.push('\n');
        texte.push_str(&regles);
    }
    texte.push('\n');
    texte.push_str(pas_recoupe());
    let quoi = if ssh_ouvert {
        regles_remises()
    } else {
        tr!(
            "Aucune règle d'ufw ne semble ouvrir SSH (22/tcp, OpenSSH) : les nouvelles connexions SSH seront refusées.",
            "No ufw rule seems to open SSH (22/tcp, OpenSSH): new SSH connections will be refused."
        )
    };
    Ok(Some(Plan {
        texte,
        avertissement: avertissement_ssh(a, s, quoi),
        non_annulable: true,
        seconde: None,
        champs: Vec::new(),
        action: Action::Outils(vec![("ufw", vec![os("--force"), os("enable")])]),
    }))
}

fn rallumer_firewalld(a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let e = etat_unite(FIREWALLD, s)?.ok_or_else(|| pas_installe(PareFeu::Firewalld))?;
    if e.0.starts_with("masked") {
        return Err(refus(tr!(
            "firewalld est masqué (systemctl mask) : Vanguard ne le démasque pas. Rien n'est fait",
            "firewalld is masked (systemctl mask): Vanguard does not unmask it. Nothing is done"
        )));
    }
    let Some(action) = manque(true, true, &e) else {
        return Ok(None);
    };
    autre_allume(PareFeu::Firewalld, a, s)?;
    Ok(Some(Plan {
        texte: format!(
            "{}\n{}",
            tr!(
                "Pare-feu firewalld : coupé → ALLUMÉ, au démarrage aussi (sa zone par défaut s'applique).",
                "firewalld firewall: off → ON, at startup too (its default zone applies)."
            ),
            pas_recoupe()
        ),
        avertissement: avertissement_ssh(a, s, regles_remises()),
        non_annulable: true,
        seconde: None,
        champs: Vec::new(),
        action: Action::UniteSysteme(action, FIREWALLD),
    }))
}

fn rallumer_nftables(a: &mut dyn Acces, s: &mut dyn Services) -> Jugement {
    let tables = tables_de_la_personne(a, s)?;
    let e = etat_unite(NFTABLES, s)?.ok_or_else(|| {
        refus(tr!(
            "nftables.service n'est pas installé : Vanguard ne sait pas quelles règles charger. Rien n'est fait",
            "nftables.service is not installed: Vanguard does not know which rules to load. Nothing is done"
        ))
    })?;
    let lance = lance_au_demarrage(&e.0);
    if !tables.is_empty() && lance {
        return Ok(None);
    }
    if e.0.starts_with("masked") {
        return Err(refus(tr!(
            "nftables.service est masqué (systemctl mask) : Vanguard ne le démasque pas. Rien n'est fait",
            "nftables.service is masked (systemctl mask): Vanguard does not unmask it. Nothing is done"
        )));
    }
    let mut actions = Vec::new();
    if !lance {
        actions.push(Action::UniteSysteme(ActionUnite::ActiverSansDemarrer, NFTABLES));
    }
    let charger = tables.is_empty();
    if charger {
        // Charger la configuration du système commence d'ordinaire par vider toutes les règles (`flush ruleset`) :
        // les blocages de Vanguard partiraient avec.
        let presentes = lire_tables(a)?;
        let a_lui = |nom: &str| presentes.iter().any(|t| de_vanguard(t) && t.1 == nom);
        let quoi = match (a_lui("vanguard"), a_lui("vanguard_public")) {
            (false, false) => None,
            (true, false) => Some(tr!(
                "les blocages de Vanguard sont en place (table inet vanguard) : charger la configuration de nftables les viderait. Rien n'est fait ; levez-les d'abord, ou rallumez nftables après",
                "Vanguard's blocks are in place (table inet vanguard): loading the nftables configuration would empty them. Nothing is done; lift them first, or turn nftables back on afterwards"
            )),
            (false, true) => Some(tr!(
                "le mode Wi-Fi public de Vanguard est en place (table inet vanguard_public) : charger la configuration de nftables le viderait. Rien n'est fait ; sortez du mode Wi-Fi public d'abord, ou rallumez nftables après",
                "Vanguard's public Wi-Fi mode is on (table inet vanguard_public): loading the nftables configuration would empty it. Nothing is done; leave public Wi-Fi mode first, or turn nftables back on afterwards"
            )),
            (true, true) => Some(tr!(
                "les blocages et le mode Wi-Fi public de Vanguard sont en place (tables inet vanguard et inet vanguard_public) : charger la configuration de nftables les viderait. Rien n'est fait ; levez les blocages et sortez du mode Wi-Fi public d'abord, ou rallumez nftables après",
                "Vanguard's blocks and public Wi-Fi mode are on (tables inet vanguard and inet vanguard_public): loading the nftables configuration would empty them. Nothing is done; lift the blocks and leave public Wi-Fi mode first, or turn nftables back on afterwards"
            )),
        };
        if let Some(q) = quoi {
            return Err(refus(q));
        }
        actions.push(Action::UniteSysteme(
            if tourne(&e.1) {
                ActionUnite::Redemarrer
            } else {
                ActionUnite::Demarrer
            },
            NFTABLES,
        ));
    }
    let mut texte = if charger {
        tr!(
            "Pare-feu nftables : coupé → ALLUMÉ : la configuration de nftables du système est chargée (nftables.service), au démarrage aussi.",
            "nftables firewall: off → ON: the system's nftables configuration is loaded (nftables.service), at startup too."
        )
    } else {
        tr!(
            "Pare-feu nftables : ses tables sont là ; nftables.service est de nouveau lancé au démarrage.",
            "nftables firewall: its tables are there; nftables.service is started at startup again."
        )
    }
    .to_string();
    texte.push('\n');
    texte.push_str(pas_recoupe());
    Ok(Some(Plan {
        texte,
        avertissement: if charger {
            avertissement_ssh(a, s, regles_remises())
        } else {
            None
        },
        non_annulable: true,
        seconde: None,
        champs: Vec::new(),
        action: Action::Suite(actions),
    }))
}
