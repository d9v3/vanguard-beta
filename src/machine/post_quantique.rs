//! Bilan post-quantique, en lecture seule : le serveur SSH (COM-PQC-001), le client SSH (COM-PQC-002) et les
//! tunnels WireGuard (COM-PQC-003). Un trafic chiffré capté aujourd'hui se garde et se lira le jour où un
//! ordinateur quantique assez gros existera (« enregistrer maintenant, déchiffrer plus tard ») : seul un échange de
//! clés post-quantique fait aujourd'hui le protège. Rien n'est changé ici : chaque constat dit ce qui manque et
//! comment le corriger soi-même ; ce qui ne se lit pas est « non vérifié », avec sa raison, jamais « sain ».
//!
//! Le jugement (fonctions `juger_*`, lecteurs de fichiers) est commun et se teste sur des valeurs inventées ; seule
//! la lecture dépend du système. Aucun programme n'est lancé : ni « sshd -T », ni « wg show » (il afficherait les
//! clés en clair, et c'est un programme tiers lancé en administrateur).

use super::{Constat, alerte, impossible_par, ok, sans_objet};
use crate::machine::regles::{Os, regle};
use crate::machine::sshd::{kex_post_quantique, liste_qui_retire, noms_a_ajouter, premiere_valeur};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;
use crate::ui::affichable;
use crate::{tr, trf};

/// Une catégorie à part : le rapport regroupe ce qui touche au post-quantique.
pub(crate) const CAT: &str = "Post-quantique";

regle!(
    "COM-PQC-001",
    Os::Tous,
    750,
    (
        "échange de clés post-quantique du serveur SSH",
        "SSH server post-quantum key exchange"
    ),
    &[
        "ANSSI, Recommandations pour un usage sécurisé d'(Open)SSH",
        "OpenSSH : Post-Quantum Cryptography (openssh.org/pq.html)"
    ],
    || vec![juger_serveur(&lire_serveur())]
);

regle!(
    "COM-PQC-002",
    Os::Tous,
    751,
    (
        "échange de clés post-quantique du client SSH",
        "SSH client post-quantum key exchange"
    ),
    &[
        "ANSSI, Recommandations pour un usage sécurisé d'(Open)SSH",
        "OpenSSH : Post-Quantum Cryptography (openssh.org/pq.html)"
    ],
    || juger_client(&lire_client())
);

regle!(
    "COM-PQC-003",
    Os::Tous,
    752,
    (
        "clé pré-partagée des tunnels WireGuard",
        "pre-shared key of WireGuard tunnels"
    ),
    &[
        "CIS Controls v8 3.10",
        "WireGuard : Protocol & Cryptography (wireguard.com/protocol)"
    ],
    || juger_wireguard(&lire_wireguard())
);

/// Ce qu'une lecture a donné : rien à juger (absence prouvée), illisible (avec sa raison), ou lu.
#[derive(Debug)]
pub(crate) enum Lecture<T> {
    Absent(Absence),
    Illisible(Raison),
    Lu(T),
}

// ── Serveur SSH ──

/// La configuration de sshd dans son ordre de lecture (fichier, partie qui vaut pour toutes les connexions), le
/// fichier principal en dernier, et la version d'OpenSSH quand elle se lit.
#[derive(Debug)]
pub(crate) struct Serveur {
    pub segments: Vec<(String, String)>,
    pub version: Option<(u32, u32)>,
}

fn version_texte(v: Option<(u32, u32)>) -> String {
    v.map_or_else(|| "?".to_string(), |(a, b)| format!("{a}.{b}"))
}

/// Comment mettre les noms post-quantiques dans la ligne KexAlgorithms écrite (`valeur`) sans la casser : un nom
/// placé devant un « + », un « - » ou un « ^ » en fait un nom inconnu, et sshd refuse alors de redémarrer. Sans
/// ligne, un « + » : une liste nue remplacerait toutes les valeurs par défaut. `None` : version trop vieille.
fn ajout_pq(valeur: Option<&str>, version: Option<(u32, u32)>) -> Option<String> {
    let noms = noms_a_ajouter(version)?;
    let valeur = valeur.map(str::trim).filter(|v| !v.is_empty());
    Some(match valeur.map(str::as_bytes) {
        None => trf!(
            "ajouter la ligne « KexAlgorithms +{noms} »",
            "add the line “KexAlgorithms +{noms}”"
        ),
        Some([b'+' | b'^', ..]) => trf!(
            "ajouter « ,{noms} » à la fin de la ligne KexAlgorithms",
            "add “,{noms}” at the end of the KexAlgorithms line"
        ),
        Some([b'-', ..]) if liste_qui_retire(valeur, version) => tr!(
            "retirer de la ligne KexAlgorithms « - » les noms qui contiennent mlkem ou sntrup",
            "remove from the KexAlgorithms “-” line the names that contain mlkem or sntrup"
        )
        .to_string(),
        Some([b'-', ..]) => trf!(
            "remplacer la ligne KexAlgorithms « - », qui ne peut rien ajouter, par une liste complète qui commence par {noms}",
            "replace the KexAlgorithms “-” line, which cannot add anything, with a full list that starts with {noms}"
        ),
        Some(_) => trf!(
            "mettre {noms} en tête de la ligne KexAlgorithms",
            "put {noms} at the start of the KexAlgorithms line"
        ),
    })
}

/// Ce qu'il faut faire soi-même pour un sshd sans échange post-quantique, selon sa version et la ligne écrite :
/// jamais un nom qu'elle ne connaît pas.
fn conseil_serveur(valeur: Option<&str>, version: Option<(u32, u32)>) -> String {
    match ajout_pq(valeur, version) {
        Some(ajout) => trf!(
            "{} ; vérifier par « sshd -t » avant de relancer sshd, et garder une session ouverte pendant l'essai",
            "{}; check with “sshd -t” before restarting sshd, and keep a session open during the test",
            majuscule(&ajout)
        ),
        None => tr!(
            "Mettre OpenSSH à jour (8.5 au moins, 9.0 pour l'avoir par défaut), puis vérifier par « sshd -t » avant de relancer, en gardant une session ouverte",
            "Update OpenSSH (8.5 at least, 9.0 to have it by default), then check with “sshd -t” before restarting, keeping a session open"
        )
        .to_string(),
    }
}

fn majuscule(texte: &str) -> String {
    let mut c = texte.chars();
    c.next()
        .map_or_else(String::new, |p| p.to_uppercase().chain(c).collect())
}

/// La raison pour laquelle aucun échange post-quantique n'est proposé : la liste écrite, ou la version.
fn raison_sans_pq(valeur: Option<&str>, fichier: &str, version: Option<(u32, u32)>) -> String {
    if liste_qui_retire(valeur, version) {
        return trf!(
            "la liste KexAlgorithms de {fichier} les retire",
            "the KexAlgorithms list in {fichier} removes them"
        );
    }
    let v = version_texte(version);
    if version.is_some_and(|v| v < (8, 5)) {
        trf!(
            "OpenSSH {v}, trop vieux : il en faut 8.5 ou plus (9.0 pour l'avoir par défaut)",
            "OpenSSH {v}, too old: 8.5 or later is needed (9.0 to have it by default)"
        )
    } else {
        trf!(
            "OpenSSH {v} : pas proposé par défaut sur cette version, et la configuration ne l'ajoute pas",
            "OpenSSH {v}: not offered by default on this version, and the configuration does not add it"
        )
    }
}

pub(crate) fn juger_serveur(l: &Lecture<Serveur>) -> Constat {
    let s = match l {
        Lecture::Absent(a) => {
            return sans_objet(
                CAT,
                *a,
                tr!(
                    "Aucun serveur SSH ne reçoit de connexions : rien à juger pour l'échange post-quantique.",
                    "No SSH server receives connections: nothing to judge for post-quantum key exchange."
                ),
            )
            .avec_objet(Objet::Seul);
        }
        Lecture::Illisible(r) => {
            return impossible_par(
                CAT,
                r.clone(),
                trf!(
                    "Serveur SSH : échange de clés post-quantique non vérifié ({}).",
                    "SSH server: post-quantum key exchange not checked ({}).",
                    r.texte()
                ),
            )
            .avec_objet(Objet::Seul);
        }
        Lecture::Lu(s) => s,
    };
    let ecrit = premiere_valeur(&s.segments, &["kexalgorithms"]);
    let valeur = ecrit.map(|(_, _, v)| v);
    let fichier = ecrit
        .and_then(|(i, _, _)| s.segments.get(i))
        .or(s.segments.last())
        .map_or("sshd_config", |(f, _)| f.as_str());
    let objet = Objet::de("sshd", fichier);
    let fichier = affichable(fichier);
    let v = version_texte(s.version);
    match kex_post_quantique(valeur, s.version) {
        Some(true) => ok(
            CAT,
            trf!(
                "Serveur SSH (OpenSSH {v}) : un échange de clés post-quantique est proposé aux clients.",
                "SSH server (OpenSSH {v}): a post-quantum key exchange is offered to clients."
            ),
        ),
        Some(false) => alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Serveur SSH : aucun échange de clés post-quantique ({}). Une session captée aujourd'hui pourrait être déchiffrée le jour où un ordinateur quantique existera.",
                "SSH server: no post-quantum key exchange ({}). A session recorded today could be decrypted once a quantum computer exists.",
                raison_sans_pq(valeur, &fichier, s.version)
            ),
        )
        .manuel(conseil_serveur(valeur, s.version), &[]),
        None => impossible_par(
            CAT,
            Raison::Illisible(tr!("version d'OpenSSH", "OpenSSH version").into()),
            tr!(
                "Serveur SSH : version d'OpenSSH illisible ; la liste d'échanges de clés en dépend, rien n'est conclu.",
                "SSH server: OpenSSH version unreadable; the key exchange list depends on it, nothing is concluded."
            ),
        ),
    }
    .avec_objet(objet)
}

// ── Client SSH ──

/// La configuration du client : chaque fichier de tête (celui du compte, puis celui du système) avec ses fichiers
/// inclus dépliés à leur place (fichier montré, numéro de ligne, ligne), et la version d'OpenSSH.
#[derive(Debug)]
pub(crate) struct Client {
    pub fichiers: Vec<Vec<(String, usize, String)>>,
    pub version: Option<(u32, u32)>,
}

/// Ce que la configuration du client dit de l'échange de clés.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ConfigClient {
    /// La première liste KexAlgorithms qui vaut pour tous les serveurs : (fichier, valeur). ssh garde la première.
    pub globale: Option<(String, String)>,
    /// Les listes écrites sous un « Host » ou un « Match » précis : jamais le nom de l'hôte, seulement la liste.
    pub par_hote: Vec<String>,
    /// Le fichier où « WarnWeakCrypto no » vaut pour tous les serveurs.
    pub avertissement_coupe: Option<String>,
}

/// Lit la configuration du client comme ssh : un « Host » qui ne nomme que « * » et « Match all » valent pour tous
/// les serveurs, comme le début de chaque fichier de tête ; la première valeur trouvée l'emporte.
pub(crate) fn lire_config_client(fichiers: &[Vec<(String, usize, String)>]) -> ConfigClient {
    let mut c = ConfigClient::default();
    let mut avertissement_vu = false;
    for lignes in fichiers {
        let mut global = true;
        for (fichier, _, ligne) in lignes {
            let ligne = ligne.split('#').next().unwrap_or_default().trim();
            let (cle, valeur) = ligne
                .split_once(|c: char| c.is_whitespace() || c == '=')
                .map_or((ligne, ""), |(c, v)| {
                    (c, v.trim_start_matches(|c: char| c.is_whitespace() || c == '='))
                });
            let valeur = valeur.trim().trim_matches('"');
            match cle.to_ascii_lowercase().as_str() {
                "host" => global = valeur.split_whitespace().all(|m| m == "*"),
                "match" => global = valeur.eq_ignore_ascii_case("all"),
                "kexalgorithms" if global => {
                    if c.globale.is_none() {
                        c.globale = Some((fichier.clone(), valeur.to_string()));
                    }
                }
                "kexalgorithms" => c.par_hote.push(valeur.to_string()),
                "warnweakcrypto" if global && !avertissement_vu => {
                    avertissement_vu = true;
                    if valeur.eq_ignore_ascii_case("no") {
                        c.avertissement_coupe = Some(fichier.clone());
                    }
                }
                _ => {}
            }
        }
    }
    c
}

/// Retirer la ligne ne suffit que si la version propose le post-quantique par défaut.
fn conseil_client(valeur: Option<&str>, version: Option<(u32, u32)>) -> String {
    let par_defaut = kex_post_quantique(None, version) == Some(true);
    match ajout_pq(valeur, version) {
        Some(ajout) if par_defaut && valeur.is_some() => trf!(
            "Retirer cette ligne KexAlgorithms, ou {ajout}",
            "Remove this KexAlgorithms line, or {ajout}"
        ),
        Some(ajout) => majuscule(&ajout),
        None => tr!(
            "Mettre OpenSSH à jour (8.5 au moins, 9.0 pour l'avoir par défaut)",
            "Update OpenSSH (8.5 at least, 9.0 to have it by default)"
        )
        .to_string(),
    }
}

pub(crate) fn juger_client(l: &Lecture<Client>) -> Vec<Constat> {
    let c = match l {
        Lecture::Absent(a) => {
            return vec![
                sans_objet(
                    CAT,
                    *a,
                    tr!(
                        "Pas de client OpenSSH sur cet ordinateur : rien à juger pour l'échange post-quantique.",
                        "No OpenSSH client on this computer: nothing to judge for post-quantum key exchange."
                    ),
                )
                .avec_objet(Objet::Seul),
            ];
        }
        Lecture::Illisible(r) => {
            return vec![
                impossible_par(
                    CAT,
                    r.clone(),
                    trf!(
                        "Client SSH : échange de clés post-quantique non vérifié ({}).",
                        "SSH client: post-quantum key exchange not checked ({}).",
                        r.texte()
                    ),
                )
                .avec_objet(Objet::Seul),
            ];
        }
        Lecture::Lu(c) => c,
    };
    let config = lire_config_client(&c.fichiers);
    let v = version_texte(c.version);
    let mut constats = Vec::new();
    let valeur = config.globale.as_ref().map(|(_, v)| v.as_str());
    let fichier = config.globale.as_ref().map(|(f, _)| f.as_str());
    let objet = Objet::de("ssh", fichier.unwrap_or("defaut"));
    constats.push(
        match kex_post_quantique(valeur, c.version) {
            Some(true) => ok(
                CAT,
                trf!(
                    "Client SSH (OpenSSH {v}) : un échange de clés post-quantique est proposé aux serveurs.",
                    "SSH client (OpenSSH {v}): a post-quantum key exchange is offered to servers."
                ),
            ),
            Some(false) if liste_qui_retire(valeur, c.version) => {
                let fichier = affichable(fichier.unwrap_or_default());
                alerte(
                    CAT,
                    Niveau::Info,
                    trf!(
                        "Client SSH : la configuration {fichier} écarte l'échange post-quantique pour tous les serveurs. Une session captée aujourd'hui pourrait être déchiffrée le jour où un ordinateur quantique existera.",
                        "SSH client: the {fichier} configuration rules out post-quantum key exchange for every server. A session recorded today could be decrypted once a quantum computer exists."
                    ),
                )
                .manuel(conseil_client(valeur, c.version), &[])
            }
            Some(false) => alerte(
                CAT,
                Niveau::Info,
                trf!(
                    "Client SSH : aucun échange de clés post-quantique ({}).",
                    "SSH client: no post-quantum key exchange ({}).",
                    raison_sans_pq(valeur, "", c.version)
                ),
            )
            .manuel(conseil_client(valeur, c.version), &[]),
            None => impossible_par(
                CAT,
                Raison::Illisible(tr!("version d'OpenSSH", "OpenSSH version").into()),
                tr!(
                    "Client SSH : version d'OpenSSH illisible ; la liste d'échanges de clés en dépend, rien n'est conclu.",
                    "SSH client: OpenSSH version unreadable; the key exchange list depends on it, nothing is concluded."
                ),
            ),
        }
        .avec_objet(objet),
    );
    let sans: usize = config
        .par_hote
        .iter()
        .filter(|l| kex_post_quantique(Some(l), c.version) == Some(false))
        .count();
    if sans > 0 {
        // Souvent voulu (un vieil appareil qui ne connaît rien d'autre) : une information, sans le nom de l'hôte.
        constats.push(
            alerte(
                CAT,
                Niveau::Info,
                trf!(
                    "Client SSH : {sans} réglage(s) pour un hôte précis écartent l'échange post-quantique (souvent voulu pour un vieil appareil qui ne connaît rien d'autre).",
                    "SSH client: {sans} setting(s) for a specific host rule out post-quantum key exchange (often wanted for an old device that knows nothing else)."
                ),
            )
            .avec_objet(Objet::de("ssh", "hotes")),
        );
    }
    if let Some(f) = &config.avertissement_coupe {
        let f = affichable(f);
        constats.push(
            alerte(
                CAT,
                Niveau::Info,
                trf!(
                    "Client SSH : « WarnWeakCrypto no » dans {f} cache l'avertissement d'OpenSSH sur les connexions sans échange post-quantique.",
                    "SSH client: “WarnWeakCrypto no” in {f} hides OpenSSH's warning about connections without post-quantum key exchange."
                ),
            )
            .manuel(
                tr!(
                    "Retirer cette ligne, ou la réserver aux vieux appareils sous leur propre « Host »",
                    "Remove this line, or keep it for old devices under their own “Host”"
                ),
                &[],
            )
            .avec_objet(Objet::de("ssh", "warnweakcrypto")),
        );
    }
    constats
}

// ── WireGuard ──

/// Les pairs d'un tunnel, comptés (jamais leurs clés).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pairs {
    pub total: usize,
    /// Sans clé pré-partagée.
    pub sans: usize,
    /// Clé gardée ailleurs (agent de NetworkManager, non enregistrée) : on ne sait pas.
    pub inconnus: usize,
}

/// Ce qui se sait d'un tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
pub(crate) enum Tunnel {
    Lu(Pairs),
    /// Aucun fichier ne le décrit : une application VPN (Mullvad, Proton…) ou « wg set » le règle elle-même,
    /// parfois avec une clé post-quantique éphémère.
    SansFichier,
    /// Le fichier est là mais ne se lit pas (droits).
    Illisible(Raison),
}

/// Les sections d'un fichier de type INI, en ordre : (nom de section en minuscules, lignes clé = valeur).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
fn sections(texte: &str) -> Vec<(String, Vec<(String, &str)>)> {
    let mut s: Vec<(String, Vec<(String, &str)>)> = Vec::new();
    for ligne in texte.lines() {
        let ligne = ligne.trim();
        if ligne.starts_with(['#', ';']) || ligne.is_empty() {
            continue;
        }
        if let Some(nom) = ligne.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            s.push((nom.trim().to_ascii_lowercase(), Vec::new()));
        } else if let (Some((cle, valeur)), Some(dernier)) = (ligne.split_once('='), s.last_mut()) {
            dernier.1.push((cle.trim().to_ascii_lowercase(), valeur.trim()));
        }
    }
    s
}

/// Une valeur non vide sous cette clé.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
fn a_valeur(lignes: &[(String, &str)], cle: &str) -> bool {
    lignes.iter().any(|(k, v)| k == cle && !v.is_empty())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
fn valeur<'a>(lignes: &[(String, &'a str)], cle: &str) -> Option<&'a str> {
    lignes.iter().find(|(k, _)| k == cle).map(|(_, v)| *v)
}

/// Un fichier de wg-quick (`/etc/wireguard/<nom>.conf`) : une section `[Peer]` par pair, PresharedKey facultative.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
pub(crate) fn pairs_wg_quick(texte: &str) -> Pairs {
    let mut p = Pairs::default();
    for (nom, lignes) in sections(texte) {
        if nom == "peer" {
            p.total += 1;
            if !a_valeur(&lignes, "presharedkey") {
                p.sans += 1;
            }
        }
    }
    p
}

/// Un profil de NetworkManager : (interface, pairs) s'il est de type wireguard. « preshared-key-flags » : 0 (ou
/// absent) la clé est dans le fichier, 4 aucune n'est demandée ; un autre drapeau la garde ailleurs (agent du
/// trousseau, non enregistrée) : on ne sait pas, jamais « absente ».
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
pub(crate) fn pairs_networkmanager(texte: &str) -> Option<(String, Pairs)> {
    let s = sections(texte);
    let connexion = s.iter().find(|(n, _)| n == "connection")?;
    if !valeur(&connexion.1, "type").is_some_and(|t| t.eq_ignore_ascii_case("wireguard")) {
        return None;
    }
    let interface = valeur(&connexion.1, "interface-name")
        .or_else(|| valeur(&connexion.1, "id"))?
        .to_string();
    let mut p = Pairs::default();
    for (nom, lignes) in &s {
        if nom.starts_with("wireguard-peer.") {
            p.total += 1;
            if a_valeur(lignes, "preshared-key") {
                continue;
            }
            match valeur(lignes, "preshared-key-flags").map(str::trim) {
                None | Some("0" | "4") => p.sans += 1,
                Some(_) => p.inconnus += 1,
            }
        }
    }
    Some((interface, p))
}

/// Un fichier .netdev de systemd-networkd : (interface, pairs) s'il décrit un WireGuard. La clé peut aussi être
/// dans un fichier à part (PresharedKeyFile=).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
pub(crate) fn pairs_netdev(texte: &str) -> Option<(String, Pairs)> {
    let s = sections(texte);
    let netdev = s.iter().find(|(n, _)| n == "netdev")?;
    if !valeur(&netdev.1, "kind").is_some_and(|k| k.eq_ignore_ascii_case("wireguard")) {
        return None;
    }
    let interface = valeur(&netdev.1, "name")?.to_string();
    let mut p = Pairs::default();
    for (nom, lignes) in &s {
        if nom == "wireguardpeer" {
            p.total += 1;
            if !a_valeur(lignes, "presharedkey") && !a_valeur(lignes, "presharedkeyfile") {
                p.sans += 1;
            }
        }
    }
    Some((interface, p))
}

/// Ce que le bilan sait de WireGuard sur cet ordinateur.
#[derive(Debug)]
pub(crate) enum Wireguard {
    /// Aucun tunnel en marche, ou rien d'installé.
    Aucun(Absence),
    /// Les tunnels en marche (nom de l'interface) et ce qui s'en sait.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Tunnels(Vec<(String, Tunnel)>),
    /// Présent, mais rangé là où Vanguard ne lit pas (configurations chiffrées pour SYSTEM, trousseau de macOS) :
    /// la raison.
    #[cfg_attr(target_os = "linux", allow(dead_code))] // Windows et macOS
    Hors(String),
}

fn conseil_wireguard() -> &'static str {
    tr!(
        "Générer une clé pré-partagée par pair (wg genpsk), l'échanger hors ligne (passée par un canal lui-même sans post-quantique, elle ne protège rien) et l'ajouter des deux côtés (PresharedKey)",
        "Generate one pre-shared key per peer (wg genpsk), exchange it offline (sent over a channel that is itself not post-quantum, it protects nothing) and add it on both sides (PresharedKey)"
    )
}

pub(crate) fn juger_wireguard(w: &Wireguard) -> Vec<Constat> {
    match w {
        Wireguard::Aucun(a) => vec![sans_objet(
            CAT,
            *a,
            tr!(
                "Aucun tunnel WireGuard en marche : rien à juger.",
                "No WireGuard tunnel running: nothing to judge."
            ),
        )
        .avec_objet(Objet::Seul)],
        Wireguard::Hors(raison) => vec![impossible_par(
            CAT,
            Raison::Refuse(raison.clone()),
            trf!(
                "WireGuard : clé pré-partagée non vérifiée ({raison}). Sans elle, un tunnel capté aujourd'hui pourrait être déchiffré le jour où un ordinateur quantique existera ; à vérifier dans l'application (wg genpsk pour en créer une).",
                "WireGuard: pre-shared key not checked ({raison}). Without it, a tunnel recorded today could be decrypted once a quantum computer exists; check in the app (wg genpsk to create one)."
            ),
        )
        .avec_objet(Objet::Seul)],
        Wireguard::Tunnels(tunnels) => tunnels
            .iter()
            .map(|(nom, t)| {
                let objet = Objet::de("wg", nom);
                let nom = affichable(nom);
                match t {
                    Tunnel::Lu(p) if p.sans > 0 => {
                        let (sans, total) = (p.sans, p.total);
                        alerte(
                            CAT,
                            Niveau::Info,
                            trf!(
                                "Tunnel WireGuard {nom} : {sans} pair(s) sur {total} sans clé pré-partagée. Elle ajoute une protection contre le déchiffrement futur du trafic enregistré (wg genpsk).",
                                "WireGuard tunnel {nom}: {sans} peer(s) out of {total} without a pre-shared key. It adds protection against future decryption of recorded traffic (wg genpsk)."
                            ),
                        )
                        .manuel(conseil_wireguard(), &[])
                    }
                    Tunnel::Lu(p) if p.inconnus > 0 => impossible_par(
                        CAT,
                        Raison::Introuvable,
                        trf!(
                            "Tunnel WireGuard {nom} : clé pré-partagée gardée hors du fichier (agent du trousseau, ou non enregistrée) pour {} pair(s) : non vérifiée.",
                            "WireGuard tunnel {nom}: pre-shared key kept outside the file (keyring agent, or not saved) for {} peer(s): not checked.",
                            p.inconnus
                        ),
                    ),
                    Tunnel::Lu(p) => ok(
                        CAT,
                        trf!(
                            "Tunnel WireGuard {nom} : clé pré-partagée pour chacun de ses {} pair(s).",
                            "WireGuard tunnel {nom}: pre-shared key for each of its {} peer(s).",
                            p.total
                        ),
                    ),
                    Tunnel::SansFichier => impossible_par(
                        CAT,
                        Raison::Introuvable,
                        trf!(
                            "Tunnel WireGuard {nom} : aucun fichier ne le décrit (réglé par une application VPN ou par « wg set ») ; seul « wg show » en administrateur le dirait, et Vanguard ne le lance pas.",
                            "WireGuard tunnel {nom}: no file describes it (set by a VPN app or by “wg set”); only “wg show” as administrator would tell, and Vanguard does not run it."
                        ),
                    ),
                    Tunnel::Illisible(r) => impossible_par(
                        CAT,
                        r.clone(),
                        trf!(
                            "Tunnel WireGuard {nom} : clé pré-partagée illisible sans droits d'administrateur.",
                            "WireGuard tunnel {nom}: pre-shared key unreadable without administrator rights."
                        ),
                    ),
                }
                .avec_objet(objet)
            })
            .collect(),
    }
}

/// Un fichier lu dans un tampon effacé dès qu'il n'en a plus besoin : celui d'un tunnel contient aussi sa clé
/// privée. Seuls des nombres de pairs en sortent.
struct Efface(Vec<u8>);

impl Drop for Efface {
    fn drop(&mut self) {
        crate::socle::effacer(&mut self.0);
    }
}

/// Lit un petit fichier (1 Mio au plus) d'un seul bloc, sans recopie intermédiaire qui resterait en mémoire.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_efface(chemin: &std::path::Path) -> std::io::Result<Efface> {
    use std::io::Read;
    let f = std::fs::File::open(chemin)?;
    let taille = f.metadata()?.len().min(1 << 20);
    let mut tampon = Efface(Vec::with_capacity(usize::try_from(taille).unwrap_or(0) + 1));
    f.take(1 << 20).read_to_end(&mut tampon.0)?;
    Ok(tampon)
}

/// Les pairs des fichiers d'un dossier dont le nom finit par `fin`, par interface. `Err` : le dossier ou un de ses
/// fichiers est réservé à root (alors une interface sans fichier trouvé n'est pas « sans fichier » : on ne sait
/// pas).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn pairs_du_dossier(
    dossier: &std::path::Path,
    fin: &str,
    lire: impl Fn(&str, &str) -> Option<(String, Pairs)>,
    trouves: &mut Vec<(String, Pairs)>,
) -> bool {
    let entrees = match std::fs::read_dir(dossier) {
        Ok(e) => e,
        Err(e) => return e.kind() == std::io::ErrorKind::PermissionDenied,
    };
    let mut refuse = false;
    for e in entrees.flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        let Some(base) = nom.strip_suffix(fin) else { continue };
        match lire_efface(&e.path()) {
            Ok(t) => {
                if let Some(trouve) = std::str::from_utf8(&t.0).ok().and_then(|texte| lire(base, texte)) {
                    trouves.push(trouve);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => refuse = true,
            Err(_) => {}
        }
    }
    refuse
}

/// Les tunnels d'après les interfaces du noyau et les fichiers trouvés : (interface, ce qui s'en sait).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // fichiers lus sous Linux seulement
pub(crate) fn tunnels(interfaces: &[String], trouves: &[(String, Pairs)], refuse: bool) -> Vec<(String, Tunnel)> {
    interfaces
        .iter()
        .map(|i| {
            let t = match trouves.iter().find(|(n, _)| n == i) {
                Some((_, p)) => Tunnel::Lu(*p),
                None if refuse => Tunnel::Illisible(Raison::Droits),
                None => Tunnel::SansFichier,
            };
            (i.clone(), t)
        })
        .collect()
}

// ── Lectures, par système ──

#[cfg(target_os = "linux")]
fn lire_serveur() -> Lecture<Serveur> {
    use crate::machine::linux::{sshd_dans_l_ordre, sshd_en_marche, version_sshd};
    // RHEL 8 passe sa politique de chiffrement à sshd en ligne de commande (CRYPTO_POLICY) : elle passe avant le
    // fichier et ne se voit que par « sshd -T », en administrateur. RHEL 9 et Fedora l'incluent dans le fichier.
    const POLITIQUE: &str = "/etc/crypto-policies/back-ends/opensshserver.config";
    match sshd_en_marche() {
        None => return Lecture::Illisible(Raison::Absente("systemd".into())),
        Some(false) => return Lecture::Absent(Absence::Inactif),
        Some(true) => {}
    }
    let segments = match sshd_dans_l_ordre() {
        Ok(s) => s,
        Err(e) => return Lecture::Illisible(e.raison),
    };
    if std::path::Path::new(POLITIQUE).exists() && !segments.iter().any(|(f, _)| f == POLITIQUE) {
        return Lecture::Illisible(Raison::Refuse(
            tr!(
                "politique de chiffrement du système passée à sshd en ligne de commande, lisible seulement par « sshd -T » en administrateur",
                "system crypto policy passed to sshd on the command line, readable only by “sshd -T” as administrator"
            )
            .into(),
        ));
    }
    Lecture::Lu(Serveur {
        segments,
        version: version_sshd(),
    })
}

#[cfg(target_os = "macos")]
fn lire_serveur() -> Lecture<Serveur> {
    // Seulement si « Session à distance » écoute le réseau (port 22), comme la règle du serveur SSH du Mac.
    let Some(netstat) = super::sortie("netstat", &["-an", "-p", "tcp"]) else {
        return Lecture::Illisible(Raison::Absente("netstat".into()));
    };
    let ecoute = super::unix::lire_netstat(&netstat, true)
        .iter()
        .any(|(adresse, port)| *port == 22 && !(adresse.starts_with("127.") || adresse == "::1"));
    if !ecoute {
        return Lecture::Absent(Absence::Inactif);
    }
    let Some(conf) = super::unix::configuration_sshd() else {
        return Lecture::Illisible(Raison::Droits);
    };
    Lecture::Lu(Serveur {
        segments: vec![("/etc/ssh/sshd_config".into(), conf)],
        version: std::fs::read("/usr/sbin/sshd")
            .ok()
            .and_then(|o| crate::machine::sshd::version_dans_le_programme(&o)),
    })
}

#[cfg(windows)]
fn lire_serveur() -> Lecture<Serveur> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let cle = r"SYSTEM\CurrentControlSet\Services\sshd";
    if winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(cle).is_err() {
        return Lecture::Absent(Absence::Logiciel);
    }
    let en_marche = super::windows::wmi::requete(r"root\cimv2", "Win32_Service", "Name='sshd'", &["State"])
        .map(|l| l.first().and_then(|l| l["State"].texte()) == Some("Running"));
    let demarrage: Option<u32> = super::windows::registre(HKEY_LOCAL_MACHINE, cle, "Start");
    // WMI muet : jugé comme s'il tournait, sauf désactivé.
    if en_marche == Some(false) && demarrage != Some(2) || en_marche.is_none() && demarrage == Some(4) {
        return Lecture::Absent(Absence::Inactif);
    }
    let dossier = std::env::var_os("ProgramData")
        .map_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"), std::path::PathBuf::from)
        .join("ssh");
    let conf = match std::fs::read_to_string(dossier.join("sshd_config")) {
        Ok(t) => crate::machine::sshd::partie_globale_sshd(&t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Lecture::Illisible(crate::modele::Echec::io("bilan/pqc-sshd", &e).raison),
    };
    // REG_EXPAND_SZ : « %SystemRoot%\System32\OpenSSH\sshd.exe » sur un Windows ordinaire, à développer.
    let programme: Option<String> = super::windows::registre(HKEY_LOCAL_MACHINE, cle, "ImagePath");
    let programme = programme.and_then(|p| super::windows::installes::developper(&p, &|v| std::env::var(v).ok()));
    let programme = programme.map_or_else(
        || {
            std::env::var_os("SystemRoot").map_or_else(|| r"C:\Windows".into(), |s| s.to_string_lossy().into_owned())
                + r"\System32\OpenSSH\sshd.exe"
        },
        |p| p.trim_matches('"').to_string(),
    );
    Lecture::Lu(Serveur {
        segments: vec![(r"%ProgramData%\ssh\sshd_config".into(), conf)],
        version: std::fs::read(programme)
            .ok()
            .and_then(|o| crate::machine::sshd::version_dans_le_programme(&o)),
    })
}

/// Les fichiers d'un motif d'inclusion de /etc/ssh/ssh_config (relatif à /etc/ssh), triés.
#[cfg(unix)]
fn inclus_du_systeme(motif: &str) -> Vec<(String, String)> {
    let chemin = if motif.starts_with('/') {
        std::path::PathBuf::from(motif)
    } else {
        std::path::Path::new("/etc/ssh").join(motif)
    };
    let nom = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut trouves: Vec<std::path::PathBuf> = if nom.contains(['*', '?']) {
        let parent = chemin.parent().unwrap_or(std::path::Path::new("/etc/ssh"));
        std::fs::read_dir(parent)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| super::joker(&nom, &e.file_name().to_string_lossy()))
            .map(|e| e.path())
            .collect()
    } else {
        vec![chemin]
    };
    trouves.sort();
    trouves
        .into_iter()
        .filter(|p| p.is_file())
        .filter_map(|p| Some((p.display().to_string(), std::fs::read_to_string(&p).ok()?)))
        .collect()
}

#[cfg(unix)]
fn lire_client() -> Lecture<Client> {
    #[cfg(target_os = "linux")]
    let version = crate::machine::linux::version_ssh();
    #[cfg(target_os = "macos")]
    let version = std::fs::read("/usr/bin/ssh")
        .ok()
        .and_then(|o| crate::machine::sshd::version_dans_le_programme(&o));
    let present = [
        "/usr/bin/ssh",
        "/bin/ssh",
        "/usr/local/bin/ssh",
        "/opt/homebrew/bin/ssh",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists());
    if !present && version.is_none() {
        return Lecture::Absent(Absence::Logiciel);
    }
    let dossier = crate::socle::maison().join(".ssh");
    let mut fichiers = Vec::new();
    for (nom, chemin, inclus) in [
        (
            "~/.ssh/config".to_string(),
            dossier.join("config"),
            &(|m: &str| super::fichiers_inclus_ssh(&dossier, m)) as &dyn Fn(&str) -> Vec<(String, String)>,
        ),
        (
            "/etc/ssh/ssh_config".to_string(),
            std::path::PathBuf::from("/etc/ssh/ssh_config"),
            &inclus_du_systeme,
        ),
    ] {
        match std::fs::read_to_string(&chemin) {
            Ok(texte) => {
                let mut lignes = Vec::new();
                super::deplier_config_ssh(&nom, &texte, inclus, 8, &mut lignes);
                fichiers.push(lignes);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Lecture::Illisible(crate::modele::Echec::io("bilan/pqc-ssh", &e).raison),
        }
    }
    Lecture::Lu(Client { fichiers, version })
}

#[cfg(windows)]
fn lire_client() -> Lecture<Client> {
    let racine =
        std::env::var_os("SystemRoot").map_or_else(|| r"C:\Windows".into(), |s| s.to_string_lossy().into_owned());
    let programme = std::path::PathBuf::from(format!(r"{racine}\System32\OpenSSH\ssh.exe"));
    let Ok(octets) = std::fs::read(&programme) else {
        return Lecture::Absent(Absence::Logiciel);
    };
    let systeme = std::env::var_os("ProgramData")
        .map_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"), std::path::PathBuf::from)
        .join(r"ssh\ssh_config");
    let mut fichiers = Vec::new();
    for (nom, chemin) in [
        (
            r"%USERPROFILE%\.ssh\config",
            crate::socle::maison().join(".ssh").join("config"),
        ),
        (r"%ProgramData%\ssh\ssh_config", systeme),
    ] {
        match std::fs::read_to_string(&chemin) {
            Ok(t) => fichiers.push(
                t.lines()
                    .enumerate()
                    .map(|(i, l)| (nom.to_string(), i + 1, l.to_string()))
                    .collect(),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Lecture::Illisible(crate::modele::Echec::io("bilan/pqc-ssh", &e).raison),
        }
    }
    Lecture::Lu(Client {
        fichiers,
        version: crate::machine::sshd::version_dans_le_programme(&octets),
    })
}

/// Les interfaces WireGuard du noyau, repérées sans droits (« DEVTYPE=wireguard » dans leur uevent).
#[cfg(target_os = "linux")]
fn interfaces_wireguard(racine: &std::path::Path) -> Vec<String> {
    let mut i: Vec<String> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            std::fs::read_to_string(e.path().join("uevent"))
                .is_ok_and(|t| t.lines().any(|l| l.trim() == "DEVTYPE=wireguard"))
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    i.sort();
    i
}

#[cfg(target_os = "linux")]
fn lire_wireguard() -> Wireguard {
    use std::path::Path;
    let interfaces = interfaces_wireguard(Path::new("/sys/class/net"));
    if interfaces.is_empty() {
        return Wireguard::Aucun(Absence::Inactif);
    }
    // Lu seulement si le bilan tourne déjà en administrateur : ces fichiers sont réservés à root (0600).
    let mut trouves = Vec::new();
    let mut refuse = pairs_du_dossier(
        Path::new("/etc/wireguard"),
        ".conf",
        |base, t| Some((base.to_string(), pairs_wg_quick(t))),
        &mut trouves,
    );
    refuse |= pairs_du_dossier(
        Path::new("/etc/NetworkManager/system-connections"),
        ".nmconnection",
        |_, t| pairs_networkmanager(t),
        &mut trouves,
    );
    refuse |= pairs_du_dossier(
        Path::new("/etc/systemd/network"),
        ".netdev",
        |_, t| pairs_netdev(t),
        &mut trouves,
    );
    Wireguard::Tunnels(tunnels(&interfaces, &trouves, refuse))
}

#[cfg(windows)]
fn lire_wireguard() -> Wireguard {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let noms: Vec<String> = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(super::windows::CLE_SERVICES)
        .map(|k| {
            k.enum_keys()
                .flatten()
                .filter_map(|n| n.strip_prefix("WireGuardTunnel$").map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if noms.is_empty() {
        return Wireguard::Aucun(Absence::Inactif);
    }
    // Les configurations (Data\Configurations\*.conf.dpapi) sont chiffrées pour SYSTEM : il faudrait se faire passer
    // pour lui, ce que Vanguard refuse.
    Wireguard::Hors(trf!(
        "{} tunnel(s) en marche ; leurs configurations sont chiffrées pour le compte SYSTEM, que Vanguard ne se fait pas passer pour lire",
        "{} tunnel(s) running; their configurations are encrypted for the SYSTEM account, which Vanguard does not impersonate to read them",
        noms.len()
    ))
}

#[cfg(target_os = "macos")]
fn lire_wireguard() -> Wireguard {
    let present = [
        "/Applications/WireGuard.app",
        "/opt/homebrew/bin/wg-quick",
        "/usr/local/bin/wg-quick",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists());
    if !present {
        return Wireguard::Aucun(Absence::Logiciel);
    }
    Wireguard::Hors(
        tr!(
            "l'application WireGuard garde ses tunnels dans le trousseau et son extension réseau, que Vanguard ne lit pas",
            "the WireGuard app keeps its tunnels in the keychain and its network extension, which Vanguard does not read"
        )
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modele::Etat;

    fn segments(f: &[(&str, &str)]) -> Vec<(String, String)> {
        f.iter().map(|(a, b)| ((*a).to_string(), (*b).to_string())).collect()
    }

    fn serveur(f: &[(&str, &str)], v: Option<(u32, u32)>) -> Constat {
        juger_serveur(&Lecture::Lu(Serveur {
            segments: segments(f),
            version: v,
        }))
    }

    #[test]
    fn serveur_selon_version_et_liste() {
        let defaut = [("/etc/ssh/sshd_config", "Port 22\n")];
        assert_eq!(serveur(&defaut, Some((9, 6))).probleme, None);
        assert_eq!(serveur(&defaut, Some((10, 0))).probleme, None);
        let vieux = serveur(&defaut, Some((7, 4)));
        assert_eq!(vieux.probleme, Some(Niveau::Info));
        assert!(
            vieux.message.contains("trop vieux") || vieux.message.contains("too old"),
            "{}",
            vieux.message
        );
        let k = vieux.correctif.as_ref().unwrap();
        assert!(
            !k.automatique && k.commandes.is_empty(),
            "jamais de correction automatique"
        );
        // 8.5 sans liste : alerte ; avec le nom @openssh.com ajouté : protégé.
        let c = serveur(&defaut, Some((8, 5)));
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(
            c.correctif
                .unwrap()
                .action
                .contains("sntrup761x25519-sha512@openssh.com")
        );
        assert!(
            !serveur(&defaut, Some((8, 5)))
                .correctif
                .unwrap()
                .action
                .contains("mlkem")
        );
        // Rien d'écrit : une ligne « + », jamais une liste nue qui remplacerait les valeurs par défaut.
        assert!(
            serveur(&defaut, Some((8, 5)))
                .correctif
                .unwrap()
                .action
                .contains("KexAlgorithms +sntrup761x25519-sha512@openssh.com")
        );
        // « - » sur 8.9 : la version est la cause, pas la liste ; le conseil ne met jamais un nom devant le « - ».
        let moins = [("/etc/ssh/sshd_config", "KexAlgorithms -diffie-hellman-group1-sha1\n")];
        let c = serveur(&moins, Some((8, 9)));
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(
            !c.message.contains("retire") && !c.message.contains("removes"),
            "{}",
            c.message
        );
        let action = c.correctif.unwrap().action;
        assert!(
            !action.contains("en tête") && !action.contains("at the start"),
            "{action}"
        );
        // « - » qui retire sntrup sur 9.6 : la liste est la cause, le conseil dit d'en retirer les noms.
        let moins = [("/etc/ssh/sshd_config", "KexAlgorithms -sntrup*\n")];
        let c = serveur(&moins, Some((9, 6)));
        assert!(
            c.message.contains("retire") || c.message.contains("removes"),
            "{}",
            c.message
        );
        let action = c.correctif.unwrap().action;
        assert!(action.contains("sntrup") && !action.contains("en tête") && !action.contains("at the start"));
        // « + » sans post-quantique sur 8.5 : les noms s'ajoutent à la fin.
        let plus = [("/etc/ssh/sshd_config", "KexAlgorithms +diffie-hellman-group14-sha256\n")];
        let action = serveur(&plus, Some((8, 5))).correctif.unwrap().action;
        assert!(action.contains(",sntrup761x25519-sha512@openssh.com"), "{action}");
        let ajoute = [
            (
                "/etc/ssh/sshd_config.d/10-pq.conf",
                "KexAlgorithms +sntrup761x25519-sha512@openssh.com\n",
            ),
            ("/etc/ssh/sshd_config", ""),
        ];
        assert_eq!(serveur(&ajoute, Some((8, 5))).probleme, None);
        // Une liste écrite qui les retire : le fichier est nommé, le conseil suit la version.
        let retire = [
            ("/etc/ssh/sshd_config.d/50-x.conf", "KexAlgorithms curve25519-sha256\n"),
            ("/etc/ssh/sshd_config", "KexAlgorithms mlkem768x25519-sha256\n"),
        ];
        let c = serveur(&retire, Some((9, 9)));
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("50-x.conf"), "{}", c.message);
        assert!(c.correctif.as_ref().unwrap().action.contains("mlkem768x25519-sha256,"));
        assert!(c.correctif.as_ref().unwrap().action.contains("sshd -t"));
        assert_eq!(
            Objet::de("sshd", "/etc/ssh/sshd_config.d/50-x.conf"),
            c.objet,
            "l'objet nomme le fichier qui écrit la liste"
        );
        // Version illisible et rien d'écrit : non vérifié, jamais sain.
        let c = serveur(&defaut, None);
        assert!(!c.verifie && matches!(c.etat(), Etat::NonVerifie(_)));
        // Version illisible, mais une liste écrite qui nomme ML-KEM : sshd tourne, il le connaît.
        let pq = [("/etc/ssh/sshd_config", "KexAlgorithms mlkem768x25519-sha256\n")];
        assert_eq!(serveur(&pq, None).probleme, None);
        assert!(serveur(&pq, None).verifie);
    }

    #[test]
    fn serveur_absent_ou_illisible() {
        let c = juger_serveur(&Lecture::Absent(Absence::Inactif));
        assert_eq!(c.etat(), Etat::SansObjet(Absence::Inactif));
        let c = juger_serveur(&Lecture::Illisible(Raison::Droits));
        assert_eq!(c.etat(), Etat::NonVerifie(Raison::Droits));
        assert!(c.coherent());
    }

    fn lignes(fichier: &str, texte: &str) -> Vec<(String, usize, String)> {
        texte
            .lines()
            .enumerate()
            .map(|(i, l)| (fichier.to_string(), i + 1, l.to_string()))
            .collect()
    }

    fn client(fichiers: Vec<Vec<(String, usize, String)>>, v: Option<(u32, u32)>) -> Vec<Constat> {
        juger_client(&Lecture::Lu(Client { fichiers, version: v }))
    }

    #[test]
    fn client_global_ou_pour_un_hote() {
        // Rien d'écrit : OpenSSH 10 le propose.
        let c = client(vec![], Some((10, 0)));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, None);
        // Sous « Host vieux-routeur » : une information, sans le nom de l'hôte.
        let config = "Host vieux-routeur.example.com\n  KexAlgorithms diffie-hellman-group14-sha256\nHost *\n  ServerAliveInterval 30\n";
        let c = client(vec![lignes("~/.ssh/config", config)], Some((10, 0)));
        assert_eq!(c.len(), 2, "{:?}", c.iter().map(|c| &c.message).collect::<Vec<_>>());
        assert_eq!(c[0].probleme, None);
        assert_eq!(c[1].probleme, Some(Niveau::Info));
        assert!(
            c.iter()
                .all(|c| !c.message.contains("vieux-routeur") && !c.message.contains("example.com"))
        );
        // Sous « Host * » : le constat, avec le fichier.
        let config = "Host *\n  KexAlgorithms curve25519-sha256\n";
        let c = client(vec![lignes("~/.ssh/config", config)], Some((10, 0)));
        assert_eq!(c[0].probleme, Some(Niveau::Info));
        assert!(c[0].message.contains("~/.ssh/config"), "{}", c[0].message);
        assert!(
            c[0].correctif
                .as_ref()
                .unwrap()
                .action
                .contains("mlkem768x25519-sha256")
        );
        // Celui du compte passe avant celui du système : la première valeur l'emporte.
        let compte = lignes("~/.ssh/config", "KexAlgorithms +mlkem768x25519-sha256\n");
        let systeme = lignes("/etc/ssh/ssh_config", "KexAlgorithms curve25519-sha256\n");
        assert_eq!(client(vec![compte, systeme], Some((9, 9)))[0].probleme, None);
        // Chaque fichier de tête recommence pour tous les serveurs.
        let compte = lignes("~/.ssh/config", "Host routeur\n  User alice\n");
        let systeme = lignes("/etc/ssh/ssh_config", "KexAlgorithms curve25519-sha256\n");
        let cfg = lire_config_client(&[compte, systeme]);
        assert_eq!(cfg.globale.as_ref().map(|g| g.0.as_str()), Some("/etc/ssh/ssh_config"));
        // « Match all » vaut pour tous ; « WarnWeakCrypto no » se dit.
        let config = "Match all\n  WarnWeakCrypto no\n";
        let c = client(vec![lignes("~/.ssh/config", config)], Some((10, 6)));
        assert!(c.iter().any(|c| c.message.contains("WarnWeakCrypto")));
        let config = "Host test\n  WarnWeakCrypto no\n";
        assert_eq!(client(vec![lignes("~/.ssh/config", config)], Some((10, 6))).len(), 1);
        // Pas de client : sans objet.
        let c = juger_client(&Lecture::Absent(Absence::Logiciel));
        assert_eq!(c[0].etat(), Etat::SansObjet(Absence::Logiciel));
    }

    /// Des clés WireGuard fabriquées pour l'essai (base64 de motifs), jamais de vraies.
    const PRIVEE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=";
    const PARTAGEE: &str = "c2VjcmV0LXBhcnRhZ2UtZXNzYWktdmFuZ3VhcmQtMDE=";

    #[test]
    fn wireguard_lu_sans_jamais_garder_les_cles() {
        let conf = format!(
            "[Interface]\nPrivateKey = {PRIVEE}\nAddress = 192.0.2.2/32\n\n[Peer]\nPublicKey = AAAA\nPresharedKey = {PARTAGEE}\nEndpoint = 192.0.2.1:51820\n\n[Peer]\nPublicKey = BBBB\nAllowedIPs = 192.0.2.0/24\n"
        );
        let p = pairs_wg_quick(&conf);
        assert_eq!(
            p,
            Pairs {
                total: 2,
                sans: 1,
                inconnus: 0
            }
        );
        let nm = format!(
            "[connection]\nid=Salon\ntype=wireguard\ninterface-name=wg-salon\n\n[wireguard]\nprivate-key={PRIVEE}\n\n[wireguard-peer.AAAA]\npreshared-key={PARTAGEE}\npreshared-key-flags=0\n\n[wireguard-peer.BBBB]\npreshared-key-flags=1\n\n[wireguard-peer.CCCC]\nallowed-ips=192.0.2.0/24;\n"
        );
        assert_eq!(
            pairs_networkmanager(&nm),
            Some((
                "wg-salon".to_string(),
                Pairs {
                    total: 3,
                    sans: 1,
                    inconnus: 1
                }
            ))
        );
        assert_eq!(pairs_networkmanager("[connection]\ntype=wifi\n"), None);
        let netdev = "[NetDev]\nName=wg1\nKind=wireguard\n\n[WireGuard]\nPrivateKeyFile=/etc/systemd/network/wg1.key\n\n[WireGuardPeer]\nPublicKey=AAAA\nPresharedKeyFile=/etc/systemd/network/wg1.psk\n";
        assert_eq!(
            pairs_netdev(netdev),
            Some((
                "wg1".to_string(),
                Pairs {
                    total: 1,
                    sans: 0,
                    inconnus: 0
                }
            ))
        );
        assert_eq!(pairs_netdev("[NetDev]\nName=br0\nKind=bridge\n"), None);
        let interfaces = [
            "wg-salon".to_string(),
            "wg0".to_string(),
            "wg1".to_string(),
            "mullvad".to_string(),
        ];
        let trouves = [
            ("wg0".to_string(), p),
            ("wg-salon".to_string(), pairs_networkmanager(&nm).unwrap().1),
            ("wg1".to_string(), pairs_netdev(netdev).unwrap().1),
        ];
        let c = juger_wireguard(&Wireguard::Tunnels(tunnels(&interfaces, &trouves, false)));
        assert_eq!(c.len(), 4);
        assert_eq!(c[0].probleme, Some(Niveau::Info), "wg-salon : un pair sans clé");
        assert_eq!(c[1].probleme, Some(Niveau::Info), "wg0 : un pair sans clé");
        assert!(
            c[1].correctif.as_ref().unwrap().action.contains("hors ligne")
                || c[1].correctif.as_ref().unwrap().action.contains("offline")
        );
        assert_eq!(c[2].probleme, None, "wg1 : toutes les clés");
        assert!(!c[3].verifie, "mullvad : aucun fichier, non vérifié, jamais alerte");
        assert_eq!(c[3].probleme, Some(Niveau::Info));
        assert!(matches!(c[3].etat(), Etat::NonVerifie(_)));
        // Aucune clé dans un message ni dans le JSON.
        let json = serde_json::to_string(&c).unwrap();
        for cle in [PRIVEE, PARTAGEE] {
            assert!(!json.contains(cle) && c.iter().all(|c| !c.message.contains(cle)));
        }
        // Sans droits : non vérifié, raison dite.
        let c = juger_wireguard(&Wireguard::Tunnels(tunnels(&["wg0".to_string()], &[], true)));
        assert_eq!(c[0].etat(), Etat::NonVerifie(Raison::Droits));
        let c = juger_wireguard(&Wireguard::Aucun(Absence::Inactif));
        assert_eq!(c[0].etat(), Etat::SansObjet(Absence::Inactif));
        let c = juger_wireguard(&Wireguard::Hors("chiffré".into()));
        assert!(!c[0].verifie);
        // Seulement agent du trousseau : non vérifié.
        let seul = "[connection]\ntype=wireguard\ninterface-name=wg2\n[wireguard-peer.A]\npreshared-key-flags=1\n";
        let (_, p) = pairs_networkmanager(seul).unwrap();
        let c = juger_wireguard(&Wireguard::Tunnels(tunnels(
            &["wg2".to_string()],
            &[("wg2".to_string(), p)],
            false,
        )));
        assert!(!c[0].verifie);
    }

    /// Les vrais fichiers d'essai, lus par la même fonction que le bilan : le tampon est effacé, le compte juste.
    #[cfg(target_os = "linux")]
    #[test]
    fn dossier_d_essai_lu() {
        let d = crate::socle::dossier_local().join("pqc-wg");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("net/wg0")).unwrap();
        std::fs::create_dir_all(d.join("net/eth0")).unwrap();
        std::fs::write(d.join("net/wg0/uevent"), "DEVTYPE=wireguard\nINTERFACE=wg0\n").unwrap();
        std::fs::write(d.join("net/eth0/uevent"), "INTERFACE=eth0\n").unwrap();
        assert_eq!(interfaces_wireguard(&d.join("net")), ["wg0"]);
        std::fs::create_dir_all(d.join("wireguard")).unwrap();
        std::fs::write(
            d.join("wireguard/wg0.conf"),
            format!("[Interface]\nPrivateKey = {PRIVEE}\n[Peer]\nPublicKey = AAAA\n"),
        )
        .unwrap();
        let mut trouves = Vec::new();
        let refuse = pairs_du_dossier(
            &d.join("wireguard"),
            ".conf",
            |b, t| Some((b.to_string(), pairs_wg_quick(t))),
            &mut trouves,
        );
        assert!(!refuse);
        assert_eq!(
            trouves,
            [(
                "wg0".to_string(),
                Pairs {
                    total: 1,
                    sans: 1,
                    inconnus: 0
                }
            )]
        );
        assert!(!pairs_du_dossier(&d.join("absent"), ".conf", |_, _| None, &mut trouves));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les trois règles sur cet ordinateur, en lecture seule : un constat au moins chacune, cohérent, avec sa règle.
    #[test]
    fn regles_reelles_bornees() {
        for id in ["COM-PQC-001", "COM-PQC-002", "COM-PQC-003"] {
            let r = crate::machine::regles::regles(Os::actuel())
                .into_iter()
                .find(|r| r.id == id)
                .unwrap();
            let c = (r.verifier)();
            assert!(!c.is_empty(), "{id}");
            assert!(c.iter().all(Constat::coherent), "{id}");
            assert!(c.iter().all(|c| c.categorie == CAT));
        }
    }
}
