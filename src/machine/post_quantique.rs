//! Bilan post-quantique, en lecture seule : le serveur SSH (COM-PQC-001), le client SSH (COM-PQC-002) et les
//! tunnels WireGuard (COM-PQC-003). Un trafic chiffré capté aujourd'hui se garde et se lira le jour où un
//! ordinateur quantique assez gros existera (« enregistrer maintenant, déchiffrer plus tard ») : seul un échange de
//! clés post-quantique fait aujourd'hui le protège. Rien n'est changé ici : chaque constat dit ce qui manque et
//! comment le corriger soi-même ; ce qui ne se lit pas est « non vérifié », avec sa raison, jamais « sain ».
//!
//! Le jugement (fonctions `juger_*`, lecteurs de fichiers) est commun et se teste sur des valeurs inventées ; seule
//! la lecture dépend du système. Aucun programme n'est lancé : ni « sshd -T », ni « wg show » (il afficherait les
//! clés en clair, et c'est un programme tiers lancé en administrateur).

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

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
    pub fichiers: Vec<Vec<super::config_ssh::Lue>>,
    pub version: Option<(u32, u32)>,
}

/// Ce que la configuration du client dit de l'échange de clés.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ConfigClient {
    /// Les listes KexAlgorithms que SSH peut garder pour un serveur quelconque, dans l'ordre : (fichier, valeur, sous
    /// une portée globale à coup sûr). SSH garde la première qui s'applique ; une liste sous un en-tête « peut-être »
    /// (`config_ssh::Etendue::PeutEtre`) ne ferme pas la recherche, la première globale à coup sûr la ferme (incluse).
    /// Sans elle, le défaut d'OpenSSH reste possible.
    pub candidates: Vec<(String, String, bool)>,
    /// Les listes écrites sous un « Host » ou un « Match » précis : jamais le nom de l'hôte, seulement la liste.
    pub par_hote: Vec<String>,
    /// Le fichier où « WarnWeakCrypto no » (ou « no-pq-kex ») vaut peut-être pour tous les serveurs : la première
    /// valeur qui coupe, parmi celles que SSH peut garder (même règle que `candidates`).
    pub avertissement_coupe: Option<String>,
    /// Une ligne que Vanguard ne découpe pas comme SSH, ou un « Include » qu'il n'a pas déplié (Windows) : (fichier,
    /// ligne). Le client n'est pas jugé sans elle : elle peut porter les algorithmes.
    pub non_lu: Option<(String, usize)>,
}

/// Lit la configuration du client comme ssh : découpée par `config_ssh::lire_ligne`, avec la portée de SSH
/// (`config_ssh::Portee` : un « Host » ou un « Match » qui couvre tout serveur, le début de chaque fichier de tête, la
/// portée remise à la fin de chaque fichier inclus) ; la première valeur qui s'applique l'emporte. Une valeur sous un
/// en-tête que SSH n'applique peut-être pas est gardée comme candidate, sans clore la recherche : seule une valeur
/// globale à coup sûr la clôt.
pub(crate) fn lire_config_client(fichiers: &[Vec<super::config_ssh::Lue>]) -> ConfigClient {
    use super::config_ssh::{Cle, Etendue, Ligne, Portee};
    let mut c = ConfigClient::default();
    let (mut kex_clos, mut avertissement_clos) = (false, false);
    for lignes in fichiers {
        let mut portee = Portee::nouvelle();
        for lue in lignes {
            let Some((fichier, n, ligne)) = portee.lire(lue) else {
                continue;
            };
            let etendue = portee.etendue();
            let sure = etendue == Etendue::Globale;
            match ligne {
                Ligne::NonInterpretee | Ligne::Include(_) => {
                    c.non_lu.get_or_insert_with(|| (fichier.to_string(), n));
                }
                Ligne::Valeur(Cle::KexAlgorithms, valeur) if etendue == Etendue::Precise => {
                    c.par_hote.push(valeur.to_string());
                }
                Ligne::Valeur(Cle::KexAlgorithms, valeur) if !kex_clos => {
                    c.candidates.push((fichier.to_string(), valeur.to_string(), sure));
                    kex_clos = sure;
                }
                Ligne::Valeur(Cle::WarnWeakCrypto, valeur) if etendue != Etendue::Precise && !avertissement_clos => {
                    avertissement_clos = sure;
                    if super::config_ssh::avertissement_coupe(valeur) {
                        c.avertissement_coupe.get_or_insert_with(|| fichier.to_string());
                        avertissement_clos = true;
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
    if let Some((fichier, ligne)) = &config.non_lu {
        let fichier = affichable(fichier);
        let r = Raison::Illisible(trf!(
            "{fichier}, ligne {ligne} non lue : forme non interprétée",
            "{fichier}, line {ligne} not read: form not interpreted"
        ));
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
    let v = version_texte(c.version);
    let mut constats = Vec::new();
    // Les valeurs que SSH peut garder pour un serveur quelconque : chaque candidate, puis le défaut d'OpenSSH si aucune
    // n'est globale à coup sûr. « Proposé » seulement si toutes le proposent ; sinon celle qui l'écarte est dite, la
    // globale à coup sûr avant une douteuse (un fait avant un doute), ou à défaut celle qui ne se juge pas :
    // (fichier, valeur, globale à coup sûr).
    let mut possibles: Vec<(Option<&str>, Option<&str>, bool)> = config
        .candidates
        .iter()
        .map(|(f, v, sure)| (Some(f.as_str()), Some(v.as_str()), *sure))
        .collect();
    if !config.candidates.last().is_some_and(|x| x.2) {
        possibles.push((None, None, true));
    }
    let juge = |p: &(Option<&str>, Option<&str>, bool)| kex_post_quantique(p.1, c.version);
    let indice = possibles
        .iter()
        .position(|p| p.2 && juge(p) == Some(false))
        .or_else(|| possibles.iter().position(|p| juge(p) == Some(false)))
        .or_else(|| possibles.iter().position(|p| juge(p).is_none()))
        .or(possibles.len().checked_sub(1));
    let (fichier, valeur, sure) = indice
        .and_then(|i| possibles.get(i))
        .copied()
        .unwrap_or((None, None, true));
    // Une valeur douteuse placée avant la globale sûre, et qui ne l'écarte pas : SSH la garde peut-être pour certains
    // serveurs, « écarte pour tous » serait faux pour eux (vérification de Fable n° 3, N4).
    let doute_avant = sure
        && indice
            .and_then(|i| possibles.get(..i))
            .is_some_and(|avant| avant.iter().any(|p| juge(p) != Some(false)));
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
            // Sous un en-tête que SSH n'applique peut-être pas à tous, ou après une valeur douteuse qui propose le
            // post-quantique : dit comme un doute, jamais tu.
            Some(false) if !sure || doute_avant => {
                let message = match fichier.map(affichable) {
                    Some(fichier) if !sure => trf!(
                        "Client SSH : la configuration {fichier} peut écarter l'échange post-quantique pour tous les serveurs : elle est sous un « Host » ou un « Match » que SSH applique peut-être à tous, et Vanguard ne peut pas trancher. Une session captée aujourd'hui pourrait être déchiffrée le jour où un ordinateur quantique existera.",
                        "SSH client: the {fichier} configuration may rule out post-quantum key exchange for every server: it sits under a “Host” or “Match” that SSH may apply to all of them, and Vanguard cannot tell. A session recorded today could be decrypted once a quantum computer exists."
                    ),
                    Some(fichier) => trf!(
                        "Client SSH : la configuration {fichier} peut écarter l'échange post-quantique pour tous les serveurs : elle l'écarte pour chacun, sauf ceux à qui un « Host » ou un « Match » placé avant, que SSH applique peut-être, donne une liste qui le propose ; Vanguard ne peut pas trancher. Une session captée aujourd'hui pourrait être déchiffrée le jour où un ordinateur quantique existera.",
                        "SSH client: the {fichier} configuration may rule out post-quantum key exchange for every server: it rules it out for each one, except those given a list that offers it by an earlier “Host” or “Match” that SSH may apply; Vanguard cannot tell. A session recorded today could be decrypted once a quantum computer exists."
                    ),
                    None => trf!(
                        "Client SSH (OpenSSH {v}) : l'échange de clés post-quantique n'est pas proposé par défaut, et seule une liste sous un « Host » ou un « Match » que SSH applique peut-être l'ajoute ; Vanguard ne peut pas trancher : il manque peut-être pour tous les serveurs.",
                        "SSH client (OpenSSH {v}): post-quantum key exchange is not offered by default, and only a list under a “Host” or “Match” that SSH may apply adds it; Vanguard cannot tell: it may be missing for every server."
                    ),
                };
                alerte(CAT, Niveau::Info, message).manuel(conseil_client(valeur, c.version), &[])
            }
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
            p.total = p.total.saturating_add(1);
            if !a_valeur(&lignes, "presharedkey") {
                p.sans = p.sans.saturating_add(1);
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
            p.total = p.total.saturating_add(1);
            if a_valeur(lignes, "preshared-key") {
                continue;
            }
            match valeur(lignes, "preshared-key-flags").map(str::trim) {
                None | Some("0" | "4") => p.sans = p.sans.saturating_add(1),
                Some(_) => p.inconnus = p.inconnus.saturating_add(1),
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
            p.total = p.total.saturating_add(1);
            if !a_valeur(lignes, "presharedkey") && !a_valeur(lignes, "presharedkeyfile") {
                p.sans = p.sans.saturating_add(1);
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
    /// Présent, mais rangé là où Vanguard ne lit pas (configurations chiffrées pour SYSTEM) :
    /// la raison.
    #[cfg_attr(target_os = "linux", allow(dead_code))] // Windows
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
    let mut tampon = Efface(Vec::with_capacity(
        usize::try_from(taille).unwrap_or(0).saturating_add(1),
    ));
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
        None if !std::path::Path::new("/run/systemd/system").is_dir() => {
            return Lecture::Illisible(Raison::Absente("systemd".into()));
        }
        None => {
            return Lecture::Illisible(Raison::Illisible(
                tr!(
                    "état du serveur SSH non lu (ni le bus système ni systemctl n'ont répondu)",
                    "SSH server state not read (neither the system bus nor systemctl answered)"
                )
                .into(),
            ));
        }
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

/// Les fichiers d'un motif d'inclusion de /etc/ssh/ssh_config (relatif à /etc/ssh), triés ; un fichier là mais non
/// lu est rendu avec sa raison (`machine::lire_inclus_ssh`).
#[cfg(unix)]
fn inclus_du_systeme(motif: &str, plafond: &mut super::Plafond) -> Vec<super::Inclus> {
    // SSH refuse « ~ » dans la configuration du système (« bad include path ») : jamais lu comme un chemin de
    // /etc/ssh, ni comme celui d'une maison.
    if motif.starts_with('~') {
        return vec![(
            motif.to_string(),
            Err(String::from(tr!(
                "« ~ » refusé par SSH dans la configuration du système",
                "\"~\" refused by SSH in the system configuration"
            ))),
        )];
    }
    let chemin = if motif.starts_with('/') {
        std::path::PathBuf::from(motif)
    } else {
        std::path::Path::new("/etc/ssh").join(motif)
    };
    super::lire_inclus_ssh(&chemin, &|p| p.display().to_string(), plafond)
}

#[cfg(unix)]
fn lire_client() -> Lecture<Client> {
    #[cfg(target_os = "linux")]
    let version = crate::machine::linux::version_ssh();
    let present = ["/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh"]
        .iter()
        .any(|p| std::path::Path::new(p).exists());
    if !present && version.is_none() {
        return Lecture::Absent(Absence::Logiciel);
    }
    let dossier = crate::socle::maison().join(".ssh");
    // Le premier lecteur porte le type de tous : sans lui, chaque fermeture a le sien.
    let inclus_ssh: &dyn Fn(&str, &mut super::Plafond) -> Vec<super::Inclus> =
        &|m: &str, plafond: &mut super::Plafond| super::fichiers_inclus_ssh(&dossier, m, plafond);
    let mut fichiers = Vec::new();
    for (nom, chemin, inclus) in [
        ("~/.ssh/config".to_string(), dossier.join("config"), inclus_ssh),
        (
            "/etc/ssh/ssh_config".to_string(),
            std::path::PathBuf::from("/etc/ssh/ssh_config"),
            &inclus_du_systeme,
        ),
    ] {
        // Lien suivi, simple fichier, borné : un tube nommé à la place de ~/.ssh/config figeait tout le bilan
        // (vérification de Fable n° 2, liens L3).
        match super::lire_texte_ssh(&chemin) {
            Ok(texte) => {
                let depliee = super::deplier_config_ssh(&nom, &texte, inclus);
                // Un fichier inclus non lu peut porter les algorithmes : le client n'est pas jugé sans lui.
                if let Some((fichier, raison)) = depliee.non_lus.into_iter().next() {
                    let fichier = affichable(&fichier);
                    let raison = affichable(&raison);
                    return Lecture::Illisible(Raison::Illisible(trf!(
                        "{fichier} non lu : {raison}",
                        "{fichier} not read: {raison}"
                    )));
                }
                fichiers.push(depliee.lignes);
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
                    .map(|(i, l)| super::config_ssh::Lue::Ligne(nom.to_string(), i + 1, l.to_string()))
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::config_ssh::Lue;
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

    fn lignes(fichier: &str, texte: &str) -> Vec<Lue> {
        texte
            .lines()
            .enumerate()
            .map(|(i, l)| Lue::Ligne(fichier.to_string(), i + 1, l.to_string()))
            .collect()
    }

    fn client(fichiers: Vec<Vec<Lue>>, v: Option<(u32, u32)>) -> Vec<Constat> {
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
        assert_eq!(
            cfg.candidates.first().map(|g| g.0.as_str()),
            Some("/etc/ssh/ssh_config")
        );
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

    /// Vérification avant 0.94 (S2, S3) : la portée est remise à la fin d'un fichier inclus, un hôte large autre que
    /// « * » vaut pour tous, « no-pq-kex » coupe l'avertissement, et une ligne non interprétée (ou un « Include » non
    /// déplié, sous Windows) laisse le client « non vérifié », jamais « proposé ».
    #[test]
    fn client_lu_avec_la_portee_de_ssh() {
        let kex = "KexAlgorithms curve25519-sha256";
        // « Include » en tête (fichier d'hôtes qui finit sous un Host précis), puis réglage général.
        let mut config = vec![Lue::Entree];
        config.extend(lignes("~/.ssh/hotes", "Host routeur\n  User alice\n"));
        config.push(Lue::Sortie);
        config.extend(lignes("~/.ssh/config", kex));
        let c = client(vec![config], Some((10, 0)));
        assert_eq!(c[0].probleme, Some(Niveau::Info), "{:?}", c[0].message);
        assert!(c[0].message.contains("~/.ssh/config"), "{}", c[0].message);
        // Sous un Host précis, le fichier inclus n'est global nulle part, même sous « Host * ».
        let mut config = lignes("~/.ssh/config", "Host routeur\n");
        config.push(Lue::Entree);
        config.extend(lignes("~/.ssh/inclus", &format!("Host *\n{kex}\n")));
        config.push(Lue::Sortie);
        assert_eq!(lire_config_client(&[config]).candidates, []);
        for config in [
            format!("Host ?*\n{kex}\n"),
            format!("Host * !routeur\n{kex}\n"),
            format!("Match host *\n{kex}\n"),
            format!("Match final all\n{kex}\n"),
            format!("={kex}\n"),
        ] {
            let cfg = lire_config_client(&[lignes("~/.ssh/config", &config)]);
            assert!(
                !cfg.candidates.is_empty() && cfg.non_lu.is_none(),
                "{config:?} : {cfg:?}"
            );
        }
        let cfg = lire_config_client(&[lignes("~/.ssh/config", "WarnWeakCrypto no-pq-kex\n")]);
        assert_eq!(cfg.avertissement_coupe.as_deref(), Some("~/.ssh/config"));
        for config in [
            "\"KexAlgorithms\" curve25519-sha256\n",
            "KexAlgorithms 'curve25519-sha256'\n",
            "Include kex.conf\n",
        ] {
            let c = client(vec![lignes("~/.ssh/config", config)], Some((10, 0)));
            assert_eq!(c.len(), 1, "{config:?}");
            assert!(
                matches!(c[0].etat(), Etat::NonVerifie(_))
                    && (c[0].message.contains("~/.ssh/config, ligne 1")
                        || c[0].message.contains("~/.ssh/config, line 1")),
                "{config:?} : {}",
                c[0].message
            );
        }
    }

    /// Vérification de Fable n° 2, P1 : sous un en-tête que SSH n'applique peut-être pas à tous les serveurs, une valeur
    /// ne ferme pas la recherche. « Proposé » seulement si toutes les valeurs possibles (jusqu'à la première globale à
    /// coup sûr, ou le défaut d'OpenSSH) le proposent ; l'avertissement est dit coupé si une valeur possible le coupe.
    #[test]
    fn client_peut_etre_global_ne_clot_pas_la_recherche() {
        let pq = "KexAlgorithms mlkem768x25519-sha256";
        let classique = "KexAlgorithms curve25519-sha256";
        let messages = |c: &[Constat]| c.iter().map(|c| c.message.clone()).collect::<Vec<_>>();
        for en_tete in [
            "Host * !serveur",
            "Match final all",
            "Match canonical all",
            "Match localuser bob",
            "Host *.*",
            "Match host *,!serveur",
            "Match user bob",
            "Match tagged essai",
            "Match exec \"false\"",
            "Match localnetwork 192.0.2.0/24",
            "Match command uptime",
            "Match version OpenSSH_1.*",
            "Match sessiontype subsystem",
            "Match !host *_*",
            "\"Host\" serveur",
        ] {
            // La bonne valeur sous l'en-tête douteux, la mauvaise sous « Host * » : jamais « proposé ».
            let config =
                format!("{en_tete}\n  {pq}\n  WarnWeakCrypto yes\nHost *\n  {classique}\n  WarnWeakCrypto no\n");
            let cfg = lire_config_client(&[lignes("~/.ssh/config", &config)]);
            assert_eq!(cfg.candidates.len(), 2, "{en_tete:?} : {cfg:?}");
            assert!(!cfg.candidates[0].2 && cfg.candidates[1].2, "{en_tete:?} : {cfg:?}");
            if cfg.non_lu.is_some() {
                continue;
            }
            let c = client(vec![lignes("~/.ssh/config", &config)], Some((10, 6)));
            // Vérification de Fable n° 3, N4 : SSH garde peut-être la bonne pour certains serveurs, « écarte pour
            // tous » serait faux pour eux ; l'alerte reste, dite comme un doute, à la ligne fautive.
            assert_eq!(c[0].probleme, Some(Niveau::Info), "{en_tete:?} : {:?}", messages(&c));
            assert!(
                c[0].message.contains("~/.ssh/config peut écarter l'échange") && c[0].message.contains("placé avant"),
                "{en_tete:?} : {}",
                c[0].message
            );
            assert!(c.iter().any(|c| c.message.contains("WarnWeakCrypto")), "{en_tete:?}");
            // L'inverse : la mauvaise sous l'en-tête douteux, dite comme un doute.
            let config =
                format!("{en_tete}\n  {classique}\n  WarnWeakCrypto no\nHost *\n  {pq}\n  WarnWeakCrypto yes\n");
            let c = client(vec![lignes("~/.ssh/config", &config)], Some((10, 6)));
            assert!(
                c[0].probleme == Some(Niveau::Info) && c[0].message.contains("peut écarter"),
                "{en_tete:?} : {:?}",
                messages(&c)
            );
            assert!(c.iter().any(|c| c.message.contains("WarnWeakCrypto")), "{en_tete:?}");
            // Les deux l'écartent : le fait (« Host * ») est dit, pas le doute.
            let config = format!("{en_tete}\n  {classique}\nHost *\n  {classique}\n");
            let c = client(vec![lignes("~/.ssh/config", &config)], Some((10, 6)));
            assert!(
                c[0].message.contains("écarte l'échange") && !c[0].message.contains("peut"),
                "{en_tete:?} : {:?}",
                messages(&c)
            );
            // Toutes proposent : proposé, sans avertissement coupé.
            let config = format!("{en_tete}\n  {pq}\nHost *\n  {pq}\n");
            let c = client(vec![lignes("~/.ssh/config", &config)], Some((10, 6)));
            assert_eq!(c.len(), 1, "{en_tete:?} : {:?}", messages(&c));
            assert_eq!(c[0].probleme, None, "{en_tete:?} : {:?}", messages(&c));
            // Sans valeur globale à coup sûr, le défaut d'OpenSSH reste possible : sans post-quantique en 8.4.
            let config = format!("{en_tete}\n  {pq}\n");
            let c = client(vec![lignes("~/.ssh/config", &config)], Some((8, 4)));
            assert_eq!(c[0].probleme, Some(Niveau::Info), "{en_tete:?} : {:?}", messages(&c));
            assert!(
                c[0].message.contains("il manque peut-être"),
                "{en_tete:?} : {:?}",
                messages(&c)
            );
        }
        // « Host * !* » ne s'applique jamais : sa valeur est celle d'un hôte précis, la suivante décide.
        let config = format!("Host * !*\n  {pq}\nHost *\n  {classique}\n");
        let cfg = lire_config_client(&[lignes("~/.ssh/config", &config)]);
        assert_eq!(cfg.candidates.len(), 1, "{cfg:?}");
        assert_eq!(cfg.par_hote.len(), 1, "{cfg:?}");
        // La première globale à coup sûr clôt la recherche : ce qui suit, même douteux, n'y change rien.
        let config = format!("{pq}\nWarnWeakCrypto yes\nMatch user bob\n  {classique}\n  WarnWeakCrypto no\n");
        let c = client(vec![lignes("~/.ssh/config", &config)], Some((10, 6)));
        assert!(c.len() == 1 && c[0].probleme.is_none(), "{:?}", messages(&c));
        // Le fichier du compte n'a que du douteux : celui du système reste candidat.
        let compte = lignes("~/.ssh/config", &format!("Match user bob\n  {pq}\n"));
        let systeme = lignes("/etc/ssh/ssh_config", &format!("{classique}\n"));
        let c = client(vec![compte, systeme], Some((10, 6)));
        assert!(c[0].message.contains("/etc/ssh/ssh_config"), "{:?}", messages(&c));
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

    /// SSH refuse « ~ » dans /etc/ssh/ssh_config : le motif est dit non lu, jamais lu dans une maison ni dans /etc/ssh.
    #[cfg(unix)]
    #[test]
    fn le_tilde_est_refuse_dans_la_configuration_du_systeme() {
        let mut plafond = super::super::Plafond {
            fichiers: 128,
            entrees: 4096,
            depasse: None,
        };
        let lus = inclus_du_systeme("~/.ssh/inclus", &mut plafond);
        assert!(
            matches!(&lus[..], [(f, Err(r))] if f == "~/.ssh/inclus"
                && (r.contains("refusé par SSH") || r.contains("refused by SSH"))),
            "{lus:?}"
        );
    }
}
