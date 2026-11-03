//! La forme des lignes des ordres du blocage (`ordres`) : la liste fermée des gestes, chacun avec ses paramètres
//! typés, écrits sous une seule forme admise et relus exactement. Du code pur, sans E/S ni texte pour la personne
//! (la phrase de chaque ordre, son permis par système, le rejugement et l'exécution restent dans `ordres`), lu aussi
//! par le banc de fuzzing (fuzz/fuzz_targets/ordres.rs) : c'est ce que l'assistant élevé de Linux et macOS, et le
//! processus élevé de Windows, lisent d'un Vanguard non élevé.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::net::IpAddr;

use super::pare_feu::PareFeu;

/// Devant chaque verbe (le même que celui des corrections natives de Windows : les verbes ne se recouvrent pas).
pub(crate) const PREFIXE: &str = "vanguard:";
/// Une ligne plus longue ne vient pas de Vanguard : le plus long ordre porte un chemin de 4 096 octets en hexadécimal.
pub(crate) const LIGNE_MAX: usize = 8448;
/// Au-delà, une liste n'est pas celle d'une session de Vanguard.
pub(crate) const LIGNES_MAX: usize = 512;
/// Le plus long chemin de programme qu'un ordre d'arrêt porte.
pub(crate) const CHEMIN_MAX: usize = 4096;

/// Un geste de la liste fermée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ordre {
    /// La règle sortante vers une adresse.
    BloquerSortie {
        pare_feu: PareFeu,
        ip: IpAddr,
    },
    DebloquerSortie {
        pare_feu: PareFeu,
        ip: IpAddr,
    },
    /// La règle qui ferme un port TCP en entrée (sauf depuis cet ordinateur).
    FermerPort {
        pare_feu: PareFeu,
        port: u16,
    },
    RouvrirPort {
        pare_feu: PareFeu,
        port: u16,
    },
    /// Couper les connexions déjà ouvertes vers une adresse (Linux : sock_diag ; macOS : pfctl -k).
    CouperConnexions {
        ip: IpAddr,
    },
    /// Arrêter ce processus, seulement s'il fait toujours tourner ce programme.
    ArreterProcessus {
        pid: u32,
        chemin: String,
    },
    /// Windows : la liste de blocage des pilotes vulnérables remise à sa valeur d'avant (`None` : valeur absente).
    RemettrePilotes {
        avant: Option<u32>,
    },
}

fn nom_pare_feu(p: PareFeu) -> &'static str {
    match p {
        PareFeu::Ufw => "ufw",
        PareFeu::Nftables => "nftables",
        PareFeu::Windows => "windows",
        PareFeu::Pf => "pf",
    }
}

fn pare_feu_de(t: &str) -> Option<PareFeu> {
    [PareFeu::Ufw, PareFeu::Nftables, PareFeu::Windows, PareFeu::Pf]
        .into_iter()
        .find(|p| nom_pare_feu(*p) == t)
}

fn hex(octets: &[u8]) -> String {
    use std::fmt::Write as _;
    octets
        .iter()
        .fold(String::with_capacity(octets.len().saturating_mul(2)), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        })
}

/// L'hexadécimal en minuscules, par paires ; `None` pour une longueur impaire ou un autre caractère.
fn de_hex(t: &str) -> Option<Vec<u8>> {
    let chiffre = |o: u8| match o {
        b'0'..=b'9' => o.checked_sub(b'0'),
        b'a'..=b'f' => o.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    };
    let (paires, reste) = t.as_bytes().as_chunks::<2>();
    if !reste.is_empty() {
        return None;
    }
    paires
        .iter()
        .map(|[h, b]| chiffre(*h)?.checked_mul(16)?.checked_add(chiffre(*b)?))
        .collect()
}

impl Ordre {
    /// La ligne qui porte cet ordre, sous sa seule forme admise.
    pub(crate) fn ligne(&self) -> String {
        match self {
            Ordre::BloquerSortie { pare_feu, ip } => {
                format!(
                    "{PREFIXE}bloquer-sortie {} {}",
                    nom_pare_feu(*pare_feu),
                    ip.to_canonical()
                )
            }
            Ordre::DebloquerSortie { pare_feu, ip } => {
                format!(
                    "{PREFIXE}debloquer-sortie {} {}",
                    nom_pare_feu(*pare_feu),
                    ip.to_canonical()
                )
            }
            Ordre::FermerPort { pare_feu, port } => format!("{PREFIXE}fermer-port {} {port}", nom_pare_feu(*pare_feu)),
            Ordre::RouvrirPort { pare_feu, port } => {
                format!("{PREFIXE}rouvrir-port {} {port}", nom_pare_feu(*pare_feu))
            }
            Ordre::CouperConnexions { ip } => format!("{PREFIXE}couper-connexions {}", ip.to_canonical()),
            Ordre::ArreterProcessus { pid, chemin } => {
                format!("{PREFIXE}arreter-processus {pid} {}", hex(chemin.as_bytes()))
            }
            Ordre::RemettrePilotes { avant: Some(v) } => format!("{PREFIXE}remettre-pilotes {v}"),
            Ordre::RemettrePilotes { avant: None } => format!("{PREFIXE}remettre-pilotes absent"),
        }
    }
}

/// L'ordre que porte une ligne, si et seulement si la ligne est exactement sa forme admise : le préfixe, un verbe de
/// la liste, des paramètres séparés par une espace, chacun reparsé puis réécrit à l'identique (une adresse IPv4
/// écrite en IPv6, un zéro de tête, une majuscule, une espace de trop : refusés).
pub(crate) fn analyser(ligne: &str) -> Option<Ordre> {
    if ligne.len() > LIGNE_MAX {
        return None;
    }
    let reste = ligne.strip_prefix(PREFIXE)?;
    let mots: Vec<&str> = reste.split(' ').collect();
    let ip = |t: &str| t.parse::<IpAddr>().ok();
    let port = |t: &str| t.parse::<u16>().ok().filter(|p| *p != 0);
    let ordre = match mots.as_slice() {
        ["bloquer-sortie", p, a] => Ordre::BloquerSortie {
            pare_feu: pare_feu_de(p)?,
            ip: ip(a)?,
        },
        ["debloquer-sortie", p, a] => Ordre::DebloquerSortie {
            pare_feu: pare_feu_de(p)?,
            ip: ip(a)?,
        },
        ["fermer-port", p, n] => Ordre::FermerPort {
            pare_feu: pare_feu_de(p)?,
            port: port(n)?,
        },
        ["rouvrir-port", p, n] => Ordre::RouvrirPort {
            pare_feu: pare_feu_de(p)?,
            port: port(n)?,
        },
        ["couper-connexions", a] => Ordre::CouperConnexions { ip: ip(a)? },
        ["arreter-processus", n, c] => {
            let chemin = String::from_utf8(de_hex(c)?).ok()?;
            let absolu = chemin_absolu(&chemin);
            if chemin.is_empty() || chemin.len() > CHEMIN_MAX || !absolu || chemin.contains(['\0', '\n', '\r']) {
                return None;
            }
            Ordre::ArreterProcessus {
                pid: n.parse::<u32>().ok().filter(|p| *p != 0)?,
                chemin,
            }
        }
        ["remettre-pilotes", "absent"] => Ordre::RemettrePilotes { avant: None },
        // Les deux seules valeurs que cette clé a jamais eues avant un blocage de Vanguard.
        ["remettre-pilotes", v @ ("0" | "1")] => Ordre::RemettrePilotes { avant: v.parse().ok() },
        _ => return None,
    };
    (ordre.ligne() == ligne).then_some(ordre)
}

/// Un chemin complet, d'Unix (« / ») ou de Windows (« C:\ », « \\?\ ») : écrit à part de `Path`, pour que la
/// ligne d'un système se relise pareil sur l'autre (les essais, et la note relue).
fn chemin_absolu(c: &str) -> bool {
    let o = c.as_bytes();
    c.starts_with('/')
        || c.starts_with(r"\\?\")
        || matches!(o, [lettre, b':', b'\\', ..] if lettre.is_ascii_alphabetic())
}
