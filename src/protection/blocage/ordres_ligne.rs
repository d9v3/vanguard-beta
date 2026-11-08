//! La forme des lignes des ordres du blocage (`ordres`) : la liste fermée des gestes, chacun avec ses paramètres
//! typés, écrits sous une seule forme admise et relus exactement. Du code pur, sans E/S ni texte pour la personne
//! (la phrase de chaque ordre, son permis par système, le rejugement et l'exécution restent dans `ordres`), lu aussi
//! par le banc de fuzzing (fuzz/fuzz_targets/ordres.rs) : c'est ce que l'assistant élevé de Linux, et le
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
/// La plus longue pause du garde des lancements (Défense L3) : un jour ; au-delà, le garde se repose ou se retire.
pub(crate) const PAUSE_MAX: u32 = 86_400;
/// Au plus autant d'adresses gardées par l'isolement (Défense R4) : les sessions à distance en cours.
pub(crate) const GARDER_MAX: usize = 16;

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
    /// Couper les connexions déjà ouvertes vers une adresse (Linux : sock_diag).
    CouperConnexions {
        ip: IpAddr,
    },
    /// Arrêter ce processus, seulement s'il fait toujours tourner ce programme. `demande` : la personne l'a demandé
    /// elle-même (jamais un geste automatique) ; une signature illisible y donne une question posée dans une vraie
    /// console, au lieu d'un refus (défense D6a, choix 3.1). Sans lui, illisible refuse.
    ArreterProcessus {
        pid: u32,
        chemin: String,
        demande: bool,
    },
    /// Suspendre ce processus (le geler sans l'arrêter), seulement s'il fait toujours tourner ce programme : toujours
    /// demandé par la personne (menu des gestes, `vanguard blocage suspendre`), jamais automatique.
    SuspendreProcessus {
        pid: u32,
        chemin: String,
        /// Son départ lu avant l'ordre (Linux : 22e champ de stat ; Windows : heure de création), s'il se lit : le
        /// processus élevé n'agit que sur ce processus-là, pas sur un autre venu sur ce numéro avec ce programme.
        depart: Option<u64>,
    },
    /// Lever la suspension de ce processus, seulement s'il fait toujours tourner ce programme (depuis `depart`, s'il
    /// est connu).
    ReprendreProcessus {
        pid: u32,
        chemin: String,
        depart: Option<u64>,
    },
    /// Couper le réseau de ce processus (Défense R3), seulement s'il fait toujours tourner ce programme depuis
    /// `depart` (obligatoire : sans lui, rien ne distingue un autre processus venu sur ce numéro). Linux : le processus
    /// dans un scope à lui, dont nf_tables jette les prises, et ses prises déjà ouvertes coupées ; Windows : deux
    /// règles du pare-feu sur le programme (tous ses processus).
    CouperReseauProgramme {
        pid: u32,
        chemin: String,
        depart: u64,
    },
    /// Rendre le réseau coupé par l'ordre précédent (les mêmes pid, chemin et départ).
    RendreReseauProgramme {
        pid: u32,
        chemin: String,
        depart: u64,
    },
    /// Windows : retirer les deux règles de coupure de Vanguard sur ce fichier, sans processus (retrouvées par leur
    /// nom dans le Pare-feu quand la liste de Vanguard ne les connaît plus).
    RendreReseauFichier {
        chemin: String,
    },
    /// Windows : la liste de blocage des pilotes vulnérables remise à sa valeur d'avant (`None` : valeur absente).
    RemettrePilotes {
        avant: Option<u32>,
    },
    /// Linux (Défense L3) : poser le garde des lancements, le service système `vanguard-garde`, pour ce compte (jamais
    /// root), qui lui prépare ses listes d'empreintes dans ce dossier (le sien, rejugé par l'élevé).
    GardePoser {
        compte: u32,
        dossier: String,
    },
    /// Le programme du garde remplacé par celui de l'assistant (une nouvelle version), son unité réécrite.
    GardeMettreAJour,
    /// Le mode du garde : `refus` refuse le certain ; sinon observation (tout passe, ce qu'il aurait refusé est noté).
    GardeRegler {
        refus: bool,
    },
    /// Le garde en pause pendant ces secondes (au plus `PAUSE_MAX`) ; zéro lève la pause.
    GardePause {
        secondes: u32,
    },
    /// Ce fichier (son SHA-256) n'est plus jamais refusé par le garde.
    GardePermettre {
        sha256: [u8; 32],
    },
    /// Le garde retiré exactement : service, programme, réglages et état.
    GardeRetirer,
    /// Isoler l'ordinateur du réseau (Défense R4) en gardant ces adresses : celles des sessions à distance en cours,
    /// montrées avant l'accord (triées, sans double, au plus `GARDER_MAX`). L'élevé relit les sessions et refuse si
    /// l'une n'y est pas ; il ajoute lui-même ce qui reste permis (boucle locale, DHCP, DNS en place, serveurs de
    /// Vanguard).
    Isoler {
        garder: Vec<IpAddr>,
    },
    /// Lever l'isolement : ce qui porte la marque de Vanguard seulement, l'état d'avant remis.
    LeverIsolement,
}

fn nom_pare_feu(p: PareFeu) -> &'static str {
    match p {
        PareFeu::Ufw => "ufw",
        PareFeu::Nftables => "nftables",
        PareFeu::Windows => "windows",
    }
}

fn pare_feu_de(t: &str) -> Option<PareFeu> {
    [PareFeu::Ufw, PareFeu::Nftables, PareFeu::Windows]
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
            Ordre::ArreterProcessus { pid, chemin, demande } => {
                let verbe = if *demande {
                    "arreter-processus-demande"
                } else {
                    "arreter-processus"
                };
                format!("{PREFIXE}{verbe} {pid} {}", hex(chemin.as_bytes()))
            }
            Ordre::SuspendreProcessus { pid, chemin, depart } => {
                format!(
                    "{PREFIXE}suspendre-processus {pid} {}{}",
                    hex(chemin.as_bytes()),
                    avec_depart(*depart)
                )
            }
            Ordre::ReprendreProcessus { pid, chemin, depart } => {
                format!(
                    "{PREFIXE}reprendre-processus {pid} {}{}",
                    hex(chemin.as_bytes()),
                    avec_depart(*depart)
                )
            }
            Ordre::CouperReseauProgramme { pid, chemin, depart } => {
                format!(
                    "{PREFIXE}couper-reseau-programme {pid} {} {depart}",
                    hex(chemin.as_bytes())
                )
            }
            Ordre::RendreReseauProgramme { pid, chemin, depart } => {
                format!(
                    "{PREFIXE}rendre-reseau-programme {pid} {} {depart}",
                    hex(chemin.as_bytes())
                )
            }
            Ordre::RendreReseauFichier { chemin } => {
                format!("{PREFIXE}rendre-reseau-fichier {}", hex(chemin.as_bytes()))
            }
            Ordre::RemettrePilotes { avant: Some(v) } => format!("{PREFIXE}remettre-pilotes {v}"),
            Ordre::RemettrePilotes { avant: None } => format!("{PREFIXE}remettre-pilotes absent"),
            Ordre::GardePoser { compte, dossier } => {
                format!("{PREFIXE}garde-poser {compte} {}", hex(dossier.as_bytes()))
            }
            Ordre::GardeMettreAJour => format!("{PREFIXE}garde-maj"),
            Ordre::GardeRegler { refus } => {
                format!("{PREFIXE}garde-regler {}", if *refus { "refus" } else { "observation" })
            }
            Ordre::GardePause { secondes } => format!("{PREFIXE}garde-pause {secondes}"),
            Ordre::GardePermettre { sha256 } => format!("{PREFIXE}garde-permettre {}", hex(sha256)),
            Ordre::GardeRetirer => format!("{PREFIXE}garde-retirer"),
            Ordre::Isoler { garder } if garder.is_empty() => format!("{PREFIXE}isoler"),
            Ordre::Isoler { garder } => {
                let liste: Vec<String> = garder.iter().map(IpAddr::to_string).collect();
                format!("{PREFIXE}isoler {}", liste.join(","))
            }
            Ordre::LeverIsolement => format!("{PREFIXE}lever-isolement"),
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
        [verbe @ ("arreter-processus" | "arreter-processus-demande"), n, c] => Ordre::ArreterProcessus {
            pid: pid_de(n)?,
            chemin: chemin_de(c)?,
            demande: *verbe == "arreter-processus-demande",
        },
        ["suspendre-processus", n, c, d @ ..] if d.len() <= 1 => Ordre::SuspendreProcessus {
            pid: pid_de(n)?,
            chemin: chemin_de(c)?,
            depart: depart_de(d).ok()?,
        },
        ["reprendre-processus", n, c, d @ ..] if d.len() <= 1 => Ordre::ReprendreProcessus {
            pid: pid_de(n)?,
            chemin: chemin_de(c)?,
            depart: depart_de(d).ok()?,
        },
        ["couper-reseau-programme", n, c, d] => Ordre::CouperReseauProgramme {
            pid: pid_de(n)?,
            chemin: chemin_de(c)?,
            depart: depart_de(&[d]).ok()??,
        },
        ["rendre-reseau-programme", n, c, d] => Ordre::RendreReseauProgramme {
            pid: pid_de(n)?,
            chemin: chemin_de(c)?,
            depart: depart_de(&[d]).ok()??,
        },
        ["rendre-reseau-fichier", c] => Ordre::RendreReseauFichier { chemin: chemin_de(c)? },
        ["remettre-pilotes", "absent"] => Ordre::RemettrePilotes { avant: None },
        // Les deux seules valeurs que cette clé a jamais eues avant un blocage de Vanguard.
        ["remettre-pilotes", v @ ("0" | "1")] => Ordre::RemettrePilotes { avant: v.parse().ok() },
        // Le compte du garde n'est jamais root : ses listes viendraient d'un dossier que personne d'autre ne tient.
        ["garde-poser", u, c] => Ordre::GardePoser {
            compte: u.parse::<u32>().ok().filter(|u| *u != 0)?,
            dossier: chemin_de(c).filter(|d| d.starts_with('/'))?,
        },
        ["garde-maj"] => Ordre::GardeMettreAJour,
        ["garde-regler", m @ ("observation" | "refus")] => Ordre::GardeRegler { refus: *m == "refus" },
        ["garde-pause", n] => Ordre::GardePause {
            secondes: n.parse::<u32>().ok().filter(|s| *s <= PAUSE_MAX)?,
        },
        ["garde-permettre", e] => Ordre::GardePermettre {
            sha256: de_hex(e)?.try_into().ok()?,
        },
        ["garde-retirer"] => Ordre::GardeRetirer,
        ["isoler"] => Ordre::Isoler { garder: Vec::new() },
        ["isoler", liste] => Ordre::Isoler {
            garder: garder_de(liste)?,
        },
        ["lever-isolement"] => Ordre::LeverIsolement,
        _ => return None,
    };
    (ordre.ligne() == ligne).then_some(ordre)
}

/// Les adresses gardées par l'isolement : séparées par une virgule, de 1 à `GARDER_MAX`, strictement croissantes
/// (ni double ni ordre au choix), chacune une adresse d'un hôte joignable : ni non spécifiée, ni multidiffusion, ni
/// IPv4 écrite en IPv6 (la même adresse aurait deux formes).
pub(crate) fn garder_de(liste: &str) -> Option<Vec<IpAddr>> {
    let garder: Vec<IpAddr> = liste
        .split(',')
        .map(|t| t.parse::<IpAddr>().ok())
        .collect::<Option<_>>()?;
    let hote = |ip: &IpAddr| !ip.is_unspecified() && !ip.is_multicast() && ip.to_canonical() == *ip;
    let valide = !garder.is_empty()
        && garder.len() <= GARDER_MAX
        && garder.iter().all(hote)
        && garder.windows(2).all(|p| matches!(p, [a, b] if a < b));
    valide.then_some(garder)
}

/// Le départ en fin de ligne d'une suspension ou d'une reprise : absent, ou un entier non nul.
fn avec_depart(d: Option<u64>) -> String {
    d.map(|d| format!(" {d}")).unwrap_or_default()
}

/// Le départ relu : aucun mot (`Ok(None)`), ou un entier non nul ; autre chose, `Err` (ligne refusée).
fn depart_de(d: &[&str]) -> Result<Option<u64>, ()> {
    match d {
        [] => Ok(None),
        [t] => t.parse::<u64>().ok().filter(|d| *d != 0).map(Some).ok_or(()),
        _ => Err(()),
    }
}

/// Un numéro de processus : ni zéro (« tout le groupe » pour kill), ni autre chose qu'un entier.
fn pid_de(t: &str) -> Option<u32> {
    t.parse::<u32>().ok().filter(|p| *p != 0)
}

/// Le chemin d'un programme, en hexadécimal : de l'UTF-8, complet, non vide, d'au plus `CHEMIN_MAX` octets, sans
/// caractère nul ni fin de ligne.
fn chemin_de(t: &str) -> Option<String> {
    let chemin = String::from_utf8(de_hex(t)?).ok()?;
    let valide = !chemin.is_empty()
        && chemin.len() <= CHEMIN_MAX
        && chemin_absolu(&chemin)
        && !chemin.contains(['\0', '\n', '\r']);
    valide.then_some(chemin)
}

/// Un chemin complet, d'Unix (« / ») ou de Windows (« C:\ », « \\?\ ») : écrit à part de `Path`, pour que la
/// ligne d'un système se relise pareil sur l'autre (les essais, et la note relue).
fn chemin_absolu(c: &str) -> bool {
    let o = c.as_bytes();
    c.starts_with('/')
        || c.starts_with(r"\\?\")
        || matches!(o, [lettre, b':', b'\\', ..] if lettre.is_ascii_alphabetic())
}
