//! La grammaire des gestes de Linux que l'assistant élevé (`machine::assistant`) fait en root, à côté des ordres du
//! blocage (`protection::blocage::ordres`) : une ligne « `vanguard:geste <famille> <champs>` » ne fait que DÉSIGNER
//! un geste d'une liste fermée, et l'enfant root la relit, la rejuge avec ses propres yeux, puis le fait sans shell,
//! par le chemin absolu de l'outil (`commande::outil_systeme`) et dans un environnement vidé
//! (`commande::environnement_propre`). Rien ici ne lance quoi que ce soit : du code pur, sans E/S, compilé partout
//! pour ses tests et lu par le banc de fuzzing (fuzz/fuzz_targets/gestes_unix.rs).
//!
//! Les familles :
//! - `programme <id>` : un programme de la table `PROGRAMMES`, avec ses arguments figés. La ligne ne porte ni chemin,
//!   ni argument, ni texte libre : seulement l'identifiant ;
//! - `unite <action> <nom>` : une action fermée (`ActionUnite`) sur une unité de systemd de la table `UNITES_CONNUES`,
//!   faite par le bus système (`machine::linux::dbus::systeme`), jamais par systemctl ; `unite reinitialiser-echecs`
//!   (reset-failed, sans nom) ;
//! - `unite-designee <action> <nom>` : arrêter, ou ne plus lancer au démarrage, une unité qui n'est pas dans la table
//!   mais que `protection::distance` a trouvée (un logiciel de prise de contrôle à distance) ; le nom suit une règle
//!   stricte (`nom_admis`), et l'enfant relit le fichier de l'unité et le reconnaît lui-même avant d'agir ;
//! - `signatures-clamav` : le geste composé de la mise à jour des signatures (arrêter clamav-freshclam, freshclam,
//!   le réactiver), pour qu'aucun « arrêter clamav-freshclam » isolé n'existe ;
//! - `defense <mot> <champs> <id>` : une correction du bilan qui retire un accès, un droit ou un lancement
//!   (`Defense` : verrouiller un compte, le retirer d'un groupe, faire redemander son mot de passe par sudo, retirer
//!   setuid ou des capacités, rendre un dossier à root, désactiver un service ajouté, retirer une ligne d'un fichier
//!   de démarrage), ou `remettre <id>`, qui la défait. Un compte suit `nom_compte_admis`, un chemin s'écrit en
//!   hexadécimal (`hex`) et se montre échappé (`echappe`), l'identifiant (`IdNote`) nomme la note d'« avant » que
//!   l'enfant écrit (`note_avant_unix`). Ni sshd, ni le gestionnaire de session, ni le réseau
//!   (`unite_portant_les_sessions`), ni un fichier hors de `fichier_de_ligne_admis` : la ligne ne se relit pas.
//!
//! Les familles des paquets, des fichiers de configuration et du réseau suivront (plan du lot Unix, U2, U4 à U7), sur
//! le même canal et avec les mêmes bornes ; elles reprendront `unite` telle quelle (masquer et démasquer y viendront
//! avec elles).
//!
//! Un geste qui affaiblit la protection ou supprime quelque chose (`demande_accord`) : l'enfant demande alors l'accord
//! de la personne sur son terminal (/dev/tty), et le refuse sans terminal (`assistant`). Un pare-feu n'est jamais
//! coupé : la ligne qui le demanderait ne se relit même pas (`refus`).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// Devant chaque geste : le préfixe des ordres (`ordres::PREFIXE`) suivi de « geste », un verbe qu'aucun ordre ni
/// aucun geste de Windows (`gestes.rs` : `vanguard:programme`, `vanguard:service`…) ne prend.
pub(crate) const PREFIXE: &str = "vanguard:geste ";
/// La plus longue ligne admise sur le canal : celle d'un ordre du blocage, `ordres::LIGNE_MAX` (repris ici pour que le
/// banc de fuzzing lise ce module seul ; l'essai `bornes_du_canal_communes_avec_les_ordres` les garde égales). Le
/// nombre de lignes d'une liste est borné par le canal lui-même (`ordres::LIGNES_MAX`, lu par l'assistant).
pub(crate) const LIGNE_MAX: usize = 8448;
/// La plus longue ligne d'un geste : celle qui retire une ligne d'un fichier (« vanguard:geste defense retirer-ligne »,
/// espace comprise, 38 octets, l'empreinte en 64 chiffres, un chemin de `CHEMIN_MAX` octets en 512 chiffres et
/// l'identifiant de 16, chacun précédé d'une espace : 633) ; tout ce qui dépasse est refusé avant d'être découpé.
pub(crate) const GESTE_MAX: usize = 640;
const _: () = assert!(GESTE_MAX <= LIGNE_MAX, "un geste tient dans une ligne du canal");

/// Un programme figé : l'outil, cherché par l'enfant dans les dossiers du système, et ses arguments, tous écrits ici.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Programme {
    /// `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    /// Le nom de l'outil, sans dossier : l'enfant le cherche par `commande::outil_systeme`, jamais par un PATH.
    pub outil: &'static str,
    pub arguments: &'static [&'static str],
    /// Les codes de sortie qui veulent dire « fait ».
    pub reussites: &'static [i32],
    /// Le délai, en secondes, au-delà duquel l'outil est arrêté et le geste compté en échec.
    pub delai: u64,
    /// Le geste baisse une protection (le remettre comme avant, après un durcissement) : accord sur le terminal.
    pub affaiblit: bool,
    /// Le geste supprime quelque chose : accord sur le terminal.
    pub supprime: bool,
    pub fr: &'static str,
    pub en: &'static str,
}

/// Les signatures de ClamAV : freshclam les télécharge. Seul 0 veut dire « fait » ; tout autre code est une erreur
/// (réseau, miroir, base verrouillée par le service clamav-freshclam), rendue avec sa raison.
pub(crate) static FRESHCLAM: Programme = Programme {
    id: "freshclam",
    outil: "freshclam",
    arguments: &[],
    reussites: &[0],
    delai: 900,
    affaiblit: false,
    supprime: false,
    fr: "Mettre à jour les signatures de virus de ClamAV (freshclam)",
    en: "Update the ClamAV virus signatures (freshclam)",
};

/// La table : un identifiant n'y est qu'une fois (essai `la_table_est_bien_formee`).
pub(crate) static PROGRAMMES: &[&Programme] = &[&FRESHCLAM];

/// Ce que l'enfant fait d'une unité de systemd, par le bus système (comme `systemctl`, sans lui).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionUnite {
    /// `enable --now` : EnableUnitFiles, Reload, puis StartUnit jusqu'à la fin du job.
    Activer,
    /// `disable --now` : DisableUnitFiles, Reload, puis StopUnit jusqu'à la fin du job.
    Desactiver,
    /// `disable` seul : DisableUnitFiles, Reload ; l'unité tourne jusqu'au prochain démarrage.
    DesactiverSansArreter,
    /// `enable` seul : EnableUnitFiles, Reload ; l'unité n'est pas lancée. Seulement pour Défaire, dans l'enfant de
    /// Défense : un service activé qui ne tournait pas revient ainsi, sans être lancé un instant (`enable --now` puis
    /// `stop` l'aurait fait). Hors de `TOUTES` : aucune ligne du parent ne la nomme.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ActiverSansDemarrer,
    /// `start`.
    Demarrer,
    /// `stop`.
    Arreter,
    /// `try-restart` : seulement si elle tourne déjà (TryRestartUnit).
    Redemarrer,
    /// `reload-or-try-restart` (ReloadOrTryRestartUnit).
    Recharger,
}

impl ActionUnite {
    pub(crate) const TOUTES: [ActionUnite; 7] = [
        ActionUnite::Activer,
        ActionUnite::Desactiver,
        ActionUnite::DesactiverSansArreter,
        ActionUnite::Demarrer,
        ActionUnite::Arreter,
        ActionUnite::Redemarrer,
        ActionUnite::Recharger,
    ];

    /// Le mot de l'action sur la ligne.
    pub(crate) fn mot(self) -> &'static str {
        match self {
            ActionUnite::Activer => "activer",
            ActionUnite::Desactiver => "desactiver",
            ActionUnite::DesactiverSansArreter => "desactiver-sans-arreter",
            ActionUnite::ActiverSansDemarrer => "activer-sans-demarrer",
            ActionUnite::Demarrer => "demarrer",
            ActionUnite::Arreter => "arreter",
            ActionUnite::Redemarrer => "redemarrer",
            ActionUnite::Recharger => "recharger",
        }
    }

    fn depuis_mot(mot: &str) -> Option<Self> {
        Self::TOUTES.into_iter().find(|a| a.mot() == mot)
    }
}

/// Ce que l'enfant protège d'une unité de la table, avant toute action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Garde {
    /// Toute action de la liste est permise.
    Ordinaire,
    /// Un pare-feu : activé ou démarré seulement ; jamais arrêté, désactivé, redémarré ni rechargé (principe « pas
    /// de pare-feu coupé », même un instant : ufw n'a pas de rechargement à lui, ReloadOrTryRestart le redémarrerait).
    PareFeu,
    /// Une protection (audit, antivirus, AppArmor) : la désactiver ou l'arrêter demande l'accord de la personne sur
    /// son terminal.
    Protection,
    /// Le réseau : l'arrêter ou le redémarrer couperait une session à distance entrante ; refusé tant qu'il y en a
    /// une, ou que les connexions ne se lisent pas. Le désactiver demande l'accord : l'ordinateur perdrait le réseau.
    Reseau,
    /// Un service ouvert au réseau local (cups-browsed écoute sur le port UDP 631, jugé « Élevé » au bilan) : l'activer
    /// ou le démarrer demande l'accord de la personne.
    Ouverte,
}

/// Une unité de systemd que Vanguard sait nommer, avec sa garde et ce qu'elle est pour une personne.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UniteConnue {
    /// Le nom complet, suffixe compris (`nom_admis`).
    pub nom: &'static str,
    pub garde: Garde,
    /// Ce qu'elle est, avec son article : « le service d'impression (CUPS) ».
    pub fr: &'static str,
    pub en: &'static str,
}

pub(crate) static UFW: UniteConnue = UniteConnue {
    nom: "ufw.service",
    garde: Garde::PareFeu,
    fr: "le pare-feu ufw",
    en: "the ufw firewall",
};
pub(crate) static FIREWALLD: UniteConnue = UniteConnue {
    nom: "firewalld.service",
    garde: Garde::PareFeu,
    fr: "le pare-feu firewalld",
    en: "the firewalld firewall",
};
pub(crate) static AUDITD: UniteConnue = UniteConnue {
    nom: "auditd.service",
    garde: Garde::Protection,
    fr: "le journal d'audit (auditd)",
    en: "the audit log (auditd)",
};
pub(crate) static APPARMOR: UniteConnue = UniteConnue {
    nom: "apparmor.service",
    garde: Garde::Protection,
    fr: "la protection AppArmor",
    en: "the AppArmor protection",
};
pub(crate) static CLAMAV_FRESHCLAM: UniteConnue = UniteConnue {
    nom: "clamav-freshclam.service",
    garde: Garde::Protection,
    fr: "la mise à jour automatique des signatures de ClamAV (clamav-freshclam)",
    en: "the automatic ClamAV signature updates (clamav-freshclam)",
};
pub(crate) static CLAMAV_DAEMON: UniteConnue = UniteConnue {
    nom: "clamav-daemon.service",
    garde: Garde::Protection,
    fr: "l'antivirus ClamAV en fond (clamav-daemon)",
    en: "the ClamAV background antivirus (clamav-daemon)",
};
pub(crate) static NETWORKMANAGER: UniteConnue = UniteConnue {
    nom: "NetworkManager.service",
    garde: Garde::Reseau,
    fr: "le gestionnaire du réseau (NetworkManager)",
    en: "the network manager (NetworkManager)",
};
pub(crate) static NETWORKD: UniteConnue = UniteConnue {
    nom: "systemd-networkd.service",
    garde: Garde::Reseau,
    fr: "le gestionnaire du réseau (systemd-networkd)",
    en: "the network manager (systemd-networkd)",
};
pub(crate) static CUPS: UniteConnue = UniteConnue {
    nom: "cups.service",
    garde: Garde::Ordinaire,
    fr: "le service d'impression (CUPS)",
    en: "the printing service (CUPS)",
};
pub(crate) static CUPS_BROWSED: UniteConnue = UniteConnue {
    nom: "cups-browsed.service",
    garde: Garde::Ouverte,
    fr: "la recherche d'imprimantes sur le réseau (cups-browsed)",
    en: "the network printer discovery (cups-browsed)",
};
pub(crate) static FSTRIM: UniteConnue = UniteConnue {
    nom: "fstrim.timer",
    garde: Garde::Ordinaire,
    fr: "l'entretien hebdomadaire du SSD (fstrim.timer)",
    en: "the weekly SSD maintenance (fstrim.timer)",
};

/// La table : seules ces unités se nomment par `unite` ; un nom n'y est qu'une fois (essai
/// `la_table_est_bien_formee`). U4 et U6 y ajouteront les leurs (sshd, ollama, smb…).
pub(crate) static UNITES_CONNUES: &[&UniteConnue] = &[
    &UFW,
    &FIREWALLD,
    &AUDITD,
    &APPARMOR,
    &CLAMAV_FRESHCLAM,
    &CLAMAV_DAEMON,
    &NETWORKMANAGER,
    &NETWORKD,
    &CUPS,
    &CUPS_BROWSED,
    &FSTRIM,
];

/// L'unité de la table de ce nom, complet ou sans « .service » (« auditd », « fstrim.timer »).
// Seuls les réglages et le retrait des programmes de contrôle à distance de Linux les demandent.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unite_connue(nom: &str) -> Option<&'static UniteConnue> {
    UNITES_CONNUES
        .iter()
        .copied()
        .find(|u| u.nom == nom || u.nom.strip_suffix(".service") == Some(nom))
}

/// Le plus long nom d'unité admis (systemd en permet 255 ; aucun service connu n'en approche).
pub(crate) const NOM_UNITE_MAX: usize = 128;
/// Les seuls genres d'unité qu'un geste vise.
const SUFFIXES: [&str; 3] = [".service", ".socket", ".timer"];

/// Un nom d'unité qu'un geste peut porter : 128 octets au plus, lettres ASCII, chiffres, « : _ . @ - » seulement (ni
/// « / », ni « \ », ni espace), sans « .. », un suffixe .service, .socket ou .timer, une base qui commence par une
/// lettre ou un chiffre (jamais une option) et qui n'est pas un gabarit (« x@.service »).
pub(crate) fn nom_admis(nom: &str) -> bool {
    if nom.is_empty() || nom.len() > NOM_UNITE_MAX || nom.contains("..") {
        return false;
    }
    if !nom.bytes().all(|o| o.is_ascii_alphanumeric() || b":_.@-".contains(&o)) {
        return false;
    }
    let Some(base) = SUFFIXES.iter().find_map(|s| nom.strip_suffix(s)) else {
        return false;
    };
    base.bytes().next().is_some_and(|o| o.is_ascii_alphanumeric()) && !base.ends_with('@')
}

/// Le nom d'une unité désignée, recopié (le geste reste `Copy`) : admis (`nom_admis`) et hors de la table, dont les
/// unités ont leur garde et ne se désignent pas autrement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct NomUnite {
    octets: [u8; NOM_UNITE_MAX],
    longueur: u8,
}

impl NomUnite {
    pub(crate) fn nouveau(nom: &str) -> Option<Self> {
        if !nom_admis(nom) || UNITES_CONNUES.iter().any(|u| u.nom == nom) {
            return None;
        }
        let mut octets = [0; NOM_UNITE_MAX];
        octets.get_mut(..nom.len())?.copy_from_slice(nom.as_bytes());
        Some(NomUnite {
            octets,
            longueur: u8::try_from(nom.len()).ok()?,
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        self.octets
            .get(..usize::from(self.longueur))
            .and_then(|o| std::str::from_utf8(o).ok())
            .unwrap_or_default()
    }
}

impl std::fmt::Debug for NomUnite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NomUnite").field(&self.as_str()).finish()
    }
}

/// Le plus long nom de compte qu'un geste de défense désigne (useradd en admet 32).
pub(crate) const NOM_COMPTE_MAX: usize = 32;

/// Un nom de compte qu'un geste de défense peut porter : une minuscule ou « _ » d'abord (jamais une option), puis
/// minuscules, chiffres, « _ », « - », « . » seulement ; 32 octets au plus. La règle de Debian (NAME_REGEX), un peu
/// élargie : un compte dont le nom n'y tient pas reste une commande montrée, jamais un geste.
pub(crate) fn nom_compte_admis(nom: &str) -> bool {
    let mut o = nom.bytes();
    o.next().is_some_and(|p| p.is_ascii_lowercase() || p == b'_')
        && nom.len() <= NOM_COMPTE_MAX
        && o.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.".contains(&c))
}

/// Un nom de compte admis (`nom_compte_admis`), recopié : le geste reste `Copy`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct NomCompte {
    octets: [u8; NOM_COMPTE_MAX],
    longueur: u8,
}

impl NomCompte {
    pub(crate) fn nouveau(nom: &str) -> Option<Self> {
        if !nom_compte_admis(nom) {
            return None;
        }
        let mut octets = [0; NOM_COMPTE_MAX];
        octets.get_mut(..nom.len())?.copy_from_slice(nom.as_bytes());
        Some(NomCompte {
            octets,
            longueur: u8::try_from(nom.len()).ok()?,
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        self.octets
            .get(..usize::from(self.longueur))
            .and_then(|o| std::str::from_utf8(o).ok())
            .unwrap_or_default()
    }
}

impl std::fmt::Debug for NomCompte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NomCompte").field(&self.as_str()).finish()
    }
}

/// Le plus long chemin qu'un geste de défense désigne, en octets.
pub(crate) const CHEMIN_MAX: usize = 256;

/// Un chemin absolu désigné par un geste de défense, octets tels quels (un nom de fichier hostile, saut de ligne ou
/// échappement de terminal compris, reste désignable : c'est souvent celui qu'il faut traiter). Sur la ligne, il
/// s'écrit en hexadécimal : ni espace, ni « / », ni octet de contrôle n'y passent. Admis : commence par « / », 256
/// octets au plus, ni octet nul, ni « // », ni composant « . » ou « .. », ni « / » final. L'enfant le résout encore
/// lui-même (il doit être son propre chemin réel) avant d'agir.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheminDesigne {
    octets: [u8; CHEMIN_MAX],
    longueur: u16,
}

/// Le chemin a-t-il la forme stricte d'un `CheminDesigne` ?
pub(crate) fn chemin_admis(c: &[u8]) -> bool {
    if c.len() < 2 || c.len() > CHEMIN_MAX || c.first() != Some(&b'/') || c.last() == Some(&b'/') || c.contains(&0) {
        return false;
    }
    c.get(1..).is_some_and(|reste| {
        reste
            .split(|o| *o == b'/')
            .all(|p| !p.is_empty() && p != b"." && p != b"..")
    })
}

impl CheminDesigne {
    pub(crate) fn nouveau(c: &[u8]) -> Option<Self> {
        if !chemin_admis(c) {
            return None;
        }
        let mut octets = [0; CHEMIN_MAX];
        octets.get_mut(..c.len())?.copy_from_slice(c);
        Some(CheminDesigne {
            octets,
            longueur: u16::try_from(c.len()).ok()?,
        })
    }

    pub(crate) fn octets(&self) -> &[u8] {
        self.octets.get(..usize::from(self.longueur)).unwrap_or_default()
    }

    /// Le chemin, lisible : les octets imprimables d'ASCII tels quels, tout autre en « \xNN » (« \ » doublé). Pur,
    /// borné à 120 octets du chemin (« … » au-delà) : ni saut de ligne, ni échappement de terminal, ni caractère
    /// de direction n'arrive à l'écran.
    pub(crate) fn lisible(&self) -> String {
        echappe(self.octets())
    }
}

/// Les octets lisibles : ASCII imprimable tel quel, « \ » doublé, le reste en « \xNN » ; 120 octets au plus.
pub(crate) fn echappe(octets: &[u8]) -> String {
    let mut s = String::new();
    for &o in octets.iter().take(120) {
        match o {
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(char::from(o)),
            _ => {
                s.push_str("\\x");
                s.push(hex_chiffre(o >> 4));
                s.push(hex_chiffre(o & 0x0f));
            }
        }
    }
    if octets.len() > 120 {
        s.push('…');
    }
    s
}

impl std::fmt::Debug for CheminDesigne {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CheminDesigne").field(&self.lisible()).finish()
    }
}

fn hex_chiffre(v: u8) -> char {
    char::from(b"0123456789abcdef".get(usize::from(v & 0x0f)).copied().unwrap_or(b'0'))
}

/// Des octets en hexadécimal minuscule.
pub(crate) fn hex(octets: &[u8]) -> String {
    let mut s = String::with_capacity(octets.len().saturating_mul(2));
    for &o in octets {
        s.push(hex_chiffre(o >> 4));
        s.push(hex_chiffre(o & 0x0f));
    }
    s
}

/// L'hexadécimal minuscule, strict (une majuscule, un nombre impair de chiffres : refusés) ; `max` octets au plus.
pub(crate) fn depuis_hex(t: &str, max: usize) -> Option<Vec<u8>> {
    let o = t.as_bytes();
    if o.is_empty() || !o.len().is_multiple_of(2) || o.len() / 2 > max {
        return None;
    }
    let chiffre = |c: u8| match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    };
    o.chunks(2)
        .map(|p| match p {
            [h, b] => Some(chiffre(*h)?.checked_mul(16)?.checked_add(chiffre(*b)?)?),
            _ => None,
        })
        .collect()
}

/// L'identifiant de la note d'« avant » d'un geste de défense : 16 chiffres hexadécimaux minuscules, tirés au
/// hasard par le parent (`machine::defense`). Il nomme le fichier de la note (`/var/lib/vanguard/avant/<id>`) : rien
/// d'autre qu'eux n'y passe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdNote([u8; 16]);

impl IdNote {
    pub(crate) fn nouveau(t: &str) -> Option<Self> {
        let o: [u8; 16] = t.as_bytes().try_into().ok()?;
        o.iter()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            .then_some(IdNote(o))
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl std::fmt::Debug for IdNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IdNote").field(&self.as_str()).finish()
    }
}

/// L'empreinte SHA-256 d'une ligne de fichier (sans son saut de ligne), qui la désigne sans la porter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Empreinte(pub(crate) [u8; 32]);

/// Le réglage du serveur SSH qu'un geste de défense ferme (lot D7b), chacun dans son propre fichier de
/// /etc/ssh/sshd_config.d, validé par `sshd -t` avant que sshd ne le relise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReglageSsh {
    /// `PermitEmptyPasswords no`.
    MotsDePasseVides,
    /// `PermitRootLogin no`.
    Root,
    /// `PasswordAuthentication no` et `KbdInteractiveAuthentication no` : les clés seules.
    MotsDePasse,
}

impl ReglageSsh {
    pub(crate) const TOUS: [ReglageSsh; 3] = [ReglageSsh::MotsDePasseVides, ReglageSsh::Root, ReglageSsh::MotsDePasse];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ReglageSsh::MotsDePasseVides => "vides",
            ReglageSsh::Root => "root",
            ReglageSsh::MotsDePasse => "mots-de-passe",
        }
    }

    fn depuis_mot(m: &str) -> Option<Self> {
        Self::TOUS.into_iter().find(|r| r.mot() == m)
    }
}

/// Le pare-feu de Linux qu'un geste de défense coupe ou rallume (lot D7c), sur le choix de la personne seulement
/// (Options de défense) : ufw, firewalld, ou les règles de nftables quand aucun des deux ne les gère.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PareFeu {
    Ufw,
    Firewalld,
    Nftables,
}

impl PareFeu {
    pub(crate) const TOUS: [PareFeu; 3] = [PareFeu::Ufw, PareFeu::Firewalld, PareFeu::Nftables];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            PareFeu::Ufw => "ufw",
            PareFeu::Firewalld => "firewalld",
            PareFeu::Nftables => "nftables",
        }
    }

    pub(crate) fn depuis_mot(m: &str) -> Option<Self> {
        Self::TOUS.into_iter().find(|p| p.mot() == m)
    }

    /// L'identifiant FIXE de la note de sa coupure : le Vanguard non élevé sait, par la seule présence de
    /// `/var/lib/vanguard/avant/<id>` (que root seul crée), que ce pare-feu est coupé par le choix de la personne
    /// (bilan, Rallumer, mode Wi-Fi public). Aucun autre geste ne prend ces identifiants (`GesteUnix::refus`).
    pub(crate) fn note(self) -> IdNote {
        match self {
            PareFeu::Ufw => IdNote(*b"000000000000fe01"),
            PareFeu::Firewalld => IdNote(*b"000000000000fe02"),
            PareFeu::Nftables => IdNote(*b"000000000000fe03"),
        }
    }

    /// Le pare-feu dont `id` est la note de coupure, s'il y en a un.
    pub(crate) fn de_la_note(id: IdNote) -> Option<Self> {
        Self::TOUS.into_iter().find(|p| p.note() == id)
    }
}

/// Une adresse Bluetooth (six octets), telle que `bluetoothctl` l'écrit : `AA:BB:CC:DD:EE:FF`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdresseBt(pub(crate) [u8; 6]);

impl AdresseBt {
    /// L'adresse en majuscules séparées par « : », seule forme passée à `bluetoothctl`.
    pub(crate) fn texte(self) -> String {
        self.0.iter().map(|o| format!("{o:02X}")).collect::<Vec<_>>().join(":")
    }

    /// Relue de la forme `AA:BB:CC:DD:EE:FF` (majuscules ou minuscules), et d'elle seule.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn lue(t: &str) -> Option<Self> {
        let morceaux: Vec<&str> = t.split(':').collect();
        if morceaux.len() != 6 {
            return None;
        }
        let mut o = [0u8; 6];
        for (octet, m) in o.iter_mut().zip(&morceaux) {
            if m.len() != 2 || !m.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            *octet = u8::from_str_radix(m, 16).ok()?;
        }
        Some(AdresseBt(o))
    }
}

/// Les dossiers où l'on ajoute des certificats racine à ceux du système (ceux que lit `certificats`) : un geste
/// de défense n'y retire qu'un fichier, directement dedans ou dans un sous-dossier, jamais ailleurs.
pub(crate) const DOSSIERS_D_ANCRES: [&str; 4] = [
    "/etc/ca-certificates/trust-source/anchors/",
    "/usr/local/share/ca-certificates/",
    "/etc/pki/ca-trust/source/anchors/",
    "/etc/pki/trust/anchors/",
];

/// Le fichier d'ancres que ce geste peut retirer : sous l'un des `DOSSIERS_D_ANCRES`, chemin admis.
pub(crate) fn ancre_admise(c: &[u8]) -> bool {
    chemin_admis(c)
        && DOSSIERS_D_ANCRES
            .iter()
            .any(|d| c.len() > d.len() && c.starts_with(d.as_bytes()))
}

/// Les noms que porte le programme de Vanguard : celui de sa copie, celui du fichier publié pour Linux.
pub(crate) const NOMS_DU_PROGRAMME: [&str; 2] = ["vanguard", "vanguard-linux-x86_64"];

/// Les dossiers des comptes et les dossiers temporaires : un compte sans droits y écrit, et root n'y remplace jamais
/// un programme (un lien ou un renommage posé au bon moment détournerait son écriture).
pub(crate) const DOSSIERS_DES_COMPTES: [&str; 6] =
    ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/"];

/// Le programme qu'un geste « Refaire » peut remettre (lot D7b, `programmes_poses`) : un chemin admis, au nom du
/// programme de Vanguard, hors des dossiers des comptes.
pub(crate) fn programme_pose_admis(c: &[u8]) -> bool {
    chemin_admis(c)
        && c.rsplit(|o| *o == b'/')
            .next()
            .is_some_and(|nom| NOMS_DU_PROGRAMME.iter().any(|n| n.as_bytes() == nom))
        && !DOSSIERS_DES_COMPTES.iter().any(|d| c.starts_with(d.as_bytes()))
}

/// Un nombre décimal écrit sans signe, sans zéro devant ni espace : la seule forme qu'un champ numérique admet.
fn decimal<T: std::str::FromStr>(t: &str) -> Option<T> {
    let propre =
        !t.is_empty() && t.len() <= 20 && t.bytes().all(|b| b.is_ascii_digit()) && (t == "0" || !t.starts_with('0'));
    if propre { t.parse().ok() } else { None }
}

/// Les groupes qui donnent des droits d'administrateur, directement ou par un détour (`linux::privileges`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupeSensible {
    Docker,
    Lxd,
    IncusAdmin,
    Libvirt,
    Disk,
    /// Le groupe des administrateurs (sudo) : wheel, sudo ou admin selon la distribution.
    Administrateurs,
}

impl GroupeSensible {
    pub(crate) const TOUS: [GroupeSensible; 6] = [
        GroupeSensible::Docker,
        GroupeSensible::Lxd,
        GroupeSensible::IncusAdmin,
        GroupeSensible::Libvirt,
        GroupeSensible::Disk,
        GroupeSensible::Administrateurs,
    ];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            GroupeSensible::Docker => "docker",
            GroupeSensible::Lxd => "lxd",
            GroupeSensible::IncusAdmin => "incus-admin",
            GroupeSensible::Libvirt => "libvirt",
            GroupeSensible::Disk => "disk",
            GroupeSensible::Administrateurs => "administrateurs",
        }
    }

    /// Les noms de groupe de /etc/group qu'il couvre (lus par les gestes de Linux seulement).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn noms(self) -> &'static [&'static str] {
        match self {
            GroupeSensible::Docker => &["docker"],
            GroupeSensible::Lxd => &["lxd"],
            GroupeSensible::IncusAdmin => &["incus-admin"],
            GroupeSensible::Libvirt => &["libvirt"],
            GroupeSensible::Disk => &["disk"],
            GroupeSensible::Administrateurs => &["wheel", "sudo", "admin"],
        }
    }

    /// Le groupe sensible de ce nom de /etc/group.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn de_nom(nom: &str) -> Option<Self> {
        Self::TOUS.into_iter().find(|g| g.noms().contains(&nom))
    }

    fn depuis_mot(mot: &str) -> Option<Self> {
        Self::TOUS.into_iter().find(|g| g.mot() == mot)
    }
}

/// Les unités qui portent une session (la connexion à distance, l'écran de connexion, la session elle-même) : jamais
/// désactivées par un geste de défense, même ajoutées à la main. Un refus, pas un avertissement : ce n'est pas un
/// verrouillage dont on se sort, c'est la session en cours qui tomberait.
pub(crate) const UNITES_DE_SESSION: [&str; 18] = [
    "sshd.service",
    "ssh.service",
    "sshd.socket",
    "ssh.socket",
    "display-manager.service",
    "gdm.service",
    "gdm3.service",
    "sddm.service",
    "lightdm.service",
    "lxdm.service",
    "xdm.service",
    "greetd.service",
    "ly.service",
    "systemd-logind.service",
    "dbus.service",
    "dbus-broker.service",
    "polkit.service",
    "xrdp.service",
];

/// Une unité qui porte les sessions (`UNITES_DE_SESSION`), ou le réseau qu'elles traversent : réseau, tunnel, VPN,
/// pare-feu, même maison (`wg-quick` d'une interface, `pare-feu.service` qui charge nft). La couper peut faire tomber
/// une connexion à distance, que le cgroup de l'unité ne montre pas. Reconnue par un morceau de son nom, sans casse :
/// en refuser trop est sans danger, en couper une ne l'est pas.
pub(crate) fn unite_portant_les_sessions(nom: &str) -> bool {
    const MORCEAUX: [&str; 26] = [
        "wg-quick",
        "wireguard",
        "openvpn",
        "tailscale",
        "zerotier",
        "netbird",
        "nebula",
        "strongswan",
        "ipsec",
        "networkmanager",
        "systemd-networkd",
        "systemd-resolved",
        "networking",
        "wpa_supplicant",
        "iwd",
        "dhcpcd",
        "connman",
        "netplan",
        "firewalld",
        "ufw",
        "nftables",
        "iptables",
        "ip6tables",
        "shorewall",
        "firewall",
        "pare-feu",
    ];
    let bas = nom.to_ascii_lowercase();
    UNITES_DE_SESSION.contains(&nom) || MORCEAUX.iter().any(|m| bas.contains(m))
}

/// Les fichiers du système dont un geste de défense retire une ligne (un lancement suspect, une ouverture de session
/// automatique) : une liste fermée, dans /etc seulement. Un nom de fichier libre (« * ») : lettres ASCII, chiffres,
/// « . _ @ - », sans point au début.
pub(crate) fn fichier_de_ligne_admis(c: &[u8]) -> bool {
    const EXACTS: [&str; 19] = [
        "/etc/ld.so.preload",
        "/etc/environment",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/bashrc",
        "/etc/zshenv",
        "/etc/zprofile",
        "/etc/zshrc",
        "/etc/zsh/zshenv",
        "/etc/zsh/zprofile",
        "/etc/zsh/zshrc",
        "/etc/crontab",
        "/etc/rc.local",
        "/etc/gdm/custom.conf",
        "/etc/gdm3/custom.conf",
        "/etc/gdm3/daemon.conf",
        "/etc/sddm.conf",
        "/etc/lightdm/lightdm.conf",
        "/etc/anacrontab",
    ];
    const DOSSIERS: [(&str, &[&str]); 8] = [
        ("/etc/profile.d/", &[".sh", ".zsh"]),
        ("/etc/environment.d/", &[".conf"]),
        ("/etc/cron.d/", &[""]),
        ("/etc/systemd/system/", &[".service", ".timer", ".socket", ".path"]),
        ("/etc/xdg/autostart/", &[".desktop"]),
        ("/etc/sddm.conf.d/", &[".conf"]),
        ("/etc/lightdm/lightdm.conf.d/", &[".conf"]),
        ("/etc/X11/Xsession.d/", &[""]),
    ];
    let Ok(t) = std::str::from_utf8(c) else {
        return false;
    };
    if !chemin_admis(c) {
        return false;
    }
    if EXACTS.contains(&t) {
        return true;
    }
    let nom_libre = |n: &str| {
        !n.starts_with('.') && !n.is_empty() && n.bytes().all(|o| o.is_ascii_alphanumeric() || b"._@-".contains(&o))
    };
    if DOSSIERS.iter().any(|(d, fins)| {
        t.strip_prefix(d)
            .is_some_and(|n| nom_libre(n) && fins.iter().any(|f| n.ends_with(f) && n.len() > f.len()))
    }) {
        return true;
    }
    // Un complément d'unité : /etc/systemd/system/<unité>.d/<nom>.conf.
    t.strip_prefix("/etc/systemd/system/")
        .and_then(|r| r.split_once('/'))
        .is_some_and(|(d, n)| {
            d.strip_suffix(".d").is_some_and(nom_admis)
                && nom_libre(n)
                && n.len() > 5
                && n.as_bytes().ends_with(b".conf")
        })
}

/// Un geste de défense (lot D7a du plan des outils de défense) : une correction du bilan qui retire un accès, un
/// droit ou un lancement, faite par l'enfant root après l'avoir rejugée, notée avant (note d'« avant », dans
/// /var/lib/vanguard/avant, que seul root écrit) et défaite par `Remettre`. Chacun demande l'accord de la personne
/// sur son terminal ; ceux qui peuvent la couper de son ordinateur (un compte, sudo, le dernier administrateur)
/// l'avertissent d'abord, et Entrée seule dit non.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Defense {
    /// `usermod --lock --expiredate 1 --shell nologin` : le compte ne s'ouvre plus, ni par mot de passe ni par clé ;
    /// rien n'est supprimé.
    VerrouillerCompte(NomCompte),
    /// `gpasswd -d` de chaque groupe de cette famille dont le compte est membre (effectif à sa prochaine session).
    RetirerDuGroupe(GroupeSensible, NomCompte),
    /// Un complément de sudo (`/etc/sudoers.d/zz-vanguard-<nom>`) qui redemande le mot de passe de ce compte, validé
    /// par visudo avant d'être posé.
    DurcirSudo(NomCompte),
    /// `chmod u-s,g-s` d'un programme setuid ou setgid suspect.
    RetirerSetuid(CheminDesigne),
    /// `setcap -r` d'un programme aux capacités suspectes.
    RetirerCapacites(CheminDesigne),
    /// Un dossier du système à un autre compte, ou ouvert en écriture au groupe : rendu à root (0:0, sans écriture du
    /// groupe ni des autres).
    RendreDossierARoot(CheminDesigne),
    /// `disable --now` d'un service ajouté à la main dans /etc/systemd/system.
    DesactiverService(NomUnite),
    /// La ligne de ce fichier du système dont l'empreinte est celle-là, retirée ; le fichier entier est noté.
    RetirerLigne(Empreinte, CheminDesigne),
    /// Lot D7b. Un réglage du serveur SSH fermé par un fichier de sshd_config.d, validé (`sshd -t`), puis sshd
    /// rechargé : les sessions ouvertes restent.
    DurcirSsh(ReglageSsh),
    /// `kernel.unprivileged_bpf_disabled=2` (et, si la personne le veut, un fichier de /etc/sysctl.d pour que ça dure).
    ReserverBpf,
    /// `Storage=persistent` pour journald, par un fichier de journald.conf.d.
    GarderJournal,
    /// Un fichier ajouté aux certificats racine que Vanguard ne sait pas lire en entier, retiré (copié dans la note).
    RetirerAncre(CheminDesigne),
    /// La ligne de réglage du proxy de ce fichier du système (`*_proxy=`) mise en commentaire (fichier copié).
    CommenterProxy(Empreinte, CheminDesigne),
    /// `bluetoothctl remove` d'un appareil jumelé : non annulable (il faudra le re-jumeler).
    OublierBluetooth(AdresseBt),
    /// Arrêter ce programme suspect (PID et sa naissance, en tops d'horloge depuis le démarrage), ses traces copiées
    /// d'abord dans /var/lib/vanguard/traces.
    ArreterProgramme(u32, u64),
    /// Lot D7b, « Refaire » : le programme d'une tâche de Vanguard remplacé hors de Vanguard, remis par un programme
    /// publié et signé par l'auteur (historique signé en Ed25519) ; celui qui y était est gardé en quarantaine
    /// (/var/lib/vanguard/quarantaine), jamais effacé. Non annulable.
    RemettreProgramme(CheminDesigne),
    /// Lot D7c. Couper ce pare-feu : une BAISSE, faite seulement depuis les Options de défense, sur le choix de la
    /// personne (question de baisse, Entrée seule : non). Sa note porte l'identifiant fixe du pare-feu
    /// (`PareFeu::note`) ; Défaire, ou Rallumer, la remet.
    CouperPareFeu(PareFeu),
    /// Lot D7c. Rallumer ce pare-feu quand aucune note de coupure n'existe : un renforcement, non annulable (Vanguard
    /// ne le recoupe pas de lui-même).
    RallumerPareFeu(PareFeu),
    /// Remet l'état que la note d'« avant » de ce geste a gardé, puis retire la note.
    Remettre,
}

impl Defense {
    fn mot(self) -> &'static str {
        match self {
            Defense::VerrouillerCompte(_) => "verrouiller-compte",
            Defense::RetirerDuGroupe(..) => "retirer-du-groupe",
            Defense::DurcirSudo(_) => "durcir-sudoers",
            Defense::RetirerSetuid(_) => "retirer-setuid",
            Defense::RetirerCapacites(_) => "retirer-capacites",
            Defense::RendreDossierARoot(_) => "rendre-a-root",
            Defense::DesactiverService(_) => "desactiver-service",
            Defense::RetirerLigne(..) => "retirer-ligne",
            Defense::DurcirSsh(_) => "durcir-ssh",
            Defense::ReserverBpf => "reserver-bpf",
            Defense::GarderJournal => "garder-journal",
            Defense::RetirerAncre(_) => "retirer-ancre",
            Defense::CommenterProxy(..) => "commenter-proxy",
            Defense::OublierBluetooth(_) => "oublier-bluetooth",
            Defense::ArreterProgramme(..) => "arreter-programme",
            Defense::RemettreProgramme(_) => "remettre-programme",
            Defense::CouperPareFeu(_) => "couper-pare-feu",
            Defense::RallumerPareFeu(_) => "rallumer-pare-feu",
            Defense::Remettre => "remettre",
        }
    }

    /// Les champs de la ligne, entre le mot et l'identifiant.
    fn champs(self) -> String {
        match self {
            Defense::VerrouillerCompte(n) | Defense::DurcirSudo(n) => format!(" {}", n.as_str()),
            Defense::RetirerDuGroupe(g, n) => format!(" {} {}", g.mot(), n.as_str()),
            Defense::RetirerSetuid(c)
            | Defense::RetirerCapacites(c)
            | Defense::RendreDossierARoot(c)
            | Defense::RetirerAncre(c)
            | Defense::RemettreProgramme(c) => {
                format!(" {}", hex(c.octets()))
            }
            Defense::DesactiverService(u) => format!(" {}", u.as_str()),
            Defense::RetirerLigne(e, c) | Defense::CommenterProxy(e, c) => {
                format!(" {} {}", hex(&e.0), hex(c.octets()))
            }
            Defense::DurcirSsh(r) => format!(" {}", r.mot()),
            Defense::CouperPareFeu(p) | Defense::RallumerPareFeu(p) => format!(" {}", p.mot()),
            Defense::OublierBluetooth(b) => format!(" {}", hex(&b.0)),
            Defense::ArreterProgramme(pid, debut) => format!(" {pid} {debut}"),
            Defense::Remettre | Defense::ReserverBpf | Defense::GarderJournal => String::new(),
        }
    }

    fn phrase(self) -> (String, String) {
        match self {
            Defense::VerrouillerCompte(n) => (
                format!(
                    "Verrouiller le compte {} (il ne s'ouvre plus ; rien n'est supprimé, réactivable)",
                    n.as_str()
                ),
                format!(
                    "Lock the account {} (it no longer opens; nothing is deleted, can be re-enabled)",
                    n.as_str()
                ),
            ),
            Defense::RetirerDuGroupe(GroupeSensible::Administrateurs, n) => (
                format!(
                    "Retirer le compte {} du groupe des administrateurs (effectif à sa prochaine session)",
                    n.as_str()
                ),
                format!(
                    "Remove the account {} from the administrators group (effective at its next session)",
                    n.as_str()
                ),
            ),
            Defense::RetirerDuGroupe(g, n) => (
                format!(
                    "Retirer le compte {} du groupe {} (effectif à sa prochaine session)",
                    n.as_str(),
                    g.mot()
                ),
                format!(
                    "Remove the account {} from the {} group (effective at its next session)",
                    n.as_str(),
                    g.mot()
                ),
            ),
            Defense::DurcirSudo(n) => (
                format!(
                    "Faire redemander son mot de passe au compte {} (complément de sudo, vérifié par visudo)",
                    n.as_str()
                ),
                format!(
                    "Ask the account {} for its password again (an addition to sudo, checked by visudo)",
                    n.as_str()
                ),
            ),
            Defense::RetirerSetuid(c) => (
                format!("Retirer le droit « setuid/setgid » du programme {}", c.lisible()),
                format!("Remove the setuid/setgid right from the program {}", c.lisible()),
            ),
            Defense::RetirerCapacites(c) => (
                format!("Retirer les capacités (droits du noyau) du programme {}", c.lisible()),
                format!(
                    "Remove the capabilities (kernel rights) from the program {}",
                    c.lisible()
                ),
            ),
            Defense::RendreDossierARoot(c) => (
                format!(
                    "Rendre le dossier {} à root (fermé en écriture aux autres comptes)",
                    c.lisible()
                ),
                format!(
                    "Give the folder {} back to root (closed to writing by other accounts)",
                    c.lisible()
                ),
            ),
            Defense::DesactiverService(u) => (
                format!(
                    "Désactiver le service {} (tout de suite et aux prochains démarrages)",
                    u.as_str()
                ),
                format!(
                    "Turn off the service {} (right away and at the next startups)",
                    u.as_str()
                ),
            ),
            Defense::RetirerLigne(_, c) => (
                format!(
                    "Retirer la ligne suspecte de {} (le fichier entier est gardé dans la note)",
                    c.lisible()
                ),
                format!(
                    "Remove the suspicious line from {} (the whole file is kept in the note)",
                    c.lisible()
                ),
            ),
            Defense::DurcirSsh(ReglageSsh::MotsDePasseVides) => (
                "Refuser en SSH les comptes sans mot de passe (PermitEmptyPasswords no)".to_string(),
                "Refuse accounts without a password over SSH (PermitEmptyPasswords no)".to_string(),
            ),
            Defense::DurcirSsh(ReglageSsh::Root) => (
                "Interdire la connexion SSH en root (PermitRootLogin no)".to_string(),
                "Forbid root login over SSH (PermitRootLogin no)".to_string(),
            ),
            Defense::DurcirSsh(ReglageSsh::MotsDePasse) => (
                "N'accepter que les clés en SSH, plus les mots de passe (PasswordAuthentication no)".to_string(),
                "Accept only keys over SSH, no more passwords (PasswordAuthentication no)".to_string(),
            ),
            Defense::ReserverBpf => (
                "Réserver BPF aux administrateurs (kernel.unprivileged_bpf_disabled=2)".to_string(),
                "Keep BPF for administrators only (kernel.unprivileged_bpf_disabled=2)".to_string(),
            ),
            Defense::GarderJournal => (
                "Garder le journal du système après un redémarrage (Storage=persistent)".to_string(),
                "Keep the system log after a restart (Storage=persistent)".to_string(),
            ),
            Defense::RetirerAncre(c) => (
                format!(
                    "Retirer le fichier ajouté aux certificats racine {} (il est copié dans la note)",
                    c.lisible()
                ),
                format!(
                    "Remove the file added to the root certificates {} (it is copied into the note)",
                    c.lisible()
                ),
            ),
            Defense::CommenterProxy(_, c) => (
                format!(
                    "Mettre en commentaire le réglage du proxy de {} (le fichier entier est copié dans la note)",
                    c.lisible()
                ),
                format!(
                    "Comment out the proxy setting in {} (the whole file is copied into the note)",
                    c.lisible()
                ),
            ),
            Defense::OublierBluetooth(b) => (
                format!("Oublier l'appareil Bluetooth {} (il faudra le re-jumeler)", b.texte()),
                format!(
                    "Forget the Bluetooth device {} (it will have to be paired again)",
                    b.texte()
                ),
            ),
            Defense::ArreterProgramme(pid, _) => (
                format!("Arrêter le programme suspect de PID {pid}, après avoir copié ses traces"),
                format!("Stop the suspicious program with PID {pid}, after copying its traces"),
            ),
            Defense::RemettreProgramme(c) => (
                format!(
                    "Remettre à {} un programme de Vanguard publié et signé par l'auteur (celui qui y est va en quarantaine)",
                    c.lisible()
                ),
                format!(
                    "Put back at {} a Vanguard program published and signed by the author (the one there goes to quarantine)",
                    c.lisible()
                ),
            ),
            Defense::CouperPareFeu(p) => (
                format!("Couper le pare-feu {} (votre choix : une protection baissée)", p.mot()),
                format!("Turn off the {} firewall (your choice: a lowered protection)", p.mot()),
            ),
            Defense::RallumerPareFeu(p) => (
                format!("Rallumer le pare-feu {}", p.mot()),
                format!("Turn the {} firewall back on", p.mot()),
            ),
            Defense::Remettre => (
                "Remettre ce qu'un geste de défense de Vanguard avait changé".to_string(),
                "Put back what a Vanguard defense step had changed".to_string(),
            ),
        }
    }
}

/// Un geste désigné par une ligne, relu.
#[allow(
    clippy::large_enum_variant,
    reason = "copié par valeur, une ligne à la fois : quelques centaines d'octets, jamais en masse"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GesteUnix {
    Programme(&'static Programme),
    /// Une action sur une unité de la table.
    Unite(ActionUnite, &'static UniteConnue),
    /// Une unité hors de la table, désignée par son nom : seulement arrêtée, ou plus lancée au démarrage.
    Designee(ActionUnite, NomUnite),
    /// `systemctl reset-failed` : oublie les échecs passés de toutes les unités, sans rien démarrer ni arrêter.
    ReinitialiserEchecs,
    /// Arrêter clamav-freshclam s'il tourne (il verrouille la base), lancer freshclam, puis le redémarrer dans tous
    /// les cas ; son lancement au démarrage n'est jamais changé (rien ne le noterait pour le défaire).
    SignaturesClamav,
    /// Un geste de défense, et l'identifiant de sa note d'« avant ».
    Defense(Defense, IdNote),
}

impl GesteUnix {
    /// La ligne qui le porte ; `analyser(g.ligne()) == Some(g)` pour tout geste sans `refus`.
    pub(crate) fn ligne(self) -> String {
        match self {
            GesteUnix::Programme(p) => format!("{PREFIXE}programme {}", p.id),
            GesteUnix::Unite(a, u) => format!("{PREFIXE}unite {} {}", a.mot(), u.nom),
            GesteUnix::Designee(a, n) => format!("{PREFIXE}unite-designee {} {}", a.mot(), n.as_str()),
            GesteUnix::ReinitialiserEchecs => format!("{PREFIXE}unite reinitialiser-echecs"),
            GesteUnix::SignaturesClamav => format!("{PREFIXE}signatures-clamav"),
            GesteUnix::Defense(d, id) => format!("{PREFIXE}defense {}{} {}", d.mot(), d.champs(), id.as_str()),
        }
    }

    /// Ce que fait le geste, en une phrase (française et anglaise) : montrée avant l'accord, par le parent, puis par
    /// l'enfant avant de le faire.
    pub(crate) fn phrase(self) -> (String, String) {
        match self {
            GesteUnix::Programme(p) => (p.fr.to_string(), p.en.to_string()),
            GesteUnix::Unite(a, u) => phrase_d_unite(a, u.fr, u.en),
            GesteUnix::Designee(a, n) => phrase_d_unite(
                a,
                &format!("le service {}", n.as_str()),
                &format!("the service {}", n.as_str()),
            ),
            GesteUnix::ReinitialiserEchecs => (
                "Remettre à zéro la liste des services en échec (rien n'est démarré ni arrêté)".to_string(),
                "Clear the list of failed services (nothing is started or stopped)".to_string(),
            ),
            GesteUnix::SignaturesClamav => (
                "Mettre à jour les signatures de virus de ClamAV (leur mise à jour automatique reste comme elle était)"
                    .to_string(),
                "Update the ClamAV virus signatures (their automatic update stays as it was)".to_string(),
            ),
            GesteUnix::Defense(d, _) => d.phrase(),
        }
    }

    /// Pourquoi ce geste n'est jamais fait, quoi qu'en dise la ligne : un pare-feu coupé, une unité désignée à qui
    /// l'on ferait autre chose que l'arrêter ou la retirer du démarrage. Une telle ligne ne se relit pas
    /// (`analyser`), et l'enfant le rejuge encore avant d'agir.
    pub(crate) fn refus(self) -> Option<(&'static str, &'static str)> {
        match self {
            GesteUnix::Unite(a, u)
                if u.garde == Garde::PareFeu && !matches!(a, ActionUnite::Activer | ActionUnite::Demarrer) =>
            {
                Some((
                    "Vanguard ne coupe jamais un pare-feu, même un instant : ni arrêt, ni désactivation, ni redémarrage, ni rechargement",
                    "Vanguard never turns a firewall off, even for a moment: no stop, no disabling, no restart, no reload",
                ))
            }
            GesteUnix::Designee(a, _) if !matches!(a, ActionUnite::Arreter | ActionUnite::DesactiverSansArreter) => {
                Some((
                    "un service désigné par son nom ne peut qu'être arrêté, ou ne plus être lancé au démarrage",
                    "a service named by its name can only be stopped, or no longer started at startup",
                ))
            }
            GesteUnix::Defense(Defense::DesactiverService(u), _) if unite_portant_les_sessions(u.as_str()) => Some((
                "ce service porte les sessions ou le réseau qu'elles traversent (connexion à distance, écran de connexion, réseau, VPN, pare-feu) : Vanguard ne le désactive jamais",
                "this service carries the sessions or the network they go through (remote connection, login screen, network, VPN, firewall): Vanguard never turns it off",
            )),
            GesteUnix::Defense(Defense::RetirerLigne(_, c), _) if !fichier_de_ligne_admis(c.octets()) => Some((
                "Vanguard ne retire une ligne que des fichiers de démarrage du système qu'il connaît",
                "Vanguard only removes a line from the system startup files it knows",
            )),
            GesteUnix::Defense(Defense::CommenterProxy(_, c), _) if !fichier_de_ligne_admis(c.octets()) => Some((
                "Vanguard ne change le réglage du proxy que des fichiers de démarrage du système qu'il connaît",
                "Vanguard only changes the proxy setting in the system startup files it knows",
            )),
            GesteUnix::Defense(Defense::RetirerAncre(c), _) if !ancre_admise(c.octets()) => Some((
                "Vanguard ne retire un certificat que des dossiers où le système range ceux qu'on ajoute",
                "Vanguard only removes a certificate from the folders where the system keeps the added ones",
            )),
            GesteUnix::Defense(Defense::RemettreProgramme(c), _) if !programme_pose_admis(c.octets()) => Some((
                "Vanguard ne remet que son propre programme, hors des dossiers des comptes et des dossiers temporaires",
                "Vanguard only puts back its own program, outside the accounts' folders and the temporary folders",
            )),
            GesteUnix::Defense(Defense::ArreterProgramme(pid, _), _) if pid <= 1 => Some((
                "Vanguard n'arrête jamais le premier processus du système ni le noyau",
                "Vanguard never stops the system's first process or the kernel",
            )),
            // La note d'une coupure porte l'identifiant fixe de son pare-feu, et lui seul : le parent la reconnaît à
            // sa seule présence. Un autre geste qui le prendrait ferait croire un pare-feu coupé par choix (ou
            // effacerait la note d'une vraie coupure) ; Remettre, lui, le prend pour la rallumer.
            GesteUnix::Defense(Defense::CouperPareFeu(p), id) if id != p.note() => Some((
                "la coupure d'un pare-feu ne se note que sous l'identifiant de ce pare-feu",
                "a firewall's turning off is only noted under that firewall's identifier",
            )),
            GesteUnix::Defense(d, id)
                if !matches!(d, Defense::CouperPareFeu(_) | Defense::Remettre) && PareFeu::de_la_note(id).is_some() =>
            {
                Some((
                    "cet identifiant est réservé à la coupure d'un pare-feu",
                    "this identifier is reserved for turning off a firewall",
                ))
            }
            _ => None,
        }
    }

    /// L'enfant demande-t-il l'accord de la personne, sur son terminal, avant de le faire ? Oui pour ce qui
    /// affaiblit : une protection baissée, un service ouvert au réseau mis en marche, le réseau coupé, un programme
    /// qui affaiblit ou supprime (`pourquoi_l_accord` dit lequel).
    pub(crate) fn demande_accord(self) -> bool {
        self.pourquoi_l_accord().is_some()
    }

    /// Pourquoi l'enfant demande l'accord, dit dans la question ; `None` : il ne le demande pas.
    pub(crate) fn pourquoi_l_accord(self) -> Option<(&'static str, &'static str)> {
        let couper = |a| {
            matches!(
                a,
                ActionUnite::Desactiver | ActionUnite::DesactiverSansArreter | ActionUnite::Arreter
            )
        };
        match self {
            GesteUnix::Programme(p) if p.supprime => Some(("ceci supprime quelque chose", "this deletes something")),
            GesteUnix::Programme(p) if p.affaiblit => Some(("ceci baisse une protection", "this lowers a protection")),
            GesteUnix::Unite(a, u) if u.garde == Garde::Protection && couper(a) => {
                Some(("ceci baisse une protection", "this lowers a protection"))
            }
            GesteUnix::Unite(a, u) if u.garde == Garde::Reseau && couper(a) => Some((
                "ceci coupe le réseau de cet ordinateur",
                "this cuts this computer's network",
            )),
            // Un logiciel de prise en main désigné peut être un bureau à distance voulu (VNC, NoMachine) qui porte
            // en ce moment la session de quelqu'un : ses connexions ne bloquent pas son arrêt (`coupe_session`), mais
            // la personne devant l'écran le confirme, après avoir dit qu'elle n'est pas connectée par lui
            // (`assistant`, question de l'arrêt). Son retrait du démarrage ne coupe rien maintenant : la question dit
            // ce qu'il change, au prochain redémarrage.
            GesteUnix::Designee(ActionUnite::Arreter, _) => Some((
                "toute session à distance qui passe par lui sera coupée, sans retour possible",
                "any remote session going through it will be cut, with no way back",
            )),
            GesteUnix::Designee(a, _) if couper(a) => Some((
                "il ne sera plus lancé au démarrage : après le prochain redémarrage, personne ne pourra plus se connecter à cet ordinateur par lui",
                "it will no longer start at boot: after the next restart, no one will be able to connect to this computer through it",
            )),
            GesteUnix::Unite(ActionUnite::Activer | ActionUnite::Demarrer, u) if u.garde == Garde::Ouverte => Some((
                "ceci ouvre cet ordinateur au réseau local",
                "this opens this computer to the local network",
            )),
            // Un geste de défense change un compte, un droit ou un fichier du système : l'enfant le montre avec ce
            // qu'il a relu, et avertit de ce qui peut couper l'accès (`assistant::defense`). Le remettre rouvre ce
            // qu'il avait fermé.
            GesteUnix::Defense(Defense::CouperPareFeu(_), _) => Some((
                "ceci baisse une protection : le pare-feu est coupé",
                "this lowers a protection: the firewall is turned off",
            )),
            GesteUnix::Defense(Defense::RallumerPareFeu(_), _) => Some((
                "ceci change les règles du pare-feu : de nouvelles connexions peuvent être refusées",
                "this changes the firewall rules: new connections may be refused",
            )),
            GesteUnix::Defense(Defense::Remettre, _) => Some((
                "ceci rouvre ce qu'un geste de défense avait fermé",
                "this reopens what a defense step had closed",
            )),
            GesteUnix::Defense(..) => Some((
                "ceci change un compte, un droit ou un fichier du système",
                "this changes an account, a right or a system file",
            )),
            _ => None,
        }
    }

    /// Le geste peut-il couper une session à distance entrante (le réseau arrêté, redémarré ou rechargé : relire sa
    /// configuration peut réappliquer les connexions et faire tomber celle en cours) ? L'enfant le refuse
    /// alors tant qu'une session est ouverte. Arrêter un logiciel de prise de contrôle désigné n'y entre pas : ses
    /// propres connexions ne bloquent jamais son retrait (le faux technicien est justement connecté par lui, et la
    /// personne a déjà choisi de le fermer), et l'arrêter n'affaiblit rien.
    pub(crate) fn coupe_session(self) -> bool {
        match self {
            GesteUnix::Unite(a, u) => {
                u.garde == Garde::Reseau
                    && matches!(
                        a,
                        ActionUnite::Arreter
                            | ActionUnite::Desactiver
                            | ActionUnite::Redemarrer
                            | ActionUnite::Recharger
                    )
            }
            GesteUnix::Designee(..)
            | GesteUnix::Programme(_)
            | GesteUnix::ReinitialiserEchecs
            | GesteUnix::SignaturesClamav
            | GesteUnix::Defense(..) => false,
        }
    }

    /// Le geste passe-t-il par systemd (le bus système) ? Sans systemd, l'enfant le refuse en le disant. La
    /// remise d'un service désactivé le demande aussi, mais seul l'enfant sait, en lisant la note, ce qu'il remet.
    pub(crate) fn par_systemd(self) -> bool {
        match self {
            GesteUnix::Unite(..)
            | GesteUnix::Designee(..)
            | GesteUnix::ReinitialiserEchecs
            | GesteUnix::SignaturesClamav
            | GesteUnix::Defense(
                Defense::DesactiverService(_)
                | Defense::DurcirSsh(_)
                | Defense::GarderJournal
                | Defense::CouperPareFeu(PareFeu::Firewalld)
                | Defense::RallumerPareFeu(PareFeu::Firewalld | PareFeu::Nftables),
                _,
            ) => true,
            GesteUnix::Programme(_) | GesteUnix::Defense(..) => false,
        }
    }

    /// Le geste a-t-il un sens sur ce système ? Linux seulement : sous macOS, rien n'est converti avant un essai sur un
    /// vrai Mac (plan du lot Unix, D8). L'absence de systemd n'y entre pas : elle se dit à part (`par_systemd`), sans
    /// faire refuser toute la liste comme une liste étrangère.
    #[allow(
        clippy::unused_self,
        reason = "les familles à venir (paquets) diront chacune où elles valent"
    )]
    pub(crate) fn permis_ici(self) -> bool {
        cfg!(target_os = "linux")
    }
}

/// La phrase d'une action sur une unité que `fr` et `en` décrivent, article compris (aucune préposition devant :
/// « à le » ou « de la » ne s'accorderaient pas).
fn phrase_d_unite(a: ActionUnite, fr: &str, en: &str) -> (String, String) {
    match a {
        ActionUnite::Activer => (
            format!("Activer {fr} (tout de suite et à chaque démarrage)"),
            format!("Turn on {en} (right away and at every startup)"),
        ),
        ActionUnite::Desactiver => (
            format!("Désactiver {fr} (tout de suite et aux prochains démarrages)"),
            format!("Turn off {en} (right away and at the next startups)"),
        ),
        ActionUnite::DesactiverSansArreter => (
            format!("Ne plus lancer {fr} au démarrage (sans l'arrêter maintenant)"),
            format!("Stop starting {en} at startup (without stopping it now)"),
        ),
        ActionUnite::ActiverSansDemarrer => (
            format!("Lancer {fr} aux prochains démarrages (sans le lancer maintenant)"),
            format!("Start {en} at the next startups (without starting it now)"),
        ),
        ActionUnite::Demarrer => (format!("Démarrer {fr}"), format!("Start {en}")),
        ActionUnite::Arreter => (format!("Arrêter {fr}"), format!("Stop {en}")),
        ActionUnite::Redemarrer => (
            format!("Redémarrer {fr} (seulement si ce service tourne déjà)"),
            format!("Restart {en} (only if it is already running)"),
        ),
        ActionUnite::Recharger => (
            format!("Recharger {fr} (relire sa configuration sans l'arrêter)"),
            format!("Reload {en} (read its configuration again without stopping it)"),
        ),
    }
}

/// Le geste qui remet une unité de la table dans l'état noté par `optimiser` : « enabled », activée et lancée ;
/// « disabled », désactivée et arrêtée. `Ok(None)` : aucun geste, pour une unité hors de la table ou un autre état
/// (« masked » d'une unité ordinaire reste une commande montrée, jusqu'à U4). `Err` : un refus, que l'appelant dit
/// et ne remplace jamais par une commande sudo (un pare-feu coupé ; un pare-feu ou une protection masqués, que plus
/// rien ne pourrait lancer).
// Seuls les réglages et le retrait des programmes de contrôle à distance de Linux les demandent.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn geste_d_unite(nom: &str, etat: &str) -> Result<Option<GesteUnix>, (&'static str, &'static str)> {
    let Some(u) = unite_connue(nom) else {
        return Ok(None);
    };
    let a = match etat {
        "enabled" => ActionUnite::Activer,
        "disabled" => ActionUnite::Desactiver,
        "masked" if matches!(u.garde, Garde::PareFeu | Garde::Protection) => {
            return Err((
                "Vanguard ne masque jamais un pare-feu ni une protection : plus rien ne pourrait les lancer",
                "Vanguard never masks a firewall or a protection: nothing could start them again",
            ));
        }
        _ => return Ok(None),
    };
    let g = GesteUnix::Unite(a, u);
    match g.refus() {
        Some(raison) => Err(raison),
        None => Ok(Some(g)),
    }
}

/// Le geste d'une unité désignée par son nom, s'il est admis (les essais ; le code passe par `designee_ou_refus`,
/// qui dit pourquoi).
#[cfg(test)]
pub(crate) fn designee(a: ActionUnite, nom: &str) -> Option<GesteUnix> {
    designee_ou_refus(a, nom).ok()
}

/// Comme `designee`, avec la raison (français, anglais) quand le geste n'est pas admis : de quoi dire à la personne
/// pourquoi rien n'est proposé, au lieu d'une commande sudo qui passerait à côté des contrôles de l'assistant.
// Seul le retrait des programmes de contrôle à distance de Linux le demande.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn designee_ou_refus(a: ActionUnite, nom: &str) -> Result<GesteUnix, (&'static str, &'static str)> {
    if UNITES_CONNUES.iter().any(|u| u.nom == nom) {
        return Err((
            "c'est un service que Vanguard ne touche que par ses propres réglages (pare-feu, protection, réseau)",
            "it is a service Vanguard only changes through its own settings (firewall, protection, network)",
        ));
    }
    let Some(n) = NomUnite::nouveau(nom) else {
        return Err((
            "son nom n'a pas la forme d'un service que Vanguard accepte de désigner",
            "its name is not the shape of a service Vanguard agrees to name",
        ));
    };
    let g = GesteUnix::Designee(a, n);
    match g.refus() {
        Some(raison) => Err(raison),
        None => Ok(g),
    }
}

/// Un identifiant de la table : minuscules ASCII, chiffres et tirets, 40 caractères au plus.
fn identifiant(t: &str) -> bool {
    !t.is_empty() && t.len() <= 40 && t.bytes().all(|o| matches!(o, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Le geste que porte une ligne, si et seulement si la ligne est exactement sa forme admise : le préfixe, une famille
/// de la liste, des champs séparés par une seule espace, réécrits à l'identique (une majuscule, une espace de trop, un
/// champ en plus, un octet nul : refusés), et un geste que rien ne refuse (`refus`).
pub(crate) fn analyser(ligne: &str) -> Option<GesteUnix> {
    if ligne.len() > GESTE_MAX {
        return None;
    }
    let reste = ligne.strip_prefix(PREFIXE)?;
    let mots: Vec<&str> = reste.split(' ').collect();
    let geste = match mots.as_slice() {
        ["programme", id] if identifiant(id) => GesteUnix::Programme(PROGRAMMES.iter().copied().find(|p| p.id == *id)?),
        ["unite", "reinitialiser-echecs"] => GesteUnix::ReinitialiserEchecs,
        ["unite", action, nom] => GesteUnix::Unite(
            ActionUnite::depuis_mot(action)?,
            UNITES_CONNUES.iter().copied().find(|u| u.nom == *nom)?,
        ),
        ["unite-designee", action, nom] => {
            GesteUnix::Designee(ActionUnite::depuis_mot(action)?, NomUnite::nouveau(nom)?)
        }
        ["signatures-clamav"] => GesteUnix::SignaturesClamav,
        ["defense", mot, champs @ .., id] => GesteUnix::Defense(defense(mot, champs)?, IdNote::nouveau(id)?),
        _ => return None,
    };
    if geste.refus().is_some() {
        return None;
    }
    (geste.ligne() == ligne).then_some(geste)
}

/// Le geste de défense de ce mot et de ces champs, relus strictement (la ligne entière est encore réécrite et
/// comparée par `analyser`).
fn defense(mot: &str, champs: &[&str]) -> Option<Defense> {
    let chemin = |h: &str| CheminDesigne::nouveau(&depuis_hex(h, CHEMIN_MAX)?);
    Some(match (mot, champs) {
        ("verrouiller-compte", [n]) => Defense::VerrouillerCompte(NomCompte::nouveau(n)?),
        ("retirer-du-groupe", [g, n]) => {
            Defense::RetirerDuGroupe(GroupeSensible::depuis_mot(g)?, NomCompte::nouveau(n)?)
        }
        ("durcir-sudoers", [n]) => Defense::DurcirSudo(NomCompte::nouveau(n)?),
        ("retirer-setuid", [c]) => Defense::RetirerSetuid(chemin(c)?),
        ("retirer-capacites", [c]) => Defense::RetirerCapacites(chemin(c)?),
        ("rendre-a-root", [c]) => Defense::RendreDossierARoot(chemin(c)?),
        ("desactiver-service", [u]) => Defense::DesactiverService(NomUnite::nouveau(u)?),
        ("retirer-ligne", [e, c]) => Defense::RetirerLigne(Empreinte(depuis_hex(e, 32)?.try_into().ok()?), chemin(c)?),
        ("durcir-ssh", [r]) => Defense::DurcirSsh(ReglageSsh::depuis_mot(r)?),
        ("reserver-bpf", []) => Defense::ReserverBpf,
        ("garder-journal", []) => Defense::GarderJournal,
        ("retirer-ancre", [c]) => Defense::RetirerAncre(chemin(c)?),
        ("commenter-proxy", [e, c]) => {
            Defense::CommenterProxy(Empreinte(depuis_hex(e, 32)?.try_into().ok()?), chemin(c)?)
        }
        ("oublier-bluetooth", [b]) => Defense::OublierBluetooth(AdresseBt(depuis_hex(b, 6)?.try_into().ok()?)),
        ("arreter-programme", [p, d]) => Defense::ArreterProgramme(decimal(p)?, decimal(d)?),
        ("remettre-programme", [c]) => Defense::RemettreProgramme(chemin(c)?),
        ("couper-pare-feu", [p]) => Defense::CouperPareFeu(PareFeu::depuis_mot(p)?),
        ("rallumer-pare-feu", [p]) => Defense::RallumerPareFeu(PareFeu::depuis_mot(p)?),
        ("remettre", []) => Defense::Remettre,
        _ => return None,
    })
}

/// La ligne commence-t-elle comme un geste (bien formé ou non) ? Une telle ligne n'est jamais confiée à un shell :
/// refusée si elle ne se relit pas.
pub(crate) fn a_le_prefixe(ligne: &str) -> bool {
    ligne.starts_with(PREFIXE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les bornes reprises d'`ordres` restent les siennes : le canal n'a qu'une limite.
    #[test]
    fn bornes_du_canal_communes_avec_les_ordres() {
        use crate::protection::blocage::ordres;
        assert_eq!(LIGNE_MAX, ordres::LIGNE_MAX);
        assert!(PREFIXE.starts_with(ordres::PREFIXE));
    }

    #[test]
    fn la_table_est_bien_formee() {
        let mut vus = std::collections::HashSet::new();
        for p in PROGRAMMES {
            assert!(identifiant(p.id), "{}", p.id);
            assert!(vus.insert(p.id), "{} en double", p.id);
            // L'outil est un nom, jamais un chemin ni une option.
            assert!(identifiant(p.outil), "{}", p.outil);
            assert!(!p.reussites.is_empty() && p.delai > 0);
            assert!(!p.fr.is_empty() && !p.en.is_empty());
            // Aucun argument ne fait passer un shell, une expansion ou un saut de ligne.
            for a in p.arguments {
                assert!(
                    !a.is_empty() && !a.contains(['\0', '\n', '\r', '$', '`', ';', '|', '&']),
                    "{a}"
                );
            }
            let g = GesteUnix::Programme(p);
            assert!(g.ligne().len() <= GESTE_MAX);
        }
        let mut noms = std::collections::HashSet::new();
        for u in UNITES_CONNUES {
            assert!(nom_admis(u.nom), "{}", u.nom);
            assert!(noms.insert(u.nom), "{} en double", u.nom);
            assert!(!u.fr.is_empty() && !u.en.is_empty());
            // Sans « .service », le nom ne désigne qu'elle.
            assert_eq!(unite_connue(u.nom), Some(*u));
        }
        // Le plus long geste possible tient dans la borne.
        let plus_long = GesteUnix::Designee(
            ActionUnite::DesactiverSansArreter,
            NomUnite::nouveau(&format!("{}.service", "a".repeat(NOM_UNITE_MAX - 8))).unwrap(),
        );
        assert!(plus_long.ligne().len() <= GESTE_MAX);
    }

    /// Propriété : chaque geste de la table se relit tel quel (`analyser(ligne(g)) == g`).
    #[test]
    fn aller_retour_de_chaque_geste() {
        for p in PROGRAMMES {
            let g = GesteUnix::Programme(p);
            assert_eq!(analyser(&g.ligne()), Some(g));
            assert!(a_le_prefixe(&g.ligne()));
        }
        let mut admis = 0;
        for a in ActionUnite::TOUTES {
            for u in UNITES_CONNUES {
                let g = GesteUnix::Unite(a, u);
                // Un geste refusé ne se relit jamais ; tous les autres se relisent tels quels.
                let attendu = g.refus().is_none().then_some(g);
                assert_eq!(analyser(&g.ligne()), attendu, "{}", g.ligne());
                admis += usize::from(attendu.is_some());
            }
            let d = GesteUnix::Designee(a, NomUnite::nouveau("anydesk.service").unwrap());
            assert_eq!(analyser(&d.ligne()), d.refus().is_none().then_some(d), "{}", d.ligne());
        }
        // 7 actions × 11 unités, moins les 5 refusées pour chacun des deux pare-feu (seuls Activer et Demarrer
        // passent).
        assert_eq!(admis, 7 * UNITES_CONNUES.len() - 2 * 5);
        for g in [GesteUnix::ReinitialiserEchecs, GesteUnix::SignaturesClamav] {
            assert_eq!(analyser(&g.ligne()), Some(g));
        }
        assert_eq!(
            GesteUnix::Unite(ActionUnite::Desactiver, &CUPS_BROWSED).ligne(),
            "vanguard:geste unite desactiver cups-browsed.service"
        );
        assert_eq!(
            GesteUnix::ReinitialiserEchecs.ligne(),
            "vanguard:geste unite reinitialiser-echecs"
        );
        assert_eq!(
            designee(ActionUnite::Arreter, "anydesk.service")
                .map(GesteUnix::ligne)
                .as_deref(),
            Some("vanguard:geste unite-designee arreter anydesk.service")
        );
    }

    /// Un pare-feu n'est jamais coupé, même par une ligne bien formée ; une unité désignée ne fait que s'arrêter ou
    /// sortir du démarrage.
    #[test]
    fn pare_feu_jamais_coupe() {
        for pf in [&UFW, &FIREWALLD] {
            for a in ActionUnite::TOUTES {
                let permis = matches!(a, ActionUnite::Activer | ActionUnite::Demarrer);
                assert_eq!(GesteUnix::Unite(a, pf).refus().is_none(), permis, "{a:?} {}", pf.nom);
            }
            assert!(
                geste_d_unite(pf.nom, "disabled").is_err(),
                "refusé, pas « aucun geste »"
            );
        }
        for l in [
            "vanguard:geste unite arreter ufw.service",
            "vanguard:geste unite desactiver ufw.service",
            "vanguard:geste unite desactiver-sans-arreter firewalld.service",
            "vanguard:geste unite redemarrer firewalld.service",
            // Recharger ufw le redémarrerait (pas de rechargement à lui) : coupé un instant.
            "vanguard:geste unite recharger ufw.service",
            "vanguard:geste unite recharger firewalld.service",
            "vanguard:geste unite desactiver firewalld.service",
            // Un pare-feu ne se désigne pas non plus par son nom, ni aucune unité de la table.
            "vanguard:geste unite-designee arreter ufw.service",
            "vanguard:geste unite-designee arreter NetworkManager.service",
            "vanguard:geste unite-designee arreter auditd.service",
            // Une unité désignée ne se démarre, ne s'active ni ne se redémarre.
            "vanguard:geste unite-designee activer anydesk.service",
            "vanguard:geste unite-designee demarrer anydesk.service",
            "vanguard:geste unite-designee desactiver anydesk.service",
            "vanguard:geste unite-designee redemarrer anydesk.service",
        ] {
            assert_eq!(analyser(l), None, "{l}");
        }
    }

    /// Les noms hostiles d'une unité désignée : chemin, remontée, gabarit, sans suffixe, trop long, octet nul,
    /// option, espace, échappement de systemd.
    #[test]
    fn noms_d_unite_hostiles() {
        for bon in [
            "anydesk.service",
            "teamviewerd.service",
            "rustdesk.service",
            // Instances de gabarit, coupées par concat! : le garde-fou de confidentialité les lirait comme des courriels.
            concat!("x11vnc", "@", "1.service"),
            "dwagent.timer",
            "a.socket",
            concat!("chrome-remote-desktop", "@", "alice.service"),
        ] {
            assert!(nom_admis(bon), "{bon}");
            assert!(NomUnite::nouveau(bon).is_some(), "{bon}");
        }
        let trop_long = format!("{}.service", "a".repeat(NOM_UNITE_MAX - 7));
        assert_eq!(trop_long.len(), NOM_UNITE_MAX + 1);
        for mauvais in [
            "",
            "../x.service",
            "..service",
            "a..b.service",
            "a/b.service",
            "/etc/systemd/system/anydesk.service",
            "@.service",
            "@",
            "x@.service",
            ".service",
            "-x.service",
            "anydesk",
            "anydesk.target",
            "anydesk.mount",
            "anydesk.service\0",
            "any\0desk.service",
            "any desk.service",
            "any\\x2ddesk.service",
            "anydesk.service;reboot",
            "anydesk.service\n",
            "anydésk.service",
            trop_long.as_str(),
        ] {
            assert!(
                !nom_admis(mauvais) || NomUnite::nouveau(mauvais).is_none(),
                "{mauvais:?}"
            );
            assert_eq!(designee(ActionUnite::Arreter, mauvais), None, "{mauvais:?}");
            let l = format!("{PREFIXE}unite-designee arreter {mauvais}");
            assert_eq!(analyser(&l), None, "{l:?}");
        }
        // Le plus long admis se relit tel quel.
        let long = format!("{}.service", "a".repeat(NOM_UNITE_MAX - 8));
        let g = designee(ActionUnite::DesactiverSansArreter, &long).unwrap();
        assert_eq!(analyser(&g.ligne()), Some(g));
        if let GesteUnix::Designee(_, n) = g {
            assert_eq!(n.as_str(), long);
        }
    }

    /// Ce que l'enfant rejuge de chaque geste : l'accord pour ce qui affaiblit (une protection baissée, le réseau
    /// coupé, cups-browsed mis en marche), la session à distance pour le réseau seulement.
    #[test]
    fn accord_et_sessions() {
        let accord = |a, u| GesteUnix::Unite(a, u).demande_accord();
        for u in [&AUDITD, &APPARMOR, &CLAMAV_FRESHCLAM, &CLAMAV_DAEMON] {
            assert!(accord(ActionUnite::Desactiver, u));
            assert!(accord(ActionUnite::DesactiverSansArreter, u));
            assert!(accord(ActionUnite::Arreter, u));
            assert!(!accord(ActionUnite::Activer, u));
            assert!(!accord(ActionUnite::Redemarrer, u));
        }
        assert!(!accord(ActionUnite::Desactiver, &CUPS_BROWSED));
        // cups-browsed écoute le réseau local : le mettre en marche demande l'accord, l'arrêter non.
        assert!(accord(ActionUnite::Activer, &CUPS_BROWSED));
        assert!(accord(ActionUnite::Demarrer, &CUPS_BROWSED));
        assert!(!accord(ActionUnite::Arreter, &CUPS_BROWSED));
        assert!(!accord(ActionUnite::Activer, &CUPS));
        // Le réseau coupé demande l'accord ; redémarré ou rechargé, non (la session à distance, elle, est rejugée).
        for u in [&NETWORKMANAGER, &NETWORKD] {
            assert!(accord(ActionUnite::Desactiver, u));
            assert!(accord(ActionUnite::DesactiverSansArreter, u));
            assert!(accord(ActionUnite::Arreter, u));
            assert!(!accord(ActionUnite::Redemarrer, u));
            assert!(!accord(ActionUnite::Recharger, u));
            assert!(!accord(ActionUnite::Activer, u));
        }
        assert!(!GesteUnix::SignaturesClamav.demande_accord());
        assert!(!GesteUnix::ReinitialiserEchecs.demande_accord());
        let coupe = |a, u| GesteUnix::Unite(a, u).coupe_session();
        for u in [&NETWORKMANAGER, &NETWORKD] {
            assert!(coupe(ActionUnite::Redemarrer, u));
            assert!(coupe(ActionUnite::Arreter, u));
            assert!(coupe(ActionUnite::Desactiver, u));
            assert!(coupe(ActionUnite::Recharger, u), "{}", u.nom);
            assert!(!coupe(ActionUnite::Activer, u));
        }
        assert!(!coupe(ActionUnite::Desactiver, &CUPS_BROWSED));
        // Arrêter un logiciel de prise de contrôle n'est jamais bloqué par ses propres connexions, ni le retirer du
        // démarrage ; mais l'un et l'autre demandent l'accord : ce peut être un bureau à distance voulu.
        for a in [ActionUnite::Arreter, ActionUnite::DesactiverSansArreter] {
            let g = designee(a, "x11vnc.service").unwrap();
            assert!(!g.coupe_session() && g.demande_accord(), "{a:?}");
        }
        assert!(!GesteUnix::Programme(&FRESHCLAM).par_systemd());
        assert!(GesteUnix::SignaturesClamav.par_systemd() && GesteUnix::ReinitialiserEchecs.par_systemd());
    }

    /// Les réglages d'`optimiser` (nom court ou complet, état noté) deviennent un geste seulement pour « enabled » et
    /// « disabled » d'une unité de la table.
    #[test]
    fn geste_d_un_reglage() {
        assert_eq!(
            geste_d_unite("cups-browsed", "disabled"),
            Ok(Some(GesteUnix::Unite(ActionUnite::Desactiver, &CUPS_BROWSED)))
        );
        assert_eq!(
            geste_d_unite("fstrim.timer", "enabled"),
            Ok(Some(GesteUnix::Unite(ActionUnite::Activer, &FSTRIM)))
        );
        assert_eq!(
            geste_d_unite("auditd", "enabled"),
            Ok(Some(GesteUnix::Unite(ActionUnite::Activer, &AUDITD)))
        );
        assert_eq!(geste_d_unite("fstrim.timer", "masked"), Ok(None));
        assert_eq!(geste_d_unite("apport", "disabled"), Ok(None));
        assert_eq!(geste_d_unite("cups-browsed", "static"), Ok(None));
        // Un refus reste un refus, distinct de « aucun geste » : l'appelant ne le remplace jamais par sudo.
        for (nom, etat) in [
            ("auditd", "masked"),
            ("ufw", "masked"),
            ("firewalld.service", "masked"),
            ("ufw", "disabled"),
            ("firewalld", "disabled"),
        ] {
            assert!(geste_d_unite(nom, etat).is_err(), "{nom} {etat}");
        }
        assert_eq!(
            geste_d_unite("ufw", "enabled"),
            Ok(Some(GesteUnix::Unite(ActionUnite::Activer, &UFW)))
        );
        // « fstrim » sans suffixe serait fstrim.service, pas le minuteur.
        assert_eq!(unite_connue("fstrim"), None);
    }

    /// Une ligne qui n'a pas exactement la forme d'un geste n'en désigne aucun.
    #[test]
    fn refus_de_l_etranger() {
        for l in [
            "",
            "vanguard:geste",
            "vanguard:geste ",
            "vanguard:geste programme",
            "vanguard:geste programme ",
            "vanguard:geste programme inconnu",
            "vanguard:geste programme FRESHCLAM",
            "vanguard:geste programme freshclam ",
            "vanguard:geste programme  freshclam",
            "vanguard:geste programme freshclam --datadir=/tmp",
            "vanguard:geste programme freshclam\0",
            "vanguard:geste programme freshclam\n",
            "vanguard:geste programme ../freshclam",
            "vanguard:geste programme /usr/bin/freshclam",
            "vanguard:geste famille-inconnue freshclam",
            "vanguard:geste Programme freshclam",
            " vanguard:geste programme freshclam",
            "vanguard:programme freshclam",
            "sudo freshclam",
        ] {
            assert_eq!(analyser(l), None, "{l:?}");
        }
        for l in [
            "vanguard:geste unite",
            "vanguard:geste unite activer",
            "vanguard:geste unite activer cups",
            "vanguard:geste unite activer cups.service ",
            "vanguard:geste unite  activer cups.service",
            "vanguard:geste unite Activer cups.service",
            "vanguard:geste unite activer CUPS.service",
            "vanguard:geste unite activer sshd.service",
            "vanguard:geste unite masquer cups.service",
            "vanguard:geste unite activer cups.service --now",
            "vanguard:geste unite reinitialiser-echecs cups.service",
            "vanguard:geste unite reinitialiser-echecs ",
            "vanguard:geste unite-designee arreter",
            "vanguard:geste unite-designee arreter anydesk.service anydesk.service",
            "vanguard:geste signatures-clamav ",
            "vanguard:geste signatures-clamav freshclam",
            "vanguard:geste Signatures-clamav",
        ] {
            assert_eq!(analyser(l), None, "{l:?}");
        }
        let longue = format!("{PREFIXE}programme {}", "a".repeat(GESTE_MAX));
        assert_eq!(analyser(&longue), None);
        let tres_longue = format!("{PREFIXE}programme freshclam{}", " ".repeat(LIGNE_MAX));
        assert_eq!(analyser(&tres_longue), None);
    }

    /// Aucune ligne forgée ne fait sauter la question « connecté par lui ? » ni l'accord de l'arrêt d'une unité
    /// désignée : la grammaire n'a aucun mot pour les dire, et toute ligne qui en ajoute un ne se lit pas. La seule qui
    /// se lit demande les deux.
    #[test]
    fn l_arret_designe_ne_se_forge_pas_sans_question() {
        let juste = "vanguard:geste unite-designee arreter anydesk.service";
        let g = analyser(juste).expect(juste);
        assert!(g.demande_accord());
        for ajout in [
            " sans-question",
            " non",
            " oui",
            " confirme",
            " --force",
            " deja-confirme",
            "\nnon",
            "\0",
            " ",
        ] {
            let l = format!("{juste}{ajout}");
            assert_eq!(analyser(&l), None, "{l:?}");
        }
        for l in [
            "vanguard:geste unite-designee  arreter anydesk.service",
            "vanguard:geste unite-designee arreter-sans-question anydesk.service",
            "vanguard:geste unite-designee arreter-confirme anydesk.service",
            "vanguard:geste unite-designee tuer anydesk.service",
            "vanguard:geste unite-designee kill anydesk.service",
            "vanguard:geste unite-designee desactiver anydesk.service",
            "vanguard:geste unite-designee arreter non anydesk.service",
            "vanguard:geste unite-designee-confirmee arreter anydesk.service",
        ] {
            assert_eq!(analyser(l), None, "{l:?}");
        }
    }

    /// Un geste de Linux n'est permis que sous Linux (aucun sous macOS, plan D8).
    #[test]
    fn permis_sous_linux_seulement() {
        assert_eq!(GesteUnix::Programme(&FRESHCLAM).permis_ici(), cfg!(target_os = "linux"));
        assert!(!GesteUnix::Programme(&FRESHCLAM).demande_accord());
    }

    fn id() -> IdNote {
        IdNote::nouveau("0123456789abcdef").unwrap()
    }

    fn tous_les_gestes_de_defense() -> Vec<Defense> {
        let n = NomCompte::nouveau("alice").unwrap();
        let c = CheminDesigne::nouveau(b"/tmp/x\n\x1b[31m").unwrap();
        let mut v = vec![
            Defense::VerrouillerCompte(n),
            Defense::DurcirSudo(n),
            Defense::RetirerSetuid(c),
            Defense::RetirerCapacites(c),
            Defense::RendreDossierARoot(CheminDesigne::nouveau(b"/opt/bin").unwrap()),
            Defense::DesactiverService(NomUnite::nouveau("minage.service").unwrap()),
            Defense::RetirerLigne(
                Empreinte([0xab; 32]),
                CheminDesigne::nouveau(b"/etc/ld.so.preload").unwrap(),
            ),
            Defense::Remettre,
            Defense::ReserverBpf,
            Defense::GarderJournal,
            Defense::RetirerAncre(CheminDesigne::nouveau(b"/usr/local/share/ca-certificates/x\n\x1b[31m.crt").unwrap()),
            Defense::CommenterProxy(
                Empreinte([0xcd; 32]),
                CheminDesigne::nouveau(b"/etc/environment").unwrap(),
            ),
            Defense::OublierBluetooth(AdresseBt([0x00, 0x1a, 0x7d, 0xda, 0x71, 0x13])),
            Defense::ArreterProgramme(4242, 123_456),
            Defense::ArreterProgramme(u32::MAX, u64::MAX),
            Defense::RemettreProgramme(CheminDesigne::nouveau(b"/usr/local/bin/vanguard").unwrap()),
            Defense::RemettreProgramme(CheminDesigne::nouveau(b"/opt/x\n\x1b[31m/vanguard-linux-x86_64").unwrap()),
        ];
        v.extend(GroupeSensible::TOUS.map(|g| Defense::RetirerDuGroupe(g, n)));
        v.extend(ReglageSsh::TOUS.map(Defense::DurcirSsh));
        v.extend(PareFeu::TOUS.map(Defense::CouperPareFeu));
        v.extend(PareFeu::TOUS.map(Defense::RallumerPareFeu));
        v
    }

    /// L'identifiant d'essai, sauf pour une coupure de pare-feu, qui ne se note que sous le sien.
    fn id_de(d: &Defense) -> IdNote {
        match d {
            Defense::CouperPareFeu(p) => p.note(),
            _ => id(),
        }
    }

    /// Chaque geste de défense se relit tel quel, tient dans la borne, ne porte ni « / », ni octet de contrôle, et
    /// demande l'accord de la personne sur son terminal.
    #[test]
    fn defense_aller_retour_et_accord() {
        for d in tous_les_gestes_de_defense() {
            let g = GesteUnix::Defense(d, id_de(&d));
            let l = g.ligne();
            assert_eq!(analyser(&l), Some(g), "{l}");
            assert!(
                l.len() <= GESTE_MAX && l.is_ascii() && !l.contains(['/', '\n', '\r', '\x1b', '\t', '\0']),
                "{l}"
            );
            assert!(g.demande_accord(), "{l}");
            assert!(!g.coupe_session());
            assert_eq!(
                g.par_systemd(),
                matches!(
                    d,
                    Defense::DesactiverService(_)
                        | Defense::DurcirSsh(_)
                        | Defense::GarderJournal
                        | Defense::CouperPareFeu(PareFeu::Firewalld)
                        | Defense::RallumerPareFeu(PareFeu::Firewalld | PareFeu::Nftables)
                )
            );
        }
        assert_eq!(
            GesteUnix::Defense(Defense::VerrouillerCompte(NomCompte::nouveau("alice").unwrap()), id()).ligne(),
            "vanguard:geste defense verrouiller-compte alice 0123456789abcdef"
        );
        assert_eq!(
            GesteUnix::Defense(Defense::RetirerSetuid(CheminDesigne::nouveau(b"/tmp/a").unwrap()), id()).ligne(),
            "vanguard:geste defense retirer-setuid 2f746d702f61 0123456789abcdef"
        );
        // La plus longue ligne possible tient dans la borne.
        let mut long = b"/etc/systemd/system/".to_vec();
        long.extend(std::iter::repeat_n(b'a', CHEMIN_MAX - long.len() - 8));
        long.extend(b".service");
        let plus_long = GesteUnix::Defense(
            Defense::RetirerLigne(Empreinte([0xff; 32]), CheminDesigne::nouveau(&long).unwrap()),
            id(),
        );
        assert_eq!(plus_long.ligne().len(), 631);
        assert!(plus_long.ligne().len() <= GESTE_MAX);
        assert_eq!(analyser(&plus_long.ligne()), Some(plus_long));
    }

    /// Lot D7c. Une coupure de pare-feu ne se relit que sous l'identifiant fixe de son pare-feu ; ces identifiants
    /// ne servent à aucun autre geste (sauf Remettre, qui rallume) ; un pare-feu hors des trois, une majuscule, un
    /// champ en plus : refusés. La coupure baisse une protection, et le dit.
    #[test]
    fn pare_feu_coupe_sous_son_seul_identifiant() {
        for p in PareFeu::TOUS {
            assert_eq!(PareFeu::depuis_mot(p.mot()), Some(p));
            assert_eq!(PareFeu::de_la_note(p.note()), Some(p));
            assert_eq!(IdNote::nouveau(p.note().as_str()), Some(p.note()));
            assert_ne!(p.note(), id());
            let coupe = GesteUnix::Defense(Defense::CouperPareFeu(p), p.note());
            assert_eq!(analyser(&coupe.ligne()), Some(coupe));
            assert_eq!(
                coupe.pourquoi_l_accord().map(|(fr, _)| fr),
                Some("ceci baisse une protection : le pare-feu est coupé")
            );
            // Sous un identifiant au hasard, ou celui d'un autre pare-feu : jamais.
            let ailleurs = GesteUnix::Defense(Defense::CouperPareFeu(p), id());
            assert!(ailleurs.refus().is_some());
            assert_eq!(analyser(&ailleurs.ligne()), None);
            for q in PareFeu::TOUS.into_iter().filter(|q| *q != p) {
                let croise = GesteUnix::Defense(Defense::CouperPareFeu(p), q.note());
                assert_eq!(analyser(&croise.ligne()), None, "{}", croise.ligne());
            }
            // Remettre prend l'identifiant fixe (Défaire, Rallumer) ; aucun autre geste.
            let remettre = GesteUnix::Defense(Defense::Remettre, p.note());
            assert_eq!(analyser(&remettre.ligne()), Some(remettre));
            for d in tous_les_gestes_de_defense()
                .into_iter()
                .filter(|d| !matches!(d, Defense::CouperPareFeu(_) | Defense::Remettre))
            {
                let g = GesteUnix::Defense(d, p.note());
                assert!(g.refus().is_some(), "{}", g.ligne());
                assert_eq!(analyser(&g.ligne()), None, "{}", g.ligne());
            }
            assert_eq!(
                GesteUnix::Defense(Defense::RallumerPareFeu(p), id()).ligne(),
                format!("vanguard:geste defense rallumer-pare-feu {} 0123456789abcdef", p.mot())
            );
        }
        assert_eq!(
            GesteUnix::Defense(Defense::CouperPareFeu(PareFeu::Ufw), PareFeu::Ufw.note()).ligne(),
            "vanguard:geste defense couper-pare-feu ufw 000000000000fe01"
        );
        for l in [
            "vanguard:geste defense couper-pare-feu iptables 000000000000fe01",
            "vanguard:geste defense couper-pare-feu UFW 000000000000fe01",
            "vanguard:geste defense couper-pare-feu  ufw 000000000000fe01",
            "vanguard:geste defense couper-pare-feu ufw firewalld 000000000000fe01",
            "vanguard:geste defense couper-pare-feu 000000000000fe01",
            "vanguard:geste defense couper-pare-feu ufw 000000000000FE01",
            "vanguard:geste defense couper-pare-feu ufw 000000000000fe01 ",
            "vanguard:geste defense couper-pare-feu ufw\n 000000000000fe01",
            "vanguard:geste defense couper-pare-feu ufw\x1b[31m 000000000000fe01",
            "vanguard:geste defense couper-pare-feu ufw\r 000000000000fe01",
            "vanguard:geste defense rallumer-pare-feu nft 0123456789abcdef",
            "vanguard:geste defense rallumer-pare-feu ufw 000000000000fe01",
            "vanguard:geste defense desactiver-service minage.service 000000000000fe03",
        ] {
            assert_eq!(analyser(l), None, "{l}");
        }
        let long = format!(
            "vanguard:geste defense couper-pare-feu {} 000000000000fe01",
            "u".repeat(5000)
        );
        assert_eq!(analyser(&long), None);
    }

    /// Une ligne de défense forgée ne se relit pas : champ en plus ou en moins, majuscule dans l'hexadécimal,
    /// identifiant trop court, chemin relatif ou qui remonte, compte hostile, service de session, fichier hors de la
    /// liste.
    #[test]
    fn defense_forgee_refusee() {
        let h = |c: &[u8]| hex(c);
        for l in [
            "vanguard:geste defense verrouiller-compte alice".to_string(),
            "vanguard:geste defense verrouiller-compte alice 0123456789ABCDEF".to_string(),
            "vanguard:geste defense verrouiller-compte alice 0123456789abcde".to_string(),
            "vanguard:geste defense verrouiller-compte alice bob 0123456789abcdef".to_string(),
            "vanguard:geste defense verrouiller-compte -oroot 0123456789abcdef".to_string(),
            "vanguard:geste defense verrouiller-compte Alice 0123456789abcdef".to_string(),
            format!(
                "vanguard:geste defense verrouiller-compte {} 0123456789abcdef",
                "a".repeat(33)
            ),
            "vanguard:geste defense retirer-du-groupe wheel alice 0123456789abcdef".to_string(),
            "vanguard:geste defense retirer-du-groupe root alice 0123456789abcdef".to_string(),
            format!("vanguard:geste defense retirer-setuid {} 0123456789abcdef", h(b"tmp/x")),
            format!(
                "vanguard:geste defense retirer-setuid {} 0123456789abcdef",
                h(b"/tmp/../etc/shadow")
            ),
            format!(
                "vanguard:geste defense retirer-setuid {} 0123456789abcdef",
                h(b"/tmp//x")
            ),
            format!(
                "vanguard:geste defense retirer-setuid {} 0123456789abcdef",
                h(b"/tmp/x/")
            ),
            format!(
                "vanguard:geste defense retirer-setuid {} 0123456789abcdef",
                h(b"/tmp/\0x")
            ),
            format!(
                "vanguard:geste defense retirer-setuid {} 0123456789abcdef",
                h(b"/tmp/x").to_uppercase()
            ),
            format!(
                "vanguard:geste defense retirer-setuid {}0 0123456789abcdef",
                h(b"/tmp/x")
            ),
            "vanguard:geste defense desactiver-service sshd.service 0123456789abcdef".to_string(),
            "vanguard:geste defense desactiver-service gdm.service 0123456789abcdef".to_string(),
            "vanguard:geste defense desactiver-service ufw.service 0123456789abcdef".to_string(),
            format!(
                "vanguard:geste defense retirer-ligne {} {} 0123456789abcdef",
                "ab".repeat(32),
                h(b"/etc/shadow")
            ),
            format!(
                "vanguard:geste defense retirer-ligne {} {} 0123456789abcdef",
                "ab".repeat(31),
                h(b"/etc/profile")
            ),
            format!(
                "vanguard:geste defense retirer-ligne {} {} 0123456789abcdef",
                "ab".repeat(32),
                h(b"/etc/profile.d/../shadow")
            ),
            format!(
                "vanguard:geste defense retirer-ligne {} {} 0123456789abcdef",
                "ab".repeat(32),
                h(b"/etc/cron.d/.cache")
            ),
            "vanguard:geste defense remettre".to_string(),
            "vanguard:geste defense remettre x 0123456789abcdef".to_string(),
            "vanguard:geste defense  remettre 0123456789abcdef".to_string(),
            "vanguard:geste defense remettre 0123456789abcdef ".to_string(),
            "vanguard:geste defense effacer 0123456789abcdef".to_string(),
            // Lot D7b : réglage inconnu, champ en trop, PID 0 ou 1, nombre signé, à zéro devant ou trop grand,
            // adresse trop courte ou en majuscules, ancre hors des dossiers d'ajouts, proxy d'un fichier inconnu.
            "vanguard:geste defense durcir-ssh tout 0123456789abcdef".to_string(),
            "vanguard:geste defense durcir-ssh root root 0123456789abcdef".to_string(),
            "vanguard:geste defense durcir-ssh 0123456789abcdef".to_string(),
            "vanguard:geste defense reserver-bpf 2 0123456789abcdef".to_string(),
            "vanguard:geste defense garder-journal volatile 0123456789abcdef".to_string(),
            "vanguard:geste defense arreter-programme 1 5 0123456789abcdef".to_string(),
            "vanguard:geste defense arreter-programme 0 5 0123456789abcdef".to_string(),
            "vanguard:geste defense arreter-programme +42 5 0123456789abcdef".to_string(),
            "vanguard:geste defense arreter-programme 042 5 0123456789abcdef".to_string(),
            "vanguard:geste defense arreter-programme 42 0123456789abcdef".to_string(),
            "vanguard:geste defense arreter-programme 4294967296 5 0123456789abcdef".to_string(),
            "vanguard:geste defense arreter-programme 42 -5 0123456789abcdef".to_string(),
            "vanguard:geste defense oublier-bluetooth 001a7dda71 0123456789abcdef".to_string(),
            "vanguard:geste defense oublier-bluetooth 001A7DDA7113 0123456789abcdef".to_string(),
            "vanguard:geste defense oublier-bluetooth 00:1a:7d:da:71:13 0123456789abcdef".to_string(),
            format!(
                "vanguard:geste defense retirer-ancre {} 0123456789abcdef",
                h(b"/etc/ssl/certs/x.pem")
            ),
            format!(
                "vanguard:geste defense retirer-ancre {} 0123456789abcdef",
                h(b"/usr/local/share/ca-certificates/")
            ),
            format!(
                "vanguard:geste defense retirer-ancre {} 0123456789abcdef",
                h(b"/usr/local/share/ca-certificates/../../../etc/shadow")
            ),
            format!(
                "vanguard:geste defense commenter-proxy {} {} 0123456789abcdef",
                "ab".repeat(32),
                h(b"/home/alice/.bashrc")
            ),
            // « Refaire » : un autre programme que celui de Vanguard, un dossier d'un compte ou temporaire, un nom qui
            // ne fait que commencer comme le sien, un champ en trop.
            format!(
                "vanguard:geste defense remettre-programme {} 0123456789abcdef",
                h(b"/usr/bin/sudo")
            ),
            format!(
                "vanguard:geste defense remettre-programme {} 0123456789abcdef",
                h(b"/home/alice/.local/share/vanguard/bin/vanguard")
            ),
            format!(
                "vanguard:geste defense remettre-programme {} 0123456789abcdef",
                h(b"/tmp/vanguard")
            ),
            format!(
                "vanguard:geste defense remettre-programme {} 0123456789abcdef",
                h(b"/usr/local/bin/vanguard.sh")
            ),
            format!(
                "vanguard:geste defense remettre-programme {} 0123456789abcdef",
                h(b"/usr/local/bin/../../../etc/vanguard")
            ),
            format!(
                "vanguard:geste defense remettre-programme {} {} 0123456789abcdef",
                h(b"/usr/local/bin/vanguard"),
                h(b"/usr/bin/sudo")
            ),
        ] {
            assert_eq!(analyser(&l), None, "{l:?}");
        }
        assert!(analyser("vanguard:geste defense remettre 0123456789abcdef").is_some());
    }

    /// Un nom de fichier hostile se désigne, mais ne s'affiche qu'échappé : ni saut de ligne, ni retour chariot, ni
    /// échappement de terminal, borné.
    #[test]
    fn chemin_hostile_echappe() {
        let c = CheminDesigne::nouveau(b"/tmp/a\nb\rc\x1b[2Jd\\e\xc3\xa9").unwrap();
        assert_eq!(c.lisible(), "/tmp/a\\x0ab\\x0dc\\x1b[2Jd\\\\e\\xc3\\xa9");
        let mut long = b"/tmp/".to_vec();
        long.extend(std::iter::repeat_n(b'\x1b', 200));
        let l = CheminDesigne::nouveau(&long).unwrap().lisible();
        assert!(l.ends_with('…') && !l.contains('\x1b') && l.len() < 600);
        let (fr, en) = GesteUnix::Defense(Defense::RetirerSetuid(c), id()).phrase();
        assert!(!fr.contains(['\n', '\r', '\x1b']) && !en.contains(['\n', '\r', '\x1b']));
        assert!(CheminDesigne::nouveau(&[b'/'; 1]).is_none());
        let mut trop = b"/".to_vec();
        trop.extend(std::iter::repeat_n(b'a', CHEMIN_MAX));
        assert!(CheminDesigne::nouveau(&trop).is_none());
        for (h, attendu) in [
            ("", None),
            ("0", None),
            ("0A", None),
            ("zz", None),
            ("00ff", Some(vec![0, 255])),
        ] {
            assert_eq!(depuis_hex(h, 8), attendu, "{h}");
        }
        assert_eq!(depuis_hex("000000", 2), None);
    }

    /// Les fichiers dont une ligne se retire : la liste fermée, et rien d'autre.
    #[test]
    fn fichiers_de_ligne() {
        // L'instance d'un modèle (getty, tty1) écrite par morceaux : son nom complet a la forme d'un courriel.
        let instance = format!("/etc/systemd/system/getty@tty1.{}.d/override.conf", "service");
        for f in [
            "/etc/ld.so.preload",
            "/etc/profile.d/x.sh",
            "/etc/cron.d/minage",
            "/etc/systemd/system/minage.service",
            instance.as_str(),
            "/etc/xdg/autostart/a.desktop",
            "/etc/gdm3/daemon.conf",
            "/etc/sddm.conf.d/autologin.conf",
        ] {
            assert!(fichier_de_ligne_admis(f.as_bytes()), "{f}");
        }
        for f in [
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/profile.d/.sh",
            "/etc/profile.d/x.py",
            "/etc/profile.d/a/b.sh",
            "/etc/cron.d/.x",
            "/etc/cron.d/a b",
            "/etc/systemd/system/x.service.d/a/b.conf",
            "/etc/systemd/system/.d/a.conf",
            "/home/alice/.bashrc",
            "/etc/ld.so.preload/x",
        ] {
            assert!(!fichier_de_ligne_admis(f.as_bytes()), "{f}");
        }
    }

    /// Les noms de compte : minuscules, jamais une option, 32 octets au plus.
    #[test]
    fn noms_de_compte() {
        for n in ["alice", "_apt", "bob-2", "a.b", &"a".repeat(32)] {
            assert!(nom_compte_admis(n), "{n}");
        }
        for n in [
            "",
            "-r",
            "Alice",
            "1a",
            "a b",
            "a\n",
            "a:b",
            "a/b",
            "é",
            &"a".repeat(33),
            "a$",
        ] {
            assert!(!nom_compte_admis(n), "{n:?}");
        }
        assert_eq!(GroupeSensible::de_nom("wheel"), Some(GroupeSensible::Administrateurs));
        assert_eq!(GroupeSensible::de_nom("docker"), Some(GroupeSensible::Docker));
        assert_eq!(GroupeSensible::de_nom("users"), None);
    }

    /// Le réseau que traverse une session (tunnel, VPN, pare-feu, même maison) n'est jamais désactivé par un geste ; un
    /// service ordinaire ajouté, si.
    #[test]
    fn reseau_des_sessions_jamais_desactive() {
        let wg = format!("wg-quick@wg0.{}", "service");
        for nom in [
            wg.as_str(),
            "openvpn-salon.service",
            "networking.service",
            "wpa_supplicant.service",
            "nftables.service",
            "pare-feu.service",
            "tailscaled.service",
            "sshd.service",
        ] {
            assert!(unite_portant_les_sessions(nom), "{nom}");
            let d = GesteUnix::Defense(
                Defense::DesactiverService(NomUnite::nouveau(nom).unwrap()),
                IdNote::nouveau("0123456789abcdef").unwrap(),
            );
            assert!(d.refus().is_some(), "{nom}");
            assert_eq!(analyser(&d.ligne()), None, "{nom}");
        }
        for nom in ["minage.service", "alice-sauvegarde.timer"] {
            assert!(!unite_portant_les_sessions(nom), "{nom}");
        }
    }
}
