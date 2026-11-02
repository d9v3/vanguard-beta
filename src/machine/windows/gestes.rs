//! La grammaire des lignes que le processus élevé (`eleve`) lit du Vanguard non élevé, pour ce qui n'est ni une
//! correction de la table (`corrections`) ni un ordre du blocage : le script PowerShell vérifié par empreinte
//! (`vanguard:script`), les programmes fixes de Windows (`vanguard:programme`), lancés par leur chemin complet avec
//! des arguments figés, sans shell, et les actes sur Windows lui-même (`vanguard:service`, `vanguard:vider`,
//! `vanguard:vider-file-impression`, `vanguard:mettre-de-cote`, `vanguard:pare-feu-actif`, `vanguard:pare-feu-public`,
//! `vanguard:reseau-categorie`, `vanguard:ifeo-debugger[-32]`, `vanguard:ifeo-silencieux[-32]`,
//! `vanguard:service-guillemets`, `vanguard:defender`, `vanguard:defender-asr`, `vanguard:defender-exclusion-retirer`,
//! `vanguard:defender-menaces-retirer`), faits par le gestionnaire de services, std::fs, les interfaces COM du
//! pare-feu et des réseaux (`pare_feu`), le registre (`portes`, `services`) et WMI (`defender_ecriture`). Un réglage
//! de Defender n'admet que des valeurs qui protègent : aucune ligne ne peut couper le temps réel ni le cloud.
//! Plus la découpe d'une liste de correctifs en morceaux (gestes natifs, scripts) et la lecture des états d'un
//! script : du code pur, sans E/S, testé sous Linux et lu par le banc de fuzzing
//! (fuzz/fuzz_targets/gestes.rs). C'est la seule entrée que le processus élevé lit d'un processus moins sûr : rien ici
//! ne dépend du reste de Vanguard.
//!
//! Le parent n'envoie jamais un chemin de programme ni un argument libre : seulement un identifiant de la table, et,
//! pour retirer une fonctionnalité de Windows, un nom pris dans une liste fermée. Le dossier, le programme et ses
//! arguments sont ceux de la table, lus par le processus élevé. De même pour un acte : un service et une action de
//! la table (`SERVICES`), un identifiant de dossier, jamais un chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::fmt::Write as _;

/// La plus longue ligne admise : celle d'un ordre du blocage (un chemin de programme) ; `ordres::LIGNE_MAX`.
pub(crate) const LIGNE_MAX: usize = 8448;
/// Au-delà, une liste n'est pas celle d'une session de Vanguard ; `ordres::LIGNES_MAX`.
pub(crate) const LIGNES_MAX: usize = 512;
/// Le verbe d'un script PowerShell vérifié par empreinte.
pub(crate) const SCRIPT: &str = "vanguard:script ";
/// Le verbe d'un programme fixe de Windows.
pub(crate) const PROGRAMME: &str = "vanguard:programme ";
/// Une ligne de programme est courte : un identifiant, et au plus un nom de fonctionnalité.
const PROGRAMME_MAX: usize = 256;
/// Au-delà, les états d'un script ne viennent pas d'un script de Vanguard.
pub(crate) const ETATS_MAX: usize = 4096;

// ------------------------------------------------------------------ le script

/// Un script PowerShell à lancer seulement si ses octets ont cette empreinte (SHA-256, hexadécimal majuscule).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Script {
    pub empreinte: String,
    pub chemin: String,
}

/// La ligne qui demande ce script.
pub(crate) fn ligne_script(empreinte: &str, chemin: &str) -> String {
    let hex = chemin.bytes().fold(String::new(), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    });
    format!("{SCRIPT}{empreinte} {hex}")
}

/// Le script d'une ligne, si et seulement si elle est exactement de sa forme : 64 chiffres hexadécimaux majuscules,
/// une espace, un chemin complet de .ps1 en hexadécimal minuscule. Le chemin est découpé sur `\` à la main (pas par
/// `Path`, qui sous Linux n'y voit pas de séparateur) : « correction-….ps1 » dans un dossier « corrections », sans
/// composant « . » ni « .. ».
pub(crate) fn analyser_script(ligne: &str) -> Option<Script> {
    let (empreinte, hex) = ligne.strip_prefix(SCRIPT)?.split_once(' ')?;
    let forme = empreinte.len() == 64 && empreinte.bytes().all(|o| matches!(o, b'0'..=b'9' | b'A'..=b'F'));
    if !forme || hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let octets: Option<Vec<u8>> = hex
        .as_bytes()
        .chunks(2)
        .map(|paire| {
            let fort = chiffre_minuscule(*paire.first()?)?;
            let faible = chiffre_minuscule(*paire.get(1)?)?;
            fort.checked_mul(16)?.checked_add(faible)
        })
        .collect();
    let chemin = String::from_utf8(octets?).ok()?;
    let o = chemin.as_bytes();
    let complet = matches!(o, [lecteur, b':', b'\\', _, ..] if lecteur.is_ascii_alphabetic());
    let mut composants = chemin.rsplit('\\');
    let nom = composants.next().unwrap_or_default();
    let dossier = composants.next().unwrap_or_default();
    let ps1 = nom.starts_with("correction-")
        && nom.to_ascii_lowercase().ends_with(".ps1")
        && dossier.eq_ignore_ascii_case("corrections");
    let sans_detour = !chemin.split(['\\', '/']).any(|c| c == "." || c == "..");
    (complet && ps1 && sans_detour && !chemin.contains(['\0', '\n', '\r']) && ligne_script(empreinte, &chemin) == ligne)
        .then(|| Script {
            empreinte: empreinte.to_string(),
            chemin,
        })
}

fn chiffre_minuscule(o: u8) -> Option<u8> {
    match o {
        b'0'..=b'9' => o.checked_sub(b'0'),
        b'a'..=b'f' => o.checked_sub(b'a')?.checked_add(10),
        _ => None,
    }
}

// ------------------------------------------------------------- les programmes

/// Où est le programme : lu par le processus élevé lui-même, jamais dans l'environnement.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Dossier {
    /// System32 (GetSystemDirectoryW).
    Systeme32,
    /// `<lecteur de Windows>\Program Files\Windows Defender` : le chemin par défaut de FOLDERID_ProgramFiles pour un
    /// programme 64 bits (« %SystemDrive%\Program Files »), le lecteur pris dans le chemin de System32.
    Defender,
}

/// Le dossier de Defender, sous le lecteur de Windows.
pub(crate) const DOSSIER_DEFENDER: &str = r"Program Files\Windows Defender";

/// Un argument du programme : figé, ou désigné par la ligne dans une liste fermée.
#[derive(Debug)]
pub(crate) enum Argument {
    Fixe(&'static str),
    /// La lettre du lecteur de Windows (« C: »), lue par le processus élevé.
    LecteurSysteme,
    /// Ce préfixe, suivi du nom donné par la ligne (une des `noms` du programme).
    Nom(&'static str),
}

/// Un programme fixe de Windows : un outil de réparation, lancé tel quel.
#[derive(Debug)]
pub(crate) struct Programme {
    /// `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    pub dossier: Dossier,
    pub exe: &'static str,
    pub arguments: &'static [Argument],
    /// Les seuls noms admis après l'identifiant ; vide : la ligne n'en porte pas.
    pub noms: &'static [&'static str],
    /// Les codes de sortie qui veulent dire « fait ».
    pub reussites: &'static [i32],
    /// Ceux qui veulent dire « reste à faire » : ni fait ni échoué, la personne doit lancer elle-même ce qui finit le
    /// travail (chkdsk /f, qui propose de vérifier au redémarrage) ; Vanguard ne programme rien.
    pub au_redemarrage: &'static [i32],
    pub fr: &'static str,
    pub en: &'static str,
}

/// 3010 : fait, redémarrage nécessaire (comme le script PowerShell le comptait déjà).
const FAIT: &[i32] = &[0, 3010];

/// Les fonctionnalités de Windows que Vanguard peut retirer : PowerShell 2.0 et le client SMBv1.
const FONCTIONS_A_RETIRER: &[&str] = &[
    "MicrosoftWindowsPowerShellV2Root",
    "MicrosoftWindowsPowerShellV2",
    "SMB1Protocol-Client",
];

/// La table fermée. Ce que le clic d'administrateur autorise pour une ligne `vanguard:programme`, ce sont ces
/// programmes-là, avec ces arguments-là.
pub(crate) static PROGRAMMES: &[Programme] = &[
    Programme {
        id: "dism-restorehealth",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Cleanup-Image"),
            Argument::Fixe("/RestoreHealth"),
        ],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Réparer l'image de Windows (DISM)",
        en: "Repair the Windows image (DISM)",
    },
    Programme {
        id: "sfc-scannow",
        dossier: Dossier::Systeme32,
        exe: "sfc.exe",
        arguments: &[Argument::Fixe("/scannow")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Vérifier et réparer les fichiers système (SFC)",
        en: "Check and repair the system files (SFC)",
    },
    Programme {
        id: "chkdsk-scan-systeme",
        dossier: Dossier::Systeme32,
        exe: "chkdsk.exe",
        arguments: &[Argument::LecteurSysteme, Argument::Fixe("/scan")],
        noms: &[],
        // Microsoft (learn.microsoft.com, chkdsk) : 0 aucune erreur, 1 erreurs trouvées et corrigées, 2 nettoyage
        // fait ou non fait faute de /f ; 3 disque non vérifiable, erreurs non corrigeables ou non corrigées faute de
        // /f. Rien n'est programmé : la personne lance chkdsk /f, qui propose de vérifier au redémarrage.
        reussites: &[0, 1, 2],
        au_redemarrage: &[3],
        fr: "Analyser le disque de Windows sans le bloquer (chkdsk /scan)",
        en: "Scan the Windows disk without locking it (chkdsk /scan)",
    },
    Programme {
        id: "netsh-winsock-reset",
        dossier: Dossier::Systeme32,
        exe: "netsh.exe",
        arguments: &[Argument::Fixe("winsock"), Argument::Fixe("reset")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Remettre Winsock à zéro",
        en: "Reset Winsock",
    },
    Programme {
        id: "netsh-ip-reset",
        dossier: Dossier::Systeme32,
        exe: "netsh.exe",
        arguments: &[Argument::Fixe("int"), Argument::Fixe("ip"), Argument::Fixe("reset")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Remettre la pile TCP/IP à zéro",
        en: "Reset the TCP/IP stack",
    },
    Programme {
        id: "netsh-winhttp-reset-proxy",
        dossier: Dossier::Systeme32,
        exe: "netsh.exe",
        arguments: &[
            Argument::Fixe("winhttp"),
            Argument::Fixe("reset"),
            Argument::Fixe("proxy"),
        ],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Retirer le proxy WinHTTP",
        en: "Remove the WinHTTP proxy",
    },
    Programme {
        id: "ipconfig-flushdns",
        dossier: Dossier::Systeme32,
        exe: "ipconfig.exe",
        arguments: &[Argument::Fixe("/flushdns")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Vider le cache DNS",
        en: "Clear the DNS cache",
    },
    Programme {
        id: "ipconfig-release",
        dossier: Dossier::Systeme32,
        exe: "ipconfig.exe",
        arguments: &[Argument::Fixe("/release")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Rendre l'adresse IP (DHCP)",
        en: "Release the IP address (DHCP)",
    },
    Programme {
        id: "ipconfig-renew",
        dossier: Dossier::Systeme32,
        exe: "ipconfig.exe",
        arguments: &[Argument::Fixe("/renew")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Redemander une adresse IP (DHCP)",
        en: "Request a new IP address (DHCP)",
    },
    Programme {
        id: "net-accounts-verrouillage",
        dossier: Dossier::Systeme32,
        exe: "net.exe",
        arguments: &[
            Argument::Fixe("accounts"),
            Argument::Fixe("/lockoutthreshold:10"),
            Argument::Fixe("/lockoutduration:10"),
            Argument::Fixe("/lockoutwindow:10"),
        ],
        noms: &[],
        reussites: &[0],
        au_redemarrage: &[],
        fr: "Bloquer un compte 10 minutes après 10 mots de passe faux",
        en: "Lock an account for 10 minutes after 10 wrong passwords",
    },
    Programme {
        id: "net-accounts-longueur-8",
        dossier: Dossier::Systeme32,
        exe: "net.exe",
        arguments: &[Argument::Fixe("accounts"), Argument::Fixe("/minpwlen:8")],
        noms: &[],
        reussites: &[0],
        au_redemarrage: &[],
        fr: "Exiger des mots de passe de 8 caractères au moins",
        en: "Require passwords of at least 8 characters",
    },
    Programme {
        id: "w32tm-resync",
        dossier: Dossier::Systeme32,
        exe: "w32tm.exe",
        arguments: &[Argument::Fixe("/resync"), Argument::Fixe("/force")],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Resynchroniser l'horloge (service de temps de Windows)",
        en: "Resynchronize the clock (Windows time service)",
    },
    Programme {
        id: "defender-signatures",
        dossier: Dossier::Defender,
        exe: "MpCmdRun.exe",
        arguments: &[Argument::Fixe("-SignatureUpdate")],
        noms: &[],
        reussites: &[0],
        au_redemarrage: &[],
        fr: "Mettre à jour les signatures de Microsoft Defender",
        en: "Update the Microsoft Defender signatures",
    },
    Programme {
        id: "dism-nettoyage-composants",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Cleanup-Image"),
            Argument::Fixe("/StartComponentCleanup"),
        ],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Retirer les versions remplacées des composants de Windows (DISM)",
        en: "Remove the replaced versions of Windows components (DISM)",
    },
    Programme {
        id: "dism-retirer-fonction",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Disable-Feature"),
            Argument::Nom("/FeatureName:"),
            Argument::Fixe("/NoRestart"),
        ],
        noms: FONCTIONS_A_RETIRER,
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Retirer une fonctionnalité de Windows (DISM)",
        en: "Remove a Windows feature (DISM)",
    },
    Programme {
        id: "dism-ajouter-netfx3",
        dossier: Dossier::Systeme32,
        exe: "dism.exe",
        arguments: &[
            Argument::Fixe("/Online"),
            Argument::Fixe("/Enable-Feature"),
            Argument::Fixe("/FeatureName:NetFx3"),
            Argument::Fixe("/All"),
            Argument::Fixe("/NoRestart"),
        ],
        noms: &[],
        reussites: FAIT,
        au_redemarrage: &[],
        fr: "Installer .NET Framework 3.5 (DISM, par Windows Update)",
        en: "Install .NET Framework 3.5 (DISM, through Windows Update)",
    },
];

/// Une ligne `vanguard:programme`, relue : le programme de la table, et son nom s'il en prend un.
#[derive(Debug)]
pub(crate) struct Appel {
    pub programme: &'static Programme,
    pub nom: Option<&'static str>,
}

impl Appel {
    /// La ligne qui le demande, telle que le parent l'envoie.
    pub(crate) fn ligne(&self) -> String {
        match self.nom {
            Some(n) => format!("{PROGRAMME}{} {n}", self.programme.id),
            None => format!("{PROGRAMME}{}", self.programme.id),
        }
    }

    /// Les arguments, dans l'ordre, avec la lettre du lecteur de Windows donnée par le processus élevé.
    pub(crate) fn arguments(&self, lecteur: &str) -> Vec<String> {
        self.programme
            .arguments
            .iter()
            .map(|a| match a {
                Argument::Fixe(t) => (*t).to_string(),
                Argument::LecteurSysteme => lecteur.to_string(),
                Argument::Nom(prefixe) => format!("{prefixe}{}", self.nom.unwrap_or_default()),
            })
            .collect()
    }

    /// La commande à montrer : le programme et ses arguments, le lecteur sous son nom de variable.
    pub(crate) fn commande(&self) -> String {
        let mut c = self.programme.exe.to_string();
        for a in self.arguments("%SystemDrive%") {
            c.push(' ');
            c.push_str(&a);
        }
        c
    }

    /// L'équivalent PowerShell, pour le chemin par script (Wine) : le programme par son chemin complet, jamais par
    /// son seul nom, et ses autres codes de réussite remis à 0.
    pub(crate) fn powershell(&self) -> String {
        let dossier = match self.programme.dossier {
            Dossier::Systeme32 => r"$env:SystemRoot\System32".to_string(),
            Dossier::Defender => format!(r"$env:SystemDrive\{DOSSIER_DEFENDER}"),
        };
        let mut c = format!(r#"& "{dossier}\{}""#, self.programme.exe);
        for a in self.arguments("$env:SystemDrive") {
            c.push(' ');
            c.push_str(&a);
        }
        let autres: Vec<String> = self
            .programme
            .reussites
            .iter()
            .filter(|r| !FAIT.contains(r))
            .map(i32::to_string)
            .collect();
        if !autres.is_empty() {
            let _ = write!(
                c,
                "; if ($LASTEXITCODE -in {}) {{ $global:LASTEXITCODE = 0 }}",
                autres.join(", ")
            );
        }
        c
    }

    /// Ce code de sortie veut-il dire « fait » ?
    pub(crate) fn reussite(&self, code: i32) -> bool {
        self.programme.reussites.contains(&code)
    }

    /// Le code veut dire « à finir au redémarrage » (chkdsk 3), ni réussite ni échec.
    pub(crate) fn au_redemarrage(&self, code: i32) -> bool {
        self.programme.au_redemarrage.contains(&code)
    }
}

/// La ligne d'un programme de la table, pour un correctif ; `nom` seulement pour un programme qui en prend un.
pub(crate) fn ligne_programme(id: &str, nom: Option<&str>) -> String {
    let ligne = match nom {
        Some(n) => format!("{PROGRAMME}{id} {n}"),
        None => format!("{PROGRAMME}{id}"),
    };
    debug_assert!(analyser_programme(&ligne).is_some(), "programme inconnu : {ligne}");
    ligne
}

/// Le programme d'une ligne, si et seulement si elle est exactement de sa forme : `vanguard:programme <id>`, suivi
/// d'une espace et d'un nom de la liste fermée pour le seul programme qui en prend un. ASCII, 256 octets au plus,
/// sensible à la casse, réécrite à l'identique.
pub(crate) fn analyser_programme(ligne: &str) -> Option<Appel> {
    if ligne.len() > PROGRAMME_MAX || !ligne.is_ascii() {
        return None;
    }
    let reste = ligne.strip_prefix(PROGRAMME)?;
    let (id, nom) = match reste.split_once(' ') {
        Some((id, nom)) => (id, Some(nom)),
        None => (reste, None),
    };
    let programme = PROGRAMMES.iter().find(|p| p.id == id)?;
    let nom = match (nom, programme.noms.is_empty()) {
        (None, true) => None,
        (Some(n), false) => Some(*programme.noms.iter().find(|&&m| m == n)?),
        _ => return None,
    };
    let appel = Appel { programme, nom };
    (appel.ligne() == ligne).then_some(appel)
}

// ------------------------------------------------------------------ les actes

/// Le verbe d'un service de la liste fermée : `vanguard:service <nom> <action>`.
pub(crate) const SERVICE: &str = "vanguard:service ";
/// Le verbe d'un dossier de Windows à vider : `vanguard:vider <id>`.
pub(crate) const VIDER: &str = "vanguard:vider ";
/// La file d'impression à vider, sans argument : le dossier est lu par le processus élevé dans le registre.
pub(crate) const VIDER_FILE: &str = "vanguard:vider-file-impression";
/// Le verbe d'un cache de Windows Update à mettre de côté (renommé, daté) : `vanguard:mettre-de-cote <id>`.
pub(crate) const METTRE_DE_COTE: &str = "vanguard:mettre-de-cote ";
/// Une ligne d'acte est courte : un verbe, un nom de la table, une action.
pub(crate) const ACTE_MAX: usize = 256;

/// Ce qu'un acte fait à un service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Arrêté, avec les services actifs qui en dépendent d'abord (comme `Stop-Service -Force`).
    Arreter,
    Demarrer,
    /// Arrêté (dépendants compris), redémarré, puis les dépendants arrêtés relancés.
    Redemarrer,
    /// Type de démarrage : désactivé.
    Desactive,
    /// Type de démarrage : manuel.
    Manuel,
    /// Type de démarrage : automatique. Le démarrage différé (DelayedAutostart) n'est pas touché.
    Auto,
    /// Désactivé → manuel ; sinon rien. Écart au plan, qui n'avait que « manuel » : la réparation de l'heure ne remet
    /// en manuel QUE un service désactivé (par un outil d'« optimisation ») : un « manuel » sans condition ferait
    /// passer en manuel un w32time réglé en automatique par la personne ou par son entreprise.
    Reactiver,
}

impl Action {
    /// Le mot de la ligne.
    pub(crate) fn mot(self) -> &'static str {
        match self {
            Action::Arreter => "arreter",
            Action::Demarrer => "demarrer",
            Action::Redemarrer => "redemarrer",
            Action::Desactive => "desactive",
            Action::Manuel => "manuel",
            Action::Auto => "auto",
            Action::Reactiver => "reactiver",
        }
    }

    #[cfg(test)]
    const TOUTES: [Action; 7] = [
        Action::Arreter,
        Action::Demarrer,
        Action::Redemarrer,
        Action::Desactive,
        Action::Manuel,
        Action::Auto,
        Action::Reactiver,
    ];
}

/// Une action permise sur un service de la table, et ce qu'elle change à la protection du PC : `durcit` (une
/// correction faite de ces seuls gestes est une protection, que « Défaire » ne propose pas), `affaiblit` (la remise
/// de ce qu'une correction avait coupé : la console élevée dit qu'elle rend le PC moins protégé).
#[derive(Debug)]
pub(crate) struct Permis {
    pub action: Action,
    pub durcit: bool,
    pub affaiblit: bool,
}

/// Un service de la liste fermée, avec ses seules actions permises.
#[derive(Debug)]
pub(crate) struct ServicePermis {
    pub nom: &'static str,
    pub permis: &'static [Permis],
}

const fn permis(action: Action, durcit: bool, affaiblit: bool) -> Permis {
    Permis {
        action,
        durcit,
        affaiblit,
    }
}

/// Les services qu'une liste peut toucher, nom exact (casse comprise), et ce qu'elle peut leur faire. Rien d'autre :
/// pas de nom libre, pas de service de sécurité (Defender, pare-feu), wuauserv jamais désactivé.
pub(crate) static SERVICES: &[ServicePermis] = &[
    // La découverte UPnP, coupée par le bilan ; manuel, auto et démarrer : sa remise (« Défaire », optimiser).
    ServicePermis {
        nom: "SSDPSRV",
        permis: &[
            permis(Action::Arreter, true, false),
            permis(Action::Desactive, true, false),
            permis(Action::Manuel, false, true),
            permis(Action::Auto, false, true),
            permis(Action::Demarrer, false, true),
        ],
    },
    // La collecte de diagnostic (réglage « Télémétrie au minimum » de l'optimiseur), coupée puis remise à
    // l'annulation : de la vie privée, pas une protection ; ni l'un ni l'autre ne durcit ou n'affaiblit le PC.
    ServicePermis {
        nom: "DiagTrack",
        permis: &[
            permis(Action::Arreter, false, false),
            permis(Action::Desactive, false, false),
            permis(Action::Manuel, false, false),
            permis(Action::Auto, false, false),
            permis(Action::Demarrer, false, false),
        ],
    },
    ServicePermis {
        nom: "RemoteRegistry",
        permis: &[
            permis(Action::Arreter, true, false),
            permis(Action::Desactive, true, false),
        ],
    },
    // Windows Update remis (désactivé par un outil d'« optimisation »), arrêté et relancé pour vider son cache.
    ServicePermis {
        nom: "wuauserv",
        permis: &[
            permis(Action::Manuel, true, false),
            permis(Action::Arreter, false, false),
            permis(Action::Demarrer, false, false),
        ],
    },
    ServicePermis {
        nom: "UsoSvc",
        permis: &[permis(Action::Auto, true, false)],
    },
    ServicePermis {
        nom: "bits",
        permis: &[
            permis(Action::Arreter, false, false),
            permis(Action::Demarrer, false, false),
        ],
    },
    ServicePermis {
        nom: "cryptsvc",
        permis: &[
            permis(Action::Arreter, false, false),
            permis(Action::Demarrer, false, false),
        ],
    },
    // L'heure exacte : sans elle, le HTTPS et Windows Update cassent.
    ServicePermis {
        nom: "w32time",
        permis: &[
            permis(Action::Auto, true, false),
            permis(Action::Reactiver, true, false),
            permis(Action::Demarrer, true, false),
        ],
    },
    ServicePermis {
        nom: "AudioEndpointBuilder",
        permis: &[permis(Action::Redemarrer, false, false)],
    },
    ServicePermis {
        nom: "Audiosrv",
        permis: &[permis(Action::Demarrer, false, false)],
    },
    ServicePermis {
        nom: "Spooler",
        permis: &[
            permis(Action::Arreter, false, false),
            permis(Action::Demarrer, false, false),
        ],
    },
];

/// Une ligne `vanguard:service`, relue : un service de la table et une de ses actions permises.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GesteService {
    pub nom: &'static str,
    pub action: Action,
    pub durcit: bool,
    pub affaiblit: bool,
}

impl GesteService {
    pub(crate) fn ligne(&self) -> String {
        format!("{SERVICE}{} {}", self.nom, self.action.mot())
    }

    /// L'équivalent PowerShell (Wine) : les commandes qu'envoyaient les correctifs avant ce geste.
    pub(crate) fn powershell(&self) -> String {
        let n = self.nom;
        match self.action {
            Action::Arreter => format!("Stop-Service {n} -Force"),
            Action::Demarrer => format!("Start-Service {n}"),
            Action::Redemarrer => format!("Restart-Service -Force {n}"),
            Action::Desactive => format!("Set-Service {n} -StartupType Disabled"),
            Action::Manuel => format!("Set-Service {n} -StartupType Manual"),
            Action::Auto => format!("Set-Service {n} -StartupType Automatic"),
            Action::Reactiver => {
                format!("if ((Get-Service {n}).StartType -eq 'Disabled') {{ Set-Service {n} -StartupType Manual }}")
            }
        }
    }
}

/// Un dossier de Windows à vider (son contenu, pas lui) : un identifiant, le chemin sous le dossier de Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vidable {
    /// `<Windows>\Temp`.
    TempWindows,
    /// `<Windows>\SoftwareDistribution\Download`.
    WuTelechargements,
}

impl Vidable {
    const TOUS: [Vidable; 2] = [Vidable::TempWindows, Vidable::WuTelechargements];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Vidable::TempWindows => "temp-windows",
            Vidable::WuTelechargements => "wu-telechargements",
        }
    }

    /// Les dossiers sous celui de Windows, un par un.
    pub(crate) fn sous_windows(self) -> &'static [&'static str] {
        match self {
            Vidable::TempWindows => &["Temp"],
            Vidable::WuTelechargements => &["SoftwareDistribution", "Download"],
        }
    }
}

/// Un cache de Windows Update à mettre de côté : renommé `<nom>.<AAAAMMJJHHmm>`, Windows en refait un neuf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ACoter {
    /// `<Windows>\SoftwareDistribution`.
    SoftwareDistribution,
    /// `<Windows>\System32\catroot2`.
    Catroot2,
}

impl ACoter {
    const TOUS: [ACoter; 2] = [ACoter::SoftwareDistribution, ACoter::Catroot2];

    pub(crate) fn id(self) -> &'static str {
        match self {
            ACoter::SoftwareDistribution => "software-distribution",
            ACoter::Catroot2 => "catroot2",
        }
    }

    /// Les dossiers sous celui de Windows, un par un ; le dernier est celui qui est renommé.
    pub(crate) fn sous_windows(self) -> &'static [&'static str] {
        match self {
            ACoter::SoftwareDistribution => &["SoftwareDistribution"],
            ACoter::Catroot2 => &["System32", "catroot2"],
        }
    }
}

/// Le Pare-feu Windows remis en marche sur ses trois profils (domaine, privé, public), sans argument : il n'a pas
/// d'inverse, un pare-feu ne se coupe jamais par une ligne.
pub(crate) const PARE_FEU_ACTIF: &str = "vanguard:pare-feu-actif";
/// Des réglages du profil Public du pare-feu : `vanguard:pare-feu-public <cle=valeur>[,<cle=valeur>…]`.
pub(crate) const PARE_FEU_PUBLIC: &str = "vanguard:pare-feu-public ";
/// La catégorie d'un réseau connu : `vanguard:reseau-categorie {GUID} <public|prive>`.
pub(crate) const RESEAU_CATEGORIE: &str = "vanguard:reseau-categorie ";

/// Un réglage du profil Public du pare-feu, tel que l'écrivait `Set-NetFirewallProfile -Profile Public
/// -PolicyStore PersistentStore` : allumé (Enabled), entrées bloquées par défaut (DefaultInboundAction), règles
/// d'entrée des programmes autorisés suivies (AllowInboundRules ; « non » : toutes les entrées bloquées, même
/// celles-là).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReglagePublic {
    Actif,
    EntrantBloque,
    ReglesEntrantes,
}

impl ReglagePublic {
    /// Dans l'ordre de la ligne : une ligne dans un autre ordre n'est pas réécrite à l'identique, donc refusée.
    pub(crate) const TOUS: [ReglagePublic; 3] = [
        ReglagePublic::Actif,
        ReglagePublic::EntrantBloque,
        ReglagePublic::ReglesEntrantes,
    ];

    pub(crate) fn cle(self) -> &'static str {
        match self {
            ReglagePublic::Actif => "actif",
            ReglagePublic::EntrantBloque => "entrant-bloque",
            ReglagePublic::ReglesEntrantes => "regles-entrantes",
        }
    }

    /// La valeur qui durcit le profil : la seule qu'écrit le mode Wi-Fi public en l'appliquant.
    pub(crate) fn durcie(self) -> ValeurPublic {
        match self {
            ReglagePublic::Actif | ReglagePublic::EntrantBloque => ValeurPublic::Oui,
            ReglagePublic::ReglesEntrantes => ValeurPublic::Non,
        }
    }

    /// Les valeurs qu'une ligne peut porter. « actif=non » n'existe pas : un pare-feu trouvé coupé n'est jamais
    /// recoupé (`Element::jamais_remis`), aucune ligne ne peut donc le couper. « absent » (la valeur retirée du
    /// magasin, « NotConfigured ») ne sert qu'à remettre « regles-entrantes » tel qu'il était : c'est le seul réglage
    /// que le mode change quand il est « non configuré ».
    fn permise(self, v: ValeurPublic) -> bool {
        match self {
            ReglagePublic::Actif => v == ValeurPublic::Oui,
            ReglagePublic::EntrantBloque => v != ValeurPublic::Absent,
            ReglagePublic::ReglesEntrantes => true,
        }
    }
}

/// La valeur d'un réglage du profil Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValeurPublic {
    Oui,
    Non,
    /// Retirée du magasin local : « non configuré », ce que Windows lit comme sa valeur par défaut.
    Absent,
}

impl ValeurPublic {
    const TOUTES: [ValeurPublic; 3] = [ValeurPublic::Oui, ValeurPublic::Non, ValeurPublic::Absent];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ValeurPublic::Oui => "oui",
            ValeurPublic::Non => "non",
            ValeurPublic::Absent => "absent",
        }
    }
}

/// Une ligne `vanguard:pare-feu-public`, relue : chaque réglage une fois au plus, au moins un.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProfilPublic {
    /// Par réglage, dans l'ordre de `ReglagePublic::TOUS`.
    valeurs: [Option<ValeurPublic>; 3],
}

impl ProfilPublic {
    /// Les réglages demandés, dans l'ordre de la ligne ; `None` si aucun, si l'un revient ou n'a pas une valeur
    /// permise.
    pub(crate) fn nouveau(reglages: &[(ReglagePublic, ValeurPublic)]) -> Option<ProfilPublic> {
        let mut valeurs = [None; 3];
        for &(r, v) in reglages {
            let i = ReglagePublic::TOUS.iter().position(|t| *t == r)?;
            let place = valeurs.get_mut(i)?;
            if place.is_some() || !r.permise(v) {
                return None;
            }
            *place = Some(v);
        }
        valeurs.iter().any(Option::is_some).then_some(ProfilPublic { valeurs })
    }

    pub(crate) fn reglages(self) -> impl Iterator<Item = (ReglagePublic, ValeurPublic)> {
        ReglagePublic::TOUS
            .into_iter()
            .zip(self.valeurs)
            .filter_map(|(r, v)| v.map(|v| (r, v)))
    }

    /// Chaque réglage à sa valeur durcie : la ligne protège, « Défaire » ne la propose pas.
    pub(crate) fn durcit(self) -> bool {
        self.reglages().all(|(r, v)| v == r.durcie())
    }

    /// Un réglage au moins hors de sa valeur durcie : une remise, que la console élevée dit moins protégée.
    pub(crate) fn affaiblit(self) -> bool {
        !self.durcit()
    }

    fn ligne(self) -> String {
        let reglages: Vec<String> = self
            .reglages()
            .map(|(r, v)| format!("{}={}", r.cle(), v.mot()))
            .collect();
        format!("{PARE_FEU_PUBLIC}{}", reglages.join(","))
    }

    fn analyser(reste: &str) -> Option<ProfilPublic> {
        let reglages: Option<Vec<(ReglagePublic, ValeurPublic)>> = reste
            .split(',')
            .map(|morceau| {
                let (cle, mot) = morceau.split_once('=')?;
                Some((
                    *ReglagePublic::TOUS.iter().find(|r| r.cle() == cle)?,
                    *ValeurPublic::TOUTES.iter().find(|v| v.mot() == mot)?,
                ))
            })
            .collect();
        ProfilPublic::nouveau(&reglages?)
    }

    /// L'équivalent PowerShell (Wine) : la commande qu'envoyait le mode Wi-Fi public avant ce geste.
    fn powershell(self) -> String {
        let mut c = String::from("Set-NetFirewallProfile -Profile Public -PolicyStore PersistentStore");
        for (r, v) in self.reglages() {
            let (nom, valeur) = match (r, v) {
                (ReglagePublic::Actif, ValeurPublic::Oui) => ("Enabled", "True"),
                (ReglagePublic::Actif, _) => ("Enabled", "False"),
                (ReglagePublic::EntrantBloque, ValeurPublic::Oui) => ("DefaultInboundAction", "Block"),
                (ReglagePublic::EntrantBloque, ValeurPublic::Non) => ("DefaultInboundAction", "Allow"),
                (ReglagePublic::EntrantBloque, ValeurPublic::Absent) => ("DefaultInboundAction", "NotConfigured"),
                (ReglagePublic::ReglesEntrantes, ValeurPublic::Oui) => ("AllowInboundRules", "True"),
                (ReglagePublic::ReglesEntrantes, ValeurPublic::Non) => ("AllowInboundRules", "False"),
                (ReglagePublic::ReglesEntrantes, ValeurPublic::Absent) => ("AllowInboundRules", "NotConfigured"),
            };
            let _ = write!(c, " -{nom} {valeur}");
        }
        c
    }
}

/// La catégorie qu'une ligne donne à un réseau. « Domaine » n'en est pas une : un réseau d'entreprise est géré par
/// elle, jamais touché.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Categorie {
    Public,
    Prive,
}

impl Categorie {
    pub(crate) fn mot(self) -> &'static str {
        match self {
            Categorie::Public => "public",
            Categorie::Prive => "prive",
        }
    }

    /// La valeur Category du registre (NetworkList\Profiles) et de NLM_NETWORK_CATEGORY.
    pub(crate) fn valeur(self) -> u32 {
        match self {
            Categorie::Public => 0,
            Categorie::Prive => 1,
        }
    }
}

/// Le GUID d'un profil réseau, `{8-4-4-4-12}` en hexadécimal ; écrit en majuscules, comme le registre et PowerShell
/// le donnent : une ligne en minuscules n'est pas réécrite à l'identique, donc refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuidReseau(pub u128);

impl GuidReseau {
    /// Lu d'un texte (casse libre : celle de PowerShell n'est pas garantie) ; `None` s'il n'a pas la forme exacte.
    pub(crate) fn lire(texte: &str) -> Option<GuidReseau> {
        let corps = texte.strip_prefix('{')?.strip_suffix('}')?;
        let groupes: Vec<&str> = corps.split('-').collect();
        if groupes.iter().map(|g| g.len()).ne([8, 4, 4, 4, 12]) {
            return None;
        }
        let mut n: u128 = 0;
        for o in groupes.concat().bytes() {
            n = n << 4 | u128::from(chiffre_hex(o)?);
        }
        Some(GuidReseau(n))
    }

    pub(crate) fn texte(self) -> String {
        let n = self.0;
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
            n >> 96,
            (n >> 80) & 0xFFFF,
            (n >> 64) & 0xFFFF,
            (n >> 48) & 0xFFFF,
            n & 0xFFFF_FFFF_FFFF
        )
    }
}

fn chiffre_hex(o: u8) -> Option<u8> {
    char::from(o).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Une ligne `vanguard:reseau-categorie`, relue. Le GUID désigne, le processus élevé juge : il relit que le profil
/// existe dans NetworkList\Profiles et qu'il n'est pas celui d'un domaine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReseauCategorie {
    pub guid: GuidReseau,
    pub categorie: Categorie,
}

impl ReseauCategorie {
    fn ligne(&self) -> String {
        format!("{RESEAU_CATEGORIE}{} {}", self.guid.texte(), self.categorie.mot())
    }

    /// Le chemin du profil sous HKLM.
    pub(crate) fn cle(&self) -> String {
        format!(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{}",
            self.guid.texte()
        )
    }

    /// L'équivalent PowerShell (Wine) : celui qu'envoyait le mode Wi-Fi public, par le profil connecté s'il l'est,
    /// sinon dans le registre, pour la prochaine connexion à ce réseau.
    fn powershell(&self) -> String {
        let g = self.guid.texte();
        let (nom, valeur) = match self.categorie {
            Categorie::Public => ("Public", 0),
            Categorie::Prive => ("Private", 1),
        };
        format!(
            "$p = Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object {{ $_.InstanceID -eq '{g}' }}; \
             if ($p) {{ $p | Set-NetConnectionProfile -NetworkCategory {nom} }} \
             else {{ Set-ItemProperty -LiteralPath 'HKLM:\\{}' -Name Category -Value {valeur} -Type DWord }}",
            self.cle()
        )
    }
}

// ------------------------------------------------------------ le registre

/// Les deux racines d'Image File Execution Options lues par le bilan : la vue 64 bits et celle des programmes 32 bits
/// (partagée avec la première depuis Windows 7, lue quand même : un ancien Windows ou une copie à la main).
pub(crate) const IFEO: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
];

/// Les deux racines de SilentProcessExit (un programme lancé à la fermeture d'un autre), 64 et 32 bits.
pub(crate) const SORTIE_SILENCIEUSE: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
];

/// Le verbe du débogueur à retirer d'un programme (IFEO, vue 64 bits) : `vanguard:ifeo-debugger <nom en hex>`.
pub(crate) const IFEO_DEBUGGER: &str = "vanguard:ifeo-debugger ";
/// Le même, sous la racine des programmes 32 bits (WOW6432Node).
pub(crate) const IFEO_DEBUGGER_32: &str = "vanguard:ifeo-debugger-32 ";
/// Le verbe du programme à ne plus lancer à la fermeture d'un autre (SilentProcessExit, MonitorProcess).
pub(crate) const IFEO_SILENCIEUX: &str = "vanguard:ifeo-silencieux ";
/// Le même, sous la racine des programmes 32 bits.
pub(crate) const IFEO_SILENCIEUX_32: &str = "vanguard:ifeo-silencieux-32 ";
/// Le verbe d'un service dont le chemin (ImagePath) est à mettre entre guillemets : `vanguard:service-guillemets
/// <nom en hex>`. Le nouveau chemin n'est jamais envoyé : le processus élevé le calcule depuis celui qu'il relit.
pub(crate) const SERVICE_GUILLEMETS: &str = "vanguard:service-guillemets ";

/// La plus longue ligne qui porte un nom : 260 unités UTF-16 de quatre chiffres hexadécimaux après le plus long verbe
/// (`DEFENDER_EXCLUSION_RETIRER` suivi de « extension » ; test borne_des_noms).
pub(crate) const ACTE_NOM_MAX: usize = 1086;
/// Le plus long nom admis, en unités UTF-16 : MAX_PATH. Un nom de clé du registre en admet 255, un service 256.
pub(crate) const NOM_MAX: usize = 260;

/// La racine visée par une ligne d'Image File Execution Options ou de SilentProcessExit : celle où le bilan a lu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vue {
    /// HKLM\SOFTWARE\Microsoft\… (vue 64 bits).
    Windows,
    /// HKLM\SOFTWARE\WOW6432Node\Microsoft\… (programmes 32 bits).
    Wow32,
}

impl Vue {
    pub(crate) const TOUTES: [Vue; 2] = [Vue::Windows, Vue::Wow32];

    /// La racine d'Image File Execution Options de cette vue, sous HKLM.
    pub(crate) fn ifeo(self) -> &'static str {
        match self {
            Vue::Windows => IFEO[0],
            Vue::Wow32 => IFEO[1],
        }
    }

    /// La racine de SilentProcessExit de cette vue, sous HKLM.
    pub(crate) fn silencieuse(self) -> &'static str {
        match self {
            Vue::Windows => SORTIE_SILENCIEUSE[0],
            Vue::Wow32 => SORTIE_SILENCIEUSE[1],
        }
    }
}

/// Un nom de programme (sous-clé d'Image File Execution Options ou de SilentProcessExit) ou de service, relu : non
/// vide, 260 unités UTF-16 au plus, sans caractère de contrôle (NUL compris), sans séparateur ni caractère interdit
/// dans un nom de fichier (`\ / : * ? " < > |`), ni « . » seul ni « .. ». Il désigne une sous-clé d'une racine fixe :
/// jamais une autre clé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NomFichier(String);

impl NomFichier {
    /// Le nom, s'il a sa forme.
    pub(crate) fn nouveau(nom: &str) -> Option<NomFichier> {
        let longueur = nom.encode_utf16().count();
        let interdit = |c: char| c.is_control() || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|');
        let bon =
            longueur > 0 && longueur <= NOM_MAX && !nom.chars().any(interdit) && nom != "." && !nom.contains("..");
        bon.then(|| NomFichier(nom.to_string()))
    }

    /// Le nom tel quel (venu du registre : à rendre affichable avant de le montrer).
    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    /// Le nom en hexadécimal minuscule, quatre chiffres par unité UTF-16 petit-boutiste (« s » : « 7300 ») : la ligne
    /// reste ASCII, sans espace, quel que soit le nom.
    pub(crate) fn hex(&self) -> String {
        self.0
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .fold(String::new(), |mut s, o| {
                let _ = write!(s, "{o:02x}");
                s
            })
    }

    /// Le nom d'un hexadécimal de `hex`, si et seulement s'il en a la forme exacte : minuscules, par groupes de quatre,
    /// UTF-16 valide (pas de demi-paire), et un nom admis par `nouveau`.
    pub(crate) fn lire(hex: &str) -> Option<NomFichier> {
        if hex.is_empty() || !hex.len().is_multiple_of(4) || hex.len() > NOM_MAX.checked_mul(4)? {
            return None;
        }
        let unites: Option<Vec<u16>> = hex
            .as_bytes()
            .chunks(4)
            .map(|q| {
                let mut o = [0u8; 2];
                for (i, paire) in q.chunks(2).enumerate() {
                    let fort = chiffre_minuscule(*paire.first()?)?;
                    let faible = chiffre_minuscule(*paire.get(1)?)?;
                    *o.get_mut(i)? = fort.checked_mul(16)?.checked_add(faible)?;
                }
                Some(u16::from_le_bytes(o))
            })
            .collect();
        let nom = String::from_utf16(&unites?).ok()?;
        NomFichier::nouveau(&nom).filter(|n| n.hex() == hex)
    }
}

/// Le texte à placer entre apostrophes dans PowerShell : chaque apostrophe, droite ou typographique, doublée. La copie
/// de `commande::ps_texte` (ce module ne dépend de rien ; test ps_texte_identique côté crate).
pub(crate) fn ps_texte(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    for c in t.chars() {
        s.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            s.push(c);
        }
    }
    s
}

/// La ligne qui retire le débogueur d'un programme ; `None` si le nom n'a pas sa forme (signalé, à retirer à la main).
pub(crate) fn ligne_ifeo_debugger(vue: Vue, nom: &str) -> Option<String> {
    NomFichier::nouveau(nom).map(|n| Acte::IfeoDebugger(vue, n).ligne())
}

/// La ligne qui ne lance plus rien à la fermeture d'un programme ; `None` si le nom n'a pas sa forme.
pub(crate) fn ligne_ifeo_silencieux(vue: Vue, nom: &str) -> Option<String> {
    NomFichier::nouveau(nom).map(|n| Acte::IfeoSilencieux(vue, n).ligne())
}

/// La ligne qui met entre guillemets le chemin d'un service ; `None` si le nom n'a pas sa forme.
pub(crate) fn ligne_service_guillemets(nom: &str) -> Option<String> {
    NomFichier::nouveau(nom).map(|n| Acte::ServiceGuillemets(n).ligne())
}

/// La ligne PowerShell (Wine) pour un service : relit ImagePath brut (ses %variables% non développées) et son type,
/// le remet entre guillemets par la même forme que le constat (« …\x.exe » puis ses arguments), avec le même type,
/// et s'arrête sans rien écrire si la valeur développée changerait autrement que par les guillemets. Écart connu avec
/// le processus élevé : le dossier modifiable n'est pas rejugé, et les variables sont celles de la fenêtre.
fn powershell_guillemets(nom: &NomFichier) -> String {
    format!(
        r#"$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\{}'; $r = Get-Item -LiteralPath $k -ErrorAction Stop; $t = $r.GetValueKind('ImagePath'); $c = [string]$r.GetValue('ImagePath', $null, 'DoNotExpandEnvironmentNames'); if (($t -ne 'String' -and $t -ne 'ExpandString') -or $c.StartsWith('"') -or $c -notmatch '^(.+?\.exe)(\s.*)?$') {{ throw 'ImagePath already quoted or not understood' }}; $n = '"' + $Matches[1] + '"' + $Matches[2]; if ([Environment]::ExpandEnvironmentVariables($c) -notmatch '^(.+?\.exe)(\s.*)?$' -or [Environment]::ExpandEnvironmentVariables($n) -cne ('"' + $Matches[1] + '"' + $Matches[2])) {{ throw 'ImagePath would change beyond the quotes' }}; Set-ItemProperty -LiteralPath $k -Name ImagePath -Value $n -Type $t"#,
        ps_texte(nom.texte())
    )
}

// ------------------------------------------------------------ Defender

/// Le verbe d'un réglage de Defender : `vanguard:defender <reglage> <valeur>`, chaque réglage n'admettant que des
/// valeurs qui protègent (`ReglageDefender::permises`).
pub(crate) const DEFENDER: &str = "vanguard:defender ";
/// Le verbe d'une règle ASR : `vanguard:defender-asr <GUID d'Optimiser> <bloquer|audit>` (jamais retirer : voir
/// `ModeAsr`).
pub(crate) const DEFENDER_ASR: &str = "vanguard:defender-asr ";
/// Le verbe d'une exclusion à retirer : `vanguard:defender-exclusion-retirer <chemin|processus|extension> <hex>`.
pub(crate) const DEFENDER_EXCLUSION_RETIRER: &str = "vanguard:defender-exclusion-retirer ";
/// Les menaces trouvées par Defender, retirées (MSFT_MpThreat.Remove), sans argument.
pub(crate) const DEFENDER_MENACES_RETIRER: &str = "vanguard:defender-menaces-retirer";

/// Règles ASR que Microsoft dit sans revers (« standard protection rules »), en minuscules comme Microsoft les
/// écrit. Ici plutôt que dans Optimiser : une ligne `defender-asr` ne désigne qu'une règle de ces listes, et ce module
/// ne dépend de rien.
pub(crate) const ASR_BASE: [&str; 3] = [
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",
];

/// Règles ASR contre les documents et pièces jointes piégés : Office, Outlook, Adobe Reader, courriel, scripts.
pub(crate) const ASR_BUREAUTIQUE: [&str; 8] = [
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
];

/// La règle ASR de ces listes qui porte exactement cet identifiant (minuscules) : une autre n'est jamais touchée,
/// pas même retirée.
pub(crate) fn asr_connue(id: &str) -> Option<&'static str> {
    ASR_BASE.iter().chain(&ASR_BUREAUTIQUE).copied().find(|r| *r == id)
}

/// Un réglage de Defender qu'une ligne peut renforcer, propriété de MSFT_MpPreference comprise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReglageDefender {
    /// La protection en temps réel (DisableRealtimeMonitoring).
    TempsReel,
    /// La protection dans le cloud (MAPSReporting).
    Maps,
    /// L'accès contrôlé aux dossiers (EnableControlledFolderAccess).
    Cfa,
    /// La protection réseau (EnableNetworkProtection).
    Np,
    /// Les applications potentiellement indésirables (PUAProtection).
    Pua,
}

impl ReglageDefender {
    pub(crate) const TOUS: [ReglageDefender; 5] = [
        ReglageDefender::TempsReel,
        ReglageDefender::Maps,
        ReglageDefender::Cfa,
        ReglageDefender::Np,
        ReglageDefender::Pua,
    ];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ReglageDefender::TempsReel => "temps-reel",
            ReglageDefender::Maps => "maps",
            ReglageDefender::Cfa => "cfa",
            ReglageDefender::Np => "np",
            ReglageDefender::Pua => "pua",
        }
    }

    /// La propriété de MSFT_MpPreference, lue avant et après, et le paramètre de sa méthode Set.
    pub(crate) fn propriete(self) -> &'static str {
        match self {
            ReglageDefender::TempsReel => "DisableRealtimeMonitoring",
            ReglageDefender::Maps => "MAPSReporting",
            ReglageDefender::Cfa => "EnableControlledFolderAccess",
            ReglageDefender::Np => "EnableNetworkProtection",
            ReglageDefender::Pua => "PUAProtection",
        }
    }

    /// Les valeurs qu'une ligne peut porter : seulement celles qui protègent. Aucune ne coupe un réglage, si bien
    /// qu'une ligne forgée ne peut rien affaiblir (« temps-reel non », « maps 0 », « cfa coupe »… sont refusées).
    pub(crate) fn permises(self) -> &'static [ValeurDefender] {
        match self {
            ReglageDefender::TempsReel => &[ValeurDefender::Actif],
            ReglageDefender::Maps => &[ValeurDefender::Avance],
            ReglageDefender::Cfa | ReglageDefender::Np | ReglageDefender::Pua => {
                &[ValeurDefender::Bloquer, ValeurDefender::Audit]
            }
        }
    }

    /// La valeur que la propriété doit relire une fois `v` écrite. Décidée par le réglage d'abord : même un acte
    /// construit hors de `permises` ne vise qu'une valeur qui protège (temps réel jamais désactivé, cloud avancé).
    pub(crate) fn attendue(self, v: ValeurDefender) -> u8 {
        match (self, v) {
            // DisableRealtimeMonitoring : faux.
            (ReglageDefender::TempsReel, _) => 0,
            // MAPSReporting : 2, « Advanced ».
            (ReglageDefender::Maps, _) | (_, ValeurDefender::Audit) => 2,
            (_, _) => 1,
        }
    }

    /// Le rang de protection d'une valeur lue de la propriété : plus haut, plus sûr. Une valeur inconnue vaut 0, la
    /// moins sûre : jamais crue plus forte qu'elle n'est. Accès contrôlé : 0 coupé, 2 et 4 audit, 3 disques seuls,
    /// 1 bloque ; protection réseau et PUA : 0 coupée, 2 audit, 1 bloque ; cloud : 0, 1 de base, 2 avancé.
    pub(crate) fn rang(self, lue: i64) -> u8 {
        match self {
            ReglageDefender::TempsReel => u8::from(lue == 0),
            ReglageDefender::Maps => match lue {
                1 => 1,
                2 => 2,
                _ => 0,
            },
            ReglageDefender::Cfa => match lue {
                2 | 4 => 1,
                3 => 2,
                1 => 3,
                _ => 0,
            },
            ReglageDefender::Np | ReglageDefender::Pua => match lue {
                2 => 1,
                1 => 2,
                _ => 0,
            },
        }
    }

    /// Faut-il écrire ? Seulement si la valeur lue protège moins que celle demandée : une ligne ne baisse jamais un
    /// réglage (« audit » sur un accès contrôlé qui bloque ne fait rien).
    pub(crate) fn a_ecrire(self, v: ValeurDefender, lue: i64) -> bool {
        self.rang(lue) < self.rang(i64::from(self.attendue(v)))
    }

    /// Le paramètre de MSFT_MpPreference.Set pour `v` : un booléen pour le temps réel, un octet (uint8) sinon.
    pub(crate) fn valeur_wmi(self, v: ValeurDefender) -> ValeurWmi {
        let n = self.attendue(v);
        match self {
            ReglageDefender::TempsReel => ValeurWmi::Booleen(n != 0),
            _ => ValeurWmi::Octet(n),
        }
    }
}

/// La valeur d'une ligne `defender`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValeurDefender {
    /// La protection en temps réel en marche.
    Actif,
    /// La protection dans le cloud complète (« Advanced »).
    Avance,
    Bloquer,
    /// Signale sans bloquer : jamais écrit sur un réglage qui bloque déjà (`ReglageDefender::a_ecrire`).
    Audit,
}

impl ValeurDefender {
    pub(crate) fn mot(self) -> &'static str {
        match self {
            ValeurDefender::Actif => "actif",
            ValeurDefender::Avance => "avance",
            ValeurDefender::Bloquer => "bloquer",
            ValeurDefender::Audit => "audit",
        }
    }
}

/// Ce qu'une ligne `defender-asr` fait d'une règle. Jamais la retirer : Optimiser ne défait pas ses règles ASR
/// (réglages protégés, écartés de l'annulation), aucune ligne légitime ne le demande, et l'enfant élevé ne saurait
/// pas prouver qu'une règle présente vient d'Optimiser plutôt que de la personne ou d'une stratégie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModeAsr {
    Bloquer,
    Audit,
}

impl ModeAsr {
    pub(crate) const TOUS: [ModeAsr; 2] = [ModeAsr::Bloquer, ModeAsr::Audit];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ModeAsr::Bloquer => "bloquer",
            ModeAsr::Audit => "audit",
        }
    }

    /// L'action de la règle (AttackSurfaceReductionRules_Actions) : 1 bloque, 2 audit.
    pub(crate) fn action(self) -> u8 {
        match self {
            ModeAsr::Bloquer => 1,
            ModeAsr::Audit => 2,
        }
    }

    /// Faut-il écrire, d'après l'action lue de la règle (`None` : absente de la liste) ? Bloquer ou auditer
    /// seulement ce qui protège moins (absente ou 0 coupée, 2 audit, 6 avertit, 1 bloque ; inconnue : 0).
    pub(crate) fn a_ecrire(self, lue: Option<i64>) -> bool {
        let rang = |a: Option<i64>| -> u8 {
            match a {
                Some(2) => 1,
                Some(6) => 2,
                Some(1) => 3,
                _ => 0,
            }
        };
        rang(lue) < rang(Some(i64::from(self.action())))
    }
}

/// La liste d'exclusions de Defender visée par une ligne `defender-exclusion-retirer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenreExclusion {
    Chemin,
    Processus,
    Extension,
}

impl GenreExclusion {
    pub(crate) const TOUS: [GenreExclusion; 3] = [
        GenreExclusion::Chemin,
        GenreExclusion::Processus,
        GenreExclusion::Extension,
    ];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            GenreExclusion::Chemin => "chemin",
            GenreExclusion::Processus => "processus",
            GenreExclusion::Extension => "extension",
        }
    }

    /// La propriété de MSFT_MpPreference, et le paramètre de sa méthode Remove.
    pub(crate) fn propriete(self) -> &'static str {
        match self {
            GenreExclusion::Chemin => "ExclusionPath",
            GenreExclusion::Processus => "ExclusionProcess",
            GenreExclusion::Extension => "ExclusionExtension",
        }
    }
}

/// Une exclusion de Defender relue : non vide, 260 unités UTF-16 au plus, de l'UTF-16 valide, sans caractère de
/// contrôle (NUL compris). Elle ne fait que désigner : le processus élevé ne la retire que si elle est, telle quelle,
/// dans la liste qu'il relit, et que le bilan la signale (`exclusions::signalee`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Exclusion(String);

impl Exclusion {
    pub(crate) fn nouvelle(texte: &str) -> Option<Exclusion> {
        let longueur = texte.encode_utf16().count();
        (longueur > 0 && longueur <= NOM_MAX && !texte.chars().any(char::is_control))
            .then(|| Exclusion(texte.to_string()))
    }

    /// Le texte tel quel (venu de Defender : à rendre affichable avant de le montrer).
    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    /// En hexadécimal minuscule, quatre chiffres par unité UTF-16 (la convention de `NomFichier`).
    pub(crate) fn hex(&self) -> String {
        let unites: Vec<u16> = self.0.encode_utf16().collect();
        hex_utf16(&unites)
    }

    /// L'exclusion d'un hexadécimal de `hex`, si et seulement s'il en a la forme exacte.
    pub(crate) fn lire(hex: &str) -> Option<Exclusion> {
        let unites = lire_hex_utf16(hex, NOM_MAX)?;
        let texte = String::from_utf16(&unites).ok()?;
        Exclusion::nouvelle(&texte).filter(|e| e.hex() == hex)
    }
}

/// Une valeur d'entrée d'une méthode WMI de Defender, décrite sans COM : le processus élevé la met dans un VARIANT
/// (`wmi::Parametre`). Les tableaux sont ceux des paramètres `string[]` et `uint8[]` de MSFT_MpPreference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValeurWmi {
    Booleen(bool),
    Octet(u8),
    Textes(Vec<String>),
    Octets(Vec<u8>),
}

/// La méthode statique de MSFT_MpPreference et ses paramètres pour un acte de Defender : Set pour un réglage, Add
/// pour une règle ASR (Set remplacerait toute la liste), Remove pour retirer une exclusion. `None` pour les autres
/// actes, et pour les menaces (MSFT_MpThreat.Remove, sans paramètre).
pub(crate) fn methode_defender(acte: &Acte) -> Option<(&'static str, Vec<(&'static str, ValeurWmi)>)> {
    const IDS: &str = "AttackSurfaceReductionRules_Ids";
    match acte {
        Acte::Defender(r, v) => Some(("Set", vec![(r.propriete(), r.valeur_wmi(*v))])),
        Acte::DefenderAsr(id, m) => {
            let ids = (IDS, ValeurWmi::Textes(vec![(*id).to_string()]));
            let actions = (
                "AttackSurfaceReductionRules_Actions",
                ValeurWmi::Octets(vec![m.action()]),
            );
            Some(("Add", vec![ids, actions]))
        }
        Acte::DefenderExclusionRetirer(g, e) => Some((
            "Remove",
            vec![(g.propriete(), ValeurWmi::Textes(vec![e.texte().to_string()]))],
        )),
        _ => None,
    }
}

/// La ligne qui renforce un réglage de Defender ; `None` si la valeur n'est pas permise pour ce réglage.
pub(crate) fn ligne_defender(r: ReglageDefender, v: ValeurDefender) -> Option<String> {
    r.permises().contains(&v).then(|| Acte::Defender(r, v).ligne())
}

/// La ligne qui règle une règle ASR ; `None` si l'identifiant n'est pas dans les listes d'Optimiser.
pub(crate) fn ligne_defender_asr(id: &str, m: ModeAsr) -> Option<String> {
    asr_connue(id).map(|id| Acte::DefenderAsr(id, m).ligne())
}

/// La ligne qui retire une exclusion ; `None` si elle n'a pas sa forme (signalée, à retirer dans Sécurité Windows).
pub(crate) fn ligne_defender_exclusion_retirer(g: GenreExclusion, texte: &str) -> Option<String> {
    Exclusion::nouvelle(texte).map(|e| Acte::DefenderExclusionRetirer(g, e).ligne())
}

/// La ligne qui retire les menaces trouvées par Defender.
pub(crate) fn ligne_defender_menaces_retirer() -> String {
    DEFENDER_MENACES_RETIRER.to_string()
}

/// Un acte du processus élevé sur Windows lui-même : un service de la table, un dossier à vider, la file
/// d'impression, un cache à mettre de côté, le pare-feu et la catégorie d'un réseau. Le parent n'envoie que des
/// identifiants et des valeurs de listes fermées ; les chemins sont calculés par le processus élevé, depuis le
/// dossier de Windows qu'il lit lui-même. Les actes du registre portent un nom (programme, service) qui désigne une
/// sous-clé d'une racine fixe ; le processus élevé relit la clé et la rejuge par la fonction du bilan avant d'écrire.
#[derive(Debug, Clone)]
pub(crate) enum Acte {
    Service(GesteService),
    Vider(Vidable),
    ViderFileImpression,
    MettreDeCote(ACoter),
    PareFeuActif,
    PareFeuPublic(ProfilPublic),
    ReseauCategorie(ReseauCategorie),
    /// Retirer la valeur Debugger d'Image File Execution Options\\`nom`.
    IfeoDebugger(Vue, NomFichier),
    /// Retirer la valeur MonitorProcess de SilentProcessExit\\`nom`.
    IfeoSilencieux(Vue, NomFichier),
    /// Mettre entre guillemets le chemin (ImagePath) du service `nom`.
    ServiceGuillemets(NomFichier),
    /// Renforcer un réglage de Defender, jamais le baisser (relu avant et après par le processus élevé).
    Defender(ReglageDefender, ValeurDefender),
    /// Une règle ASR des listes d'Optimiser.
    DefenderAsr(&'static str, ModeAsr),
    /// Retirer une exclusion de Defender, rejugée contre le constat relu.
    DefenderExclusionRetirer(GenreExclusion, Exclusion),
    /// Retirer les menaces trouvées par Defender.
    DefenderMenacesRetirer,
}

impl Acte {
    pub(crate) fn ligne(&self) -> String {
        match self {
            Acte::Service(s) => s.ligne(),
            Acte::Vider(v) => format!("{VIDER}{}", v.id()),
            Acte::ViderFileImpression => VIDER_FILE.to_string(),
            Acte::MettreDeCote(c) => format!("{METTRE_DE_COTE}{}", c.id()),
            Acte::PareFeuActif => PARE_FEU_ACTIF.to_string(),
            Acte::PareFeuPublic(p) => p.ligne(),
            Acte::ReseauCategorie(r) => r.ligne(),
            Acte::IfeoDebugger(Vue::Windows, n) => format!("{IFEO_DEBUGGER}{}", n.hex()),
            Acte::IfeoDebugger(Vue::Wow32, n) => format!("{IFEO_DEBUGGER_32}{}", n.hex()),
            Acte::IfeoSilencieux(Vue::Windows, n) => format!("{IFEO_SILENCIEUX}{}", n.hex()),
            Acte::IfeoSilencieux(Vue::Wow32, n) => format!("{IFEO_SILENCIEUX_32}{}", n.hex()),
            Acte::ServiceGuillemets(n) => format!("{SERVICE_GUILLEMETS}{}", n.hex()),
            Acte::Defender(r, v) => format!("{DEFENDER}{} {}", r.mot(), v.mot()),
            Acte::DefenderAsr(id, m) => format!("{DEFENDER_ASR}{id} {}", m.mot()),
            Acte::DefenderExclusionRetirer(g, e) => format!("{DEFENDER_EXCLUSION_RETIRER}{} {}", g.mot(), e.hex()),
            Acte::DefenderMenacesRetirer => DEFENDER_MENACES_RETIRER.to_string(),
        }
    }

    /// L'acte protège-t-il le PC (une correction qui n'en a que de tels est une protection, que « Défaire » ne propose
    /// pas) ?
    pub(crate) fn durcit(&self) -> bool {
        match self {
            Acte::Service(s) => s.durcit,
            Acte::PareFeuActif
            | Acte::IfeoDebugger(..)
            | Acte::IfeoSilencieux(..)
            | Acte::ServiceGuillemets(_)
            | Acte::Defender(..)
            | Acte::DefenderAsr(..)
            | Acte::DefenderExclusionRetirer(..) => true,
            Acte::PareFeuPublic(p) => p.durcit(),
            Acte::ReseauCategorie(r) => r.categorie == Categorie::Public,
            // Retirer des menaces nettoie : ni une protection remise, ni une remise qui affaiblit.
            Acte::Vider(_) | Acte::ViderFileImpression | Acte::MettreDeCote(_) | Acte::DefenderMenacesRetirer => false,
        }
    }

    /// L'acte rend-il le PC moins protégé (la remise de ce qu'une correction avait coupé) ? La console élevée le dit
    /// en toutes lettres avant l'accord.
    pub(crate) fn affaiblit(&self) -> bool {
        match self {
            Acte::Service(s) => s.affaiblit,
            Acte::PareFeuPublic(p) => p.affaiblit(),
            Acte::ReseauCategorie(r) => r.categorie == Categorie::Prive,
            Acte::PareFeuActif
            | Acte::DefenderAsr(..)
            | Acte::Vider(_)
            | Acte::ViderFileImpression
            | Acte::MettreDeCote(_)
            | Acte::IfeoDebugger(..)
            | Acte::IfeoSilencieux(..)
            | Acte::ServiceGuillemets(_)
            | Acte::Defender(..)
            | Acte::DefenderExclusionRetirer(..)
            | Acte::DefenderMenacesRetirer => false,
        }
    }

    /// L'équivalent PowerShell, pour le chemin par script (Wine). Le dossier de Windows vient de .NET, jamais d'une
    /// variable d'environnement nue, et un dossier vide arrête la ligne : « Join-Path '' 'Temp' » viserait le dossier
    /// courant. Un fichier encore ouvert reste, comme avant.
    pub(crate) fn powershell(&self) -> String {
        match self {
            Acte::Service(s) => s.powershell(),
            Acte::Vider(Vidable::TempWindows) => "$w = [Environment]::GetFolderPath('Windows'); if (-not $w) { throw 'Windows folder not found' }; Get-ChildItem -LiteralPath (Join-Path $w 'Temp') -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue".to_string(),
            Acte::Vider(Vidable::WuTelechargements) => "$w = [Environment]::GetFolderPath('Windows'); if (-not $w) { throw 'Windows folder not found' }; Get-ChildItem -LiteralPath (Join-Path $w 'SoftwareDistribution\\Download') -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue".to_string(),
            Acte::ViderFileImpression => "$w = [Environment]::GetFolderPath('Windows'); if (-not $w) { throw 'Windows folder not found' }; Get-ChildItem -LiteralPath (Join-Path $w 'System32\\spool\\PRINTERS') -File | Remove-Item -Force".to_string(),
            // Les lignes de la réparation « Windows Update bloqué », le dossier de Windows pris comme ci-dessus.
            Acte::MettreDeCote(ACoter::SoftwareDistribution) => "$w = [Environment]::GetFolderPath('Windows'); if (-not $w) { throw 'Windows folder not found' }; Rename-Item -LiteralPath (Join-Path $w 'SoftwareDistribution') \"SoftwareDistribution.$(Get-Date -Format yyyyMMddHHmm)\"".to_string(),
            Acte::MettreDeCote(ACoter::Catroot2) => "$w = [Environment]::GetFolderPath('Windows'); if (-not $w) { throw 'Windows folder not found' }; Rename-Item -LiteralPath (Join-Path $w 'System32\\catroot2') \"catroot2.$(Get-Date -Format yyyyMMddHHmm)\"".to_string(),
            // Les lignes d'avant du bilan et de la réparation « Pare-feu coupé », puis celles du mode Wi-Fi public.
            Acte::PareFeuActif => "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True".to_string(),
            Acte::PareFeuPublic(p) => p.powershell(),
            Acte::ReseauCategorie(r) => r.powershell(),
            // Les lignes d'avant du bilan des portes dérobées, la clé entre apostrophes doublées.
            Acte::IfeoDebugger(v, n) => format!(
                "Remove-ItemProperty -LiteralPath '{}' -Name Debugger",
                ps_texte(&format!(r"HKLM:\{}\{}", v.ifeo(), n.texte()))
            ),
            Acte::IfeoSilencieux(v, n) => format!(
                "Remove-ItemProperty -LiteralPath '{}' -Name MonitorProcess",
                ps_texte(&format!(r"HKLM:\{}\{}", v.silencieuse(), n.texte()))
            ),
            Acte::ServiceGuillemets(n) => powershell_guillemets(n),
            // Aucune commande de Defender dans un script : AMSI les juge comme celles d'un programme qui le désarme,
            // et le chemin du programme passe par WMI (`defender_ecriture`). Sous Wine, il n'y a pas de Defender :
            // l'erreur est dite par la fenêtre, jamais un geste deviné.
            Acte::Defender(..)
            | Acte::DefenderAsr(..)
            | Acte::DefenderExclusionRetirer(..)
            | Acte::DefenderMenacesRetirer => "throw 'Vanguard : geste sans équivalent PowerShell'".to_string(),
        }
    }
}

/// La ligne commence-t-elle par le verbe d'un acte ? Une telle ligne est un acte ou rien : jamais confiée à un autre
/// validateur (`valider`).
pub(crate) fn est_un_acte(ligne: &str) -> bool {
    ligne.starts_with(SERVICE)
        || ligne.starts_with(VIDER)
        || ligne.starts_with(VIDER_FILE)
        || ligne.starts_with(METTRE_DE_COTE)
        || ligne.starts_with(PARE_FEU_ACTIF)
        || ligne.starts_with(PARE_FEU_PUBLIC)
        || ligne.starts_with(RESEAU_CATEGORIE)
        || ligne.starts_with(IFEO_DEBUGGER)
        || ligne.starts_with(IFEO_DEBUGGER_32)
        || ligne.starts_with(IFEO_SILENCIEUX)
        || ligne.starts_with(IFEO_SILENCIEUX_32)
        || ligne.starts_with(SERVICE_GUILLEMETS)
        || ligne.starts_with(DEFENDER)
        || ligne.starts_with(DEFENDER_ASR)
        || ligne.starts_with(DEFENDER_EXCLUSION_RETIRER)
        || ligne.starts_with(DEFENDER_MENACES_RETIRER)
}

/// L'acte d'une ligne, si et seulement si elle est exactement de sa forme : ASCII, 256 octets au plus (1086 pour
/// une ligne qui porte un nom en hexadécimal), sensible à la casse, un nom et une action de la table (une seule espace
/// entre chaque), réécrite à l'identique.
pub(crate) fn analyser_acte(ligne: &str) -> Option<Acte> {
    if ligne.len() > ACTE_NOM_MAX || !ligne.is_ascii() {
        return None;
    }
    if let Some((hex, faire)) = verbe_nomme(ligne) {
        return NomFichier::lire(hex).map(faire).filter(|a| a.ligne() == ligne);
    }
    if let Some(reste) = ligne.strip_prefix(DEFENDER_EXCLUSION_RETIRER) {
        let (mot, hex) = reste.split_once(' ')?;
        let genre = *GenreExclusion::TOUS.iter().find(|g| g.mot() == mot)?;
        return Some(Acte::DefenderExclusionRetirer(genre, Exclusion::lire(hex)?)).filter(|a| a.ligne() == ligne);
    }
    if ligne.len() > ACTE_MAX {
        return None;
    }
    let acte = if let Some(reste) = ligne.strip_prefix(SERVICE) {
        let (nom, mot) = reste.split_once(' ')?;
        let service = SERVICES.iter().find(|s| s.nom == nom)?;
        let p = service.permis.iter().find(|p| p.action.mot() == mot)?;
        Acte::Service(GesteService {
            nom: service.nom,
            action: p.action,
            durcit: p.durcit,
            affaiblit: p.affaiblit,
        })
    } else if let Some(id) = ligne.strip_prefix(VIDER) {
        Acte::Vider(*Vidable::TOUS.iter().find(|v| v.id() == id)?)
    } else if ligne == VIDER_FILE {
        Acte::ViderFileImpression
    } else if ligne == PARE_FEU_ACTIF {
        Acte::PareFeuActif
    } else if let Some(reste) = ligne.strip_prefix(PARE_FEU_PUBLIC) {
        Acte::PareFeuPublic(ProfilPublic::analyser(reste)?)
    } else if let Some(reste) = ligne.strip_prefix(DEFENDER) {
        let (mot, valeur) = reste.split_once(' ')?;
        let reglage = *ReglageDefender::TOUS.iter().find(|r| r.mot() == mot)?;
        Acte::Defender(reglage, *reglage.permises().iter().find(|v| v.mot() == valeur)?)
    } else if let Some(reste) = ligne.strip_prefix(DEFENDER_ASR) {
        let (id, mot) = reste.split_once(' ')?;
        Acte::DefenderAsr(asr_connue(id)?, *ModeAsr::TOUS.iter().find(|m| m.mot() == mot)?)
    } else if ligne == DEFENDER_MENACES_RETIRER {
        Acte::DefenderMenacesRetirer
    } else if let Some(reste) = ligne.strip_prefix(RESEAU_CATEGORIE) {
        let (guid, mot) = reste.split_once(' ')?;
        Acte::ReseauCategorie(ReseauCategorie {
            guid: GuidReseau::lire(guid)?,
            categorie: *[Categorie::Public, Categorie::Prive].iter().find(|c| c.mot() == mot)?,
        })
    } else {
        let id = ligne.strip_prefix(METTRE_DE_COTE)?;
        Acte::MettreDeCote(*ACoter::TOUS.iter().find(|c| c.id() == id)?)
    };
    (acte.ligne() == ligne).then_some(acte)
}

/// L'acte du registre fait d'un nom relu.
type FaireActe = fn(NomFichier) -> Acte;

/// Les verbes des actes du registre qui portent un nom. Aucun verbe n'est le début d'un autre : « ifeo-debugger-32 »
/// n'a pas d'espace après « ifeo-debugger ».
const ACTES_NOMMES: [(&str, FaireActe); 5] = [
    (IFEO_DEBUGGER_32, |n| Acte::IfeoDebugger(Vue::Wow32, n)),
    (IFEO_DEBUGGER, |n| Acte::IfeoDebugger(Vue::Windows, n)),
    (IFEO_SILENCIEUX_32, |n| Acte::IfeoSilencieux(Vue::Wow32, n)),
    (IFEO_SILENCIEUX, |n| Acte::IfeoSilencieux(Vue::Windows, n)),
    (SERVICE_GUILLEMETS, Acte::ServiceGuillemets),
];

/// L'hexadécimal du nom et l'acte, si la ligne a le verbe d'un acte du registre qui porte un nom (sa forme est
/// jugée ensuite : un verbe connu suivi d'un nom mal formé est refusé, jamais lu comme un autre acte).
fn verbe_nomme(ligne: &str) -> Option<(&str, FaireActe)> {
    ACTES_NOMMES
        .iter()
        .find_map(|(verbe, faire)| ligne.strip_prefix(verbe).map(|hex| (hex, *faire)))
}

/// La ligne d'un acte sur un service de la table, pour un correctif.
pub(crate) fn ligne_service(nom: &str, action: Action) -> String {
    let ligne = format!("{SERVICE}{nom} {}", action.mot());
    debug_assert!(
        analyser_acte(&ligne).is_some(),
        "service ou action hors de la table : {ligne}"
    );
    ligne
}

/// La ligne qui vide un dossier de Windows.
pub(crate) fn ligne_vider(dossier: Vidable) -> String {
    Acte::Vider(dossier).ligne()
}

/// La ligne qui vide la file d'impression.
pub(crate) fn ligne_vider_file_impression() -> String {
    VIDER_FILE.to_string()
}

/// La ligne qui met un cache de Windows Update de côté.
pub(crate) fn ligne_mettre_de_cote(cache: ACoter) -> String {
    Acte::MettreDeCote(cache).ligne()
}

/// La ligne qui remet le Pare-feu Windows en marche sur ses trois profils.
pub(crate) fn ligne_pare_feu_actif() -> String {
    PARE_FEU_ACTIF.to_string()
}

/// La ligne qui règle le profil Public du pare-feu ; `None` : aucun réglage, un réglage deux fois, ou une valeur
/// hors liste (« actif=non »).
pub(crate) fn ligne_pare_feu_public(reglages: &[(ReglagePublic, ValeurPublic)]) -> Option<String> {
    ProfilPublic::nouveau(reglages).map(ProfilPublic::ligne)
}

/// La ligne qui donne une catégorie à un réseau, le GUID réécrit en majuscules ; `None` s'il n'a pas sa forme.
pub(crate) fn ligne_reseau_categorie(guid: &str, categorie: Categorie) -> Option<String> {
    GuidReseau::lire(guid).map(|guid| ReseauCategorie { guid, categorie }.ligne())
}

// ------------------------------------------------------------------ le compte

/// Le verbe d'un geste du compte : une valeur du HKCU de la personne (ou son mode d'alimentation), faite par Vanguard
/// NON élevé, dans son propre processus, qui tourne déjà sous le compte de la personne. Le processus élevé la refuse
/// (`valider`) : elle ne passe jamais l'UAC, et une fenêtre administrateur ouverte par un autre compte (« par-dessus
/// l'épaule ») ne l'écrit pas dans son HKCU à elle.
pub(crate) const COMPTE: &str = "vanguard:compte ";
/// Le plus long nom de valeur Run admis, en unités UTF-16 : celui du registre (16 383 caractères). Un maliciel qui
/// prend un nom très long ne doit pas échapper au retrait.
pub(crate) const RUN_NOM_MAX: usize = 16_383;
/// La plus longue ligne du compte : un retrait RunOnce au nom le plus long. Elle ne passe jamais le tube du processus
/// élevé (`valider` la refuse), d'où une borne à elle, au-dessus de `LIGNE_MAX`.
pub(crate) const COMPTE_LIGNE_MAX: usize = COMPTE.len() + "run-retirer runonce ".len() + 4 * RUN_NOM_MAX;
/// Les caractères d'un nom montrés au plus : un nom très long est coupé à l'écran, jamais dans le geste.
const NOM_MONTRE_MAX: usize = 200;
/// Les clés de démarrage du compte, sous HKCU.
pub(crate) const CLE_RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub(crate) const CLE_RUNONCE: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
/// Les versions d'Office qui gardent leurs réglages dans le registre (2010, 2013, 2016 à 365) et leurs programmes à
/// macros : (clé, nom montré).
pub(crate) const OFFICE_VERSIONS: [&str; 3] = ["16.0", "15.0", "14.0"];
pub(crate) const OFFICE_PROGRAMMES: [(&str, &str); 6] = [
    ("word", "Word"),
    ("excel", "Excel"),
    ("powerpoint", "PowerPoint"),
    ("access", "Access"),
    ("publisher", "Publisher"),
    ("visio", "Visio"),
];

/// Ce qu'un geste du compte met dans sa valeur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Donnee {
    Dword(u32),
    /// Un texte (REG_SZ).
    Sz(&'static str),
    /// La valeur retirée.
    Retirer,
    /// DirectXUserGlobalSettings : seul « SwapEffectUpgradeEnable » change, le reste du texte est gardé
    /// (`avec_swap_effect`).
    SwapEffect,
}

/// Une valeur fixe du compte : sa clé sous HKCU, son nom, ce qu'elle reçoit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValeurCompte {
    pub id: &'static str,
    pub cle: &'static str,
    pub nom: &'static str,
    pub donnee: Donnee,
    /// Un réglage d'Internet : WinINet est prévenu une fois la valeur changée, pour que les navigateurs le prennent
    /// tout de suite.
    pub rafraichir: bool,
    /// Le geste renforce la sécurité : son annulation n'est pas proposée (`Defaire::Protection`).
    pub durcit: bool,
    pub fr: &'static str,
    pub en: &'static str,
}

/// Les valeurs fixes du compte, liste fermée. Seul l'identifiant voyage : la clé, le nom et la donnée sont ceux-ci.
pub(crate) static VALEURS_COMPTE: &[ValeurCompte] = &[
    ValeurCompte {
        id: "jeux-mode",
        cle: r"Software\Microsoft\GameBar",
        nom: "AutoGameModeEnabled",
        donnee: Donnee::Dword(1),
        rafraichir: false,
        durcit: false,
        fr: "Activer le Mode Jeu",
        en: "Turn on Game Mode",
    },
    ValeurCompte {
        id: "jeux-dvr",
        cle: r"System\GameConfigStore",
        nom: "GameDVR_Enabled",
        donnee: Donnee::Dword(0),
        rafraichir: false,
        durcit: false,
        fr: "Couper l'enregistrement de jeu en arrière-plan",
        en: "Turn off background game recording",
    },
    ValeurCompte {
        id: "jeux-capture",
        cle: r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
        nom: "AppCaptureEnabled",
        donnee: Donnee::Dword(0),
        rafraichir: false,
        durcit: false,
        fr: "Couper la capture de jeu de la Xbox Game Bar",
        en: "Turn off Xbox Game Bar game capture",
    },
    ValeurCompte {
        id: "souris-vitesse",
        cle: r"Control Panel\Mouse",
        nom: "MouseSpeed",
        donnee: Donnee::Sz("0"),
        rafraichir: false,
        durcit: false,
        fr: "Couper l'accélération de la souris (vitesse)",
        en: "Turn off mouse acceleration (speed)",
    },
    ValeurCompte {
        id: "souris-seuil1",
        cle: r"Control Panel\Mouse",
        nom: "MouseThreshold1",
        donnee: Donnee::Sz("0"),
        rafraichir: false,
        durcit: false,
        fr: "Couper l'accélération de la souris (premier seuil)",
        en: "Turn off mouse acceleration (first threshold)",
    },
    ValeurCompte {
        id: "souris-seuil2",
        cle: r"Control Panel\Mouse",
        nom: "MouseThreshold2",
        donnee: Donnee::Sz("0"),
        rafraichir: false,
        durcit: false,
        fr: "Couper l'accélération de la souris (second seuil)",
        en: "Turn off mouse acceleration (second threshold)",
    },
    ValeurCompte {
        id: "jeux-fenetres",
        cle: r"Software\Microsoft\DirectX\UserGpuPreferences",
        nom: "DirectXUserGlobalSettings",
        donnee: Donnee::SwapEffect,
        rafraichir: false,
        durcit: false,
        fr: "Activer les optimisations pour les jeux en fenêtre",
        en: "Turn on optimizations for windowed games",
    },
    ValeurCompte {
        id: "ps-strategie",
        cle: r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
        nom: "ExecutionPolicy",
        donnee: Donnee::Sz("RemoteSigned"),
        rafraichir: false,
        durcit: true,
        fr: "Remettre la stratégie d'exécution de PowerShell de ce compte à RemoteSigned",
        en: "Set this account's PowerShell execution policy back to RemoteSigned",
    },
    // Décision 4 b) du plan : un retrait de persistance n'est pas « Protection » ; son annulation exacte (valeur
    // d'avant relevée) revient au lot 3.5.
    ValeurCompte {
        id: "winlogon-shell-compte",
        cle: r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        nom: "Shell",
        donnee: Donnee::Retirer,
        rafraichir: false,
        durcit: false,
        fr: "Retirer le shell de remplacement de ce compte (l'Explorateur revient)",
        en: "Remove this account's replacement shell (Explorer comes back)",
    },
    ValeurCompte {
        id: "proxy-coupe",
        cle: r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        nom: "ProxyEnable",
        donnee: Donnee::Dword(0),
        rafraichir: true,
        durcit: false,
        fr: "Couper le proxy de ce compte",
        en: "Turn off this account's proxy",
    },
    ValeurCompte {
        id: "proxy-script-retire",
        cle: r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        nom: "AutoConfigURL",
        donnee: Donnee::Retirer,
        rafraichir: true,
        durcit: false,
        fr: "Retirer le script de configuration du proxy de ce compte",
        en: "Remove this account's proxy configuration script",
    },
];

/// Un geste du compte, relu de sa ligne.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GesteCompte {
    /// Une valeur de `VALEURS_COMPTE`.
    Valeur(&'static ValeurCompte),
    /// VBAWarnings à 2 (« désactivées avec notification ») pour un programme d'Office : version et programme pris
    /// dans `OFFICE_VERSIONS` et `OFFICE_PROGRAMMES`.
    Macros {
        version: &'static str,
        programme: &'static str,
        nom: &'static str,
    },
    /// Une valeur de démarrage du compte retirée (Run ou RunOnce) ; un nom vide désigne la valeur par défaut.
    RetirerRun { runonce: bool, nom: Vec<u16> },
    /// Le mode d'alimentation « Performances élevées » (powercfg, qui n'a pas besoin d'administrateur pour un mode
    /// qui existe).
    Alimentation,
}

const MACROS: &str = "macros-office ";
const RUN_RETIRER: &str = "run-retirer ";
const ALIMENTATION: &str = "alimentation-performances";
const RUN_DEFAUT: &str = "defaut";

impl GesteCompte {
    /// La ligne de ce geste.
    pub(crate) fn ligne(&self) -> String {
        match self {
            GesteCompte::Valeur(v) => format!("{COMPTE}{}", v.id),
            GesteCompte::Macros { version, programme, .. } => format!("{COMPTE}{MACROS}{version} {programme}"),
            GesteCompte::RetirerRun { runonce, nom } => {
                let cle = if *runonce { "runonce" } else { "run" };
                let nom = if nom.is_empty() {
                    RUN_DEFAUT.to_string()
                } else {
                    hex_utf16(nom)
                };
                format!("{COMPTE}{RUN_RETIRER}{cle} {nom}")
            }
            GesteCompte::Alimentation => format!("{COMPTE}{ALIMENTATION}"),
        }
    }

    /// La clé sous HKCU, et le nom de la valeur en UTF-16 (vide : la valeur par défaut) ; `None` pour le mode
    /// d'alimentation, qui n'est pas une valeur du compte.
    pub(crate) fn valeur(&self) -> Option<(String, Vec<u16>)> {
        match self {
            GesteCompte::Valeur(v) => Some((v.cle.to_string(), v.nom.encode_utf16().collect())),
            GesteCompte::Macros { version, programme, .. } => Some((
                format!(r"Software\Microsoft\Office\{version}\{programme}\Security"),
                "VBAWarnings".encode_utf16().collect(),
            )),
            GesteCompte::RetirerRun { runonce, nom } => {
                Some(((if *runonce { CLE_RUNONCE } else { CLE_RUN }).to_string(), nom.clone()))
            }
            GesteCompte::Alimentation => None,
        }
    }

    /// Ce que la valeur reçoit ; `None` pour le mode d'alimentation.
    pub(crate) fn donnee(&self) -> Option<Donnee> {
        match self {
            GesteCompte::Valeur(v) => Some(v.donnee),
            GesteCompte::Macros { .. } => Some(Donnee::Dword(2)),
            GesteCompte::RetirerRun { .. } => Some(Donnee::Retirer),
            GesteCompte::Alimentation => None,
        }
    }

    /// WinINet doit-il être prévenu une fois le geste fait ?
    pub(crate) fn rafraichir(&self) -> bool {
        matches!(self, GesteCompte::Valeur(v) if v.rafraichir)
    }

    /// Le geste renforce-t-il la sécurité (annulation non proposée) ? Les macros et la stratégie de PowerShell, oui ;
    /// un retrait de démarrage (décision 4 b) du plan) ou un réglage de jeu, non : ils seront annulables (lot 3.5).
    pub(crate) fn durcit(&self) -> bool {
        match self {
            GesteCompte::Valeur(v) => v.durcit,
            GesteCompte::Macros { .. } => true,
            GesteCompte::RetirerRun { .. } | GesteCompte::Alimentation => false,
        }
    }

    /// Le geste dit à la personne, dans sa langue. Un nom de démarrage est montré sans caractère de contrôle.
    pub(crate) fn texte(&self, francais: bool) -> String {
        match self {
            GesteCompte::Valeur(v) => (if francais { v.fr } else { v.en }).to_string(),
            GesteCompte::Macros { version, nom, .. } => {
                if francais {
                    format!("Faire demander {nom} ({version}) avant de lancer une macro")
                } else {
                    format!("Make {nom} ({version}) ask before running a macro")
                }
            }
            GesteCompte::RetirerRun { runonce, nom } => {
                let lu = String::from_utf16_lossy(nom);
                let mut affiche: String = lu
                    .chars()
                    .take(NOM_MONTRE_MAX)
                    .map(|c| if c.is_control() { '?' } else { c })
                    .collect();
                if lu.chars().count() > NOM_MONTRE_MAX {
                    affiche.push('…');
                }
                let cle = if *runonce { "RunOnce" } else { "Run" };
                match (francais, nom.is_empty()) {
                    (true, true) => format!("Retirer la valeur par défaut du démarrage de ce compte ({cle})"),
                    (true, false) => format!("Retirer « {affiche} » du démarrage de ce compte ({cle})"),
                    (false, true) => format!("Remove the default value from this account's startup ({cle})"),
                    (false, false) => format!("Remove “{affiche}” from this account's startup ({cle})"),
                }
            }
            GesteCompte::Alimentation => {
                if francais {
                    "Passer au mode d'alimentation « Performances élevées »".to_string()
                } else {
                    "Switch to the “High performance” power plan".to_string()
                }
            }
        }
    }
}

/// Un nom UTF-16 en hexadécimal minuscule, quatre chiffres par unité petit-boutiste (la convention de `NomFichier`).
fn hex_utf16(unites: &[u16]) -> String {
    unites
        .iter()
        .flat_map(|u| u.to_le_bytes())
        .fold(String::new(), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        })
}

/// Les unités UTF-16 d'un hexadécimal de `hex_utf16`, s'il en a la forme exacte : minuscules, par groupes de quatre,
/// de 1 à `max` unités, aucune unité nulle (un nom du registre n'en a pas). Toute autre unité est admise : un nom de
/// valeur peut ne pas être de l'UTF-16 valide, il doit pourtant pouvoir se retirer.
fn lire_hex_utf16(hex: &str, max: usize) -> Option<Vec<u16>> {
    if hex.is_empty() || !hex.len().is_multiple_of(4) || hex.len() > max.checked_mul(4)? {
        return None;
    }
    hex.as_bytes()
        .chunks(4)
        .map(|q| {
            let mut o = [0u8; 2];
            for (i, paire) in q.chunks(2).enumerate() {
                let fort = chiffre_minuscule(*paire.first()?)?;
                let faible = chiffre_minuscule(*paire.get(1)?)?;
                *o.get_mut(i)? = fort.checked_mul(16)?.checked_add(faible)?;
            }
            Some(u16::from_le_bytes(o)).filter(|&u| u != 0)
        })
        .collect()
}

/// Le geste d'une ligne du compte, si et seulement si elle est exactement de sa forme (relue, elle se réécrit à
/// l'identique) : un identifiant de `VALEURS_COMPTE`, `macros-office <version> <programme>` des listes d'Office,
/// `run-retirer <run|runonce> <nom en hexadécimal|defaut>` ou `alimentation-performances`.
pub(crate) fn analyser_compte(ligne: &str) -> Option<GesteCompte> {
    let reste = ligne.strip_prefix(COMPTE)?;
    if ligne.len() > COMPTE_LIGNE_MAX || !ligne.is_ascii() {
        return None;
    }
    let geste = if let Some(r) = reste.strip_prefix(MACROS) {
        let (version, programme) = r.split_once(' ')?;
        let version = OFFICE_VERSIONS.into_iter().find(|v| *v == version)?;
        let (programme, nom) = OFFICE_PROGRAMMES.into_iter().find(|p| p.0 == programme)?;
        GesteCompte::Macros {
            version,
            programme,
            nom,
        }
    } else if let Some(r) = reste.strip_prefix(RUN_RETIRER) {
        let (cle, nom) = r.split_once(' ')?;
        let runonce = match cle {
            "run" => false,
            "runonce" => true,
            _ => return None,
        };
        let nom = if nom == RUN_DEFAUT {
            Vec::new()
        } else {
            lire_hex_utf16(nom, RUN_NOM_MAX)?
        };
        GesteCompte::RetirerRun { runonce, nom }
    } else if reste == ALIMENTATION {
        GesteCompte::Alimentation
    } else {
        GesteCompte::Valeur(VALEURS_COMPTE.iter().find(|v| v.id == reste)?)
    };
    (geste.ligne() == ligne).then_some(geste)
}

/// La ligne d'une valeur fixe du compte ; `None` : identifiant hors de `VALEURS_COMPTE`.
pub(crate) fn ligne_compte(id: &str) -> Option<String> {
    VALEURS_COMPTE
        .iter()
        .find(|v| v.id == id)
        .map(|v| GesteCompte::Valeur(v).ligne())
}

/// La ligne qui fait demander un programme d'Office avant une macro ; `None` : version ou programme hors liste.
pub(crate) fn ligne_macros(version: &str, programme: &str) -> Option<String> {
    let version = OFFICE_VERSIONS.into_iter().find(|v| *v == version)?;
    let (programme, nom) = OFFICE_PROGRAMMES.into_iter().find(|p| p.0 == programme)?;
    Some(
        GesteCompte::Macros {
            version,
            programme,
            nom,
        }
        .ligne(),
    )
}

/// La ligne qui retire une valeur de démarrage du compte, désignée par son nom exact (UTF-16 tel que lu dans le
/// registre ; vide : la valeur par défaut) ; `None` : nom trop long ou porteur d'une unité nulle.
pub(crate) fn ligne_run_retirer(runonce: bool, nom: &[u16]) -> Option<String> {
    if nom.len() > RUN_NOM_MAX || nom.contains(&0) {
        return None;
    }
    Some(
        GesteCompte::RetirerRun {
            runonce,
            nom: nom.to_vec(),
        }
        .ligne(),
    )
}

/// La ligne qui passe au mode d'alimentation « Performances élevées ».
pub(crate) fn ligne_alimentation() -> String {
    GesteCompte::Alimentation.ligne()
}

/// DirectXUserGlobalSettings avec « SwapEffectUpgradeEnable=1; » : l'ancien réglage (« =0 », « =1 », suivi ou non de
/// « ; », casse ignorée, comme le `-replace` de PowerShell qu'il remplace) est retiré, le reste du texte gardé tel
/// quel, et le nôtre ajouté au bout.
pub(crate) fn avec_swap_effect(ancien: &str) -> String {
    const CLE: &str = "SwapEffectUpgradeEnable=";
    let mut nouveau = String::with_capacity(ancien.len().saturating_add(CLE.len()).saturating_add(2));
    let mut reste = ancien;
    while !reste.is_empty() {
        let tete = reste.get(..CLE.len()).is_some_and(|t| t.eq_ignore_ascii_case(CLE));
        let chiffre = reste.as_bytes().get(CLE.len()).is_some_and(u8::is_ascii_digit);
        if tete && chiffre {
            let apres = CLE.len().saturating_add(1);
            let fin = if reste.as_bytes().get(apres) == Some(&b';') {
                apres.saturating_add(1)
            } else {
                apres
            };
            reste = reste.get(fin..).unwrap_or_default();
            continue;
        }
        let mut c = reste.chars();
        if let Some(premier) = c.next() {
            nouveau.push(premier);
        }
        reste = c.as_str();
    }
    // Le réglage d'avant sans « ; » final ne doit pas se coller au nôtre (« VRROptimizeEnable=0SwapEffect… »).
    if !nouveau.is_empty() && !nouveau.ends_with(';') {
        nouveau.push(';');
    }
    nouveau.push_str(CLE);
    nouveau.push_str("1;");
    nouveau
}

// ------------------------------------------------------------------ la liste

/// Une ligne de la liste, relue : celle d'un autre module (correction, ordre), un script, un programme ou un acte.
pub(crate) enum Ligne<E> {
    Autre(E),
    Script(Script),
    Programme(Appel),
    Acte(Acte),
}

/// La liste telle que le processus élevé la recevra, validée ligne à ligne, dans l'ordre ; `None` dès qu'une ligne
/// est trop longue, n'a pas sa forme, est un geste du compte (`COMPTE`), ou n'est pas reconnue par `autre`, qu'il y
/// en a trop ou aucune, ou qu'un même script (même empreinte) revient. Le parent l'appelle AVANT la demande
/// d'administrateur, le processus élevé à la réception : la même fonction des deux côtés. Un script seul est admis
/// (une liste toute en PowerShell).
pub(crate) fn valider<E>(lignes: &[String], mut autre: impl FnMut(&str) -> Option<E>) -> Option<Vec<Ligne<E>>> {
    if lignes.is_empty() || lignes.len() > LIGNES_MAX {
        return None;
    }
    let mut empreintes = std::collections::HashSet::new();
    lignes
        .iter()
        .map(|l| {
            // Un geste du compte n'est jamais fait par le processus élevé : sa place est Vanguard non élevé.
            if l.len() > LIGNE_MAX || l.starts_with(COMPTE) {
                return None;
            }
            if l.starts_with(SCRIPT) {
                let s = analyser_script(l)?;
                return empreintes.insert(s.empreinte.clone()).then_some(Ligne::Script(s));
            }
            if l.starts_with(PROGRAMME) {
                return analyser_programme(l).map(Ligne::Programme);
            }
            if est_un_acte(l) {
                return analyser_acte(l).map(Ligne::Acte);
            }
            autre(l).map(Ligne::Autre)
        })
        .collect()
}

// ---------------------------------------------------------------- la découpe

/// Un morceau d'une liste de correctifs : une suite de lignes natives (chacune désignée par son correctif et sa
/// place), ou un script fait des lignes PowerShell qui se suivent, correctif par correctif.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Morceau {
    Natif(Vec<(usize, usize)>),
    Script(Vec<(usize, Vec<usize>)>),
}

/// Découpe des correctifs en morceaux, dans l'ordre : chaque correctif est coupé là où il passe du natif au
/// PowerShell (le point de restauration en tête d'une réparation devient ainsi un geste natif à lui seul, avant le
/// script). Le résultat d'un correctif est le ET de ses morceaux ; un correctif vide n'en a aucun (rien à faire).
pub(crate) fn decouper(correctifs: &[Vec<String>], natif: impl Fn(&str) -> bool) -> Vec<Morceau> {
    let mut morceaux: Vec<Morceau> = Vec::new();
    for (i, c) in correctifs.iter().enumerate() {
        for (j, l) in c.iter().enumerate() {
            if natif(l) {
                match morceaux.last_mut() {
                    Some(Morceau::Natif(v)) => v.push((i, j)),
                    _ => morceaux.push(Morceau::Natif(vec![(i, j)])),
                }
                continue;
            }
            match morceaux.last_mut() {
                Some(Morceau::Script(v)) => match v.last_mut() {
                    Some((k, suite)) if *k == i => suite.push(j),
                    _ => v.push((i, vec![j])),
                },
                _ => morceaux.push(Morceau::Script(vec![(i, vec![j])])),
            }
        }
    }
    morceaux
}

// ------------------------------------------------------------ la séparation

/// Les lignes d'un correctif, rangées par qui les fait : les points de restauration et le reste du travail élevé
/// (par le processus élevé), les gestes du compte (par Vanguard non élevé). Chaque place est celle de la ligne dans
/// son correctif, dans l'ordre.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Separe {
    pub points: Vec<usize>,
    pub eleves: Vec<usize>,
    pub compte: Vec<usize>,
}

/// Range chaque ligne de chaque correctif : un point de restauration (`est_point`) va aux points, une ligne du compte
/// que `analyser_compte` reconnaît aux gestes du compte, toute autre ligne au travail élevé. Une ligne qui se donne
/// pour un geste du compte sans en avoir la forme exacte reste au travail élevé, où elle est refusée avant l'UAC
/// (aucune ligne « vanguard: » inconnue ne passe) : jamais faite par erreur sous un autre nom.
pub(crate) fn separer(correctifs: &[Vec<String>], est_point: impl Fn(&str) -> bool) -> Vec<Separe> {
    correctifs
        .iter()
        .map(|c| {
            let mut s = Separe::default();
            for (j, l) in c.iter().enumerate() {
                if est_point(l) {
                    s.points.push(j);
                } else if analyser_compte(l).is_some() {
                    s.compte.push(j);
                } else {
                    s.eleves.push(j);
                }
            }
            s
        })
        .collect()
}

/// Ce que rend le passage élevé : le résultat et les lignes notées de chaque correctif envoyé, et s'il a été arrêté à
/// la demande de la personne (point refusé, demande d'administrateur refusée).
pub(crate) struct PassageEleve {
    pub resultats: Vec<bool>,
    pub notes: Vec<Vec<String>>,
    pub arrete: bool,
}

/// Un geste du compte fait : réussi ou non, déjà bon (rien d'écrit, la ligne n'est pas notée), la valeur d'avant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FaitCompte {
    pub reussi: bool,
    pub rien: bool,
    pub avant: Option<String>,
}

/// Fait une liste de correctifs en deux temps, l'ordre gardé : d'abord, en UN passage élevé (`eleve`), pour chaque
/// correctif ses points de restauration puis son travail élevé (deux correctifs envoyés, pour savoir si le point a
/// tenu) ; ensuite seulement, dans ce processus, les gestes du compte (`compte`), correctif par correctif. Ainsi le
/// point de restauration est toujours pris avant la moindre écriture du compte.
///
/// Aucun geste du compte n'est fait si le passage élevé a été arrêté à la demande de la personne, ou si un point de
/// restauration n'a pas tenu (le processus élevé s'arrête alors, et tout ce qui suit le point, les gestes du compte
/// compris, reste à faire). Rien d'élevé à faire : aucun passage élevé, aucune demande d'administrateur.
///
/// Le résultat d'un correctif est le ET de ses trois parts ; un geste du compte non fait est un échec. Ses lignes
/// notées : celles du passage élevé (points, puis travail élevé), puis ses gestes du compte, la valeur d'avant
/// ajoutée ; un geste déjà bon n'est pas noté, et un correctif dont il ne reste que des points n'a plus rien à noter.
/// `None` : le passage élevé n'a rien fait (dit par lui) ; aucun geste du compte n'est fait.
pub(crate) fn lancer_separe(
    correctifs: &[Vec<String>],
    est_point: impl Fn(&str) -> bool,
    eleve: impl FnOnce(&[Vec<String>]) -> Option<PassageEleve>,
    mut compte: impl FnMut(&GesteCompte) -> FaitCompte,
) -> Option<(Vec<bool>, Vec<Vec<String>>)> {
    let separes = separer(correctifs, &est_point);
    let ligne = |i: usize, j: usize| correctifs.get(i).and_then(|c| c.get(j)).cloned();
    // Pour chaque correctif, la place de ses points et de son travail élevé dans la liste envoyée.
    let mut envoyes: Vec<Vec<String>> = Vec::new();
    let mut places: Vec<(Option<usize>, Option<usize>)> = Vec::with_capacity(correctifs.len());
    for (i, s) in separes.iter().enumerate() {
        let mut place = |js: &[usize]| {
            if js.is_empty() {
                return None;
            }
            envoyes.push(js.iter().filter_map(|&j| ligne(i, j)).collect());
            envoyes.len().checked_sub(1)
        };
        let p = place(&s.points);
        let e = place(&s.eleves);
        places.push((p, e));
    }
    let passage = if envoyes.is_empty() {
        PassageEleve {
            resultats: Vec::new(),
            notes: Vec::new(),
            arrete: false,
        }
    } else {
        eleve(&envoyes)?
    };
    let reussi = |k: Option<usize>| k.is_none_or(|k| passage.resultats.get(k).copied().unwrap_or(false));
    let notes_de = |k: Option<usize>| k.and_then(|k| passage.notes.get(k).cloned()).unwrap_or_default();
    let points_tenus = places.iter().all(|&(p, _)| reussi(p));
    let permis = !passage.arrete && points_tenus;
    let mut resultats = Vec::with_capacity(correctifs.len());
    let mut notes = Vec::with_capacity(correctifs.len());
    for (i, (s, &(p, e))) in separes.iter().zip(&places).enumerate() {
        let mut ok = reussi(p) && reussi(e);
        let mut n = notes_de(p);
        n.extend(notes_de(e));
        for &j in &s.compte {
            let Some(l) = ligne(i, j) else {
                ok = false;
                continue;
            };
            let fait = analyser_compte(&l).filter(|_| permis).map(|g| compte(&g));
            match fait {
                Some(FaitCompte {
                    reussi: true,
                    rien: true,
                    ..
                }) => {}
                Some(f) => {
                    ok &= f.reussi;
                    n.push(match f.avant {
                        Some(avant) => format!("{l} (avant : {avant})"),
                        None => l,
                    });
                }
                None => {
                    ok = false;
                    n.push(l);
                }
            }
        }
        let a_du_travail = s.eleves.len().saturating_add(s.compte.len()) > 0;
        if a_du_travail && n.iter().all(|l| est_point(l.split(" (").next().unwrap_or_default())) {
            n.clear();
        }
        resultats.push(ok);
        notes.push(n);
    }
    Some((resultats, notes))
}

// ---------------------------------------------------------------- les états

/// La réponse d'un script en échec : son code et l'état de chacun de ses correctifs (« 1 » fait, « 0 » non fait),
/// dans l'ordre, tels que le script les a écrits.
pub(crate) fn raison_du_script(code: i32, etats: &[bool]) -> String {
    let etats: String = etats
        .iter()
        .take(ETATS_MAX)
        .map(|&e| if e { '1' } else { '0' })
        .collect();
    format!("code={code} etats={etats}")
}

/// Les états d'une réponse « echec code=N etats=… » ; `None` : la réponse n'en porte pas (rien de sûr : tout est
/// « non fait »).
pub(crate) fn etats_du_script(reponse: &str) -> Option<Vec<bool>> {
    let (code, reste) = reponse.strip_prefix("echec code=")?.split_once(' ')?;
    code.parse::<i32>().ok()?;
    let etats = reste.strip_prefix("etats=")?.split(' ').next()?;
    if etats.len() > ETATS_MAX {
        return None;
    }
    etats
        .bytes()
        .map(|o| match o {
            b'1' => Some(true),
            b'0' => Some(false),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POINT: &str = "vanguard:point-de-restauration";

    fn natif(l: &str) -> bool {
        l.starts_with("vanguard:") && !l.starts_with(SCRIPT)
    }

    fn lignes(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| (*s).to_string()).collect()
    }

    /// Le bogue P0 : une réparation avec point de restauration (« Internet ne marche plus », DISM/sfc, Gaming) met
    /// le point EN TÊTE du même correctif que ses commandes PowerShell. Le correctif entier partait dans le script, la
    /// liste n'était faite que d'un script, et le processus élevé la refusait (« jamais seul ») après l'UAC. Le point
    /// doit être un geste natif à lui seul, avant le script.
    #[test]
    fn le_point_en_tete_est_un_morceau_a_lui() {
        let c = vec![lignes(&[POINT, "ipconfig /flushdns", "ipconfig /renew"])];
        assert_eq!(
            decouper(&c, natif),
            [Morceau::Natif(vec![(0, 0)]), Morceau::Script(vec![(0, vec![1, 2])])]
        );
    }

    #[test]
    fn la_decoupe_garde_l_ordre_et_chaque_ligne_une_fois() {
        let p = ligne_programme("sfc-scannow", None);
        // Natif seul : un seul morceau, sur plusieurs correctifs.
        let c = vec![lignes(&[POINT]), vec![p.clone(), p.clone()]];
        assert_eq!(decouper(&c, natif), [Morceau::Natif(vec![(0, 0), (1, 0), (1, 1)])]);
        // PowerShell seul : un seul script, un groupe par correctif ; un correctif vide n'a aucun morceau.
        let c = vec![lignes(&["a", "b"]), vec![], lignes(&["c"])];
        assert_eq!(
            decouper(&c, natif),
            [Morceau::Script(vec![(0, vec![0, 1]), (2, vec![0])])]
        );
        // Alternés, dans un même correctif et d'un correctif à l'autre.
        let c = vec![
            lignes(&["a", POINT, "b"]),
            lignes(&["c"]),
            vec![p.clone(), "d".to_string()],
        ];
        assert_eq!(
            decouper(&c, natif),
            [
                Morceau::Script(vec![(0, vec![0])]),
                Morceau::Natif(vec![(0, 1)]),
                Morceau::Script(vec![(0, vec![2]), (1, vec![0])]),
                Morceau::Natif(vec![(2, 0)]),
                Morceau::Script(vec![(2, vec![1])]),
            ]
        );
        assert_eq!(decouper(&[], natif), []);
    }

    fn empreinte(n: u8) -> String {
        format!("{n:02X}").repeat(32)
    }

    fn script(n: u8) -> String {
        ligne_script(
            &empreinte(n),
            &format!(r"C:\Users\a\AppData\Local\vanguard\corrections\correction-{n}.ps1"),
        )
    }

    fn valide(l: &[String]) -> bool {
        valider(l, |l| (l == POINT).then_some(())).is_some()
    }

    #[test]
    fn la_liste_hostile_est_refusee() {
        // Un script seul passe (liste toute en PowerShell), et deux scripts différents aussi ; le même deux fois, non.
        assert!(valide(&[script(1)]));
        assert!(valide(&[script(1), POINT.to_string(), script(2)]));
        assert!(!valide(&[script(1), script(1)]));
        let meme = ligne_script(&empreinte(1), r"C:\x\corrections\correction-autre.ps1");
        assert!(!valide(&[script(1), meme]));
        // Ni vide, ni trop longue (513 lignes), ni une ligne démesurée, ni une ligne inconnue.
        assert!(!valide(&[]));
        assert!(valide(&vec![ligne_programme("sfc-scannow", None); LIGNES_MAX]));
        assert!(!valide(&vec![ligne_programme("sfc-scannow", None); LIGNES_MAX + 1]));
        assert!(!valide(&[POINT.repeat(LIGNE_MAX)]));
        assert!(!valide(&[POINT.to_string(), "ipconfig /flushdns".to_string()]));
        // Les programmes : seulement la forme exacte.
        for l in [
            "vanguard:programme dism-restorehealth",
            "vanguard:programme chkdsk-scan-systeme",
            "vanguard:programme dism-retirer-fonction SMB1Protocol-Client",
            "vanguard:programme dism-retirer-fonction MicrosoftWindowsPowerShellV2Root",
        ] {
            assert!(valide(&[l.to_string()]), "{l}");
            assert_eq!(analyser_programme(l).map(|a| a.ligne()).as_deref(), Some(l));
        }
        for l in [
            "vanguard:programme inconnu",
            "vanguard:programme ",
            "vanguard:programme",
            "vanguard:programme  sfc-scannow",
            "vanguard:programme sfc-scannow ",
            "vanguard:programme sfc-scannow /offbootdir=C:\\",
            "vanguard:programme sfc-scannow x",
            "vanguard:programme SFC-SCANNOW",
            "VANGUARD:PROGRAMME sfc-scannow",
            "vanguard:programme sfc-scannow\0",
            "vanguard:programme sfc-scannow\n",
            "vanguard:programme ../sfc-scannow",
            "vanguard:programme ..\\System32\\cmd",
            "vanguard:programme dism-retirer-fonction",
            "vanguard:programme dism-retirer-fonction smb1protocol-client",
            "vanguard:programme dism-retirer-fonction SMB1Protocol-Client x",
            "vanguard:programme dism-retirer-fonction SMB1Protocol",
            "vanguard:programme dism-retirer-fonction Microsoft-Windows-Subsystem-Linux",
            "vanguard:programme dism-ajouter-netfx3 NetFx3",
            "vanguard:programme dism-restorehealth\u{a0}",
            "vanguard:programme aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(analyser_programme(l).is_none(), "{l:?}");
            assert!(!valide(&[l.to_string()]), "{l:?}");
        }
        assert!(analyser_programme(&format!("vanguard:programme {}", "a".repeat(PROGRAMME_MAX))).is_none());
    }

    #[test]
    fn la_table_est_bien_formee() {
        let mut ids = std::collections::HashSet::new();
        for p in PROGRAMMES {
            assert!(ids.insert(p.id), "{}", p.id);
            assert!(
                !p.id.is_empty()
                    && p.id.len() <= 40
                    && p.id
                        .bytes()
                        .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-'),
                "{}",
                p.id
            );
            assert!(p.reussites.contains(&0) && !p.fr.is_empty() && !p.en.is_empty());
            let a_un_nom = p.arguments.iter().any(|a| matches!(a, Argument::Nom(_)));
            assert_eq!(a_un_nom, !p.noms.is_empty(), "{}", p.id);
            // Ni séparateur ni espace dans un exe ou un argument : rien ne s'y glisse en passant par une ligne de
            // commande.
            assert!(p.exe.strip_suffix(".exe").is_some_and(|n| !n.is_empty()) && !p.exe.contains(['\\', '/', ' ']));
            for a in p.arguments {
                if let Argument::Fixe(t) | Argument::Nom(t) = a {
                    assert!(!t.is_empty() && !t.contains([' ', '"', '\'', ';', '&', '|']), "{t}");
                }
            }
        }
        for n in FONCTIONS_A_RETIRER {
            assert!(n.bytes().all(|o| o.is_ascii_alphanumeric() || o == b'-'), "{n}");
        }
    }

    /// Pour Wine (le chemin par script) : chaque programme par son chemin complet, jamais par son seul nom, que
    /// PowerShell chercherait dans le PATH.
    #[test]
    fn chaque_programme_a_son_equivalent_powershell_complet() {
        for p in PROGRAMMES {
            let nom = p.noms.first().copied();
            let a = analyser_programme(&ligne_programme(p.id, nom)).unwrap();
            let ps = a.powershell();
            let attendu = match p.dossier {
                Dossier::Systeme32 => format!(r#"& "$env:SystemRoot\System32\{}" "#, p.exe),
                Dossier::Defender => format!(r#"& "$env:SystemDrive\Program Files\Windows Defender\{}" "#, p.exe),
            };
            assert!(ps.starts_with(&attendu), "{ps}");
            assert!(!a.commande().contains('$'), "{}", a.commande());
        }
        let chkdsk = analyser_programme("vanguard:programme chkdsk-scan-systeme").unwrap();
        assert_eq!(
            chkdsk.powershell(),
            r#"& "$env:SystemRoot\System32\chkdsk.exe" $env:SystemDrive /scan; if ($LASTEXITCODE -in 1, 2) { $global:LASTEXITCODE = 0 }"#
        );
        assert_eq!(chkdsk.arguments("D:"), ["D:", "/scan"]);
        assert!(chkdsk.reussite(1) && chkdsk.reussite(2) && !chkdsk.reussite(3));
        // 3 : ni fait ni échoué, à finir au redémarrage ; aucun autre programme n'a ce troisième état.
        assert!(chkdsk.au_redemarrage(3) && !chkdsk.au_redemarrage(0) && !chkdsk.au_redemarrage(1));
        assert!(
            PROGRAMMES
                .iter()
                .all(|p| p.id == "chkdsk-scan-systeme" || p.au_redemarrage.is_empty())
        );
        assert!(
            PROGRAMMES
                .iter()
                .all(|p| p.au_redemarrage.iter().all(|c| !p.reussites.contains(c)))
        );
        let smb = analyser_programme("vanguard:programme dism-retirer-fonction SMB1Protocol-Client").unwrap();
        assert_eq!(
            smb.commande(),
            "dism.exe /Online /Disable-Feature /FeatureName:SMB1Protocol-Client /NoRestart"
        );
        assert!(smb.reussite(3010) && !smb.reussite(1));
        // ipconfig et netsh winhttp, autrefois par leur seul nom dans le script administrateur : leur chemin dans
        // System32, leurs arguments fixes.
        for (id, commande) in [
            ("ipconfig-flushdns", "ipconfig.exe /flushdns"),
            ("ipconfig-release", "ipconfig.exe /release"),
            ("ipconfig-renew", "ipconfig.exe /renew"),
            ("netsh-winhttp-reset-proxy", "netsh.exe winhttp reset proxy"),
            // net accounts (comptes.rs), lui aussi par son nom autrefois. powercfg n'est plus ici : sans
            // administrateur, il passe par Vanguard non élevé (`COMPTE`, « alimentation-performances »).
            (
                "net-accounts-verrouillage",
                "net.exe accounts /lockoutthreshold:10 /lockoutduration:10 /lockoutwindow:10",
            ),
            ("net-accounts-longueur-8", "net.exe accounts /minpwlen:8"),
        ] {
            let a = analyser_programme(&format!("{PROGRAMME}{id}")).unwrap();
            assert_eq!(a.commande(), commande);
            assert!(
                a.powershell().starts_with(r#"& "$env:SystemRoot\System32\"#),
                "{}",
                a.powershell()
            );
        }
    }

    #[test]
    fn le_script_a_une_forme_fixe() {
        let bon = script(0xAB);
        assert_eq!(
            analyser_script(&bon)
                .map(|s| ligne_script(&s.empreinte, &s.chemin))
                .as_deref(),
            Some(bon.as_str())
        );
        for chemin in [
            r"corrections\correction-1.ps1",
            r"C:\x\autre\correction-1.ps1",
            r"C:\x\corrections\script.ps1",
            r"C:\x\corrections\correction-1.ps1.txt",
            r"C:\x\corrections\..\corrections\correction-1.ps1",
            r"C:\x\corrections\.\correction-1.ps1",
            "C:\\x\\corrections\\correction-1.ps1\0",
        ] {
            assert!(
                analyser_script(&ligne_script(&empreinte(1), chemin)).is_none(),
                "{chemin}"
            );
        }
        let hex_majuscule = bon.replace("5c", "5C");
        assert!(analyser_script(&hex_majuscule).is_none());
        assert!(analyser_script(&bon.replacen(&empreinte(0xAB), &empreinte(0xAB).to_lowercase(), 1)).is_none());
        assert!(analyser_script(&format!("{bon}0")).is_none());
        assert!(analyser_script(&format!("{bon} ")).is_none());
    }

    #[test]
    fn les_etats_se_lisent() {
        assert_eq!(raison_du_script(1, &[true, false, true]), "code=1 etats=101");
        assert_eq!(etats_du_script("echec code=1 etats=101"), Some(vec![true, false, true]));
        assert_eq!(etats_du_script("echec code=-1 etats="), Some(vec![]));
        assert_eq!(etats_du_script("echec code=1 etats=10 suite"), Some(vec![true, false]));
        for r in [
            "ok",
            "echec code=6 script modifié",
            "echec code=x etats=1",
            "echec code=1 etats=12",
            "echec etats=1",
            "echec code=1  etats=1",
        ] {
            assert_eq!(etats_du_script(r), None, "{r}");
        }
        let long = format!("echec code=1 etats={}", "1".repeat(ETATS_MAX + 1));
        assert_eq!(etats_du_script(&long), None);
        assert_eq!(
            raison_du_script(1, &vec![true; ETATS_MAX + 9]).len(),
            "code=1 etats=".len() + ETATS_MAX
        );
    }

    /// Les bornes recopiées ici (module sans dépendance, pour le banc de fuzzing) restent celles des ordres.
    /// Les actes : seulement un nom et une action de la table, écrits à l'identique. Un service de sécurité, une
    /// action qui n'est pas permise à ce service, une espace de trop, une casse changée, un identifiant inconnu : refusés,
    /// et jamais confiés à un autre validateur.
    #[test]
    fn les_actes_hors_table_sont_refuses() {
        for bonne in [
            "vanguard:service SSDPSRV arreter",
            "vanguard:service RemoteRegistry desactive",
            "vanguard:service wuauserv manuel",
            "vanguard:service w32time reactiver",
            "vanguard:service AudioEndpointBuilder redemarrer",
            "vanguard:vider temp-windows",
            "vanguard:vider wu-telechargements",
            "vanguard:vider-file-impression",
            "vanguard:mettre-de-cote software-distribution",
            "vanguard:mettre-de-cote catroot2",
        ] {
            assert!(est_un_acte(bonne), "{bonne}");
            assert_eq!(analyser_acte(bonne).map(|a| a.ligne()).as_deref(), Some(bonne));
        }
        let long = format!("vanguard:service SSDPSRV arreter{}", " ".repeat(ACTE_MAX));
        for mauvaise in [
            "vanguard:service WinDefend arreter",
            "vanguard:service MpsSvc desactive",
            "vanguard:service ssdpsrv arreter",
            "vanguard:service SSDPSRV supprimer",
            "vanguard:service SSDPSRV Arreter",
            "vanguard:service wuauserv desactive",
            "vanguard:service RemoteRegistry demarrer",
            "vanguard:service UsoSvc desactive",
            "vanguard:service SSDPSRV  arreter",
            "vanguard:service  SSDPSRV arreter",
            "vanguard:service SSDPSRV arreter ",
            "vanguard:service SSDPSRV",
            "vanguard:service ",
            "vanguard:service SSDPSRV arrêter",
            "vanguard:service SSDPSRV\tarreter",
            "vanguard:vider ",
            "vanguard:vider temp",
            "vanguard:vider temp-windows ",
            r"vanguard:vider C:\Windows\Temp",
            "vanguard:vider ../temp-windows",
            "vanguard:vider-file-impression ",
            "vanguard:vider-file-impressions",
            "vanguard:mettre-de-cote System32",
            "vanguard:mettre-de-cote catroot2 ",
            "vanguard:mettre-de-cote Catroot2",
            long.as_str(),
        ] {
            assert!(analyser_acte(mauvaise).is_none(), "{mauvaise:?}");
            // Refusée, elle n'est pas pour autant un « autre » : la liste entière tombe.
            assert!(est_un_acte(mauvaise), "{mauvaise:?}");
            assert!(valider(&[mauvaise.to_string()], |_| Some(())).is_none(), "{mauvaise:?}");
        }
        // Le seul acte permis est accepté dans une liste, en plus d'une ligne d'un autre module.
        let liste = valider(&lignes(&[POINT, "vanguard:service SSDPSRV arreter"]), |l| {
            (l == POINT).then_some(())
        })
        .expect("liste valide");
        assert!(matches!(&liste[1], Ligne::Acte(Acte::Service(s)) if s.nom == "SSDPSRV" && s.durcit));
    }

    const G: &str = "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}";

    /// Le pare-feu et les réseaux : des clés et des valeurs de listes fermées, chaque clé une fois, dans l'ordre de la
    /// table ; un GUID de la seule forme `{8-4-4-4-12}` en majuscules. Tout le reste est refusé, et pas confié à un
    /// autre validateur.
    #[test]
    fn les_actes_du_pare_feu_hors_forme_sont_refuses() {
        let bonnes = [
            "vanguard:pare-feu-actif".to_string(),
            "vanguard:pare-feu-public actif=oui,entrant-bloque=oui,regles-entrantes=non".to_string(),
            "vanguard:pare-feu-public regles-entrantes=non".to_string(),
            "vanguard:pare-feu-public regles-entrantes=absent".to_string(),
            "vanguard:pare-feu-public entrant-bloque=non,regles-entrantes=oui".to_string(),
            format!("vanguard:reseau-categorie {G} public"),
            format!("vanguard:reseau-categorie {G} prive"),
            // Le GUID nul a la forme : la grammaire le laisse passer, le processus élevé le refuse ensuite faute de
            // profil réseau de ce GUID (`pare_feu::categorie`).
            "vanguard:reseau-categorie {00000000-0000-0000-0000-000000000000} public".to_string(),
        ];
        for bonne in &bonnes {
            assert!(est_un_acte(bonne), "{bonne}");
            assert_eq!(analyser_acte(bonne).map(|a| a.ligne()).as_ref(), Some(bonne));
        }
        let long = format!(
            "vanguard:pare-feu-public regles-entrantes=non{}",
            ",regles-entrantes=non".repeat(ACTE_MAX / 20)
        );
        assert!(long.len() > ACTE_MAX);
        let mauvaises = [
            // Couper le pare-feu ne s'écrit pas, ni « non configuré » pour allumé ou les entrées par défaut.
            "vanguard:pare-feu-public actif=non".to_string(),
            "vanguard:pare-feu-public actif=absent".to_string(),
            "vanguard:pare-feu-public entrant-bloque=absent".to_string(),
            // La même clé deux fois, un autre ordre, rien, une clé ou une valeur hors liste, la casse.
            "vanguard:pare-feu-public regles-entrantes=non,regles-entrantes=oui".to_string(),
            "vanguard:pare-feu-public regles-entrantes=non,actif=oui".to_string(),
            // Sans aucun réglage : rien, ou une virgule seule.
            "vanguard:pare-feu-public ".to_string(),
            "vanguard:pare-feu-public ,".to_string(),
            "vanguard:pare-feu-public sortant-bloque=oui".to_string(),
            "vanguard:pare-feu-public actif=peut-etre".to_string(),
            "vanguard:pare-feu-public regles-entrantes=Non".to_string(),
            "vanguard:pare-feu-public Regles-entrantes=non".to_string(),
            "vanguard:pare-feu-public regles-entrantes=False".to_string(),
            // Une espace, une virgule ou un signe de trop ; une espace après la virgule aussi (aucune tolérance : la
            // ligne se réécrit à l'identique ou elle est refusée).
            "vanguard:pare-feu-public actif=oui, entrant-bloque=oui".to_string(),
            "vanguard:pare-feu-public actif=oui,".to_string(),
            "vanguard:pare-feu-public ,actif=oui".to_string(),
            "vanguard:pare-feu-public actif==oui".to_string(),
            "vanguard:pare-feu-public actif=oui ".to_string(),
            "vanguard:pare-feu-public  actif=oui".to_string(),
            "vanguard:pare-feu-actif ".to_string(),
            "vanguard:pare-feu-actif public".to_string(),
            "vanguard:pare-feu-actifs".to_string(),
            long,
            // La catégorie : le domaine n'en est pas une ; la casse, l'espace, le GUID mal formé.
            format!("vanguard:reseau-categorie {G} domaine"),
            format!("vanguard:reseau-categorie {G} Public"),
            format!("vanguard:reseau-categorie {G} private"),
            format!("vanguard:reseau-categorie {G}  public"),
            format!("vanguard:reseau-categorie {G} public "),
            format!("vanguard:reseau-categorie {G}"),
            format!("vanguard:reseau-categorie {} public", G.to_lowercase()),
            "vanguard:reseau-categorie 0B8C2F4E-1A2B-4C3D-9E8F-001122334455 public".to_string(),
            "vanguard:reseau-categorie {0B8C2F4E1A2B-4C3D-9E8F-001122334455} public".to_string(),
            "vanguard:reseau-categorie {0B8C2F4E-1A2B-4C3D-9E8F-00112233445} public".to_string(),
            "vanguard:reseau-categorie {0B8C2F4E-1A2B-4C3D-9E8F-0011223344556} public".to_string(),
            "vanguard:reseau-categorie {0B8C2F4G-1A2B-4C3D-9E8F-001122334455} public".to_string(),
            "vanguard:reseau-categorie {+B8C2F4E-1A2B-4C3D-9E8F-001122334455} public".to_string(),
            "vanguard:reseau-categorie {0B8C2F4E-1A2B-4C3D-9E8F-001122334455}' public".to_string(),
            "vanguard:reseau-categorie {0B8C2F4E-1A2B-4C3D-9E8F-001122334455}}; public".to_string(),
            "vanguard:reseau-categorie {0B8C2F4É-1A2B-4C3D-9E8F-001122334455} public".to_string(),
            "vanguard:reseau-categorie {} public".to_string(),
        ];
        // Sans l'espace, ce n'est pas même le préfixe d'un acte : refusé aussi.
        assert!(analyser_acte("vanguard:pare-feu-public").is_none());
        let nul = analyser_acte("vanguard:reseau-categorie {00000000-0000-0000-0000-000000000000} public");
        assert!(matches!(nul, Some(Acte::ReseauCategorie(r)) if r.guid == GuidReseau(0)));
        for mauvaise in &mauvaises {
            assert!(analyser_acte(mauvaise).is_none(), "{mauvaise:?}");
            assert!(est_un_acte(mauvaise), "{mauvaise:?}");
            assert!(
                valider(std::slice::from_ref(mauvaise), |_| Some(())).is_none(),
                "{mauvaise:?}"
            );
        }
        // Les constructeurs refusent ce que l'analyse refuse, et écrivent le GUID dans sa forme unique.
        assert!(ligne_pare_feu_public(&[]).is_none());
        assert!(ligne_pare_feu_public(&[(ReglagePublic::Actif, ValeurPublic::Non)]).is_none());
        assert!(
            ligne_pare_feu_public(&[
                (ReglagePublic::ReglesEntrantes, ValeurPublic::Non),
                (ReglagePublic::ReglesEntrantes, ValeurPublic::Oui),
            ])
            .is_none()
        );
        assert_eq!(
            ligne_reseau_categorie(&G.to_lowercase(), Categorie::Public),
            Some(format!("vanguard:reseau-categorie {G} public"))
        );
        assert!(ligne_reseau_categorie("{pas un guid}", Categorie::Public).is_none());
        assert_eq!(GuidReseau::lire(G).map(GuidReseau::texte).as_deref(), Some(G));
        assert_eq!(
            GuidReseau::lire(G),
            Some(GuidReseau(0x0B8C_2F4E_1A2B_4C3D_9E8F_0011_2233_4455))
        );
    }

    /// Ce que le mode Wi-Fi public et le bilan posent durcit ; les remises affaiblissent, dites telles dans la console
    /// élevée ; jamais les deux. Toutes les combinaisons du profil Public sont essayées.
    #[test]
    fn les_actes_du_pare_feu_durcissent_ou_affaiblissent() {
        let a = |l: &str| analyser_acte(l).expect(l);
        assert!(a("vanguard:pare-feu-actif").durcit());
        assert!(a("vanguard:pare-feu-public actif=oui,entrant-bloque=oui,regles-entrantes=non").durcit());
        assert!(a(&format!("vanguard:reseau-categorie {G} public")).durcit());
        // Un seul réglage présent, à sa valeur durcie : la ligne durcit (les absents ne comptent pas).
        let seul = a("vanguard:pare-feu-public entrant-bloque=oui");
        assert!(seul.durcit() && !seul.affaiblit());
        for remise in [
            "vanguard:pare-feu-public entrant-bloque=non".to_string(),
            "vanguard:pare-feu-public regles-entrantes=oui".to_string(),
            "vanguard:pare-feu-public regles-entrantes=absent".to_string(),
            "vanguard:pare-feu-public actif=oui,regles-entrantes=absent".to_string(),
            format!("vanguard:reseau-categorie {G} prive"),
        ] {
            let acte = a(&remise);
            assert!(acte.affaiblit() && !acte.durcit(), "{remise}");
        }
        let valeurs = [
            None,
            Some(ValeurPublic::Oui),
            Some(ValeurPublic::Non),
            Some(ValeurPublic::Absent),
        ];
        let mut vues = 0;
        for actif in valeurs {
            for entrant in valeurs {
                for regles in valeurs {
                    let reglages: Vec<(ReglagePublic, ValeurPublic)> = ReglagePublic::TOUS
                        .into_iter()
                        .zip([actif, entrant, regles])
                        .filter_map(|(r, v)| Some((r, v?)))
                        .collect();
                    let Some(ligne) = ligne_pare_feu_public(&reglages) else {
                        assert!(
                            reglages.is_empty()
                                || actif.is_some_and(|v| v != ValeurPublic::Oui)
                                || entrant == Some(ValeurPublic::Absent),
                            "{reglages:?}"
                        );
                        continue;
                    };
                    vues += 1;
                    assert!(ligne.len() <= ACTE_MAX);
                    let acte = a(&ligne);
                    assert!(acte.durcit() != acte.affaiblit(), "{ligne}");
                    let Acte::PareFeuPublic(p) = acte else {
                        panic!("{ligne}")
                    };
                    assert!(p.reglages().eq(reglages.iter().copied()), "{ligne}");
                }
            }
        }
        // Allumé : absent ou oui (2) ; entrées par défaut : absent, oui, non (3) ; règles : 4 ; moins la ligne vide.
        assert_eq!(vues, 2 * 3 * 4 - 1);
        for l in ["vanguard:service SSDPSRV arreter", "vanguard:vider temp-windows"] {
            assert!(!(a(l).durcit() && a(l).affaiblit()), "{l}");
        }
    }

    /// Le chemin par script (Wine) : les commandes d'avant, à l'identique, pour le bilan, la réparation et le mode
    /// Wi-Fi public.
    #[test]
    fn les_actes_du_pare_feu_ont_leur_equivalent_powershell() {
        let ps = |l: &str| analyser_acte(l).expect(l).powershell();
        assert_eq!(
            ps("vanguard:pare-feu-actif"),
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
        );
        assert_eq!(
            ps("vanguard:pare-feu-public actif=oui,entrant-bloque=oui,regles-entrantes=non"),
            "Set-NetFirewallProfile -Profile Public -PolicyStore PersistentStore -Enabled True -DefaultInboundAction Block -AllowInboundRules False"
        );
        assert_eq!(
            ps("vanguard:pare-feu-public entrant-bloque=non,regles-entrantes=absent"),
            "Set-NetFirewallProfile -Profile Public -PolicyStore PersistentStore -DefaultInboundAction Allow -AllowInboundRules NotConfigured"
        );
        let public = ps(&format!("vanguard:reseau-categorie {G} public"));
        assert!(
            public.contains(&format!("InstanceID -eq '{G}'"))
                && public.contains("-NetworkCategory Public")
                && public.contains(&format!(
                    r"'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{G}' -Name Category -Value 0 -Type DWord"
                )),
            "{public}"
        );
        let prive = ps(&format!("vanguard:reseau-categorie {G} prive"));
        assert!(
            prive.contains("-NetworkCategory Private") && prive.contains("-Value 1 -Type DWord"),
            "{prive}"
        );
    }

    /// La table : des noms sans espace ni caractère hors ASCII, chacun une fois, chaque action une fois par service,
    /// jamais à la fois « durcit » et « affaiblit », aucun service de sécurité, wuauserv jamais désactivé ; chaque
    /// constructeur rend une ligne relue à l'identique.
    #[test]
    fn la_table_des_services_est_bien_formee() {
        let mut noms = std::collections::HashSet::new();
        for s in SERVICES {
            assert!(noms.insert(s.nom.to_ascii_lowercase()), "{} deux fois", s.nom);
            assert!(
                !s.nom.is_empty() && s.nom.bytes().all(|o| o.is_ascii_alphanumeric()),
                "{}",
                s.nom
            );
            assert!(
                ![
                    "windefend",
                    "mpssvc",
                    "wscsvc",
                    "sense",
                    "bfe",
                    "eventlog",
                    "termservice",
                    "sshd"
                ]
                .contains(&s.nom.to_ascii_lowercase().as_str()),
                "{}",
                s.nom
            );
            let mut actions = std::collections::HashSet::new();
            for p in s.permis {
                assert!(actions.insert(p.action.mot()), "{} {:?} deux fois", s.nom, p.action);
                assert!(!(p.durcit && p.affaiblit), "{} {:?}", s.nom, p.action);
                let l = ligne_service(s.nom, p.action);
                assert!(l.len() <= ACTE_MAX);
                let Some(Acte::Service(g)) = analyser_acte(&l) else {
                    panic!("{l}");
                };
                assert!(g.nom == s.nom && g.action == p.action && g.durcit == p.durcit && g.affaiblit == p.affaiblit);
            }
            for a in Action::TOUTES {
                let l = format!("{SERVICE}{} {}", s.nom, a.mot());
                assert_eq!(analyser_acte(&l).is_some(), actions.contains(a.mot()), "{l}");
            }
        }
        let wu = SERVICES.iter().find(|s| s.nom == "wuauserv").unwrap();
        assert!(!wu.permis.iter().any(|p| p.action == Action::Desactive));
        for v in Vidable::TOUS {
            assert!(matches!(analyser_acte(&ligne_vider(v)), Some(Acte::Vider(w)) if w == v));
            assert!(
                v.sous_windows()
                    .iter()
                    .all(|c| !c.is_empty() && !c.contains(['\\', '/', '.', ':']))
            );
        }
        for c in ACoter::TOUS {
            assert!(matches!(analyser_acte(&ligne_mettre_de_cote(c)), Some(Acte::MettreDeCote(d)) if d == c));
            assert!(
                c.sous_windows()
                    .iter()
                    .all(|p| !p.is_empty() && !p.contains(['\\', '/', '.', ':']))
            );
        }
        assert!(matches!(
            analyser_acte(&ligne_vider_file_impression()),
            Some(Acte::ViderFileImpression)
        ));
    }

    /// Le chemin par script (Wine) : les commandes d'avant pour les services ; pour les dossiers, celui de Windows
    /// lu par .NET, une ligne arrêtée s'il est vide, jamais `$env:` ni un chemin écrit par le parent.
    #[test]
    fn chaque_acte_a_son_equivalent_powershell() {
        let ps = |l: &str| analyser_acte(l).expect(l).powershell();
        assert_eq!(ps("vanguard:service SSDPSRV arreter"), "Stop-Service SSDPSRV -Force");
        assert_eq!(ps("vanguard:service Spooler demarrer"), "Start-Service Spooler");
        assert_eq!(
            ps("vanguard:service AudioEndpointBuilder redemarrer"),
            "Restart-Service -Force AudioEndpointBuilder"
        );
        assert_eq!(
            ps("vanguard:service SSDPSRV desactive"),
            "Set-Service SSDPSRV -StartupType Disabled"
        );
        assert_eq!(
            ps("vanguard:service wuauserv manuel"),
            "Set-Service wuauserv -StartupType Manual"
        );
        assert_eq!(
            ps("vanguard:service UsoSvc auto"),
            "Set-Service UsoSvc -StartupType Automatic"
        );
        assert_eq!(
            ps("vanguard:service w32time reactiver"),
            "if ((Get-Service w32time).StartType -eq 'Disabled') { Set-Service w32time -StartupType Manual }"
        );
        for l in [
            "vanguard:vider temp-windows",
            "vanguard:vider wu-telechargements",
            "vanguard:vider-file-impression",
            "vanguard:mettre-de-cote software-distribution",
            "vanguard:mettre-de-cote catroot2",
        ] {
            let c = ps(l);
            assert!(
                c.starts_with("$w = [Environment]::GetFolderPath('Windows'); if (-not $w) { throw "),
                "{c}"
            );
            assert!(
                !c.contains("$env:") && c.contains("-LiteralPath (Join-Path $w '"),
                "{c}"
            );
        }
        assert!(
            ps("vanguard:vider-file-impression").ends_with(r"'System32\spool\PRINTERS') -File | Remove-Item -Force")
        );
        assert!(ps("vanguard:mettre-de-cote catroot2").contains(r#""catroot2.$(Get-Date -Format yyyyMMddHHmm)""#));
    }

    /// Le plus long verbe qui porte un nom, suivi du plus long nom : la borne des actes nommés, ni plus ni moins.
    #[test]
    fn borne_des_noms() {
        for verbe in [
            IFEO_DEBUGGER,
            IFEO_DEBUGGER_32,
            IFEO_SILENCIEUX,
            IFEO_SILENCIEUX_32,
            SERVICE_GUILLEMETS,
        ] {
            assert!(verbe.len() + 4 * NOM_MAX < ACTE_NOM_MAX, "{verbe}");
        }
        assert_eq!(
            ACTE_NOM_MAX,
            DEFENDER_EXCLUSION_RETIRER.len() + "extension ".len() + 4 * NOM_MAX
        );
        assert!(GenreExclusion::TOUS.iter().all(|g| g.mot().len() <= "extension".len()));
        let nom = "a".repeat(NOM_MAX);
        let l = ligne_ifeo_silencieux(Vue::Wow32, &nom).expect("260 unités admises");
        assert_eq!(l.len(), IFEO_SILENCIEUX_32.len() + 4 * NOM_MAX);
        assert!(matches!(analyser_acte(&l), Some(Acte::IfeoSilencieux(Vue::Wow32, n)) if n.texte() == nom));
        let l = ligne_defender_exclusion_retirer(GenreExclusion::Extension, &nom).expect("260 unités admises");
        assert_eq!(l.len(), ACTE_NOM_MAX);
        assert!(
            matches!(analyser_acte(&l), Some(Acte::DefenderExclusionRetirer(GenreExclusion::Extension, e)) if e.texte() == nom)
        );
        assert_eq!(
            ligne_defender_exclusion_retirer(GenreExclusion::Chemin, &format!("{nom}a")),
            None
        );
        // 261 unités : refusé à la construction et à la lecture (même par un verbe court).
        let trop = "a".repeat(NOM_MAX + 1);
        assert_eq!(ligne_ifeo_debugger(Vue::Windows, &trop), None);
        let hex: String = "6100".repeat(NOM_MAX + 1);
        assert!(analyser_acte(&format!("{IFEO_DEBUGGER}{hex}")).is_none());
        assert!(analyser_acte(&format!("{SERVICE_GUILLEMETS}{hex}")).is_none());
        // Un caractère hors du plan de base compte pour deux unités UTF-16.
        let emoji = "\u{1F600}".repeat(NOM_MAX / 2);
        assert!(ligne_service_guillemets(&emoji).is_some());
        assert!(ligne_service_guillemets(&format!("{emoji}a")).is_none());
    }

    /// Les noms du registre : en hexadécimal UTF-16 petit-boutiste minuscule, relus à l'identique ; tout nom qui
    /// changerait de clé (séparateur, « .. », NUL, contrôle) ou que Windows refuse dans un nom de fichier est refusé à
    /// la construction (le bilan le signale, à retirer à la main) comme à la lecture, avant toute demande d'UAC.
    #[test]
    fn les_noms_du_registre_ont_une_forme_fermee() {
        assert_eq!(NomFichier::nouveau("s").map(|n| n.hex()).as_deref(), Some("7300"));
        assert_eq!(
            ligne_ifeo_debugger(Vue::Windows, "sethc.exe").as_deref(),
            Some("vanguard:ifeo-debugger 730065007400680063002e00650078006500")
        );
        for (nom, vue) in [
            ("sethc.exe", Vue::Windows),
            ("Bonjour Service", Vue::Wow32),
            ("Intel(R) Outil ’x’ é", Vue::Windows),
            ("notepad.exe", Vue::Wow32),
        ] {
            for l in [
                ligne_ifeo_debugger(vue, nom),
                ligne_ifeo_silencieux(vue, nom),
                ligne_service_guillemets(nom),
            ] {
                let l = l.expect(nom);
                assert!(l.is_ascii() && !l.contains(['\n', '\r']), "{l}");
                assert!(est_un_acte(&l), "{l}");
                let a = analyser_acte(&l).expect(&l);
                assert_eq!(a.ligne(), l);
                assert!(a.durcit() && !a.affaiblit());
                assert!(valider(std::slice::from_ref(&l), |_| None::<()>).is_some(), "{l}");
            }
        }
        for piege in [
            "",
            ".",
            "..",
            r"..\sethc.exe",
            r"a\b",
            "a/b",
            "a..b",
            "a\0b",
            "a\nb",
            "a\rb",
            "a\tb",
            "a\u{7f}b",
            "a\u{85}b",
            "c:x",
            "a*",
            "a?",
            "a\"b",
            "a<b",
            "a>b",
            "a|b",
        ] {
            assert!(NomFichier::nouveau(piege).is_none(), "{piege:?}");
            assert_eq!(ligne_ifeo_debugger(Vue::Windows, piege), None, "{piege:?}");
            assert_eq!(ligne_ifeo_silencieux(Vue::Wow32, piege), None, "{piege:?}");
            assert_eq!(ligne_service_guillemets(piege), None, "{piege:?}");
            // Forgée par un parent hostile, la ligne est refusée à la lecture aussi.
            let hex = piege
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .fold(String::new(), |mut s, o| {
                    let _ = write!(s, "{o:02x}");
                    s
                });
            for verbe in [
                IFEO_DEBUGGER,
                IFEO_DEBUGGER_32,
                IFEO_SILENCIEUX,
                IFEO_SILENCIEUX_32,
                SERVICE_GUILLEMETS,
            ] {
                let l = format!("{verbe}{hex}");
                assert!(analyser_acte(&l).is_none(), "{l}");
                assert!(est_un_acte(&l), "{l}");
                assert!(valider(std::slice::from_ref(&l), |_| Some(())).is_none(), "{l}");
            }
        }
        // L'hexadécimal hostile : majuscules, longueur impaire ou hors groupes de quatre, demi-paire, espace, vide.
        for hex in [
            "730065007400680063002E00650078006500",
            "730",
            "73006",
            "730065",
            "00d8",
            "00dc4100",
            "7300 6500",
            " 7300",
            "7300 ",
            "",
            "zz00",
            "+300",
            "-300",
        ] {
            assert!(NomFichier::lire(hex).is_none(), "{hex:?}");
            assert!(analyser_acte(&format!("{IFEO_DEBUGGER}{hex}")).is_none(), "{hex:?}");
        }
        // Verbe mal écrit : jamais un autre acte, jamais confié à un autre validateur.
        for l in [
            "vanguard:ifeo-debugger-64 7300",
            "vanguard:ifeo-debugger-327300",
            "vanguard:ifeo-debugger  7300",
            "vanguard:service-guillemets",
            "vanguard:service-guillemets ",
        ] {
            assert!(analyser_acte(l).is_none(), "{l}");
        }
        // Un acte ordinaire reste borné à 256 octets.
        let long = format!("vanguard:service SSDPSRV arreter{}", " ".repeat(ACTE_NOM_MAX - 40));
        assert!(analyser_acte(&long).is_none());
    }

    /// Chaque réglage n'admet que ce qui protège : une ligne forgée qui couperait le temps réel, le cloud, l'accès
    /// contrôlé, la protection réseau ou PUA est refusée, comme toute valeur hors de la liste.
    #[test]
    fn defender_seulement_vers_le_plus_sur() {
        for (r, v) in [
            (ReglageDefender::TempsReel, ValeurDefender::Actif),
            (ReglageDefender::Maps, ValeurDefender::Avance),
            (ReglageDefender::Cfa, ValeurDefender::Bloquer),
            (ReglageDefender::Cfa, ValeurDefender::Audit),
            (ReglageDefender::Np, ValeurDefender::Bloquer),
            (ReglageDefender::Np, ValeurDefender::Audit),
            (ReglageDefender::Pua, ValeurDefender::Bloquer),
            (ReglageDefender::Pua, ValeurDefender::Audit),
        ] {
            let l = ligne_defender(r, v).unwrap();
            let a = analyser_acte(&l).unwrap();
            assert!(matches!(a, Acte::Defender(r2, v2) if r2 == r && v2 == v), "{l}");
            assert!(a.durcit() && !a.affaiblit() && est_un_acte(&l), "{l}");
        }
        assert_eq!(
            ligne_defender(ReglageDefender::TempsReel, ValeurDefender::Actif).unwrap(),
            "vanguard:defender temps-reel actif"
        );
        assert_eq!(
            ligne_defender(ReglageDefender::TempsReel, ValeurDefender::Bloquer),
            None
        );
        assert_eq!(ligne_defender(ReglageDefender::Maps, ValeurDefender::Audit), None);
        for l in [
            "vanguard:defender temps-reel non",
            "vanguard:defender temps-reel coupe",
            "vanguard:defender temps-reel inactif",
            "vanguard:defender temps-reel 0",
            "vanguard:defender temps-reel bloquer",
            "vanguard:defender temps-reel audit",
            "vanguard:defender maps 0",
            "vanguard:defender maps coupe",
            "vanguard:defender maps base",
            "vanguard:defender maps bloquer",
            "vanguard:defender cfa 0",
            "vanguard:defender cfa coupe",
            "vanguard:defender cfa desactive",
            "vanguard:defender cfa actif",
            "vanguard:defender np desactive",
            "vanguard:defender np 0",
            "vanguard:defender pua 0",
            "vanguard:defender pua coupe",
            "vanguard:defender pua avertir",
            "vanguard:defender behavior bloquer",
            "vanguard:defender Temps-reel actif",
            "vanguard:defender temps-reel Actif",
            "vanguard:defender temps-reel actif ",
            "vanguard:defender  temps-reel actif",
            "vanguard:defender temps-reel  actif",
            "vanguard:defender temps-reel",
            "vanguard:defender ",
            "vanguard:defender",
            "vanguard:defender cfa bloquer,maps 0",
        ] {
            assert!(analyser_acte(l).is_none(), "{l}");
        }
        // Même construit à la main hors de la liste, un acte ne vise qu'une valeur qui protège.
        assert_eq!(ReglageDefender::TempsReel.attendue(ValeurDefender::Bloquer), 0);
        assert_eq!(ReglageDefender::Maps.attendue(ValeurDefender::Audit), 2);
        for r in ReglageDefender::TOUS {
            for v in [
                ValeurDefender::Actif,
                ValeurDefender::Avance,
                ValeurDefender::Bloquer,
                ValeurDefender::Audit,
            ] {
                assert!(r.rang(i64::from(r.attendue(v))) > 0, "{r:?} {v:?}");
            }
        }
    }

    /// Le processus élevé n'écrit que vers plus sûr : la valeur lue d'abord, comparée par rang.
    #[test]
    fn defender_ne_baisse_jamais() {
        let (cfa, np, maps, rtp) = (
            ReglageDefender::Cfa,
            ReglageDefender::Np,
            ReglageDefender::Maps,
            ReglageDefender::TempsReel,
        );
        // Coupé : écrit ; déjà bloqué : rien, même pour « audit ».
        assert!(cfa.a_ecrire(ValeurDefender::Bloquer, 0) && cfa.a_ecrire(ValeurDefender::Audit, 0));
        assert!(!cfa.a_ecrire(ValeurDefender::Audit, 1) && !cfa.a_ecrire(ValeurDefender::Bloquer, 1));
        // Audit des disques seuls (4) → bloquer : écrit ; disques bloqués (3) → audit : rien.
        assert!(cfa.a_ecrire(ValeurDefender::Bloquer, 4) && !cfa.a_ecrire(ValeurDefender::Audit, 3));
        assert!(!np.a_ecrire(ValeurDefender::Audit, 1) && np.a_ecrire(ValeurDefender::Bloquer, 2));
        // Une valeur inconnue compte pour la moins sûre.
        assert!(np.a_ecrire(ValeurDefender::Audit, 7) && cfa.a_ecrire(ValeurDefender::Audit, -1));
        assert!(maps.a_ecrire(ValeurDefender::Avance, 0) && maps.a_ecrire(ValeurDefender::Avance, 1));
        assert!(!maps.a_ecrire(ValeurDefender::Avance, 2));
        // DisableRealtimeMonitoring : vrai (1) → écrire faux ; déjà faux → rien.
        assert!(rtp.a_ecrire(ValeurDefender::Actif, 1) && !rtp.a_ecrire(ValeurDefender::Actif, 0));
        assert_eq!(rtp.valeur_wmi(ValeurDefender::Actif), ValeurWmi::Booleen(false));
        assert_eq!(maps.valeur_wmi(ValeurDefender::Avance), ValeurWmi::Octet(2));
        assert_eq!(np.valeur_wmi(ValeurDefender::Audit), ValeurWmi::Octet(2));
        assert_eq!(cfa.valeur_wmi(ValeurDefender::Bloquer), ValeurWmi::Octet(1));
        // ASR : absente, coupée, audit, avertit, bloque.
        assert!(ModeAsr::Bloquer.a_ecrire(None) && ModeAsr::Bloquer.a_ecrire(Some(0)));
        assert!(ModeAsr::Bloquer.a_ecrire(Some(2)) && ModeAsr::Bloquer.a_ecrire(Some(6)));
        assert!(!ModeAsr::Bloquer.a_ecrire(Some(1)));
        assert!(ModeAsr::Audit.a_ecrire(None) && ModeAsr::Audit.a_ecrire(Some(0)));
        assert!(!ModeAsr::Audit.a_ecrire(Some(1)) && !ModeAsr::Audit.a_ecrire(Some(6)));
        assert!(!ModeAsr::Audit.a_ecrire(Some(2)));
    }

    /// Une règle ASR des listes d'Optimiser, en minuscules : une autre est refusée ; aucune ne se retire.
    #[test]
    fn defender_asr_de_la_liste() {
        for id in ASR_BASE.iter().chain(&ASR_BUREAUTIQUE) {
            for m in ModeAsr::TOUS {
                let l = ligne_defender_asr(id, m).unwrap();
                let a = analyser_acte(&l).unwrap();
                assert!(matches!(a, Acte::DefenderAsr(i, m2) if i == *id && m2 == m), "{l}");
                assert!(a.durcit() && !a.affaiblit());
            }
        }
        let id = ASR_BASE[0];
        assert_eq!(
            ligne_defender_asr(id, ModeAsr::Bloquer).unwrap(),
            format!("vanguard:defender-asr {id} bloquer")
        );
        // Une règle écartée (processus d'une clé USB : bloquerait Vanguard), une inventée, une en majuscules.
        assert_eq!(
            ligne_defender_asr("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", ModeAsr::Bloquer),
            None
        );
        for l in [
            "vanguard:defender-asr b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 bloquer",
            "vanguard:defender-asr 00000000-0000-0000-0000-000000000000 bloquer",
            // Retirer une règle connue couperait une protection posée par la personne ou une stratégie.
            "vanguard:defender-asr 56a863a9-875e-4185-98a7-b882c64b5ce5 retirer",
            "vanguard:defender-asr 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 retirer",
            "vanguard:defender-asr 56A863A9-875E-4185-98A7-B882C64B5CE5 bloquer",
            "vanguard:defender-asr {56a863a9-875e-4185-98a7-b882c64b5ce5} bloquer",
            "vanguard:defender-asr 56a863a9-875e-4185-98a7-b882c64b5ce5 coupe",
            "vanguard:defender-asr 56a863a9-875e-4185-98a7-b882c64b5ce5 0",
            "vanguard:defender-asr 56a863a9-875e-4185-98a7-b882c64b5ce5 avertir",
            "vanguard:defender-asr 56a863a9-875e-4185-98a7-b882c64b5ce5",
            "vanguard:defender-asr 56a863a9-875e-4185-98a7-b882c64b5ce5 bloquer ",
            "vanguard:defender-asr  56a863a9-875e-4185-98a7-b882c64b5ce5 bloquer",
        ] {
            assert!(analyser_acte(l).is_none(), "{l}");
        }
        // Les paramètres de la méthode : un seul identifiant, une seule action (Add), jamais Set (toute la liste).
        let a = analyser_acte(&ligne_defender_asr(id, ModeAsr::Audit).unwrap()).unwrap();
        assert_eq!(
            methode_defender(&a),
            Some((
                "Add",
                vec![
                    (
                        "AttackSurfaceReductionRules_Ids",
                        ValeurWmi::Textes(vec![id.to_string()])
                    ),
                    ("AttackSurfaceReductionRules_Actions", ValeurWmi::Octets(vec![2])),
                ]
            ))
        );
        let a = analyser_acte("vanguard:defender pua bloquer").unwrap();
        assert_eq!(
            methode_defender(&a),
            Some(("Set", vec![("PUAProtection", ValeurWmi::Octet(1))]))
        );
        let a = analyser_acte("vanguard:defender temps-reel actif").unwrap();
        assert_eq!(
            methode_defender(&a),
            Some(("Set", vec![("DisableRealtimeMonitoring", ValeurWmi::Booleen(false))]))
        );
        assert_eq!(methode_defender(&Acte::DefenderMenacesRetirer), None);
        assert_eq!(methode_defender(&Acte::PareFeuActif), None);
    }

    /// Une exclusion à retirer : en hexadécimal minuscule, de l'UTF-16 valide, sans contrôle ; relue à l'identique.
    #[test]
    fn defender_exclusion_a_retirer() {
        let l = ligne_defender_exclusion_retirer(GenreExclusion::Chemin, "C:\\").unwrap();
        assert_eq!(l, "vanguard:defender-exclusion-retirer chemin 43003a005c00");
        let a = analyser_acte(&l).unwrap();
        assert!(matches!(&a, Acte::DefenderExclusionRetirer(GenreExclusion::Chemin, e) if e.texte() == "C:\\"));
        assert!(a.durcit() && !a.affaiblit());
        assert_eq!(
            methode_defender(&a),
            Some((
                "Remove",
                vec![("ExclusionPath", ValeurWmi::Textes(vec!["C:\\".to_string()]))]
            ))
        );
        // Les séparateurs et les caractères interdits dans un nom de fichier sont admis ici (un chemin, « *.exe »).
        for (g, t) in [
            (GenreExclusion::Processus, "C:\\Outils d'été\\powershell.exe"),
            (GenreExclusion::Extension, "*.exe"),
            (GenreExclusion::Chemin, "%TEMP%\\*"),
            (GenreExclusion::Chemin, "D:\\\u{1F600}"),
        ] {
            let l = ligne_defender_exclusion_retirer(g, t).unwrap();
            assert!(
                matches!(analyser_acte(&l), Some(Acte::DefenderExclusionRetirer(g2, e)) if g2 == g && e.texte() == t)
            );
        }
        assert_eq!(ligne_defender_exclusion_retirer(GenreExclusion::Chemin, ""), None);
        assert_eq!(
            ligne_defender_exclusion_retirer(GenreExclusion::Chemin, "C:\\\nx"),
            None
        );
        assert_eq!(ligne_defender_exclusion_retirer(GenreExclusion::Chemin, "C:\0"), None);
        for l in [
            // Majuscules, demi-paire, NUL, contrôle, longueur impaire, genre inconnu, espaces de trop.
            "vanguard:defender-exclusion-retirer chemin 43003A005C00",
            "vanguard:defender-exclusion-retirer chemin 00d8",
            "vanguard:defender-exclusion-retirer chemin 43000000",
            "vanguard:defender-exclusion-retirer chemin 43000a00",
            "vanguard:defender-exclusion-retirer chemin 43003a005c0",
            "vanguard:defender-exclusion-retirer dossier 43003a005c00",
            "vanguard:defender-exclusion-retirer Chemin 43003a005c00",
            "vanguard:defender-exclusion-retirer chemin  43003a005c00",
            "vanguard:defender-exclusion-retirer chemin 43003a005c00 ",
            "vanguard:defender-exclusion-retirer chemin ",
            "vanguard:defender-exclusion-retirer chemin",
            "vanguard:defender-exclusion-retirer ",
        ] {
            assert!(analyser_acte(l).is_none(), "{l}");
        }
        let trop = format!("{DEFENDER_EXCLUSION_RETIRER}chemin {}", "6100".repeat(NOM_MAX + 1));
        assert!(analyser_acte(&trop).is_none());
    }

    #[test]
    fn defender_menaces_et_powershell() {
        let l = ligne_defender_menaces_retirer();
        let a = analyser_acte(&l).unwrap();
        assert!(matches!(a, Acte::DefenderMenacesRetirer) && !a.durcit() && !a.affaiblit());
        for l in [
            "vanguard:defender-menaces-retirer ",
            "vanguard:defender-menaces-retirer tout",
            "vanguard:defender-menaces",
        ] {
            assert!(analyser_acte(l).is_none(), "{l}");
        }
        // Aucune commande de Defender dans un script : sous Wine, l'erreur est dite.
        for l in [
            l,
            "vanguard:defender maps avance".to_string(),
            ligne_defender_asr(ASR_BASE[1], ModeAsr::Bloquer).unwrap(),
            ligne_defender_exclusion_retirer(GenreExclusion::Extension, ".exe").unwrap(),
        ] {
            let ps = analyser_acte(&l).unwrap().powershell();
            assert!(ps.starts_with("throw ") && !ps.contains("Mp"), "{ps}");
        }
        // Les verbes ne se recouvrent pas : chacun est refusé sous la forme d'un autre.
        assert!(analyser_acte("vanguard:defender asr 56a863a9-875e-4185-98a7-b882c64b5ce5 bloquer").is_none());
        assert!(analyser_acte("vanguard:defender-asr temps-reel actif").is_none());
        // Une liste qui en porte une forgée est refusée en entier.
        let lignes = vec![
            "vanguard:defender cfa bloquer".to_string(),
            "vanguard:defender cfa 0".to_string(),
        ];
        assert!(valider(&lignes, |_| Some(())).is_none());
    }

    /// La traduction PowerShell (Wine) : celle que le bilan écrivait avant, la clé entre apostrophes doublées.
    #[test]
    fn les_actes_du_registre_ont_leur_equivalent_powershell() {
        let ps = |l: Option<String>| analyser_acte(&l.unwrap()).unwrap().powershell();
        assert_eq!(
            ps(ligne_ifeo_debugger(Vue::Windows, "sethc.exe")),
            r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger"
        );
        assert_eq!(
            ps(ligne_ifeo_debugger(Vue::Wow32, "it's.exe")),
            r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\it''s.exe' -Name Debugger"
        );
        assert_eq!(
            ps(ligne_ifeo_silencieux(Vue::Windows, "notepad.exe")),
            r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe' -Name MonitorProcess"
        );
        assert_eq!(
            ps(ligne_ifeo_silencieux(Vue::Wow32, "a’b.exe")),
            r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\a’’b.exe' -Name MonitorProcess"
        );
        assert_eq!(
            ps(ligne_service_guillemets("Mon ’Outil")),
            r#"$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\Mon ’’Outil'; $r = Get-Item -LiteralPath $k -ErrorAction Stop; $t = $r.GetValueKind('ImagePath'); $c = [string]$r.GetValue('ImagePath', $null, 'DoNotExpandEnvironmentNames'); if (($t -ne 'String' -and $t -ne 'ExpandString') -or $c.StartsWith('"') -or $c -notmatch '^(.+?\.exe)(\s.*)?$') { throw 'ImagePath already quoted or not understood' }; $n = '"' + $Matches[1] + '"' + $Matches[2]; if ([Environment]::ExpandEnvironmentVariables($c) -notmatch '^(.+?\.exe)(\s.*)?$' -or [Environment]::ExpandEnvironmentVariables($n) -cne ('"' + $Matches[1] + '"' + $Matches[2])) { throw 'ImagePath would change beyond the quotes' }; Set-ItemProperty -LiteralPath $k -Name ImagePath -Value $n -Type $t"#
        );
        // La copie de ps_texte est celle de commande.rs.
        for t in ["a'b", "‘’‚‛", "x\u{2019}\u{2019}", "rien", "é'’"] {
            assert_eq!(ps_texte(t), crate::commande::ps_texte(t), "{t}");
        }
    }

    #[test]
    fn les_bornes_sont_celles_des_ordres() {
        use crate::protection::blocage::ordres;
        assert_eq!(LIGNE_MAX, ordres::LIGNE_MAX);
        assert_eq!(LIGNES_MAX, ordres::LIGNES_MAX);
    }

    // ------------------------------------------------------------ le compte

    #[test]
    fn chaque_geste_du_compte_se_relit_a_l_identique() {
        for v in VALEURS_COMPTE {
            let l = ligne_compte(v.id).unwrap();
            assert_eq!(analyser_compte(&l), Some(GesteCompte::Valeur(v)), "{l}");
            assert!(!v.cle.starts_with(['\\', '/']) && !v.cle.contains(".."), "{}", v.id);
        }
        let ids: std::collections::HashSet<&str> = VALEURS_COMPTE.iter().map(|v| v.id).collect();
        assert_eq!(ids.len(), VALEURS_COMPTE.len(), "identifiant en double");
        for version in OFFICE_VERSIONS {
            for (programme, _) in OFFICE_PROGRAMMES {
                let l = ligne_macros(version, programme).unwrap();
                let g = analyser_compte(&l).unwrap();
                assert_eq!(g.ligne(), l);
                assert!(g.durcit());
                assert_eq!(g.donnee(), Some(Donnee::Dword(2)));
                assert_eq!(
                    g.valeur().unwrap().0,
                    format!(r"Software\Microsoft\Office\{version}\{programme}\Security")
                );
            }
        }
        assert_eq!(ligne_macros("17.0", "word"), None);
        assert_eq!(ligne_macros("16.0", "outlook"), None);
        let a = ligne_alimentation();
        assert_eq!(a, "vanguard:compte alimentation-performances");
        assert_eq!(analyser_compte(&a), Some(GesteCompte::Alimentation));
        assert_eq!(GesteCompte::Alimentation.valeur(), None);
    }

    #[test]
    fn une_valeur_run_se_designe_par_son_nom_exact() {
        let nom: Vec<u16> = "Mise à jour".encode_utf16().collect();
        let l = ligne_run_retirer(false, &nom).unwrap();
        assert_eq!(l, format!("{COMPTE}run-retirer run {}", hex_utf16(&nom)));
        let g = analyser_compte(&l).unwrap();
        assert_eq!(g.valeur(), Some((CLE_RUN.to_string(), nom.clone())));
        assert_eq!(g.donnee(), Some(Donnee::Retirer));
        // Décision 4 b) : un retrait de démarrage n'est pas une protection.
        assert!(!g.durcit());
        // La valeur par défaut, et une demi-paire (un nom que le registre admet) : désignées telles quelles.
        let defaut = ligne_run_retirer(true, &[]).unwrap();
        assert_eq!(defaut, "vanguard:compte run-retirer runonce defaut");
        assert_eq!(
            analyser_compte(&defaut).unwrap().valeur(),
            Some((CLE_RUNONCE.to_string(), Vec::new()))
        );
        let demi = ligne_run_retirer(false, &[0xd800, 0x41]).unwrap();
        assert_eq!(analyser_compte(&demi).unwrap().ligne(), demi);
        // Refusés : unité nulle, nom trop long, hexadécimal en majuscules, groupe incomplet, clé hors liste.
        assert_eq!(ligne_run_retirer(false, &[0x41, 0]), None);
        assert_eq!(ligne_run_retirer(false, &vec![0x41; RUN_NOM_MAX + 1]), None);
        let longue = ligne_run_retirer(true, &vec![0x41; RUN_NOM_MAX]).unwrap();
        assert_eq!(longue.len(), COMPTE_LIGNE_MAX);
        assert_eq!(analyser_compte(&longue).unwrap().ligne(), longue);
        assert!(!valide(std::slice::from_ref(&longue)));
        // À l'écran, un nom très long est coupé.
        let montre = analyser_compte(&longue).unwrap().texte(true);
        assert!(montre.contains(&format!("{}…", "A".repeat(NOM_MONTRE_MAX))) && montre.len() < 400);
        for faux in [
            "vanguard:compte run-retirer run 4100",
            "vanguard:compte run-retirer run 0000",
            "vanguard:compte run-retirer run 4A00",
            "vanguard:compte run-retirer run 410",
            "vanguard:compte run-retirer run ",
            "vanguard:compte run-retirer runservices 4100",
            "vanguard:compte run-retirer run 4100 ",
            "vanguard:compte run-retirer run defaut ",
        ] {
            let attendu = faux == "vanguard:compte run-retirer run 4100";
            assert_eq!(analyser_compte(faux).is_some(), attendu, "{faux}");
        }
    }

    #[test]
    fn une_ligne_du_compte_hors_de_sa_forme_est_refusee() {
        for faux in [
            "vanguard:compte ",
            "vanguard:compte inconnu",
            "vanguard:compte jeux-mode ",
            " vanguard:compte jeux-mode",
            "vanguard:compte  jeux-mode",
            "vanguard:compte JEUX-MODE",
            "vanguard:compte\tjeux-mode",
            "vanguard:compte macros-office 16.0 Word",
            "vanguard:compte macros-office 16.0  word",
            "vanguard:compte macros-office 16.0",
            "vanguard:compte alimentation-performances ",
            "vanguard:comptejeux-mode",
            "vanguard:compte jeux-modé",
        ] {
            assert_eq!(analyser_compte(faux), None, "{faux}");
        }
    }

    #[test]
    fn le_processus_eleve_refuse_tout_geste_du_compte() {
        // Même bien formée : un geste du compte se fait sous le compte de la personne, jamais derrière l'UAC.
        for v in VALEURS_COMPTE {
            let l = lignes(&[&ligne_compte(v.id).unwrap()]);
            assert!(valider(&l, |_| Some(())).is_none(), "{l:?}");
        }
        let l = lignes(&[&ligne_alimentation()]);
        assert!(valider(&l, |_| Some(())).is_none());
        assert!(valider(&lignes(&["vanguard:compte inconnu"]), |_| Some(())).is_none());
        // Et aucune ne passe pour un programme, un acte ou un script.
        for v in VALEURS_COMPTE {
            let l = ligne_compte(v.id).unwrap();
            assert!(analyser_programme(&l).is_none() && !est_un_acte(&l) && analyser_script(&l).is_none());
        }
    }

    #[test]
    fn swap_effect_seul_change_le_reste_est_garde() {
        assert_eq!(avec_swap_effect(""), "SwapEffectUpgradeEnable=1;");
        assert_eq!(
            avec_swap_effect("VRROptimizeEnable=0;SwapEffectUpgradeEnable=0;"),
            "VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;"
        );
        assert_eq!(
            avec_swap_effect("SwapEffectUpgradeEnable=0;VRROptimizeEnable=1;"),
            "VRROptimizeEnable=1;SwapEffectUpgradeEnable=1;"
        );
        // Casse ignorée et « ; » final absent, comme le -replace de PowerShell d'avant.
        assert_eq!(
            avec_swap_effect("AutoHDREnable=1;swapeffectupgradeenable=0"),
            "AutoHDREnable=1;SwapEffectUpgradeEnable=1;"
        );
        // Déjà bon : relu, il redonne le même texte (rien à écrire).
        let bon = "VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;";
        assert_eq!(avec_swap_effect(bon), bon);
        // Sans chiffre après « = », rien n'est retiré ; un texte non ASCII est gardé tel quel.
        assert_eq!(
            avec_swap_effect("SwapEffectUpgradeEnable=;é"),
            "SwapEffectUpgradeEnable=;é;SwapEffectUpgradeEnable=1;"
        );
        // Un réglage d'avant sans « ; » final ne se colle pas au nôtre.
        assert_eq!(
            avec_swap_effect("VRROptimizeEnable=0"),
            "VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;"
        );
        assert_eq!(
            avec_swap_effect("SwapEffectUpgradeEnable=0;AutoHDREnable=1"),
            "AutoHDREnable=1;SwapEffectUpgradeEnable=1;"
        );
    }

    // ------------------------------------------------------------ la séparation

    fn est_point(l: &str) -> bool {
        l == POINT
    }

    /// Le plan, §3.8 : la séparation ne change pas l'ordre. Le point de restauration d'abord, puis le reste du travail
    /// élevé, en un seul passage ; ensuite seulement les écritures du compte, dans ce processus.
    #[test]
    fn point_puis_eleve_puis_compte() {
        let mode = ligne_compte("jeux-mode").unwrap();
        let souris = ligne_compte("souris-vitesse").unwrap();
        let correctifs = vec![
            lignes(&[POINT, &mode, "vanguard:gaming-hags", &souris]),
            lignes(&["Set-Service x"]),
        ];
        let journal = std::cell::RefCell::new(Vec::<String>::new());
        let (resultats, notes) = lancer_separe(
            &correctifs,
            est_point,
            |envoyes| {
                journal.borrow_mut().push(format!("eleve {envoyes:?}"));
                Some(PassageEleve {
                    resultats: vec![true; envoyes.len()],
                    notes: envoyes.to_vec(),
                    arrete: false,
                })
            },
            |g| {
                journal.borrow_mut().push(g.ligne());
                FaitCompte {
                    reussi: true,
                    rien: false,
                    avant: Some("absent".into()),
                }
            },
        )
        .unwrap();
        let journal = journal.into_inner();
        // Un seul passage élevé : le point, seul, en tête ; le travail élevé du premier correctif ; puis le second.
        assert_eq!(journal.len(), 3, "{journal:?}");
        assert_eq!(
            journal[0],
            format!(
                "eleve {:?}",
                vec![
                    lignes(&[POINT]),
                    lignes(&["vanguard:gaming-hags"]),
                    lignes(&["Set-Service x"])
                ]
            )
        );
        assert_eq!(journal[1..], [mode.clone(), souris.clone()]);
        assert_eq!(resultats, [true, true]);
        assert_eq!(
            notes[0],
            [
                POINT.to_string(),
                "vanguard:gaming-hags".into(),
                format!("{mode} (avant : absent)"),
                format!("{souris} (avant : absent)"),
            ]
        );
        assert_eq!(notes[1], ["Set-Service x"]);
    }

    #[test]
    fn rien_d_eleve_aucun_passage_eleve() {
        let mode = ligne_compte("jeux-mode").unwrap();
        let mut eleve_appele = false;
        let (resultats, notes) = lancer_separe(
            &[lignes(&[&mode]), Vec::new()],
            est_point,
            |_| {
                eleve_appele = true;
                None
            },
            |_| FaitCompte {
                reussi: true,
                rien: true,
                avant: None,
            },
        )
        .unwrap();
        assert!(!eleve_appele, "aucune demande d'administrateur pour un geste du compte");
        assert_eq!(resultats, [true, true]);
        // Déjà bon : rien à noter.
        assert_eq!(notes, [Vec::<String>::new(), Vec::new()]);
    }

    /// Un point refusé, ou tout arrêté à la demande : aucun geste du compte, et ce n'est pas « fait ».
    #[test]
    fn point_refuse_ou_arret_aucun_geste_du_compte() {
        let mode = ligne_compte("jeux-mode").unwrap();
        let correctifs = vec![lignes(&[POINT, "vanguard:gaming-hags", &mode]), lignes(&[&mode])];
        for (point_ok, arrete) in [(false, false), (true, true), (false, true)] {
            let mut faits = 0;
            let (resultats, notes) = lancer_separe(
                &correctifs,
                est_point,
                |envoyes| {
                    Some(PassageEleve {
                        resultats: vec![point_ok, false],
                        notes: envoyes.to_vec(),
                        arrete,
                    })
                },
                |_| {
                    faits += 1;
                    FaitCompte {
                        reussi: true,
                        rien: false,
                        avant: None,
                    }
                },
            )
            .unwrap();
            assert_eq!(faits, 0, "point_ok={point_ok} arrete={arrete}");
            assert_eq!(resultats, [false, false]);
            assert_eq!(notes[1], std::slice::from_ref(&mode));
        }
        // Le passage élevé n'a rien fait (dit par lui) : rien du compte non plus.
        let mut faits = 0;
        let r = lancer_separe(
            &correctifs,
            est_point,
            |_| None,
            |_| {
                faits += 1;
                FaitCompte {
                    reussi: true,
                    rien: false,
                    avant: None,
                }
            },
        );
        assert!(r.is_none() && faits == 0);
    }

    #[test]
    fn un_echec_eleve_n_empeche_pas_le_compte_mais_le_correctif_echoue() {
        let mode = ligne_compte("jeux-mode").unwrap();
        let souris = ligne_compte("souris-vitesse").unwrap();
        let correctifs = vec![lignes(&[POINT, "Set-Service x", &mode]), lignes(&[&souris])];
        let (resultats, notes) = lancer_separe(
            &correctifs,
            est_point,
            |envoyes| {
                Some(PassageEleve {
                    resultats: vec![true, false],
                    notes: envoyes.to_vec(),
                    arrete: false,
                })
            },
            |g| FaitCompte {
                reussi: g.ligne() != souris,
                rien: false,
                avant: None,
            },
        )
        .unwrap();
        assert_eq!(resultats, [false, false]);
        assert_eq!(notes[1], std::slice::from_ref(&souris));
        // Un correctif dont tout le reste était déjà bon : il ne reste que le point, rien à noter.
        let (resultats, notes) = lancer_separe(
            &[lignes(&[POINT, &mode])],
            est_point,
            |envoyes| {
                (envoyes == [lignes(&[POINT])]).then(|| PassageEleve {
                    resultats: vec![true],
                    notes: vec![vec![format!("{POINT} (ok sans-point)")]],
                    arrete: false,
                })
            },
            |_| FaitCompte {
                reussi: true,
                rien: true,
                avant: None,
            },
        )
        .unwrap();
        assert_eq!(resultats, [true]);
        assert_eq!(notes, [Vec::<String>::new()]);
    }

    #[test]
    fn separer_range_chaque_ligne_une_fois() {
        let mode = ligne_compte("jeux-mode").unwrap();
        let s = separer(
            &[lignes(&[POINT, &mode, "vanguard:compte faux", "Set-Service x", POINT])],
            est_point,
        );
        // Une ligne du compte mal formée reste au travail élevé, où `lignes_pour_eleve` la refuse avant l'UAC.
        assert_eq!(
            s,
            [Separe {
                points: vec![0, 4],
                eleves: vec![2, 3],
                compte: vec![1],
            }]
        );
    }
}
