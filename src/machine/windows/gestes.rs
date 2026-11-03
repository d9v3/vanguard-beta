//! La grammaire des lignes que le processus élevé (`eleve`) lit du Vanguard non élevé, pour ce qui n'est ni une
//! correction de la table (`corrections`) ni un ordre du blocage : le script PowerShell vérifié par empreinte
//! (`vanguard:script`), les programmes fixes de Windows (`vanguard:programme`), lancés par leur chemin complet avec
//! des arguments figés, sans shell, et les actes sur Windows lui-même (`vanguard:service`, `vanguard:vider`,
//! `vanguard:vider-file-impression`, `vanguard:mettre-de-cote`, `vanguard:pare-feu-actif`, `vanguard:pare-feu-public`,
//! `vanguard:reseau-categorie`, `vanguard:ifeo-debugger[-32]`, `vanguard:ifeo-silencieux[-32]`,
//! `vanguard:service-guillemets`, `vanguard:defender`, `vanguard:defender-asr`, `vanguard:defender-exclusion-retirer`,
//! `vanguard:defender-menaces-retirer`, `vanguard:hosts-ecrire`, `vanguard:dns-auto`, `vanguard:dns-serveurs`,
//! `vanguard:compte-desactiver`, `vanguard:certificat-retirer`, `vanguard:partage-retirer-acces`), faits
//! par le gestionnaire de services, std::fs, les interfaces COM du pare-feu et des réseaux (`pare_feu`), le registre
//! (`portes`, `services`), WMI (`defender_ecriture`), iphlpapi (`reseau_ecriture`), netapi32 et crypt32
//! (`comptes_ecriture`, `certificats_ecriture`, `partages_ecriture`). Un réglage de Defender n'admet
//! que des valeurs qui protègent : aucune ligne ne peut couper le temps réel ni le cloud. Une nouvelle version du
//! hosts n'admet hors du bloc de Vanguard que des lignes mises en commentaire (`juger_hosts`) ; un serveur DNS, que
//! ceux de la liste fermée (`RESOLVEURS`).
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
    format!("{SCRIPT}{empreinte} {}", chemin_hex(chemin))
}

/// Le script d'une ligne, si et seulement si elle est exactement de sa forme : 64 chiffres hexadécimaux majuscules,
/// une espace, un chemin complet de .ps1 en hexadécimal minuscule. Le chemin est découpé sur `\` à la main (pas par
/// `Path`, qui sous Linux n'y voit pas de séparateur) : « correction-….ps1 » dans un dossier « corrections », sans
/// composant « . » ni « .. ».
pub(crate) fn analyser_script(ligne: &str) -> Option<Script> {
    let (empreinte, hex) = ligne.strip_prefix(SCRIPT)?.split_once(' ')?;
    if !empreinte_majuscule(empreinte) {
        return None;
    }
    let chemin = lire_chemin_hex(hex)?;
    let mut composants = chemin.rsplit('\\');
    let nom = composants.next().unwrap_or_default();
    let dossier = composants.next().unwrap_or_default();
    let ps1 = nom.starts_with("correction-")
        && nom.to_ascii_lowercase().ends_with(".ps1")
        && dossier.eq_ignore_ascii_case("corrections");
    (ps1 && chemin_sur(&chemin) && ligne_script(empreinte, &chemin) == ligne).then(|| Script {
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

// ------------------------------------------------------------------ le réseau

/// Le verbe de l'écriture du fichier hosts : `vanguard:hosts-ecrire <empreinte du hosts lu> <empreinte du fichier
/// préparé> <chemin du fichier préparé en hexadécimal>`. Le processus élevé relit le hosts et le fichier préparé,
/// vérifie les deux empreintes, rejuge la différence (`juger_hosts`), la montre avant l'accord, puis écrit les octets
/// vérifiés en gardant une copie de ceux d'avant (ReplaceFileW).
pub(crate) const HOSTS_ECRIRE: &str = "vanguard:hosts-ecrire ";
/// Le verbe qui remet en automatique (ceux du DHCP) les serveurs DNS d'une carte réseau : `vanguard:dns-auto {GUID}`.
pub(crate) const DNS_AUTO: &str = "vanguard:dns-auto ";
/// Le verbe qui règle les serveurs DNS d'une carte réseau : `vanguard:dns-serveurs {GUID} <IPv4>|<IPv6>`, chaque
/// côté « - » (laissé tel quel), vide (remis en automatique) ou une liste d'adresses de `RESOLVEURS`.
pub(crate) const DNS_SERVEURS: &str = "vanguard:dns-serveurs ";
/// La plus longue ligne `hosts-ecrire` : le verbe, deux empreintes, un chemin de 900 octets en hexadécimal.
pub(crate) const HOSTS_LIGNE_MAX: usize = 2048;
/// Le plus gros fichier hosts admis, avant comme après : 1 Mo. Au-delà, ce n'est pas un hosts que Vanguard réécrit.
pub(crate) const HOSTS_MAX: usize = 1 << 20;
/// Le dossier du fichier préparé (sous celui de Vanguard), et son nom.
pub(crate) const HOSTS_DOSSIER: &str = "hosts-prepare";
pub(crate) const HOSTS_NOM: &str = "hosts";
/// Ce que Vanguard met devant une ligne qui détourne un nom, pour la mettre en commentaire.
pub(crate) const HOSTS_COMMENTE: &str = "# Vanguard : ";
/// La marque de début du bloc des sites bloqués (`protection::sites_bloques`).
pub(crate) const HOSTS_DEBUT: &str = "# >>> Vanguard";
/// La marque de fin du bloc.
pub(crate) const HOSTS_FIN: &str = "# <<< Vanguard <<<";
/// Dans la marque de début : le hosts ne finissait pas par une fin de ligne, Vanguard en a ajouté une.
pub(crate) const HOSTS_FDL_AJOUTEE: &str = "(fin de ligne ajoutée)";
/// La plus longue marque de début admise : celle de Vanguard en fait 150.
const HOSTS_ENTETE_MAX: usize = 512;

/// Les seuls serveurs DNS qu'une ligne peut poser : ceux de « DNS le plus rapide » (`dns_rapide::PUBLICS`, test
/// resolveurs_de_dns_rapide), le Bouclier canadien compris (mode Wi-Fi public). Une ligne forgée ne peut pas envoyer
/// les questions DNS de l'ordinateur vers un serveur choisi par un autre programme. Seule exception : remettre la
/// valeur d'avant (la box, le DNS de l'entreprise), que le processus élevé a lui-même notée en la remplaçant, dans une
/// clé que seul un administrateur écrit (`DNS_AVANT_CLE`) ; il refuse toute autre adresse.
pub(crate) const RESOLVEURS: [&str; 20] = [
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "9.9.9.9",
    "149.112.112.112",
    "2620:fe::fe",
    "2620:fe::9",
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "94.140.14.14",
    "94.140.15.15",
    "2a10:50c0::ad1:ff",
    "2a10:50c0::ad2:ff",
    "149.112.121.20",
    "149.112.122.20",
    "2620:10a:80bb::20",
    "2620:10a:80bc::20",
];
/// La clé de HKLM où le processus élevé note les serveurs DNS hors de `RESOLVEURS` qu'il remplace, valeur
/// « {GUID} v4 » ou « {GUID} v6 » : ce qu'il accepte de remettre en défaisant.
pub(crate) const DNS_AVANT_CLE: &str = r"SOFTWARE\Vanguard\DnsAvant";
/// Au plus quatre serveurs par famille : Windows n'en essaie pas plus, et la liste n'en a pas plus d'un service.
const DNS_PAR_FAMILLE_MAX: usize = 4;

/// Une ligne `vanguard:hosts-ecrire`, relue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostsEcrire {
    /// L'empreinte (SHA-256, hexadécimal majuscule) du hosts lu par Vanguard non élevé.
    pub avant: String,
    /// Celle du fichier préparé.
    pub apres: String,
    /// Le chemin complet du fichier préparé : « hosts » dans un dossier « hosts-prepare ».
    pub chemin: String,
}

impl HostsEcrire {
    fn ligne(&self) -> String {
        format!(
            "{HOSTS_ECRIRE}{} {} {}",
            self.avant,
            self.apres,
            chemin_hex(&self.chemin)
        )
    }

    fn analyser(reste: &str) -> Option<HostsEcrire> {
        let mut champs = reste.split(' ');
        let (avant, apres, hex) = (champs.next()?, champs.next()?, champs.next()?);
        if champs.next().is_some() || !empreinte_majuscule(avant) || !empreinte_majuscule(apres) {
            return None;
        }
        let chemin = lire_chemin_hex(hex)?;
        let mut composants = chemin.rsplit('\\');
        let nom = composants.next().unwrap_or_default();
        let dossier = composants.next().unwrap_or_default();
        (chemin_sur(&chemin) && nom.eq_ignore_ascii_case(HOSTS_NOM) && dossier.eq_ignore_ascii_case(HOSTS_DOSSIER))
            .then(|| HostsEcrire {
                avant: avant.to_string(),
                apres: apres.to_string(),
                chemin,
            })
    }
}

/// Un côté (IPv4 ou IPv6) d'une ligne `vanguard:dns-serveurs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoteDns {
    /// « - » : laissé tel quel.
    Garder,
    /// Vide : remis en automatique (NameServer vide, les serveurs du DHCP).
    Vider,
    /// Ces serveurs, dans l'ordre, de la bonne famille, sans doublon, d'adresse unicast ; hors de `RESOLVEURS`, seulement
    /// la valeur d'avant notée (`hors_liste`, jugé par le processus élevé).
    Serveurs(Vec<std::net::IpAddr>),
}

impl CoteDns {
    /// Le texte du côté : « - », vide, ou « ip,ip » (la forme de NameServer, virgules comprises).
    pub(crate) fn texte(&self) -> String {
        match self {
            CoteDns::Garder => "-".to_string(),
            CoteDns::Vider => String::new(),
            CoteDns::Serveurs(l) => l.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
        }
    }

    /// La valeur NameServer à écrire ; `None` pour un côté laissé tel quel.
    pub(crate) fn valeur(&self) -> Option<String> {
        match self {
            CoteDns::Garder => None,
            CoteDns::Vider | CoteDns::Serveurs(_) => Some(self.texte()),
        }
    }

    /// Un serveur au moins est-il hors de `RESOLVEURS` ? Le processus élevé n'accepte alors que la valeur d'avant
    /// qu'il a notée pour cette carte et cette famille.
    pub(crate) fn hors_liste(&self) -> bool {
        match self {
            CoteDns::Serveurs(l) => l.iter().any(|ip| !RESOLVEURS.contains(&ip.to_string().as_str())),
            CoteDns::Garder | CoteDns::Vider => false,
        }
    }

    fn lire(t: &str, v6: bool) -> Option<CoteDns> {
        match t {
            "-" => return Some(CoteDns::Garder),
            "" => return Some(CoteDns::Vider),
            _ => {}
        }
        let mut serveurs: Vec<std::net::IpAddr> = Vec::new();
        for s in t.split(',') {
            let ip: std::net::IpAddr = s.parse().ok()?;
            // Écrite à l'identique (pas de zéros en tête, IPv6 en minuscules et abrégée), de la bonne famille, une
            // seule fois, une adresse d'hôte (ni bouclage, ni « 0.0.0.0 », ni multidiffusion, ni IPv4 dans IPv6).
            let hote = match ip {
                std::net::IpAddr::V4(a) => {
                    !a.is_loopback() && !a.is_unspecified() && !a.is_multicast() && !a.is_broadcast()
                }
                std::net::IpAddr::V6(a) => {
                    !a.is_loopback() && !a.is_unspecified() && !a.is_multicast() && a.to_ipv4_mapped().is_none()
                }
            };
            let bonne = ip.to_string() == s && ip.is_ipv6() == v6 && hote && !serveurs.contains(&ip);
            if !bonne || serveurs.len() >= DNS_PAR_FAMILLE_MAX {
                return None;
            }
            serveurs.push(ip);
        }
        Some(CoteDns::Serveurs(serveurs))
    }
}

/// Une ligne `vanguard:dns-serveurs`, relue. Le GUID désigne, le processus élevé juge : il relit que la carte existe
/// dans la liste de Windows (GetAdaptersAddresses), sinon il refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsServeurs {
    pub guid: GuidReseau,
    pub v4: CoteDns,
    pub v6: CoteDns,
}

impl DnsServeurs {
    fn ligne(&self) -> String {
        format!(
            "{DNS_SERVEURS}{} {}|{}",
            self.guid.texte(),
            self.v4.texte(),
            self.v6.texte()
        )
    }

    /// Les deux côtés laissés tels quels ne font rien, et les deux vidés s'écrivent `dns-auto` : une seule ligne par
    /// geste.
    fn analyser(reste: &str) -> Option<DnsServeurs> {
        let (guid, serveurs) = reste.split_once(' ')?;
        let (v4, v6) = serveurs.split_once('|')?;
        let d = DnsServeurs {
            guid: GuidReseau::lire(guid)?,
            v4: CoteDns::lire(v4, false)?,
            v6: CoteDns::lire(v6, true)?,
        };
        let utile = !matches!(
            (&d.v4, &d.v6),
            (CoteDns::Garder, CoteDns::Garder) | (CoteDns::Vider, CoteDns::Vider)
        );
        utile.then_some(d)
    }

    /// L'équivalent PowerShell (Wine), quand les deux côtés sont donnés : la commande d'avant d'Optimiser. Un côté
    /// laissé tel quel n'en a pas : Set-DnsClientServerAddress écrit les deux familles d'un coup.
    fn powershell(&self) -> String {
        let (CoteDns::Vider | CoteDns::Serveurs(_), CoteDns::Vider | CoteDns::Serveurs(_)) = (&self.v4, &self.v6)
        else {
            return SANS_POWERSHELL.to_string();
        };
        let serveurs: Vec<String> = [&self.v4, &self.v6]
            .iter()
            .filter_map(|c| match c {
                CoteDns::Serveurs(l) => Some(l.iter().map(|ip| format!("'{ip}'")).collect::<Vec<_>>()),
                CoteDns::Garder | CoteDns::Vider => None,
            })
            .flatten()
            .collect();
        format!(
            "{}; Set-DnsClientServerAddress -InterfaceIndex $carteDns.ifIndex -ServerAddresses @({})",
            powershell_dns_auto(self.guid),
            serveurs.join(",")
        )
    }
}

/// Une ligne sans équivalent PowerShell : le chemin par script (Wine) s'arrête et le dit.
const SANS_POWERSHELL: &str = "throw 'Vanguard : geste sans équivalent PowerShell'";

/// La remise en automatique par PowerShell (Wine) : la commande d'avant de la remise du DNS.
fn powershell_dns_auto(guid: GuidReseau) -> String {
    format!(
        "$carteDns = Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq '{}' }} | Select-Object -First 1; \
         if (-not $carteDns) {{ throw 'network adapter not found' }}; \
         Set-DnsClientServerAddress -InterfaceIndex $carteDns.ifIndex -ResetServerAddresses",
        guid.texte()
    )
}

/// 64 chiffres hexadécimaux majuscules : une empreinte SHA-256 telle que `sha256_hex` l'écrit.
fn empreinte_majuscule(e: &str) -> bool {
    e.len() == 64 && e.bytes().all(|o| matches!(o, b'0'..=b'9' | b'A'..=b'F'))
}

/// Le chemin en hexadécimal minuscule de ses octets UTF-8 : aucune espace, aucun caractère que la ligne couperait.
fn chemin_hex(chemin: &str) -> String {
    chemin.bytes().fold(String::new(), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

/// Le texte d'un chemin en hexadécimal minuscule ; `None` s'il n'en a pas la forme ou n'est pas de l'UTF-8.
fn lire_chemin_hex(hex: &str) -> Option<String> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
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
    String::from_utf8(octets?).ok()
}

/// Un chemin complet (« X:\… »), sans composant « . » ni « .. », sans NUL ni fin de ligne. Découpé sur `\` et `/` à
/// la main (pas par `Path`, qui sous Linux n'y voit pas de séparateur).
fn chemin_sur(chemin: &str) -> bool {
    let o = chemin.as_bytes();
    let complet = matches!(o, [lecteur, b':', b'\\', _, ..] if lecteur.is_ascii_alphabetic());
    let sans_detour = !chemin.split(['\\', '/']).any(|c| c == "." || c == "..");
    complet && sans_detour && !chemin.contains(['\0', '\n', '\r'])
}

/// La ligne qui écrit le fichier préparé `chemin` à la place du hosts ; `None` si elle n'a pas sa forme.
pub(crate) fn ligne_hosts_ecrire(avant: &str, apres: &str, chemin: &str) -> Option<String> {
    let ligne = HostsEcrire {
        avant: avant.to_string(),
        apres: apres.to_string(),
        chemin: chemin.to_string(),
    }
    .ligne();
    analyser_acte(&ligne).is_some().then_some(ligne)
}

/// La ligne qui remet en automatique le DNS d'une carte ; `None` si le GUID n'a pas sa forme.
pub(crate) fn ligne_dns_auto(guid: &str) -> Option<String> {
    GuidReseau::lire(guid).map(|g| Acte::DnsAuto(g).ligne())
}

/// La ligne qui règle le DNS d'une carte (`None` pour un côté laissé tel quel, `Some("")` pour le remettre en
/// automatique, sinon « ip,ip ») ; `None` si la ligne ne se lit pas (adresse mal écrite, de la mauvaise famille, de
/// bouclage, plus de quatre) ou ne ferait rien. Hors de la liste fermée, elle se lit : seul le processus élevé la
/// juge, contre la valeur d'avant qu'il a notée.
/// Les deux côtés vides donnent `dns-auto`.
pub(crate) fn ligne_dns(guid: &str, v4: Option<&str>, v6: Option<&str>) -> Option<String> {
    if v4 == Some("") && v6 == Some("") {
        return ligne_dns_auto(guid);
    }
    let guid = GuidReseau::lire(guid)?;
    let ligne = format!(
        "{DNS_SERVEURS}{} {}|{}",
        guid.texte(),
        v4.unwrap_or("-"),
        v6.unwrap_or("-")
    );
    analyser_acte(&ligne).is_some().then_some(ligne)
}

/// Ce geste couperait-il une connexion à distance en cours ? Rendre ou redemander l'adresse IP coupe toutes les
/// connexions ; changer les serveurs DNS ou la carte, non, mais une session à distance (Bureau à distance, SSH) n'est
/// jamais exposée à un geste sur le réseau : refusé dès qu'il y en a une, ou que les connexions ne se lisent pas
/// (`sessions` : celles de `gardes::sessions_a_distance`, `None` si illisibles).
pub(crate) fn coupe_une_session(touche_le_reseau: bool, bureau_a_distance: bool, sessions: Option<usize>) -> bool {
    touche_le_reseau && (bureau_a_distance || sessions != Some(0))
}

impl Appel {
    /// Le programme rend-il ou redemande-t-il l'adresse IP (toutes les connexions coupées) ?
    pub(crate) fn coupe_le_reseau(&self) -> bool {
        matches!(self.programme.id, "ipconfig-release" | "ipconfig-renew")
    }
}

// --------------------------------------------------------------- le hosts

/// Pourquoi une nouvelle version du hosts est refusée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefusHosts {
    /// Plus de `HOSTS_MAX` octets.
    TropGros,
    /// Une marque d'ordre des octets UTF-16 ou un octet nul : un hosts en UTF-16, que Vanguard ne réécrit pas.
    Utf16,
    /// Une marque du bloc sans l'autre, deux blocs, ou un bloc « fin de ligne ajoutée » qui n'est pas à la fin.
    BlocAbime,
    /// Une marque de début trop longue ou avec un caractère de contrôle.
    Entete,
    /// Le fichier préparé n'a plus l'empreinte de la ligne (changé après l'avoir préparé, ou pendant la demande
    /// d'administrateur).
    PrepareChange,
    /// Le hosts n'a plus l'empreinte lue par Vanguard non élevé : un autre programme l'a changé entre-temps.
    HostsChange,
    /// Une ligne du bloc qui n'est pas « 0.0.0.0 nom » ni « :: nom » (montrée telle quelle, rendue lisible).
    LigneDuBloc(String),
    /// Un nom que Vanguard ne bloque jamais (mises à jour de Windows, Defender, ses propres mises à jour).
    NomProtege(String),
    /// Une ligne ajoutée hors du bloc.
    LigneAjoutee(String),
    /// Une ligne retirée hors du bloc.
    LigneRetiree(String),
    /// Une ligne changée hors du bloc, autrement qu'en la mettant en commentaire.
    LigneChangee(String),
}

/// Ce qui change dans le hosts, d'après `juger_hosts`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DiffHosts {
    /// Les lignes mises en commentaire, telles qu'elles étaient (sans leur fin de ligne, rendues lisibles).
    pub commentees: Vec<String>,
    /// Les noms bloqués en plus, puis ceux qui ne le sont plus.
    pub ajoutes: Vec<String>,
    pub retires: Vec<String>,
    /// Le bloc de Vanguard était-il là, l'est-il après ?
    pub bloc_avant: bool,
    pub bloc_apres: bool,
}

impl DiffHosts {
    /// Rien ne change (hors la date du bloc).
    pub(crate) fn vide(&self) -> bool {
        self.commentees.is_empty()
            && self.ajoutes.is_empty()
            && self.retires.is_empty()
            && self.bloc_avant == self.bloc_apres
    }
}

/// Les noms que le bloc ne prend jamais : eux et leurs sous-domaines. Bloquer les mises à jour de Windows ou de
/// Defender, la vérification de connexion de Windows, la connexion au compte Microsoft, l'avis de VirusTotal, la
/// révocation des certificats (Let's Encrypt, Google), les DNS chiffrés de la liste ou les mises à jour de Vanguard
/// servirait celui qui forgerait la liste, jamais la personne.
const NOMS_PROTEGES: [&str; 19] = [
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "virustotal.com",
    "lencr.org",
    "pki.goog",
    "windowsupdate.com",
    "windows.com",
    "msftncsi.com",
    "msftconnecttest.com",
    "digicert.com",
    "github.com",
    "githubusercontent.com",
    "abuse.ch",
    "cloudflare-dns.com",
    "quad9.net",
    "dns.google",
    "adguard-dns.com",
    "cira.ca",
];

/// Ce nom est-il un de `NOMS_PROTEGES`, ou un de leurs sous-domaines ?
pub(crate) fn nom_protege(nom: &str) -> bool {
    NOMS_PROTEGES
        .iter()
        .any(|p| nom == *p || nom.strip_suffix(p).is_some_and(|d| d.ends_with('.')))
}

/// Une partie d'une adresse IPv4 écrite à l'ancienne (inet_aton) : décimale, octale si elle commence par 0, hexadécimale
/// après « 0x » ; au moins un chiffre, 32 bits au plus.
fn partie_v4(p: &str) -> Option<u32> {
    let (chiffres, base) = match p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        Some(h) => (h, 16),
        None if p.len() > 1 && p.starts_with('0') => (p.get(1..)?, 8),
        None => (p, 10),
    };
    // from_str_radix admet un « + » de tête : une adresse n'en a jamais.
    if chiffres.is_empty() || !chiffres.bytes().all(|o| char::from(o).is_digit(base)) {
        return None;
    }
    u32::from_str_radix(chiffres, base).ok()
}

/// Une adresse IPv4 écrite à l'ancienne : une à quatre parties séparées par des points, la dernière remplissant les
/// octets qui restent (« 127.1 » = 127.0.0.1, « 2130706433 » = 127.0.0.1, « 0x7f.0.0.1 », « 0177.0.0.1 »).
fn v4_ancienne(t: &str) -> Option<std::net::Ipv4Addr> {
    let parties = t.split('.').map(partie_v4).collect::<Option<Vec<u32>>>()?;
    let (derniere, tete) = parties.split_last()?;
    if tete.len() > 3 || tete.iter().any(|p| *p > 255) {
        return None;
    }
    // Ce qui reste pour la dernière partie : 32 bits moins 8 par partie de tête.
    let bits = 32_u32.checked_sub(8_u32.checked_mul(u32::try_from(tete.len()).ok()?)?)?;
    if bits < 32 && derniere.checked_shr(bits).is_some_and(|reste| reste != 0) {
        return None;
    }
    let tete = tete.iter().fold(0_u32, |a, p| a.wrapping_shl(8) | p);
    let valeur = if bits == 32 {
        *derniere
    } else {
        tete.wrapping_shl(bits) | derniere
    };
    Some(std::net::Ipv4Addr::from(valeur))
}

/// L'adresse d'un mot de hosts, lue au plus large de ce qu'un système peut admettre, puis ramenée à sa forme normale :
/// la forme stricte, l'IPv4 à l'ancienne (`v4_ancienne`), un indice de zone (« %eth0 », « %3 ») retiré, une IPv4
/// écrite en IPv6 (« ::ffff:1.2.3.4 ») rendue en IPv4. Plus large que ce que Windows admet sûrement : une adresse
/// qu'il prendrait ne doit pas échapper au constat ni à la mise en commentaire sous une forme inhabituelle, et un
/// nom qu'il pourrait lire comme une adresse n'entre pas dans le bloc.
pub(crate) fn adresse_hosts(mot: &str) -> Option<std::net::IpAddr> {
    let (adresse, zone) = match mot.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (mot, None),
    };
    if zone.is_some_and(|z| {
        z.is_empty() || z.len() > 64 || !z.bytes().all(|o| o.is_ascii_alphanumeric() || b"_.-".contains(&o))
    }) {
        return None;
    }
    let ip = match adresse.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => std::net::IpAddr::V4(v4_ancienne(adresse)?),
    };
    Some(ip.to_canonical())
}

/// Un nom qu'un fichier hosts peut tenir : minuscules, chiffres, tirets, soulignés, points ; ni une adresse IP sous
/// aucune forme (hosts ne bloque que des noms), ni un nom sans point, 253 octets au plus, chaque étiquette de 1 à 63.
pub(crate) fn nom_hosts_valide(n: &str) -> bool {
    n.len() <= 253
        && n.contains('.')
        && adresse_hosts(n).is_none()
        && n.split('.').all(|e| !e.is_empty() && e.len() <= 63)
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.' || b == b'_')
}

/// Les octets d'une ligne sans ses blancs de fin (fin de ligne comprise).
fn sans_blancs_de_fin(l: &[u8]) -> &[u8] {
    let fin = l
        .iter()
        .rposition(|o| !o.is_ascii_whitespace())
        .map_or(0, |i| i.saturating_add(1));
    l.get(..fin).unwrap_or_default()
}

/// Une ligne rendue lisible pour être montrée : texte (les octets qui n'en sont pas remplacés), sans fin de ligne,
/// coupée à 200 caractères, chaque caractère de contrôle remplacé.
/// Un caractère qui change l'affichage sans se voir : marques de sens d'écriture (une ligne retournée à l'écran),
/// espaces et jointures de largeur nulle, marque d'ordre des octets.
fn invisible(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

fn lisible(l: &[u8]) -> String {
    String::from_utf8_lossy(sans_blancs_de_fin(l))
        .chars()
        .take(200)
        .map(|c| if c.is_control() || invisible(c) { '\u{FFFD}' } else { c })
        .collect()
}

/// Le hosts découpé : les lignes hors du bloc (fin de ligne comprise, celle ajoutée par Vanguard retirée), les noms
/// du bloc et le nombre de blocs.
struct Decoupe<'a> {
    hors: Vec<&'a [u8]>,
    noms: std::collections::BTreeSet<String>,
    blocs: usize,
}

/// Le nom d'une ligne du bloc, si elle est exactement « 0.0.0.0 nom » ou « :: nom », puis sa fin de ligne.
fn nom_du_bloc(l: &[u8]) -> Option<&str> {
    let corps = l.strip_suffix(b"\r\n").or_else(|| l.strip_suffix(b"\n"))?;
    let nom = corps.strip_prefix(b"0.0.0.0 ").or_else(|| corps.strip_prefix(b":: "))?;
    std::str::from_utf8(nom).ok().filter(|n| nom_hosts_valide(n))
}

/// Découpe un hosts. `strict` : celui que Vanguard va écrire, dont chaque ligne du bloc est jugée ; sinon celui lu
/// sur le disque, dont le bloc est retiré ou remplacé tel quel (retirer une ligne ne détourne rien).
fn decouper_hosts(o: &[u8], strict: bool) -> Result<Decoupe<'_>, RefusHosts> {
    if o.len() > HOSTS_MAX {
        return Err(RefusHosts::TropGros);
    }
    if o.starts_with(&[0xFF, 0xFE]) || o.starts_with(&[0xFE, 0xFF]) || o.contains(&0) {
        return Err(RefusHosts::Utf16);
    }
    let mut d = Decoupe {
        hors: Vec::new(),
        noms: std::collections::BTreeSet::new(),
        blocs: 0,
    };
    let mut dedans = false;
    let mut fdl = false;
    let mut apres_fdl = false;
    for l in o.split_inclusive(|&c| c == b'\n') {
        let t = sans_blancs_de_fin(l);
        if apres_fdl {
            // Une ligne après un bloc « fin de ligne ajoutée » : retirer celle-ci collerait deux lignes en une.
            return Err(RefusHosts::BlocAbime);
        }
        if t.starts_with(HOSTS_DEBUT.as_bytes()) {
            if dedans || d.blocs > 0 {
                return Err(RefusHosts::BlocAbime);
            }
            let entete = std::str::from_utf8(t).map_err(|_| RefusHosts::Entete)?;
            if strict && (t.len() > HOSTS_ENTETE_MAX || entete.chars().any(char::is_control)) {
                return Err(RefusHosts::Entete);
            }
            dedans = true;
            d.blocs = d.blocs.saturating_add(1);
            fdl = entete.contains(HOSTS_FDL_AJOUTEE);
            if fdl && let Some(derniere) = d.hors.last_mut() {
                let l = *derniere;
                *derniere = l.strip_suffix(b"\r\n").or_else(|| l.strip_suffix(b"\n")).unwrap_or(l);
            }
        } else if t == HOSTS_FIN.as_bytes() {
            if !dedans {
                return Err(RefusHosts::BlocAbime);
            }
            dedans = false;
            apres_fdl = fdl;
        } else if dedans {
            match nom_du_bloc(l) {
                Some(n) if strict && nom_protege(n) => return Err(RefusHosts::NomProtege(n.to_string())),
                Some(n) => {
                    d.noms.insert(n.to_string());
                }
                None if strict => return Err(RefusHosts::LigneDuBloc(lisible(l))),
                None => {}
            }
        } else {
            d.hors.push(l);
        }
    }
    if dedans {
        return Err(RefusHosts::BlocAbime);
    }
    Ok(d)
}

/// L'adresse d'une ligne que Vanguard peut mettre en commentaire : une adresse IP, puis au moins un nom ; ni un
/// commentaire, ni une adresse de bouclage ou « 0.0.0.0 » / « :: » (listes de blocage, « localhost »). L'adresse est
/// lue sous toutes ses formes et rendue normale (`adresse_hosts`) : « 0x5d.0.0.1 » est jugée comme 93.0.0.1.
fn adresse_commentable(l: &[u8]) -> Option<std::net::IpAddr> {
    let texte = String::from_utf8_lossy(l);
    let mut mots = texte.split('#').next().unwrap_or_default().split_whitespace();
    let ip = adresse_hosts(mots.next()?)?;
    (mots.next().is_some() && !ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// Juge la nouvelle version d'un hosts contre celle lue, octet par octet : hors du bloc de Vanguard, chaque ligne est
/// gardée telle quelle ou mise en commentaire (« # Vanguard : » devant, rien d'autre ne change), aucune n'est
/// ajoutée ni retirée ; le bloc, s'il y en a un, n'a que des lignes « 0.0.0.0 nom » ou « :: nom » d'un nom qui n'est
/// pas protégé. Plus de 1 Mo, ou de l'UTF-16 (marque d'ordre des octets, octet nul), d'un côté ou de l'autre : refusé.
/// Le processus élevé l'appelle sur les octets vérifiés par leur empreinte, le parent avant de demander : la même
/// fonction des deux côtés.
pub(crate) fn juger_hosts(avant: &[u8], apres: &[u8]) -> Result<DiffHosts, RefusHosts> {
    let a = decouper_hosts(avant, false)?;
    let b = decouper_hosts(apres, true)?;
    let mut diff = DiffHosts {
        bloc_avant: a.blocs > 0,
        bloc_apres: b.blocs > 0,
        ajoutes: b.noms.difference(&a.noms).cloned().collect(),
        retires: a.noms.difference(&b.noms).cloned().collect(),
        ..DiffHosts::default()
    };
    for (i, ligne_b) in b.hors.iter().enumerate() {
        let Some(ligne_a) = a.hors.get(i) else {
            return Err(RefusHosts::LigneAjoutee(lisible(ligne_b)));
        };
        if ligne_a == ligne_b {
            continue;
        }
        let commentee = ligne_b
            .strip_prefix(HOSTS_COMMENTE.as_bytes())
            .is_some_and(|reste| reste == *ligne_a && adresse_commentable(ligne_a).is_some());
        if !commentee {
            return Err(RefusHosts::LigneChangee(lisible(ligne_b)));
        }
        diff.commentees.push(lisible(ligne_a));
    }
    if let Some(retiree) = a.hors.get(b.hors.len()) {
        return Err(RefusHosts::LigneRetiree(lisible(retiree)));
    }
    Ok(diff)
}

/// L'empreinte d'un hosts telle qu'une ligne `vanguard:hosts-ecrire` la porte : SHA-256 en hexadécimal majuscule
/// (celle de `sha256_hex`, test empreinte_des_scripts_et_du_hosts).
pub(crate) fn empreinte_hosts(octets: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(octets)
        .iter()
        .fold(String::with_capacity(64), |mut s, o| {
            let _ = write!(s, "{o:02X}");
            s
        })
}

/// Ce que le processus élevé juge avant de montrer, et rejuge avant d'écrire : les octets du fichier préparé et du
/// hosts, lus une seule fois chacun, ont les empreintes de la ligne, puis leur différence est admise par
/// `juger_hosts`. Ce sont ces octets-là, et eux seuls, qui seront écrits.
pub(crate) fn verifier_hosts(h: &HostsEcrire, prepare: &[u8], hosts: &[u8]) -> Result<DiffHosts, RefusHosts> {
    if prepare.len() > HOSTS_MAX || hosts.len() > HOSTS_MAX {
        return Err(RefusHosts::TropGros);
    }
    if empreinte_hosts(prepare) != h.apres {
        return Err(RefusHosts::PrepareChange);
    }
    if empreinte_hosts(hosts) != h.avant {
        return Err(RefusHosts::HostsChange);
    }
    juger_hosts(hosts, prepare)
}

/// Le hosts avec en commentaire chaque ligne hors du bloc de Vanguard qui envoie un nom vers une adresse que
/// `a_commenter` désigne (les adresses d'Internet, pour la réparation « Navigation détournée ») : « # Vanguard : »
/// devant, le reste de chaque octet inchangé, encodage et fins de ligne compris. Ce que `juger_hosts` admet.
pub(crate) fn hosts_commente(avant: &[u8], a_commenter: impl Fn(std::net::IpAddr) -> bool) -> Vec<u8> {
    let mut sortie = Vec::with_capacity(avant.len());
    let mut dedans = false;
    for l in avant.split_inclusive(|&c| c == b'\n') {
        let t = sans_blancs_de_fin(l);
        if t.starts_with(HOSTS_DEBUT.as_bytes()) {
            dedans = true;
        } else if t == HOSTS_FIN.as_bytes() {
            dedans = false;
        } else if !dedans && adresse_commentable(l).is_some_and(&a_commenter) {
            sortie.extend_from_slice(HOSTS_COMMENTE.as_bytes());
        }
        sortie.extend_from_slice(l);
    }
    sortie
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
/// Le verbe d'un choix exact de la personne pour un réglage de Defender : `vanguard:defender-choix <reglage> <choix>`
/// (`ReglageDefender::choix`). Contrairement à `defender`, qui ne fait que renforcer, ce choix peut baisser : le sens
/// n'est jamais lu dans la ligne, le processus élevé le juge sur la valeur relue (`sens`), montre une baisse et pose sa
/// question avant de rien écrire, puis note la valeur d'avant pour « Rallumer » (`choix_avant`).
pub(crate) const DEFENDER_CHOIX: &str = "vanguard:defender-choix ";
/// Le verbe d'un choix exact pour une règle ASR : `vanguard:defender-asr-choix <GUID de ASR_TOUTES>
/// <bloquer|audit|desactiver>`, jugé comme `defender-choix`.
pub(crate) const DEFENDER_ASR_CHOIX: &str = "vanguard:defender-asr-choix ";
/// Le verbe qui rallume ce qu'un choix a baissé : `vanguard:rallumer <id>`, sans aucune valeur. Le processus élevé
/// calcule la cible lui-même (`cible_rallumer`) : la valeur d'avant de la note si elle est valide et au moins au
/// plancher, sinon la valeur sûre. Une ligne ne peut donc jamais faire « rallumer » plus faible qu'allumé.
pub(crate) const RALLUMER: &str = "vanguard:rallumer ";
/// Le verbe d'une exclusion de Defender que la personne ajoute : `vanguard:defender-exclusion-ajouter
/// <chemin|processus|extension> <hex>`. Une baisse (P5), jugée, montrée, confirmée et notée comme `defender-choix`
/// (`defender-exclusion-<genre>-<empreinte>`) ; « Rallumer » la retire.
pub(crate) const DEFENDER_EXCLUSION_AJOUTER: &str = "vanguard:defender-exclusion-ajouter ";
/// Le verbe d'un programme que la personne permet malgré l'accès contrôlé aux dossiers :
/// `vanguard:defender-dossiers-autoriser <hex>`, jugé comme `defender-exclusion-ajouter`.
pub(crate) const DEFENDER_DOSSIERS_AUTORISER: &str = "vanguard:defender-dossiers-autoriser ";
/// Le verbe qui note un réglage coupé hors de Vanguard comme le choix de la personne (« C'est moi », P11) :
/// `vanguard:choix-noter <id>`. Rien n'est écrit dans Defender ; la note (avant : la valeur sûre) est posée par le
/// processus élevé, après la même question qu'une baisse.
pub(crate) const CHOIX_NOTER: &str = "vanguard:choix-noter ";

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

/// Les 19 règles ASR que Microsoft documente (« Attack surface reduction rules reference »), en minuscules : celles
/// qu'une ligne `defender-asr-choix` peut désigner (le choix de la personne, dans les Options), et que l'écran lit.
pub(crate) const ASR_TOUTES: [&str; 19] = [
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "01443614-cd74-433a-b99e-2ecdc07bfc25",
    "c1db55ab-c21a-4637-bb3f-a12568109d35",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
    "33ddedf1-c6e0-47cb-833e-de6133960387",
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6",
];

/// La règle de `ASR_TOUTES` qui porte exactement cet identifiant (minuscules, sans accolades).
pub(crate) fn asr_toute(id: &str) -> Option<&'static str> {
    ASR_TOUTES.iter().copied().find(|r| *r == id)
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
    /// L'envoi d'échantillons au cloud (SubmitSamplesConsent) : un choix de vie privée, jamais renforcé par une ligne
    /// `defender` (`permises` vide).
    Echantillons,
    /// La surveillance du comportement (DisableBehaviorMonitoring).
    Comportement,
    /// L'analyse des téléchargements et pièces jointes (DisableIOAVProtection).
    Telechargements,
    /// L'analyse des scripts (DisableScriptScanning).
    Scripts,
    /// Le blocage à la première détection (DisableBlockAtFirstSeen).
    PremiereVue,
}

impl ReglageDefender {
    pub(crate) const TOUS: [ReglageDefender; 10] = [
        ReglageDefender::TempsReel,
        ReglageDefender::Maps,
        ReglageDefender::Cfa,
        ReglageDefender::Np,
        ReglageDefender::Pua,
        ReglageDefender::Echantillons,
        ReglageDefender::Comportement,
        ReglageDefender::Telechargements,
        ReglageDefender::Scripts,
        ReglageDefender::PremiereVue,
    ];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ReglageDefender::TempsReel => "temps-reel",
            ReglageDefender::Maps => "maps",
            ReglageDefender::Cfa => "cfa",
            ReglageDefender::Np => "np",
            ReglageDefender::Pua => "pua",
            ReglageDefender::Echantillons => "echantillons",
            ReglageDefender::Comportement => "comportement",
            ReglageDefender::Telechargements => "telechargements",
            ReglageDefender::Scripts => "scripts",
            ReglageDefender::PremiereVue => "premiere-vue",
        }
    }

    /// Un `Disable…` de MSFT_MpPreference : un booléen, faux (0) en marche, vrai (1) coupé.
    pub(crate) fn booleen(self) -> bool {
        matches!(
            self,
            ReglageDefender::TempsReel
                | ReglageDefender::Comportement
                | ReglageDefender::Telechargements
                | ReglageDefender::Scripts
                | ReglageDefender::PremiereVue
        )
    }

    /// La propriété de MSFT_MpPreference, lue avant et après, et le paramètre de sa méthode Set.
    pub(crate) fn propriete(self) -> &'static str {
        match self {
            ReglageDefender::TempsReel => "DisableRealtimeMonitoring",
            ReglageDefender::Maps => "MAPSReporting",
            ReglageDefender::Cfa => "EnableControlledFolderAccess",
            ReglageDefender::Np => "EnableNetworkProtection",
            ReglageDefender::Pua => "PUAProtection",
            ReglageDefender::Echantillons => "SubmitSamplesConsent",
            ReglageDefender::Comportement => "DisableBehaviorMonitoring",
            ReglageDefender::Telechargements => "DisableIOAVProtection",
            ReglageDefender::Scripts => "DisableScriptScanning",
            ReglageDefender::PremiereVue => "DisableBlockAtFirstSeen",
        }
    }

    /// Les valeurs qu'une ligne peut porter : seulement celles qui protègent. Aucune ne coupe un réglage, si bien
    /// qu'une ligne forgée ne peut rien affaiblir (« temps-reel non », « maps 0 », « cfa coupe »… sont refusées).
    pub(crate) fn permises(self) -> &'static [ValeurDefender] {
        match self {
            r if r.booleen() => &[ValeurDefender::Actif],
            ReglageDefender::Maps => &[ValeurDefender::Avance],
            // L'envoi d'échantillons est un choix de vie privée : seule la personne le règle, dans les Options.
            ReglageDefender::Echantillons => &[],
            _ => &[ValeurDefender::Bloquer, ValeurDefender::Audit],
        }
    }

    /// La valeur que la propriété doit relire une fois `v` écrite. Décidée par le réglage d'abord : même un acte
    /// construit hors de `permises` ne vise qu'une valeur qui protège (temps réel jamais désactivé, cloud avancé).
    pub(crate) fn attendue(self, v: ValeurDefender) -> u8 {
        match (self, v) {
            // DisableRealtimeMonitoring et les autres `Disable…` : faux.
            (r, _) if r.booleen() => 0,
            // SubmitSamplesConsent : 1, les fichiers sûrs (2 serait « jamais » : jamais visé par un renforcement).
            (ReglageDefender::Echantillons, _) => 1,
            // MAPSReporting : 2, « Advanced ».
            (ReglageDefender::Maps, _) | (_, ValeurDefender::Audit) => 2,
            (_, _) => 1,
        }
    }

    /// Le rang de protection d'une valeur lue de la propriété : plus haut, plus sûr. Une valeur inconnue vaut 0, la
    /// moins sûre : jamais crue plus forte qu'elle n'est. Accès contrôlé : 0 coupé, 2 et 4 audit, 3 disques seuls,
    /// 1 bloque ; protection réseau et PUA : 0 coupée, 2 audit, 1 bloque ; cloud : 0, 1 de base, 2 avancé.
    /// Envoi d'échantillons : 2 jamais, 0 toujours demander, 1 fichiers sûrs, 3 tous.
    pub(crate) fn rang(self, lue: i64) -> u8 {
        match self {
            r if r.booleen() => u8::from(lue == 0),
            ReglageDefender::Echantillons => match lue {
                0 => 1,
                1 => 2,
                3 => 3,
                _ => 0,
            },
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
            _ => match lue {
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
        if self.booleen() {
            ValeurWmi::Booleen(n != 0)
        } else {
            ValeurWmi::Octet(n)
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

// ------------------------------------------------- choix de la personne (baisse, Rallumer)

/// Le choix exact d'une ligne `defender-choix`, que le réglage admet ou non (`ReglageDefender::choix`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChoixDefender {
    /// La protection en temps réel en marche.
    Allume,
    /// Le réglage coupé.
    Coupe,
    /// Le cloud complet (« Advanced »).
    Avance,
    /// Le cloud de base (« Basic »).
    Base,
    Bloquer,
    /// L'accès contrôlé aux dossiers qui ne bloque que l'écriture sur les disques.
    Disques,
    /// Signale sans bloquer.
    Audit,
    /// Envoi d'échantillons : tous les fichiers, sans demander (3).
    Tous,
    /// Envoi d'échantillons : les fichiers sûrs, sans demander (1).
    Surs,
    /// Envoi d'échantillons : toujours demander (0).
    Demander,
    /// Envoi d'échantillons : jamais (2).
    Jamais,
}

impl ChoixDefender {
    pub(crate) const TOUS: [ChoixDefender; 11] = [
        ChoixDefender::Allume,
        ChoixDefender::Coupe,
        ChoixDefender::Avance,
        ChoixDefender::Base,
        ChoixDefender::Bloquer,
        ChoixDefender::Disques,
        ChoixDefender::Audit,
        ChoixDefender::Tous,
        ChoixDefender::Surs,
        ChoixDefender::Demander,
        ChoixDefender::Jamais,
    ];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ChoixDefender::Allume => "allume",
            ChoixDefender::Coupe => "coupe",
            ChoixDefender::Avance => "avance",
            ChoixDefender::Base => "base",
            ChoixDefender::Bloquer => "bloquer",
            ChoixDefender::Disques => "disques",
            ChoixDefender::Audit => "audit",
            ChoixDefender::Tous => "tous",
            ChoixDefender::Surs => "surs",
            ChoixDefender::Demander => "demander",
            ChoixDefender::Jamais => "jamais",
        }
    }
}

impl ReglageDefender {
    /// Les choix qu'une ligne `defender-choix` peut porter pour ce réglage, coupé compris.
    pub(crate) fn choix(self) -> &'static [ChoixDefender] {
        match self {
            r if r.booleen() => &[ChoixDefender::Allume, ChoixDefender::Coupe],
            ReglageDefender::Echantillons => &[
                ChoixDefender::Tous,
                ChoixDefender::Surs,
                ChoixDefender::Demander,
                ChoixDefender::Jamais,
            ],
            ReglageDefender::Maps => &[ChoixDefender::Avance, ChoixDefender::Base, ChoixDefender::Coupe],
            ReglageDefender::Cfa => &[
                ChoixDefender::Bloquer,
                ChoixDefender::Disques,
                ChoixDefender::Audit,
                ChoixDefender::Coupe,
            ],
            _ => &[ChoixDefender::Bloquer, ChoixDefender::Audit, ChoixDefender::Coupe],
        }
    }

    /// La valeur de la propriété pour un choix de ce réglage (DisableRealtimeMonitoring : 0 en marche, 1 coupée) ;
    /// `None` pour un choix que le réglage n'admet pas.
    pub(crate) fn valeur_choix(self, c: ChoixDefender) -> Option<i64> {
        if !self.choix().contains(&c) {
            return None;
        }
        Some(match (self, c) {
            (r, ChoixDefender::Coupe) if r.booleen() => 1,
            (_, ChoixDefender::Bloquer | ChoixDefender::Base | ChoixDefender::Surs) => 1,
            (_, ChoixDefender::Avance | ChoixDefender::Audit | ChoixDefender::Jamais) => 2,
            (_, ChoixDefender::Disques | ChoixDefender::Tous) => 3,
            (_, _) => 0,
        })
    }

    /// L'identifiant du réglage dans les Options et dans les notes (`defender-<id>`), celui de `options_defense::Opt`.
    pub(crate) fn id_choix(self) -> &'static str {
        match self {
            ReglageDefender::TempsReel => "temps-reel",
            ReglageDefender::Maps => "cloud",
            ReglageDefender::Cfa => "dossiers",
            ReglageDefender::Np => "reseau",
            ReglageDefender::Pua => "pua",
            ReglageDefender::Echantillons => "echantillons",
            ReglageDefender::Comportement => "comportement",
            ReglageDefender::Telechargements => "telechargements",
            ReglageDefender::Scripts => "scripts",
            ReglageDefender::PremiereVue => "premiere-vue",
        }
    }

    /// La valeur sûre par défaut, celle que vise « Rallumer » sans note valide : en marche, cloud avancé, échantillons
    /// sûrs sans demander, bloquer.
    pub(crate) fn sure(self) -> i64 {
        match self {
            r if r.booleen() => 0,
            ReglageDefender::Maps => 2,
            _ => 1,
        }
    }

    /// Le paramètre de MSFT_MpPreference.Set pour une valeur exacte de la propriété : un booléen pour le temps réel
    /// (0 ou 1 seulement), un octet sinon ; `None` pour une valeur hors de ce que le réglage connaît.
    pub(crate) fn wmi_de(self, v: i64) -> Option<ValeurWmi> {
        match self {
            r if r.booleen() => match v {
                0 => Some(ValeurWmi::Booleen(false)),
                1 => Some(ValeurWmi::Booleen(true)),
                _ => None,
            },
            ReglageDefender::Cfa => u8::try_from(v).ok().filter(|n| *n <= 4).map(ValeurWmi::Octet),
            ReglageDefender::Echantillons => u8::try_from(v).ok().filter(|n| *n <= 3).map(ValeurWmi::Octet),
            _ => u8::try_from(v).ok().filter(|n| *n <= 2).map(ValeurWmi::Octet),
        }
    }
}

/// Le choix exact d'une ligne `defender-asr-choix` : l'action de la règle (1 bloque, 2 audit, 0 désactivée).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChoixAsr {
    Bloquer,
    Audit,
    Desactiver,
}

impl ChoixAsr {
    pub(crate) const TOUS: [ChoixAsr; 3] = [ChoixAsr::Bloquer, ChoixAsr::Audit, ChoixAsr::Desactiver];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ChoixAsr::Bloquer => "bloquer",
            ChoixAsr::Audit => "audit",
            ChoixAsr::Desactiver => "desactiver",
        }
    }

    pub(crate) fn action(self) -> i64 {
        match self {
            ChoixAsr::Bloquer => 1,
            ChoixAsr::Audit => 2,
            ChoixAsr::Desactiver => 0,
        }
    }
}

/// L'empreinte d'un élément de liste de Defender (une exclusion, un programme permis) : les 8 premiers octets du
/// SHA-256 de son texte en minuscules (Windows compare chemins et extensions sans casse). Elle nomme la note et la
/// ligne `rallumer` sans jamais y mettre le chemin lui-même.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct EmpreinteElement([u8; 8]);

impl EmpreinteElement {
    pub(crate) fn de(texte: &str) -> EmpreinteElement {
        use sha2::Digest;
        let h = sha2::Sha256::digest(texte.to_lowercase().as_bytes());
        let mut e = [0u8; 8];
        for (d, s) in e.iter_mut().zip(h.iter()) {
            *d = *s;
        }
        EmpreinteElement(e)
    }

    /// 16 chiffres hexadécimaux minuscules.
    pub(crate) fn hex(self) -> String {
        self.0.iter().fold(String::with_capacity(16), |mut t, o| {
            let _ = write!(t, "{o:02x}");
            t
        })
    }

    /// L'empreinte de 16 chiffres hexadécimaux minuscules, et seulement de cette forme.
    pub(crate) fn lire(hex: &str) -> Option<EmpreinteElement> {
        if hex.len() != 16 || !hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut e = [0u8; 8];
        for (d, paire) in e.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            *d = u8::from_str_radix(std::str::from_utf8(paire).ok()?, 16).ok()?;
        }
        Some(EmpreinteElement(e))
    }
}

/// Ce qu'un choix règle, nommé dans les notes « avant » (`choix_avant`) et dans `vanguard:rallumer <id>` :
/// `defender-<id>`, `asr-<GUID>`, `defender-exclusion-<genre>-<empreinte>` ou
/// `defender-dossiers-autorise-<empreinte>`. Pour une exclusion et un programme permis, la valeur est 0 absent (le
/// plus sûr) ou 1 présent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdChoix {
    Defender(ReglageDefender),
    Asr(&'static str),
    /// Une exclusion de l'analyse de Defender (ExclusionPath, ExclusionProcess, ExclusionExtension).
    Exclusion(GenreExclusion, EmpreinteElement),
    /// Un programme permis malgré l'accès contrôlé aux dossiers (ControlledFolderAccessAllowedApplications).
    DossiersAutorise(EmpreinteElement),
    /// Un réglage d'un profil du pare-feu : 1 la valeur la plus fermée (`ReglagePareFeu`).
    PareFeu(ProfilPareFeu, ReglagePareFeu),
    /// Une règle existante du pare-feu, désignée par son action et son empreinte (`RegleLue::empreinte`) : 1 active,
    /// 0 inactive.
    PareFeuRegle(ActionRegle, EmpreinteElement),
}

impl IdChoix {
    pub(crate) fn texte(self) -> String {
        match self {
            IdChoix::Defender(r) => format!("defender-{}", r.id_choix()),
            IdChoix::Asr(id) => format!("asr-{id}"),
            IdChoix::Exclusion(g, e) => format!("defender-exclusion-{}-{}", g.mot(), e.hex()),
            IdChoix::DossiersAutorise(e) => format!("defender-dossiers-autorise-{}", e.hex()),
            IdChoix::PareFeu(p, r) => format!("pare-feu-{}-{}", p.mot(), r.mot()),
            IdChoix::PareFeuRegle(a, e) => format!("pare-feu-regle-{}-{}", a.mot(), e.hex()),
        }
    }

    /// L'identifiant d'un texte, si et seulement s'il en a la forme exacte.
    pub(crate) fn lire(texte: &str) -> Option<IdChoix> {
        let id = if let Some(reste) = texte.strip_prefix("defender-exclusion-") {
            let (genre, hex) = reste.split_once('-')?;
            let g = *GenreExclusion::TOUS.iter().find(|g| g.mot() == genre)?;
            IdChoix::Exclusion(g, EmpreinteElement::lire(hex)?)
        } else if let Some(hex) = texte.strip_prefix("defender-dossiers-autorise-") {
            IdChoix::DossiersAutorise(EmpreinteElement::lire(hex)?)
        } else if let Some(r) = texte.strip_prefix("defender-") {
            IdChoix::Defender(*ReglageDefender::TOUS.iter().find(|x| x.id_choix() == r)?)
        } else if let Some(reste) = texte.strip_prefix("pare-feu-regle-") {
            let (action, hex) = reste.split_once('-')?;
            let a = *[ActionRegle::Bloque, ActionRegle::Autorise]
                .iter()
                .find(|a| a.mot() == action)?;
            IdChoix::PareFeuRegle(a, EmpreinteElement::lire(hex)?)
        } else if let Some(reste) = texte.strip_prefix("pare-feu-") {
            let (profil, reglage) = reste.split_once('-')?;
            IdChoix::PareFeu(
                *ProfilPareFeu::TOUS.iter().find(|p| p.mot() == profil)?,
                *ReglagePareFeu::TOUS.iter().find(|r| r.mot() == reglage)?,
            )
        } else {
            IdChoix::Asr(asr_toute(texte.strip_prefix("asr-")?)?)
        };
        (id.texte() == texte).then_some(id)
    }

    /// Un élément de liste (exclusion, programme permis) : 0 absent, 1 présent.
    pub(crate) fn element(self) -> bool {
        matches!(self, IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_))
    }

    /// « Rallumer » n'y touche que si Vanguard l'a noté : un élément de liste, une règle du pare-feu (celles des
    /// autres ne sont jamais réglées d'office).
    pub(crate) fn note_requise(self) -> bool {
        self.element() || matches!(self, IdChoix::PareFeuRegle(..))
    }

    /// Un choix du pare-feu (profil ou règle), lu et écrit par COM (`pare_feu.rs`), jamais par Defender.
    pub(crate) fn pare_feu(self) -> bool {
        matches!(self, IdChoix::PareFeu(..) | IdChoix::PareFeuRegle(..))
    }

    /// Le rang de protection d'une valeur (`None` : règle ASR absente de la liste). Plus haut, plus sûr ; une valeur
    /// inconnue vaut 0. Un élément de liste absent (0) protège plus que présent.
    pub(crate) fn rang(self, v: Option<i64>) -> u8 {
        match self {
            IdChoix::Defender(r) => v.map_or(0, |v| r.rang(v)),
            IdChoix::Asr(_) => rang_asr(v),
            // Absent ; une règle d'autorisation inactive.
            IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_) | IdChoix::PareFeuRegle(ActionRegle::Autorise, _) => {
                u8::from(v == Some(0))
            }
            // 1 : allumé, bloquer, tout bloquer ; une règle de blocage active.
            IdChoix::PareFeu(..) | IdChoix::PareFeuRegle(ActionRegle::Bloque, _) => u8::from(v == Some(1)),
        }
    }

    /// Le rang le plus bas qu'une valeur d'avant notée peut avoir pour que « Rallumer » la remette : allumé (audit
    /// compris), jamais coupé ; pour l'envoi d'échantillons, « toujours demander » (rang 1) : seul « jamais » est
    /// remplacé ; pour un élément de liste, absent.
    pub(crate) fn plancher(self) -> u8 {
        match self {
            IdChoix::Defender(_)
            | IdChoix::Asr(_)
            | IdChoix::Exclusion(..)
            | IdChoix::DossiersAutorise(_)
            | IdChoix::PareFeu(..)
            | IdChoix::PareFeuRegle(..) => 1,
        }
    }

    /// Une valeur baissée (`None` : règle absente) : sous la valeur sûre, montrée telle à l'écran, avec « Rallumer »
    /// et « C'est moi ». Pour l'envoi d'échantillons, « toujours demander » est un choix de vie privée (plan §2.1) et
    /// non une baisse : seul « jamais » l'est.
    pub(crate) fn baissee(self, v: Option<i64>) -> bool {
        let seuil = match self {
            IdChoix::Defender(ReglageDefender::Echantillons) => self.plancher(),
            // Une règle d'autorisation active n'est pas une protection baissée : Windows en a des dizaines.
            IdChoix::PareFeuRegle(ActionRegle::Autorise, _) => return false,
            _ => self.rang(Some(self.sure())),
        };
        self.rang(v) < seuil
    }

    /// La valeur sûre par défaut : en marche, cloud avancé, échantillons sûrs, bloquer ; un élément de liste absent.
    pub(crate) fn sure(self) -> i64 {
        match self {
            IdChoix::Defender(r) => r.sure(),
            IdChoix::PareFeu(_, r) => r.sure(),
            // Une règle de blocage active ; une règle d'autorisation n'est jamais « baissée » : l'activer est un
            // choix noté (elle ouvre), la laisser inactive ne protège pas moins que Windows.
            IdChoix::Asr(_) | IdChoix::PareFeuRegle(ActionRegle::Bloque, _) => 1,
            IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_) | IdChoix::PareFeuRegle(ActionRegle::Autorise, _) => {
                0
            }
        }
    }
}

/// La cible de `vanguard:rallumer` : la valeur d'avant d'une note valide (`None` : pas de note, ou abîmée) si elle
/// est au moins au plancher, sinon la valeur sûre. Une note forgée, tronquée ou qui dit « coupé » ne fait donc jamais
/// rallumer plus faible qu'allumé.
#[allow(clippy::option_option)] // None : illisible ou sans note ; Some(None) : valeur absente
pub(crate) fn cible_rallumer(id: IdChoix, avant_note: Option<Option<i64>>) -> i64 {
    match avant_note {
        Some(Some(v)) if id.rang(Some(v)) >= id.plancher() => v,
        _ => id.sure(),
    }
}

/// Le sens d'un geste, jugé sur la valeur relue, jamais lu dans la ligne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sens {
    Renforce,
    Baisse,
    /// Déjà à la valeur demandée : rien à écrire.
    Rien,
}

/// Ce que la personne a vu d'un choix avant son accord : son sens, et la valeur relue alors (`None` : illisible,
/// `Some(None)` : règle absente). Le processus élevé ne fait une baisse que si la valeur relue juste avant d'écrire
/// est celle qui a été montrée : la note garde ainsi la valeur que la personne a vue, jamais une autre arrivée entre
/// l'affichage et l'écriture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Montre {
    pub(crate) sens: Sens,
    #[allow(clippy::option_option)] // None : illisible ; Some(None) : valeur absente
    pub(crate) lue: Option<Option<i64>>,
}

/// Le sens d'un choix : `lue`, la valeur relue (`None` : illisible, `Some(None)` : règle absente) ; `cible`, la
/// valeur demandée. Illisible : une baisse, pour que la question soit posée (le geste échouera de toute façon, faute
/// de relecture). Plus fort : un renforcement ; la même valeur : rien. Plus faible, ou une autre valeur du même rang
/// (audit des disques et audit de tout, deux valeurs inconnues ou coupées) : une baisse, montrée puis confirmée et
/// notée, pour qu'aucun changement de réglage ne se fasse sans que la personne l'ait vu.
#[allow(clippy::option_option)] // None : illisible ou sans note ; Some(None) : valeur absente
pub(crate) fn sens(id: IdChoix, lue: Option<Option<i64>>, cible: Option<i64>) -> Sens {
    let Some(lue) = lue else {
        return Sens::Baisse;
    };
    if id.rang(cible) > id.rang(lue) {
        Sens::Renforce
    } else if lue == cible {
        Sens::Rien
    } else {
        Sens::Baisse
    }
}

/// Une liste reçue par le processus élevé, jugée : `sens`, pour chaque ligne, celui d'un choix (`None` : un autre
/// geste, dont le sens est celui de son type). `Ok(true)` : une liste de baisses, que la question `[o/N]` garde ;
/// `Ok(false)` : une liste ordinaire, gardée par l'accord habituel ; `Err(())` : une liste mêlée (une baisse parmi
/// des gestes qui ne sont pas des choix), refusée en entier. Une liste de baisses peut porter d'autres choix (un
/// réglage remonté en même temps, un réglage déjà à la valeur demandée) : chacun est montré avec son sens, et rejugé
/// avant l'écriture (devenu une baisse sans avoir été montré comme telle, il est refusé). Une baisse ne se cache donc
/// jamais parmi les corrections du bilan.
#[allow(clippy::result_unit_err)]
pub(crate) fn liste_pure(sens: &[Option<Sens>]) -> Result<bool, ()> {
    if !sens.contains(&Some(Sens::Baisse)) {
        return Ok(false);
    }
    if sens.iter().all(Option::is_some) {
        Ok(true)
    } else {
        Err(())
    }
}

/// Les deux listes que le parent envoie au processus élevé, en une seule demande d'administrateur (P7) : les places
/// des lignes ordinaires, puis celles des choix exacts (`defender-choix`, `defender-asr-choix`), chacune dans son
/// ordre. Une liste sans choix, ou faite seulement de choix, reste seule. Le processus élevé juge chacune à part
/// (`liste_pure`) : les choix y sont montrés et demandés à part, jamais cachés parmi d'autres gestes. Les lignes
/// ordinaires passent d'abord, les choix ensuite : ce qui renforce (un point de restauration, les corrections du
/// bilan) est fait avant qu'une baisse soit même demandée, et un refus de la baisse (la réponse par défaut) ne
/// retire rien de ce qui a été accepté. Si un renforcement et un choix visent le même réglage, le choix, fait en
/// dernier, l'emporte ; sa liste est jugée et montrée juste avant ses gestes, avec la valeur que le renforcement a
/// laissée.
pub(crate) fn separer_choix(lignes: &[String]) -> Vec<Vec<usize>> {
    let (choix, autres): (Vec<usize>, Vec<usize>) = (0..lignes.len()).partition(|&i| {
        lignes
            .get(i)
            .and_then(|l| analyser_acte(l))
            .is_some_and(|a| a.choix().is_some())
    });
    [autres, choix].into_iter().filter(|l| !l.is_empty()).collect()
}

/// La ligne qui sépare deux listes dans le tube du processus élevé (P7) : jamais une ligne d'une liste (ni acte, ni
/// correction, ni ordre : `valider` la refuse).
pub(crate) const SUITE: &str = "suite";
/// Le plus de listes qu'un envoi porte : les lignes ordinaires, puis les choix (`separer_choix`).
pub(crate) const LISTES_MAX: usize = 2;

/// Les lignes à envoyer pour ces listes (`separer_choix`), séparées par `SUITE`, et la place d'origine de chaque
/// ligne envoyée, dans l'ordre d'envoi (celui des réponses).
pub(crate) fn joindre_listes(lignes: &[String], groupes: &[Vec<usize>]) -> (Vec<String>, Vec<usize>) {
    let mut envoi = Vec::with_capacity(lignes.len().saturating_add(groupes.len()));
    let mut ordre = Vec::with_capacity(lignes.len());
    for (k, g) in groupes.iter().enumerate() {
        if k > 0 {
            envoi.push(SUITE.to_string());
        }
        for &i in g {
            if let Some(l) = lignes.get(i) {
                envoi.push(l.clone());
                ordre.push(i);
            }
        }
    }
    (envoi, ordre)
}

/// Les listes reçues par le processus élevé : `None` si l'une est vide (deux `SUITE` de suite, ou en tête ou en fin)
/// ou s'il y en a plus de `LISTES_MAX`.
pub(crate) fn decouper_listes(lignes: &[String]) -> Option<Vec<Vec<String>>> {
    let listes: Vec<Vec<String>> = lignes.split(|l| l == SUITE).map(<[String]>::to_vec).collect();
    (listes.len() <= LISTES_MAX && listes.iter().all(|l| !l.is_empty())).then_some(listes)
}

/// Les réponses, reçues dans l'ordre d'envoi, remises à la place de leur ligne ; `None` si leur nombre ou les places
/// ne vont pas (une réponse perdue ne prend jamais la place d'une autre).
pub(crate) fn remettre_en_ordre<T>(ordre: &[usize], reponses: Vec<T>) -> Option<Vec<T>> {
    if ordre.len() != reponses.len() {
        return None;
    }
    let mut places: Vec<Option<T>> = std::iter::repeat_with(|| None).take(ordre.len()).collect();
    for (&i, r) in ordre.iter().zip(reponses) {
        let place = places.get_mut(i)?;
        if place.is_some() {
            return None;
        }
        *place = Some(r);
    }
    places.into_iter().collect()
}

/// La méthode de MSFT_MpPreference pour écrire une valeur exacte d'un choix : Set pour un réglage, Add pour une
/// règle ASR (Set remplacerait toute la liste) ; `None` pour une valeur que le réglage ne connaît pas.
pub(crate) fn methode_choix(id: IdChoix, v: i64) -> Option<(&'static str, Vec<(&'static str, ValeurWmi)>)> {
    match id {
        IdChoix::Defender(r) => Some(("Set", vec![(r.propriete(), r.wmi_de(v)?)])),
        // Un élément de liste s'écrit avec son texte, que l'identifiant ne porte pas : `defender_ecriture` ; le
        // pare-feu, par COM (`pare_feu.rs`).
        IdChoix::Exclusion(..) | IdChoix::DossiersAutorise(_) | IdChoix::PareFeu(..) | IdChoix::PareFeuRegle(..) => {
            None
        }
        IdChoix::Asr(guid) => {
            let action = u8::try_from(v).ok().filter(|a| matches!(a, 0 | 1 | 2 | 6))?;
            Some((
                "Add",
                vec![
                    (
                        "AttackSurfaceReductionRules_Ids",
                        ValeurWmi::Textes(vec![guid.to_string()]),
                    ),
                    ("AttackSurfaceReductionRules_Actions", ValeurWmi::Octets(vec![action])),
                ],
            ))
        }
    }
}

/// La ligne d'un choix exact pour un réglage de Defender, qui peut baisser ; `None` si le réglage n'admet pas ce
/// choix. Appelée seulement par l'écran des Options, où la personne la choisit (règle
/// `les_baisses_ne_viennent_que_des_options` de `autotest/lecture_seule.rs`) : jamais par le bilan.
pub(crate) fn ligne_baisse_defender(r: ReglageDefender, c: ChoixDefender) -> Option<String> {
    r.choix().contains(&c).then(|| Acte::DefenderChoix(r, c).ligne())
}

/// La ligne d'un choix exact pour une règle ASR, qui peut baisser ; `None` hors de `ASR_TOUTES`. Mêmes appelants que
/// `ligne_baisse_defender`.
pub(crate) fn ligne_baisse_asr(id: &str, c: ChoixAsr) -> Option<String> {
    asr_toute(id).map(|id| Acte::DefenderAsrChoix(id, c).ligne())
}

/// La ligne qui rallume ce qu'un choix a baissé (un renforcement : permise partout).
pub(crate) fn ligne_rallumer(id: IdChoix) -> String {
    Acte::Rallumer(id).ligne()
}

/// La ligne d'une exclusion que la personne ajoute (une baisse) ; `None` pour un texte vide, trop long ou avec un
/// caractère de contrôle. Mêmes appelants que `ligne_baisse_defender`.
pub(crate) fn ligne_ajout_exclusion(g: GenreExclusion, texte: &str) -> Option<String> {
    Exclusion::nouvelle(texte).map(|e| Acte::DefenderExclusionAjouter(g, e).ligne())
}

/// La ligne d'un programme permis malgré l'accès contrôlé aux dossiers (une baisse). Mêmes appelants.
pub(crate) fn ligne_autoriser_dossiers(texte: &str) -> Option<String> {
    Exclusion::nouvelle(texte).map(|e| Acte::DefenderDossiersAutoriser(e).ligne())
}

/// La ligne « C'est moi, le noter » (P11). Mêmes appelants.
pub(crate) fn ligne_noter(id: IdChoix) -> String {
    Acte::ChoixNoter(id).ligne()
}

// ------------------------------------------------------------ Pare-feu : les choix de la personne (D5)

/// Le verbe d'un réglage d'un profil du pare-feu, au choix exact de la personne : `vanguard:pare-feu-profil
/// <domaine|prive|public> <actif|tout-bloquer>=<oui|non>` ou `<entrant|sortant>=<bloquer|autoriser>`, un seul réglage
/// par ligne. Jugé comme `defender-choix` : le sens vient de la valeur relue, une baisse est montrée, confirmée et
/// notée (`pare-feu-<profil>-<reglage>`).
pub(crate) const PARE_FEU_PROFIL: &str = "vanguard:pare-feu-profil ";
/// Le verbe d'une règle existante du pare-feu activée ou désactivée au choix de la personne :
/// `vanguard:pare-feu-regle-etat <bloque|autorise>-<empreinte> <active|inactive>`. La règle n'est jamais effacée ;
/// l'empreinte désigne toutes les règles de mêmes nom, sens, action, programme, ports et profils (`RegleLue`).
pub(crate) const PARE_FEU_REGLE_ETAT: &str = "vanguard:pare-feu-regle-etat ";

/// Un profil du Pare-feu Windows, avec son bit de NET_FW_PROFILE_TYPE2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProfilPareFeu {
    Domaine,
    Prive,
    Public,
}

impl ProfilPareFeu {
    pub(crate) const TOUS: [ProfilPareFeu; 3] = [ProfilPareFeu::Domaine, ProfilPareFeu::Prive, ProfilPareFeu::Public];

    /// Domaine 1, privé 2, public 4.
    pub(crate) fn bit(self) -> i32 {
        match self {
            ProfilPareFeu::Domaine => 1,
            ProfilPareFeu::Prive => 2,
            ProfilPareFeu::Public => 4,
        }
    }

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ProfilPareFeu::Domaine => "domaine",
            ProfilPareFeu::Prive => "prive",
            ProfilPareFeu::Public => "public",
        }
    }
}

/// Un réglage d'un profil que la personne choisit. La valeur 1 est la plus fermée (allumé, bloquer, bloquer, tout
/// bloquer) ; 0, l'autre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReglagePareFeu {
    /// FirewallEnabled.
    Actif,
    /// DefaultInboundAction : 1 bloquer.
    Entrant,
    /// DefaultOutboundAction : 1 bloquer (le défaut de Windows est « autoriser »).
    Sortant,
    /// BlockAllInboundTraffic : 1 toutes les entrées bloquées, même celles des programmes autorisés.
    ToutBloquer,
}

impl ReglagePareFeu {
    pub(crate) const TOUS: [ReglagePareFeu; 4] = [
        ReglagePareFeu::Actif,
        ReglagePareFeu::Entrant,
        ReglagePareFeu::Sortant,
        ReglagePareFeu::ToutBloquer,
    ];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ReglagePareFeu::Actif => "actif",
            ReglagePareFeu::Entrant => "entrant",
            ReglagePareFeu::Sortant => "sortant",
            ReglagePareFeu::ToutBloquer => "tout-bloquer",
        }
    }

    /// Le mot d'une valeur dans la ligne : « oui »/« non », ou « bloquer »/« autoriser ».
    pub(crate) fn mot_valeur(self, fermee: bool) -> &'static str {
        match (self, fermee) {
            (ReglagePareFeu::Actif | ReglagePareFeu::ToutBloquer, true) => "oui",
            (ReglagePareFeu::Actif | ReglagePareFeu::ToutBloquer, false) => "non",
            (ReglagePareFeu::Entrant | ReglagePareFeu::Sortant, true) => "bloquer",
            (ReglagePareFeu::Entrant | ReglagePareFeu::Sortant, false) => "autoriser",
        }
    }

    /// La valeur sûre, celle de Windows : allumé, entrées bloquées, sorties autorisées, règles des programmes
    /// suivies.
    pub(crate) fn sure(self) -> i64 {
        match self {
            ReglagePareFeu::Actif | ReglagePareFeu::Entrant => 1,
            ReglagePareFeu::Sortant | ReglagePareFeu::ToutBloquer => 0,
        }
    }
}

/// L'action d'une règle existante.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ActionRegle {
    Bloque,
    Autorise,
}

impl ActionRegle {
    pub(crate) fn mot(self) -> &'static str {
        match self {
            ActionRegle::Bloque => "bloque",
            ActionRegle::Autorise => "autorise",
        }
    }
}

/// Une règle du Pare-feu Windows telle qu'elle est relue (INetFwRule). Le protocole suit NET_FW_IP_PROTOCOL (TCP 6,
/// tous 256) ; les profils, le masque de NET_FW_PROFILE_TYPE2 (tous : 0x7FFFFFFF).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RegleLue {
    pub(crate) nom: String,
    pub(crate) entrante: bool,
    pub(crate) bloque: bool,
    pub(crate) active: bool,
    pub(crate) profils: i32,
    pub(crate) programme: String,
    pub(crate) protocole: i32,
    pub(crate) ports_locaux: String,
    pub(crate) ports_distants: String,
    pub(crate) adresses_distantes: String,
    pub(crate) adresses_locales: String,
    /// InterfaceTypes (« All », « Lan »…) ; une liste d'interfaces précises (Interfaces) s'y écrit « précises ».
    pub(crate) interfaces: String,
    pub(crate) service: String,
    pub(crate) groupe: String,
}

/// TCP et « tous les protocoles » dans NET_FW_IP_PROTOCOL.
const PROTOCOLE_TCP: i32 = 6;
const PROTOCOLE_TOUS: i32 = 256;
/// Les ports des sessions à distance que le pare-feu ne doit jamais fermer : Bureau à distance et SSH.
pub(crate) const PORTS_SESSION: [u16; 2] = [3389, 22];

impl RegleLue {
    pub(crate) fn action(&self) -> ActionRegle {
        if self.bloque {
            ActionRegle::Bloque
        } else {
            ActionRegle::Autorise
        }
    }

    /// L'empreinte de (nom, sens, action, programme, ports locaux et distants, profils), sans casse : plusieurs
    /// règles peuvent porter le même nom, celles qui ont aussi tout cela en commun sont réglées ensemble.
    pub(crate) fn empreinte(&self) -> EmpreinteElement {
        EmpreinteElement::de(&format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.nom,
            if self.entrante { "in" } else { "out" },
            self.action().mot(),
            self.programme,
            self.ports_locaux,
            self.ports_distants,
            self.profils
        ))
    }

    pub(crate) fn id(&self) -> IdChoix {
        IdChoix::PareFeuRegle(self.action(), self.empreinte())
    }

    /// La règle s'applique-t-elle à l'un des profils de ce masque ?
    pub(crate) fn sur(&self, masque: i32) -> bool {
        self.profils & masque != 0
    }

    fn tcp(&self) -> bool {
        matches!(self.protocole, PROTOCOLE_TCP | PROTOCOLE_TOUS)
    }

    /// Chaque élément de LocalPorts : `Some(true)` le port y est nommé (seul ou dans une plage), `Some(false)` « * »
    /// ou rien (tous les ports), `None` absent.
    fn port_dans(&self, port: u16) -> Option<bool> {
        let t = self.ports_locaux.trim();
        if t.is_empty() || t == "*" {
            return Some(false);
        }
        t.split(',').map(str::trim).find_map(|x| {
            if x == "*" {
                return Some(false);
            }
            let (a, b) = x.split_once('-').unwrap_or((x, x));
            let (a, b) = (a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?);
            (a <= port && port <= b).then_some(true)
        })
    }

    /// La règle vise-t-elle ce port local en TCP, nommé ou par « tous les ports » ?
    pub(crate) fn touche_port(&self, port: u16) -> bool {
        self.tcp() && self.port_dans(port).is_some()
    }

    /// La règle nomme-t-elle ce port local en TCP (pas seulement « tous les ports ») ?
    pub(crate) fn nomme_port(&self, port: u16) -> bool {
        self.tcp() && self.port_dans(port) == Some(true)
    }

    /// Cette règle d'autorisation laisse-t-elle sûrement entrer une session sur ce port : le port nommé, depuis
    /// toute adresse distante, vers toute adresse locale, sur toute interface, de tout port distant, pour le Bureau à
    /// distance (svchost, TermService), System ou sshd, ou sans programme ni service ? Dans le doute, non : la garde
    /// refuse alors plutôt que de couper.
    fn ouvre(&self, port: u16) -> bool {
        let partout = |t: &str| {
            let t = t.trim();
            t.is_empty() || t == "*" || t.eq_ignore_ascii_case("all")
        };
        let programme = self.programme.trim().to_lowercase();
        let fichier = programme.rsplit(['\\', '/']).next().unwrap_or(&programme);
        let service = self.service.trim().to_lowercase();
        !self.bloque
            && self.nomme_port(port)
            && partout(&self.adresses_distantes)
            && partout(&self.adresses_locales)
            && partout(&self.ports_distants)
            && partout(&self.interfaces)
            && matches!(fichier, "" | "svchost.exe" | "system" | "sshd.exe")
            && matches!(service.as_str(), "" | "*" | "termservice" | "sshd")
    }
}

/// Un profil du pare-feu tel qu'il s'applique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // les quatre réglages d'un profil, chacun pour lui-même
pub(crate) struct EtatProfil {
    pub(crate) actif: bool,
    pub(crate) entrant_bloque: bool,
    pub(crate) sortant_bloque: bool,
    pub(crate) tout_bloque: bool,
}

impl EtatProfil {
    /// Le profil après ce réglage.
    pub(crate) fn avec(self, r: ReglagePareFeu, fermee: bool) -> EtatProfil {
        let mut e = self;
        match r {
            ReglagePareFeu::Actif => e.actif = fermee,
            ReglagePareFeu::Entrant => e.entrant_bloque = fermee,
            ReglagePareFeu::Sortant => e.sortant_bloque = fermee,
            ReglagePareFeu::ToutBloquer => e.tout_bloque = fermee,
        }
        e
    }

    pub(crate) fn valeur(self, r: ReglagePareFeu) -> bool {
        match r {
            ReglagePareFeu::Actif => self.actif,
            ReglagePareFeu::Entrant => self.entrant_bloque,
            ReglagePareFeu::Sortant => self.sortant_bloque,
            ReglagePareFeu::ToutBloquer => self.tout_bloque,
        }
    }

    fn sorties_bloquees(self) -> bool {
        self.actif && self.sortant_bloque
    }
}

/// Une connexion entrante sur ce port passe-t-elle, sur ce profil (`bit`), avec ces règles ? Coupé, tout passe ; une
/// règle de blocage active qui touche le port l'emporte ; tout bloquer ferme ; entrées autorisées par défaut, le
/// port passe ; sinon il faut une règle d'autorisation sûre (`RegleLue::ouvre`).
pub(crate) fn port_ouvert(e: EtatProfil, bit: i32, port: u16, regles: &[RegleLue]) -> bool {
    if !e.actif {
        return true;
    }
    let actives = || regles.iter().filter(|r| r.active && r.entrante && r.sur(bit));
    if actives().any(|r| r.bloque && r.touche_port(port)) {
        return false;
    }
    if e.tout_bloque {
        return false;
    }
    if !e.entrant_bloque {
        return true;
    }
    actives().any(|r| r.ouvre(port))
}

/// Les ports locaux qu'utilise la session à distance en cours ; `None` : aucune session. `rdp` : ce processus tourne
/// dans une session du Bureau à distance ; `lue` : les connexions relues (`None` : illisibles), une session en cours
/// et ses ports locaux (VNC, RustDesk, SSH sur un autre port…). Connexions illisibles, ou une session dont aucun port
/// ne se lit : 3389 et 22, au cas où. Le Bureau à distance ajoute 3389. Les règles qui nomment 3389 ou 22 restent
/// gardées de toute façon (`refus_regle_session`).
pub(crate) fn session_pare_feu(rdp: bool, lue: Option<(bool, &[u16])>) -> Option<Vec<u16>> {
    if !rdp && matches!(lue, Some((false, _))) {
        return None;
    }
    let mut ports: Vec<u16> = match lue {
        Some((true, lus)) if !lus.is_empty() => lus.to_vec(),
        Some((true, _)) | None => PORTS_SESSION.to_vec(),
        Some((false, _)) => Vec::new(),
    };
    if rdp {
        ports.push(PORTS_SESSION[0]);
    }
    ports.sort_unstable();
    ports.dedup();
    Some(ports)
}

fn courant(courants: Option<i32>, bit: i32) -> bool {
    // CurrentProfileTypes illisible : chaque profil compte comme courant.
    courants.is_none_or(|m| m & bit != 0)
}

/// Pourquoi ce réglage d'un profil couperait la session à distance en cours (plan §2.3, gardes B), ou `None`.
/// `session` : les ports à garder (`session_pare_feu`), `None` sans session ; `courants` : CurrentProfileTypes
/// (`None` : illisible, tous les profils comptent) ; `avant` : le profil relu ; `regles` : les règles relues. Sur un
/// profil courant, pendant une session ou si on ne sait pas : tout bloquer, et les sorties bloquées par défaut (AnyDesk,
/// TeamViewer, un VPN passent par une sortie), sont refusés ; allumer le pare-feu ou bloquer les entrées par défaut
/// l'est aussi s'il fermerait un port de la session ou bloquerait les sorties. Couper le pare-feu et autoriser
/// n'ouvrent que davantage : jamais refusés pour cette raison. Un profil absent du masque courant reste réglable.
pub(crate) fn refus_profil_session(
    session: Option<&[u16]>,
    courants: Option<i32>,
    p: ProfilPareFeu,
    r: ReglagePareFeu,
    fermee: bool,
    avant: EtatProfil,
    regles: &[RegleLue],
) -> Option<RefusSession> {
    let ports = session?;
    if !courant(courants, p.bit()) {
        return None;
    }
    let apres = avant.avec(r, fermee);
    if r == ReglagePareFeu::ToutBloquer && fermee {
        return Some(RefusSession::ToutBloquer);
    }
    if (r == ReglagePareFeu::Sortant && fermee) || (apres.sorties_bloquees() && !avant.sorties_bloquees()) {
        return Some(RefusSession::Sorties);
    }
    ports
        .iter()
        .any(|&port| port_ouvert(avant, p.bit(), port, regles) && !port_ouvert(apres, p.bit(), port, regles))
        .then_some(RefusSession::PortFerme)
}

/// Pourquoi activer (`active`) ou désactiver cette règle couperait la session à distance en cours, ou `None`. Pendant
/// une session ou si on ne sait pas, est refusé : désactiver une règle d'autorisation entrante d'un profil courant ;
/// une sortante d'un profil courant si les sorties y sont (ou peuvent y être) bloquées par défaut (`sorties_bloquees`,
/// sur les profils courants ; `None` : illisible) ; une règle d'autorisation qui nomme 3389, 22 ou un port de la
/// session, sur n'importe quel profil ; activer une règle de blocage sortante d'un profil courant, ou entrante qui
/// touche un port de la session. Activer une autorisation et désactiver un blocage n'ouvrent que davantage.
pub(crate) fn refus_regle_session(
    session: Option<&[u16]>,
    courants: Option<i32>,
    sorties_bloquees: Option<bool>,
    regle: &RegleLue,
    active: bool,
) -> Option<RefusSession> {
    let ports = session?;
    let sur_courant = regle.sur(courants.unwrap_or(0x7FFF_FFFF));
    let gardes = || ports.iter().chain(PORTS_SESSION.iter());
    match (regle.bloque, active) {
        (false, false)
            if (sur_courant && (regle.entrante || sorties_bloquees != Some(false)))
                || (regle.entrante && gardes().any(|&p| regle.nomme_port(p))) =>
        {
            Some(RefusSession::RegleAutorisation)
        }
        (true, true) if sur_courant && (!regle.entrante || gardes().any(|&p| regle.touche_port(p))) => {
            Some(RefusSession::RegleBlocage)
        }
        _ => None,
    }
}

/// La valeur d'une règle désignée par son empreinte (`IdChoix::PareFeuRegle`), d'après l'état de chacune des règles
/// qui la portent : 1 toutes actives, 0 toutes inactives ; partagées, la plus faible (une règle de blocage inactive,
/// une règle d'autorisation active), pour que « Rallumer » les remette toutes ; `None` : aucune règle.
pub(crate) fn etat_des_regles(a: ActionRegle, actives: impl IntoIterator<Item = bool>) -> Option<i64> {
    let (mut oui, mut non) = (false, false);
    for x in actives {
        if x {
            oui = true;
        } else {
            non = true;
        }
    }
    match (oui, non) {
        (false, false) => None,
        (true, false) => Some(1),
        (false, true) => Some(0),
        (true, true) => Some(i64::from(a == ActionRegle::Autorise)),
    }
}

/// Pourquoi un geste du pare-feu est refusé pendant une session à distance (ou si les connexions ne se lisent pas) ;
/// le texte est dit par `pare_feu.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusSession {
    /// Tout bloquer en entrée sur un profil courant.
    ToutBloquer,
    /// Bloquer les sorties sur un profil courant (par le réglage, ou en allumant un profil qui les bloque).
    Sorties,
    /// Allumer, ou bloquer les entrées par défaut, fermerait un port de la session.
    PortFerme,
    /// Désactiver une règle d'autorisation.
    RegleAutorisation,
    /// Activer une règle de blocage.
    RegleBlocage,
}

/// La ligne d'un réglage de profil du pare-feu au choix exact de la personne, qui peut baisser. Appelée seulement par
/// l'écran des Options et par la question du mode Wi-Fi public à sa sortie (règle
/// `les_baisses_ne_viennent_que_des_options` de `autotest/lecture_seule.rs`) : jamais par le bilan.
pub(crate) fn ligne_baisse_pare_feu(p: ProfilPareFeu, r: ReglagePareFeu, fermee: bool) -> String {
    Acte::PareFeuProfil(p, r, fermee).ligne()
}

/// La ligne d'une règle existante activée ou désactivée au choix de la personne. Mêmes appelants que
/// `ligne_baisse_pare_feu`, le mode Wi-Fi public excepté.
pub(crate) fn ligne_regle_etat(regle: &RegleLue, active: bool) -> String {
    Acte::PareFeuRegleEtat(regle.action(), regle.empreinte(), active).ligne()
}

fn analyser_pare_feu_profil(reste: &str) -> Option<Acte> {
    let (profil, paire) = reste.split_once(' ')?;
    let (cle, valeur) = paire.split_once('=')?;
    let p = *ProfilPareFeu::TOUS.iter().find(|p| p.mot() == profil)?;
    let r = *ReglagePareFeu::TOUS.iter().find(|r| r.mot() == cle)?;
    let fermee = [true, false].into_iter().find(|f| r.mot_valeur(*f) == valeur)?;
    Some(Acte::PareFeuProfil(p, r, fermee))
}

fn analyser_regle_etat(reste: &str) -> Option<Acte> {
    let (designee, etat) = reste.split_once(' ')?;
    let (action, hex) = designee.split_once('-')?;
    let a = *[ActionRegle::Bloque, ActionRegle::Autorise]
        .iter()
        .find(|a| a.mot() == action)?;
    let active = match etat {
        "active" => true,
        "inactive" => false,
        _ => return None,
    };
    Some(Acte::PareFeuRegleEtat(a, EmpreinteElement::lire(hex)?, active))
}

/// Une exclusion large (R8) : la racine d'un disque, Windows, Téléchargements, le dossier temporaire, les
/// programmes, scripts ou interpréteurs en entier, un joker. La question le dit plus fort.
pub(crate) fn exclusion_large(g: GenreExclusion, texte: &str) -> bool {
    let t = texte.trim().trim_end_matches(['\\', '/']).to_lowercase();
    if t.is_empty() || t.contains('*') || t.contains('?') {
        return true;
    }
    match g {
        GenreExclusion::Extension => matches!(
            t.trim_start_matches('.'),
            "exe" | "ps1" | "dll" | "bat" | "cmd" | "vbs" | "js" | "scr" | "msi" | "com" | "hta" | "lnk"
        ),
        GenreExclusion::Processus => {
            let nom = t.rsplit(['\\', '/']).next().unwrap_or(&t);
            matches!(
                nom,
                "powershell.exe"
                    | "pwsh.exe"
                    | "cmd.exe"
                    | "wscript.exe"
                    | "cscript.exe"
                    | "mshta.exe"
                    | "rundll32.exe"
            )
        }
        GenreExclusion::Chemin => {
            (t.len() <= 2 && t.ends_with(':'))
                || t.contains("%temp%")
                || t.contains("%tmp%")
                || t.contains("\\appdata\\local\\temp")
                || t.ends_with("\\downloads")
                || t.ends_with("\\téléchargements")
                || t.ends_with(":\\windows")
                || t.contains(":\\windows\\temp")
                || t.ends_with(":\\users")
                || t.ends_with(":\\program files")
                || t.ends_with(":\\program files (x86)")
                || t.ends_with(":\\programdata")
                || t.starts_with("\\\\")
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
        rang_asr(lue) < rang_asr(Some(i64::from(self.action())))
    }
}

/// Le rang de protection de l'action lue d'une règle ASR (`None` : absente de la liste) : absente ou 0 coupée, 2
/// audit, 6 avertit, 1 bloque ; une action inconnue vaut 0, jamais crue plus forte qu'elle n'est.
pub(crate) fn rang_asr(lue: Option<i64>) -> u8 {
    match lue {
        Some(2) => 1,
        Some(6) => 2,
        Some(1) => 3,
        _ => 0,
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

// ------------------------------------------------- comptes, certificats et partages

/// Désactiver un compte local, désigné par son RID (le dernier nombre de son SID) : `vanguard:compte-desactiver
/// <RID>`. Le processus élevé relit les comptes, rejuge par la fonction du bilan et refuse la personne, son propre
/// compte, le dernier administrateur actif, un compte réservé de Windows et un compte qui a un programme ouvert
/// (`refus_desactivation`).
pub(crate) const COMPTE_DESACTIVER: &str = "vanguard:compte-desactiver ";
/// Retirer un certificat racine signalé par le bilan : `vanguard:certificat-retirer <lm|cu> <SHA-1 en hex
/// minuscule>`, exporté avant dans la quarantaine de Vanguard. Jamais un ajout.
pub(crate) const CERTIFICAT_RETIRER: &str = "vanguard:certificat-retirer ";
/// Retirer d'un partage les autorisations d'un compte ouvert sans mot de passe (Tout le monde, Invités…) :
/// `vanguard:partage-retirer-acces <nom en hex> <SID>`, la liste d'avant notée (SDDL).
pub(crate) const PARTAGE_RETIRER_ACCES: &str = "vanguard:partage-retirer-acces ";

/// Le plus petit RID d'un compte : 500 (Administrateur intégré) ; en dessous, des groupes et des comptes de Windows.
pub(crate) const RID_MIN: u32 = 500;
/// La plus longue d'un nom de partage, en unités UTF-16 (NNLEN de lmcons.h).
pub(crate) const PARTAGE_NOM_MAX: usize = 80;

/// Le magasin « Root » d'où retirer un certificat : celui de l'ordinateur ou celui de la personne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MagasinRacine {
    Ordinateur,
    Compte,
}

impl MagasinRacine {
    pub(crate) const TOUS: [MagasinRacine; 2] = [MagasinRacine::Ordinateur, MagasinRacine::Compte];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            MagasinRacine::Ordinateur => "lm",
            MagasinRacine::Compte => "cu",
        }
    }

    /// Le nom du magasin dans les lignes « CERT|… » du bilan (`magasins::racines`).
    pub(crate) fn nom(self) -> &'static str {
        match self {
            MagasinRacine::Ordinateur => "LocalMachine",
            MagasinRacine::Compte => "CurrentUser",
        }
    }
}

/// Une empreinte SHA-1 de certificat : 40 chiffres hexadécimaux minuscules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Empreinte(String);

impl Empreinte {
    /// L'empreinte d'un texte de 40 chiffres hexadécimaux, majuscules admises (Thumbprint) : rendue en minuscules.
    pub(crate) fn nouvelle(texte: &str) -> Option<Empreinte> {
        (texte.len() == 40 && texte.bytes().all(|o| o.is_ascii_hexdigit()))
            .then(|| Empreinte(texte.to_ascii_lowercase()))
    }

    /// L'empreinte d'une ligne : minuscules seulement.
    fn lire(texte: &str) -> Option<Empreinte> {
        (texte.len() == 40 && texte.bytes().all(|o| chiffre_minuscule(o).is_some()))
            .then(|| Empreinte(texte.to_string()))
    }

    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    /// Les 20 octets, pour chercher le certificat par son empreinte.
    pub(crate) fn octets(&self) -> Option<[u8; 20]> {
        let mut o = [0u8; 20];
        for (i, paire) in self.0.as_bytes().chunks(2).enumerate() {
            let fort = chiffre_minuscule(*paire.first()?)?;
            let faible = chiffre_minuscule(*paire.get(1)?)?;
            *o.get_mut(i)? = fort.checked_mul(16)?.checked_add(faible)?;
        }
        Some(o)
    }
}

/// Un nom de partage relu : 1 à 80 unités UTF-16, de l'UTF-16 valide, sans caractère de contrôle, et jamais un partage
/// caché ou administratif (fini par « $ » : ADMIN$, IPC$, C$… ; le Bureau à distance et l'administration à distance
/// en dépendent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NomPartage(String);

impl NomPartage {
    pub(crate) fn nouveau(nom: &str) -> Option<NomPartage> {
        let longueur = nom.encode_utf16().count();
        (longueur > 0 && longueur <= PARTAGE_NOM_MAX && !nom.chars().any(char::is_control) && !nom.ends_with('$'))
            .then(|| NomPartage(nom.to_string()))
    }

    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    pub(crate) fn hex(&self) -> String {
        let unites: Vec<u16> = self.0.encode_utf16().collect();
        hex_utf16(&unites)
    }

    fn lire(hex: &str) -> Option<NomPartage> {
        let unites = lire_hex_utf16(hex, PARTAGE_NOM_MAX)?;
        NomPartage::nouveau(&String::from_utf16(&unites).ok()?).filter(|n| n.hex() == hex)
    }
}

/// Un SID en texte, de forme stricte : « S-1- », puis de 2 à 15 nombres décimaux séparés par « - », sans zéro de
/// tête ; l'autorité tient sur 48 bits, chaque sous-autorité sur 32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidTexte(String);

impl SidTexte {
    pub(crate) fn lire(texte: &str) -> Option<SidTexte> {
        let reste = texte.strip_prefix("S-1-")?;
        let nombres: Vec<&str> = reste.split('-').collect();
        // L'autorité, puis de 1 à 15 sous-autorités (SID_MAX_SUB_AUTHORITIES).
        if !(2..=16).contains(&nombres.len()) {
            return None;
        }
        let decimal = |n: &str| {
            !n.is_empty() && n.len() <= 15 && n.bytes().all(|o| o.is_ascii_digit()) && (n == "0" || !n.starts_with('0'))
        };
        let (autorite, sous) = nombres.split_first()?;
        let bon = decimal(autorite)
            && autorite.parse::<u64>().is_ok_and(|a| a < (1u64 << 48))
            && sous.iter().all(|s| decimal(s) && s.parse::<u32>().is_ok());
        bon.then(|| SidTexte(texte.to_string()))
    }

    pub(crate) fn texte(&self) -> &str {
        &self.0
    }
}

/// Retirer d'un partage les autorisations d'un compte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccesPartage {
    pub nom: NomPartage,
    pub sid: SidTexte,
}

/// Le RID d'une ligne : décimal, sans zéro de tête, de 500 à 4 294 967 295.
fn lire_rid(texte: &str) -> Option<u32> {
    (!texte.starts_with('0') && texte.bytes().all(|o| o.is_ascii_digit()))
        .then(|| texte.parse::<u32>().ok())
        .flatten()
        .filter(|&r| r >= RID_MIN)
}

/// Le RID d'un compte local d'après son SID : « S-1-5-21-a-b-c-RID » exactement (le domaine de cet ordinateur ou
/// d'un domaine) ; `None` pour tout autre SID.
pub(crate) fn rid_local(sid: &str) -> Option<u32> {
    let s = SidTexte::lire(sid)?;
    let nombres: Vec<&str> = s.texte().split('-').collect();
    match nombres.as_slice() {
        ["S", "1", "5", "21", _, _, _, rid] => lire_rid(rid),
        _ => None,
    }
}

/// La ligne qui désactive un compte local d'après son SID ; `None` si ce n'est pas un compte local de RID 500 ou plus.
pub(crate) fn ligne_compte_desactiver(sid: &str) -> Option<String> {
    rid_local(sid).map(|rid| Acte::CompteDesactiver(rid).ligne())
}

/// La ligne qui retire une racine ; `None` si l'empreinte n'a pas sa forme ou le magasin n'est pas l'un des deux.
pub(crate) fn ligne_certificat_retirer(magasin: &str, empreinte: &str) -> Option<String> {
    let m = *MagasinRacine::TOUS.iter().find(|m| m.nom() == magasin)?;
    Some(Acte::CertificatRetirer(m, Empreinte::nouvelle(empreinte)?).ligne())
}

/// La ligne qui retire d'un partage les autorisations d'un compte ; `None` pour un nom ou un SID hors de leur forme
/// (un partage caché ou administratif compris) : la correction reste alors à faire soi-même.
pub(crate) fn ligne_partage_retirer_acces(nom: &str, sid: &str) -> Option<String> {
    Some(
        Acte::PartageRetirerAcces(AccesPartage {
            nom: NomPartage::nouveau(nom)?,
            sid: SidTexte::lire(sid)?,
        })
        .ligne(),
    )
}

/// Pourquoi le processus élevé refuse de désactiver un compte (`refus_desactivation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusCompte {
    /// Le compte de la personne n'a pas pu être lu dans le jeton du Vanguard qui a demandé.
    PersonneIllisible,
    /// Aucun compte local, ou plus d'un, n'a ce RID.
    Introuvable,
    /// Le compte de la personne, ou celui de ce processus administrateur.
    CompteEnCours,
    /// Un compte réservé de Windows (RID de 502 à 999 : DefaultAccount, WDAGUtilityAccount…).
    Reserve,
    /// Le bilan relu ne propose pas de le désactiver.
    NonSignale,
    /// Le dernier administrateur actif de l'ordinateur.
    DernierAdministrateur,
    /// Les programmes ouverts ne se lisent pas : une session (Bureau à distance, SSH) en dépend peut-être.
    ProgrammesIllisibles,
    /// Un programme tourne sous ce compte : une session ouverte (sur l'écran, Bureau à distance, SSH) en dépend.
    SessionOuverte,
}

/// Ce que le processus élevé relit avant de désactiver un compte.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EtatCompte<'a> {
    /// Le RID de la ligne.
    pub rid: u32,
    /// Les SID des comptes locaux qui ont ce RID (exactement un pour agir).
    pub trouves: &'a [&'a str],
    /// Le compte de la personne, lu dans le jeton du parent.
    pub personne: Option<&'a str>,
    /// Le compte de ce processus administrateur.
    pub soi: Option<&'a str>,
    /// Le bilan relu propose-t-il cette ligne, automatiquement ?
    pub signale: bool,
    /// Le compte est-il membre des Administrateurs ?
    pub administrateur: bool,
    /// Combien d'autres comptes locaux activés sont administrateurs.
    pub autres_administrateurs: usize,
    /// Un programme tourne-t-il sous ce compte (`None` : illisible) ?
    pub programmes: Option<bool>,
}

/// Le motif de refus d'une désactivation ; `None` si elle peut se faire. Pure, pour l'essayer : aucun compte ne gagne
/// de droits, la personne ne se retrouve jamais dehors, ni l'ordinateur sans administrateur, ni une session à
/// distance coupée.
pub(crate) fn refus_desactivation(e: &EtatCompte) -> Option<RefusCompte> {
    let Some(personne) = e.personne else {
        return Some(RefusCompte::PersonneIllisible);
    };
    let [cible] = e.trouves else {
        return Some(RefusCompte::Introuvable);
    };
    if rid_local(cible) != Some(e.rid) {
        return Some(RefusCompte::Introuvable);
    }
    if cible.eq_ignore_ascii_case(personne) || e.soi.is_none_or(|s| cible.eq_ignore_ascii_case(s)) {
        return Some(RefusCompte::CompteEnCours);
    }
    if e.rid != 500 && e.rid != 501 && e.rid < 1000 {
        return Some(RefusCompte::Reserve);
    }
    if !e.signale {
        return Some(RefusCompte::NonSignale);
    }
    if e.administrateur && e.autres_administrateurs == 0 {
        return Some(RefusCompte::DernierAdministrateur);
    }
    match e.programmes {
        None => Some(RefusCompte::ProgrammesIllisibles),
        Some(true) => Some(RefusCompte::SessionOuverte),
        Some(false) => None,
    }
}

// ------------------------------------------------- persistance et prise en main à distance (lot 3.5)

/// Retirer une valeur de démarrage de la machine (HKLM Run, RunOnce, ou Run des programmes 32 bits) :
/// `vanguard:run-retirer <run|runonce|run32> <nom en hex|defaut>`. Le processus élevé relit la valeur, refait le
/// bilan sur elle (persistance suspecte, ou outil de prise en main à distance), refuse une entrée de Windows ou de
/// Defender (`run_protege`), note la donnée d'avant dans `RUN_AVANT_CLE`, retire, puis relit.
pub(crate) const RUN_RETIRER_MACHINE: &str = "vanguard:run-retirer ";
/// Remettre exactement la donnée qu'un `run-retirer` a notée : `vanguard:run-remettre <clé> <nom en hex|defaut>`.
/// La ligne ne porte aucune donnée : seule celle que le processus élevé a notée lui-même revient, jamais par-dessus
/// une valeur présente. Elle rend le PC moins protégé (un lancement jugé suspect revient) : dit avant l'accord.
pub(crate) const RUN_REMETTRE: &str = "vanguard:run-remettre ";
/// Désactiver une tâche planifiée signalée : `vanguard:tache-desactiver <chemin en hex>` (passe b).
pub(crate) const TACHE_DESACTIVER: &str = "vanguard:tache-desactiver ";
/// Réactiver une tâche que Vanguard a désactivée : `vanguard:tache-reactiver <chemin en hex>` (passe b).
pub(crate) const TACHE_REACTIVER: &str = "vanguard:tache-reactiver ";
/// Mettre en quarantaine un fichier du dossier Démarrage commun : `vanguard:demarrage-quarantaine <chemin en hex>`
/// (passe b). Le dossier Démarrage de la personne reste à vider soi-même.
pub(crate) const DEMARRAGE_QUARANTAINE: &str = "vanguard:demarrage-quarantaine ";
/// Ressortir de la quarantaine un fichier que Vanguard y a mis : `vanguard:demarrage-remettre <chemin en hex>`.
pub(crate) const DEMARRAGE_REMETTRE: &str = "vanguard:demarrage-remettre ";
/// Retirer un abonnement WMI (consumer, binding, filtre non partagé) : `vanguard:wmi-abonnement-retirer
/// <commande|script> <nom du consumer en hex>` (passe c).
pub(crate) const WMI_ABONNEMENT_RETIRER: &str = "vanguard:wmi-abonnement-retirer ";
/// Recréer un abonnement WMI que Vanguard a retiré, d'après ses propriétés notées (passe c).
pub(crate) const WMI_ABONNEMENT_REMETTRE: &str = "vanguard:wmi-abonnement-remettre ";
/// Supprimer le service d'un outil de prise en main à distance : `vanguard:service-retirer <nom en hex>` (passe d).
/// Irréversible : jamais de remise, une deuxième confirmation.
pub(crate) const SERVICE_RETIRER: &str = "vanguard:service-retirer ";
/// Désactiver un programme lancé à l'ouverture de session de toute la machine, comme le fait le Gestionnaire des
/// tâches (sa valeur dans HKLM\…\StartupApproved), sans rien retirer : `vanguard:lancement-desactiver
/// <run|run32|dossier> <nom en hex> <valeur>`, la valeur étant celle de Windows pour « désactivé » (`03000000` puis
/// l'heure, 12 octets en hexadécimal). Le processus élevé relit le lancement, refuse ce qu'Optimiser garde (sécurité,
/// pilotes, Vanguard) et toute entrée de Windows ou de Defender, note les octets d'avant dans `LANCEMENT_AVANT_CLE`,
/// écrit, puis relit.
pub(crate) const LANCEMENT_DESACTIVER: &str = "vanguard:lancement-desactiver ";
/// Remettre exactement les octets qu'un `lancement-desactiver` a notés : `vanguard:lancement-reactiver <liste> <nom en
/// hex>`, seulement si la valeur est encore celle que Vanguard a écrite.
pub(crate) const LANCEMENT_REACTIVER: &str = "vanguard:lancement-reactiver ";

/// La clé (sous HKLM, vue 64 bits) où le processus élevé note la donnée d'une valeur de démarrage qu'il retire : seul
/// un administrateur y écrit, la remise ne lit qu'elle.
pub(crate) const RUN_AVANT_CLE: &str = r"SOFTWARE\Vanguard\RunAvant";
/// Où le processus élevé note le XML d'une tâche qu'il désactive, avant et après : la réactivation n'a lieu que si la
/// tâche est restée telle que Vanguard l'a laissée.
pub(crate) const TACHE_AVANT_CLE: &str = r"SOFTWARE\Vanguard\TacheAvant";
/// Où le processus élevé note la copie en quarantaine d'un fichier du dossier Démarrage commun (son nom et son
/// empreinte) : la remise ne lit qu'elle.
pub(crate) const DEMARRAGE_AVANT_CLE: &str = r"SOFTWARE\Vanguard\DemarrageAvant";
/// Où le processus élevé note les octets d'avant d'une valeur de StartupApproved qu'il écrit, et ceux qu'il écrit.
pub(crate) const LANCEMENT_AVANT_CLE: &str = r"SOFTWARE\Vanguard\LancementAvant";
/// Le plus long nom de valeur de démarrage de la machine, en unités UTF-16 : ce que tient une ligne du tube
/// (`LIGNE_MAX`). Au-delà, la valeur est signalée et se retire à la main.
pub(crate) const RUN_MACHINE_NOM_MAX: usize = 2048;
/// Le plus long chemin de tâche planifiée, en unités UTF-16.
pub(crate) const TACHE_CHEMIN_MAX: usize = 512;
/// Le plus long chemin de fichier, en unités UTF-16 : celui de Windows (32 767).
pub(crate) const CHEMIN_MAX: usize = 32_767;
/// Le plus long nom de consumer WMI, en unités UTF-16.
pub(crate) const CONSUMER_NOM_MAX: usize = 256;
/// Le plus long nom de service, en unités UTF-16 (celui du gestionnaire de services).
pub(crate) const SERVICE_NOM_MAX: usize = 256;

/// Le mot d'une ligne de démarrage pour la valeur par défaut (sans nom).
const RUN_DEFAUT_MACHINE: &str = "defaut";

/// Un texte en hexadécimal UTF-16 (la convention de `hex_utf16`).
fn hex_texte(t: &str) -> String {
    hex_utf16(&t.encode_utf16().collect::<Vec<_>>())
}

/// Le texte d'un hexadécimal UTF-16 de 1 à `max` unités, s'il est de l'UTF-16 valide sans NUL.
fn lire_texte_hex(hex: &str, max: usize) -> Option<String> {
    String::from_utf16(&lire_hex_utf16(hex, max)?).ok()
}

/// Un nom montré à la personne : sans caractère de contrôle, coupé à `NOM_MONTRE_MAX` caractères (jamais dans le
/// geste).
pub(crate) fn montrer_nom(lu: &str) -> String {
    let mut affiche: String = lu
        .chars()
        .take(NOM_MONTRE_MAX)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if lu.chars().count() > NOM_MONTRE_MAX {
        affiche.push('…');
    }
    affiche
}

/// La clé de démarrage de la machine d'où retirer une valeur : celles que le bilan lit sous HKLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleRun {
    Run,
    RunOnce,
    /// La clé Run des programmes 32 bits (WOW6432Node).
    Run32,
}

impl CleRun {
    pub(crate) const TOUTES: [CleRun; 3] = [CleRun::Run, CleRun::RunOnce, CleRun::Run32];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            CleRun::Run => "run",
            CleRun::RunOnce => "runonce",
            CleRun::Run32 => "run32",
        }
    }

    /// Le chemin sous HKLM, à ouvrir dans la vue 64 bits (WOW6432Node y est nommé, jamais deviné par la redirection).
    pub(crate) fn chemin(self) -> &'static str {
        match self {
            CleRun::Run => r"Software\Microsoft\Windows\CurrentVersion\Run",
            CleRun::RunOnce => r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            CleRun::Run32 => r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        }
    }

    /// La clé d'un nom de la lecture (« HKLM:\Software\… », comme PowerShell l'écrit) ; `None` hors de ces trois.
    pub(crate) fn depuis_ps(cle: &str) -> Option<CleRun> {
        let chemin = cle.strip_prefix(r"HKLM:\")?;
        CleRun::TOUTES
            .into_iter()
            .find(|c| c.chemin().eq_ignore_ascii_case(chemin))
    }
}

/// Un nom de valeur de démarrage, mot par mot (un nom peut ne pas être de l'UTF-16 valide, il doit pourtant pouvoir
/// se retirer) : jamais de NUL, `RUN_MACHINE_NOM_MAX` unités au plus ; vide, la valeur par défaut (« defaut » dans la
/// ligne, jamais un hexadécimal vide).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NomRun(Vec<u16>);

impl NomRun {
    pub(crate) fn nouveau(unites: &[u16]) -> Option<NomRun> {
        (unites.len() <= RUN_MACHINE_NOM_MAX && !unites.contains(&0)).then(|| NomRun(unites.to_vec()))
    }

    pub(crate) fn unites(&self) -> &[u16] {
        &self.0
    }

    /// Le nom montré (sans caractère de contrôle, coupé) ; `None` pour la valeur par défaut.
    pub(crate) fn montre(&self) -> Option<String> {
        (!self.0.is_empty()).then(|| montrer_nom(&String::from_utf16_lossy(&self.0)))
    }

    fn mot(&self) -> String {
        if self.0.is_empty() {
            RUN_DEFAUT_MACHINE.to_string()
        } else {
            hex_utf16(&self.0)
        }
    }

    fn lire(mot: &str) -> Option<NomRun> {
        if mot == RUN_DEFAUT_MACHINE {
            return Some(NomRun(Vec::new()));
        }
        lire_hex_utf16(mot, RUN_MACHINE_NOM_MAX).and_then(|u| NomRun::nouveau(&u))
    }
}

/// Une valeur de démarrage de la machine : sa clé et son nom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValeurRunMachine {
    pub cle: CleRun,
    pub nom: NomRun,
}

/// La ligne qui retire une valeur de démarrage de la machine, d'après la clé de la lecture (« HKLM:\… ») ; `None`
/// pour une autre clé ou un nom hors de sa forme (la valeur reste signalée, à retirer à la main).
pub(crate) fn ligne_run_retirer_machine(cle: &str, nom: &[u16]) -> Option<String> {
    Some(
        Acte::RunRetirer(ValeurRunMachine {
            cle: CleRun::depuis_ps(cle)?,
            nom: NomRun::nouveau(nom)?,
        })
        .ligne(),
    )
}

/// Une valeur de démarrage que Vanguard ne retire jamais : celles de Sécurité Windows et de Defender, par leur nom ou
/// par leur programme. Un programme malveillant qui en prend le nom reste signalé, à retirer à la main : un refus de
/// trop ne casse rien, un retrait de trop couperait l'icône de la protection.
pub(crate) fn run_protege(nom: &str, programme: &str) -> bool {
    const NOMS: [&str; 4] = [
        "securityhealth",
        "windowsdefender",
        "windows defender",
        "windows security",
    ];
    const PROGRAMMES: [&str; 5] = [
        "securityhealthsystray.exe",
        "msascuil.exe",
        "msascui.exe",
        "msmpeng.exe",
        "mpcmdrun.exe",
    ];
    let nom = nom.trim().to_lowercase();
    let exe = programme.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let fichier = exe.rsplit('\\').next().unwrap_or(&exe);
    NOMS.contains(&nom.as_str())
        || PROGRAMMES.contains(&fichier)
        || exe.contains(r"\windows defender\")
        || exe.contains(r"\microsoft\windows defender\")
}

/// Un composant de chemin admis : non vide, ni « . » ni « .. », sans caractère de contrôle ni `/ : * ? " < > |`, sans
/// espace ni point final (Windows les ôte : « x.lnk. » désignerait « x.lnk »), et jamais un nom de périphérique de
/// DOS (`peripherique_dos` : « NUL.lnk » ouvrirait le périphérique, pas un fichier).
fn composant_sur(c: &str) -> bool {
    let interdit = |x: char| x.is_control() || matches!(x, '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\\');
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.chars().any(interdit)
        && !c.ends_with([' ', '.'])
        && !peripherique_dos(c)
}

/// Un nom que Windows lit comme un périphérique, quelle que soit l'extension : CON, PRN, AUX, NUL, CONIN$, CONOUT$,
/// COM0 à COM9 et LPT0 à LPT9 (chiffres en exposant compris), en majuscules ou non, suivis ou non d'espaces.
fn peripherique_dos(c: &str) -> bool {
    let tige = c
        .split('.')
        .next()
        .unwrap_or(c)
        .trim_end_matches(' ')
        .to_ascii_lowercase();
    if ["con", "prn", "aux", "nul", "conin$", "conout$"].contains(&tige.as_str()) {
        return true;
    }
    let mut lettres = tige.chars();
    let debut: String = lettres.by_ref().take(3).collect();
    let chiffre: Vec<char> = lettres.collect();
    (debut == "com" || debut == "lpt")
        && matches!(chiffre.as_slice(), [d] if d.is_ascii_digit() || matches!(d, '¹' | '²' | '³'))
}

/// Le premier composant d'un chemin de tâche pourrait-il être « Microsoft » pour Windows ? Le planificateur compare
/// sans tenir compte de la casse, avec sa propre table : « ı », « ſ » ou « K » (Kelvin) y valent peut-être « I »,
/// « S », « K ». Tout caractère non ASCII compte donc comme la lettre attendue : refusé au moindre doute.
fn peut_etre_microsoft(composant: &str) -> bool {
    composant.chars().count() == "microsoft".len()
        && composant
            .chars()
            .zip("microsoft".chars())
            .all(|(c, m)| !c.is_ascii() || c.to_ascii_lowercase() == m)
}

/// Un chemin de tâche planifiée : « \dossier\tâche », chaque composant sûr (`composant_sur`), `TACHE_CHEMIN_MAX`
/// unités au plus, et jamais sous \Microsoft\ (les tâches de Windows, que le bilan ne lit pas : une ligne qui en
/// désigne une est forgée), même écrit avec une lettre non ASCII (`peut_etre_microsoft`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheminTache(String);

impl CheminTache {
    pub(crate) fn nouveau(chemin: &str) -> Option<CheminTache> {
        let reste = chemin.strip_prefix('\\')?;
        let microsoft = peut_etre_microsoft(reste.split('\\').next().unwrap_or(reste));
        let bon =
            chemin.encode_utf16().count() <= TACHE_CHEMIN_MAX && !microsoft && reste.split('\\').all(composant_sur);
        bon.then(|| CheminTache(chemin.to_string()))
    }

    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    fn hex(&self) -> String {
        hex_texte(&self.0)
    }

    fn lire(hex: &str) -> Option<CheminTache> {
        CheminTache::nouveau(&lire_texte_hex(hex, TACHE_CHEMIN_MAX)?).filter(|c| c.hex() == hex)
    }
}

/// Un chemin de fichier local complet : « X:\… », chaque composant sûr (`composant_sur` : ni « .. », ni flux
/// alternatif « : »), `CHEMIN_MAX` unités au plus. Jamais « \\?\ », « \\.\ » ni un partage (« \\serveur\… ») : ils
/// commencent par « \ ». Jamais un nom court de DOS (« PROGRA~1 » : « ~ » suivi d'un chiffre), qui désignerait un
/// autre fichier que celui que la ligne montre. Le processus élevé le résout encore et le compare au dossier qu'il lit
/// lui-même.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheminFichier(String);

impl CheminFichier {
    pub(crate) fn nouveau(chemin: &str) -> Option<CheminFichier> {
        let o = chemin.as_bytes();
        let lecteur = matches!(o, [l, b':', b'\\', _, ..] if l.is_ascii_alphabetic());
        let bon = lecteur
            && chemin.encode_utf16().count() <= CHEMIN_MAX
            && chemin.get(3..).is_some_and(|r| r.split('\\').all(composant_sur))
            && !nom_court_dos(chemin);
        bon.then(|| CheminFichier(chemin.to_string()))
    }

    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    fn hex(&self) -> String {
        hex_texte(&self.0)
    }

    fn lire(hex: &str) -> Option<CheminFichier> {
        CheminFichier::nouveau(&lire_texte_hex(hex, CHEMIN_MAX)?).filter(|c| c.hex() == hex)
    }
}

/// Un nom court de DOS dans un chemin : « ~ » suivi d'un chiffre (« PROGRA~1 »).
fn nom_court_dos(chemin: &str) -> bool {
    chemin
        .as_bytes()
        .windows(2)
        .any(|p| matches!(p, [b'~', d] if d.is_ascii_digit()))
}

/// La classe d'un consumer WMI qui lance quelque chose : une commande ou un script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClasseConsumer {
    Commande,
    Script,
}

impl ClasseConsumer {
    pub(crate) const TOUTES: [ClasseConsumer; 2] = [ClasseConsumer::Commande, ClasseConsumer::Script];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ClasseConsumer::Commande => "commande",
            ClasseConsumer::Script => "script",
        }
    }

    /// La classe de root\subscription.
    pub(crate) fn classe(self) -> &'static str {
        match self {
            ClasseConsumer::Commande => "CommandLineEventConsumer",
            ClasseConsumer::Script => "ActiveScriptEventConsumer",
        }
    }
}

/// Un nom de consumer WMI : 1 à `CONSUMER_NOM_MAX` unités UTF-16, sans caractère de contrôle ni `" ' \` (le nom entre
/// dans un chemin d'objet WMI entre guillemets : il ne peut ni en sortir ni y glisser un échappement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NomConsumer(String);

impl NomConsumer {
    pub(crate) fn nouveau(nom: &str) -> Option<NomConsumer> {
        let n = nom.encode_utf16().count();
        let interdit = |c: char| c.is_control() || matches!(c, '"' | '\'' | '\\');
        (n > 0 && n <= CONSUMER_NOM_MAX && !nom.chars().any(interdit)).then(|| NomConsumer(nom.to_string()))
    }

    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    fn hex(&self) -> String {
        hex_texte(&self.0)
    }

    fn lire(hex: &str) -> Option<NomConsumer> {
        NomConsumer::nouveau(&lire_texte_hex(hex, CONSUMER_NOM_MAX)?).filter(|n| n.hex() == hex)
    }
}

/// Un abonnement WMI désigné par son consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbonnementWmi {
    pub classe: ClasseConsumer,
    pub nom: NomConsumer,
}

/// Les abonnements WMI que Vanguard ne touche jamais, liste fermée (noms comparés sans la casse) : ceux que pose
/// Windows (« SCM Event Log Consumer » et son filtre ; « BVTConsumer » et « BVTFilter » des anciennes versions), et tout
/// nom de Sécurité Windows ou de Defender. Un abonnement malveillant qui en prend le nom reste signalé, à retirer à la
/// main : un refus de trop ne casse rien, un retrait de trop couperait un abonnement de Windows ou de l'antivirus.
pub(crate) fn abonnement_wmi_protege(nom: &str) -> bool {
    const NOMS: [&str; 4] = [
        "scm event log consumer",
        "scm event log filter",
        "bvtconsumer",
        "bvtfilter",
    ];
    const MOTS: [&str; 5] = [
        "windows defender",
        "microsoft defender",
        "windows security",
        "securityhealth",
        "msmpeng",
    ];
    let n = nom.trim().to_lowercase();
    NOMS.contains(&n.as_str()) || MOTS.iter().any(|m| n.contains(m))
}

/// Un consumer qui lance un programme de Sécurité Windows ou de Defender (`run_protege`) : son programme
/// (ExecutablePath), le premier mot de sa ligne de commande (entre guillemets ou jusqu'à la première espace), ou son
/// fichier de script.
pub(crate) fn consumer_wmi_protege(nom: &str, programmes: &[&str]) -> bool {
    abonnement_wmi_protege(nom)
        || programmes.iter().any(|p| {
            let p = p.trim();
            let premier = match p.strip_prefix('"') {
                Some(reste) => reste.split('"').next().unwrap_or_default(),
                None => p.split(' ').next().unwrap_or_default(),
            };
            run_protege("", p) || run_protege("", premier)
        })
}

/// La ligne qui retire un abonnement WMI signalé par le bilan ; `None` pour une classe autre que
/// CommandLineEventConsumer et ActiveScriptEventConsumer, un nom hors de la forme de `NomConsumer`, un nom protégé
/// (`abonnement_wmi_protege`), ou un nom qui porte « ¦ » (la lecture du bilan y change « | » : ce nom-là n'est pas
/// forcément le vrai).
pub(crate) fn ligne_wmi_abonnement_retirer(classe: &str, nom: &str) -> Option<String> {
    let classe = ClasseConsumer::TOUTES
        .into_iter()
        .find(|c| c.classe().eq_ignore_ascii_case(classe))?;
    if nom.contains('¦') || abonnement_wmi_protege(nom) {
        return None;
    }
    Some(
        Acte::WmiAbonnementRetirer(AbonnementWmi {
            classe,
            nom: NomConsumer::nouveau(nom)?,
        })
        .ligne(),
    )
}

/// Où le processus élevé note les trois objets d'un abonnement WMI qu'il retire (`NoteWmi`).
pub(crate) const WMI_AVANT_CLE: &str = r"SOFTWARE\Vanguard\WmiAvant";
/// L'en-tête d'une note d'abonnement, avec sa version : une autre version est refusée, jamais devinée.
const NOTE_WMI_ENTETE: &[u8; 6] = b"VGWMI\x01";
/// La plus longue note, en octets (un registre en tient bien plus ; au-delà, l'abonnement se retire à la main).
pub(crate) const NOTE_WMI_MAX: usize = 512 * 1024;
/// Le plus long texte noté, en octets UTF-8 (un ScriptText tient en quelques kilo-octets).
pub(crate) const NOTE_WMI_TEXTE_MAX: usize = 256 * 1024;
/// Le plus long chemin d'objet noté, en octets.
pub(crate) const NOTE_WMI_CHEMIN_MAX: usize = 4096;
/// Le plus de liaisons notées pour un consumer.
pub(crate) const NOTE_WMI_LIAISONS_MAX: usize = 16;

/// Le genre d'une propriété notée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenreWmi {
    Texte,
    Entier,
    Booleen,
}

/// Les propriétés notées d'un __EventFilter, dans l'ordre de la note ; le nom d'abord.
pub(crate) const PROPRIETES_FILTRE: [(&str, GenreWmi); 5] = [
    ("Name", GenreWmi::Texte),
    ("Query", GenreWmi::Texte),
    ("QueryLanguage", GenreWmi::Texte),
    ("EventNamespace", GenreWmi::Texte),
    ("EventAccess", GenreWmi::Texte),
];
/// Celles d'un CommandLineEventConsumer : ce qu'il lance et comment (les réglages de fenêtre plus rares, position et
/// couleurs d'une console, ne sont pas notés et ne reviennent pas).
pub(crate) const PROPRIETES_COMMANDE: [(&str, GenreWmi); 13] = [
    ("Name", GenreWmi::Texte),
    ("ExecutablePath", GenreWmi::Texte),
    ("CommandLineTemplate", GenreWmi::Texte),
    ("WorkingDirectory", GenreWmi::Texte),
    ("DesktopName", GenreWmi::Texte),
    ("WindowTitle", GenreWmi::Texte),
    ("KillTimeout", GenreWmi::Entier),
    ("Priority", GenreWmi::Entier),
    ("ShowWindowCommand", GenreWmi::Entier),
    ("RunInteractively", GenreWmi::Booleen),
    ("CreateNewConsole", GenreWmi::Booleen),
    ("CreateNewProcessGroup", GenreWmi::Booleen),
    ("UseDefaultErrorMode", GenreWmi::Booleen),
];
/// Celles d'un ActiveScriptEventConsumer.
pub(crate) const PROPRIETES_SCRIPT: [(&str, GenreWmi); 5] = [
    ("Name", GenreWmi::Texte),
    ("ScriptingEngine", GenreWmi::Texte),
    ("ScriptText", GenreWmi::Texte),
    ("ScriptFileName", GenreWmi::Texte),
    ("KillTimeout", GenreWmi::Entier),
];
/// Celles d'une __FilterToConsumerBinding, hors ses deux références : la remise les refait vers le filtre et le
/// consumer recréés, jamais depuis un texte noté.
pub(crate) const PROPRIETES_LIAISON: [(&str, GenreWmi); 4] = [
    ("DeliverSynchronously", GenreWmi::Booleen),
    ("MaintainSecurityContext", GenreWmi::Booleen),
    ("SlowDownProviders", GenreWmi::Booleen),
    ("DeliveryQoS", GenreWmi::Entier),
];

impl ClasseConsumer {
    /// Les propriétés notées de cette classe de consumer.
    pub(crate) fn proprietes(self) -> &'static [(&'static str, GenreWmi)] {
        match self {
            ClasseConsumer::Commande => &PROPRIETES_COMMANDE,
            ClasseConsumer::Script => &PROPRIETES_SCRIPT,
        }
    }
}

/// Une valeur notée : absente (nulle dans WMI), un texte, un entier ou un booléen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValeurNotee {
    Absente,
    Texte(String),
    Entier(i64),
    Booleen(bool),
}

impl ValeurNotee {
    fn convient(&self, genre: GenreWmi) -> bool {
        match self {
            ValeurNotee::Absente => true,
            ValeurNotee::Texte(t) => genre == GenreWmi::Texte && t.len() <= NOTE_WMI_TEXTE_MAX,
            ValeurNotee::Entier(_) => genre == GenreWmi::Entier,
            ValeurNotee::Booleen(_) => genre == GenreWmi::Booleen,
        }
    }
}

/// Un objet WMI noté : son chemin relatif (__RELPATH, pour dire seulement s'il diffère après la remise, jamais pour
/// écrire) et ses valeurs, dans l'ordre de la liste de sa classe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjetNote {
    pub chemin: String,
    pub valeurs: Vec<ValeurNotee>,
}

impl ObjetNote {
    fn convient(&self, proprietes: &[(&str, GenreWmi)]) -> bool {
        self.chemin.len() <= NOTE_WMI_CHEMIN_MAX
            && !self.chemin.chars().any(char::is_control)
            && self.valeurs.len() == proprietes.len()
            && self.valeurs.iter().zip(proprietes).all(|(v, (_, g))| v.convient(*g))
    }

    /// Le nom de l'objet (sa première valeur), s'il est un texte.
    pub(crate) fn nom(&self) -> Option<&str> {
        match self.valeurs.first()? {
            ValeurNotee::Texte(t) => Some(t),
            _ => None,
        }
    }
}

/// Une liaison notée, avec son filtre ; `filtre_retire` : le filtre a été supprimé avec elle (il ne servait à aucune
/// autre liaison et n'est pas protégé), et la remise le recrée ; sinon, il est resté et la remise le retrouve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiaisonNotee {
    pub filtre_retire: bool,
    pub filtre: ObjetNote,
    pub liaison: ObjetNote,
}

/// La note d'un abonnement WMI retiré : son consumer et ses liaisons, avec leurs filtres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoteWmi {
    pub classe: ClasseConsumer,
    pub consumer: ObjetNote,
    pub liaisons: Vec<LiaisonNotee>,
}

/// Un nom de filtre admis dans une note : 1 à 256 unités UTF-16, sans caractère de contrôle (il entre dans un chemin
/// d'objet, que WMI échappe lui-même).
fn nom_filtre_admis(nom: &str) -> bool {
    let n = nom.encode_utf16().count();
    n > 0 && n <= CONSUMER_NOM_MAX && !nom.chars().any(char::is_control)
}

impl NoteWmi {
    /// La note est-elle bien formée et celle de `attendu` ? Le consumer a exactement le nom et la classe de la ligne,
    /// chaque objet a les propriétés de sa classe, chaque filtre un nom admis et distinct, et aucun filtre protégé
    /// n'est à recréer.
    pub(crate) fn valide(&self, attendu: &AbonnementWmi) -> bool {
        let mut noms = Vec::new();
        self.classe == attendu.classe
            && self.consumer.convient(self.classe.proprietes())
            && self.consumer.nom() == Some(attendu.nom.texte())
            && self.liaisons.len() <= NOTE_WMI_LIAISONS_MAX
            && self.liaisons.iter().all(|l| {
                let Some(nom) = l.filtre.nom() else {
                    return false;
                };
                let neuf = !noms.contains(&nom);
                noms.push(nom);
                neuf && nom_filtre_admis(nom)
                    && l.filtre.convient(&PROPRIETES_FILTRE)
                    && l.liaison.convient(&PROPRIETES_LIAISON)
                    && !(l.filtre_retire && abonnement_wmi_protege(nom))
            })
    }

    /// Les octets de la note : l'en-tête et sa version, la classe, le consumer, les liaisons, puis l'empreinte
    /// SHA-256 de tout ce qui précède. `None` si elle dépasse ses bornes.
    pub(crate) fn octets(&self) -> Option<Vec<u8>> {
        let mut o = NOTE_WMI_ENTETE.to_vec();
        o.push(match self.classe {
            ClasseConsumer::Commande => 0,
            ClasseConsumer::Script => 1,
        });
        ecrire_objet(&mut o, &self.consumer, self.classe.proprietes())?;
        if self.liaisons.len() > NOTE_WMI_LIAISONS_MAX {
            return None;
        }
        o.push(u8::try_from(self.liaisons.len()).ok()?);
        for l in &self.liaisons {
            o.push(u8::from(l.filtre_retire));
            ecrire_objet(&mut o, &l.filtre, &PROPRIETES_FILTRE)?;
            ecrire_objet(&mut o, &l.liaison, &PROPRIETES_LIAISON)?;
        }
        o.extend_from_slice(&empreinte_note(&o));
        (o.len() <= NOTE_WMI_MAX).then_some(o)
    }

    /// Relit une note ; `None` à la moindre différence avec la forme écrite par `octets` : autre version, borne
    /// dépassée, octet de trop ou de moins, UTF-8 invalide, booléen autre que 0 ou 1, empreinte qui ne correspond
    /// pas.
    pub(crate) fn lire(octets: &[u8]) -> Option<NoteWmi> {
        if octets.len() > NOTE_WMI_MAX {
            return None;
        }
        let (corps, empreinte) = octets.split_at_checked(octets.len().checked_sub(32)?)?;
        if empreinte != empreinte_note(corps).as_slice() {
            return None;
        }
        let mut c = Curseur(corps);
        if c.prendre(NOTE_WMI_ENTETE.len())? != NOTE_WMI_ENTETE {
            return None;
        }
        let classe = match c.octet()? {
            0 => ClasseConsumer::Commande,
            1 => ClasseConsumer::Script,
            _ => return None,
        };
        let consumer = c.objet(classe.proprietes())?;
        let n = usize::from(c.octet()?);
        if n > NOTE_WMI_LIAISONS_MAX {
            return None;
        }
        let mut liaisons = Vec::with_capacity(n);
        for _ in 0..n {
            let filtre_retire = c.booleen()?;
            let filtre = c.objet(&PROPRIETES_FILTRE)?;
            let liaison = c.objet(&PROPRIETES_LIAISON)?;
            liaisons.push(LiaisonNotee {
                filtre_retire,
                filtre,
                liaison,
            });
        }
        c.0.is_empty().then_some(NoteWmi {
            classe,
            consumer,
            liaisons,
        })
    }
}

fn empreinte_note(octets: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(octets).into()
}

fn ecrire_texte(o: &mut Vec<u8>, t: &str, max: usize) -> Option<()> {
    if t.len() > max {
        return None;
    }
    o.extend_from_slice(&u32::try_from(t.len()).ok()?.to_le_bytes());
    o.extend_from_slice(t.as_bytes());
    Some(())
}

fn ecrire_objet(o: &mut Vec<u8>, objet: &ObjetNote, proprietes: &[(&str, GenreWmi)]) -> Option<()> {
    if !objet.convient(proprietes) {
        return None;
    }
    ecrire_texte(o, &objet.chemin, NOTE_WMI_CHEMIN_MAX)?;
    for v in &objet.valeurs {
        match v {
            ValeurNotee::Absente => o.push(0),
            ValeurNotee::Texte(t) => {
                o.push(1);
                ecrire_texte(o, t, NOTE_WMI_TEXTE_MAX)?;
            }
            ValeurNotee::Entier(n) => {
                o.push(2);
                o.extend_from_slice(&n.to_le_bytes());
            }
            ValeurNotee::Booleen(b) => {
                o.push(3);
                o.push(u8::from(*b));
            }
        }
    }
    Some(())
}

/// La lecture d'une note, octet après octet, sans jamais lire au-delà.
struct Curseur<'a>(&'a [u8]);

impl<'a> Curseur<'a> {
    fn prendre(&mut self, n: usize) -> Option<&'a [u8]> {
        let (tete, reste) = self.0.split_at_checked(n)?;
        self.0 = reste;
        Some(tete)
    }

    fn octet(&mut self) -> Option<u8> {
        self.prendre(1)?.first().copied()
    }

    fn booleen(&mut self) -> Option<bool> {
        match self.octet()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn texte(&mut self, max: usize) -> Option<String> {
        let n = usize::try_from(u32::from_le_bytes(self.prendre(4)?.try_into().ok()?)).ok()?;
        if n > max {
            return None;
        }
        String::from_utf8(self.prendre(n)?.to_vec()).ok()
    }

    fn objet(&mut self, proprietes: &[(&str, GenreWmi)]) -> Option<ObjetNote> {
        let chemin = self.texte(NOTE_WMI_CHEMIN_MAX)?;
        let mut valeurs = Vec::with_capacity(proprietes.len());
        for _ in proprietes {
            valeurs.push(match self.octet()? {
                0 => ValeurNotee::Absente,
                1 => ValeurNotee::Texte(self.texte(NOTE_WMI_TEXTE_MAX)?),
                2 => ValeurNotee::Entier(i64::from_le_bytes(self.prendre(8)?.try_into().ok()?)),
                3 => ValeurNotee::Booleen(self.booleen()?),
                _ => return None,
            });
        }
        let objet = ObjetNote { chemin, valeurs };
        objet.convient(proprietes).then_some(objet)
    }
}

/// Un nom de service : 1 à `SERVICE_NOM_MAX` unités UTF-16, sans caractère de contrôle, sans « \ » ni « / » (que le
/// gestionnaire de services refuse), sans espace au début ni à la fin. Espaces et parenthèses admises : les outils de
/// prise en main s'installent sous « ScreenConnect Client (…) ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NomService(String);

impl NomService {
    pub(crate) fn nouveau(nom: &str) -> Option<NomService> {
        let n = nom.encode_utf16().count();
        let interdit = |c: char| c.is_control() || matches!(c, '\\' | '/');
        let bon = n > 0 && n <= SERVICE_NOM_MAX && !nom.chars().any(interdit) && nom.trim() == nom;
        bon.then(|| NomService(nom.to_string()))
    }

    pub(crate) fn texte(&self) -> &str {
        &self.0
    }

    fn hex(&self) -> String {
        hex_texte(&self.0)
    }

    fn lire(hex: &str) -> Option<NomService> {
        NomService::nouveau(&lire_texte_hex(hex, SERVICE_NOM_MAX)?).filter(|n| n.hex() == hex)
    }
}

/// La liste de lancements de la machine où le Gestionnaire des tâches désactive un programme : les valeurs Run (64 et
/// 32 bits) et le dossier Démarrage commun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListeLancement {
    Run,
    Run32,
    Dossier,
}

impl ListeLancement {
    pub(crate) const TOUTES: [ListeLancement; 3] =
        [ListeLancement::Run, ListeLancement::Run32, ListeLancement::Dossier];

    pub(crate) fn mot(self) -> &'static str {
        match self {
            ListeLancement::Run => "run",
            ListeLancement::Run32 => "run32",
            ListeLancement::Dossier => "dossier",
        }
    }

    /// Sa liste sous StartupApproved.
    pub(crate) fn approuvee(self) -> &'static str {
        match self {
            ListeLancement::Run => "Run",
            ListeLancement::Run32 => "Run32",
            ListeLancement::Dossier => "StartupFolder",
        }
    }

    /// La liste d'un nom de StartupApproved (« Run », « Run32 », « StartupFolder »), sensible à la casse.
    pub(crate) fn depuis_approuvee(l: &str) -> Option<ListeLancement> {
        ListeLancement::TOUTES.into_iter().find(|x| x.approuvee() == l)
    }
}

/// Un lancement de la machine désigné par sa liste et son nom : 1 à `RUN_MACHINE_NOM_MAX` unités UTF-16 valides, sans
/// caractère de contrôle ; dans le dossier Démarrage, un nom de fichier seul (`composant_sur`, jamais un chemin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LancementMachine {
    liste: ListeLancement,
    nom: String,
}

impl LancementMachine {
    pub(crate) fn nouveau(liste: ListeLancement, nom: &str) -> Option<LancementMachine> {
        let n = nom.encode_utf16().count();
        let bon = n > 0
            && n <= RUN_MACHINE_NOM_MAX
            && !nom.chars().any(char::is_control)
            // Un nom court de DOS désignerait le fichier sans être le nom que StartupApproved retient : « fait »
            // sans effet.
            && (liste != ListeLancement::Dossier || (composant_sur(nom) && !nom_court_dos(nom)));
        bon.then(|| LancementMachine {
            liste,
            nom: nom.to_string(),
        })
    }

    pub(crate) fn liste(&self) -> ListeLancement {
        self.liste
    }

    pub(crate) fn nom(&self) -> &str {
        &self.nom
    }

    fn mots(&self) -> String {
        format!("{} {}", self.liste.mot(), hex_texte(&self.nom))
    }

    fn lire(reste: &str) -> Option<LancementMachine> {
        let (mot, hex) = reste.split_once(' ')?;
        let liste = ListeLancement::TOUTES.into_iter().find(|l| l.mot() == mot)?;
        LancementMachine::nouveau(liste, &lire_texte_hex(hex, RUN_MACHINE_NOM_MAX)?).filter(|l| l.mots() == reste)
    }
}

/// La valeur que Windows écrit dans StartupApproved pour « désactivé » : 12 octets, `03 00 00 00` puis l'heure du
/// changement (FILETIME). Rien d'autre n'entre dans une ligne : ni « activé », ni une autre longueur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValeurDesactivee([u8; 12]);

impl ValeurDesactivee {
    pub(crate) fn lire(hex: &str) -> Option<ValeurDesactivee> {
        let o = hex.as_bytes();
        if o.len() != 24 || !o.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)) {
            return None;
        }
        let mut v = [0u8; 12];
        for (case, paire) in v.iter_mut().zip(o.chunks(2)) {
            *case = u8::from_str_radix(std::str::from_utf8(paire).ok()?, 16).ok()?;
        }
        (v[..4] == [3, 0, 0, 0]).then_some(ValeurDesactivee(v))
    }

    pub(crate) fn octets(&self) -> &[u8; 12] {
        &self.0
    }

    fn hex(&self) -> String {
        use std::fmt::Write;
        self.0.iter().fold(String::with_capacity(24), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        })
    }
}

/// La ligne d'Optimiser pour un programme de démarrage de toute la machine (liste de StartupApproved, nom, valeur
/// voulue en hexadécimal) : désactiver avec la valeur de Windows, ou remettre les octets notés par le processus élevé
/// (une valeur voulue vide ou « activé »). `None` hors de ces formes : rien ne part.
pub(crate) fn ligne_lancement(liste: &str, nom: &str, voulue: Option<&str>) -> Option<String> {
    let l = LancementMachine::nouveau(ListeLancement::depuis_approuvee(liste)?, nom)?;
    let desactiver = voulue
        .filter(|h| !h.is_empty())
        .and_then(|h| h.get(..2))
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 1 == 1);
    let acte = if desactiver {
        Acte::LancementDesactiver(l, ValeurDesactivee::lire(voulue?)?)
    } else {
        Acte::LancementReactiver(l)
    };
    Some(acte.ligne())
}

/// La ligne qui désactive une tâche signalée par le bilan, d'après son dossier (« \…\ », comme TaskPath) et son nom ;
/// `None` hors de la forme de `CheminTache` (la tâche reste signalée, à désactiver à la main).
pub(crate) fn ligne_tache_desactiver(dossier: &str, nom: &str) -> Option<String> {
    let chemin = format!("{}\\{nom}", dossier.trim_end_matches('\\'));
    Some(Acte::TacheDesactiver(CheminTache::nouveau(&chemin)?).ligne())
}

/// La ligne qui met en quarantaine un fichier du dossier Démarrage commun ; `None` hors de la forme de
/// `CheminFichier`.
pub(crate) fn ligne_demarrage_quarantaine(chemin: &str) -> Option<String> {
    Some(Acte::DemarrageQuarantaine(CheminFichier::nouveau(chemin)?).ligne())
}

/// Les verbes de la persistance et de la prise en main à distance (lot 3.5).
const VERBES_PERSISTANCE: [&str; 11] = [
    RUN_RETIRER_MACHINE,
    RUN_REMETTRE,
    TACHE_DESACTIVER,
    TACHE_REACTIVER,
    DEMARRAGE_QUARANTAINE,
    DEMARRAGE_REMETTRE,
    WMI_ABONNEMENT_RETIRER,
    WMI_ABONNEMENT_REMETTRE,
    SERVICE_RETIRER,
    LANCEMENT_DESACTIVER,
    LANCEMENT_REACTIVER,
];

/// La ligne porte-t-elle un verbe de la persistance ? Elle n'est alors lue que par `analyser_persistance`.
fn est_persistance(ligne: &str) -> bool {
    VERBES_PERSISTANCE.iter().any(|v| ligne.starts_with(v))
}

/// L'acte d'une ligne de persistance (lot 3.5), si et seulement si elle est exactement de sa forme. Bornée par
/// `LIGNE_MAX` (un nom de valeur ou un chemin), `ACTE_NOM_MAX` pour un consumer ou un service.
fn analyser_persistance(ligne: &str) -> Option<Acte> {
    let long = |verbe: &str| {
        ligne
            .strip_prefix(verbe)
            .filter(|_| ligne.len() <= LIGNE_MAX && ligne.is_ascii())
    };
    let court = |verbe: &str| {
        ligne
            .strip_prefix(verbe)
            .filter(|_| ligne.len() <= ACTE_NOM_MAX && ligne.is_ascii())
    };
    let run = |reste: &str| {
        let (mot, nom) = reste.split_once(' ')?;
        Some(ValeurRunMachine {
            cle: CleRun::TOUTES.into_iter().find(|c| c.mot() == mot)?,
            nom: NomRun::lire(nom)?,
        })
    };
    let wmi = |reste: &str| {
        let (mot, hex) = reste.split_once(' ')?;
        Some(AbonnementWmi {
            classe: ClasseConsumer::TOUTES.into_iter().find(|c| c.mot() == mot)?,
            // Jamais un abonnement de Windows ni de Defender, ni dans un sens ni dans l'autre.
            nom: NomConsumer::lire(hex).filter(|n| !abonnement_wmi_protege(n.texte()))?,
        })
    };
    let acte = if let Some(r) = long(RUN_RETIRER_MACHINE) {
        run(r).map(Acte::RunRetirer)
    } else if let Some(r) = long(RUN_REMETTRE) {
        run(r).map(Acte::RunRemettre)
    } else if let Some(r) = long(TACHE_DESACTIVER) {
        CheminTache::lire(r).map(Acte::TacheDesactiver)
    } else if let Some(r) = long(TACHE_REACTIVER) {
        CheminTache::lire(r).map(Acte::TacheReactiver)
    } else if let Some(r) = long(DEMARRAGE_QUARANTAINE) {
        CheminFichier::lire(r).map(Acte::DemarrageQuarantaine)
    } else if let Some(r) = long(DEMARRAGE_REMETTRE) {
        CheminFichier::lire(r).map(Acte::DemarrageRemettre)
    } else if let Some(r) = court(WMI_ABONNEMENT_RETIRER) {
        wmi(r).map(Acte::WmiAbonnementRetirer)
    } else if let Some(r) = court(WMI_ABONNEMENT_REMETTRE) {
        wmi(r).map(Acte::WmiAbonnementRemettre)
    } else if let Some(r) = court(SERVICE_RETIRER) {
        NomService::lire(r).map(Acte::ServiceRetirer)
    } else if let Some(r) = long(LANCEMENT_DESACTIVER) {
        r.rsplit_once(' ').and_then(|(l, v)| {
            Some(Acte::LancementDesactiver(
                LancementMachine::lire(l)?,
                ValeurDesactivee::lire(v)?,
            ))
        })
    } else if let Some(r) = long(LANCEMENT_REACTIVER) {
        LancementMachine::lire(r).map(Acte::LancementReactiver)
    } else {
        None
    };
    acte.filter(|a| a.ligne() == ligne)
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
    /// Mettre un réglage de Defender au choix exact de la personne, baisse comprise : une baisse, jugée sur la
    /// valeur relue, n'est faite que montrée, dans une liste de baisses seulement, et confirmée (`liste_pure`).
    DefenderChoix(ReglageDefender, ChoixDefender),
    /// Mettre une règle ASR au choix exact de la personne, mêmes gardes que `DefenderChoix`.
    DefenderAsrChoix(&'static str, ChoixAsr),
    /// Remettre ce qu'un choix a baissé : la valeur d'avant notée si elle est au moins allumée, sinon la valeur sûre.
    /// La ligne ne porte aucune valeur.
    Rallumer(IdChoix),
    /// Ajouter une exclusion de Defender au choix de la personne (P5) : une baisse, mêmes gardes que `DefenderChoix`.
    DefenderExclusionAjouter(GenreExclusion, Exclusion),
    /// Permettre un programme malgré l'accès contrôlé aux dossiers, au choix de la personne : une baisse.
    DefenderDossiersAutoriser(Exclusion),
    /// Noter comme choix de la personne un réglage coupé hors de Vanguard (P11), après la question d'une baisse.
    ChoixNoter(IdChoix),
    /// Régler un profil du pare-feu au choix exact de la personne (`true` : la valeur la plus fermée), mêmes gardes
    /// que `DefenderChoix`, plus celle de la session à distance au moment d'écrire (`refus_profil_session`).
    PareFeuProfil(ProfilPareFeu, ReglagePareFeu, bool),
    /// Activer (`true`) ou désactiver une règle existante du pare-feu, jamais l'effacer ; mêmes gardes
    /// (`refus_regle_session`).
    PareFeuRegleEtat(ActionRegle, EmpreinteElement, bool),
    /// Écrire le fichier préparé à la place du hosts, la différence rejugée (`juger_hosts`) et montrée avant.
    HostsEcrire(HostsEcrire),
    /// Remettre en automatique les serveurs DNS d'une carte réseau.
    DnsAuto(GuidReseau),
    /// Régler les serveurs DNS d'une carte réseau, sur des serveurs de la liste fermée (`RESOLVEURS`).
    DnsServeurs(DnsServeurs),
    /// Désactiver le compte local de ce RID, jamais l'activer (`refus_desactivation`).
    CompteDesactiver(u32),
    /// Retirer un certificat racine signalé, jamais en ajouter.
    CertificatRetirer(MagasinRacine, Empreinte),
    /// Retirer d'un partage les autorisations d'un compte, jamais en donner.
    PartageRetirerAcces(AccesPartage),
    /// Retirer une valeur de démarrage de la machine que le bilan signale (donnée d'avant notée).
    RunRetirer(ValeurRunMachine),
    /// Remettre la donnée qu'un retrait de valeur de démarrage a notée, jamais une autre.
    RunRemettre(ValeurRunMachine),
    /// Désactiver une tâche planifiée signalée (passe b).
    TacheDesactiver(CheminTache),
    /// Réactiver une tâche que Vanguard a désactivée (passe b).
    TacheReactiver(CheminTache),
    /// Mettre en quarantaine un fichier du dossier Démarrage commun (passe b).
    DemarrageQuarantaine(CheminFichier),
    /// Ressortir de la quarantaine un fichier que Vanguard y a mis (passe b).
    DemarrageRemettre(CheminFichier),
    /// Retirer un abonnement WMI signalé (passe c).
    WmiAbonnementRetirer(AbonnementWmi),
    /// Recréer un abonnement WMI que Vanguard a retiré (passe c).
    WmiAbonnementRemettre(AbonnementWmi),
    /// Supprimer le service d'un outil de prise en main à distance (passe d), irréversible.
    ServiceRetirer(NomService),
    /// Désactiver un programme de démarrage de la machine comme le Gestionnaire des tâches (StartupApproved).
    LancementDesactiver(LancementMachine, ValeurDesactivee),
    /// Remettre les octets de StartupApproved qu'un `LancementDesactiver` a notés.
    LancementReactiver(LancementMachine),
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
            Acte::DefenderChoix(r, c) => format!("{DEFENDER_CHOIX}{} {}", r.id_choix(), c.mot()),
            Acte::DefenderAsrChoix(id, c) => format!("{DEFENDER_ASR_CHOIX}{id} {}", c.mot()),
            Acte::Rallumer(id) => format!("{RALLUMER}{}", id.texte()),
            Acte::DefenderExclusionAjouter(g, e) => format!("{DEFENDER_EXCLUSION_AJOUTER}{} {}", g.mot(), e.hex()),
            Acte::DefenderDossiersAutoriser(e) => format!("{DEFENDER_DOSSIERS_AUTORISER}{}", e.hex()),
            Acte::ChoixNoter(id) => format!("{CHOIX_NOTER}{}", id.texte()),
            Acte::PareFeuProfil(p, r, f) => format!("{PARE_FEU_PROFIL}{} {}={}", p.mot(), r.mot(), r.mot_valeur(*f)),
            Acte::PareFeuRegleEtat(a, e, actif) => format!(
                "{PARE_FEU_REGLE_ETAT}{}-{} {}",
                a.mot(),
                e.hex(),
                if *actif { "active" } else { "inactive" }
            ),
            Acte::HostsEcrire(h) => h.ligne(),
            Acte::DnsAuto(g) => format!("{DNS_AUTO}{}", g.texte()),
            Acte::DnsServeurs(d) => d.ligne(),
            Acte::CompteDesactiver(rid) => format!("{COMPTE_DESACTIVER}{rid}"),
            Acte::CertificatRetirer(m, e) => format!("{CERTIFICAT_RETIRER}{} {}", m.mot(), e.texte()),
            Acte::PartageRetirerAcces(a) => format!("{PARTAGE_RETIRER_ACCES}{} {}", a.nom.hex(), a.sid.texte()),
            Acte::RunRetirer(v) => format!("{RUN_RETIRER_MACHINE}{} {}", v.cle.mot(), v.nom.mot()),
            Acte::RunRemettre(v) => format!("{RUN_REMETTRE}{} {}", v.cle.mot(), v.nom.mot()),
            Acte::TacheDesactiver(t) => format!("{TACHE_DESACTIVER}{}", t.hex()),
            Acte::TacheReactiver(t) => format!("{TACHE_REACTIVER}{}", t.hex()),
            Acte::DemarrageQuarantaine(f) => format!("{DEMARRAGE_QUARANTAINE}{}", f.hex()),
            Acte::DemarrageRemettre(f) => format!("{DEMARRAGE_REMETTRE}{}", f.hex()),
            Acte::WmiAbonnementRetirer(w) => format!("{WMI_ABONNEMENT_RETIRER}{} {}", w.classe.mot(), w.nom.hex()),
            Acte::WmiAbonnementRemettre(w) => format!("{WMI_ABONNEMENT_REMETTRE}{} {}", w.classe.mot(), w.nom.hex()),
            Acte::ServiceRetirer(n) => format!("{SERVICE_RETIRER}{}", n.hex()),
            Acte::LancementDesactiver(l, v) => format!("{LANCEMENT_DESACTIVER}{} {}", l.mots(), v.hex()),
            Acte::LancementReactiver(l) => format!("{LANCEMENT_REACTIVER}{}", l.mots()),
        }
    }

    /// Ce qu'un choix règle et la valeur exacte qu'il vise (`None` : règle ASR absente, jamais visée ; pour
    /// `ChoixNoter`, rien n'est visé : la valeur reste) ; `None` pour un autre acte, `Rallumer` compris (sa cible
    /// dépend de la note relue).
    pub(crate) fn choix(&self) -> Option<(IdChoix, Option<i64>)> {
        match self {
            Acte::DefenderChoix(r, c) => Some((IdChoix::Defender(*r), r.valeur_choix(*c))),
            Acte::DefenderAsrChoix(id, c) => Some((IdChoix::Asr(id), Some(c.action()))),
            Acte::DefenderExclusionAjouter(g, e) => {
                Some((IdChoix::Exclusion(*g, EmpreinteElement::de(e.texte())), Some(1)))
            }
            Acte::DefenderDossiersAutoriser(e) => {
                Some((IdChoix::DossiersAutorise(EmpreinteElement::de(e.texte())), Some(1)))
            }
            Acte::ChoixNoter(id) => Some((*id, None)),
            Acte::PareFeuProfil(p, r, f) => Some((IdChoix::PareFeu(*p, *r), Some(i64::from(*f)))),
            Acte::PareFeuRegleEtat(a, e, actif) => Some((IdChoix::PareFeuRegle(*a, *e), Some(i64::from(*actif)))),
            _ => None,
        }
    }

    /// L'acte touche-t-il aux réglages d'une carte réseau (ses serveurs DNS) ? Refusé pendant une session à
    /// distance (`coupe_une_session`).
    pub(crate) fn touche_le_reseau(&self) -> bool {
        matches!(self, Acte::DnsAuto(_) | Acte::DnsServeurs(_))
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
            | Acte::DefenderExclusionRetirer(..)
            | Acte::CompteDesactiver(_)
            | Acte::CertificatRetirer(..)
            | Acte::PartageRetirerAcces(_)
            | Acte::Rallumer(_)
            // Supprimer un service ne se défait pas : une protection, que « Défaire » ne propose jamais.
            | Acte::ServiceRetirer(_) => true,
            Acte::PareFeuPublic(p) => p.durcit(),
            Acte::ReseauCategorie(r) => r.categorie == Categorie::Public,
            // Retirer des menaces nettoie : ni une protection remise, ni une remise qui affaiblit. Le hosts et le DNS
            // dépendent de ce qui change : la console élevée le dit d'après la différence relue.
            Acte::Vider(_)
            | Acte::ViderFileImpression
            | Acte::MettreDeCote(_)
            | Acte::DefenderMenacesRetirer
            // Un choix exact dépend de la valeur relue : le processus élevé en juge le sens (`sens`) avant d'écrire.
            | Acte::DefenderChoix(..)
            | Acte::DefenderAsrChoix(..)
            | Acte::DefenderExclusionAjouter(..)
            | Acte::DefenderDossiersAutoriser(..)
            | Acte::ChoixNoter(..)
            | Acte::PareFeuProfil(..)
            | Acte::PareFeuRegleEtat(..)
            | Acte::HostsEcrire(_)
            | Acte::DnsAuto(_)
            | Acte::DnsServeurs(_)
            // Retirer un lancement suspect se défait (donnée notée) : ni une protection remise que « Défaire » tairait,
            // ni une remise. Les remises, elles, affaiblissent.
            | Acte::RunRetirer(_)
            | Acte::RunRemettre(_)
            | Acte::TacheDesactiver(_)
            | Acte::TacheReactiver(_)
            | Acte::DemarrageQuarantaine(_)
            | Acte::DemarrageRemettre(_)
            | Acte::WmiAbonnementRetirer(_)
            | Acte::WmiAbonnementRemettre(_)
            // Un programme de démarrage choisi dans Optimiser : un confort, défait par Optimiser lui-même.
            | Acte::LancementDesactiver(..)
            | Acte::LancementReactiver(_) => false,
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
            | Acte::DefenderMenacesRetirer
            // Le sens d'un choix se juge sur la valeur relue (`sens`), jamais sur le type ; rallumer protège.
            | Acte::DefenderChoix(..)
            | Acte::DefenderAsrChoix(..)
            | Acte::DefenderExclusionAjouter(..)
            | Acte::DefenderDossiersAutoriser(..)
            | Acte::ChoixNoter(..)
            | Acte::PareFeuProfil(..)
            | Acte::PareFeuRegleEtat(..)
            | Acte::Rallumer(_)
            | Acte::HostsEcrire(_)
            | Acte::DnsAuto(_)
            | Acte::DnsServeurs(_)
            | Acte::CompteDesactiver(_)
            | Acte::CertificatRetirer(..)
            | Acte::PartageRetirerAcces(_)
            | Acte::RunRetirer(_)
            | Acte::TacheDesactiver(_)
            | Acte::DemarrageQuarantaine(_)
            | Acte::WmiAbonnementRetirer(_)
            | Acte::ServiceRetirer(_)
            // Remettre un programme qu'Optimiser avait désactivé (jamais un lancement jugé suspect par le bilan) ne
            // touche pas à la protection.
            | Acte::LancementDesactiver(..)
            | Acte::LancementReactiver(_) => false,
            // Un lancement que le bilan jugeait suspect revient : dit en toutes lettres avant l'accord.
            Acte::RunRemettre(_)
            | Acte::TacheReactiver(_)
            | Acte::DemarrageRemettre(_)
            | Acte::WmiAbonnementRemettre(_) => true,
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
            | Acte::DefenderMenacesRetirer
            | Acte::DefenderChoix(..)
            | Acte::DefenderAsrChoix(..)
            | Acte::DefenderExclusionAjouter(..)
            | Acte::DefenderDossiersAutoriser(..)
            | Acte::ChoixNoter(..)
            | Acte::Rallumer(_)
            // Les choix du pare-feu se jugent sur la valeur relue et la session en cours : par COM seulement.
            | Acte::PareFeuProfil(..)
            | Acte::PareFeuRegleEtat(..)
            // Aucun PowerShell sur le chemin d'écriture du hosts, des comptes, des racines ni des partages : sous Wine,
            // l'erreur est dite.
            | Acte::HostsEcrire(_)
            | Acte::CompteDesactiver(_)
            | Acte::CertificatRetirer(..)
            | Acte::PartageRetirerAcces(_)
            // Ni la persistance ni la prise en main à distance (lot 3.5) : natif seulement.
            | Acte::RunRetirer(_)
            | Acte::RunRemettre(_)
            | Acte::TacheDesactiver(_)
            | Acte::TacheReactiver(_)
            | Acte::DemarrageQuarantaine(_)
            | Acte::DemarrageRemettre(_)
            | Acte::WmiAbonnementRetirer(_)
            | Acte::WmiAbonnementRemettre(_)
            | Acte::ServiceRetirer(_)
            | Acte::LancementDesactiver(..)
            | Acte::LancementReactiver(_) => SANS_POWERSHELL.to_string(),
            Acte::DnsAuto(g) => powershell_dns_auto(*g),
            Acte::DnsServeurs(d) => d.powershell(),
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
        || ligne.starts_with(PARE_FEU_PROFIL)
        || ligne.starts_with(PARE_FEU_REGLE_ETAT)
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
        || ligne.starts_with(DEFENDER_CHOIX)
        || ligne.starts_with(DEFENDER_ASR_CHOIX)
        || ligne.starts_with(RALLUMER)
        || ligne.starts_with(HOSTS_ECRIRE)
        || ligne.starts_with(DNS_AUTO)
        || ligne.starts_with(DNS_SERVEURS)
        || ligne.starts_with(COMPTE_DESACTIVER)
        || ligne.starts_with(CERTIFICAT_RETIRER)
        || ligne.starts_with(PARTAGE_RETIRER_ACCES)
        || est_persistance(ligne)
}

/// L'acte d'une ligne, si et seulement si elle est exactement de sa forme : ASCII, 256 octets au plus (1086 pour
/// une ligne qui porte un nom en hexadécimal), sensible à la casse, un nom et une action de la table (une seule espace
/// entre chaque), réécrite à l'identique.
pub(crate) fn analyser_acte(ligne: &str) -> Option<Acte> {
    // L'écriture du hosts porte un chemin, plus long qu'un nom : sa propre borne.
    if let Some(reste) = ligne.strip_prefix(HOSTS_ECRIRE) {
        return (ligne.len() <= HOSTS_LIGNE_MAX && ligne.is_ascii())
            .then(|| HostsEcrire::analyser(reste))
            .flatten()
            .map(Acte::HostsEcrire)
            .filter(|a| a.ligne() == ligne);
    }
    // La persistance (lot 3.5) porte un nom de valeur ou un chemin : ses propres bornes.
    if est_persistance(ligne) {
        return analyser_persistance(ligne);
    }
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
    if let Some(reste) = ligne.strip_prefix(DEFENDER_EXCLUSION_AJOUTER) {
        let (mot, hex) = reste.split_once(' ')?;
        let genre = *GenreExclusion::TOUS.iter().find(|g| g.mot() == mot)?;
        return Some(Acte::DefenderExclusionAjouter(genre, Exclusion::lire(hex)?)).filter(|a| a.ligne() == ligne);
    }
    if let Some(hex) = ligne.strip_prefix(DEFENDER_DOSSIERS_AUTORISER) {
        return Some(Acte::DefenderDossiersAutoriser(Exclusion::lire(hex)?)).filter(|a| a.ligne() == ligne);
    }
    if let Some(reste) = ligne.strip_prefix(PARTAGE_RETIRER_ACCES) {
        let (hex, sid) = reste.split_once(' ')?;
        let acces = AccesPartage {
            nom: NomPartage::lire(hex)?,
            sid: SidTexte::lire(sid)?,
        };
        return Some(Acte::PartageRetirerAcces(acces)).filter(|a| a.ligne() == ligne);
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
    } else if let Some(reste) = ligne.strip_prefix(PARE_FEU_PROFIL) {
        analyser_pare_feu_profil(reste)?
    } else if let Some(reste) = ligne.strip_prefix(PARE_FEU_REGLE_ETAT) {
        analyser_regle_etat(reste)?
    } else if let Some(reste) = ligne.strip_prefix(DEFENDER) {
        let (mot, valeur) = reste.split_once(' ')?;
        let reglage = *ReglageDefender::TOUS.iter().find(|r| r.mot() == mot)?;
        Acte::Defender(reglage, *reglage.permises().iter().find(|v| v.mot() == valeur)?)
    } else if let Some(reste) = ligne.strip_prefix(DEFENDER_ASR) {
        let (id, mot) = reste.split_once(' ')?;
        Acte::DefenderAsr(asr_connue(id)?, *ModeAsr::TOUS.iter().find(|m| m.mot() == mot)?)
    } else if ligne == DEFENDER_MENACES_RETIRER {
        Acte::DefenderMenacesRetirer
    } else if let Some(reste) = ligne.strip_prefix(DEFENDER_CHOIX) {
        let (id, mot) = reste.split_once(' ')?;
        let reglage = *ReglageDefender::TOUS.iter().find(|r| r.id_choix() == id)?;
        Acte::DefenderChoix(reglage, *reglage.choix().iter().find(|c| c.mot() == mot)?)
    } else if let Some(reste) = ligne.strip_prefix(DEFENDER_ASR_CHOIX) {
        let (id, mot) = reste.split_once(' ')?;
        Acte::DefenderAsrChoix(asr_toute(id)?, *ChoixAsr::TOUS.iter().find(|c| c.mot() == mot)?)
    } else if let Some(id) = ligne.strip_prefix(RALLUMER) {
        Acte::Rallumer(IdChoix::lire(id)?)
    } else if let Some(id) = ligne.strip_prefix(CHOIX_NOTER) {
        Acte::ChoixNoter(IdChoix::lire(id)?)
    } else if let Some(reste) = ligne.strip_prefix(RESEAU_CATEGORIE) {
        let (guid, mot) = reste.split_once(' ')?;
        Acte::ReseauCategorie(ReseauCategorie {
            guid: GuidReseau::lire(guid)?,
            categorie: *[Categorie::Public, Categorie::Prive].iter().find(|c| c.mot() == mot)?,
        })
    } else if let Some(guid) = ligne.strip_prefix(DNS_AUTO) {
        Acte::DnsAuto(GuidReseau::lire(guid)?)
    } else if let Some(reste) = ligne.strip_prefix(DNS_SERVEURS) {
        Acte::DnsServeurs(DnsServeurs::analyser(reste)?)
    } else if let Some(rid) = ligne.strip_prefix(COMPTE_DESACTIVER) {
        Acte::CompteDesactiver(lire_rid(rid)?)
    } else if let Some(reste) = ligne.strip_prefix(CERTIFICAT_RETIRER) {
        let (mot, empreinte) = reste.split_once(' ')?;
        let magasin = *MagasinRacine::TOUS.iter().find(|m| m.mot() == mot)?;
        Acte::CertificatRetirer(magasin, Empreinte::lire(empreinte)?)
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

// Commune avec Linux et macOS (`machine::decoupe`) : où une liste de correctifs passe du natif au reste.
#[cfg_attr(not(windows), allow(unused_imports))]
pub(crate) use super::decoupe::{Morceau, decouper};

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

    // ------------------------------------------------------------ le réseau

    const GUID: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
    const PREPARE: &str = r"C:\Users\alice\AppData\Local\Vanguard\hosts-prepare\hosts";

    fn ligne_hosts(avant: &[u8], apres: &[u8]) -> String {
        ligne_hosts_ecrire(&empreinte_hosts(avant), &empreinte_hosts(apres), PREPARE).unwrap()
    }

    fn hosts_ecrire(l: &str) -> HostsEcrire {
        match analyser_acte(l) {
            Some(Acte::HostsEcrire(h)) => h,
            autre => panic!("{autre:?}"),
        }
    }

    #[test]
    fn la_ligne_du_hosts_a_une_forme_fixe() {
        let l = ligne_hosts(b"a", b"b");
        let h = hosts_ecrire(&l);
        assert_eq!(h.chemin, PREPARE);
        let a = analyser_acte(&l).unwrap();
        assert!(!a.durcit() && !a.affaiblit() && !a.touche_le_reseau());
        assert_eq!(a.powershell(), SANS_POWERSHELL);
        assert!(est_un_acte(&l));
        let e = empreinte_hosts(b"x");
        let hex = |c: &str| chemin_hex(c);
        for faux in [
            // Empreinte en minuscules, trop courte ; un champ de trop ; une espace doublée.
            format!("{HOSTS_ECRIRE}{} {e} {}", e.to_lowercase(), hex(PREPARE)),
            format!("{HOSTS_ECRIRE}{} {e} {}", &e[1..], hex(PREPARE)),
            format!("{HOSTS_ECRIRE}{e} {e} {} x", hex(PREPARE)),
            format!("{HOSTS_ECRIRE}{e}  {e} {}", hex(PREPARE)),
            // Chemin en majuscules hexadécimales, relatif, avec « .. », vers un autre fichier ou un autre dossier.
            format!("{HOSTS_ECRIRE}{e} {e} {}", hex(PREPARE).to_uppercase()),
            format!("{HOSTS_ECRIRE}{e} {e} {}", hex(r"hosts-prepare\hosts")),
            format!(
                "{HOSTS_ECRIRE}{e} {e} {}",
                hex(r"C:\x\hosts-prepare\..\hosts-prepare\hosts")
            ),
            format!("{HOSTS_ECRIRE}{e} {e} {}", hex(r"C:\x\hosts-prepare\hosts.ps1")),
            format!(
                "{HOSTS_ECRIRE}{e} {e} {}",
                hex(r"C:\Windows\System32\drivers\etc\hosts")
            ),
            format!("{HOSTS_ECRIRE}{e} {e} {}", hex("C:\\x\\hosts-prepare\\hosts\n")),
            // Trop longue.
            format!(
                "{HOSTS_ECRIRE}{e} {e} {}",
                hex(&format!(r"C:\{}\hosts-prepare\hosts", "a".repeat(HOSTS_LIGNE_MAX)))
            ),
        ] {
            assert!(analyser_acte(&faux).is_none(), "{faux}");
        }
        assert!(ligne_hosts_ecrire(&e, &e, r"C:\Windows\hosts").is_none());
    }

    #[test]
    fn le_diff_hostile_du_hosts_est_refuse() {
        let avant = b"127.0.0.1 localhost\r\n1.2.3.4 www.google.com\r\n".as_slice();
        let ok = |apres: &[u8]| juger_hosts(avant, apres);
        let bloc = |lignes: &str| format!("{HOSTS_DEBUT} : sites dangereux >>>\r\n{lignes}{HOSTS_FIN}\r\n");
        let avec = |lignes: &str| [avant, bloc(lignes).as_bytes()].concat();
        // Une ligne ajoutée hors du bloc, qui n'est pas de Vanguard, ou qui détourne.
        assert!(matches!(
            ok(&[avant, b"5.6.7.8 banque.ca\r\n"].concat()),
            Err(RefusHosts::LigneAjoutee(_))
        ));
        assert!(matches!(
            ok(&[avant, b"127.0.0.1 windowsupdate.com\r\n"].concat()),
            Err(RefusHosts::LigneAjoutee(_))
        ));
        // Dans le bloc : seulement « 0.0.0.0 nom » ou « :: nom », jamais un nom protégé.
        assert!(matches!(
            ok(&avec("127.0.0.1 windowsupdate.com\r\n")),
            Err(RefusHosts::LigneDuBloc(_))
        ));
        assert!(matches!(
            ok(&avec("5.6.7.8 banque.ca\r\n")),
            Err(RefusHosts::LigneDuBloc(_))
        ));
        assert!(matches!(
            ok(&avec("0.0.0.0  double.example\r\n")),
            Err(RefusHosts::LigneDuBloc(_))
        ));
        assert!(matches!(
            ok(&avec("0.0.0.0 a.example b.example\r\n")),
            Err(RefusHosts::LigneDuBloc(_))
        ));
        assert!(matches!(
            ok(&avec("0.0.0.0 Majuscule.example\r\n")),
            Err(RefusHosts::LigneDuBloc(_))
        ));
        for protege in [
            "windowsupdate.com",
            "download.windowsupdate.com",
            "github.com",
            "urlhaus-api.abuse.ch",
        ] {
            assert_eq!(
                ok(&avec(&format!("0.0.0.0 {protege}\r\n"))),
                Err(RefusHosts::NomProtege(protege.to_string())),
                "{protege}"
            );
        }
        // Un nom qui finit comme un nom protégé sans en être un sous-domaine passe.
        assert!(ok(&avec("0.0.0.0 pasgithub.com\r\n:: pasgithub.com\r\n")).is_ok());
        // Une ligne changée autrement qu'en commentaire, retirée, une fin de ligne changée.
        assert!(matches!(
            ok(b"127.0.0.1 localhost\r\n1.2.3.5 www.google.com\r\n"),
            Err(RefusHosts::LigneChangee(_))
        ));
        assert!(matches!(
            ok(b"127.0.0.1 localhost\r\n"),
            Err(RefusHosts::LigneRetiree(_))
        ));
        assert!(matches!(
            ok(b"127.0.0.1 localhost\n1.2.3.4 www.google.com\r\n"),
            Err(RefusHosts::LigneChangee(_))
        ));
        // Mettre « localhost » ou une liste de blocage en commentaire : refusé (seules les adresses d'hôte).
        assert!(matches!(
            ok(&[
                b"# Vanguard : 127.0.0.1 localhost\r\n".as_slice(),
                b"1.2.3.4 www.google.com\r\n"
            ]
            .concat()),
            Err(RefusHosts::LigneChangee(_))
        ));
        // UTF-16 (marque d'ordre des octets, octet nul), d'un côté ou de l'autre ; plus de 1 Mo.
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("127.0.0.1 localhost\r\n".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(ok(&utf16), Err(RefusHosts::Utf16));
        assert_eq!(juger_hosts(&utf16, avant), Err(RefusHosts::Utf16));
        assert_eq!(ok(&utf16[2..]), Err(RefusHosts::Utf16));
        let gros = [avant, &vec![b'#'; HOSTS_MAX]].concat();
        assert_eq!(ok(&gros), Err(RefusHosts::TropGros));
        assert_eq!(juger_hosts(&gros, avant), Err(RefusHosts::TropGros));
        // Deux blocs, une marque sans l'autre, une ligne après un bloc « fin de ligne ajoutée » (deux lignes collées).
        assert_eq!(
            ok(&[avec(""), bloc("").into_bytes()].concat()),
            Err(RefusHosts::BlocAbime)
        );
        assert_eq!(
            ok(&[avant, HOSTS_FIN.as_bytes(), b"\r\n"].concat()),
            Err(RefusHosts::BlocAbime)
        );
        assert_eq!(
            ok(&[avant, HOSTS_DEBUT.as_bytes(), b"\r\n"].concat()),
            Err(RefusHosts::BlocAbime)
        );
        let fdl = b"127.0.0.1 localhost\r\n1.2.3.4 www.google.com";
        let colle = [
            fdl.as_slice(),
            b"\r\n",
            format!("{HOSTS_DEBUT} {HOSTS_FDL_AJOUTEE} >>>\r\n{HOSTS_FIN}\r\n").as_bytes(),
            b"evil.example\r\n",
        ]
        .concat();
        assert_eq!(juger_hosts(fdl, &colle), Err(RefusHosts::BlocAbime));
        // Une marque de début démesurée ou avec un caractère de contrôle.
        let entete = format!("{HOSTS_DEBUT} {}\r\n{HOSTS_FIN}\r\n", "x".repeat(HOSTS_ENTETE_MAX));
        assert_eq!(ok(&[avant, entete.as_bytes()].concat()), Err(RefusHosts::Entete));
        let entete = format!("{HOSTS_DEBUT} \x1b[2J\r\n{HOSTS_FIN}\r\n");
        assert_eq!(ok(&[avant, entete.as_bytes()].concat()), Err(RefusHosts::Entete));

        // Dans le bloc, une tabulation ou un CR seul (deux lignes pour Windows, une pour qui découpe aux LF) : refusé.
        assert!(matches!(
            ok(&avec("0.0.0.0\tbanque.ca\r\n")),
            Err(RefusHosts::LigneDuBloc(_))
        ));
        assert!(matches!(
            ok(&avec("0.0.0.0 a.example\r5.6.7.8 banque.ca\r\n")),
            Err(RefusHosts::LigneDuBloc(_))
        ));
        // Un bloc vide (plus aucun site bloqué) est admis.
        assert!(ok(&avec("")).is_ok());
        // Un hosts qui commence par la marque UTF-8 (BOM) : elle reste en tête, rien ne s'ajoute.
        let bom = b"\xEF\xBB\xBF127.0.0.1 localhost\r\n1.2.3.4 www.google.com\r\n".as_slice();
        let commente = hosts_commente(bom, |_| true);
        assert!(
            commente.starts_with(b"\xEF\xBB\xBF127.0.0.1 localhost\r\n# Vanguard : 1.2.3.4"),
            "{commente:?}"
        );
        assert!(juger_hosts(bom, &commente).is_ok());
        assert!(matches!(
            juger_hosts(bom, &[bom, b"5.6.7.8 banque.ca\r\n"].concat()),
            Err(RefusHosts::LigneAjoutee(_))
        ));
    }

    /// Une ligne montrée dans la fenêtre élevée ne peut pas se maquiller : ni contrôle, ni marque de sens d'écriture
    /// (U+202E retournerait la ligne à l'écran), ni caractère invisible.
    #[test]
    fn une_ligne_montree_ne_se_maquille_pas() {
        for piege in [
            "\u{202E}", "\u{2066}", "\u{200B}", "\u{200F}", "\u{FEFF}", "\u{061C}", "\x1b",
        ] {
            let l = lisible(format!("1.2.3.4 a{piege}b.example").as_bytes());
            assert_eq!(l, "1.2.3.4 a\u{FFFD}b.example", "{piege:?}");
        }
        assert_eq!(lisible("1.2.3.4 é.example".as_bytes()), "1.2.3.4 é.example");
    }

    #[test]
    fn le_hosts_prepare_change_apres_l_empreinte_est_refuse() {
        let avant = b"1.2.3.4 www.google.com\r\n".to_vec();
        let apres = hosts_commente(&avant, |_| true);
        let h = hosts_ecrire(&ligne_hosts(&avant, &apres));
        let diff = verifier_hosts(&h, &apres, &avant).unwrap();
        assert_eq!(diff.commentees, ["1.2.3.4 www.google.com"]);
        // Le fichier préparé change pendant la demande d'administrateur : refusé, même pour un changement admis.
        let autre = [
            apres.as_slice(),
            format!("{HOSTS_DEBUT} >>>\r\n0.0.0.0 x.example\r\n{HOSTS_FIN}\r\n").as_bytes(),
        ]
        .concat();
        assert!(juger_hosts(&avant, &autre).is_ok());
        assert_eq!(verifier_hosts(&h, &autre, &avant), Err(RefusHosts::PrepareChange));
        // Le hosts change entre la lecture et l'écriture.
        assert_eq!(
            verifier_hosts(&h, &apres, b"9.9.9.9 x.example\r\n"),
            Err(RefusHosts::HostsChange)
        );
        // Plus de 1 Mo : refusé avant toute empreinte.
        assert_eq!(
            verifier_hosts(&h, &vec![b'#'; HOSTS_MAX + 1], &avant),
            Err(RefusHosts::TropGros)
        );
        // Une ligne forgée qui a les bonnes empreintes reste jugée.
        let forge = [avant.as_slice(), b"127.0.0.1 windowsupdate.com\r\n"].concat();
        let h = hosts_ecrire(&ligne_hosts(&avant, &forge));
        assert!(matches!(
            verifier_hosts(&h, &forge, &avant),
            Err(RefusHosts::LigneAjoutee(_))
        ));
    }

    #[test]
    fn mettre_en_commentaire_puis_bloquer_puis_retirer() {
        // Fins de ligne mêlées, accent, dernière ligne sans fin de ligne : chaque octet hors du bloc est gardé.
        let avant = "# à moi\n127.0.0.1 localhost\r\n0.0.0.0 pub.example\n192.168.1.5 nas.local\n1.2.3.4 www.google.com # détourné\n2001:db8::1 v6.example".as_bytes();
        let commente = hosts_commente(avant, |ip| !matches!(ip, std::net::IpAddr::V4(a) if a.is_private()));
        let d = juger_hosts(avant, &commente).unwrap();
        assert_eq!(
            d.commentees,
            ["1.2.3.4 www.google.com # détourné", "2001:db8::1 v6.example"]
        );
        assert!(!d.vide() && !d.bloc_avant && !d.bloc_apres);
        assert_eq!(juger_hosts(avant, avant).unwrap(), DiffHosts::default());
        assert!(juger_hosts(avant, avant).unwrap().vide());
        // Un bloc ajouté après une dernière ligne sans fin de ligne (« fin de ligne ajoutée »), puis retiré.
        let bloque = [
            commente.as_slice(),
            format!("\n{HOSTS_DEBUT} {HOSTS_FDL_AJOUTEE} : le 2026-11-02 >>>\n0.0.0.0 mal.example\n:: mal.example\n{HOSTS_FIN}\n").as_bytes(),
        ]
        .concat();
        let d = juger_hosts(&commente, &bloque).unwrap();
        assert_eq!(d.ajoutes, ["mal.example"]);
        assert!(d.retires.is_empty() && d.bloc_apres && !d.bloc_avant);
        let d = juger_hosts(&bloque, &commente).unwrap();
        assert_eq!(d.retires, ["mal.example"]);
        // Le hosts lu peut avoir un bloc abîmé dans ses lignes (retirer ne détourne rien), pas le nouveau.
        let vieux = format!("1.1.1.1 a.example\n{HOSTS_DEBUT} >>>\n127.0.0.1 vieux.example\n{HOSTS_FIN}\n");
        assert!(juger_hosts(vieux.as_bytes(), b"1.1.1.1 a.example\n").is_ok());
        assert!(matches!(
            juger_hosts(b"1.1.1.1 a.example\n", vieux.as_bytes()),
            Err(RefusHosts::LigneDuBloc(_))
        ));
    }

    /// Une adresse écrite autrement (IPv4 à l'ancienne, indice de zone, IPv4 en IPv6) est lue comme celle qu'elle
    /// désigne : elle n'échappe ni à la mise en commentaire, ni au refus d'un nom du bloc qui serait une adresse.
    #[test]
    fn les_adresses_ecrites_autrement_sont_lues() {
        let ip = |t: &str| t.parse::<std::net::IpAddr>().unwrap();
        for (ecrite, lue) in [
            ("127.1", "127.0.0.1"),
            ("0x7f.0.0.1", "127.0.0.1"),
            ("0X7F.0.0.1", "127.0.0.1"),
            ("0177.0.0.1", "127.0.0.1"),
            ("2130706433", "127.0.0.1"),
            ("0x7f000001", "127.0.0.1"),
            ("::ffff:1.2.3.4", "1.2.3.4"),
            ("1.2.3.4%eth0", "1.2.3.4"),
            ("fe80::1%3", "fe80::1"),
            ("2a00:1450::1%5", "2a00:1450::1"),
            ("0x5d.0xb8.0xd8.0x22", "93.184.216.34"),
            ("93.12113954", "93.184.216.34"),
            ("93.184.55330", "93.184.216.34"),
            ("1572395042", "93.184.216.34"),
            ("0", "0.0.0.0"),
            ("00.0.0.0", "0.0.0.0"),
            ("1.2.3.4", "1.2.3.4"),
            ("::", "::"),
        ] {
            assert_eq!(adresse_hosts(ecrite), Some(ip(lue)), "{ecrite}");
        }
        for pas_une in [
            "",
            "1.2.3.4.5",
            "1.2.3.",
            ".1.2.3",
            "256.0.0.1",
            "1.2.3.256",
            "1.2.65536",
            "1.16777216",
            "4294967296",
            "08.0.0.1",
            "0x.0.0.1",
            "0xg.0.0.1",
            "+1.2.3.4",
            "1.2.3.4%",
            "1.2.3.4%a b",
            "1.2.3.4%a/b",
            "1.2.3.4%%",
            "pub.exemple.com",
            "1.2.3.4.nip.io",
        ] {
            assert_eq!(adresse_hosts(pas_une), None, "{pas_une:?}");
        }
        // Un nom du bloc qui serait une adresse sous une autre forme est refusé.
        for n in ["127.1", "0x7f.0.0.1", "0177.0.0.1", "93.12113954"] {
            assert!(!nom_hosts_valide(n), "{n}");
        }
        assert!(nom_hosts_valide("1.2.3.4.nip.io"));
        // Mises en commentaire : chaque redirection, quelle que soit sa forme ; jamais le bouclage écrit autrement.
        let avant = "127.1 localhost\n0177.0.0.1 boucle.example\n0x5d.0xb8.0xd8.0x22 banque.example\n\
                     1572395042 hexa.example\n::ffff:93.184.216.34 mappee.example\n93.184.216.34%eth0 zone.example\n\
                     2130706433 boucle2.example\n"
            .as_bytes();
        let commente = hosts_commente(avant, |_| true);
        let d = juger_hosts(avant, &commente).unwrap();
        assert_eq!(
            d.commentees,
            [
                "0x5d.0xb8.0xd8.0x22 banque.example",
                "1572395042 hexa.example",
                "::ffff:93.184.216.34 mappee.example",
                "93.184.216.34%eth0 zone.example"
            ]
        );
        // Mettre en commentaire une ligne de bouclage écrite autrement reste refusé.
        let forge = [HOSTS_COMMENTE.as_bytes(), avant].concat();
        assert!(matches!(juger_hosts(avant, &forge), Err(RefusHosts::LigneChangee(_))));
        // Le bloc n'admet que « 0.0.0.0 » ou « :: » écrits ainsi : « 0 nom » ou « 0x0.0.0.0 nom » sont refusés.
        for ligne in ["0 mal.example", "0x0.0.0.0 mal.example", "::ffff:0.0.0.0 mal.example"] {
            let b = format!("{HOSTS_DEBUT} : le 2026-11-02 >>>\n{ligne}\n{HOSTS_FIN}\n");
            assert!(
                matches!(juger_hosts(b"", b.as_bytes()), Err(RefusHosts::LigneDuBloc(_))),
                "{ligne}"
            );
        }
    }

    #[test]
    fn empreinte_des_scripts_et_du_hosts() {
        // Les vecteurs de SHA-256 (FIPS 180-2), en majuscules comme PowerShell et `sha256_hex`.
        assert_eq!(
            empreinte_hosts(b"abc"),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert!(empreinte_majuscule(&empreinte_hosts(b"")));
    }

    #[test]
    fn le_dns_d_une_carte_hors_liste_ou_hors_forme_est_refuse() {
        let a = |l: Option<String>| analyser_acte(&l.unwrap()).unwrap();
        let auto = a(ligne_dns_auto(&GUID.to_lowercase()));
        assert!(matches!(auto, Acte::DnsAuto(_)) && auto.touche_le_reseau());
        assert_eq!(auto.ligne(), format!("{DNS_AUTO}{GUID}"));
        assert!(auto.powershell().contains("-ResetServerAddresses") && auto.powershell().contains(GUID));
        assert_eq!(ligne_dns(GUID, Some(""), Some("")), ligne_dns_auto(GUID));
        let d = a(ligne_dns(GUID, Some("1.1.1.1,1.0.0.1"), Some("2606:4700:4700::1111")));
        assert!(d.touche_le_reseau() && !d.durcit() && !d.affaiblit());
        assert!(
            d.powershell()
                .ends_with("@('1.1.1.1','1.0.0.1','2606:4700:4700::1111')"),
            "{}",
            d.powershell()
        );
        // Un côté laissé tel quel : pas d'équivalent PowerShell (il écrit les deux familles).
        assert_eq!(a(ligne_dns(GUID, Some("9.9.9.9"), None)).powershell(), SANS_POWERSHELL);
        let Acte::DnsServeurs(s) = a(ligne_dns(GUID, Some("192.168.1.1"), Some(""))) else {
            panic!()
        };
        // La box : hors de la liste, acceptée par la grammaire, jugée par le processus élevé (valeur d'avant notée).
        assert!(s.v4.hors_liste() && !s.v6.hors_liste() && s.v6 == CoteDns::Vider);
        // La ligne la plus longue de la liste tient dans la borne.
        let v6 = RESOLVEURS
            .iter()
            .filter(|r| r.contains(':'))
            .take(4)
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        let v4 = RESOLVEURS
            .iter()
            .filter(|r| !r.contains(':'))
            .take(4)
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        assert!(ligne_dns(GUID, Some(&v4), Some(&v6)).is_some());
        for (v4, v6) in [
            // Mauvaise famille, écriture non canonique, doublon, plus de quatre, bouclage, « 0.0.0.0 », multidiffusion,
            // diffusion, IPv4 dans IPv6, espace, nom.
            (Some("2620:fe::fe"), None),
            (None, Some("9.9.9.9")),
            (Some("009.9.9.9"), None),
            (None, Some("2620:FE::FE")),
            (None, Some("2620:00fe::fe")),
            (Some("9.9.9.9,9.9.9.9"), None),
            (Some("1.1.1.1,1.0.0.1,9.9.9.9,8.8.8.8,8.8.4.4"), None),
            (Some("127.0.0.1"), None),
            (Some("0.0.0.0"), None),
            (Some("224.0.0.1"), None),
            (Some("255.255.255.255"), None),
            (None, Some("::1")),
            (None, Some("::")),
            (None, Some("ff02::1")),
            (None, Some("::ffff:1.1.1.1")),
            (Some("1.1.1.1, 1.0.0.1"), None),
            (Some("dns.google"), None),
            (Some("1.1.1.1,"), None),
            // Ne rien faire, ou tout vider autrement que par dns-auto.
            (None, None),
        ] {
            assert!(ligne_dns(GUID, v4, v6).is_none(), "{v4:?} {v6:?}");
        }
        let l = |reste: &str| analyser_acte(&format!("{DNS_SERVEURS}{reste}"));
        assert!(l(&format!("{GUID} |")).is_none());
        assert!(l(&format!("{GUID} -|-")).is_none());
        assert!(l(&format!("{GUID} 1.1.1.1")).is_none());
        assert!(l(&format!("{GUID} 1.1.1.1|-|-")).is_none());
        assert!(l(&format!("{GUID}  1.1.1.1|-")).is_none());
        // Le GUID : forme exacte, réécrit en majuscules.
        for guid in [
            "4D36E972-E325-11CE-BFC1-08002BE10318",
            "{4D36E972-E325-11CE-BFC1-08002BE1031}",
            "{4D36E972E32511CEBFC108002BE10318}",
            "{4D36E972-E325-11CE-BFC1-08002BE1031G}",
            "{../../../../../../..../hosts}",
            "",
        ] {
            assert!(ligne_dns_auto(guid).is_none(), "{guid}");
            assert!(ligne_dns(guid, Some("1.1.1.1"), None).is_none(), "{guid}");
        }
        assert!(analyser_acte(&format!("{DNS_AUTO}{}", GUID.to_lowercase())).is_none());
        assert!(analyser_acte(&format!("{DNS_AUTO}{GUID} ")).is_none());
    }

    #[test]
    fn le_reseau_n_est_jamais_touche_pendant_une_session_a_distance() {
        let release = analyser_programme(&ligne_programme("ipconfig-release", None)).unwrap();
        let renew = analyser_programme(&ligne_programme("ipconfig-renew", None)).unwrap();
        let flush = analyser_programme(&ligne_programme("ipconfig-flushdns", None)).unwrap();
        assert!(release.coupe_le_reseau() && renew.coupe_le_reseau() && !flush.coupe_le_reseau());
        let dns = analyser_acte(&ligne_dns_auto(GUID).unwrap()).unwrap();
        for touche in [release.coupe_le_reseau(), dns.touche_le_reseau()] {
            // Bureau à distance, une session SSH ou de prise en main, ou des connexions illisibles : refusé.
            assert!(coupe_une_session(touche, true, Some(0)));
            assert!(coupe_une_session(touche, false, Some(1)));
            assert!(coupe_une_session(touche, false, None));
            assert!(!coupe_une_session(touche, false, Some(0)));
        }
        assert!(!coupe_une_session(flush.coupe_le_reseau(), true, None));
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

    fn hex(s: &str) -> String {
        hex_utf16(&s.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn desactiver_un_compte_se_lit_par_son_rid() {
        let a = analyser_acte("vanguard:compte-desactiver 501").unwrap();
        assert!(matches!(a, Acte::CompteDesactiver(501)) && a.durcit() && !a.affaiblit() && !a.touche_le_reseau());
        assert_eq!(a.powershell(), SANS_POWERSHELL);
        assert!(est_un_acte(&a.ligne()) && analyser_compte(&a.ligne()).is_none());
        assert_eq!(
            ligne_compte_desactiver("S-1-5-21-1004336348-1177238915-682003330-500").as_deref(),
            Some("vanguard:compte-desactiver 500")
        );
        assert_eq!(
            analyser_acte("vanguard:compte-desactiver 4294967295").unwrap().ligne(),
            "vanguard:compte-desactiver 4294967295"
        );
        // Hors d'un compte local S-1-5-21-a-b-c-RID de RID 500 ou plus : aucune ligne.
        for sid in [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-1-2-3-499",
            "S-1-5-21-1-2-500",
            "S-1-5-21-1-2-3-4-500",
            "S-1-5-21-1-2-3-0500",
            "S-1-5-80-1-2-3-500",
            "s-1-5-21-1-2-3-500",
            "",
        ] {
            assert_eq!(ligne_compte_desactiver(sid), None, "{sid}");
        }
    }

    #[test]
    fn les_lignes_de_compte_forgees_sont_refusees() {
        for reste in [
            "499",
            "0",
            "0500",
            "00500",
            "4294967296",
            "99999999999999999999",
            "+500",
            "-500",
            " 500",
            "500 ",
            "500\n",
            "5 00",
            "",
            "0x1f4",
            "500.0",
            "５００",
            "S-1-5-21-1-2-3-500",
            "alice",
        ] {
            assert!(
                analyser_acte(&format!("{COMPTE_DESACTIVER}{reste}")).is_none(),
                "{reste:?}"
            );
        }
        // Aucun verbe pour activer, ajouter à un groupe ou changer un mot de passe : la ligne n'est rien.
        for l in [
            "vanguard:compte-activer 1001",
            "vanguard:compte-desactiver",
            "vanguard:compte-desactiver  500",
            "Vanguard:compte-desactiver 500",
            "vanguard:compte-administrateur 1001",
        ] {
            assert!(analyser_acte(l).is_none(), "{l:?}");
        }
    }

    #[test]
    fn retirer_une_racine_se_lit_en_minuscules() {
        let e = "0123456789abcdef0123456789abcdef01234567";
        for (mot, m) in [("lm", MagasinRacine::Ordinateur), ("cu", MagasinRacine::Compte)] {
            let l = format!("{CERTIFICAT_RETIRER}{mot} {e}");
            let a = analyser_acte(&l).unwrap();
            assert!(matches!(&a, Acte::CertificatRetirer(m2, e2) if *m2 == m && e2.texte() == e));
            assert!(a.durcit() && !a.affaiblit() && a.powershell() == SANS_POWERSHELL);
            assert_eq!(
                ligne_certificat_retirer(m.nom(), &e.to_ascii_uppercase()).as_deref(),
                Some(l.as_str())
            );
        }
        let Some(Acte::CertificatRetirer(_, emp)) = analyser_acte(&format!("{CERTIFICAT_RETIRER}lm {e}")) else {
            panic!()
        };
        assert_eq!(
            emp.octets().unwrap(),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
                0x23, 0x45, 0x67
            ]
        );
        assert_eq!(ligne_certificat_retirer("Disallowed", e), None);
        assert_eq!(ligne_certificat_retirer("LocalMachine", &e[1..]), None);
    }

    #[test]
    fn les_lignes_de_racine_forgees_sont_refusees() {
        let e = "0123456789abcdef0123456789abcdef01234567";
        for reste in [
            format!("lm {}", &e[1..]),
            format!("lm {e}0"),
            format!("lm {}", e.to_ascii_uppercase()),
            format!("lm {}g", &e[1..]),
            format!("lm  {e}"),
            format!("lm {e} "),
            format!("LM {e}"),
            format!("ca {e}"),
            format!("root {e}"),
            format!("disallowed {e}"),
            e.to_string(),
            "lm".to_string(),
            format!("lm {e} lm"),
            // Aucun ajout : seul « retirer » existe.
            format!("lm {e} ajouter"),
        ] {
            assert!(
                analyser_acte(&format!("{CERTIFICAT_RETIRER}{reste}")).is_none(),
                "{reste:?}"
            );
        }
        assert!(analyser_acte(&format!("vanguard:certificat-ajouter lm {e}")).is_none());
    }

    #[test]
    fn retirer_un_acces_de_partage_se_lit() {
        let l = format!("{PARTAGE_RETIRER_ACCES}{} S-1-1-0", hex("Données"));
        let a = analyser_acte(&l).unwrap();
        assert!(matches!(&a, Acte::PartageRetirerAcces(p) if p.nom.texte() == "Données" && p.sid.texte() == "S-1-1-0"));
        assert!(a.durcit() && !a.affaiblit() && !a.touche_le_reseau() && a.powershell() == SANS_POWERSHELL);
        assert_eq!(
            ligne_partage_retirer_acces("Données", "S-1-1-0").as_deref(),
            Some(l.as_str())
        );
        // Un nom de 80 unités et un SID de 15 nombres : la ligne la plus longue passe.
        let long = "é".repeat(PARTAGE_NOM_MAX);
        let sid = format!("S-1-281474976710655{}", "-4294967295".repeat(14));
        let l = ligne_partage_retirer_acces(&long, &sid).unwrap();
        assert!(l.len() > ACTE_MAX && l.len() <= ACTE_NOM_MAX);
        assert!(analyser_acte(&l).is_some());
    }

    #[test]
    fn les_partages_administratifs_ne_se_touchent_jamais() {
        // ADMIN$, IPC$, C$ : le Bureau à distance, l'administration à distance et les partages cachés en dépendent.
        for nom in ["ADMIN$", "IPC$", "C$", "print$", "Caché$", "$"] {
            assert_eq!(ligne_partage_retirer_acces(nom, "S-1-1-0"), None, "{nom}");
            assert!(
                analyser_acte(&format!("{PARTAGE_RETIRER_ACCES}{} S-1-1-0", hex(nom))).is_none(),
                "{nom}"
            );
        }
    }

    #[test]
    fn les_lignes_de_partage_forgees_sont_refusees() {
        let p = hex("Public");
        let mut refusees = vec![
            // Nom : vide, trop long, majuscules, unité nulle, contrôle, demi-substitut, groupe incomplet.
            " S-1-1-0".to_string(),
            format!("{} S-1-1-0", hex(&"a".repeat(PARTAGE_NOM_MAX + 1))),
            format!("{} S-1-1-0", p.to_ascii_uppercase()),
            format!("{p}0000 S-1-1-0"),
            format!("{} S-1-1-0", hex("Pub\nlic")),
            format!("{p}00d8 S-1-1-0"),
            format!("{p}50 S-1-1-0"),
            "Public S-1-1-0".to_string(),
            // SID : forme stricte seulement.
            format!("{p} S-1-1"),
            format!("{p} S-1-01-0"),
            format!("{p} S-1-1-00"),
            format!("{p} s-1-1-0"),
            format!("{p} S-2-1-0"),
            format!("{p} S-1-1-0-"),
            format!("{p} S-1--1-0"),
            format!("{p} S-1-1-4294967296"),
            format!("{p} S-1-281474976710656-0"),
            format!("{p} S-1-1-+0"),
            // 16 sous-autorités : une de plus que SID_MAX_SUB_AUTHORITIES.
            format!("{p} S-1-5{}", "-1".repeat(16)),
            format!("{p} Everyone"),
            format!("{p} S-1-1-0 "),
            format!("{p}  S-1-1-0"),
            p.clone(),
            format!("{p} S-1-1-0 S-1-1-0"),
        ];
        refusees.push(format!("{} S-1-1-0", "00".repeat(ACTE_NOM_MAX)));
        for reste in refusees {
            assert!(
                analyser_acte(&format!("{PARTAGE_RETIRER_ACCES}{reste}")).is_none(),
                "{reste:?}"
            );
        }
        assert!(analyser_acte(&format!("vanguard:partage-ajouter-acces {p} S-1-1-0")).is_none());
        // 15 sous-autorités, le plus que Windows admet : lu.
        assert!(analyser_acte(&format!("{PARTAGE_RETIRER_ACCES}{p} S-1-5{}", "-1".repeat(15))).is_some());
    }

    type Changer = fn(&mut EtatCompte);

    fn etat<'a>(trouves: &'a [&'a str]) -> EtatCompte<'a> {
        EtatCompte {
            rid: 500,
            trouves,
            personne: Some("S-1-5-21-1-2-3-1001"),
            soi: Some("S-1-5-21-1-2-3-1002"),
            signale: true,
            administrateur: true,
            autres_administrateurs: 1,
            programmes: Some(false),
        }
    }

    #[test]
    fn les_gardes_de_desactivation() {
        let admin = ["S-1-5-21-1-2-3-500"];
        assert_eq!(refus_desactivation(&etat(&admin)), None);
        let cas: [(Changer, RefusCompte); 12] = [
            (|e| e.personne = None, RefusCompte::PersonneIllisible),
            (|e| e.trouves = &[], RefusCompte::Introuvable),
            (
                |e| e.trouves = &["S-1-5-21-1-2-3-500", "S-1-5-21-9-9-9-500"],
                RefusCompte::Introuvable,
            ),
            (|e| e.trouves = &["S-1-5-21-1-2-3-501"], RefusCompte::Introuvable),
            // Le compte de la personne, ou celui du processus administrateur : jamais.
            (|e| e.personne = Some("S-1-5-21-1-2-3-500"), RefusCompte::CompteEnCours),
            (|e| e.personne = Some("s-1-5-21-1-2-3-500"), RefusCompte::CompteEnCours),
            (|e| e.soi = Some("S-1-5-21-1-2-3-500"), RefusCompte::CompteEnCours),
            (|e| e.soi = None, RefusCompte::CompteEnCours),
            (|e| e.signale = false, RefusCompte::NonSignale),
            // Le dernier administrateur actif : jamais.
            (|e| e.autres_administrateurs = 0, RefusCompte::DernierAdministrateur),
            // Une session ouverte sous ce compte (sur l'écran, Bureau à distance, SSH) : jamais coupée.
            (|e| e.programmes = Some(true), RefusCompte::SessionOuverte),
            (|e| e.programmes = None, RefusCompte::ProgrammesIllisibles),
        ];
        for (changer, refus) in cas {
            let mut e = etat(&admin);
            changer(&mut e);
            assert_eq!(refus_desactivation(&e), Some(refus), "{e:?}");
        }
        // Un compte qui n'est pas administrateur peut partir même seul ; un compte réservé de Windows, jamais.
        let invite = ["S-1-5-21-1-2-3-501"];
        let mut e = etat(&invite);
        e.rid = 501;
        e.administrateur = false;
        e.autres_administrateurs = 0;
        assert_eq!(refus_desactivation(&e), None);
        for rid in [503, 504, 999] {
            let sid = [format!("S-1-5-21-1-2-3-{rid}")];
            let trouves = [sid[0].as_str()];
            let mut e = etat(&trouves);
            e.rid = rid;
            assert_eq!(refus_desactivation(&e), Some(RefusCompte::Reserve), "{rid}");
        }
    }

    // ------------------------------------------------- persistance et prise en main à distance (lot 3.5)

    /// La ligne passe-t-elle `valider`, seule (aucune ligne autre qu'un acte admise) ?
    fn valide_seule(ligne: &str) -> bool {
        valider(&[ligne.to_string()], |_| None::<()>).is_some()
    }

    #[test]
    fn retrait_run_machine_aller_retour() {
        let nom: Vec<u16> = "Mise à jour".encode_utf16().collect();
        for (cle, mot) in [
            (r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "run"),
            (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
            (
                r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                "run32",
            ),
        ] {
            let ligne = ligne_run_retirer_machine(cle, &nom).expect(cle);
            assert_eq!(ligne, format!("{RUN_RETIRER_MACHINE}{mot} {}", hex_utf16(&nom)));
            let a = analyser_acte(&ligne).expect(&ligne);
            assert!(matches!(&a, Acte::RunRetirer(v) if v.nom.unites() == nom.as_slice() && v.cle.mot() == mot));
            assert!(!a.durcit() && !a.affaiblit() && !a.touche_le_reseau());
            assert_eq!(a.powershell(), SANS_POWERSHELL);
            assert!(valide_seule(&ligne), "{ligne}");
            // La remise : même forme, elle affaiblit.
            let remise = ligne.replacen(RUN_RETIRER_MACHINE, RUN_REMETTRE, 1);
            let r = analyser_acte(&remise).expect(&remise);
            assert!(matches!(r, Acte::RunRemettre(_)) && r.affaiblit() && !r.durcit());
            assert!(valide_seule(&remise));
        }
        // La valeur par défaut : « defaut », jamais un hexadécimal vide.
        let defaut = ligne_run_retirer_machine(r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", &[]).unwrap();
        assert_eq!(defaut, format!("{RUN_RETIRER_MACHINE}run defaut"));
        assert!(matches!(analyser_acte(&defaut), Some(Acte::RunRetirer(v)) if v.nom.unites().is_empty()));
        // Un nom qui n'est pas de l'UTF-16 valide se retire quand même.
        let orphelin =
            ligne_run_retirer_machine(r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", &[0xd800, 0x41]);
        assert!(orphelin.as_deref().and_then(analyser_acte).is_some());
        // Les clés de la personne et toute autre clé : pas une ligne de la machine.
        for cle in [
            r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
            r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ] {
            assert_eq!(ligne_run_retirer_machine(cle, &nom), None, "{cle}");
        }
        // Le plus long nom tient dans une ligne du tube ; un de plus, non.
        let long = vec![0x41u16; RUN_MACHINE_NOM_MAX];
        let ligne = ligne_run_retirer_machine(
            r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            &long,
        )
        .unwrap();
        assert!(ligne.len() <= LIGNE_MAX && valide_seule(&ligne));
        let trop = vec![0x41u16; RUN_MACHINE_NOM_MAX + 1];
        assert_eq!(
            ligne_run_retirer_machine(r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", &trop),
            None
        );
        assert!(analyser_acte(&format!("{RUN_RETIRER_MACHINE}run {}", hex_utf16(&trop))).is_none());
    }

    #[test]
    fn retrait_run_machine_forge_refuse() {
        let a = hex_utf16(&[0x41]);
        let lignes = [
            // Nom vide en hexadécimal, NUL, hexadécimal mal formé, majuscules, clé inconnue ou en majuscules.
            format!("{RUN_RETIRER_MACHINE}run "),
            format!("{RUN_RETIRER_MACHINE}run 0000"),
            format!("{RUN_RETIRER_MACHINE}run 00410000"),
            format!("{RUN_RETIRER_MACHINE}run 041"),
            format!("{RUN_RETIRER_MACHINE}run 004A"),
            format!("{RUN_RETIRER_MACHINE}run Defaut"),
            format!("{RUN_RETIRER_MACHINE}runservices {a}"),
            format!("{RUN_RETIRER_MACHINE}Run {a}"),
            format!("{RUN_RETIRER_MACHINE}run32once {a}"),
            // Espaces en trop, champ en trop ou manquant.
            format!("{RUN_RETIRER_MACHINE}run  {a}"),
            format!("{RUN_RETIRER_MACHINE}run {a} "),
            format!("{RUN_RETIRER_MACHINE}run {a} {a}"),
            format!("{RUN_RETIRER_MACHINE}run"),
            format!("{RUN_RETIRER_MACHINE}{a}"),
            format!("{RUN_REMETTRE}run {a}x"),
            // Plus long que ce que tient le tube.
            format!("{RUN_RETIRER_MACHINE}run {}", "0041".repeat(LIGNE_MAX)),
        ];
        for l in &lignes {
            assert!(analyser_acte(l).is_none(), "{l}");
            assert!(!valide_seule(l), "{l}");
        }
    }

    #[test]
    fn run_protege_garde_windows_et_defender() {
        for (nom, programme) in [
            ("SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe"),
            ("securityhealth", r"C:\autre.exe"),
            ("Windows Defender", r"C:\x.exe"),
            ("WindowsDefender", r"C:\x.exe"),
            ("Mise à jour", r#""C:\Program Files\Windows Defender\MSASCuiL.exe""#),
            (
                "x",
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            ),
            ("x", r"c:/windows/system32/securityhealthsystray.exe"),
        ] {
            assert!(run_protege(nom, programme), "{nom} {programme}");
        }
        for (nom, programme) in [
            ("Updater", r"C:\Users\Public\updater.exe"),
            ("SecurityHealthX", r"C:\x.exe"),
            ("", r"C:\Users\Public\a.exe"),
        ] {
            assert!(!run_protege(nom, programme), "{nom} {programme}");
        }
    }

    #[test]
    fn tache_et_demarrage_chemins() {
        let t = |c: &str| format!("{TACHE_DESACTIVER}{}", hex_texte(c));
        for c in [
            r"\Mise à jour",
            r"\Dossier\Tâche 2",
            r"\MicrosoftEdgeUpdateTaskMachineCore",
        ] {
            let a = analyser_acte(&t(c)).unwrap_or_else(|| panic!("{c}"));
            assert!(matches!(&a, Acte::TacheDesactiver(p) if p.texte() == c) && !a.affaiblit());
            let r = analyser_acte(&t(c).replacen(TACHE_DESACTIVER, TACHE_REACTIVER, 1)).unwrap();
            assert!(r.affaiblit() && !r.durcit());
        }
        for c in [
            "",
            r"Tache",
            r"\",
            r"\\serveur\x",
            r"\a\\b",
            r"\a\..\Microsoft\Windows\x",
            r"\a\.\b",
            r"\Microsoft",
            r"\microsoft\windows\Defrag\ScheduledDefrag",
            r"\MICROSOFT\Windows\x",
            // Une lettre non ASCII que la table de casse de Windows peut ramener à « Microsoft ».
            "\\M\u{131}crosoft\\Windows\\x",
            "\\Micro\u{17f}oft",
            "\\Micro\u{17f}oft\\x",
            r"\a\NUL",
            r"\a/b",
            r"\a:b",
            "\\a\u{0}b",
            "\\a\nb",
            r"\a\b.",
            r"\a ",
        ] {
            assert!(analyser_acte(&t(c)).is_none(), "{c:?}");
        }
        assert!(analyser_acte(&t(&format!(r"\{}", "a".repeat(TACHE_CHEMIN_MAX)))).is_none());
        assert!(analyser_acte(&t(&format!(r"\{}", "a".repeat(TACHE_CHEMIN_MAX - 1)))).is_some());

        let d = |c: &str| format!("{DEMARRAGE_QUARANTAINE}{}", hex_texte(c));
        let commun = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\x.lnk";
        let a = analyser_acte(&d(commun)).unwrap();
        assert!(matches!(&a, Acte::DemarrageQuarantaine(f) if f.texte() == commun));
        let r = analyser_acte(&d(commun).replacen(DEMARRAGE_QUARANTAINE, DEMARRAGE_REMETTRE, 1)).unwrap();
        assert!(r.affaiblit());
        for c in [
            r"\\?\C:\x.lnk",
            r"\\.\C:\x.lnk",
            r"\\serveur\partage\x.lnk",
            r"\x.lnk",
            r"C:x.lnk",
            r"C:\",
            r"1:\x.lnk",
            r"C:\a\x.lnk:flux",
            r"C:\a\x.lnk::$DATA",
            r"C:\a\..\Windows\x.lnk",
            r"C:\a\.\x.lnk",
            r"C:\a\\x.lnk",
            r"C:\a/x.lnk",
            "C:\\a\\x\u{0}.lnk",
            r"C:\a\x.lnk.",
            r"C:\a\x.lnk ",
            r"C:\a\*.lnk",
            r#"C:\a\"x".lnk"#,
            // Périphériques de DOS, quelle que soit l'extension, et noms courts.
            r"C:\a\NUL.lnk",
            r"C:\a\con",
            r"C:\a\Com1.lnk",
            r"C:\a\lpt9 .lnk",
            "C:\\a\\COM\u{b9}.lnk",
            r"C:\a\CONOUT$.lnk",
            r"C:\PROGRA~1\x.lnk",
            r"C:\a\XLNK~12.LNK",
        ] {
            assert!(analyser_acte(&d(c)).is_none(), "{c:?}");
        }
        // Ce qui y ressemble sans en être reste admis.
        for c in [
            r"C:\a\console.lnk",
            r"C:\a\COM10.lnk",
            r"C:\a\nulle.lnk",
            r"C:\a\x~y.lnk",
        ] {
            assert!(analyser_acte(&d(c)).is_some(), "{c:?}");
        }
        // Plus de 32 767 unités : refusé (et la ligne dépasse de toute façon le tube).
        let long = format!(r"C:\{}", "a".repeat(CHEMIN_MAX));
        assert_eq!(CheminFichier::nouveau(&long), None);
        assert!(analyser_acte(&d(&long)).is_none());
        assert!(CheminFichier::nouveau(&format!(r"C:\{}", "a".repeat(CHEMIN_MAX - 3))).is_some());
        // Toute ligne portée par le tube reste sous LIGNE_MAX.
        let plus_long = format!(r"\{}", "a".repeat(TACHE_CHEMIN_MAX - 1));
        assert!(t(&plus_long).len() <= LIGNE_MAX);
    }

    #[test]
    fn wmi_et_service_noms() {
        let ligne_wmi = |classe: &str, n: &str| format!("{WMI_ABONNEMENT_RETIRER}{classe} {}", hex_texte(n));
        let a = analyser_acte(&ligne_wmi("commande", "BVTConsumer x")).unwrap();
        assert!(matches!(&a, Acte::WmiAbonnementRetirer(c) if c.classe.classe() == "CommandLineEventConsumer"));
        assert!(!a.affaiblit() && !a.durcit());
        assert!(matches!(
            analyser_acte(&ligne_wmi("script", "s")),
            Some(Acte::WmiAbonnementRetirer(_))
        ));
        let remise =
            analyser_acte(&ligne_wmi("script", "s").replacen(WMI_ABONNEMENT_RETIRER, WMI_ABONNEMENT_REMETTRE, 1))
                .unwrap();
        assert!(remise.affaiblit());
        for (classe, n) in [
            ("commande", ""),
            ("Commande", "a"),
            ("log", "a"),
            ("script", "a\u{0}"),
            ("script", "a\tb"),
            // Ne sort pas des guillemets d'un chemin d'objet WMI, n'y glisse pas d'échappement.
            ("script", "a\"b"),
            ("script", "a'b"),
            ("commande", "a\\b"),
        ] {
            assert!(analyser_acte(&ligne_wmi(classe, n)).is_none(), "{classe} {n:?}");
        }
        assert!(analyser_acte(&ligne_wmi("script", &"a".repeat(CONSUMER_NOM_MAX + 1))).is_none());
        assert!(analyser_acte(&ligne_wmi("script", &"a".repeat(CONSUMER_NOM_MAX))).is_some());

        let ligne_service = |n: &str| format!("{SERVICE_RETIRER}{}", hex_texte(n));
        for n in ["AnyDesk", "ScreenConnect Client (0123abcd)", "TeamViewer"] {
            let a = analyser_acte(&ligne_service(n)).unwrap_or_else(|| panic!("{n}"));
            // Irréversible : une protection, jamais une remise.
            assert!(matches!(&a, Acte::ServiceRetirer(x) if x.texte() == n) && a.durcit() && !a.affaiblit());
            assert!(valide_seule(&ligne_service(n)));
        }
        for n in ["", " AnyDesk", "AnyDesk ", r"a\b", "a/b", "a\u{0}", "a\nb"] {
            assert!(analyser_acte(&ligne_service(n)).is_none(), "{n:?}");
        }
        assert!(analyser_acte(&ligne_service(&"a".repeat(SERVICE_NOM_MAX + 1))).is_none());
        assert!(analyser_acte(&ligne_service(&"a".repeat(SERVICE_NOM_MAX))).is_some());
        // Le service et la classe sont en hexadécimal : jamais le nom en clair.
        assert!(analyser_acte(&format!("{SERVICE_RETIRER}AnyDesk")).is_none());
    }

    #[test]
    fn wmi_abonnements_proteges_refuses() {
        let ligne_wmi = |classe: &str, n: &str| format!("{WMI_ABONNEMENT_RETIRER}{classe} {}", hex_texte(n));
        for n in [
            "SCM Event Log Consumer",
            "scm event log consumer",
            " SCM Event Log Filter ",
            "BVTConsumer",
            "bvtfilter",
            "Windows Defender scan",
            "MICROSOFT DEFENDER",
            "Windows Security Health",
            "SecurityHealthService",
            "MsMpEng",
        ] {
            assert!(abonnement_wmi_protege(n), "{n}");
            // Ni par la grammaire (ligne forgée), ni par le bilan.
            for verbe in [WMI_ABONNEMENT_RETIRER, WMI_ABONNEMENT_REMETTRE] {
                let l = ligne_wmi("commande", n).replacen(WMI_ABONNEMENT_RETIRER, verbe, 1);
                assert!(analyser_acte(&l).is_none(), "{l}");
            }
            assert!(
                ligne_wmi_abonnement_retirer("CommandLineEventConsumer", n).is_none(),
                "{n}"
            );
        }
        for n in ["Updater", "BVTConsumer x", "SCM Event Log Consumer 2"] {
            assert!(!abonnement_wmi_protege(n), "{n}");
        }
        // Le bilan : la classe sans la casse, aller-retour par la grammaire.
        let l = ligne_wmi_abonnement_retirer("commandlineeventconsumer", "Updater").unwrap();
        assert_eq!(l, ligne_wmi("commande", "Updater"));
        assert!(matches!(analyser_acte(&l), Some(Acte::WmiAbonnementRetirer(w)) if w.nom.texte() == "Updater"));
        let l = ligne_wmi_abonnement_retirer("ActiveScriptEventConsumer", "s").unwrap();
        assert!(matches!(analyser_acte(&l), Some(Acte::WmiAbonnementRetirer(w)) if w.classe == ClasseConsumer::Script));
        for (classe, n) in [
            ("LogFileEventConsumer", "a"),
            ("NTEventLogEventConsumer", "a"),
            ("CommandLineEventConsumer", "a¦b"),
            ("CommandLineEventConsumer", "a\u{1b}b"),
            ("CommandLineEventConsumer", ""),
        ] {
            assert!(ligne_wmi_abonnement_retirer(classe, n).is_none(), "{classe} {n:?}");
        }
        // Un consumer qui lance Defender, quel que soit son nom.
        assert!(consumer_wmi_protege(
            "x",
            &[r#""C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan"#]
        ));
        assert!(!consumer_wmi_protege("x", &[r"C:\Users\alice\AppData\evil.exe -q"]));
    }

    fn note_essai() -> (AbonnementWmi, NoteWmi) {
        let w = AbonnementWmi {
            classe: ClasseConsumer::Commande,
            nom: NomConsumer::nouveau("Updater").unwrap(),
        };
        let t = |s: &str| ValeurNotee::Texte(s.to_string());
        let mut consumer = vec![ValeurNotee::Absente; PROPRIETES_COMMANDE.len()];
        consumer[0] = t("Updater");
        consumer[2] = t(r"cmd.exe /c C:\Users\Public\x.bat");
        consumer[6] = ValeurNotee::Entier(0);
        consumer[9] = ValeurNotee::Booleen(false);
        let filtre = |n: &str| ObjetNote {
            chemin: format!("__EventFilter.Name=\"{n}\""),
            valeurs: vec![
                t(n),
                t("SELECT * FROM __InstanceModificationEvent WITHIN 60"),
                t("WQL"),
                t(r"root\cimv2"),
                ValeurNotee::Absente,
            ],
        };
        let liaison = ObjetNote {
            chemin: "__FilterToConsumerBinding.Consumer=\"x\",Filter=\"y\"".to_string(),
            valeurs: vec![
                ValeurNotee::Booleen(false),
                ValeurNotee::Booleen(true),
                ValeurNotee::Absente,
                ValeurNotee::Entier(0),
            ],
        };
        let note = NoteWmi {
            classe: ClasseConsumer::Commande,
            consumer: ObjetNote {
                chemin: "CommandLineEventConsumer.Name=\"Updater\"".to_string(),
                valeurs: consumer,
            },
            liaisons: vec![
                LiaisonNotee {
                    filtre_retire: true,
                    filtre: filtre("F1"),
                    liaison: liaison.clone(),
                },
                LiaisonNotee {
                    filtre_retire: false,
                    filtre: filtre("Partagé"),
                    liaison,
                },
            ],
        };
        (w, note)
    }

    #[test]
    fn note_wmi_aller_retour_et_alterations() {
        let (w, note) = note_essai();
        assert!(note.valide(&w));
        let o = note.octets().unwrap();
        assert_eq!(NoteWmi::lire(&o).as_ref(), Some(&note));
        // Chaque octet changé, une troncature, un octet de plus : refusés (l'empreinte, puis la forme).
        for i in 0..o.len() {
            let mut x = o.clone();
            x[i] ^= 0x01;
            assert!(NoteWmi::lire(&x).is_none(), "octet {i}");
        }
        for n in 0..o.len() {
            assert!(NoteWmi::lire(&o[..n]).is_none(), "tronquée à {n}");
        }
        let mut plus = o.clone();
        plus.push(0);
        assert!(NoteWmi::lire(&plus).is_none());
        // Une autre version, même avec une empreinte refaite : refusée.
        let mut autre = o[..o.len() - 32].to_vec();
        autre[5] = 2;
        let e = empreinte_note(&autre);
        autre.extend_from_slice(&e);
        assert!(NoteWmi::lire(&autre).is_none());
        // Un octet de trop dans le corps, empreinte refaite : refusé (lecture exacte).
        let mut long = o[..o.len() - 32].to_vec();
        long.push(0);
        let e = empreinte_note(&long);
        long.extend_from_slice(&e);
        assert!(NoteWmi::lire(&long).is_none());
        assert!(NoteWmi::lire(&[]).is_none());
        assert!(NoteWmi::lire(&vec![0; NOTE_WMI_MAX + 1]).is_none());
    }

    #[test]
    fn note_wmi_valide_et_bornes() {
        let (w, note) = note_essai();
        // La note d'un autre abonnement, d'une autre classe : refusée.
        let autre = AbonnementWmi {
            nom: NomConsumer::nouveau("Autre").unwrap(),
            ..w.clone()
        };
        assert!(!note.valide(&autre));
        let script = AbonnementWmi {
            classe: ClasseConsumer::Script,
            ..w.clone()
        };
        assert!(!note.valide(&script));
        // Un filtre protégé à recréer : refusé ; resté en place, admis.
        let mut n = note.clone();
        n.liaisons[0].filtre.valeurs[0] = ValeurNotee::Texte("SCM Event Log Filter".to_string());
        assert!(!n.valide(&w));
        n.liaisons[0].filtre_retire = false;
        assert!(n.valide(&w));
        // Deux fois le même filtre, un nom de filtre vide ou avec un contrôle : refusés.
        let mut n = note.clone();
        n.liaisons[1].filtre = n.liaisons[0].filtre.clone();
        assert!(!n.valide(&w));
        for mauvais in ["", "a\nb"] {
            let mut n = note.clone();
            n.liaisons[0].filtre.valeurs[0] = ValeurNotee::Texte(mauvais.to_string());
            assert!(!n.valide(&w), "{mauvais:?}");
        }
        // Une valeur du mauvais genre, une propriété de moins : refusées.
        let mut n = note.clone();
        n.consumer.valeurs[6] = ValeurNotee::Texte("0".to_string());
        assert!(!n.valide(&w));
        let mut n = note.clone();
        n.consumer.valeurs.pop();
        assert!(!n.valide(&w));
        // Bornes : un texte trop long, trop de liaisons, un chemin trop long ne s'écrivent pas.
        let mut n = note.clone();
        n.consumer.valeurs[2] = ValeurNotee::Texte("a".repeat(NOTE_WMI_TEXTE_MAX + 1));
        assert!(n.octets().is_none() && !n.valide(&w));
        let mut n = note.clone();
        n.consumer.valeurs[2] = ValeurNotee::Texte("a".repeat(NOTE_WMI_TEXTE_MAX));
        assert!(n.valide(&w));
        assert_eq!(NoteWmi::lire(&n.octets().unwrap()), Some(n));
        let mut n = note.clone();
        n.liaisons = (0..=NOTE_WMI_LIAISONS_MAX)
            .map(|i| {
                let mut l = note.liaisons[0].clone();
                l.filtre.valeurs[0] = ValeurNotee::Texte(format!("F{i}"));
                l
            })
            .collect();
        assert!(n.octets().is_none() && !n.valide(&w));
        n.liaisons.pop();
        assert!(n.valide(&w) && n.octets().is_some());
        let mut n = note.clone();
        n.consumer.chemin = "a".repeat(NOTE_WMI_CHEMIN_MAX + 1);
        assert!(n.octets().is_none() && !n.valide(&w));
    }

    #[test]
    fn persistance_hexadecimal_canonique() {
        // Un contenu valide pour chaque verbe : écrit en majuscules, il est refusé pour cette seule raison.
        for (verbe, valide) in [
            (TACHE_DESACTIVER, r"\A"),
            (DEMARRAGE_QUARANTAINE, r"C:\x.lnk"),
            (SERVICE_RETIRER, "z"),
        ] {
            let hex = hex_texte(valide);
            assert!(valide_seule(&format!("{verbe}{hex}")), "{valide}");
            let l = format!("{verbe}{}", hex.to_ascii_uppercase());
            assert!(analyser_acte(&l).is_none(), "{l}");
            // NUL ajouté, unité incomplète, demi-caractère orphelin, rien : refusé.
            for suite in ["0000", "41", "00d8"] {
                let l = format!("{verbe}{hex}{suite}");
                assert!(analyser_acte(&l).is_none(), "{l}");
            }
            assert!(analyser_acte(verbe).is_none() && analyser_acte(verbe.trim_end()).is_none());
        }
        // Un octet non ASCII : refusé avant toute lecture.
        assert!(analyser_acte(&format!("{SERVICE_RETIRER}é")).is_none());
        // Un verbe proche n'est pas lu comme un autre acte.
        assert!(analyser_acte("vanguard:run-retirerx run 0041").is_none());
        assert!(est_un_acte(&format!("{SERVICE_RETIRER}zz")) && !valide_seule(&format!("{SERVICE_RETIRER}zz")));
    }

    #[test]
    fn lancement_machine_aller_retour() {
        let v = "030000001122334455667788";
        for (liste, mot) in [("Run", "run"), ("Run32", "run32"), ("StartupFolder", "dossier")] {
            let nom = "Mise à jour.lnk";
            let ligne = ligne_lancement(liste, nom, Some(v)).expect(liste);
            assert_eq!(ligne, format!("{LANCEMENT_DESACTIVER}{mot} {} {v}", hex_texte(nom)));
            let a = analyser_acte(&ligne).expect(&ligne);
            assert!(
                matches!(&a, Acte::LancementDesactiver(l, x) if l.nom() == nom && l.liste().mot() == mot && x.hex() == v)
            );
            assert!(!a.durcit() && !a.affaiblit() && !a.touche_le_reseau());
            assert_eq!(a.powershell(), SANS_POWERSHELL);
            assert!(est_un_acte(&ligne) && valide_seule(&ligne), "{ligne}");
            // Réactiver : la valeur d'avant (activée, ou absente) n'est pas dans la ligne, la note de l'enfant la porte.
            for voulue in [None, Some(""), Some("020000000000000000000000"), Some("06000000")] {
                let r = ligne_lancement(liste, nom, voulue).expect(liste);
                assert_eq!(r, format!("{LANCEMENT_REACTIVER}{mot} {}", hex_texte(nom)));
                assert!(matches!(analyser_acte(&r), Some(Acte::LancementReactiver(_))) && valide_seule(&r));
            }
        }
        // Le plus long nom tient dans une ligne du tube.
        let long = "a".repeat(RUN_MACHINE_NOM_MAX);
        let ligne = ligne_lancement("Run", &long, Some(v)).unwrap();
        assert!(ligne.len() <= LIGNE_MAX && valide_seule(&ligne));
        assert_eq!(ligne_lancement("Run", &format!("{long}a"), Some(v)), None);
        // Liste inconnue (celle du compte, RunOnce), nom vide, de contrôle, de fichier non sûr : pas de ligne.
        for (liste, nom) in [
            ("RunOnce", "x"),
            ("run", "x"),
            ("Run", ""),
            ("Run", "a\nb"),
            ("StartupFolder", r"..\x.lnk"),
            ("StartupFolder", r"a\b.lnk"),
            ("StartupFolder", "a:flux"),
        ] {
            assert_eq!(ligne_lancement(liste, nom, Some(v)), None, "{liste} {nom:?}");
        }
        // Une valeur désactivée autre que 03 00 00 00 + 8 octets : pas de ligne.
        assert_eq!(ligne_lancement("Run", "x", Some("0700000011223344")), None);
    }

    #[test]
    fn lancement_machine_forge_refuse() {
        let a = hex_texte("A");
        let v = "030000001122334455667788";
        let lignes = [
            // Valeur : majuscules, autre en-tête, longueur fausse, absente, en trop.
            format!("{LANCEMENT_DESACTIVER}run {a} 03000000112233445566778A"),
            format!("{LANCEMENT_DESACTIVER}run {a} 020000001122334455667788"),
            format!("{LANCEMENT_DESACTIVER}run {a} 07000000112233445566778"),
            format!("{LANCEMENT_DESACTIVER}run {a} 0300000011223344556677889"),
            format!("{LANCEMENT_DESACTIVER}run {a} 03000000112233445566778899"),
            format!("{LANCEMENT_DESACTIVER}run {a}"),
            format!("{LANCEMENT_REACTIVER}run {a} {v}"),
            // Liste inconnue ou en majuscules, nom vide, en majuscules, NUL, de dossier avec « \ ».
            format!("{LANCEMENT_DESACTIVER}Run {a} {v}"),
            format!("{LANCEMENT_DESACTIVER}runonce {a} {v}"),
            format!("{LANCEMENT_DESACTIVER}startupfolder {a} {v}"),
            format!("{LANCEMENT_DESACTIVER}run  {v}"),
            format!("{LANCEMENT_DESACTIVER}run 6A00 {v}"),
            format!("{LANCEMENT_DESACTIVER}run 41 {v}"),
            format!("{LANCEMENT_DESACTIVER}run 0000 {v}"),
            format!("{LANCEMENT_DESACTIVER}run 410000d8 {v}"),
            format!("{LANCEMENT_DESACTIVER}dossier {} {v}", hex_texte(r"a\b.lnk")),
            format!("{LANCEMENT_DESACTIVER}dossier {} {v}", hex_texte("..")),
            format!("{LANCEMENT_REACTIVER}dossier {}", hex_texte(r"..\x")),
            // Nom court de DOS : désignerait le fichier sans être le nom que StartupApproved retient.
            format!("{LANCEMENT_DESACTIVER}dossier {} {v}", hex_texte("SECURI~1.LNK")),
            format!("{LANCEMENT_REACTIVER}dossier {}", hex_texte("MAJ~2.LNK")),
            // Espaces en trop, champ manquant.
            format!("{LANCEMENT_DESACTIVER}run {a}  {v}"),
            format!("{LANCEMENT_DESACTIVER}run {a} {v} "),
            format!("{LANCEMENT_REACTIVER}run {a} "),
            format!("{LANCEMENT_REACTIVER}run"),
            format!("{LANCEMENT_REACTIVER}{a}"),
            // Plus long que ce que tient le tube.
            format!("{LANCEMENT_REACTIVER}run {}", "0041".repeat(LIGNE_MAX)),
            // Une tâche de Windows, même écrite comme une ligne de Vanguard.
            format!(
                "{TACHE_DESACTIVER}{}",
                hex_texte(r"\Microsoft\Windows\Defrag\ScheduledDefrag")
            ),
        ];
        for l in &lignes {
            assert!(analyser_acte(l).is_none(), "{l}");
            assert!(!valide_seule(l), "{l}");
        }
        // Le nom en clair n'est jamais lu.
        assert!(analyser_acte(&format!("{LANCEMENT_REACTIVER}run SecurityHealth")).is_none());
    }

    #[test]
    fn montrer_nom_coupe_et_nettoie() {
        assert_eq!(montrer_nom("a\u{1b}[2Jb"), "a?[2Jb");
        let long = "x".repeat(NOM_MONTRE_MAX + 5);
        let m = montrer_nom(&long);
        assert_eq!(m.chars().count(), NOM_MONTRE_MAX + 1);
        assert!(m.ends_with('…'));
        assert_eq!(NomRun::nouveau(&[]).and_then(|n| n.montre()), None);
    }

    /// Les choix exacts, baisses comprises, s'écrivent et se relisent à l'identique ; une forme approchée, une valeur
    /// que le réglage n'admet pas ou une règle hors de la table est refusée. Aucun n'est un renforcement déclaré par
    /// son type : le sens vient de la relecture (`sens`).
    #[test]
    fn choix_grammaire() {
        let mut vues = 0;
        for r in ReglageDefender::TOUS {
            for c in ChoixDefender::TOUS {
                let Some(l) = ligne_baisse_defender(r, c) else {
                    assert!(r.valeur_choix(c).is_none(), "{r:?} {c:?}");
                    continue;
                };
                vues += 1;
                let a = analyser_acte(&l).unwrap();
                assert!(matches!(a, Acte::DefenderChoix(r2, c2) if r2 == r && c2 == c), "{l}");
                assert_eq!(a.ligne(), l);
                assert!(
                    est_un_acte(&l) && !a.durcit() && !a.affaiblit() && !a.touche_le_reseau(),
                    "{l}"
                );
                assert_eq!(a.powershell(), SANS_POWERSHELL);
                let (id, v) = a.choix().unwrap();
                assert_eq!(id, IdChoix::Defender(r));
                assert!(methode_choix(id, v.unwrap()).is_some(), "{l}");
            }
        }
        // Cinq interrupteurs (allumé, coupé), le cloud (3), l'accès contrôlé (4), NP et PUA (3), les échantillons (4).
        assert_eq!(vues, 5 * 2 + 3 + 4 + 3 + 3 + 4);
        assert_eq!(
            ligne_baisse_defender(ReglageDefender::TempsReel, ChoixDefender::Coupe).unwrap(),
            "vanguard:defender-choix temps-reel coupe"
        );
        assert_eq!(
            ligne_baisse_defender(ReglageDefender::TempsReel, ChoixDefender::Audit),
            None
        );
        assert_eq!(
            ligne_baisse_defender(ReglageDefender::Maps, ChoixDefender::Bloquer),
            None
        );
        for id in ASR_TOUTES {
            for c in ChoixAsr::TOUS {
                let l = ligne_baisse_asr(id, c).unwrap();
                let a = analyser_acte(&l).unwrap();
                assert_eq!(a.ligne(), l);
                assert_eq!(a.choix(), Some((IdChoix::Asr(id), Some(c.action()))));
                assert!(!a.durcit() && !a.affaiblit());
            }
        }
        assert_eq!(
            ligne_baisse_asr("{56A863A9-875E-4185-98A7-B882C64B5CE5}", ChoixAsr::Audit),
            None
        );
        assert_eq!(
            ligne_baisse_asr("00000000-0000-0000-0000-000000000000", ChoixAsr::Audit),
            None
        );
        for l in [
            "vanguard:defender-choix temps-reel",
            "vanguard:defender-choix temps-reel 1",
            "vanguard:defender-choix temps-reel Coupe",
            "vanguard:defender-choix temps-reel coupe ",
            "vanguard:defender-choix  temps-reel coupe",
            "vanguard:defender-choix maps coupe",
            "vanguard:defender-choix cloud bloquer",
            "vanguard:defender-choix pua disques",
            "vanguard:defender-choix echantillons bloquer",
            "vanguard:defender-choix scripts audit",
            "vanguard:defender-choix cfa coupe",
            "vanguard:defender-asr-choix 56A863A9-875E-4185-98A7-B882C64B5CE5 audit",
            "vanguard:defender-asr-choix 56a863a9-875e-4185-98a7-b882c64b5ce5 avertir",
            "vanguard:defender-asr-choix 56a863a9-875e-4185-98a7-b882c64b5ce5 0",
            "vanguard:defender-asr-choix 56a863a9-875e-4185-98a7-b882c64b5ce5",
            "vanguard:defender-choix pua coupe,vanguard:defender-choix maps coupe",
        ] {
            assert!(analyser_acte(l).is_none() && est_un_acte(l), "{l}");
        }
    }

    /// `vanguard:rallumer` ne porte que l'identifiant, jamais de valeur ; c'est un renforcement, que « Défaire » ne
    /// propose pas.
    #[test]
    fn rallumer_grammaire() {
        let mut ids: Vec<IdChoix> = ReglageDefender::TOUS.iter().map(|r| IdChoix::Defender(*r)).collect();
        ids.extend(ASR_TOUTES.iter().map(|g| IdChoix::Asr(g)));
        for id in ids {
            assert_eq!(IdChoix::lire(&id.texte()), Some(id));
            let l = ligne_rallumer(id);
            let a = analyser_acte(&l).unwrap();
            assert_eq!(a.ligne(), l);
            assert!(matches!(a, Acte::Rallumer(i) if i == id));
            assert!(a.durcit() && !a.affaiblit() && a.choix().is_none() && est_un_acte(&l));
        }
        assert_eq!(
            ligne_rallumer(IdChoix::Defender(ReglageDefender::TempsReel)),
            "vanguard:rallumer defender-temps-reel"
        );
        for l in [
            "vanguard:rallumer defender-temps-reel 1",
            "vanguard:rallumer defender-temps-reel coupe",
            "vanguard:rallumer defender-maps",
            "vanguard:rallumer defender-",
            "vanguard:rallumer defender-Temps-reel",
            "vanguard:rallumer asr-56A863A9-875E-4185-98A7-B882C64B5CE5",
            "vanguard:rallumer asr-{56a863a9-875e-4185-98a7-b882c64b5ce5}",
            "vanguard:rallumer asr-00000000-0000-0000-0000-000000000000",
            "vanguard:rallumer ",
            "vanguard:rallumer",
            "vanguard:rallumer  defender-pua",
        ] {
            assert!(analyser_acte(l).is_none(), "{l}");
        }
        for t in [
            "defender-maps",
            "defender-",
            "asr-",
            "asr-x",
            "pua",
            "defender-pua ",
            "",
        ] {
            assert_eq!(IdChoix::lire(t), None, "{t}");
        }
    }

    #[test]
    fn toujours_demander_n_est_pas_une_baisse() {
        // Plan §2.1 : « toujours demander » des échantillons est un choix de vie privée ; seul « jamais » est baissé.
        let ech = IdChoix::Defender(ReglageDefender::Echantillons);
        assert!(!ech.baissee(Some(0)) && !ech.baissee(Some(1)) && !ech.baissee(Some(3)));
        assert!(ech.baissee(Some(2)) && ech.baissee(None));
        assert_eq!(cible_rallumer(ech, Some(Some(0))), 0);
        // Ailleurs, sous la valeur sûre est baissé : le cloud de base, l'audit, une règle ASR absente.
        assert!(IdChoix::Defender(ReglageDefender::Maps).baissee(Some(1)));
        assert!(IdChoix::Defender(ReglageDefender::Cfa).baissee(Some(2)));
        assert!(IdChoix::Asr(ASR_TOUTES[0]).baissee(None));
        assert!(!IdChoix::Defender(ReglageDefender::Pua).baissee(Some(1)));
    }

    /// Rallumer ne vise jamais plus faible qu'allumé : sans note, note abîmée (`None`), ou note qui dit « coupé » ou
    /// une valeur inconnue, c'est la valeur sûre.
    #[test]
    fn rallumer_plancher_allume() {
        let rtp = IdChoix::Defender(ReglageDefender::TempsReel);
        let maps = IdChoix::Defender(ReglageDefender::Maps);
        let cfa = IdChoix::Defender(ReglageDefender::Cfa);
        let pua = IdChoix::Defender(ReglageDefender::Pua);
        let asr = IdChoix::Asr(ASR_TOUTES[0]);
        assert_eq!(cible_rallumer(rtp, None), 0);
        assert_eq!(cible_rallumer(rtp, Some(Some(1))), 0);
        assert_eq!(cible_rallumer(rtp, Some(Some(0))), 0);
        assert_eq!(cible_rallumer(rtp, Some(None)), 0);
        assert_eq!(cible_rallumer(maps, Some(Some(1))), 1);
        assert_eq!(cible_rallumer(maps, Some(Some(0))), 2);
        assert_eq!(cible_rallumer(maps, Some(Some(7))), 2);
        assert_eq!(cible_rallumer(cfa, Some(Some(2))), 2);
        assert_eq!(cible_rallumer(cfa, Some(Some(3))), 3);
        assert_eq!(cible_rallumer(cfa, Some(Some(0))), 1);
        assert_eq!(cible_rallumer(pua, None), 1);
        assert_eq!(cible_rallumer(pua, Some(Some(-1))), 1);
        assert_eq!(cible_rallumer(asr, Some(None)), 1);
        assert_eq!(cible_rallumer(asr, Some(Some(0))), 1);
        assert_eq!(cible_rallumer(asr, Some(Some(5))), 1);
        assert_eq!(cible_rallumer(asr, Some(Some(6))), 6);
        assert_eq!(cible_rallumer(asr, Some(Some(2))), 2);
        // La cible s'écrit toujours (une méthode WMI existe), et elle est au moins allumée.
        for id in [rtp, maps, cfa, pua, asr, IdChoix::Defender(ReglageDefender::Np)] {
            assert!(id.rang(Some(id.sure())) >= id.plancher(), "{id:?}");
            assert!(methode_choix(id, id.sure()).is_some(), "{id:?}");
        }
    }

    /// Le sens se juge sur la valeur relue : plus fort, plus faible, déjà là ; illisible compte comme une baisse.
    #[test]
    fn sens_par_relecture() {
        let rtp = IdChoix::Defender(ReglageDefender::TempsReel);
        let cfa = IdChoix::Defender(ReglageDefender::Cfa);
        let asr = IdChoix::Asr(ASR_TOUTES[3]);
        assert_eq!(sens(rtp, Some(Some(0)), Some(1)), Sens::Baisse);
        assert_eq!(sens(rtp, Some(Some(1)), Some(0)), Sens::Renforce);
        assert_eq!(sens(rtp, Some(Some(1)), Some(1)), Sens::Rien);
        assert_eq!(sens(rtp, None, Some(0)), Sens::Baisse);
        assert_eq!(sens(cfa, Some(Some(1)), Some(2)), Sens::Baisse);
        assert_eq!(sens(cfa, Some(Some(3)), Some(1)), Sens::Renforce);
        // Même rang, autre valeur connue (audit de tout, audit des disques) : montrée comme une baisse, confirmée et
        // notée (relecture adverse : un changement de même rang ne passe plus sans question).
        assert_eq!(sens(cfa, Some(Some(4)), Some(2)), Sens::Baisse);
        assert_eq!(sens(cfa, Some(Some(2)), Some(4)), Sens::Baisse);
        assert_eq!(sens(cfa, Some(Some(4)), Some(4)), Sens::Rien);
        // Coupé et une valeur inconnue : même rang 0, jamais cru plus fort.
        assert_eq!(sens(cfa, Some(Some(9)), Some(0)), Sens::Baisse);
        assert_eq!(sens(asr, Some(None), Some(0)), Sens::Baisse);
        assert_eq!(sens(asr, Some(None), Some(1)), Sens::Renforce);
        assert_eq!(sens(asr, Some(Some(6)), Some(2)), Sens::Baisse);
        assert_eq!(sens(asr, Some(Some(2)), Some(2)), Sens::Rien);
    }

    /// Une baisse ne passe que dans une liste faite de choix ; parmi d'autres gestes, la liste est refusée en entier.
    #[test]
    fn liste_melee_refusee() {
        use Sens::{Baisse, Renforce, Rien};
        assert_eq!(liste_pure(&[]), Ok(false));
        assert_eq!(liste_pure(&[None, None]), Ok(false));
        assert_eq!(liste_pure(&[None, Some(Renforce), Some(Rien)]), Ok(false));
        assert_eq!(liste_pure(&[Some(Baisse)]), Ok(true));
        assert_eq!(liste_pure(&[Some(Baisse), Some(Rien), Some(Renforce)]), Ok(true));
        assert_eq!(liste_pure(&[Some(Baisse), None]), Err(()));
        assert_eq!(liste_pure(&[None, Some(Rien), Some(Baisse)]), Err(()));
        // Le parent sépare les choix des autres lignes : deux listes, chacune jugée à part.
        let l = |s: &str| s.to_string();
        let lignes = [
            l("vanguard:defender pua bloquer"),
            l("vanguard:defender-choix temps-reel coupe"),
            l("vanguard:rallumer defender-cloud"),
            l("vanguard:defender-asr-choix 56a863a9-875e-4185-98a7-b882c64b5ce5 audit"),
        ];
        assert_eq!(separer_choix(&lignes), vec![vec![0, 2], vec![1, 3]]);
        assert_eq!(separer_choix(&lignes[..1]), vec![vec![0]]);
        assert_eq!(separer_choix(&lignes[1..2]), vec![vec![0]]);
        assert_eq!(separer_choix(&[]), Vec::<Vec<usize>>::new());
    }

    /// L'écriture d'un choix vise la valeur exacte : Set pour un réglage (booléen pour le temps réel), Add pour une
    /// règle (Set remplacerait toute la liste) ; une valeur hors de ce que le réglage connaît n'a pas de méthode.
    #[test]
    fn methode_des_choix() {
        let rtp = IdChoix::Defender(ReglageDefender::TempsReel);
        assert_eq!(
            methode_choix(rtp, 1),
            Some(("Set", vec![("DisableRealtimeMonitoring", ValeurWmi::Booleen(true))]))
        );
        assert_eq!(methode_choix(rtp, 2), None);
        assert_eq!(
            methode_choix(IdChoix::Defender(ReglageDefender::Pua), 0),
            Some(("Set", vec![("PUAProtection", ValeurWmi::Octet(0))]))
        );
        assert_eq!(methode_choix(IdChoix::Defender(ReglageDefender::Maps), 3), None);
        assert_eq!(methode_choix(IdChoix::Defender(ReglageDefender::Cfa), -1), None);
        let (m, p) = methode_choix(IdChoix::Asr(ASR_TOUTES[0]), 0).unwrap();
        assert_eq!(m, "Add");
        assert_eq!(
            p[1],
            ("AttackSurfaceReductionRules_Actions", ValeurWmi::Octets(vec![0]))
        );
        assert_eq!(methode_choix(IdChoix::Asr(ASR_TOUTES[0]), 5), None);
        assert_eq!(methode_choix(IdChoix::Asr(ASR_TOUTES[0]), 256), None);
    }

    // ------------------------------------------------------------ le pare-feu : profils et règles (D5)

    /// Le Bureau à distance tel que Windows le pose : TCP 3389 entrant autorisé, svchost, TermService.
    fn regle_rdp(profils: i32) -> RegleLue {
        RegleLue {
            nom: "Remote Desktop - User Mode (TCP-In)".into(),
            entrante: true,
            active: true,
            profils,
            programme: r"%SystemRoot%\system32\svchost.exe".into(),
            protocole: PROTOCOLE_TCP,
            ports_locaux: "3389".into(),
            service: "termservice".into(),
            ..RegleLue::default()
        }
    }

    const ALLUME: EtatProfil = EtatProfil {
        actif: true,
        entrant_bloque: true,
        sortant_bloque: false,
        tout_bloque: false,
    };

    /// Une session vraie (Bureau à distance, SSH lue) et une session inconnue (connexions illisibles) : les deux
    /// gardent 3389 et 22 au moins ; aucune session, rien à garder.
    #[test]
    fn la_session_du_pare_feu_se_lit_au_plus_prudent() {
        assert_eq!(session_pare_feu(false, Some((false, &[]))), None);
        assert_eq!(session_pare_feu(false, None), Some(vec![22, 3389]));
        assert_eq!(session_pare_feu(false, Some((true, &[]))), Some(vec![22, 3389]));
        assert_eq!(session_pare_feu(false, Some((true, &[5900]))), Some(vec![5900]));
        assert_eq!(session_pare_feu(true, Some((false, &[]))), Some(vec![3389]));
        assert_eq!(session_pare_feu(true, Some((true, &[2222]))), Some(vec![2222, 3389]));
    }

    /// Les sessions simulées : vraie (Bureau à distance) et inconnue (connexions illisibles).
    fn sessions() -> [Vec<u16>; 2] {
        [
            session_pare_feu(true, Some((false, &[]))).unwrap(),
            session_pare_feu(false, None).unwrap(),
        ]
    }

    /// Gardes B (plan §2.3) : pendant une session, vraie ou inconnue, tout bloquer et bloquer les sorties sont
    /// refusés sur chaque profil du masque courant, et sur tous si le masque ne se lit pas.
    #[test]
    fn tout_bloquer_et_sorties_refuses_pendant_une_session() {
        let regles = [regle_rdp(0x7FFF_FFFF)];
        for s in sessions() {
            for p in ProfilPareFeu::TOUS {
                for courants in [Some(p.bit()), Some(7), None] {
                    assert_eq!(
                        refus_profil_session(
                            Some(&s),
                            courants,
                            p,
                            ReglagePareFeu::ToutBloquer,
                            true,
                            ALLUME,
                            &regles
                        ),
                        Some(RefusSession::ToutBloquer),
                        "{p:?} {courants:?}"
                    );
                    assert_eq!(
                        refus_profil_session(Some(&s), courants, p, ReglagePareFeu::Sortant, true, ALLUME, &regles),
                        Some(RefusSession::Sorties),
                        "{p:?} {courants:?}"
                    );
                }
            }
        }
    }

    /// Allumer un profil coupé qui bloquerait les sorties, ou tout en entrée, est refusé pendant une session.
    #[test]
    fn allumer_un_profil_qui_couperait_est_refuse() {
        let regles = [regle_rdp(0x7FFF_FFFF)];
        let coupe_sorties = EtatProfil {
            actif: false,
            sortant_bloque: true,
            ..ALLUME
        };
        let coupe_tout = EtatProfil {
            actif: false,
            tout_bloque: true,
            ..ALLUME
        };
        for s in sessions() {
            let p = ProfilPareFeu::Prive;
            assert_eq!(
                refus_profil_session(
                    Some(&s),
                    Some(2),
                    p,
                    ReglagePareFeu::Actif,
                    true,
                    coupe_sorties,
                    &regles
                ),
                Some(RefusSession::Sorties)
            );
            assert_eq!(
                refus_profil_session(Some(&s), Some(2), p, ReglagePareFeu::Actif, true, coupe_tout, &regles),
                Some(RefusSession::PortFerme)
            );
        }
        // Allumé tel que Windows le règle, avec la règle du Bureau à distance : la session du Bureau à distance passe
        // encore ; une session inconnue garde aussi 22, qu'aucune règle n'ouvre ici : refusé.
        let coupe = EtatProfil { actif: false, ..ALLUME };
        let [rdp, inconnue] = sessions();
        let p = ProfilPareFeu::Prive;
        assert_eq!(
            refus_profil_session(Some(&rdp), Some(2), p, ReglagePareFeu::Actif, true, coupe, &regles),
            None
        );
        assert_eq!(
            refus_profil_session(Some(&inconnue), Some(2), p, ReglagePareFeu::Actif, true, coupe, &regles),
            Some(RefusSession::PortFerme)
        );
    }

    /// Bloquer les entrées par défaut ferme la session sans règle qui l'ouvre ; avec la règle du Bureau à distance
    /// (et une règle SSH pour une session inconnue), elle passe.
    #[test]
    fn entrees_bloquees_selon_les_regles_de_la_session() {
        let ouvert = EtatProfil {
            entrant_bloque: false,
            ..ALLUME
        };
        let ssh = RegleLue {
            nom: "OpenSSH SSH Server (sshd)".into(),
            programme: r"C:\Windows\System32\OpenSSH\sshd.exe".into(),
            ports_locaux: "22".into(),
            service: String::new(),
            ..regle_rdp(0x7FFF_FFFF)
        };
        for s in sessions() {
            let p = ProfilPareFeu::Public;
            assert_eq!(
                refus_profil_session(Some(&s), Some(4), p, ReglagePareFeu::Entrant, true, ouvert, &[]),
                Some(RefusSession::PortFerme)
            );
            assert_eq!(
                refus_profil_session(
                    Some(&s),
                    Some(4),
                    p,
                    ReglagePareFeu::Entrant,
                    true,
                    ouvert,
                    &[regle_rdp(0x7FFF_FFFF), ssh.clone()]
                ),
                None
            );
        }
        // Une règle du Bureau à distance limitée à une adresse ne compte pas : dans le doute, refusé.
        let limitee = RegleLue {
            adresses_distantes: "192.168.1.20".into(),
            ..regle_rdp(0x7FFF_FFFF)
        };
        let s = session_pare_feu(true, Some((false, &[]))).unwrap();
        assert_eq!(
            refus_profil_session(
                Some(&s),
                Some(4),
                ProfilPareFeu::Public,
                ReglagePareFeu::Entrant,
                true,
                ouvert,
                &[limitee]
            ),
            Some(RefusSession::PortFerme)
        );
    }

    /// Couper le pare-feu ou autoriser n'ouvre que davantage : jamais refusé ; un profil hors du masque courant
    /// reste réglable ; sans session, rien n'est refusé.
    #[test]
    fn ce_qui_ouvre_et_les_profils_non_courants_restent_reglables() {
        for s in sessions() {
            for p in ProfilPareFeu::TOUS {
                for r in ReglagePareFeu::TOUS {
                    assert_eq!(
                        refus_profil_session(Some(&s), None, p, r, false, ALLUME, &[]),
                        None,
                        "{r:?}"
                    );
                }
            }
            // Domaine absent du masque courant (privé) : tout bloquer y est permis.
            assert_eq!(
                refus_profil_session(
                    Some(&s),
                    Some(2),
                    ProfilPareFeu::Domaine,
                    ReglagePareFeu::ToutBloquer,
                    true,
                    ALLUME,
                    &[]
                ),
                None
            );
        }
        assert_eq!(
            refus_profil_session(
                None,
                None,
                ProfilPareFeu::Public,
                ReglagePareFeu::ToutBloquer,
                true,
                ALLUME,
                &[]
            ),
            None
        );
    }

    /// Règles, pendant une session vraie ou inconnue : désactiver une autorisation entrante d'un profil courant est
    /// refusé ; désactiver celle de 3389 ou 22 l'est même sur un profil non courant ; une autorisation sortante
    /// l'est si les sorties sont (ou peuvent être) bloquées ; activer un blocage sortant, ou entrant qui touche la
    /// session, l'est aussi. Activer une autorisation et désactiver un blocage restent permis.
    #[test]
    fn regles_gardees_pendant_une_session() {
        let rdp_domaine = regle_rdp(1);
        let autre_entrante = RegleLue {
            nom: "Partage".into(),
            ports_locaux: "445".into(),
            programme: "System".into(),
            service: String::new(),
            profils: 2,
            ..regle_rdp(2)
        };
        let sortante = RegleLue {
            nom: "Navigateur".into(),
            entrante: false,
            ports_locaux: String::new(),
            programme: r"C:\Program Files\Nav\nav.exe".into(),
            service: String::new(),
            ..regle_rdp(2)
        };
        let ssh_bloque = RegleLue {
            nom: "Bloque SSH".into(),
            bloque: true,
            active: false,
            ports_locaux: "20-25".into(),
            ..regle_rdp(2)
        };
        let bloque_sortant = RegleLue {
            nom: "Bloque tout".into(),
            entrante: false,
            bloque: true,
            active: false,
            ..sortante.clone()
        };
        let autre_bloque = RegleLue {
            nom: "Bloque 8080".into(),
            bloque: true,
            active: false,
            ports_locaux: "8080".into(),
            ..regle_rdp(2)
        };
        for s in sessions() {
            let s = Some(s.as_slice());
            for courants in [Some(2), None] {
                assert_eq!(
                    refus_regle_session(s, courants, Some(false), &autre_entrante, false),
                    Some(RefusSession::RegleAutorisation)
                );
                // 3389 sur le domaine, profil non courant : gardée quand même.
                assert_eq!(
                    refus_regle_session(s, courants, Some(false), &rdp_domaine, false),
                    Some(RefusSession::RegleAutorisation)
                );
                for sorties in [Some(true), None] {
                    assert_eq!(
                        refus_regle_session(s, courants, sorties, &sortante, false),
                        Some(RefusSession::RegleAutorisation)
                    );
                }
                assert_eq!(refus_regle_session(s, courants, Some(false), &sortante, false), None);
                assert_eq!(
                    refus_regle_session(s, courants, Some(false), &ssh_bloque, true),
                    Some(RefusSession::RegleBlocage)
                );
                assert_eq!(
                    refus_regle_session(s, courants, Some(false), &bloque_sortant, true),
                    Some(RefusSession::RegleBlocage)
                );
                assert_eq!(refus_regle_session(s, courants, Some(false), &autre_bloque, true), None);
                // Ce qui ouvre davantage.
                assert_eq!(
                    refus_regle_session(s, courants, Some(true), &autre_entrante, true),
                    None
                );
                assert_eq!(refus_regle_session(s, courants, Some(true), &ssh_bloque, false), None);
            }
            // Une autorisation entrante d'un profil non courant, sans port gardé : permis.
            assert_eq!(
                refus_regle_session(s, Some(4), Some(false), &autre_entrante, false),
                None
            );
        }
        assert_eq!(refus_regle_session(None, None, None, &rdp_domaine, false), None);
    }

    #[test]
    fn etat_partage_des_regles() {
        assert_eq!(etat_des_regles(ActionRegle::Bloque, []), None);
        assert_eq!(etat_des_regles(ActionRegle::Bloque, [true, true]), Some(1));
        assert_eq!(etat_des_regles(ActionRegle::Bloque, [false]), Some(0));
        assert_eq!(etat_des_regles(ActionRegle::Bloque, [true, false]), Some(0));
        assert_eq!(etat_des_regles(ActionRegle::Autorise, [true, false]), Some(1));
    }

    /// Chaque ligne du pare-feu se relit à l'identique ; chaque identifiant aussi ; une forme voisine est refusée.
    #[test]
    fn lignes_et_identifiants_du_pare_feu() {
        for p in ProfilPareFeu::TOUS {
            for r in ReglagePareFeu::TOUS {
                for f in [true, false] {
                    let l = ligne_baisse_pare_feu(p, r, f);
                    assert!(est_un_acte(&l), "{l}");
                    assert_eq!(analyser_acte(&l).map(|a| a.ligne()), Some(l.clone()));
                    assert!(analyser_acte(&format!("{l} ")).is_none(), "{l}");
                    assert!(analyser_acte(&l.to_uppercase()).is_none(), "{l}");
                }
                let id = IdChoix::PareFeu(p, r);
                assert_eq!(IdChoix::lire(&id.texte()), Some(id));
                assert!(id.pare_feu() && !id.note_requise());
            }
        }
        let regle = regle_rdp(7);
        for active in [true, false] {
            let l = ligne_regle_etat(&regle, active);
            assert!(est_un_acte(&l), "{l}");
            assert!(matches!(
                analyser_acte(&l),
                Some(Acte::PareFeuRegleEtat(ActionRegle::Autorise, e, a)) if e == regle.empreinte() && a == active
            ));
        }
        let id = regle.id();
        assert_eq!(IdChoix::lire(&id.texte()), Some(id));
        assert!(id.pare_feu() && id.note_requise());
        for faux in [
            "pare-feu-salon-actif",
            "pare-feu-prive-allume",
            "pare-feu-regle-ouvre-00",
            "pare-feu-prive",
        ] {
            assert_eq!(IdChoix::lire(faux), None, "{faux}");
        }
    }

    /// Rang, valeur sûre et baisse : allumé, entrées bloquées, sorties autorisées, pas tout bloquer ; une règle de
    /// blocage active ; une règle d'autorisation n'est jamais « baissée ». « Rallumer » ne remet jamais plus faible.
    #[test]
    fn rangs_et_rallumage_du_pare_feu() {
        let actif = IdChoix::PareFeu(ProfilPareFeu::Public, ReglagePareFeu::Actif);
        assert!(actif.baissee(Some(0)) && !actif.baissee(Some(1)));
        assert_eq!(actif.sure(), 1);
        assert_eq!(cible_rallumer(actif, Some(Some(0))), 1);
        assert_eq!(cible_rallumer(actif, None), 1);
        let sortant = IdChoix::PareFeu(ProfilPareFeu::Public, ReglagePareFeu::Sortant);
        assert_eq!(sortant.sure(), 0);
        assert!(!sortant.baissee(Some(0)) && !sortant.baissee(Some(1)));
        // Les sorties bloquées notées avant : remises telles quelles (plus fermé).
        assert_eq!(cible_rallumer(sortant, Some(Some(1))), 1);
        let tout = IdChoix::PareFeu(ProfilPareFeu::Public, ReglagePareFeu::ToutBloquer);
        assert_eq!(tout.sure(), 0);
        let bloque = IdChoix::PareFeuRegle(ActionRegle::Bloque, regle_rdp(1).empreinte());
        assert!(bloque.baissee(Some(0)) && !bloque.baissee(Some(1)));
        assert_eq!(cible_rallumer(bloque, Some(Some(0))), 1);
        let autorise = regle_rdp(1).id();
        assert!(!autorise.baissee(Some(1)) && !autorise.baissee(Some(0)));
        assert_eq!(cible_rallumer(autorise, Some(Some(1))), 0);
        assert!(autorise.rang(Some(0)) > autorise.rang(Some(1)));
    }
}
