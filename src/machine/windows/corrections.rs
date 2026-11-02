//! Les corrections natives de Windows : une liste fermée, appliquée par les fonctions de Windows (registre…) dans
//! le processus élevé (`eleve`), au lieu d'un script PowerShell. Une correction se désigne par `vanguard:<id>` :
//! jamais du code ni une commande libre. C'est le processus élevé qui relit chaque ligne contre cette table : ce
//! que le clic d'administrateur autorise, ce sont ces gestes-là, et rien d'autre. Chaque entrée garde son
//! équivalent PowerShell, pour le chemin par script (Wine, une DLL posée à côté de Vanguard).
//!
//! La règle d'origine, « un identifiant, jamais un paramètre », vaut pour cette table. Depuis le 22 octobre 2026, le
//! processus élevé accepte aussi les ordres du blocage (`protection::blocage::ordres`), qui portent des paramètres
//! TYPÉS (une adresse, un port, un numéro de processus et son programme, une valeur d'avant) : il les reparse, refuse
//! toute autre forme, puis rejuge lui-même chaque geste (garde-fous du blocage). Toujours pas de texte libre.

use crate::langue::anglais;

/// Devant chaque identifiant, pour qu'aucune commande PowerShell ne soit prise pour une correction native.
pub(crate) const PREFIXE: &str = "vanguard:";
/// Au-delà, une liste n'est pas celle d'une session de Vanguard.
#[cfg(test)]
pub(crate) const LIGNES_MAX: usize = 64;
/// Une ligne plus longue qu'un identifiant ne vient pas de Vanguard (le canal la refuse avant de l'analyser).
pub(crate) const LIGNE_MAX: usize = 256;

/// L'identifiant du point de restauration, passé en premier par `reparer::point_restauration`.
pub(crate) const POINT: &str = "vanguard:point-de-restauration";

/// Ce qu'une correction change.
pub(crate) enum Geste {
    /// Une valeur DWORD sous HKEY_LOCAL_MACHINE, mise à la donnée voulue (la clé est créée si elle manque).
    Dword {
        cle: &'static str,
        valeur: &'static str,
        donnee: u32,
    },
    /// Une valeur texte (REG_SZ) sous HKEY_LOCAL_MACHINE, mise à la donnée voulue ; la clé doit exister.
    Sz {
        cle: &'static str,
        valeur: &'static str,
        donnee: &'static str,
    },
    /// Une valeur retirée sous HKEY_LOCAL_MACHINE : absente, c'est le réglage de Windows.
    RetirerValeur { cle: &'static str, valeur: &'static str },
    /// Une valeur DWORD dans le registre du compte de la personne (HKEY_USERS\<SID>) : le SID est pris par le
    /// processus élevé dans le jeton du Vanguard qui l'a lancé (PID vérifié par le tube), jamais un paramètre.
    DwordCompte {
        cle: &'static str,
        valeur: &'static str,
        donnee: u32,
    },
    /// Userinit de Winlogon remis à `<dossier de Windows>\system32\userinit.exe,` : le dossier est lu par le
    /// processus élevé (GetSystemWindowsDirectoryW), la ligne ne porte aucun argument.
    Userinit,
    /// NetBIOS sur TCP/IP coupé sur chaque carte : NetbiosOptions = 2 sous NetBT\Parameters\Interfaces\Tcpip_*.
    NetbiosCoupe,
    /// SMBv1 coupé dans le serveur de partage, par WMI (MSFT_SmbServerConfiguration.SetConfiguration).
    Smb1Serveur,
    /// Le point de restauration, avant de toucher au système.
    PointDeRestauration,
}

pub(crate) struct Correction {
    /// Sans le préfixe : `[a-z0-9-]`, 40 caractères au plus.
    pub id: &'static str,
    pub geste: Geste,
    fr: &'static str,
    en: &'static str,
    /// La commande PowerShell du chemin par script quand elle est fixe : celle que le constat écrivait avant que le
    /// geste passe par Windows, reprise telle quelle. `None` : calculée par `powershell`.
    ps: Option<&'static str>,
    /// Le bilan refait par le processus élevé, pour une entrée qui ne remet pas seulement une valeur de durcissement :
    /// la fonction même du constat, sur les lectures de cet instant (`rejuger`). Sans juge : une valeur de
    /// durcissement, toujours bonne à poser.
    juge: Option<Juge>,
}

/// Les constats du bilan refait ici (`compte` : le SID de la personne, pour ce qui se lit dans son registre) ; `None`
/// si ce qu'il lit ne se lit pas.
type Juge = fn(&Result<String, String>) -> Option<Vec<crate::machine::Constat>>;

impl Correction {
    /// Ce que la correction fait, en une phrase, montré par le processus élevé avant de la faire.
    pub(crate) fn texte(&self) -> &'static str {
        if anglais() { self.en } else { self.fr }
    }

    /// L'équivalent PowerShell, pour le chemin par script. La clé n'est créée que si elle manque : « New-Item -Force »
    /// sur une clé existante l'écraserait avec ses autres valeurs.
    pub(crate) fn powershell(&self) -> String {
        if let Some(ps) = self.ps {
            return ps.to_string();
        }
        match self.geste {
            Geste::Dword { cle, valeur, donnee } => format!(
                "if (-not (Test-Path -LiteralPath 'HKLM:\\{cle}')) {{ New-Item -Path 'HKLM:\\{cle}' -Force | Out-Null }}; \
                 Set-ItemProperty -LiteralPath 'HKLM:\\{cle}' -Name {valeur} -Value {donnee} -Type DWord"
            ),
            Geste::RetirerValeur { cle, valeur } => {
                format!("Remove-ItemProperty -LiteralPath 'HKLM:\\{cle}' -Name {valeur}")
            }
            // Le compte de la personne, comme le constat l'écrivait (la fenêtre PowerShell de Wine n'a pas de jeton
            // de parent à lire : le SID est celui de ce processus).
            Geste::DwordCompte { cle, valeur, donnee } => {
                ps_dword_compte(crate::reparer::sid_de_la_personne().as_deref(), cle, valeur, donnee)
            }
            Geste::Userinit => ps_userinit(&super::portes::racine_windows()),
            Geste::Sz { .. } | Geste::NetbiosCoupe | Geste::Smb1Serveur => {
                "throw 'Vanguard : geste sans équivalent PowerShell'".to_string()
            }
            Geste::PointDeRestauration => crate::reparer::point_restauration_powershell(),
        }
    }
}

/// La commande d'un DWORD du compte de la personne, pour le SID donné (sans SID : HKCU de la fenêtre).
fn ps_dword_compte(sid: Option<&str>, cle: &str, valeur: &str, donnee: u32) -> String {
    format!(
        "Set-ItemProperty -LiteralPath '{}' -Name {valeur} -Value {donnee} -Type DWord",
        crate::reparer::hkcu_de_la_personne(sid, cle)
    )
}

/// La commande qui remet Userinit d'origine, pour la racine de Windows donnée.
fn ps_userinit(racine: &str) -> String {
    use crate::commande::ps_texte;
    format!(
        "Set-ItemProperty -LiteralPath '{}' -Name Userinit -Value '{}' -Type String",
        ps_texte(&format!(r"HKLM:\{}", super::portes::WINLOGON)),
        ps_texte(&format!(r"{racine}\system32\userinit.exe,"))
    )
}

const WDIGEST: &str = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
const RDP_TCP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const APPINIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
const APPINIT_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows";
const TERMINAL_SERVER: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
const INSTALLEUR: &str = r"SOFTWARE\Policies\Microsoft\Windows\Installer";
const NETBT_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
/// La clé que le basculeur « Liste de blocage des pilotes vulnérables » de Sécurité Windows écrit (Isolation du noyau).
pub(crate) const PILOTES_VULNERABLES: &str = r"SYSTEM\CurrentControlSet\Control\CI\Config";

/// La liste fermée. Chaque entrée renforce la sécurité, ou remet une valeur d'origine de Windows (`heure-ntp`,
/// `winlogon-shell`, `winlogon-userinit`), sauf les réglages pour jouer de la machine (`gaming-*`, les valeurs
/// `Ruche::Machine` de gaming/windows.rs, liste fermée elle aussi), qui s'annulent par leur valeur d'avant ; aucune ne coupe un pare-feu, Defender, BitLocker ou l'UAC, ni une connexion
/// à distance en cours (`rdp-nla` exige une authentification ; `rdp-coupe` est refusé par le processus élevé pendant
/// une session du Bureau à distance).
static TABLE: &[Correction] = &[
    Correction {
        id: "point-de-restauration",
        geste: Geste::PointDeRestauration,
        fr: "Point de restauration, pour pouvoir revenir en arrière",
        en: "Restore point, so you can go back",
        juge: None,
        ps: None,
    },
    Correction {
        id: "wdigest-coupe",
        geste: Geste::Dword {
            cle: WDIGEST,
            valeur: "UseLogonCredential",
            donnee: 0,
        },
        fr: "Couper WDigest : plus de mot de passe en clair dans la mémoire (HKLM\\…\\WDigest, UseLogonCredential = 0)",
        en: "Turn WDigest off: no more clear-text password in memory (HKLM\\...\\WDigest, UseLogonCredential = 0)",
        juge: None,
        ps: None,
    },
    Correction {
        id: "rdp-nla",
        geste: Geste::Dword {
            cle: RDP_TCP,
            valeur: "UserAuthentication",
            donnee: 1,
        },
        fr: "Exiger l'authentification au niveau réseau (NLA) pour le Bureau à distance (HKLM\\…\\RDP-Tcp, UserAuthentication = 1)",
        en: "Require Network Level Authentication (NLA) for Remote Desktop (HKLM\\...\\RDP-Tcp, UserAuthentication = 1)",
        juge: None,
        ps: None,
    },
    dword(
        "comptes-sans-mdp-limites",
        LSA,
        "LimitBlankPasswordUse",
        1,
        "Réserver les comptes sans mot de passe à l'écran de connexion (HKLM\\…\\Lsa, LimitBlankPasswordUse = 1)",
        "Restrict password-less accounts to the sign-in screen (HKLM\\...\\Lsa, LimitBlankPasswordUse = 1)",
    ),
    dword(
        "ntlmv2-seul",
        LSA,
        "LmCompatibilityLevel",
        3,
        "NTLMv2 seulement, le réglage par défaut de Windows (HKLM\\…\\Lsa, LmCompatibilityLevel = 3)",
        "NTLMv2 only, the Windows default (HKLM\\...\\Lsa, LmCompatibilityLevel = 3)",
    ),
    dword(
        "sam-anonyme-ferme",
        LSA,
        "RestrictAnonymousSAM",
        1,
        "Refuser la liste des comptes aux connexions anonymes (HKLM\\…\\Lsa, RestrictAnonymousSAM = 1)",
        "Refuse the account list to anonymous connections (HKLM\\...\\Lsa, RestrictAnonymousSAM = 1)",
    ),
    dword(
        "anonyme-hors-tous",
        LSA,
        "EveryoneIncludesAnonymous",
        0,
        "Sortir l'anonyme du groupe « Tout le monde » (HKLM\\…\\Lsa, EveryoneIncludesAnonymous = 0)",
        "Take anonymous out of the Everyone group (HKLM\\...\\Lsa, EveryoneIncludesAnonymous = 0)",
    ),
    dword(
        "lmhash-coupe",
        LSA,
        "NoLMHash",
        1,
        "Ne plus garder l'ancienne forme LM des mots de passe (HKLM\\…\\Lsa, NoLMHash = 1)",
        "Stop keeping the old LM form of passwords (HKLM\\...\\Lsa, NoLMHash = 1)",
    ),
    dword(
        "appinit-coupe",
        APPINIT,
        "LoadAppInit_DLLs",
        0,
        "Ne plus charger les DLL AppInit, le réglage d'origine (HKLM\\…\\Windows, LoadAppInit_DLLs = 0)",
        "Stop loading AppInit DLLs, the original setting (HKLM\\...\\Windows, LoadAppInit_DLLs = 0)",
    ),
    dword(
        "appinit-coupe-32",
        APPINIT_32,
        "LoadAppInit_DLLs",
        0,
        "Ne plus charger les DLL AppInit des programmes 32 bits (HKLM\\…\\WOW6432Node\\…\\Windows, LoadAppInit_DLLs = 0)",
        "Stop loading AppInit DLLs in 32-bit programs (HKLM\\...\\WOW6432Node\\...\\Windows, LoadAppInit_DLLs = 0)",
    ),
    dword(
        "wpad-coupe",
        r"SYSTEM\CurrentControlSet\Services\WinHttp\Parameters",
        "DisableWpad",
        1,
        "Couper la découverte automatique du proxy (WPAD) (HKLM\\…\\WinHttp\\Parameters, DisableWpad = 1)",
        "Turn proxy auto-discovery (WPAD) off (HKLM\\...\\WinHttp\\Parameters, DisableWpad = 1)",
    ),
    dword(
        "smb-invite-coupe",
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "AllowInsecureGuestAuth",
        0,
        "Couper les connexions invité aux partages (HKLM\\…\\LanmanWorkstation\\Parameters, AllowInsecureGuestAuth = 0)",
        "Turn guest connections to shares off (HKLM\\...\\LanmanWorkstation\\Parameters, AllowInsecureGuestAuth = 0)",
    ),
    dword(
        "journal-powershell",
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        1,
        "Journaliser les scripts PowerShell (HKLM\\…\\ScriptBlockLogging, EnableScriptBlockLogging = 1)",
        "Log PowerShell scripts (HKLM\\...\\ScriptBlockLogging, EnableScriptBlockLogging = 1)",
    ),
    dword(
        "uac-active",
        UAC,
        "EnableLUA",
        1,
        "Réactiver l'UAC, effectif après redémarrage (HKLM\\…\\Policies\\System, EnableLUA = 1)",
        "Turn UAC back on, effective after a restart (HKLM\\...\\Policies\\System, EnableLUA = 1)",
    ),
    dword(
        "uac-demande",
        UAC,
        "ConsentPromptBehaviorAdmin",
        5,
        "Remettre la demande de l'UAC, le réglage de Windows (HKLM\\…\\Policies\\System, ConsentPromptBehaviorAdmin = 5)",
        "Bring back the UAC prompt, the Windows setting (HKLM\\...\\Policies\\System, ConsentPromptBehaviorAdmin = 5)",
    ),
    dword(
        "pilotes-vulnerables-bloques",
        PILOTES_VULNERABLES,
        "VulnerableDriverBlocklistEnable",
        1,
        "Activer la liste de Microsoft qui bloque les pilotes vulnérables, effectif après redémarrage (HKLM\\…\\CI\\Config, VulnerableDriverBlocklistEnable = 1)",
        "Turn on Microsoft's vulnerable driver blocklist, effective after a restart (HKLM\\...\\CI\\Config, VulnerableDriverBlocklistEnable = 1)",
    ),
    dword(
        "llmnr-coupe",
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "EnableMulticast",
        0,
        "Couper LLMNR, la résolution de noms par diffusion (HKLM\\…\\DNSClient, EnableMulticast = 0)",
        "Turn LLMNR (broadcast name resolution) off (HKLM\\...\\DNSClient, EnableMulticast = 0)",
    ),
    // Le processus élevé refuse de le couper pendant une session ouverte par le Bureau à distance : la personne
    // perdrait la connexion (le constat ne le propose pas non plus dans ce cas).
    Correction {
        id: "rdp-coupe",
        geste: Geste::Dword {
            cle: TERMINAL_SERVER,
            valeur: "fDenyTSConnections",
            donnee: 1,
        },
        fr: "Désactiver le Bureau à distance (HKLM\\…\\Terminal Server, fDenyTSConnections = 1)",
        en: "Turn Remote Desktop off (HKLM\\...\\Terminal Server, fDenyTSConnections = 1)",
        juge: Some(juge_bureau_distance),
        ps: Some(
            r"Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1",
        ),
    },
    Correction {
        id: "latfp-retire",
        geste: Geste::RetirerValeur {
            cle: UAC,
            valeur: "LocalAccountTokenFilterPolicy",
        },
        fr: "Remettre le contrôle de compte pour les connexions à distance des comptes locaux (HKLM\\…\\Policies\\System, LocalAccountTokenFilterPolicy retiré)",
        en: "Put account control back for remote connections of local accounts (HKLM\\...\\Policies\\System, LocalAccountTokenFilterPolicy removed)",
        juge: Some(juge_jeton_distant),
        ps: None,
    },
    Correction {
        id: "aie-machine",
        geste: Geste::Dword {
            cle: INSTALLEUR,
            valeur: "AlwaysInstallElevated",
            donnee: 0,
        },
        fr: "Couper l'installation avec les droits du système pour l'ordinateur (HKLM\\…\\Installer, AlwaysInstallElevated = 0)",
        en: "Turn off installing with system rights for the computer (HKLM\\...\\Installer, AlwaysInstallElevated = 0)",
        juge: Some(juge_installation_elevee),
        ps: Some(
            r"Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord",
        ),
    },
    Correction {
        id: "aie-compte",
        geste: Geste::DwordCompte {
            cle: INSTALLEUR,
            valeur: "AlwaysInstallElevated",
            donnee: 0,
        },
        fr: "Couper l'installation avec les droits du système pour votre compte (HKCU\\…\\Installer, AlwaysInstallElevated = 0)",
        en: "Turn off installing with system rights for your account (HKCU\\...\\Installer, AlwaysInstallElevated = 0)",
        juge: Some(juge_installation_elevee),
        ps: None,
    },
    Correction {
        id: "heure-ntp",
        geste: Geste::Sz {
            cle: r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
            valeur: "Type",
            donnee: "NTP",
        },
        fr: "Régler l'heure par Internet (HKLM\\…\\W32Time\\Parameters, Type = NTP)",
        en: "Set the time from the Internet (HKLM\\...\\W32Time\\Parameters, Type = NTP)",
        juge: Some(juge_heure),
        ps: Some(
            r"Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name Type -Value NTP",
        ),
    },
    Correction {
        id: "winlogon-shell",
        geste: Geste::Sz {
            cle: super::portes::WINLOGON,
            valeur: "Shell",
            donnee: "explorer.exe",
        },
        fr: "Remettre le bureau de Windows seul (HKLM\\…\\Winlogon, Shell = explorer.exe, la valeur d'origine)",
        en: "Put Windows' desktop back alone (HKLM\\...\\Winlogon, Shell = explorer.exe, the original value)",
        juge: Some(juge_winlogon),
        ps: Some(
            r"Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'explorer.exe' -Type String",
        ),
    },
    Correction {
        id: "winlogon-userinit",
        geste: Geste::Userinit,
        fr: "Remettre Userinit d'origine (HKLM\\…\\Winlogon, Userinit = <dossier de Windows>\\system32\\userinit.exe, ; le dossier est lu par Windows)",
        en: "Put the original Userinit back (HKLM\\...\\Winlogon, Userinit = <Windows folder>\\system32\\userinit.exe, ; the folder is read from Windows)",
        juge: None,
        ps: None,
    },
    Correction {
        id: "netbios-coupe",
        geste: Geste::NetbiosCoupe,
        fr: "Couper NetBIOS sur TCP/IP sur toutes les cartes réseau, VPN et virtuelles comprises (HKLM\\…\\NetBT\\Parameters\\Interfaces, NetbiosOptions = 2 ; effectif au prochain redémarrage)",
        en: "Turn off NetBIOS over TCP/IP on all network adapters, VPN and virtual ones included (HKLM\\...\\NetBT\\Parameters\\Interfaces, NetbiosOptions = 2; effective at the next restart)",
        juge: None,
        ps: Some(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null",
        ),
    },
    Correction {
        id: "smb1-serveur-coupe",
        geste: Geste::Smb1Serveur,
        fr: "Désactiver SMBv1 dans le partage de fichiers de Windows (serveur SMB, par WMI)",
        en: "Turn SMBv1 off in Windows file sharing (SMB server, through WMI)",
        juge: None,
        ps: Some("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"),
    },
    // Réglage pour jouer, sous HKLM (le seul : les autres sont du compte, `gestes::VALEURS_COMPTE`). Ce n'est pas une
    // protection : Gaming relève et note sa valeur d'avant, et la remet sur demande (`gaming::windows::VALEURS`).
    dword(
        "gaming-hags",
        r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
        "HwSchMode",
        2,
        "Activer la planification GPU matérielle (HAGS, au redémarrage)",
        "Turn on hardware-accelerated GPU scheduling (HAGS, after a restart)",
    ),
];

/// Une entrée de la table qui met une valeur DWORD sous HKLM.
const fn dword(
    id: &'static str,
    cle: &'static str,
    valeur: &'static str,
    donnee: u32,
    fr: &'static str,
    en: &'static str,
) -> Correction {
    Correction {
        id,
        geste: Geste::Dword { cle, valeur, donnee },
        fr,
        en,
        juge: None,
        ps: None,
    }
}

/// L'identifiant complet d'une correction de la table (« vanguard:wdigest-coupe »), à mettre dans un `Correctif`.
pub(crate) fn id(court: &str) -> String {
    debug_assert!(
        TABLE.iter().any(|c| c.id == court),
        "correction native inconnue : {court}"
    );
    format!("{PREFIXE}{court}")
}

/// La correction désignée par une ligne, si et seulement si la ligne est exactement un identifiant de la table :
/// le préfixe, puis des minuscules, chiffres et tirets, rien d'autre (ni espace, ni paramètre, ni fin de ligne).
pub(crate) fn analyser(ligne: &str) -> Option<&'static Correction> {
    if ligne.len() > LIGNE_MAX {
        return None;
    }
    let court = ligne.strip_prefix(PREFIXE)?;
    let forme = !court.is_empty()
        && court.len() <= 40
        && court
            .bytes()
            .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-');
    if !forme {
        return None;
    }
    TABLE.iter().find(|c| c.id == court)
}

/// Comment se défait une correction faite de ces commandes : une correction native (un DWORD sous HKLM, une valeur
/// d'origine remise, une valeur dangereuse retirée) durcit Windows (WDigest, NLA, Lsa, UAC, Winlogon…) ; c'est une
/// protection, que Vanguard ne défait jamais. Défaite d'après une note de
/// reglages.json, que tout programme du compte peut réécrire, elle remettait en administrateur la valeur qu'une
/// note forgée choisissait (UseLogonCredential = 1). La personne peut toujours la changer elle-même dans Windows. Un
/// acte de service qui durcit (`gestes::SERVICES`, RemoteRegistry désactivé…) compte de même, comme le pare-feu remis
/// en marche, le profil Public durci, un réseau passé en Public, un débogueur IFEO retiré ou un chemin de service mis
/// entre guillemets ; un acte qui ne durcit pas (arrêter puis relancer
/// wuauserv), comme le reste (PowerShell, le point de restauration seul, un dossier vidé, un réglage pour jouer
/// `gaming-*`), n'est pas relevé. Un geste du compte (`gestes::COMPTE`) compte selon `GesteCompte::durcit` : les
/// macros d'Office et la stratégie de PowerShell oui (« Protection ») ; un retrait de démarrage, de shell ou de proxy
/// non (décision 4 b) du plan), un réglage pour jouer non plus : « Inconnu » pour l'instant, la valeur d'avant n'est
/// notée que pour être lue (coupée, sans son type). Son annulation exacte, par une valeur d'avant relevée, revient au
/// lot 3.5.
pub(crate) fn comment_defaire(commandes: &[String]) -> crate::machine::Defaire {
    use crate::machine::Defaire;
    use crate::machine::gestes::{self, Acte};
    // Chaque ligne : `Some(durcit)`, ou `None` si elle n'est ni une correction de la table ni un acte de service.
    let durcies: Option<Vec<bool>> = commandes
        .iter()
        .map(|l| match (analyser(l), gestes::analyser_acte(l)) {
            (None, None) => gestes::analyser_compte(l).map(|g| g.durcit()),
            (Some(c), _) => Some(!matches!(c.geste, Geste::PointDeRestauration) && !c.id.starts_with("gaming-")),
            (
                None,
                Some(
                    a @ (Acte::Service(_)
                    | Acte::PareFeuActif
                    | Acte::PareFeuPublic(_)
                    | Acte::ReseauCategorie(_)
                    | Acte::IfeoDebugger(..)
                    | Acte::IfeoSilencieux(..)
                    | Acte::ServiceGuillemets(_)
                    | Acte::Defender(..)
                    | Acte::DefenderAsr(..)
                    | Acte::DefenderExclusionRetirer(..)
                    | Acte::DefenderMenacesRetirer
                    | Acte::CompteDesactiver(_)
                    | Acte::CertificatRetirer(..)
                    | Acte::PartageRetirerAcces(_)
                    | Acte::RunRetirer(_)
                    | Acte::RunRemettre(_)
                    | Acte::TacheDesactiver(_)
                    | Acte::TacheReactiver(_)
                    | Acte::DemarrageQuarantaine(_)
                    | Acte::DemarrageRemettre(_)
                    | Acte::WmiAbonnementRetirer(_)
                    | Acte::WmiAbonnementRemettre(_)
                    | Acte::ServiceRetirer(_)),
                ),
            ) => Some(a.durcit()),
            _ => None,
        })
        .collect();
    match durcies {
        Some(d) if d.contains(&true) => Defaire::Protection,
        _ => Defaire::Inconnu,
    }
}

/// La phrase d'un acte de la table, montrée avant l'UAC et dans la fenêtre administrateur. Un acte qui affaiblit le
/// dit en toutes lettres ; la phrase décrit ce qui sera fait, rien de plus : le processus élevé ne lit ni l'état du
/// mode Wi-Fi public ni les changements notés, il ne peut pas savoir d'où vient une ligne (forgée, elle n'est pas
/// « ce que Vanguard avait coupé »).
pub(crate) fn texte_acte(acte: &crate::machine::gestes::Acte) -> String {
    use crate::ui::trf;
    let phrase = phrase_acte(acte);
    if acte.affaiblit() {
        trf!(
            "{phrase} — rend le PC moins protégé",
            "{phrase} — makes the PC less protected"
        )
    } else {
        phrase
    }
}

/// Un réglage du profil Public, en clair : ce que le processus élevé va en faire.
fn texte_reglage_public(r: crate::machine::gestes::ReglagePublic, v: crate::machine::gestes::ValeurPublic) -> String {
    use crate::machine::gestes::{ReglagePublic, ValeurPublic};
    use crate::ui::tr;
    match (r, v) {
        (ReglagePublic::Actif, _) => tr!("le mettre en marche", "turn it on"),
        (ReglagePublic::EntrantBloque, ValeurPublic::Oui) => {
            tr!("bloquer les entrées par défaut", "block inbound by default")
        }
        (ReglagePublic::EntrantBloque, _) => tr!(
            "autoriser les entrées par défaut (Windows les bloque par défaut)",
            "allow inbound by default (Windows blocks it by default)"
        ),
        (ReglagePublic::ReglesEntrantes, ValeurPublic::Non) => tr!(
            "bloquer toutes les entrées, même celles des programmes autorisés",
            "block all inbound, even for allowed programs"
        ),
        (ReglagePublic::ReglesEntrantes, ValeurPublic::Oui) => {
            tr!("laisser entrer les programmes autorisés", "let allowed programs in")
        }
        (ReglagePublic::ReglesEntrantes, ValeurPublic::Absent) => tr!(
            "remettre les règles entrantes à non configuré (défaut de Windows : les programmes autorisés entrent)",
            "put inbound rules back to not configured (Windows default: allowed programs get in)"
        ),
    }
    .to_string()
}

/// Le réseau d'un acte, nommé : son nom tel que le registre le garde, avec le GUID que l'acte désigne (le nom ne
/// fait que le montrer, deux réseaux peuvent s'appeler pareil).
fn reseau_nomme(r: &crate::machine::gestes::ReseauCategorie) -> String {
    use super::pare_feu::NomReseau;
    use crate::ui::trf;
    let g = r.guid.texte();
    match super::pare_feu::nom_du_reseau(r) {
        NomReseau::Lu(n) => {
            // Un nom choisi par qui a créé le réseau : rendu inoffensif et court.
            let n: String = n.chars().take(64).collect();
            trf!("« {} » {g}", "“{}” {g}", crate::ui::affichable(&n))
        }
        NomReseau::Absent => trf!("{g} (inconnu de ce PC)", "{g} (unknown to this PC)"),
        NomReseau::Illisible => trf!("{g} (nom illisible)", "{g} (name unreadable)"),
    }
}

fn phrase_acte(acte: &crate::machine::gestes::Acte) -> String {
    use crate::machine::gestes::{
        ACoter, Acte, Action, Categorie, CleRun, GenreExclusion, MagasinRacine, ModeAsr, ReglageDefender,
        ValeurDefender, Vidable, Vue,
    };
    use crate::ui::{tr, trf};
    match acte {
        Acte::Service(s) => {
            let n = s.nom;
            match s.action {
                Action::Arreter => trf!(
                    "Arrêter le service {n} (et les services qui en dépendent)",
                    "Stop the {n} service (and the services that depend on it)"
                ),
                Action::Demarrer => trf!("Démarrer le service {n}", "Start the {n} service"),
                Action::Redemarrer => trf!(
                    "Redémarrer le service {n} (et les services qui en dépendent)",
                    "Restart the {n} service (and the services that depend on it)"
                ),
                Action::Desactive => trf!("Désactiver le service {n}", "Disable the {n} service"),
                Action::Manuel => trf!(
                    "Mettre le service {n} en démarrage manuel",
                    "Set the {n} service to manual start"
                ),
                Action::Auto => trf!(
                    "Mettre le service {n} en démarrage automatique",
                    "Set the {n} service to automatic start"
                ),
                Action::Reactiver => trf!(
                    "Remettre le service {n} en manuel s'il est désactivé",
                    "Set the {n} service back to manual if it is disabled"
                ),
            }
        }
        Acte::Vider(Vidable::TempWindows) => tr!(
            r"Vider le dossier temporaire de Windows (Windows\Temp ; ce qui est en usage reste)",
            r"Empty the Windows temporary folder (Windows\Temp; what is in use stays)"
        )
        .to_string(),
        Acte::Vider(Vidable::WuTelechargements) => tr!(
            r"Vider les téléchargements de Windows Update (Windows\SoftwareDistribution\Download)",
            r"Empty the Windows Update downloads (Windows\SoftwareDistribution\Download)"
        )
        .to_string(),
        Acte::ViderFileImpression => tr!(
            "Vider la file d'impression (les fichiers du dossier du spouleur)",
            "Empty the print queue (the files in the spooler folder)"
        )
        .to_string(),
        Acte::MettreDeCote(ACoter::SoftwareDistribution) => tr!(
            r"Mettre de côté le cache de Windows Update (Windows\SoftwareDistribution, renommé avec la date)",
            r"Set aside the Windows Update cache (Windows\SoftwareDistribution, renamed with the date)"
        )
        .to_string(),
        Acte::MettreDeCote(ACoter::Catroot2) => tr!(
            r"Mettre de côté le catalogue des signatures (Windows\System32\catroot2, renommé avec la date)",
            r"Set aside the signature catalog (Windows\System32\catroot2, renamed with the date)"
        )
        .to_string(),
        Acte::PareFeuActif => tr!(
            "Remettre le Pare-feu Windows en marche sur les trois profils (domaine, privé, public)",
            "Turn the Windows Firewall back on for the three profiles (domain, private, public)"
        )
        .to_string(),
        Acte::PareFeuPublic(p) => {
            let reglages: Vec<String> = p.reglages().map(|(r, v)| texte_reglage_public(r, v)).collect();
            trf!(
                "Profil Public du Pare-feu Windows : {}",
                "Windows Firewall Public profile: {}",
                reglages.join(tr!(" ; ", "; "))
            )
        }
        Acte::IfeoDebugger(vue, n) => {
            let n = crate::ui::affichable(n.texte());
            match vue {
                Vue::Windows => trf!(
                    "Retirer le débogueur imposé à « {n} » (Image File Execution Options, valeur Debugger)",
                    "Remove the debugger forced on “{n}” (Image File Execution Options, Debugger value)"
                ),
                Vue::Wow32 => trf!(
                    "Retirer le débogueur imposé à « {n} » (Image File Execution Options des programmes 32 bits, valeur Debugger)",
                    "Remove the debugger forced on “{n}” (Image File Execution Options of 32-bit programs, Debugger value)"
                ),
            }
        }
        Acte::IfeoSilencieux(vue, n) => {
            let n = crate::ui::affichable(n.texte());
            match vue {
                Vue::Windows => trf!(
                    "Ne plus rien lancer à la fermeture de « {n} » (SilentProcessExit, valeur MonitorProcess)",
                    "Stop launching anything when “{n}” closes (SilentProcessExit, MonitorProcess value)"
                ),
                Vue::Wow32 => trf!(
                    "Ne plus rien lancer à la fermeture de « {n} » (SilentProcessExit des programmes 32 bits, valeur MonitorProcess)",
                    "Stop launching anything when “{n}” closes (SilentProcessExit of 32-bit programs, MonitorProcess value)"
                ),
            }
        }
        Acte::ServiceGuillemets(n) => {
            let n = crate::ui::affichable(n.texte());
            trf!(
                "Mettre entre guillemets le chemin du service « {n} » (ImagePath, relu et recalculé ici avant d'écrire)",
                "Put the path of the “{n}” service in quotes (ImagePath, read and recomputed here before writing)"
            )
        }
        Acte::Defender(r, v) => {
            let mode = || match v {
                ValeurDefender::Audit => tr!(
                    "en audit (signale sans bloquer)",
                    "in audit mode (reports, does not block)"
                ),
                ValeurDefender::Actif | ValeurDefender::Avance | ValeurDefender::Bloquer => {
                    tr!("en blocage", "in block mode")
                }
            };
            match r {
                ReglageDefender::TempsReel => tr!(
                    "Remettre en marche la protection en temps réel de Defender",
                    "Turn Defender real-time protection back on"
                )
                .to_string(),
                ReglageDefender::Maps => tr!(
                    "Mettre la protection dans le cloud de Defender au niveau avancé",
                    "Set Defender cloud protection to the advanced level"
                )
                .to_string(),
                ReglageDefender::Cfa => trf!(
                    "Mettre l'accès contrôlé aux dossiers de Defender {} (jamais baissé s'il bloque déjà)",
                    "Set Defender controlled folder access {} (never lowered if it already blocks)",
                    mode()
                ),
                ReglageDefender::Np => trf!(
                    "Mettre la protection réseau de Defender {} (jamais baissée si elle bloque déjà)",
                    "Set Defender network protection {} (never lowered if it already blocks)",
                    mode()
                ),
                ReglageDefender::Pua => trf!(
                    "Mettre la protection de Defender contre les applications indésirables (PUA) {} (jamais baissée si elle bloque déjà)",
                    "Set Defender protection against potentially unwanted apps (PUA) {} (never lowered if it already blocks)",
                    mode()
                ),
            }
        }
        Acte::DefenderAsr(id, m) => {
            let n = crate::optimiser::defender::nom_asr(id);
            match m {
                ModeAsr::Bloquer => trf!(
                    "Règle ASR de Defender « {n} » : bloquer",
                    "Defender ASR rule “{n}”: block"
                ),
                ModeAsr::Audit => trf!(
                    "Règle ASR de Defender « {n} » : audit (signale sans bloquer ; jamais baissée si elle bloque déjà)",
                    "Defender ASR rule “{n}”: audit (reports, does not block; never lowered if it already blocks)"
                ),
            }
        }
        Acte::DefenderExclusionRetirer(g, e) => {
            let x = crate::ui::affichable(e.texte());
            match g {
                GenreExclusion::Chemin => trf!(
                    "Retirer l'exclusion de Defender du dossier « {x} » (relue et rejugée ici avant de la retirer)",
                    "Remove the Defender exclusion of the folder “{x}” (read and judged again here before removing it)"
                ),
                GenreExclusion::Processus => trf!(
                    "Retirer l'exclusion de Defender du programme « {x} » (relue et rejugée ici avant de la retirer)",
                    "Remove the Defender exclusion of the program “{x}” (read and judged again here before removing it)"
                ),
                GenreExclusion::Extension => trf!(
                    "Retirer l'exclusion de Defender des fichiers « {x} » (relue et rejugée ici avant de la retirer)",
                    "Remove the Defender exclusion of the “{x}” files (read and judged again here before removing it)"
                ),
            }
        }
        Acte::DefenderMenacesRetirer => tr!(
            "Supprimer définitivement les menaces actives trouvées par Defender",
            "Permanently delete the active threats found by Defender"
        )
        .to_string(),
        Acte::CompteDesactiver(rid) => trf!(
            "Désactiver le compte local n° {rid} (relu et rejugé ici ; jamais le vôtre, le dernier administrateur actif ni un compte d'une session ouverte) : il ne pourra plus ouvrir de session. Non annulable par Vanguard (protection) ; état d'avant noté, à réactiver dans Windows au besoin",
            "Disable local account no. {rid} (read and judged again here; never yours, the last active administrator or an account with an open session): it can no longer sign in. Not undoable by Vanguard (protection); previous state noted, reactivate it in Windows if needed"
        ),
        Acte::CertificatRetirer(m, e) => {
            let x = e.texte();
            match m {
                MagasinRacine::Ordinateur => trf!(
                    "Retirer la racine {x} du magasin de l'ordinateur (relue et rejugée ici ; une copie .cer est gardée dans ProgramData\\Vanguard\\quarantaine si ce dossier est sûr). Non annulable par Vanguard (protection) : jamais une racine n'est remise",
                    "Remove root {x} from the computer store (read and judged again here; a .cer copy is kept in ProgramData\\Vanguard\\quarantaine if that folder is safe). Not undoable by Vanguard (protection): a root is never put back"
                ),
                MagasinRacine::Compte => trf!(
                    "Retirer la racine {x} de votre magasin (relue et rejugée ici ; Windows demande lui-même de confirmer ; une copie .cer est gardée dans ProgramData\\Vanguard\\quarantaine si ce dossier est sûr). Non annulable par Vanguard (protection) : jamais une racine n'est remise",
                    "Remove root {x} from your store (read and judged again here; Windows asks for its own confirmation; a .cer copy is kept in ProgramData\\Vanguard\\quarantaine if that folder is safe). Not undoable by Vanguard (protection): a root is never put back"
                ),
            }
        }
        Acte::PartageRetirerAcces(a) => {
            let (n, c) = (crate::ui::affichable(a.nom.texte()), a.sid.texte());
            trf!(
                "Retirer l'accès de {c} au partage « {n} » (relu et rejugé ici) : les appareils qui s'y connectaient sans mot de passe le perdent ; s'il ne reste personne, plus personne n'y entre avant qu'un accès soit redonné dans Windows. Non annulable par Vanguard (protection) ; droits d'avant notés",
                "Remove the access of {c} to share “{n}” (read and judged again here): devices that connected without a password lose it; if nobody is left, nobody gets in until access is given back in Windows. Not undoable by Vanguard (protection); previous permissions noted"
            )
        }
        Acte::RunRetirer(v) | Acte::RunRemettre(v) => {
            let n = v.nom.montre().map_or_else(
                || tr!("(par défaut)", "(default)").to_string(),
                |n| crate::ui::affichable(&n),
            );
            let cle = match v.cle {
                CleRun::Run => r"HKLM\…\CurrentVersion\Run",
                CleRun::RunOnce => r"HKLM\…\CurrentVersion\RunOnce",
                CleRun::Run32 => r"HKLM\…\WOW6432Node\…\CurrentVersion\Run",
            };
            if matches!(acte, Acte::RunRetirer(_)) {
                trf!(
                    "Retirer le lancement au démarrage « {n} » de la machine ({cle} ; relu et rejugé ici, jamais une entrée de Windows ou de Defender). Le programme lui-même reste ; sa donnée d'avant est notée",
                    "Remove the machine startup entry “{n}” ({cle}; read and judged again here, never a Windows or Defender entry). The program itself stays; its previous data is noted"
                )
            } else {
                trf!(
                    "Remettre le lancement au démarrage « {n} » de la machine ({cle}), exactement tel que Vanguard l'avait noté : rend le PC moins protégé, ce lancement avait été jugé suspect",
                    "Put back the machine startup entry “{n}” ({cle}), exactly as Vanguard noted it: makes the PC less protected, this entry had been judged suspicious"
                )
            }
        }
        Acte::TacheDesactiver(t) => {
            let t = crate::ui::affichable(t.texte());
            trf!("Désactiver la tâche planifiée « {t} »", "Disable the scheduled task “{t}”")
        }
        Acte::TacheReactiver(t) => {
            let t = crate::ui::affichable(t.texte());
            trf!(
                "Réactiver la tâche planifiée « {t} » : rend le PC moins protégé",
                "Re-enable the scheduled task “{t}”: makes the PC less protected"
            )
        }
        Acte::DemarrageQuarantaine(f) => {
            let f = crate::ui::affichable(f.texte());
            trf!(
                "Mettre de côté le fichier de démarrage « {f} »",
                "Set aside the startup file “{f}”"
            )
        }
        Acte::DemarrageRemettre(f) => {
            let f = crate::ui::affichable(f.texte());
            trf!(
                "Remettre le fichier de démarrage « {f} » : rend le PC moins protégé",
                "Put back the startup file “{f}”: makes the PC less protected"
            )
        }
        Acte::WmiAbonnementRetirer(w) => {
            let (n, c) = (crate::ui::affichable(w.nom.texte()), w.classe.classe());
            trf!(
                "Retirer l'abonnement WMI « {n} » ({c})",
                "Remove the WMI subscription “{n}” ({c})"
            )
        }
        Acte::WmiAbonnementRemettre(w) => {
            let (n, c) = (crate::ui::affichable(w.nom.texte()), w.classe.classe());
            trf!(
                "Recréer l'abonnement WMI « {n} » ({c}) : rend le PC moins protégé",
                "Recreate the WMI subscription “{n}” ({c}): makes the PC less protected"
            )
        }
        Acte::ServiceRetirer(n) => {
            let n = crate::ui::affichable(n.texte());
            trf!(
                "Supprimer le service « {n} ». Non annulable",
                "Delete the “{n}” service. Not undoable"
            )
        }
        Acte::HostsEcrire(_) => tr!(
            "Réécrire le fichier hosts préparé par Vanguard (différence ci-dessous, relue et rejugée ici ; une copie d'avant est gardée)",
            "Rewrite the hosts file prepared by Vanguard (difference below, read and judged again here; a copy of the previous one is kept)"
        )
        .to_string(),
        Acte::DnsAuto(g) => trf!(
            "Remettre en automatique (DHCP) les serveurs DNS de la carte réseau {}, IPv4 et IPv6, puis vider le cache DNS",
            "Set the DNS servers of network adapter {} back to automatic (DHCP), IPv4 and IPv6, then clear the DNS cache",
            g.texte()
        ),
        Acte::DnsServeurs(d) => {
            let cote = |c: &crate::machine::gestes::CoteDns| match c {
                crate::machine::gestes::CoteDns::Garder => tr!("inchangé", "unchanged").to_string(),
                crate::machine::gestes::CoteDns::Vider => tr!("automatique", "automatic").to_string(),
                crate::machine::gestes::CoteDns::Serveurs(_) if c.hors_liste() => trf!(
                    "{} (valeur d'avant, acceptée seulement si Vanguard l'a notée)",
                    "{} (previous value, accepted only if Vanguard noted it)",
                    c.texte()
                ),
                crate::machine::gestes::CoteDns::Serveurs(_) => c.texte(),
            };
            trf!(
                "Régler les serveurs DNS de la carte réseau {} : IPv4 {}, IPv6 {}",
                "Set the DNS servers of network adapter {}: IPv4 {}, IPv6 {}",
                d.guid.texte(),
                cote(&d.v4),
                cote(&d.v6)
            )
        }
        Acte::ReseauCategorie(r) => {
            let g = reseau_nomme(r);
            match r.categorie {
                Categorie::Public => trf!(
                    "Passer le réseau {g} en catégorie Public",
                    "Set the network {g} to the Public category"
                ),
                Categorie::Prive => trf!(
                    "Passer le réseau {g} en catégorie Privé (le pare-feu y applique son profil Privé)",
                    "Set the network {g} to the Private category (the firewall applies its Private profile there)"
                ),
            }
        }
    }
}

/// La ligne est-elle faite par le processus élevé lui-même, sans PowerShell : une correction de la table, un ordre du
/// blocage permis sous Windows, un programme fixe (`gestes::PROGRAMMES`) ou un acte (`gestes::SERVICES`…) ?
pub(crate) fn native(ligne: &str) -> bool {
    analyser(ligne).is_some()
        || crate::protection::blocage::ordres::analyser(ligne).is_some_and(|o| o.permis_ici())
        || crate::machine::gestes::analyser_programme(ligne).is_some()
        || crate::machine::gestes::analyser_acte(ligne).is_some()
}

/// La phrase d'un programme fixe, avec la commande lancée : « Réparer les fichiers de Windows (SFC) : sfc.exe /scannow ».
pub(crate) fn texte_programme(a: &crate::machine::gestes::Appel) -> String {
    crate::trf!(
        "{} : {}",
        "{}: {}",
        if anglais() { a.programme.en } else { a.programme.fr },
        a.commande()
    )
}

/// La liste telle que le processus élevé la recevra, validée ligne à ligne, dans l'ordre ; `None` dès qu'une ligne
/// n'est pas une correction de la table, qu'il y en a trop, ou qu'une revient deux fois (une liste de Vanguard
/// n'applique jamais deux fois le même geste : une répétition est un signe de bricolage).
#[cfg(test)]
pub(crate) fn valider(lignes: &[String]) -> Option<Vec<&'static Correction>> {
    if lignes.is_empty() || lignes.len() > LIGNES_MAX {
        return None;
    }
    let mut vues = std::collections::HashSet::new();
    lignes
        .iter()
        .map(|l| analyser(l).filter(|c| vues.insert(c.id)))
        .collect()
}

/// Pour le chemin par script : chaque correction native, chaque ordre du blocage, chaque programme fixe et chaque acte,
/// remplacé par son équivalent PowerShell, le reste inchangé.
pub(crate) fn en_powershell(correctifs: &[Vec<String>]) -> Vec<Vec<String>> {
    use crate::protection::blocage::ordres;
    correctifs
        .iter()
        .map(|c| {
            c.iter()
                .map(|l| match (analyser(l), ordres::analyser(l)) {
                    (Some(c), _) => c.powershell(),
                    // Un ordre sans équivalent (couper une connexion, qu'aucun Vanguard ne demande sous Windows) : une
                    // erreur dite par la fenêtre, jamais un geste deviné.
                    (None, Some(o)) => ordres::powershell(&o)
                        .unwrap_or_else(|| "throw 'Vanguard : geste sans équivalent PowerShell'".to_string()),
                    (None, None) => {
                        use crate::machine::gestes;
                        match (gestes::analyser_programme(l), gestes::analyser_acte(l)) {
                            (Some(a), _) => a.powershell(),
                            (None, Some(a)) => a.powershell(),
                            (None, None) => l.clone(),
                        }
                    }
                })
                .collect()
        })
        .collect()
}

/// Le texte à montrer pour une commande : la phrase d'une correction native ou d'un ordre, la commande elle-même sinon.
pub(crate) fn affichable(commande: &str) -> String {
    if let Some(g) = crate::machine::gestes::analyser_compte(commande) {
        return crate::ui::affichable(&g.texte(!anglais()));
    }
    if let Some(a) = crate::machine::gestes::analyser_programme(commande) {
        return texte_programme(&a);
    }
    if let Some(a) = crate::machine::gestes::analyser_acte(commande) {
        return texte_acte(&a);
    }
    analyser(commande).map_or_else(
        || crate::protection::blocage::ordres::affichable(commande),
        |c| c.texte().to_string(),
    )
}

/// La valeur actuelle de VulnerableDriverBlocklistEnable ; `None` : absente ou illisible.
pub(crate) fn valeur_pilotes() -> Option<u32> {
    let racine = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    racine
        .open_subkey_with_flags(PILOTES_VULNERABLES, winreg::enums::KEY_READ)
        .ok()?
        .get_value::<u32, _>("VulnerableDriverBlocklistEnable")
        .ok()
}

/// La liste de blocage des pilotes vulnérables remise à sa valeur d'avant (`None` : la valeur est retirée), puis
/// relue : l'annulation exacte du geste « Pilotes » du blocage.
pub(crate) fn remettre_pilotes(avant: Option<u32>) -> crate::protection::blocage::ordres::Resultat {
    use crate::protection::blocage::ordres::Resultat;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    const VALEUR: &str = "VulnerableDriverBlocklistEnable";
    let racine = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Some(v) = avant {
        let ecrit = racine
            .create_subkey_with_flags(PILOTES_VULNERABLES, KEY_READ | KEY_WRITE)
            .and_then(|(k, _)| k.set_value(VALEUR, &v).map(|()| k))
            .and_then(|k| k.get_value::<u32, _>(VALEUR));
        return match ecrit {
            Ok(relu) if relu == v => Resultat::ok(),
            Ok(relu) => Resultat::echec(format!("relu {relu} au lieu de {v}")),
            Err(e) => Resultat::echec(e.to_string()),
        };
    }
    let cle = match racine.open_subkey_with_flags(PILOTES_VULNERABLES, KEY_READ | KEY_WRITE) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Resultat::ok(),
        Err(e) => return Resultat::echec(e.to_string()),
    };
    match cle.delete_value(VALEUR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Resultat::echec(e.to_string()),
    }
    match cle.get_raw_value(VALEUR) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Resultat::ok(),
        _ => Resultat::echec(crate::tr!(
            "la valeur est toujours là après son retrait",
            "the value is still there after its removal"
        )),
    }
}

/// Résultat d'une correction appliquée par le processus élevé : réussie ou non, et la valeur d'avant quand il y en
/// a une (« 1 », « absent »), pour l'annuler exactement.
pub(crate) struct Resultat {
    pub reussi: bool,
    /// Déjà bon, rien d'écrit : réussi, mais absent de « Ce que Vanguard a changé » (`Resultat::rien`).
    pub rien: bool,
    pub avant: Option<String>,
    pub raison: String,
}

impl Resultat {
    /// Fait : la valeur d'avant est notée.
    pub(crate) fn fait(avant: String) -> Resultat {
        Resultat {
            reussi: true,
            rien: false,
            avant: Some(avant),
            raison: String::new(),
        }
    }

    /// Rien à faire (déjà bon, rien d'écrit) : réussi, et dit tel quel.
    pub(crate) fn rien(raison: String) -> Resultat {
        Resultat {
            reussi: true,
            rien: true,
            avant: None,
            raison,
        }
    }

    /// Échec, avec sa raison ; la valeur d'avant quand elle a été lue.
    pub(crate) fn echec(avant: Option<String>, raison: String) -> Resultat {
        Resultat {
            reussi: false,
            rien: false,
            avant,
            raison,
        }
    }
}

/// Une valeur d'avant prête à noter : sans caractère de contrôle, et courte (le parent borne chaque ligne du tube).
pub(crate) fn avant_notable(v: &str) -> String {
    crate::ui::couper(&crate::ui::affichable(v), AVANT_MAX)
}

/// Au-delà, une valeur d'avant est coupée : elle sert à la montrer, pas à la remettre (ces gestes sont des protections).
const AVANT_MAX: usize = 512;

/// Le bilan refait par le processus élevé pour une correction de la table, avant le premier geste de la liste : un
/// geste de la liste ne change pas le jugement d'un autre (aie-machine, puis aie-compte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bilan {
    /// Le bilan propose encore cette correction (ou elle n'a pas de juge : une valeur de durcissement).
    Signale,
    /// Le bilan ne la proposerait pas : rien n'est écrit, sauf à dire qu'il n'y a rien à faire.
    NeSignalePas,
    /// Ce que le bilan lit ne se lit pas : rien n'est écrit.
    Illisible,
}

/// Le bilan refait ici pour `c` : la fonction même du constat (`Correction::juge`), sur les lectures de cet instant.
/// Une ligne forgée qui désigne une entrée de la table n'écrit donc que ce que le bilan aurait proposé.
pub(crate) fn rejuger(c: &Correction, compte: &Result<String, String>) -> Bilan {
    let Some(juge) = c.juge else {
        return Bilan::Signale;
    };
    match juge(compte) {
        None => Bilan::Illisible,
        Some(constats) => bilan_des_constats(c, &constats),
    }
}

/// Le bilan propose-t-il exactement la ligne de `c` parmi ces constats ?
pub(crate) fn bilan_des_constats(c: &Correction, constats: &[crate::machine::Constat]) -> Bilan {
    let ligne = format!("{PREFIXE}{}", c.id);
    let propose = constats
        .iter()
        .filter_map(|k| k.correctif.as_ref())
        .any(|k| k.commandes.contains(&ligne));
    if propose { Bilan::Signale } else { Bilan::NeSignalePas }
}

/// Le refus d'une valeur que le bilan, refait ici, ne signalerait pas : le même texte que `portes::rejuger`.
fn refus_du_bilan(avant: Option<String>) -> Resultat {
    Resultat::echec(
        avant,
        crate::tr!(
            "refusé : le bilan refait ici ne juge pas cette valeur dangereuse ; rien d'écrit",
            "refused: the check redone here does not find this value dangerous; nothing written"
        )
        .to_string(),
    )
}

/// Le juge de `rdp-coupe` : le constat du Bureau à distance, refait ici (stratégie, session à distance comprises).
// La signature commune des juges (`Juge`) : ce constat-ci se lit toujours.
#[allow(clippy::unnecessary_wraps)]
fn juge_bureau_distance(_: &Result<String, String>) -> Option<Vec<crate::machine::Constat>> {
    Some(vec![super::bureau_distance()])
}

/// Le juge de `latfp-retire` : le constat de LocalAccountTokenFilterPolicy, refait ici.
// La signature commune des juges (`Juge`) : ce constat-ci se lit toujours.
#[allow(clippy::unnecessary_wraps)]
fn juge_jeton_distant(_: &Result<String, String>) -> Option<Vec<crate::machine::Constat>> {
    Some(super::durcissement::jeton_distant())
}

/// Le juge d'`aie-machine` et d'`aie-compte` : le constat d'AlwaysInstallElevated, refait ici avec le registre du
/// compte de la personne (HKEY_USERS\<SID>) ; sans SID, illisible.
fn juge_installation_elevee(compte: &Result<String, String>) -> Option<Vec<crate::machine::Constat>> {
    compte
        .as_ref()
        .ok()
        .map(|sid| super::durcissement::installation_elevee_de(sid))
}

/// Le juge de `heure-ntp` : le constat de l'heure (`machine::heure`), refait ici.
fn juge_heure(_: &Result<String, String>) -> Option<Vec<crate::machine::Constat>> {
    crate::machine::heure::constat().map(|c| vec![c])
}

/// Le juge de `winlogon-shell` : le constat de Winlogon pour l'ordinateur, refait ici.
fn juge_winlogon(_: &Result<String, String>) -> Option<Vec<crate::machine::Constat>> {
    super::portes::winlogon_de_l_ordinateur()
}

/// Ce qu'une écriture de texte fait de la valeur qu'elle trouve.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Ecrire,
    /// Rien d'écrit, réussi : la raison dite telle quelle.
    Rien(String),
    /// Rien d'écrit, refusé.
    Refus,
}

/// La décision pour une valeur texte de la table (`winlogon-shell`, `heure-ntp`), sur la valeur trouvée (`None` :
/// absente) : déjà bonne, rien d'écrit ; le bilan refait ici ne la signale pas, refus ; un type de synchronisation de
/// l'heure qui en règle déjà une (NT5DS, AllSync d'une machine de domaine) n'est jamais remplacé par NTP, seul le
/// service de temps est alors à remettre.
fn decider_sz(id: &str, donnee: &str, avant: Option<&str>, bilan: Bilan, racine: &str) -> Decision {
    use crate::ui::trf;
    let deja = avant.is_some_and(|v| match id {
        "winlogon-shell" => super::portes::bureau_d_origine(v, racine),
        _ => v.trim().eq_ignore_ascii_case(donnee),
    });
    if let Some(v) = avant.filter(|_| deja) {
        return Decision::Rien(trf!(
            "déjà « {} », rien d'écrit",
            "already “{}”, nothing written",
            avant_notable(v)
        ));
    }
    if bilan != Bilan::Signale {
        return Decision::Refus;
    }
    if id == "heure-ntp"
        && let Some(v) = avant.filter(|v| !v.trim().is_empty() && crate::machine::heure::type_synchronise(v))
    {
        return Decision::Rien(trf!(
            "Type = « {} » règle déjà l'heure (machine d'un domaine) : gardé, rien d'écrit",
            "Type = “{}” already sets the time (domain computer): kept, nothing written",
            avant_notable(v)
        ));
    }
    Decision::Ecrire
}

/// Applique une correction de la table avec les droits du processus (élevé) : la valeur d'avant est lue, la nouvelle
/// écrite puis relue, et seul ce qui se relit tel qu'écrit compte comme réussi. Une valeur déjà bonne n'est pas
/// réécrite, et c'est dit. `compte` : le SID de la personne, lu dans le jeton du Vanguard qui a lancé ce processus
/// (tenu par une poignée dès le tube vérifié), ou dans le sien quand Vanguard est lui-même administrateur ; l'erreur
/// de lecture sinon.
///
/// `bilan` : celui de `rejuger`, refait avant le premier geste. Illisible, rien n'est écrit ; s'il ne signale rien,
/// une valeur déjà bonne est dite telle quelle et toute autre est refusée.
pub(crate) fn appliquer(c: &Correction, compte: &Result<String, String>, bilan: Bilan) -> Resultat {
    if bilan == Bilan::Illisible {
        return Resultat::echec(
            None,
            crate::tr!(
                "refusé : le bilan refait ici ne se lit pas ; rien d'écrit",
                "refused: the check redone here cannot be read; nothing written"
            )
            .to_string(),
        );
    }
    let permis = bilan == Bilan::Signale;
    match c.geste {
        // Couper le Bureau à distance depuis une session qu'il affiche couperait la personne : refusé ici aussi, même
        // si la ligne a été forgée (le constat ne le propose pas dans ce cas).
        Geste::Dword { .. } if c.id == "rdp-coupe" && super::session_a_distance() => Resultat::echec(
            None,
            crate::tr!(
                "refusé : cette session passe par le Bureau à distance, le couper vous déconnecterait ; rien d'écrit",
                "refused: this session goes through Remote Desktop, turning it off would disconnect you; nothing written"
            )
            .to_string(),
        ),
        Geste::Dword { cle, valeur, donnee } => ecrire_dword(cle, valeur, donnee, permis),
        Geste::Sz { cle, valeur, donnee } => {
            let racine = super::portes::racine_windows();
            ecrire_sz(cle, valeur, donnee, |v| decider_sz(c.id, donnee, v, bilan, &racine))
        }
        Geste::RetirerValeur { cle, valeur } => retirer_valeur(cle, valeur, permis),
        Geste::DwordCompte { cle, valeur, donnee } => ecrire_dword_compte(cle, valeur, donnee, compte, permis),
        Geste::Userinit => remettre_userinit(),
        Geste::NetbiosCoupe => couper_netbios(),
        Geste::Smb1Serveur => couper_smb1_serveur(),
        Geste::PointDeRestauration => {
            let (reussi, raison) = super::eleve::point_de_restauration();
            Resultat {
                reussi,
                rien: false,
                avant: None,
                raison,
            }
        }
    }
}

/// La valeur d'avant, telle qu'on saura la remettre : un DWORD (« 1 »), « absent » (valeur absente) ou « clé absente ».
/// Autre type, ou lecture en échec : rien n'est changé, puisque le retour arrière effacerait une valeur qui existait.
fn valeur_d_avant(racine: &winreg::RegKey, cle: &str, valeur: &str) -> Result<String, String> {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{KEY_READ, RegType};
    let k = match racine.open_subkey_with_flags(cle, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == NotFound => return Ok("clé absente".into()),
        Err(e) => return Err(format!("valeur d'avant illisible, rien changé : {e}")),
    };
    match k.get_raw_value(valeur) {
        Err(e) if e.kind() == NotFound => Ok("absent".into()),
        Err(e) => Err(format!("valeur d'avant illisible, rien changé : {e}")),
        // Un DWORD fait 4 octets : sinon, le même refus qu'un type inattendu, jamais une valeur inventée.
        Ok(brute) => match <[u8; 4]>::try_from(&*brute.bytes) {
            Ok(octets) if brute.vtype == RegType::REG_DWORD => Ok(u32::from_le_bytes(octets).to_string()),
            _ => Err(format!(
                "valeur d'avant de type inattendu ({:?}), rien changé",
                brute.vtype
            )),
        },
    }
}

fn ecrire_dword(cle: &str, valeur: &str, donnee: u32, permis: bool) -> Resultat {
    let racine = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    ecrire_dword_sous(&racine, cle, valeur, donnee, permis)
}

/// Un DWORD posé sous `racine` : la valeur d'avant lue (refus si elle ne se remettrait pas), rien d'écrit si elle est
/// déjà la bonne, refus si le bilan refait ici ne la signale pas (`permis`), sinon écrit puis relu.
pub(super) fn ecrire_dword_sous(
    racine: &winreg::RegKey,
    cle: &str,
    valeur: &str,
    donnee: u32,
    permis: bool,
) -> Resultat {
    use crate::ui::trf;
    use winreg::enums::{KEY_READ, KEY_WRITE};
    let avant = match valeur_d_avant(racine, cle, valeur) {
        Ok(avant) => avant,
        Err(raison) => return Resultat::echec(None, raison),
    };
    if avant == donnee.to_string() {
        return Resultat::rien(trf!("déjà {donnee}, rien d'écrit", "already {donnee}, nothing written"));
    }
    if !permis {
        return refus_du_bilan(None);
    }
    // RegCreateKeyEx ouvre une clé qui existe sans toucher à ses valeurs (au contraire de New-Item -Force).
    let ecrit = racine
        .create_subkey_with_flags(cle, KEY_READ | KEY_WRITE)
        .and_then(|(k, _)| k.set_value(valeur, &donnee).map(|()| k))
        .and_then(|k| k.get_value::<u32, _>(valeur));
    match ecrit {
        Ok(relu) if relu == donnee => Resultat::fait(avant),
        Ok(relu) => Resultat::echec(Some(avant), format!("relu {relu} au lieu de {donnee}")),
        Err(e) => Resultat::echec(Some(avant), e.to_string()),
    }
}

/// Le texte d'une valeur REG_SZ ou REG_EXPAND_SZ, jusqu'au premier zéro (ce que Windows en lit) ; `None` pour un
/// autre type ou un UTF-16 invalide.
pub(super) fn texte_reg(brute: &winreg::RegValue) -> Option<String> {
    use winreg::enums::RegType::{REG_EXPAND_SZ, REG_SZ};
    if !matches!(brute.vtype, REG_SZ | REG_EXPAND_SZ) || !brute.bytes.len().is_multiple_of(2) {
        return None;
    }
    let (paires, _) = brute.bytes.as_chunks::<2>();
    let unites: Vec<u16> = paires.iter().map(|o| u16::from_le_bytes(*o)).collect();
    let texte = String::from_utf16(&unites).ok()?;
    Some(texte.split('\0').next().unwrap_or_default().to_string())
}

/// Une valeur quelconque, décrite pour la noter : son texte, son DWORD, ou son type.
pub(super) fn decrire(brute: &winreg::RegValue) -> String {
    use winreg::enums::RegType::REG_DWORD;
    if let Some(t) = texte_reg(brute) {
        return avant_notable(&t);
    }
    match <[u8; 4]>::try_from(&*brute.bytes) {
        Ok(octets) if brute.vtype == REG_DWORD => u32::from_le_bytes(octets).to_string(),
        _ => format!("{:?}", brute.vtype),
    }
}

/// Une valeur texte sous HKLM mise à `donnee` (REG_SZ) dans une clé qui existe ; `decider` : que faire de la valeur
/// trouvée (`None` : absente) ? La valeur d'avant doit être un texte ou absente : un autre type est refusé.
fn ecrire_sz(cle: &str, valeur: &str, donnee: &str, decider: impl Fn(Option<&str>) -> Decision) -> Resultat {
    use crate::ui::trf;
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};
    let k =
        match winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(cle, KEY_QUERY_VALUE | KEY_SET_VALUE) {
            Ok(k) => k,
            Err(e) => {
                return Resultat::echec(
                    None,
                    trf!(
                        "clé HKLM\\{cle} inaccessible, rien d'écrit : {e}",
                        "key HKLM\\{cle} not reachable, nothing written: {e}"
                    ),
                );
            }
        };
    let avant = match k.get_raw_value(valeur) {
        Err(e) if e.kind() == NotFound => None,
        Err(e) => {
            return Resultat::echec(
                None,
                trf!(
                    "valeur d'avant illisible, rien d'écrit : {e}",
                    "previous value unreadable, nothing written: {e}"
                ),
            );
        }
        Ok(brute) => match texte_reg(&brute) {
            Some(t) => Some(t),
            None => {
                return Resultat::echec(
                    None,
                    trf!(
                        "valeur d'avant de type inattendu ({:?}), rien d'écrit",
                        "previous value of unexpected type ({:?}), nothing written",
                        brute.vtype
                    ),
                );
            }
        },
    };
    match decider(avant.as_deref()) {
        Decision::Ecrire => {}
        Decision::Rien(raison) => return Resultat::rien(raison),
        Decision::Refus => return refus_du_bilan(None),
    }
    let note = avant.as_deref().map_or_else(|| "absent".to_string(), avant_notable);
    let relu = k
        .set_value(valeur, &donnee.to_string())
        .and_then(|()| k.get_raw_value(valeur));
    match relu {
        Ok(r) if texte_reg(&r).as_deref() == Some(donnee) => Resultat::fait(note),
        Ok(r) => Resultat::echec(
            Some(note),
            trf!(
                "relu « {} » au lieu de « {donnee} »",
                "read back “{}” instead of “{donnee}”",
                decrire(&r)
            ),
        ),
        Err(e) => Resultat::echec(Some(note), e.to_string()),
    }
}

/// Une valeur retirée sous HKLM : déjà absente, rien d'écrit ; refusée si le bilan refait ici ne la signale pas
/// (`permis`) ; sinon notée, retirée, et l'absence relue.
fn retirer_valeur(cle: &str, valeur: &str, permis: bool) -> Resultat {
    use crate::ui::{tr, trf};
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};
    let k = match winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(cle, KEY_QUERY_VALUE | KEY_SET_VALUE)
    {
        Ok(k) => k,
        Err(e) if e.kind() == NotFound => {
            return Resultat::rien(tr!("déjà absente, rien d'écrit", "already absent, nothing written").to_string());
        }
        Err(e) => {
            return Resultat::echec(
                None,
                trf!(
                    "clé HKLM\\{cle} inaccessible, rien d'écrit : {e}",
                    "key HKLM\\{cle} not reachable, nothing written: {e}"
                ),
            );
        }
    };
    let avant = match k.get_raw_value(valeur) {
        Err(e) if e.kind() == NotFound => {
            return Resultat::rien(tr!("déjà absente, rien d'écrit", "already absent, nothing written").to_string());
        }
        Err(e) => {
            return Resultat::echec(
                None,
                trf!(
                    "valeur d'avant illisible, rien d'écrit : {e}",
                    "previous value unreadable, nothing written: {e}"
                ),
            );
        }
        Ok(brute) => decrire(&brute),
    };
    if !permis {
        return refus_du_bilan(None);
    }
    match k.delete_value(valeur) {
        Ok(()) => {}
        Err(e) if e.kind() == NotFound => {}
        Err(e) => return Resultat::echec(Some(avant), e.to_string()),
    }
    match k.get_raw_value(valeur) {
        Err(e) if e.kind() == NotFound => Resultat::fait(avant),
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "la valeur est toujours là après son retrait",
                "the value is still there after its removal"
            )
            .to_string(),
        ),
    }
}

/// Un DWORD dans le registre du compte de la personne (HKEY_USERS\<SID>) : le SID est lu dans le jeton du Vanguard
/// qui a lancé ce processus (tenu par une poignée dès le tube vérifié), ou dans le sien quand Vanguard est lui-même
/// administrateur. Jamais un paramètre de la ligne : un administrateur venu par-dessus l'épaule n'écrit pas dans son
/// propre compte à la place de celui de la personne.
fn ecrire_dword_compte(
    cle: &str,
    valeur: &str,
    donnee: u32,
    compte: &Result<String, String>,
    permis: bool,
) -> Resultat {
    use crate::ui::trf;
    match compte {
        Ok(sid) => {
            let racine = winreg::RegKey::predef(winreg::enums::HKEY_USERS);
            ecrire_dword_sous(&racine, &format!(r"{sid}\{cle}"), valeur, donnee, permis)
        }
        Err(e) => Resultat::echec(
            None,
            trf!(
                "compte de la personne illisible (jeton du Vanguard qui a demandé), rien d'écrit : {e}",
                "the person's account is unreadable (token of the Vanguard that asked), nothing written: {e}"
            ),
        ),
    }
}

/// Userinit de Winlogon remis d'origine : le dossier de Windows lu par ce processus (GetSystemWindowsDirectoryW), le
/// programme vérifié présent ; une valeur que le constat jugerait d'origine (`portes::userinit_d_origine`) n'est pas
/// réécrite. Une erreur ici empêcherait d'ouvrir une session : rien n'est écrit sans userinit.exe sur le disque.
fn remettre_userinit() -> Resultat {
    use crate::ui::{tr, trf};
    let Some(dossier) = super::environnement::dossier_windows() else {
        return Resultat::echec(
            None,
            tr!(
                "dossier de Windows illisible, rien d'écrit",
                "Windows folder unreadable, nothing written"
            )
            .to_string(),
        );
    };
    let racine = dossier.to_string_lossy().trim_end_matches('\\').to_string();
    let programme = format!(r"{racine}\system32\userinit.exe");
    if !std::path::Path::new(&programme).is_file() {
        return Resultat::echec(
            None,
            trf!(
                "{programme} introuvable, rien d'écrit",
                "{programme} not found, nothing written"
            ),
        );
    }
    let origine = format!("{programme},");
    // Rejugé de fait : une valeur que le constat jugerait d'origine n'est pas réécrite, toute autre est signalée.
    ecrire_sz(super::portes::WINLOGON, "Userinit", &origine, |v| match v {
        Some(v) if super::portes::userinit_d_origine(v, &racine) => Decision::Rien(trf!(
            "déjà « {} », rien d'écrit",
            "already “{}”, nothing written",
            avant_notable(v)
        )),
        _ => Decision::Ecrire,
    })
}

/// NetBIOS sur TCP/IP coupé sur chaque carte : la liste des cartes (NetBT\Parameters\Interfaces\Tcpip_*) est lue
/// d'abord (Microsoft déconseille d'écrire pendant l'énumération), puis NetbiosOptions = 2 posé et relu dans chacune.
/// L'avant est noté par carte ; toutes déjà à 2 : rien d'écrit.
fn couper_netbios() -> Resultat {
    use crate::ui::trf;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_READ, KEY_WRITE};
    let racine = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    // Une sous-clé dont le nom ne se lit pas est comptée illisible, jamais oubliée : la carte resterait ouverte.
    let mut illisibles = Vec::new();
    let cartes: Vec<String> = match racine.open_subkey_with_flags(NETBT_INTERFACES, KEY_ENUMERATE_SUB_KEYS) {
        Ok(k) => k
            .enum_keys()
            .filter_map(|n| match n {
                Ok(n) => Some(n),
                Err(e) => {
                    illisibles.push(trf!("sous-clé illisible : {e}", "unreadable subkey: {e}"));
                    None
                }
            })
            .filter(|n| n.starts_with("Tcpip_"))
            .collect(),
        Err(e) => {
            return Resultat::echec(
                None,
                trf!(
                    "cartes réseau illisibles (NetBT), rien d'écrit : {e}",
                    "network adapters unreadable (NetBT), nothing written: {e}"
                ),
            );
        }
    };
    let mut avants = Vec::new();
    for carte in cartes {
        let cle = format!(r"{NETBT_INTERFACES}\{carte}");
        match valeur_d_avant(&racine, &cle, "NetbiosOptions") {
            Ok(a) => avants.push((carte, a)),
            Err(raison) => illisibles.push(trf!("{carte} : {raison}", "{carte}: {raison}")),
        }
    }
    let mut echecs = Vec::new();
    for (carte, a) in &avants {
        if a == "2" {
            continue;
        }
        let relu = racine
            .open_subkey_with_flags(format!(r"{NETBT_INTERFACES}\{carte}"), KEY_READ | KEY_WRITE)
            .and_then(|k| k.set_value("NetbiosOptions", &2u32).map(|()| k))
            .and_then(|k| k.get_value::<u32, _>("NetbiosOptions"));
        match relu {
            Ok(2) => {}
            Ok(n) => echecs.push(trf!("{carte} : relu {n}", "{carte}: read back {n}")),
            Err(e) => echecs.push(trf!("{carte} : {e}", "{carte}: {e}")),
        }
    }
    issue_netbios(&avants, &illisibles, &echecs)
}

/// L'issue d'une coupure de NetBIOS, à partir de ce qui a été lu et écrit : `avants`, chaque carte lue et sa valeur
/// d'avant ; `illisibles` et `echecs`, une raison par carte non lue ou mal écrite. Réussie seulement si chaque carte
/// a été lue et chaque écriture relue à 2 ; sinon, le compte dit ce qui a été fait (« 3 cartes, 1 écrite… »).
/// Écrit, NetbiosOptions ne prend effet qu'au prochain redémarrage (ou à la reconnexion de la carte) : dit aussi.
fn issue_netbios(avants: &[(String, String)], illisibles: &[String], echecs: &[String]) -> Resultat {
    use crate::ui::{tr, trf};
    let cartes = avants.len() + illisibles.len();
    if cartes == 0 {
        return Resultat::echec(
            None,
            tr!(
                "aucune carte réseau sous NetBT, rien d'écrit",
                "no network adapter under NetBT, nothing written"
            )
            .to_string(),
        );
    }
    let a_ecrire = avants.iter().filter(|(_, a)| a != "2").count();
    let ecrites = a_ecrire.saturating_sub(echecs.len());
    let mut compte = compte_netbios(cartes, ecrites, illisibles.len());
    if ecrites > 0 {
        compte = trf!(
            "{compte}, effectif au prochain redémarrage",
            "{compte}, effective at the next restart"
        );
    }
    let note = note_netbios(&compte, avants);
    if illisibles.is_empty() && echecs.is_empty() {
        return if a_ecrire == 0 {
            Resultat::rien(
                tr!(
                    "NetbiosOptions déjà à 2 sur chaque carte, rien d'écrit",
                    "NetbiosOptions already 2 on every adapter, nothing written"
                )
                .to_string(),
            )
        } else {
            Resultat::fait(note)
        };
    }
    let raisons = illisibles
        .iter()
        .chain(echecs)
        .cloned()
        .collect::<Vec<_>>()
        .join(tr!(" ; ", "; "));
    Resultat::echec(
        Some(note),
        avant_notable(&trf!("{compte} : {raisons}", "{compte}: {raisons}")),
    )
}

/// NetBIOS est-il coupé dans le registre (NetbiosOptions = 2) sur chaque carte ? Pour le bilan : le port 137 reste
/// ouvert jusqu'au prochain redémarrage après la coupure. Une carte ou une valeur illisible n'est pas coupée.
pub(super) fn netbios_coupe() -> bool {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    let Ok(k) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(NETBT_INTERFACES, KEY_READ) else {
        return false;
    };
    let valeurs: Vec<Option<u32>> = k
        .enum_keys()
        .filter(|n| n.as_ref().map_or(true, |n| n.starts_with("Tcpip_")))
        .map(|n| {
            n.ok()
                .and_then(|n| k.open_subkey(n).ok()?.get_value("NetbiosOptions").ok())
        })
        .collect();
    coupe_partout(&valeurs)
}

/// Coupé partout : au moins une carte, et chacune lue à 2.
fn coupe_partout(valeurs: &[Option<u32>]) -> bool {
    !valeurs.is_empty() && valeurs.iter().all(|v| *v == Some(2))
}

/// Le compte d'une coupure de NetBIOS : « 3 cartes, 2 écrites, 1 illisibles ».
fn compte_netbios(cartes: usize, ecrites: usize, illisibles: usize) -> String {
    crate::ui::trf!(
        "{cartes} cartes, {ecrites} écrites, {illisibles} illisibles",
        "{cartes} adapters, {ecrites} written, {illisibles} unreadable"
    )
}

/// La valeur d'avant de chaque carte, après le compte (« 2 cartes, 1 écrites, 0 illisibles : Tcpip_{…}=0;… ») ;
/// trop longue, elle le dit (« … coupé ») au lieu de perdre des cartes en silence.
fn note_netbios(compte: &str, avants: &[(String, String)]) -> String {
    use crate::ui::{affichable, couper, largeur_affichee, tr, trf};
    let liste = avants
        .iter()
        .map(|(carte, a)| format!("{carte}={a}"))
        .collect::<Vec<_>>()
        .join(";");
    let entiere = affichable(&trf!("{compte} : {liste}", "{compte}: {liste}"));
    if largeur_affichee(&entiere) <= AVANT_MAX {
        return entiere;
    }
    let marque = tr!(" coupé", " cut");
    couper(&entiere, AVANT_MAX - largeur_affichee(marque)) + marque
}

/// SMBv1 coupé dans le serveur de partage par WMI (MSFT_SmbServerConfiguration.SetConfiguration, ce que fait
/// Set-SmbServerConfiguration), puis relu par la même fonction que le constat (`smb1_actif`). Déjà coupé : rien d'écrit.
fn couper_smb1_serveur() -> Resultat {
    use super::wmi::{CLASSE_ABSENTE, Parametre, Retour};
    use crate::ui::{tr, trf};
    const ESPACE: &str = r"root\Microsoft\Windows\Smb";
    const DELAI: std::time::Duration = std::time::Duration::from_secs(60);
    let lu = || {
        winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
            .ok()
            .and_then(|k| k.get_value::<u32, _>("SMB1").ok())
            .map_or_else(|| "absent".to_string(), |v| v.to_string())
    };
    match super::smb1_actif() {
        None => {
            return Resultat::echec(
                None,
                tr!(
                    "état de SMBv1 illisible, rien d'écrit",
                    "SMBv1 state unreadable, nothing written"
                )
                .to_string(),
            );
        }
        Some(false) => {
            return Resultat::rien(tr!("déjà coupé, rien d'écrit", "already off, nothing written").to_string());
        }
        Some(true) => {}
    }
    let avant = format!("SMB1={}", lu());
    let retour = super::wmi::methode(
        ESPACE,
        "MSFT_SmbServerConfiguration",
        "SetConfiguration",
        vec![("EnableSMB1Protocol", Parametre::Booleen(false))],
        DELAI,
    );
    let refus = match retour {
        Retour::Valeur(0) => None,
        Retour::Valeur(n) => Some(trf!("WMI a répondu {n}", "WMI answered {n}")),
        Retour::Refuse(code) if CLASSE_ABSENTE.contains(&code) => Some(trf!(
            "le réglage SMB de Windows est absent (WMI 0x{code:08X})",
            "Windows' SMB setting is missing (WMI 0x{code:08X})"
        )),
        Retour::Refuse(code) => Some(trf!("WMI a refusé (0x{code:08X})", "WMI refused (0x{code:08X})")),
        Retour::SansReponse => Some(tr!("WMI n'a pas répondu à temps", "WMI did not answer in time").to_string()),
    };
    if let Some(r) = refus {
        return Resultat::echec(Some(avant), r);
    }
    match super::smb1_actif() {
        Some(false) => Resultat::fait(avant),
        _ => Resultat::echec(
            Some(avant),
            trf!(
                "WMI a répondu 0, mais SMBv1 se relit encore actif (SMB1={})",
                "WMI answered 0, but SMBv1 still reads as on (SMB1={})",
                lu()
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les actes du pare-feu et des réseaux : une remise est dite moins protégée avant l'accord, ce qui durcit ne
    /// l'est pas ; le pare-feu rallumé, le profil Public durci et un réseau passé en Public sont des protections, que
    /// « Défaire » ne propose pas ; une remise seule ne l'est pas. Le chemin de Wine reprend les commandes d'avant.
    #[test]
    fn les_actes_du_pare_feu_se_montrent_et_se_defont() {
        use crate::machine::Defaire;
        use crate::machine::gestes;
        let g = "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}";
        let moins = |l: &str| {
            let t = affichable(l);
            assert!(!t.starts_with("vanguard:"), "{t}");
            // Ce que l'élevé ne peut pas savoir d'une ligne n'est jamais affirmé.
            assert!(!t.contains("avait coupé") && !t.contains("had turned off"), "{t}");
            t.contains("moins protégé") || t.contains("less protected")
        };
        let durcies = [
            gestes::ligne_pare_feu_actif(),
            "vanguard:pare-feu-public actif=oui,entrant-bloque=oui,regles-entrantes=non".to_string(),
            format!("vanguard:reseau-categorie {g} public"),
        ];
        for l in &durcies {
            assert!(native(l) && !moins(l), "{l}");
            assert_eq!(comment_defaire(std::slice::from_ref(l)), Defaire::Protection, "{l}");
        }
        let remises = [
            "vanguard:pare-feu-public regles-entrantes=absent".to_string(),
            "vanguard:pare-feu-public entrant-bloque=non".to_string(),
            format!("vanguard:reseau-categorie {g} prive"),
        ];
        for l in &remises {
            assert!(native(l) && moins(l), "{l}");
            assert_eq!(comment_defaire(std::slice::from_ref(l)), Defaire::Inconnu, "{l}");
        }
        // Le réseau est désigné par son GUID, et dit inconnu quand aucun profil ne le porte (ni sous Wine ni dans la VM).
        let t = affichable(&format!("vanguard:reseau-categorie {g} prive"));
        assert!(
            t.contains(g) && (t.contains("inconnu de ce PC") || t.contains("unknown to this PC")),
            "{t}"
        );
        let t = affichable("vanguard:pare-feu-public regles-entrantes=absent");
        assert!(t.contains("non configuré") || t.contains("not configured"), "{t}");
        let ps = en_powershell(&[vec![gestes::ligne_pare_feu_actif()]]);
        assert_eq!(
            ps,
            vec![vec![
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True".to_string()
            ]]
        );
    }

    /// Lecture seule : rien n'est écrit dans le registre de la machine de test.
    #[test]
    fn valeur_d_avant_exacte_ou_refus() {
        let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
        let nt = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        assert_eq!(
            valeur_d_avant(&hklm, r"SOFTWARE\VanguardInexistante", "X").unwrap(),
            "clé absente"
        );
        assert_eq!(valeur_d_avant(&hklm, nt, "VanguardInexistante").unwrap(), "absent");
        // Une chaîne (REG_SZ) ne se remet pas comme un DWORD : refusée, rien n'est changé.
        assert!(
            valeur_d_avant(&hklm, nt, "ProductName")
                .unwrap_err()
                .contains("type inattendu")
        );
    }

    #[test]
    fn la_table_est_bien_formee() {
        for c in TABLE {
            assert!(analyser(&id(c.id)).is_some_and(|t| std::ptr::eq(t, c)), "{}", c.id);
            assert!(!c.powershell().is_empty() && !c.texte().is_empty());
            // Aucun geste de la table n'affaiblit la sécurité : les valeurs écrites sont celles du durcissement, ou,
            // pour un réglage pour jouer (`gaming-*`, liste fermée), HAGS seul, qui ne touche à aucune protection.
            if c.id.starts_with("gaming-") {
                assert!(
                    matches!(
                        c.geste,
                        Geste::Dword {
                            valeur: "HwSchMode",
                            donnee: 2,
                            ..
                        }
                    ),
                    "{}",
                    c.id
                );
                assert_eq!(comment_defaire(&[id(c.id)]), crate::machine::Defaire::Inconnu);
                continue;
            }
            if let Geste::Dword { valeur, donnee, .. } = c.geste {
                const DURCIES: &[(&str, u32)] = &[
                    ("UseLogonCredential", 0),
                    ("UserAuthentication", 1),
                    ("LimitBlankPasswordUse", 1),
                    ("LmCompatibilityLevel", 3),
                    ("RestrictAnonymousSAM", 1),
                    ("EveryoneIncludesAnonymous", 0),
                    ("NoLMHash", 1),
                    ("LoadAppInit_DLLs", 0),
                    ("DisableWpad", 1),
                    ("AllowInsecureGuestAuth", 0),
                    ("EnableScriptBlockLogging", 1),
                    ("EnableLUA", 1),
                    ("ConsentPromptBehaviorAdmin", 5),
                    ("EnableMulticast", 0),
                    ("VulnerableDriverBlocklistEnable", 1),
                    ("fDenyTSConnections", 1),
                    ("AlwaysInstallElevated", 0),
                ];
                assert!(DURCIES.contains(&(valeur, donnee)), "{valeur} = {donnee}");
            }
            // Les autres gestes : des valeurs d'origine de Windows remises, une valeur dangereuse retirée, le compte
            // de la personne durci comme l'ordinateur ; rien d'autre.
            match c.geste {
                Geste::Sz { valeur, donnee, .. } => {
                    assert!(
                        [("Type", "NTP"), ("Shell", "explorer.exe")].contains(&(valeur, donnee)),
                        "{valeur}"
                    );
                }
                Geste::RetirerValeur { valeur, .. } => assert_eq!(valeur, "LocalAccountTokenFilterPolicy"),
                Geste::DwordCompte { valeur, donnee, .. } => assert_eq!((valeur, donnee), ("AlwaysInstallElevated", 0)),
                _ => {}
            }
        }
        assert_eq!(analyser(POINT).map(|c| c.id), Some("point-de-restauration"));
        // Le chemin par script crée la clé seulement si elle manque, puis écrit un vrai DWORD.
        let llmnr = analyser(&id("llmnr-coupe")).unwrap().powershell();
        assert!(llmnr.starts_with(
            "if (-not (Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient'))"
        ));
        assert!(llmnr.ends_with("-Name EnableMulticast -Value 0 -Type DWord"));
    }

    /// Chaque geste de registre passé de PowerShell à Windows (lot 3.1) garde, pour le chemin par script, la commande
    /// que le constat écrivait avant, mot pour mot ; c'est une protection, que « Défaire » ne propose pas.
    #[test]
    fn les_gestes_du_registre_gardent_leur_powershell() {
        use crate::machine::Defaire;
        let ps = |court: &str| analyser(&id(court)).unwrap().powershell();
        let fixes = [
            (
                "rdp-coupe",
                r"Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1",
            ),
            (
                "latfp-retire",
                r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy",
            ),
            (
                "aie-machine",
                r"Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord",
            ),
            (
                "heure-ntp",
                r"Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name Type -Value NTP",
            ),
            (
                "winlogon-shell",
                r"Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'explorer.exe' -Type String",
            ),
            (
                "netbios-coupe",
                "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null",
            ),
            (
                "smb1-serveur-coupe",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            ),
        ];
        for (court, attendu) in fixes {
            assert_eq!(ps(court), attendu, "{court}");
        }
        // Calculées comme le constat les calculait (le HKCU de la personne, la racine de Windows) : comparées à la
        // commande attendue, écrite en entier.
        assert_eq!(
            ps_dword_compte(Some("S-1-5-21-1-2-3-1001"), INSTALLEUR, "AlwaysInstallElevated", 0),
            r"Set-ItemProperty -LiteralPath 'Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord"
        );
        assert_eq!(
            ps_dword_compte(None, INSTALLEUR, "AlwaysInstallElevated", 0),
            r"Set-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord"
        );
        assert_eq!(
            ps_userinit(r"C:\Windows"),
            r"Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,' -Type String"
        );
        // Une apostrophe dans la racine est doublée : elle ne ferme pas la chaîne.
        assert_eq!(
            ps_userinit(r"D:\Win'dows"),
            r"Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -Value 'D:\Win''dows\system32\userinit.exe,' -Type String"
        );
        for court in [
            "rdp-coupe",
            "latfp-retire",
            "aie-machine",
            "aie-compte",
            "heure-ntp",
            "winlogon-shell",
            "winlogon-userinit",
            "netbios-coupe",
            "smb1-serveur-coupe",
        ] {
            let l = id(court);
            assert!(native(&l), "{court}");
            assert_eq!(
                comment_defaire(std::slice::from_ref(&l)),
                Defaire::Protection,
                "{court}"
            );
            assert!(!affichable(&l).starts_with("vanguard:"), "{court}");
        }
        // Aucun paramètre : ni la racine de Userinit, ni le SID du compte, ni une carte réseau.
        for hostile in [
            "vanguard:winlogon-userinit x",
            r"vanguard:winlogon-userinit C:\Evil",
            "vanguard:aie-compte S-1-5-21-1-2-3-500",
            "vanguard:netbios-coupe Tcpip_{0}",
        ] {
            assert!(analyser(hostile).is_none() && !native(hostile), "{hostile}");
        }
    }

    /// Le juge d'une entrée est la fonction de son constat : sur les mêmes données, le bilan refait dit « signale »
    /// exactement quand le constat propose la ligne de l'entrée. Sans SID, le juge du compte ne se lit pas.
    #[test]
    fn le_juge_est_la_fonction_du_constat() {
        use super::super::{durcissement, portes};
        let c = |court: &str| analyser(&id(court)).unwrap();
        let en_liste = |k: Option<crate::machine::Constat>| k.into_iter().collect::<Vec<_>>();
        for court in ["aie-machine", "aie-compte"] {
            let juge = |m, k| bilan_des_constats(c(court), &en_liste(durcissement::juger_installation_elevee(m, k)));
            assert_eq!(juge(Some(1), Some(1)), Bilan::Signale, "{court}");
            for (m, k) in [(Some(1), Some(0)), (Some(0), Some(1)), (Some(1), None), (None, None)] {
                assert_eq!(juge(m, k), Bilan::NeSignalePas, "{court} {m:?} {k:?}");
            }
            assert_eq!(
                rejuger(c(court), &Err("jeton illisible".into())),
                Bilan::Illisible,
                "{court}"
            );
        }
        let jeton = |v| bilan_des_constats(c("latfp-retire"), &en_liste(durcissement::juger_jeton_distant(v)));
        assert_eq!(jeton(Some(1)), Bilan::Signale);
        assert_eq!(jeton(Some(0)), Bilan::NeSignalePas);
        assert_eq!(jeton(None), Bilan::NeSignalePas);
        let userinit = r"C:\Windows\system32\userinit.exe,";
        let shell = |s| {
            bilan_des_constats(
                c("winlogon-shell"),
                &portes::juger_winlogon(Some(s), Some(userinit), None, r"C:\Windows"),
            )
        };
        assert_eq!(shell(r"C:\Users\alice\AppData\Roaming\bureau.exe"), Bilan::Signale);
        assert_eq!(shell("explorer.exe"), Bilan::NeSignalePas);
        assert_eq!(shell(r"C:\Windows\explorer.exe"), Bilan::NeSignalePas);
        // Une entrée sans juge (une valeur de durcissement) garde son écriture.
        assert_eq!(rejuger(c("wdigest-coupe"), &Err(String::new())), Bilan::Signale);
    }

    /// L'issue d'une coupure de NetBIOS : réussie seulement si chaque carte a été lue et relue à 2 ; une carte
    /// illisible ou mal écrite en fait un échec qui dit le compte ; la note garde chaque carte, ou dit qu'elle est
    /// coupée ; déjà à 2 partout, rien.
    #[test]
    fn netbios_compte_chaque_carte() {
        let avants = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter().map(|(c, a)| ((*c).to_string(), (*a).to_string())).collect()
        };
        let deux = avants(&[("Tcpip_{A}", "0"), ("Tcpip_{B}", "2")]);
        // Tout lu et écrit : fait, avec le compte, la réserve du redémarrage et chaque valeur d'avant.
        let r = issue_netbios(&deux, &[], &[]);
        assert!(r.reussi && !r.rien);
        assert_eq!(
            r.avant.as_deref(),
            Some("2 cartes, 1 écrites, 0 illisibles, effectif au prochain redémarrage : Tcpip_{A}=0;Tcpip_{B}=2")
        );
        // Déjà à 2 partout : rien d'écrit, et pas noté parmi ce que Vanguard a changé.
        let r = issue_netbios(&avants(&[("Tcpip_{A}", "2")]), &[], &[]);
        assert!(r.reussi && r.rien && r.avant.is_none());
        // Une carte illisible : jamais « fait », même si le reste est écrit.
        let illisible = vec!["Tcpip_{C} : valeur d'avant illisible".to_string()];
        let r = issue_netbios(&deux, &illisible, &[]);
        assert!(!r.reussi);
        assert!(
            r.raison.starts_with("3 cartes, 1 écrites, 1 illisibles"),
            "{}",
            r.raison
        );
        assert!(
            r.raison.ends_with("Tcpip_{C} : valeur d'avant illisible"),
            "{}",
            r.raison
        );
        // Une écriture relue autrement : échec, rien de compté écrit.
        let r = issue_netbios(&deux, &[], &["Tcpip_{A} : relu 0".to_string()]);
        assert!(!r.reussi);
        assert!(
            r.raison
                .starts_with("2 cartes, 0 écrites, 0 illisibles : Tcpip_{A} : relu 0"),
            "{}",
            r.raison
        );
        assert!(!r.raison.contains("redémarrage"), "{}", r.raison);
        // Aucune carte du tout : échec, rien d'écrit.
        let r = issue_netbios(&[], &[], &[]);
        assert!(!r.reussi && r.avant.is_none());
        // Seules des cartes illisibles : échec.
        assert!(!issue_netbios(&[], &illisible, &[]).reussi);
        // Trop de cartes pour la note : coupée, et dit.
        let beaucoup: Vec<(String, String)> = (0..40)
            .map(|i| (format!("Tcpip_{{{i:08}-0000-0000-0000-000000000000}}"), "0".to_string()))
            .collect();
        let note = note_netbios("40 cartes, 40 écrites, 0 illisibles", &beaucoup);
        assert!(note.ends_with("… coupé"), "{note}");
        assert!(crate::ui::largeur_affichee(&note) <= AVANT_MAX);
        assert!(note.starts_with("40 cartes, 40 écrites, 0 illisibles : Tcpip_{00000000-"));
        // Le bilan : coupé seulement si chaque carte est lue à 2.
        assert!(coupe_partout(&[Some(2), Some(2)]));
        assert!(!coupe_partout(&[Some(2), None]));
        assert!(!coupe_partout(&[Some(2), Some(0)]));
        assert!(!coupe_partout(&[]));
    }

    /// Ce qu'une écriture de texte fait de la valeur trouvée : déjà bonne, dit ; le bilan muet, refusé ; un type de
    /// domaine (NT5DS, AllSync) jamais remplacé par NTP.
    #[test]
    fn decider_sz_refuse_ce_que_le_bilan_ne_signale_pas() {
        let racine = r"C:\Windows";
        let d = |id, donnee, avant, bilan| decider_sz(id, donnee, avant, bilan, racine);
        let rien = |x: Decision| matches!(x, Decision::Rien(_));
        // Une ligne forgée sur une machine d'un domaine : le bilan ne signale rien, refusée.
        assert_eq!(
            d("heure-ntp", "NTP", Some("NT5DS"), Bilan::NeSignalePas),
            Decision::Refus
        );
        assert_eq!(
            d("heure-ntp", "NTP", Some("AllSync"), Bilan::NeSignalePas),
            Decision::Refus
        );
        assert_eq!(
            d("heure-ntp", "NTP", Some("NoSync"), Bilan::NeSignalePas),
            Decision::Refus
        );
        // Service coupé sur une machine d'un domaine : signalé, mais le type est gardé.
        let Decision::Rien(t) = d("heure-ntp", "NTP", Some("NT5DS"), Bilan::Signale) else {
            panic!("NT5DS remplacé");
        };
        assert!(t.contains("NT5DS"), "{t}");
        assert!(rien(d("heure-ntp", "NTP", Some("AllSync"), Bilan::Signale)));
        // Déjà NTP : dit, même si le bilan ne signale rien.
        assert!(rien(d("heure-ntp", "NTP", Some(" ntp "), Bilan::NeSignalePas)));
        assert_eq!(d("heure-ntp", "NTP", Some("NoSync"), Bilan::Signale), Decision::Ecrire);
        assert_eq!(d("heure-ntp", "NTP", Some(""), Bilan::Signale), Decision::Ecrire);
        assert_eq!(d("heure-ntp", "NTP", None, Bilan::Signale), Decision::Ecrire);
        // Winlogon : le chemin complet d'origine est déjà bon ; un autre programme ne s'écrase que signalé.
        assert!(rien(d(
            "winlogon-shell",
            "explorer.exe",
            Some(r"C:\Windows\explorer.exe"),
            Bilan::NeSignalePas
        )));
        assert_eq!(
            d(
                "winlogon-shell",
                "explorer.exe",
                Some("bureau.exe"),
                Bilan::NeSignalePas
            ),
            Decision::Refus
        );
        assert_eq!(
            d("winlogon-shell", "explorer.exe", Some("bureau.exe"), Bilan::Signale),
            Decision::Ecrire
        );
    }

    /// Les actes du registre (débogueur IFEO, SilentProcessExit, guillemets d'un service) : montrés par leur nom rendu
    /// inoffensif, jamais par leur ligne ; des protections.
    #[test]
    fn les_actes_du_registre_se_montrent_et_se_defont() {
        use crate::machine::Defaire;
        use crate::machine::gestes::{self, Vue};
        let lignes = [
            gestes::ligne_ifeo_debugger(Vue::Windows, "sethc.exe").unwrap(),
            gestes::ligne_ifeo_debugger(Vue::Wow32, "sethc.exe").unwrap(),
            gestes::ligne_ifeo_silencieux(Vue::Windows, "notepad.exe").unwrap(),
            gestes::ligne_service_guillemets("Mon Service").unwrap(),
        ];
        for l in &lignes {
            let t = affichable(l);
            assert!(
                native(l) && !t.starts_with("vanguard:") && !t.contains("moins protégé"),
                "{t}"
            );
            assert_eq!(comment_defaire(std::slice::from_ref(l)), Defaire::Protection, "{l}");
        }
        assert!(affichable(&lignes[0]).contains("sethc.exe"));
        assert!(affichable(&lignes[1]).contains("32"));
        assert!(affichable(&lignes[3]).contains("Mon Service"));
        let ps = en_powershell(&[lignes.to_vec()]);
        assert_eq!(
            ps[0][0],
            r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger"
        );
    }

    /// Tout ce qui n'est pas exactement un identifiant de la table est refusé : du PowerShell, un identifiant
    /// décoré, un paramètre, une casse différente, un caractère de contrôle, une ligne trop longue.
    #[test]
    fn les_lignes_hostiles_sont_refusees() {
        for hostile in [
            "",
            "vanguard:",
            "Set-ItemProperty HKLM:\\x -Name y -Value 1",
            "vanguard:wdigest-coupe; Remove-Item C:\\",
            "vanguard:wdigest-coupe ",
            " vanguard:wdigest-coupe",
            "vanguard:wdigest-coupe\n",
            "vanguard:wdigest-coupe\r",
            "vanguard:wdigest-coupe\0",
            "vanguard:WDIGEST-COUPE",
            "vanguard:wdigest-coupe 1",
            "vanguard:wdigest-coupe=1",
            "vanguard:../wdigest-coupe",
            "vanguard:inconnue",
            "vanguard:uac-coupe",
            "Vanguard:wdigest-coupe",
            "vanguard:vanguard:wdigest-coupe",
            "vanguard:wdigést-coupe",
        ] {
            assert!(analyser(hostile).is_none(), "{hostile:?}");
        }
        let longue = format!("vanguard:{}", "a".repeat(41));
        assert!(analyser(&longue).is_none());
        let tres_longue = format!("vanguard:wdigest-coupe{}", " ".repeat(LIGNE_MAX));
        assert!(analyser(&tres_longue).is_none());
    }

    #[test]
    fn la_liste_est_validee_entiere_ou_pas_du_tout() {
        let bonne = vec![POINT.to_string(), id("wdigest-coupe"), id("rdp-nla")];
        let v = valider(&bonne).unwrap();
        assert_eq!(
            v.iter().map(|c| c.id).collect::<Vec<_>>(),
            ["point-de-restauration", "wdigest-coupe", "rdp-nla"]
        );
        // Une seule ligne étrangère, et rien ne passe.
        let mut melee = bonne.clone();
        melee.push("Disable-LocalUser alice".into());
        assert!(valider(&melee).is_none());
        // Une répétition non plus, ni une liste vide ou trop longue.
        assert!(valider(&[id("rdp-nla"), id("rdp-nla")]).is_none());
        assert!(valider(&[]).is_none());
        assert!(valider(&vec![id("rdp-nla"); LIGNES_MAX + 1]).is_none());
    }

    #[test]
    fn liste_mixte_vers_powershell() {
        let correctifs = vec![
            vec![POINT.to_string()],
            vec![id("rdp-nla")],
            vec!["Update-MpSignature".to_string()],
            vec![crate::machine::gestes::ligne_programme("sfc-scannow", None)],
        ];
        assert!(correctifs[..2].iter().flatten().all(|l| native(l)));
        assert!(!native(&correctifs[2][0]) && native(&correctifs[3][0]));
        let ps = en_powershell(&correctifs);
        assert!(ps[0][0].contains("Checkpoint-Computer"), "{}", ps[0][0]);
        assert!(ps[1][0].contains("UserAuthentication -Value 1"), "{}", ps[1][0]);
        assert_eq!(ps[2][0], "Update-MpSignature");
        assert!(affichable(&id("rdp-nla")).contains("NLA"));
        assert_eq!(affichable("Update-MpSignature"), "Update-MpSignature");
        // Un programme fixe : par son chemin dans System32, jamais par le PATH ; montré avec sa commande.
        assert_eq!(ps[3][0], r#"& "$env:SystemRoot\System32\sfc.exe" /scannow"#);
        assert!(
            affichable(&correctifs[3][0]).ends_with("sfc.exe /scannow"),
            "{}",
            affichable(&correctifs[3][0])
        );
    }

    /// Un geste du compte se défait selon ce qu'il fait : les macros d'Office et la stratégie de PowerShell durcissent
    /// (protection) ; un réglage pour jouer, un retrait de démarrage, de shell ou de proxy non (décision 4 b) du plan),
    /// pas plus que HAGS (`gaming-hags`) : pas encore annulables (« Inconnu », non relevé), le lot 3.5 les relèvera. Il se montre dans les mots de la personne, jamais sous sa ligne brute.
    #[test]
    fn un_geste_du_compte_se_defait_selon_ce_qu_il_fait() {
        use crate::machine::Defaire;
        use crate::machine::gestes;
        let durcis = [
            gestes::ligne_compte("ps-strategie").unwrap(),
            gestes::ligne_macros("16.0", "word").unwrap(),
        ];
        for l in &durcis {
            assert_eq!(comment_defaire(std::slice::from_ref(l)), Defaire::Protection, "{l}");
        }
        let non_proteges = [
            gestes::ligne_compte("jeux-mode").unwrap(),
            gestes::ligne_compte("winlogon-shell-compte").unwrap(),
            gestes::ligne_compte("proxy-coupe").unwrap(),
            gestes::ligne_compte("proxy-script-retire").unwrap(),
            gestes::ligne_run_retirer(true, &[0x61]).unwrap(),
            gestes::ligne_alimentation(),
            id("gaming-hags"),
        ];
        for l in &non_proteges {
            assert_eq!(comment_defaire(std::slice::from_ref(l)), Defaire::Inconnu, "{l}");
        }
        // Avec un geste qui durcit dans la même liste : protection.
        let melee = vec![non_proteges[0].clone(), durcis[0].clone()];
        assert_eq!(comment_defaire(&melee), Defaire::Protection);
        for l in durcis.iter().chain(&non_proteges) {
            let t = affichable(l);
            assert!(!t.contains("vanguard:") && !t.is_empty(), "{t}");
        }
        let t = affichable(&gestes::ligne_run_retirer(false, &"l'agent".encode_utf16().collect::<Vec<_>>()).unwrap());
        assert!(t.contains("l'agent"), "{t}");
    }
}
