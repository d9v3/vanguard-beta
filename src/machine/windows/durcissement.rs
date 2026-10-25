//! Durcissement de Windows : ce qui livre les mots de passe ou ouvre une porte, au-delà du pare-feu et de l'antivirus.
//! WDigest qui garde les mots de passe en clair dans la mémoire (ce qu'un voleur de mots de passe lit), la protection
//! de l'autorité de sécurité locale (LSA) qui protège ces secrets, PowerShell 2.0 qui échappe à l'antivirus et aux
//! journaux, et l'Assistance à distance, la porte des faux techniciens. Le registre se lit sans droits
//! administrateur ; PowerShell 2.0 et Credential Guard, par WMI (PowerShell seulement si WMI ne répond pas).

use super::*;

const DURCI: &str = "Durcissement";
const WDIGEST: &str = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";

fn lire_dword(cle: &str, valeur: &str) -> Option<u32> {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(cle)
        .ok()?
        .get_value(valeur)
        .ok()
}

/// WDigest : `UseLogonCredential` à 1 garde chaque mot de passe en clair dans la mémoire de LSASS.
pub(super) fn juger_wdigest(valeur: Option<u32>) -> Constat {
    if valeur == Some(1) {
        alerte(
            DURCI,
            Niveau::Eleve,
            tr!(
                "WDigest garde les mots de passe en clair dans la mémoire : un voleur de mots de passe (Mimikatz et ses copies) les lit tels quels.",
                "WDigest keeps passwords in clear text in memory: a password stealer (Mimikatz and its copies) reads them as they are."
            ),
        )
        .corriger(
            tr!(
                "Couper WDigest (valeur par défaut depuis Windows 8.1 ; effet à la prochaine ouverture de session)",
                "Turn WDigest off (the default since Windows 8.1; takes effect at the next sign-in)"
            ),
            &[&super::corrections::id("wdigest-coupe")],
        )
    } else {
        ok(
            DURCI,
            tr!(
                "WDigest ne garde pas les mots de passe en clair dans la mémoire.",
                "WDigest does not keep passwords in clear text in memory."
            ),
        )
    }
}

/// Protection LSA : `RunAsPPL` à 1 ou 2 (2 : sans verrou UEFI). Absente : une information, à activer soi-même (un
/// pilote ancien peut la refuser, Windows le dit alors).
pub(super) fn juger_lsa(valeur: Option<u32>) -> Constat {
    if matches!(valeur, Some(1 | 2)) {
        ok(
            DURCI,
            tr!(
                "Protection de l'autorité de sécurité locale (LSA) active : les secrets de connexion sont protégés.",
                "Local Security Authority (LSA) protection on: sign-in secrets are protected."
            ),
        )
    } else {
        alerte(
            DURCI,
            Niveau::Info,
            tr!(
                "Protection de l'autorité de sécurité locale (LSA) inactive : un programme avec les droits administrateur peut lire les secrets de connexion.",
                "Local Security Authority (LSA) protection off: a program with administrator rights can read sign-in secrets."
            ),
        )
        .manuel(
            tr!(
                "Sécurité Windows › Sécurité de l'appareil › Isolation du noyau › Protection de l'autorité de sécurité locale, puis redémarrer",
                "Windows Security › Device security › Core isolation › Local Security Authority protection, then restart"
            ),
            &["Start-Process windowsdefender://coreisolation"],
        )
    }
}

/// PowerShell 2.0 : `InstallState` du composant (1 : installé). Il ne passe ni par AMSI (l'antivirus) ni par les
/// journaux de scripts : les attaques le rappellent exprès.
pub(super) fn juger_powershell2(installe: Option<bool>) -> Option<Constat> {
    Some(if installe? {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "PowerShell 2.0 est encore installé : cette vieille version échappe à l'antivirus et aux journaux, les attaques s'en servent exprès.",
                "PowerShell 2.0 is still installed: this old version escapes the antivirus and the logs, attacks use it on purpose."
            ),
        )
        .corriger(
            tr!(
                "Retirer PowerShell 2.0 (les versions actuelles restent ; remis par « Activer ou désactiver des fonctionnalités Windows »)",
                "Remove PowerShell 2.0 (the current versions stay; put back through “Turn Windows features on or off”)"
            ),
            &["Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null"],
        )
    } else {
        ok(
            DURCI,
            tr!("PowerShell 2.0 n'est pas installé.", "PowerShell 2.0 is not installed."),
        )
    })
}

/// Assistance à distance (`fAllowToGetHelp`) : une information, à couper soi-même (couper ici pourrait interrompre
/// une assistance en cours, et Vanguard ne coupe jamais une connexion à distance).
pub(super) fn juger_assistance(valeur: Option<u32>) -> Option<Constat> {
    (valeur == Some(1)).then(|| {
        alerte(
            "Accès à distance",
            Niveau::Info,
            tr!(
                "L'Assistance à distance de Windows accepte les invitations : c'est l'outil que les faux techniciens demandent d'ouvrir.",
                "Windows Remote Assistance accepts invitations: it is the tool fake technicians ask you to open."
            ),
        )
        .manuel(
            tr!(
                "Si personne ne vous aide ainsi : Panneau de configuration › Système › Paramètres d'utilisation à distance, décocher « Autoriser les connexions d'assistance à distance »",
                "If nobody helps you this way: Control Panel › System › Remote settings, uncheck “Allow Remote Assistance connections”"
            ),
            &["Start-Process SystemPropertiesRemote.exe"],
        )
    })
}

fn lire_texte(cle: &str, valeur: &str) -> Option<String> {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(cle)
        .ok()?
        .get_value(valeur)
        .ok()
}

const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// Ouverture de session automatique : avec `DefaultPassword`, le mot de passe est écrit en clair dans le registre,
/// lisible par tout programme qui tourne sur l'ordinateur. Sans lui (réglage par netplwiz, gardé chiffré), une
/// information : quiconque allume l'ordinateur entre dans la session.
pub(super) fn juger_ouverture_auto(auto: Option<&str>, mot_de_passe: bool) -> Option<Constat> {
    if auto.map(str::trim) != Some("1") {
        return None;
    }
    Some(if mot_de_passe {
        alerte(
            "Comptes",
            Niveau::Eleve,
            tr!(
                "Ouverture de session automatique avec le mot de passe écrit en clair dans le registre : tout programme qui tourne ici peut le lire.",
                "Automatic sign-in with the password written in clear text in the registry: any program running here can read it."
            ),
        )
        .manuel(
            tr!(
                "Touche Windows + R, « netplwiz », cocher « Les utilisateurs doivent entrer un nom et un mot de passe » ; puis retirer DefaultPassword (commande ci-dessous, en administrateur)",
                "Windows key + R, “netplwiz”, check “Users must enter a user name and password”; then remove DefaultPassword (command below, as administrator)"
            ),
            &[r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword"],
        )
    } else {
        alerte(
            "Comptes",
            Niveau::Info,
            tr!(
                "Ouverture de session automatique : quiconque allume l'ordinateur entre dans la session, sans mot de passe.",
                "Automatic sign-in: anyone who turns the computer on gets into the session, without a password."
            ),
        )
        .manuel(
            tr!(
                "Si l'ordinateur sort de votre domicile : touche Windows + R, « netplwiz », cocher « Les utilisateurs doivent entrer un nom et un mot de passe »",
                "If the computer leaves the house: Windows key + R, “netplwiz”, check “Users must enter a user name and password”"
            ),
            &[],
        )
    })
}

/// SmartScreen coupé (réglage de l'Explorateur à « Off », ou stratégie EnableSmartScreen à 0) : un programme téléchargé
/// inconnu se lance sans avertissement.
pub(super) fn juger_smartscreen(explorateur: Option<&str>, strategie: Option<u32>) -> Option<Constat> {
    let coupe = explorateur.is_some_and(|v| v.eq_ignore_ascii_case("off")) || strategie == Some(0);
    coupe.then(|| {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "SmartScreen est coupé : un programme téléchargé inconnu se lance sans le moindre avertissement.",
                "SmartScreen is off: an unknown downloaded program starts without any warning."
            ),
        )
        .manuel(
            tr!(
                "Sécurité Windows › Contrôle des applications et du navigateur › Protection fondée sur la réputation : tout activer",
                "Windows Security › App & browser control › Reputation-based protection: turn everything on"
            ),
            &["Start-Process windowsdefender://appbrowser"],
        )
    })
}

/// `LocalAccountTokenFilterPolicy` à 1 : un compte local administrateur garde tous ses droits quand il se connecte à
/// distance, ce que les attaques par « pass-the-hash » utilisent pour passer d'un ordinateur à l'autre.
pub(super) fn juger_jeton_distant(valeur: Option<u32>) -> Option<Constat> {
    (valeur == Some(1)).then(|| {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "Le contrôle de compte est désactivé pour les connexions à distance des comptes locaux : un mot de passe d'administrateur volé ouvre cet ordinateur depuis le réseau.",
                "Account control is off for remote connections of local accounts: a stolen administrator password opens this computer from the network."
            ),
        )
        .corriger(
            tr!(
                "Remettre le contrôle de compte pour les connexions à distance (un outil d'administration à distance peut en avoir besoin : il le dira)",
                "Put account control back for remote connections (a remote administration tool may need it off: it will say so)"
            ),
            &[r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy"],
        )
    })
}

/// Intégrité de la mémoire (HVCI) : bloque les pilotes modifiés ou vulnérables. Une information : quelques vieux
/// pilotes (et anti-triches) la refusent, Windows le dit alors.
pub(super) fn juger_integrite_memoire(active: Option<u32>) -> Constat {
    if active == Some(1) {
        ok(
            DURCI,
            tr!(
                "Intégrité de la mémoire active : les pilotes modifiés ou vulnérables sont bloqués.",
                "Memory integrity on: modified or vulnerable drivers are blocked."
            ),
        )
    } else {
        alerte(
            DURCI,
            Niveau::Info,
            tr!(
                "Intégrité de la mémoire inactive : un pilote vulnérable peut servir à désarmer l'antivirus.",
                "Memory integrity off: a vulnerable driver can be used to disarm the antivirus."
            ),
        )
        .manuel(
            tr!(
                "Sécurité Windows › Sécurité de l'appareil › Isolation du noyau › Intégrité de la mémoire, puis redémarrer",
                "Windows Security › Device security › Core isolation › Memory integrity, then restart"
            ),
            &["Start-Process windowsdefender://coreisolation"],
        )
    }
}

/// Mises à jour en pause : la date de fin (« 2026-11-02T… ») dans le futur.
pub(super) fn juger_pause(fin: Option<&str>, aujourd_hui: &str) -> Option<Constat> {
    let date = fin?.get(..10)?;
    (date > aujourd_hui).then(|| {
        alerte(
            "Mises à jour",
            Niveau::Info,
            trf!(
                "Les mises à jour de Windows sont en pause jusqu'au {date} : les corrections de sécurité attendent aussi.",
                "Windows updates are paused until {date}: security fixes wait too."
            ),
        )
        .manuel(
            tr!(
                "Paramètres › Windows Update › Reprendre les mises à jour",
                "Settings › Windows Update › Resume updates"
            ),
            &["Start-Process ms-settings:windowsupdate"],
        )
    })
}

/// Authentification réseau : `LmCompatibilityLevel` sous 3 laisse partir des réponses LM ou NTLMv1, qu'un mot de
/// passe intercepté sur le réseau (faux partage, relais) fait casser en quelques minutes. Absente : 3 par défaut
/// depuis Vista, rien à dire.
pub(super) fn juger_ntlm(niveau: Option<u32>) -> Option<Constat> {
    let n = niveau.filter(|&n| n < 3)?;
    Some(
        alerte(
            DURCI,
            Niveau::Eleve,
            trf!(
                "L'authentification réseau accepte encore LM ou NTLMv1 (niveau {n}) : un mot de passe intercepté sur le réseau se casse en quelques minutes.",
                "Network authentication still allows LM or NTLMv1 (level {n}): a password intercepted on the network is cracked in minutes."
            ),
        )
        .corriger(
            tr!(
                "Revenir au réglage par défaut de Windows : NTLMv2 seulement (un très vieux NAS peut ne plus répondre : il faudra le mettre à jour)",
                "Go back to Windows' default: NTLMv2 only (a very old NAS may stop answering: it will need an update)"
            ),
            &[&super::corrections::id("ntlmv2-seul")],
        ),
    )
}

/// Versions d'Office qui gardent leurs réglages dans le registre (2010, 2013, 2016 à 365) et programmes à macros.
const OFFICE_VERSIONS: [&str; 3] = ["16.0", "15.0", "14.0"];
const OFFICE_PROGRAMMES: [(&str, &str); 6] = [
    ("word", "Word"),
    ("excel", "Excel"),
    ("powerpoint", "PowerPoint"),
    ("access", "Access"),
    ("publisher", "Publisher"),
    ("visio", "Visio"),
];

/// Les programmes d'Office qui lancent toutes les macros sans demander (VBAWarnings à 1 ; la stratégie de groupe
/// passe avant le réglage) : (clé du programme, nom, version, imposé par une stratégie). `lire` donne VBAWarnings
/// d'une clé du compte.
pub(super) fn macros_ouvertes(
    lire: impl Fn(&str) -> Option<u32>,
) -> Vec<(&'static str, &'static str, &'static str, bool)> {
    let mut ouvertes = Vec::new();
    for version in OFFICE_VERSIONS {
        for (cle, nom) in OFFICE_PROGRAMMES {
            let strategie = lire(&format!(r"Software\Policies\Microsoft\Office\{version}\{cle}\Security"));
            let reglage = lire(&format!(r"Software\Microsoft\Office\{version}\{cle}\Security"));
            if strategie.or(reglage) == Some(1) {
                ouvertes.push((cle, nom, version, strategie.is_some()));
            }
        }
    }
    ouvertes
}

/// Macros toutes permises : un document reçu par courriel installe un programme malveillant dès son ouverture.
/// Remises à « désactivées avec notification » (2, le réglage d'Office) pour ce compte ; imposées par une stratégie
/// de groupe, c'est à l'organisation de les changer.
pub(super) fn juger_macros(ouvertes: &[(&str, &str, &str, bool)], sid: Option<&str>) -> Option<Constat> {
    if ouvertes.is_empty() {
        return None;
    }
    let mut noms: Vec<&str> = ouvertes.iter().map(|o| o.1).collect();
    noms.dedup();
    let constat = alerte(
        DURCI,
        Niveau::Eleve,
        trf!(
            "Office lance toutes les macros sans demander ({}) : un document reçu par courriel peut installer un programme malveillant dès son ouverture.",
            "Office runs every macro without asking ({}): a document received by email can install malware as soon as it is opened.",
            noms.join(", ")
        ),
    );
    if ouvertes.iter().any(|o| o.3) {
        return Some(constat.manuel(
            tr!(
                "Réglé par une stratégie de groupe : à changer par qui gère l'ordinateur (entreprise, école)",
                "Set by a group policy: to be changed by whoever manages the computer (company, school)"
            ),
            &[],
        ));
    }
    let commandes: Vec<String> = ouvertes
        .iter()
        .map(|(cle, _, version, _)| {
            let chemin = crate::reparer::hkcu_de_la_personne(
                sid,
                &format!(r"Software\Microsoft\Office\{version}\{cle}\Security"),
            );
            format!("Set-ItemProperty -LiteralPath '{chemin}' -Name VBAWarnings -Value 2 -Type DWord")
        })
        .collect();
    Some(constat.corriger(
        tr!(
            "Revenir au réglage d'Office : macros désactivées, avec une barre pour les activer dans un document de confiance",
            "Go back to Office's setting: macros off, with a bar to turn them on in a trusted document"
        ),
        &commandes,
    ))
}

/// Démarrage sécurisé, lu dans le registre (Confirm-SecureBootUEFI demande les droits admin). Clé absente : un
/// ancien BIOS sans UEFI, rien à conclure.
pub(super) fn demarrage_securise() -> Option<Constat> {
    juger_demarrage_securise(lire_dword(
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        "UEFISecureBootEnabled",
    ))
}

pub(super) fn juger_demarrage_securise(actif: Option<u32>) -> Option<Constat> {
    match actif? {
        0 => Some(
            alerte(
                "Secure Boot",
                Niveau::Info,
                tr!(
                    "Secure Boot désactivé : un programme malveillant peut se loger avant Windows, hors de portée de l'antivirus.",
                    "Secure Boot off: malware can hide before Windows starts, out of the antivirus's reach."
                ),
            )
            .manuel(
                tr!(
                    "À activer dans les réglages UEFI de l'ordinateur (Paramètres > Système > Récupération > Démarrage avancé > Paramètres du microprogramme UEFI). Un Linux installé à côté doit avoir un chargeur signé",
                    "Turn it on in the computer's UEFI settings (Settings > System > Recovery > Advanced startup > UEFI Firmware Settings). A Linux installed alongside needs a signed boot loader"
                ),
                &[],
            ),
        ),
        _ => Some(ok("Secure Boot", tr!("Démarrage sécurisé actif.", "Secure Boot on."))),
    }
}

/// Accès anonyme : RestrictAnonymousSAM à 0 laisse n'importe qui sur le réseau lister les comptes de l'ordinateur
/// sans mot de passe ; EveryoneIncludesAnonymous à 1 donne aux connexions anonymes les droits de « Tout le monde ».
/// Les deux valeurs de Windows sont remises (1 et 0) : aucun usage courant n'en dépend.
pub(super) fn juger_anonyme(restreint_sam: Option<u32>, tous_inclut_anonyme: Option<u32>) -> Option<Constat> {
    let sam_ouvert = restreint_sam == Some(0);
    let anonyme_dans_tous = tous_inclut_anonyme == Some(1);
    if !sam_ouvert && !anonyme_dans_tous {
        return None;
    }
    let mut commandes = Vec::new();
    if sam_ouvert {
        commandes.push(super::corrections::id("sam-anonyme-ferme"));
    }
    if anonyme_dans_tous {
        commandes.push(super::corrections::id("anonyme-hors-tous"));
    }
    let message = if sam_ouvert {
        tr!(
            "N'importe qui sur le réseau peut lister les comptes de l'ordinateur sans mot de passe : il ne reste plus qu'à deviner les mots de passe.",
            "Anyone on the network can list the computer's accounts without a password: only the passwords are left to guess."
        )
    } else {
        tr!(
            "Une connexion anonyme du réseau a les droits de « Tout le monde » sur l'ordinateur.",
            "An anonymous network connection gets “Everyone” rights on the computer."
        )
    };
    Some(alerte(DURCI, Niveau::Moyen, message).corriger(
        tr!(
            "Remettre les réglages de Windows pour les connexions anonymes",
            "Restore Windows' settings for anonymous connections"
        ),
        &commandes,
    ))
}

/// Empreintes LM : NoLMHash à 0 garde, au prochain changement de mot de passe, une empreinte LM (mot de passe en
/// majuscules, coupé en deux moitiés de 7 caractères) qui se casse en secondes. Windows met 1 depuis Vista.
pub(super) fn juger_empreinte_lm(sans_lm: Option<u32>) -> Option<Constat> {
    (sans_lm == Some(0)).then(|| {
        alerte(
            DURCI,
            Niveau::Eleve,
            tr!(
                "Windows garde les mots de passe sous une vieille forme (LM) qui se casse en quelques secondes si quelqu'un copie la base des comptes.",
                "Windows keeps passwords in an old form (LM) that is cracked in seconds if someone copies the account database."
            ),
        )
        .corriger(
            tr!(
                "Ne plus garder cette forme (réglage de Windows) ; changer ensuite son mot de passe efface l'ancienne",
                "Stop keeping this form (Windows' setting); changing your password afterwards erases the old one"
            ),
            &[&super::corrections::id("lmhash-coupe")],
        )
    })
}

/// Registre à distance : démarré avec Windows (Start à 2), il laisse un compte du réseau lire et changer le registre
/// de cet ordinateur. Coupé d'office sur un Windows de bureau (Start à 4) ; seul un ordinateur géré en a besoin.
pub(super) fn juger_registre_distant(demarrage: Option<u32>) -> Option<Constat> {
    (demarrage == Some(2)).then(|| {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "Le Registre à distance démarre avec Windows : un compte du réseau peut lire et changer les réglages de cet ordinateur.",
                "Remote Registry starts with Windows: an account on the network can read and change this computer's settings."
            ),
        )
        .corriger(
            tr!(
                "Arrêter le Registre à distance et le désactiver, comme Windows le livre",
                "Stop Remote Registry and turn it off, as Windows ships it"
            ),
            &[
                "Stop-Service RemoteRegistry -Force",
                "Set-Service RemoteRegistry -StartupType Disabled",
            ],
        )
    })
}

const WINHTTP: &str = r"SYSTEM\CurrentControlSet\Services\WinHttp\Parameters";

/// WPAD : Windows cherche tout seul sur le réseau un fichier qui dit par où passer pour aller sur Internet. Dans un café
/// ou un hôtel, n'importe quel appareil du Wi-Fi peut répondre et faire passer la navigation par lui (même famille
/// d'attaques que LLMNR et NetBIOS). `DisableWpad` à 1 coupe la recherche pour WinHTTP, celle des services de Windows
/// et de beaucoup de programmes ; un navigateur peut garder la sienne, selon le réglage « Détecter automatiquement les
/// paramètres » du compte, dans un format que Vanguard ne réécrit pas : la correction le dit. Un proxy réglé à la
/// main ou par une adresse PAC marche toujours. Sur un ordinateur d'entreprise
/// (compte de domaine), le proxy vient souvent de WPAD : rien à dire.
pub(super) fn juger_wpad(desactive: Option<u32>, domaine: bool) -> Option<Constat> {
    (desactive != Some(1) && !domaine).then(|| {
        alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "Windows cherche son proxy tout seul sur le réseau (WPAD) : sur un Wi-Fi public, un autre appareil peut répondre et faire passer votre navigation par lui.",
                "Windows looks for its proxy by itself on the network (WPAD): on public Wi-Fi, another device can answer and route your browsing through itself."
            ),
        )
        .corriger(
            tr!(
                "Couper la recherche automatique du proxy de Windows (effective au prochain redémarrage) ; pour le navigateur, décochez aussi « Détecter automatiquement les paramètres » (Paramètres > Réseau > Proxy)",
                "Turn off Windows' automatic proxy discovery (takes effect at the next restart); for the browser, also untick “Automatically detect settings” (Settings > Network > Proxy)"
            ),
            // Clé créée seulement si elle manque, comme pour LLMNR : « New-Item -Force » écraserait ses autres valeurs.
            &[&super::corrections::id("wpad-coupe")],
        )
    })
}

/// Un compte de domaine (entreprise, école) : son domaine n'est pas le nom de l'ordinateur.
fn compte_de_domaine() -> bool {
    match (std::env::var("USERDOMAIN"), std::env::var("COMPUTERNAME")) {
        (Ok(domaine), Ok(ordinateur)) => !domaine.eq_ignore_ascii_case(&ordinateur),
        _ => false,
    }
}

/// Client SMBv1 (pilote mrxsmb10) : installé et pas désactivé, Windows peut encore parler SMBv1 à un partage du
/// réseau, un protocole sans protection contre l'interception. Absent sur Windows 11 ; le serveur SMBv1 est jugé à
/// part (`smb1`).
pub(super) fn juger_client_smb1(demarrage: Option<u32>) -> Option<Constat> {
    demarrage.filter(|&d| d != 4).map(|_| {
        alerte(
            "SMBv1",
            Niveau::Moyen,
            tr!(
                "Le client SMBv1 est encore installé : Windows peut ouvrir un partage avec ce vieux protocole, que n'importe quel appareil du réseau peut intercepter.",
                "The SMBv1 client is still installed: Windows can open a share with this old protocol, which any device on the network can intercept."
            ),
        )
        .corriger(
            tr!(
                "Retirer le client SMBv1 (effectif après redémarrage ; un très vieux NAS peut ne plus s'ouvrir)",
                "Remove the SMBv1 client (effective after a restart; a very old NAS may no longer open)"
            ),
            &["Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart"],
        )
    })
}

/// AlwaysInstallElevated à 1 pour l'ordinateur ET pour le compte : n'importe quel compte installe un paquet MSI avec
/// les droits du système, un moyen connu de devenir administrateur. Un seul des deux ne suffit pas à Windows.
pub(super) fn juger_installation_elevee(
    machine: Option<u32>,
    compte: Option<u32>,
    cle_du_compte: &str,
) -> Option<Constat> {
    (machine == Some(1) && compte == Some(1)).then(|| {
        alerte(
            DURCI,
            Niveau::Eleve,
            tr!(
                "Windows installe n'importe quel paquet MSI avec les droits du système (AlwaysInstallElevated) : un programme lancé sans droits peut devenir administrateur.",
                "Windows installs any MSI package with system rights (AlwaysInstallElevated): a program run without rights can become administrator."
            ),
        )
        .corriger(
            tr!(
                "Couper l'installation avec les droits du système (le réglage de Windows)",
                "Turn off installing with system rights (Windows' setting)"
            ),
            &[
                r"Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -Value 0 -Type DWord".to_string(),
                format!("Set-ItemProperty -LiteralPath '{cle_du_compte}' -Name AlwaysInstallElevated -Value 0 -Type DWord"),
            ],
        )
    })
}

/// Protection contre les exploits pour tout le système (Get-ProcessMitigation -System) : « DEP|BottomUp|CFG|SEHOP »,
/// chacune ON, OFF ou NOTSET (le réglage de Windows, actif). Seul OFF compte : un « optimiseur » pour le jeu les
/// coupe parfois, et une faille de n'importe quel programme devient bien plus facile à exploiter.
pub(super) fn juger_protection_exploits(valeurs: Option<&str>) -> Option<Constat> {
    let noms = ["DEP", "BottomUp", "CFG", "SEHOP"];
    let coupees: Vec<&str> = valeurs?
        .split('|')
        .zip(noms)
        .filter(|(v, _)| v.trim().eq_ignore_ascii_case("OFF"))
        .map(|(_, n)| n)
        .collect();
    if coupees.is_empty() {
        return None;
    }
    let liste = coupees.join(", ");
    Some(
        alerte(
            DURCI,
            Niveau::Eleve,
            trf!(
                "Protection contre les exploits coupée pour tout le système ({liste}) : une faille de n'importe quel programme devient bien plus facile à exploiter.",
                "Exploit protection turned off system-wide ({liste}): a flaw in any program becomes much easier to exploit."
            ),
        )
        .corriger(
            tr!(
                "Rallumer ces protections (le réglage de Windows ; effectif après redémarrage)",
                "Turn these protections back on (Windows' setting; effective after a restart)"
            ),
            &[&format!("Set-ProcessMitigation -System -Enable {}", coupees.join(","))],
        ),
    )
}

/// Windows Update coupé, souvent par un outil « d'allègement » : service wuauserv ou orchestrateur UsoSvc désactivés
/// (Start à 4), ou stratégie NoAutoUpdate à 1. Plus aucune faille ne se corrige toute seule. Les services sont remis
/// comme Windows les livre (wuauserv manuel, UsoSvc automatique) ; la stratégie peut venir de qui gère l'ordinateur :
/// à retirer soi-même.
pub(super) fn juger_windows_update(
    service: Option<u32>,
    orchestrateur: Option<u32>,
    sans_maj_auto: Option<u32>,
) -> Option<Constat> {
    let mut commandes = Vec::new();
    if service == Some(4) {
        commandes.push("Set-Service wuauserv -StartupType Manual");
    }
    if orchestrateur == Some(4) {
        commandes.push("Set-Service UsoSvc -StartupType Automatic");
    }
    if !commandes.is_empty() {
        return Some(
            alerte(
                "Mises à jour",
                Niveau::Eleve,
                tr!(
                    "Le service Windows Update est désactivé : plus aucune mise à jour de sécurité ne s'installe, ni toute seule ni à la main.",
                    "The Windows Update service is disabled: no security update installs anymore, neither by itself nor by hand."
                ),
            )
            .corriger(
                tr!(
                    "Remettre les services de Windows Update comme Windows les livre",
                    "Put the Windows Update services back as Windows ships them"
                ),
                &commandes,
            ),
        );
    }
    (sans_maj_auto == Some(1)).then(|| {
        alerte(
            "Mises à jour",
            Niveau::Moyen,
            tr!(
                "Une stratégie empêche Windows Update de s'installer tout seul : les failles corrigées restent ouvertes tant que personne ne lance les mises à jour.",
                "A policy stops Windows Update from installing by itself: fixed flaws stay open until someone runs the updates."
            ),
        )
        .manuel(
            tr!(
                "Si personne ne gère cet ordinateur (entreprise, école) : retirer la stratégie (commande ci-dessous, en administrateur)",
                "If nobody manages this computer (company, school): remove the policy (command below, as administrator)"
            ),
            &[r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate"],
        )
    })
}

/// Signature SMB : le client qui ne l'exige pas peut se faire relayer vers un faux partage. Une information, à
/// activer soi-même (un vieux NAS sans signature ne répondrait plus) ; Windows 11 24H2 l'exige déjà.
pub(super) fn juger_signature_smb(client_exige: Option<u32>) -> Option<Constat> {
    (client_exige == Some(0)).then(|| {
        alerte(
            DURCI,
            Niveau::Info,
            tr!(
                "Les partages de fichiers n'exigent pas de signature : un appareil du réseau peut se placer au milieu et relayer la connexion.",
                "File shares do not require signing: a device on the network can get in the middle and relay the connection."
            ),
        )
        .manuel(
            tr!(
                "Si aucun vieux NAS n'est utilisé : exiger la signature (commande ci-dessous, en administrateur), puis redémarrer",
                "If no old NAS is in use: require signing (command below, as administrator), then restart"
            ),
            &["Set-SmbClientConfiguration -RequireSecuritySignature $true -Force"],
        )
    })
}

/// Connexion « invité » aux partages sans mot de passe (AllowInsecureGuestAuth à 1, la stratégie de groupe passant
/// avant le réglage) : un faux partage du réseau peut se faire passer pour le NAS et servir des fichiers piégés, sans
/// signature possible. Laissée à la main : un vieux NAS ou une box peut en dépendre.
pub(super) fn juger_invite_smb(strategie: Option<u32>, reglage: Option<u32>) -> Option<Constat> {
    let impose = strategie.is_some();
    (strategie.or(reglage) == Some(1)).then(|| {
        let constat = alerte(
            DURCI,
            Niveau::Moyen,
            tr!(
                "Les partages réseau acceptent une connexion « invité » sans mot de passe : un faux partage peut se faire passer pour votre NAS et vous donner des fichiers piégés.",
                "Network shares accept a password-less “guest” connection: a fake share can pose as your NAS and hand you booby-trapped files."
            ),
        );
        if impose {
            constat.manuel(
                tr!(
                    "Réglé par une stratégie de groupe : à changer par qui gère l'ordinateur (Station de travail Lanman, « Activer les ouvertures de session invité non sécurisées »)",
                    "Set by a group policy: to be changed by whoever manages the computer (Lanman Workstation, “Enable insecure guest logons”)"
                ),
                &[],
            )
        } else {
            constat.manuel(
                tr!(
                    "Si aucun vieux NAS ne s'ouvre sans mot de passe : couper la connexion invité (commande ci-dessous, en administrateur)",
                    "If no old NAS opens without a password: turn guest connections off (command below, as administrator)"
                ),
                &[r"Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -Value 0 -Type DWord"],
            )
        }
    })
}

/// La stratégie d'exécution de PowerShell qui s'applique : celle des stratégies de groupe (machine puis compte),
/// sinon celle du compte, sinon celle de l'ordinateur. `(valeur, imposée par une stratégie)`.
pub(super) fn strategie_effective(
    strategie_machine: Option<&str>,
    strategie_compte: Option<&str>,
    compte: Option<&str>,
    machine: Option<&str>,
) -> Option<(String, bool)> {
    fn defini(v: Option<&str>) -> Option<&str> {
        v.map(str::trim)
            .filter(|v| !v.is_empty() && !v.eq_ignore_ascii_case("Undefined"))
    }
    if let Some(v) = defini(strategie_machine).or(defini(strategie_compte)) {
        return Some((v.to_string(), true));
    }
    defini(compte).or(defini(machine)).map(|v| (v.to_string(), false))
}

/// PowerShell en « Unrestricted » ou « Bypass » : un script téléchargé se lance sans avertissement. Remis à
/// « RemoteSigned » pour ce compte (un script écrit ici se lance toujours, un script téléchargé doit être signé) ;
/// imposé par une stratégie de groupe, c'est à l'organisation de le changer.
pub(super) fn juger_strategie_ps(effective: Option<(String, bool)>, cle_du_compte: &str) -> Option<Constat> {
    let (valeur, imposee) = effective?;
    if !(valeur.eq_ignore_ascii_case("Unrestricted") || valeur.eq_ignore_ascii_case("Bypass")) {
        return None;
    }
    let constat = alerte(
        DURCI,
        Niveau::Moyen,
        trf!(
            "PowerShell lance n'importe quel script sans avertissement (stratégie « {valeur} ») : un script téléchargé ou reçu par courriel s'exécute d'un double-clic.",
            "PowerShell runs any script without warning (“{valeur}” policy): a script downloaded or received by email runs with a double-click."
        ),
    );
    Some(if imposee {
        constat.manuel(
            tr!(
                "Réglé par une stratégie de groupe : à changer par qui gère l'ordinateur (entreprise, école)",
                "Set by a group policy: to be changed by whoever manages the computer (company, school)"
            ),
            &[],
        )
    } else {
        constat.corriger(
            tr!(
                "Revenir à « RemoteSigned » pour ce compte : un script écrit ici se lance toujours, un script téléchargé doit être signé",
                "Go back to “RemoteSigned” for this account: a script written here still runs, a downloaded script must be signed"
            ),
            &[&format!(
                "Set-ItemProperty -LiteralPath '{cle_du_compte}' -Name ExecutionPolicy -Value RemoteSigned"
            )],
        )
    })
}

/// Journalisation des scripts PowerShell (événement 4104) : ce que lance une attaque par PowerShell reste lisible
/// après coup. La clé de stratégie n'est créée que si elle manque (New-Item -Force écraserait ses autres valeurs).
const JOURNAL_PS: &str = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";

inventory::submit! {
    crate::machine::regles::Regle {
        id: "WIN-JRN-001",
        systeme: crate::machine::regles::Os::Windows,
        rang: 251,
        sujet: ("journalisation des scripts PowerShell", "PowerShell script logging"),
        references: &["Microsoft : about_Logging_Windows", "MITRE ATT&CK M1047"],
        verifier: || vec![juger_journal_powershell(lire_dword(JOURNAL_PS, "EnableScriptBlockLogging"))],
    }
}

inventory::submit! {
    crate::machine::regles::Regle {
        id: "WIN-JRN-002",
        systeme: crate::machine::regles::Os::Windows,
        rang: 252,
        sujet: ("Sysmon, quand il est installé", "Sysmon, when installed"),
        references: &["Microsoft Sysinternals : Sysmon", "MITRE ATT&CK M1047"],
        verifier: || {
            juger_sysmon(["Sysmon64", "Sysmon"].iter().any(|s| {
                winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
                    .open_subkey(format!(r"SYSTEM\CurrentControlSet\Services\{s}"))
                    .is_ok()
            }))
            .into_iter()
            .collect()
        },
    }
}

pub(super) fn juger_journal_powershell(valeur: Option<u32>) -> Constat {
    if valeur == Some(1) {
        return ok(
            DURCI,
            tr!(
                "Les scripts PowerShell sont journalisés : une attaque par PowerShell laisse une trace lisible.",
                "PowerShell scripts are logged: an attack through PowerShell leaves a readable trace."
            ),
        );
    }
    alerte(
        DURCI,
        Niveau::Info,
        tr!(
            "Les scripts PowerShell ne sont pas journalisés : après une attaque, rien ne dit ce qu'elle a lancé.",
            "PowerShell scripts are not logged: after an attack, nothing tells what it ran."
        ),
    )
    .corriger(
        tr!(
            "Journaliser les scripts PowerShell (journal Microsoft-Windows-PowerShell/Operational)",
            "Log PowerShell scripts (Microsoft-Windows-PowerShell/Operational log)"
        ),
        &[&super::corrections::id("journal-powershell")],
    )
}

/// Credential Guard (`SecurityServicesRunning` de Win32_DeviceGuard contient 1) : seulement sur les éditions
/// Entreprise et Éducation, les seules qui l'ont ; ailleurs, rien à dire.
pub(super) fn juger_credential_guard(edition: Option<&str>, services: Option<&str>) -> Option<Constat> {
    if !edition.is_some_and(credential_guard_possible) {
        return None;
    }
    let actif = services?.split([',', ' ']).any(|s| s.trim() == "1");
    Some(if actif {
        ok(
            DURCI,
            tr!(
                "Credential Guard isole les secrets de connexion du reste du système.",
                "Credential Guard isolates sign-in secrets from the rest of the system."
            ),
        )
    } else {
        alerte(
            DURCI,
            Niveau::Info,
            tr!(
                "Credential Guard est coupé : les secrets de connexion restent dans la mémoire de LSASS, où un voleur de mots de passe les cherche.",
                "Credential Guard is off: sign-in secrets stay in LSASS memory, where a password stealer looks for them."
            ),
        )
        .manuel(
            tr!(
                "Stratégie de groupe : Configuration ordinateur › Modèles d'administration › Système › Device Guard › Activer la sécurité basée sur la virtualisation, puis redémarrer",
                "Group Policy: Computer Configuration › Administrative Templates › System › Device Guard › Turn On Virtualization Based Security, then restart"
            ),
            &[],
        )
    })
}

fn credential_guard_possible(edition: &str) -> bool {
    edition.starts_with("Enterprise") || edition.starts_with("Education")
}

/// La protection contre les exploits de tout le système, telle que Set-ProcessMitigation -System l'écrit
/// (`MitigationOptions`, un champ par demi-octet : 0 réglage de Windows, 1 forcée, 2 coupée). Sans la valeur, ou
/// sans aucun champ autre que 0 ou 1, rien n'est coupé : Get-ProcessMitigation n'a pas à être lancé. Sinon, lui
/// seul nomme sans erreur les protections coupées (la place de chacune dans la valeur n'est pas documentée).
pub(super) fn exploits_a_demander(options: Option<&[u8]>) -> bool {
    options.is_some_and(|o| o.iter().any(|octet| octet & 0x0F > 1 || octet >> 4 > 1))
}

/// Les sections PS2, MIT et CG de l'ancien script, chacune seulement quand WMI ou le registre n'y ont pas répondu.
fn script_de_secours(ps2: bool, exploits: bool, credential_guard: bool) -> Option<String> {
    let parties: Vec<&str> = [
        (ps2, "try { 'PS2|' + (Get-CimInstance Win32_OptionalFeature -Filter \"Name='MicrosoftWindowsPowerShellV2Root'\").InstallState; 'PS2_FIN' } catch {}"),
        (exploits, "try { $m = Get-ProcessMitigation -System; 'MIT|' + $m.DEP.Enable + '|' + $m.ASLR.BottomUp + '|' + $m.CFG.Enable + '|' + $m.SEHOP.Enable; 'MIT_FIN' } catch {}"),
        (credential_guard, "try { 'CG|' + ((Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning -join ','); 'CG_FIN' } catch {}"),
    ]
    .into_iter()
    .filter_map(|(utile, partie)| utile.then_some(partie))
    .collect();
    (!parties.is_empty()).then(|| parties.join("; "))
}

/// État de PowerShell 2.0 (`InstallState`) : 1 installé ; 2 retiré, 3 absent ; le reste, inconnu.
fn powershell2_installe(etat: Option<i64>) -> Option<bool> {
    match etat? {
        1 => Some(true),
        2 | 3 => Some(false),
        _ => None,
    }
}

/// Sysmon, quand il est là : il journalise processus et connexions en détail. Son absence n'est pas un défaut sur un
/// ordinateur personnel.
pub(super) fn juger_sysmon(present: bool) -> Option<Constat> {
    present.then(|| {
        ok(
            DURCI,
            tr!(
                "Sysmon journalise l'activité du système (programmes lancés, connexions).",
                "Sysmon logs system activity (programs started, connections)."
            ),
        )
    })
}

/// Ce qu'une règle du durcissement dit quand aucun réglage n'est faible : chaque lecture qui n'a rien rendu est un
/// réglage à sa valeur sûre (celle de Windows, ou absent), comme dans la règle unique d'avant ; une règle ne rend
/// jamais rien (`regles::MUETTES_TOLEREES`).
fn sain_si_vide(mut c: Vec<Constat>, sain: (&'static str, &'static str)) -> Vec<Constat> {
    if c.is_empty() {
        c.push(ok(DURCI, if crate::langue::anglais() { sain.1 } else { sain.0 }));
    }
    c
}

/// WIN-DUR-001 : ce qui protège les secrets de connexion et le noyau. Les autres réglages qu'elle regroupait ont
/// chacun leur règle (WIN-DUR-002 à 005, WIN-MAJ-003, WIN-SES-002) : l'historique et le rapport suivent un réglage
/// précis, et chaque règle cite sa référence.
pub(super) fn durcissement() -> Vec<Constat> {
    let mut c = vec![
        juger_wdigest(lire_dword(WDIGEST, "UseLogonCredential")),
        juger_lsa(lire_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")),
    ];
    // WMI et le registre d'abord : quelques millisecondes, là où chaque PowerShell coûte près d'une demi-seconde.
    // Un seul PowerShell, et seulement pour ce qu'ils n'ont pas pu dire ; chaque lecture garde sa section, et
    // l'échec de l'une laisse les autres.
    let edition = lire_texte(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID");
    let credential_guard = edition.as_deref().is_some_and(credential_guard_possible);
    let ps2_wmi = wmi::requete(
        r"root\cimv2",
        "Win32_OptionalFeature",
        "Name='MicrosoftWindowsPowerShellV2Root'",
        &["InstallState"],
    );
    let exploits = exploits_a_demander(
        winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel")
            .and_then(|k| k.get_raw_value("MitigationOptions"))
            .ok()
            .map(|v| v.bytes)
            .as_deref(),
    );
    let cg_wmi = credential_guard
        .then(|| {
            wmi::requete(
                r"root\Microsoft\Windows\DeviceGuard",
                "Win32_DeviceGuard",
                "",
                &["SecurityServicesRunning"],
            )
        })
        .flatten()
        .map(|lignes| {
            // Comme le `-join ','` du script : aucune instance, une liste vide.
            lignes.first().map_or_else(String::new, |l| {
                l["SecurityServicesRunning"]
                    .liste()
                    .iter()
                    .filter_map(|v| v.entier().map(|n| n.to_string()))
                    .collect::<Vec<_>>()
                    .join(",")
            })
        });
    let secours = script_de_secours(ps2_wmi.is_none(), exploits, credential_guard && cg_wmi.is_none())
        .and_then(|script| ps(&script));
    let installe = match &ps2_wmi {
        Some(lignes) => powershell2_installe(lignes.first().and_then(|l| l["InstallState"].entier())),
        None => powershell2_installe(
            section(secours.as_deref(), "PS2").and_then(|l| l.first().and_then(|v| v.trim().parse().ok())),
        ),
    };
    c.extend(juger_powershell2(installe));
    c.extend(juger_protection_exploits(
        section(secours.as_deref(), "MIT").and_then(|l| l.first().copied()),
    ));
    c.extend(juger_credential_guard(
        edition.as_deref(),
        cg_wmi
            .as_deref()
            .or_else(|| section(secours.as_deref(), "CG").and_then(|l| l.first().copied())),
    ));
    c.push(juger_integrite_memoire(lire_dword(
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    )));
    c
}

/// WIN-DUR-002 : l'authentification par le réseau (NTLM, anciennes empreintes LM, connexions anonymes).
pub(super) fn authentification_reseau() -> Vec<Constat> {
    let mut c = Vec::new();
    c.extend(juger_ntlm(lire_dword(
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "LmCompatibilityLevel",
    )));
    c.extend(juger_anonyme(
        lire_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM"),
        lire_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "EveryoneIncludesAnonymous"),
    ));
    c.extend(juger_empreinte_lm(lire_dword(
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "NoLMHash",
    )));
    sain_si_vide(
        c,
        (
            "Aucun réglage faible parmi : NTLM, empreintes LM, accès anonyme.",
            "No weak setting among: NTLM, LM hashes, anonymous access.",
        ),
    )
}

/// WIN-DUR-003 : le client de partage de fichiers (SMBv1, signature, connexions invité).
pub(super) fn partage_smb() -> Vec<Constat> {
    let mut c = Vec::new();
    c.extend(juger_client_smb1(lire_dword(
        r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
        "Start",
    )));
    c.extend(juger_signature_smb(lire_dword(
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "RequireSecuritySignature",
    )));
    c.extend(juger_invite_smb(
        lire_dword(
            r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
            "AllowInsecureGuestAuth",
        ),
        lire_dword(
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "AllowInsecureGuestAuth",
        ),
    ));
    sain_si_vide(
        c,
        (
            "Aucun réglage faible parmi : client SMBv1, signature SMB, connexions invité.",
            "No weak setting among: SMBv1 client, SMB signing, guest connections.",
        ),
    )
}

/// WIN-DUR-004 : les portes d'accès à distance hors du Bureau à distance (Assistance, Registre à distance, comptes
/// locaux par le réseau, découverte du proxy).
pub(super) fn acces_distant() -> Vec<Constat> {
    let mut c = Vec::new();
    c.extend(juger_assistance(lire_dword(
        r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
        "fAllowToGetHelp",
    )));
    c.extend(juger_registre_distant(lire_dword(
        r"SYSTEM\CurrentControlSet\Services\RemoteRegistry",
        "Start",
    )));
    c.extend(juger_jeton_distant(lire_dword(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "LocalAccountTokenFilterPolicy",
    )));
    c.extend(juger_wpad(lire_dword(WINHTTP, "DisableWpad"), compte_de_domaine()));
    sain_si_vide(
        c,
        (
            "Aucun réglage faible parmi : Assistance à distance, Registre à distance, comptes locaux par le réseau, WPAD.",
            "No weak setting among: Remote Assistance, Remote Registry, local accounts over the network, WPAD.",
        ),
    )
}

/// WIN-DUR-005 : ce qui laisse passer un programme ou un document piégé (SmartScreen, scripts PowerShell, macros
/// Office, installations toujours élevées).
pub(super) fn programmes_et_documents() -> Vec<Constat> {
    let mut c = Vec::new();
    c.extend(juger_smartscreen(
        lire_texte(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "SmartScreenEnabled",
        )
        .as_deref(),
        lire_dword(r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"),
    ));
    let shell_ids = r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell";
    let strategies = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell";
    let du_compte = |cle: &str| {
        winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(cle)
            .ok()?
            .get_value::<String, _>("ExecutionPolicy")
            .ok()
    };
    let effective = strategie_effective(
        lire_texte(strategies, "ExecutionPolicy").as_deref(),
        du_compte(strategies).as_deref(),
        du_compte(shell_ids).as_deref(),
        lire_texte(shell_ids, "ExecutionPolicy").as_deref(),
    );
    let sid = crate::reparer::sid_de_la_personne();
    let installeur = r"SOFTWARE\Policies\Microsoft\Windows\Installer";
    let installeur_du_compte = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(installeur)
        .ok()
        .and_then(|k| k.get_value::<u32, _>("AlwaysInstallElevated").ok());
    c.extend(juger_installation_elevee(
        lire_dword(installeur, "AlwaysInstallElevated"),
        installeur_du_compte,
        &crate::reparer::hkcu_de_la_personne(sid.as_deref(), installeur),
    ));
    c.extend(juger_strategie_ps(
        effective,
        &crate::reparer::hkcu_de_la_personne(sid.as_deref(), shell_ids),
    ));
    let vba = |cle: &str| {
        winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(cle)
            .ok()?
            .get_value::<u32, _>("VBAWarnings")
            .ok()
    };
    c.extend(juger_macros(&macros_ouvertes(vba), sid.as_deref()));
    sain_si_vide(
        c,
        (
            "Aucun réglage faible parmi : SmartScreen, stratégie des scripts PowerShell, macros Office, installations toujours élevées.",
            "No weak setting among: SmartScreen, PowerShell script policy, Office macros, always-elevated installs.",
        ),
    )
}

/// WIN-MAJ-003 : Windows Update coupé (service désactivé, stratégie) ou en pause.
pub(super) fn windows_update_bloque() -> Vec<Constat> {
    let mut c = Vec::new();
    c.extend(juger_windows_update(
        lire_dword(r"SYSTEM\CurrentControlSet\Services\wuauserv", "Start"),
        lire_dword(r"SYSTEM\CurrentControlSet\Services\UsoSvc", "Start"),
        lire_dword(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate"),
    ));
    let aujourd_hui = chrono::Local::now().format("%Y-%m-%d").to_string();
    c.extend(juger_pause(
        lire_texte(
            r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
            "PauseUpdatesExpiryTime",
        )
        .as_deref(),
        &aujourd_hui,
    ));
    sain_si_vide(
        c,
        (
            "Windows Update n'est ni coupé ni en pause.",
            "Windows Update is neither off nor paused.",
        ),
    )
}

/// WIN-SES-002 : la session qui s'ouvre toute seule, mot de passe gardé dans le registre.
pub(super) fn ouverture_automatique() -> Vec<Constat> {
    let mut c = Vec::new();
    c.extend(juger_ouverture_auto(
        lire_texte(WINLOGON, "AutoAdminLogon").as_deref(),
        lire_texte(WINLOGON, "DefaultPassword").is_some_and(|m| !m.is_empty()),
    ));
    sain_si_vide(
        c,
        (
            "La session ne s'ouvre pas toute seule.",
            "The session does not open by itself.",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journalisation_credential_guard_et_sysmon() {
        assert_eq!(juger_journal_powershell(Some(1)).probleme, None);
        let coupe = juger_journal_powershell(None);
        assert_eq!(coupe.probleme, Some(Niveau::Info));
        // La clé n'est créée que si elle manque, puis la valeur est posée.
        let commandes = &coupe.correctif.as_ref().unwrap().commandes;
        assert_eq!(commandes, &["vanguard:journal-powershell"]);
        // Credential Guard : seulement en Entreprise ou Éducation.
        assert!(juger_credential_guard(Some("Core"), Some("")).is_none());
        assert!(juger_credential_guard(Some("Professional"), Some("")).is_none());
        assert_eq!(
            juger_credential_guard(Some("Enterprise"), Some("1,2")).map(|c| c.probleme),
            Some(None)
        );
        assert_eq!(
            juger_credential_guard(Some("Education"), Some("2")).map(|c| c.probleme),
            Some(Some(Niveau::Info))
        );
        assert!(juger_credential_guard(Some("Enterprise"), None).is_none());
        assert!(juger_sysmon(false).is_none() && juger_sysmon(true).is_some_and(|c| c.probleme.is_none()));
    }

    #[test]
    fn exploits_par_le_registre() {
        // Valeur absente, ou rien que des réglages de Windows (0) et des protections forcées (1) : rien de coupé.
        assert!(!exploits_a_demander(None));
        assert!(!exploits_a_demander(Some(&[0; 24])));
        // DEP et BottomUp forcés (01, 00, 01 : l'exemple de Set-ProcessMitigation -System -Enable DEP,BottomUp).
        assert!(!exploits_a_demander(Some(&[0x01, 0x00, 0x01, 0x00])));
        // DEP coupé (02) ; un « optimiseur » qui coupe tout (22…) ; un champ coupé dans le demi-octet haut.
        assert!(exploits_a_demander(Some(&[0x02, 0x00, 0x01, 0x00])));
        assert!(exploits_a_demander(Some(&[0x22; 16])));
        assert!(exploits_a_demander(Some(&[0x00, 0x00, 0x20])));
        // Un champ inconnu (3) n'est pas deviné : Get-ProcessMitigation le nommera.
        assert!(exploits_a_demander(Some(&[0x03])));
    }

    #[test]
    fn secours_par_powershell() {
        assert_eq!(script_de_secours(false, false, false), None);
        let tout = script_de_secours(true, true, true).unwrap();
        for (nom, cmdlet) in [
            ("PS2", "Win32_OptionalFeature"),
            ("MIT", "Get-ProcessMitigation"),
            ("CG", "Win32_DeviceGuard"),
        ] {
            assert!(tout.contains(&format!("'{nom}_FIN'")) && tout.contains(cmdlet), "{nom}");
        }
        let seul = script_de_secours(false, true, false).unwrap();
        assert!(seul.contains("MIT_FIN") && !seul.contains("PS2") && !seul.contains("CG|"));
        assert_eq!(powershell2_installe(Some(1)), Some(true));
        assert_eq!(powershell2_installe(Some(2)), Some(false));
        assert_eq!(powershell2_installe(Some(3)), Some(false));
        assert_eq!(powershell2_installe(Some(0)), None);
        assert_eq!(powershell2_installe(None), None);
    }

    /// Sous Wine, sans PowerShell ni Win32_OptionalFeature : PowerShell 2.0 et Credential Guard restent sans constat
    /// (jamais « sain »), et le reste de l'audit se fait quand même.
    #[test]
    fn durcissement_sans_powershell() {
        let c = durcissement();
        assert!(!c.is_empty());
        assert!(!c.iter().any(|x| x.message.contains("PowerShell 2.0")));
    }

    #[test]
    fn durcissement_juge() {
        let w = juger_wdigest(Some(1));
        assert_eq!(w.probleme, Some(Niveau::Eleve));
        assert_eq!(w.correctif.as_ref().unwrap().commandes[0], "vanguard:wdigest-coupe");
        assert!(juger_wdigest(None).probleme.is_none() && juger_wdigest(Some(0)).probleme.is_none());
        assert!(juger_lsa(Some(2)).probleme.is_none());
        assert_eq!(juger_lsa(None).probleme, Some(Niveau::Info));
        assert_eq!(juger_powershell2(Some(true)).unwrap().probleme, Some(Niveau::Moyen));
        assert!(juger_powershell2(Some(false)).unwrap().probleme.is_none());
        assert!(juger_powershell2(None).is_none());
        let a = juger_assistance(Some(1)).unwrap();
        assert!(!a.correctif.as_ref().unwrap().automatique);
        assert!(juger_assistance(Some(0)).is_none() && juger_assistance(None).is_none());
        assert_eq!(
            juger_ouverture_auto(Some("1"), true).unwrap().probleme,
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger_ouverture_auto(Some("1"), false).unwrap().probleme,
            Some(Niveau::Info)
        );
        assert!(juger_ouverture_auto(Some("0"), true).is_none() && juger_ouverture_auto(None, false).is_none());
        assert!(juger_smartscreen(Some("Off"), None).is_some() && juger_smartscreen(None, Some(0)).is_some());
        assert!(juger_smartscreen(Some("Warn"), None).is_none() && juger_smartscreen(None, Some(1)).is_none());
        assert!(
            juger_jeton_distant(Some(1))
                .unwrap()
                .correctif
                .as_ref()
                .unwrap()
                .automatique
        );
        assert!(juger_jeton_distant(Some(0)).is_none());
        assert!(juger_integrite_memoire(Some(1)).probleme.is_none());
        assert_eq!(juger_integrite_memoire(None).probleme, Some(Niveau::Info));
        let p = juger_pause(Some("2026-11-02T09:00:00Z"), "2026-10-19").unwrap();
        assert!(p.message.contains("2026-11-02"));
        let effective = strategie_effective(None, None, Some("Unrestricted"), Some("RemoteSigned"));
        assert_eq!(effective, Some(("Unrestricted".to_string(), false)));
        assert_eq!(
            strategie_effective(Some("Bypass"), None, Some("Restricted"), None),
            Some(("Bypass".to_string(), true))
        );
        assert_eq!(strategie_effective(None, None, Some("Undefined"), None), None);
        let corrigee = juger_strategie_ps(
            effective,
            r"HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
        )
        .unwrap();
        assert!(corrigee.correctif.as_ref().unwrap().automatique);
        assert!(corrigee.correctif.as_ref().unwrap().commandes[0].contains("RemoteSigned"));
        let imposee = juger_strategie_ps(Some(("Bypass".into(), true)), "x").unwrap();
        assert!(!imposee.correctif.as_ref().unwrap().automatique);
        assert!(juger_strategie_ps(Some(("RemoteSigned".into(), false)), "x").is_none());
        assert_eq!(juger_ntlm(Some(1)).unwrap().probleme, Some(Niveau::Eleve));
        assert_eq!(
            juger_ntlm(Some(1)).unwrap().correctif.unwrap().commandes[0],
            "vanguard:ntlmv2-seul"
        );
        assert!(juger_ntlm(Some(3)).is_none() && juger_ntlm(Some(5)).is_none() && juger_ntlm(None).is_none());
        assert_eq!(juger_signature_smb(Some(0)).unwrap().probleme, Some(Niveau::Info));
        assert!(juger_signature_smb(Some(1)).is_none() && juger_signature_smb(None).is_none());
        // Macros d'Office : la stratégie passe avant le réglage ; une commande par programme ouvert.
        let lu = |cle: &str| match cle {
            r"Software\Microsoft\Office\16.0\word\Security"
            | r"Software\Microsoft\Office\16.0\excel\Security"
            | r"Software\Microsoft\Office\15.0\word\Security" => Some(1),
            r"Software\Policies\Microsoft\Office\16.0\excel\Security" => Some(2),
            r"Software\Microsoft\Office\16.0\powerpoint\Security" => Some(3),
            _ => None,
        };
        let ouvertes = macros_ouvertes(lu);
        assert_eq!(
            ouvertes,
            [("word", "Word", "16.0", false), ("word", "Word", "15.0", false)]
        );
        let macros = juger_macros(&ouvertes, Some("S-1-5-21-1-2-3-1001")).unwrap();
        assert!(macros.probleme == Some(Niveau::Eleve) && macros.message.contains("(Word)"));
        let remise = macros.correctif.unwrap();
        assert!(remise.automatique && remise.commandes.len() == 2);
        assert_eq!(
            remise.commandes[1],
            r"Set-ItemProperty -LiteralPath 'Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Microsoft\Office\15.0\word\Security' -Name VBAWarnings -Value 2 -Type DWord"
        );
        assert!(juger_macros(&[], None).is_none());
        let imposees = juger_macros(&[("excel", "Excel", "16.0", true)], None)
            .unwrap()
            .correctif
            .unwrap();
        assert!(!imposees.automatique && imposees.commandes.is_empty());
        // Empreintes LM : seulement NoLMHash à 0 ; absent ou 1, rien.
        assert!(juger_empreinte_lm(None).is_none() && juger_empreinte_lm(Some(1)).is_none());
        let lm = juger_empreinte_lm(Some(0)).unwrap();
        assert!(lm.probleme == Some(Niveau::Eleve) && lm.correctif.unwrap().commandes[0] == "vanguard:lmhash-coupe");
        // Registre à distance : seulement démarré avec Windows (2) ; manuel (3) ou désactivé (4), rien.
        assert!(
            [None, Some(3), Some(4)]
                .into_iter()
                .all(|d| juger_registre_distant(d).is_none())
        );
        let distant = juger_registre_distant(Some(2)).unwrap();
        assert!(distant.probleme == Some(Niveau::Moyen) && distant.correctif.unwrap().commandes.len() == 2);
        // Client SMBv1 : pilote absent ou désactivé (4), rien ; sinon une correction.
        assert!(juger_client_smb1(None).is_none() && juger_client_smb1(Some(4)).is_none());
        let client = juger_client_smb1(Some(2)).unwrap();
        assert!(client.probleme == Some(Niveau::Moyen) && client.categorie == "SMBv1");
        // Installation avec les droits du système : seulement si l'ordinateur ET le compte le permettent.
        assert!(juger_installation_elevee(Some(1), None, "HKCU:\\x").is_none());
        assert!(
            juger_installation_elevee(Some(1), Some(0), "HKCU:\\x").is_none()
                && juger_installation_elevee(None, Some(1), "HKCU:\\x").is_none()
        );
        let msi = juger_installation_elevee(
            Some(1),
            Some(1),
            r"Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\SOFTWARE\Policies\Microsoft\Windows\Installer",
        )
        .unwrap();
        let remise = msi.correctif.unwrap();
        assert!(msi.probleme == Some(Niveau::Eleve) && remise.commandes.len() == 2);
        assert!(
            remise.commandes[1]
                .starts_with(r"Set-ItemProperty -LiteralPath 'Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\SOFTWARE")
        );
        // Protection contre les exploits : seul OFF compte, NOTSET étant le réglage de Windows.
        assert!(juger_protection_exploits(None).is_none());
        assert!(juger_protection_exploits(Some("NOTSET|NOTSET|ON|NOTSET")).is_none());
        let exploits = juger_protection_exploits(Some("OFF|NOTSET|OFF|ON")).unwrap();
        assert!(exploits.probleme == Some(Niveau::Eleve) && exploits.message.contains("(DEP, CFG)"));
        assert_eq!(
            exploits.correctif.unwrap().commandes,
            ["Set-ProcessMitigation -System -Enable DEP,CFG"]
        );
        // Windows Update : services désactivés (élevé, corrigé) avant la stratégie (moyen, à la main).
        assert!(juger_windows_update(Some(3), Some(2), None).is_none());
        let service = juger_windows_update(Some(4), Some(2), Some(1)).unwrap();
        assert_eq!(service.probleme, Some(Niveau::Eleve));
        assert_eq!(
            service.correctif.unwrap().commandes,
            ["Set-Service wuauserv -StartupType Manual"]
        );
        let les_deux = juger_windows_update(Some(4), Some(4), None).unwrap().correctif.unwrap();
        assert_eq!(les_deux.commandes.len(), 2);
        let strategie = juger_windows_update(Some(3), Some(2), Some(1)).unwrap();
        assert!(strategie.probleme == Some(Niveau::Moyen) && !strategie.correctif.unwrap().automatique);
        // Secure Boot : clé absente (ancien BIOS), rien ; 0 coupé, une information à régler soi-même.
        assert!(juger_demarrage_securise(None).is_none());
        assert_eq!(juger_demarrage_securise(Some(1)).unwrap().probleme, None);
        let coupe = juger_demarrage_securise(Some(0)).unwrap();
        assert!(coupe.probleme == Some(Niveau::Info) && !coupe.correctif.unwrap().automatique);
        // Accès anonyme : seules les valeurs ouvertes sont remises, chacune par sa commande.
        assert!(juger_anonyme(Some(1), Some(0)).is_none() && juger_anonyme(None, None).is_none());
        let sam = juger_anonyme(Some(0), Some(0)).unwrap();
        assert_eq!(sam.probleme, Some(Niveau::Moyen));
        let remise = sam.correctif.unwrap();
        assert!(
            remise.automatique && remise.commandes.len() == 1 && remise.commandes[0] == "vanguard:sam-anonyme-ferme"
        );
        let les_deux = juger_anonyme(Some(0), Some(1)).unwrap().correctif.unwrap();
        assert!(les_deux.commandes.len() == 2 && les_deux.commandes[1] == "vanguard:anonyme-hors-tous");
        // Connexion invité : la stratégie passe avant le réglage ; imposée, rien à lancer d'ici.
        assert!(juger_invite_smb(None, None).is_none() && juger_invite_smb(None, Some(0)).is_none());
        assert!(juger_invite_smb(Some(0), Some(1)).is_none());
        let c = juger_invite_smb(None, Some(1)).unwrap();
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.correctif.unwrap().commandes[0].ends_with("-Name AllowInsecureGuestAuth -Value 0 -Type DWord"));
        let impose = juger_invite_smb(Some(1), Some(0)).unwrap().correctif.unwrap();
        assert_eq!(impose.commandes.len(), 0);
        assert!(
            juger_pause(Some("2026-10-01T09:00:00Z"), "2026-10-19").is_none()
                && juger_pause(None, "2026-10-19").is_none()
        );
    }

    #[test]
    fn recherche_automatique_du_proxy() {
        assert!(juger_wpad(Some(1), false).is_none());
        // Compte de domaine : le proxy de l'entreprise vient souvent de WPAD.
        assert!(juger_wpad(None, true).is_none());
        for valeur in [None, Some(0)] {
            let c = juger_wpad(valeur, false).unwrap();
            assert_eq!(c.probleme, Some(Niveau::Moyen));
            let k = c.correctif.unwrap();
            assert!(k.automatique && k.commandes == ["vanguard:wpad-coupe"]);
        }
    }
}
