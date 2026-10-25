//! Les règles du bilan de Windows, déclarées au registre (`machine::regles`) dans l'ordre où le bilan les montre. Les
//! vérifications restent dans leurs fichiers ; une nouvelle règle se déclare plutôt à côté de la sienne.

use super::*;
use crate::machine::ParBilan;
use crate::machine::regles::{Os, regle};

/// Lus une fois par bilan, et deux lectures pourraient se contredire : le pare-feu (sa règle et celles des ports TCP
/// et UDP le demandent en même temps) et l'adresse de ce PC sur le réseau local (les deux règles des ports).
static PARE_FEU: ParBilan<Constat> = ParBilan::new();
static ADRESSE: ParBilan<Option<String>> = ParBilan::new();

fn adresse_locale() -> Option<String> {
    crate::reseau::scan::reseau_local().map(|l| l.1.to_string())
}

regle!(
    "WIN-PFE-001",
    Os::Windows,
    10,
    ("pare-feu", "firewall"),
    &[
        "CIS Controls v8 4.5",
        "Microsoft : Windows Firewall overview",
        "MITRE ATT&CK M1037"
    ],
    || vec![PARE_FEU.lire(pare_feu)]
);

regle!(
    "WIN-ANV-001",
    Os::Windows,
    100,
    ("antivirus", "antivirus"),
    &[
        "CIS Controls v8 10.1",
        "Microsoft : Microsoft Defender Antivirus in Windows overview",
        "MITRE ATT&CK M1049"
    ],
    || { antivirus().into_iter().collect() }
);

regle!(
    "WIN-ANV-002",
    Os::Windows,
    110,
    ("exclusions de Defender", "Defender exclusions"),
    &[
        "CIS Controls v8 10.1",
        "Microsoft : Exclusions for Microsoft Defender Antivirus",
        "MITRE ATT&CK T1685"
    ],
    || exclusions::exclusions().into_iter().collect()
);

regle!(
    "WIN-ANV-003",
    Os::Windows,
    115,
    (
        "protections de Defender (ASR, réseau, PUA, dossiers contrôlés)",
        "Defender protections (ASR, network, PUA, controlled folders)"
    ),
    &[
        "CIS Controls v8 10.5",
        "Microsoft : Attack surface reduction rules reference",
        "Microsoft : Turn on network protection",
        "MITRE ATT&CK M1040",
    ],
    defender::protections_de_defender
);

regle!(
    "WIN-RES-001",
    Os::Windows,
    120,
    ("services TCP ouverts sur le réseau", "TCP services open to the network"),
    &["CIS Controls v8 4.8", "MITRE ATT&CK M1035"],
    || {
        let actif = PARE_FEU.lire(pare_feu).probleme.is_none();
        let ip = ADRESSE.lire(adresse_locale);
        ports_ecoute(actif, ip.as_deref())
    }
);

regle!(
    "WIN-RES-002",
    Os::Windows,
    130,
    ("services UDP ouverts sur le réseau", "UDP services open to the network"),
    &["CIS Controls v8 4.8", "MITRE ATT&CK M1035"],
    || {
        let actif = PARE_FEU.lire(pare_feu).probleme.is_none();
        let ip = ADRESSE.lire(adresse_locale);
        ports_udp(actif, ip.as_deref())
    }
);

regle!(
    "WIN-RES-003",
    Os::Windows,
    140,
    ("SMBv1", "SMBv1"),
    &[
        "CIS Controls v8 4.8",
        "Microsoft : Detect, enable, and disable SMBv1, SMBv2, and SMBv3 in Windows",
        "MITRE ATT&CK M1042"
    ],
    || vec![smb1()]
);

regle!(
    "WIN-DIS-001",
    Os::Windows,
    150,
    ("Bureau à distance", "Remote Desktop"),
    &["CIS Controls v8 6.4", "CIS Controls v8 4.8", "MITRE ATT&CK M1035"],
    || vec![bureau_distance()]
);

regle!(
    "WIN-PRV-001",
    Os::Windows,
    160,
    ("contrôle de compte d'utilisateur (UAC)", "User Account Control (UAC)"),
    &[
        "CIS Controls v8 5.4",
        "Microsoft : User Account Control settings and configuration",
        "MITRE ATT&CK M1052"
    ],
    || vec![uac()]
);

regle!(
    "WIN-SES-001",
    Os::Windows,
    170,
    ("verrouillage de l'écran", "screen lock"),
    &["CIS Controls v8 4.3"],
    || vec![verrouillage::verrouillage()]
);

regle!(
    "WIN-MAJ-001",
    Os::Windows,
    180,
    ("Windows Update", "Windows Update"),
    &["CIS Controls v8 7.3", "MITRE ATT&CK M1051"],
    || vec![mises_a_jour()]
);

regle!(
    "WIN-MAJ-002",
    Os::Windows,
    185,
    ("logiciels pas à jour", "outdated software"),
    &["CIS Controls v8 7.4", "MITRE ATT&CK M1051"],
    crate::protection::perimes::constats
);

regle!(
    "WIN-CHF-001",
    Os::Windows,
    190,
    ("chiffrement BitLocker", "BitLocker encryption"),
    &[
        "CIS Controls v8 3.6",
        "Microsoft : BitLocker overview",
        "MITRE ATT&CK M1041"
    ],
    || vec![chiffrement()]
);

regle!(
    "WIN-DEM-001",
    Os::Windows,
    200,
    ("démarrage sécurisé (Secure Boot)", "Secure Boot"),
    &[
        "CIS Controls v8 4.1",
        "Microsoft : Secure the Windows boot process",
        "MITRE ATT&CK M1046"
    ],
    || durcissement::demarrage_securise().into_iter().collect()
);

regle!(
    "WIN-CPT-001",
    Os::Windows,
    210,
    ("comptes et administrateurs", "accounts and administrators"),
    &["CIS Controls v8 5.4", "MITRE ATT&CK M1026"],
    || comptes().into_iter().collect()
);

regle!(
    "WIN-CPT-002",
    Os::Windows,
    211,
    (
        "règle des mots de passe des comptes locaux",
        "local account password policy"
    ),
    &[
        "CIS Controls v8 4.10",
        "CIS Controls v8 5.2",
        "Microsoft : Account lockout threshold",
        "MITRE ATT&CK M1027"
    ],
    || politique().into_iter().collect()
);

regle!(
    "WIN-PRS-001",
    Os::Windows,
    220,
    ("ce qui se lance tout seul", "what starts by itself"),
    &[
        "CIS Controls v8 2.3",
        "MITRE ATT&CK T1547.001",
        "MITRE ATT&CK T1053.005"
    ],
    || persistance().into_iter().collect()
);

regle!(
    "WIN-SRV-001",
    Os::Windows,
    230,
    ("services au chemin sans guillemets", "unquoted service paths"),
    &["CIS Controls v8 4.1", "MITRE ATT&CK T1574.009"],
    || services::services_sans_guillemets().into_iter().collect()
);

regle!(
    "WIN-SSH-001",
    Os::Windows,
    232,
    ("serveur OpenSSH", "OpenSSH server"),
    &[
        "CIS Controls v8 4.6",
        "Microsoft : OpenSSH Server configuration for Windows",
        "Microsoft : Key-based authentication in OpenSSH for Windows",
        "MITRE ATT&CK M1042",
    ],
    ssh::serveur
);

regle!(
    "WIN-SSH-002",
    Os::Windows,
    234,
    ("clés SSH du compte", "the account's SSH keys"),
    &[
        "CIS Controls v8 3.3",
        "Microsoft : Key-based authentication in OpenSSH for Windows",
        "MITRE ATT&CK M1022",
        "MITRE ATT&CK M1027"
    ],
    ssh::cles_du_compte
);

regle!(
    "WIN-WIF-001",
    Os::Windows,
    240,
    ("réseaux Wi-Fi", "Wi-Fi networks"),
    &["CIS Controls v8 12.6"],
    || wifi().into_iter().collect()
);

regle!(
    "WIN-DUR-001",
    Os::Windows,
    250,
    (
        "protection des secrets et du noyau (WDigest, LSA, Credential Guard, exploits)",
        "protection of secrets and kernel (WDigest, LSA, Credential Guard, exploits)"
    ),
    &[
        "CIS Controls v8 10.5",
        "Microsoft : Configure added LSA protection",
        "Microsoft : Credential Guard overview",
        "MITRE ATT&CK M1043",
        "MITRE ATT&CK M1025",
        "MITRE ATT&CK M1050"
    ],
    durcissement::durcissement
);

regle!(
    "WIN-DUR-002",
    Os::Windows,
    253,
    (
        "authentification réseau (NTLM, empreintes LM, accès anonyme)",
        "network authentication (NTLM, LM hashes, anonymous access)"
    ),
    &[
        "CIS Controls v8 4.1",
        "Microsoft : Network security: LAN Manager authentication level",
        "MITRE ATT&CK M1028",
    ],
    durcissement::authentification_reseau
);

regle!(
    "WIN-DUR-003",
    Os::Windows,
    254,
    (
        "client de partage SMB (SMBv1, signature, invité)",
        "SMB sharing client (SMBv1, signing, guest)"
    ),
    &[
        "CIS Controls v8 4.8",
        "Microsoft : Overview of Server Message Block signing",
        "MITRE ATT&CK M1042"
    ],
    durcissement::partage_smb
);

regle!(
    "WIN-DUR-004",
    Os::Windows,
    255,
    (
        "accès à distance (Assistance, Registre à distance, WPAD)",
        "remote access (Assistance, Remote Registry, WPAD)"
    ),
    &[
        "CIS Controls v8 4.8",
        "Microsoft : Windows security baselines",
        "MITRE ATT&CK M1042"
    ],
    durcissement::acces_distant
);

regle!(
    "WIN-DUR-005",
    Os::Windows,
    256,
    (
        "programmes et documents (SmartScreen, scripts, macros)",
        "programs and documents (SmartScreen, scripts, macros)"
    ),
    &[
        "CIS Controls v8 2.7",
        "Microsoft : Macros from the internet are blocked by default in Office",
        "MITRE ATT&CK M1038"
    ],
    durcissement::programmes_et_documents
);

regle!(
    "WIN-MAJ-003",
    Os::Windows,
    182,
    ("Windows Update coupé ou en pause", "Windows Update off or paused"),
    &[
        "CIS Controls v8 7.3",
        "Microsoft : Manage additional Windows Update settings",
        "MITRE ATT&CK M1051"
    ],
    durcissement::windows_update_bloque
);

regle!(
    "WIN-SES-002",
    Os::Windows,
    172,
    ("session ouverte toute seule", "automatic sign-in"),
    &["CIS Controls v8 4.3", "Microsoft : Turn on automatic logon in Windows"],
    durcissement::ouverture_automatique
);
