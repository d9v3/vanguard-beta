//! Les règles du bilan de macOS, déclarées au registre (`machine::regles`) dans l'ordre où le bilan les montre. Les
//! vérifications restent dans leurs fichiers ; une nouvelle règle se déclare plutôt à côté de la sienne.

use super::*;
use crate::machine::ParBilan;
use crate::machine::regles::{Os, regle};

/// Le pare-feu, lu une fois par bilan : sa règle et celle des ports le demandent en même temps, et deux lectures
/// pourraient se contredire.
static PARE_FEU: ParBilan<Constat> = ParBilan::new();

regle!(
    "MAC-PFE-001",
    Os::MacOs,
    10,
    ("pare-feu", "firewall"),
    &["CIS Controls v8 4.5", "MITRE ATT&CK M1037"],
    || vec![PARE_FEU.lire(pare_feu)]
);

regle!(
    "MAC-PFE-002",
    Os::MacOs,
    100,
    ("mode furtif du pare-feu", "firewall stealth mode"),
    &["CIS Controls v8 4.5", "MITRE ATT&CK M1037"],
    || vec![mode_furtif()]
);

regle!(
    "MAC-WIF-001",
    Os::MacOs,
    110,
    ("réseaux Wi-Fi", "Wi-Fi networks"),
    &["CIS Controls v8 12.6"],
    || wifi().into_iter().collect()
);

regle!(
    "MAC-RES-001",
    Os::MacOs,
    120,
    ("services ouverts sur le réseau", "services open to the network"),
    &["CIS Controls v8 4.8", "MITRE ATT&CK M1035"],
    || ports_ecoute(PARE_FEU.lire(pare_feu).probleme.is_none())
);

regle!(
    "MAC-CHF-001",
    Os::MacOs,
    130,
    ("FileVault", "FileVault"),
    &["CIS Controls v8 3.6", "MITRE ATT&CK M1041"],
    || vec![chiffrement_disque()]
);

regle!(
    "MAC-SYS-001",
    Os::MacOs,
    140,
    ("SIP et Gatekeeper", "SIP and Gatekeeper"),
    &[
        "CIS Controls v8 10.5",
        "CIS Controls v8 2.5",
        "MITRE ATT&CK M1045",
        "MITRE ATT&CK M1038"
    ],
    || protection_systeme().into_iter().collect()
);

regle!(
    "MAC-SYS-002",
    Os::MacOs,
    150,
    ("volume système signé", "signed system volume"),
    &["CIS Controls v8 4.1", "MITRE ATT&CK M1045"],
    || durcissement::systeme_signe().into_iter().collect()
);

regle!(
    "MAC-SYS-003",
    Os::MacOs,
    160,
    ("extensions du noyau de tiers", "third-party kernel extensions"),
    &["CIS Controls v8 2.5", "MITRE ATT&CK T1547.006"],
    || vec![durcissement::extensions_tierces()]
);

regle!(
    "MAC-PAR-001",
    Os::MacOs,
    170,
    ("AirDrop", "AirDrop"),
    &["CIS Controls v8 4.8", "MITRE ATT&CK M1042"],
    || { durcissement::airdrop().into_iter().collect() }
);

regle!(
    "MAC-RES-002",
    Os::MacOs,
    175,
    (
        "découverte automatique du proxy (WPAD)",
        "automatic proxy discovery (WPAD)"
    ),
    &["CIS Controls v8 4.1", "MITRE ATT&CK M1042"],
    || durcissement::decouverte_proxy().into_iter().collect()
);

regle!(
    "MAC-SES-001",
    Os::MacOs,
    180,
    ("verrouillage de l'écran", "screen lock"),
    &["CIS Controls v8 4.3"],
    || verrouillage_ecran().into_iter().collect()
);

regle!(
    "MAC-SES-002",
    Os::MacOs,
    190,
    ("session ouverte toute seule", "automatic login"),
    &["CIS Controls v8 4.3"],
    || ouverture_de_session().into_iter().collect()
);

regle!(
    "MAC-CPT-001",
    Os::MacOs,
    200,
    ("comptes", "accounts"),
    &["CIS Controls v8 4.7"],
    || vec![comptes()]
);

regle!(
    "MAC-PRV-001",
    Os::MacOs,
    210,
    ("compte root activé", "root account enabled"),
    &["CIS Controls v8 4.7", "MITRE ATT&CK M1026"],
    || privileges::compte_root().into_iter().collect()
);

regle!(
    "MAC-PRV-002",
    Os::MacOs,
    220,
    ("sudo sans mot de passe", "passwordless sudo"),
    &["CIS Controls v8 5.4", "MITRE ATT&CK T1548.003", "MITRE ATT&CK M1026"],
    || privileges::sudo_sans_mot_de_passe().into_iter().collect()
);

regle!(
    "MAC-PRV-003",
    Os::MacOs,
    230,
    (
        "fichiers secrets lisibles par d'autres",
        "secret files readable by others"
    ),
    &["CIS Controls v8 3.3", "MITRE ATT&CK M1022"],
    || privileges::fichiers_secrets().into_iter().collect()
);

regle!(
    "MAC-PRV-004",
    Os::MacOs,
    235,
    ("dossiers de commandes ouverts à tous", "command folders open to all"),
    &["CIS Controls v8 3.3", "MITRE ATT&CK T1574.007", "MITRE ATT&CK M1022"],
    || privileges::dossiers_de_commandes().into_iter().collect()
);

regle!(
    "MAC-DIS-001",
    Os::MacOs,
    240,
    ("gestion à distance (MDM)", "remote management (MDM)"),
    &["CIS Controls v8 4.8"],
    || gestion_a_distance().into_iter().collect()
);

regle!(
    "MAC-PRF-001",
    Os::MacOs,
    245,
    ("profils de configuration", "configuration profiles"),
    &["CIS Controls v8 4.1"],
    || protection::profils_de_configuration().into_iter().collect()
);

regle!(
    "MAC-ANV-001",
    Os::MacOs,
    248,
    ("définitions de XProtect", "XProtect definitions"),
    &["CIS Controls v8 10.2", "MITRE ATT&CK M1049"],
    || vec![protection::xprotect()]
);

regle!(
    "MAC-MAJ-001",
    Os::MacOs,
    250,
    ("mises à jour automatiques", "automatic updates"),
    &["CIS Controls v8 7.3", "MITRE ATT&CK M1051"],
    || vec![mises_a_jour_automatiques()]
);

regle!(
    "MAC-MAJ-002",
    Os::MacOs,
    260,
    ("mises à jour en attente", "pending updates"),
    &["CIS Controls v8 7.3", "MITRE ATT&CK M1051"],
    || maj::mises_a_jour().into_iter().collect()
);

regle!(
    "MAC-MAJ-003",
    Os::MacOs,
    270,
    ("Homebrew", "Homebrew"),
    &["CIS Controls v8 7.4", "MITRE ATT&CK M1051"],
    || { maj::homebrew_a_jour().into_iter().collect() }
);

regle!(
    "MAC-MAJ-004",
    Os::MacOs,
    275,
    ("logiciels pas à jour", "outdated software"),
    &["CIS Controls v8 7.4", "MITRE ATT&CK M1051"],
    crate::protection::perimes::constats
);

regle!(
    "MAC-SAV-001",
    Os::MacOs,
    280,
    ("sauvegardes Time Machine", "Time Machine backups"),
    &["CIS Controls v8 11.2", "MITRE ATT&CK M1053"],
    || vec![sauvegardes()]
);

regle!(
    "MAC-SAV-002",
    Os::MacOs,
    290,
    ("Time Machine chiffrée", "encrypted Time Machine"),
    &["CIS Controls v8 11.3", "MITRE ATT&CK M1041"],
    || sauvegarde_chiffree().into_iter().collect()
);

regle!(
    "MAC-PRS-001",
    Os::MacOs,
    300,
    ("ce qui se lance tout seul", "what starts by itself"),
    &[
        "CIS Controls v8 2.3",
        "MITRE ATT&CK T1543.001",
        "MITRE ATT&CK T1543.004"
    ],
    || persistance().into_iter().collect()
);

regle!(
    "MAC-SSH-001",
    Os::MacOs,
    310,
    ("clés SSH du compte", "the account's SSH keys"),
    &["CIS Controls v8 3.3", "MITRE ATT&CK M1022", "MITRE ATT&CK M1027"],
    || cles_ssh().into_iter().collect()
);

regle!(
    "MAC-SSH-002",
    Os::MacOs,
    320,
    ("session à distance (SSH)", "Remote Login (SSH)"),
    &["CIS Controls v8 4.6", "MITRE ATT&CK M1054"],
    || vec![ssh_serveur()]
);

regle!(
    "MAC-CPT-002",
    Os::MacOs,
    205,
    (
        "règle des mots de passe et blocage des comptes",
        "password policy and account lockout"
    ),
    &[
        "CIS Controls v8 4.10",
        "CIS Controls v8 5.2",
        "MITRE ATT&CK M1027",
        "MITRE ATT&CK M1036"
    ],
    parite::politique_mots_de_passe
);

regle!(
    "MAC-DEM-001",
    Os::MacOs,
    155,
    ("sécurité du démarrage", "startup security"),
    &[
        "CIS Controls v8 4.1",
        "Apple Platform Security : Startup Security Utility",
        "MITRE ATT&CK M1046"
    ],
    || vec![parite::demarrage_securise()]
);

regle!(
    "MAC-PRS-002",
    Os::MacOs,
    302,
    ("éléments d'ouverture et de fond", "login and background items"),
    &["CIS Controls v8 2.3", "CIS Controls v8 10.7", "MITRE ATT&CK T1547.015"],
    parite::elements_d_ouverture
);

regle!(
    "MAC-PRS-003",
    Os::MacOs,
    304,
    (
        "crochets de connexion et extensions d'autorisation",
        "login hooks and authorization plugins"
    ),
    &["CIS Controls v8 2.5", "CIS Controls v8 10.7", "MITRE ATT&CK T1037.002"],
    parite::crochets_et_extensions
);
