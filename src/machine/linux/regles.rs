//! Les règles du bilan de Linux, déclarées au registre (`machine::regles`) dans l'ordre où le bilan les montre. Les
//! vérifications restent dans leurs fichiers ; une nouvelle règle se déclare plutôt à côté de la sienne
//! (`plateforme.rs`).

use super::*;
use crate::machine::ParBilan;
use crate::machine::regles::{Os, regle};

/// Le pare-feu, lu une fois par bilan : sa règle et celle des ports le demandent en même temps, et deux lectures
/// pourraient se contredire.
static PARE_FEU: ParBilan<Constat> = ParBilan::new();

regle!(
    "LNX-PFE-001",
    Os::Linux,
    10,
    ("pare-feu", "firewall"),
    &[
        "CIS Controls v8 4.5",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "MITRE ATT&CK M1037"
    ],
    || vec![PARE_FEU.lire(pare_feu)]
);

regle!(
    "LNX-RES-001",
    Os::Linux,
    100,
    ("services ouverts sur le réseau", "services open to the network"),
    &["CIS Controls v8 4.8", "MITRE ATT&CK M1035"],
    || {
        let actif = PARE_FEU.lire(pare_feu).probleme.is_none();
        ports_ecoute(actif, actif && ufw_actif())
    }
);

regle!(
    "LNX-CTN-001",
    Os::Linux,
    110,
    ("Docker exposé ou trop permis", "Docker exposed or over-permissive"),
    &["CIS Controls v8 4.8", "CIS Docker Benchmark", "MITRE ATT&CK M1035"],
    || docker().into_iter().collect()
);

regle!(
    "LNX-SSH-001",
    Os::Linux,
    120,
    ("serveur SSH", "SSH server"),
    &[
        "CIS Controls v8 4.6",
        "ANSSI, Recommandations pour un usage sécurisé d'(Open)SSH",
        "MITRE ATT&CK M1054"
    ],
    || vec![ssh_serveur()]
);

regle!(
    "LNX-SSH-004",
    Os::Linux,
    125,
    (
        "ports renvoyés par SSH ouverts au réseau",
        "SSH-forwarded ports open to the network"
    ),
    &[
        "CIS Controls v8 4.6",
        "ANSSI, Recommandations pour un usage sécurisé d'(Open)SSH",
        "MITRE ATT&CK M1054"
    ],
    || ports_ssh().into_iter().collect()
);

regle!(
    "LNX-SSH-005",
    Os::Linux,
    126,
    ("réglages secondaires de sshd", "secondary sshd settings"),
    &[
        "CIS Controls v8 4.6",
        "ANSSI, Recommandations pour un usage sécurisé d'(Open)SSH",
        "MITRE ATT&CK M1054"
    ],
    || ssh_secondaire().into_iter().collect()
);

regle!(
    "LNX-SSH-002",
    Os::Linux,
    130,
    ("échecs de connexion SSH", "failed SSH logins"),
    &["CIS Controls v8 8.11", "MITRE ATT&CK T1110"],
    || ssh_echecs().into_iter().collect()
);

regle!(
    "LNX-MAJ-001",
    Os::Linux,
    140,
    ("mises à jour en attente", "pending updates"),
    &["CIS Controls v8 7.3", "MITRE ATT&CK M1051"],
    || vec![mises_a_jour()]
);

regle!(
    "LNX-MAJ-002",
    Os::Linux,
    150,
    ("mises à jour de sécurité automatiques", "automatic security updates"),
    &["CIS Controls v8 7.3", "MITRE ATT&CK M1051"],
    || maj_automatiques().into_iter().collect()
);

regle!(
    "LNX-MAJ-003",
    Os::Linux,
    160,
    ("failles connues des paquets", "known package flaws"),
    &["CIS Controls v8 7.7", "MITRE ATT&CK M1016", "MITRE ATT&CK M1051"],
    || vec![failles_connues()]
);

regle!(
    "LNX-MAJ-004",
    Os::Linux,
    170,
    (
        "Flatpak, micrologiciels et autres mises à jour",
        "Flatpak, firmware and other updates"
    ),
    &["CIS Controls v8 7.4", "MITRE ATT&CK M1051"],
    || autres_mises_a_jour().into_iter().collect()
);

regle!(
    "LNX-MAJ-005",
    Os::Linux,
    180,
    ("redémarrage demandé", "restart required"),
    &["CIS Controls v8 7.3", "MITRE ATT&CK M1051"],
    || vec![redemarrage()]
);

regle!(
    "LNX-CHF-001",
    Os::Linux,
    190,
    ("chiffrement du disque", "disk encryption"),
    &["CIS Controls v8 3.6", "MITRE ATT&CK M1041"],
    || vec![chiffrement_disque()]
);

regle!(
    "LNX-SES-001",
    Os::Linux,
    200,
    ("session ouverte toute seule", "automatic login"),
    &["CIS Controls v8 4.3"],
    || ouverture_automatique().into_iter().collect()
);

regle!(
    "LNX-SES-002",
    Os::Linux,
    210,
    ("verrouillage de l'écran", "screen lock"),
    &["CIS Controls v8 4.3"],
    || verrouillage_ecran().into_iter().collect()
);

regle!(
    "LNX-SES-003",
    Os::Linux,
    220,
    ("affichage X11 ouvert", "open X11 display"),
    &["CIS Controls v8 4.8", "MITRE ATT&CK M1035"],
    || acces_x11().into_iter().collect()
);

regle!(
    "LNX-NOY-003",
    Os::Linux,
    230,
    (
        "réglages du noyau pour la mémoire et les processus (sysctl)",
        "kernel settings for memory and processes (sysctl)"
    ),
    &[
        "CIS Controls v8 10.5",
        "ANSSI BP-028 (paramétrage du noyau)",
        "MITRE ATT&CK M1028",
        "MITRE ATT&CK M1050"
    ],
    || vec![durcissement_noyau(durcissement::Groupe::Memoire)]
);

regle!(
    "LNX-NOY-007",
    Os::Linux,
    230,
    (
        "liens et fichiers de /tmp protégés par le noyau (sysctl)",
        "links and files in /tmp protected by the kernel (sysctl)"
    ),
    &[
        "CIS Controls v8 4.1",
        "ANSSI BP-028 (paramétrage du noyau)",
        "MITRE ATT&CK M1028"
    ],
    || vec![durcissement_noyau(durcissement::Groupe::FichiersPartages)]
);

regle!(
    "LNX-RES-003",
    Os::Linux,
    230,
    (
        "réglages réseau du noyau (SYN, redirections ICMP)",
        "kernel network settings (SYN, ICMP redirects)"
    ),
    &[
        "CIS Controls v8 4.1",
        "ANSSI BP-028 (paramétrage réseau du noyau)",
        "MITRE ATT&CK M1028"
    ],
    || vec![durcissement_noyau(durcissement::Groupe::Reseau)]
);

regle!(
    "LNX-NOY-004",
    Os::Linux,
    240,
    ("AppArmor ou SELinux", "AppArmor or SELinux"),
    &[
        "CIS Controls v8 4.1",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "MITRE ATT&CK M1048"
    ],
    || vec![module_securite()]
);

regle!(
    "LNX-SAV-001",
    Os::Linux,
    250,
    ("sauvegardes et instantanés", "backups and snapshots"),
    &["CIS Controls v8 11.2", "MITRE ATT&CK M1053"],
    || vec![sauvegardes()]
);

regle!(
    "LNX-PRS-001",
    Os::Linux,
    260,
    ("fichiers suspects", "suspicious files"),
    &["CIS Controls v8 10.1", "MITRE ATT&CK T1548.001"],
    || fichiers_suspects().into_iter().collect()
);

regle!(
    "LNX-PRS-002",
    Os::Linux,
    270,
    ("persistance cachée", "hidden persistence"),
    &[
        "CIS Controls v8 13.2",
        "MITRE ATT&CK T1574.006",
        "MITRE ATT&CK T1543.002",
        "MITRE ATT&CK T1547.013",
        "MITRE ATT&CK T1053.003",
        "MITRE ATT&CK T1546.004"
    ],
    || persistance().into_iter().collect()
);

regle!(
    "LNX-DEM-001",
    Os::Linux,
    280,
    ("démarrage sécurisé (Secure Boot)", "Secure Boot"),
    &[
        "CIS Controls v8 4.1",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "MITRE ATT&CK M1046"
    ],
    || vec![demarrage_securise()]
);

regle!(
    "LNX-SSH-003",
    Os::Linux,
    290,
    ("clés SSH du compte", "the account's SSH keys"),
    &[
        "CIS Controls v8 3.3",
        "ANSSI, Recommandations pour un usage sécurisé d'(Open)SSH",
        "MITRE ATT&CK M1022",
        "MITRE ATT&CK M1027"
    ],
    || cles_ssh().into_iter().collect()
);

regle!(
    "LNX-PRV-001",
    Os::Linux,
    300,
    (
        "fichiers secrets lisibles par d'autres",
        "secret files readable by others"
    ),
    &[
        "CIS Controls v8 3.3",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "MITRE ATT&CK M1022"
    ],
    || fichiers_secrets().into_iter().collect()
);

regle!(
    "LNX-MAT-001",
    Os::Linux,
    310,
    ("failles du processeur", "processor flaws"),
    &["CIS Controls v8 10.5"],
    || vec![processeur()]
);

regle!(
    "LNX-PRV-002",
    Os::Linux,
    320,
    ("groupes équivalents à root", "root-equivalent groups"),
    &[
        "CIS Controls v8 5.4",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "MITRE ATT&CK M1026"
    ],
    || groupes_privilegies().into_iter().collect()
);

regle!(
    "LNX-PRV-003",
    Os::Linux,
    330,
    ("sudo sans mot de passe", "passwordless sudo"),
    &[
        "CIS Controls v8 5.4",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "MITRE ATT&CK T1548.003",
        "MITRE ATT&CK M1026"
    ],
    || sudo_sans_mot_de_passe().into_iter().collect()
);

regle!(
    "LNX-PRV-004",
    Os::Linux,
    335,
    (
        "dossiers de commandes modifiables par d'autres",
        "command folders writable by others"
    ),
    &["CIS Controls v8 3.3", "MITRE ATT&CK T1574.007", "MITRE ATT&CK M1022"],
    || dossiers_de_commandes().into_iter().collect()
);

regle!(
    "LNX-MAJ-006",
    Os::Linux,
    340,
    ("paquets de l'AUR", "AUR packages"),
    &["CIS Controls v8 2.2"],
    || paquets_aur().into_iter().collect()
);

regle!(
    "LNX-CPT-001",
    Os::Linux,
    350,
    ("comptes aux droits root cachés", "hidden accounts with root rights"),
    &["CIS Controls v8 5.4", "MITRE ATT&CK T1136.001"],
    || vec![comptes()]
);

regle!(
    "LNX-CPT-002",
    Os::Linux,
    351,
    (
        "blocage des comptes et longueur des mots de passe (PAM)",
        "account lockout and password length (PAM)"
    ),
    &[
        "CIS Controls v8 4.10",
        "CIS Controls v8 5.2",
        "MITRE ATT&CK M1027",
        "MITRE ATT&CK M1036"
    ],
    || pam()
);

regle!(
    "LNX-WIF-001",
    Os::Linux,
    360,
    ("réseaux Wi-Fi", "Wi-Fi networks"),
    &["CIS Controls v8 12.6"],
    || wifi(crate::reseau::scan::passerelle().map(|g| g.to_string()))
);

regle!(
    "LNX-SRV-001",
    Os::Linux,
    370,
    ("services en échec", "failed services"),
    &["CIS Controls v8 4.1"],
    || vec![services_en_echec()]
);
