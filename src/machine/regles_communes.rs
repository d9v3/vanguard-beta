//! Les règles du bilan communes aux trois systèmes, déclarées au registre (`machine::regles`) après celles du système,
//! dans l'ordre où le bilan les montre.

use crate::machine::regles::{Os, regle};

regle!(
    "COM-DNS-001",
    Os::Tous,
    500,
    ("DNS utilisé", "DNS in use"),
    &["CIS Controls v8 4.9"],
    || super::dns::dns().into_iter().collect()
);

regle!(
    "COM-CRT-001",
    Os::Tous,
    510,
    ("certificats racine ajoutés", "added root certificates"),
    &["CIS Controls v8 3.10", "MITRE ATT&CK T1553.004"],
    || super::certificats::certificats().into_iter().collect()
);

regle!(
    "COM-NAV-001",
    Os::Tous,
    520,
    ("extensions des navigateurs", "browser extensions"),
    &["CIS Controls v8 9.4", "MITRE ATT&CK T1176.001"],
    || super::extensions::extensions().into_iter().collect()
);

regle!(
    "COM-NAV-002",
    Os::Tous,
    530,
    ("réglages de sécurité des navigateurs", "browser security settings"),
    &["CIS Controls v8 9.1", "MITRE ATT&CK M1054"],
    || super::navigateur::navigateurs().into_iter().collect()
);

regle!(
    "COM-NAV-004",
    Os::Tous,
    535,
    (
        "échange de clés post-quantique des navigateurs",
        "browsers' post-quantum key exchange"
    ),
    &["CIS Controls v8 3.10", "Mozilla : PostQuantumKeyAgreementEnabled"],
    super::navigateur::post_quantique
);

regle!(
    "COM-NAV-003",
    Os::Tous,
    540,
    (
        "navigation détournée (proxy, hosts)",
        "hijacked browsing (proxy, hosts)"
    ),
    &["CIS Controls v8 4.9"],
    || vec![super::navigation_detournee::constat()]
);

regle!(
    "COM-MDP-001",
    Os::Tous,
    550,
    (
        "mots de passe gardés par le navigateur",
        "passwords kept by the browser"
    ),
    &["CIS Controls v8 5.2", "MITRE ATT&CK M1027"],
    || super::mots_de_passe::constats().into_iter().collect()
);

regle!(
    "COM-FIC-001",
    Os::Tous,
    560,
    ("fichiers sensibles qui traînent", "sensitive files lying around"),
    &["CIS Controls v8 3.2", "MITRE ATT&CK M1047"],
    || super::sensibles::constats().into_iter().collect()
);

regle!(
    "COM-MAT-001",
    Os::Tous,
    570,
    ("santé de l'ordinateur", "computer health"),
    &["CIS Controls v8 11.1"],
    || super::sante::sante().into_iter().collect()
);

regle!(
    "COM-PAR-001",
    Os::Tous,
    580,
    ("partages ouverts à tous", "shares open to everyone"),
    &["CIS Controls v8 3.3", "MITRE ATT&CK M1035"],
    || super::partages::partages().into_iter().collect()
);

regle!(
    "COM-BLU-001",
    Os::Tous,
    590,
    ("Bluetooth", "Bluetooth"),
    &["CIS Controls v8 4.8", "MITRE ATT&CK M1042"],
    || { super::bluetooth::constats().into_iter().collect() }
);

regle!(
    "COM-LOG-001",
    Os::Tous,
    605,
    (
        "logiciels installés depuis le dernier bilan",
        "software installed since the last check"
    ),
    &["CIS Controls v8 2.1", "CIS Controls v8 2.3"],
    || vec![super::logiciels_vus::constat()]
);

regle!(
    "COM-CPT-001",
    Os::Tous,
    600,
    ("nouveaux administrateurs", "new administrators"),
    &[
        "CIS Controls v8 5.4",
        "MITRE ATT&CK T1098.007",
        "MITRE ATT&CK T1136.001"
    ],
    || super::administrateurs::constat().into_iter().collect()
);

regle!(
    "COM-JRN-001",
    Os::Tous,
    610,
    ("journaux effacés ou en erreur", "erased or failing logs"),
    &["CIS Controls v8 8.2", "CIS Controls v8 8.3", "MITRE ATT&CK T1685.005"],
    || super::journaux::journaux().into_iter().collect()
);

regle!(
    "COM-HEU-001",
    Os::Tous,
    620,
    ("heure de l'ordinateur", "computer clock"),
    &["CIS Controls v8 8.4"],
    || super::heure::constat().into_iter().collect()
);

regle!(
    "COM-MAJ-001",
    Os::Tous,
    630,
    ("fin de support", "end of support"),
    &["CIS Controls v8 2.2", "MITRE ATT&CK M1051"],
    || super::fin_de_support::constats().into_iter().collect()
);

regle!(
    "COM-CPT-002",
    Os::Tous,
    640,
    ("comptes oubliés", "forgotten accounts"),
    &["CIS Controls v8 5.3", "MITRE ATT&CK M1018"],
    || super::comptes_oublies::constats().into_iter().collect()
);

regle!(
    "COM-INT-001",
    Os::Tous,
    650,
    ("intégrité des fichiers critiques", "critical file integrity"),
    &[
        "CIS Controls v8 10.7",
        "ANSSI BP-028 (configuration d'un système GNU/Linux)",
        "MITRE ATT&CK T1556.003",
        "MITRE ATT&CK T1053.003",
        "MITRE ATT&CK T1543.002"
    ],
    || vec![crate::protection::integrite::constat()]
);

regle!(
    "COM-INT-002",
    Os::Tous,
    660,
    ("fichiers-pièges contre les rançongiciels", "ransomware decoy files"),
    &["CIS Controls v8 10.7", "MITRE ATT&CK T1486"],
    || crate::protection::pieges::constat().into_iter().collect()
);

regle!(
    "COM-DIS-001",
    Os::Tous,
    670,
    ("prise de contrôle à distance", "remote takeover"),
    &["CIS Controls v8 2.3", "MITRE ATT&CK T1219.002"],
    || crate::protection::distance::constats().into_iter().collect()
);

regle!(
    "COM-ESP-001",
    Os::Tous,
    675,
    ("logiciels espions", "spyware"),
    &["CIS Controls v8 10.1"],
    crate::protection::espions::constats
);

regle!(
    "COM-CLE-001",
    Os::Tous,
    680,
    ("manifeste de la clé VANGUARD", "VANGUARD key manifest"),
    &["CIS Controls v8 2.5"],
    || crate::protection::manifeste::constat().into_iter().collect()
);

regle!(
    "COM-HIS-001",
    Os::Tous,
    690,
    ("évolution depuis le dernier bilan", "changes since the last check"),
    &["CIS Controls v8 4.1"],
    || crate::historique::constat().into_iter().collect()
);

regle!(
    "COM-ETA-001",
    Os::Tous,
    695,
    ("état de Vanguard scellé", "Vanguard's sealed state"),
    &["CIS Controls v8 4.1"],
    // Le journal des événements en plus des sceaux : une ligne retirée au milieu laisse sa tête scellée intacte.
    || {
        let mut c = crate::sceau::constat();
        c.extend(crate::modele::journal::constat());
        c
    }
);

regle!(
    "COM-PUB-001",
    Os::Tous,
    697,
    ("mode Wi-Fi public", "public Wi-Fi mode"),
    &["CIS Controls v8 4.5"],
    || crate::reseau::wifi_public::constat()
);

regle!(
    "COM-SUR-001",
    Os::Tous,
    700,
    ("surveillance de cet ordinateur", "monitoring of this computer"),
    &["CIS Controls v8 7.5"],
    || crate::reseau::surveillance::constat().into_iter().collect()
);

regle!(
    "COM-SUR-003",
    Os::Tous,
    702,
    (
        "entretien du mois de cet ordinateur",
        "monthly check-up of this computer"
    ),
    &["CIS Controls v8 7.1"],
    || crate::entretien::constat().into_iter().collect()
);

regle!(
    "COM-SUR-002",
    Os::Tous,
    701,
    (
        "protection en temps réel de Vanguard",
        "Vanguard's real-time protection"
    ),
    &["CIS Controls v8 10.7"],
    || vec![crate::protection::temps_reel::constat()]
);

regle!(
    "COM-CLE-002",
    Os::Tous,
    710,
    ("données de la clé chiffrées", "encrypted key data"),
    &["CIS Controls v8 3.9", "MITRE ATT&CK M1041"],
    || crate::chiffrement::constat().into_iter().collect()
);

regle!(
    "COM-CLE-003",
    Os::Tous,
    711,
    (
        "identité de la clé VANGUARD et son carnet",
        "VANGUARD key identity and its record"
    ),
    &["CIS Controls v8 3.9"],
    crate::protection::cles_connues::constats
);

regle!(
    "COM-SAV-001",
    Os::Tous,
    720,
    ("sauvegarde automatique", "automatic backup"),
    &["CIS Controls v8 11.2", "MITRE ATT&CK M1053"],
    || crate::sauvegarde::constats().into_iter().collect()
);

regle!(
    "COM-AGT-001",
    Os::Tous,
    730,
    ("serveurs d'IA ouverts au réseau", "AI servers open to the network"),
    &[
        "CIS Controls v8 4.8",
        "OWASP Top 10 for LLM Applications",
        "MITRE ATT&CK M1035"
    ],
    super::agents_ia::exposition
);

regle!(
    "COM-AGT-002",
    Os::Tous,
    740,
    (
        "réglages des agents d'IA (permissions, serveurs MCP, clés en clair)",
        "AI agent settings (permissions, MCP servers, clear-text keys)"
    ),
    &[
        "CIS Controls v8 3.11",
        "OWASP Top 10 for LLM Applications",
        "MCP Security Best Practices",
        "MITRE ATT&CK M1054"
    ],
    super::agents_ia::reglages
);
