//! Les outils du menu : leur liste, leurs groupes, leurs places et leurs interrupteurs.

#[cfg(target_os = "linux")]
use crate::machine;
use crate::ui::*;
use crate::{depanner, entretien, langue, logiciels, optimiser, protection, raccourci, reseau, selection, ui};

/// Une catégorie de réglages a-t-elle de quoi proposer ici ? Lire les réglages lance des commandes du système : une
/// fois par session suffit, alors que le menu principal le demande à chaque affichage (pour sa recherche).
fn reglages_disponibles(c: optimiser::Categorie) -> bool {
    use optimiser::Categorie::{Confidentialite, Confort, Performance, Protection};
    static CATEGORIES: std::sync::OnceLock<[bool; 3]> = std::sync::OnceLock::new();
    let [confidentialite, performance, confort] =
        *CATEGORIES.get_or_init(|| [Confidentialite, Performance, Confort].map(optimiser::a_des_reglages));
    match c {
        Confidentialite => confidentialite,
        Performance => performance,
        Confort => confort,
        Protection => cfg!(windows),
    }
}

/// Ce que le menu sait faire, dans l'ordre des sous-menus : la ligne d'un outil dans `OUTILS` est à son numéro.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    Complet,
    Corriger,
    Rapport,
    Audit,
    Maj,
    DernieresFailles,
    Integrite,
    Entretien,
    Fiche,
    ALaisser,
    Developpeurs,
    SecretsGit,
    Conteneurs,
    LogicielsPerimes,
    OptionsDefense,
    Appareils,
    Scanner,
    Appareil,
    AuditReseau,
    Nommer,
    Objets,
    Cameras,
    ListesNoires,
    Surveillance,
    Tableau,
    WifiPublic,
    Antivirus,
    AntivirusRapide,
    AntivirusComplet,
    AntivirusDossier,
    Yara,
    AntivirusEtat,
    LogicielsEspions,
    QuiParle,
    Memoire,
    Pieges,
    VerifierFichier,
    Bac,
    Quarantaine,
    Lien,
    CourrielSuspect,
    Distance,
    MotsDePasse,
    Navigateurs,
    Courriel,
    CameraMicro,
    Acces,
    Blocage,
    SitesDangereux,
    DepannerInfection,
    DepannerCompte,
    Traces,
    Evenements,
    Changements,
    OptimiserAnnuler,
    Signaler,
    JournauxWindows,
    Veilleur,
    CopierFichiers,
    SauvegardeAuto,
    VerifierCopies,
    VerifierSauvegarde,
    VerifierCopie,
    VerifierCle,
    Guide,
    Depanner,
    Reparer,
    Diagnostic,
    Logiciels,
    Nettoyer,
    Lenteur,
    Demarrage,
    OptimiserRecommandes,
    Gaming,
    DnsRapide,
    Connexion,
    Nat,
    WifiCanaux,
    OptimiserConfidentialite,
    OptimiserConfort,
    OptimiserPerformance,
    Parametres,
    Appris,
    MettreAJour,
    VerifierVanguard,
    VerifierMoi,
    Autotest,
    Regles,
    Ordinateurs,
    ProtegerDonnees,
    Sauvegarder,
    Raccourci,
    Extensions,
    Desinstaller,
}

/// Un outil du menu : la sous-commande qui fait la même chose en ligne de commande (vide : aucune, et la raison est
/// dans `MENU_SEULEMENT`), son groupe (aucun pour 1, 2 et 3, au menu principal), sa lettre des menus d'avant la 0.43
/// (vide : aucune ; les chiffres, eux, ont changé de sens), son titre et sa précision en français puis en anglais, et
/// les mots que la recherche trouve en plus, jamais affichés. Une seule table pour le menu et la ligne de commande :
/// les tests de `tests_menu` la comparent aux sous-commandes, à leur aide anglaise, au README et à `outils/LISEZMOI.txt`.
pub(crate) struct Outil {
    pub(crate) action: Action,
    pub(crate) commande: &'static str,
    pub(crate) groupe: Option<Groupe>,
    pub(crate) lettre: &'static str,
    pub(crate) titre: [&'static str; 2],
    pub(crate) precision: [&'static str; 2],
    pub(crate) mots: &'static str,
}

/// Une ligne par outil, dans l'ordre de `Action` et des sous-menus (4.1, 4.2…). La précision des outils à interrupteur
/// (surveillance, entretien) suit leur état : `Action::libelle`.
#[rustfmt::skip] // une ligne de données par outil, que rustfmt étalerait sur huit
pub(crate) const OUTILS: &[Outil] = &[
    // Au menu principal : 1, 2, 3.
    Outil { action: Action::Complet, commande: "bilan", groupe: None, lettre: "",
        titre: ["Bilan de sécurité complet", "Full security check"], precision: ["← commencer ici", "← start here"],
        mots: "" },
    Outil { action: Action::Corriger, commande: "corriger", groupe: None, lettre: "",
        titre: ["Corriger les problèmes trouvés", "Fix the problems found"], precision: ["un à un, avec votre accord", "one by one, with your consent"],
        mots: "" },
    Outil { action: Action::Rapport, commande: "rapport", groupe: None, lettre: "",
        titre: ["Rapport détaillé", "Detailed report"], precision: ["dans le navigateur", "in the browser"],
        mots: "" },
    // 4 Cet ordinateur. Les lignes propres à un système en fin de groupe : Defender toujours en 4.10.
    Outil { action: Action::Audit, commande: "audit", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Audit de sécurité", "Security audit"],
        precision: ["pare-feu, comptes, chiffrement…", "firewall, accounts, encryption…"],
        mots: "sécurité security pare-feu firewall ports ssh chiffrement encryption comptes accounts" },
    Outil { action: Action::Maj, commande: "mises-a-jour", groupe: Some(Groupe::Ordinateur), lettre: "u",
        titre: ["Mises à jour du système", "System updates"], precision: ["système, programmes, pilotes", "system, programs, drivers"],
        mots: "update upgrade pilotes drivers firmware bios windows update" },
    Outil { action: Action::DernieresFailles, commande: "dernieres-failles", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Dernières failles exploitées", "Latest exploited flaws"],
        precision: ["catalogue de la CISA, 7 jours", "CISA catalog, 7 days"],
        mots: "failles flaws vulnérabilités vulnerabilities cve kev cisa exploitées exploited récentes latest \
               nouvelles new rançongiciel ransomware" },
    Outil { action: Action::Integrite, commande: "integrite", groupe: Some(Groupe::Ordinateur), lettre: "i",
        titre: ["Intégrité des fichiers critiques", "Critical file integrity"],
        precision: ["comptes, sudo, SSH, démarrage…", "accounts, sudo, SSH, startup…"],
        mots: "blake3 empreintes fingerprints fichiers files" },
    Outil { action: Action::Entretien, commande: "entretien", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Entretien du mois", "Monthly maintenance"], precision: ["", ""],
        mots: "maintenance mensuel monthly mois month rappel reminder notification" },
    Outil { action: Action::Fiche, commande: "fiche-ordinateur", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Fiche de l'ordinateur", "Computer specs"],
        precision: ["modèle, processeur, mémoire…", "model, processor, memory…"],
        mots: "fiche specs matériel hardware modèle model processeur carte graphique gpu mémoire ram série" },
    Outil { action: Action::ALaisser, commande: "rapport-a-laisser", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Rapport à laisser", "Report to leave behind"],
        precision: ["une page simple, à imprimer", "a simple page, to print"],
        mots: "rapport report imprimer print dépannage help famille family laisser leave page résumé summary" },
    Outil { action: Action::Developpeurs, commande: "", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Pour les développeurs", "For developers"],
        precision: ["secrets git, images Docker", "git secrets, Docker images"],
        mots: "développeur developer programmeur programmer git docker conteneur container" },
    Outil { action: Action::SecretsGit, commande: "secrets", groupe: None, lettre: "",
        titre: ["Secrets dans les projets git", "Secrets in git projects"],
        precision: ["mots de passe et clés oubliés", "forgotten passwords and keys"],
        mots: "secrets git gitleaks clé key api jeton token mot de passe password historique history dépôt \
               repository fuite leak" },
    Outil { action: Action::Conteneurs, commande: "conteneurs", groupe: None, lettre: "",
        titre: ["Failles des images Docker", "Flaws in Docker images"],
        precision: ["failles connues (trivy)", "known flaws (trivy)"],
        mots: "docker podman conteneur container image trivy faille vulnerability cve" },
    Outil { action: Action::LogicielsPerimes, commande: "logiciels-perimes", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Logiciels pas à jour", "Outdated software"],
        precision: ["versions, failles exploitées", "versions, exploited flaws"],
        mots: "logiciel software version périmé outdated mise à jour update navigateur browser chrome edge \
               firefox brave office word excel acrobat reader java kev faille exploitée exploited" },
    Outil { action: Action::OptionsDefense, commande: "options-defense", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Options de défense", "Defense options"],
        precision: ["Defender, règles ASR, pare-feu", "Defender, ASR rules, firewall"],
        mots: "defender antivirus temps réel real-time cloud asr pare-feu firewall exclusion pua couper turn off \
               rallumer turn on falsifications tamper gpo intune stratégie policy options défense defense bloquer \
               block exploit dossiers contrôlés controlled folder ufw firewalld nftables" },
    // 5 Réseau et Internet.
    Outil { action: Action::Appareils, commande: "appareils", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Appareils du réseau", "Devices on the network"],
        precision: ["scan, ports, nouveaux appareils", "scan, ports, new devices"],
        mots: "scan scanner appareils devices ports réseau network nmap" },
    Outil { action: Action::Scanner, commande: "appareils", groupe: None, lettre: "",
        titre: ["Scan du réseau", "Network scan"],
        precision: ["ports courants, nouveaux venus", "common ports, newcomers"],
        mots: "appareils devices ports réseau network lan nmap" },
    Outil { action: Action::Appareil, commande: "appareils", groupe: None, lettre: "",
        titre: ["Tous les ports d'un appareil", "All ports of one device"], precision: ["scan approfondi, plus long", "deep scan, takes longer"],
        mots: "appareils devices ports réseau network lan nmap" },
    Outil { action: Action::AuditReseau, commande: "audit-reseau", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Audit du réseau", "Network audit"],
        precision: ["six notes : routeur, Wi-Fi, DNS…", "six grades: router, Wi-Fi, DNS…"],
        mots: "audit réseau network exposition exposure wifi dns tls segmentation appareils devices objets postes \
               computers upnp redirection note grade cyberdéfense cyberdefense box routeur router" },
    Outil { action: Action::Nommer, commande: "nommer", groupe: Some(Groupe::Reseau), lettre: "n",
        titre: ["Nommer un appareil", "Name a device"], precision: ["« imprimante HP »", "“HP printer”"],
        mots: "surnom nickname" },
    Outil { action: Action::Objets, commande: "objets-connectes", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Routeur et objets connectés", "Router and smart devices"],
        precision: ["modèle, mots de passe d'origine", "model, default passwords"],
        mots: "box routeur router modem objets connectés iot smart caméra camera imprimante printer nas télé tv \
               domotique smart home mot de passe d'origine default password firmware upnp" },
    Outil { action: Action::Cameras, commande: "cameras-cachees", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Caméras cachées ?", "Hidden cameras?"],
        precision: ["location, hébergement", "rentals, short stays"],
        mots: "caméra camera espion spy cachée hidden location rental airbnb rtsp onvif" },
    Outil { action: Action::ListesNoires, commande: "listes-noires", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Adresse publique sur liste noire ?", "Public address on a blocklist?"],
        precision: ["si oui, un appareil est infecté", "if so, a device is infected"],
        mots: "spamhaus botnet liste noire blocklist blacklist dnsbl" },
    Outil { action: Action::Surveillance, commande: "surveillance", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Surveillance toutes les heures", "Hourly monitoring"], precision: ["", ""],
        mots: "monitor surveiller notification" },
    Outil { action: Action::Tableau, commande: "tableau-de-bord", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Tableau de bord", "Dashboard"],
        precision: ["bilan, alertes, appareils, menu", "check, alerts, devices, menu"],
        mots: "tableau dashboard historique history alertes alerts nouveaux new appareils devices botnet \
               connexions suspectes suspicious connections" },
    Outil { action: Action::WifiPublic, commande: "wifi-public", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Mode Wi-Fi public", "Public Wi-Fi mode"],
        precision: ["café, hôtel : allumer, éteindre", "café, hotel: turn on, off"],
        mots: "wifi public café cafe hôtel hotel aéroport airport portail captif captive portal pare-feu firewall \
               partage sharing découverte discovery dns chiffré encrypted" },
    // 6 Virus et logiciels espions.
    Outil { action: Action::Antivirus, commande: "antivirus", groupe: Some(Groupe::Virus), lettre: "",
        titre: ["Analyse antivirus", "Antivirus scan"],
        precision: ["rapide, complète, clé USB, YARA", "quick, full, USB drive, YARA"],
        mots: "antivirus virus analyse scan clamav defender malware" },
    Outil { action: Action::AntivirusRapide, commande: "antivirus", groupe: None, lettre: "",
        titre: ["Analyse rapide", "Quick scan"], precision: ["téléchargements, bureau…", "downloads, desktop…"],
        mots: "virus malware clamav defender" },
    Outil { action: Action::AntivirusComplet, commande: "antivirus", groupe: None, lettre: "",
        titre: ["Analyse complète", "Full scan"], precision: ["dossier perso (Windows : tout)", "home folder (Windows: all of it)"],
        mots: "virus malware clamav defender" },
    Outil { action: Action::AntivirusDossier, commande: "antivirus", groupe: None, lettre: "a",
        titre: ["Clé USB ou dossier", "USB drive or folder"], precision: ["et pièges de clé USB", "and USB drive traps"],
        mots: "virus usb clé autorun" },
    Outil { action: Action::Yara, commande: "yara", groupe: None, lettre: "",
        titre: ["Règles YARA sur un dossier", "YARA rules on a folder"],
        precision: ["logiciels malveillants connus", "known malware"],
        mots: "yara règles rules malware" },
    Outil { action: Action::AntivirusEtat, commande: "antivirus", groupe: None, lettre: "",
        titre: ["État de l'antivirus", "Antivirus status"],
        precision: ["moteur, bases, temps réel", "engine, databases, real time"],
        mots: "état status moteur engine bases databases clamav malwarebazaar yara pua second avis opinion \
               temps réel real time" },
    Outil { action: Action::LogicielsEspions, commande: "logiciels-espions", groupe: Some(Groupe::Virus), lettre: "",
        titre: ["Logiciels espions : en ai-je un ?", "Spyware: is someone watching me?"],
        precision: ["clavier épié, indicateurs Échap", "keyboard spying, Échap indicators"],
        mots: "espion spyware stalkerware logiciel espion keylogger enregistreur de frappe clavier keyboard \
               surveillance monitoring harcèlement stalking échap mspy flexispy contrôle parental parental control" },
    Outil { action: Action::QuiParle, commande: "connexions-sortantes", groupe: Some(Groupe::Virus), lettre: "",
        titre: ["Qui parle à Internet ?", "Who talks to the Internet?"],
        precision: ["connexions de chaque programme", "each program's connections"],
        mots: "connexions connections sortantes outbound espion spyware mouchard télémétrie telemetry serveurs \
               servers" },
    Outil { action: Action::Memoire, commande: "memoire", groupe: Some(Groupe::Virus), lettre: "",
        titre: ["Mémoire des processus", "Process memory"],
        precision: ["YARA sur ce qui tourne", "YARA on what is running"],
        mots: "mémoire memory yara processus sans fichier fileless" },
    Outil { action: Action::Pieges, commande: "pieges", groupe: Some(Groupe::Virus), lettre: "",
        titre: ["Fichiers-pièges anti-rançongiciel", "Ransomware decoy files"],
        precision: ["alerte si un fichier est chiffré", "alert if a file gets encrypted"],
        mots: "rançongiciel ransomware leurre decoy piège trap" },
    Outil { action: Action::VerifierFichier, commande: "verifier-fichier", groupe: Some(Groupe::Virus), lettre: "",
        titre: ["Vérifier un fichier téléchargé", "Check a downloaded file"],
        precision: ["empreinte, YARA, antivirus", "checksum, YARA, antivirus"],
        mots: "sha256 empreinte checksum hash télécharger download iso installateur installer fichier file" },
    Outil { action: Action::Bac, commande: "isoler", groupe: Some(Groupe::Virus), lettre: "b",
        titre: ["Bac à sable : programme inconnu", "Sandbox: run an unknown program"],
        precision: ["sans réseau, isolé", "no network, isolated"],
        mots: "sandbox isoler firejail bubblewrap" },
    Outil { action: Action::Quarantaine, commande: "quarantaine", groupe: Some(Groupe::Virus), lettre: "",
        titre: ["Quarantaine : remettre un fichier", "Quarantine: restore a file"],
        precision: ["isolés, remis à l'identique", "isolated, put back exactly"],
        mots: "quarantaine quarantine isolé isolated faux positif false positive remettre restore restaurer" },
    // 7 Arnaques et vie privée.
    Outil { action: Action::Lien, commande: "lien", groupe: Some(Groupe::Arnaques), lettre: "",
        titre: ["Ce lien est-il dangereux ?", "Is this link dangerous?"],
        precision: ["examiné sans l'ouvrir", "checked without opening it"],
        mots: "url lien link phishing hameçonnage arnaque scam texto sms courriel email domaine domain" },
    Outil { action: Action::CourrielSuspect, commande: "courriel-suspect", groupe: Some(Groupe::Arnaques), lettre: "",
        titre: ["Ce courriel est-il une arnaque ?", "Is this email a scam?"],
        precision: ["examiné sans rien ouvrir", "checked without opening anything"],
        mots: "courriel email mail eml arnaque scam hameçonnage phishing expéditeur sender pièce jointe attachment \
               spf dkim dmarc thunderbird outlook gmail msg usurpation spoofing" },
    Outil { action: Action::Distance, commande: "acces-a-distance", groupe: Some(Groupe::Arnaques), lettre: "",
        titre: ["Mon ordinateur est-il contrôlé ?", "Is my computer being controlled?"],
        precision: ["faux technicien, accès à distance", "tech-support scam, remote access"],
        mots: "arnaque scam faux technicien fake tech support anydesk teamviewer rustdesk accès distance remote \
               access contrôle control prise de contrôle" },
    Outil { action: Action::MotsDePasse, commande: "fuite-mot-de-passe", groupe: Some(Groupe::Arnaques), lettre: "p",
        titre: ["Mots de passe : ont-ils fuité ?", "Passwords: have they leaked?"],
        precision: ["rien n'est envoyé en clair", "nothing sent in clear"],
        mots: "password hibp pwned fuite leak" },
    Outil { action: Action::Navigateurs, commande: "mots-de-passe-navigateurs", groupe: Some(Groupe::Arnaques), lettre: "",
        titre: ["Mots de passe des navigateurs", "Browser passwords"],
        precision: ["comptés, jamais lus", "counted, never read"],
        mots: "navigateur browser firefox chrome edge chromium brave vivaldi mots de passe password \
               enregistrés saved faible weak réutilisé reused fuite leak checkup about:logins" },
    Outil { action: Action::Courriel, commande: "fuite-courriel", groupe: Some(Groupe::Arnaques), lettre: "e",
        titre: ["Courriel : a-t-il fuité ?", "Email address: has it leaked?"],
        precision: ["avec votre accord", "with your consent"],
        mots: "email mail fuite leak" },
    Outil { action: Action::CameraMicro, commande: "camera-micro", groupe: Some(Groupe::Arnaques), lettre: "",
        titre: ["Caméra et micro : qui s'en sert ?", "Camera and mic: who uses them?"],
        precision: ["programmes et dernière fois", "programs and last time"],
        mots: "caméra camera webcam micro microphone espion spy écoute voyant light enregistre record" },
    Outil { action: Action::Acces, commande: "bilan-confidentialite", groupe: Some(Groupe::Arnaques), lettre: "",
        titre: ["Bilan de confidentialité", "Privacy check"],
        precision: ["position, contacts, caméra, micro", "location, contacts, camera, mic"],
        mots: "confidentialité privacy permissions autorisations accès access position location localisation gps \
               contacts carnet address book caméra camera micro microphone flatpak snap tcc applications apps" },
    // 8 Bloquer et réagir : 8.3 à 8.5 mènent aux parcours 11.7, 11.10 et 11.11 (un incident est de la défense).
    Outil { action: Action::Blocage, commande: "blocage", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Blocage des menaces", "Threat blocking"], precision: ["", ""],
        mots: "bloquer block blocage blocking protection active automatique automatic pare-feu firewall arrêter stop \
               processus process quarantaine quarantine malwarebazaar botnet threatfox pilotes drivers annuler undo" },
    Outil { action: Action::SitesDangereux, commande: "sites-dangereux", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Bloquer les sites dangereux", "Block dangerous sites"],
        precision: ["fichier hosts, annulable", "hosts file, undoable"],
        mots: "bloquer block sites dangereux dangerous malveillant malicious hosts urlhaus threatfox botnet \
               hameçonnage phishing" },
    Outil { action: Action::DepannerInfection, commande: "depanner", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Après une infection, pas à pas", "After an infection, step by step"],
        precision: ["raccourci vers 11.7", "shortcut to 11.7"],
        mots: "infection infecté infected virus incident nettoyer" },
    Outil { action: Action::DepannerCompte, commande: "depanner", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Compte piraté, pas à pas", "Hacked account, step by step"],
        precision: ["raccourci vers 11.10", "shortcut to 11.10"],
        mots: "piraté hacked compte account mot de passe password" },
    Outil { action: Action::Traces, commande: "depanner", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Collecter les traces", "Collect the evidence"],
        precision: ["avant de nettoyer, daté", "before cleaning up, dated"],
        mots: "traces evidence preuves forensics incident chronologie timeline" },
    Outil { action: Action::Evenements, commande: "evenements", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Journal des évènements", "Event log"],
        precision: ["alertes, blocages, incidents", "alerts, blocks, incidents"],
        mots: "journal log événements events évènements alertes alerts incidents" },
    Outil { action: Action::Changements, commande: "changements", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Ce que Vanguard a changé", "What Vanguard changed"],
        precision: ["chaque correction, datée", "each fix, dated"],
        mots: "changements changes historique history corrections fixes journal log annuler undo" },
    Outil { action: Action::OptimiserAnnuler, commande: "annuler", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Tout remettre comme avant", "Put everything back"],
        precision: ["annule ce que Vanguard a changé", "undo what Vanguard changed"],
        mots: "annuler undo restaurer" },
    Outil { action: Action::Signaler, commande: "signaler", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Signaler une faille à un éditeur", "Report a flaw to a vendor"],
        precision: ["rien n'est envoyé, vous relisez", "nothing is sent, you review"],
        mots: "signaler disclose signalement report divulgation disclosure faille vulnerability bogue bug éditeur \
               vendor msrc microsoft google chrome mozilla bugzilla apple ghsa github cert prime bounty" },
    // Avant le veilleur, propre à Linux : les lignes communes gardent leur place sous les trois systèmes.
    Outil { action: Action::JournauxWindows, commande: "journaux-windows", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Journaux de Windows", "Windows logs"],
        precision: ["que s'est-il passé ?", "what happened?"],
        mots: "journaux logs windows événements events evtx observateur viewer que s'est-il passé what happened \
               chronologie timeline effacé cleared tâche task processus process attaque attack" },
    Outil { action: Action::Veilleur, commande: "veilleur", groupe: Some(Groupe::Reagir), lettre: "",
        titre: ["Veilleur : lancements, connexions, fichiers", "Watcher: launches, connections, files"], precision: ["", ""],
        mots: "veilleur watcher lancements launches processus processes connexions connections brèves brief \
               connecteur connector temps réel live fichiers files fanotify téléchargements downloads" },
    // 9 Données et sauvegardes : les fichiers de la personne.
    Outil { action: Action::CopierFichiers, commande: "copier-fichiers", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Copier mes fichiers", "Copy my files"],
        precision: ["vers un disque externe, vérifié", "to an external disk, checked"],
        mots: "copier copy sauvegarde backup photos disque externe external drive fichiers" },
    Outil { action: Action::SauvegardeAuto, commande: "sauvegarde-auto", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Sauvegarde automatique", "Automatic backup"],
        precision: ["chaque jour, sur un autre disque", "every day, to an external disk"],
        mots: "sauvegarde backup automatique automatic time machine historique des fichiers file history deja dup \
               rsync disque externe external drive" },
    Outil { action: Action::VerifierCopies, commande: "", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Vérifier une copie ou sauvegarde", "Check a copy or backup"],
        precision: ["relue, comparée aux originaux", "read back, compared to originals"],
        mots: "vérifier check copie copy sauvegarde backup" },
    Outil { action: Action::VerifierSauvegarde, commande: "verifier-sauvegarde", groupe: None, lettre: "",
        titre: ["La sauvegarde automatique", "The automatic backup"],
        precision: ["relue pour de vrai", "actually read back"],
        mots: "sauvegarde backup vérifier verify restauration restore test rsync time machine" },
    Outil { action: Action::VerifierCopie, commande: "verifier-copie", groupe: None, lettre: "",
        titre: ["Une copie (un dossier)", "A copy (a folder)"],
        precision: ["comparée aux originaux", "compared to the originals"],
        mots: "restauration restore test vérifier verify copie copy sauvegarde backup relire" },
    Outil { action: Action::VerifierCle, commande: "verifier-cle", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Vérifier une clé USB ou un disque", "Check a USB drive or a disk"],
        precision: ["vraie capacité, vitesse, erreurs", "real capacity, speed, errors"],
        mots: "clé key usb fausse fake capacité capacity vitesse speed débit secteurs sectors erreurs errors f3 h2testw \
               disque externe external drive" },
    // 10 et 11 s'ouvrent directement ; 11.13 et 11.14 suivent les douze parcours.
    Outil { action: Action::Guide, commande: "guide", groupe: Some(Groupe::Guide), lettre: "",
        titre: ["Guide des commandes", "Command guide"],
        precision: ["Linux, Windows, tous", "Linux, Windows, all"],
        mots: "commandes commands terminal aide help" },
    Outil { action: Action::Depanner, commande: "depanner", groupe: Some(Groupe::Depanner), lettre: "",
        titre: ["Dépanner pas à pas", "Troubleshoot step by step"],
        precision: ["Internet, son, imprimante…", "Internet, sound, printer…"],
        mots: "dépanner troubleshoot panne problème internet son imprimante" },
    Outil { action: Action::Reparer, commande: "reparer", groupe: Some(Groupe::Depanner), lettre: "r",
        titre: ["Réparer une panne connue", "Repair a known problem"],
        precision: ["Internet, disque, mises à jour…", "Internet, disk, updates…"],
        mots: "internet wifi dns proxy hosts pare-feu firewall antivirus disque disk smart heure time sfc dism \
               winsock" },
    Outil { action: Action::Diagnostic, commande: "diagnostic", groupe: Some(Groupe::Depanner), lettre: "o",
        titre: ["Diagnostic du matériel", "Hardware diagnostics"], precision: ["matériel, plantages, erreurs", "hardware, crashes, errors"],
        mots: "plantages crashes erreurs errors écran bleu bsod journal logs matériel hardware" },
    // 12 Optimiser et installer : 12.11 à 12.13 selon le système.
    Outil { action: Action::Logiciels, commande: "logiciels", groupe: Some(Groupe::Optimiser), lettre: "l",
        titre: ["Logiciels recommandés", "Recommended software"], precision: ["les meilleurs, par catégorie", "the best ones, by category"],
        mots: "apps programmes programs installer install firefox vlc libreoffice" },
    Outil { action: Action::Nettoyer, commande: "nettoyer", groupe: Some(Groupe::Optimiser), lettre: "v",
        titre: ["Nettoyer le système", "Clean up the system"],
        precision: ["caches, temporaires, corbeille…", "caches, temp files, trash…"],
        mots: "place space disque plein disk full cache corbeille trash" },
    Outil { action: Action::Lenteur, commande: "lenteur", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Pourquoi c'est lent ?", "Why is it slow?"],
        precision: ["processeur, mémoire, démarrage", "processor, memory, startup"],
        mots: "lent slow lenteur rame processeur cpu mémoire memory ram démarrage startup" },
    Outil { action: Action::Demarrage, commande: "demarrage", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Programmes au démarrage", "Startup programs"],
        precision: ["ce qui se lance tout seul", "what starts on its own"],
        mots: "démarrage startup autostart login lancement" },
    Outil { action: Action::OptimiserRecommandes, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Réglages recommandés", "Recommended settings"],
        precision: ["en une fois, tout s'annule", "in one go, all undoable"],
        mots: "réglages settings" },
    Outil { action: Action::Gaming, commande: "jeux", groupe: Some(Groupe::Optimiser), lettre: "g",
        titre: ["Jeux vidéo", "Gaming"],
        precision: if cfg!(windows) { ["composants et réglages de Windows", "components and Windows settings"] }
            else { ["Steam, Vulkan, GameMode, Wine…", "Steam, Vulkan, GameMode, Wine…"] },
        mots: "jeux games steam directx vulkan" },
    Outil { action: Action::DnsRapide, commande: "dns-rapide", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["DNS le plus rapide", "Fastest DNS"], precision: ["mesuré ici, annulable", "measured here, undoable"],
        mots: "dns rapide fast résolveur resolver cloudflare quad9 google adguard vitesse speed" },
    Outil { action: Action::Connexion, commande: "test-connexion", groupe: Some(Groupe::Optimiser), lettre: "c",
        titre: ["Test de connexion", "Connection test"],
        precision: ["ping, gigue, débit, bufferbloat", "ping, jitter, speed, bufferbloat"],
        mots: "ping latence latency débit speed jitter gigue bufferbloat jeu" },
    Outil { action: Action::Nat, commande: "nat", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Type de NAT pour le jeu", "NAT type for gaming"],
        precision: ["ouvert, modéré ou strict", "open, moderate or strict"],
        mots: "nat stun upnp console xbox playstation jeu game multijoueur multiplayer redirection port forwarding \
               ouvert open modéré moderate strict" },
    Outil { action: Action::WifiCanaux, commande: "canaux-wifi", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Wi-Fi encombré ?", "Crowded Wi-Fi?"],
        precision: ["canaux voisins, le plus libre", "nearby channels, the freest"],
        mots: "wifi canal canaux channel encombré crowded interférences interference voisins neighbors signal box \
               router" },
    Outil { action: Action::OptimiserConfidentialite, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Réglages de confidentialité", "Privacy settings"],
        precision: if cfg!(windows) { ["télémétrie, publicités, suivi", "telemetry, ads, tracking"] }
            else { ["rapports et statistiques", "reports and statistics"] },
        mots: "télémétrie telemetry vie privée privacy publicité ads" },
    Outil { action: Action::OptimiserConfort, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Confort et fichiers", "Comfort and files"],
        precision: if cfg!(windows) { ["extensions, clés USB, clic droit", "extensions, USB drives, menus"] }
            else { ["annonces d'Ubuntu", "Ubuntu announcements"] },
        mots: "extensions fichiers cachés hidden files" },
    Outil { action: Action::OptimiserPerformance, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Performance et fiabilité", "Performance and reliability"],
        precision: if cfg!(windows) { ["démarrage rapide, widgets…", "fast startup, widgets…"] }
            else { ["SSD, taille du journal", "SSD, journal size"] },
        mots: "ssd démarrage startup journal" },
    // 13 Vanguard : ses réglages, sa mise à jour, ce qu'il a posé ici ; « s » ouvre aussi Paramètres.
    Outil { action: Action::Parametres, commande: "parametres", groupe: Some(Groupe::Vanguard), lettre: "s",
        titre: ["Paramètres", "Settings"],
        precision: ["langue, surveillance, blocage…", "language, monitoring, blocking…"],
        mots: "paramètres settings réglages options préférences preferences langue language emojis internet \
               hors ligne offline surveillance monitoring entretien maintenance appris learned blocage blocking \
               restrictions temps réel real-time realtime pause" },
    Outil { action: Action::Appris, commande: "appris", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Ce que Vanguard a appris", "What Vanguard has learned"],
        precision: ["vos choix, vos habitudes", "your choices, your habits"],
        mots: "apprentissage learning appris learned choix choices normal oublier forget" },
    Outil { action: Action::MettreAJour, commande: "se-mettre-a-jour", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Mettre Vanguard à jour", "Update Vanguard"],
        precision: ["sur cet ordinateur, depuis la clé", "on this computer, from the key"],
        mots: "mise à jour mettre update upgrade vanguard version nouvelle new copie copy installer install" },
    Outil { action: Action::VerifierVanguard, commande: "", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Vérifier Vanguard lui-même", "Verify Vanguard itself"],
        precision: ["empreinte, signature, autotest", "hash, signature, self-test"],
        mots: "vérifier verify empreinte hash signature autotest self-test" },
    Outil { action: Action::VerifierMoi, commande: "verifier-moi", groupe: None, lettre: "",
        titre: ["Empreinte du programme", "Program hash"],
        precision: ["à comparer à la page de la version", "to compare with the release page"],
        mots: "empreinte hash sha256 signature version" },
    Outil { action: Action::Autotest, commande: "autotest", groupe: None, lettre: "",
        titre: ["Autotest des règles", "Rule self-test"],
        precision: ["chaque règle, sans rien changer", "every rule, changing nothing"],
        mots: "autotest self-test règles rules" },
    Outil { action: Action::Regles, commande: "regles", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Règles du bilan", "Check rules"],
        precision: ["identifiants, références CIS", "IDs, CIS references"],
        mots: "règles rules cis anssi références references" },
    Outil { action: Action::Ordinateurs, commande: "ordinateurs", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Mes ordinateurs", "My computers"],
        precision: ["suivis par la clé VANGUARD", "tracked by the VANGUARD key"],
        mots: "ordinateurs computers tableau dashboard suivi parc famille family clé key" },
    Outil { action: Action::ProtegerDonnees, commande: "", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Protéger les données de la clé", "Protect the drive's data"],
        precision: ["carnet chiffré par une phrase", "record encrypted by a passphrase"],
        mots: "chiffrer encrypt chiffrement encryption phrase passphrase mot de passe password protéger protect \
               perdue lost" },
    Outil { action: Action::Sauvegarder, commande: "exporter", groupe: Some(Groupe::Vanguard), lettre: "d",
        titre: ["Exporter ou importer les réglages", "Export or import settings"],
        precision: ["appareils nommés, préférences", "named devices, preferences"],
        mots: "backup restore sauvegarde base" },
    Outil { action: Action::Raccourci, commande: "raccourci", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Raccourci sur cet ordinateur", "Shortcut on this computer"],
        precision: ["lancer Vanguard d'un clic", "start Vanguard with one click"],
        mots: "raccourci shortcut bureau desktop installer install menu lancer launch icône icon" },
    Outil { action: Action::Extensions, commande: "extensions", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Extensions", "Extensions"],
        precision: ["plugins et scripts, hors Vanguard", "plugins and scripts, not Vanguard"],
        mots: "plugin plugins extension module ajouter add expérimental experimental script labo lab laboratoire \
               programme program essai test" },
    Outil { action: Action::Desinstaller, commande: "desinstaller", groupe: Some(Groupe::Vanguard), lettre: "",
        titre: ["Retirer Vanguard de cet ordinateur", "Remove Vanguard from this computer"],
        precision: ["ce qu'il a posé, montré d'abord", "what it placed, shown first"],
        mots: "désinstaller uninstall désinstallation retirer remove supprimer delete effacer erase installer install \
               installé installed" },
];

// Une action ajoutée sans sa ligne décalerait toutes les suivantes : la compilation s'arrête.
#[cfg_attr(
    all(target_os = "linux", not(test)),
    expect(
        clippy::as_conversions,
        reason = "le rang d'une variante : seul `as` le donne, et en constante"
    )
)]
const _: () = assert!(OUTILS.len() == Action::Desinstaller as usize + 1);

/// La précision de la ligne Surveillance. Le temps réel coupé, la minuterie est là, mais chaque passe s'arrête au
/// début : « activée » seul le cacherait.
pub(crate) fn precision_surveillance(active: bool, temps_reel_coupe: bool) -> &'static str {
    match (active, temps_reel_coupe) {
        (true, true) => tr!("activée, en pause (temps réel)", "on, paused (real-time off)"),
        (true, false) => tr!("activée", "on"),
        (false, _) => tr!("désactivée", "off"),
    }
}

/// La précision de la ligne du veilleur, qui n'existe que sous Linux.
fn precision_veilleur() -> &'static str {
    #[cfg(target_os = "linux")]
    return machine::linux::veilleur::precision();
    #[cfg(not(target_os = "linux"))]
    ""
}

/// Le garde des lancements : fanotify, du noyau Linux ; ailleurs, la commande le dit.
pub(crate) fn garde(action: Option<&str>, argument: Option<&str>) {
    #[cfg(target_os = "linux")]
    machine::linux::garde::compte::commande(action, argument);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (action, argument);
        trp!(
            "Le garde des lancements n'existe que sous Linux : il s'appuie sur fanotify, du noyau Linux.",
            "The launch guard exists only on Linux: it relies on fanotify, from the Linux kernel."
        );
    }
}

/// Le veilleur : il lit deux flux du noyau Linux ; ailleurs, la commande le dit.
pub(crate) fn veilleur(etat: Option<&str>, sous_etat: Option<&str>, servir: bool) {
    #[cfg(target_os = "linux")]
    machine::linux::veilleur::commande(etat, sous_etat, servir);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (etat, sous_etat, servir);
        trp!(
            "Le veilleur n'existe que sous Linux : il lit deux flux du noyau Linux (programmes lancés, connexions fermées). Ici, la surveillance horaire prend une photo par heure : vanguard surveillance on.",
            "The watcher exists only on Linux: it reads two Linux kernel streams (programs started, connections closed). Here, hourly monitoring takes one snapshot an hour: vanguard monitor on."
        );
    }
}

impl Action {
    pub(crate) fn outil(self) -> &'static Outil {
        #[expect(
            clippy::indexing_slicing,
            reason = "Desinstaller est la dernière variante et l'assertion const sous OUTILS fixe OUTILS.len() à Desinstaller + 1"
        )]
        #[cfg_attr(
            all(target_os = "linux", not(test)),
            expect(
                clippy::as_conversions,
                reason = "le rang d'une variante sans valeur : seul `as` le donne"
            )
        )]
        &OUTILS[self as usize]
    }

    /// Un outil qui ouvre ses propres écrans, marqué « › » comme un écran à choix.
    pub(crate) fn ouvre_ses_ecrans(self) -> bool {
        matches!(self, Action::Logiciels | Action::Gaming | Action::Extensions)
    }

    /// Les variantes de son écran à choix (aucune : un outil ordinaire).
    pub(crate) fn variantes(self) -> &'static [Action] {
        ECRANS.iter().find(|(e, _)| *e == self).map_or(&[], |(_, v)| v)
    }

    /// Ce que l'aperçu du menu dit qu'il ouvre, quand ce ne sont pas des lignes du menu : les variantes de son écran à
    /// choix, les catégories des logiciels recommandés (sinon l'aperçu prendrait un logiciel de chacune pour son nom).
    pub(crate) fn ce_qu_il_ouvre(self) -> Vec<String> {
        if self == Action::Logiciels {
            return logiciels::rubriques();
        }
        self.variantes()
            .iter()
            .filter(|v| v.disponible())
            .map(|v| v.libelle().0.to_string())
            .collect()
    }

    /// Texte de la ligne de menu et sa précision en gris.
    pub(crate) fn libelle(self) -> (&'static str, &'static str) {
        let precision = match self {
            Action::Entretien if entretien::active() => tr!("activé : une notification", "on: one notification"),
            Action::Entretien => tr!("désactivé", "off"),
            Action::Surveillance => precision_surveillance(
                reseau::surveillance::active(),
                protection::temps_reel::coupure().is_some(),
            ),
            Action::Blocage => protection::blocage::etat_court(),
            Action::Veilleur => precision_veilleur(),
            Action::WifiPublic => reseau::wifi_public::etat_court(),
            Action::OptionsDefense if cfg!(target_os = "linux") => {
                tr!("pare-feu ufw, firewalld, nftables", "ufw, firewalld, nftables firewall")
            }
            _ => texte(self.outil().precision),
        };
        (texte(self.outil().titre), precision)
    }

    /// L'outil a-t-il quelque chose à proposer sur ce système ? (une catégorie de réglages vide n'est pas montrée)
    pub(crate) fn disponible(self) -> bool {
        match self {
            Action::OptimiserConfidentialite => reglages_disponibles(optimiser::Categorie::Confidentialite),
            Action::OptimiserPerformance => reglages_disponibles(optimiser::Categorie::Performance),
            Action::OptimiserConfort => reglages_disponibles(optimiser::Categorie::Confort),
            // Defender, le pare-feu et le registre de Windows ; sous Linux, le pare-feu (ufw, firewalld, nftables).
            Action::OptionsDefense => cfg!(any(windows, target_os = "linux")),
            // Deux flux du noyau Linux : ailleurs, la ligne ne serait que du bruit.
            Action::Veilleur => cfg!(target_os = "linux"),
            // Sous Linux, le gestionnaire de paquets et le catalogue de la CISA (bilan, Failles connues) s'en chargent.
            Action::LogicielsPerimes => cfg!(windows),
            _ => true,
        }
    }

    /// Après l'outil, attendre Entrée avant de revenir au menu ? Pas pour ceux qui ont leurs propres écrans et se
    /// quittent par Échap (le guide, le dépannage) : on y reviendrait deux fois.
    pub(crate) fn attendre_apres(self) -> bool {
        !matches!(
            self,
            Action::Guide | Action::Depanner | Action::QuiParle | Action::Extensions | Action::Parametres
        ) && self.variantes().is_empty()
    }
}

/// Un texte de la table dans la langue de l'interface.
pub(crate) fn texte([fr, en]: [&'static str; 2]) -> &'static str {
    if langue::anglais() { en } else { fr }
}

/// Un groupe d'outils du menu principal, ouvert en sous-menu : la cyberdéfense (4 à 8), puis le reste (9 à 13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Groupe {
    Ordinateur,
    Reseau,
    Virus,
    Arnaques,
    Reagir,
    Donnees,
    Guide,
    Depanner,
    Optimiser,
    Vanguard,
}

pub(crate) const GROUPES: [Groupe; 10] = [
    Groupe::Ordinateur,
    Groupe::Reseau,
    Groupe::Virus,
    Groupe::Arnaques,
    Groupe::Reagir,
    Groupe::Donnees,
    Groupe::Guide,
    Groupe::Depanner,
    Groupe::Optimiser,
    Groupe::Vanguard,
];

/// Le premier groupe de la section « EN PLUS » du menu principal : avant lui, la cyberdéfense.
pub(crate) const PREMIER_EN_PLUS: Groupe = Groupe::Donnees;

/// Les écrans à choix : une ligne du groupe (« 6.1 Analyse antivirus › ») qui ouvre ses variantes (6.1.1 à 6.1.4).
/// Une variante n'a pas de groupe : elle n'est que dans son écran, joignable aussi par son chemin et la recherche.
pub(crate) const ECRANS: &[(Action, &[Action])] = &[
    (Action::Developpeurs, &[Action::SecretsGit, Action::Conteneurs]),
    (Action::Appareils, &[Action::Scanner, Action::Appareil]),
    (
        Action::Antivirus,
        &[
            Action::AntivirusRapide,
            Action::AntivirusComplet,
            Action::AntivirusDossier,
            Action::Yara,
            Action::AntivirusEtat,
        ],
    ),
    (
        Action::VerifierCopies,
        &[Action::VerifierSauvegarde, Action::VerifierCopie],
    ),
    (Action::VerifierVanguard, &[Action::VerifierMoi, Action::Autotest]),
];

impl Groupe {
    pub(crate) fn titre(self) -> &'static str {
        texte(self.titres())
    }

    /// Son titre en français et en anglais (le guide des commandes en a besoin dans les deux langues).
    pub(crate) fn titres(self) -> [&'static str; 2] {
        match self {
            Groupe::Ordinateur => ["Cet ordinateur", "This computer"],
            Groupe::Reseau => ["Réseau et Internet", "Network and Internet"],
            Groupe::Virus => ["Virus et logiciels espions", "Viruses and spyware"],
            Groupe::Arnaques => ["Arnaques et vie privée", "Scams and privacy"],
            Groupe::Reagir => ["Bloquer et réagir", "Block and respond"],
            Groupe::Donnees => ["Données et sauvegardes", "Data and backups"],
            Groupe::Guide => ["Guide des commandes", "Command guide"],
            Groupe::Depanner => ["Dépanner pas à pas", "Step-by-step troubleshooting"],
            Groupe::Optimiser => ["Optimiser et installer", "Optimize and install"],
            Groupe::Vanguard => ["Vanguard", "Vanguard"],
        }
    }

    pub(crate) fn resume(self) -> &'static str {
        match self {
            Groupe::Ordinateur => tr!("failles, mises à jour, intégrité", "flaws, updates, integrity"),
            Groupe::Reseau => tr!("routeur, Wi-Fi, objets connectés", "router, Wi-Fi, smart devices"),
            Groupe::Virus => tr!("antivirus, espions, rançongiciels", "antivirus, spyware, ransomware"),
            Groupe::Arnaques => tr!("liens, courriels, mots de passe", "links, emails, passwords"),
            Groupe::Reagir => tr!("blocage, incident, tout annuler", "blocking, incidents, undo all"),
            Groupe::Donnees => tr!("copier, sauvegarder, vérifier", "copy, back up, verify"),
            Groupe::Guide => tr!("Linux, Windows, pas à pas", "Linux, Windows, how-tos"),
            Groupe::Depanner => tr!("Internet, son, lenteur, réparer", "Internet, sound, slowness, repair"),
            Groupe::Optimiser => tr!("logiciels, nettoyage, réglages", "software, cleanup, settings"),
            Groupe::Vanguard => tr!("réglages, mise à jour, extensions", "settings, update, extensions"),
        }
    }

    /// Ouvert directement, sans sous-menu : son premier outil a ses propres écrans (le guide, les parcours).
    pub(crate) fn direct(self) -> bool {
        matches!(self, Groupe::Guide | Groupe::Depanner)
    }

    /// Ses outils, dans l'ordre du sous-menu.
    pub(crate) fn actions(self) -> Vec<Action> {
        OUTILS
            .iter()
            .filter(|o| o.groupe == Some(self))
            .map(|o| o.action)
            .collect()
    }
}

/// Chaque place du menu et son outil, dans l'ordre de l'écran : « 4.1 », « 4.8.2 » (une variante de l'écran à choix
/// 4.8), « 11.13 » (après les douze parcours de Dépanner). Une seule liste pour les chemins tapés, la recherche et les
/// places annoncées (`touche_de`) ; un outil sans rien à proposer sur ce système n'y est pas, et ne décale rien après
/// lui que les lignes de fin de groupe, propres à un système.
pub(crate) fn places() -> Vec<(String, Action)> {
    let mut places = Vec::new();
    for (i, groupe) in GROUPES.iter().enumerate() {
        let cle = i.saturating_add(4);
        let actions = groupe.actions().into_iter().filter(|a| a.disponible());
        if *groupe == Groupe::Depanner {
            // Le groupe s'ouvre sur les parcours (11.1 à 11.12) ; ses autres outils les suivent.
            let parcours = depanner::nombre_de_parcours();
            for (j, a) in actions.filter(|a| *a != Action::Depanner).enumerate() {
                places.push((format!("{cle}.{}", parcours.saturating_add(j).saturating_add(1)), a));
            }
            continue;
        }
        if groupe.direct() {
            continue;
        }
        for (j, a) in actions.enumerate() {
            places.push((format!("{cle}.{}", j.saturating_add(1)), a));
            for (k, v) in a.variantes().iter().copied().filter(|v| v.disponible()).enumerate() {
                places.push((format!("{cle}.{}.{}", j.saturating_add(1), k.saturating_add(1)), v));
            }
        }
    }
    places
}

/// La valeur d'un interrupteur, dans les mots de l'une ou l'autre langue : « on » (oui, marche, yes), « off » (non,
/// arret, no) ou « etat » (status : le dire sans rien changer). Un seul analyseur pour surveillance, entretien,
/// veilleur, raccourci, sites-dangereux et wifi-public.
pub(crate) fn interrupteur(mot: &str) -> Result<String, String> {
    match selection::simplifier(mot.trim()).as_str() {
        "on" | "oui" | "o" | "marche" | "yes" | "y" | "activer" => Ok("on".into()),
        "off" | "non" | "n" | "arret" | "no" | "desactiver" => Ok("off".into()),
        "etat" | "status" | "state" => Ok("etat".into()),
        _ => Err(trf!(
            "« {} » : oui ou non (on, off ; marche, arret), ou etat",
            "“{}”: on or off (yes, no), or status",
            ui::affichable(mot)
        )),
    }
}

/// « etat » ne change rien : comme sans valeur, la commande dit son état (jamais lu comme « off »).
pub(crate) fn sans_etat(valeur: Option<&str>) -> Option<&str> {
    valeur.filter(|v| *v != "etat")
}

/// Le veilleur prend aussi « rancongiciel » (ransomware), pour la surveillance en direct des dossiers, « connus »
/// (known), pour l'arrêt du malware connu à son lancement, et « isolement » (isolation), pour l'isolement du réseau
/// pendant la réponse à un rançongiciel (défense R5).
pub(crate) fn interrupteur_veilleur(mot: &str) -> Result<String, String> {
    match selection::simplifier(mot.trim()).as_str() {
        "rancongiciel" | "ransomware" => Ok("rancongiciel".into()),
        "connus" | "connu" | "known" => Ok("connus".into()),
        "isolement" | "isolation" => Ok("isolement".into()),
        _ => interrupteur(mot),
    }
}

/// Le mode Wi-Fi public prend aussi « portail » (portal), pour la page de connexion d'un café ou d'un hôtel.
pub(crate) fn interrupteur_wifi_public(mot: &str) -> Result<String, String> {
    match selection::simplifier(mot.trim()).as_str() {
        "portail" | "portal" => Ok("portail".into()),
        _ => interrupteur(mot),
    }
}

/// Les interrupteurs de protection : un identifiant stable (pour `--json`), leur nom et leur état, dans la langue du
/// moment. Le veilleur n'existe que sous Linux.
pub(crate) fn interrupteurs() -> Vec<(&'static str, &'static str, String)> {
    let oui_non = |b: bool| {
        if b {
            tr!("activé", "on")
        } else {
            tr!("désactivé", "off")
        }
    };
    let mut lignes = vec![
        (
            "temps-reel",
            tr!("Protection en temps réel", "Real-time protection"),
            protection::temps_reel::valeur(),
        ),
        (
            "surveillance",
            tr!("Surveillance toutes les heures", "Hourly monitoring"),
            precision_surveillance(
                reseau::surveillance::active(),
                protection::temps_reel::coupure().is_some(),
            )
            .to_string(),
        ),
        (
            "entretien",
            tr!("Entretien du mois", "Monthly maintenance"),
            oui_non(entretien::active()).to_string(),
        ),
        (
            "blocage",
            tr!("Blocage des menaces", "Threat blocking"),
            protection::blocage::etat_court().to_string(),
        ),
    ];
    if cfg!(target_os = "linux") {
        lignes.push(("veilleur", tr!("Veilleur", "Watcher"), precision_veilleur().to_string()));
    }
    lignes.extend([
        (
            "sites-dangereux",
            tr!("Sites dangereux bloqués", "Dangerous sites blocked"),
            oui_non(protection::sites_bloques::bloc_present()).to_string(),
        ),
        (
            "wifi-public",
            tr!("Mode Wi-Fi public", "Public Wi-Fi mode"),
            reseau::wifi_public::etat_court().to_string(),
        ),
        (
            "raccourci",
            tr!("Raccourci sur cet ordinateur", "Shortcut on this computer"),
            oui_non(raccourci::chemin().is_some_and(|c| c.exists())).to_string(),
        ),
    ]);
    lignes
}

/// `vanguard protection --json` : les interrupteurs, sans rien changer ni verser au journal (un état, pas un examen).
pub(crate) fn interrupteurs_json(lignes: &[(&str, &str, String)]) -> String {
    let liste: Vec<serde_json::Value> = lignes
        .iter()
        .map(|(id, nom, etat)| serde_json::json!({"interrupteur": id, "nom": nom, "etat": etat}))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "interrupteurs": liste })).unwrap_or_default()
}

/// `vanguard protection` : chaque interrupteur de protection et son état, en un écran.
pub(crate) fn etat_de_la_protection() {
    titre(tr!("Protection : les interrupteurs", "Protection: the switches"));
    for (_, nom, etat) in interrupteurs() {
        println!("  {:<32} {etat}", format!("{nom} :"));
    }
    trp!(
        "\n  {GRIS}vanguard protection non [--pendant 1h|4h] : couper d'un coup la protection en temps réel ; oui : la remettre.{RESET}",
        "\n  {GRIS}vanguard protection off [--for 1h|4h]: turn real-time protection off at once; on: turn it back on.{RESET}"
    );
}
