//! La liste fermée : les seules commandes de `vanguard` que la fenêtre sait lancer, chacune avec ses arguments
//! fixés ici, dans le code. Un clic ou une saisie choisit une entrée de cette liste, jamais un texte : aucun argument
//! libre ne part vers `vanguard`, et une saisie qui n'est pas un nom de la liste ne lance rien. Lot 1 : des commandes
//! qui ne changent rien à l'ordinateur (elles lisent, et notent leur résultat dans les données de Vanguard).

use std::time::Duration;

/// Les rubriques du rail, dans l'ordre du menu de Vanguard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rubrique {
    Accueil,
    Ordinateur,
    Reseau,
    Virus,
    Arnaques,
    Bloquer,
    Donnees,
    Guide,
    Depanner,
    Optimiser,
    Vanguard,
}

impl Rubrique {
    pub const TOUTES: [Rubrique; 11] = [
        Rubrique::Accueil,
        Rubrique::Ordinateur,
        Rubrique::Reseau,
        Rubrique::Virus,
        Rubrique::Arnaques,
        Rubrique::Bloquer,
        Rubrique::Donnees,
        Rubrique::Guide,
        Rubrique::Depanner,
        Rubrique::Optimiser,
        Rubrique::Vanguard,
    ];

    /// Le nom du rail, coupé en lignes courtes.
    pub fn nom_court(self) -> &'static str {
        match self {
            Rubrique::Accueil => crate::tr!("Menu\nprincipal", "Main\nmenu"),
            Rubrique::Ordinateur => crate::tr!("Cet\nordinateur", "This\ncomputer"),
            Rubrique::Reseau => crate::tr!("Réseau et\nInternet", "Network and\nInternet"),
            Rubrique::Virus => crate::tr!("Virus et\nlogiciels\nespions", "Viruses\nand\nspyware"),
            Rubrique::Arnaques => crate::tr!("Arnaques et\nvie privée", "Scams and\nprivacy"),
            Rubrique::Bloquer => crate::tr!("Bloquer et\nréagir", "Block and\nrespond"),
            Rubrique::Donnees => crate::tr!("Données et\nsauvegardes", "Data and\nbackups"),
            Rubrique::Guide => crate::tr!("Guide des\ncommandes", "Command\nguide"),
            Rubrique::Depanner => crate::tr!("Dépanner\npas à pas", "Step-by-step\nhelp"),
            Rubrique::Optimiser => crate::tr!("Optimiser et\ninstaller", "Optimize and\ninstall"),
            Rubrique::Vanguard => "Vanguard",
        }
    }

    /// Le nom en titre, sur une ligne.
    pub fn nom(self) -> &'static str {
        match self {
            Rubrique::Accueil => crate::tr!("Vue d'ensemble", "Overview"),
            Rubrique::Ordinateur => crate::tr!("Cet ordinateur", "This computer"),
            Rubrique::Reseau => crate::tr!("Réseau et Internet", "Network and Internet"),
            Rubrique::Virus => crate::tr!("Virus et logiciels espions", "Viruses and spyware"),
            Rubrique::Arnaques => crate::tr!("Arnaques et vie privée", "Scams and privacy"),
            Rubrique::Bloquer => crate::tr!("Bloquer et réagir", "Block and respond"),
            Rubrique::Donnees => crate::tr!("Données et sauvegardes", "Data and backups"),
            Rubrique::Guide => crate::tr!("Guide des commandes", "Command guide"),
            Rubrique::Depanner => crate::tr!("Dépanner pas à pas", "Step-by-step help"),
            Rubrique::Optimiser => crate::tr!("Optimiser et installer", "Optimize and install"),
            Rubrique::Vanguard => "Vanguard",
        }
    }

    /// Les commandes de la liste rangées dans cette rubrique, celles de ce système seulement.
    pub fn commandes(self) -> impl Iterator<Item = Commande> {
        Commande::ici().filter(move |c| c.rubrique() == self)
    }
}

/// La forme de ce que la commande écrit sur sa sortie : la fenêtre choisit son lecteur d'après elle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Forme {
    /// `audit --json` : note, fiabilité, constats.
    Audit,
    /// Le résultat commun des outils (`modele::resultat` de Vanguard) : couverture et constats.
    Resultat,
    /// `protection --json` : les interrupteurs.
    Protection,
    /// `evenements --json` : le journal.
    Evenements,
    /// `appareils --json` : le scan du réseau local (`donnees::appareils`).
    Appareils,
    /// `audit-reseau --json` : six domaines, chacun ses constats, sa note retenue quand il est incomplet.
    AuditReseau,
    /// Un autre JSON, montré tel quel (clés et valeurs), borné.
    Libre,
}

/// Une commande de la liste fermée.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Commande {
    Bilan,
    Protection,
    Evenements,
    Diagnostic,
    TestConnexion,
    ConnexionsSortantes,
    AccesADistance,
    LogicielsEspions,
    LogicielsPerimes,
    BilanConfidentialite,
    Lenteur,
    FicheOrdinateur,
    OptionsDefense,
    Antivirus,
    EtatAntivirus,
    Yara,
    Memoire,
    Integrite,
    DernieresFailles,
    MisesAJour,
    Demarrage,
    ObjetsConnectes,
    Appareils,
    AuditReseau,
    JournauxWindows,
    Autotest,
    CamerasCachees,
    Nat,
    CanauxWifi,
    Conteneurs,
    Secrets,
    Changements,
    VerifierMoi,
    Regles,
}

impl Commande {
    /// L'ordre compte : le relais reçoit le rang d'une commande dans cette liste (`protocole`). Une commande
    /// nouvelle s'ajoute à la fin.
    pub const TOUTES: [Commande; 34] = [
        Commande::Bilan,
        Commande::Protection,
        Commande::Evenements,
        Commande::Diagnostic,
        Commande::TestConnexion,
        Commande::ConnexionsSortantes,
        Commande::AccesADistance,
        Commande::LogicielsEspions,
        Commande::LogicielsPerimes,
        Commande::BilanConfidentialite,
        Commande::Lenteur,
        Commande::FicheOrdinateur,
        Commande::OptionsDefense,
        Commande::Antivirus,
        Commande::EtatAntivirus,
        Commande::Yara,
        Commande::Memoire,
        Commande::Integrite,
        Commande::DernieresFailles,
        Commande::MisesAJour,
        Commande::Demarrage,
        Commande::ObjetsConnectes,
        Commande::Appareils,
        Commande::AuditReseau,
        Commande::JournauxWindows,
        Commande::Autotest,
        Commande::CamerasCachees,
        Commande::Nat,
        Commande::CanauxWifi,
        Commande::Conteneurs,
        Commande::Secrets,
        Commande::Changements,
        Commande::VerifierMoi,
        Commande::Regles,
    ];

    /// Les commandes de la liste que ce système sait lancer, dans l'ordre de la liste. Une commande propre à un autre
    /// système reste dans `TOUTES` (le rang du relais ne bouge pas), mais n'est ni montrée, ni comprise, ni lancée.
    pub fn ici() -> impl Iterator<Item = Commande> {
        Commande::TOUTES.into_iter().filter(|c| c.sur_ce_systeme())
    }

    /// Faux pour une commande d'un autre système : les journaux de Windows ne se lisent que sous Windows (lire un
    /// dossier de .evtx demanderait un chemin, jamais donné d'ici).
    pub fn sur_ce_systeme(self) -> bool {
        !matches!(self, Commande::JournauxWindows) || cfg!(windows)
    }

    /// Le nom tapé dans la console (français).
    pub fn nom(self) -> &'static str {
        match self {
            Commande::Bilan => "bilan",
            Commande::Protection => "protection",
            Commande::Evenements => "evenements",
            Commande::Diagnostic => "diagnostic",
            Commande::TestConnexion => "test-connexion",
            Commande::ConnexionsSortantes => "connexions-sortantes",
            Commande::AccesADistance => "acces-a-distance",
            Commande::LogicielsEspions => "logiciels-espions",
            Commande::LogicielsPerimes => "logiciels-perimes",
            Commande::BilanConfidentialite => "bilan-confidentialite",
            Commande::Lenteur => "lenteur",
            Commande::FicheOrdinateur => "fiche-ordinateur",
            Commande::OptionsDefense => "options-defense",
            Commande::Antivirus => "antivirus",
            Commande::EtatAntivirus => "etat-antivirus",
            Commande::Yara => "yara",
            Commande::Memoire => "memoire",
            Commande::Integrite => "integrite",
            Commande::DernieresFailles => "dernieres-failles",
            Commande::MisesAJour => "mises-a-jour",
            Commande::Demarrage => "demarrage",
            Commande::ObjetsConnectes => "objets-connectes",
            Commande::Appareils => "appareils",
            Commande::AuditReseau => "audit-reseau",
            Commande::JournauxWindows => "journaux-windows",
            Commande::Autotest => "autotest",
            Commande::CamerasCachees => "cameras-cachees",
            Commande::Nat => "nat",
            Commande::CanauxWifi => "canaux-wifi",
            Commande::Conteneurs => "conteneurs",
            Commande::Secrets => "secrets",
            Commande::Changements => "changements",
            Commande::VerifierMoi => "verifier-moi",
            Commande::Regles => "regles",
        }
    }

    /// Le nom anglais, accepté aussi (les alias de Vanguard).
    pub fn nom_anglais(self) -> &'static str {
        match self {
            Commande::Bilan => "check",
            Commande::Protection => "protection",
            Commande::Evenements => "events",
            Commande::Diagnostic => "diagnostics",
            Commande::TestConnexion => "connection-test",
            Commande::ConnexionsSortantes => "outbound-connections",
            Commande::AccesADistance => "remote-access",
            Commande::LogicielsEspions => "spyware",
            Commande::LogicielsPerimes => "outdated-software",
            Commande::BilanConfidentialite => "privacy-review",
            Commande::Lenteur => "slow",
            Commande::FicheOrdinateur => "specs",
            Commande::OptionsDefense => "defense-options",
            Commande::Antivirus => "antivirus",
            Commande::EtatAntivirus => "antivirus-status",
            Commande::Yara => "yara",
            Commande::Memoire => "memory",
            Commande::Integrite => "integrity",
            Commande::DernieresFailles => "latest-flaws",
            Commande::MisesAJour => "updates",
            Commande::Demarrage => "startup",
            Commande::ObjetsConnectes => "smart-devices",
            Commande::Appareils => "devices",
            Commande::AuditReseau => "network-audit",
            Commande::JournauxWindows => "windows-logs",
            Commande::Autotest => "self-test",
            Commande::CamerasCachees => "hidden-cameras",
            Commande::Nat => "nat",
            Commande::CanauxWifi => "wifi-channels",
            Commande::Conteneurs => "containers",
            Commande::Secrets => "secrets",
            Commande::Changements => "changes",
            Commande::VerifierMoi => "self-check",
            Commande::Regles => "rules",
        }
    }

    /// Le nom montré dans la langue de l'interface.
    pub fn nom_affiche(self) -> &'static str {
        if crate::langue::anglais() {
            self.nom_anglais()
        } else {
            self.nom()
        }
    }

    /// Les arguments donnés à `vanguard`, fixés ici. Chacun écrit du JSON et ne pose aucune question (stdin fermé).
    /// « bilan » lance l'audit de cet ordinateur (`audit --json`), pas le bilan complet du terminal, qui demande.
    pub fn arguments(self) -> &'static [&'static str] {
        match self {
            Commande::Bilan => &["audit", "--json"],
            Commande::Protection => &["protection", "--json"],
            Commande::Evenements => &["evenements", "--json"],
            Commande::Diagnostic => &["diagnostic", "--json"],
            Commande::TestConnexion => &["test-connexion", "--json"],
            Commande::ConnexionsSortantes => &["connexions-sortantes", "--json"],
            Commande::AccesADistance => &["acces-a-distance", "--json"],
            Commande::LogicielsEspions => &["logiciels-espions", "--json"],
            Commande::LogicielsPerimes => &["logiciels-perimes", "--json"],
            Commande::BilanConfidentialite => &["bilan-confidentialite", "--json"],
            Commande::Lenteur => &["lenteur", "--json"],
            Commande::FicheOrdinateur => &["fiche-ordinateur", "--json"],
            Commande::OptionsDefense => &["options-defense", "--json"],
            // L'analyse rapide (les endroits à risque) : jamais un dossier choisi ni le dossier personnel entier.
            Commande::Antivirus => &["antivirus", "--json"],
            Commande::EtatAntivirus => &["antivirus", "--etat", "--json"],
            Commande::Yara => &["yara", "--json"],
            Commande::Memoire => &["memoire", "--json"],
            // Vérifier seulement : jamais --accepter (une nouvelle référence), jamais le temps réel.
            Commande::Integrite => &["integrite", "--json"],
            Commande::DernieresFailles => &["dernieres-failles", "--json"],
            // La liste de ce qui attend, rien d'installé.
            Commande::MisesAJour => &["mises-a-jour", "--json"],
            // La liste, rien de retiré.
            Commande::Demarrage => &["demarrage", "--json"],
            Commande::ObjetsConnectes => &["objets-connectes", "--json"],
            // Le scan du réseau local, ports courants : jamais une cible ni une liste de ports choisie d'ici.
            Commande::Appareils => &["appareils", "--json"],
            // Jamais --invite (une affirmation de la personne) ni --html (un navigateur ouvert).
            Commande::AuditReseau => &["audit-reseau", "--json"],
            // Les journaux de ce Windows, sur la semaine : jamais un dossier choisi d'ici.
            Commande::JournauxWindows => &["journaux-windows", "--json"],
            // Hors ligne (jamais --internet), sans valeur lue (jamais --detail).
            Commande::Autotest => &["autotest", "--json"],
            Commande::CamerasCachees => &["cameras-cachees", "--json"],
            Commande::Nat => &["nat", "--json"],
            Commande::CanauxWifi => &["canaux-wifi", "--json"],
            Commande::Conteneurs => &["conteneurs", "--json"],
            Commande::Secrets => &["secrets", "--json"],
            Commande::Changements => &["changements", "--json"],
            // Cette copie seulement : jamais le chemin d'un autre programme.
            Commande::VerifierMoi => &["verifier-moi", "--json"],
            Commande::Regles => &["regles", "--json"],
        }
    }

    /// Le délai au-delà duquel la commande est arrêtée (son groupe tué) : l'audit en prend quelques secondes, les
    /// outils qui lisent une liste en ligne jusqu'à quelques minutes sur une connexion lente.
    pub fn delai(self) -> Duration {
        Duration::from_secs(match self {
            // trivy lit chaque image, et télécharge sa base la première fois.
            // L'historique de chaque projet git du dossier personnel : secrets s'arrête de lui-même après 1200 s
            // (BUDGET_S) et un dépôt commencé peut prendre 420 s de plus, d'où 1800 s.
            Commande::Antivirus | Commande::Yara | Commande::Memoire | Commande::Conteneurs | Commande::Secrets => 1800,
            Commande::Bilan
            | Commande::LogicielsEspions
            | Commande::LogicielsPerimes
            | Commande::MisesAJour
            | Commande::Integrite
            | Commande::JournauxWindows
            | Commande::Autotest => 300,
            // Le scan du réseau local : une douzaine de secondes sur un /24, plus sur une plage large ou lente.
            Commande::TestConnexion
            | Commande::ConnexionsSortantes
            | Commande::Lenteur
            | Commande::DernieresFailles
            | Commande::Appareils
            | Commande::AuditReseau
            | Commande::CamerasCachees
            | Commande::VerifierMoi => 180,
            _ => 120,
        })
    }

    pub fn forme(self) -> Forme {
        match self {
            Commande::Bilan => Forme::Audit,
            Commande::Protection => Forme::Protection,
            Commande::Evenements => Forme::Evenements,
            Commande::Appareils => Forme::Appareils,
            Commande::AuditReseau => Forme::AuditReseau,
            // Un historique (changements) et une liste (regles) n'ont pas de verdict : JSON simple, montré tel quel.
            Commande::FicheOrdinateur
            | Commande::OptionsDefense
            | Commande::Autotest
            | Commande::Changements
            | Commande::Regles => Forme::Libre,
            _ => Forme::Resultat,
        }
    }

    /// Le titre de son écran.
    pub fn titre(self) -> &'static str {
        match self {
            Commande::Bilan => crate::tr!("Bilan de cet ordinateur", "Check of this computer"),
            Commande::Protection => crate::tr!("Protection", "Protection"),
            Commande::Evenements => crate::tr!("Alertes et événements", "Alerts and events"),
            Commande::Diagnostic => crate::tr!("Diagnostic du réseau", "Network diagnostics"),
            Commande::TestConnexion => crate::tr!("Test de la connexion", "Connection test"),
            Commande::ConnexionsSortantes => crate::tr!("Connexions sortantes", "Outbound connections"),
            Commande::AccesADistance => crate::tr!("Accès à distance", "Remote access"),
            Commande::LogicielsEspions => crate::tr!("Logiciels espions", "Spyware"),
            Commande::LogicielsPerimes => crate::tr!("Logiciels périmés", "Outdated software"),
            Commande::BilanConfidentialite => crate::tr!("Bilan de confidentialité", "Privacy review"),
            Commande::Lenteur => crate::tr!("Pourquoi c'est lent", "Why it is slow"),
            Commande::FicheOrdinateur => crate::tr!("Fiche de l'ordinateur", "Computer specs"),
            Commande::OptionsDefense => crate::tr!("Options de défense", "Defense options"),
            Commande::Antivirus => crate::tr!("Antivirus, analyse rapide", "Antivirus, quick scan"),
            Commande::EtatAntivirus => crate::tr!("État de l'antivirus", "Antivirus status"),
            Commande::Yara => crate::tr!("Analyse YARA", "YARA scan"),
            Commande::Memoire => crate::tr!("Mémoire des programmes", "Program memory"),
            Commande::Integrite => crate::tr!("Fichiers critiques", "Critical files"),
            Commande::DernieresFailles => crate::tr!("Dernières failles exploitées", "Latest exploited flaws"),
            Commande::MisesAJour => crate::tr!("Mises à jour en attente", "Pending updates"),
            Commande::Demarrage => crate::tr!("Programmes au démarrage", "Startup programs"),
            Commande::ObjetsConnectes => crate::tr!("Routeur et objets connectés", "Router and smart devices"),
            Commande::Appareils => crate::tr!("Appareils du réseau", "Network devices"),
            Commande::AuditReseau => crate::tr!("Audit du réseau", "Network audit"),
            Commande::JournauxWindows => crate::tr!("Journaux de Windows", "Windows logs"),
            Commande::Autotest => crate::tr!("Autodiagnostic de Vanguard", "Vanguard self-test"),
            Commande::CamerasCachees => crate::tr!("Caméras cachées", "Hidden cameras"),
            Commande::Nat => crate::tr!("Type de NAT", "NAT type"),
            Commande::CanauxWifi => crate::tr!("Canaux Wi-Fi", "Wi-Fi channels"),
            Commande::Conteneurs => crate::tr!("Images de conteneurs", "Container images"),
            Commande::Secrets => crate::tr!("Secrets dans git", "Secrets in git"),
            Commande::Changements => crate::tr!("Ce que Vanguard a changé", "What Vanguard changed"),
            Commande::VerifierMoi => crate::tr!("Vérifier cette copie de Vanguard", "Verify this copy of Vanguard"),
            Commande::Regles => crate::tr!("Règles du bilan", "Check rules"),
        }
    }

    /// Ce qu'elle fait, en une phrase.
    pub fn description(self) -> &'static str {
        match self {
            Commande::Bilan => crate::tr!(
                "Pare-feu, comptes, mises à jour, chiffrement, persistance… tout se lit sur cet ordinateur.",
                "Firewall, accounts, updates, encryption, persistence… all read on this computer."
            ),
            Commande::Protection => crate::tr!(
                "L'état de chaque interrupteur de la protection. Rien n'est changé.",
                "The state of each protection switch. Nothing is changed."
            ),
            Commande::Evenements => crate::tr!(
                "Le journal de Vanguard : alertes, preuves, actions, et s'il est intact.",
                "Vanguard's journal: alerts, evidence, actions, and whether it is intact."
            ),
            Commande::Diagnostic => crate::tr!(
                "Carte réseau, passerelle, DNS : ce qui marche et ce qui bloque.",
                "Network card, gateway, DNS: what works and what is stuck."
            ),
            Commande::TestConnexion => crate::tr!(
                "Débit, latence et noms de domaine, mesurés en ligne.",
                "Speed, latency and domain names, measured online."
            ),
            Commande::ConnexionsSortantes => crate::tr!(
                "Les programmes qui parlent à Internet en ce moment.",
                "The programs talking to the Internet right now."
            ),
            Commande::AccesADistance => crate::tr!(
                "Bureau à distance, SSH, outils de prise en main : ce qui est ouvert.",
                "Remote desktop, SSH, remote-control tools: what is open."
            ),
            Commande::LogicielsEspions => crate::tr!(
                "Les logiciels espions connus (liste d'Échap), cherchés sur cet ordinateur.",
                "Known stalkerware (Échap's list), searched for on this computer."
            ),
            Commande::LogicielsPerimes => crate::tr!(
                "Les logiciels qui n'ont plus leurs mises à jour de sécurité.",
                "Software that no longer gets security updates."
            ),
            Commande::BilanConfidentialite => crate::tr!(
                "Caméra, micro, position : quelles applications y ont accès.",
                "Camera, microphone, location: which apps can use them."
            ),
            Commande::Lenteur => crate::tr!(
                "Ce qui force en ce moment : processeur, mémoire, disque.",
                "What is straining right now: processor, memory, disk."
            ),
            Commande::FicheOrdinateur => crate::tr!(
                "Le modèle, le processeur, la mémoire et les disques, sans numéro de série.",
                "Model, processor, memory and disks, without serial numbers."
            ),
            Commande::OptionsDefense => crate::tr!(
                "Les baisses de protection choisies, et ce qui peut se rallumer.",
                "The protection decreases you chose, and what can be turned back on."
            ),
            Commande::Antivirus => crate::tr!(
                "Téléchargements, bureau, démarrage : les endroits à risque, analysés. Rien n'est isolé d'ici.",
                "Downloads, desktop, startup: the risky places, scanned. Nothing is isolated from here."
            ),
            Commande::EtatAntivirus => crate::tr!(
                "Le moteur, ses bases et leur date, et ce qu'il ne lit pas. Rien n'est analysé.",
                "The engine, its databases and their date, and what it does not read. Nothing is scanned."
            ),
            Commande::Yara => crate::tr!(
                "Les règles de familles de logiciels malveillants, passées aux endroits à risque.",
                "Malware family rules, run over the risky places."
            ),
            Commande::Memoire => crate::tr!(
                "Les programmes en marche : un logiciel malveillant sans fichier ne vit que là.",
                "Running programs: fileless malware only lives there."
            ),
            Commande::Integrite => crate::tr!(
                "Ce qui a changé dans les fichiers critiques depuis la référence. La référence ne se pose pas d'ici.",
                "What changed in critical files since the reference. The reference is not set from here."
            ),
            Commande::DernieresFailles => crate::tr!(
                "Les failles attaquées ces derniers jours (CISA), celles de cet ordinateur en tête.",
                "Flaws attacked in recent days (CISA), those of this computer first."
            ),
            Commande::MisesAJour => crate::tr!(
                "Système, programmes, pilotes : ce qui attend. Rien n'est installé d'ici.",
                "System, programs, drivers: what is waiting. Nothing is installed from here."
            ),
            Commande::Demarrage => crate::tr!(
                "Ce qui se lance avec l'ordinateur, jugé. Rien n'est retiré d'ici.",
                "What starts with the computer, judged. Nothing is removed from here."
            ),
            Commande::ObjetsConnectes => crate::tr!(
                "Le routeur et les objets du dernier scan du réseau, et leurs risques.",
                "The router and devices from the last network scan, and their risks."
            ),
            Commande::Appareils => crate::tr!(
                "Les appareils du réseau local, leurs ports ouverts et leurs risques, et ce qui est nouveau depuis le dernier scan.",
                "Devices on the local network, their open ports and risks, and what is new since the last scan."
            ),
            Commande::AuditReseau => crate::tr!(
                "Exposition à Internet, Wi-Fi, séparation, DNS et TLS, appareils, ordinateurs : six domaines notés, sans rien attaquer.",
                "Internet exposure, Wi-Fi, separation, DNS and TLS, devices, computers: six graded areas, without attacking anything."
            ),
            Commande::JournauxWindows => crate::tr!(
                "Les traces d'attaque de la semaine dans les journaux de ce Windows : effacements, comptes, mots de passe devinés.",
                "Attack traces from the past week in this Windows' logs: wiped logs, accounts, guessed passwords."
            ),
            Commande::Autotest => crate::tr!(
                "Vanguard vérifie ses propres lectures, hors ligne, sans rien changer.",
                "Vanguard checks its own readings, offline, without changing anything."
            ),
            Commande::CamerasCachees => crate::tr!(
                "Sur le réseau d'une location, les appareils qui ressemblent à des caméras. Aucune image n'est lue.",
                "On a rental's network, the devices that look like cameras. No image is read."
            ),
            Commande::Nat => crate::tr!(
                "Ouvert, modéré ou strict pour le jeu, d'après deux serveurs publics.",
                "Open, moderate or strict for gaming, from two public servers."
            ),
            Commande::CanauxWifi => crate::tr!(
                "Les réseaux voisins par canal, et le plus libre à régler sur le routeur. Rien n'est réglé d'ici.",
                "Nearby networks by channel, and the freest one to set on the router. Nothing is set from here."
            ),
            Commande::Conteneurs => crate::tr!(
                "Les failles connues des images Docker ou Podman, par trivy s'il est installé.",
                "Known flaws in Docker or Podman images, by trivy if installed."
            ),
            Commande::Secrets => crate::tr!(
                "Mots de passe et clés oubliés dans l'historique des projets git. Aucun secret n'est montré.",
                "Passwords and keys left in git project history. No secret is shown."
            ),
            Commande::Changements => crate::tr!(
                "Chaque correction lancée sur cet ordinateur, sa date et son résultat.",
                "Each fix run on this computer, its date and its result."
            ),
            Commande::VerifierMoi => crate::tr!(
                "Ce programme est-il bien celui publié ? Son empreinte et le manifeste de la clé ; l'historique signé se compare dans le menu.",
                "Is this program the one published? Its fingerprint and the key's manifest; the signed history is compared in the menu."
            ),
            Commande::Regles => crate::tr!(
                "Les règles du bilan pour ce système : identifiant, sujet, références.",
                "The check rules for this system: identifier, subject, references."
            ),
        }
    }

    pub fn rubrique(self) -> Rubrique {
        match self {
            Commande::Bilan
            | Commande::FicheOrdinateur
            | Commande::Lenteur
            | Commande::Integrite
            | Commande::DernieresFailles
            | Commande::MisesAJour
            | Commande::Conteneurs
            | Commande::Secrets => Rubrique::Ordinateur,
            Commande::Diagnostic
            | Commande::TestConnexion
            | Commande::ConnexionsSortantes
            | Commande::AccesADistance
            | Commande::ObjetsConnectes
            | Commande::Appareils
            | Commande::AuditReseau
            | Commande::CamerasCachees => Rubrique::Reseau,
            Commande::LogicielsEspions
            | Commande::Antivirus
            | Commande::EtatAntivirus
            | Commande::Yara
            | Commande::Memoire => Rubrique::Virus,
            Commande::BilanConfidentialite => Rubrique::Arnaques,
            Commande::Protection
            | Commande::Evenements
            | Commande::OptionsDefense
            | Commande::JournauxWindows
            | Commande::Changements => Rubrique::Bloquer,
            Commande::LogicielsPerimes | Commande::Demarrage | Commande::Nat | Commande::CanauxWifi => {
                Rubrique::Optimiser
            }
            Commande::Autotest | Commande::VerifierMoi | Commande::Regles => Rubrique::Vanguard,
        }
    }
}

/// Comment une tâche a fini.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issue {
    Terminee,
    /// Arrêtée à la demande (bouton Arrêter).
    Arretee,
    DelaiDepasse,
    /// La sortie dépassait `SORTIE_MAX` : arrêtée, rien de montré.
    TropLongue,
    /// Le programme n'a pas pu être lancé.
    Impossible(String),
}

/// La fin d'une tâche.
#[derive(Clone, Debug)]
pub struct Fin {
    pub commande: Commande,
    pub code: Option<i32>,
    pub sortie: Vec<u8>,
    pub issue: Issue,
    pub duree: Duration,
}

/// Ce qu'une saisie de la console demande.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Saisie {
    /// Rien (ligne vide).
    Rien,
    /// Une commande de la liste.
    Lancer(Commande),
    /// La liste des commandes permises, sans rien lancer.
    Aide,
    /// Vider la console.
    Effacer,
    /// Tout le reste : rien n'est lancé. Le texte tapé, nettoyé et coupé, pour le redire.
    Refusee(String),
}

/// Les mots de la console qui ne lancent rien.
const AIDE: [&str; 3] = ["aide", "help", "?"];
const EFFACER: [&str; 2] = ["effacer", "clear"];

/// Lit une saisie de la console : un seul mot, nom français ou anglais d'une commande de la liste (« vanguard »
/// devant est permis), sans argument. Tout autre texte est refusé tel quel : jamais découpé, jamais complété,
/// jamais passé à un programme.
pub fn comprendre(saisie: &str) -> Saisie {
    let t = saisie.trim();
    if t.is_empty() {
        return Saisie::Rien;
    }
    let refus = || Saisie::Refusee(crate::nettoyage::nom(t, 60));
    let mots: Vec<&str> = t.split_whitespace().collect();
    let mot = match mots.as_slice() {
        [m] => *m,
        [v, m] if v.eq_ignore_ascii_case("vanguard") => *m,
        _ => return refus(),
    };
    let m = mot.to_ascii_lowercase();
    if AIDE.contains(&m.as_str()) {
        return Saisie::Aide;
    }
    if EFFACER.contains(&m.as_str()) {
        return Saisie::Effacer;
    }
    Commande::ici()
        .find(|c| c.nom() == m || c.nom_anglais() == m)
        .map_or_else(refus, Saisie::Lancer)
}

/// Complète un début de nom (touche Tab) quand un seul nom de la liste commence ainsi.
pub fn completer(debut: &str) -> Option<&'static str> {
    let d = debut.trim().to_ascii_lowercase();
    if d.is_empty() {
        return None;
    }
    let mut noms: Vec<&'static str> = Commande::ici()
        .map(Commande::nom_affiche)
        .chain([crate::tr!("aide", "help"), crate::tr!("effacer", "clear")])
        .filter(|n| n.starts_with(&d))
        .collect();
    noms.dedup();
    match noms.as_slice() {
        [un] => Some(*un),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_commande_a_des_noms_uniques_et_du_json() {
        let mut noms: Vec<&str> = Commande::TOUTES.iter().map(|c| c.nom()).collect();
        // Le même mot dans les deux langues : compté une fois.
        noms.extend(
            Commande::TOUTES
                .iter()
                .filter(|c| c.nom() != c.nom_anglais())
                .map(|c| c.nom_anglais()),
        );
        let avant = noms.len();
        noms.sort_unstable();
        noms.dedup();
        assert_eq!(noms.len(), avant, "un nom sert deux fois");
        for c in Commande::TOUTES {
            let a = c.arguments();
            // La sous-commande, --json à la fin, et entre les deux seulement une option qui lit (--etat) : aucun mot
            // qui agit (« oui », « non », --choisir, --rallumer, --accepter, --complet…), aucun chemin.
            assert!(a.len() == 2 || a == ["antivirus", "--etat", "--json"], "{c:?}");
            assert_eq!(a.last(), Some(&"--json"), "{c:?}");
            assert!(!AIDE.contains(&c.nom()) && !EFFACER.contains(&c.nom()));
            assert!(c.delai().as_secs() >= 60 && c.delai().as_secs() <= 1800, "{c:?}");
        }
    }

    #[test]
    fn la_console_n_accepte_que_la_liste() {
        assert_eq!(comprendre("bilan"), Saisie::Lancer(Commande::Bilan));
        assert_eq!(comprendre("  Bilan  "), Saisie::Lancer(Commande::Bilan));
        assert_eq!(comprendre("check"), Saisie::Lancer(Commande::Bilan));
        assert_eq!(
            comprendre("vanguard spyware"),
            Saisie::Lancer(Commande::LogicielsEspions)
        );
        assert_eq!(comprendre("aide"), Saisie::Aide);
        assert_eq!(comprendre("?"), Saisie::Aide);
        assert_eq!(comprendre("clear"), Saisie::Effacer);
        assert_eq!(comprendre("   "), Saisie::Rien);
        // Un argument de plus, une commande qui agit, un shell, une option : refusés, rien de lancé.
        for refus in [
            "bilan --html",
            "protection non",
            "protection --json non",
            "corriger",
            "options-defense --rallumer pare-feu",
            "rm -rf ~",
            "bilan; rm -rf ~",
            "bilan && corriger",
            "$(corriger)",
            "`corriger`",
            "audit",
            "--json",
            "vanguard",
            "vanguard vanguard bilan",
            "bilan\u{0}",
            "bilan\ncorriger",
            "biIan",
        ] {
            assert!(matches!(comprendre(refus), Saisie::Refusee(_)), "{refus:?} accepté");
        }
    }

    #[test]
    fn un_refus_redit_le_texte_nettoye_et_court() {
        let Saisie::Refusee(t) = comprendre(&format!("\u{1b}]52;c;eA==\u{7}x{}", "y".repeat(500))) else {
            panic!("accepté");
        };
        assert!(t.chars().count() <= 60, "{t}");
        assert!(!t.contains('\u{1b}'));
    }

    #[test]
    fn une_commande_d_un_autre_systeme_n_est_ni_montree_ni_comprise() {
        let windows = cfg!(windows);
        assert_eq!(Commande::JournauxWindows.sur_ce_systeme(), windows);
        assert_eq!(Commande::ici().any(|c| c == Commande::JournauxWindows), windows);
        assert_eq!(
            Rubrique::Bloquer.commandes().any(|c| c == Commande::JournauxWindows),
            windows
        );
        for saisie in ["journaux-windows", "windows-logs", "vanguard journaux-windows"] {
            assert_eq!(
                matches!(comprendre(saisie), Saisie::Lancer(Commande::JournauxWindows)),
                windows,
                "{saisie}"
            );
        }
        assert_eq!(completer("journaux-w").is_some(), windows);
        // Toujours dans la liste, à son rang : le relais et la fenêtre gardent le même ordre sur les deux systèmes.
        assert_eq!(
            Commande::TOUTES.iter().position(|c| *c == Commande::JournauxWindows),
            Some(24)
        );
    }

    #[test]
    fn les_commandes_nouvelles_sont_a_la_fin() {
        // Le relais reçoit le rang : les 22 premières gardent le leur.
        assert_eq!(Commande::TOUTES[0], Commande::Bilan);
        assert_eq!(Commande::TOUTES[21], Commande::ObjetsConnectes);
        assert_eq!(Commande::TOUTES[22], Commande::Appareils);
        assert_eq!(Commande::TOUTES[33], Commande::Regles);
    }

    #[test]
    fn tab_complete_un_seul_nom() {
        assert_eq!(completer("bil"), None, "bilan et bilan-confidentialite");
        assert_eq!(completer("bilan-"), Some("bilan-confidentialite"));
        assert_eq!(completer("lo"), None);
        assert_eq!(completer("logiciels-e"), Some("logiciels-espions"));
        assert_eq!(completer("eff"), Some("effacer"));
        assert_eq!(completer(""), None);
        assert_eq!(completer("zzz"), None);
        assert_eq!(completer("appa"), Some("appareils"));
        assert_eq!(completer("ver"), Some("verifier-moi"));
    }

    #[test]
    fn chaque_rubrique_garde_ses_commandes() {
        let total: usize = Rubrique::TOUTES.iter().map(|r| r.commandes().count()).sum();
        assert_eq!(total, Commande::ici().count());
        assert_eq!(Rubrique::Accueil.commandes().count(), 0);
        assert_eq!(Rubrique::Vanguard.commandes().count(), 3);
        for r in Rubrique::TOUTES {
            assert!(r.nom_court().lines().all(|l| l.chars().count() <= 12), "{r:?}");
        }
    }
}
