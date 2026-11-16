//! La liste fermée : les seules commandes de `vanguard` que la fenêtre sait lancer, chacune avec ses arguments
//! fixés ici, dans le code. Un clic ou une saisie choisit une entrée de cette liste, jamais un texte : aucun argument
//! libre ne part vers `vanguard`, et une saisie qui n'est pas un nom de la liste ne lance rien. Lot 1 : des commandes
//! qui ne changent rien à l'ordinateur (elles lisent, et notent leur résultat dans les données de Vanguard). Lot 2a :
//! un seul changement, retirer ou remettre un programme au démarrage (`Changement`), désigné par son empreinte et
//! demandé par un clic confirmé, jamais par la console.

use std::time::Duration;

pub(crate) use crate::valeur::{Argument, Refus};

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

    /// Les commandes de la liste rangées dans cette rubrique, celles de ce système seulement, et sans celles qui ne
    /// se lancent qu'avec une valeur tapée (un clic n'en a pas).
    pub fn commandes(self) -> impl Iterator<Item = Commande> {
        Commande::ici().filter(move |c| c.rubrique() == self && !c.valeur_requise())
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
    /// `changements --json` : ce que Vanguard a changé, ligne par ligne (`donnees::changements`).
    Changements,
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
    /// Les couleurs de la fenêtre, lues par `vanguard` (`couleurs --json`) : jamais montrée ni tapée dans la console,
    /// demandée par la fenêtre elle-même (au lancement, après un changement de couleurs).
    Couleurs,
    Agent,
    CameraMicro,
    Logiciels,
    Nettoyer,
    Desinstaller,
    SitesDangereux,
    Parametres,
    Blocage,
    VerifierSauvegarde,
    Ordinateurs,
    /// Les quatre suivantes ne se lancent qu'avec une valeur tapée dans la console (`Commande::argument`) : ni
    /// montrées dans le rail, ni lancées d'un clic.
    Chercher,
    Lien,
    VerifierFichier,
    CourrielSuspect,
}

impl Commande {
    /// L'ordre compte : le relais reçoit le rang d'une commande dans cette liste (`protocole`). Une commande
    /// nouvelle s'ajoute à la fin.
    pub const TOUTES: [Commande; 49] = [
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
        Commande::Couleurs,
        Commande::Agent,
        Commande::CameraMicro,
        Commande::Logiciels,
        Commande::Nettoyer,
        Commande::Desinstaller,
        Commande::SitesDangereux,
        Commande::Parametres,
        Commande::Blocage,
        Commande::VerifierSauvegarde,
        Commande::Ordinateurs,
        Commande::Chercher,
        Commande::Lien,
        Commande::VerifierFichier,
        Commande::CourrielSuspect,
    ];

    /// Les commandes de la liste que ce système sait lancer et que la personne choisit, dans l'ordre de la liste. Une
    /// commande propre à un autre système reste dans `TOUTES` (le rang du relais ne bouge pas), mais n'est ni montrée,
    /// ni comprise, ni lancée. La lecture des couleurs non plus n'est ni montrée ni comprise : la fenêtre la demande
    /// elle-même.
    pub fn ici() -> impl Iterator<Item = Commande> {
        Commande::TOUTES
            .into_iter()
            .filter(|c| c.sur_ce_systeme() && *c != Commande::Couleurs)
    }

    /// Faux pour une commande d'un autre système : les journaux de Windows ne se lisent que sous Windows (lire un
    /// dossier de .evtx demanderait un chemin, jamais donné d'ici).
    pub fn sur_ce_systeme(self) -> bool {
        !matches!(self, Commande::JournauxWindows) || cfg!(windows)
    }

    /// La sorte de valeur que la console accepte après son nom (`verifier-fichier ~/Téléchargements/x.pdf`) : une
    /// seule par commande, et aucune pour toutes les autres. Liste fermée, relue par les essais (`attaques`).
    pub fn argument(self) -> Option<Argument> {
        match self {
            Commande::Chercher => Some(Argument::Mots),
            Commande::Lien => Some(Argument::Adresse),
            Commande::Evenements => Some(Argument::Incident),
            Commande::DernieresFailles | Commande::JournauxWindows => Some(Argument::Jours),
            Commande::VerifierFichier | Commande::CourrielSuspect | Commande::VerifierMoi => Some(Argument::Chemin),
            _ => None,
        }
    }

    /// Une commande qui ne se lance qu'avec sa valeur : sans elle, elle n'a rien à lire.
    pub fn valeur_requise(self) -> bool {
        matches!(
            self,
            Commande::Chercher | Commande::Lien | Commande::VerifierFichier | Commande::CourrielSuspect
        )
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
            Commande::Couleurs => "couleurs",
            Commande::Agent => "agent",
            Commande::CameraMicro => "camera-micro",
            Commande::Logiciels => "logiciels",
            Commande::Nettoyer => "nettoyer",
            Commande::Desinstaller => "desinstaller",
            Commande::SitesDangereux => "sites-dangereux",
            Commande::Parametres => "parametres",
            Commande::Blocage => "blocage",
            Commande::VerifierSauvegarde => "verifier-sauvegarde",
            Commande::Ordinateurs => "ordinateurs",
            Commande::Chercher => "chercher",
            Commande::Lien => "lien",
            Commande::VerifierFichier => "verifier-fichier",
            Commande::CourrielSuspect => "courriel-suspect",
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
            Commande::Couleurs => "colors",
            Commande::Agent => "agent",
            Commande::CameraMicro => "camera-mic",
            Commande::Logiciels => "software",
            Commande::Nettoyer => "clean",
            Commande::Desinstaller => "uninstall",
            Commande::SitesDangereux => "dangerous-sites",
            Commande::Parametres => "settings",
            Commande::Blocage => "blocking",
            Commande::VerifierSauvegarde => "check-backup",
            Commande::Ordinateurs => "computers",
            Commande::Chercher => "search",
            Commande::Lien => "link",
            Commande::VerifierFichier => "check-file",
            Commande::CourrielSuspect => "suspicious-email",
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
            Commande::Couleurs => &["couleurs", "--json"],
            // Lecture seule, sans aucune donnée personnelle : ses interrupteurs ne se changent pas d'ici.
            Commande::Agent => &["agent", "--json"],
            Commande::CameraMicro => &["camera-micro", "--json"],
            // La liste, rien d'installé : jamais --recommandes (qui installe), jamais un nom tapé.
            Commande::Logiciels => &["logiciels", "--liste", "--json"],
            // La liste, rien d'effacé.
            Commande::Nettoyer => &["nettoyer", "--liste", "--json"],
            // La liste, rien de retiré.
            Commande::Desinstaller => &["desinstaller", "--liste", "--json"],
            // L'état seulement : jamais « on » ni « off » (droits d'administrateur, fichier hosts).
            Commande::SitesDangereux => &["sites-dangereux", "--json"],
            // Sans aucun mot : avec un réglage et une valeur, « parametres » change ce réglage.
            Commande::Parametres => &["parametres", "--json"],
            // « etat » seulement : tout autre mot règle une catégorie ou annule un blocage.
            Commande::Blocage => &["blocage", "etat", "--json"],
            Commande::VerifierSauvegarde => &["verifier-sauvegarde", "--json"],
            // Sans menu : jamais renommer ni oublier un ordinateur d'ici.
            Commande::Ordinateurs => &["ordinateurs", "--json"],
            // Jamais lancées sans valeur (`Lancement::AvecValeur`) : la fenêtre et le relais le refusent avant. Si
            // c'était quand même le cas, `vanguard console` sans « -- <valeur> » est refusé par sa ligne de
            // commande, sans rien faire.
            Commande::Chercher => &["console", "chercher"],
            Commande::Lien => &["console", "lien"],
            Commande::VerifierFichier => &["console", "verifier-fichier"],
            Commande::CourrielSuspect => &["console", "courriel-suspect"],
        }
    }

    /// Les seules formes d'arguments à trois mots : entre la sous-commande et --json, une option ou un mot qui LIT
    /// (l'état, une liste), fixé ici. Liste fermée, relue par les essais (`attaques`) : aucun mot qui agit (« oui »,
    /// « on », --appliquer, --accepter, --recommandes…), aucun chemin, aucun nom tapé.
    #[cfg(test)]
    pub(crate) const LECTURES_A_TROIS_MOTS: [[&'static str; 3]; 5] = [
        ["antivirus", "--etat", "--json"],
        ["logiciels", "--liste", "--json"],
        ["nettoyer", "--liste", "--json"],
        ["desinstaller", "--liste", "--json"],
        ["blocage", "etat", "--json"],
    ];

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
            | Commande::Autotest
            // La taille de chaque cache, mesurée ; la base des paquets lue.
            | Commande::Nettoyer
            // Un fichier reçu (jusqu'à quelques centaines de Mo) passé aux règles, comme l'analyse d'un dossier.
            | Commande::VerifierFichier
            | Commande::Logiciels => 300,
            // Le scan du réseau local : une douzaine de secondes sur un /24, plus sur une plage large ou lente.
            Commande::TestConnexion
            | Commande::ConnexionsSortantes
            | Commande::Lenteur
            | Commande::DernieresFailles
            | Commande::Appareils
            | Commande::AuditReseau
            | Commande::CamerasCachees
            | Commande::VerifierMoi => 180,
            // Un petit fichier et le thème du système : quelques millisecondes ; le délai le plus court de la liste.
            Commande::Couleurs => 60,
            // Quelques fichiers relus sur le disque de sauvegarde (jusqu'à 1 Gio chacun), cache contourné.
            Commande::VerifierSauvegarde => 600,
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
            Commande::Changements => Forme::Changements,
            // Une liste (regles) n'a pas de verdict : JSON simple, montré tel quel.
            Commande::FicheOrdinateur
            | Commande::OptionsDefense
            | Commande::Autotest
            | Commande::Regles
            | Commande::Couleurs
            | Commande::Agent
            | Commande::CameraMicro
            | Commande::Logiciels
            | Commande::Nettoyer
            | Commande::Desinstaller
            | Commande::SitesDangereux
            | Commande::Parametres
            | Commande::Blocage
            | Commande::VerifierSauvegarde
            | Commande::Ordinateurs
            | Commande::Chercher => Forme::Libre,
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
            Commande::Couleurs => crate::tr!("Couleurs de la fenêtre", "Window colors"),
            Commande::Agent => crate::tr!("Agent Vanguard", "Vanguard Agent"),
            Commande::CameraMicro => crate::tr!("Caméra et micro", "Camera and microphone"),
            Commande::Logiciels => crate::tr!("Logiciels conseillés", "Recommended software"),
            Commande::Nettoyer => crate::tr!("Place à libérer", "Space to free up"),
            Commande::Desinstaller => crate::tr!("Ce que Vanguard a posé ici", "What Vanguard placed here"),
            Commande::SitesDangereux => crate::tr!("Sites dangereux bloqués", "Dangerous sites blocked"),
            Commande::Parametres => crate::tr!("Paramètres de Vanguard", "Vanguard settings"),
            Commande::Blocage => crate::tr!("Blocage des menaces", "Threat blocking"),
            Commande::VerifierSauvegarde => {
                crate::tr!("Vérifier la sauvegarde automatique", "Check the automatic backup")
            }
            Commande::Ordinateurs => crate::tr!("Mes ordinateurs", "My computers"),
            Commande::Chercher => crate::tr!("Chercher dans Vanguard", "Search Vanguard"),
            Commande::Lien => crate::tr!("Vérifier un lien", "Check a link"),
            Commande::VerifierFichier => crate::tr!("Vérifier un fichier", "Check a file"),
            Commande::CourrielSuspect => crate::tr!("Courriel suspect", "Suspicious email"),
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
                "Ce qui se lance avec l'ordinateur, jugé. Un programme ordinaire se retire d'un clic, après confirmation ; il reste installé.",
                "What starts with the computer, judged. An ordinary program is removed with one click, after confirmation; it stays installed."
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
            Commande::Couleurs => crate::tr!(
                "Les couleurs réglées pour chaque thème, et celles du système, lues par Vanguard.",
                "The colors set for each theme, and the system's, read by Vanguard."
            ),
            Commande::Agent => crate::tr!(
                "Ses missions, leur dernier tour et son journal, sans aucune donnée personnelle. Rien n'est changé ni envoyé.",
                "Its missions, their last run and its journal, with no personal data. Nothing is changed or sent."
            ),
            Commande::CameraMicro => crate::tr!(
                "Les programmes qui se servent de la caméra et du micro, ou s'en sont servis. Rien n'est changé.",
                "Programs using the camera and microphone, or that used them. Nothing is changed."
            ),
            Commande::Logiciels => crate::tr!(
                "Des logiciels sûrs et gratuits, par catégorie, et ceux déjà installés. Rien n'est installé d'ici.",
                "Safe, free software by category, and what is already installed. Nothing is installed from here."
            ),
            Commande::Nettoyer => crate::tr!(
                "Paquets téléchargés, caches, corbeille : ce qui pourrait partir, et sa taille. Rien n'est effacé d'ici.",
                "Downloaded packages, caches, trash: what could go, and its size. Nothing is deleted from here."
            ),
            Commande::Desinstaller => crate::tr!(
                "Tâches, raccourcis, programme et dossier de données : ce que retirer Vanguard enlèverait. Rien n'est retiré d'ici.",
                "Tasks, shortcuts, program and data folder: what removing Vanguard would take away. Nothing is removed from here."
            ),
            Commande::SitesDangereux => crate::tr!(
                "La liste des sites malveillants dans le fichier hosts : posée ou non, intacte, depuis quand. Rien n'est changé.",
                "The list of malicious sites in the hosts file: in place or not, intact, since when. Nothing is changed."
            ),
            Commande::Parametres => crate::tr!(
                "Chaque réglage de Vanguard et sa valeur. Rien ne se change d'ici : le menu Paramètres.",
                "Each Vanguard setting and its value. Nothing is changed from here: the Settings menu."
            ),
            Commande::Blocage => crate::tr!(
                "Pour chaque menace : automatique, un clic ou désactivé, et le geste fait. Rien ne se règle d'ici.",
                "For each threat: automatic, one click or off, and the action taken. Nothing is set from here."
            ),
            Commande::VerifierSauvegarde => crate::tr!(
                "Quelques fichiers relus sur le disque de sauvegarde, comparés à leur original. Rien n'est écrit ni effacé.",
                "A few files read back from the backup disk, compared with their original. Nothing is written or deleted."
            ),
            Commande::Ordinateurs => crate::tr!(
                "Le tableau de la clé VANGUARD : chaque ordinateur vu, sa note et ses problèmes restants. Rien n'est écrit.",
                "The VANGUARD key's table: each computer seen, its grade and its remaining problems. Nothing is written."
            ),
            Commande::Chercher => crate::tr!(
                "Les dix meilleurs résultats de la recherche du menu, et leur commande. Rien ne s'ouvre ni ne se lance.",
                "The ten best results of the menu's search, and their command. Nothing is opened or run."
            ),
            Commande::Lien => crate::tr!(
                "Les signes d'un lien piégé, lus sur cet ordinateur : le lien n'est jamais ouvert, rien n'est envoyé.",
                "The signs of a trapped link, read on this computer: the link is never opened, nothing is sent."
            ),
            Commande::VerifierFichier => crate::tr!(
                "Un fichier de Téléchargements, Bureau, Documents ou d'un support amovible, examiné ici, sans Internet.",
                "A file from Downloads, Desktop, Documents or a removable drive, examined here, without Internet."
            ),
            Commande::CourrielSuspect => crate::tr!(
                "Un courriel enregistré (.eml) : expéditeur, liens et pièces jointes, lus ici, sans Internet.",
                "A saved email (.eml): sender, links and attachments, read here, without Internet."
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
            | Commande::Memoire
            | Commande::VerifierFichier => Rubrique::Virus,
            Commande::BilanConfidentialite | Commande::CameraMicro | Commande::Lien | Commande::CourrielSuspect => {
                Rubrique::Arnaques
            }
            Commande::Chercher => Rubrique::Accueil,
            Commande::Protection
            | Commande::Evenements
            | Commande::OptionsDefense
            | Commande::JournauxWindows
            | Commande::Changements
            | Commande::SitesDangereux
            | Commande::Blocage => Rubrique::Bloquer,
            Commande::VerifierSauvegarde | Commande::Ordinateurs => Rubrique::Donnees,
            Commande::LogicielsPerimes
            | Commande::Demarrage
            | Commande::Nat
            | Commande::CanauxWifi
            | Commande::Logiciels
            | Commande::Nettoyer => Rubrique::Optimiser,
            Commande::Autotest
            | Commande::VerifierMoi
            | Commande::Regles
            | Commande::Couleurs
            | Commande::Agent
            | Commande::Desinstaller
            | Commande::Parametres => Rubrique::Vanguard,
        }
    }
}

/// Ce qu'un changement fait d'un programme au démarrage (lot 2a) : le seul que la fenêtre sait demander.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Sorte {
    /// Le retirer du démarrage : il reste installé.
    Retirer,
    /// Remettre exactement comme avant ce que Vanguard en a retiré.
    Remettre,
}

impl Sorte {
    /// Le mot de `vanguard demarrage --json` (« geste ») et de son issue.
    pub fn mot(self) -> &'static str {
        match self {
            Sorte::Retirer => "retirer",
            Sorte::Remettre => "remettre",
        }
    }

    /// Lit le mot écrit par Vanguard ; tout autre : rien.
    pub fn lire(mot: &str) -> Option<Sorte> {
        [Sorte::Retirer, Sorte::Remettre].into_iter().find(|s| s.mot() == mot)
    }

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    /// L'octet du protocole du relais : 1 ou 2.
    pub fn octet(self) -> u8 {
        match self {
            Sorte::Retirer => 1,
            Sorte::Remettre => 2,
        }
    }

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    pub fn depuis_octet(o: u8) -> Option<Sorte> {
        [Sorte::Retirer, Sorte::Remettre].into_iter().find(|s| s.octet() == o)
    }
}

/// Ce qui désigne un programme au démarrage : les 16 octets que `vanguard demarrage --json` donne à chacun (BLAKE3
/// de son objet). Jamais un nom ni un chemin : Vanguard retrouve lui-même le programme, et refuse le reste.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Empreinte([u8; 16]);

impl Empreinte {
    /// Le jeton de la mise à jour de Vanguard (`mise_a_jour::apercu::JETON` dans Vanguard) : « mise-a-jour-vang ».
    /// Il n'y en a qu'une à la fois ; le relais n'admet que lui pour cette famille.
    pub const MISE_A_JOUR: Empreinte = Empreinte(*b"mise-a-jour-vang");

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    pub fn depuis_octets(o: [u8; 16]) -> Empreinte {
        Empreinte(o)
    }

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    pub fn octets(self) -> [u8; 16] {
        self.0
    }

    /// Exactement 32 chiffres hexadécimaux minuscules ; tout autre texte (majuscule, espace, longueur voisine) :
    /// rien.
    pub fn lire(texte: &str) -> Option<Empreinte> {
        let o = texte.as_bytes();
        if o.len() != 32 {
            return None;
        }
        let (paires, []) = o.as_chunks::<2>() else {
            return None;
        };
        let chiffre = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut e = [0u8; 16];
        for (case, &[h, b]) in e.iter_mut().zip(paires) {
            *case = (chiffre(h)? << 4) | chiffre(b)?;
        }
        Some(Empreinte(e))
    }

    /// Les 32 chiffres hexadécimaux minuscules, tels que Vanguard les attend.
    pub fn hex(self) -> String {
        use std::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(32), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        })
    }
}

/// Un geste sur un constat, désigné par son jeton : celui d'une correction du bilan (`audit --json`), ou celui d'une
/// note d'annulation (`changements --json`). Une liste fermée : la fenêtre ne fabrique jamais un geste d'un nom, d'un
/// chemin ni d'un message. Chaque geste qui change suit le « voir » de sa famille : il rend le jeton et l'accord que
/// cet aperçu a donnés, rien d'autre.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SorteGeste {
    /// `correction --voir <jeton> --json` : l'aperçu d'une correction, lecture seule.
    VoirCorrection,
    /// `correction --appliquer <jeton> --accord <accord> --json` : l'appliquer, telle que montrée.
    AppliquerCorrection,
    /// `changements --voir <jeton> --json` : ce qui serait remis comme avant, lecture seule.
    VoirAnnulation,
    /// `changements --annuler <jeton> --accord <accord> --json` : le remettre, tel que montré.
    Annuler,
    /// `se-mettre-a-jour --voir --json` : ce que la mise à jour installerait, lecture seule. Son jeton est fixe
    /// (`Empreinte::MISE_A_JOUR`) : aucune liste ne l'offre, et il ne part jamais en argument.
    VoirMiseAJour,
    /// `se-mettre-a-jour --appliquer --accord <accord> --json` : l'installer, telle que montrée.
    MettreAJour,
}

/// La famille d'un geste : un « voir » et le geste qui change après lui. Le relais retient par famille la dernière
/// liste et le dernier aperçu (`relais::Etat`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Famille {
    /// Les corrections du bilan.
    Correction,
    /// Les annulations de « Ce que Vanguard a changé ».
    Annulation,
    /// La mise à jour de Vanguard (la carte « Mettre à jour Vanguard ») : une seule, sans liste.
    MiseAJour,
}

impl Famille {
    /// La commande dont relève un geste de cette famille : la lecture de la liste qui offre ses « voir », ou, pour
    /// la mise à jour (qu'aucune liste n'offre), les réglages de la fenêtre, où est sa carte (comme les couleurs et
    /// les animations). Son nom montré reste le sien : voir `Lancement::nom_affiche`.
    pub fn liste(self) -> Commande {
        match self {
            Famille::Correction => Commande::Bilan,
            Famille::Annulation => Commande::Changements,
            Famille::MiseAJour => Commande::Couleurs,
        }
    }

    /// Une liste offre-t-elle les « voir » de cette famille ? Pas la mise à jour : son « voir » a un jeton fixe.
    pub fn offerte_par_une_liste(self) -> bool {
        match self {
            Famille::Correction | Famille::Annulation => true,
            Famille::MiseAJour => false,
        }
    }

    /// Le « voir » de cette famille.
    pub fn voir(self) -> SorteGeste {
        match self {
            Famille::Correction => SorteGeste::VoirCorrection,
            Famille::Annulation => SorteGeste::VoirAnnulation,
            Famille::MiseAJour => SorteGeste::VoirMiseAJour,
        }
    }

    /// Le geste qui change, après le « voir ».
    pub fn changer(self) -> SorteGeste {
        match self {
            Famille::Correction => SorteGeste::AppliquerCorrection,
            Famille::Annulation => SorteGeste::Annuler,
            Famille::MiseAJour => SorteGeste::MettreAJour,
        }
    }
}

impl SorteGeste {
    const TOUTES: [SorteGeste; 6] = [
        SorteGeste::VoirCorrection,
        SorteGeste::AppliquerCorrection,
        SorteGeste::VoirAnnulation,
        SorteGeste::Annuler,
        SorteGeste::VoirMiseAJour,
        SorteGeste::MettreAJour,
    ];

    /// Le mot de Vanguard (« sorte » du geste offert, « geste » de l'issue).
    pub fn mot(self) -> &'static str {
        match self {
            SorteGeste::VoirCorrection => "voir-correction",
            SorteGeste::AppliquerCorrection => "appliquer-correction",
            SorteGeste::VoirAnnulation => "voir-annulation",
            SorteGeste::Annuler => "annuler-correction",
            SorteGeste::VoirMiseAJour => "voir-mise-a-jour",
            SorteGeste::MettreAJour => "mettre-a-jour",
        }
    }

    /// Lit le mot écrit par Vanguard ; tout autre : rien.
    pub fn lire(mot: &str) -> Option<SorteGeste> {
        SorteGeste::TOUTES.into_iter().find(|s| s.mot() == mot)
    }

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    /// L'octet du protocole du relais (10 et 11 : voir et appliquer une correction ; 12 et 13 : voir et faire une
    /// annulation ; 14 et 15 : voir et installer la mise à jour ; les suivants viendront avec leurs lots).
    pub fn octet(self) -> u8 {
        match self {
            SorteGeste::VoirCorrection => 10,
            SorteGeste::AppliquerCorrection => 11,
            SorteGeste::VoirAnnulation => 12,
            SorteGeste::Annuler => 13,
            SorteGeste::VoirMiseAJour => 14,
            SorteGeste::MettreAJour => 15,
        }
    }

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    pub fn depuis_octet(o: u8) -> Option<SorteGeste> {
        SorteGeste::TOUTES.into_iter().find(|s| s.octet() == o)
    }

    /// Un « voir » : il ne change rien, s'interrompt comme une lecture, et son accord est tout à zéro. Les autres
    /// changent : ils passent seuls, ne s'interrompent pas, et leur accord n'est jamais tout à zéro.
    pub fn voir(self) -> bool {
        match self {
            SorteGeste::VoirCorrection | SorteGeste::VoirAnnulation | SorteGeste::VoirMiseAJour => true,
            SorteGeste::AppliquerCorrection | SorteGeste::Annuler | SorteGeste::MettreAJour => false,
        }
    }

    pub fn famille(self) -> Famille {
        match self {
            SorteGeste::VoirCorrection | SorteGeste::AppliquerCorrection => Famille::Correction,
            SorteGeste::VoirAnnulation | SorteGeste::Annuler => Famille::Annulation,
            SorteGeste::VoirMiseAJour | SorteGeste::MettreAJour => Famille::MiseAJour,
        }
    }
}

/// Un geste offert par un constat du bilan, tel que Vanguard l'écrit (`machine::apercu::GesteOffert`) : ses deux
/// champs, en texte brut (ni nettoyés ni tolérés : un sélecteur ou une séquence d'échappement collés au jeton le
/// rendent faux, pas propre), présents, jamais `null`, et seulement eux. La fenêtre (`donnees::bilan`, le bouton
/// « Voir la correction ») et le relais (`relais::gestes_offerts`, les gestes qu'il admet) lisent avec cette même
/// structure : la fenêtre ne montre pas de bouton que le relais refuserait.
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct GesteOffert {
    sorte: String,
    jeton: String,
}

impl GesteOffert {
    /// Le jeton et la sorte, exacts : 32 chiffres hexadécimaux minuscules, un « voir » de la liste ; sinon, rien.
    /// Une liste n'offre jamais directement un geste qui change : il ne part qu'après son aperçu. Ni la mise à
    /// jour : seule sa carte la demande.
    pub fn lire(&self) -> Option<(Empreinte, SorteGeste)> {
        let sorte = SorteGeste::lire(&self.sorte).filter(|s| s.voir() && s.famille().offerte_par_une_liste())?;
        Some((Empreinte::lire(&self.jeton)?, sorte))
    }
}

/// L'accord d'un aperçu : les 32 octets (64 chiffres) que Vanguard calcule sur tout ce qu'il a montré. La fenêtre le
/// garde tel quel ; elle ne le calcule pas et n'en déduit rien. Tout à zéro pour un « voir ».
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Accord([u8; 32]);

impl Accord {
    pub const NUL: Accord = Accord([0; 32]);

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    pub fn depuis_octets(o: [u8; 32]) -> Accord {
        Accord(o)
    }

    // Le protocole du relais n'existe que sous Linux (les essais le lisent partout).
    #[cfg(any(target_os = "linux", test))]
    pub fn octets(self) -> [u8; 32] {
        self.0
    }

    /// Exactement 64 chiffres hexadécimaux minuscules ; tout autre texte : rien.
    pub fn lire(texte: &str) -> Option<Accord> {
        let (moitie_a, moitie_b) = (texte.get(..32)?, texte.get(32..)?);
        let (a, b) = (Empreinte::lire(moitie_a)?, Empreinte::lire(moitie_b)?);
        let mut o = [0u8; 32];
        o[..16].copy_from_slice(&a.0);
        o[16..].copy_from_slice(&b.0);
        Some(Accord(o))
    }

    /// Les 64 chiffres hexadécimaux minuscules, tels que Vanguard les a donnés.
    pub fn hex(self) -> String {
        use std::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(64), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        })
    }

    /// Tout à zéro : pas d'accord (celui d'un « voir », ou absent de la liste du démarrage).
    pub fn nul(self) -> bool {
        self == Accord::NUL
    }
}

/// Un geste qui change part 2 s au moins après la fin de son aperçu : le temps de le lire. La fenêtre n'active
/// « Appliquer » qu'après (conception, Q7), le relais le revérifie, et Vanguard l'exige aussi (son carnet des aperçus).
pub const APERCU_LU: std::time::Duration = std::time::Duration::from_secs(2);

/// Un geste demandé par un clic : sa sorte, le jeton du constat, et l'accord (tout à zéro pour un « voir »).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Geste {
    pub sorte: SorteGeste,
    pub jeton: Empreinte,
    pub accord: Accord,
}

impl Geste {
    /// Voir la correction de ce constat (pour les essais : la fenêtre passe par `voir`, avec la famille de la feuille).
    #[cfg(test)]
    pub fn voir_correction(jeton: Empreinte) -> Geste {
        Geste::voir(Famille::Correction, jeton)
    }

    /// Le « voir » de cette famille, pour ce jeton.
    pub fn voir(famille: Famille, jeton: Empreinte) -> Geste {
        Geste {
            sorte: famille.voir(),
            jeton,
            accord: Accord::NUL,
        }
    }

    /// Le geste qui change de cette famille, avec le jeton et l'accord que son aperçu a donnés, tels quels.
    pub fn changer(famille: Famille, jeton: Empreinte, accord: Accord) -> Geste {
        Geste {
            sorte: famille.changer(),
            jeton,
            accord,
        }
    }
}

/// Un changement demandé après confirmation : un seul programme, par son empreinte, avec l'accord que Vanguard a
/// donné pour ce geste dans la liste (`demarrage --json`). Tout à zéro s'il n'en a pas donné : le changement part
/// sans `--accord`, et Vanguard le refuse (« accord manquant »), refus montré tel quel.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Changement {
    pub sorte: Sorte,
    pub empreinte: Empreinte,
    pub accord: Accord,
}

/// Un changement des couleurs de la fenêtre, pour un thème : un choix (sa base et ses cinq couleurs), ou `None` pour
/// remettre celles de Vanguard. `vanguard` le revérifie et l'écrit ; la fenêtre n'écrit jamais rien.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ChangementCouleurs {
    pub theme: crate::couleurs::Theme,
    pub choix: Option<crate::couleurs::Choix>,
}

/// Une commande de la console et la valeur tapée après son nom (`verifier-fichier ~/Téléchargements/x.pdf`), jugée
/// sur sa forme (`valeur::valider`) pour la sorte que la commande accepte, et pour elle seule. Ses champs sont privés :
/// seule `nouvelle` en fait une, et le relais la refait avec le chemin réel avant de lancer quoi que ce soit.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AvecValeur {
    commande: Commande,
    valeur: String,
}

impl AvecValeur {
    /// Refusée si la commande n'accepte aucune valeur, ou si la valeur n'a pas la forme de sa sorte (vide, « - »
    /// devant, caractère de contrôle ou invisible, trop longue…).
    pub fn nouvelle(commande: Commande, valeur: &str) -> Result<AvecValeur, Refus> {
        let sorte = commande.argument().ok_or(Refus::Forme)?;
        crate::valeur::valider(sorte, valeur)?;
        Ok(AvecValeur {
            commande,
            valeur: valeur.to_owned(),
        })
    }

    pub fn commande(&self) -> Commande {
        self.commande
    }

    // Lues par le protocole du relais (Linux seulement) et par les essais d'attaque : ailleurs, elles n'existent pas.
    #[cfg(any(target_os = "linux", test))]
    pub fn valeur(&self) -> &str {
        &self.valeur
    }

    /// La sorte de la valeur : celle de la commande (toujours là, `nouvelle` l'a vérifié).
    #[cfg(any(target_os = "linux", test))]
    pub fn sorte(&self) -> Argument {
        self.commande.argument().unwrap_or(Argument::Mots)
    }
}

/// Ce qu'une tâche lance : une commande de la liste (elle lit), la même avec une valeur tapée dans la console (elle
/// lit aussi), ou un changement (seulement par un clic confirmé, jamais par la console) : au démarrage, des couleurs
/// de la fenêtre, ou ses animations (`true` : réduites), gardées par `vanguard` pour les prochaines ouvertures.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Lancement {
    Commande(Commande),
    /// Une commande de la console avec sa valeur : `vanguard console <nom> -- <valeur>`, toujours en lecture.
    AvecValeur(AvecValeur),
    Changement(Changement),
    Couleurs(ChangementCouleurs),
    Animations(bool),
    /// Un geste sur un constat du bilan (`Geste`), par son jeton.
    Geste(Geste),
}

impl From<Commande> for Lancement {
    fn from(c: Commande) -> Lancement {
        Lancement::Commande(c)
    }
}

impl Lancement {
    /// Les arguments donnés à `vanguard`. Un changement n'a qu'une forme : `demarrage --retirer|--remettre
    /// <32 chiffres> --accord <64 chiffres> --json` (sans `--accord` s'il n'y en a pas), sans question (stdin fermé ; la fenêtre administrateur du système, s'il en faut une,
    /// est la seule).
    pub fn arguments(&self) -> Vec<String> {
        match self {
            Lancement::Commande(c) => c.arguments().iter().map(|a| (*a).to_string()).collect(),
            // Une liste fermée de quatre mots : la valeur n'en est que la dernière case, toujours après « -- » (jamais
            // lue comme une option), jamais passée par un shell. `vanguard console` la rejuge en entier.
            Lancement::AvecValeur(av) => vec![
                "console".to_string(),
                av.commande.nom().to_string(),
                "--".to_string(),
                av.valeur.clone(),
            ],
            Lancement::Changement(ch) => {
                let option = match ch.sorte {
                    Sorte::Retirer => "--retirer",
                    Sorte::Remettre => "--remettre",
                };
                let mut a = vec!["demarrage".to_string(), option.to_string(), ch.empreinte.hex()];
                if !ch.accord.nul() {
                    a.extend(["--accord".to_string(), ch.accord.hex()]);
                }
                a.push("--json".to_string());
                a
            }
            // Des mots fermés et des couleurs de six chiffres hexadécimaux, construits ici depuis des valeurs typées.
            Lancement::Couleurs(cc) => {
                let mut a = vec![
                    "couleurs".to_string(),
                    "--theme".to_string(),
                    cc.theme.mot().to_string(),
                ];
                match cc.choix {
                    Some(c) => a.extend([
                        "--base".to_string(),
                        c.base.mot().to_string(),
                        "--vifs".to_string(),
                        crate::couleurs::vifs_hex(&c.vifs),
                    ]),
                    None => a.push("--defaut".to_string()),
                }
                a.push("--json".to_string());
                a
            }
            // Deux mots fermés, rien d'autre.
            Lancement::Animations(reduites) => {
                let mot = if *reduites { "reduites" } else { "toutes" };
                ["couleurs", "--animations", mot, "--json"].map(str::to_string).to_vec()
            }
            // Une forme fixe par sorte, le jeton en 32 chiffres et l'accord en 64 construits ici depuis leurs octets :
            // jamais un texte relu par la fenêtre.
            Lancement::Geste(g) => {
                let (commande, option) = match g.sorte {
                    SorteGeste::VoirCorrection => ("correction", "--voir"),
                    SorteGeste::AppliquerCorrection => ("correction", "--appliquer"),
                    SorteGeste::VoirAnnulation => ("changements", "--voir"),
                    SorteGeste::Annuler => ("changements", "--annuler"),
                    SorteGeste::VoirMiseAJour => ("se-mettre-a-jour", "--voir"),
                    SorteGeste::MettreAJour => ("se-mettre-a-jour", "--appliquer"),
                };
                let mut a = vec![commande.to_string(), option.to_string()];
                // La mise à jour n'a qu'un jeton, fixe : Vanguard ne le demande pas en argument.
                if g.sorte.famille() != Famille::MiseAJour {
                    a.push(g.jeton.hex());
                }
                if !g.sorte.voir() {
                    a.extend(["--accord".to_string(), g.accord.hex()]);
                }
                a.push("--json".to_string());
                a
            }
        }
    }

    /// Un changement (au démarrage, des couleurs ou des animations) : il passe seul, et ne s'interrompt pas.
    pub fn change(&self) -> bool {
        match self {
            Lancement::Commande(_) | Lancement::AvecValeur(_) => false,
            Lancement::Geste(g) => !g.sorte.voir(),
            Lancement::Changement(_) | Lancement::Couleurs(_) | Lancement::Animations(_) => true,
        }
    }

    /// Un changement attend peut-être le mot de passe dans la fenêtre administrateur (Windows) : quinze minutes. C'est
    /// le seul cas où il est coupé : ni « Arrêter », ni la fermeture de la fenêtre ne l'interrompent (`relais`).
    pub fn delai(&self) -> Duration {
        match self {
            Lancement::Commande(c) => c.delai(),
            Lancement::AvecValeur(av) => av.commande.delai(),
            Lancement::Changement(_) => Duration::from_mins(15),
            // Écrire un petit fichier, scellé.
            Lancement::Couleurs(_) | Lancement::Animations(_) => Duration::from_mins(1),
            // La mise à jour : l'aperçu peut attendre GitHub (cinq minutes) ; l'installer télécharge, vérifie, essaie
            // et pose chaque copie (trente minutes, une connexion lente comprise).
            Lancement::Geste(g) if g.sorte == SorteGeste::VoirMiseAJour => Duration::from_mins(5),
            Lancement::Geste(g) if g.sorte == SorteGeste::MettreAJour => Duration::from_mins(30),
            // Une seule règle relue (et, pour un geste qui change, quelques droits posés) : quelques secondes, deux
            // minutes pour une règle lente.
            Lancement::Geste(_) => Duration::from_mins(2),
        }
    }

    pub fn sur_ce_systeme(&self) -> bool {
        self.commande().sur_ce_systeme()
    }

    /// Le nom montré dans la console et les messages : celui de sa commande, sauf la mise à jour, qui a le sien
    /// (elle n'est ni « couleurs » ni une autre commande).
    pub fn nom_affiche(&self) -> &'static str {
        match self {
            Lancement::Geste(g) if g.sorte.famille() == Famille::MiseAJour => {
                crate::tr!("Mettre à jour Vanguard", "Update Vanguard")
            }
            _ => self.commande().nom_affiche(),
        }
    }

    /// La commande de la liste dont il relève : celle dont l'écran montre le résultat.
    pub fn commande(&self) -> Commande {
        match self {
            Lancement::Commande(c) => *c,
            Lancement::AvecValeur(av) => av.commande,
            Lancement::Changement(_) => Commande::Demarrage,
            Lancement::Couleurs(_) | Lancement::Animations(_) => Commande::Couleurs,
            Lancement::Geste(g) => g.sorte.famille().liste(),
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
    pub lancement: Lancement,
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
    /// Une commande de la liste et la valeur tapée après son nom, de la forme qu'elle accepte.
    LancerAvec(AvecValeur),
    /// Une commande qui ne se lance qu'avec sa valeur, tapée sans elle : rien n'est lancé, la forme est redite.
    ValeurManquante(Commande),
    /// Une valeur après une commande qui n'en prend aucune : rien n'est lancé.
    SansValeur(Commande),
    /// Une valeur qui n'a pas la forme attendue : rien n'est lancé, la raison est dite (jamais la valeur relue
    /// autrement).
    ValeurRefusee(Commande, Refus),
    /// La liste des commandes permises, sans rien lancer.
    Aide,
    /// `aide <commande>` : ce que fait une commande de la liste, sans la lancer.
    AideSur(Commande),
    /// Vider la console.
    Effacer,
    /// Tout le reste : rien n'est lancé. Le texte tapé, nettoyé et coupé, pour le redire.
    Refusee(String),
}

/// Les mots de la console qui ne lancent rien.
const AIDE: [&str; 3] = ["aide", "help", "?"];
const EFFACER: [&str; 2] = ["effacer", "clear"];

/// Lit une saisie de la console : le nom français ou anglais d'une commande de la liste (« vanguard » devant est
/// permis), seul ou suivi d'UNE valeur si cette commande en accepte une (`Commande::argument`) : tout le reste de la
/// ligne, entre guillemets s'il le faut (`verifier-fichier "~/Téléchargements/mon fichier.pdf"`). La valeur est
/// jugée sur sa forme (`AvecValeur::nouvelle`) ; jamais découpée en plusieurs, jamais lue comme une option, jamais
/// passée à un shell. Tout autre texte est refusé tel quel.
pub fn comprendre(saisie: &str) -> Saisie {
    let t = saisie.trim();
    if t.is_empty() {
        return Saisie::Rien;
    }
    let refus = || Saisie::Refusee(crate::nettoyage::nom(t, 60));
    let (premier, apres) = couper(t);
    let (mot, reste) = if premier.eq_ignore_ascii_case("vanguard") && !apres.is_empty() {
        couper(apres)
    } else {
        (premier, apres)
    };
    let m = mot.to_ascii_lowercase();
    if AIDE.contains(&m.as_str()) {
        return match couper(reste) {
            ("", _) => Saisie::Aide,
            (nom, "") => de_nom(nom).map_or_else(refus, Saisie::AideSur),
            _ => refus(),
        };
    }
    if EFFACER.contains(&m.as_str()) {
        return if reste.is_empty() { Saisie::Effacer } else { refus() };
    }
    let Some(c) = de_nom(&m) else {
        return refus();
    };
    if reste.is_empty() {
        return if c.valeur_requise() {
            Saisie::ValeurManquante(c)
        } else {
            Saisie::Lancer(c)
        };
    }
    if c.argument().is_none() {
        return Saisie::SansValeur(c);
    }
    let Some(valeur) = sans_guillemets(reste) else {
        return Saisie::ValeurRefusee(c, Refus::Forme);
    };
    match AvecValeur::nouvelle(c, valeur) {
        Ok(av) => Saisie::LancerAvec(av),
        Err(r) => Saisie::ValeurRefusee(c, r),
    }
}

/// Le premier mot et le reste, coupés au premier espace ou tab seulement : un autre blanc (U+2028, espace insécable)
/// ne sépare rien, il reste dans le mot, qui n'est alors aucun nom de la liste.
fn couper(t: &str) -> (&str, &str) {
    match t.split_once([' ', '\t']) {
        Some((a, b)) => (a, b.trim_start_matches([' ', '\t'])),
        None => (t, ""),
    }
}

/// La valeur sans ses guillemets, droits ou simples, s'ils l'entourent : sans autre guillemet du même genre dedans
/// (`None` sinon). Sans guillemets autour, la valeur telle quelle.
fn sans_guillemets(reste: &str) -> Option<&str> {
    for g in ['"', '\''] {
        if let Some(dedans) = reste.strip_prefix(g) {
            return dedans.strip_suffix(g).filter(|v| !v.contains(g));
        }
    }
    Some(reste)
}

/// La commande de ce système qui porte ce nom, français ou anglais (casse ASCII ignorée).
fn de_nom(mot: &str) -> Option<Commande> {
    let m = mot.to_ascii_lowercase();
    Commande::ici().find(|c| c.nom() == m || c.nom_anglais() == m)
}

/// Suggestions montrées au plus sous la saisie.
pub const SUGGESTIONS_MAX: usize = 6;
/// Un mot plus long n'est pas comparé (la distance coûte le produit des longueurs).
const MOT_MAX: usize = 40;

/// Les commandes que la saisie peut vouloir dire, pour la liste sous la console : celles dont un nom commence par
/// le mot tapé, puis celles qui le contiennent, puis celles à une ou deux fautes près (« bilna » → bilan), la plus
/// proche d'abord. Seulement une proposition : rien ne se lance sans qu'elle soit choisie (Entrée sur elle, ou un
/// clic). Le mot est le seul de la saisie, ou celui après « vanguard » ou « aide ».
pub fn suggestions(saisie: &str) -> Vec<Commande> {
    let mots: Vec<String> = saisie.split_whitespace().map(str::to_lowercase).collect();
    let mot = match mots.as_slice() {
        [m] => m.as_str(),
        [v, m] if v == "vanguard" || AIDE.contains(&v.as_str()) => m.as_str(),
        _ => return Vec::new(),
    };
    if mot.chars().count() > MOT_MAX || AIDE.contains(&mot) || EFFACER.contains(&mot) {
        return Vec::new();
    }
    let noms = |c: Commande| [c.nom(), c.nom_anglais()];
    let mut v: Vec<Commande> = Commande::ici()
        .filter(|c| noms(*c).iter().any(|n| n.starts_with(mot)))
        .collect();
    for c in Commande::ici() {
        if !v.contains(&c) && mot.chars().count() >= 3 && noms(c).iter().any(|n| n.contains(mot)) {
            v.push(c);
        }
    }
    // Les fautes : une seule pour un mot court, deux à partir de six lettres.
    let seuil = if mot.chars().count() >= 6 { 2 } else { 1 };
    let mut proches: Vec<(usize, Commande)> = Commande::ici()
        .filter(|c| !v.contains(c) && mot.chars().count() >= 3)
        .filter_map(|c| {
            let d = noms(c).iter().map(|n| distance(mot, n)).min().unwrap_or(usize::MAX);
            (d <= seuil).then_some((d, c))
        })
        .collect();
    proches.sort_by_key(|(d, _)| *d);
    v.extend(proches.into_iter().map(|(_, c)| c));
    v.truncate(SUGGESTIONS_MAX);
    v
}

/// La distance entre deux mots, en fautes de frappe : une lettre de plus, de moins, changée, ou deux voisines
/// inversées (distance de Damerau-Levenshtein restreinte). Bornée par l'appelant (`MOT_MAX` lettres).
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    // Une case hors des rangées vaut « très loin » (jamais atteint : les indices restent dans les rangées).
    let lire = |v: &[usize], k: usize| v.get(k).copied().unwrap_or(usize::MAX / 2);
    // Trois rangées : l'avant-dernière (pour l'inversion), la dernière, la courante.
    let mut avant: Vec<usize> = Vec::new();
    let mut prec: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cour: Vec<usize> = Vec::with_capacity(b.len().saturating_add(1));
        cour.push(i.saturating_add(1));
        for (j, cb) in b.iter().enumerate() {
            let change = usize::from(ca != cb);
            let mut d = lire(&prec, j + 1)
                .saturating_add(1)
                .min(lire(&cour, j).saturating_add(1))
                .min(lire(&prec, j).saturating_add(change));
            let inverses = i > 0 && j > 0 && a.get(i - 1) == Some(cb) && b.get(j - 1) == Some(ca) && ca != cb;
            if inverses {
                d = d.min(lire(&avant, j - 1).saturating_add(1));
            }
            cour.push(d);
        }
        avant = std::mem::replace(&mut prec, cour);
    }
    lire(&prec, b.len())
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
            assert!(!AIDE.contains(&c.nom()) && !EFFACER.contains(&c.nom()));
            assert!(c.delai().as_secs() >= 60 && c.delai().as_secs() <= 1800, "{c:?}");
            // Une commande qui ne part qu'avec sa valeur : `console <nom>`, puis « -- » et la valeur (`AvecValeur`).
            if c.valeur_requise() {
                assert_eq!(a, ["console", c.nom()], "{c:?}");
                assert!(c.argument().is_some(), "{c:?}");
                continue;
            }
            // La sous-commande, --json à la fin, et entre les deux seulement une option qui lit (--etat) : aucun mot
            // qui agit (« oui », « non », --choisir, --rallumer, --accepter, --complet…), aucun chemin.
            assert!(
                a.len() == 2 || Commande::LECTURES_A_TROIS_MOTS.iter().any(|f| a == f),
                "{c:?}"
            );
            assert_eq!(a.last(), Some(&"--json"), "{c:?}");
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
            assert!(rien_ne_part(&comprendre(refus)), "{refus:?} accepté");
        }
    }

    /// Une saisie refusée, sous l'une de ses formes : rien ne part.
    fn rien_ne_part(s: &Saisie) -> bool {
        matches!(
            s,
            Saisie::Refusee(_) | Saisie::SansValeur(_) | Saisie::ValeurRefusee(..)
        )
    }

    /// La console ne demande jamais un changement : ni la forme de Vanguard, ni un nom, ni une empreinte.
    #[test]
    fn la_console_refuse_tout_changement() {
        let e = "0123456789abcdef0123456789abcdef";
        for refus in [
            format!("demarrage --retirer {e}"),
            format!("demarrage --remettre {e} --json"),
            format!("vanguard demarrage --retirer {e}"),
            format!("startup --remove {e}"),
            "retirer".to_string(),
            "remettre".to_string(),
            "retirer-du-demarrage".to_string(),
            e.to_string(),
        ] {
            assert!(rien_ne_part(&comprendre(&refus)), "{refus:?} accepté");
        }
        // « demarrage » seul : la liste, qui ne change rien.
        assert_eq!(comprendre("demarrage"), Saisie::Lancer(Commande::Demarrage));
        assert_eq!(
            Lancement::from(Commande::Demarrage).arguments(),
            ["demarrage", "--json"]
        );
    }

    /// Une empreinte : exactement 32 chiffres hexadécimaux minuscules, relus à l'identique ; le changement n'a qu'une
    /// forme d'arguments.
    #[test]
    fn l_empreinte_et_la_forme_du_changement() {
        let texte = "00ff10a0b1c2d3e4f5a6b7c8d9e0f1ab";
        let e = Empreinte::lire(texte).unwrap();
        assert_eq!(e.hex(), texte);
        assert_eq!(Empreinte::depuis_octets(e.octets()), e);
        for faux in [
            String::new(),
            "0".repeat(31),
            "0".repeat(33),
            "0A".repeat(16),
            format!(" {}", "0".repeat(31)),
            format!("{}\n", "0".repeat(31)),
            "g".repeat(32),
            "+0".repeat(16),
            "\u{ff10}".repeat(16),
            "../../etc/passwd/../../etc/pass".to_string(),
        ] {
            assert_eq!(Empreinte::lire(&faux), None, "{faux:?}");
        }
        for (sorte, option) in [(Sorte::Retirer, "--retirer"), (Sorte::Remettre, "--remettre")] {
            // Sans accord donné par la liste : la forme sans `--accord`, que Vanguard refuse.
            let sans = Lancement::Changement(Changement {
                sorte,
                empreinte: e,
                accord: Accord::NUL,
            });
            assert_eq!(sans.arguments(), ["demarrage", option, texte, "--json"]);
            let accord = "5a".repeat(32);
            let l = Lancement::Changement(Changement {
                sorte,
                empreinte: e,
                accord: Accord::lire(&accord).unwrap(),
            });
            assert_eq!(
                l.arguments(),
                ["demarrage", option, texte, "--accord", &accord, "--json"]
            );
            assert_eq!(l.commande(), Commande::Demarrage);
            assert!(l.sur_ce_systeme());
            assert!(l.delai().as_secs() >= 300);
            assert_eq!(Sorte::lire(sorte.mot()), Some(sorte));
            assert_eq!(Sorte::depuis_octet(sorte.octet()), Some(sorte));
        }
        assert_eq!(Sorte::lire("tout-retirer"), None);
        assert_eq!(Sorte::depuis_octet(0), None);
        assert_eq!(Sorte::depuis_octet(3), None);
    }

    /// « Mettre à jour Vanguard » : `se-mettre-a-jour --voir --json`, puis `se-mettre-a-jour --appliquer --accord
    /// <64 chiffres> --json`, sans jeton en argument (le sien est fixe, celui de Vanguard) ; relevant de la rubrique
    /// Vanguard ; le geste qui change a le temps de télécharger. Aucune liste ne l'offre, même écrit tel quel.
    #[test]
    fn la_mise_a_jour_a_sa_forme_fermee() {
        assert_eq!(Empreinte::MISE_A_JOUR.hex(), "6d6973652d612d6a6f75722d76616e67");
        let j = Empreinte::MISE_A_JOUR;
        let l = Lancement::Geste(Geste::voir(Famille::MiseAJour, j));
        assert_eq!(l.arguments(), ["se-mettre-a-jour", "--voir", "--json"]);
        // Rangée avec les réglages où est sa carte (comme les couleurs), jamais sous le nom d'une autre commande.
        assert_eq!(l.commande(), Commande::Couleurs);
        assert_eq!(l.commande().rubrique(), Rubrique::Vanguard);
        assert!(
            ["Mettre à jour Vanguard", "Update Vanguard"].contains(&l.nom_affiche()),
            "{}",
            l.nom_affiche()
        );
        assert!(!l.change());
        let a = Accord::lire(&"e1".repeat(32)).unwrap();
        let l = Lancement::Geste(Geste::changer(Famille::MiseAJour, j, a));
        assert_eq!(
            l.arguments(),
            [
                "se-mettre-a-jour",
                "--appliquer",
                "--accord",
                &"e1".repeat(32),
                "--json"
            ]
        );
        assert!(l.change());
        assert!(l.delai() >= Duration::from_mins(30));
        for sorte in ["voir-mise-a-jour", "mettre-a-jour"] {
            let offert: GesteOffert = serde_json::from_str(&format!(
                r#"{{"sorte":"{sorte}","jeton":"6d6973652d612d6a6f75722d76616e67"}}"#
            ))
            .unwrap();
            assert_eq!(offert.lire(), None, "{sorte}");
        }
    }

    /// « Voir la correction » : `correction --voir <jeton> --json`, rien d'autre ; pas un changement ; son mot et son
    /// octet se relisent, les autres non ; un accord se lit en 64 chiffres minuscules exactement.
    #[test]
    fn voir_une_correction_a_sa_forme_fermee() {
        let texte = "0123456789abcdef0123456789abcdef";
        let j = Empreinte::lire(texte).unwrap();
        let l = Lancement::Geste(Geste::voir_correction(j));
        assert_eq!(l.arguments(), ["correction", "--voir", texte, "--json"]);
        assert_eq!(l.commande(), Commande::Bilan);
        assert!(!l.change());
        for s in SorteGeste::TOUTES {
            assert_eq!(SorteGeste::lire(s.mot()), Some(s));
            assert_eq!(SorteGeste::depuis_octet(s.octet()), Some(s));
        }
        assert_eq!(SorteGeste::lire("Voir-correction"), None);
        // Les gestes qui changent : le jeton puis l'accord, construits depuis leurs octets ; la liste de leur
        // famille ; ils changent.
        let a = Accord::lire(&"cd".repeat(32)).unwrap();
        let l = Lancement::Geste(Geste::changer(Famille::Correction, j, a));
        assert_eq!(
            l.arguments(),
            [
                "correction",
                "--appliquer",
                texte,
                "--accord",
                &"cd".repeat(32),
                "--json"
            ]
        );
        assert_eq!(l.commande(), Commande::Bilan);
        assert!(l.change());
        let l = Lancement::Geste(Geste::voir(Famille::Annulation, j));
        assert_eq!(l.arguments(), ["changements", "--voir", texte, "--json"]);
        assert_eq!(l.commande(), Commande::Changements);
        assert!(!l.change());
        let l = Lancement::Geste(Geste::changer(Famille::Annulation, j, a));
        assert_eq!(
            l.arguments(),
            [
                "changements",
                "--annuler",
                texte,
                "--accord",
                &"cd".repeat(32),
                "--json"
            ]
        );
        assert_eq!(l.commande(), Commande::Changements);
        assert!(l.change());
        // Une liste n'offre qu'un « voir ».
        for (sorte, offert) in [
            ("voir-correction", true),
            ("voir-annulation", true),
            ("appliquer-correction", false),
            ("annuler-correction", false),
        ] {
            let g = GesteOffert {
                jeton: texte.to_string(),
                sorte: sorte.to_string(),
            };
            assert_eq!(g.lire().is_some(), offert, "{sorte}");
        }
        for o in [0, 1, 2, 9, 16, 255] {
            assert_eq!(SorteGeste::depuis_octet(o), None);
        }
        let a = Accord::lire(&"ab".repeat(32)).unwrap();
        assert_eq!(Accord::depuis_octets(a.octets()), a);
        assert_eq!(a.octets(), [0xab; 32]);
        for faux in [
            "AB".repeat(32),
            "ab".repeat(31),
            "ab".repeat(33),
            format!("{}zz", "ab".repeat(31)),
        ] {
            assert_eq!(Accord::lire(&faux), None, "{faux}");
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
        assert_eq!(Commande::TOUTES[34], Commande::Couleurs);
        assert_eq!(Commande::TOUTES[35], Commande::Agent);
        assert_eq!(Commande::TOUTES[44], Commande::Ordinateurs);
        assert_eq!(
            Commande::TOUTES[45..],
            [
                Commande::Chercher,
                Commande::Lien,
                Commande::VerifierFichier,
                Commande::CourrielSuspect
            ]
        );
    }

    /// Les lectures ajoutées au lot « console, commandes » : chacune se tape en français et en anglais, part à la fin
    /// de la liste (rang du relais), sous sa forme fixée qui lit, et sa sortie (forme libre) se lit. Un mot de plus
    /// (celui qui, dans un terminal, changerait un réglage) est refusé : la console ne prend qu'un mot.
    #[test]
    fn les_lectures_ajoutees_se_tapent_et_se_lisent() {
        let ajoutees: [(Commande, Rubrique, &str); 10] = [
            (
                Commande::Agent,
                Rubrique::Vanguard,
                r#"{"schema":1,"agent":"en-marche","missions":[]}"#,
            ),
            (
                Commande::CameraMicro,
                Rubrique::Arnaques,
                r#"{"schema":1,"historique":false,"camera":[],"micro":null,"tout_lu":false,"suspects":0,"conclusion":"x"}"#,
            ),
            (
                Commande::Logiciels,
                Rubrique::Optimiser,
                r#"{"schema":1,"proposes":1,"installes":1,"a_installer":0,"categories":[{"categorie":"Navigateurs","logiciels":[{"nom":"Firefox","installe":true,"source":"paquet"}]}],"a_savoir":"x"}"#,
            ),
            (
                Commande::Nettoyer,
                Rubrique::Optimiser,
                r#"{"schema":1,"disque_libre":"1 Go","disque_total":"2 Go","elements":[{"titre":"Corbeille","octets":10,"taille":"10 o","coche_d_office":true,"propre":false,"prudence":null}],"a_liberer_coche":"10 o","a_liberer_tout":"10 o","a_savoir":"x"}"#,
            ),
            (
                Commande::Desinstaller,
                Rubrique::Vanguard,
                r#"{"schema":1,"elements":[{"element":"Dossier","precision":"p","detail":"d","coche_d_office":false}],"changements_a_defaire_d_abord":[],"a_faire_soi_meme":[],"pas_a_vanguard":[],"non_verifie":[],"a_savoir":["x"]}"#,
            ),
            (
                Commande::SitesDangereux,
                Rubrique::Bloquer,
                r#"{"schema":1,"fichier":"/etc/hosts","bloc_abime":false,"bloques":false,"sites":null,"depuis":null,"a_savoir":"x"}"#,
            ),
            (
                Commande::Parametres,
                Rubrique::Vanguard,
                r#"{"schema":1,"parametres_json":"lu","reglages":[{"reglage":"langue","valeur":"auto"}],"a_savoir":"x"}"#,
            ),
            (
                Commande::Blocage,
                Rubrique::Bloquer,
                r#"{"schema":1,"categories":[{"categorie":"c","mode":"un clic","geste":"g"}],"protection_active":false,"accord_le":null,"a_savoir":[]}"#,
            ),
            (
                Commande::VerifierSauvegarde,
                Rubrique::Donnees,
                r#"{"schema":1,"mise_en_place":"rsync","date":"2020-01-01","destination":"/x","etat":"se_relit","conclusion":"x","relus":{"identiques":3},"problemes":[]}"#,
            ),
            (
                Commande::Ordinateurs,
                Rubrique::Donnees,
                r#"{"schema":1,"cle":true,"ordinateurs":[{"surnom":"Portable","ici":true,"problemes":[]}],"a_savoir":[]}"#,
            ),
        ];
        for (c, rubrique, exemple) in ajoutees {
            let rang = Commande::TOUTES.iter().position(|x| *x == c).unwrap();
            assert!(rang >= 35, "{c:?} : une commande nouvelle se met à la fin");
            assert_eq!(comprendre(c.nom()), Saisie::Lancer(c));
            assert_eq!(comprendre(c.nom_anglais()), Saisie::Lancer(c));
            assert_eq!(comprendre(&format!("vanguard {}", c.nom())), Saisie::Lancer(c));
            for de_plus in ["on", "off", "langue en", "annuler", "--appliquer", "--recommandes"] {
                assert!(
                    rien_ne_part(&comprendre(&format!("{} {de_plus}", c.nom()))),
                    "{c:?} {de_plus}"
                );
            }
            assert!(c.sur_ce_systeme() && Commande::ici().any(|x| x == c), "{c:?}");
            assert_eq!(c.rubrique(), rubrique, "{c:?}");
            assert_eq!(c.forme(), Forme::Libre, "{c:?}");
            assert!(!Lancement::from(c).change(), "{c:?}");
            let vue = crate::donnees::libre::lire(exemple.as_bytes()).unwrap();
            assert!(!vue.lignes.is_empty() && !vue.coupe, "{c:?}");
            assert!(!c.titre().is_empty() && !c.description().is_empty(), "{c:?}");
        }
        assert_eq!(Commande::TOUTES.len(), 49);
    }

    fn avec(c: Commande, v: &str) -> Saisie {
        Saisie::LancerAvec(AvecValeur::nouvelle(c, v).unwrap())
    }

    /// Une valeur après le nom : une seule case, de la sorte de la commande, telle que tapée (guillemets autour
    /// retirés, « ~ » gardé : le relais et `vanguard` seuls le développent).
    #[test]
    fn une_valeur_se_tape_apres_le_nom() {
        use Commande::{Chercher, CourrielSuspect, DernieresFailles, Evenements, Lien, VerifierFichier};
        let f = "~/Téléchargements/x.pdf";
        assert_eq!(comprendre(&format!("verifier-fichier {f}")), avec(VerifierFichier, f));
        assert_eq!(comprendre(&format!("check-file {f}")), avec(VerifierFichier, f));
        assert_eq!(
            comprendre(&format!("vanguard verifier-fichier {f}")),
            avec(VerifierFichier, f)
        );
        assert_eq!(
            comprendre(&format!("verifier-fichier\t\t{f}  ")),
            avec(VerifierFichier, f)
        );
        let espace = "~/Téléchargements/ma facture.pdf";
        assert_eq!(
            comprendre(&format!("verifier-fichier \"{espace}\"")),
            avec(VerifierFichier, espace)
        );
        assert_eq!(
            comprendre(&format!("verifier-fichier '{espace}'")),
            avec(VerifierFichier, espace)
        );
        assert_eq!(
            comprendre(&format!("verifier-fichier {espace}")),
            avec(VerifierFichier, espace)
        );
        assert_eq!(
            comprendre("courriel-suspect /run/media/alice/CLE/message.eml"),
            avec(CourrielSuspect, "/run/media/alice/CLE/message.eml")
        );
        assert_eq!(
            comprendre("lien https://exemple.test/a?b=c"),
            avec(Lien, "https://exemple.test/a?b=c")
        );
        assert_eq!(
            comprendre("chercher pare-feu ouvert"),
            avec(Chercher, "pare-feu ouvert")
        );
        assert_eq!(
            comprendre("evenements inc-20261116-1"),
            avec(Evenements, "inc-20261116-1")
        );
        assert_eq!(comprendre("evenements"), Saisie::Lancer(Evenements));
        assert_eq!(comprendre("dernieres-failles 30"), avec(DernieresFailles, "30"));
        assert_eq!(comprendre("dernieres-failles"), Saisie::Lancer(DernieresFailles));
        // Sans sa valeur : la forme est redite, rien ne part.
        for c in [Chercher, Lien, VerifierFichier, CourrielSuspect] {
            assert_eq!(comprendre(c.nom()), Saisie::ValeurManquante(c));
            assert_eq!(comprendre(c.nom_anglais()), Saisie::ValeurManquante(c));
            assert_eq!(comprendre(&format!("aide {}", c.nom())), Saisie::AideSur(c));
        }
        // Une valeur pour une commande qui n'en prend pas.
        assert_eq!(comprendre("bilan x"), Saisie::SansValeur(Commande::Bilan));
        assert_eq!(
            comprendre("protection --json"),
            Saisie::SansValeur(Commande::Protection)
        );
    }

    /// La fenêtre et `vanguard console` s'accordent : les mêmes commandes prennent une valeur, chacune de la même
    /// sorte (la règle de la valeur, elle, est un seul fichier compilé des deux côtés, `src/socle/valeur_console.rs`).
    #[test]
    fn la_fenetre_et_vanguard_ont_la_meme_liste_de_valeurs() {
        const VANGUARD: &str = include_str!("../../src/demarrage/console.rs");
        let mut cote_vanguard: Vec<(String, String)> = Vec::new();
        let corps = VANGUARD
            .split("fn sorte(")
            .nth(1)
            .unwrap()
            .split("_ => return None")
            .next()
            .unwrap();
        for ligne in corps.lines().filter(|l| l.contains("=> Argument::")) {
            let (noms, sorte) = ligne.split_once("=>").unwrap();
            let sorte = sorte.trim().trim_end_matches(',').trim_start_matches("Argument::");
            for n in noms.split('|') {
                cote_vanguard.push((n.trim().trim_matches('"').to_string(), sorte.to_string()));
            }
        }
        let mut cote_fenetre: Vec<(String, String)> = Commande::TOUTES
            .iter()
            .filter_map(|c| Some((c.nom().to_string(), format!("{:?}", c.argument()?))))
            .collect();
        cote_vanguard.sort();
        cote_fenetre.sort();
        assert_eq!(cote_fenetre, cote_vanguard);
        assert_eq!(cote_fenetre.len(), 8);
        // Et la liste fermée de `vanguard console` (NOMS) est exactement celle-là.
        let noms = VANGUARD
            .split("NOMS: [&str; 8] = [")
            .nth(1)
            .unwrap()
            .split("];")
            .next()
            .unwrap();
        let mut noms: Vec<String> = noms
            .split(',')
            .map(|n| n.trim().trim_matches('"').to_string())
            .filter(|n| !n.is_empty())
            .collect();
        noms.sort();
        assert_eq!(noms, cote_fenetre.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>());
    }

    /// Chaque refus de la valeur, avec sa raison : rien ne part, la phrase dit pourquoi.
    #[test]
    fn chaque_refus_de_valeur_a_sa_raison() {
        use Commande::{Chercher, DernieresFailles, Evenements, Lien, VerifierFichier};
        for (saisie, c, r) in [
            ("lien --internet", Lien, Refus::Tiret),
            ("lien -x", Lien, Refus::Tiret),
            ("lien \"--internet\"", Lien, Refus::Tiret),
            ("lien \"\"", Lien, Refus::Vide),
            ("lien \"   \"", Lien, Refus::Vide),
            ("lien ' x'", Lien, Refus::Bords),
            ("lien a b", Lien, Refus::Forme),
            ("lien \"a\"b\"", Lien, Refus::Forme),
            ("lien \"a", Lien, Refus::Forme),
            ("chercher a\u{202E}b", Chercher, Refus::Invisible),
            ("chercher a\u{200E}b", Chercher, Refus::Invisible),
            ("chercher a\u{2066}b", Chercher, Refus::Invisible),
            ("chercher a\u{2028}b", Chercher, Refus::Invisible),
            ("chercher a\u{2029}b", Chercher, Refus::Invisible),
            ("chercher a\u{200B}b", Chercher, Refus::Invisible),
            ("chercher a\u{7f}b", Chercher, Refus::Controle),
            ("chercher a\u{85}b", Chercher, Refus::Controle),
            ("chercher a\u{1b}[2Kb", Chercher, Refus::Controle),
            ("chercher a\nb", Chercher, Refus::Controle),
            ("chercher a\0b", Chercher, Refus::Controle),
            ("dernieres-failles 0", DernieresFailles, Refus::Forme),
            ("dernieres-failles 3651", DernieresFailles, Refus::Forme),
            ("dernieres-failles 030", DernieresFailles, Refus::Forme),
            ("dernieres-failles ３", DernieresFailles, Refus::Forme),
            ("dernieres-failles ３０", DernieresFailles, Refus::TropLongue),
            ("dernieres-failles 10000", DernieresFailles, Refus::TropLongue),
            ("evenements inc 1", Evenements, Refus::Forme),
            ("evenements ../x", Evenements, Refus::Forme),
            ("verifier-fichier x.pdf", VerifierFichier, Refus::Relatif),
            (
                "verifier-fichier ../../.ssh/id_ed25519",
                VerifierFichier,
                Refus::Remontee,
            ),
            (
                "verifier-fichier ~/../alice/.ssh/id_ed25519",
                VerifierFichier,
                Refus::Remontee,
            ),
            ("verifier-fichier ~alice/x", VerifierFichier, Refus::Tilde),
            ("verifier-fichier ~//etc/passwd", VerifierFichier, Refus::Relatif),
        ] {
            assert_eq!(comprendre(saisie), Saisie::ValeurRefusee(c, r), "{saisie:?}");
            assert_ne!(r.phrase(), "");
        }
        // Les bornes : 256 octets de mots passent, 257 non ; 4096 de chemin passent, 4097 non.
        assert_eq!(
            comprendre(&format!("chercher {}", "a".repeat(256))),
            avec(Chercher, &"a".repeat(256))
        );
        assert_eq!(
            comprendre(&format!("chercher {}", "a".repeat(257))),
            Saisie::ValeurRefusee(Chercher, Refus::TropLongue)
        );
        let chemin = format!("/{}", "a".repeat(4095));
        assert_eq!(
            comprendre(&format!("verifier-fichier {chemin}")),
            avec(VerifierFichier, &chemin)
        );
        assert_eq!(
            comprendre(&format!("verifier-fichier {chemin}a")),
            Saisie::ValeurRefusee(VerifierFichier, Refus::TropLongue)
        );
        assert_eq!(
            comprendre(&format!("lien https://exemple.test/{}", "a".repeat(5000))),
            Saisie::ValeurRefusee(Lien, Refus::TropLongue)
        );
        // `AvecValeur` ne se fabrique que par la règle : une commande sans sorte n'en a pas.
        assert_eq!(AvecValeur::nouvelle(Commande::Bilan, "x"), Err(Refus::Forme));
    }

    /// Un changement de couleurs part en mots fermés et en couleurs construites ici ; la lecture des couleurs n'est
    /// ni montrée, ni comprise par la console.
    #[test]
    fn les_couleurs_partent_en_valeurs_construites_et_restent_cachees() {
        use crate::couleurs::{Base, Choix, Theme};
        let c = Choix::du_prereglage(Base::Braise, Theme::Sombre);
        let l = Lancement::Couleurs(ChangementCouleurs {
            theme: Theme::Sombre,
            choix: Some(c),
        });
        assert_eq!(
            l.arguments(),
            [
                "couleurs",
                "--theme",
                "sombre",
                "--base",
                "braise",
                "--vifs",
                &crate::couleurs::vifs_hex(&c.vifs),
                "--json"
            ]
        );
        assert!(l.change());
        assert_eq!(l.commande(), Commande::Couleurs);
        let defaut = Lancement::Couleurs(ChangementCouleurs {
            theme: Theme::Clair,
            choix: None,
        });
        assert_eq!(
            defaut.arguments(),
            ["couleurs", "--theme", "clair", "--defaut", "--json"]
        );
        assert!(!Lancement::from(Commande::Couleurs).change());
        // Les animations : deux mots fermés, un changement qui passe seul.
        for (reduites, mot) in [(true, "reduites"), (false, "toutes")] {
            let a = Lancement::Animations(reduites);
            assert_eq!(a.arguments(), ["couleurs", "--animations", mot, "--json"]);
            assert!(a.change());
            assert_eq!(a.commande(), Commande::Couleurs);
        }
        assert!(Commande::ici().all(|c| c != Commande::Couleurs));
        for saisie in ["couleurs", "colors", "vanguard couleurs"] {
            assert!(matches!(comprendre(saisie), Saisie::Refusee(_)), "{saisie}");
        }
        assert_eq!(completer("coul"), None);
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
        assert_eq!(completer("ver"), None, "verifier-moi et verifier-sauvegarde");
        assert_eq!(completer("verifier-m"), Some("verifier-moi"));
        assert_eq!(completer("verifier-s"), Some("verifier-sauvegarde"));
    }

    /// Les suggestions : les noms qui commencent par le mot, puis ceux qui le contiennent, puis les fautes de frappe
    /// (« bilna » → bilan) ; jamais un mot qui n'est pas un nom de la liste, jamais plus de six.
    #[test]
    fn les_suggestions_tolerent_les_fautes() {
        assert_eq!(suggestions("bilna").first(), Some(&Commande::Bilan));
        assert_eq!(suggestions("bialn").first(), Some(&Commande::Bilan));
        assert_eq!(suggestions("vanguard bilna").first(), Some(&Commande::Bilan));
        assert_eq!(suggestions("aide bilna").first(), Some(&Commande::Bilan));
        assert_eq!(suggestions("Bil").first(), Some(&Commande::Bilan));
        assert!(suggestions("bil").contains(&Commande::BilanConfidentialite));
        assert_eq!(suggestions("chek").first(), Some(&Commande::Bilan));
        assert_eq!(suggestions("appareil").first(), Some(&Commande::Appareils));
        for rien in [
            "",
            "   ",
            "zzzz",
            "bilan corriger",
            "aide",
            "effacer",
            "x",
            &"a".repeat(41),
        ] {
            assert_eq!(suggestions(rien), Vec::<Commande>::new(), "{rien:?}");
        }
        assert!(suggestions("e").len() <= SUGGESTIONS_MAX);
        // Une suggestion n'est qu'une proposition : la saisie fautive reste refusée.
        assert!(matches!(comprendre("bilna"), Saisie::Refusee(_)));
        assert_eq!(distance("bilna", "bilan"), 1);
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("abc", ""), 3);
        assert_eq!(distance("abc", "abc"), 0);
        assert_eq!(distance("kitten", "sitting"), 3);
    }

    /// `aide <commande>` : seulement un nom de la liste, sans rien lancer ; tout le reste est refusé.
    #[test]
    fn aide_sur_une_commande() {
        assert_eq!(comprendre("aide bilan"), Saisie::AideSur(Commande::Bilan));
        assert_eq!(comprendre("HELP check"), Saisie::AideSur(Commande::Bilan));
        assert_eq!(comprendre("? appareils"), Saisie::AideSur(Commande::Appareils));
        for refus in [
            "aide bilna",
            "aide bilan --json",
            "aide aide",
            "aide corriger",
            "aide demarrage --retirer",
        ] {
            assert!(matches!(comprendre(refus), Saisie::Refusee(_)), "{refus:?}");
        }
    }

    #[test]
    fn chaque_rubrique_garde_ses_commandes() {
        let total: usize = Rubrique::TOUTES.iter().map(|r| r.commandes().count()).sum();
        // Les commandes qui ne partent qu'avec leur valeur ne sont dans aucune rubrique : elles se tapent.
        assert_eq!(total, Commande::ici().filter(|c| !c.valeur_requise()).count());
        assert_eq!(Rubrique::Accueil.commandes().count(), 0);
        assert_eq!(Rubrique::Vanguard.commandes().count(), 6);
        assert_eq!(Rubrique::Donnees.commandes().count(), 2);
        for r in Rubrique::TOUTES {
            assert!(r.nom_court().lines().all(|l| l.chars().count() <= 12), "{r:?}");
        }
    }
}
