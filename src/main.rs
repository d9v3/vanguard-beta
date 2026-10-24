//! Vanguard — cyberdéfense portable des postes et des réseaux : bilan, correctifs, réglages.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

mod a_laisser;
mod annulation;
mod apprentissage;
mod archives;
mod audit;
mod autotest;
#[cfg(test)]
mod canaris;
mod changements;
mod chiffrement;
mod commande;
mod copier;
mod corriger;
mod depanner;
mod desinstaller;
mod diagnostic;
mod dns_rapide;
mod donnees;
mod entretien;
#[cfg(test)]
mod essais;
mod evenements;
mod fenetre;
mod fiche;
mod gaming;
mod guide;
mod historique;
mod http;
mod journal;
mod langue;
mod lenteur;
mod logiciels;
mod machine;
mod maj;
mod mise_a_jour;
mod modele;
mod nettoyer;
mod optimiser;
mod ordinateurs;
mod parametres;
mod passage;
#[cfg(any(windows, test))]
mod pe;
#[cfg(any(target_os = "macos", test))]
mod plist;
mod plugins;
mod prediction;
mod protection;
mod raccourci;
mod rapport;
mod reparer;
mod reseau;
mod risk;
mod sauvegarde;
mod sceau;
mod selection;
mod signaler;
mod socle;
mod sqlite;
mod traces;
mod ui;
mod verifier_cle;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use machine::Audit;
use reseau::{Options, Rapport};
use selection::{Ligne, choisir, choisir_au_sommet};
use ui::*;

#[derive(Parser)]
#[command(
    version,
    about = "Cyberdéfense portable des postes et des réseaux : bilan, correctifs, réglages. Sans argument : menu."
)]
struct Args {
    #[command(subcommand)]
    commande: Option<Commande>,
}

#[derive(Subcommand)]
enum Commande {
    /// Bilan complet : cet ordinateur puis le réseau.
    #[command(visible_alias = "full")]
    Complet {
        /// Ouvrir aussi le rapport HTML dans le navigateur.
        #[arg(long)]
        html: bool,
        /// Afficher le rapport en texte simple (Markdown) dans le terminal : sans navigateur ni affichage graphique.
        #[arg(long, visible_alias = "text")]
        texte: bool,
    },
    /// Audit de cet ordinateur (pare-feu, ports, SSH, mises à jour, chiffrement…).
    #[command(visible_alias = "audit")]
    Machine {
        #[arg(long)]
        json: bool,
    },
    /// Audit de l'ordinateur puis application guidée des correctifs.
    #[command(visible_alias = "fix")]
    Corriger,
    /// Scan du réseau : appareils, ports ouverts, risques, nouveautés depuis les scans précédents.
    #[command(visible_alias = "network")]
    Reseau {
        /// IP, réseau CIDR (10.0.0.0/24) ou plage (10.0.0.1-50). Par défaut : votre réseau local.
        cible: Option<String>,
        /// « courants » (défaut), « tous » (1-65535) ou liste « 22,80,8000-8100 ».
        #[arg(short, long, default_value = "courants")]
        ports: String,
        /// Délai de connexion par port, en millisecondes.
        #[arg(short, long, default_value_t = 500)]
        timeout: u64,
        /// Nombre de connexions simultanées.
        #[arg(short = 'j', long, default_value_t = 512)]
        parallele: usize,
        #[arg(long)]
        json: bool,
    },
    /// Audit du réseau par domaine : six notes (exposition à Internet, Wi-Fi, segmentation, DNS et TLS, objets
    /// connectés, ordinateurs) d'après le scan du réseau local, les constats réseau de cet ordinateur et quelques
    /// lectures de plus, sans rien attaquer ; ce qui n'a pas pu être vérifié est dit, jamais compté comme sain.
    #[command(name = "audit-reseau", visible_alias = "network-audit")]
    AuditReseau {
        #[arg(long)]
        json: bool,
        /// Ouvrir aussi le rapport HTML dans le navigateur.
        #[arg(long)]
        html: bool,
        /// Vous êtes sur le réseau invité : Vanguard vérifie qu'il est bien séparé du réseau principal.
        #[arg(long, visible_alias = "guest")]
        invite: bool,
    },
    /// Recherche de malwares : ClamAV (Linux, macOS) ou Microsoft Defender (Windows).
    Antivirus {
        /// Tout le dossier personnel au lieu des endroits à risque.
        #[arg(long, visible_alias = "full")]
        complet: bool,
        /// Une clé USB, un disque externe ou un dossier à analyser en entier.
        dossier: Option<std::path::PathBuf>,
    },
    /// Active ou désactive la surveillance horaire du réseau (notification si appareil inconnu).
    #[command(visible_alias = "monitor")]
    Surveillance {
        #[arg(value_parser = ["on", "off"])]
        etat: String,
    },
    /// Tableau de bord de la surveillance dans le navigateur : son état, les alertes jour par jour, les nouveaux
    /// appareils et les connexions suspectes. Page locale, rien n'est envoyé.
    #[command(visible_alias = "dashboard")]
    Tableau {
        /// Écrire la page sans l'ouvrir (sans affichage graphique, par SSH).
        #[arg(long, visible_alias = "no-open")]
        sans_ouvrir: bool,
    },
    /// Dernières failles exploitées : celles que la CISA a ajoutées à son catalogue (attaques réelles connues) ces
    /// derniers jours, les plus récentes d'abord ; sous Arch, celles qui touchent un paquet de cet ordinateur en tête.
    #[command(name = "dernieres-failles", visible_alias = "latest-flaws")]
    DernieresFailles {
        /// Combien de jours en arrière (7 par défaut).
        #[arg(long, visible_alias = "days", default_value_t = 7)]
        jours: u32,
    },
    /// Sites dangereux bloqués par le fichier hosts : ceux d'URLhaus et les serveurs de commande de ThreatFox (clé
    /// abuse.ch), après accord et avec les droits d'administrateur ; « off » les retire exactement. Sans argument :
    /// leur état.
    #[command(name = "sites-dangereux", visible_alias = "dangerous-sites")]
    SitesDangereux {
        #[arg(value_parser = ["on", "off"])]
        etat: Option<String>,
    },
    /// Veilleur (Linux 6.6 et plus) : chaque programme lancé et chaque connexion fermée, vus sur le moment et jugés
    /// comme au bilan ; avec la protection active, il peut geler et arrêter un rançongiciel quasi certain. Coupé par
    /// défaut. Sans argument : son état, puis l'allumer ou le couper, après accord. « rancongiciel on|off » règle la
    /// veille anti-rançongiciel des dossiers personnels.
    #[command(visible_alias = "watcher")]
    Veilleur {
        #[arg(value_parser = ["on", "off", "rancongiciel", "ransomware"])]
        etat: Option<String>,
        /// Pour « rancongiciel » : on ou off.
        #[arg(value_parser = ["on", "off"])]
        sous_etat: Option<String>,
        /// Le service lui-même, lancé par systemd.
        #[arg(long, hide = true)]
        servir: bool,
    },
    /// Entretien du mois : une fois par mois, en silence, la note, les mises à jour en attente, la place à libérer et
    /// les problèmes nouveaux, en une notification ; rien n'est changé. Sans argument : ce qu'il dirait maintenant.
    #[command(visible_alias = "maintenance")]
    Entretien {
        #[arg(value_parser = ["on", "off"])]
        etat: Option<String>,
    },
    /// Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord.
    #[command(visible_alias = "update", alias = "mises-a-jour")]
    Maj,
    /// Réparations courantes : réseau, navigation détournée, pare-feu, antivirus, fichiers système, disque, place, mises à jour, heure.
    #[command(visible_alias = "repair")]
    Reparer,
    /// Gaming : composants pour les jeux (Windows : Visual C++, DirectX… ; Linux : Steam, Vulkan, GameMode, Wine… ;
    /// macOS : Rosetta, Steam, Epic…) et réglages du système.
    Gaming,
    /// Diagnostic de l'ordinateur : matériel, système et problèmes récents (plantages, erreurs). Lecture seule.
    #[command(visible_alias = "diag")]
    Diagnostic,
    /// Logiciels : les meilleurs, libres pour la plupart (navigateurs, mots de passe, bureautique, vidéo, création,
    /// outils système…), par catégorie : choisir puis installer depuis la source officielle du système.
    #[command(visible_alias = "apps")]
    Logiciels {
        /// Montrer chaque logiciel proposé et son état, sans rien installer.
        #[arg(long, visible_alias = "list")]
        liste: bool,
        /// Installer le pack de départ (navigateur, mots de passe, vidéo, bureautique, archives), après accord.
        #[arg(long, visible_alias = "recommended")]
        recommandes: bool,
    },
    /// Nettoyer le système : caches, fichiers temporaires, paquets téléchargés, vieux journaux, corbeille… La place
    /// libérée par chaque élément est montrée avant ; on coche, puis on accepte.
    #[command(visible_alias = "clean")]
    Nettoyer {
        /// Montrer ce qui pourrait être nettoyé et la place à gagner, sans rien effacer.
        #[arg(long, visible_alias = "list")]
        liste: bool,
    },
    /// Optimiser : les réglages recommandés, ceux de confidentialité, de performance (sauf macOS) et de confort, chacun
    /// montré, accepté puis annulable exactement ; « annuler » remet tout comme avant. Sans argument : le menu
    /// Optimiser.
    #[command(visible_alias = "optimize")]
    Optimiser {
        /// recommandes, confidentialite, performance, confort ou annuler.
        #[arg(value_parser = [
            "recommandes", "recommended", "confidentialite", "privacy", "performance", "confort", "comfort",
            "annuler", "undo",
        ])]
        quoi: Option<String>,
    },
    /// Ce que Vanguard a appris sur cet ordinateur : les alertes déclarées normales, et les oublier.
    #[command(visible_alias = "learned")]
    Appris,
    /// Test de connexion pour le jeu : ping, gigue, pertes, débit et bufferbloat.
    #[command(visible_alias = "connection")]
    Connexion,
    /// L'adresse Internet publique est-elle sur une liste noire (Spamhaus, SpamCop, DroneBL, PSBL) ? Si oui, un
    /// appareil est sans doute infecté. Après accord : les listes voient l'adresse.
    #[command(name = "listes-noires", visible_alias = "blocklists")]
    ListesNoires,
    /// Wi-Fi encombré : les réseaux voisins par canal, et le canal le plus libre à régler sur le routeur. Lecture
    /// seule.
    #[command(visible_alias = "channels")]
    Canaux,
    /// Type de NAT pour le jeu (ouvert, modéré ou strict), d'après deux serveurs publics (STUN). Lecture seule.
    Nat,
    /// Caméras cachées : sur le réseau d'une location ou de quelqu'un, les appareils qui ressemblent à des caméras.
    /// Lecture seule.
    Cameras,
    /// Routeur et objets connectés d'après le dernier scan gardé : ce que le routeur annonce (modèle, logiciel), son
    /// administration en HTTP seul, les caméras, imprimantes, NAS… et leur mot de passe d'origine. Rien n'est sondé.
    #[command(visible_alias = "iot")]
    Objets,
    /// DNS le plus rapide : mesure le DNS actuel et des DNS publics, puis propose le plus rapide, annulable. Un DNS
    /// qui protège (NextDNS, chiffré, filtrant) est gardé.
    #[command(name = "dns-rapide", visible_alias = "fast-dns")]
    DnsRapide,
    /// Mode Wi-Fi public (café, hôtel, aéroport) : entrées fermées sur ce réseau, partage de fichiers et annonce du
    /// nom coupés, DNS protecteur (chiffré sous Linux avec systemd-resolved), après accord et avec les droits
    /// d'administrateur ; « off » remet tout exactement, « portail » rouvre la page de connexion du réseau. Sans
    /// argument : son état.
    #[command(name = "wifi-public", visible_alias = "public-wifi")]
    WifiPublic {
        #[arg(value_parser = ["on", "off", "portail", "portal"])]
        etat: Option<String>,
    },
    /// Intégrité des fichiers critiques : référence d'empreintes BLAKE3, puis ce qui a changé depuis.
    #[command(visible_alias = "integrity")]
    Integrite {
        /// Prendre l'état actuel comme nouvelle référence (après une mise à jour du système).
        #[arg(long, visible_alias = "accept")]
        accepter: bool,
        /// Surveiller les fichiers critiques en direct jusqu'à Ctrl-C.
        #[arg(long, visible_alias = "live")]
        temps_reel: bool,
    },
    /// Fichiers-pièges contre les rançongiciels : les poser (après accord), voir s'ils sont intacts, ou les retirer.
    #[command(visible_alias = "decoys")]
    Pieges {
        /// Retirer les fichiers-pièges posés.
        #[arg(long, visible_alias = "remove")]
        retirer: bool,
    },
    /// Blocages de Windows Defender : règles ASR, protection réseau, logiciels indésirables, accès contrôlé aux
    /// dossiers. Chacun s'active après accord et s'annule exactement (Windows seulement).
    #[command(visible_alias = "harden")]
    Durcir,
    /// Analyse YARA : 308 règles de familles de logiciels malveillants (ReversingLabs) et les empreintes de
    /// MalwareBazaar, en complément de l'antivirus. Sans dossier : téléchargements, bureau, démarrage. Lecture seule.
    Yara {
        /// Tout le dossier personnel au lieu des endroits à risque.
        #[arg(long, visible_alias = "full")]
        complet: bool,
        /// Une clé USB, un disque externe ou un dossier à analyser en entier.
        dossier: Option<std::path::PathBuf>,
    },
    /// Mémoire des processus en marche passée aux 308 règles YARA : un logiciel malveillant sans fichier ne vit que
    /// là. Lecture seule, à la demande ; LSASS et processus protégés : leur mémoire n'est jamais lue ; rien n'est
    /// gardé.
    #[command(visible_alias = "memory")]
    Memoire,
    /// Lance un programme inconnu dans un bac à sable : pas de réseau, dossier personnel invisible.
    #[command(visible_alias = "sandbox")]
    Isoler {
        /// Programme ou script à lancer.
        fichier: std::path::PathBuf,
    },
    /// Fuites d'adresse courriel : l'adresse est envoyée au service de recherche, après votre accord.
    #[command(visible_alias = "email")]
    Courriel,
    /// Vérifie si des mots de passe ont fuité (Have I Been Pwned) ; seuls 5 caractères de leur empreinte partent.
    #[command(name = "motdepasse", visible_alias = "password")]
    MotDePasse,
    /// Mots de passe enregistrés dans les navigateurs : combien et comment protégés (comptés, jamais lus), où lancer
    /// la vérification intégrée du navigateur (faibles, réutilisés, compromis), et la vérification HIBP d'un mot tapé.
    #[command(visible_alias = "browser-passwords")]
    Navigateurs,
    /// Qui parle à Internet ? Les connexions en cours de chaque programme, avec le nom du serveur. Lecture seule.
    #[command(visible_alias = "outbound")]
    Sortantes,
    /// Mon ordinateur est-il contrôlé ? Les logiciels de prise de contrôle à distance (AnyDesk, TeamViewer,
    /// RustDesk…) installés, lancés au démarrage, en cours ou téléchargés : l'outil des faux techniciens. Retrait
    /// après accord ; un programme en cours demande un second accord.
    #[command(visible_alias = "remote-access")]
    Distance,
    /// Ce lien est-il dangereux ? Examiné sans jamais l'ouvrir ; après accord, son âge et des listes publiques.
    #[command(visible_alias = "link")]
    Lien {
        /// Le lien reçu (entre guillemets s'il contient « & » ou « ? »).
        adresse: String,
    },
    /// Vérifier un fichier téléchargé : empreinte comparée à celle du site, nom et contenu, YARA et antivirus.
    #[command(name = "verifier-fichier", visible_alias = "check-file")]
    VerifierFichier {
        /// Le fichier téléchargé.
        fichier: std::path::PathBuf,
        /// L'empreinte publiée par le site (SHA-256 de préférence). Sinon : un SHA256SUMS ou .sha256 à côté.
        empreinte: Option<String>,
    },
    /// Ce courriel est-il une arnaque ? Un courriel enregistré (.eml) examiné sans rien ouvrir : l'expéditeur et son
    /// authentification écrite par votre fournisseur, les liens, les pièces jointes ; après accord, l'âge des domaines
    /// et leur présence dans des listes publiques.
    #[command(name = "courriel-suspect", visible_alias = "suspicious-email")]
    CourrielSuspect {
        /// Le courriel enregistré (.eml) : « Enregistrer sous » de Thunderbird, « Télécharger le message » de Gmail,
        /// « Télécharger » d'Outlook sur le web.
        fichier: std::path::PathBuf,
        /// Le résultat en JSON, pour un script : l'examen sur l'ordinateur seulement (ni vérification en ligne,
        /// ni analyse des pièces jointes, dites non vérifiées).
        #[arg(long)]
        json: bool,
    },
    /// Logiciels espions : serveurs et sites connus (liste d'Échap), programmes qui lisent le clavier, autorisations
    /// de surveillance, logiciels de surveillance connus. Lecture seule.
    #[command(name = "logiciels-espions", visible_alias = "spyware")]
    LogicielsEspions {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
    /// Logiciels pas à jour (Windows, macOS) : navigateurs, Office, Acrobat, Java, 7-Zip, PuTTY, Slack comparés à leur
    /// dernière version ; failles exploitées. Lecture seule.
    #[command(name = "logiciels-perimes", visible_alias = "outdated-software")]
    LogicielsPerimes {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
    /// Préparer un signalement à un éditeur (MSRC, Google, Chrome, Mozilla, Apple, avis GHSA, CERT/CC, CERT-FR,
    /// Vanguard) : trié d'abord (une faille connue se corrige par une mise à jour, un logiciel malveillant n'est pas une
    /// faille), un brouillon au format du programme, ce qui est personnel retiré, écrit sur cet ordinateur et montré en
    /// entier. Rien n'est jamais envoyé : la personne le relit, le copie et le soumet elle-même.
    #[command(visible_alias = "disclose")]
    Signaler {
        /// L'identifiant d'un événement du journal (vanguard evenements) : son incident est repris.
        #[arg(long)]
        incident: Option<String>,
        /// Le dernier examen d'un outil (PRO-ESP-001, PRO-PER-001, PRO-COU-001).
        #[arg(long)]
        outil: Option<String>,
        /// Le programme : msrc, google, chrome, mozilla, apple, ghsa, cert-cc, cert-fr ou vanguard.
        #[arg(long)]
        programme: Option<String>,
        /// La langue du brouillon (fr ou en) ; par défaut, celle que le programme lit.
        #[arg(long)]
        langue: Option<String>,
        /// Le tri et le brouillon en JSON, pour un script : rien n'est écrit ni noté, aucune question.
        #[arg(long)]
        json: bool,
        /// Liste les brouillons gardés et les efface après accord.
        #[arg(long)]
        effacer: bool,
    },
    /// Caméra et micro : qui s'en sert ? Sous Windows, chaque programme et la dernière fois ; sous Linux, ce qui les
    /// tient en ce moment. Lecture seule.
    #[command(name = "camera-micro", visible_alias = "camera-mic")]
    CameraMicro,
    /// Bilan de confidentialité : les applications qui ont accès à la position, aux contacts, à la caméra et au micro,
    /// et leur dernier usage quand il est noté. Lecture seule.
    #[command(visible_alias = "permissions")]
    Acces,
    /// Quarantaine : les fichiers isolés par l'antivirus ou YARA, à remettre à leur place (faux positif) ou à
    /// supprimer pour de bon.
    #[command(visible_alias = "quarantine")]
    Quarantaine,
    /// Secrets dans l'historique des projets git du dossier personnel (mots de passe, clés d'API, jetons), cherchés par
    /// Vanguard, et aussi par gitleaks s'il est installé. Aucun secret n'est affiché. Lecture seule.
    Secrets,
    /// Failles connues des images Docker ou Podman de cet ordinateur, par trivy s'il est installé. Lecture seule.
    #[command(visible_alias = "containers")]
    Conteneurs,
    /// Paramètres : tous les réglages de Vanguard (langue, emojis, travail sans Internet, protection en temps réel,
    /// surveillance, entretien, alertes apprises, blocage, restrictions des extensions, clé abuse.ch, versions des
    /// logiciels, autodiagnostic de la semaine). Sans argument : leur état ; avec un réglage et une valeur : le change, la valeur d'avant montrée
    /// pour revenir. « temps-reel non --pendant 1h|4h » coupe la protection en temps réel de Vanguard pour ce temps
    /// (sans --pendant : jusqu'à reprise), après accord ; jamais Defender, le pare-feu ni l'UAC.
    #[command(visible_alias = "settings")]
    Parametres {
        /// Un réglage (langue, emojis, sans-internet, temps-reel, surveillance, entretien, appris, blocage,
        /// restrictions, abuse.ch, versions-logiciels, autotest) et sa valeur ; temps-reel non prend aussi --pendant 1h ou 4h.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        quoi: Vec<String>,
    },
    /// Blocage des menaces : chaque menace trouvée propose « Bloquer » (le geste montré, accepté, noté, annulable) ;
    /// la protection active, après un accord donné une fois, bloque toute seule le certain (empreinte de
    /// MalwareBazaar, outil d'attaque connu, serveur de commande), puis prévient. Sans argument : le menu.
    #[command(visible_alias = "blocking")]
    Blocage {
        /// « chercher », « annuler », « etat », « auto » ou « clic » (la protection active), ou une catégorie
        /// (programmes, connexions, demarrage, agents) suivie d'un mode (off, clic, auto).
        quoi: Vec<String>,
    },
    /// Sauvegarde la base des appareils et l'état de la surveillance dans un fichier JSON.
    #[command(visible_alias = "backup")]
    Sauvegarder {
        /// Fichier à écrire (par défaut : vanguard-sauvegarde-AAAA-MM-JJ.json dans le dossier personnel ou Documents).
        fichier: Option<std::path::PathBuf>,
    },
    /// Ajoute une sauvegarde (ou un appareils.json) à la base actuelle, sans rien effacer.
    #[command(visible_alias = "restore")]
    Restaurer { fichier: std::path::PathBuf },
    /// Donne un surnom à un appareil de la base (« imprimante HP »), désigné par son IP ou sa MAC.
    #[command(visible_alias = "name")]
    Nommer {
        /// IP (sur le réseau actuel) ou adresse MAC de l'appareil.
        appareil: String,
        /// Le surnom ; vide pour le retirer.
        surnom: Vec<String>,
    },
    /// Guide des commandes : celles d'Omarchy, d'Arch, de Fedora, de Debian, des autres Linux, de Windows, de macOS et
    /// de tous les systèmes, rangées par programme, avec des marches à suivre ; et les exemples de tldr-pages,
    /// téléchargés chaque semaine.
    Guide {
        /// Un système (omarchy, arch, fedora, debian, windows, macos, tous ; linux : les programmes communs ; tldr), un
        /// programme (systemctl, winget, tar…) ou des mots à chercher.
        quoi: Vec<String>,
    },
    /// Pourquoi c'est lent ? Ce qui occupe le processeur, la mémoire et le disque, le démarrage, les programmes lancés
    /// à l'ouverture de session. Lecture seule.
    #[command(visible_alias = "slow")]
    Lenteur,
    /// Programmes au démarrage : ceux qui se lancent à l'ouverture de session, à retirer ou à remettre après accord.
    /// Chaque retrait s'annule exactement (Optimiser › Tout remettre comme avant).
    #[command(visible_alias = "startup")]
    Demarrage,
    /// Fiche de l'ordinateur : modèle, carte mère, processeur, mémoire, carte graphique, disques, système. Les numéros
    /// de série s'affichent à l'écran seulement.
    #[command(visible_alias = "specs")]
    Fiche {
        /// La fiche en JSON, pour un script (sans les numéros de série).
        #[arg(long)]
        json: bool,
    },
    /// Copier mes fichiers (Documents, Images, Bureau, Vidéos, Musique) vers un disque externe : copie vérifiée, rien
    /// n'est effacé ni écrasé, une copie interrompue reprend.
    #[command(name = "copier-fichiers", visible_alias = "copy-files")]
    CopierFichiers {
        /// Un dossier d'un disque externe (par défaut : choisi parmi les disques branchés).
        destination: Option<std::path::PathBuf>,
    },
    /// Vérifier une copie faite par « Copier mes fichiers » (test de restauration) : des fichiers répartis sur toute
    /// la copie, relus sur le disque et comparés à leur original. Rien n'est écrit ni effacé.
    #[command(name = "verifier-copie", visible_alias = "check-copy")]
    VerifierCopie {
        /// Le disque ou le dossier de la copie (par défaut : choisi parmi les disques branchés).
        dossier: Option<std::path::PathBuf>,
    },
    /// Vérifier ma sauvegarde : la sauvegarde mise en place par Vanguard relue pour de vrai, des fichiers répartis
    /// sur toute la sauvegarde comparés à leur original ; pour Time Machine, Déjà Dup et l'Historique des fichiers,
    /// la marche à suivre. Rien n'est écrit ni effacé.
    #[command(name = "verifier-sauvegarde", visible_alias = "check-backup")]
    VerifierSauvegarde,
    /// Vérifier ma clé : capacité réelle (fausses clés), vitesses et blocs en erreur d'une clé USB ou d'un disque
    /// externe. Écrit dans l'espace libre après accord, relit, puis efface ; vos fichiers ne sont pas touchés.
    #[command(name = "verifier-cle", visible_alias = "check-drive")]
    VerifierCle {
        /// Un dossier de la clé ou du disque (par défaut : choisi parmi les disques branchés).
        dossier: Option<std::path::PathBuf>,
    },
    /// Rapport à laisser : une page simple pour la personne qu'on vient de dépanner (note, ce qu'il lui reste à faire,
    /// ce qui va bien), posée sur son Bureau après accord et ouverte dans le navigateur.
    #[command(name = "a-laisser", visible_alias = "handout")]
    ALaisser,
    /// Ce que Vanguard a changé : chaque correction lancée sur cet ordinateur, sa date et son résultat.
    #[command(visible_alias = "changes")]
    Changements,
    /// Le journal des événements : alertes, preuves relevées avant un geste, gestes, annulations, alertes déclarées
    /// normales et passages de version, reliés entre eux, avec l'état de sa chaîne scellée. Lecture seule.
    #[command(visible_alias = "events")]
    Evenements {
        /// Le journal en JSON, pour un script.
        #[arg(long)]
        json: bool,
        /// Le fil d'un incident : cet événement, ce qui l'a causé et ce qu'il a causé.
        #[arg(long)]
        incident: Option<String>,
    },
    /// Sauvegarde automatique : mise en place avec l'outil du système (Déjà Dup ou rsync chaque jour, Time Machine,
    /// Historique des fichiers) vers un disque externe, après accord, annulable exactement.
    #[command(name = "sauvegarde-auto", visible_alias = "auto-backup")]
    SauvegardeAuto {
        /// Retirer la sauvegarde automatique mise en place par Vanguard (les fichiers sauvegardés restent).
        #[arg(long, visible_alias = "undo")]
        annuler: bool,
    },
    /// Raccourci sur cet ordinateur : Vanguard copié ici et lancé d'un clic (menu des applications sous Linux, Bureau
    /// sous Windows et macOS). Sans argument : l'état, puis la proposition.
    #[command(visible_alias = "shortcut")]
    Raccourci {
        #[arg(value_parser = ["on", "off"])]
        etat: Option<String>,
    },
    /// Mes ordinateurs : ceux où la clé VANGUARD a fait un bilan, leur note et leurs problèmes restants (sur la
    /// partition VANGUARDLOG de la clé).
    #[command(visible_alias = "computers")]
    Ordinateurs,
    /// Mettre Vanguard à jour sur cet ordinateur : depuis une clé VANGUARD plus récente, ou depuis la dernière version
    /// publiée sur GitHub, signée par l'auteur et vérifiée ; toujours sur accord, jamais vers une version plus ancienne.
    #[command(name = "se-mettre-a-jour", visible_alias = "self-update")]
    SeMettreAJour,
    /// Retirer Vanguard de cet ordinateur : ce qu'il y a posé (surveillance, entretien, sauvegarde automatique,
    /// fichiers-pièges, raccourci et icône, copie du programme, restes d'une version d'avant), retrouvé, montré puis
    /// coché. Le dossier de données n'est retiré qu'après un second accord ; la clé USB n'est jamais touchée.
    #[command(visible_alias = "uninstall")]
    Desinstaller {
        /// Montrer ce qui serait retiré, sans rien retirer.
        #[arg(long, visible_alias = "list")]
        liste: bool,
    },
    /// Les règles du bilan déclarées pour ce système : identifiant stable, sujet, références de durcissement.
    #[command(visible_alias = "rules")]
    Regles,
    /// Autodiagnostic : Vanguard vérifie ses propres lectures sur cet ordinateur. Chaque règle du bilan sous garde et
    /// délai, en lecture seule prouvée (empreintes avant et après), et ses lectures comparées à celles des outils du
    /// système (pacman, systemctl, ss, PowerShell…). Rien n'est changé ; hors ligne sauf --internet ; un écart va au
    /// journal des erreurs, sans aucune valeur de l'ordinateur. Code de sortie : 0 sain, 1 écart, 2 non vérifié.
    #[command(visible_alias = "self-test")]
    Autotest {
        /// Le rapport en JSON, pour un script (sans aucune valeur lue sur l'ordinateur).
        #[arg(long, conflicts_with = "detail")]
        json: bool,
        /// Laisser les règles qui en ont besoin aller sur Internet (mises à jour, versions des logiciels).
        #[arg(long)]
        internet: bool,
        /// Montrer à l'écran les valeurs qui diffèrent (noms de paquets, d'unités, de comptes), ici seulement.
        #[arg(long)]
        detail: bool,
        /// Les règles une par une, pour des durées sans les voisines (plus lent).
        #[arg(long = "une-par-une", visible_alias = "one-by-one")]
        une_par_une: bool,
    },
    /// Collecter les traces après une infection, avant de nettoyer : processus, connexions, ce qui se lance tout seul,
    /// comptes, journaux des 7 derniers jours, fichiers récents et la chronologie de l'incident, dans un dossier daté
    /// (LISEZMOI, empreintes SHA-256). Lecture seule ; rien ne part sur Internet.
    #[command(visible_alias = "evidence")]
    Traces {
        /// Le dossier où créer traces-AAAAMMJJ-HHMMSS (par défaut : la clé VANGUARD si Vanguard tourne depuis elle,
        /// sinon le dossier de Vanguard de l'ordinateur).
        dossier: Option<std::path::PathBuf>,
    },
    /// Dépanner pas à pas : pas d'Internet, Wi-Fi qui coupe, ordinateur lent, pas de son, imprimante, disque plein ;
    /// après une infection, nouvel ordinateur, ordinateur qui part (vente, don).
    #[command(visible_alias = "troubleshoot")]
    Depanner {
        /// Le sujet : internet, wifi, lent, son, imprimante, disque, infection, nouveau, depart (ou des mots qui le
        /// décrivent).
        sujet: Vec<String>,
    },
    /// Ordinateur d'un proche : trois questions (qui s'en sert, pourquoi on vous l'a confié, son réseau), le bilan, un
    /// résumé en mots simples, les corrections acceptées une à une, puis la page à laisser avec ses conseils.
    #[command(visible_alias = "relative")]
    Proche,
    /// Vérifier Vanguard lui-même : version, date de compilation, empreinte SHA-256 du programme (à comparer à la
    /// page de la version), sur la clé du propriétaire le manifeste de la clé, et après accord l'historique signé des
    /// versions publiées ; ou une autre copie de Vanguard, par son empreinte et cet historique.
    #[command(name = "verifier-moi", visible_alias = "self-check")]
    VerifierMoi {
        /// Une autre copie de Vanguard à vérifier (celle d'une autre clé, une version d'avant), par son empreinte et
        /// l'historique signé des versions.
        programme: Option<std::path::PathBuf>,
    },
    /// Manifeste de la clé VANGUARD : écrit au déploiement (outils/deployer.sh), comparé à la clé branchée.
    #[command(hide = true)]
    Manifeste {
        /// Écrire le manifeste de ce dossier (la racine de la clé) dans la référence de cet ordinateur.
        #[arg(long)]
        ecrire: Option<std::path::PathBuf>,
        /// Accepter le carnet de la clé branchée tel qu'il est (copie restaurée, protection retirée ailleurs).
        #[arg(long)]
        accepter: bool,
        /// Redire à la référence les images et le menu de Ventoy de la clé montée ici, après leur mise à jour par
        /// outils/images-cle.sh (seulement les images nommées par --image, qu'il vient de copier et de vérifier).
        #[arg(long)]
        images: Option<std::path::PathBuf>,
        /// Une image copiée et vérifiée par outils/images-cle.sh (son nom dans ISO/), avec --images.
        #[arg(long, requires = "images")]
        image: Vec<String>,
    },
    /// Plugins : des programmes à vous ajoutés à Vanguard sans changer son code (essais, outils expérimentaux), chacun
    /// dans un dossier avec un plugin.toml. « ajouter <dossier> » le copie et l'approuve (empreintes SHA-256),
    /// « approuver <nom> » après un changement, « liste », « retirer <nom> », ou « <nom> [arguments] » pour le
    /// lancer (« --rapport » : ses constats dans le rapport HTML) ; sans argument, la liste à choisir. Jamais en
    /// administrateur ; hors de la note.
    Plugin {
        /// ajouter <dossier>, approuver <nom>, liste, retirer <nom>, ou <nom> [--rapport] [arguments].
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        quoi: Vec<String>,
    },
    /// Laboratoire : un script posé tel quel dans le dossier du labo (.sh, .bash, .ps1, .py ou un programme), pour
    /// essayer une idée hors du programme de Vanguard. Sans argument : la liste à choisir ; « ouvrir » : le dossier ;
    /// « <fichier> [arguments] » le lance (approuvé par son empreinte au premier lancement). Jamais en administrateur.
    #[command(visible_alias = "lab")]
    Labo {
        /// ouvrir, liste, ou <fichier> [arguments].
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        quoi: Vec<String>,
    },
    /// Extensions : le menu des plugins et des scripts du labo, à choisir et lancer.
    #[command(visible_alias = "ext")]
    Extensions {
        /// on : les restrictions des extensions coupées (sans accord, empreinte ni analyse, avec tous vos droits) ;
        /// off : remises. Le dossier des extensions doit rester à vous seul.
        #[arg(long, visible_alias = "no-restrictions", value_parser = ["on", "off"])]
        sans_restrictions: Option<String>,
    },
    /// Scan silencieux + notifications (utilisé par la surveillance).
    #[command(hide = true)]
    Surveiller,
    /// Entretien silencieux + notification (utilisé par le planificateur, une fois par mois).
    #[command(hide = true)]
    Entretenir,
    /// Windows : le processus élevé qui applique les corrections natives (lancé par Vanguard lui-même, après la
    /// demande d'administrateur ; voir machine/windows/eleve.rs).
    #[command(name = "appliquer-eleve", hide = true)]
    AppliquerEleve {
        #[arg(long)]
        canal: String,
        #[arg(long)]
        parent: u32,
    },
}

/// Résultats de la session, pour le rapport HTML et les corrections.
#[derive(Default)]
struct Session {
    audit: Option<Audit>,
    reseau: Option<Rapport>,
    /// Quand le scan du réseau local (ports courants) a fini : l'audit du réseau le réutilise s'il a moins de dix
    /// minutes.
    scan_le: Option<std::time::Instant>,
    audit_reseau: Option<audit::AuditReseau>,
}

impl Session {
    async fn scanner_reseau(&mut self, cible: Option<String>, ports: &str) {
        let du_reseau_local = cible.is_none() && ports == "courants";
        match reseau::executer(Options::defaut(cible, ports)).await {
            Ok(r) => {
                self.reseau = Some(r);
                self.scan_le = du_reseau_local.then(std::time::Instant::now);
            }
            Err(e) => {
                journal::erreur("scan réseau", &e);
                eprintln!("{}", trf!("Scan réseau impossible : {e}", "Network scan failed: {e}"));
            }
        }
    }

    /// L'audit du réseau par domaine : le scan de la session s'il a moins de dix minutes, sinon un scan silencieux ;
    /// puis les six domaines, à l'écran ou en JSON. Sans réseau local, six domaines « non vérifié ».
    async fn audit_reseau(&mut self, json: bool, html: bool, invite: bool) {
        let recent = self
            .scan_le
            .is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(600));
        if self.reseau.is_none() || !recent {
            if !json {
                trp!(
                    "  {GRIS}Scan du réseau local en cours…{RESET}",
                    "  {GRIS}Scanning the local network…{RESET}"
                );
            }
            let options = Options {
                silencieux: true,
                ..Options::defaut(None, "courants")
            };
            match reseau::executer(options).await {
                Ok(r) => {
                    self.reseau = Some(r);
                    self.scan_le = Some(std::time::Instant::now());
                }
                Err(e) => {
                    journal::erreur("audit du réseau", &e);
                    let a = audit::AuditReseau::sans_reseau(&e);
                    audit::rendre(&a, json);
                    self.audit_reseau = Some(a);
                    if html {
                        rapport::ouvrir(None, None, self.audit_reseau.as_ref());
                    }
                    return;
                }
            }
        }
        let Some(scan) = &self.reseau else { return };
        let a = audit::auditer(scan, None, invite, false).await;
        audit::rendre(&a, json);
        self.audit_reseau = Some(a);
        if html {
            rapport::ouvrir(None, self.reseau.as_ref(), self.audit_reseau.as_ref());
        }
    }

    async fn complet(&mut self) {
        self.audit = Some(machine::executer(false));
        self.scanner_reseau(None, "courants").await;
        // L'audit du réseau par domaine, après le scan : les constats réseau du bilan qui vient de finir lui servent
        // tels quels (le domaine Postes), sans relancer ces règles.
        if let Some(scan) = &self.reseau {
            let machine = self.audit.as_ref().map(|a| {
                a.constats
                    .iter()
                    .filter(|c| audit::regle_du_reseau(c.regle))
                    .cloned()
                    .collect()
            });
            let a = audit::auditer(scan, machine, false, false).await;
            audit::afficher(&a);
            self.audit_reseau = Some(a);
        }
        // Les extensions sans restrictions qui l'ont demandé (dans_le_bilan) : à part, hors de la note.
        plugins::avec_le_bilan();
        titre(tr!("Bilan global", "Overall result"));
        let m = self.audit.as_ref().filter(|a| a.fiable()).map(|a| a.score);
        let r = self.reseau.as_ref().map(|r| r.score_global);
        let audit_reseau = self.audit_reseau.as_ref().and_then(|a| a.score);
        match m {
            Some(m) => afficher_note(tr!("Cette machine", "This machine"), m),
            None => trp!(
                "  Cette machine : pas de note (vérifications impossibles)",
                "  This machine: no grade (checks could not be done)"
            ),
        }
        if let Some(r) = r {
            afficher_note(tr!("Réseau", "Network"), r);
        }
        match (self.audit_reseau.as_ref(), audit_reseau) {
            (Some(_), Some(s)) => afficher_note(tr!("Audit du réseau", "Network audit"), s),
            (Some(_), None) => trp!(
                "  Audit du réseau : pas de note (domaines non vérifiés)",
                "  Network audit: no grade (domains not checked)"
            ),
            (None, _) => {}
        }
        if let Some(g) = [m, r, audit_reseau].into_iter().flatten().min() {
            afficher_note(tr!("Global", "Overall"), g);
        }
        let (precedent, nouveau) =
            historique::enregistrer_complet(self.audit.as_ref(), self.reseau.as_ref(), self.audit_reseau.as_ref());
        // Sur la clé VANGUARD branchée (partition VANGUARDLOG) : la visite de cet ordinateur, pour « Mes ordinateurs ».
        ordinateurs::noter(self.audit.as_ref(), self.reseau.as_ref());
        if let Some(p) = precedent {
            historique::afficher_changements(&p, &nouveau);
        }
        // Les menaces à bloquer : le certain tout seul si la protection active est en marche, le reste d'un clic.
        protection::blocage::au_bilan();
        let a_corriger = self.audit.as_ref().is_some_and(|a| {
            a.constats
                .iter()
                .any(|c| c.correctif.as_ref().is_some_and(|k| k.automatique))
        });
        if a_corriger {
            let cle = cle_a_molette();
            trp!(
                "\n  {cle} Des corrections sont possibles : choix « 2 » du menu ou « vanguard corriger ».",
                "\n  {cle} Fixes are available: menu choice “2” or “vanguard fix”."
            );
        }
        let _ = rapport::generer(self.audit.as_ref(), self.reseau.as_ref(), self.audit_reseau.as_ref());
    }

    fn corriger(&mut self) {
        let audit = self.audit.get_or_insert_with(|| machine::executer(false));
        if let Some(nouveau) = corriger::corriger(audit, self.reseau.as_ref()) {
            self.audit = Some(nouveau);
        }
    }
}

fn nommer(appareil: &str, surnom: &str) {
    let surnom = Some(surnom.trim()).filter(|s| !s.is_empty());
    match reseau::nommer(appareil, surnom) {
        Ok(qui) => match surnom {
            Some(s) => trp!(
                "  {VERT}✔{RESET} {qui} s'appelle maintenant « {s} ».",
                "  {VERT}✔{RESET} {qui} is now called “{s}”."
            ),
            None => trp!(
                "  {VERT}✔{RESET} Surnom retiré pour {qui}.",
                "  {VERT}✔{RESET} Nickname removed for {qui}."
            ),
        },
        Err(e) => println!("  ✖ {e}"),
    }
}

/// Lancé en root (sudo) : Vanguard n'en a pas besoin, et une sortie piégée aurait tous les droits. Dit, jamais imposé :
/// sans session graphique ni agent polkit, pkexec ne peut rien demander, et « sudo vanguard » est alors la seule façon
/// de corriger. Sous Windows, une console administrateur est l'habitude de certains : rien d'alarmant.
#[cfg(unix)]
fn avertir_si_root() {
    // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire ; il rend l'identifiant effectif du processus.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    for (i, ligne) in envelopper(
        tr!(
            "Vanguard tourne en root (sudo) : il n'en a pas besoin, chaque correction demande le mot de passe au moment voulu, et une sortie piégée aurait ici tous les droits. Relancez-le sans sudo, sauf si aucune fenêtre ne peut demander le mot de passe sur cet ordinateur (pas de session graphique) : alors continuez.",
            "Vanguard is running as root (sudo): it does not need it, each fix asks for the password when needed, and a booby-trapped output would have every right here. Start it again without sudo, unless no window can ask for the password on this computer (no graphical session): then carry on."
        ),
        LARGEUR - 4,
    )
    .into_iter()
    .enumerate()
    {
        if i == 0 {
            eprintln!("  {}⚠{RESET} {ligne}", couleur(risk::Niveau::Moyen));
        } else {
            eprintln!("    {ligne}");
        }
    }
}

#[cfg(windows)]
fn avertir_si_root() {}

/// État affiché en tête du menu : dernier bilan, dernier test de connexion, clé, surveillance, et un avis s'il y en
/// a un (copie périmée, nouvelle version sur la clé).
fn etat_du_menu(surveillance_active: bool) -> Vec<String> {
    let historique = historique::charger();
    let bilan = match historique.last() {
        Some(b) => {
            let note = |s: Option<u32>| s.map_or_else(|| "—".to_string(), etiquette_note);
            trf!(
                "  {GRIS}Dernier bilan{RESET}  {}   ordinateur {}   réseau {}",
                "  {GRIS}Last check{RESET}     {}   machine {}   network {}",
                b.date,
                note(b.machine),
                note(b.reseau)
            )
        }
        None => trf!(
            "  {GRIS}Aucun bilan encore : commencez par 1.{RESET}",
            "  {GRIS}No check yet: start with 1.{RESET}"
        ),
    };
    let connexion = reseau::connexion::historique().last().map(|c| {
        let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
        let bufferbloat = c
            .hausse_ms
            .map(|h| {
                let (n, niveau) = reseau::connexion::note_bufferbloat(h);
                format!("{}{n}{RESET}", couleur(niveau))
            })
            .unwrap_or_default();
        trf!(
            "  {GRIS}Connexion{RESET}      {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            "  {GRIS}Connection{RESET}     {:.0} ms · ↓ {} ↑ {} Mbit/s · bufferbloat {bufferbloat}",
            c.internet_ms,
            debit(c.descendant),
            debit(c.montant)
        )
    });
    let cle = match reseau::etat_de_la_cle() {
        reseau::EtatCle::ProtegeeEnEcriture => format!(
            "{VERT}{}{RESET}",
            tr!(
                "clé VANGUARD branchée (protégée en écriture)",
                "VANGUARD key plugged in (write-protected)"
            )
        ),
        reseau::EtatCle::Branchee => format!(
            "{VERT}{}{RESET}",
            tr!("clé VANGUARD branchée", "VANGUARD key plugged in")
        ),
        // Un volume au témoin sans jeton connu d'ici : dit, pour que personne ne croie sa clé reconnue.
        reseau::EtatCle::Inconnue => format!(
            "{}{}{RESET}",
            couleur(risk::Niveau::Moyen),
            tr!("clé VANGUARD inconnue, ignorée", "unknown VANGUARD key, ignored")
        ),
        reseau::EtatCle::Aucune => format!("{GRIS}{}{RESET}", tr!("clé non branchée", "key not plugged in")),
    };
    let surveillance = if surveillance_active {
        format!("{VERT}{}{RESET}", tr!("surveillance active", "monitoring on"))
    } else {
        format!("{GRIS}{}{RESET}", tr!("surveillance coupée", "monitoring off"))
    };
    let cle = ligne_de_la_cle(&cle, &surveillance, protection::temps_reel::en_tete());
    // La copie périmée d'abord : remettre la clé à jour passe avant d'en recopier le programme.
    let avis = protection::manifeste::avertissement_perime()
        .map(|a| format!("  {}⚠{RESET} {a}", couleur(risk::Niveau::Moyen)))
        .or_else(|| {
            touche_de(Action::MettreAJour)
                .and_then(|t| mise_a_jour::avertissement(&t))
                .map(|a| format!("  {ACCENT}↑{RESET} {a}"))
        });
    lignes_d_etat(bilan, connexion, cle, avis)
}

/// La ligne de la clé et de la surveillance, avec la protection en temps réel quand elle est coupée : à côté de la
/// surveillance si tout tient dans la largeur, sinon à sa place (elle ne passe plus, de toute façon), et sans son
/// échéance en dernier recours.
fn ligne_de_la_cle(cle: &str, surveillance: &str, temps_reel: Option<(String, String)>) -> String {
    let point = format!(" {GRIS}·{RESET} ");
    let Some((long, court)) = temps_reel else {
        return format!("  {cle}{point}{surveillance}");
    };
    [
        format!("  {cle}{point}{surveillance}{point}{long}"),
        format!("  {cle}{point}{long}"),
    ]
    .into_iter()
    .find(|l| largeur_affichee(l) <= LARGEUR)
    .unwrap_or_else(|| format!("  {cle}{point}{court}"))
}

/// Les lignes d'état, trois au plus : avec plus, le menu ne tiendrait plus dans un terminal de 24 lignes (test). Un
/// avis prend la place de la connexion, la ligne la moins utile ici.
fn lignes_d_etat(bilan: String, connexion: Option<String>, cle: String, avis: Option<String>) -> Vec<String> {
    match avis {
        Some(avis) => vec![bilan, cle, avis],
        None => [Some(bilan), connexion, Some(cle)].into_iter().flatten().collect(),
    }
}

/// La touche d'un outil au menu principal (« 9.9 » : groupe 9, 9e outil proposé ici), comme la recherche la tape.
fn touche_de(action: Action) -> Option<String> {
    let groupe = OUTILS.iter().find(|o| o.action == action)?.groupe?;
    let i = GROUPES.iter().position(|g| *g == groupe)?;
    let j = groupe
        .actions()
        .into_iter()
        .filter(|a| a.disponible())
        .position(|a| a == action)?;
    Some(format!("{}.{}", i + 4, j + 1))
}

/// Lignes vides et sous-titre « ── NOM ──── » d'un menu.
fn section_du_menu(t: &str) -> [Ligne; 2] {
    [Ligne::Texte(String::new()), Ligne::Texte(ligne_section(t))]
}

/// Les lignes du menu principal, sous l'état (dernier bilan, clé, surveillance).
fn lignes_du_menu(etat: Vec<String>) -> Vec<Ligne> {
    let mut lignes: Vec<Ligne> = lignes_cadre(
        &format!("{ACCENT}VANGUARD{RESET} {GRIS}{}{RESET}", env!("CARGO_PKG_VERSION")),
        tr!(
            "Cyberdéfense portable des postes et des réseaux",
            "Portable cyber defense for endpoints and networks"
        ),
    )
    .into_iter()
    .map(Ligne::Texte)
    .collect();
    lignes.extend(etat.into_iter().map(Ligne::Texte));

    lignes.extend(section_du_menu(tr!("BILAN DE SÉCURITÉ", "SECURITY CHECK")));
    let principal = [Action::Complet, Action::Corriger, Action::Rapport];
    for (touche, action) in principal.into_iter().enumerate() {
        let a_droite = if touche == 0 {
            tr!("← commencer ici", "← start here")
        } else {
            ""
        };
        lignes.push(Ligne::choix(&(touche + 1).to_string(), action.libelle().0, a_droite));
    }

    // Sans ligne vide au-dessus : avec le 9e groupe (extensions), le menu tient encore dans 24 lignes.
    lignes.push(Ligne::Texte(ligne_section(tr!("OUTILS", "TOOLS"))));
    for (touche, groupe) in GROUPES.iter().enumerate() {
        lignes.push(Ligne::choix(
            &(touche + 4).to_string(),
            &format!("{} {ACCENT}›{RESET}", groupe.titre()),
            groupe.resume(),
        ));
    }

    // « q » suit les groupes, et l'aide le suit, sans ligne vide : avec le 8e groupe (dépanner), le menu tient
    // encore dans un terminal de 24 lignes (macOS, beaucoup de Linux), où les flèches marchent.
    lignes.push(Ligne::choix(
        "q",
        tr!("Quitter", "Quit"),
        tr!("s : paramètres", "s: settings"),
    ));

    // Ce que la recherche trouve en plus, sans l'afficher : chaque outil des sous-menus (« 5.2 » : groupe 5, 2e outil,
    // aussi tapable tel quel), chaque parcours de dépannage et chaque page du guide. Les pages du guide en dernier :
    // la recherche garde cet ordre, et un outil ou un parcours répond mieux à « son » qu'une commande à taper.
    let mut pages_du_guide = Vec::new();
    for (i, groupe) in GROUPES.iter().enumerate() {
        let cle = (i + 4).to_string();
        if matches!(groupe, Groupe::Guide) {
            pages_du_guide = guide::lignes_de_recherche(&cle);
            continue;
        }
        if matches!(groupe, Groupe::Depanner) {
            lignes.extend(depanner::lignes_de_recherche(&cle));
            continue;
        }
        let chemin = format!("{} ›", groupe.titre());
        for (j, a) in groupe.actions().into_iter().filter(|a| a.disponible()).enumerate() {
            let (texte, precision) = a.libelle();
            // Le nom de sa sous-commande aussi : qui connaît « vanguard sortantes » la retrouve au menu.
            let mots = format!("{} {}", a.outil().mots, a.outil().commande);
            lignes.push(Ligne::cachee(&format!("{cle}.{}", j + 1), &chemin, texte, precision).avec_mots(&mots));
        }
    }
    lignes.extend(pages_du_guide);
    lignes
}

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

/// Un outil désigné par son chemin, tapé ou trouvé par la recherche : « 5.2 », le 2e outil du groupe 5.
fn outil_au_chemin(chemin: &str) -> Option<Action> {
    let (groupe, outil) = chemin.split_once('.')?;
    let groupe = GROUPES.get(groupe.parse::<usize>().ok()?.checked_sub(4)?)?;
    // Le guide et le dépannage ont leurs propres chemins : système puis programme, parcours (`guide::chemin`,
    // `depanner::chemin`).
    if matches!(groupe, Groupe::Guide | Groupe::Depanner) {
        return None;
    }
    let outil = outil.parse::<usize>().ok()?.checked_sub(1)?;
    groupe.actions().into_iter().filter(|a| a.disponible()).nth(outil)
}

async fn menu() {
    let mut s = Session::default();
    // La ligne en surbrillance au retour dans le menu : la dernière choisie.
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let lignes = lignes_du_menu(etat_du_menu(reseau::surveillance::active()));
        let invite = format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: "));
        let Some(choix) = choisir_au_sommet(&lignes, &invite, &dernier, tr!("quitter", "quit")) else {
            break;
        };
        let choix = choix.trim().to_lowercase();
        println!();
        // Un outil, une page ou une commande du guide, trouvés par la recherche (ou leur chemin tapé : « 5.2 »,
        // « 10.3.1 », « 10.3.1.2 »).
        if let Some((groupe, reste)) = choix.split_once('.') {
            let cle_de = |voulu: Groupe| GROUPES.iter().position(|g| *g == voulu).map(|i| (i + 4).to_string());
            if cle_de(Groupe::Guide).as_deref() == Some(groupe) {
                if let Some((systeme, programme, commande)) = guide::chemin(reste) {
                    dernier = groupe.to_string();
                    guide::ouvrir(systeme, programme, commande);
                }
            } else if cle_de(Groupe::Depanner).as_deref() == Some(groupe) {
                if let Some(n) = depanner::chemin(reste) {
                    dernier = groupe.to_string();
                    depanner::ouvrir(n);
                }
            } else if let Some(action) = outil_au_chemin(&choix) {
                dernier = groupe.to_string();
                executer(&mut s, action).await;
                revenir_au_menu(action);
            }
            continue;
        }
        let groupe = choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(4))
            .and_then(|i| GROUPES.get(i));
        if let Some(g) = groupe {
            dernier = choix;
            sous_menu(&mut s, *g).await;
            continue;
        }
        let action = match choix.as_str() {
            "1" => Action::Complet,
            "2" => Action::Corriger,
            "3" => Action::Rapport,
            "q" => break,
            // Raccourcis des versions précédentes (une lettre par outil), toujours acceptés.
            autre => match OUTILS.iter().find(|o| !o.lettre.is_empty() && o.lettre == autre) {
                Some(o) => o.action,
                None => continue,
            },
        };
        dernier = choix;
        executer(&mut s, action).await;
        revenir_au_menu(action);
    }
}

/// Le choix fait dans un menu, avec l'invite commune (`None` : Échap, qui fait `echap`).
fn choix_du_menu(lignes: &[Ligne], dernier: &str, echap: &str) -> Option<String> {
    let invite = format!("  {ACCENT}›{RESET} {}", tr!("Choix : ", "Choice: "));
    choisir(lignes, &invite, dernier, echap)
}

/// Après un outil lancé du menu : Entrée pour y revenir, sauf pour ceux qui ont leurs propres écrans.
fn revenir_au_menu(action: Action) {
    // Quitté par « revenir » : l'outil s'est arrêté à ta demande, la pause serait un appui de trop.
    if action.attendre_apres() && !ui::vient_de_revenir() {
        crate::selection::attendre_retour(&trf!(
            "\n{GRIS}Entrée pour revenir au menu…{RESET}",
            "\n{GRIS}Enter to go back to the menu…{RESET}"
        ));
    }
}

/// Ce que le menu sait faire, dans l'ordre des sous-menus : la ligne d'un outil dans `OUTILS` est à son numéro.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Complet,
    Corriger,
    Rapport,
    Audit,
    Maj,
    Reparer,
    Diagnostic,
    Integrite,
    Appris,
    Lenteur,
    Fiche,
    ALaisser,
    Changements,
    Entretien,
    Scanner,
    AuditReseau,
    Appareil,
    Nommer,
    Surveillance,
    Tableau,
    Veilleur,
    Connexion,
    ListesNoires,
    WifiCanaux,
    Nat,
    Cameras,
    Objets,
    WifiPublic,
    AntivirusRapide,
    AntivirusComplet,
    AntivirusDossier,
    Yara,
    Memoire,
    Pieges,
    Protection,
    Bac,
    MotsDePasse,
    Navigateurs,
    Courriel,
    QuiParle,
    CameraMicro,
    Acces,
    Distance,
    Lien,
    VerifierFichier,
    Quarantaine,
    SecretsGit,
    Conteneurs,
    Blocage,
    SitesDangereux,
    DernieresFailles,
    CourrielSuspect,
    LogicielsEspions,
    LogicielsPerimes,
    Signaler,
    Logiciels,
    Gaming,
    Nettoyer,
    OptimiserRecommandes,
    OptimiserConfidentialite,
    #[cfg(not(target_os = "macos"))]
    OptimiserPerformance,
    OptimiserConfort,
    DnsRapide,
    OptimiserAnnuler,
    Sauvegarder,
    CopierFichiers,
    SauvegardeAuto,
    VerifierCopie,
    VerifierCle,
    Raccourci,
    Ordinateurs,
    ProtegerDonnees,
    MettreAJour,
    VerifierSauvegarde,
    Desinstaller,
    Guide,
    Depanner,
    Extensions,
    Parametres,
}

/// Un outil du menu : la sous-commande qui fait la même chose en ligne de commande (vide : aucune, et la raison est
/// dans `MENU_SEULEMENT`), son groupe (aucun pour 1, 2 et 3, au menu principal), sa lettre des menus d'avant la 0.43
/// (vide : aucune ; les chiffres, eux, ont changé de sens), son titre et sa précision en français puis en anglais, et
/// les mots que la recherche trouve en plus, jamais affichés. Une seule table pour le menu et la ligne de commande :
/// les tests de `tests_menu` la comparent aux sous-commandes, à leur aide anglaise, au README et à `outils/LISEZMOI.txt`.
struct Outil {
    action: Action,
    commande: &'static str,
    groupe: Option<Groupe>,
    lettre: &'static str,
    titre: [&'static str; 2],
    precision: [&'static str; 2],
    mots: &'static str,
}

/// Une ligne par outil, dans l'ordre de `Action` et des sous-menus (4.1, 4.2…). La précision des outils à interrupteur
/// (surveillance, entretien) suit leur état : `Action::libelle`.
#[rustfmt::skip] // une ligne de données par outil, que rustfmt étalerait sur huit
const OUTILS: &[Outil] = &[
    Outil { action: Action::Complet, commande: "complet", groupe: None, lettre: "",
        titre: ["Bilan complet : ordinateur, réseau", "Full check: machine + network"], precision: ["", ""],
        mots: "" },
    Outil { action: Action::Corriger, commande: "corriger", groupe: None, lettre: "",
        titre: ["Corriger les problèmes trouvés", "Fix the problems found"], precision: ["", ""],
        mots: "" },
    Outil { action: Action::Rapport, commande: "", groupe: None, lettre: "",
        titre: ["Rapport détaillé dans le navigateur", "Detailed report in the browser"], precision: ["", ""],
        mots: "" },
    Outil { action: Action::Audit, commande: "machine", groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Audit de sécurité", "Security audit"],
        precision: ["pare-feu, comptes, chiffrement…", "firewall, accounts, encryption…"],
        mots: "sécurité security pare-feu firewall ports ssh chiffrement encryption comptes accounts" },
    Outil { action: Action::Maj, commande: "maj", groupe: Some(Groupe::Machine), lettre: "u",
        titre: ["Mises à jour", "Updates"], precision: ["système, programmes, pilotes", "system, programs, drivers"],
        mots: "update upgrade pilotes drivers firmware bios windows update" },
    Outil { action: Action::Reparer, commande: "reparer", groupe: Some(Groupe::Machine), lettre: "r",
        titre: ["Réparer et nettoyer", "Repair and clean up"],
        precision: ["réseau, disque, système…", "network, disk, system…"],
        mots: "internet wifi dns proxy hosts pare-feu firewall antivirus disque disk smart heure time sfc dism \
               winsock" },
    Outil { action: Action::Diagnostic, commande: "diagnostic", groupe: Some(Groupe::Machine), lettre: "o",
        titre: ["Diagnostic", "Diagnostic"], precision: ["matériel, plantages, erreurs", "hardware, crashes, errors"],
        mots: "plantages crashes erreurs errors écran bleu bsod journal logs matériel hardware" },
    Outil { action: Action::Integrite, commande: "integrite", groupe: Some(Groupe::Machine), lettre: "i",
        titre: ["Intégrité des fichiers critiques", "Critical file integrity"],
        precision: ["comptes, sudo, SSH, démarrage…", "accounts, sudo, SSH, startup…"],
        mots: "blake3 empreintes fingerprints fichiers files" },
    Outil { action: Action::Appris, commande: "appris", groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Ce que Vanguard a appris", "What Vanguard has learned"],
        precision: ["vos choix, vos habitudes", "your choices, your habits"],
        mots: "apprentissage learning appris learned choix choices normal oublier forget" },
    Outil { action: Action::Lenteur, commande: "lenteur", groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Pourquoi c'est lent ?", "Why is it slow?"],
        precision: ["processeur, mémoire, démarrage", "processor, memory, startup"],
        mots: "lent slow lenteur rame processeur cpu mémoire memory ram démarrage startup" },
    Outil { action: Action::Fiche, commande: "fiche", groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Fiche de l'ordinateur", "Computer specs"],
        precision: ["modèle, processeur, mémoire…", "model, processor, memory…"],
        mots: "fiche specs matériel hardware modèle model processeur carte graphique gpu mémoire ram série" },
    Outil { action: Action::ALaisser, commande: "a-laisser", groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Rapport à laisser", "Report to leave behind"],
        precision: ["une page simple, à imprimer", "a simple page, to print"],
        mots: "rapport report imprimer print dépannage help famille family laisser leave page résumé summary" },
    Outil { action: Action::Changements, commande: "changements", groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Ce que Vanguard a changé", "What Vanguard changed"],
        precision: ["chaque correction, datée", "each fix, dated"],
        mots: "changements changes historique history corrections fixes journal log annuler undo" },
    Outil { action: Action::Entretien, commande: "entretien", groupe: Some(Groupe::Machine), lettre: "",
        titre: ["Entretien du mois", "Monthly check-up"], precision: ["", ""],
        mots: "maintenance mensuel monthly mois month rappel reminder notification" },
    Outil { action: Action::Scanner, commande: "reseau", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Scanner le réseau", "Scan the network"],
        precision: ["appareils, ports, nouveautés", "devices, ports, changes"],
        mots: "appareils devices ports réseau network lan nmap" },
    Outil { action: Action::AuditReseau, commande: "audit-reseau", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Audit du réseau", "Network audit"],
        precision: ["six notes : routeur, Wi-Fi, DNS…", "six grades: router, Wi-Fi, DNS…"],
        mots: "audit réseau network exposition exposure wifi dns tls segmentation appareils devices objets postes \
               computers upnp redirection note grade cyberdéfense cyberdefense box routeur router" },
    Outil { action: Action::Appareil, commande: "reseau", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Scan approfondi d'un appareil", "Deep scan of one device"], precision: ["tous les ports", "all ports"],
        mots: "appareils devices ports réseau network lan nmap" },
    Outil { action: Action::Nommer, commande: "nommer", groupe: Some(Groupe::Reseau), lettre: "n",
        titre: ["Nommer un appareil", "Name a device"], precision: ["« imprimante HP »", "“HP printer”"],
        mots: "surnom nickname" },
    Outil { action: Action::Surveillance, commande: "surveillance", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Surveillance toutes les heures", "Hourly monitoring"], precision: ["", ""],
        mots: "monitor surveiller notification" },
    Outil { action: Action::Tableau, commande: "tableau", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Tableau de bord de la surveillance", "Monitoring dashboard"],
        precision: ["alertes, nouveaux appareils", "alerts, new devices"],
        mots: "tableau dashboard historique history alertes alerts nouveaux new appareils devices botnet \
               connexions suspectes suspicious connections" },
    Outil { action: Action::Veilleur, commande: "veilleur", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Veilleur : lancements et connexions", "Watcher: launches and connections"], precision: ["", ""],
        mots: "veilleur watcher lancements launches processus processes connexions connections brèves brief \
               connecteur connector temps réel live" },
    Outil { action: Action::Connexion, commande: "connexion", groupe: Some(Groupe::Reseau), lettre: "c",
        titre: ["Test de connexion pour le jeu", "Connection test for gaming"],
        precision: ["ping, gigue, débit, bufferbloat", "ping, jitter, speed, bufferbloat"],
        mots: "ping latence latency débit speed jitter gigue bufferbloat jeu" },
    Outil { action: Action::ListesNoires, commande: "listes-noires", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Adresse sur liste noire ?", "Address on blocklists?"],
        precision: ["si oui, un appareil est infecté", "if so, a device is infected"],
        mots: "spamhaus botnet liste noire blocklist blacklist dnsbl" },
    Outil { action: Action::WifiCanaux, commande: "canaux", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Wi-Fi encombré ?", "Crowded Wi-Fi?"],
        precision: ["canaux voisins, le plus libre", "nearby channels, the freest"],
        mots: "wifi canal canaux channel encombré crowded interférences interference voisins neighbors signal box \
               router" },
    Outil { action: Action::Nat, commande: "nat", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Type de NAT pour le jeu", "NAT type for gaming"],
        precision: ["ouvert, modéré ou strict", "open, moderate or strict"],
        mots: "nat stun upnp console xbox playstation jeu game multijoueur multiplayer redirection port forwarding \
               ouvert open modéré moderate strict" },
    Outil { action: Action::Cameras, commande: "cameras", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Caméras cachées ?", "Hidden cameras?"],
        precision: ["location, chez quelqu'un", "rental, someone else's place"],
        mots: "caméra camera espion spy cachée hidden location rental airbnb rtsp onvif" },
    Outil { action: Action::Objets, commande: "objets", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Routeur et objets connectés", "Router and connected devices"],
        precision: ["modèle, mots de passe d'origine", "model, default passwords"],
        mots: "box routeur router modem objets connectés iot smart caméra camera imprimante printer nas télé tv \
               domotique smart home mot de passe d'origine default password firmware upnp" },
    Outil { action: Action::WifiPublic, commande: "wifi-public", groupe: Some(Groupe::Reseau), lettre: "",
        titre: ["Mode Wi-Fi public", "Public Wi-Fi mode"],
        precision: ["café, hôtel : allumer, éteindre", "café, hotel: turn on, off"],
        mots: "wifi public café cafe hôtel hotel aéroport airport portail captif captive portal pare-feu firewall \
               partage sharing découverte discovery dns chiffré encrypted" },
    Outil { action: Action::AntivirusRapide, commande: "antivirus", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Analyse rapide", "Quick scan"], precision: ["téléchargements, bureau…", "downloads, desktop…"],
        mots: "virus malware clamav defender" },
    Outil { action: Action::AntivirusComplet, commande: "antivirus", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Analyse complète", "Full scan"], precision: ["dossier personnel", "home folder"],
        mots: "virus malware clamav defender" },
    Outil { action: Action::AntivirusDossier, commande: "antivirus", groupe: Some(Groupe::Protection), lettre: "a",
        titre: ["Clé USB ou dossier", "USB drive or folder"], precision: ["et pièges de clé", "and drive traps"],
        mots: "virus usb clé autorun" },
    Outil { action: Action::Yara, commande: "yara", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Analyse YARA", "YARA scan"],
        precision: ["règles de logiciels malveillants", "malware detection rules"],
        mots: "yara règles rules malware" },
    Outil { action: Action::Memoire, commande: "memoire", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Mémoire des processus", "Process memory"],
        precision: ["YARA sur ce qui tourne", "YARA on what is running"],
        mots: "mémoire memory yara processus sans fichier fileless" },
    Outil { action: Action::Pieges, commande: "pieges", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Fichiers-pièges", "Decoy files"],
        precision: ["alerte si un rançongiciel chiffre", "early ransomware warning"],
        mots: "rançongiciel ransomware leurre decoy piège trap" },
    Outil { action: Action::Protection, commande: "durcir", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Blocages de Windows Defender", "Windows Defender blocking"],
        precision: ["ASR, réseau, dossiers contrôlés", "ASR, network, folders"],
        mots: "defender asr bloquer block exploit dossiers contrôlés controlled folder pua" },
    // Titres de 34 caractères au plus dans ce groupe : au-delà, la colonne des précisions recule et les plus
    // longues (YARA, fichiers-pièges) sortent des 76 colonnes.
    Outil { action: Action::Bac, commande: "isoler", groupe: Some(Groupe::Protection), lettre: "b",
        titre: ["Bac à sable : programme inconnu", "Sandbox: run an unknown program"],
        precision: ["sans réseau, isolé", "no network, isolated"],
        mots: "sandbox isoler firejail bubblewrap" },
    Outil { action: Action::MotsDePasse, commande: "motdepasse", groupe: Some(Groupe::Protection), lettre: "p",
        titre: ["Mots de passe : ont-ils fuité ?", "Passwords: have they leaked?"],
        precision: ["rien n'est envoyé en clair", "nothing sent in clear"],
        mots: "password hibp pwned fuite leak" },
    Outil { action: Action::Navigateurs, commande: "navigateurs", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Mots de passe des navigateurs", "Browser passwords"],
        precision: ["comptés, jamais lus", "counted, never read"],
        mots: "navigateur browser firefox chrome edge chromium brave vivaldi mots de passe password \
               enregistrés saved faible weak réutilisé reused fuite leak checkup about:logins" },
    Outil { action: Action::Courriel, commande: "courriel", groupe: Some(Groupe::Protection), lettre: "e",
        titre: ["Courriel : a-t-il fuité ?", "Email address: has it leaked?"],
        precision: ["avec votre accord", "with your consent"],
        mots: "email mail fuite leak" },
    Outil { action: Action::QuiParle, commande: "sortantes", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Qui parle à Internet ?", "Who talks to the Internet?"],
        precision: ["connexions de chaque programme", "each program's connections"],
        mots: "connexions connections sortantes outbound espion spyware mouchard télémétrie telemetry serveurs \
               servers" },
    Outil { action: Action::CameraMicro, commande: "camera-micro", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Caméra et micro : qui s'en sert ?", "Camera and mic: who uses them?"],
        precision: ["programmes et dernière fois", "programs and last time"],
        mots: "caméra camera webcam micro microphone espion spy écoute voyant light enregistre record" },
    Outil { action: Action::Acces, commande: "acces", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Bilan de confidentialité", "Privacy check"],
        precision: ["position, contacts, caméra, micro", "location, contacts, camera, mic"],
        mots: "confidentialité privacy permissions autorisations accès access position location localisation gps \
               contacts carnet address book caméra camera micro microphone flatpak snap tcc applications apps" },
    Outil { action: Action::Distance, commande: "distance", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Mon ordinateur est-il contrôlé ?", "Is my computer being controlled?"],
        precision: ["faux technicien, accès à distance", "tech-support scam, remote access"],
        mots: "arnaque scam faux technicien fake tech support anydesk teamviewer rustdesk accès distance remote \
               access contrôle control prise de contrôle" },
    Outil { action: Action::Lien, commande: "lien", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Ce lien est-il dangereux ?", "Is this link dangerous?"],
        precision: ["examiné sans l'ouvrir", "checked without opening it"],
        mots: "url lien link phishing hameçonnage arnaque scam texto sms courriel email domaine domain" },
    Outil { action: Action::VerifierFichier, commande: "verifier-fichier", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Vérifier un fichier téléchargé", "Check a downloaded file"],
        precision: ["empreinte, YARA, antivirus", "checksum, YARA, antivirus"],
        mots: "sha256 empreinte checksum hash télécharger download iso installateur installer fichier file" },
    Outil { action: Action::Quarantaine, commande: "quarantaine", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Quarantaine : remettre un fichier", "Quarantine: restore a file"],
        precision: ["isolés, remis à l'identique", "isolated, put back exactly"],
        mots: "quarantaine quarantine isolé isolated faux positif false positive remettre restore restaurer" },
    Outil { action: Action::SecretsGit, commande: "secrets", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Secrets dans les projets git", "Secrets in git projects"],
        precision: ["mots de passe et clés oubliés", "forgotten passwords and keys"],
        mots: "secrets git gitleaks clé key api jeton token mot de passe password historique history dépôt \
               repository fuite leak" },
    Outil { action: Action::Conteneurs, commande: "conteneurs", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Failles des images Docker", "Flaws in Docker images"],
        precision: ["failles connues (trivy)", "known flaws (trivy)"],
        mots: "docker podman conteneur container image trivy faille vulnerability cve" },
    Outil { action: Action::Blocage, commande: "blocage", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Blocage des menaces", "Threat blocking"], precision: ["", ""],
        mots: "bloquer block blocage blocking protection active automatique automatic pare-feu firewall arrêter stop \
               processus process quarantaine quarantine malwarebazaar botnet threatfox pilotes drivers annuler undo" },
    Outil { action: Action::SitesDangereux, commande: "sites-dangereux", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Bloquer les sites dangereux", "Block dangerous sites"],
        precision: ["fichier hosts, annulable", "hosts file, undoable"],
        mots: "bloquer block sites dangereux dangerous malveillant malicious hosts urlhaus threatfox botnet \
               hameçonnage phishing" },
    Outil { action: Action::DernieresFailles, commande: "dernieres-failles", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Dernières failles exploitées", "Latest exploited flaws"],
        precision: ["catalogue de la CISA, 7 jours", "CISA catalog, 7 days"],
        mots: "failles flaws vulnérabilités vulnerabilities cve kev cisa exploitées exploited récentes latest \
               nouvelles new rançongiciel ransomware" },
    Outil { action: Action::CourrielSuspect, commande: "courriel-suspect", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Ce courriel est-il une arnaque ?", "Is this email a scam?"],
        precision: ["examiné sans rien ouvrir", "checked without opening anything"],
        mots: "courriel email mail eml arnaque scam hameçonnage phishing expéditeur sender pièce jointe attachment \
               spf dkim dmarc thunderbird outlook gmail msg usurpation spoofing" },
    Outil { action: Action::LogicielsEspions, commande: "logiciels-espions", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Logiciels espions : en ai-je un ?", "Spyware: is someone watching me?"],
        precision: ["clavier épié, indicateurs Échap", "keyboard spying, Échap indicators"],
        mots: "espion spyware stalkerware logiciel espion keylogger enregistreur de frappe clavier keyboard \
               surveillance monitoring harcèlement stalking échap mspy flexispy contrôle parental parental control" },
    Outil { action: Action::LogicielsPerimes, commande: "logiciels-perimes", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Logiciels pas à jour", "Outdated software"],
        precision: ["versions, failles exploitées", "versions, exploited flaws"],
        mots: "logiciel software version périmé outdated mise à jour update navigateur browser chrome edge \
               firefox brave office word excel acrobat reader java kev faille exploitée exploited" },
    Outil { action: Action::Signaler, commande: "signaler", groupe: Some(Groupe::Protection), lettre: "",
        titre: ["Signaler une faille à un éditeur", "Report a flaw to a vendor"],
        precision: ["rien n'est envoyé, vous relisez", "nothing is sent, you review"],
        mots: "signaler disclose signalement report divulgation disclosure faille vulnerability bogue bug éditeur \
               vendor msrc microsoft google chrome mozilla bugzilla apple ghsa github cert prime bounty" },
    Outil { action: Action::Logiciels, commande: "logiciels", groupe: Some(Groupe::Installer), lettre: "l",
        titre: ["Logiciels", "Software"], precision: ["les meilleurs, par catégorie", "the best ones, by category"],
        mots: "apps programmes programs installer install firefox vlc libreoffice" },
    Outil { action: Action::Gaming, commande: "gaming", groupe: Some(Groupe::Installer), lettre: "g",
        titre: ["Gaming", "Gaming"],
        precision: if cfg!(windows) { ["composants et réglages de Windows", "components and Windows settings"] }
            else if cfg!(target_os = "macos") { ["Rosetta, Steam, Epic, GOG…", "Rosetta, Steam, Epic, GOG…"] }
            else { ["Steam, Vulkan, GameMode, Wine…", "Steam, Vulkan, GameMode, Wine…"] },
        mots: "jeux games steam directx vulkan" },
    Outil { action: Action::Nettoyer, commande: "nettoyer", groupe: Some(Groupe::Optimiser), lettre: "v",
        titre: ["Nettoyer le système", "Clean up the system"],
        precision: ["caches, temporaires, corbeille…", "caches, temp files, trash…"],
        mots: "place space disque plein disk full cache corbeille trash" },
    Outil { action: Action::OptimiserRecommandes, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Réglages recommandés", "Recommended settings"],
        precision: ["en une fois, tout s'annule", "in one go, all undoable"],
        mots: "réglages settings" },
    Outil { action: Action::OptimiserConfidentialite, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Confidentialité", "Privacy"],
        precision: if cfg!(windows) { ["télémétrie, publicités, suivi", "telemetry, ads, tracking"] }
            else if cfg!(target_os = "macos") { ["publicités, analyses", "ads, analytics"] }
            else { ["rapports et statistiques", "reports and statistics"] },
        mots: "télémétrie telemetry vie privée privacy publicité ads" },
    #[cfg(not(target_os = "macos"))]
    Outil { action: Action::OptimiserPerformance, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Performance et fiabilité", "Performance and reliability"],
        precision: if cfg!(windows) { ["démarrage rapide, widgets…", "fast startup, widgets…"] }
            else { ["SSD, taille du journal", "SSD, journal size"] },
        mots: "ssd démarrage startup journal" },
    Outil { action: Action::OptimiserConfort, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Confort et fichiers", "Comfort and files"],
        precision: if cfg!(windows) { ["extensions, clés USB, clic droit", "extensions, USB drives, menus"] }
            else if cfg!(target_os = "macos") { ["extensions, .DS_Store, Finder", "extensions, .DS_Store, Finder"] }
            else { ["annonces d'Ubuntu", "Ubuntu announcements"] },
        mots: "extensions fichiers cachés hidden files" },
    Outil { action: Action::DnsRapide, commande: "dns-rapide", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["DNS le plus rapide", "Fastest DNS"], precision: ["mesuré ici, annulable", "measured here, undoable"],
        mots: "dns rapide fast résolveur resolver cloudflare quad9 google adguard vitesse speed" },
    Outil { action: Action::OptimiserAnnuler, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Tout remettre comme avant", "Put everything back"],
        precision: ["annule ce que Vanguard a changé", "undo what Vanguard changed"],
        mots: "annuler undo restaurer" },
    Outil { action: Action::Sauvegarder, commande: "sauvegarder", groupe: Some(Groupe::Donnees), lettre: "d",
        titre: ["Sauvegarder ou restaurer", "Back up or restore"],
        precision: ["base des appareils, réglages", "device database, settings"],
        mots: "backup restore sauvegarde base" },
    Outil { action: Action::CopierFichiers, commande: "copier-fichiers", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Copier mes fichiers", "Copy my files"],
        precision: ["vers un disque externe, vérifié", "to an external disk, checked"],
        mots: "copier copy sauvegarde backup photos disque externe external drive fichiers" },
    Outil { action: Action::SauvegardeAuto, commande: "sauvegarde-auto", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Sauvegarde automatique", "Automatic backup"],
        precision: ["chaque jour, sur un autre disque", "every day, to an external disk"],
        mots: "sauvegarde backup automatique automatic time machine historique des fichiers file history deja dup \
               rsync disque externe external drive" },
    Outil { action: Action::VerifierCopie, commande: "verifier-copie", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Vérifier une copie", "Check a copy"],
        precision: ["relue, comparée aux originaux", "read back, compared"],
        mots: "restauration restore test vérifier verify copie copy sauvegarde backup relire" },
    Outil { action: Action::VerifierCle, commande: "verifier-cle", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Vérifier ma clé", "Check my drive"],
        precision: ["vraie capacité, vitesse, erreurs", "real capacity, speed, errors"],
        mots: "clé key usb fausse fake capacité capacity vitesse speed débit secteurs sectors erreurs errors f3 h2testw \
               disque externe external drive" },
    Outil { action: Action::Raccourci, commande: "raccourci", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Raccourci sur cet ordinateur", "Shortcut on this computer"],
        precision: ["lancer Vanguard d'un clic", "start Vanguard with one click"],
        mots: "raccourci shortcut bureau desktop installer install menu lancer launch icône icon" },
    Outil { action: Action::Ordinateurs, commande: "ordinateurs", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Mes ordinateurs", "My computers"],
        precision: ["suivis par la clé VANGUARD", "tracked by the VANGUARD key"],
        mots: "ordinateurs computers tableau dashboard suivi parc famille family clé key" },
    Outil { action: Action::ProtegerDonnees, commande: "", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Protéger les données de la clé", "Protect the key's data"],
        precision: ["carnet chiffré par une phrase", "record encrypted by a passphrase"],
        mots: "chiffrer encrypt chiffrement encryption phrase passphrase mot de passe password protéger protect \
               perdue lost" },
    Outil { action: Action::MettreAJour, commande: "se-mettre-a-jour", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Mettre Vanguard à jour", "Update Vanguard"],
        precision: ["sur cet ordinateur, depuis la clé", "on this computer, from the key"],
        mots: "mise à jour mettre update upgrade vanguard version nouvelle new copie copy installer install" },
    Outil { action: Action::VerifierSauvegarde, commande: "verifier-sauvegarde", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Vérifier ma sauvegarde", "Check my backup"],
        precision: ["relue pour de vrai", "really read back"],
        mots: "sauvegarde backup vérifier verify restauration restore test rsync time machine" },
    // Au bout de Données, avec ce qui installe Vanguard ici (raccourci, mise à jour) : Paramètres ne montre que des
    // réglages avec leur valeur, et aucune place annoncée ne bouge.
    Outil { action: Action::Desinstaller, commande: "desinstaller", groupe: Some(Groupe::Donnees), lettre: "",
        titre: ["Retirer Vanguard de cet ordinateur", "Remove Vanguard from this computer"],
        precision: ["ce qu'il a posé, montré d'abord", "what it placed, shown first"],
        mots: "désinstaller uninstall désinstallation retirer remove supprimer delete effacer erase installer install \
               installé installed" },
    Outil { action: Action::Guide, commande: "guide", groupe: Some(Groupe::Guide), lettre: "",
        titre: ["Guide des commandes", "Command guide"],
        precision: ["Linux, Windows, macOS, tous", "Linux, Windows, macOS, all"],
        mots: "commandes commands terminal aide help" },
    Outil { action: Action::Depanner, commande: "depanner", groupe: Some(Groupe::Depanner), lettre: "",
        titre: ["Dépanner pas à pas", "Troubleshoot step by step"],
        precision: ["Internet, son, imprimante…", "Internet, sound, printer…"],
        mots: "dépanner troubleshoot panne problème internet son imprimante" },
    Outil { action: Action::Extensions, commande: "extensions", groupe: Some(Groupe::Extensions), lettre: "",
        titre: ["Extensions", "Extensions"],
        precision: ["plugins et labo, hors Vanguard", "plugins and lab, not Vanguard"],
        mots: "plugin plugins extension module ajouter add expérimental experimental script labo lab laboratoire \
               programme program essai test" },
    // Au bout de Cette machine, et « s » au menu principal (dit sur la ligne de « q ») : aucune ligne de plus au
    // menu principal, qui doit tenir dans 24 lignes.
    Outil { action: Action::Parametres, commande: "parametres", groupe: Some(Groupe::Machine), lettre: "s",
        titre: ["Paramètres", "Settings"],
        precision: ["langue, surveillance, blocage…", "language, monitoring, blocking…"],
        mots: "paramètres settings réglages options préférences preferences langue language emojis internet \
               hors ligne offline surveillance monitoring entretien maintenance appris learned blocage blocking \
               restrictions temps réel real-time realtime pause" },
];

// Une action ajoutée sans sa ligne décalerait toutes les suivantes : la compilation s'arrête.
const _: () = assert!(OUTILS.len() == Action::Parametres as usize + 1);

/// La précision de la ligne Surveillance. Le temps réel coupé, la minuterie est là, mais chaque passe s'arrête au
/// début : « activée » seul le cacherait.
fn precision_surveillance(active: bool, temps_reel_coupe: bool) -> &'static str {
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

/// Le veilleur : il lit deux flux du noyau Linux ; ailleurs, la commande le dit.
fn veilleur(etat: Option<&str>, sous_etat: Option<&str>, servir: bool) {
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
    fn outil(self) -> &'static Outil {
        &OUTILS[self as usize]
    }

    /// Texte de la ligne de menu et sa précision en gris.
    fn libelle(self) -> (&'static str, &'static str) {
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
            _ => texte(self.outil().precision),
        };
        (texte(self.outil().titre), precision)
    }

    /// L'outil a-t-il quelque chose à proposer sur ce système ? (une catégorie de réglages vide n'est pas montrée)
    fn disponible(self) -> bool {
        match self {
            Action::OptimiserConfidentialite => reglages_disponibles(optimiser::Categorie::Confidentialite),
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance => reglages_disponibles(optimiser::Categorie::Performance),
            Action::OptimiserConfort => reglages_disponibles(optimiser::Categorie::Confort),
            // Lire l'état de Defender lance PowerShell : vérifié seulement à l'ouverture (`optimiser::protection`).
            Action::Protection => cfg!(windows),
            // Deux flux du noyau Linux : ailleurs, la ligne ne serait que du bruit.
            Action::Veilleur => cfg!(target_os = "linux"),
            // Sous Linux, le gestionnaire de paquets et le catalogue de la CISA (bilan, Failles connues) s'en chargent.
            Action::LogicielsPerimes => cfg!(any(windows, target_os = "macos")),
            _ => true,
        }
    }

    /// Après l'outil, attendre Entrée avant de revenir au menu ? Pas pour ceux qui ont leurs propres écrans et se
    /// quittent par Échap (le guide, le dépannage) : on y reviendrait deux fois.
    fn attendre_apres(self) -> bool {
        !matches!(
            self,
            Action::Guide | Action::Depanner | Action::QuiParle | Action::Extensions | Action::Parametres
        )
    }
}

/// Un texte de la table dans la langue de l'interface.
fn texte([fr, en]: [&'static str; 2]) -> &'static str {
    if langue::anglais() { en } else { fr }
}

/// Un groupe d'outils du menu principal, ouvert en sous-menu.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Groupe {
    Machine,
    Reseau,
    Protection,
    Installer,
    Optimiser,
    Donnees,
    Guide,
    Depanner,
    Extensions,
}

const GROUPES: [Groupe; 9] = [
    Groupe::Machine,
    Groupe::Reseau,
    Groupe::Protection,
    Groupe::Installer,
    Groupe::Optimiser,
    Groupe::Donnees,
    Groupe::Guide,
    Groupe::Depanner,
    Groupe::Extensions,
];

impl Groupe {
    fn titre(self) -> &'static str {
        match self {
            Groupe::Machine => tr!("Cette machine", "This machine"),
            Groupe::Reseau => tr!("Réseau et Internet", "Network and Internet"),
            Groupe::Protection => tr!("Antivirus et protection", "Antivirus and protection"),
            Groupe::Installer => tr!("Installer et jouer", "Install and play"),
            Groupe::Optimiser => tr!("Optimiser", "Optimize"),
            Groupe::Donnees => tr!("Données", "Data"),
            Groupe::Guide => tr!("Guide des commandes", "Command guide"),
            Groupe::Depanner => tr!("Dépanner pas à pas", "Troubleshoot step by step"),
            Groupe::Extensions => tr!("Extensions", "Extensions"),
        }
    }

    fn resume(self) -> &'static str {
        match self {
            Groupe::Machine => tr!("audit, mises à jour, réparer…", "audit, updates, repair…"),
            Groupe::Reseau => tr!("appareils, surveillance, débit", "devices, monitoring, speed test"),
            Groupe::Protection => tr!("analyses, clé USB, fuites…", "scans, USB drive, leaks…"),
            Groupe::Installer => tr!("logiciels libres, gaming", "open source software, gaming"),
            Groupe::Optimiser => tr!("nettoyer, confidentialité…", "clean up, privacy…"),
            Groupe::Donnees => tr!("sauvegarder, copier mes fichiers", "back up, copy my files"),
            Groupe::Guide => tr!("Linux, Windows, macOS, pas à pas", "Linux, Windows, macOS, how-tos"),
            Groupe::Depanner => tr!("Internet, son, imprimante…", "Internet, sound, printer…"),
            Groupe::Extensions => tr!("plugins et labo, hors Vanguard", "plugins and lab, not Vanguard"),
        }
    }

    /// Ses outils, dans l'ordre du sous-menu.
    fn actions(self) -> Vec<Action> {
        OUTILS
            .iter()
            .filter(|o| o.groupe == Some(self))
            .map(|o| o.action)
            .collect()
    }
}

/// Sous-menu d'un groupe : ses outils numérotés, Entrée pour revenir au menu principal. Un groupe d'un seul outil
/// (Données) l'ouvre directement. Un outil sans rien à proposer sur ce système n'est pas montré.
async fn sous_menu(s: &mut Session, groupe: Groupe) {
    let actions: Vec<Action> = groupe.actions().into_iter().filter(|a| a.disponible()).collect();
    if let [seule] = actions[..] {
        executer(s, seule).await;
        revenir_au_menu(seule);
        return;
    }
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = lignes_cadre(
            &format!("{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} {}", groupe.titre()),
            groupe.resume(),
        )
        .into_iter()
        .map(Ligne::Texte)
        .collect();
        lignes.push(Ligne::Texte(String::new()));
        for (i, a) in actions.iter().enumerate() {
            let (texte, precision) = a.libelle();
            lignes.push(Ligne::choix(&(i + 1).to_string(), texte, precision));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix(
            "↵",
            tr!("Revenir au menu principal", "Back to the main menu"),
            "",
        ));
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choix_du_menu(&lignes, &dernier, tr!("revenir", "back")) else {
            return;
        };
        let choix = choix.trim();
        if choix.is_empty() || choix == "↵" || choix.eq_ignore_ascii_case("q") {
            return;
        }
        let Some(&action) = choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| actions.get(i))
        else {
            continue;
        };
        dernier = choix.to_string();
        println!();
        executer(s, action).await;
        if !ui::vient_de_revenir() {
            crate::selection::attendre_retour(&trf!(
                "\n{GRIS}Entrée pour revenir…{RESET}",
                "\n{GRIS}Enter to go back…{RESET}"
            ));
        }
    }
}

async fn executer(s: &mut Session, action: Action) {
    // Le choix de l'outil dans le menu n'est pas un « revenir » : seul compte ce qui se répond dans l'outil.
    ui::noter_retour(false);
    match action {
        Action::Complet => s.complet().await,
        Action::Corriger => s.corriger(),
        Action::Rapport => {
            if s.audit.is_none() && s.reseau.is_none() {
                s.complet().await;
            }
            rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref(), s.audit_reseau.as_ref());
        }
        Action::Audit => s.audit = Some(machine::executer(false)),
        Action::Integrite => protection::integrite::verifier(false),
        Action::Appris => apprentissage::menu(),
        Action::Changements => changements::afficher(),
        Action::Lenteur => lenteur::menu(),
        Action::Fiche => fiche::fiche(false),
        Action::ALaisser => {
            let audit = s.audit.get_or_insert_with(|| machine::executer(false));
            a_laisser::laisser(audit);
        }
        Action::Entretien => entretien::activer(!entretien::active()),
        Action::Diagnostic => diagnostic::diagnostic(),
        Action::Maj => maj::executer(),
        Action::Reparer => reparer::menu(),
        Action::Scanner => s.scanner_reseau(None, "courants").await,
        Action::AuditReseau => s.audit_reseau(false, false, false).await,
        Action::Appareil => {
            let ip = demander(tr!(
                "Adresse IP de l'appareil (ex. 10.0.0.1) : ",
                "IP address of the device (e.g. 10.0.0.1): "
            ));
            s.scanner_reseau(Some(ip), "tous").await;
        }
        Action::Nommer => {
            let qui = demander(tr!(
                "IP ou adresse MAC de l'appareil : ",
                "IP or MAC address of the device: "
            ));
            let surnom = demander(tr!(
                "Surnom (vide pour le retirer) : ",
                "Nickname (empty to remove it): "
            ));
            nommer(&qui, &surnom);
        }
        Action::Surveillance => reseau::surveillance::activer(!reseau::surveillance::active()),
        Action::Tableau => reseau::tableau::ouvrir(false),
        Action::Veilleur => veilleur(None, None, false),
        Action::Connexion => reseau::connexion::tester().await,
        Action::ListesNoires => reseau::listes_noires::verifier(),
        Action::WifiCanaux => reseau::canaux::analyser(),
        Action::Nat => reseau::nat::tester(),
        Action::Cameras => reseau::cameras::chercher_cameras().await,
        Action::Objets => reseau::objets::montrer(),
        Action::WifiPublic => reseau::wifi_public::commande(None),
        Action::AntivirusRapide => protection::antivirus::analyser(protection::antivirus::Portee::Rapide),
        Action::AntivirusComplet => protection::antivirus::analyser(protection::antivirus::Portee::Complete),
        Action::AntivirusDossier => protection::antivirus::choisir(),
        Action::Yara => protection::yara::menu(),
        Action::Memoire => protection::memoire::analyser(),
        Action::Pieges => protection::pieges::menu(),
        Action::Bac => {
            let chemin = demander(tr!("  Programme à isoler (chemin) : ", "  Program to isolate (path): "));
            let chemin = chemin.trim().trim_matches(['"', '\'']);
            if !chemin.is_empty() {
                protection::isoler::isoler(std::path::Path::new(chemin));
            }
        }
        Action::MotsDePasse => protection::fuites::verifier(),
        Action::Navigateurs => machine::mots_de_passe::navigateurs(),
        Action::Courriel => protection::fuites::verifier_courriel(),
        Action::QuiParle => protection::sortantes::menu(),
        Action::SitesDangereux => protection::sites_bloques::menu(),
        Action::DernieresFailles => protection::kev::ecran(7),
        Action::CameraMicro => protection::camera::afficher_tout(),
        Action::Acces => protection::acces::afficher_tout(),
        Action::Distance => protection::distance::menu(),
        Action::Lien => protection::lien::verifier(None),
        Action::CourrielSuspect => protection::courriel_suspect::verifier(None),
        Action::LogicielsEspions => protection::espions::afficher(),
        Action::LogicielsPerimes => protection::perimes::afficher(),
        Action::Signaler => signaler::menu(),
        Action::VerifierFichier => protection::telechargement::verifier(None, None),
        Action::Quarantaine => protection::quarantaine::menu(),
        Action::SecretsGit => protection::secrets_git::analyser(),
        Action::Conteneurs => protection::conteneurs::analyser(),
        Action::Blocage => protection::blocage::menu(),
        Action::Logiciels => logiciels::menu(),
        Action::Gaming => gaming::menu(),
        Action::Nettoyer => nettoyer::menu(),
        Action::OptimiserRecommandes => optimiser::recommandes(),
        Action::OptimiserConfidentialite => optimiser::menu(optimiser::Categorie::Confidentialite),
        #[cfg(not(target_os = "macos"))]
        Action::OptimiserPerformance => optimiser::menu(optimiser::Categorie::Performance),
        Action::OptimiserConfort => optimiser::menu(optimiser::Categorie::Confort),
        Action::Protection => optimiser::protection(),
        Action::DnsRapide => dns_rapide::mesurer_et_proposer(),
        Action::OptimiserAnnuler => optimiser::tout_annuler(),
        Action::Sauvegarder => donnees::menu(),
        Action::CopierFichiers => copier::menu(),
        Action::SauvegardeAuto => sauvegarde::menu(),
        Action::VerifierCopie => copier::verifier_copie(None),
        Action::VerifierSauvegarde => sauvegarde::verifier_sauvegarde(),
        Action::Desinstaller => desinstaller::commande(false),
        Action::VerifierCle => verifier_cle::menu(),
        Action::Raccourci => raccourci::commande(None),
        Action::Ordinateurs => ordinateurs::menu(),
        Action::ProtegerDonnees => chiffrement::menu(),
        Action::MettreAJour => mise_a_jour::commande(),
        Action::Guide => guide::menu(),
        Action::Depanner => depanner::menu(),
        Action::Extensions => plugins::extensions(),
        Action::Parametres => parametres::menu(),
    }
}

/// Aide anglaise des commandes : la française est dans les commentaires de `Commande`.
#[rustfmt::skip] // une ligne par aide, que rustfmt étalerait sur quatre
const AIDES_EN: &[(&str, &str)] = &[
    ("complet", "Full check: this machine, then the network"),
    ("machine", "Audit this machine (firewall, ports, SSH, updates, encryption…)"),
    ("corriger", "Audit the machine, then apply the fixes step by step"),
    ("reseau", "Network scan: devices, open ports, risks, changes since previous scans"),
    ("audit-reseau", "Network audit by domain: six grades (exposure to the Internet, Wi-Fi, segmentation, DNS and TLS, \
                      connected devices, computers) from the local network scan, this machine's network findings and \
                      a few more read-only checks, attacking nothing; what could not be checked is said, never counted \
                      as safe"),
    ("antivirus", "Malware scan: ClamAV (Linux, macOS) or Microsoft Defender (Windows)"),
    ("surveillance", "Turn hourly network monitoring on or off (notification for unknown devices)"),
    ("tableau", "Monitoring dashboard in the browser: its state, the alerts day by day, the new devices and the \
                 suspicious connections. Local page, nothing is sent"),
    ("dernieres-failles", "Latest exploited flaws: those CISA added to its catalog (known real attacks) in the last \
                            days, newest first; on Arch, those affecting a package on this computer first"),
    ("sites-dangereux", "Dangerous sites blocked by the hosts file: URLhaus ones and ThreatFox command servers \
                          (abuse.ch key), after your consent and with administrator rights; \"off\" removes them \
                          exactly. Without argument: their state"),
    ("veilleur", "Watcher (Linux 6.6 and later): each program started and each connection closed, seen as they \
                   happen and judged as in the check; with active protection, it can freeze and stop an almost \
                   certain ransomware. Off by default. Without argument: its state, then turning it on or off, after \
                   your consent. \"ransomware on|off\" sets the personal-folder ransomware watch"),
    ("entretien", "Monthly check-up: once a month, silently, the grade, waiting updates, space to free and new \
                   problems, in one notification; nothing is changed. Without argument: what it would say now"),
    ("maj", "Updates: system, programs, drivers and firmware checked at once, then installed with your consent"),
    ("reparer", "Common repairs: network, hijacked browsing, firewall, antivirus, system files, disk, space, updates, \
                 time"),
    ("logiciels", "Software: the best programs, mostly open source (browsers, passwords, office, video, design, system \
                   tools…), by category: choose, then install from the system's official source"),
    ("diagnostic", "Computer diagnostic: hardware, system and recent problems (crashes, errors). Read only"),
    ("nettoyer", "Clean up the system: caches, temporary files, downloaded packages, old logs, trash… The space each \
                  item frees is shown first; check, then accept"),
    ("connexion", "Connection test for gaming: ping, jitter, packet loss, speed and bufferbloat"),
    ("appris", "What Vanguard has learned on this computer: the alerts declared normal, and forgetting them"),
    ("listes-noires", "Is your home's Internet address on a blocklist (Spamhaus, SpamCop, DroneBL, PSBL)? If so, a \
                       device is probably infected. After your consent: the lists see the address"),
    ("yara", "YARA scan: 308 rules for malware families (ReversingLabs) and MalwareBazaar's fingerprints, alongside \
              the antivirus. Without a folder: downloads, desktop, startup. Read-only"),
    ("memoire", "Memory of running processes passed through the 308 YARA rules: fileless malware lives nowhere else. \
                 Read-only, on demand; LSASS and protected processes: their memory is never read; nothing is kept"),
    ("secrets", "Secrets in the history of the home folder's git projects (passwords, API keys, tokens), searched by \
                 Vanguard, and also by gitleaks if installed. No secret is shown. Read-only"),
    ("conteneurs", "Known flaws in this computer's Docker or Podman images, by trivy if installed. Read-only"),
    ("parametres", "Settings: all of Vanguard's settings (language, emojis, working without the Internet, real-time \
                    protection, monitoring, monthly check-up, learned alerts, blocking, extension restrictions, \
                    abuse.ch key, software versions, weekly self-test). No argument: their state; with a setting and a value: changes it, showing the \
                    previous value to go back. “real-time no --for 1h|4h” turns Vanguard's real-time protection off \
                    for that long (without --for: until turned back on), after your consent; never Defender, the \
                    firewall or UAC"),
    ("blocage", "Threat blocking: each threat found offers “Block” (the action shown, accepted, written down, \
                 undoable); active protection, after a consent given once, blocks what is certain by itself \
                 (MalwareBazaar fingerprint, known attack tool, command server), then warns you. No argument: the menu"),
    ("canaux", "Crowded Wi-Fi: nearby networks by channel, and the freest channel to set on the router. Read-only"),
    ("nat", "NAT type for gaming (open, moderate or strict), from two public servers (STUN). Read-only"),
    ("cameras", "Hidden cameras: on a rental's or someone's network, the devices that look like cameras. Read-only"),
    ("objets", "Router and connected devices from the last kept scan: what the router announces (model, software), \
                its HTTP-only admin page, the cameras, printers, NAS… and their default password. Nothing is probed"),
    ("dns-rapide", "Fastest DNS: measures the current DNS and public ones, then offers the fastest, undoable. A DNS \
                    that protects (NextDNS, encrypted, filtering) is kept"),
    ("wifi-public", "Public Wi-Fi mode (café, hotel, airport): incoming connections closed on this network, file \
                     sharing and name announcement off, protective DNS (encrypted on Linux with systemd-resolved), \
                     after your consent and with administrator rights; \"off\" puts everything back exactly, \
                     \"portal\" reopens the network's login page. Without argument: its state"),
    ("pieges", "Decoy files against ransomware: place them (after your consent), see whether they are intact, or \
                remove them"),
    ("durcir", "Windows Defender blocking: ASR rules, network protection, unwanted software, controlled folder access. \
                Each one is turned on after your consent and undoes exactly (Windows only)"),
    ("isoler", "Run an unknown program in a sandbox: no network, home folder hidden"),
    ("courriel", "Email address leaks: the address is sent to the search service, after your consent"),
    ("integrite", "Critical file integrity: BLAKE3 fingerprint reference, then what changed since"),
    ("motdepasse", "Check whether passwords have leaked (Have I Been Pwned); only 5 characters of their fingerprint \
                    are sent"),
    ("navigateurs", "Passwords saved in the browsers: how many and how protected (counted, never read), where to run \
                     the browser's built-in check (weak, reused, compromised), and the HIBP check of a typed password"),
    ("sortantes", "Who talks to the Internet? Each program's current connections, with the server's name. Read-only"),
    ("verifier-moi", "Check Vanguard itself: version, build date, SHA-256 fingerprint of the program (to compare with the release page), on the owner's key the key manifest, and after your consent the signed history of published versions; or another copy of Vanguard, by its fingerprint and that history"),
    ("distance", "Is my computer being controlled? Remote control software (AnyDesk, TeamViewer, RustDesk…) installed, started at boot, running or downloaded: the fake technicians' tool. Removed after your consent; a running program asks for a second consent"),
    ("lien", "Is this link dangerous? Checked without ever opening it; after your consent, its age and public lists"),
    ("verifier-fichier", "Check a downloaded file: checksum compared with the site's, name and content, YARA and \
                          antivirus"),
    ("courriel-suspect", "Is this email a scam? A saved email (.eml) examined without opening anything: the sender \
                          and its authentication (SPF, DKIM, DMARC) as written by your provider, the links (shown \
                          text against real address) and the attachments (name, content, YARA, antivirus); after \
                          your consent, the domains' age and public lists"),
    ("logiciels-espions", "Spyware: known stalkerware servers and sites (Échap list, CC-BY 4.0) in current \
                           connections and the DNS cache, programs reading the keyboard, apps allowed input \
                           monitoring, accessibility or screen recording (macOS), known monitoring software. \
                           Read-only"),
    ("logiciels-perimes", "Outdated software (Windows, macOS): browsers, Office, Acrobat, Java, 7-Zip, PuTTY and \
                           Slack compared with their latest version (publishers' sites, endoflife.date, Homebrew; \
                           public files downloaded in full, nothing about this computer is sent), each product's \
                           exploited flaws in CISA's catalog, Firefox and Edge checked flaw by flaw (Mozilla \
                           advisories, Microsoft's list). Read-only"),
    ("signaler", "Prepare a report for a vendor (MSRC, Google, Chrome, Mozilla, Apple, GHSA advisory, CERT/CC, \
                  CERT-FR, Vanguard): sorted first (a known flaw is fixed by an update, malware is not a flaw), a \
                  draft in the program's format, what is personal removed, written on this computer and shown in \
                  full. Nothing is ever sent: you read it, copy it and submit it yourself"),
    ("camera-micro", "Camera and microphone: who uses them? On Windows, each program and the last time; on Linux, \
                      what holds them right now. Read-only"),
    ("acces", "Privacy check: the apps that have access to the location, contacts, camera and microphone, and their \
               last use when it is recorded. Read-only"),
    ("quarantaine", "Quarantine: the files isolated by the antivirus or YARA, to put back in their place (false \
                     positive) or to delete for good"),
    ("sauvegarder", "Back up the device database and the monitoring state to a JSON file"),
    ("restaurer", "Add a backup (or an appareils.json) to the current database, without erasing anything"),
    ("nommer", "Give a nickname to a device of the database (“HP printer”), by its IP or MAC"),
    ("gaming", "Gaming: components for games (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, Wine…; \
                macOS: Rosetta, Steam, Epic…) and system settings"),
    ("guide", "Command guide: the useful commands of Omarchy, Arch, Fedora, Debian, other Linux, Windows, macOS and \
               all systems, sorted by program, with step-by-step guides; plus the tldr-pages examples, downloaded \
               every week"),
    ("lenteur", "Why is it slow? What keeps the processor, memory and disk busy, startup, the programs started at \
                 login. Read only"),
    ("demarrage", "Startup programs: those that start at login, to remove or put back after your consent. Each removal \
                   is undone exactly (Optimize › Put everything back)"),
    ("fiche", "Computer specs: model, motherboard, processor, memory, graphics card, disks, system. Serial numbers are \
               shown on screen only"),
    ("copier-fichiers", "Copy my files (Documents, Pictures, Desktop, Videos, Music) to an external disk: checked \
                         copy, nothing deleted or overwritten, an interrupted copy resumes"),
    ("verifier-copie", "Check a copy made by “Copy my files” (restore test): files spread over the whole copy, read \
                        back from the disk and compared with their original. Nothing is written or deleted"),
    ("verifier-sauvegarde", "Check my backup: the backup set up by Vanguard really read back, files spread over the \
                             whole backup compared with their original; for Time Machine, Déjà Dup and File History, \
                             the steps. Nothing is written or deleted"),
    ("verifier-cle", "Check my drive: real capacity (fake drives), speeds and bad blocks of a USB stick or an \
                      external disk. Writes into the free space after your consent, reads back, then erases; your \
                      files are not touched"),
    ("changements", "What Vanguard changed: each fix run on this computer, its date and its result"),
    ("evenements", "The event log: alerts, evidence recorded before an action, actions, undos, alerts declared normal \
                    and version changes, linked together, with the state of its sealed chain. Read only"),
    ("a-laisser", "Report to leave behind: a simple page for the person you just helped (grade, what is left to do, \
                   what is fine), put on their Desktop after consent and opened in the browser"),
    ("sauvegarde-auto", "Automatic backup: set up with the system's tool (Déjà Dup or rsync every day, Time Machine, \
                         File History) to an external disk, after your consent, exactly undoable"),
    ("raccourci", "Shortcut on this computer: Vanguard copied here and started with one click (applications menu on \
                   Linux, Desktop on Windows and macOS). Without argument: the state, then the offer"),
    ("regles", "The check rules declared for this system: stable identifier, subject, hardening references"),
    ("autotest", "Self-test: Vanguard checks its own readings on this computer. Every check rule under a guard and a \
                  time limit, read only and proven so (fingerprints before and after), and its readings compared with \
                  those of the system's tools (pacman, systemctl, ss, PowerShell…). Nothing is changed; offline unless \
                  --internet; a gap goes to the error log, without any value from the computer. Exit code: 0 sound, \
                  1 gap, 2 not checked"),
    ("se-mettre-a-jour", "Update Vanguard on this computer: from a newer VANGUARD key, or from the latest version \
                          published on GitHub, signed by the author and checked; always after your consent, never to \
                          an older version"),
    ("desinstaller", "Remove Vanguard from this computer: what it placed there (monitoring, monthly check-up, \
                      automatic backup, decoy files, shortcut and icon, program copy, leftovers of an earlier \
                      version), found, shown, then checked. The data folder is removed only after a second consent; \
                      the USB key is never touched"),
    ("ordinateurs", "My computers: those where the VANGUARD key ran a check, their grade and remaining problems (on the \
     key's VANGUARDLOG partition)"),
    ("traces", "Collect the traces after an infection, before cleaning up: processes, connections, what starts by \
                itself, accounts, logs of the last 7 days, recent files and the incident timeline, in a dated folder \
                (README, SHA-256 fingerprints). Read-only; nothing goes to the Internet"),
    ("depanner", "Troubleshoot step by step: no Internet, Wi-Fi dropping, slow computer, no sound, printer, disk full; \
                  after an infection, new computer, computer leaving (sale, gift)"),
    ("plugin", "Plugins: programs of yours added to Vanguard without changing its code (tests, experimental tools), \
                each in a folder with a plugin.toml. “add <folder>” copies and approves it (SHA-256 fingerprints), \
                “approve <name>” after a change, “list”, “remove <name>”, or “<name> [arguments]” to run it \
                (“--report”: its findings in the HTML report); no argument: the list to choose from. Never as \
                administrator; outside the grade"),
    ("labo", "Lab: a script put as it is in the lab folder (.sh, .bash, .ps1, .py or a program), to try an idea \
              outside Vanguard's program. No argument: the list to choose from; “open”: the folder; “<file> \
              [arguments]” runs it (approved by its fingerprint on the first run). Never as administrator"),
    ("extensions", "Extensions: the menu of plugins and lab scripts, to choose and run"),
    ("optimiser", "Optimize: the recommended settings, the privacy, performance (except macOS) and comfort ones, each \
                   shown, accepted, then exactly undoable; “undo” puts everything back as it was. No argument: the \
                   Optimize menu"),
    ("proche", "A relative's computer: three questions (who uses it, why you were asked to look at it, their \
                network), the check-up, a summary in plain words, the fixes accepted one by one, then the page to \
                leave with its tips"),
];

/// Aide anglaise des options : (commande, option, aide).
#[rustfmt::skip]
const OPTIONS_EN: &[(&str, &str, &str)] = &[
    ("dernieres-failles", "jours", "How many days back (7 by default)"),
    ("nettoyer", "liste", "Show what could be cleaned up and the space to gain, deleting nothing"),
    ("desinstaller", "liste", "Show what would be removed, without removing anything"),
    ("logiciels", "liste", "Show each program offered and its state, without installing anything"),
    ("logiciels", "recommandes", "Install the starter pack (browser, passwords, video, office, archives), after your \
                                  consent"),
    ("complet", "html", "Also open the HTML report in the browser"),
    ("tableau", "sans_ouvrir", "Write the page without opening it (no graphical display, over SSH)"),
    ("complet", "texte", "Show the report as plain text (Markdown) in the terminal: no browser or graphical display \
                          needed"),
    ("reseau", "cible", "IP, CIDR network (10.0.0.0/24) or range (10.0.0.1-50). Default: your local network"),
    ("reseau", "ports", "“courants”/“common” (default), “tous”/“all” (1-65535) or a list “22,80,8000-8100”"),
    ("reseau", "timeout", "Connection timeout per port, in milliseconds"),
    ("reseau", "parallele", "Number of simultaneous connections"),
    ("audit-reseau", "html", "Also open the HTML report in the browser"),
    ("audit-reseau", "invite", "You are on the guest network: Vanguard checks that it is really separated from the main \
                                one"),
    ("antivirus", "complet", "The whole home folder instead of the risky places"),
    ("antivirus", "dossier", "A USB drive, external disk or folder to scan entirely"),
    ("isoler", "fichier", "Program or script to run"),
    ("pieges", "retirer", "Remove the decoy files placed"),
    ("veilleur", "sous_etat", "For “ransomware”: on or off"),
    ("yara", "complet", "The whole home folder instead of the risky places"),
    ("yara", "dossier", "A USB drive, external disk or folder to scan entirely"),
    ("integrite", "accepter", "Take the current state as the new reference (after a system update)"),
    ("integrite", "temps_reel", "Watch the critical files live until Ctrl-C"),
    ("sauvegarder", "fichier", "File to write (default: vanguard-sauvegarde-YYYY-MM-DD.json in the home or Documents \
                                folder)"),
    ("nommer", "appareil", "IP (on the current network) or MAC address of the device"),
    ("nommer", "surnom", "The nickname; empty to remove it"),
    ("lien", "adresse", "The link you received (in quotes if it contains “&” or “?”)"),
    ("verifier-fichier", "fichier", "The downloaded file"),
    ("courriel-suspect", "fichier", "The saved email (.eml): Thunderbird “Save As”, Gmail “Download message”, \
                                     Outlook on the web “Download”"),
    ("verifier-fichier", "empreinte", "The checksum published by the site (preferably SHA-256). Otherwise: a \
                                       SHA256SUMS or .sha256 next to it"),
    ("guide", "quoi", "A system (omarchy, arch, fedora, debian, windows, macos, all; linux: the common programs; tldr), \
                       a program (systemctl, winget, tar…) or words to look for"),
    ("fiche", "json", "The specs as JSON, for a script (without the serial numbers)"),
    ("evenements", "json", "The log as JSON, for a script"),
    ("logiciels-espions", "json", "The result as JSON, for a script"),
    ("logiciels-perimes", "json", "The result as JSON, for a script"),
    ("signaler", "incident", "The identifier of a log event (vanguard events): its incident is used"),
    ("signaler", "outil", "The last examination of a tool (PRO-ESP-001, PRO-PER-001, PRO-COU-001)"),
    ("signaler", "programme", "The program: msrc, google, chrome, mozilla, apple, ghsa, cert-cc, cert-fr or vanguard"),
    ("signaler", "langue", "The draft's language (fr or en); by default, the one the program reads"),
    ("signaler", "json", "The sorting and the draft as JSON, for a script: nothing written or recorded, no question"),
    ("signaler", "effacer", "List the kept drafts and erase them after your consent"),
    ("courriel-suspect", "json", "The result as JSON, for a script: the examination on the computer only (neither \
                                  the online check nor the attachments scan, said not checked)"),
    ("evenements", "incident", "One incident's thread: this event, what caused it and what it caused"),
    ("autotest", "json", "The report as JSON, for a script (without any value read on the computer)"),
    ("autotest", "internet", "Let the rules that need it go on the Internet (updates, software versions)"),
    ("autotest", "detail", "Show on screen the values that differ (package, unit, account names), here only"),
    ("autotest", "une_par_une", "The rules one by one, for timings without their neighbours (slower)"),
    ("copier-fichiers", "destination", "A folder on an external disk (default: chosen among the plugged-in disks)"),
    ("verifier-copie", "dossier", "The disk or the folder of the copy (default: chosen among the plugged-in disks)"),
    ("verifier-cle", "dossier", "A folder of the drive or disk (default: chosen among the plugged-in disks)"),
    ("sauvegarde-auto", "annuler", "Remove the automatic backup set up by Vanguard (the backed-up files stay)"),
    ("traces", "dossier", "The folder where traces-YYYYMMDD-HHMMSS is created (default: the VANGUARD key if Vanguard \
                           runs from it, otherwise this computer's Vanguard folder)"),
    ("plugin", "quoi", "add <folder>, approve <name>, list, remove <name>, or <name> [--report] [arguments]"),
    ("labo", "quoi", "open, list, or <file> [arguments]"),
    ("extensions", "sans_restrictions", "on: the extensions' restrictions turned off (no consent, fingerprint or scan, \
                                         with all your rights); off: back on. The extensions folder must stay yours \
                                         alone"),
    ("parametres", "quoi", "A setting (language, emojis, offline, real-time, monitoring, maintenance, learned, \
                              blocking, restrictions, abuse.ch, software-versions, autotest) and its value; real-time no also \
                              takes --for 1h or 4h"),
    ("blocage", "quoi", "“search”, “undo”, “status”, “auto” or “click” (active protection), or a category (programs, \
                           connections, startup, agents) followed by a mode (off, click, auto)"),
    ("optimiser", "quoi", "recommended, privacy, performance, comfort or undo"),
    ("verifier-moi", "programme", "Another copy of Vanguard to check (from another key, an earlier version), by its \
                                     fingerprint and the signed version history"),
    ("depanner", "sujet", "The subject: internet, wifi, slow, sound, printer, disk, infection, new, leaving (or words \
                             describing it)"),
];

/// La ligne de commande, avec son aide en anglais si l'interface est en anglais (l'aide écrite plus haut, en
/// commentaires, est la version française).
fn ligne_de_commande() -> clap::Command {
    let c = Args::command();
    if !langue::anglais() {
        return c;
    }
    let mut c =
        c.about("Portable cyber defense for endpoints and networks: check, fixes, settings. No argument: menu.");
    for &(nom, aide) in AIDES_EN {
        c = c.mut_subcommand(nom, |s| s.about(aide));
    }
    for &(commande, option, aide) in OPTIONS_EN {
        c = c.mut_subcommand(commande, |s| s.mut_arg(option, |a| a.help(aide)));
    }
    c
}

/// `vanguard optimiser [quoi]` : l'outil du menu Optimiser qui porte ce nom, lancé comme depuis le menu (la même
/// ligne de `OUTILS`, la même `executer`) ; sans nom, le sous-menu.
async fn optimiser_en_ligne_de_commande(quoi: Option<&str>) {
    let mut s = Session::default();
    let action = match quoi {
        None => return sous_menu(&mut s, Groupe::Optimiser).await,
        Some("recommandes" | "recommended") => Action::OptimiserRecommandes,
        Some("confidentialite" | "privacy") => Action::OptimiserConfidentialite,
        #[cfg(not(target_os = "macos"))]
        Some("performance") => Action::OptimiserPerformance,
        Some("confort" | "comfort") => Action::OptimiserConfort,
        Some("annuler" | "undo") => Action::OptimiserAnnuler,
        Some(_) => {
            trp!(
                "Pas de réglages de performance proposés sur ce système.",
                "No performance settings offered on this system."
            );
            return;
        }
    };
    executer(&mut s, action).await;
}

/// La portée d'une analyse demandée en ligne de commande : le dossier donné, sinon tout le dossier personnel
/// (--complet), sinon les endroits à risque.
fn portee(dossier: Option<std::path::PathBuf>, complet: bool) -> protection::antivirus::Portee {
    match (dossier, complet) {
        (Some(d), _) => protection::antivirus::Portee::Dossier(d),
        (None, true) => protection::antivirus::Portee::Complete,
        (None, false) => protection::antivirus::Portee::Rapide,
    }
}

#[tokio::main]
async fn main() {
    // Couleurs ANSI dans l'ancienne console Windows (Windows Terminal les gère déjà) : crossterm ouvre CONOUT$ et y
    // active ENABLE_VIRTUAL_TERMINAL_PROCESSING, le même appel que faisait une crate à part pour cela seul.
    #[cfg(windows)]
    let _ = crossterm::ansi_support::supports_ansi();
    // Le processus élevé ne fait que sa liste : rien d'autre ne doit tourner avec le jeton administrateur (journal,
    // passage, reconnaissance de la clé écrivent dans des dossiers que le compte contrôle).
    #[cfg(windows)]
    if std::env::args_os().nth(1).is_some_and(|a| a == "appliquer-eleve") {
        let code = match Args::from_arg_matches(&ligne_de_commande().get_matches()) {
            Ok(Args {
                commande: Some(Commande::AppliquerEleve { canal, parent }),
            }) => machine::windows::eleve::executer(&canal, parent),
            _ => 2,
        };
        std::process::exit(code);
    }
    // Les réglages du lancement (langue, emojis, travail sans Internet), avant tout affichage.
    parametres::au_lancement();
    journal::installer();
    #[cfg(unix)]
    protection::cle::proteger_cle();
    protection::environnement::afficher();
    avertir_si_root();
    passage::au_lancement();
    // Après le passage, qui a pu déplacer l'ancien dossier avec ses droits d'avant.
    #[cfg(unix)]
    crate::socle::proteger_dossier_local();
    protection::cles_connues::reconnaitre_la_cle_du_programme();
    let args = Args::from_arg_matches(&ligne_de_commande().get_matches()).unwrap_or_else(|e| e.exit());
    match args.commande {
        None => menu().await,
        Some(Commande::Complet { html, texte }) => {
            let mut s = Session::default();
            s.complet().await;
            if html {
                rapport::ouvrir(s.audit.as_ref(), s.reseau.as_ref(), s.audit_reseau.as_ref());
            }
            if texte {
                println!(
                    "\n{}",
                    rapport::markdown(s.audit.as_ref(), s.reseau.as_ref(), s.audit_reseau.as_ref())
                );
            }
        }
        Some(Commande::Machine { json }) => {
            machine::executer(json);
        }
        Some(Commande::Corriger) => Session::default().corriger(),
        Some(Commande::Reseau {
            cible,
            ports,
            timeout,
            parallele,
            json,
        }) => {
            let o = Options {
                cible,
                ports,
                timeout,
                parallele,
                json,
                silencieux: false,
            };
            if let Err(e) = reseau::executer(o).await {
                journal::erreur("scan réseau", &e);
                eprintln!("{}", trf!("Erreur : {e}", "Error: {e}"));
                std::process::exit(1);
            }
        }
        Some(Commande::AuditReseau { json, html, invite }) => {
            Session::default().audit_reseau(json, html, invite).await;
        }
        Some(Commande::Antivirus { complet, dossier }) => protection::antivirus::analyser(portee(dossier, complet)),
        Some(Commande::Surveillance { etat }) => reseau::surveillance::activer(etat == "on"),
        Some(Commande::Tableau { sans_ouvrir }) => reseau::tableau::ouvrir(sans_ouvrir),
        Some(Commande::Veilleur {
            etat,
            sous_etat,
            servir,
        }) => veilleur(etat.as_deref(), sous_etat.as_deref(), servir),
        Some(Commande::SitesDangereux { etat }) => protection::sites_bloques::commande(etat.as_deref()),
        Some(Commande::DernieresFailles { jours }) => protection::kev::ecran(jours),
        Some(Commande::Surveiller) => reseau::surveillance::surveiller().await,
        Some(Commande::Entretien { etat }) => match etat {
            Some(e) => entretien::activer(e == "on"),
            None => entretien::maintenant(),
        },
        Some(Commande::Entretenir) => entretien::entretenir(),
        Some(Commande::AppliquerEleve { canal, parent }) => {
            #[cfg(windows)]
            std::process::exit(machine::windows::eleve::executer(&canal, parent));
            #[cfg(not(windows))]
            {
                let _ = (canal, parent);
                trp!("Sous Windows seulement.", "Windows only.");
            }
        }
        Some(Commande::Maj) => maj::executer(),
        Some(Commande::Reparer) => reparer::menu(),
        Some(Commande::Gaming) => gaming::menu(),
        Some(Commande::Nettoyer { liste }) => {
            if liste {
                nettoyer::liste();
            } else {
                nettoyer::menu();
            }
        }
        Some(Commande::Connexion) => reseau::connexion::tester().await,
        Some(Commande::Diagnostic) => diagnostic::diagnostic(),
        Some(Commande::Logiciels { liste, recommandes }) => {
            if liste {
                logiciels::liste();
            } else if recommandes {
                logiciels::recommandes();
            } else {
                logiciels::menu();
            }
        }
        Some(Commande::MotDePasse) => protection::fuites::verifier(),
        Some(Commande::Navigateurs) => machine::mots_de_passe::navigateurs(),
        Some(Commande::Courriel) => protection::fuites::verifier_courriel(),
        // Un seul écran, sans la boucle du menu (clé abuse.ch, « Après une infection ») : une commande se lit d'un
        // script. Le menu, lui, lance `sortantes::menu`, qui montre le même écran puis propose la suite.
        Some(Commande::Sortantes) => protection::sortantes::afficher(),
        Some(Commande::Distance) => protection::distance::menu(),
        Some(Commande::VerifierMoi { programme }) => protection::manifeste::verifier_moi(programme.as_deref()),
        Some(Commande::Manifeste {
            ecrire,
            accepter,
            images,
            image,
        }) => {
            protection::manifeste::commande(ecrire.as_deref(), accepter, images.as_deref().map(|d| (d, &image[..])));
        }
        Some(Commande::Lien { adresse }) => protection::lien::verifier(Some(&adresse)),
        Some(Commande::VerifierFichier { fichier, empreinte }) => {
            protection::telechargement::verifier(Some(&fichier), empreinte.as_deref());
        }
        Some(Commande::CourrielSuspect { fichier, json: false }) => {
            protection::courriel_suspect::verifier(Some(&fichier));
        }
        Some(Commande::CourrielSuspect { fichier, json: true }) => protection::courriel_suspect::json(&fichier),
        Some(Commande::LogicielsEspions { json: false }) => protection::espions::afficher(),
        Some(Commande::LogicielsEspions { json: true }) => protection::espions::json(),
        Some(Commande::LogicielsPerimes { json: false }) => protection::perimes::afficher(),
        Some(Commande::LogicielsPerimes { json: true }) => protection::perimes::json(),
        Some(Commande::Signaler {
            incident,
            outil,
            programme,
            langue,
            json,
            effacer,
        }) => signaler::commande(&signaler::Options {
            incident,
            outil,
            programme,
            langue,
            json,
            effacer,
        }),
        Some(Commande::CameraMicro) => protection::camera::afficher_tout(),
        Some(Commande::Acces) => protection::acces::afficher_tout(),
        Some(Commande::Quarantaine) => protection::quarantaine::menu(),
        Some(Commande::Secrets) => protection::secrets_git::analyser(),
        Some(Commande::Conteneurs) => protection::conteneurs::analyser(),
        Some(Commande::Blocage { quoi }) => protection::blocage::commande(&quoi),
        Some(Commande::Parametres { quoi }) => parametres::commande(&quoi),
        Some(Commande::Isoler { fichier }) => protection::isoler::isoler(&fichier),
        Some(Commande::Pieges { retirer }) => protection::pieges::commande(retirer),
        Some(Commande::Durcir) => optimiser::protection(),
        // La portée vient des options ; le menu la demande (`yara::menu`), puis lance la même analyse.
        Some(Commande::Yara { complet, dossier }) => protection::yara::analyser(&portee(dossier, complet)),
        Some(Commande::Memoire) => protection::memoire::analyser(),
        Some(Commande::ListesNoires) => reseau::listes_noires::verifier(),
        Some(Commande::Canaux) => reseau::canaux::analyser(),
        Some(Commande::Nat) => reseau::nat::tester(),
        Some(Commande::Cameras) => reseau::cameras::chercher_cameras().await,
        Some(Commande::Objets) => reseau::objets::montrer(),
        Some(Commande::DnsRapide) => dns_rapide::mesurer_et_proposer(),
        Some(Commande::Optimiser { quoi }) => optimiser_en_ligne_de_commande(quoi.as_deref()).await,
        Some(Commande::WifiPublic { etat }) => reseau::wifi_public::commande(etat.as_deref()),
        Some(Commande::Appris) => apprentissage::menu(),
        Some(Commande::Integrite { accepter, temps_reel }) => {
            if temps_reel {
                protection::integrite::temps_reel();
            } else {
                protection::integrite::verifier(accepter);
            }
        }
        Some(Commande::Sauvegarder { fichier }) => donnees::sauvegarder(fichier),
        Some(Commande::Restaurer { fichier }) => donnees::restaurer(&fichier),
        Some(Commande::Nommer { appareil, surnom }) => nommer(&appareil, &surnom.join(" ")),
        Some(Commande::Guide { quoi }) => guide::executer(&quoi.join(" ")),
        Some(Commande::Lenteur) => lenteur::commande(),
        Some(Commande::Demarrage) => optimiser::programmes_au_demarrage(),
        Some(Commande::Fiche { json }) => fiche::fiche(json),
        Some(Commande::CopierFichiers { destination }) => copier::commande(destination.as_deref()),
        Some(Commande::VerifierCopie { dossier }) => copier::verifier_copie(dossier.as_deref()),
        Some(Commande::VerifierSauvegarde) => sauvegarde::verifier_sauvegarde(),
        Some(Commande::VerifierCle { dossier }) => verifier_cle::commande(dossier.as_deref()),
        Some(Commande::Changements) => changements::afficher(),
        Some(Commande::Evenements { json, incident }) => evenements::afficher(json, incident.as_deref()),
        Some(Commande::ALaisser) => a_laisser::laisser(&machine::executer(false)),
        Some(Commande::SauvegardeAuto { annuler }) => {
            if annuler {
                sauvegarde::annuler();
            } else {
                sauvegarde::menu();
            }
        }
        Some(Commande::Raccourci { etat }) => raccourci::commande(etat.map(|e| e == "on")),
        Some(Commande::Ordinateurs) => ordinateurs::menu(),
        Some(Commande::SeMettreAJour) => mise_a_jour::commande(),
        Some(Commande::Desinstaller { liste }) => desinstaller::commande(liste),
        Some(Commande::Regles) => machine::regles::afficher(),
        Some(Commande::Autotest {
            json,
            internet,
            detail,
            une_par_une,
        }) => {
            let code = autotest::executer(&autotest::Options {
                json,
                internet,
                detail,
                une_par_une,
            });
            // La sortie du processus arrête aussi une règle restée bloquée au-delà de son délai.
            std::process::exit(code);
        }
        Some(Commande::Depanner { sujet }) => depanner::executer(&sujet.join(" ")),
        Some(Commande::Proche) => depanner::executer("proche"),
        Some(Commande::Plugin { quoi }) => {
            let code = plugins::commande(&quoi);
            if code != 0 {
                std::process::exit(code);
            }
        }
        Some(Commande::Labo { quoi }) => {
            let code = plugins::labo::commande(&quoi);
            if code != 0 {
                std::process::exit(code);
            }
        }
        Some(Commande::Extensions { sans_restrictions }) => match sans_restrictions {
            None => plugins::extensions(),
            Some(etat) => {
                let code = plugins::regler_restrictions(etat == "on");
                if code != 0 {
                    std::process::exit(code);
                }
            }
        },
        Some(Commande::Traces { dossier }) => {
            if !traces::commande(dossier.as_deref()) {
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests_menu {
    use super::*;

    /// Le menu, `--help` et le lanceur reprennent l'accroche de la vitrine (la ligne en gras du README, sans
    /// « depuis une clé USB ») : changée d'un côté seulement, les deux se contredisaient sans que rien le voie.
    #[test]
    fn l_accroche_est_celle_de_la_vitrine() {
        let lire = |f: &str| std::fs::read_to_string(format!("{}/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let (menu, lanceur) = (lire("src/main.rs"), lire("src/raccourci.rs"));
        for (readme, fin) in [
            ("README.md", ", depuis une clé USB."),
            ("README.en.md", ", from a USB key."),
        ] {
            let texte = lire(readme);
            let accroche = texte
                .lines()
                .find_map(|l| l.trim().strip_prefix("<b>")?.split("</b>").next()?.strip_suffix(fin))
                .unwrap_or_else(|| panic!("accroche introuvable dans {readme}"));
            let citee = format!("\"{accroche}");
            // Dans main.rs : le menu et `--help`.
            assert!(
                menu.matches(&citee).count() >= 2,
                "{readme} : « {accroche} » manque dans main.rs"
            );
            assert!(
                lanceur.contains(&citee),
                "{readme} : « {accroche} » manque dans raccourci.rs"
            );
        }
    }

    #[test]
    fn chaque_commande_a_son_aide_en_anglais() {
        // Une commande oubliée gardait son aide française dans l'interface anglaise (« distance »).
        let traduites: Vec<&str> = AIDES_EN.iter().map(|(nom, _)| *nom).collect();
        let manquantes: Vec<String> = Args::command()
            .get_subcommands()
            // Les commandes cachées (surveillance, planificateur) n'apparaissent pas dans l'aide.
            .filter(|s| !s.is_hide_set())
            .map(|s| s.get_name().to_string())
            .filter(|nom| nom != "help" && !traduites.contains(&nom.as_str()))
            .collect();
        assert_eq!(manquantes, Vec::<String>::new());
    }

    #[test]
    fn chaque_option_a_son_aide_en_anglais() {
        let traduites: Vec<(&str, &str)> = OPTIONS_EN.iter().map(|(c, o, _)| (*c, *o)).collect();
        let mut manquantes = Vec::new();
        for s in Args::command().get_subcommands().filter(|s| !s.is_hide_set()) {
            for a in s.get_arguments().filter(|a| !a.is_hide_set() && a.get_help().is_some()) {
                let (c, o) = (s.get_name(), a.get_id().as_str());
                if !traduites.contains(&(c, o)) {
                    manquantes.push(format!("{c} {o}"));
                }
            }
        }
        assert_eq!(manquantes, Vec::<String>::new());
    }

    #[test]
    fn chaque_outil_a_sa_place() {
        // 1, 2, 3 au menu principal ; tout le reste dans un seul groupe.
        let principal = [Action::Complet, Action::Corriger, Action::Rapport];
        for (i, o) in OUTILS.iter().enumerate() {
            // La ligne d'un outil est à son numéro : `Action::outil` la trouve sans chercher.
            assert_eq!(o.action as usize, i);
            let groupes = GROUPES.iter().filter(|g| g.actions().contains(&o.action)).count();
            assert_eq!(groupes + usize::from(principal.contains(&o.action)), 1);
        }
        // Raccourcis uniques, et jamais un chiffre (les chiffres ouvrent les groupes).
        let mut lettres: Vec<&str> = OUTILS.iter().map(|o| o.lettre).filter(|l| !l.is_empty()).collect();
        assert!(
            lettres
                .iter()
                .all(|l| !l.starts_with(|c: char| c.is_ascii_digit()) && *l != "q")
        );
        let n = lettres.len();
        lettres.sort_unstable();
        lettres.dedup();
        assert_eq!(lettres.len(), n);
    }

    /// Les logiciels pas à jour : juste après les logiciels espions, avant le signalement à un éditeur (ajouté à la fin
    /// du groupe : aucune place annoncée ne bouge) ; montrée sous Windows et macOS seulement (sous Linux, le
    /// gestionnaire de paquets tient les versions).
    #[test]
    fn logiciels_perimes_en_fin_de_protection() {
        let protection = Groupe::Protection.actions();
        assert!(protection.ends_with(&[Action::LogicielsEspions, Action::LogicielsPerimes, Action::Signaler]));
        assert!(Action::Signaler.disponible());
        assert_eq!(
            Action::LogicielsPerimes.disponible(),
            cfg!(any(windows, target_os = "macos"))
        );
    }

    #[test]
    fn le_menu_principal_tient_dans_24_lignes() {
        // Trois lignes d'état au plus (dernier bilan, connexion ou avis, clé) : le menu le plus haut. Avec l'aide et
        // la saisie, il doit tenir dans un terminal de 24 lignes, sinon les flèches ne marchent plus.
        let s = |t: &str| t.to_string();
        for (connexion, avis) in [
            (None, None),
            (Some(s("c")), None),
            (None, Some(s("a"))),
            (Some(s("c")), Some(s("a"))),
        ] {
            assert!(lignes_d_etat(s("b"), connexion, s("k"), avis).len() <= 3);
        }
        assert_eq!(
            lignes_d_etat(s("b"), Some(s("c")), s("k"), Some(s("a"))),
            [s("b"), s("k"), s("a")]
        );
        let lignes = lignes_du_menu(vec![String::new(); 3]);
        let affichees = lignes.iter().filter(|l| !matches!(l, Ligne::Cachee { .. })).count();
        assert!(affichees + 2 <= 24, "{affichees} lignes affichées");
        // La recherche voit plus que l'écran : outils des sous-menus et pages du guide.
        assert!(lignes.len() > affichees + 50);
    }

    /// Le temps réel coupé, la ligne Surveillance dit la pause, dans la largeur d'une précision.
    #[test]
    fn surveillance_en_pause_au_menu() {
        assert_eq!(precision_surveillance(true, false), tr!("activée", "on"));
        let pause = precision_surveillance(true, true);
        assert!(
            pause.contains(tr!("pause", "paused")) && largeur_affichee(pause) <= 33,
            "{pause}"
        );
        assert_eq!(precision_surveillance(false, true), tr!("désactivée", "off"));
    }

    /// La protection en temps réel coupée se dit sur la ligne de la clé, à côté de la surveillance, sans jamais
    /// dépasser la largeur : la clé la plus longue lui laisse la place de la surveillance, puis sans son échéance.
    #[test]
    fn temps_reel_coupe_dans_l_en_tete() {
        let coupe = Some((
            "temps réel coupé → 22/10 01:30".to_string(),
            "temps réel coupé".to_string(),
        ));
        let courte = ligne_de_la_cle("clé non branchée", "surveillance active", coupe.clone());
        assert!(
            courte.contains("surveillance active") && courte.contains("→ 22/10"),
            "{courte}"
        );
        assert_eq!(
            ligne_de_la_cle("clé non branchée", "surveillance active", None),
            format!("  clé non branchée {GRIS}·{RESET} surveillance active")
        );
        for cle in [
            "clé VANGUARD branchée (protégée en écriture)",
            "clé VANGUARD inconnue, ignorée",
            &"x".repeat(60),
        ] {
            let l = ligne_de_la_cle(cle, "surveillance coupée", coupe.clone());
            assert!(l.contains("temps réel coupé"), "{l}");
            assert!(largeur_affichee(&l) <= LARGEUR || cle.len() == 60, "{l}");
        }
    }

    #[test]
    fn chaque_outil_trouve_par_la_recherche_s_ouvre() {
        for (i, g) in GROUPES.iter().enumerate() {
            if matches!(g, Groupe::Guide | Groupe::Depanner) {
                continue;
            }
            for (j, a) in g.actions().into_iter().filter(|a| a.disponible()).enumerate() {
                assert!(outil_au_chemin(&format!("{}.{}", i + 4, j + 1)) == Some(a));
            }
        }
        assert!(outil_au_chemin("4.99").is_none() && outil_au_chemin("x.1").is_none());
        assert!(outil_au_chemin("10.1").is_none(), "le guide a ses propres chemins");
        assert!(outil_au_chemin("11.1").is_none(), "le dépannage a ses propres chemins");
        assert!(outil_au_chemin("12.1") == Some(Action::Extensions));
        // La place annoncée au menu, dans l'aide et l'historique des versions.
        assert_eq!(touche_de(Action::MettreAJour).as_deref(), Some("9.9"));
        assert_eq!(touche_de(Action::Desinstaller).as_deref(), Some("9.11"));
        // Les places annoncées : 4.7, 4.8 et 9.2.
        assert!(outil_au_chemin("4.7") == Some(Action::Lenteur));
        assert!(outil_au_chemin("4.8") == Some(Action::Fiche));
        assert!(outil_au_chemin("9.2") == Some(Action::CopierFichiers));
        // Paramètres : au bout de Cette machine, et « s » au menu principal, sans ligne de plus.
        assert_eq!(touche_de(Action::Parametres).as_deref(), Some("4.12"));
        assert!(OUTILS.iter().any(|o| o.action == Action::Parametres && o.lettre == "s"));
        assert!(depanner::chemin("1").is_some());
    }

    /// Les outils du menu qui n'ont pas de sous-commande, et pourquoi.
    const MENU_SEULEMENT: &[(Action, &str)] = &[
        (Action::Rapport, "vanguard complet --html : le bilan puis son rapport"),
        (
            Action::ProtegerDonnees,
            "la phrase se tape et se confirme à l'écran, sur l'ordinateur du propriétaire",
        ),
    ];

    /// Les sous-commandes sans outil du menu, et pourquoi.
    const LIGNE_DE_COMMANDE_SEULEMENT: &[(&str, &str)] = &[
        (
            "restaurer",
            "le menu Données › Sauvegarder propose aussi la restauration",
        ),
        ("regles", "la liste des règles du bilan, pour un script ou un relecteur"),
        (
            "evenements",
            "le journal relié, pour un script ou les traces ; le tableau de bord en montre les alertes",
        ),
        ("demarrage", "dans le menu, l'écran de Pourquoi c'est lent ? le propose"),
        ("verifier-moi", "pour comparer l'empreinte à la page de la version"),
        ("plugin", "le menu Extensions les liste et les lance"),
        ("labo", "le menu Extensions les liste et les lance"),
        ("proche", "dans le menu, un parcours de Dépanner pas à pas"),
        (
            "traces",
            "dans le menu, un parcours de Dépanner pas à pas (après une infection)",
        ),
        (
            "autotest",
            "pour vérifier Vanguard lui-même ; le diagnostic dit le dernier, la surveillance le refait chaque semaine",
        ),
    ];

    /// Les sous-commandes visibles : (nom, alias visibles).
    fn sous_commandes() -> Vec<(String, Vec<String>)> {
        Args::command()
            .get_subcommands()
            .filter(|s| !s.is_hide_set() && s.get_name() != "help")
            .map(|s| {
                let alias = s.get_visible_aliases().map(str::to_string).collect();
                (s.get_name().to_string(), alias)
            })
            .collect()
    }

    fn lire(fichier: &str) -> String {
        std::fs::read_to_string(format!("{}/{fichier}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// Une seule table d'outils : chaque outil du menu nomme la sous-commande qui fait la même chose, ou dit pourquoi
    /// il n'en a pas ; chaque sous-commande a son outil, ou dit pourquoi. Un outil ajouté d'un côté seulement (les
    /// cinq d'Optimiser n'avaient aucune commande, aucun script ne pouvait tout annuler) arrête ce test.
    #[test]
    fn menu_et_ligne_de_commande_ont_les_memes_outils() {
        let commandes = sous_commandes();
        let existe = |nom: &str| commandes.iter().any(|(n, _)| n == nom);
        for o in OUTILS {
            let sans = MENU_SEULEMENT.iter().any(|(a, _)| *a == o.action);
            if o.commande.is_empty() {
                assert!(
                    sans,
                    "« {} » : ni sous-commande, ni raison dans MENU_SEULEMENT",
                    o.titre[0]
                );
            } else {
                assert!(
                    !sans,
                    "« {} » : une sous-commande et une raison de ne pas en avoir",
                    o.titre[0]
                );
                assert!(
                    existe(o.commande),
                    "« {} » : la sous-commande « {} » n'existe pas",
                    o.titre[0],
                    o.commande
                );
            }
        }
        for (nom, _) in &commandes {
            let dans_le_menu = OUTILS.iter().any(|o| o.commande == nom);
            let a_part = LIGNE_DE_COMMANDE_SEULEMENT.iter().any(|(n, _)| n == nom);
            assert!(
                dans_le_menu != a_part,
                "vanguard {nom} : {}",
                if a_part {
                    "dans le menu et dans LIGNE_DE_COMMANDE_SEULEMENT"
                } else {
                    "ni outil du menu, ni raison dans LIGNE_DE_COMMANDE_SEULEMENT"
                }
            );
        }
        for (nom, _) in LIGNE_DE_COMMANDE_SEULEMENT {
            assert!(existe(nom), "LIGNE_DE_COMMANDE_SEULEMENT : « {nom} » n'existe plus");
        }
    }

    /// Chaque sous-commande visible a son aide française : un commentaire décollé de sa commande donnait à
    /// `dernieres-failles` l'aide de trois commandes, et aucune au veilleur ni aux sites dangereux.
    #[test]
    fn chaque_commande_a_son_aide() {
        for s in Args::command()
            .get_subcommands()
            .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        {
            let aide = s.get_about().map(ToString::to_string).unwrap_or_default();
            assert!(!aide.trim().is_empty(), "vanguard {} : sans aide", s.get_name());
        }
        // Celle de « dernieres-failles » parle des failles, pas du veilleur ni des sites.
        let commande = Args::command();
        let failles = commande.find_subcommand("dernieres-failles").unwrap();
        let aide = failles.get_about().unwrap().to_string();
        assert!(aide.starts_with("Dernières failles exploitées"), "{aide}");
    }

    /// Le tableau des commandes du README (« | `vanguard nom …` | … ») a une ligne par sous-commande visible : le
    /// nom français dans README.md, l'alias anglais (ou le nom, s'il n'en a pas) dans README.en.md.
    #[test]
    fn le_readme_liste_chaque_commande() {
        let lignes_du_tableau = |texte: &str| -> Vec<String> {
            texte
                .lines()
                .filter_map(|l| l.strip_prefix("| `vanguard "))
                .filter_map(|l| l.split([' ', '`']).next().map(str::to_string))
                .collect()
        };
        let (fr, en) = (
            lignes_du_tableau(&lire("README.md")),
            lignes_du_tableau(&lire("README.en.md")),
        );
        let mut manquantes = Vec::new();
        for (nom, alias) in sous_commandes() {
            if !fr.contains(&nom) {
                manquantes.push(format!("README.md : {nom}"));
            }
            if !en.iter().any(|e| *e == nom || alias.contains(e)) {
                manquantes.push(format!("README.en.md : {nom} ({})", alias.join(", ")));
            }
        }
        // Les noms de l'autre langue, dans le paragraphe qui les liste : les alias anglais dans README.md, les noms
        // français dans README.en.md.
        let (readme, readme_en) = (lire("README.md"), lire("README.en.md"));
        for (nom, alias) in sous_commandes() {
            for a in &alias {
                if !readme.contains(&format!("`{a}`")) {
                    manquantes.push(format!("README.md, noms anglais : {a}"));
                }
            }
            // Un nom sans alias est le même dans les deux langues (antivirus, yara…) : rien à traduire.
            if !alias.is_empty() && !readme_en.contains(&format!("`{nom}`")) {
                manquantes.push(format!("README.en.md, noms français : {nom}"));
            }
        }
        assert_eq!(manquantes, Vec::<String>::new());
    }

    /// Le mode d'emploi de la clé (outils/LISEZMOI.txt, outils/README.txt) cite chaque outil du menu : par son titre
    /// tel que le menu l'affiche, ou par sa commande (« vanguard memoire »).
    #[test]
    fn le_mode_d_emploi_de_la_cle_cite_chaque_outil() {
        let (lisezmoi, readme) = (lire("outils/LISEZMOI.txt"), lire("outils/README.txt"));
        let commandes = sous_commandes();
        let mut manquants = Vec::new();
        for o in OUTILS {
            let alias = commandes
                .iter()
                .find(|(n, _)| n == o.commande)
                .map(|(_, a)| a.clone())
                .unwrap_or_default();
            let cite_fr = lisezmoi.contains(o.titre[0])
                || (!o.commande.is_empty() && lisezmoi.contains(&format!("vanguard {}", o.commande)));
            let cite_en = readme.contains(o.titre[1])
                || alias
                    .iter()
                    .chain(std::iter::once(&o.commande.to_string()))
                    .any(|c| !c.is_empty() && readme.contains(&format!("vanguard {c}")));
            if !cite_fr {
                manquants.push(format!("LISEZMOI.txt : {}", o.titre[0]));
            }
            if !cite_en {
                manquants.push(format!("README.txt : {}", o.titre[1]));
            }
        }
        assert_eq!(manquants, Vec::<String>::new());
    }

    /// Le tableau Structure de CONTRIBUTING.md et CONTRIBUTING.en.md nomme chaque fichier de src/ : par son chemin,
    /// son nom seul dans une ligne qui en groupe plusieurs (`dns.rs`, `wifi.rs`), ou un dossier qui le contient quand
    /// la ligne vaut pour tout ce dossier (`src/machine/linux/`). Un module ajouté sans sa ligne arrête ce test.
    #[test]
    fn le_tableau_structure_nomme_chaque_module() {
        let fichiers: Vec<String> = {
            let mut tous = Vec::new();
            let mut a_voir = vec![std::path::PathBuf::from(format!("{}/src", env!("CARGO_MANIFEST_DIR")))];
            while let Some(d) = a_voir.pop() {
                for e in std::fs::read_dir(&d).unwrap().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        a_voir.push(p);
                    } else if p.extension().is_some_and(|x| x == "rs") {
                        let relatif = p.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap();
                        tous.push(relatif.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
            tous.sort();
            tous
        };
        for (document, titre) in [("CONTRIBUTING.md", "## Structure"), ("CONTRIBUTING.en.md", "## Layout")] {
            let texte = lire(document);
            let debut = texte
                .find(titre)
                .unwrap_or_else(|| panic!("{document} : pas de « {titre} »"));
            let section = &texte[debut..];
            let section = &section[..section[titre.len()..]
                .find("\n## ")
                .map_or(section.len(), |f| f + titre.len())];
            // Ce qui est entre accents graves, coupé aux virgules et aux espaces (« `a.rs`, `b.rs` »).
            let cites: Vec<&str> = section
                .split('`')
                .skip(1)
                .step_by(2)
                .flat_map(|c| c.split([',', ' ', '(', ')']))
                .filter(|c| !c.is_empty())
                .collect();
            let mut manquants = Vec::new();
            for f in &fichiers {
                let (dossier, nom) = f.rsplit_once('/').unwrap();
                let dossier = format!("{dossier}/");
                // mod.rs et tests.rs vont avec leur dossier ; `src/` seul ne vaut pas pour tout le programme.
                let par_le_dossier = cites
                    .iter()
                    .any(|c| c.ends_with('/') && *c != "src/" && f.starts_with(*c));
                let par_le_nom = matches!(nom, "mod.rs" | "tests.rs")
                    && cites.iter().any(|c| c.starts_with(&dossier) || *c == f.as_str());
                if !(cites.contains(&f.as_str()) || cites.contains(&nom) || par_le_dossier || par_le_nom) {
                    manquants.push(f.clone());
                }
            }
            assert_eq!(manquants, Vec::<String>::new(), "{document}, tableau « {titre} »");
        }
    }
}
