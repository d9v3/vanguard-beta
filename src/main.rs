//! Vanguard — cyberdéfense portable des postes et des réseaux : bilan, correctifs, réglages.
//!
//! N'utilise le scan réseau que sur un réseau qui t'appartient ou que tu as le droit d'auditer.
//! Lancé sans argument, affiche un menu.

mod a_laisser;
// Le socle d'analyse des fichiers (lot AV1 de l'antivirus maison) : ses lecteurs servent aux motifs, aux signatures
// et aux heuristiques des lots suivants (AV2 à AV4), qui ne sont pas encore branchés.
#[cfg_attr(not(test), allow(dead_code))]
mod analyse;
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
mod deploiement;
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
mod journaux_windows;
mod langue;
mod lenteur;
mod logiciels;
mod machine;
mod maj;
mod masque;
mod mise_a_jour;
mod modele;
mod nettoyer;
mod optimiser;
mod ordinateurs;
mod parametres;
mod passage;
mod pe;
#[cfg(any(target_os = "macos", test))]
mod plist;
mod plugins;
mod prediction;
mod programmes_poses;
mod protection;
mod raccourci;
mod rapport;
mod recherche;
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
mod voulues;

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
    #[command(name = "bilan", visible_alias = "check")]
    Complet {
        /// Ouvrir aussi le rapport HTML dans le navigateur.
        #[arg(long)]
        html: bool,
        /// Afficher le rapport en texte simple (Markdown) dans le terminal : sans navigateur ni affichage graphique.
        #[arg(long, visible_alias = "text")]
        texte: bool,
    },
    /// Audit de cet ordinateur (pare-feu, ports, SSH, mises à jour, chiffrement…).
    #[command(name = "audit")]
    Machine {
        #[arg(long)]
        json: bool,
    },
    /// Audit de l'ordinateur puis application guidée des correctifs.
    #[command(visible_alias = "fix")]
    Corriger,
    /// Chercher un outil, une page du guide, un logiciel ou un réglage : les dix meilleurs résultats, avec leur place
    /// au menu et leur commande ; dans un terminal, un numéro ouvre le résultat. Synonymes (box, routeur) et fautes
    /// de frappe compris. Code de sortie 1 si rien n'est trouvé.
    #[command(visible_alias = "search")]
    Chercher {
        /// Les mots cherchés.
        #[arg(required = true)]
        mots: Vec<String>,
        /// Ouvrir tout de suite le meilleur résultat.
        #[arg(long, visible_alias = "first")]
        premier: bool,
        #[arg(long)]
        json: bool,
    },
    /// Rapport détaillé dans le navigateur : le bilan de cette session s'il y en a un, sinon un bilan complet d'abord.
    #[command(visible_alias = "report")]
    Rapport,
    /// Tout remettre comme avant : défait ce que Vanguard a changé (réglages d'Optimiser, corrections du bilan, jeux,
    /// blocages, mode Wi-Fi public), la valeur d'avant remise, après accord. Comme « optimiser annuler ».
    #[command(visible_alias = "undo")]
    Annuler,
    /// Protection : l'état de chaque interrupteur (temps réel, surveillance, entretien, blocage, veilleur, sites
    /// dangereux, Wi-Fi public, raccourci) ; « oui » ou « non » [--pendant 1h|4h] agit sur la protection en temps
    /// réel, comme « parametres temps-reel ».
    Protection {
        /// L'état des interrupteurs en JSON, pour un script : rien n'est changé.
        #[arg(long)]
        json: bool,
        /// oui ou non (on, off), puis --pendant 1h ou 4h pour une coupure qui se termine seule.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        quoi: Vec<String>,
    },
    /// Scan du réseau : appareils, ports ouverts, risques, nouveautés depuis les scans précédents.
    #[command(name = "appareils", visible_alias = "devices")]
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
        #[arg(value_parser = interrupteur, value_name = "on|off")]
        etat: String,
    },
    /// Tableau de bord de la surveillance dans le navigateur : son état, les alertes jour par jour, les nouveaux
    /// appareils et les connexions suspectes. Page locale, rien n'est envoyé.
    #[command(name = "tableau-de-bord", visible_alias = "dashboard")]
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
        #[arg(value_parser = interrupteur, value_name = "on|off")]
        etat: Option<String>,
    },
    /// Veilleur (Linux 6.6 et plus) : chaque programme lancé et chaque connexion fermée, vus sur le moment et jugés
    /// comme au bilan ; avec la protection active, il peut geler et arrêter un rançongiciel quasi certain. Coupé par
    /// défaut. Sans argument : son état, puis l'allumer ou le couper, après accord. « rancongiciel on|off » règle la
    /// veille anti-rançongiciel des dossiers personnels.
    #[command(visible_alias = "watcher")]
    Veilleur {
        #[arg(value_parser = interrupteur_veilleur, value_name = "on|off|rancongiciel")]
        etat: Option<String>,
        /// Pour « rancongiciel » : on ou off.
        #[arg(value_parser = interrupteur, value_name = "on|off")]
        sous_etat: Option<String>,
        /// Le service lui-même, lancé par systemd.
        #[arg(long, hide = true)]
        servir: bool,
    },
    /// Entretien du mois : une fois par mois, en silence, la note, les mises à jour en attente, la place à libérer et
    /// les problèmes nouveaux, en une notification ; rien n'est changé. Sans argument : ce qu'il dirait maintenant.
    #[command(visible_alias = "maintenance")]
    Entretien {
        #[arg(value_parser = interrupteur, value_name = "on|off")]
        etat: Option<String>,
    },
    /// Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord.
    #[command(name = "mises-a-jour", visible_alias = "updates")]
    Maj,
    /// Réparations courantes : réseau, navigation détournée, pare-feu, antivirus, fichiers système, disque, place, mises à jour, heure.
    #[command(visible_alias = "repair")]
    Reparer,
    /// Gaming : composants pour les jeux (Windows : Visual C++, DirectX… ; Linux : Steam, Vulkan, GameMode, Wine… ;
    /// macOS : Rosetta, Steam, Epic…) et réglages du système.
    #[command(name = "jeux", visible_alias = "gaming")]
    Gaming,
    /// Diagnostic de l'ordinateur : matériel, système et problèmes récents (plantages, erreurs). Lecture seule.
    #[command(name = "diagnostic", visible_alias = "diagnostics")]
    Diagnostic {
        /// Le résultat en JSON, pour un script : rien ne change.
        #[arg(long)]
        json: bool,
    },
    /// Logiciels : les meilleurs, libres pour la plupart (navigateurs, mots de passe, bureautique, vidéo, création,
    /// outils système…), par catégorie : choisir puis installer depuis la source officielle du système.
    #[command(name = "logiciels", visible_alias = "software")]
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
    #[command(name = "test-connexion", visible_alias = "connection-test")]
    Connexion {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
    /// L'adresse Internet publique est-elle sur une liste noire (Spamhaus, SpamCop, DroneBL, PSBL) ? Si oui, un
    /// appareil est sans doute infecté. Après accord : les listes voient l'adresse.
    #[command(name = "listes-noires", visible_alias = "blocklists")]
    ListesNoires {
        /// Le résultat en JSON, pour un script : sans --internet, rien n'est envoyé et l'adresse est dite non
        /// vérifiée.
        #[arg(long)]
        json: bool,
        /// Accord donné d'avance : les quatre listes voient l'adresse publique (pour --json, qui ne demande rien).
        #[arg(long)]
        internet: bool,
    },
    /// Wi-Fi encombré : les réseaux voisins par canal, et le canal le plus libre à régler sur le routeur. Lecture
    /// seule.
    #[command(name = "canaux-wifi", visible_alias = "wifi-channels")]
    Canaux,
    /// Type de NAT pour le jeu (ouvert, modéré ou strict), d'après deux serveurs publics (STUN). Lecture seule.
    Nat,
    /// Caméras cachées : sur le réseau d'une location ou de quelqu'un, les appareils qui ressemblent à des caméras.
    /// Lecture seule.
    #[command(name = "cameras-cachees", visible_alias = "hidden-cameras")]
    Cameras,
    /// Routeur et objets connectés d'après le dernier scan gardé : ce que le routeur annonce (modèle, logiciel), son
    /// administration en HTTP seul, les caméras, imprimantes, NAS… et leur mot de passe d'origine. Rien n'est sondé.
    #[command(name = "objets-connectes", visible_alias = "smart-devices")]
    Objets {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
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
        #[arg(value_parser = interrupteur_wifi_public, value_name = "on|off|portail")]
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
    /// dossiers. Chacun s'active après accord ; une protection, que Vanguard ne défait pas (Windows seulement).
    #[command(name = "defender")]
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
    #[command(name = "fuite-courriel", visible_alias = "email-leak")]
    Courriel,
    /// Vérifie si des mots de passe ont fuité (Have I Been Pwned) ; seuls 5 caractères de leur empreinte partent.
    #[command(name = "fuite-mot-de-passe", visible_alias = "password-leak")]
    MotDePasse,
    /// Mots de passe enregistrés dans les navigateurs : combien et comment protégés (comptés, jamais lus), où lancer
    /// la vérification intégrée du navigateur (faibles, réutilisés, compromis), et la vérification HIBP d'un mot tapé.
    #[command(name = "mots-de-passe-navigateurs", visible_alias = "browser-passwords")]
    Navigateurs,
    /// Qui parle à Internet ? Les connexions en cours de chaque programme, avec le nom du serveur. Lecture seule.
    #[command(name = "connexions-sortantes", visible_alias = "outbound-connections")]
    Sortantes {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
    /// Mon ordinateur est-il contrôlé ? Les logiciels de prise de contrôle à distance (AnyDesk, TeamViewer,
    /// RustDesk…) installés, lancés au démarrage, en cours ou téléchargés : l'outil des faux techniciens. Retrait
    /// après accord ; un programme en cours demande un second accord.
    #[command(name = "acces-a-distance", visible_alias = "remote-access")]
    Distance {
        /// Le résultat en JSON, pour un script : rien n'est retiré, aucune question.
        #[arg(long)]
        json: bool,
    },
    /// Ce lien est-il dangereux ? Examiné sans jamais l'ouvrir ; après accord, son âge et des listes publiques.
    #[command(visible_alias = "link")]
    Lien {
        /// Le lien reçu (entre guillemets s'il contient « & » ou « ? »).
        adresse: String,
        /// Le résultat en JSON, pour un script : sans --internet, l'examen sur l'ordinateur seulement (âge du domaine
        /// et listes publiques dits non vérifiés).
        #[arg(long)]
        json: bool,
        /// Accord donné d'avance : l'âge du domaine et les listes publiques sont demandés en ligne (pour --json).
        #[arg(long)]
        internet: bool,
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
    #[command(name = "bilan-confidentialite", visible_alias = "privacy-review")]
    Acces {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
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
    /// logiciels, autodiagnostic de la semaine, paquets de l'AUR). Sans argument : leur état ; avec un réglage et une
    /// valeur : le change, la valeur d'avant montrée pour revenir. « temps-reel non --pendant 1h|4h » coupe la protection en temps réel de Vanguard pour ce temps
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
    #[command(name = "exporter", visible_alias = "export")]
    Sauvegarder {
        /// Fichier à écrire (par défaut : vanguard-sauvegarde-AAAA-MM-JJ.json dans le dossier personnel ou Documents).
        fichier: Option<std::path::PathBuf>,
    },
    /// Ajoute une sauvegarde (ou un appareils.json) à la base actuelle, sans rien effacer.
    #[command(name = "importer", visible_alias = "import")]
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
        /// Un système (omarchy, arch, fedora, debian, windows, macos, tous ; linux : les programmes communs ; tldr ;
        /// vanguard), un programme (systemctl, winget, tar…), un chemin (6.7.2) ou des mots à chercher.
        quoi: Vec<String>,
        /// Pour un système : la liste de ses programmes et leur chemin, sans leurs commandes.
        #[arg(long, visible_alias = "summary")]
        sommaire: bool,
    },
    /// Pourquoi c'est lent ? Ce qui occupe le processeur, la mémoire et le disque, le démarrage, les programmes lancés
    /// à l'ouverture de session. Lecture seule.
    #[command(visible_alias = "slow")]
    Lenteur {
        /// Le résultat en JSON, pour un script : rien ne change.
        #[arg(long)]
        json: bool,
    },
    /// Programmes au démarrage : ceux qui se lancent à l'ouverture de session, à retirer ou à remettre après accord.
    /// Chaque retrait s'annule exactement (Optimiser › Tout remettre comme avant).
    #[command(visible_alias = "startup")]
    Demarrage,
    /// Fiche de l'ordinateur : modèle, carte mère, processeur, mémoire, carte graphique, disques, système. Les numéros
    /// de série s'affichent à l'écran seulement.
    #[command(name = "fiche-ordinateur", visible_alias = "specs")]
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
    #[command(name = "rapport-a-laisser", visible_alias = "handout")]
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
    /// Journaux de Windows : que s'est-il passé ? Les règles EVT- (traces effacées, service d'attaque, administrateur
    /// de plus, mot de passe deviné, Bureau à distance, PowerShell, Defender…) sur les journaux de cet ordinateur
    /// (Windows) ou d'un dossier de .evtx (tout système), puis les alertes dans l'ordre du temps. Lecture seule.
    #[command(name = "journaux-windows", visible_alias = "windows-logs")]
    JournauxWindows {
        /// Un dossier de journaux .evtx (winevt\Logs d'un disque monté, dossier de « depanner traces ») ; sans lui,
        /// ceux de ce Windows.
        #[arg(long, visible_alias = "folder")]
        dossier: Option<std::path::PathBuf>,
        /// Combien de jours en arrière (7 par défaut).
        #[arg(long, visible_alias = "days", default_value_t = 7, value_parser = clap::value_parser!(u32).range(1..=3650))]
        jours: u32,
        /// Le résultat en JSON, pour un script : rien n'est demandé.
        #[arg(long)]
        json: bool,
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
        #[arg(value_parser = interrupteur, value_name = "on|off")]
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
    /// Dépanner pas à pas : pas d'Internet, Wi-Fi qui coupe, ordinateur lent, pas de son, imprimante, disque plein ;
    /// après une infection, nouvel ordinateur, ordinateur qui part (vente, don), compte piraté, collecter les traces
    /// (« traces `[dossier]` » : processus, connexions, démarrage, comptes, journaux, fichiers récents et chronologie,
    /// dans un dossier daté ; lecture seule), ordinateur d'un proche.
    #[command(visible_alias = "troubleshoot")]
    Depanner {
        /// Le sujet : internet, wifi, lent, son, imprimante, disque, infection, nouveau, depart, compte, traces `[dossier]`,
        /// proche (ou des mots qui le décrivent).
        sujet: Vec<String>,
    },
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
        /// Avec --ecrire : réécrire la référence même si la clé a changé ailleurs que dans ce que le déploiement y
        /// pose (l'auteur a regardé l'écart ; outils/deployer.sh --accepter-cle).
        #[arg(long, requires = "ecrire")]
        forcer: bool,
        /// Accepter le carnet de la clé branchée tel qu'il est (copie restaurée, protection retirée ailleurs).
        #[arg(long)]
        accepter: bool,
        /// Redire à la référence les images et le menu de Ventoy de la clé montée ici, après leur mise à jour par
        /// outils/images-cle.sh (seulement les images nommées par --image, qu'il vient de copier et de vérifier).
        #[arg(long)]
        images: Option<std::path::PathBuf>,
        /// Une image copiée et vérifiée par outils/images-cle.sh (son nom dans ISO/, « NOM=SHA256 » avec l'empreinte
        /// relue sur la clé), avec --images.
        #[arg(long, requires = "images")]
        image: Vec<String>,
    },
    /// Étapes de outils/deployer.sh confiées au programme : archives tldr de la clé, vérification du programme
    /// Windows, témoins de la clé.
    #[command(hide = true)]
    Deploiement {
        #[command(subcommand)]
        etape: deploiement::Etape,
    },
    /// Plugins : des programmes à vous ajoutés à Vanguard sans changer son code (essais, outils expérimentaux), chacun
    /// dans un dossier avec un plugin.toml. « ajouter `<dossier>` » le copie et l'approuve (empreintes SHA-256),
    /// « approuver `<nom>` » après un changement, « liste », « retirer `<nom>` », ou « `<nom>` `[arguments]` » pour le
    /// lancer (« --rapport » : ses constats dans le rapport HTML) ; sans argument, la liste à choisir. Jamais en
    /// administrateur ; hors de la note.
    #[command(name = "plugins")]
    Plugin {
        /// ajouter `<dossier>`, approuver `<nom>`, liste, retirer `<nom>`, ou `<nom>` [--rapport] `[arguments]`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        quoi: Vec<String>,
    },
    /// Laboratoire : un script posé tel quel dans le dossier du labo (.sh, .bash, .ps1, .py ou un programme), pour
    /// essayer une idée hors du programme de Vanguard. Sans argument : la liste à choisir ; « ouvrir » : le dossier ;
    /// « `<fichier>` `[arguments]` » le lance (approuvé par son empreinte au premier lancement). Jamais en administrateur.
    #[command(visible_alias = "lab")]
    Labo {
        /// ouvrir, liste, ou `<fichier>` `[arguments]`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        quoi: Vec<String>,
    },
    /// Extensions : le menu des plugins et des scripts du labo, à choisir et lancer.
    #[command(name = "extensions")]
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
    /// Linux et macOS : l'assistant élevé qui fait les ordres du blocage (lancé par Vanguard lui-même, par pkexec, run0
    /// ou sudo ; voir machine/assistant.rs).
    AppliquerEleve {
        #[arg(long)]
        canal: Option<String>,
        #[arg(long)]
        parent: Option<u32>,
        #[arg(long)]
        langue: Option<String>,
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
            Some(m) => afficher_note(tr!("Cet ordinateur", "This computer"), m),
            None => trp!(
                "  Cet ordinateur : pas de note (vérifications impossibles)",
                "  This computer: no grade (checks could not be done)"
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

/// Vanguard lui-même en administrateur : root ou setuid (compte effectif ≠ compte réel), console administrateur
/// sous Windows. Un jeton illisible compte pour élevé : c'est un garde-fou, il échoue fermé.
fn processus_eleve() -> bool {
    #[cfg(unix)]
    {
        // SAFETY : geteuid et getuid ne prennent aucun argument, ne touchent aucune mémoire et ne peuvent pas échouer.
        let (effectif, reel) = unsafe { (libc::geteuid(), libc::getuid()) };
        (effectif == 0 && !root_d_un_espace_de_noms()) || effectif != reel
    }
    #[cfg(windows)]
    {
        machine::windows::processus::eleve_ou_inconnu()
    }
}

/// Root seulement dans un espace de noms d'utilisateurs (« unshare -r », conteneur sans droits) : le compte 0 y est
/// un compte ordinaire de l'ordinateur, sans aucun droit sur lui.
#[cfg(unix)]
fn root_d_un_espace_de_noms() -> bool {
    std::fs::read_to_string("/proc/self/uid_map").is_ok_and(|t| root_hors_de_l_espace(&t) == Some(false))
}

/// Le compte 0 de cet espace est-il le root de l'ordinateur ? D'après /proc/self/uid_map (« dedans dehors nombre »
/// par ligne) ; `None` si 0 n'y est pas.
#[cfg(any(unix, test))]
fn root_hors_de_l_espace(uid_map: &str) -> Option<bool> {
    uid_map.lines().find_map(|l| {
        let mut champs = l.split_whitespace().map(str::parse::<u64>);
        let (Some(Ok(dedans)), Some(Ok(dehors)), Some(Ok(nombre))) = (champs.next(), champs.next(), champs.next())
        else {
            return None;
        };
        (dedans == 0 && nombre > 0).then_some(dehors == 0)
    })
}

/// Vanguard élevé l'a-t-il été depuis un compte ordinaire, qui pourrait le relancer sans droits et ne demander les
/// droits qu'au moment voulu ? Windows : un jeton élevé séparé par l'UAC (type 2), ou illisible (échoue fermé) ; pas
/// sans UAC ni pour le compte Administrateur intégré, qui n'ont pas de jeton ordinaire. Ailleurs : venu de sudo, run0,
/// pkexec ou doas, ou d'une session ouverte par un autre compte (`venu_d_un_autre_compte`) ; pas « ssh root@ » ni un
/// conteneur où root est le seul compte.
fn droits_demandables() -> bool {
    #[cfg(unix)]
    {
        let variables = ["SUDO_UID", "PKEXEC_UID", "DOAS_USER"]
            .iter()
            .any(|v| std::env::var_os(v).is_some());
        let session = std::fs::read_to_string("/proc/self/loginuid")
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        venu_d_un_autre_compte(variables, session)
    }
    #[cfg(windows)]
    {
        machine::windows::processus::type_d_elevation() != Some(1)
    }
}

/// `variables` : SUDO_UID, PKEXEC_UID ou DOAS_USER présentes (run0 pose aussi SUDO_UID) ; `session` : le compte qui a
/// ouvert la session (/proc/self/loginuid, Linux ; 4294967295 : aucun).
#[cfg(any(unix, test))]
fn venu_d_un_autre_compte(variables: bool, session: Option<u32>) -> bool {
    variables || session.is_some_and(|u| u != 0 && u != u32::MAX)
}

/// Les outils d'Optimiser installent, effacent, changent des réglages ou lisent ce que le réseau leur envoie : rien
/// de cela n'a à tourner avec tous les droits dans le processus, chaque geste d'administrateur est demandé à part.
/// Refusés quand Vanguard est déjà élevé depuis un compte ordinaire (`droits_demandables`) ; là où ce compte n'existe
/// pas (root seul, Windows sans UAC), le refus ne protégerait rien : l'outil tourne, avec l'avertissement.
fn optimiser_refuse(eleve: bool, demandables: bool) -> bool {
    eleve && demandables
}

fn texte_refus_optimiser() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Vanguard tourne en administrateur : les outils d'Optimiser refusent de tourner avec tous les droits (ils installent, effacent, changent des réglages ou lisent ce que le réseau envoie). Relancez Vanguard normalement (double-clic, ou une console ordinaire) : chaque outil demandera l'autorisation de Windows au moment voulu.",
            "Vanguard is running as administrator: the Optimize tools refuse to run with full administrator rights (they install, delete, change settings or read what the network sends). Start Vanguard again normally (double-click, or an ordinary console): each tool will ask for Windows' permission when needed."
        )
    } else {
        tr!(
            "Vanguard tourne en root (sudo) : les outils d'Optimiser refusent de tourner avec tous les droits (ils installent, effacent, changent des réglages ou lisent ce que le réseau envoie). Relancez Vanguard sans sudo : chaque outil demandera le mot de passe au moment voulu.",
            "Vanguard is running as root (sudo): the Optimize tools refuse to run with full administrator rights (they install, delete, change settings or read what the network sends). Start Vanguard again without sudo: each tool will ask for the password when needed."
        )
    }
}

/// Un outil d'Optimiser demandé alors qu'il est refusé (`optimiser_refuse`) : le refus est dit, et l'outil ne part pas.
fn refuser_optimiser() -> bool {
    if !optimiser_refuse(processus_eleve(), droits_demandables()) {
        return false;
    }
    avertir(texte_refus_optimiser());
    true
}

/// Une sous-commande d'un outil d'Optimiser (`optimiser_refuse`) ; « optimiser annuler » n'en est pas une : c'est
/// « Tout remettre comme avant », qui doit marcher en urgence. Le test `commandes_d_optimiser` la compare à la table.
fn commande_d_optimiser(c: &Commande) -> bool {
    match c {
        Commande::Optimiser { quoi } => !matches!(quoi.as_deref(), Some("annuler" | "undo")),
        Commande::Logiciels { .. }
        | Commande::Nettoyer { .. }
        | Commande::Lenteur { .. }
        | Commande::Demarrage
        | Commande::Gaming
        | Commande::DnsRapide
        | Commande::Connexion { .. }
        | Commande::Nat
        | Commande::Canaux => true,
        _ => false,
    }
}

/// Un avertissement, enveloppé, sur la sortie d'erreur.
fn avertir(texte: &str) {
    for (i, ligne) in envelopper(texte, LARGEUR - 4).into_iter().enumerate() {
        if i == 0 {
            eprintln!("  {}⚠{RESET} {ligne}", couleur(risk::Niveau::Moyen));
        } else {
            eprintln!("    {ligne}");
        }
    }
}

/// Lancé en administrateur : Vanguard n'en a pas besoin (chaque correction demande les droits au moment voulu, par
/// pkexec, run0 ou sudo dans le terminal, ou l'UAC), et une sortie piégée aurait ici tous les droits. Dit, jamais
/// imposé ; seuls les outils d'Optimiser refusent, et seulement là où un compte ordinaire existe (`optimiser_refuse`).
fn avertir_si_eleve() {
    if !processus_eleve() {
        return;
    }
    avertir(match (cfg!(windows), droits_demandables()) {
        (true, true) => tr!(
            "Vanguard tourne en administrateur : il n'en a pas besoin, chaque correction demande l'autorisation de Windows au moment voulu. Les outils d'Optimiser refuseront : relancez-le normalement pour eux.",
            "Vanguard is running as administrator: it does not need it, each fix asks for Windows' permission when needed. The Optimize tools will refuse: start it again normally for them."
        ),
        (true, false) => tr!(
            "Vanguard tourne en administrateur sans contrôle de compte (UAC coupé, ou compte Administrateur intégré) : il continue ainsi, mais une sortie piégée aurait ici tous les droits. Mieux vaut un compte ordinaire, avec l'UAC.",
            "Vanguard is running as administrator without account control (UAC off, or the built-in Administrator account): it carries on this way, but a booby-trapped output would have full administrator rights here. An ordinary account, with UAC, is better."
        ),
        (false, true) => tr!(
            "Vanguard tourne en root (sudo) : il n'en a pas besoin, chaque correction demande le mot de passe au moment voulu (même sans session graphique), et une sortie piégée aurait ici tous les droits. Relancez-le sans sudo ; les outils d'Optimiser refuseront sinon.",
            "Vanguard is running as root (sudo): it does not need it, each fix asks for the password when needed (even without a graphical session), and a booby-trapped output would have full administrator rights here. Start it again without sudo; otherwise the Optimize tools will refuse."
        ),
        (false, false) => tr!(
            "Vanguard tourne en root, ouvert directement par ce compte (pas depuis un compte ordinaire) : il continue ainsi, mais une sortie piégée aurait ici tous les droits.",
            "Vanguard is running as root, opened directly by that account (not from an ordinary account): it carries on this way, but a booby-trapped output would have full administrator rights here."
        ),
    });
}

/// État affiché en tête du menu : dernier bilan, dernier test de connexion, clé, surveillance, et un avis s'il y en
/// a un (copie périmée, nouvelle version sur la clé).
fn etat_du_menu(surveillance_active: bool, nouveau_menu: bool) -> Vec<String> {
    let historique = historique::charger();
    let bilan = match historique.last() {
        Some(b) => {
            let note = |s: Option<u32>| s.map_or_else(|| "—".to_string(), etiquette_note);
            trf!(
                "  {GRIS}Dernier bilan{RESET}  {}   ordinateur {}   réseau {}",
                "  {GRIS}Last check{RESET}     {}   computer {}   network {}",
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
        })
        .or_else(|| {
            nouveau_menu.then(|| {
                // Posée quand l'avis paraît, pas avant : caché par un autre avis, il revient à la session suivante.
                avis_du_nouveau_menu_vu();
                trf!(
                    "  {ACCENT}›{RESET} Le menu a été réorganisé : tapez un mot pour retrouver un outil.",
                    "  {ACCENT}›{RESET} The menu has been reorganized: type a word to find a tool."
                )
            })
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

/// La place d'un outil au menu (« 13.3 » : groupe 13, 3e outil proposé ici), comme la recherche la tape.
fn touche_de(action: Action) -> Option<String> {
    places()
        .into_iter()
        .find(|(_, a)| *a == action)
        .map(|(chemin, _)| chemin)
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

    // Trois intertitres, sans ligne vide : cadre (3), état (3 au plus), intertitres (3) et 13 lignes font 22 rangées,
    // et l'aide et la saisie 24, la hauteur d'un petit terminal où les flèches marchent encore.
    lignes.push(Ligne::Texte(ligne_section(tr!("BILAN DE SÉCURITÉ", "SECURITY CHECK"))));
    for (touche, action) in [Action::Complet, Action::Corriger, Action::Rapport]
        .into_iter()
        .enumerate()
    {
        let (texte, precision) = action.libelle();
        let commande = action.outil().commande;
        let anciens = ANCIENS_NOMS
            .iter()
            .find(|(n, _)| *n == commande)
            .map_or("", |(_, a)| *a);
        lignes.push(
            Ligne::choix(&(touche + 1).to_string(), texte, precision).avec_mots(&format!("{commande} {anciens}")),
        );
    }
    for (i, groupe) in GROUPES.iter().enumerate() {
        if i == 0 {
            lignes.push(Ligne::Texte(ligne_section(tr!("CYBERDÉFENSE", "CYBER DEFENSE"))));
        } else if *groupe == PREMIER_EN_PLUS {
            lignes.push(Ligne::Texte(ligne_section(tr!("EN PLUS", "ALSO INCLUDED"))));
        }
        lignes.push(Ligne::choix(
            &(i + 4).to_string(),
            &format!("{} {ACCENT}›{RESET}", groupe.titre()),
            groupe.resume(),
        ));
    }

    // Ce que la recherche trouve en plus, sans l'afficher : chaque place des sous-menus (« 5.2 », « 6.1.3 », aussi
    // tapable telle quelle), chaque parcours de dépannage et chaque page du guide. Les pages du guide en dernier : la
    // recherche garde cet ordre, et un outil ou un parcours répond mieux à « son » qu'une commande à taper.
    let cle_de = |voulu: Groupe| {
        GROUPES
            .iter()
            .position(|g| *g == voulu)
            .map_or(0, |i| i + 4)
            .to_string()
    };
    lignes.extend(depanner::lignes_de_recherche(&cle_de(Groupe::Depanner)));
    for (chemin, a) in places() {
        let mut niveaux = chemin.split('.');
        let groupe = niveaux
            .next()
            .and_then(|g| g.parse::<usize>().ok())
            .and_then(|g| GROUPES.get(g - 4));
        let mut ou = groupe.map_or_else(String::new, |g| format!("{} ›", g.titre()));
        // Une variante : l'écran à choix d'où elle vient, après le groupe.
        if let Some(parent) = ECRANS.iter().find(|(_, v)| v.contains(&a)).map(|(e, _)| *e) {
            ou = format!("{ou} {} ›", parent.libelle().0);
        }
        let (texte, precision) = a.libelle();
        // Le nom de sa sous-commande aussi, et ses anciens noms : qui connaît « vanguard connexions-sortantes » ou
        // « harden » la retrouve au menu.
        let commande = a.outil().commande;
        // Les raccourcis 8.3 à 8.5 mènent à « depanner » : ses anciens noms (« proche », « traces ») restent au groupe 11.
        let raccourci = matches!(a, Action::DepannerInfection | Action::DepannerCompte | Action::Traces);
        let anciens = ANCIENS_NOMS
            .iter()
            .find(|(n, _)| *n == commande && !raccourci)
            .map_or("", |(_, a)| *a);
        let mots = format!("{} {commande} {anciens}", a.outil().mots);
        lignes.push(Ligne::cachee(&chemin, &ou, texte, precision).avec_mots(&mots));
    }
    // Ce qu'il y a dans les outils : les logiciels du catalogue, les réglages des Paramètres.
    if let Some(cle) = touche_de(Action::Logiciels) {
        lignes.extend(logiciels::lignes_de_recherche(&cle));
    }
    if let Some(cle) = touche_de(Action::Parametres) {
        lignes.extend(parametres::lignes_de_recherche(&cle));
    }
    lignes.extend(guide::lignes_de_recherche(&cle_de(Groupe::Guide)));
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

/// Un outil désigné par son chemin, tapé ou trouvé par la recherche : « 5.2 », « 6.1.3 », « 11.13 ».
fn outil_au_chemin(chemin: &str) -> Option<Action> {
    places().into_iter().find(|(c, _)| c == chemin).map(|(_, a)| a)
}

/// L'autotest lancé du menu, dans un Vanguard à part : il pose pour tout son processus la lecture seule et le travail
/// sans Internet, et n'arrête une règle bloquée qu'en sortant. Lancé ici, la suite de la session n'écrirait plus rien
/// (corrections non notées, donc impossibles à défaire) et se croirait hors ligne.
fn autotest_a_part() {
    let lance = std::env::current_exe().and_then(|exe| std::process::Command::new(exe).arg("autotest").status());
    if let Err(e) = lance {
        trp!(
            "  ✖ Autotest impossible à lancer : {e}. En ligne de commande : vanguard autotest.",
            "  ✖ Could not start the self-test: {e}. From the command line: vanguard self-test."
        );
    }
}

/// Où mène une touche du menu principal, tapée ou trouvée par la recherche.
#[derive(Debug, PartialEq)]
enum Destination {
    /// Une page ou une commande du guide (« 10.3.1.2 »).
    Guide(usize, Option<usize>, Option<usize>),
    /// Un parcours de dépannage (« 11.4 »).
    Parcours(usize),
    /// Un outil par son chemin (« 5.2 », « 6.1.3 », « 11.13 »).
    Chemin(Action),
    /// Un logiciel du catalogue : sa catégorie (« 12.1.5 »).
    Logiciel(usize),
    /// Un groupe (« 5 »).
    Groupe(Groupe),
    /// 1 à 3, ou une lettre d'avant la 0.43.
    Outil(Action),
}

/// La destination d'une touche : 1 à 3, un groupe, un chemin, une page du guide, un parcours, un logiciel, une
/// lettre d'avant la 0.43. Un seul aiguillage pour le menu et `vanguard chercher` ; `None` : rien n'y répond.
fn destination(choix: &str) -> Option<Destination> {
    let cle_de = |voulu: Groupe| GROUPES.iter().position(|g| *g == voulu).map(|i| (i + 4).to_string());
    if let Some((groupe, reste)) = choix.split_once('.') {
        if cle_de(Groupe::Guide).as_deref() == Some(groupe) {
            return guide::chemin(reste).map(|(s, p, c)| Destination::Guide(s, p, c));
        }
        if cle_de(Groupe::Depanner).as_deref() == Some(groupe)
            && let Some(n) = depanner::chemin(reste)
        {
            return Some(Destination::Parcours(n));
        }
        if let Some(action) = outil_au_chemin(choix) {
            return Some(Destination::Chemin(action));
        }
        return touche_de(Action::Logiciels)
            .and_then(|l| choix.strip_prefix(&format!("{l}.")).map(str::to_string))
            .and_then(|n| n.parse::<usize>().ok())
            .map(Destination::Logiciel);
    }
    if let Some(g) = choix
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(4))
        .and_then(|i| GROUPES.get(i))
    {
        return Some(Destination::Groupe(*g));
    }
    match choix {
        "1" => Some(Destination::Outil(Action::Complet)),
        "2" => Some(Destination::Outil(Action::Corriger)),
        "3" => Some(Destination::Outil(Action::Rapport)),
        // Raccourcis des versions précédentes (une lettre par outil), toujours acceptés.
        autre => OUTILS
            .iter()
            .find(|o| !o.lettre.is_empty() && o.lettre == autre)
            .map(|o| Destination::Outil(o.action)),
    }
}

/// Ouvre ce que désigne une touche du menu principal (`destination`). `false` : rien n'y répond.
async fn ouvrir_touche(s: &mut Session, choix: &str) -> bool {
    match destination(choix) {
        None => return false,
        Some(Destination::Guide(systeme, programme, commande)) => guide::ouvrir(systeme, programme, commande),
        Some(Destination::Parcours(n)) => depanner::ouvrir(n),
        Some(Destination::Chemin(action)) => {
            lancer(s, action, &chemin_de(choix)).await;
            revenir_au_menu(action);
        }
        Some(Destination::Logiciel(place)) => {
            if refuser_optimiser() {
                revenir_au_menu(Action::Logiciels);
            } else {
                logiciels::ouvrir_sur(place);
            }
        }
        Some(Destination::Groupe(g)) => sous_menu(s, g).await,
        Some(Destination::Outil(action)) => {
            executer(s, action).await;
            revenir_au_menu(action);
        }
    }
    true
}

/// `vanguard chercher` : les dix meilleurs résultats de la recherche du menu, avec leur place et leur commande ; un
/// numéro (dans un terminal) ou `--premier` ouvre le résultat par le même aiguillage que le menu. `false` : rien trouvé.
async fn chercher(requete: &str, premier: bool, json: bool) -> bool {
    use std::io::IsTerminal;
    let lignes = lignes_du_menu(Vec::new());
    let (trouves, corrections, partiels) = selection::chercher(&lignes, requete);
    let trouves: Vec<_> = trouves.into_iter().take(10).collect();
    let commande_de = |touche: &str| {
        outil_au_chemin(touche)
            .map(|a| a.outil().commande)
            .filter(|c| !c.is_empty())
            .map(|c| format!("vanguard {c}"))
            .unwrap_or_default()
    };
    if json {
        let liste: Vec<serde_json::Value> = trouves
            .iter()
            .map(|t| {
                serde_json::json!({
                    "touche": t.touche, "texte": t.texte, "precision": t.precision, "commande": commande_de(&t.touche)
                })
            })
            .collect();
        let corrections: Vec<_> = corrections
            .iter()
            .map(|(a, b)| serde_json::json!({"tape": a, "corrige": b}))
            .collect();
        println!(
            "{}",
            serde_json::json!({"resultats": liste, "partiels": partiels, "corrections": corrections})
        );
        return !trouves.is_empty();
    }
    if trouves.is_empty() {
        trp!(
            "  Aucun résultat pour « {} ». Essayez : disque, wifi, dns, mise à jour.",
            "  No result for “{}”. Try: disk, wifi, dns, update.",
            affichable(requete)
        );
        return false;
    }
    if premier && let Some(trouve) = trouves.first() {
        let touche = trouve.touche.clone();
        let mut s = Session::default();
        return ouvrir_touche(&mut s, &touche).await;
    }
    for (a, b) in &corrections {
        trp!(
            "  {GRIS}Résultats pour « {b} » (tapé : « {a} »).{RESET}",
            "  {GRIS}Results for “{b}” (typed: “{a}”).{RESET}"
        );
    }
    if partiels {
        trp!(
            "  {GRIS}Aucun résultat n'a tous les mots : résultats partiels.{RESET}",
            "  {GRIS}No result has every word: partial results.{RESET}"
        );
    }
    let largeur = trouves.iter().map(|t| largeur_affichee(&t.touche)).max().unwrap_or(0);
    for (i, t) in trouves.iter().enumerate() {
        let commande = commande_de(&t.touche);
        let tete = format!("  {:>2}  {:<largeur$}  ", i + 1, t.touche);
        let reste = LARGEUR.saturating_sub(largeur_affichee(&tete));
        println!("{tete}{}", couper(&t.texte, reste));
        let detail: Vec<&str> = [t.precision.as_str(), commande.as_str()]
            .into_iter()
            .filter(|x| !x.is_empty())
            .collect();
        if !detail.is_empty() {
            println!(
                "{}{GRIS}{}{RESET}",
                " ".repeat(largeur_affichee(&tete)),
                couper(&detail.join(" · "), reste)
            );
        }
    }
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return true;
    }
    let reponse = demander(tr!(
        "\n  Numéro à ouvrir (Entrée : rien) : ",
        "\n  Number to open (Enter: nothing): "
    ));
    if let Some(t) = reponse
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| trouves.get(i))
    {
        let mut s = Session::default();
        ouvrir_touche(&mut s, &t.touche).await;
    }
    true
}

/// La touche du guide au menu principal (« 10 »).
fn cle_du_guide() -> String {
    GROUPES
        .iter()
        .position(|g| *g == Groupe::Guide)
        .map_or(0, |i| i + 4)
        .to_string()
}

/// Les commandes qui ne changent rien sur l'ordinateur (elles lisent, montrent, cherchent ; au plus une page ou un
/// rapport dans le dossier de Vanguard) : le guide (10.10) les dit « ✔ ne fait que lire ». Toute autre est marquée ⚠,
/// même si chaque changement demande un accord.
const COMMANDES_EN_LECTURE: &[&str] = &[
    "bilan",
    "rapport",
    "chercher",
    "audit",
    "dernieres-failles",
    "fiche-ordinateur",
    "secrets",
    "conteneurs",
    "logiciels-perimes",
    "appareils",
    "audit-reseau",
    "objets-connectes",
    "cameras-cachees",
    "listes-noires",
    "tableau-de-bord",
    "logiciels-espions",
    "connexions-sortantes",
    "memoire",
    "verifier-fichier",
    "lien",
    "courriel-suspect",
    "fuite-mot-de-passe",
    "mots-de-passe-navigateurs",
    "fuite-courriel",
    "camera-micro",
    "bilan-confidentialite",
    "evenements",
    "journaux-windows",
    "changements",
    "verifier-sauvegarde",
    "verifier-copie",
    "guide",
    "diagnostic",
    "lenteur",
    "test-connexion",
    "nat",
    "canaux-wifi",
    "verifier-moi",
    "autotest",
    "regles",
    "ordinateurs",
];

/// L'essentiel d'une aide de commande pour le guide, qui tient en deux lignes : ce qui précède son premier « : »,
/// « ; » ou point (« Rapport détaillé dans le navigateur : le bilan… » → « Rapport détaillé dans le navigateur »).
fn essentiel(aide: &str) -> String {
    aide.split([':', ';', '.']).next().unwrap_or(aide).trim().to_string()
}

/// Une explication du guide en deux lignes au plus (la règle de ses pages), sa place au menu gardée : des mots
/// retirés à la fin, remplacés par « … », quand il le faut.
fn en_deux_lignes(texte: &str, place: &str) -> String {
    let tient = |t: &str| envelopper(t, LARGEUR - 6).len() <= 2;
    let mut mots: Vec<&str> = texte.split_whitespace().collect();
    let entier = format!("{texte}{place}");
    if tient(&entier) {
        return entier;
    }
    while mots.len() > 1 {
        mots.pop();
        let court = format!("{}…{place}", mots.join(" "));
        if tient(&court) {
            return court;
        }
    }
    entier
}

/// La place au menu d'une commande : 1 à 3, le chemin de son outil (les raccourcis 8.3 à 8.5 laissés de côté pour
/// « depanner »), ou la touche d'un groupe ouvert directement (« 10 », « 11 »).
fn place_de_commande(nom: &str) -> Option<String> {
    let principal = [Action::Complet, Action::Corriger, Action::Rapport];
    let raccourcis = [Action::DepannerInfection, Action::DepannerCompte, Action::Traces];
    let outil = OUTILS
        .iter()
        .find(|o| o.commande == nom && !raccourcis.contains(&o.action))?;
    if let Some(i) = principal.iter().position(|a| *a == outil.action) {
        return Some((i + 1).to_string());
    }
    if let Some(g) = outil.groupe.filter(|g| g.direct())
        && g.actions().first() == Some(&outil.action)
    {
        return GROUPES.iter().position(|x| *x == g).map(|i| (i + 4).to_string());
    }
    touche_de(outil.action)
}

/// Les commandes de Vanguard pour le guide (10.10) : un programme par rubrique de `--help`, une commande par ligne,
/// avec son aide et sa place au menu. Construites une fois, depuis le menu et clap.
fn programmes_vanguard() -> &'static [guide::Programme] {
    static PROGRAMMES: std::sync::OnceLock<Vec<guide::Programme>> = std::sync::OnceLock::new();
    PROGRAMMES.get_or_init(|| {
        let garder = |t: String| -> &'static str { Box::leak(t.into_boxed_str()) };
        let clap = Args::command();
        rubriques_des_commandes()
            .into_iter()
            .map(|(groupe, noms)| {
                let (numero, [fr, en]) = match groupe {
                    None => ("1 2 3".to_string(), ["Bilan de sécurité", "Security check"]),
                    Some(g) => (
                        GROUPES.iter().position(|x| *x == g).map_or(0, |i| i + 4).to_string(),
                        g.titres(),
                    ),
                };
                let titre = (fr, en);
                let commandes: Vec<guide::Commande> = noms
                    .iter()
                    .filter_map(|nom| clap.find_subcommand(nom))
                    .map(|c| {
                        let nom = c.get_name();
                        let anglais = c.get_visible_aliases().next().unwrap_or(nom);
                        let aide_fr = c.get_about().map(ToString::to_string).unwrap_or_default();
                        let aide_en = AIDES_EN
                            .iter()
                            .find(|(n, _)| *n == nom)
                            .map_or(aide_fr.clone(), |(_, a)| (*a).to_string());
                        let place = place_de_commande(nom)
                            .map(|t| (format!(" (menu {t})"), format!(" (menu {t})")))
                            .unwrap_or_default();
                        guide::traduite(
                            garder(format!("vanguard {nom}")),
                            garder(format!("vanguard {anglais}")),
                            garder(en_deux_lignes(&essentiel(&aide_fr), &place.0)),
                            garder(en_deux_lignes(&essentiel(&aide_en), &place.1)),
                            !COMMANDES_EN_LECTURE.contains(&nom),
                        )
                    })
                    .collect();
                guide::Programme {
                    nom: garder(format!("vanguard ({numero})")),
                    role: titre,
                    executable: "",
                    commandes: Box::leak(commandes.into_boxed_slice()),
                }
            })
            .collect()
    })
}

/// Les noms de commandes d'avant la 0.87, que la ligne de commande n'accepte plus (décision de l'auteur) : la
/// recherche les trouve encore (« harden » mène à Defender, « maj » aux mises à jour).
const ANCIENS_NOMS: &[(&str, &str)] = &[
    ("bilan", "complet full"),
    ("audit", "machine"),
    ("appareils", "reseau network"),
    ("mises-a-jour", "maj update"),
    ("fuite-mot-de-passe", "motdepasse password"),
    ("fuite-courriel", "courriel email"),
    ("mots-de-passe-navigateurs", "navigateurs"),
    ("connexions-sortantes", "sortantes outbound"),
    ("acces-a-distance", "distance"),
    ("bilan-confidentialite", "acces permissions"),
    ("objets-connectes", "objets iot"),
    ("cameras-cachees", "cameras"),
    ("canaux-wifi", "canaux channels"),
    ("test-connexion", "connexion connection"),
    ("tableau-de-bord", "tableau"),
    ("fiche-ordinateur", "fiche"),
    ("defender", "durcir harden"),
    ("rapport-a-laisser", "a-laisser"),
    ("exporter", "sauvegarder backup"),
    ("jeux", "gaming"),
    ("depanner", "traces evidence proche relative"),
];

/// Le titre de l'écran d'où s'ouvre un outil désigné par son chemin (« 6.1.3 » : Virus et logiciels espions).
fn chemin_de(chemin: &str) -> String {
    chemin
        .split('.')
        .next()
        .and_then(|g| g.parse::<usize>().ok()?.checked_sub(4))
        .and_then(|i| GROUPES.get(i))
        .map_or_else(String::new, |g| g.titre().to_string())
}

/// La première ouverture du menu de la 0.87 par quelqu'un qui connaissait l'ancien (un bilan déjà fait) : l'en-tête
/// le dit pendant cette session, à la place d'un autre avis, sans touche de plus (les essais de la VM tapent leurs
/// chemins à l'aveugle). Les chemins 4.x, 6.x, 7.x, 8.x et 12.x ont changé de sens ; rien ne se modifie sans accord,
/// mais un ancien chemin ouvre un autre écran.
fn premiere_ouverture_du_nouveau_menu() -> bool {
    !marque_du_nouveau_menu().exists() && !historique::charger().is_empty()
}

fn marque_du_nouveau_menu() -> std::path::PathBuf {
    socle::dossier_local().join("menu-0.87")
}

/// L'avis du nouveau menu a paru : la marque est posée une fois (sans suivre de lien : Vanguard peut tourner en root
/// avec le dossier d'un compte). Sans dossier inscriptible, l'avis reviendra à la prochaine session : rien de faux.
fn avis_du_nouveau_menu_vu() {
    static VU: std::sync::Once = std::sync::Once::new();
    VU.call_once(|| {
        let _ = socle::ecrire_atomique(&marque_du_nouveau_menu(), b"");
    });
}

async fn menu() {
    // La tête du journal notée dès l'ouverture du menu (preuve d'une prochaine mise à jour, `sceau::forme_d_avant`).
    crate::modele::journal::noter_version();
    let mut s = Session::default();
    let nouveau_menu = premiere_ouverture_du_nouveau_menu();
    // La ligne en surbrillance au retour dans le menu : la dernière choisie.
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let lignes = lignes_du_menu(etat_du_menu(reseau::surveillance::active(), nouveau_menu));
        let invite = format!(
            "  {ACCENT}›{RESET} {}",
            tr!("Numéro, ou un mot à chercher : ", "Number, or a word to search: ")
        );
        let Some(choix) = choisir_au_sommet(&lignes, &invite, &dernier, tr!("quitter", "quit")) else {
            break;
        };
        let choix = choix.trim().to_lowercase();
        if choix == "q" {
            break;
        }
        println!();
        if ouvrir_touche(&mut s, &choix).await {
            // Le groupe d'où vient l'outil, en surbrillance au retour (« 5 » pour « 5.2 »).
            dernier = choix.split('.').next().unwrap_or(&choix).to_string();
        }
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
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
    Protection,
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
    #[cfg(not(target_os = "macos"))]
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
    Outil { action: Action::Protection, commande: "defender", groupe: Some(Groupe::Ordinateur), lettre: "",
        titre: ["Blocages de Windows Defender", "Windows Defender blocking"],
        precision: ["ASR, réseau, dossiers contrôlés", "ASR, network, folders"],
        mots: "defender asr bloquer block exploit dossiers contrôlés controlled folder pua" },
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
        titre: ["Tableau de bord de la surveillance", "Monitoring dashboard"],
        precision: ["alertes, nouveaux appareils", "alerts, new devices"],
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
        titre: ["Analyse complète", "Full scan"], precision: ["tout le dossier personnel", "the whole home folder"],
        mots: "virus malware clamav defender" },
    Outil { action: Action::AntivirusDossier, commande: "antivirus", groupe: None, lettre: "a",
        titre: ["Clé USB ou dossier", "USB drive or folder"], precision: ["et pièges de clé USB", "and USB drive traps"],
        mots: "virus usb clé autorun" },
    Outil { action: Action::Yara, commande: "yara", groupe: None, lettre: "",
        titre: ["Règles YARA sur un dossier", "YARA rules on a folder"],
        precision: ["logiciels malveillants connus", "known malware"],
        mots: "yara règles rules malware" },
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
        titre: ["Veilleur : lancements, connexions", "Watcher: launches, connections"], precision: ["", ""],
        mots: "veilleur watcher lancements launches processus processes connexions connections brèves brief \
               connecteur connector temps réel live" },
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
        precision: ["Linux, Windows, macOS, tous", "Linux, Windows, macOS, all"],
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
            else if cfg!(target_os = "macos") { ["Rosetta, Steam, Epic, GOG…", "Rosetta, Steam, Epic, GOG…"] }
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
            else if cfg!(target_os = "macos") { ["publicités, analyses", "ads, analytics"] }
            else { ["rapports et statistiques", "reports and statistics"] },
        mots: "télémétrie telemetry vie privée privacy publicité ads" },
    Outil { action: Action::OptimiserConfort, commande: "optimiser", groupe: Some(Groupe::Optimiser), lettre: "",
        titre: ["Confort et fichiers", "Comfort and files"],
        precision: if cfg!(windows) { ["extensions, clés USB, clic droit", "extensions, USB drives, menus"] }
            else if cfg!(target_os = "macos") { ["extensions, .DS_Store, Finder", "extensions, .DS_Store, Finder"] }
            else { ["annonces d'Ubuntu", "Ubuntu announcements"] },
        mots: "extensions fichiers cachés hidden files" },
    #[cfg(not(target_os = "macos"))]
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
const _: () = assert!(OUTILS.len() == Action::Desinstaller as usize + 1);

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
        #[expect(
            clippy::indexing_slicing,
            reason = "Desinstaller est la dernière variante et l'assertion const sous OUTILS fixe OUTILS.len() à Desinstaller + 1"
        )]
        &OUTILS[self as usize]
    }

    /// Un outil qui ouvre ses propres écrans, marqué « › » comme un écran à choix.
    fn ouvre_ses_ecrans(self) -> bool {
        matches!(self, Action::Logiciels | Action::Gaming | Action::Extensions)
    }

    /// Les variantes de son écran à choix (aucune : un outil ordinaire).
    fn variantes(self) -> &'static [Action] {
        ECRANS.iter().find(|(e, _)| *e == self).map_or(&[], |(_, v)| v)
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
        ) && self.variantes().is_empty()
    }
}

/// Un texte de la table dans la langue de l'interface.
fn texte([fr, en]: [&'static str; 2]) -> &'static str {
    if langue::anglais() { en } else { fr }
}

/// Un groupe d'outils du menu principal, ouvert en sous-menu : la cyberdéfense (4 à 8), puis le reste (9 à 13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Groupe {
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

const GROUPES: [Groupe; 10] = [
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
const PREMIER_EN_PLUS: Groupe = Groupe::Donnees;

/// Les écrans à choix : une ligne du groupe (« 6.1 Analyse antivirus › ») qui ouvre ses variantes (6.1.1 à 6.1.4).
/// Une variante n'a pas de groupe : elle n'est que dans son écran, joignable aussi par son chemin et la recherche.
const ECRANS: &[(Action, &[Action])] = &[
    (Action::Developpeurs, &[Action::SecretsGit, Action::Conteneurs]),
    (Action::Appareils, &[Action::Scanner, Action::Appareil]),
    (
        Action::Antivirus,
        &[
            Action::AntivirusRapide,
            Action::AntivirusComplet,
            Action::AntivirusDossier,
            Action::Yara,
        ],
    ),
    (
        Action::VerifierCopies,
        &[Action::VerifierSauvegarde, Action::VerifierCopie],
    ),
    (Action::VerifierVanguard, &[Action::VerifierMoi, Action::Autotest]),
];

impl Groupe {
    fn titre(self) -> &'static str {
        texte(self.titres())
    }

    /// Son titre en français et en anglais (le guide des commandes en a besoin dans les deux langues).
    fn titres(self) -> [&'static str; 2] {
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

    fn resume(self) -> &'static str {
        match self {
            Groupe::Ordinateur => tr!("failles, mises à jour, intégrité", "flaws, updates, integrity"),
            Groupe::Reseau => tr!("routeur, Wi-Fi, objets connectés", "router, Wi-Fi, smart devices"),
            Groupe::Virus => tr!("antivirus, espions, rançongiciels", "antivirus, spyware, ransomware"),
            Groupe::Arnaques => tr!("liens, courriels, mots de passe", "links, emails, passwords"),
            Groupe::Reagir => tr!("blocage, incident, tout annuler", "blocking, incidents, undo all"),
            Groupe::Donnees => tr!("copier, sauvegarder, vérifier", "copy, back up, verify"),
            Groupe::Guide => tr!("Linux, Windows, macOS, pas à pas", "Linux, Windows, macOS, how-tos"),
            Groupe::Depanner => tr!("Internet, son, lenteur, réparer", "Internet, sound, slowness, repair"),
            Groupe::Optimiser => tr!("logiciels, nettoyage, réglages", "software, cleanup, settings"),
            Groupe::Vanguard => tr!("réglages, mise à jour, extensions", "settings, update, extensions"),
        }
    }

    /// Ouvert directement, sans sous-menu : son premier outil a ses propres écrans (le guide, les parcours).
    fn direct(self) -> bool {
        matches!(self, Groupe::Guide | Groupe::Depanner)
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

/// Chaque place du menu et son outil, dans l'ordre de l'écran : « 4.1 », « 4.8.2 » (une variante de l'écran à choix
/// 4.8), « 11.13 » (après les douze parcours de Dépanner). Une seule liste pour les chemins tapés, la recherche et les
/// places annoncées (`touche_de`) ; un outil sans rien à proposer sur ce système n'y est pas, et ne décale rien après
/// lui que les lignes de fin de groupe, propres à un système.
fn places() -> Vec<(String, Action)> {
    let mut places = Vec::new();
    for (i, groupe) in GROUPES.iter().enumerate() {
        let cle = i + 4;
        let actions = groupe.actions().into_iter().filter(|a| a.disponible());
        if *groupe == Groupe::Depanner {
            // Le groupe s'ouvre sur les parcours (11.1 à 11.12) ; ses autres outils les suivent.
            let parcours = depanner::nombre_de_parcours();
            for (j, a) in actions.filter(|a| *a != Action::Depanner).enumerate() {
                places.push((format!("{cle}.{}", parcours + j + 1), a));
            }
            continue;
        }
        if groupe.direct() {
            continue;
        }
        for (j, a) in actions.enumerate() {
            places.push((format!("{cle}.{}", j + 1), a));
            for (k, v) in a.variantes().iter().copied().filter(|v| v.disponible()).enumerate() {
                places.push((format!("{cle}.{}.{}", j + 1, k + 1), v));
            }
        }
    }
    places
}

/// Un écran d'outils numérotés (un groupe, ou les variantes d'un écran à choix), Entrée pour revenir.
async fn liste_d_outils(s: &mut Session, chemin: &str, resume: &str, actions: &[Action], retour: &str) {
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes: Vec<Ligne> = lignes_cadre(&format!("{ACCENT}VANGUARD{RESET} {GRIS}›{RESET} {chemin}"), resume)
            .into_iter()
            .map(Ligne::Texte)
            .collect();
        lignes.push(Ligne::Texte(String::new()));
        for (i, a) in actions.iter().enumerate() {
            let (texte, precision) = a.libelle();
            let texte = if a.variantes().is_empty() && !a.ouvre_ses_ecrans() {
                texte.to_string()
            } else {
                format!("{texte} {ACCENT}›{RESET}")
            };
            lignes.push(Ligne::choix(&(i + 1).to_string(), &texte, precision));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", retour, ""));
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
        lancer(s, action, chemin).await;
        if action.attendre_apres() && !ui::vient_de_revenir() {
            crate::selection::attendre_retour(&trf!(
                "\n{GRIS}Entrée pour revenir…{RESET}",
                "\n{GRIS}Enter to go back…{RESET}"
            ));
        }
    }
}

/// Un outil, ou l'écran de ses variantes s'il en a (`chemin` : celui de l'écran d'où il est ouvert).
async fn lancer(s: &mut Session, action: Action, chemin: &str) {
    let variantes: Vec<Action> = action.variantes().iter().copied().filter(|v| v.disponible()).collect();
    if variantes.is_empty() {
        return executer(s, action).await;
    }
    let (titre, precision) = action.libelle();
    let chemin = format!("{chemin} {GRIS}›{RESET} {titre}");
    Box::pin(liste_d_outils(
        s,
        &chemin,
        precision,
        &variantes,
        tr!("Revenir", "Back"),
    ))
    .await;
}

/// Sous-menu d'un groupe. Le guide et le dépannage s'ouvrent directement sur leurs propres écrans.
async fn sous_menu(s: &mut Session, groupe: Groupe) {
    let actions: Vec<Action> = groupe.actions().into_iter().filter(|a| a.disponible()).collect();
    // Un groupe direct sans outil disponible tombe sur sa liste (vide) plutôt que d'arrêter le programme.
    if groupe.direct()
        && let Some(&premier) = actions.first()
    {
        executer(s, premier).await;
        revenir_au_menu(premier);
        return;
    }
    liste_d_outils(
        s,
        groupe.titre(),
        groupe.resume(),
        &actions,
        tr!("Revenir au menu principal", "Back to the main menu"),
    )
    .await;
}

/// Dépanner pas à pas : les parcours, puis les autres outils du groupe (réparer une panne connue, le matériel).
fn depanner_avec_ses_outils() {
    let autres: Vec<Action> = Groupe::Depanner
        .actions()
        .into_iter()
        .filter(|a| *a != Action::Depanner && a.disponible())
        .collect();
    let lignes: Vec<(&str, &str, &str)> = autres
        .iter()
        .map(|a| {
            let (titre, precision) = a.libelle();
            (titre, precision, a.outil().mots)
        })
        .collect();
    depanner::menu(&lignes, &mut |i| {
        // `i` vient d'une ligne de `lignes`, bâtie depuis `autres` : un numéro hors liste ne lance rien.
        let Some(&action) = autres.get(i) else { return };
        match action {
            Action::Reparer => reparer::menu(),
            Action::Diagnostic => diagnostic::diagnostic(),
            // Le test `depanner_a_ses_deux_outils` arrête tout autre outil ajouté au groupe sans sa ligne ici.
            _ => {}
        }
        revenir_au_menu(action);
    });
}

async fn executer(s: &mut Session, action: Action) {
    // Le choix de l'outil dans le menu n'est pas un « revenir » : seul compte ce qui se répond dans l'outil.
    ui::noter_retour(false);
    if action.outil().groupe == Some(Groupe::Optimiser) && refuser_optimiser() {
        return;
    }
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
        Action::Depanner => depanner_avec_ses_outils(),
        Action::DepannerInfection => depanner::executer("infection"),
        Action::DepannerCompte => depanner::executer("compte"),
        // Le parcours 11.11, avec son conseil (avant de nettoyer, et où ranger le dossier).
        Action::Traces => depanner::executer("traces"),
        Action::Evenements => evenements::afficher(false, None),
        Action::JournauxWindows => journaux_windows::commande::menu(),
        Action::Demarrage => optimiser::programmes_au_demarrage(),
        Action::Regles => machine::regles::afficher(),
        Action::VerifierMoi => protection::manifeste::verifier_moi(None),
        Action::Autotest => autotest_a_part(),
        // Les écrans à choix passent par `lancer` : jamais exécutés eux-mêmes.
        Action::Developpeurs
        | Action::Appareils
        | Action::Antivirus
        | Action::VerifierCopies
        | Action::VerifierVanguard => {}
        Action::Extensions => plugins::extensions(),
        Action::Parametres => parametres::menu(),
    }
}

/// La valeur d'un interrupteur, dans les mots de l'une ou l'autre langue : « on » (oui, marche, yes), « off » (non,
/// arret, no) ou « etat » (status : le dire sans rien changer). Un seul analyseur pour surveillance, entretien,
/// veilleur, raccourci, sites-dangereux et wifi-public.
fn interrupteur(mot: &str) -> Result<String, String> {
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
fn sans_etat(valeur: Option<&str>) -> Option<&str> {
    valeur.filter(|v| *v != "etat")
}

/// Le veilleur prend aussi « rancongiciel » (ransomware), pour la surveillance en direct des dossiers.
fn interrupteur_veilleur(mot: &str) -> Result<String, String> {
    match selection::simplifier(mot.trim()).as_str() {
        "rancongiciel" | "ransomware" => Ok("rancongiciel".into()),
        _ => interrupteur(mot),
    }
}

/// Le mode Wi-Fi public prend aussi « portail » (portal), pour la page de connexion d'un café ou d'un hôtel.
fn interrupteur_wifi_public(mot: &str) -> Result<String, String> {
    match selection::simplifier(mot.trim()).as_str() {
        "portail" | "portal" => Ok("portail".into()),
        _ => interrupteur(mot),
    }
}

/// Les interrupteurs de protection : un identifiant stable (pour `--json`), leur nom et leur état, dans la langue du
/// moment. Le veilleur n'existe que sous Linux.
fn interrupteurs() -> Vec<(&'static str, &'static str, String)> {
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
fn interrupteurs_json(lignes: &[(&str, &str, String)]) -> String {
    let liste: Vec<serde_json::Value> = lignes
        .iter()
        .map(|(id, nom, etat)| serde_json::json!({"interrupteur": id, "nom": nom, "etat": etat}))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "interrupteurs": liste })).unwrap_or_default()
}

/// `vanguard protection` : chaque interrupteur de protection et son état, en un écran.
fn etat_de_la_protection() {
    titre(tr!("Protection : les interrupteurs", "Protection: the switches"));
    for (_, nom, etat) in interrupteurs() {
        println!("  {:<32} {etat}", format!("{nom} :"));
    }
    trp!(
        "\n  {GRIS}vanguard protection non [--pendant 1h|4h] : couper d'un coup la protection en temps réel ; oui : la remettre.{RESET}",
        "\n  {GRIS}vanguard protection off [--for 1h|4h]: turn real-time protection off at once; on: turn it back on.{RESET}"
    );
}

/// Aide anglaise des commandes : la française est dans les commentaires de `Commande`.
#[rustfmt::skip] // une ligne par aide, que rustfmt étalerait sur quatre
const AIDES_EN: &[(&str, &str)] = &[
    ("bilan", "Full check: this computer, then the network"),
    ("audit", "Audit this computer (firewall, ports, SSH, updates, encryption…)"),
    ("corriger", "Audit the machine, then apply the fixes step by step"),
    ("appareils", "Network scan: devices, open ports, risks, changes since previous scans"),
    ("audit-reseau", "Network audit by domain: six grades (exposure to the Internet, Wi-Fi, segmentation, DNS and TLS, \
                      connected devices, computers) from the local network scan, this computer's network findings and \
                      a few more read-only checks, attacking nothing; what could not be checked is said, never counted \
                      as safe"),
    ("antivirus", "Malware scan: ClamAV (Linux, macOS) or Microsoft Defender (Windows)"),
    ("surveillance", "Turn hourly network monitoring on or off (notification for unknown devices)"),
    ("tableau-de-bord", "Monitoring dashboard in the browser: its state, the alerts day by day, the new devices and the \
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
    ("mises-a-jour", "Updates: system, programs, drivers and firmware checked at once, then installed with your consent"),
    ("reparer", "Common repairs: network, hijacked browsing, firewall, antivirus, system files, disk, space, updates, \
                 time"),
    ("logiciels", "Software: the best programs, mostly open source (browsers, passwords, office, video, design, system \
                   tools…), by category: choose, then install from the system's official source"),
    ("diagnostic", "Computer diagnostic: hardware, system and recent problems (crashes, errors). Read only"),
    ("nettoyer", "Clean up the system: caches, temporary files, downloaded packages, old logs, trash… The space each \
                  item frees is shown first; check, then accept"),
    ("test-connexion", "Connection test for gaming: ping, jitter, packet loss, speed and bufferbloat"),
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
                    abuse.ch key, software versions, weekly self-test, AUR packages). \
                    No argument: their state; with a setting and a value: changes it, showing the \
                    previous value to go back. “real-time no --for 1h|4h” turns Vanguard's real-time protection off \
                    for that long (without --for: until turned back on), after your consent; never Defender, the \
                    firewall or UAC"),
    ("blocage", "Threat blocking: each threat found offers “Block” (the action shown, accepted, written down, \
                 undoable); active protection, after a consent given once, blocks what is certain by itself \
                 (MalwareBazaar fingerprint, known attack tool, command server), then warns you. No argument: the menu"),
    ("canaux-wifi", "Crowded Wi-Fi: nearby networks by channel, and the freest channel to set on the router. Read-only"),
    ("nat", "NAT type for gaming (open, moderate or strict), from two public servers (STUN). Read-only"),
    ("cameras-cachees", "Hidden cameras: on a rental's or someone's network, the devices that look like cameras. Read-only"),
    ("objets-connectes", "Router and connected devices from the last kept scan: what the router announces (model, software), \
                its HTTP-only admin page, the cameras, printers, NAS… and their default password. Nothing is probed"),
    ("dns-rapide", "Fastest DNS: measures the current DNS and public ones, then offers the fastest, undoable. A DNS \
                    that protects (NextDNS, encrypted, filtering) is kept"),
    ("wifi-public", "Public Wi-Fi mode (café, hotel, airport): incoming connections closed on this network, file \
                     sharing and name announcement off, protective DNS (encrypted on Linux with systemd-resolved), \
                     after your consent and with administrator rights; \"off\" puts everything back exactly, \
                     \"portal\" reopens the network's login page. Without argument: its state"),
    ("pieges", "Decoy files against ransomware: place them (after your consent), see whether they are intact, or \
                remove them"),
    ("defender", "Windows Defender blocking: ASR rules, network protection, unwanted software, controlled folder access. \
                Each one is turned on after your consent; a protection Vanguard does not undo (Windows only)"),
    ("isoler", "Run an unknown program in a sandbox: no network, home folder hidden"),
    ("fuite-courriel", "Email address leaks: the address is sent to the search service, after your consent"),
    ("integrite", "Critical file integrity: BLAKE3 fingerprint reference, then what changed since"),
    ("fuite-mot-de-passe", "Check whether passwords have leaked (Have I Been Pwned); only 5 characters of their fingerprint \
                    are sent"),
    ("mots-de-passe-navigateurs", "Passwords saved in the browsers: how many and how protected (counted, never read), where to run \
                     the browser's built-in check (weak, reused, compromised), and the HIBP check of a typed password"),
    ("connexions-sortantes", "Who talks to the Internet? Each program's current connections, with the server's name. Read-only"),
    ("verifier-moi", "Check Vanguard itself: version, build date, SHA-256 fingerprint of the program (to compare with the release page), on the owner's key the key manifest, and after your consent the signed history of published versions; or another copy of Vanguard, by its fingerprint and that history"),
    ("acces-a-distance", "Is my computer being controlled? Remote control software (AnyDesk, TeamViewer, RustDesk…) installed, started at boot, running or downloaded: the fake technicians' tool. Removed after your consent; a running program asks for a second consent"),
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
    ("bilan-confidentialite", "Privacy check: the apps that have access to the location, contacts, camera and microphone, and their \
               last use when it is recorded. Read-only"),
    ("quarantaine", "Quarantine: the files isolated by the antivirus or YARA, to put back in their place (false \
                     positive) or to delete for good"),
    ("exporter", "Back up the device database and the monitoring state to a JSON file"),
    ("importer", "Add a backup (or an appareils.json) to the current database, without erasing anything"),
    ("nommer", "Give a nickname to a device of the database (“HP printer”), by its IP or MAC"),
    ("jeux", "Gaming: components for games (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, Wine…; \
                macOS: Rosetta, Steam, Epic…) and system settings"),
    ("guide", "Command guide: the useful commands of Omarchy, Arch, Fedora, Debian, other Linux, Windows, macOS and \
               all systems, sorted by program, with step-by-step guides; plus the tldr-pages examples, downloaded \
               every week"),
    ("lenteur", "Why is it slow? What keeps the processor, memory and disk busy, startup, the programs started at \
                 login. Read only"),
    ("demarrage", "Startup programs: those that start at login, to remove or put back after your consent. Each removal \
                   is undone exactly (Block and respond › Put everything back)"),
    ("fiche-ordinateur", "Computer specs: model, motherboard, processor, memory, graphics card, disks, system. Serial numbers are \
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
    ("journaux-windows", "Windows logs: what happened? The EVT- rules (cleared traces, attack service, one more \
                          administrator, guessed password, Remote Desktop, PowerShell, Defender…) on this computer's \
                          logs (Windows) or a folder of .evtx (any system), then the alerts in time order. Read only"),
    ("rapport-a-laisser", "Report to leave behind: a simple page for the person you just helped (grade, what is left to do, \
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
    ("depanner", "Troubleshoot step by step: no Internet, Wi-Fi dropping, slow computer, no sound, printer, disk full; \
                  after an infection, new computer, computer leaving (sale, gift), hacked account, collect the \
                  evidence (“evidence [folder]”: processes, connections, startup, accounts, logs, recent files and \
                  timeline, in a dated folder; read-only), a relative's computer"),
    ("chercher", "Search for a tool, a guide page, a program or a setting: the ten best results, with their place in \
                  the menu and their command; in a terminal, a number opens the result. Synonyms (box, router) and \
                  typos included. Exit code 1 if nothing is found"),
    ("rapport", "Detailed report in the browser: this session's check if there is one, otherwise a full check first"),
    ("annuler", "Put everything back: undoes what Vanguard changed (Optimize settings, check-up fixes, gaming, blocks, \
                 public Wi-Fi mode), the previous value put back, after your consent. Like “optimize undo”"),
    ("protection", "Protection: the state of each switch (real-time, monitoring, maintenance, blocking, watcher, \
                    dangerous sites, public Wi-Fi, shortcut); “on” or “off” [--for 1h|4h] acts on real-time \
                    protection, like “settings real-time”"),
    ("plugins", "Plugins: programs of yours added to Vanguard without changing its code (tests, experimental tools), \
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
    ("bilan", "html", "Also open the HTML report in the browser"),
    ("tableau-de-bord", "sans_ouvrir", "Write the page without opening it (no graphical display, over SSH)"),
    ("bilan", "texte", "Show the report as plain text (Markdown) in the terminal: no browser or graphical display \
                          needed"),
    ("appareils", "cible", "IP, CIDR network (10.0.0.0/24) or range (10.0.0.1-50). Default: your local network"),
    ("appareils", "ports", "“courants”/“common” (default), “tous”/“all” (1-65535) or a list “22,80,8000-8100”"),
    ("appareils", "timeout", "Connection timeout per port, in milliseconds"),
    ("appareils", "parallele", "Number of simultaneous connections"),
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
    ("exporter", "fichier", "File to write (default: vanguard-sauvegarde-YYYY-MM-DD.json in the home or Documents \
                                folder)"),
    ("nommer", "appareil", "IP (on the current network) or MAC address of the device"),
    ("nommer", "surnom", "The nickname; empty to remove it"),
    ("lien", "adresse", "The link you received (in quotes if it contains “&” or “?”)"),
    ("verifier-fichier", "fichier", "The downloaded file"),
    ("courriel-suspect", "fichier", "The saved email (.eml): Thunderbird “Save As”, Gmail “Download message”, \
                                     Outlook on the web “Download”"),
    ("verifier-fichier", "empreinte", "The checksum published by the site (preferably SHA-256). Otherwise: a \
                                       SHA256SUMS or .sha256 next to it"),
    ("guide", "quoi", "A system (omarchy, arch, fedora, debian, windows, macos, all; linux: the common programs; tldr; \
                       vanguard), a program (systemctl, winget, tar…), a path (6.7.2) or words to look for"),
    ("fiche-ordinateur", "json", "The specs as JSON, for a script (without the serial numbers)"),
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
    ("journaux-windows", "dossier", "A folder of .evtx logs (winevt\\Logs of a mounted disk, folder of “troubleshoot \
                                    evidence”); without it, this Windows' logs"),
    ("journaux-windows", "jours", "How many days back (7 by default)"),
    ("journaux-windows", "json", "The result as JSON, for a script: nothing is asked"),
    ("autotest", "json", "The report as JSON, for a script (without any value read on the computer)"),
    ("protection", "json", "The switches' state as JSON, for a script: nothing is changed"),
    ("diagnostic", "json", "The result as JSON, for a script: nothing changes"),
    ("lenteur", "json", "The result as JSON, for a script: nothing changes"),
    ("connexions-sortantes", "json", "The result as JSON, for a script"),
    ("acces-a-distance", "json", "The result as JSON, for a script: nothing is removed, no question"),
    ("bilan-confidentialite", "json", "The result as JSON, for a script"),
    ("test-connexion", "json", "The result as JSON, for a script"),
    ("objets-connectes", "json", "The result as JSON, for a script"),
    ("lien", "json", "The result as JSON, for a script: without --internet, the examination on the computer only \
                      (domain age and public lists said not checked)"),
    ("lien", "internet", "Consent given in advance: the domain age and the public lists are asked online (for --json)"),
    ("listes-noires", "json", "The result as JSON, for a script: without --internet, nothing is sent and the address \
                               is said not checked"),
    ("listes-noires", "internet", "Consent given in advance: the four lists see the public address (for --json, which \
                                   asks nothing)"),
    ("autotest", "internet", "Let the rules that need it go on the Internet (updates, software versions)"),
    ("autotest", "detail", "Show on screen the values that differ (package, unit, account names), here only"),
    ("autotest", "une_par_une", "The rules one by one, for timings without their neighbours (slower)"),
    ("copier-fichiers", "destination", "A folder on an external disk (default: chosen among the plugged-in disks)"),
    ("verifier-copie", "dossier", "The disk or the folder of the copy (default: chosen among the plugged-in disks)"),
    ("verifier-cle", "dossier", "A folder of the drive or disk (default: chosen among the plugged-in disks)"),
    ("sauvegarde-auto", "annuler", "Remove the automatic backup set up by Vanguard (the backed-up files stay)"),
    ("depanner", "sujet", "The subject: internet, wifi, slow, sound, printer, disk, infection, new, leaving, account, \
                           evidence [folder], relative (or words that describe it)"),
    ("protection", "quoi", "on or off, then --for 1h or 4h for a cut that ends by itself"),
    ("chercher", "mots", "The words searched for"),
    ("guide", "sommaire", "For a system: the list of its programs and their path, without their commands"),
    ("chercher", "premier", "Open the best result right away"),
    ("plugins", "quoi", "add <folder>, approve <name>, list, remove <name>, or <name> [--report] [arguments]"),
    ("labo", "quoi", "open, list, or <file> [arguments]"),
    ("extensions", "sans_restrictions", "on: the extensions' restrictions turned off (no consent, fingerprint or scan, \
                                         with all your rights); off: back on. The extensions folder must stay yours \
                                         alone"),
    ("parametres", "quoi", "A setting (language, emojis, offline, real-time, monitoring, maintenance, learned, \
                              blocking, restrictions, abuse.ch, software-versions, autotest, aur-packages) and its \
                              value; real-time no also takes --for 1h or 4h"),
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

/// Les commandes de la ligne de commande qui ne sont l'outil d'aucune ligne du menu, et la rubrique de `--help` où
/// elles vont.
const RUBRIQUE_DES_AUTRES: &[(&str, Groupe)] = &[
    ("protection", Groupe::Reagir),
    ("importer", Groupe::Vanguard),
    ("plugins", Groupe::Vanguard),
    ("labo", Groupe::Vanguard),
];

/// Le nom d'une commande dans la langue de l'interface : son alias anglais visible en anglais, s'il en a un.
fn nom_de_commande(commande: &clap::Command) -> String {
    if langue::anglais()
        && let Some(alias) = commande.get_visible_aliases().next()
    {
        return alias.to_string();
    }
    commande.get_name().to_string()
}

/// Les commandes de `--help`, rangées comme le menu : (rubrique, noms dans l'ordre des lignes), puis celles qui ne
/// sont dans aucune rubrique (aucune, d'après le test `l_aide_cite_chaque_commande`).
fn rubriques_de_l_aide() -> Vec<(String, Vec<String>)> {
    let clap = Args::command();
    let visibles: Vec<&clap::Command> = clap
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();
    let nom = |commande: &str| {
        visibles
            .iter()
            .find(|c| c.get_name() == commande)
            .map(|c| nom_de_commande(c))
    };
    let rubriques_fr = rubriques_des_commandes();
    let vus: Vec<&str> = rubriques_fr.iter().flat_map(|(_, n)| n.iter().copied()).collect();
    let mut rubriques: Vec<(String, Vec<String>)> = rubriques_fr
        .into_iter()
        .map(|(groupe, noms)| {
            let titre = match groupe {
                None => tr!("Bilan de sécurité", "Security check").to_string(),
                Some(g) => format!(
                    "{} {}",
                    GROUPES.iter().position(|x| *x == g).map_or(0, |i| i + 4),
                    g.titre()
                ),
            };
            (titre, noms.into_iter().filter_map(nom).collect())
        })
        .collect();
    let reste: Vec<String> = visibles
        .iter()
        .filter(|c| !vus.contains(&c.get_name()))
        .map(|c| nom_de_commande(c))
        .collect();
    if !reste.is_empty() {
        rubriques.push((tr!("Aussi", "Also").to_string(), reste));
    }
    rubriques
}

/// Les commandes visibles rangées comme le menu, par leur nom français : (groupe, aucun pour la rubrique du bilan ;
/// noms dans l'ordre des lignes). Sans langue : `--help` et le guide (10.10) s'en servent.
fn rubriques_des_commandes() -> Vec<(Option<Groupe>, Vec<&'static str>)> {
    let clap = Args::command();
    let existe = |commande: &str| {
        clap.get_subcommands()
            .any(|c| !c.is_hide_set() && c.get_name() == commande)
    };
    let mut vus: Vec<&'static str> = Vec::new();
    let mut ajouter = |liste: &mut Vec<&'static str>, commande: &'static str| {
        if !commande.is_empty() && !vus.contains(&commande) && existe(commande) {
            vus.push(commande);
            liste.push(commande);
        }
    };
    let mut rubriques = Vec::new();
    let mut premiere = Vec::new();
    for a in [Action::Complet, Action::Corriger, Action::Rapport] {
        ajouter(&mut premiere, a.outil().commande);
    }
    // La recherche de l'accueil, en ligne de commande.
    ajouter(&mut premiere, "chercher");
    rubriques.push((None, premiere));
    for g in GROUPES {
        let mut liste = Vec::new();
        // Les raccourcis d'incident (8.3 à 8.5) mènent à « depanner » : sa rubrique est celle de Dépanner.
        let raccourcis = [Action::DepannerInfection, Action::DepannerCompte, Action::Traces];
        for a in g.actions().into_iter().filter(|a| !raccourcis.contains(a)) {
            ajouter(&mut liste, a.outil().commande);
            for v in a.variantes() {
                ajouter(&mut liste, v.outil().commande);
            }
        }
        for (commande, _) in RUBRIQUE_DES_AUTRES.iter().filter(|(_, r)| *r == g) {
            ajouter(&mut liste, commande);
        }
        rubriques.push((Some(g), liste));
    }
    rubriques
}

/// `vanguard --help` : toutes les commandes en rubriques, aux noms et numéros du menu, générées depuis `OUTILS` et
/// clap (jamais écrites à la main).
fn aide_longue() -> String {
    use std::fmt::Write;
    let mut t = trf!(
        "Vanguard {} : cyberdéfense portable des postes et des réseaux.\nSans argument : le menu.\n\nUsage : vanguard [commande] [options]\n\n",
        "Vanguard {}: portable cyber defense for endpoints and networks.\nNo argument: the menu.\n\nUsage: vanguard [command] [options]\n\n",
        env!("CARGO_PKG_VERSION")
    );
    let rubriques = rubriques_de_l_aide();
    let colonne = rubriques.iter().map(|(r, _)| largeur_affichee(r)).max().unwrap_or(0) + 2;
    for (rubrique, noms) in rubriques {
        let lignes = envelopper(&noms.join(", "), LARGEUR - 2 - colonne);
        for (i, ligne) in lignes.iter().enumerate() {
            let tete = if i == 0 { rubrique.as_str() } else { "" };
            let blanc = " ".repeat(colonne - largeur_affichee(tete));
            let _ = writeln!(t, "  {tete}{blanc}{ligne}");
        }
    }
    t += tr!(
        "\nDétail d'une commande : vanguard <commande> --help.\nAnciens noms de commandes : dans l'historique des versions (CHANGELOG.md).\nCe que Vanguard protège ou non : MODELE-DE-MENACE.md, dans le dépôt.\nCe que voient ses règles : COUVERTURE-ATTACK.md.\n",
        "\nDetail of a command: vanguard <command> --help.\nFormer command names: in the version history (CHANGELOG.en.md).\nWhat Vanguard protects or not: MODELE-DE-MENACE.en.md, in the repository.\nWhat its rules see: COUVERTURE-ATTACK.en.md.\n"
    );
    t
}

/// `vanguard -h` : l'essentiel, en une quinzaine de lignes.
fn aide_courte() -> String {
    use std::fmt::Write;
    let mut t = trf!(
        "Vanguard {} : cyberdéfense portable des postes et des réseaux.\nSans argument : le menu (↑ ↓, ou un mot pour chercher un outil).\n\n",
        "Vanguard {}: portable cyber defense for endpoints and networks.\nNo argument: the menu (↑ ↓, or a word to find a tool).\n\n",
        env!("CARGO_PKG_VERSION")
    );
    let clap = Args::command();
    let nom = |commande: &str| {
        clap.find_subcommand(commande)
            .map_or_else(|| commande.to_string(), nom_de_commande)
    };
    let lignes: [(String, &str); 7] = [
        (
            nom("bilan"),
            tr!("le bilan de sécurité complet", "the full security check"),
        ),
        (
            nom("corriger"),
            tr!(
                "corriger les problèmes trouvés, un à un",
                "fix the problems found, one by one"
            ),
        ),
        (
            nom("rapport"),
            tr!(
                "le rapport détaillé dans le navigateur",
                "the detailed report in the browser"
            ),
        ),
        (
            nom("protection"),
            tr!("l'état des protections ; les couper", "the protections: state, off, on"),
        ),
        (
            format!("{} [{}]", nom("depanner"), tr!("sujet", "subject")),
            tr!(
                "dépanner pas à pas (internet, son, lent…)",
                "troubleshooting (internet, sound, slow…)"
            ),
        ),
        (
            format!("{} <{}>", nom("chercher"), tr!("mots", "words")),
            tr!(
                "trouver un outil, un logiciel, un réglage",
                "find a tool, a program, a setting"
            ),
        ),
        (
            format!("{} [{}]", nom("guide"), tr!("quoi", "what")),
            tr!("les commandes utiles, expliquées", "useful commands, explained"),
        ),
    ];
    for (commande, quoi) in lignes {
        let _ = writeln!(t, "  vanguard {commande:<24}{quoi}");
    }
    t += tr!(
        "\nvanguard --help : toutes les commandes, rangées comme le menu.\n",
        "\nvanguard --help: every command, sorted like the menu.\n"
    );
    t
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
    // « vanguard --version » (ou -V) seul : la version, rien d'autre. Ni réglages, ni journal, ni sceaux : un verrou
    // des sceaux gardé ailleurs le faisait attendre des secondes pour une ligne connue d'avance.
    if let [v] = std::env::args_os().skip(1).collect::<Vec<_>>().as_slice()
        && (v == "--version" || v == "-V")
    {
        return println!("vanguard {}", env!("CARGO_PKG_VERSION"));
    }
    // Le processus élevé ne fait que sa liste : rien d'autre ne doit tourner avec le jeton administrateur (journal,
    // passage, reconnaissance de la clé écrivent dans des dossiers que le compte contrôle).
    if std::env::args_os().nth(1).is_some_and(|a| a == "appliquer-eleve") {
        // La langue du Vanguard qui demande, avant le premier texte (l'aide de clap en est un) : pkexec et run0
        // donnent au fils un environnement neuf, sans LANG.
        #[cfg(unix)]
        {
            let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
            if let Some(i) = args.iter().position(|a| a == "--langue")
                && let Some(l) = args.get(i + 1)
            {
                langue::forcer(l == "en");
            }
        }
        let code = match Args::from_arg_matches(&ligne_de_commande().get_matches()) {
            #[cfg(windows)]
            Ok(Args {
                commande:
                    Some(Commande::AppliquerEleve {
                        canal: Some(canal),
                        parent: Some(parent),
                        ..
                    }),
            }) => machine::windows::eleve::executer(&canal, parent),
            #[cfg(unix)]
            Ok(Args {
                commande: Some(Commande::AppliquerEleve { langue, parent, .. }),
            }) => machine::assistant::executer(langue.as_deref(), parent),
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
    avertir_si_eleve();
    passage::au_lancement();
    // Après le passage, qui a pu déplacer l'ancien dossier avec ses droits d'avant.
    #[cfg(unix)]
    crate::socle::proteger_dossier_local();
    protection::cles_connues::reconnaitre_la_cle_du_programme();
    // « vanguard -h » ou « --help » seuls : les aides générées depuis le menu (`aide_courte`, `aide_longue`). L'aide
    // d'une commande reste celle de clap (« vanguard bilan --help »), et « vanguard help » sa liste à plat, dans
    // l'ordre des déclarations (outils/page-fonctions.py la lit). args_os : un argument qui n'est pas de l'UTF-8
    // (un nom de fichier) ne doit pas arrêter le programme ici.
    let premiers: Vec<std::ffi::OsString> = std::env::args_os().skip(1).take(2).collect();
    match premiers.as_slice() {
        [h] if h == "-h" => return print!("{}", aide_courte()),
        [h] if h == "--help" => return print!("{}", aide_longue()),
        _ => {}
    }
    let args = Args::from_arg_matches(&ligne_de_commande().get_matches()).unwrap_or_else(|e| e.exit());
    if args.commande.as_ref().is_some_and(commande_d_optimiser) && refuser_optimiser() {
        machine::quitter(2);
    }
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
                machine::quitter(1);
            }
        }
        Some(Commande::AuditReseau { json, html, invite }) => {
            Session::default().audit_reseau(json, html, invite).await;
        }
        Some(Commande::Antivirus { complet, dossier }) => protection::antivirus::analyser(portee(dossier, complet)),
        Some(Commande::Surveillance { etat }) => match etat.as_str() {
            "on" | "off" => reseau::surveillance::activer(etat == "on"),
            _ => println!(
                "  {} : {}",
                tr!("Surveillance toutes les heures", "Hourly monitoring"),
                precision_surveillance(
                    reseau::surveillance::active(),
                    protection::temps_reel::coupure().is_some()
                )
            ),
        },
        Some(Commande::Tableau { sans_ouvrir }) => reseau::tableau::ouvrir(sans_ouvrir),
        Some(Commande::Veilleur {
            etat,
            sous_etat,
            servir,
        }) => veilleur(sans_etat(etat.as_deref()), sans_etat(sous_etat.as_deref()), servir),
        Some(Commande::SitesDangereux { etat }) => protection::sites_bloques::commande(sans_etat(etat.as_deref())),
        Some(Commande::DernieresFailles { jours }) => protection::kev::ecran(jours),
        Some(Commande::Surveiller) => reseau::surveillance::surveiller().await,
        Some(Commande::Entretien { etat }) => match sans_etat(etat.as_deref()) {
            Some(e) => entretien::activer(e == "on"),
            None => entretien::maintenant(),
        },
        Some(Commande::Entretenir) => entretien::entretenir(),
        // Traité au tout début de main, avant tout le reste : jamais ici.
        Some(Commande::AppliquerEleve { .. }) => machine::quitter(2),
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
        Some(Commande::Connexion { json: false }) => reseau::connexion::tester().await,
        Some(Commande::Connexion { json: true }) => reseau::connexion::json().await,
        Some(Commande::Diagnostic { json: false }) => diagnostic::diagnostic(),
        Some(Commande::Diagnostic { json: true }) => diagnostic::json(),
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
        Some(Commande::Sortantes { json: false }) => protection::sortantes::afficher(),
        Some(Commande::Sortantes { json: true }) => protection::sortantes::json(),
        Some(Commande::Distance { json: false }) => protection::distance::menu(),
        Some(Commande::Distance { json: true }) => protection::distance::json(),
        Some(Commande::VerifierMoi { programme }) => protection::manifeste::verifier_moi(programme.as_deref()),
        Some(Commande::Manifeste {
            ecrire,
            forcer,
            accepter,
            images,
            image,
        }) => {
            protection::manifeste::commande(
                ecrire.as_deref(),
                forcer,
                accepter,
                images.as_deref().map(|d| (d, &image[..])),
            );
        }
        Some(Commande::Deploiement { etape }) => {
            let code = deploiement::executer(etape);
            if code != 0 {
                std::process::exit(code);
            }
        }
        Some(Commande::Lien {
            adresse, json: false, ..
        }) => protection::lien::verifier(Some(&adresse)),
        Some(Commande::Lien {
            adresse,
            json: true,
            internet,
        }) => protection::lien::json(&adresse, internet),
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
        Some(Commande::Acces { json: false }) => protection::acces::afficher_tout(),
        Some(Commande::Acces { json: true }) => protection::acces::json(),
        Some(Commande::Quarantaine) => protection::quarantaine::menu(),
        Some(Commande::Secrets) => protection::secrets_git::analyser(),
        Some(Commande::Conteneurs) => protection::conteneurs::analyser(),
        Some(Commande::Blocage { quoi }) => protection::blocage::commande(&quoi),
        Some(Commande::Parametres { quoi }) => parametres::commande(&quoi),
        Some(Commande::Chercher { mots, premier, json }) => {
            if !chercher(&mots.join(" "), premier, json).await {
                machine::quitter(1);
            }
        }
        // Le rapport du dernier bilan s'il a moins d'une heure ; sinon un bilan complet d'abord.
        Some(Commande::Rapport) => {
            if let Some(chemin) = rapport::recent(std::time::Duration::from_secs(3600)) {
                trp!("  Rapport : {}", "  Report: {}", chemin.display());
                machine::ouvrir(&chemin.display().to_string());
            } else {
                let mut s = Session::default();
                executer(&mut s, Action::Rapport).await;
            }
        }
        Some(Commande::Annuler) => optimiser::tout_annuler(),
        // `quoi` prend tout ce qui suit le premier mot (trailing_var_arg) : « etat --json » y laisse --json, qui vaut
        // pourtant pour la commande ; sans cela, l'écran sortait là où un script attendait du JSON.
        Some(Commande::Protection { json, quoi }) if json || quoi.iter().any(|m| m == "--json") => {
            let mots: Vec<&String> = quoi.iter().filter(|m| *m != "--json").collect();
            let etat = match mots.as_slice() {
                [] => true,
                [mot] => interrupteur(mot).as_deref() == Ok("etat"),
                _ => false,
            };
            if !etat {
                eprintln!(
                    "  ✖ {}",
                    tr!(
                        "--json montre l'état seulement : sans oui ni non",
                        "--json shows the state only: without on or off"
                    )
                );
                machine::quitter(2);
            }
            println!("{}", interrupteurs_json(&interrupteurs()));
        }
        Some(Commande::Protection { quoi, .. }) => match quoi.split_first() {
            None => etat_de_la_protection(),
            Some((valeur, reste)) => match interrupteur(valeur).as_deref() {
                Ok("etat") => etat_de_la_protection(),
                // oui, marche, on… : la valeur que « parametres temps-reel » connaît.
                Ok(v) => {
                    let mots: Vec<String> = ["temps-reel".to_string(), v.to_string()]
                        .into_iter()
                        .chain(reste.iter().cloned())
                        .collect();
                    parametres::commande(&mots);
                }
                Err(e) => {
                    eprintln!("  ✖ {e}");
                    machine::quitter(2);
                }
            },
        },
        Some(Commande::Isoler { fichier }) => protection::isoler::isoler(&fichier),
        Some(Commande::Pieges { retirer }) => protection::pieges::commande(retirer),
        Some(Commande::Durcir) => optimiser::protection(),
        // La portée vient des options ; le menu la demande (`yara::menu`), puis lance la même analyse.
        Some(Commande::Yara { complet, dossier }) => protection::yara::analyser(&portee(dossier, complet)),
        Some(Commande::Memoire) => protection::memoire::analyser(),
        Some(Commande::ListesNoires { json: false, .. }) => reseau::listes_noires::verifier(),
        Some(Commande::ListesNoires { json: true, internet }) => reseau::listes_noires::json(internet),
        Some(Commande::Canaux) => reseau::canaux::analyser(),
        Some(Commande::Nat) => reseau::nat::tester(),
        Some(Commande::Cameras) => reseau::cameras::chercher_cameras().await,
        Some(Commande::Objets { json: false }) => reseau::objets::montrer(),
        Some(Commande::Objets { json: true }) => reseau::objets::json(),
        Some(Commande::DnsRapide) => dns_rapide::mesurer_et_proposer(),
        Some(Commande::Optimiser { quoi }) => optimiser_en_ligne_de_commande(quoi.as_deref()).await,
        Some(Commande::WifiPublic { etat }) => reseau::wifi_public::commande(sans_etat(etat.as_deref())),
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
        Some(Commande::Guide { quoi, sommaire }) => guide::executer(&quoi.join(" "), sommaire),
        Some(Commande::Lenteur { json: false }) => lenteur::commande(),
        Some(Commande::Lenteur { json: true }) => lenteur::json(),
        Some(Commande::Demarrage) => optimiser::programmes_au_demarrage(),
        Some(Commande::Fiche { json }) => fiche::fiche(json),
        Some(Commande::CopierFichiers { destination }) => copier::commande(destination.as_deref()),
        Some(Commande::VerifierCopie { dossier }) => copier::verifier_copie(dossier.as_deref()),
        Some(Commande::VerifierSauvegarde) => sauvegarde::verifier_sauvegarde(),
        Some(Commande::VerifierCle { dossier }) => verifier_cle::commande(dossier.as_deref()),
        Some(Commande::Changements) => changements::afficher(),
        Some(Commande::Evenements { json, incident }) => evenements::afficher(json, incident.as_deref()),
        Some(Commande::JournauxWindows { dossier, jours, json }) => {
            journaux_windows::commande::executer(dossier.as_deref(), jours, json);
        }
        Some(Commande::ALaisser) => a_laisser::laisser(&machine::executer(false)),
        Some(Commande::SauvegardeAuto { annuler }) => {
            if annuler {
                sauvegarde::annuler();
            } else {
                sauvegarde::menu();
            }
        }
        Some(Commande::Raccourci { etat }) => raccourci::commande(sans_etat(etat.as_deref()).map(|e| e == "on")),
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
            machine::quitter(code);
        }
        Some(Commande::Depanner { sujet }) if sujet.is_empty() => depanner_avec_ses_outils(),
        // « depanner traces [dossier] » : la collecte, comme l'ancienne commande « traces », avec son code de sortie
        // (1 si elle a échoué) pour un script ou une tâche ; le menu passe par le parcours 11.11 et son conseil.
        Some(Commande::Depanner { sujet })
            if sujet.len() <= 2 && matches!(sujet.first().map(String::as_str), Some("traces" | "evidence")) =>
        {
            if !traces::commande(sujet.get(1).map(std::path::Path::new)) {
                machine::quitter(1);
            }
        }
        Some(Commande::Depanner { sujet }) => depanner::executer(&sujet.join(" ")),
        Some(Commande::Plugin { quoi }) => {
            let code = plugins::commande(&quoi);
            if code != 0 {
                machine::quitter(code);
            }
        }
        Some(Commande::Labo { quoi }) => {
            let code = plugins::labo::commande(&quoi);
            if code != 0 {
                machine::quitter(code);
            }
        }
        Some(Commande::Extensions { sans_restrictions }) => match sans_restrictions {
            None => plugins::extensions(),
            Some(etat) => {
                let code = plugins::regler_restrictions(etat == "on");
                if code != 0 {
                    machine::quitter(code);
                }
            }
        },
    }
    // Une page ouverte juste avant la fin (« vanguard rapport », le tableau de bord) : son ouverture aboutit avant
    // que le processus ne parte.
    machine::attendre_ouvertures();
    // Les événements remis faute de verrou du journal, écrits avant que la commande ne parte avec eux.
    modele::journal::ecrire_differes();
}

#[cfg(test)]
mod tests_menu {
    use super::*;

    /// Les sous-commandes refusées en administrateur sont exactement celles des outils d'Optimiser de la table.
    #[test]
    fn commandes_d_optimiser() {
        for o in OUTILS.iter().filter(|o| !o.commande.is_empty()) {
            let Ok(args) = Args::try_parse_from(["vanguard", o.commande]) else {
                assert_ne!(
                    o.groupe,
                    Some(Groupe::Optimiser),
                    "{} : sous-commande illisible",
                    o.commande
                );
                continue;
            };
            let refusee = args.commande.as_ref().is_some_and(commande_d_optimiser);
            assert_eq!(refusee, o.groupe == Some(Groupe::Optimiser), "{}", o.commande);
        }
        let refusee = |l: &[&str]| {
            Args::try_parse_from(l)
                .unwrap()
                .commande
                .as_ref()
                .is_some_and(commande_d_optimiser)
        };
        assert!(!refusee(&["vanguard", "optimiser", "annuler"]));
        assert!(!refusee(&["vanguard", "optimize", "undo"]));
        assert!(refusee(&["vanguard", "optimiser", "confort"]));
        assert!(refusee(&["vanguard", "lenteur", "--json"]));
        assert!(refusee(&["vanguard", "nettoyer", "--liste"]));
    }

    #[test]
    fn optimiser_refuse_seulement_eleve_depuis_un_compte_ordinaire() {
        assert!(optimiser_refuse(true, true));
        // Root seul (ssh root@, conteneur), Windows sans UAC : refuser ne protégerait rien.
        assert!(!optimiser_refuse(true, false));
        assert!(!optimiser_refuse(false, true));
        assert!(!optimiser_refuse(false, false));
    }

    #[test]
    fn venu_de_sudo_ou_d_une_session_ordinaire() {
        assert!(venu_d_un_autre_compte(true, None));
        assert!(venu_d_un_autre_compte(true, Some(0)));
        // su ou sudo -i sans variables : la session reste celle du compte ordinaire.
        assert!(venu_d_un_autre_compte(false, Some(1000)));
        // ssh root@, console root, conteneur sans session.
        assert!(!venu_d_un_autre_compte(false, Some(0)));
        assert!(!venu_d_un_autre_compte(false, Some(u32::MAX)));
        assert!(!venu_d_un_autre_compte(false, None));
    }

    #[test]
    fn root_d_un_espace_de_noms_ou_de_l_ordinateur() {
        assert_eq!(root_hors_de_l_espace("         0          0 4294967295\n"), Some(true));
        // unshare -r : le compte 0 de l'espace est le compte 1000 de l'ordinateur.
        assert_eq!(root_hors_de_l_espace("         0       1000          1\n"), Some(false));
        assert_eq!(root_hors_de_l_espace("         0     100000      65536\n"), Some(false));
        assert_eq!(root_hors_de_l_espace("      1000       1000          1\n"), None);
        assert_eq!(root_hors_de_l_espace("0 0 0\n"), None);
        assert_eq!(root_hors_de_l_espace(""), None);
        assert_eq!(root_hors_de_l_espace("x y z\n"), None);
    }

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
        // 1, 2, 3 au menu principal ; une variante dans un seul écran à choix ; tout le reste dans un seul groupe.
        let principal = [Action::Complet, Action::Corriger, Action::Rapport];
        for (i, o) in OUTILS.iter().enumerate() {
            // La ligne d'un outil est à son numéro : `Action::outil` la trouve sans chercher.
            assert_eq!(o.action as usize, i);
            let groupes = GROUPES.iter().filter(|g| g.actions().contains(&o.action)).count();
            let ecrans = ECRANS.iter().filter(|(_, v)| v.contains(&o.action)).count();
            assert_eq!(
                groupes + ecrans + usize::from(principal.contains(&o.action)),
                1,
                "{}",
                o.titre[0]
            );
        }
        // Un écran à choix est dans un groupe, et ses variantes n'en ouvrent pas d'autre (trois niveaux au plus).
        for (ecran, variantes) in ECRANS {
            assert!(ecran.outil().groupe.is_some(), "{}", ecran.outil().titre[0]);
            assert!(variantes.len() >= 2 && variantes.iter().all(|v| v.variantes().is_empty()));
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

    /// Les lignes propres à un système vont en fin de groupe : les places annoncées (4.1 à 4.8, 8.1 à 8.9, 12.1 à
    /// 12.10…) sont les mêmes sous Linux, Windows et macOS.
    #[test]
    fn lignes_propres_a_un_systeme_en_fin() {
        let propres = [
            Action::LogicielsPerimes,
            Action::Protection,
            Action::Veilleur,
            Action::OptimiserConfidentialite,
            Action::OptimiserConfort,
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance,
        ];
        for g in GROUPES {
            let actions = g.actions();
            let premiere = actions.iter().position(|a| propres.contains(a));
            if let Some(p) = premiere {
                assert!(
                    actions[p..].iter().all(|a| propres.contains(a)),
                    "{} : une ligne commune après une ligne propre à un système",
                    g.titre()
                );
            }
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(Groupe::Optimiser.actions().last(), Some(&Action::OptimiserPerformance));
        assert!(Action::Signaler.disponible());
        assert_eq!(
            Action::LogicielsPerimes.disponible(),
            cfg!(any(windows, target_os = "macos"))
        );
    }

    /// Le test de la VM lit Defender en 4.10 : toujours là sous Windows, juste après les logiciels pas à jour.
    #[test]
    fn defender_toujours_en_4_10_sous_windows() {
        assert_eq!(
            touche_de(Action::Protection).as_deref(),
            cfg!(windows).then_some("4.10")
        );
        assert_eq!(
            touche_de(Action::LogicielsPerimes).as_deref(),
            cfg!(any(windows, target_os = "macos")).then_some("4.9")
        );
    }

    /// Aucun écran ne défile : un groupe ou un écran à choix fait au plus 15 lignes (cadre, aide et saisie compris,
    /// 24 rangées), comme le menu principal.
    #[test]
    fn chaque_sous_menu_tient_dans_24_lignes() {
        for g in GROUPES {
            let n = g.actions().len();
            assert!(n + 9 <= 24 || g.direct(), "{} : {n} lignes", g.titre());
        }
        for (ecran, variantes) in ECRANS {
            assert!(variantes.len() + 9 <= 24, "{}", ecran.outil().titre[0]);
        }
        // Dépanner : `depanner::tests::l_ecran_tient_dans_24_lignes`, avec ses deux outils.
    }

    /// Dépanner s'ouvre sur ses parcours, suivis de ses deux outils : `depanner_avec_ses_outils` sait lancer chacun.
    #[test]
    fn depanner_a_ses_deux_outils() {
        assert_eq!(
            Groupe::Depanner.actions(),
            [Action::Depanner, Action::Reparer, Action::Diagnostic]
        );
        assert_eq!(touche_de(Action::Reparer).as_deref(), Some("11.13"));
        assert_eq!(touche_de(Action::Diagnostic).as_deref(), Some("11.14"));
        assert_eq!(Groupe::Guide.actions(), [Action::Guide]);
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
        let places = places();
        for (chemin, a) in &places {
            assert!(outil_au_chemin(chemin) == Some(*a), "{chemin}");
        }
        // Chaque outil disponible a une place, une seule (sauf 1, 2, 3, au menu principal, et les deux groupes ouverts
        // directement).
        for o in OUTILS.iter().filter(|o| o.action.disponible()) {
            let n = places.iter().filter(|(_, a)| *a == o.action).count();
            let ailleurs = matches!(
                o.action,
                Action::Complet | Action::Corriger | Action::Rapport | Action::Guide | Action::Depanner
            );
            assert_eq!(n, usize::from(!ailleurs), "{}", o.titre[0]);
        }
        assert!(outil_au_chemin("4.99").is_none() && outil_au_chemin("x.1").is_none());
        assert!(outil_au_chemin("10.1").is_none(), "le guide a ses propres chemins");
        assert!(outil_au_chemin("11.1").is_none(), "le dépannage a ses propres chemins");
        assert!(depanner::chemin("1").is_some());
        // Les places de la conception (§ 2.5), citées par l'aide, le CHANGELOG et le test de la VM.
        for (chemin, action) in [
            ("4.1", Action::Audit),
            ("4.6", Action::Fiche),
            ("4.8.2", Action::Conteneurs),
            ("5.1.1", Action::Scanner),
            ("5.2", Action::AuditReseau),
            ("6.1.3", Action::AntivirusDossier),
            ("6.2", Action::LogicielsEspions),
            ("7.1", Action::Lien),
            ("8.1", Action::Blocage),
            ("8.8", Action::OptimiserAnnuler),
            ("8.9", Action::Signaler),
            ("9.1", Action::CopierFichiers),
            ("9.3.1", Action::VerifierSauvegarde),
            ("12.1", Action::Logiciels),
            ("12.10", Action::WifiCanaux),
            ("13.1", Action::Parametres),
            ("13.3", Action::MettreAJour),
            ("13.4.2", Action::Autotest),
            ("13.10", Action::Extensions),
            ("13.11", Action::Desinstaller),
        ] {
            assert!(outil_au_chemin(chemin) == Some(action), "{chemin}");
        }
        // Paramètres : en 13.1, et « s » au menu principal.
        assert!(OUTILS.iter().any(|o| o.action == Action::Parametres && o.lettre == "s"));
    }

    /// `--help` range chaque commande visible dans une rubrique du menu (aucune dans « Aussi »), et ses deux aides
    /// tiennent dans la largeur ; `-h` reste court.
    #[test]
    fn l_aide_cite_chaque_commande() {
        let rubriques = rubriques_de_l_aide();
        assert_eq!(rubriques.len(), 11, "bilan puis les dix groupes");
        let noms: Vec<&String> = rubriques.iter().flat_map(|(_, n)| n).collect();
        for (nom, _) in sous_commandes() {
            assert_eq!(
                noms.iter().filter(|n| ***n == nom).count(),
                1,
                "vanguard {nom} dans --help"
            );
        }
        for aide in [aide_longue(), aide_courte()] {
            for ligne in aide.lines() {
                assert!(largeur_affichee(ligne) <= LARGEUR, "{ligne}");
            }
        }
        assert!(aide_courte().lines().count() <= 15);
    }

    /// Le tableau « Toutes les commandes » du README suit les rubriques de `--help`, dans le même ordre.
    #[test]
    fn le_readme_suit_les_rubriques_de_l_aide() {
        let readme = lire("README.md");
        let tableau: Vec<String> = readme
            .lines()
            .filter_map(|l| l.strip_prefix("| `vanguard "))
            .filter_map(|l| l.split([' ', '`']).next().map(str::to_string))
            .collect();
        let aide: Vec<String> = rubriques_de_l_aide().into_iter().flat_map(|(_, n)| n).collect();
        assert_eq!(tableau, aide);
    }

    /// Un interrupteur se dit dans l'une ou l'autre langue ; « etat » ne change jamais rien.
    #[test]
    fn interrupteurs_dans_les_deux_langues() {
        for (mot, attendu) in [
            ("on", "on"),
            ("oui", "on"),
            ("Marche", "on"),
            ("off", "off"),
            ("non", "off"),
            ("arrêt", "off"),
            ("etat", "etat"),
            ("status", "etat"),
        ] {
            assert_eq!(interrupteur(mot).as_deref(), Ok(attendu), "{mot}");
        }
        assert!(interrupteur("peut-etre").is_err());
        assert_eq!(interrupteur_veilleur("ransomware").as_deref(), Ok("rancongiciel"));
        assert_eq!(interrupteur_wifi_public("portal").as_deref(), Ok("portail"));
        assert_eq!(sans_etat(Some("etat")), None);
        assert_eq!(sans_etat(Some("on")), Some("on"));
    }

    /// Chaque touche de l'index de recherche (outils, variantes, parcours, logiciels, réglages, guide) mène quelque
    /// part par `destination`, le même aiguillage que le menu et `vanguard chercher`.
    #[test]
    fn chaque_touche_de_l_index_s_ouvre() {
        for l in lignes_du_menu(Vec::new()) {
            let (Ligne::Choix { touche, .. } | Ligne::Cachee { touche, .. }) = &l else {
                continue;
            };
            if touche != "q" {
                assert!(destination(touche).is_some(), "« {touche} » ne mène nulle part");
            }
        }
        assert_eq!(destination("12.1.7"), Some(Destination::Logiciel(7)));
        assert_eq!(destination("zz"), None);
    }

    /// Les mots de la conception (§ 5.9) mettent leur cible dans les trois premiers résultats.
    #[test]
    fn la_recherche_trouve_ce_qu_on_attend() {
        let lignes = lignes_du_menu(Vec::new());
        let trois = |requete: &str| -> Vec<String> {
            selection::chercher(&lignes, requete)
                .0
                .into_iter()
                .take(3)
                .map(|t| t.touche)
                .collect()
        };
        let place = |a: Action| touche_de(a).unwrap();
        for (requete, cible) in [
            ("wifi public", place(Action::WifiPublic)),
            ("mot de passe", place(Action::MotsDePasse)),
            ("password", place(Action::MotsDePasse)),
            ("lent", "11.3".to_string()),
            ("imprimante", "11.5".to_string()),
            ("imprimnte", "11.5".to_string()),
            ("ransomware", place(Action::Pieges)),
            ("box", place(Action::Objets)),
            ("maj", place(Action::Maj)),
            ("sortantes", place(Action::QuiParle)),
        ] {
            assert!(
                trois(requete).contains(&cible),
                "« {requete} » : {:?}, attendu {cible}",
                trois(requete)
            );
        }
        let logiciels = format!("{}.", place(Action::Logiciels));
        assert!(
            trois("gimp").iter().any(|t| t.starts_with(&logiciels)),
            "{:?}",
            trois("gimp")
        );
        // Proton VPN et Mullvad VPN n'ont de paquet que sous Arch (et winget, Homebrew) : ailleurs, la recherche ne
        // propose pas un logiciel qu'elle ne saurait installer (`pour_ce_systeme`), la CI Ubuntu comprise.
        let vpn_ici = lignes.iter().any(|l| {
            matches!(l, Ligne::Cachee { touche, texte, .. } if touche.starts_with(&logiciels) && texte.contains("VPN"))
        });
        assert_eq!(
            trois("vpn").iter().any(|t| t.starts_with(&logiciels)),
            vpn_ici,
            "{:?}",
            trois("vpn")
        );
        #[cfg(windows)]
        assert!(trois("harden").contains(&"4.10".to_string()));
        assert!(
            !selection::chercher(&lignes, "imprimnte").1.is_empty(),
            "la faute est dite"
        );
    }

    /// Les commandes dites « en lecture » au guide existent, et celles qui changent quelque chose y sont marquées ⚠.
    #[test]
    fn le_guide_dit_ce_qui_change() {
        let commandes = sous_commandes();
        for nom in COMMANDES_EN_LECTURE {
            assert!(commandes.iter().any(|(n, _)| n == nom), "{nom}");
        }
        let marquee = |ligne: &str| {
            programmes_vanguard()
                .iter()
                .flat_map(|p| p.commandes.iter())
                .find(|c| c.ligne == ligne)
                .map(|c| c.modifie)
        };
        assert_eq!(marquee("vanguard corriger"), Some(true));
        assert_eq!(marquee("vanguard nettoyer"), Some(true));
        assert_eq!(marquee("vanguard audit"), Some(false));
        assert_eq!(place_de_commande("depanner").as_deref(), Some("11"));
        assert_eq!(place_de_commande("guide").as_deref(), Some("10"));
        assert_eq!(place_de_commande("bilan").as_deref(), Some("1"));
    }

    /// Les outils du menu qui n'ont pas de sous-commande, et pourquoi.
    const MENU_SEULEMENT: &[(Action, &str)] = &[
        (
            Action::ProtegerDonnees,
            "la phrase se tape et se confirme à l'écran, sur l'ordinateur du propriétaire",
        ),
        (
            Action::Developpeurs,
            "un écran à choix : secrets et conteneurs ont chacun leur commande",
        ),
        (
            Action::VerifierCopies,
            "un écran à choix : verifier-sauvegarde et verifier-copie",
        ),
        (Action::VerifierVanguard, "un écran à choix : verifier-moi et autotest"),
    ];

    /// Les sous-commandes sans outil du menu, et pourquoi.
    const LIGNE_DE_COMMANDE_SEULEMENT: &[(&str, &str)] = &[
        (
            "importer",
            "le menu Vanguard › Exporter ou importer les réglages propose aussi l'import",
        ),
        ("plugins", "le menu Extensions les liste et les lance"),
        ("labo", "le menu Extensions les liste et les lance"),
        (
            "protection",
            "l'état de tous les interrupteurs d'un coup ; chacun a aussi sa ligne dans son groupe",
        ),
        (
            "chercher",
            "la recherche de l'accueil (« Numéro, ou un mot à chercher »)",
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
