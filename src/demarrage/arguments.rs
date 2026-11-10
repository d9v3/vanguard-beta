//! La ligne de commande : les arguments et les sous-commandes (clap), et leur aide en français.

use crate::menu::outils::{interrupteur, interrupteur_veilleur, interrupteur_wifi_public};
use crate::{compte_rendu, deploiement};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about = "Cyberdéfense portable des postes et des réseaux : bilan, correctifs, réglages. Sans argument : la fenêtre \
             de Vanguard, ou le menu.",
    args_conflicts_with_subcommands = true
)]
pub(crate) struct Args {
    /// Le menu du terminal, même quand la fenêtre de Vanguard pourrait s'ouvrir.
    #[arg(long, visible_alias = "terminal")]
    pub(crate) menu: bool,
    #[command(subcommand)]
    pub(crate) commande: Option<Commande>,
}

#[derive(Subcommand)]
pub(crate) enum Commande {
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
    /// Audit de l'ordinateur puis application guidée des correctifs. Code de sortie : 0 tout ce qui a été accepté
    /// est fait (ou rien à faire), 1 une correction acceptée n'est pas faite (« N » ou Entrée dans la fenêtre
    /// administrateur, UAC refusée, échec), 2 des corrections refusées dans la liste (« n » ou Entrée), les autres
    /// faites. « i » (c'est normal chez moi) n'est pas un refus.
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
    /// Recherche de malwares : le moteur de Vanguard (empreintes, YARA, base ClamAV installée, heuristiques), avec
    /// clamscan en second avis sous Linux s'il est installé, ou Microsoft Defender d'abord sous Windows.
    Antivirus {
        /// Tout le dossier personnel au lieu des endroits à risque.
        #[arg(long, visible_alias = "full", conflicts_with = "etat")]
        complet: bool,
        /// L'état de l'antivirus, sans rien analyser : moteur, bases et leur date, ce qui n'est pas lu, choix du
        /// second avis et des PUA, temps réel des fichiers.
        #[arg(long, visible_alias = "status", conflicts_with = "dossier")]
        etat: bool,
        /// Avec --etat : lire toute la base ClamAV pour compter ce qu'elle a d'écarté (environ 10 secondes).
        #[arg(long, requires = "etat")]
        detail: bool,
        /// Une clé USB, un disque externe ou un dossier à analyser en entier.
        dossier: Option<std::path::PathBuf>,
        /// Le résultat en JSON, pour un script : l'analyse rapide (ou, avec --etat, l'état), sans question ; rien
        /// n'est mis en quarantaine, rien ne change, rien n'est téléchargé.
        #[arg(long, conflicts_with_all = ["complet", "dossier", "detail"])]
        json: bool,
    },
    /// Active ou désactive la surveillance horaire du réseau (notification si appareil inconnu).
    #[command(visible_alias = "monitor")]
    Surveillance {
        #[arg(value_parser = interrupteur, value_name = "on|off")]
        etat: String,
    },
    /// Tableau de bord dans le navigateur : la surveillance, le dernier bilan, la protection, les alertes, les nouveaux
    /// appareils, les connexions suspectes et toutes les fonctions du menu. Page locale, rien n'est envoyé.
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
        /// Le résultat en JSON, pour un script : rien ne change sur l'ordinateur ; le catalogue est relu en ligne
        /// s'il a plus d'un jour. Hors ligne, la copie gardée seule, sans rien croiser avec les paquets d'ici (dit non
        /// vérifié).
        #[arg(long)]
        json: bool,
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
    /// comme au bilan, et chaque fichier posé dans Téléchargements, le Bureau, ~/.local/bin ou ~/.config/autostart,
    /// examiné par le moteur de Vanguard ; avec la protection active et votre accord, il peut arrêter un malware connu à son lancement,
    /// et geler puis arrêter un rançongiciel quasi certain. Coupé par défaut. Sans argument : son état, puis l'allumer
    /// ou le couper, après accord. « connus on|off » règle l'arrêt du malware connu ; « rancongiciel on|off » la veille
    /// anti-rançongiciel des dossiers personnels ; « isolement on|off » l'isolement du réseau quand un rançongiciel
    /// est gelé.
    #[command(visible_alias = "watcher")]
    Veilleur {
        #[arg(value_parser = interrupteur_veilleur, value_name = "on|off|connus|rancongiciel|isolement")]
        etat: Option<String>,
        /// Pour « connus », « rancongiciel » ou « isolement » : on ou off.
        #[arg(value_parser = interrupteur, value_name = "on|off")]
        sous_etat: Option<String>,
        /// Le service lui-même, lancé par systemd.
        #[arg(long, hide = true)]
        servir: bool,
    },
    /// Garde des lancements (Linux) : un service système qui voit chaque programme lancé et compare son empreinte aux
    /// listes de programmes certainement malveillants ; posé en observation (rien n'est refusé, tout est noté), il ne
    /// refuse qu'après « refus », avec le mot de passe. Sans argument : son état et ses derniers événements. « on »
    /// le pose, « off » le retire, « maj » refait ses listes, « pause `<minutes>` », « permettre `<SHA-256>` ».
    /// Caché jusqu'au menu, au bilan et aux documents de L5.
    #[command(alias = "guard", hide = true)]
    Garde {
        #[arg(
            value_parser = ["etat", "on", "off", "maj", "update", "refus", "refuse", "observation", "observe", "pause", "permettre", "allow"],
            value_name = "etat|on|off|maj|refus|observation|pause|permettre"
        )]
        action: Option<String>,
        /// Pour « pause » : les minutes (0 la lève) ; pour « permettre » : l'empreinte SHA-256.
        argument: Option<String>,
    },
    /// Le garde des lancements lui-même, lancé par systemd en root (voir machine/linux/garde/servir.rs).
    #[command(name = "garde-servir", hide = true)]
    GardeServir,
    /// Entretien du mois : une fois par mois, en silence, la note, les mises à jour en attente, la place à libérer et
    /// les problèmes nouveaux, en une notification ; rien n'est changé. Sans argument : ce qu'il dirait maintenant.
    #[command(visible_alias = "maintenance")]
    Entretien {
        #[arg(value_parser = interrupteur, value_name = "on|off")]
        etat: Option<String>,
    },
    /// Mises à jour : système, programmes, pilotes et firmware vérifiés d'un coup, puis installés après accord.
    #[command(name = "mises-a-jour", visible_alias = "updates")]
    Maj {
        /// Les mises à jour en attente en JSON, pour un script : rien n'est installé ni demandé.
        #[arg(long)]
        json: bool,
    },
    /// Réparations courantes : réseau, navigation détournée, pare-feu, antivirus, fichiers système, disque, place, mises à jour, heure.
    #[command(visible_alias = "repair")]
    Reparer,
    /// Gaming : composants pour les jeux (Windows : Visual C++, DirectX… ; Linux : Steam, Vulkan, GameMode, Wine…) et
    /// réglages du système.
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
    /// Optimiser : les réglages recommandés, ceux de confidentialité, de performance et de confort, chacun
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
    Canaux {
        /// Le résultat en JSON, pour un script : rien n'est demandé ni changé.
        #[arg(long)]
        json: bool,
    },
    /// Type de NAT pour le jeu (ouvert, modéré ou strict), d'après deux serveurs publics (STUN). Lecture seule.
    Nat {
        /// Le résultat en JSON, pour un script : rien n'est demandé ni changé.
        #[arg(long)]
        json: bool,
    },
    /// Caméras cachées : sur le réseau d'une location ou de quelqu'un, les appareils qui ressemblent à des caméras.
    /// Lecture seule.
    #[command(name = "cameras-cachees", visible_alias = "hidden-cameras")]
    Cameras {
        /// Le résultat en JSON, pour un script : rien n'est demandé ni changé.
        #[arg(long)]
        json: bool,
    },
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
        /// La comparaison en JSON, pour un script : rien n'est demandé ni écrit, et sans référence aucune n'est posée.
        #[arg(long, conflicts_with_all = ["accepter", "temps_reel"])]
        json: bool,
    },
    /// Fichiers-pièges contre les rançongiciels : les poser (après accord), voir s'ils sont intacts, ou les retirer.
    #[command(visible_alias = "decoys")]
    Pieges {
        /// Retirer les fichiers-pièges posés.
        #[arg(long, visible_alias = "remove")]
        retirer: bool,
    },
    /// Analyse YARA : 308 règles de familles de logiciels malveillants (ReversingLabs) et les empreintes de
    /// MalwareBazaar, en complément de l'antivirus. Sans dossier : téléchargements, bureau, démarrage. Lecture seule.
    Yara {
        /// Tout le dossier personnel au lieu des endroits à risque.
        #[arg(long, visible_alias = "full")]
        complet: bool,
        /// Une clé USB, un disque externe ou un dossier à analyser en entier.
        dossier: Option<std::path::PathBuf>,
        /// Le résultat en JSON, pour un script : les endroits à risque, sans question ; rien n'est mis en
        /// quarantaine, rien ne change, rien n'est téléchargé.
        #[arg(long, conflicts_with_all = ["complet", "dossier"])]
        json: bool,
    },
    /// Mémoire des processus en marche passée aux 308 règles YARA : un logiciel malveillant sans fichier ne vit que
    /// là. Lecture seule, à la demande ; LSASS et processus protégés : leur mémoire n'est jamais lue ; rien n'est
    /// gardé.
    #[command(visible_alias = "memory")]
    Memoire {
        /// Le résultat en JSON, pour un script : rien ne change.
        #[arg(long)]
        json: bool,
    },
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
    /// Vérifier un fichier téléchargé : empreinte comparée à celle du site, nom et contenu, moteur de Vanguard et
    /// antivirus du système.
    #[command(name = "verifier-fichier", visible_alias = "check-file")]
    VerifierFichier {
        /// Le fichier téléchargé.
        fichier: std::path::PathBuf,
        /// L'empreinte publiée par le site (SHA-256 de préférence). Sinon : un SHA256SUMS ou .sha256 à côté.
        empreinte: Option<String>,
        /// Le résultat en JSON, pour un script : rien n'est demandé ; l'antivirus du système n'est pas lancé (dit non
        /// vérifié), le moteur de Vanguard l'est, son verdict à part.
        #[arg(long)]
        json: bool,
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
    /// Logiciels espions : serveurs et sites connus (liste d'Échap), programmes qui lisent le clavier, logiciels de
    /// surveillance connus. Lecture seule.
    #[command(name = "logiciels-espions", visible_alias = "spyware")]
    LogicielsEspions {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
    /// Logiciels pas à jour (Windows) : navigateurs, Office, Acrobat, Java, 7-Zip, PuTTY, Slack comparés à leur
    /// dernière version ; failles exploitées. Lecture seule.
    #[command(name = "logiciels-perimes", visible_alias = "outdated-software")]
    LogicielsPerimes {
        /// Le résultat en JSON, pour un script.
        #[arg(long)]
        json: bool,
    },
    /// Options de défense de Windows : Microsoft Defender (mode, temps réel, cloud, protection contre les
    /// falsifications, chaque option), exclusions, règles ASR, Pare-feu Windows par profil, stratégies (GPO, Intune)
    /// qui imposent une valeur, antivirus tiers, PC géré. Sous Linux : le pare-feu (ufw, firewalld, nftables), allumé
    /// ou coupé. Chaque option se choisit, ce qu'une baisse change est dit ; rien n'est changé sans être montré, puis
    /// confirmé (fenêtre administrateur, ou question [o/N] de Vanguard administrateur sous Linux).
    #[command(name = "options-defense", visible_aliases = ["defense-options", "defender"])]
    OptionsDefense {
        /// Le résultat en JSON, pour un script (sans chemin, nom de compte ni nom de machine).
        #[arg(long)]
        json: bool,
        /// Un choix de Defender ou du pare-feu (pua bloquer, asr-GUID audit, pare-feu-prive-actif non… ; sous Linux,
        /// pare-feu-ufw coupe…), montré puis fait en administrateur ; une baisse y est confirmée par un oui tapé, sa
        /// valeur d'avant notée.
        #[arg(long, visible_alias = "choose", num_args = 2, value_names = ["ID", "VALEUR"], conflicts_with_all = ["json", "rallumer", "exclure", "permettre", "noter"])]
        choisir: Option<Vec<String>>,
        /// Remet un réglage : la valeur d'avant notée si elle protège, sinon la valeur sûre (sous Linux,
        /// pare-feu-ufw, pare-feu-firewalld ou pare-feu-nftables : l'état noté avant la coupure).
        #[arg(long, visible_alias = "turn-back-on", value_name = "ID", conflicts_with_all = ["json", "exclure", "permettre", "noter"])]
        rallumer: Option<String>,
        /// Une exclusion de l'analyse (dossier, programme ou type, puis le texte), montrée puis confirmée dans la
        /// fenêtre administrateur comme une baisse.
        #[arg(long, visible_alias = "exclude", num_args = 2, value_names = ["GENRE", "TEXTE"], conflicts_with_all = ["json", "permettre", "noter"])]
        exclure: Option<Vec<String>>,
        /// Un programme permis malgré l'accès contrôlé aux dossiers, montré puis confirmé comme une baisse.
        #[arg(long, visible_alias = "allow", value_name = "PROGRAMME", conflicts_with_all = ["json", "noter"])]
        permettre: Option<String>,
        /// « C'est moi » : une valeur baissée hors de Vanguard, notée « par votre choix » (même question qu'une
        /// baisse) ; le bilan cesse d'alerter.
        #[arg(long, visible_alias = "note", value_name = "ID", conflicts_with = "json")]
        noter: Option<String>,
        /// Remet ce qu'une correction du registre a noté (smartscreen, hvci, maj-pause… ou `service:<nom>` pour le
        /// chemin d'un service) : une baisse, montrée puis confirmée dans la fenêtre administrateur.
        #[arg(long, visible_alias = "put-back", value_name = "MOT", conflicts_with_all = ["json", "choisir", "rallumer", "exclure", "permettre", "noter"])]
        remettre: Option<String>,
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
    Secrets {
        /// Le résultat en JSON, pour un script : le genre, le fichier, la ligne et le commit de chaque secret, jamais
        /// le secret lui-même ; rien ne change.
        #[arg(long)]
        json: bool,
    },
    /// Failles connues des images Docker ou Podman de cet ordinateur, par trivy s'il est installé. Lecture seule.
    #[command(visible_alias = "containers")]
    Conteneurs {
        /// Le résultat en JSON, pour un script : rien n'est demandé ni changé.
        #[arg(long)]
        json: bool,
    },
    /// Paramètres : tous les réglages de Vanguard (langue, emojis, travail sans Internet, protection en temps réel,
    /// surveillance, entretien, alertes apprises, blocage, restrictions des extensions, clé abuse.ch, second avis de
    /// ClamAV, programmes indésirables (PUA), versions des logiciels, autodiagnostic de la semaine, paquets de l'AUR, Agent Vanguard, partage avec l'auteur). Sans
    /// argument : leur état ; avec un réglage et une valeur : le change, la valeur d'avant montrée pour revenir.
    /// « temps-reel non --pendant 1h|4h » coupe la protection en temps réel de Vanguard pour ce temps (sans
    /// --pendant : jusqu'à reprise), après accord ; jamais Defender, le pare-feu ni l'UAC.
    #[command(visible_alias = "settings")]
    Parametres {
        /// Un réglage (langue, emojis, sans-internet, temps-reel, surveillance, entretien, appris, blocage,
        /// restrictions, abuse.ch, second-avis, pua, versions-logiciels, autotest, paquets-aur, auto-reglage, partage) et sa valeur ; temps-reel non prend aussi --pendant 1h ou 4h.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        quoi: Vec<String>,
    },
    /// Blocage des menaces : chaque menace trouvée propose « Bloquer » (le geste montré, accepté, noté, annulable) ;
    /// la protection active, après un accord donné une fois, bloque toute seule le certain (empreinte de
    /// MalwareBazaar, outil d'attaque connu, serveur de commande), puis prévient. Sans argument : le menu.
    #[command(visible_alias = "blocking")]
    Blocage {
        /// « chercher », « annuler », « etat », « auto » ou « clic » (la protection active), une catégorie
        /// (programmes, connexions, demarrage, agents) suivie d'un mode (off, clic, auto), ou « juger » un PID,
        /// « parent » ou un fichier (ce que le blocage refuserait, et pourquoi, sans rien faire), « suspendre » un PID
        /// (réversible) ou « reprendre » (un PID, ou tous ceux que Vanguard a suspendus), « couper-reseau » un PID
        /// (réversible) ou « rendre-reseau » (un PID, ou tous ceux que Vanguard a coupés), « isoler » (l'ordinateur
        /// coupé du réseau, sauf la session à distance en cours) ou « lever-isolement ».
        quoi: Vec<String>,
    },
    /// Une alerte notifiée, par l'identifiant que donne sa notification : l'alerte est relue dans le journal scellé,
    /// la menace cherchée de nouveau et rejugée, puis ses gestes proposés (bloquer, suspendre, surveiller de plus
    /// près, faire confiance, ignorer). Rien d'autre que l'identifiant n'est pris de la ligne de commande.
    #[command(visible_alias = "alert")]
    Alerte {
        /// L'identifiant de l'alerte, tel que la notification le donne (vanguard evenements les montre aussi).
        id: String,
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
    /// Guide des commandes : celles d'Omarchy, d'Arch, de Fedora, de Debian, des autres Linux, de Windows et de
    /// tous les systèmes, rangées par programme, avec des marches à suivre ; et les exemples de tldr-pages,
    /// téléchargés chaque semaine.
    Guide {
        /// Un système (omarchy, arch, fedora, debian, windows, tous ; linux : les programmes communs ; tldr ;
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
    Demarrage {
        /// La liste jugée en JSON, pour un script : rien n'est retiré ni demandé. Avec --retirer ou --remettre :
        /// l'issue en une ligne JSON, la dernière.
        #[arg(long)]
        json: bool,
        /// Retirer du démarrage le seul programme de cette empreinte (32 chiffres hexadécimaux, donnée par --json) :
        /// un programme ordinaire qui se lance, jamais un programme à garder ni un pare-feu. Il reste installé.
        #[arg(
            long,
            visible_alias = "remove",
            value_name = "EMPREINTE",
            conflicts_with = "remettre"
        )]
        retirer: Option<String>,
        /// Remettre exactement comme avant le programme de cette empreinte que Vanguard a retiré (d'après sa note).
        #[arg(long, visible_alias = "put-back", value_name = "EMPREINTE")]
        remettre: Option<String>,
    },
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
    /// sur toute la sauvegarde comparés à leur original ; pour Déjà Dup et l'Historique des fichiers,
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
    Changements {
        /// L'historique en JSON, pour un script : les plus récents, sans rien proposer d'annuler ; rien ne change.
        #[arg(long)]
        json: bool,
    },
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
    /// Sauvegarde automatique : mise en place avec l'outil du système (Déjà Dup ou rsync chaque jour, Historique
    /// des fichiers) vers un disque externe, après accord, annulable exactement.
    #[command(name = "sauvegarde-auto", visible_alias = "auto-backup")]
    SauvegardeAuto {
        /// Retirer la sauvegarde automatique mise en place par Vanguard (les fichiers sauvegardés restent).
        #[arg(long, visible_alias = "undo")]
        annuler: bool,
    },
    /// Raccourci sur cet ordinateur : Vanguard copié ici et lancé d'un clic (menu des applications sous Linux, Bureau
    /// sous Windows). Sans argument : l'état, puis la proposition.
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
    Regles {
        /// La liste en JSON, pour un script : rien ne change.
        #[arg(long)]
        json: bool,
    },
    /// Autodiagnostic : Vanguard vérifie ses propres lectures sur cet ordinateur. Chaque règle du bilan sous garde et
    /// délai, en lecture seule prouvée (empreintes avant et après), et ses lectures comparées à celles des outils du
    /// système (pacman, systemctl, ss, PowerShell…). Rien n'est changé ; hors ligne sauf --internet ; un écart va au
    /// journal des erreurs, sans aucune valeur de l'ordinateur. Code de sortie : 0 sain, 1 écart, 2 non vérifié.
    #[command(visible_alias = "self-test")]
    Autotest {
        /// Le rapport en JSON, pour un script (sans aucune valeur lue sur l'ordinateur).
        #[arg(long, conflicts_with = "detail")]
        json: bool,
        /// Le compte rendu pour Claude en JSON : une cause par écart, avec ses identifiants (format de la veille de
        /// nuit, sans aucune valeur lue sur l'ordinateur).
        #[arg(long = "compte-rendu", visible_alias = "report-for-claude", conflicts_with_all = ["detail", "json"])]
        compte_rendu: bool,
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
        /// Le résultat en JSON, pour un script : sans question, donc sans l'historique signé (qui demande un accord),
        /// dit non comparé ; ce qui n'a pas pu être vérifié est dit, rien ne change.
        #[arg(long)]
        json: bool,
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
    /// L'Agent Vanguard (sans IA), en lecture seule : ses missions (délais, cache, relevé local, avis sur les
    /// corrections), leur dernier tour et son journal, sans aucune donnée personnelle. Rien n'est changé ni envoyé.
    /// Ses interrupteurs sont dans Paramètres (« parametres auto-reglage »).
    Agent {
        /// La vue en JSON (schéma 1) : rien d'autre que des noms fermés, des identifiants de règle, des nombres et des
        /// dates.
        #[arg(long)]
        json: bool,
    },
    /// Les comptes rendus pour Claude, lus par la veille de nuit (outils/veille/) : seulement des champs validés.
    #[command(name = "compte-rendu", hide = true)]
    CompteRendu {
        #[command(subcommand)]
        quoi: compte_rendu::Quoi,
    },
    /// Entretien silencieux + notification (utilisé par le planificateur, une fois par mois).
    #[command(hide = true)]
    Entretenir,
    /// Windows : le processus élevé qui applique les corrections natives (lancé par Vanguard lui-même, après la
    /// demande d'administrateur ; voir machine/windows/eleve.rs).
    #[command(name = "appliquer-eleve", hide = true)]
    /// Linux : l'assistant élevé qui fait les ordres du blocage (lancé par Vanguard lui-même, par pkexec, run0
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
