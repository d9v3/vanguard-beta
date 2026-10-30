//! Ce que l'aperçu des menus dit de chaque outil et de chaque groupe, sous son titre et à côté de son sous-menu
//! (`selection::apercu`) : ce qu'il fait concrètement, et s'il ne fait que lire ou change quelque chose. Sans `_` :
//! un outil ajouté sans sa description ne compile pas.

use crate::{Action, Groupe, tr};

impl Action {
    pub(crate) fn description(self) -> &'static str {
        match self {
            Action::Complet => tr!(
                "Vérifie cet ordinateur puis votre réseau, et donne une note à chacun. Ne corrige rien (choix 2) ; seuls les blocages réglés d'avance s'appliquent.",
                "Checks this computer, then your network, and grades each. Fixes nothing (choice 2); only blocking set up beforehand applies."
            ),
            Action::Corriger => tr!(
                "Reprend les problèmes du dernier bilan et montre chaque correction avant de la faire. Chacune est notée ; celles qui le peuvent s'annulent.",
                "Takes the problems from the last check and shows each fix before applying it. Each is logged; those that can be are undoable."
            ),
            Action::Rapport => tr!(
                "Écrit une page HTML autonome du dernier bilan et l'ouvre ; sans bilan, il le lance d'abord. Rien n'est envoyé.",
                "Writes a self-contained HTML page of the last check and opens it; with no check yet, runs one first. Nothing is sent."
            ),
            Action::Audit => tr!(
                "Vérifie les réglages de sécurité de cet ordinateur et lui donne une note. Ne change rien : les corrections passent par « Corriger ».",
                "Checks this computer's security settings and grades it. Changes nothing: fixes go through “Fix the problems found”."
            ),
            Action::Maj => tr!(
                "Cherche d'un coup les mises à jour en attente, puis installe celles que vous acceptez.",
                "Looks for all pending updates at once, then installs the ones you accept."
            ),
            Action::DernieresFailles => tr!(
                "Les failles dont une attaque réelle est connue, ajoutées récemment ; celles utilisées par des rançongiciels sont signalées. Lecture seule.",
                "Flaws with a known real-world attack, added recently; those used by ransomware are flagged. Read-only."
            ),
            Action::Integrite => tr!(
                "Prend l'empreinte des fichiers sensibles au premier passage, puis dit ce qui a été modifié, ajouté ou supprimé depuis. Ne change rien.",
                "Fingerprints sensitive files on the first run, then shows what was modified, added or deleted since. Changes nothing."
            ),
            Action::Entretien => tr!(
                "Une notification par mois : note, mises à jour en attente, place à libérer, problèmes nouveaux. Rien n'est changé. La ligne l'active ou le coupe.",
                "One notification a month: grade, pending updates, space to free, new problems. Nothing is changed. The line turns it on or off."
            ),
            Action::Fiche => tr!(
                "Ce qu'on demande au téléphone ou pour acheter une pièce : carte mère, carte graphique, disques, système. Lecture seule.",
                "What you are asked on the phone or to buy a part: motherboard, graphics card, disks, system. Read-only."
            ),
            Action::ALaisser => tr!(
                "Une page en mots simples : la note, ce qui reste à faire, trois bonnes habitudes. Posée sur le Bureau après accord, sans nom ni adresse.",
                "A page in plain words: the grade, what is left to do, three good habits. Saved to the Desktop with consent, with no names or addresses."
            ),
            Action::Developpeurs => tr!(
                "Deux analyses pour qui programme : les secrets restés dans l'historique git et les failles des images de conteneurs. Rien n'est changé.",
                "Two scans for programmers: secrets left in git history and flaws in container images. Nothing is changed."
            ),
            Action::SecretsGit => tr!(
                "Relit l'historique des dépôts git du dossier personnel. Seuls le fichier, la ligne, le genre et le commit sont montrés, jamais le secret.",
                "Reads the history of git repositories in your home folder. Only the file, line, kind and commit are shown, never the secret."
            ),
            Action::Conteneurs => tr!(
                "Si trivy est installé, liste les failles graves ou critiques des paquets de chaque image Docker ou Podman. Lecture seule.",
                "If trivy is installed, lists the serious or critical flaws in the packages of each Docker or Podman image. Read-only."
            ),
            Action::LogicielsPerimes => tr!(
                "Compare la version installée des navigateurs, d'Office, d'Acrobat, de Java et d'autres logiciels courants à la dernière publiée. Lecture seule.",
                "Compares the installed version of browsers, Office, Acrobat, Java and other common software with the latest release. Read-only."
            ),
            Action::Protection => tr!(
                "Des blocages supplémentaires de Defender, appliqués après accord et annulables ; proposés seulement si Defender est l'antivirus actif.",
                "Extra Defender blocking, applied with your consent and undoable; offered only if Defender is the active antivirus."
            ),
            Action::Appareils => tr!(
                "Trouve les appareils branchés à votre réseau et leurs ports ouverts : tout le réseau d'un coup, ou un seul appareil en profondeur.",
                "Finds the devices on your network and their open ports: the whole network at once, or one device in depth."
            ),
            Action::Scanner => tr!(
                "Cherche les appareils du réseau local, teste leurs ports courants et compare au scan précédent. Sans droits d'administrateur.",
                "Finds the devices on the local network, tests their common ports and compares with the previous scan. No admin rights needed."
            ),
            Action::Appareil => tr!(
                "Teste les 65 535 ports TCP d'un seul appareil, dont vous donnez l'adresse IP. Rien n'y est changé.",
                "Tests all 65,535 TCP ports of a single device, whose IP address you give. Nothing on it is changed."
            ),
            Action::AuditReseau => tr!(
                "Note votre réseau dans six domaines à partir d'un scan. Observe seulement : aucune attaque ni aucun essai de mot de passe.",
                "Grades your network in six areas from a scan. It only observes: no attack and no password attempts."
            ),
            Action::Nommer => tr!(
                "Donne un surnom à un appareil, par son adresse IP ou MAC, gardé dans la base des appareils de Vanguard. Un surnom vide le retire.",
                "Gives a device a nickname, by its IP or MAC address, kept in Vanguard's device database. An empty nickname removes it."
            ),
            Action::Objets => tr!(
                "Ce que le scan sait déjà de la box et des objets du réseau, avec des conseils. Rien n'est sondé en plus, aucun mot de passe essayé.",
                "What the scan already knows about the router and smart devices, with advice. Nothing more is probed, no password is tried."
            ),
            Action::Cameras => tr!(
                "Cherche sur le réseau les appareils qui ressemblent à des caméras : fabricant, flux vidéo, ONVIF. Aucune image n'est lue.",
                "Looks on the network for devices that look like cameras: maker, video stream, ONVIF. No image is viewed."
            ),
            Action::ListesNoires => tr!(
                "Interroge quatre listes publiques (Spamhaus, SpamCop…) sur l'adresse publique de la maison, après accord, car elles la voient.",
                "Queries four public lists (Spamhaus, SpamCop…) about your home's public address, with consent, since they see it."
            ),
            Action::Surveillance => tr!(
                "Scanne le réseau chaque heure et prévient si un appareil inconnu arrive ou si un programme parle à un botnet. La ligne l'active ou la coupe.",
                "Scans the network every hour and alerts you if an unknown device appears or a program talks to a botnet. The line turns it on or off."
            ),
            Action::Tableau => tr!(
                "Écrit une page sur cet ordinateur et l'ouvre dans le navigateur : l'historique de la surveillance horaire. Rien n'est envoyé.",
                "Writes a page on this computer and opens it in the browser: the history of hourly monitoring. Nothing is sent."
            ),
            Action::WifiPublic => tr!(
                "Ferme les entrées de l'ordinateur, coupe le partage et pose un DNS protecteur. Chaque changement est montré ; l'extinction remet tout.",
                "Closes the computer's inbound access, turns off sharing and sets a protective DNS. Each change is shown; turning it off restores all."
            ),
            Action::Antivirus => tr!(
                "Cherche les logiciels malveillants avec ClamAV (Linux, macOS) ou Microsoft Defender (Windows), ou avec les règles YARA intégrées.",
                "Looks for malware with ClamAV (Linux, macOS) or Microsoft Defender (Windows), or with the built-in YARA rules."
            ),
            Action::AntivirusRapide => tr!(
                "Analyse les endroits où arrivent les menaces, puis montre ce qui se lance au démarrage. Un fichier détecté : quarantaine ou suppression, au choix.",
                "Scans where threats arrive, then shows what runs at startup. A detected file: quarantine or delete, your choice."
            ),
            Action::AntivirusComplet => tr!(
                "Plus long que l'analyse rapide. Si un fichier est détecté, vous choisissez : quarantaine réversible, suppression ou rien.",
                "Takes longer than the quick scan. If a file is detected, you choose: reversible quarantine, delete, or nothing."
            ),
            Action::AntivirusDossier => tr!(
                "Analyse la clé ou le dossier choisi, puis cherche à sa racine les pièges des vers de clé USB : autorun.inf, raccourcis, scripts.",
                "Scans the chosen drive or folder, then checks its root for USB worm traps: autorun.inf, shortcuts, scripts."
            ),
            Action::Yara => tr!(
                "Applique les règles de ReversingLabs au dossier choisi et compare chaque fichier aux empreintes de MalwareBazaar. Rien n'est déplacé.",
                "Applies the ReversingLabs rules to the chosen folder and checks each file against MalwareBazaar hashes. Nothing is moved."
            ),
            Action::LogicielsEspions => tr!(
                "Cherche les signes d'un logiciel espion posé par un proche. Rien n'est retiré : celui qui l'a posé le verrait ; l'écran dit qui appeler.",
                "Looks for signs of spyware planted by someone close. Nothing is removed, as whoever planted it would notice; the screen says who to call."
            ),
            Action::QuiParle => tr!(
                "Les connexions vers Internet, par programme, avec le nom du serveur ; ce qui est suspect est signalé. Rien n'est coupé ni bloqué.",
                "Connections to the Internet, by program, with the server's name; anything suspicious is flagged. Nothing is cut off or blocked."
            ),
            Action::Memoire => tr!(
                "Applique les règles YARA à la mémoire des programmes en marche, où se cache un logiciel malveillant sans fichier. Aucun processus n'est touché.",
                "Applies YARA rules to the memory of running programs, where fileless malware hides. No process is touched."
            ),
            Action::Pieges => tr!(
                "Pose deux leurres dans Documents, Images et Bureau ; chaque bilan et la surveillance horaire les vérifient. Posés et retirés après accord.",
                "Places two decoys in Documents, Pictures and Desktop; each check and hourly monitoring verify them. Placed and removed with consent."
            ),
            Action::VerifierFichier => tr!(
                "Compare son empreinte à celle publiée par le site, repère un programme déguisé en document, puis l'analyse. Rien n'est déplacé.",
                "Compares its checksum with the one the site publishes, spots a program disguised as a document, then scans it. Nothing is moved."
            ),
            Action::Bac => tr!(
                "Lance le programme à l'écart avec l'outil du système (bubblewrap, Windows Sandbox, sandbox-exec). Votre dossier personnel lui est caché.",
                "Runs the program apart using the system's tool (bubblewrap, Windows Sandbox, sandbox-exec). Your home folder is hidden from it."
            ),
            Action::Quarantaine => tr!(
                "Les fichiers isolés par l'antivirus ou YARA ; celui que vous choisissez revient à sa place, avec ses permissions, sans rien écraser.",
                "Files isolated by the antivirus or YARA; the one you pick goes back to its place, with its permissions, without overwriting anything."
            ),
            Action::Lien => tr!(
                "Repère les pièges d'un lien collé : fausse marque, lettres imitées, raccourcisseur. Après accord, seul le nom de domaine est vérifié en ligne.",
                "Spots the traps in a pasted link: fake brand, look-alike letters, shortener. With consent, only the domain name is checked online."
            ),
            Action::CourrielSuspect => tr!(
                "Lit un courriel enregistré (.eml) : vrai expéditeur, SPF, DKIM, DMARC, liens et pièces jointes. Aucun lien suivi, rien d'exécuté.",
                "Reads a saved email (.eml): real sender, SPF, DKIM, DMARC, links and attachments. No link followed, nothing run."
            ),
            Action::Distance => tr!(
                "Cherche AnyDesk, TeamViewer, RustDesk et les autres, installés ou en marche, et les retire après accord ; un programme en marche en demande un second.",
                "Looks for AnyDesk, TeamViewer, RustDesk and others, installed or running, and removes them with consent; a running one needs a second consent."
            ),
            Action::MotsDePasse => tr!(
                "Tapez un mot de passe : seuls 5 caractères de son empreinte partent vers Have I Been Pwned, et la comparaison se fait ici.",
                "Type a password: only 5 characters of its hash go to Have I Been Pwned, and the comparison happens here."
            ),
            Action::Navigateurs => tr!(
                "Dans Firefox, Chrome, Edge, Brave et les autres : combien de mots de passe sont enregistrés, et ce qui les protège ou non.",
                "In Firefox, Chrome, Edge, Brave and others: how many passwords are saved, and what protects them or not."
            ),
            Action::Courriel => tr!(
                "Cherche votre adresse dans les fuites connues (XposedOrNot, ou Have I Been Pwned avec une clé). L'adresse elle-même est envoyée au service.",
                "Looks up your address in known leaks (XposedOrNot, or Have I Been Pwned with a key). The address itself is sent to the service."
            ),
            Action::CameraMicro => tr!(
                "Windows : qui s'en est servi, et quand. Linux : qui s'en sert en ce moment. macOS : où le voir. Lecture seule.",
                "Windows: who used them, and when. Linux: who is using them right now. macOS: where to look. Read-only."
            ),
            Action::Acces => tr!(
                "Les applications autorisées et, si le système le note, leur dernière utilisation. Lecture seule : la marche à suivre pour retirer est donnée.",
                "Apps with permission and, when the system records it, their last use. Read-only: the steps to revoke are given."
            ),
            Action::Blocage => tr!(
                "Règle, par catégorie, ce que Vanguard bloque : rien sans votre clic, ou le certain tout seul. Chaque blocage est noté et s'annule.",
                "Sets, by category, what Vanguard blocks: nothing without your click, or what is certain on its own. Each block is logged and undoable."
            ),
            Action::SitesDangereux => tr!(
                "Ajoute au fichier hosts les sites malveillants d'URLhaus et de ThreatFox. Après accord, en administrateur ; se retire exactement.",
                "Adds URLhaus and ThreatFox malicious sites to the hosts file. With consent, as administrator; removed exactly."
            ),
            Action::DepannerInfection => tr!(
                "Garder les traces, faire ce qui presse, laisser Vanguard vérifier, puis changer les mots de passe dans l'ordre. Rien sans accord.",
                "Keep the evidence, do what is urgent, let Vanguard check, then change passwords in order. Nothing without consent."
            ),
            Action::DepannerCompte => tr!(
                "Reprendre la main par la page officielle, puis mot de passe, deux étapes, sessions ; Vanguard vérifie que cet ordinateur n'est pas la cause.",
                "Regain control through the service's official page, then password, two-step, sessions; Vanguard checks this computer is not the cause."
            ),
            Action::Traces => tr!(
                "Enregistre processus, connexions, démarrage, comptes et journaux de 7 jours dans un dossier, avec leurs empreintes. Rien n'est arrêté ni déplacé.",
                "Saves processes, connections, startup items, accounts and 7 days of logs to a folder, with their hashes. Nothing is stopped or moved."
            ),
            Action::Evenements => tr!(
                "Le journal commun de Vanguard, avec l'état de sa chaîne : un journal modifié se lit quand même, mais il est dit non vérifié.",
                "Vanguard's shared log, with the state of its chain: a tampered log is still shown, but marked unverified."
            ),
            Action::Changements => tr!(
                "Les corrections lancées après accord, avec leurs commandes et leur résultat ; celles qui le peuvent s'annulent une à une.",
                "Fixes run with your consent, with their commands and result; those that can be are undone one by one."
            ),
            Action::OptimiserAnnuler => tr!(
                "Défait corrections, réglages, blocages et mode Wi-Fi public, du plus récent au plus ancien, après un seul accord. Ce qui ne revient pas est dit.",
                "Undoes fixes, settings, blocks and public Wi-Fi mode, newest first, after a single consent. Anything that does not come back is reported."
            ),
            Action::Signaler => tr!(
                "Trie votre cas, puis prépare un brouillon au format de l'éditeur (Microsoft, Google, Mozilla, Apple…) dans un fichier, à soumettre vous-même.",
                "Sorts out your case, then drafts a report in the vendor's format (Microsoft, Google, Mozilla, Apple…) in a file, for you to submit."
            ),
            Action::JournauxWindows => tr!(
                "Cherche les signes d'attaque dans les journaux d'événements des 7 derniers jours. Hors de Windows, lit un dossier de fichiers .evtx.",
                "Looks for signs of attack in the last 7 days of event logs. Outside Windows, reads a folder of .evtx files."
            ),
            Action::Veilleur => tr!(
                "Voit chaque programme lancé et chaque connexion fermée, même brefs, entre deux passes de la surveillance. Observe seulement ; posé après accord.",
                "Sees every program started and every connection closed, even brief ones, between monitoring passes. Only observes; set up with consent."
            ),
            Action::CopierFichiers => tr!(
                "Copie Documents, Images, Bureau, Vidéos et Musique dans un dossier daté, puis relit chaque fichier. Rien n'est effacé ni écrasé.",
                "Copies Documents, Pictures, Desktop, Videos and Music to a dated folder, then reads each file back. Nothing is deleted or overwritten."
            ),
            Action::SauvegardeAuto => tr!(
                "Met en place l'outil du système (Déjà Dup ou rsync, Time Machine ; guidé sous Windows), après accord. S'annule exactement.",
                "Sets up the system's tool (Déjà Dup or rsync, Time Machine; guided on Windows), with your consent. Undone exactly."
            ),
            Action::VerifierCopies => tr!(
                "Relit une copie ou la sauvegarde sur le disque et compare des fichiers à leurs originaux. Rien n'est écrit ni effacé.",
                "Reads a copy or the backup back from disk and compares files with their originals. Nothing is written or deleted."
            ),
            Action::VerifierSauvegarde => tr!(
                "Relit des fichiers répartis dans la sauvegarde mise en place par Vanguard et les compare à leurs originaux. Rien n'est écrit ni effacé.",
                "Reads back files spread across the backup Vanguard set up and compares them with the originals. Nothing is written or deleted."
            ),
            Action::VerifierCopie => tr!(
                "Test de restauration : des fichiers de la copie sont relus sur le disque, sans le cache, et comparés. Rien n'est écrit ni effacé.",
                "Restore test: files from the copy are read back from disk, bypassing the cache, and compared. Nothing is written or deleted."
            ),
            Action::VerifierCle => tr!(
                "Écrit des fichiers d'essai dans l'espace libre (tout, en mode complet) puis les relit pour démasquer une fausse clé ou une clé qui meurt. Après accord ; les fichiers d'essai sont effacés à la fin.",
                "Writes test files to the free space (all of it, in full mode), then reads them back to unmask a fake or dying drive. With consent; the test files are deleted at the end."
            ),
            Action::Guide => tr!(
                "Les commandes utiles de chaque système, rangées par programme et expliquées ; une commande qui ne fait que lire peut se lancer ici.",
                "Useful commands for each system, sorted by program and explained; a command that only reads can be run here."
            ),
            Action::Depanner => tr!(
                "Pour une panne courante : quelques questions, Vanguard vérifie ce qu'il peut, puis propose la bonne réparation. Rien sans accord.",
                "For a common problem: a few questions, Vanguard checks what it can, then offers the right repair. Nothing without consent."
            ),
            Action::Reparer => tr!(
                "Chaque réparation est montrée (pourquoi, durée, commandes), puis lancée après accord, avec un point de restauration si le système change.",
                "Each repair is shown (why, duration, commands), then run with consent, with a restore point if the system is changed."
            ),
            Action::Diagnostic => tr!(
                "Matériel, système et problèmes récents, comme les plantages ou les écrans bleus, avec une copie texte enregistrée. Lecture seule.",
                "Hardware, system and recent problems, such as crashes or blue screens, with a text copy saved. Read-only."
            ),
            Action::Logiciels => tr!(
                "Chacun est montré installé ou non, puis installé après accord depuis la source officielle (paquets, Flathub, winget, Homebrew).",
                "Each is shown as installed or not, then installed with consent from the official source (packages, Flathub, winget, Homebrew)."
            ),
            Action::Nettoyer => tr!(
                "Montre la place que chaque élément libère ; ce qui se refait seul est coché, la corbeille jamais. Aucun document ni réglage n'est touché.",
                "Shows the space each item frees; what rebuilds itself is ticked, the trash never. No document or setting is touched."
            ),
            Action::Lenteur => tr!(
                "Mesure ce qui occupe processeur, mémoire et disque, programme par programme, et ce qui retarde le démarrage. Lecture seule, avec conseils.",
                "Measures what uses the processor, memory and disk, program by program, and what delays startup. Read-only, with advice."
            ),
            Action::Demarrage => tr!(
                "Retire ou remet un programme lancé à l'ouverture de session, après accord ; il reste installé. Ce qui protège l'ordinateur n'est pas proposé.",
                "Removes or restores a program launched at sign-in, with consent; it stays installed. What protects the computer is not offered."
            ),
            Action::OptimiserRecommandes => tr!(
                "Applique les réglages recommandés qui ne sont pas encore en place, après accord ; chacun note sa valeur d'avant.",
                "Applies the recommended settings not yet in place, with your consent; each one records its previous value."
            ),
            Action::Gaming => tr!(
                "Montre les composants et réglages utiles aux jeux, faits ou à faire, puis applique ceux choisis après accord. Les réglages s'annulent.",
                "Shows the components and settings games need, done or to do, then applies the chosen ones with consent. Settings are undoable."
            ),
            Action::DnsRapide => tr!(
                "Compare votre DNS aux grands DNS publics. Un DNS qui vous protège est gardé ; sinon, le plus rapide est proposé, annulable.",
                "Compares your DNS with the major public ones. A DNS that protects you is kept; otherwise the fastest is offered, undoable."
            ),
            Action::Connexion => tr!(
                "Mesure la latence, la gigue et les pertes vers la box et Internet, le débit, et le lag quand le réseau est chargé. Ne change rien.",
                "Measures latency, jitter and loss to the router and the Internet, speed, and lag when the network is busy. Changes nothing."
            ),
            Action::Nat => tr!(
                "Deux serveurs STUN disent quelle adresse et quel port ils voient ; Vanguard en déduit le type de NAT de la box. Lecture seule.",
                "Two STUN servers report which address and port they see; Vanguard deduces the router's NAT type. Read-only."
            ),
            Action::WifiCanaux => tr!(
                "Les réseaux voisins par bande et par canal, et votre signal. Lecture seule : le canal se règle dans l'administration de la box.",
                "Nearby networks by band and channel, and your signal. Read-only: the channel is set in the router's admin page."
            ),
            Action::OptimiserConfidentialite => tr!(
                "Réduit ce que le système envoie ou affiche. Chaque réglage montre son état, s'applique après accord et s'annule exactement.",
                "Reduces what the system sends or shows. Each setting shows its state, applies with consent and undoes exactly."
            ),
            Action::OptimiserConfort => tr!(
                "Rend le système plus pratique au quotidien. Chaque réglage montre son état, s'applique après accord et s'annule exactement.",
                "Makes the system handier day to day. Each setting shows its state, applies with consent and undoes exactly."
            ),
            #[cfg(not(target_os = "macos"))]
            Action::OptimiserPerformance => tr!(
                "Réglages de vitesse et de fiabilité. Chacun montre son état, s'applique après accord et s'annule exactement.",
                "Speed and reliability settings. Each shows its state, applies with consent and undoes exactly."
            ),
            Action::Parametres => tr!(
                "Tous les réglages de Vanguard au même endroit ; chaque changement est montré avec sa valeur d'avant.",
                "All of Vanguard's settings in one place; each change is shown with its previous value."
            ),
            Action::Appris => tr!(
                "Les alertes que vous avez déclarées normales ici ; elles reviennent après 90 jours ou si elles s'aggravent. Vous pouvez en faire oublier.",
                "Alerts you marked as normal here; they come back after 90 days or if they get worse. You can make it forget them."
            ),
            Action::MettreAJour => tr!(
                "Remplace, après accord, la copie de cet ordinateur par la version plus récente de la clé, ou par celle de GitHub, signée et vérifiée.",
                "With consent, replaces this computer's copy with the newer version from the key, or the signed, verified one from GitHub."
            ),
            Action::VerifierVanguard => tr!(
                "Deux contrôles : ce programme est-il bien celui publié, et lit-il correctement cet ordinateur ? Rien n'est changé.",
                "Two checks: is this program the one that was released, and does it read this computer correctly? Nothing is changed."
            ),
            Action::VerifierMoi => tr!(
                "Montre la version et l'empreinte SHA-256 de ce programme ; après accord, la compare à l'historique signé des versions publiées.",
                "Shows this program's version and SHA-256 hash; with consent, compares it with the signed history of releases."
            ),
            Action::Autotest => tr!(
                "Vanguard vérifie ses propres lectures sur cet ordinateur et mesure ce qui ralentit. Rien n'est envoyé.",
                "Vanguard checks its own readings on this computer and measures what is slow. Nothing is sent."
            ),
            Action::Regles => tr!(
                "Chaque vérification du bilan pour ce système, puis celles de l'audit du réseau, avec leur sujet. Lecture seule.",
                "Every check-up rule for this system, then the network audit's, with their subject. Read-only."
            ),
            Action::Ordinateurs => tr!(
                "Chaque bilan complet y note sa visite : système, modèle, notes, problèmes restants. Gardé sur la clé, sans nom ni adresse.",
                "Each full check records its visit: system, model, grades, remaining problems. Kept on the key, with no names or addresses."
            ),
            Action::ProtegerDonnees => tr!(
                "Chiffre le carnet des appareils sur la clé ; sur un autre ordinateur, Vanguard demande la phrase. Contre une clé perdue ou prêtée.",
                "Encrypts the device record on the key; on another computer, Vanguard asks for the passphrase. Against a lost or lent key."
            ),
            Action::Sauvegarder => tr!(
                "Enregistre la base des appareils et l'état de la surveillance dans un fichier, ou les reprend ; la reprise ajoute sans rien effacer.",
                "Saves the device database and monitoring state to a file, or loads them back; loading adds without erasing anything."
            ),
            Action::Raccourci => tr!(
                "Copie Vanguard sur cet ordinateur et pose un raccourci (menu des applications, Bureau). Montré puis accepté ; se retire aussi simplement.",
                "Copies Vanguard to this computer and adds a shortcut (app menu, Desktop). Shown, then accepted; removed just as easily."
            ),
            Action::Extensions => tr!(
                "Lance les plugins et scripts ajoutés, approuvés par leur empreinte ; jamais en administrateur, et ils ne comptent pas dans la note.",
                "Runs added plugins and scripts, approved by their hash; never as administrator, and they do not count in the grade."
            ),
            Action::Desinstaller => tr!(
                "Retrouve ce que Vanguard a posé (surveillance, raccourci, copie…) et retire ce que vous cochez. Le dossier de données demande un second accord.",
                "Finds what Vanguard placed (monitoring, shortcut, copy…) and removes what you tick. The data folder needs a second consent."
            ),
        }
    }
}

impl Groupe {
    /// Ce que le groupe sert à faire ; la liste de ses outils suit dans l'aperçu.
    pub(crate) fn description(self) -> &'static str {
        match self {
            Groupe::Ordinateur => tr!(
                "Vérifier la sécurité de cet ordinateur et de ce qui y est installé, et le garder à jour.",
                "Check the security of this computer and what is installed on it, and keep it up to date."
            ),
            Groupe::Reseau => tr!(
                "Voir qui est sur votre réseau, ce qui y est exposé, et le surveiller.",
                "See who is on your network, what is exposed on it, and keep watch over it."
            ),
            Groupe::Virus => tr!(
                "Chercher les logiciels malveillants et espions, et se préparer aux rançongiciels.",
                "Look for malware and spyware, and get ready for ransomware."
            ),
            Groupe::Arnaques => tr!(
                "Démasquer les liens et courriels piégés, vérifier vos mots de passe et ce que vos applications voient.",
                "Unmask trapped links and emails, check your passwords and what your apps can see."
            ),
            Groupe::Reagir => tr!(
                "Bloquer les menaces, réagir à un incident et défaire ce que Vanguard a changé.",
                "Block threats, respond to an incident and undo what Vanguard changed."
            ),
            Groupe::Donnees => tr!(
                "Mettre vos fichiers à l'abri sur un autre disque et vérifier que la copie se relit.",
                "Keep your files safe on another disk and check that the copy reads back."
            ),
            Groupe::Guide => tr!(
                "Retrouver une commande utile de Linux, Windows ou macOS, expliquée, à copier ou à lancer.",
                "Find a useful Linux, Windows or macOS command, explained, to copy or run."
            ),
            Groupe::Depanner => tr!(
                "Régler une panne courante pas à pas, en répondant à quelques questions.",
                "Fix a common problem step by step, by answering a few questions."
            ),
            Groupe::Optimiser => tr!(
                "Installer de bons logiciels, libérer de la place, accélérer et régler le système, jeux compris.",
                "Install good software, free up space, speed up and tune the system, games included."
            ),
            Groupe::Vanguard => tr!(
                "Régler Vanguard, le mettre à jour, vérifier qu'il est authentique et gérer ce qu'il a posé ici.",
                "Set up Vanguard, update it, check it is genuine and manage what it placed here."
            ),
        }
    }
}
