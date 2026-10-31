# Développer Vanguard

**Français** · [English](CONTRIBUTING.en.md)

Le code, ses commentaires et ses noms internes sont en français ; chaque texte montré à l'utilisateur existe dans les
deux langues (`tr!("fr", "en")` dans `src/langue.rs`).

Avec Claude Code : `CLAUDE.md` donne les commandes et les règles du projet, `/verifier` et `/livrer`
(`.claude/skills/`) vérifient tout et livrent une version ; un crochet remet en forme le Rust après chaque
modification. Sur GitHub, `@claude` dans un ticket ou une demande de fusion le fait répondre, et chaque ticket
« journal » est analysé tout seul (`.github/workflows/claude*.yml`, à activer une fois avec `/install-github-app`).

Une faille de sécurité ? Pas de ticket ni de demande de fusion publics : signale-la en privé, voir
[SECURITY.md](SECURITY.md).

## Structure

| Fichier | Rôle |
|---|---|
| `src/main.rs` | menu et sous-commandes |
| `src/deploiement.rs` | étapes de `outils/deployer.sh` confiées au programme (`vanguard deploiement …`, commande cachée) : gardes du vanguard.exe, témoins de la clé, archives tldr de la clé |
| `src/ui.rs` | couleurs, titres, cadres, barres, lignes coupées et alignées dans 76 colonnes |
| `src/selection.rs` | menus et listes à cocher au clavier (flèches, Entrée, Échap ou Retour arrière), recherche par mot dans les menus, aperçu à droite de la ligne en surbrillance (fenêtre assez large) |
| `src/descriptions.rs` | ce que l'aperçu des menus dit de chaque outil et de chaque groupe |
| `src/recherche.rs` | la recherche : score par mot, synonymes (« box » → routeur), fautes de frappe corrigées ; pour le menu et `vanguard chercher` |
| `src/prediction.rs` | prédiction du mot en cours de frappe, la même dans tous les menus : sa fin en gris, Tab la complète |
| `src/langue.rs` | choix de la langue et macros de traduction |
| `src/masque.rs` | masque dans le binaire les mots d'attaque que Vanguard cherche (noms de commandes d'outils offensifs, contournements d'AMSI) par un XOR fait à la compilation (`liste_masquee!`, `mot_masque!`), décodé en mémoire au premier usage : qu'un antivirus ne prenne pas Vanguard pour l'outil qu'il traque ; le code source reste en clair |
| `src/parametres.rs` | menu Paramètres et `vanguard parametres` : les réglages du lancement (langue, emojis, sans Internet) dans parametres.json, lus avant tout affichage, une variable d'environnement l'emportant ; protection en temps réel, surveillance, entretien, alertes apprises, blocage, restrictions des extensions et clé abuse.ch changés par leur propre code |
| `src/machine/mod.rs` | types communs, affichage, exécution parallèle des vérifications |
| `src/machine/regles.rs` | registre des règles du bilan : chacune se déclare où elle est écrite (`inventory::submit!`), avec un identifiant stable (« LNX-PLT-001 ») et au moins une référence du CIS, de Microsoft ou de l'ANSSI ; chacune tourne sous son délai (au-delà : non vérifiée, le bilan continue) ; `vanguard regles` les liste |
| `src/machine/corpus.rs` | régression de détection (tests seulement) : les adaptateurs qui donnent les cas fabriqués et inoffensifs de tests/corpus-detection aux fonctions de jugement des règles (un `corpus.rs` aussi dans `linux/`, `windows/`, `macos/` et `journaux_windows/regles/`) ; `src/modele/corpus.rs` charge les cas, exige que chacun tire et que son cas propre reste muet, et tient la liste fermée des règles de détection |
| `src/machine/linux/plateforme.rs` | sécurité de la plateforme d'après fwupd (HSI), verrouillage du noyau, BPF, espaces de noms, auditd : les premières règles du registre |
| `src/machine/linux/natif.rs` | lectures natives de Linux, sans lancer de programme : le PATH (présence et chemin d'un programme, dossiers du système pour ce que lance sudo), les unités systemd, les processus, les bases de pacman, dpkg (une seule règle « installé », paquets retenus compris), Flatpak et Snap, les disques, la racine, les groupes du compte |
| `src/machine/linux/paquets.rs` | ce qui est installé, lu dans les bases (pacman, dpkg, Flatpak), commande en secours ; sert à Gaming, aux logiciels et à la protection |
| `src/machine/linux/dbus.rs` | petit client D-Bus écrit pour le projet, sans bibliothèque : bus système, authentification EXTERNAL, messages encodés et décodés à la main ; seules des méthodes de lecture partent (unités en échec, durée du démarrage et chaîne critique de systemd, SMART par udisks2) |
| `src/machine/linux/zstd.rs`, `journal_systemd.rs` | décodeur zstd écrit pour le projet (RFC 8878 : bases de pacman en zstd, champs compressés du journal) ; lecture des fichiers du journal de systemd par leur table de hachage (erreurs du démarrage, échecs SSH), journalctl en secours |
| `src/machine/linux/`, `src/machine/windows/`, `src/machine/macos/` | audit propre à chaque système, un fichier par thème ; sous Windows, comptes (NetUserEnum, groupe S-1-5-32-544) et démarrage (clés Run par winreg, raccourcis .lnk lus en Rust) sans PowerShell, lui en secours ; `windows/corrections.rs` et `windows/eleve.rs` : la liste fermée des corrections natives et le processus élevé qui les applique, ordres du blocage compris (relance « runas », tube nommé vérifié des deux côtés), avec le script PowerShell d'une liste mêlée, lu en mémoire et vérifié par empreinte, dans la même et seule demande UAC ; `windows/pare_feu.rs` : les règles du blocage par INetFwPolicy2 ; `windows/chargement.rs` : DLL importées prises dans System32 seulement (Load Config du PE) ; `ancrages.rs` : DLL chargées par Windows lui-même (paquets de LSA, AppCertDlls, moniteurs d'impression, fournisseurs de temps, catalogue Winsock) ; `pilotes.rs` : pilotes du noyau (emplacement, pilotes vulnérables connus de LOLDrivers) |
| `src/sqlite.rs` | lecteur SQLite écrit pour le projet, sans sqlite3 : compte les lignes d'une table (identifiants des navigateurs) et lit quelques colonnes (TCC.db de macOS) ; borné contre une base abîmée (pages qui bouclent, débordement, profondeur) |
| `src/plist.rs` | lecteur des plist d'Apple, XML et binaires (« bplist00 »), à la place de defaults et plutil ; borné contre un fichier hostile (taille, profondeur, nombre de valeurs, références qui bouclent) |
| `src/archives/` (`gzip.rs`, `tar.rs`, `zip.rs`, `crc32.rs`), `src/pe.rs` | archives lues en Rust, sans zcat, tar ni unzip : gzip (CRC-32 et taille contrôlés pour un fichier téléchargé), tar (noms longs pax et GNU, archive coupée refusée), zip (tldr-pages ; contrôle entier, CRC-32 compris, pour la copie de la clé ; parcours entrée par entrée pour l'analyse des fichiers) ; version et architecture d'un .exe lues dans sa ressource de version (RT_VERSION), par morceaux, sans fonction de Windows, et les gardes du vanguard.exe livré (DependentLoadFlags, manifeste). Bornés en taille et en nombre d'entrées contre un fichier hostile |
| `src/analyse/` | socle de l'antivirus maison (lot AV1), sans interface ni verdict : un fichier en arbre de parties (type reconnu par le contenu, chemin interne, taille, SHA-256, faits, ce qui n'a pas été lu et pourquoi) ; lecteurs écrits d'après leur spécification : ELF, Mach-O et universels, fichiers composés OLE ([MS-CFB]), macros VBA ([MS-OVBA] : compression, flux dir, procédures qui se lancent seules), Word et Excel 97 (chiffrement, feuilles XLM), OOXML, raccourcis ([MS-SHLLINK]), textes et scripts ; bornes (taille, profondeur, parties, octets produits et examinés, taux de compression, temps), quines ; 7z, RAR, CAB, ISO, PDF, chiffré ou coupé : dits non vérifiés, jamais sains |
| `src/machine/windows/portes.rs`, `evenements.rs` | portes dérobées classiques (débogueur sur un programme d'accessibilité de l'écran de connexion par IFEO ou SilentProcessExit, sethc et utilman remplacés, Shell et Userinit de Winlogon, AppInit_DLLs, abonnements WMI), corrigées quand l'état d'origine est connu ; journaux d'événements des 7 derniers jours (mots de passe faux en rafale par le réseau, journal de sécurité effacé, comptes créés, services suspects) |
| `src/machine/linux/dissimulation.rs`, `algorithmes_ssh.rs` | signes de rootkit lus dans /proc et /sys : processus cachés, programmes sans fichier (memfd, effacés, /tmp), module du noyau qui se cache, modules non signés inconnus, carte en mode promiscuité ; algorithmes cassés de sshd (configuration lue dans l'ordre des Include), retirés par `00-vanguard.conf` après `sshd -t` |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `partages.rs`, `sante.rs`, `wifi.rs`, `bluetooth.rs`, `agents_ia.rs` | vérifications communes aux trois systèmes (partages.rs : partages de fichiers ouverts à tout le monde ; bluetooth.rs : ordinateur visible, appareils appairés depuis peu ; agents_ia.rs : serveur d'IA local ouvert au réseau, réglages risqués des agents de code et de leurs serveurs MCP, lus sans jamais montrer une valeur secrète) |
| `src/machine/chasse.rs` | chasse aux menaces en direct, sur les trois systèmes : connexion réussie depuis une adresse qui venait de rater au moins dix mots de passe (journal de sshd sous Linux, 4625 puis 4624 sous Windows ; non vérifié sous macOS) ; programmes en marche suspects (outil offensif connu, ligne de commande qui télécharge ou cache ce qu'elle exécute, programme lancé de Téléchargements, d'un dossier temporaire, Public ou de la corbeille), jugés par des fonctions pures, Vanguard et ce qu'il lance mis à part |
| `src/machine/linux/veilleur.rs` | le veilleur : connecteur de processus (exec, fork, fin) et fins de prises de sock_diag (groupes « destroy ») décodés à la main par libc, sans root ni eBPF ; les programmes jugés comme COM-PRG-001, les connexions par les serveurs de commande gardés ; journal du tableau de bord à débit borné ; service de l'utilisateur coupé par défaut ; il n'arrête rien |
| `src/machine/wifi/elements.rs`, `nl80211.rs`, `networkmanager.rs`, `wlanapi.rs`, `profils.rs` | Wi-Fi lu sans programme externe : éléments d'information des balises 802.11 (chiffrements RSN et WPA, WPS) décodés octet par octet ; bornes entendues par le noyau Linux (nl80211, dernier balayage), gardées par NetworkManager (D-Bus, lecture seule) et par Windows (wlanapi) ; réseaux enregistrés (NetworkManager, iwd, macOS, profils Windows) |
| `src/machine/unix.rs` | vérifications communes à Linux et macOS : fichiers secrets, sudo |
| `src/machine/darwin.rs`, `macos/noyau.rs`, `macos/config_reseau.rs` | macOS lu sans lancer d'outil : structures de libproc, table de routage, arguments des processus et SIP écrites à la main d'après les en-têtes de XNU (tailles vérifiées à la compilation, octets testés sous Linux) ; processus, prises, routes, voisins, échange, SIP (csr_get_active_config par dlsym), options de démarrage, montages demandés au noyau ; DNS, proxy et services réseau à SystemConfiguration ; l'outil d'Apple reste en secours, et des tests d'oracle comparent les deux sur le Mac de GitHub |
| `src/machine/heure.rs`, `fin_de_support.rs`, `comptes_oublies.rs`, `mots_de_passe.rs`, `sensibles.rs` | heure réglée automatiquement ; système, programmes abandonnés et navigateurs sans mise à jour ; comptes inutilisés ; mots de passe du navigateur sans protection ; fichiers sensibles qui traînent |
| `src/changements.rs` | ce que Vanguard a changé : chaque correction lancée par `machine::appliquer_chacune`, notée sur l'ordinateur ; un blocage avec de quoi l'annuler exactement, jamais élagué tant qu'il est en place ; une correction du bilan qui se défait, liée à sa note, annulée une par une |
| `src/signaler/` | `vanguard signaler` (alias `disclose`) : préparer un signalement à un éditeur sans jamais l'envoyer ; tri (faille connue, logiciel malveillant, hameçonnage, détection ratée, contournement) dans `tri.rs`, liste fermée des programmes et de leurs champs dans `programmes.rs`, brouillon pur dans `brouillon.rs`, garde-fou de confidentialité en trois couches (réduire, masquer, contrôle final) dans `garde.rs`, neutralisation Markdown pure (banc de fuzzing) dans `markdown.rs` ; aucun code réseau, vérifié par une liste fermée des appels |
| `src/evenements.rs` | `vanguard evenements [--json] [--incident id]` : le journal des événements montré, l'état de sa chaîne d'abord (un journal falsifié se lit, mais non vérifié), le fil d'un incident remonté par `cause` |
| `src/journaux_windows/` | journaux d'événements de Windows lus par Vanguard lui-même, sous tous les systèmes : lecteur .evtx (`evtx/` : en-tête, morceaux de 64 Kio vérifiés par leur CRC32, BinXml de [MS-EVEN6] avec gabarits et substitutions, `binxml.rs`, `valeurs.rs`), borné en taille, profondeur et travail, ce qui n'a pas pu être lu compté dans un bilan ; lu croisé avec la crate `evtx` dans ses tests) ; une seule forme d'événement (`evenement.rs`) pour deux sources : un dossier de .evtx (`fichiers.rs`) et les journaux de l'ordinateur sous Windows (`vivant.rs`, XML du service des journaux changé en l'arbre du lecteur par `xml.rs`) ; trous dans la suite des numéros d'enregistrement (`trous.rs` : retirés, absents, copie à chaud, illisibles, avant l'export) ; règles `EVT-` (`regles/` : moteur sans écran, un événement, rafale ou rafale puis réussite, ce qui n'a pas pu être lu dit « non vérifié » dans `moteur.rs` ; treize règles écrites d'après la documentation de Microsoft et ATT&CK dans `jeu.rs`, dont les tâches planifiées et les lignes de commande des processus, une source de rechange suffisant quand Windows en a deux ; constats et couverture, dossier .evtx ou ordinateur vivant, et ceux du bilan (WIN-JRN-003, dans `src/machine/windows/evenements.rs`), dans `resultat.rs`) ; « Que s'est-il passé ? » : les alertes dans l'ordre du temps et la période lue par journal, sans écran (`chronologie.rs`, reprise par CHRONOLOGIE.txt des traces), et `vanguard journaux-windows` (`commande.rs`) |
| `src/annulation.rs` | « Tout remettre comme avant » : corrections du bilan, réglages d'Optimiser et de Gaming, blocages et mode Wi-Fi public, montrés puis défaits du plus récent au plus ancien, en une demande administrateur, relus après coup |
| `src/sauvegarde.rs`, `src/raccourci.rs`, `src/mise_a_jour.rs`, `src/a_laisser.rs` | sauvegarde automatique guidée (Déjà Dup ou rsync, Time Machine, Historique des fichiers) et vérifier ma sauvegarde (la copie rsync relue sans cache, des fichiers au hasard comparés à leur original ; un original plus récent n'est pas une erreur) ; raccourci sur cet ordinateur ; mise à jour de sa copie depuis la clé (version gravée dans le programme, lue sans le lancer) ou depuis GitHub (`mise_a_jour/github.rs` : manifeste signé en Ed25519 publié dans d9v3/vanguard-update, taille, empreinte et version du programme vérifiées) ; rapport à laisser à la personne dépannée |
| `src/corriger.rs` | application guidée des correctifs |
| `src/socle/` | le socle commun, sans rien savoir du réseau ni de la protection : dossier de Vanguard, écriture atomique et verrou (`fichiers.rs`), cache des listes téléchargées (`cache.rs`), portée d'une adresse IP selon les RFC (`adresses.rs`), dossier personnel et place sur les disques (`personnel.rs`), processus de Linux et macOS (`processus.rs`), JSON avec commentaires (`jsonc.rs`), os-release (`systeme.rs`), empreintes en hexadécimal (`hachage.rs`) |
| `src/reseau/mod.rs`, `src/reseau/scan.rs`, `ping.rs` | scan réseau (TCP connect, sans root), ARP, carnets des réseaux ; écho ICMP sans lancer ping |
| `src/reseau/nmap.rs` | versions des services par nmap -sV, s'il est installé : scan approfondi d'un appareil du réseau local, sur ses ports déjà trouvés ouverts |
| `src/reseau/empoisonnement.rs` | empoisonneur de noms (Responder) : un nom tiré au hasard, qui n'existe pas, demandé en LLMNR, NetBIOS et mDNS pendant le scan ; l'appareil qui répond aux deux essais est signalé (paquets écrits et lus en Rust) |
| `src/risk.rs` | base de connaissances des ports et niveaux de risque |
| `src/reseau/connexion.rs` | test de connexion pour le jeu |
| `src/protection/antivirus.rs` | ClamAV / Defender, quarantaine |
| `src/protection/yara.rs`, `src/protection/pieges.rs` | analyse YARA (règles intégrées, appliquées par le moteur de Vanguard) ; fichiers-pièges contre les rançongiciels |
| `src/protection/regles_yara.rs`, `moteur_yara.rs`, `motifs.rs`, `oracle_yara.rs` | moteur YARA maison : lecteur du sous-ensemble du langage qu'utilisent les règles (le reste refusé, nommé, « non vérifié »), conditions et modules pe et elf (`moteur_yara.rs`, champs pe dans `src/pe.rs`), recherche multi-motifs d'après Aho-Corasick, en tampon ou en flux borné (`motifs.rs`, commun aux futures signatures ClamAV) ; YARA-X en oracle des tests seulement (`oracle_yara.rs`) |
| `src/protection/rancongiciel/` | veilleur anti-rançongiciel : écoute en direct des dossiers personnels (`notify`, déjà présent), score à règles par groupe de processus sur une fenêtre de 10 s (rafale, contenu chiffré, noms, note de rançon, piège touché, copies effacées), attribution par les compteurs d'écriture et les descripteurs (`/proc/<pid>/io` et `fd`, sans root ni crate nouvelle) ; avec la protection active et un cas quasi certain, gel de la lignée, preuve, arrêt et quarantaine ; décisions en fonctions pures (testées sous Linux et Wine) |
| `src/protection/memoire.rs`, `src/machine/windows/memoire.rs` | mémoire des programmes (`vanguard memoire`, à la demande) : les règles YARA sur les régions privées ou exécutables des processus en marche et sur les images chargées que leur fichier ne suffit plus à juger (fichier effacé ou sur tmpfs, pages de code privées), chaque image ou allocation recollée d'un seul tenant, bornées (64 Mio par région, 512 Mio par processus, 4 Gio et 5 minutes en tout) ; /proc/<pid>/smaps et mem sous Linux, VirtualQueryEx, QueryWorkingSetEx et ReadProcessMemory sous Windows (LSASS, processus protégés et critiques jamais lus) ; macOS non vérifié ; rien de lu n'est gardé |
| `src/protection/empreintes.rs` | empreintes SHA-256 de MalwareBazaar (abuse.ch, avec la clé) : liste complète chaque semaine (archive zip), récentes chaque jour, gardées dans le dossier de Vanguard et triées ; l'analyse YARA y cherche chaque fichier lu |
| `src/protection/abuse_ch.rs` | listes d'abuse.ch et clé de la personne (MalwareBazaar, URLhaus, ThreatFox depuis la fermeture des exports publics) : gardée sur l'ordinateur (600), montrée masquée, jamais dans une adresse écrite ; sans clé ou clé refusée, listes non vérifiées |
| `src/protection/outil.rs`, `src/protection/secrets_git.rs`, `src/protection/conteneurs.rs` | secrets dans l'historique des projets git (règles de Vanguard, gitleaks en plus s'il est là) ; outils libres lancés s'ils sont installés, installation proposée sinon (trivy sur les images Docker ou Podman) |
| `src/reseau/surveillance.rs` | minuterie systemd / Planificateur de tâches / agent launchd, notifications |
| `src/reseau/tableau.rs` | tableau de bord de la surveillance : journal des alertes (borné en nombre et en âge), page HTML locale d'un seul fichier (état, alertes par jour, nouveaux appareils, connexions vers des botnets) |
| `src/audit/mod.rs`, `score.rs`, `fiches.rs` | audit du réseau par domaine (Exposition, Wi-Fi, Segmentation, DNS et TLS, Appareils, Postes), défensif seulement : notes (100 moins les pénalités, pas de note quand plus du tiers n'a pas pu être vérifié), fiches des règles (identifiant « COM-XXX-000 », sujet FR/EN, références citées) |
| `src/audit/exposition.rs`, `igd.rs`, `http_local.rs`, `ipv6.rs` | domaine Exposition : ce que la maison montre à Internet d'après le scan, l'adresse vue d'Internet (STUN) et l'IPv6 ; client UPnP IGD en Rust pur (SSDP, description XML, actions SOAP, bornés ; seulement la passerelle, les autres qui se disent box sont signalés ; jamais cette machine ni un autre hôte que celui de la description) avec son client HTTP/1.1 minuscule pour le réseau local ; adresses IPv6 publiques de l'ordinateur et voisins qui en ont une (netlink) |
| `src/audit/wifi.rs`, `segmentation.rs`, `arp.rs` | domaines Wi-Fi (chiffrement du réseau connecté, WPS, plusieurs émetteurs pour un nom, réseaux gardés en mémoire), Segmentation (objets connectés avec les ordinateurs, réseau invité, qui distribue les adresses, routeurs IPv6) et intégrité ARP (MAC de la box qui change, adresse d'un fabricant d'ordinateurs, une MAC pour plusieurs IP) |
| `src/audit/dns_tls.rs`, `dns_client.rs`, `bail.rs` | domaine DNS et TLS : DNS distribué par la box comparé à celui de la machine, DNS chiffré (DoT, DoH, DDR), résolveur comparé à deux résolveurs publics, exceptions de certificat et racines poussées dans Firefox ; client DNS maison en UDP (A, AAAA, TXT, SVCB, HTTPS, EDNS0, bit DO), borné ; bail DHCP et configuration DNS effective lus dans les fichiers et le registre |
| `src/audit/tls_pq.rs`, `ssh_kex.rs` | post-quantique de l'audit, sans aucun calcul de clé : ClientHello TLS 1.3 écrit à la main (X25519MLKEM768 seul, part de clé vide, bourré jusqu'à 1 600 octets) et lecture de la réponse (HelloRetryRequest ou alerte) ; KEXINIT d'un serveur SSH du réseau local lu puis connexion fermée ; bornés, fuzzés |
| `src/audit/appareils.rs`, `postes.rs` | domaines Appareils (objets connectés reconnus d'après le scan, rien de sondé en plus que la recherche des caméras) et Postes (cet ordinateur vu du réseau : les constats réseau du bilan ; les autres ordinateurs d'après le scan) |
| `src/rapport.rs`, `src/historique.rs` | rapport HTML, historique des bilans, courbe des notes |
| `src/modele/` | modèle commun des constats : clé `règle + objet` sans texte traduit (`id.rs`), état sain, sans objet, non vérifié avec sa raison ou problème (`etat.rs`, `raison.rs`), préfixes et identifiants des outils (`registre.rs`), inventaire versionné des fichiers d'état dont `sceau` tire ce qu'il protège (`inventaire.rs`) ; canal d'erreur commun `Echec` avec son code stable (`raison.rs`) ; journal des événements en ajout seul, chaîné sur les octets exacts, tête scellée, mois clos scellés, reliés par `cause` (`evenement.rs`, `journal.rs`) ; résultat sérialisable des outils lancés seuls, versé dans `examens/` et au journal (`resultat.rs`, repris par le `resultat.rs` d'`espions`, `perimes`, `courriel_suspect`, `acces`, `lien`, `sortantes`, `distance`, `diagnostic`, `lenteur`, `reseau::objets`, `reseau::connexion` et `reseau::listes_noires`) ; référentiels reconnus des règles : CIS, Microsoft, ANSSI (`reference.rs`) |
| `src/canaris.rs` | canaris de format (essais seulement) : chaque source réelle téléchargée par la même demande que le programme et relue par son lecteur ; lancés par la veille de nuit (`VANGUARD_CANARIS`), jamais par `cargo test` |
| `src/autotest/` | autodiagnostic (`vanguard autotest`, et chaque semaine avec la surveillance) : règles du bilan sous garde et délai, invariants des constats, rapport sans valeur lue, code de sortie (`mod.rs`) ; interrupteur de lecture seule du processus et preuve par empreintes BLAKE3 du dossier de données (`lecture_seule.rs`) ; registre des lectures croisées natif contre outil du système, commandes de lecture permises (`croisees.rs`, déclarées dans `machine/linux/croisees.rs` et `machine/windows/croisees.rs`) ; journal des mesures, durée de chaque règle en résumé par jour, régressions (`mesures.rs`) |
| `src/sceau.rs` | sceaux de l'état de Vanguard (alertes acceptées, référence d'intégrité, botnets signalés, versions vues et révocation de la clé principale, valeurs d'avant d'Optimiser, alertes déclarées normales, temps réel, audit, sites et passerelle déjà signalés) : changé hors de Vanguard, il ne compte plus et le bilan le dit ; effacé avec les sceaux, « inconnu », jamais un premier passage ; seulement un simple fichier de taille bornée ; en root, seulement dans un dossier à root |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming/` | réparations, mises à jour, gaming |
| `src/optimiser/` | réglages de confidentialité, de performance et de confort, avec annulation exacte ; le même mécanisme pour les corrections du bilan et les réglages pour jouer (`annulables.rs` : gestes d'une liste fermée, valeur d'avant relevée puis scellée dans reglages.json, notes de jeux.json reprises) ; programmes au démarrage (`demarrage.rs`) ; blocages de Windows Defender : règles ASR, protection réseau, PUA, accès contrôlé aux dossiers (`defender.rs`) |
| `src/nettoyer/` | nettoyage : éléments par système, place mesurée avant et après |
| `src/logiciels/` | logiciels à installer : catalogue vérifié (`catalogue.rs`), état et installation par système |
| `src/protection/fuites.rs`, `src/donnees.rs` | mots de passe fuités, sauvegarde des données |
| `src/protection/cle.rs` | protection de la clé USB sous Linux et macOS : partition remontée en lecture seule hors de l'ordinateur du propriétaire |
| `src/guide/` | guide des commandes : un fichier par système (`arch.rs`, `omarchy.rs`, `fedora.rs`, `debian.rs` : programmes et marches à suivre de chaque distribution ; `linux.rs` : programmes communs à toutes, et openSUSE ; `windows.rs`, `macos.rs`, `tous.rs`), menus et recherche (`mod.rs`), commandes lancées ici (`lancement.rs`), exemples de tldr-pages téléchargés chaque semaine et copiés sur la clé au déploiement (`tldr.rs`, `tldr/cle.rs`) |
| `src/apprentissage.rs` | ce que Vanguard apprend ici : alertes déclarées normales (appris.json), habitudes |
| `src/reseau/listes_noires.rs` | adresse Internet de la maison dans les listes noires (DNSBL), après accord |
| `src/voulues.rs`, `src/programmes_poses.rs` | défenses voulues (surveillance horaire, veilleur, veille anti-rançongiciel) : mise en marche et arrêt par Vanguard notés dans un état scellé et au journal, coupure sans Vanguard dite, état douteux jamais vert ; programme lancé par chaque tâche (surveillance, entretien, veilleur) : chemin et empreinte BLAKE3 scellés à la pose et à la mise à jour, comparés au bilan |
| `src/entretien.rs` | entretien du mois : note, mises à jour, place, problèmes nouveaux, en une notification |
| `src/protection/sortantes.rs` | qui parle à Internet : connexions établies par programme (ss, PowerShell, lsof), DNS inverse ; serveurs de commande de botnets (Feodo Tracker sans clé, ThreatFox avec la clé abuse.ch : export complet lu par son en-tête, et API) |
| `src/protection/environnement.rs` | au démarrage : bibliothèque injectée dans la session (LD_PRELOAD, DYLD, AppInit_DLLs), jugée comme le préchargement |
| `src/protection/manifeste.rs` | vérifier Vanguard lui-même (version, date du commit, SHA-256) et manifeste de la clé (empreintes BLAKE3 gardées chez le propriétaire, une référence par clé, comparées au bilan ; menu de Ventoy et taille des images ISO compris, redits par images-cle.sh ; clé reconnue dont l'identifiant de volume a changé : signalée) |
| `src/protection/cles_connues.rs` | clés VANGUARD connues de cet ordinateur (jeton `vanguard.jeton` posé au déploiement, `cles-connues.json`) ; par clé, l'empreinte du carnet tel que Vanguard l'a écrit et sa protection : un carnet changé hors de Vanguard n'est ni lu ni réécrit |
| `src/protection/distance.rs` | mon ordinateur est-il contrôlé ? logiciels de prise de contrôle à distance (installés, au démarrage, en cours, téléchargés), au bilan et en parcours guidé |
| `src/protection/espions/` | logiciels espions : en ai-je un ? `echap` (liste d'Échap, CC-BY 4.0, téléchargée à l'usage, lue par un lecteur YAML borné écrit pour le projet ; serveurs, sites, noms), `connus` (logiciels de surveillance de bureau, chaque motif avec sa source), `clavier` (Linux : qui tient /dev/input), `tcc` (macOS : Surveillance de l'entrée, Accessibilité, Enregistrement de l'écran), `windows` (installés, services, Run, processus) ; lecture seule, au bilan sans réseau |
| `src/protection/perimes/` | logiciels pas à jour (Windows, macOS) : `version` (comparaison stricte, normalisation par éditeur), `sources` (table fermée de fichiers publics fixes, téléchargés en entier, les mêmes pour tous ; copie gardée un jour, réponse illisible refusée), `produits` (table des logiciels suivis et de leurs lignes au catalogue de la CISA), `windows` et `macos` (inventaire : exécutables, fichiers des éditeurs, registre sans RegLoadKey, Info.plist), `verdicts` (une règle par produit), `mozilla_avis` (avis de Mozilla lus sans bibliothèque YAML : Firefox jugé faille par faille), `rapport` (écran et bilan) ; lecture seule |
| `src/protection/courriel_suspect/` | ce courriel est-il une arnaque ? lecture MIME bornée et autonome (`mime.rs`, fuzzée), expéditeur et SPF/DKIM/DMARC du fournisseur (`entetes.rs`), liens du texte et du HTML (`corps.rs`), pièces jointes dans un dossier jetable (`pieces.rs`) |
| `src/protection/lien.rs` | ce lien est-il dangereux ? examen local (punycode, marques imitées…), puis RDAP, URLhaus, Spamhaus DBL, SURBL |
| `src/protection/telechargement.rs` | vérifier un fichier téléchargé : empreinte par l'outil du système, nom et contenu, YARA et antivirus ; programmes arrivés dans Téléchargements, pour la surveillance |
| `src/protection/blocage/` | blocage des menaces : chaque menace propose « Bloquer » (geste montré, accepté, noté, annulable) ; protection active, après un accord donné une fois, qui bloque toute seule le certain (empreinte de MalwareBazaar, outil d'attaque connu, serveur de commande) au bilan et dans la surveillance horaire ; en administrateur, l'accord et les modes automatiques de blocage.json (scellé, mais qu'un programme du compte qui refait le sceau peut encore écrire) ne font rien bloquer tout seul (`pour_agir`). `parametres` (blocage.json : un mode par catégorie), `menaces` (ce qui se trouve), `gestes` (préparer, faire, défaire), `gardes` (garde-fous purs : Vanguard, processus critiques, programmes du système, sessions à distance), `pare_feu` (ufw, nftables, Pare-feu Windows, pf), `ordres` (la liste fermée des gestes faits en administrateur, à paramètres typés, reparsés et rejugés par celui qui agit), `arret` (arrêt d'un processus par son numéro et son programme, sans course : pidfd sous Linux) |
| `src/machine/assistant.rs` | l'assistant élevé de Linux et macOS (`vanguard appliquer-eleve`, caché) : Vanguard relancé par pkexec, run0 ou sudo, sur l'image qui tourne (/proc/<pid>/exe), qui fait les ordres du blocage sans aucun shell ; canal par son entrée et sa sortie, liste relue puis rejugée |
| `src/machine/linux/netlink.rs`, `nftables.rs`, `couper.rs` | netlink écrit pour le projet : la table `inet vanguard` de nf_tables posée et retirée en un lot (octets vérifiés contre nft, essai dans un espace de noms à part), et la coupure des connexions déjà ouvertes par SOCK_DESTROY (à la place de « ss -K ») |
| `src/protection/temps_reel.rs` | protection en temps réel de Vanguard : coupée d'un coup (temps-reel.json : début et échéance, 1 h, 4 h ou jusqu'à reprise), elle arrête chaque passe de la surveillance au début et fait proposer d'un clic le certain du blocage, sans toucher à leurs réglages ; échue, elle ne vaut plus, et la surveillance retire le fichier ; illisible, rien n'est coupé ; jamais Defender, le pare-feu ni l'UAC ; ne se règle pas en administrateur |
| `src/protection/quarantaine.rs`, `src/protection/camera.rs` | quarantaine réversible, seul chemin pour le blocage, l'antivirus et YARA : isoler (empreinte SHA-256 gardée, geste noté et annulable), remettre exactement, supprimer ; caméra et micro : qui s'en sert (registre sous Windows, /dev/video et pactl sous Linux) |
| `src/protection/acces.rs` | bilan de confidentialité : applications qui ont accès à la position, aux contacts, à la caméra et au micro (ConsentStore sous Windows, Flatpak et Snap sous Linux, TCC.db sous macOS) ; lecture seule |
| `src/reseau/canaux.rs`, `src/reseau/nat.rs` | Wi-Fi encombré (réseaux voisins par canal) ; type de NAT (client STUN maison) |
| `src/dns_rapide.rs` | DNS le plus rapide : mesure, DNS qui protège gardé, réglage annulable par `optimiser/` |
| `src/reseau/cameras.rs` | caméras cachées : fabricant, flux RTSP, recherche ONVIF (WS-Discovery), page web |
| `src/reseau/wifi_public/` | mode Wi-Fi public : état d'avant scellé et validé (`etat.rs`), commandes pures et lectures par système (`linux.rs`, `windows.rs`, `macos.rs`), suggestion et page du portail sans rien envoyer (`portail.rs`), allumer, éteindre, extinction sûre et constat du bilan (`mod.rs`) |
| `src/reseau/objets.rs` | box et objets connectés : ce que la box annonce (SNMP, UPnP, en-tête web), administration en HTTP seul, objets reconnus à leur fabricant, leur nom, leurs ports et leurs annonces ; conseil du mot de passe d'origine, jamais vérifié (aucun essai, rien de sondé en plus) ; section du scan et `vanguard objets-connectes` d'après le carnet |
| `src/depanner/` | dépanner pas à pas : les parcours (`mod.rs`), réseau et Wi-Fi (`reseau.rs`), son (`son.rs`), imprimante (`imprimante.rs`), après une infection (`infection.rs`), nouvel ordinateur (`nouveau.rs`), ordinateur qui part (`depart.rs`), compte piraté (`compte.rs`), ordinateur d'un proche (`proche.rs` : trois questions, résumé de cinq points au plus mis en ordre selon les réponses, conseils de la page à laisser), lent depuis une mise à jour (`depuis_maj.rs`) |
| `src/protection/preuve.rs`, `src/protection/sources.rs`, `src/protection/normales.rs` | la preuve relevée avant chaque blocage ou quarantaine (processus, ligne de commande, SHA-256, connexions ; « impossible (raison) » sinon) ; la voie unique des sources de menaces (MalwareBazaar, outils offensifs, COM-PRG-001) pour le blocage, le bilan et le veilleur ; les alertes du veilleur, de la surveillance et du blocage déclarées normales (scellées, 90 jours) |
| `src/traces/` | collecter les traces : processus avec leur SHA-256, réseau, démarrage, bilan JSON, comptes, journaux des 7 jours, fichiers récents, ce que Vanguard a vu et fait (`vanguard.rs` : alertes, gestes et leur preuve, fils d'incident, fichiers d'état recopiés), puis LISEZMOI et MANIFESTE (format de `sha256sum -c`), dans un dossier daté ; partie commune (`mod.rs`), par système (`linux.rs`, `windows.rs`, `macos.rs`, `unix.rs`), chronologie de l'incident (`chronologie.rs` : CHRONOLOGIE.txt, ce qui a été lu de daté remis dans l'ordre du temps sur 7 jours, 5 000 lignes au plus ; sous Windows, les alertes EVT- à leur heure, par `journaux_windows.rs`) ; lecture seule |
| `src/lenteur.rs`, `src/fiche.rs` | pourquoi c'est lent (instantané en deux mesures, démarrage) ; fiche de l'ordinateur |
| `src/copier.rs` | copier mes fichiers vers un disque externe : copie vérifiée (BLAKE3), reprise, jamais d'écrasement ; vérifier une copie (test de restauration) |
| `src/verifier_cle.rs` | vérifier ma clé : capacité réelle, vitesses et blocs en erreur, écrits dans le libre et relus sans cache, puis effacés |
| `src/passage.rs` | reprise de ce qu'une version d'avant le changement de nom a posé (données, minuteries, raccourci, règles du pare-feu), restes listés pour la désinstallation ; à retirer à la 1.0 |
| `src/desinstaller.rs` | retirer Vanguard d'un ordinateur : ce qu'il a posé, recalculé sans registre (avec passage.rs pour les noms d'avant), montré, coché ; données après un second accord |
| `src/ordinateurs.rs` | mes ordinateurs : la visite de chaque ordinateur notée sur VANGUARDLOG (catégories et niveaux seulement) |
| `src/plugins/` | extensions : plugins (`mod.rs` : dossier sûr, approbation par SHA-256, copie vérifiée puis lancée, `manifeste.rs` : plugin.toml lu par un analyseur maison borné, `archive.rs` : .zip déplié en Rust), laboratoire (`labo.rs`), protocole des constats (`sortie.rs`), interrupteur des restrictions (`reglages.rs`), menus (`menu.rs`) ; voir la section Extensions |
| `extensions/` | bibliothèque Rust pour écrire un plugin (`sdk/`, crate `vanguard-extension`, hors de l'espace de travail) et exemples (`exemples/`) ; mode d'emploi : `extensions/LISEZMOI.md` |
| `src/chiffrement.rs` | données de la clé protégées : carnet chiffré (XChaCha20-Poly1305), clé de données gardée chez le propriétaire et enveloppée par la phrase (Argon2id) |
| `assets/oui.tsv` | fabricants par préfixe MAC (liste IEEE), rangés en tableaux triés à la compilation (`build.rs`) |
| `assets/yara/` | règles YARA de ReversingLabs (licence MIT), rassemblées par `outils/maj-yara.sh` |
| `assets/banniere-blanche.png`, `assets/banniere-noire.png`, `assets/icones/`, `assets/vanguard.ico` | la bannière (sans fond, une par thème de GitHub) et l'icône (le V), dessinées case par case dans l'écriture de la bannière du terminal par `outils/icone.py` |
| `LICENCES-TIERCES.txt` | avis de licence des bibliothèques incluses (`outils/licences-tierces.py`) |
| `src/commande.rs` | lancement des commandes du système avec un délai maximal (`commande::lancer`), sorties lues en fond : un outil qui ne répond plus ne fige jamais Vanguard |
| `src/http.rs`, `src/http/envois.rs` | les demandes HTTPS de Vanguard (reqwest, à la place de curl), bornées en taille et en durée, vers une liste fermée d'hôtes que le test `envois` compare au modèle de menace ; une clé d'API ne passe jamais par la ligne de commande d'un autre programme |
| `src/journal.rs` | journal des erreurs, anonymisé, sur la partition VANGUARDLOG de la clé ou dans le dossier de Vanguard ; rapatrié par `outils/deployer.sh` |
| `src/diagnostic.rs` | diagnostic de l'ordinateur : matériel, système, erreurs et plantages récents ; une copie texte enregistrée |
| `src/fenetre.rs` | la fenêtre du terminal à la taille de chaque menu, centrée sur l'écran |
| `src/essais.rs` | pour les tests seulement : un essai qui ne peut pas tourner ici se dit « sauté », et `outils/verifier.sh` compte les sauts |
| `src/machine/administrateurs.rs`, `journaux.rs`, `navigateur.rs`, `navigation_detournee.rs` | nouveaux administrateurs (notés la première fois qu'ils sont vus) ; journaux scellés ou effacés ; réglages de sécurité des navigateurs ; proxy imposé et fichier hosts détourné, au bilan |
| `src/machine/logiciels_vus.rs`, `sshd.rs`, `windows/ssh.rs`, `windows/defender.rs`, `macos/parite.rs` | logiciels installés gardés d'un bilan à l'autre (logiciels-vus.json, scellé, jamais envoyé) ; lecture de sshd_config commune aux trois systèmes ; serveur OpenSSH et clés .ssh sous Windows (registre, WMI, droits des fichiers) ; protections de Defender que « durcir » active, relues au bilan ; mots de passe, démarrage sécurisé et persistance hors de launchd sous macOS |
| `src/machine/post_quantique.rs` | bilan post-quantique en lecture seule (COM-PQC-001 à 003) : liste d'échanges de clés que sshd et ssh retiennent vraiment selon la version d'OpenSSH (calcul dans `sshd.rs`), clé pré-partagée des tunnels WireGuard comptée sans jamais garder les clés ; l'échange post-quantique des navigateurs (COM-NAV-004) est dans `navigateur.rs` |
| `src/mise_a_jour/github.rs` | mise à jour depuis GitHub : manifeste signé en Ed25519 (clé principale ou de secours), plus haute version déjà vue, fraîcheur ; historique signé des versions, pour vérifier une copie qui n'est pas la dernière |
| `src/protection/integrite.rs`, `isoler.rs`, `memoire_dns.rs` | intégrité des fichiers critiques (empreintes BLAKE3) ; bac à sable d'un programme inconnu (bubblewrap ou firejail, Windows Sandbox, sandbox-exec), aussi pour les extensions ; la mémoire DNS de l'ordinateur, lue sans la vider |
| `src/protection/kev.rs`, `sites_bloques.rs`, `src/reseau/upnp.rs` | catalogue des failles exploitées de la CISA ; sites dangereux bloqués par le fichier hosts (URLhaus, ThreatFox) ; ports ouverts vers Internet par UPnP |
| `fuzz/` | banc de fuzzing, hors de la compilation du programme : une cible par lecteur, qui inclut son module de `src/` par son chemin (`fuzz/cale/` pour le reste), graines aux valeurs inventées (`outils/fuzz.sh`) |

### Extensions (plugins et laboratoire)

Une extension ajoute un programme sans toucher au code de Vanguard : un plugin (dossier + `plugin.toml`, outil
durable) ou un script du labo (posé tel quel). Le mode d'emploi, le manifeste et le protocole des constats sont dans
[extensions/LISEZMOI.md](extensions/LISEZMOI.md) ; un plugin en Rust s'écrit avec [extensions/sdk](extensions/sdk).

Ce qui ne doit pas changer sans relire la conception (`src/plugins/mod.rs`, en tête) :

- une extension ne tourne qu'à la demande et ses constats ne touchent jamais la note : ni l'audit, ni
  l'historique, ni `risk::score` ne les voient (section à part du rapport HTML) ;
- restrictions actives (par défaut) : approbation par SHA-256 de tout le dossier, analyse YARA et MalwareBazaar
  avant l'accord, la copie hachée est celle qui tourne, aucun lien suivi, jamais tout seul en administrateur, sans
  terminal (setsid, CREATE_NO_WINDOW), `commande::lancer_borne`, environnement minimal ;
- un manifeste ne fait que demander (`confiance`, `dans_le_bilan`, `dans_la_surveillance`) : seule la personne
  accorde, et l'accord est lié à l'empreinte (`reglages::Confiance`) ;
- en administrateur, rien du dossier ne lève une garde : jamais tout seul, et chaque lancement est demandé ;
- même restrictions coupées, le dossier des extensions reste à soi et fermé aux autres comptes (`dossier_sur`).

Les essais (`src/plugins/tests.rs`) lancent de vrais scripts dans des dossiers jetables, et `tests/programme.rs`
ajoute puis lance le plugin d'exemple par le vrai programme. `outils/verifier.sh` compile et teste aussi le sdk et
l'exemple en Rust (étape « extensions »).

### Ajouter une règle au bilan

Une règle s'écrit dans le fichier de son thème et s'y déclare, sans liste centrale :

```rust
inventory::submit! {
    crate::machine::regles::Regle {
        id: "LNX-NOY-002",                 // système, domaine, numéro : stable, jamais réutilisé
        systeme: crate::machine::regles::Os::Linux,
        sujet: ("BPF réservé à root", "BPF reserved for root"),
        references: &["kernel.org : unprivileged_bpf_disabled"],
        verifier: || bpf().into_iter().collect(),
    }
}
```

Le bilan la lance en parallèle avec les autres, dans l'ordre des rangs (`rang` : 10 pour le pare-feu, 100 et plus pour
le système, 500 et plus pour les règles communes), et chacun de ses constats porte son identifiant jusqu'au rapport
JSON. Les vérifications d'avant le registre sont déclarées dans `regles.rs` de leur système et dans
`src/machine/regles_communes.rs` ; une nouvelle se déclare plutôt à côté de sa vérification, avec la macro `regle!`.
Le jugement s'écrit à part (`juger_…`, sans rien lire du système), pour se tester sur des données inventées.

## Règles d'une contribution

- Tout en Rust ; les petites briques faites maison ; aucune nouvelle dépendance sans décision de l'auteur ;
  cryptographie auditée seulement, jamais écrite pour Vanguard.
- Une nouvelle destination réseau : une ligne dans « Ce qui sort de l'ordinateur » de MODELE-DE-MENACE.md (et .en.md),
  sinon le test `envois` échoue.
- Une nouvelle règle : sa technique MITRE ATT&CK (détection) ou sa mesure d'atténuation (durcissement) dans ses
  références, puis `python3 outils/couverture-attack.py` pour refaire la carte.
- Un fichier d'état que Vanguard relit : scellé, et une valeur changée hors de Vanguard ne coupe aucune défense ni ne
  donne aucun accord.

## Compiler, tester, déployer

Prérequis : `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu`, `musl` (musl-gcc), `mingw-w64-gcc`
et `clang` : ring (TLS) compile un peu de C pour chaque cible, et YARA-X aussi, l'oracle des tests (clang pour clippy sur les cibles Mac, voir
`outils/verifier.sh`). Pour déployer, aussi `cargo install cargo-auditable --locked --version 0.7.7` et
`cargo install cargo-audit --locked --version 0.22.2`, les versions de la CI (`.github/workflows/ci.yml`) :
`deployer.sh` grave dans chaque programme la liste de ses dépendances, versions comprises (`cargo auditable build`),
puis y cherche les failles connues (`outils/failles-programmes.sh`) ; sans eux, ou dans une autre version, il refuse.

```sh
outils/deployer.sh     # compile Linux (musl, statique) + Windows, installe en local, pousse sur GitHub, met à jour la clé
```

Bilan lent ? `VANGUARD_CHRONO=1 vanguard audit --json >/dev/null` donne le temps de chaque vérification (elles
tournent en même temps : la plus lente fait la durée).

Tests : `cargo test` (Linux, dans un dossier de données jetable : jamais les vraies données de l'ordinateur) ; tests
Windows sous Wine (`cargo test --target x86_64-pc-windows-gnu` avec un lanceur Wine) ; `cargo clippy --all-targets`
sur les quatre cibles (Linux, Windows, `aarch64-apple-darwin`, `x86_64-apple-darwin`), en mode strict (pedantic),
sans remarque ; `cargo fmt --check`. Les fonctions internes sont testées dans leur module ; `tests/programme.rs` lance
le vrai programme comme le ferait quelqu'un (aide dans les deux langues, menus quittés, listes, refus respectés, audit
et scan de 127.0.0.1 en JSON), avec un dossier personnel jetable, sans la clé ni la session de l'utilisateur. Essais
complets : `outils/test-linux/essai.sh`, `outils/test-macos/essai.sh` (sur
un Mac de GitHub) et, dans la machine virtuelle Windows, `TESTER-VANGUARD.bat` (déposé par `deployer.sh`).

macOS : compilé et testé sur un Mac de GitHub (`.github/workflows/macos.yml`, programme universel Apple Silicon +
Intel), chaque nuit si le code a changé ou à la demande (`gh workflow run macos.yml`). `deployer.sh` récupère la
dernière compilation réussie pour la clé. Sur master, il produit aussi les nomenclatures (SBOM CycloneDX,
`outils/sbom.sh`), et un travail à part, « attester », atteste le programme et ces nomenclatures (actions/attest,
Sigstore), sans rien lancer du dépôt.

Intégration continue (`.github/workflows/ci.yml`) : à chaque envoi sur master et à chaque demande de fusion,
`outils/verifier.sh --ci`, la même vérification que sur l'ordinateur de l'auteur sauf Wine, puis le bilan sur de
vraies distributions ; un vrai Windows (PowerShell, registre) à chaque envoi, à chaque demande de fusion, la nuit si
le code a changé (`.github/hors-code.txt`) et à la demande (`gh workflow run ci.yml`), avec la compilation
reproductible et le .exe livré (MinGW) essayé sur Windows. `verifier.sh` relit aussi les workflows avec zizmor (hors ligne) et
compile tout en `--locked`. Chaque nuit : cargo audit, cargo deny, et cinq minutes
de fuzzing par cible. Le dépôt est public : les minutes de Linux et de Windows ne comptent pas.

Tests sautés : un test qui ne peut pas tourner sur un ordinateur (outil du système absent, registre inaccessible,
root d'un espace de noms) ne rend pas la main en silence, il appelle `crate::essais::saute("raison")`
(`src/essais.rs`) : `verifier.sh` compte ces sauts à côté des tests passés et en montre les raisons, car un test
sauté n'a rien vérifié. La navigation dans les menus est essayée pour de vrai dans un pseudo-terminal
(`tests/programme.rs`, `menus_dans_un_terminal`), et les textes affichés comparés à master (`outils/textes.py`).

Dépendances : `cargo deny` (`deny.toml` : failles connues de RustSec, licences de sa liste, crates.io seulement,
doublons ; `extensions/deny.toml` pour la bibliothèque des extensions et l'exemple en Rust, sans dépendance) et
`cargo audit` (second avis sur les failles, avec les seules exceptions de `deny.toml`, que `.cargo/audit.toml` recopie),
dans `outils/verifier.sh` (sautés sans l'outil, cargo audit aussi sans Internet) et chaque nuit dans la CI. `cargo vet`
(`supply-chain/`) exige en plus, à chaque vérification et hors ligne, une relecture importée (Google, Mozilla,
Bytecode Alliance, Zcash, ISRG) ou une exemption au numéro exact pour chaque version : après un `cargo update`,
`cargo vet` (avec Internet) relit les registres et nomme ce qui manque ; chaque version qui reste reçoit son exemption
une à une, avec sa raison (`cargo vet add-exemption <crate> <version> --criteria … --notes "…"`), jamais par
`cargo vet regenerate exemptions`, qui exempterait d'un coup une dépendance inconnue entrée avec les autres ;
`cargo vet prune` retire ce qui ne sert plus, et le diff de `supply-chain/config.toml` se relit. La liste
ne garde que des licences permissives (MIT, Apache-2.0, BSD, ISC…), compatibles avec la GPL-3.0-or-later et avec une
double licence possible de Vanguard : toute autre, même libre et compatible avec la GPL (MPL, LGPL), demande d'abord
l'accord de l'auteur.

Fuzzing : `outils/fuzz.sh [cible|tout] [secondes]` (cargo-fuzz et la chaîne nightly), sur les lecteurs de données venues
d'ailleurs (plist, réponses HTTP et DNS, journaux de la chronologie, journaux .evtx de Windows, XML UPnP de la box, SQLite, YAML d'Échap,
archives, ressources des .exe…). `outils/verifier.sh` compile le banc et passe cinq secondes sur chaque cible (une
cible cassée par un changement de `src/` se voit tout de suite), la CI cinq minutes chaque nuit ; ses dépendances
passent à cargo deny (`fuzz/deny.toml`). Une cible s'ajoute dans `fuzz/Cargo.toml`, que `fuzz.sh` lit.

Preuves : `outils/preuves.sh [tout|miri|kani]` (chaîne nightly avec Miri, et Kani), chaque jeudi par la veille
continue. Miri interprète les essais des `unsafe` qui portent sur la mémoire de Vanguard, et eux seuls : le script
les lance à leur nom exact ; un essai qui appelle le système n'est pas dans sa liste ; Kani prouve, dans
une borne, quelques lecteurs de données hostiles (`outils/preuves/`, inclus par `#[cfg(kani)]` à la fin de leur
module). À relancer après avoir touché à l'un d'eux ; `outils/verifier.sh` compile les preuves de Kani à chaque
vérification (quelques secondes, sans les lancer).

Liens morts : `outils/liens.py` ouvre tous les liens du dépôt (documentation, code du programme hors tests, scripts,
licences) et vérifie les liens internes des pages Markdown : fichier visé, titre d'une ancre, téléchargements de la
dernière version. Il est lancé tout seul avant chaque envoi par `deployer.sh` et avant chaque page de version ; la CI
vérifie les liens internes (`--hors-ligne`). Un lien mort arrête l'envoi, un lien douteux (site qui refuse les
programmes, serveur en panne) est seulement montré. Les liens qu'on ne peut pas ouvrir tels quels (point d'accès
d'une API, espace de noms) se décrivent dans `outils/liens.txt`.


### Compilation reproductible

Les programmes publiés sont compilés par `outils/compiler-version.sh`, la même recette pour `outils/deployer.sh`, la
CI et quiconque veut refaire un programme à partir de son étiquette : la chaîne de `rust-toolchain.toml`, Cargo.lock
tel quel, cargo-auditable de la version de la CI, la date du commit (jamais l'heure de la compilation), et les chemins
de la compilation retirés (le dépôt devient `/vanguard`, le dossier de cargo `/cargo`). Mesuré le 23 octobre 2026 :
le même commit compilé dans deux dossiers différents de cet ordinateur donne deux programmes identiques, Linux comme
Windows ; avant, les chemins du dossier personnel restaient dans le .exe (`~/Projects/vanguard/target/…`), et deux
dossiers donnaient deux programmes. Ce qui peut encore différer d'un ordinateur à l'autre : les versions de musl-gcc
et de MinGW (gcc, binutils, bibliothèques de démarrage), qui compilent le C de ring et lient les
programmes. La CI écrit l'empreinte de ses compilations dans son journal (`EMPREINTE-VANGUARD-LINUX`, `-WINDOWS`), à
comparer à `SHA256SUMS.txt` ; elles ne sont pas encore les mêmes que celles de l'ordinateur de l'auteur tant que ces
outils diffèrent (Arch contre Ubuntu).

## Captures d'écran et image de partage

`outils/captures.py` refait les captures du README (`assets/captures/`, en français et en anglais) et l'image de
partage du dépôt (`assets/partage.png`). `deployer.sh` le lance pour chaque version publiée, puisque le menu montre
son numéro, et commite les images à part.

Vanguard y tourne pour de vrai, dans un pseudo-terminal de 80 colonnes, depuis une fausse clé et sur une copie des
données : rien de vrai n'est touché. Le nom du réseau devient « Salon » ; adresses MAC (préfixe du fabricant gardé),
adresses IP (un réseau inventé, longueurs et ordre gardés), noms d'appareils et dossiers du compte sont remplacés, au
hasard à chaque passe ; du bilan de la machine, seul un extrait sans rien de personnel est montré. Puis le garde-fou
de confidentialité relit chaque image : si un détail de la maison restait visible, aucune n'est écrite.

```sh
uv run --no-project --with pyte python outils/captures.py [programme] [--connexion | --sans-connexion]
```

## Confidentialité

`outils/confidentialite.py` empêche qu'un détail personnel parte sur GitHub. Il est lancé tout seul : à chaque commit
(lignes ajoutées, noms de fichiers, auteur, message), avant chaque envoi par `deployer.sh`, avant chaque page de
version (notes et programmes compilés), avant chaque ticket du journal et avant d'écrire les captures. Une fois par
copie du dépôt :

```sh
git config core.hooksPath outils/hooks                                     # crochets pre-commit et commit-msg
git config user.email "<id>+<compte>@users.noreply.github.com"            # commits sans ton courriel
```

Ce qui est personnel est lu sur l'ordinateur, jamais écrit dans le dépôt : `~/.config/vanguard-dev/confidentiel.txt`
(une expression par ligne : nom, courriels, adresse…), l'identité Git globale, le dossier personnel, les appareils et
adresses MAC de la base de Vanguard, les réseaux Wi-Fi enregistrés. Les données des autres (la clé passe chez des
amis, et leur journal d'erreurs revient ici) sont reconnues à leur forme : compte d'un dossier personnel, courriel,
SID de Windows ; un ticket du journal est masqué avant l'envoi, adresses MAC et IP comprises. Sur GitHub, la CI le
repasse sur les commits de chaque envoi et de chaque demande de fusion (`--generique --plage`) : seulement les données
reconnues à leur forme, sans l'identité de la machine qui le lance.
`python3 outils/confidentialite.py --depot` relit tout le dépôt et son historique. Dans les tests, des valeurs
inventées : adresses MAC au préfixe du fabricant gardé, réseau « Salon », comptes « alice », « bob », « Zoé »,
« Jean Dupont », courriels `@example.com`.

Rust garde le chemin des bibliothèques dans les programmes (`/home/<compte>/.cargo/registry/…`) : pour publier une
version, compiler avec `rustflags = ["--remap-path-prefix=/home/<compte>=~"]` dans `~/.cargo/config.toml`
(`publier-version.sh` refuse un programme qui contient encore le dossier personnel).

## Publier une version

`outils/publier-version.sh` crée la page de la version sur GitHub (Releases) avec les trois programmes
(`vanguard-windows-x86_64.exe`, `vanguard-linux-x86_64`, `vanguard-macos`), leurs empreintes SHA-256, leurs
nomenclatures (`vanguard-<système>.cdx.json`, faites par `outils/sbom.sh`, qui demande cargo-cyclonedx 0.5.9 : identiques
à celles du Mac de GitHub, dont l'attestation est vérifiée avant de publier) et, en notes, le
commit de chaque version depuis la page précédente (titre et puces), la plus récente en tête ; les liens de
téléchargement du README pointent toujours vers la dernière. `--notes` montre ces notes sans rien publier.

Chaque publication va sur la clé, dans la VM et sur GitHub (le code), avec sa page, 0.x.0 comme 0.x.y : une par jour en
règle générale, puisque moins de pages, c'est moins de minutes de Mac sur GitHub, et moins de programmes neufs que
Defender et SmartScreen ne connaissent pas encore. Une version intermédiaire d'une série livrée d'affilée
(`VANGUARD_INTERMEDIAIRE=1 outils/deployer.sh`) va sur la clé et sur GitHub, sans page ni dépôt dans la VM : rien ne se
perd, puisque la page suivante reprend les versions d'avant. Le Mac de GitHub compile la nuit quand le code a
changé, et pour chaque page : la version macOS de la clé peut retarder sur les deux autres, et le déploiement le dit.
Après chaque envoi, il met aussi à jour la page du dépôt (`outils/github.py`) : description en anglais suivie de la
dernière version publiée, lien, sujets et options, écrits dans `.github/depot.json`. Seule l'image de partage se
change à la main (Settings > Social preview).

## La clé USB

La clé (exFAT, étiquette `VANGUARD`, fichier témoin `vanguard.cle`) contient `Linux/`, `Windows/`, `macOS/`, `donnees/`
(base des appareils, portable), `source/` (ce dépôt) et le guide en deux langues (`LISEZMOI.txt`, `README.txt`, tirés
de `outils/`). L'historique des bilans et la quarantaine restent sur chaque ordinateur.

Sur le PC de développement, elle se met à jour toute seule (unités systemd dans `outils/systemd/`, installées par
`outils/systemd/installer.sh`) : après chaque compilation (`vanguard-copie.service`), à chaque branchement avec la
dernière version de GitHub, compilée si elle est nouvelle (`vanguard-cle.service`, `deployer.sh --branchement`), et
chaque jour si elle reste branchée (`vanguard-cle-maj.timer`, `outils/maj-cle.sh` : le programme comme au branchement,
puis les images ; sautée sans erreur si la clé n'est pas montée).

La clé a deux partitions : `VANGUARD`, en lecture seule partout sauf sur l'ordinateur du propriétaire (attribut GPT
respecté par Windows ; sous Linux et macOS, Vanguard la remonte lui-même en lecture seule), et `VANGUARDLOG`, qui ne
reçoit que le journal des erreurs, anonymisé. `outils/preparer-cle.sh` prépare une nouvelle clé.

En préparation, une clé de secours qui démarre aussi les ordinateurs : `outils/cle-secours.sh`, faite par défaut,
sauf sur un ordinateur dont le réglage local la coupe (`CLE_SECOURS=non` dans `~/.config/vanguard/images-cle.conf`,
lu sans être exécuté ; le détail en tête de `outils/images-cle.sh`). Là, la clé ne porte que le programme : ni images,
ni Ventoy, ni `WIN11` ni `MACOS`, les commandes qui en poseraient refusent en le disant et les minuteries ne copient
rien. Ventoy démarre l'installateur d'Omarchy, Arch, Debian et Fedora en installateurs par Internet, SystemRescue et Windows 11 en secours,
tenus à jour par `outils/images-cle.sh` (signature de chaque projet vérifiée, minuterie du 1er et du 15 du mois qui
copie aussitôt sur la clé branchée, copie au branchement, une notification au début de chaque téléchargement et quand
rien n'est nouveau ; une image téléchargée ailleurs entre dans le cache par `--importer`, vérifiée de même ; le cache
peut être un lien vers un autre disque : disque absent, rien n'est recréé ailleurs ; une image en option, coupée par
défaut, n'y entre que sur un ordinateur dont le réglage local la demande, lu sans être exécuté) ; une partition FAT32
`WIN11` installe Windows 11 avec Secure Boot actif, sans ajouter de clé au PC (`install.wim` découpé par wimlib sous la
limite de 4 Go) ; une partition HFS+ porte la récupération de macOS des Mac Intel ; `VANGUARD` et `VANGUARDLOG` comme
avant. `--plan` et `--essai` (sur une image de disque) ne touchent à aucun disque ; seul `--ecrire` efface la clé.
Ventoy lui-même : sa version sur la clé est lue chaque jour et au branchement (`cle-secours.sh --a-jour`) ; plus
ancienne que celle épinglée, sa mise à jour, qui n'efface rien (`Ventoy2Disk.sh -u`, journalisée), est proposée par une
notification à cliquer. Elle passe par une partie root à part, `outils/ventoy-racine.sh`, installée une fois en fichier
de root (`cle-secours.sh --installer-racine`, dans `/usr/local/libexec/vanguard/`) et lancée par pkexec : le compte ne
peut pas la modifier, et c'est elle qui tient l'épingle et revérifie tout (la clé et son numéro de série, l'archive, une
version plus ancienne sur la clé). Un Ventoy plus récent sur GitHub est signalé au développeur par la recherche du 1er
et du 15, jamais pris tout seul : l'archive n'est pas signée, l'épingle change à la main, puis la partie root se
réinstalle. Windows 11 de plus de six mois (la date des fichiers de son image) est signalé par une notification, pas
remplacé : Microsoft ne donne qu'un lien de 24 heures, et l'empreinte qui vérifie l'image se lit sur sa page. La
récupération de macOS n'a pas d'âge qui compte : elle installe le dernier macOS, pris chez Apple au moment d'installer.
`outils/essais-cle.sh` (lancé par `outils/verifier.sh`) éprouve ces outils sans rien toucher : espace de noms à part,
sans Internet, fausse clé et faux disque.

## Erreurs et plantages

Vanguard les note sans rien de personnel (sur la clé, ou dans son dossier quand la clé n'est pas branchée). Au
déploiement, `deployer.sh` les rapatrie et `outils/journal-vers-github.py` en fait des tickets GitHub (étiquette
« journal ») avec `gh` : un ticket par erreur, les répétitions en commentaire. Aucun mot de passe GitHub dans le
programme ni sur la clé.
