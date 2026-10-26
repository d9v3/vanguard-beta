# Historique des versions

*[English](CHANGELOG.en.md)*

Ce que chaque journée a apporté à Vanguard, la plus récente en haut. Depuis le 19 octobre 2026, Vanguard a en principe
une seule publication par jour, qui regroupe le travail de la journée ; le 21 octobre en a eu deux, la 0.82 au matin et
la 0.84 au soir, qui reprend la 0.83 livrée juste avant elle. Seule la dernière version a sa page de téléchargement ;
chaque version garde son étiquette dans le dépôt (`git checkout v0.62.0`, par exemple), pour être recompilée au besoin.

## Prochaine version

- **Régression de détection.** Un corpus de cas fabriqués et inoffensifs (tests/corpus-detection) prouve, par 77 cas
  (une partie par système), que les règles et outils de détection tirent encore (selon le système : chacune tourne là
  où elle existe), à leur gravité exacte, et qu'un cas propre les laisse muettes. Pour cela, les 21 règles dont la
  lecture et le jugement étaient mêlés (persistance et programmes privilégiés de Linux, comptes, SSH, sudo, intégrité,
  agents et extensions de macOS, démarrage et journaux de Windows, fiches de l'audit du réseau) ont leur jugement à
  part, au même comportement. Chaque règle qui cite une technique d'ATT&CK, et chaque outil qui détecte, a son cas ou
  sa raison ; le fil de chaque règle jusqu'à son jugement est tenu, et verifier.sh en fait deux étapes (Linux et
  Wine). Une règle qui ne rend qu'une information se prouve par un cas propre muet, et une règle qui dit toujours une
  partie non vérifiée (un magasin illisible sans outil) le dit aussi dans son cas propre, à côté d'au moins un constat
  vérifié, sauf une, nommée avec sa raison. Les outils et les alertes de la surveillance (fichier téléchargé, lien,
  courriel, logiciel espion, prise de contrôle, secret dans un dépôt, serveur de commande, fichiers critiques,
  routeur, Wi-Fi, appareil ou port nouveau, empoisonneur de noms) ont aussi les leurs ; les analyses YARA, les
  veilleurs en direct et la protection active, ainsi que la liste des programmes qui parlent à Internet (un
  inventaire), sont exemptés avec leur raison.
- **Autres fichiers d'état scellés, un seul juge.** La liste des fichiers-pièges, les ports bloqués, le carnet des
  appareils de cet ordinateur, les références de la clé VANGUARD, l'entretien du mois, la note de la sauvegarde et la
  dernière passe de la surveillance sont scellés : changés, effacés ou acceptés tels quels après des sceaux refaits,
  ils ne coupent plus rien (un piège reste attendu, un port exposé est redit, chaque appareil est redit nouveau, la
  clé n'est jamais dite intacte, rien n'est annulé d'après une note forgée), et c'est dit. Tous les lecteurs suivent
  le même juge ; seul un fichier repris par une mise à jour connue se croit tel quel. Une mise à jour ne se croit que
  sur preuve : la tête du journal des événements, scellée, écrite par la version d'avant ; sans elle (journal effacé,
  tête réécrite), des sceaux ramenés à une forme d'avant n'acceptent ce qui est là que tel quel, sans le croire, et le
  bilan dit les sceaux refaits. Une version plus ancienne repassée ici (une clé ou un Mac restés en arrière) se dit au
  bilan un cran plus bas, sans rien faire reprendre. Un verrou des sceaux gardé par un autre programme ne fait plus
  attendre qu'une fois, une seconde en tout, et se dit au bilan ; vanguard --version n'attend rien ; les événements
  qui n'ont pu être notés sont comptés et dits au bilan une fois le verrou rendu (si Vanguard est tué avant, ses
  événements en attente se perdent sans compte), et « sceaux refaits » retombe une fois dit. Un test relit le code
  pour que chaque nom de fichier scellé n'y paraisse que là où il est permis, exceptions dites ; VANGUARD_ORIGINE
  n'est crue qu'aux octets du programme qui tourne. Le modèle de menace dit les limites : le dossier effacé en entier,
  et un programme qui vise exprès ce mécanisme.
- **Extensions et listes téléchargées scellées.** Les réglages des extensions (« sans restrictions », « à moi »,
  lancement avec le bilan ou la surveillance) et leurs approbations sont scellés : changés hors de Vanguard, ou
  acceptés tels quels (sceaux refaits, version d'avant), ils n'accordent plus rien, rien ne tourne tout seul, et c'est
  dit au menu et au bilan (COM-ETA-001). Chaque liste téléchargée (Feodo Tracker, ThreatFox, URLhaus, MalwareBazaar,
  KEV, Échap, LOLDrivers, versions des logiciels) est scellée avec sa date de téléchargement : son âge vient de cette
  date, plus de celle du fichier ; vidée, sans sceau ou datée dans le futur, elle est redemandée, et si elle ne peut
  pas l'être, « non vérifiée » avec la raison, jamais saine.
- **Défenses voulues et programme lancé, jugés sur un état scellé.** La mise en marche et l'arrêt de la surveillance
  horaire, du veilleur et de la veille anti-rançongiciel par Vanguard sont notés dans un état scellé et au journal
  (ceux d'une version d'avant sont repris tels quels) : leur marque effacée avec leur tâche, ou cette note changée
  hors de Vanguard, le bilan dit la défense coupée sans passer par Vanguard (jamais plus « coupée, comme par
  défaut ») ; une note perdue avec les sceaux est « non vérifiée », jamais verte. L'état du veilleur est scellé, et un veilleur
  n'est dit vivant que si son processus lance le programme de l'unité ; celui d'avant une mise à jour, encore en
  marche, est dit avec le remède et relancé par la mise à jour de Vanguard. Le programme que lance chaque tâche
  (surveillance, entretien, veilleur) et le texte de la tâche (unité et minuterie, tâche planifiée, agent) ont leur
  empreinte BLAKE3 scellée à la pose et à chaque mise à jour par Vanguard : un autre chemin, d'autres octets ou une
  tâche changée sont une alerte élevée ; une version publiée et signée posée hors de Vanguard est reconnue par
  l'historique signé des versions et dite en information.
- **Journaux de Windows : un seul juge, deux règles de plus, une place au menu.** Le bilan (WIN-JRN-003) ne lit plus
  les journaux lui-même : il reprend les treize règles EVT- de « Que s'est-il passé ? », alertes au même niveau, et
  « non vérifié » avec sa raison quand un journal manque ou est réservé à l'administrateur ; le rapport HTML ne montre
  plus deux fois les journaux de cet ordinateur. Nouvelles règles : EVT-TAC-001, tâche planifiée créée ou changée
  pour lancer un interpréteur, une commande encodée ou un programme d'un dossier temporaire (audit des tâches, ou
  historique du Planificateur) ; EVT-PRC-001, processus suspects (outils d'attaque connus, commande encodée,
  téléchargement par certutil, bitsadmin, mshta, regsvr32 ou rundll32), si la ligne de commande est journalisée.
  Coupés d'origine, ces réglages sont nommés quand ils manquent. Une tâche mise à jour (événement 140 du
  Planificateur) est dite en information. Le bilan liste aussi les services ordinaires installés pendant la période
  (cinq noms au plus), et un journal effacé n'y est plus dit deux fois : COM-JRN-001 laisse à WIN-JRN-003 ceux qu'il a
  lus, et dit lui-même les autres, chacun à part (une alerte déclarée normale n'en tait plus un autre). Menu Bloquer et réagir › Journaux de
  Windows : ce Windows, ou un dossier de .evtx sous Linux et macOS.
- **macOS maintenu, sans nouveautés propres.** Le programme macOS reste publié et testé automatiquement sur un Mac
  de GitHub ; il n'a jamais été essayé sur un vrai Mac, et la page, les README et les notices le disent.
- **Optimiser refusé en administrateur.** Les outils d'Optimiser (logiciels, nettoyage, réglages, jeux, mesures du
  réseau) refusent de tourner quand Vanguard a été élevé depuis un compte ordinaire (`sudo vanguard`, console
  administrateur avec l'UAC) : ils installent, effacent ou lisent ce que le réseau envoie, et chaque geste
  d'administrateur se demande déjà au moment voulu. « Tout remettre comme avant » n'est jamais refusé ; root seul et
  Windows sans UAC gardent les outils, avec l'avertissement.
- **Post-quantique sous Windows.** La version du serveur OpenSSH de Windows est lue (son chemin `%SystemRoot%\…` est
  développé) : COM-PQC-001 ne la dit plus illisible.
- **Clé USB : les images de secours de nouveau par défaut.** Les outils du dépôt refont la clé de secours partout :
  Ventoy, les images d'installation et de réparation (SystemRescue, Arch, Omarchy, Debian, Fedora, chacune vérifiée
  par la signature de son projet), Windows 11 et la récupération de macOS. Une ligne `CLE_SECOURS=non` dans
  `~/.config/vanguard/images-cle.conf` la coupe sur un ordinateur (la clé ne porte alors que le programme) ; Kali Linux
  reste en option (`IMAGES_EN_PLUS="kali"`). Le démarrage de la clé sur un vrai ordinateur n'a pas encore été essayé.
- **Paquets de l'AUR envoyés seulement avec votre accord.** Sous Arch Linux, le bilan envoyait à aur.archlinux.org le
  nom de chaque paquet installé hors des dépôts officiels, sans le demander (règle LNX-MAJ-006, et les mises à jour de
  l'AUR quand yay ou paru est là). Un nouveau réglage, Paramètres › Paquets de l'AUR (13ᵉ, coupé par défaut), donne
  cet accord ; sans lui, rien n'est envoyé et ces paquets sont dits non vérifiés.
- **Liste fermée de ce qui sort.** Vanguard ne joint plus en HTTPS qu'une liste fermée de sites, même au bout d'une
  redirection (seul rdap.org peut renvoyer au registre d'un domaine, et sur GitHub seuls les dépôts lus sont permis) ; le modèle de menace les nomme tous, avec les
  connexions directes (DNS, STUN, listes noires) et ce qui part vers chacun. Un test échoue si une destination écrite
  dans le code manque à la page. L'âge du domaine d'un lien examiné se lit de nouveau (la redirection de rdap.org
  vers le registre était refusée) ; le nom inventé du bilan DNS ne nomme plus Vanguard et ne part plus hors ligne.
- **Carte de couverture MITRE ATT&CK.** Les règles citent la technique d'ATT&CK qu'elles détectent (T…) ou la
  mesure d'atténuation qu'elles appliquent (M…) dans leurs références, comme le CIS : 160 règles sur 206. Une page
  générée, [COUVERTURE-ATTACK.md](COUVERTURE-ATTACK.md), les range par tactique (version 20 d'ATT&CK) et montre les
  techniques qu'aucune règle ne voit encore : la liste des manques, tenue à jour par le code. Un test refuse un
  identifiant qui n'existe pas ou plus dans ATT&CK, et `outils/verifier.sh` une carte qui n'est plus à jour.
- **Modèle de menace.** Une page dit ce que Vanguard protège, contre qui, ce qu'il ne protège pas (un attaquant
  déjà administrateur, le noyau, une menace encore sans signature…) et ce qu'il suppose
  ([MODELE-DE-MENACE.md](MODELE-DE-MENACE.md)) ; le README et `vanguard --help` y renvoient.
- **Publication des versions et clé** (campagne d'attaque n° 4). La reprise d'un déploiement arrêté en route ne fait
  plus entrer dans la référence de la clé ce qui y a changé entre-temps : ce que le déploiement pose et qui diffère est
  retiré de la clé, puis reposé (un programme Mac sans compilation n'y revient pas). Le point sûr que la clé de secours ne dépasse pas se forge
  lui aussi avec la clé principale volée : signé par elle, ses versions (date et début des empreintes) sont montrées à
  l'auteur, et la clé de secours ne contresigne rien sans « contresigner » tapé. Seul l'auteur sait ce qu'il a publié :
  une version forgée sous un numéro qu'il reconnaît, sans date ni empreinte qu'il remarque, passe encore. Claude sur
  GitHub ne se lance plus sur un ticket ou une demande de fusion écrits par un autre que le propriétaire, ni sur un
  ticket du journal de la clé (écrit depuis n'importe quel ordinateur) : il les lirait comme des consignes.
- **Argument qui n'est pas de l'UTF-8.** Une erreur notée au journal de la clé pendant une commande dont un argument
  n'est pas de l'UTF-8 (un nom de fichier) ne fait plus avorter Vanguard : la commande y est écrite avec « � » à la
  place des octets illisibles.

## 24 octobre 2026 : version 0.87

- **Sécurité de la clé et de la publication** (campagne d'attaque n° 3). Au branchement, la clé est comparée à sa
  référence avant toute écriture : un fichier planté en voyage (raccourci, image, menu de Ventoy, archive tldr) ne
  devient plus « la clé n'a pas changé » ; rien n'y est écrit, une notification le dit, et seul
  `outils/deployer.sh --accepter-cle` reprend la clé telle qu'elle est. Les outils ne reconnaissent la clé qu'à son
  jeton connu de cet ordinateur, comme le programme : un volume étiqueté VANGUARD ne reçoit plus le programme ni le
  code source. Les images ISO sont suivies par leur empreinte SHA-256, relues une à une, recopiées si elles ont été
  remplacées ; la partition de démarrage VTOYEFI, par l'empreinte de ses fichiers. Le journal de la clé ne fait plus
  que 5 tickets GitHub par passage (10 par jour), et rien d'un journal suspect sans l'accord de l'auteur. La
  signature des versions garde un point sûr que la clé de secours ne dépasse pas ; les programmes publiés sont, octet
  pour octet, ceux de la compilation de leur commit (la 0.86.0 publiée est bien celle de son commit : seuls les
  compilateurs C de la CI diffèrent). Claude sur GitHub ne touche plus une demande de fusion venue d'un fork. La file
  d'essais de la VM ne fait plus que des travaux signés (HMAC du secret tiré à son installation, à refaire une fois),
  et ses verdicts sont signés.
- **Clé USB : le programme seul par défaut.** Une clé préparée par les outils du dépôt, sur n'importe quel ordinateur,
  ne porte plus que Vanguard, sa base, ses rapports et la partition VANGUARDLOG : ni images d'installation, ni Ventoy,
  ni partitions WIN11 et MACOS. La clé de secours complète ne se fait que sur un ordinateur dont le réglage local la
  demande (`CLE_SECOURS=oui` dans `~/.config/vanguard/images-cle.conf`, avec au besoin `IMAGES="…"` et
  `IMAGES_EN_PLUS="kali"` ; lu, jamais exécuté) ; sans lui, les commandes qui poseraient des images refusent en disant
  comment l'allumer, et les minuteries de recopie ne copient rien. La page du projet gagne sa section « Télécharger,
  vérifier, installer » : le programme de votre système, son empreinte vérifiée par `SHA256SUMS.txt`, puis
  `vanguard raccourci` et `vanguard se-mettre-a-jour` ; la clé USB en option, pour dépanner.
- **Fenêtre du menu.** Sous Linux (Hyprland), le cadre garde une hauteur fixe d'un menu à l'autre : chaque changement de taille s'animait, et la transition se voyait. Sous Windows, la fenêtre suit encore la hauteur de chaque menu, mais reste là où elle a été mise (ramenée dans l'écran seulement si elle en sort). Près du bas de l'écran, elle ne remonte que de ce qu'il faut ; dans la vieille console, qui ne signale pas qu'elle change de taille, le menu se redessine quand même.
- **Logiciels proposés.** Bitwarden s'installe par Flathub sous Arch (le paquet de la distribution est resté en
  2026.3.1) ; Flathub n'y distribue plus que sa version commerciale, qui se dit donc « pas libre »,
  alors que winget et Homebrew installent la version GPL-3.0. VeraCrypt sert aux clés USB, disques externes et coffres,
  le disque système allant à BitLocker ou LUKS. Rôles au vouvoiement.
- **Vouvoiement et vocabulaire.** Tout ce que Vanguard affiche en français vouvoie (menus, messages, aide de la
  ligne de commande, guide, rapports) et parle de « routeur », de « réseau local » et d'« adresse Internet publique »
  au lieu de « box » et de « maison » ; « Quelqu'un contrôle mon ordi ? » devient « Mon ordinateur est-il contrôlé ? »,
  « Box et objets connectés » « Routeur et objets connectés ». `outils/textes.py` refuse désormais un tutoiement dans
  un texte affiché. La surveillance horaire et l'entretien du mois notent la génération des textes : la première passe
  après la mise à jour compare les constats sans leur formulation, par ce qui désigne leur objet (adresses, ports,
  CVE), sans fausse alerte. Les alertes
  déclarées normales, reconnues à leur texte quand elles n'ont pas de clé, peuvent revenir une fois en français.
- **Données piégées.** Une archive de tldr-pages fabriquée (blocs deflate vides, entrées qui partagent leurs données)
  ne fige plus le guide des commandes : elle est refusée à sa forme, et la lecture s'arrête après 5 s ; une archive
  « fraîche » de la clé est contrôlée comme les autres, refusée si elle est abîmée ou datée dans le futur. Mémoire des
  programmes : une bibliothèque réécrite en mémoire, un programme effacé ou posé sur tmpfs est lu en entier, ses
  régions recollées (l'en-tête et le code ensemble, le point d'entrée à sa place) ; ce qui ne se juge pas est dit non
  vérifié, jamais ✔. Un faux point d'accès qui recopie l'adresse du routeur sur un autre canal est signalé. Plus
  jamais « rien trouvé » pour un fichier à vérifier qui est un lien ou un tube, pour un journal Windows présent mais
  vide, ni pour une liste coupée à sa borne (profils Wi-Fi, sessions, comptes) ; un faux GameMode ne reporte plus
  l'autotest de la semaine sans fin ; la comparaison de la clé à son manifeste ne suit plus un lien ni n'attend sur
  un tube. L'analyse des fichiers, pas encore branchée, voit les archives collées derrière
  une image, les macros dont seul le code compilé compte, les procédures cachées par une continuation de ligne et les
  relations OOXML cachées par un détail XML.

- **Nouveau menu.** La défense d'abord : sous « Bilan de sécurité » (1 à 3, inchangés), la partie **Cyberdéfense**
  (4 Cet ordinateur, 5 Réseau et Internet, 6 Virus et logiciels espions, 7 Arnaques et vie privée, 8 Bloquer et
  réagir), puis **En plus** (9 Données et sauvegardes, 10 Guide des commandes, 11 Dépanner pas à pas, 12 Optimiser et
  installer, 13 Vanguard). Aucun écran ne défile plus : les variantes passent dans un écran à choix (6.1 Analyse
  antivirus › rapide, complète, clé USB, YARA ; 5.1 Appareils du réseau ; 4.8 Pour les développeurs ; 9.3 Vérifier une
  copie ou sauvegarde ; 13.4 Vérifier Vanguard lui-même), joignable aussi par son chemin (« 6.1.3 »). Les lignes
  propres à un système vont en fin de groupe : Defender est toujours en 4.10. Entrent au menu : Programmes au démarrage
  (12.4), Journal des évènements (8.6), Règles du bilan (13.5), l'empreinte et l'autotest (13.4), et des raccourcis
  d'incident (8.3 à 8.5 vers les parcours 11.7, 11.10 et 11.11). L'invite dit « Numéro, ou un mot à chercher » ; la
  première ouverture le rappelle en tête du menu. Les chemins 1, 2, 3, 5.2, 10 et 11.1 à 11.12, les lettres d'avant la
  0.43 et « s » ne bougent pas ; les autres chemins ont changé de sens (rien ne se modifie sans accord) :

| 0.86 | 0.87 | | 0.86 | 0.87 | | 0.86 | 0.87 |
|---|---|---|---|---|---|---|---|
| 4.1 Audit de sécurité | 4.1 | | 5.14 Mode Wi-Fi public | 5.9 | | 6.20 Images Docker | 4.8.2 |
| 4.2 Mises à jour | 4.2 | | 6.1 Analyse rapide | 6.1.1 | | 6.21 Blocage des menaces | 8.1 |
| 4.3 Réparer et nettoyer | 11.13 | | 6.2 Analyse complète | 6.1.2 | | 6.22 Sites dangereux | 8.2 |
| 4.4 Diagnostic | 11.14 | | 6.3 Clé USB ou dossier | 6.1.3 | | 6.23 Dernières failles | 4.3 |
| 4.5 Intégrité | 4.4 | | 6.4 Analyse YARA | 6.1.4 | | 6.24 Courriel suspect | 7.2 |
| 4.6 Ce que Vanguard a appris | 13.2 | | 6.5 Mémoire des processus | 6.4 | | 6.25 Logiciels espions | 6.2 |
| 4.7 Pourquoi c'est lent ? | 12.3 | | 6.6 Fichiers-pièges | 6.5 | | 6.26 Logiciels pas à jour | 4.9 |
| 4.8 Fiche de l'ordinateur | 4.6 | | 6.7 Defender | 4.10 | | 6.27 Signaler | 8.9 |
| 4.9 Rapport à laisser | 4.7 | | 6.8 Bac à sable | 6.7 | | 7.1 Logiciels | 12.1 |
| 4.10 Ce que Vanguard a changé | 8.7 | | 6.9 Mots de passe : fuite | 7.4 | | 7.2 Gaming | 12.6 |
| 4.11 Entretien du mois | 4.5 | | 6.10 Mots de passe des navigateurs | 7.5 | | 8.1 Nettoyer | 12.2 |
| 4.12 Paramètres | 13.1 | | 6.11 Courriel : fuite | 7.6 | | 8.2 Réglages recommandés | 12.5 |
| 5.1 Scanner le réseau | 5.1.1 | | 6.12 Qui parle à Internet ? | 6.3 | | 8.3 Confidentialité | 12.11 |
| 5.3 Scan approfondi | 5.1.2 | | 6.13 Caméra et micro | 7.7 | | 8.4 Performance | 12.13 |
| 5.4 Nommer | 5.3 | | 6.14 Bilan de confidentialité | 7.8 | | 8.5 Confort et fichiers | 12.12 |
| 5.5 Surveillance | 5.7 | | 6.15 Contrôle à distance | 7.3 | | 8.6 DNS le plus rapide | 12.7 |
| 5.6 Tableau de bord | 5.8 | | 6.16 Ce lien est-il dangereux ? | 7.1 | | 8.7 Tout remettre comme avant | 8.8 |
| 5.7 Veilleur (Linux) | 8.10 | | 6.17 Vérifier un fichier | 6.6 | | 9.1 Sauvegarder ou restaurer | 13.8 |
| 5.8 Test de connexion | 12.8 | | 6.18 Quarantaine | 6.8 | | 9.2 à 9.3 Copier, sauvegarde auto | 9.1, 9.2 |
| 5.9 Liste noire | 5.6 | | 6.19 Secrets git | 4.8.1 | | 9.4 Vérifier une copie | 9.3.2 |
| 5.10 Wi-Fi encombré | 12.10 | | 9.5 Vérifier ma clé | 9.4 | | 9.6 Raccourci | 13.9 |
| 5.11 Type de NAT | 12.9 | | 9.7 Mes ordinateurs | 13.6 | | 9.8 Protéger les données de la clé | 13.7 |
| 5.12 Caméras cachées | 5.5 | | 9.9 Mettre Vanguard à jour | 13.3 | | 9.10 Vérifier ma sauvegarde | 9.3.1 |
| 5.13 Box et objets connectés | 5.4 | | 9.11 Retirer Vanguard | 13.11 | | 12 Extensions | 13.10 |

- **Logiciels : sept de plus, deux catégories.** Ente Auth (double authentification, en tête de « Comptes et
  chiffrement », l'ancienne « Sécurité et vie privée »), Proton Pass, Mullvad Browser, Mullvad VPN (le seul payant,
  dit dans son rôle), LuLu (macOS), Kopia (Windows, macOS) et Déjà Dup (Linux), chacun depuis la source de son éditeur,
  vérifiée en ligne le 24 octobre 2026. Deux catégories en fin, sans décaler les numéros : « Vie privée et réseau » (Tor
  Browser, Mullvad Browser, Proton VPN, Mullvad VPN, Wireshark, LuLu) et « Sauvegarde ». Proton Pass, Mullvad Browser
  et Kopia ne sont pas proposés sous Linux : leur Flathub ne vient pas de l'éditeur. Dernière ligne de l'écran : mettre
  tout l'ordinateur à jour (4.2). La recherche ne propose que les logiciels qui s'installent sur cet ordinateur.

- **Petites listes au clavier.** Les questions à lettres (quarantaine : remettre ou supprimer ; sites dangereux :
  bloquer ou retirer ; qui parle à Internet : la clé abuse.ch ; protection des données de la clé ; mes ordinateurs)
  deviennent de petites listes dessinées sous le résultat, sans l'effacer : ↑ ↓ et Entrée, la lettre restant un
  raccourci (elle pose la marque, Entrée confirme). Extensions : « ↵ Revenir » comme partout, au lieu de « 0 ».

- **Guide des commandes.** Une nouvelle page en fin, 10.10 « Commandes de Vanguard » : chaque commande, rangée comme
  le menu, avec ce qu'elle fait et sa place au menu, générée depuis le programme (jamais à recopier). Le curseur
  s'ouvre sur le système de l'ordinateur. Chaque page de programme et de commande finit par son chemin et sa commande (« Chemin : 10.6.7.2 ·
  vanguard guide 6.7.2 »). `vanguard guide <chemin>` ouvre une page directement ; `--sommaire` liste les programmes
  d'un système avec leur chemin. Aucun chemin d'avant ne change (test).

- **Recherche.** Un mot tapé au menu principal trouve chaque outil, ses variantes, les parcours, les pages du guide,
  les logiciels du catalogue (« gimp » ouvre sa catégorie) et les réglages des Paramètres, classés par pertinence :
  le titre avant le reste, des synonymes (« box » → routeur, « ransomware », « mdp », « maj ») et une faute de frappe
  corrigée et dite (« imprimnte »). Les anciens noms de commandes s'y cherchent encore (« harden » mène à Defender).
  `vanguard chercher <mots>` (`search`) fait de même en ligne de commande : les dix meilleurs, avec leur place et
  leur commande ; `--premier` ouvre le meilleur, `--json` pour un script.

- **Commandes renommées.** Des noms entiers, sans abréviation, qui suivent les libellés du menu ; l'alias anglais
  traduit vraiment le nom français. Les anciens noms ne sont plus acceptés : un script ou une tâche qui les appelle
  est à mettre à jour (les tâches que Vanguard pose lui-même gardent leurs noms). Nouvelles commandes : `rapport`
  (`report`), `annuler` (`undo`, comme `optimiser annuler`) et `protection` (l'état de chaque interrupteur ; `oui` ou
  `non` agit sur la protection en temps réel). Les interrupteurs prennent `oui|non`, `on|off`, `marche|arret` et
  `etat`. `vanguard -h` donne l'essentiel en quelques lignes, `vanguard --help` toutes les commandes rangées comme le
  menu, générées depuis lui.

| 0.86 | 0.87 | | 0.86 | 0.87 |
|---|---|---|---|---|
| `complet / full` | `bilan / check` | | `tableau` | `tableau-de-bord` |
| `machine / audit` | `audit` | | `fiche` | `fiche-ordinateur` |
| `reseau / network` | `appareils / devices` | | `durcir / harden` | `defender` |
| `maj / update` | `mises-a-jour / updates` | | `a-laisser` | `rapport-a-laisser` |
| `motdepasse / password` | `fuite-mot-de-passe / password-leak` | | `sauvegarder / backup` | `exporter / export` |
| `courriel / email` | `fuite-courriel / email-leak` | | `restaurer / restore` | `importer / import` |
| `navigateurs` | `mots-de-passe-navigateurs` | | `gaming` | `jeux / gaming` |
| `sortantes / outbound` | `connexions-sortantes / outbound-connections` | | `plugin` | `plugins` |
| `distance` | `acces-a-distance` | | `diag (alias)` | `diagnostics` |
| `acces / permissions` | `bilan-confidentialite / privacy-review` | | `apps (alias)` | `software` |
| `objets / iot` | `objets-connectes / smart-devices` | | `ext (alias)` | — |
| `cameras` | `cameras-cachees / hidden-cameras` | | `traces / evidence` | `depanner traces / troubleshoot evidence` |
| `canaux / channels` | `canaux-wifi / wifi-channels` | | `proche / relative` | `depanner proche / troubleshoot relative` |
| `connexion / connection` | `test-connexion / connection-test` | |  |  |

- **Résultats pour les scripts.** `diagnostic`, `lenteur`, `connexions-sortantes`, `acces-a-distance`,
  `bilan-confidentialite`, `test-connexion`, `lien`, `objets-connectes` et `listes-noires` prennent `--json`, au même
  format que `logiciels-espions` : les constats, ce qui a été vérifié et ce qui ne l'a pas été, jamais « sain » par
  défaut. Sous `--json`, rien n'est demandé ni changé ; `lien` et `listes-noires` ne vont sur Internet qu'avec
  `--internet`, l'accord donné d'avance. Chaque examen, à l'écran comme en JSON, est gardé pour le rapport et le
  journal des événements. `protection --json` donne l'état de chaque interrupteur, sans rien changer.
- **Outils de la clé en Rust.** Au déploiement, Vanguard vérifie lui-même le vanguard.exe livré (DLL chargées depuis
  System32, manifeste lu là où Windows le lit), écrit les témoins de la clé et y met les archives de tldr-pages
  contrôlées entières (CRC-32 de chaque entrée, sans chevauchement) : plus de Python au déploiement. La CI compile les
  règles YARA d'origine avec le moteur du programme. Le lanceur de la clé ne prend plus un PowerShell absent ou bloqué
  pour un blocage de Defender, et appelle PowerShell (et les autres programmes de Windows) par son chemin complet dans
  System32 : un powershell.exe posé à la racine de la clé n'est plus lancé à sa place.
- **Le système lu directement.** Plus de programmes externes là où le système répond lui-même : Wi-Fi lu par l'API
  WLAN, NetworkManager (bus, lecture seule) et le noyau, sans netsh, nmcli ni iw, et une liste de voisins trop vieille
  est dite non vérifiée ; état des services par systemd sur le bus ; puce TPM lue sans droits d'administrateur ; ports
  en écoute, passerelle, table ARP et écho de la box par les tables du système (Windows, macOS), avec un ping qui ne
  prend plus un « hôte inaccessible » pour une réponse ; comptes des traces et export des journaux sans PowerShell ni
  wevtutil ; liens et fichiers ouverts sans cmd ; programmes de démarrage du menu antivirus lus sans PowerShell, et une
  source illisible n'y passe plus pour vide.
- **macOS sans outils intermédiaires.** Processus, prises réseau, table de routage, échange, SIP, options de démarrage,
  volumes montés, DNS, proxy et services réseau se lisent directement auprès du noyau et de configd ; ps, lsof, scutil,
  networksetup, csrutil et nvram ne servent plus qu'en secours, et des tests les comparent sur un vrai Mac. SIP réglé à
  la carte est signalé comme réduit ; les options de démarrage sont jugées pour le démarrage en cours et pour le
  prochain ; le diagnostic lit le modèle, la carte graphique et les disques même sur un Mac en français ; les traces
  d'incident placent la lecture de Vanguard à côté de la sortie des outils, pour qu'un outil remplacé se voie ;
  « logiciels-espions » vérifie maintenant les connexions sous macOS.
- **Linux lu par Vanguard lui-même.** Bluetooth, DNS sur TLS, fwupd, NetworkManager, systemd (unités, minuteries,
  sauvegardes), sessions et dernières connexions (utmp, wtmp, lastlog2, wtmpdb, logind), journal de systemd,
  plantages, réseau des traces, cache de pacman, dpkg --verify, Docker et snapd se lisent par D-Bus, netlink et leurs
  fichiers, plus par des outils qu'un rootkit peut remplacer ; ce qui ne se lit pas est dit impossible, jamais sain.
  Dans les traces, la sortie des outils reste à côté en témoin, et un écart entre les deux est signalé. Activations
  d'unités, notifications et réglages de Déjà Dup passent par une liste fermée d'actions D-Bus, sur le bus de la
  session seulement.
- **Blocage sans shell.** Chaque geste fait en administrateur est un ordre d'une liste fermée, à paramètres typés,
  que Vanguard rejuge lui-même avant d'agir (sessions à distance, réseau local, ports 22 et 3389 jamais touchés). Sous
  Linux et macOS, Vanguard se relance lui-même (pkexec, run0 ou sudo) au lieu de lancer « sudo sh -c » ; nf_tables
  est écrit directement par netlink, les connexions déjà ouvertes sont coupées par le noyau (échec dit) et un
  processus s'arrête sans course sur son numéro. Sous Windows, les règles du Pare-feu passent par son interface, et
  une liste mêlée de PowerShell ne demande plus qu'une autorisation, au nom de Vanguard. Les annulations notées par
  les versions d'avant restent rejouables telles quelles.
- **Antivirus maison, première brique.** Vanguard lit lui-même les fichiers qu'il analyse (programmes Windows, Linux et
  macOS, documents Office et leurs macros VBA, raccourcis, scripts, archives zip, gzip et tar), bornés contre les
  fichiers piégés (bombes de décompression, archives qui se contiennent elles-mêmes) ; ce qu'il ne sait pas lire
  (7z, RAR, ISO, PDF, chiffré, coupé) est dit non vérifié, jamais sain.
- **YARA maison.** Les 308 règles de ReversingLabs sont appliquées par un moteur YARA écrit pour Vanguard (recherche
  multi-motifs d'après Aho-Corasick, modules pe et elf) ; une règle qu'il ne comprend pas est refusée, nommée et rend
  l'analyse incomplète, jamais saine. YARA-X ne sert plus qu'à vérifier ce moteur dans les tests, sans un écart : le
  programme Windows passe de 34 à 18 Mo, avec 150 bibliothèques de moins.
- **Journaux de Windows lus par Vanguard lui-même (première partie).** Un lecteur maison des fichiers .evtx, écrit
  d'après la spécification de Microsoft, borné contre les fichiers piégés et passé au fuzzing, lit les journaux sous
  Linux, macOS et Windows ; une seule forme d'événement sert aux fichiers comme au Windows en marche, avec le refus dit
  (journal de sécurité sans droits d'administrateur, journal absent ou illisible) au lieu d'un silence. Les numéros des
  événements révèlent ceux qu'on a retirés (effacement partiel), sans prendre pour un effacement un journal qui
  tourne, un morceau abîmé ou une copie faite pendant l'écriture ; un morceau abîmé est relu, ses événements marqués
  non vérifiés. Onze règles maison (EVT-), écrites d'après la documentation de Microsoft et ATT&CK, jugent ces
  événements : traces effacées et enregistrements retirés, service d'attaque, administrateur de plus, mot de passe
  deviné, Bureau à distance depuis Internet ou par un tunnel, autres identifiants, PowerShell malveillant, Defender
  désarmé, BITS, persistance WMI, politique d'audit réduite. Un journal absent, refusé, vide, muet, abîmé ou non
  audité rend la règle « non vérifiée », jamais « rien vu ». `vanguard journaux-windows [--dossier D] [--jours N]
  [--json]` répond à « Que s'est-il passé ? » : le verdict de chaque règle, les alertes dans l'ordre du temps avec
  compte, programme, adresse, journal et numéro, la période vraiment lue par journal et ce qui reste au-delà des
  bornes ; sur ce Windows, ou sur un dossier de .evtx depuis n'importe quel système. Le rapport a sa section « Journaux
  de Windows », CHRONOLOGIE.txt des traces place les alertes à leur heure, et une alerte qui n'est pas critique peut
  être déclarée normale. Essayées sur un vrai Windows 11 installé le jour même, ces règles ne donnent plus d'alerte
  pour ce que fait Windows lui-même : les blocs que PowerShell juge suspects sans motif d'attaque reconnu (ses propres
  modules) font une information par script, qui dit combien ; la mise en route et le serveur OpenSSH de Windows se
  servent d'identifiants sans alerte ; l'abonnement WMI que Windows pose lui-même n'est plus signalé ; le premier
  administrateur créé par la mise en route est dit tel quand la date d'installation et le journal de sécurité le
  confirment. Chargeurs de code en mémoire, vidage de mémoire, vol de jeton, enregistreur de frappe et fausse fenêtre
  de connexion sont reconnus en plus.
- **Windows, deux correctifs vus dans un vrai Windows.** Le Wi-Fi d'un ordinateur sans carte Wi-Fi (bureau, machine virtuelle) est « sans objet » au lieu de « non vérifié » quand le service WLAN est arrêté. La liste des programmes à mettre à jour repasse par PowerShell quand winget, lancé directement, répond par une erreur sans tableau : elle disait « non vérifié » dans une machine virtuelle.
- **Sécurité des dépendances.** crypto-bigint 0.7.6 (avis RUSTSEC-2026-0387 : des calculs censés prendre toujours le même temps n'y arrivaient pas), amené par YARA-X.
- **Vérification continue remise au vert.** Le programme Windows réserve 8 Mio de pile (1 Mio d'origine avec MSVC : la version de mise au point débordait dès le démarrage) ; les journaux des tickets ne passent plus par Claude dans GitHub ; le fuzzing de nuit tourne enfin (cargo-fuzz installé à part, empreinte vérifiée) ; la compilation reproductible vérifie la garde des DLL avec un éditeur de liens assez récent.
- **Les mots d'attaque cherchés ne sont plus en clair dans le programme.** Les noms de commandes d'outils offensifs et de contournements d'AMSI que Vanguard reconnaît dans les scripts sont brouillés dans le binaire (décodés en mémoire au besoin), pour qu'un antivirus ne prenne pas Vanguard pour l'outil qu'il traque. Rien de caché : le code source reste en clair et un garde-fou inspecte le binaire pour qu'aucun de ces mots n'y revienne en clair.
- **Sécurité de l'état.** Ce que Vanguard garde sur l'ordinateur ne se retourne plus contre lui. Un tube nommé ou un
  lien vers /dev/zero posé à la place d'un fichier d'état ne fige plus Vanguard (même `--version`, la surveillance, le
  veilleur) et ne lui fait plus charger sans fin : chaque fichier relu l'est en simple fichier, borné. Le relevé des
  changements (`changements.jsonl`), les réglages qui coupent une défense (`parametres.json` : travail sans Internet,
  autodiagnostic, versions des logiciels ; `blocage.json` : catégories désactivées), les comptes administrateurs et
  appareils Bluetooth déjà vus et les clés connues sont scellés : changés hors de Vanguard, rien n'y est rejoué en
  administrateur, rien ne s'y coupe (un réglage ignoré se dit dans les Paramètres, le menu du blocage et le bilan, et
  se règle de nouveau), et ce qui était déjà vu est redit. Les fichiers repris d'une version d'avant à la mise à jour
  gardent leurs valeurs ; acceptés après des sceaux effacés, ils ne coupent rien ni ne sont crus. Un blocage noté
  avant le sceau ne se défait tout seul que s'il se rejuge
  sans sa note (une règle de pare-feu, un programme remis au démarrage), le reste à la main. « Tout remettre comme
  avant » ne rejoue plus jamais une ancienne note telle quelle : elle repasse par les garde-fous des ordres (jamais
  SSH ni le Bureau à distance rouverts). Un port fermé par ufw sans relecture se dit « non vérifié », pas « bloqué ».
  Le journal des événements s'écrit en deux temps : des lignes ajoutées sans sa tête se lisent falsifiées, puis
  comme une rupture dite au bilan, jamais reprises comme celles de Vanguard. Effacer les sceaux avec leur verrou ne
  ramène plus au premier usage, et un mois posé « en 2099 » ne relie plus un geste à une fausse cause. Le journal,
  les sceaux et la base des appareils ne s'écrivent plus jamais sans leur verrou (un verrou du système, rendu dès
  qu'un Vanguard s'arrête, qui respecte celui d'une version d'avant) : deux Vanguard qui écrivent en même temps sur un
  Windows lent ne font plus croire à un journal falsifié. Un événement qui attend trop est remis à la prochaine
  écriture ou à la fin du programme, le reste refusé, et c'est dit au journal des erreurs, jamais écrit à moitié ; un
  verrou tenu sans fin se dit au bilan.

## 23 octobre 2026 : version 0.86

- **Logiciels espions.** `vanguard logiciels-espions` (alias `spyware` ; menu Antivirus et protection, en dernier)
  cherche les signes d'un logiciel espion posé par un proche : connexions en cours et noms demandés récemment vers les
  serveurs et sites des logiciels espions connus (liste de l'association Échap, CC-BY 4.0, téléchargée à l'usage et
  gardée un jour, jamais intégrée), logiciels de surveillance connus installés ou en marche (FlexiSPY, Spyrix, Refog,
  Ardamax… ; contrôle parental et surveillance d'employés dits normaux s'ils ont été installés exprès), programmes qui
  lisent le clavier (Linux : /dev/input ; reconnus : compositeur, remappage, Steam, OBS), autorisations Surveillance
  de l'entrée, Accessibilité et Enregistrement de l'écran (macOS, lues par un lecteur SQLite écrit pour Vanguard).
  Tout est lu en Rust, sans commande externe. Lecture seule : rien n'est retiré, car celui qui l'a posé pourrait le
  voir ; l'écran dit de garder des captures et de demander de l'aide d'abord. Ce qui n'a pas pu être vérifié est
  compté, et le verdict n'est jamais « aucun logiciel espion ». Au bilan aussi, sans réseau.
- **Logiciels pas à jour.** `vanguard logiciels-perimes` (alias `outdated-software` ; menu Antivirus et protection, en
  dernier ; au bilan sous Windows et macOS) compare la version installée des navigateurs (Chrome, y compris le canal
  Extended, Edge, Firefox et ESR, Brave), d'Office, d'Acrobat et Reader, de Java, de 7-Zip, de PuTTY et de Slack à la
  dernière publiée : fichiers publics des éditeurs, d'endoflife.date et de Homebrew (formula.json, pris sous Windows
  aussi pour 7-Zip et PuTTY, dont les formules suivent l'amont), téléchargés en entier une fois par jour, les mêmes
  pour tous : la liste des logiciels ne sort jamais de l'ordinateur (Paramètres › Versions des logiciels pour couper
  ces téléchargements). La version est lue dans le fichier même (lecteur de la ressource de version des .exe écrit
  pour Vanguard, Info.plist, dossier du Cellar de Homebrew), pour tous les comptes en administrateur ; Slack par
  compte, dans son dossier de version, pas son lanceur. Firefox : chaque faille exploitée du catalogue de la CISA est
  vérifiée contre la version installée (avis de sécurité de Mozilla) ; Edge Stable de même, d'après les failles que
  Microsoft dit corrigées par chaque version ; une version antérieure au correctif est critique. Pour les autres, le
  nombre de failles exploitées du produit au catalogue, sans conclure pour la version installée (Slack embarque
  Chromium, mais ses failles ne se reportent pas sur lui). Ce qui n'a pas de source (Edge Extended Stable, Acrobat
  2020 et 2024, App Store) est dit non vérifié, comme une réponse de Slack d'une forme inattendue (son API n'est pas
  documentée), une formule de Homebrew désactivée ou obsolète, ou une liste de failles d'Edge d'une autre forme ; un
  navigateur qui ne se compare pas garde le contrôle des 60 jours sans mise à jour, qui quitte la fin de support.
  formula.json, cask.json et endoflife.date se lisent en flux, avec un plafond d'entrées : un petit fichier hostile ne
  fait plus allouer des Gio. L'historique ne montre plus « réglé » puis « nouveau » pour un logiciel dont la version
  change sans être à jour. Sous Linux, la commande renvoie au gestionnaire de paquets. Le lecteur zip (guide des
  commandes) écarte une entrée dont le contenu n'a pas la taille annoncée, qui pouvait dépasser sa borne ; gzip et zip
  passent au banc de fuzzing.
- **Mode Wi-Fi public** (`vanguard wifi-public`, Réseau et Internet › Mode Wi-Fi public). On l'allume en arrivant dans
  un café, un hôtel ou un aéroport, on l'éteint en partant : l'ordinateur n'accepte plus aucune connexion venue de ce
  réseau (une session SSH déjà ouverte reste), le partage de fichiers et l'annonce de son nom sont coupés (sous macOS,
  le pare-feu ferme le partage ; Bonjour et AirDrop restent), et le DNS passe au Bouclier canadien « Protégé »,
  chiffré sous Linux quand systemd-resolved répond (un résolveur sur l'ordinateur, comme NextDNS, est gardé, et un DNS
  déjà chiffré et filtrant aussi, à condition que tous ses serveurs filtrent : sinon le Bouclier est posé, et le bilan
  ne dit plus qu'un tel DNS bloque les sites dangereux). Sous Linux, une table nftables à part, qui ferme aussi le
  transit venu de la carte Wi-Fi (un port de conteneur publié par Docker, podman ou k3s, qui passe par DNAT puis
  `forward` et jamais par `input`, n'est plus joignable du réseau public), et des services masqués jusqu'au
  redémarrage, puis mDNS, LLMNR et le DNS chiffré sur le seul profil du réseau public ; sous Windows, catégorie
  Public, profil Public du pare-feu fermé aux entrées, NetBIOS coupé, en une seule demande d'administrateur ; sous
  macOS, pare-feu en « tout bloquer » et mode furtif. Les entrées qui n'ont pas pu être fermées (pas de nft, pare-feu
  illisible, sous Windows un réseau resté en Privé, d'entreprise ou à la catégorie illisible) sont dites au menu et au
  bilan, « allumé, entrées ouvertes », jamais « tout est en place » ; un réglage qui ne se relit pas s'affiche non
  vérifié, jamais ✔. Sous Linux, un DNS, un DNS chiffré, mDNS ou LLMNR défait par un programme du compte
  (NetworkManager le permet sans mot de passe) se voit au bilan (Moyen), sur la ligne du menu et dans son en-tête,
  avec de quoi le reposer. Chaque changement est montré avec sa valeur d'avant, notée et scellée avant la première
  commande ; l'extinction remet tout dans l'ordre inverse, relu, même après un plantage ou un redémarrage (le menu et
  le bilan le disent). Un état changé hors de Vanguard n'est jamais remis : extinction sûre à la place, qui ne retire
  que la table de Vanguard. Un pare-feu trouvé coupé est allumé et jamais recoupé. `vanguard wifi-public portail`
  rouvre la page de connexion du réseau : le DNS chiffré se relâche jusqu'à Entrée, dix minutes au plus, et le
  lancement suivant le remet strict si Vanguard a été fermé avant. Rien n'est envoyé pour reconnaître un réseau
  public : une suggestion seulement. Essayé sous Linux (table posée puis retirée dans un espace de noms à part,
  aperçus) ; Windows et macOS : compilés et testés en partie, pas encore essayés sur un vrai système, ni le DNS
  chiffré sur un vrai réseau public.
- **Menus : les flèches, et une fenêtre à leur taille.** Dans les menus, → lance la ligne choisie comme Entrée (sauf
  quand il complète une prédiction de la recherche) et ← revient comme Échap ; pendant une recherche, ← l'efface. Au
  menu principal, ← ne fait rien : un appui de trop en sortant d'un sous-menu fermerait Vanguard (Échap et q quittent
  toujours). Dans les listes à cocher, ← revient mais → ne valide pas : ces listes lancent des changements (nettoyer,
  désinstaller), Entrée seule les confirme. Les pauses « Entrée pour revenir » se quittent d'une seule touche (Entrée,
  ←, Échap ou Retour arrière), les questions qui se tapent reviennent par ← ou Échap sur une ligne vide, et quitter un
  outil par « revenir » ne demande plus une pause de plus. À chaque menu, la fenêtre prend 78 colonnes et la hauteur
  du menu, bornée à l'écran, puis se centre ; seulement une fenêtre ouverte pour Vanguard : sous Hyprland, la fenêtre
  flottante de son terminal ; sous Windows, une console où Vanguard est seul, l'ancienne console ou le Terminal
  Windows. Ailleurs, rien ne bouge.
- **Les corrections du bilan s'annulent, une par une, et « Tout remettre comme avant » défait tout.** Avant chaque
  correction (Linux, Windows, macOS), Vanguard relève l'état d'avant de ce qu'elle change (fichier de sysctl ou de
  sshd posé par Vanguard, réglages du noyau, service, heure réseau, droits d'un fichier personnel, valeur du registre,
  préférence) et le note, scellé, dans reglages.json, comme Optimiser. « Ce que Vanguard a changé » annule une
  correction marquée « annulable », puis relit l'état : revenu, ou pas (et pourquoi). Une correction dont l'état
  d'avant ne se relève pas est dite « non annulable » avant d'être appliquée ; celle qui rallume une protection
  (pare-feu, antivirus, BitLocker, UAC, SELinux, Gatekeeper) ne se défait jamais. « Tout remettre comme avant »
  (`vanguard optimiser annuler`) défait maintenant le bilan, Optimiser, Gaming, les blocages et le mode Wi-Fi public,
  du plus récent au plus ancien, en une demande administrateur. Les réglages de Gaming passent par le même mécanisme :
  leurs notes de jeux.json, qui n'était pas scellé, sont reprises sans perte, une seule fois, jamais par-dessus un
  reglages.json adopté. Les corrections d'un même « [t]out appliquer » qui touchent le même fichier partagent une
  note : en annuler une les marque toutes défaites ; deux notes sur la même cible défaites ensemble sont toutes deux
  remises, sans faux ✖. Un service activé mais arrêté est dit non annulable plutôt que faussement remis, et les droits
  de ~/.ssh corrigés s'annulent.
- **Annuler ne rouvre jamais ce qu'une correction a fermé, ni ne rejoue une commande.** reglages.json, dont les
  valeurs sont remises en administrateur, est scellé : réécrit par un autre programme, il n'est plus cru (il est mis
  de côté, intact, et rien n'en est remis), et un reglages.json accepté sans sceau n'est pas rescellé à la lecture :
  le bilan continue de le dire. Chaque valeur est vérifiée à la remise, sur une liste fermée (un état de service
  connu, un booléen, un nombre, des adresses IP, un mot simple) ; une valeur d'une autre forme fait revenir celle d'un
  système neuf, écrite dans le programme. Une note des fichiers de sysctl et de sshd que Vanguard pose n'est remise
  que si elle porte les valeurs sûres qu'il y écrit (« ptrace_scope = 0 », « PermitRootLogin yes » ou un algorithme
  faible ajouté sont refusés), et leur contenu est montré avant la question ; une note qui viserait l'UAC est refusée
  sous Windows. Annuler un blocage, seul ou par « Tout remettre comme avant », ne rejoue plus jamais le texte d'une
  commande lu dans le relevé ou dans changements.jsonl (que tout programme du compte peut écrire) : les commandes sont
  refaites depuis l'adresse, le port ou la valeur notés, et un blocage non reconnu est refusé et montré au lieu de
  partir en administrateur. Annuler ne remet qu'une copie de réglages de Claude Code faite par Vanguard, et remettre
  comme avant les réglages pour jouer ne réécrit en root que ce que Vanguard met dans /etc.
- **Signaler une faille à un éditeur** (`vanguard signaler`, alias `disclose` ; menu Antivirus et protection). Un
  assistant prépare le brouillon d'un rapport de faille, que la personne relit et envoie elle-même. Il trie d'abord :
  une faille déjà connue (CVE, catalogue de la CISA) se corrige par une mise à jour ; un logiciel malveillant, une
  détection ratée ou un site d'hameçonnage ne sont pas des failles de l'éditeur (le bon destinataire est nommé, rien
  n'est préparé) ; un contournement d'AppLocker ou de l'accès contrôlé aux dossiers est dit non corrigé par défaut
  chez Microsoft. Pour un comportement anormal, le brouillon suit le format du programme choisi (MSRC, Google, Chrome,
  Mozilla, Apple, avis GHSA, CERT/CC, CERT-FR, Vanguard) et reprend le fil d'un incident ou l'examen d'un outil, avec
  l'état du journal (falsifié : « non vérifié » ; adopté ou incomplet : « non prouvé ») ; il reste titré INCOMPLET tant
  qu'il manque ce que seule la personne sait (ses étapes, ce qui s'est passé, la preuve de concept qu'exigent MSRC,
  Apple et Chrome). Un examen sain, non vérifié ou falsifié ne tranche rien, et sans CVE citée, le catalogue de la
  CISA est « non vérifié », jamais « absente ». Ce qui est personnel est retiré en trois couches : rien d'inutile (ni
  ligne de commande, ni compte d'un proche, ni nom de fichier personnel), tout masqué (chemins, noms, adresses,
  requêtes des adresses web), puis un contrôle final qui refuse d'écrire si un nom connu survit ; le décompte est
  montré. L'examen des logiciels pas à jour n'emporte que le produit touché par une faille exploitée, jamais la liste
  des logiciels installés. Les valeurs venues de l'extérieur vont dans des blocs de code, le reste est neutralisé (ni
  mention, ni image, ni lien). Le texte est montré en entier, écrit après accord dans le dossier de Vanguard de cet
  ordinateur (fichier 0600) et noté au journal sans son contenu ; `--effacer` retire les brouillons, que la
  désinstallation compte avant. Rien n'est jamais envoyé : aucun code réseau dans le module (vérifié par une liste
  fermée des appels), ni presse-papier, ni courriel.
- **Autodiagnostic** (`vanguard autotest`, alias `self-test`). Vanguard vérifie ses propres lectures sur l'ordinateur
  où il travaille, sans rien y changer. Chaque règle du bilan tourne sous garde et délai, en lecture seule prouvée : un
  interrupteur refuse toute écriture d'état, même d'une règle restée bloquée au-delà de son délai, et des empreintes
  BLAKE3 du dossier de Vanguard, avant et après, nommeraient ce qui a changé (une passe de la surveillance pendant
  l'essai rend la preuve non concluante, jamais « changé »). Chaque constat passe par des invariants. Dix lectures
  croisées sous Linux (pacman, dpkg, AUR, unités activées et en échec, groupes, ports en écoute, racine chiffrée,
  version de sshd, DNS de resolved) et quatre sous Windows (pare-feu, Defender, BitLocker en administrateur, comptes
  locaux, en JSON) comparent ce que lit Vanguard à ce que disent les outils du système ; les tests « comme l'outil »
  appellent les mêmes fonctions. Hors ligne par défaut (`--internet` pour les règles qui en ont besoin) ; `--json` ne
  contient aucune valeur de l'ordinateur, `--detail` montre les valeurs à l'écran seulement ; code de sortie 0, 1 ou
  2. La durée de chaque règle va au journal des mesures (huit semaines, résumées par jour), qui signale une règle
  trois fois plus lente que d'habitude ou proche de son délai. Une fois par semaine, la surveillance refait les
  lectures croisées sur le bilan de sa passe (réglage « autotest », reporté pendant un jeu sous GameMode) ; une
  lecture contredite est dite à côté des constats sains de ses règles, et le diagnostic montre le dernier
  autodiagnostic. Un écart va au journal des erreurs (identifiants, nombres, genre d'écart, aucune valeur de
  l'ordinateur) ; `journal-vers-github.py` réunit les occurrences d'un même envoi en un seul commentaire et ne mêle
  plus deux identifiants dans un même ticket. Jamais un faux « sain » : deux lectures ratées de Defender ou de
  BitLocker, une ligne de `ss` illisible ou des unités du compte non lues donnent « non vérifié », ni « pareil » ni
  « sans objet » ; une lecture contredite reste annoncée, avec sa date, tant qu'un nouvel essai ne l'a pas tranchée ;
  avant cinq semaines de mesures, la comparaison des durées est dite non vérifiée.
- **Veilleur anti-rançongiciel** (Linux, `vanguard veilleur rancongiciel on`). Le veilleur peut maintenant surveiller
  en direct les dossiers personnels (Documents, Images, Bureau, Musique, Vidéos et Téléchargements) : une rafale de
  chiffrement (des dizaines de fichiers réécrits en quelques secondes, un contenu qui ne ressemble plus à son format,
  une note de rançon, un fichier-piège touché, des copies de secours effacées) donne une alerte en quelques secondes
  au lieu d'attendre la vérification horaire des pièges, et « Bloquer » est proposé au bilan suivant. Ni droits
  d'administrateur ni nouvelle dépendance : inotify, par la crate déjà présente, voit les fichiers changer, et les
  compteurs d'écriture des processus disent qui écrit. Avec la protection active et un cas quasi certain (piège touché
  et rafale attribuée sans ambiguïté à un programme), Vanguard gèle le programme et sa descendance, relève la preuve,
  puis l'arrête et le met en quarantaine, avec tous les garde-fous du blocage ; un programme qu'un garde-fou refuse
  d'arrêter reste gelé, et c'est dit. Sinon, Vanguard alerte seulement. Proposé dans le même accord que
  `vanguard veilleur on`, coupé par défaut. Retirer les pièges ne fait pas crier « rançongiciel possible », et l'alerte
  d'un outil de chiffrement voulu peut se déclarer normale. Limites dites : un programme malveillant du compte peut
  éteindre la veille, et la sauvegarde reste la vraie protection ; une écriture par un lien physique placé hors de ces
  dossiers échappe à la veille en direct (les pièges restent vérifiés chaque heure).
- **Bilan post-quantique, en lecture seule.** Un trafic chiffré capté aujourd'hui peut être gardé et lu le jour où un
  ordinateur quantique existera : le bilan dit où cet ordinateur n'a pas d'échange de clés post-quantique, sans rien
  changer et sans bibliothèque ajoutée. Serveur et client SSH (COM-PQC-001, 002) : la liste que sshd et ssh retiennent
  vraiment, d'après la version d'OpenSSH lue sans la lancer (sntrup depuis 8.5, par défaut depuis 9.0, ML-KEM depuis
  9.9) et les « + », « - » ou « ^ » écrits dans la configuration. Le conseil ne nomme jamais un algorithme que cette
  version ne connaît pas, ne place jamais un nom devant un « + », un « - » ou un « ^ » (sshd ne redémarrerait pas) et
  dit de passer `sshd -t` d'abord ; un réglage propre à un seul hôte reste une information, sans le nom de l'hôte.
  Navigateurs (COM-NAV-004) : X25519MLKEM768 coupé par une préférence de Firefox ou par une stratégie (Firefox ;
  Chrome et Edge jusqu'à 146, au-delà la stratégie est dite sans effet). Pour Firefox, policies.json, puis sous
  Windows le registre (la stratégie et ses Preferences) et distribution\policies.json ; une préférence mise à false
  seulement par défaut compte tant que le profil n'écrit rien, et security.tls.enable_kyber, que Firefox refuse dans
  Preferences, ne compte pas. Sans coupure, la version décide : Firefox avant 132 et Chrome avant 124 ne le proposent
  pas par défaut, Chrome de 124 à 130 propose X25519Kyber768, et une version illisible (Brave, Vivaldi, Zen…) n'est pas
  vérifiée. WireGuard (COM-PQC-003) : les pairs sans clé pré-partagée, comptés sans jamais garder une clé ; les
  fichiers ne se lisent qu'en administrateur, et sans droits, sans fichier ou chiffrés pour SYSTEM, le constat est non
  vérifié, raison dite. À l'audit du réseau : l'administration du routeur (SSH, HTTPS trouvés ouverts par le scan) qui
  ne propose rien de post-quantique, en une information regroupée (COM-TLS-004), et le chemin vers Internet qui
  retirerait l'échange (COM-TLS-005), par une sonde TLS écrite à la main vers le site de référence déjà contacté, sans
  calculer aucune clé. Un refus n'est conclu que si l'interception se voit déjà au certificat, sinon c'est non
  vérifié ; un proxy réglé ou illisible laisse aussi non vérifié (sous Linux, celui du bureau GNOME ou KDE compris).
- **Un journal des événements relié et scellé.** Les alertes, la preuve relevée avant chaque geste, les blocages,
  quarantaines et corrections, leurs annulations, les alertes déclarées normales et les passages de version vont dans
  un seul journal (evenements/AAAA-MM.jsonl, sur cet ordinateur seulement), écrit en ajout seul : chaque ligne porte
  l'empreinte de la précédente, la tête est scellée, chaque mois clos aussi, 13 mois et 20 Mo au plus. Une ligne
  retirée, changée ou ajoutée se voit ; une fin qui ne correspond plus est notée dans le journal même. L'alerte d'un
  serveur de botnet, la preuve, le blocage et son annulation sont reliés (`vanguard evenements --incident <id>`), et
  un blocage ne peut plus être noté sans son relevé. Le tableau de bord et les traces d'incident lisent ce journal (et
  l'ancien, qu'une version d'avant écrit encore) ; une faille du catalogue KEV y est critique. Il se lit borné en tout
  (mois, octets, événements), les plus récents d'abord, et dit ce qu'il n'a pas lu. Une chaîne rompue est dite au
  bilan ; des fichiers posés aux noms de mois à venir (2099…) n'y comptent pas, ne sont ni suivis par l'écriture ni
  comptés par l'élagage, ne font plus sortir le vrai mois en cours de la lecture et des traces, et sont dits ; une
  horloge en avance ne vide pas l'historique, et un mois plein refuse d'écrire plutôt que de devenir illisible. Les
  logiciels espions, les logiciels pas à jour et le courriel suspect rendent un résultat (`--json`), gardé pour le
  rapport (« Derniers examens des outils ») et scellé : un « rien trouvé » réécrit hors de Vanguard se montre non
  vérifié, jamais vert. Les erreurs du blocage, de la quarantaine et des versions vues ont un code stable.
- **La preuve avant le geste, et ce que Vanguard a fait dans les traces.** Avant d'arrêter un programme, de mettre un
  fichier en quarantaine ou de bloquer une adresse, y compris tout seul la nuit, Vanguard relève ce que le geste va
  effacer : le programme, sa ligne de commande, son parent, son compte, l'empreinte SHA-256 du fichier, les connexions
  en cours. Ce qui ne se lit pas est noté « impossible (raison) », et le blocage se fait quand même ; sous Windows, le
  relevé n'attend pas WMI plus de 3 secondes avant l'arrêt, et un numéro de processus repris n'est pas décrit. La
  preuve est gardée avec le blocage (« Ce que Vanguard a changé » la résume) ; la quarantaine garde l'empreinte de
  chaque fichier. « vanguard traces » reprend enfin ce que Vanguard a vu et fait (07-vanguard.txt) : ses alertes, ses
  blocages et quarantaines avec leur preuve, et des fils qui relient l'alerte, la preuve et le geste d'un même
  programme ou d'une même adresse ; ces repères entrent dans la chronologie, et les fichiers d'état de Vanguard sont
  recopiés tels quels pour que le MANIFESTE les couvre. Un fichier supprimé du menu Quarantaine, ou après une analyse
  de ClamAV, s'y lit « supprimé », avec son empreinte relevée ; les traces lancées avec sudo lisent les données du
  compte qui les a lancées, et un tube nommé ou un lien à la place d'un fichier d'état ne les bloque plus. Une seule
  voie mène à la quarantaine : celle de l'antivirus et de YARA est désormais notée et s'annule par « vanguard blocage
  annuler », comme celle du blocage ; elle ne suit plus de lien, et root n'y écrit plus dans le dossier d'un compte.
  Le même fichier téléchargé de nouveau après une quarantaine est reproposé au blocage. Le veilleur juge les
  programmes par les mêmes sources que le blocage : il reconnaît aussi les empreintes connues de MalwareBazaar (celles
  des dernières 48 heures, la liste complète ne tenant pas dans sa mémoire), et ne reste plus pris sur un fichier qui
  ne répond pas (non haché, dit non vérifié). Installer ClamAV ou un outil tiers est noté comme toute correction.
- **« C'est normal » pour la surveillance, le veilleur et le blocage.** Une alerte qui revient sans raison (un outil
  de développement lancé depuis /tmp, un appareil connu) se déclare normale pour 90 jours dans Ce que Vanguard a
  appris, et une menace proposée au blocage par « i ». Le choix porte sur ce dont parle l'alerte (le programme, avec
  sa raison et son script, l'adresse, l'appareil), pas sur son texte : déclarer python3 normal pour une commande qui
  télécharge ne fait pas taire python3 qui lance autre chose. Il s'oublie au même endroit. Une alerte n'est proposée
  que si son genre est celui de sa clé, et ce qu'elle désigne est montré avant de choisir ; une menace certaine, et
  l'alerte de son blocage, ne se taisent jamais. La liste est scellée : changée hors de Vanguard, elle ne fait rien
  taire.
- **Un problème reconnu à sa règle et à son objet, plus à son texte traduit.** Les ports ouverts, les lancements
  automatiques suspects, les extensions de navigateur, les comptes oubliés ou ajoutés aux administrateurs, les
  logiciels espions, la prise de contrôle à distance, les logiciels périmés et le carnet de la clé VANGUARD portent
  maintenant une clé (« LNX-RES-001|port:8080/tcp:python3 ») : changer de langue ne fait plus revenir une alerte
  déclarée normale, ne fait plus voir de « nouveau » problème dans l'historique et ne renotifie rien dans la
  surveillance. Les choix d'avant sont retrouvés par leur texte puis complétés de leur clé ; un choix ne vaut que pour
  son objet (un autre programme sur le même port, une autre version périmée reviennent), et un seul choix par clé
  compte, le plus récent. Sous macOS, un agent de démarrage est reconnu à son fichier et à ce qu'il lance, sous Linux
  chaque ligne de lancement suspecte à son empreinte : une commande réécrite ou une ligne ajoutée dans un fichier déjà
  signalé n'est jamais tue par un choix d'avant. La surveillance renotifie une alerte qui s'aggrave sans changer de
  clé (une extension qui gagne l'accès à tous les sites). L'historique garde sa première empreinte telle quelle et en
  gagne une seconde, qui couvre les clés et les notes de l'audit du réseau : une clé n'est jamais hors d'une
  empreinte, et un bilan sans elle est dit non vérifié, comparé sur son texte. Le JSON du bilan gagne `objet`, `cle`
  et `etat` (sain, sans objet, non vérifié avec sa raison, problème). L'inventaire des fichiers d'état gagne le carnet
  des appareils, ses verrous, la reprise d'une version d'avant et le dossier des traces, et son test lit aussi les
  variables du dossier de données.
- **Une règle qui ne rend rien dit « non vérifié », jamais un silence lu comme sain** (hors d'une liste de règles
  tolérées, qui ne peut que rétrécir). Le Wi-Fi n'est plus tu quand NetworkManager manque (iwd, systemd-networkd) :
  sans carte, « rien à juger » ; avec une carte, non vérifié ; une liste des cartes réseau illisible (/sys/class/net)
  donne « non vérifié », jamais « pas de carte Wi-Fi ». Sous Windows, un réseau que netsh cache faute d'autorisation
  de localisation est dit non vérifié ; sous macOS, le mode furtif illisible et la session à distance aussi. Seule la
  lecture du pare-feu lui-même décide si la note tient : le mode furtif illisible ne la retire plus à lui seul. Un
  constat « sans objet » ne compte plus parmi les vérifications pour la fiabilité de la note. `vanguard regles` montre
  aussi les règles de l'audit du réseau et les outils : un seul registre d'identifiants, vérifié par les tests, avec
  l'inventaire des fichiers d'état dont les sceaux tirent la liste à protéger.
- **Nouvelles règles du bilan : SSH et Defender sous Windows, mots de passe, démarrage et persistance sous macOS, une
  référence et un délai par règle.** Windows gagne le serveur OpenSSH (service, configuration de %ProgramData%\ssh,
  connexion par mot de passe, droits de administrators_authorized_keys, lus en Rust : registre, WMI, fichiers et leurs
  droits) et les clés de %USERPROFILE%\.ssh (sans phrase de passe, lisibles par d'autres), WIN-SSH-001 et 002. Un
  serveur désinstallé dont la configuration est restée est sans objet ; administrators_authorized_keys ouvert est
  moyen quand StrictModes (par défaut) le fait refuser, critique sans lui, et ses fichiers sont bornés avant d'être
  lus. Le bilan relit les protections de Defender que « durcir » active (règles ASR, protection réseau, PUA, dossiers
  contrôlés, WIN-ANV-003) : une protection posée par Vanguard (Optimiser ou une correction du bilan) puis coupée est
  une alerte élevée ; les blocages de base, la protection réseau et PUA sont proposés, chaque correction annulable ;
  rien n'est dit « qui bloque » quand la protection en temps réel est coupée, ni sain quand rien ne bloque. macOS
  gagne la règle des mots de passe et le blocage des comptes (pwpolicy, MAC-CPT-002), la sécurité du démarrage (bputil
  ou puce T2, MAC-DEM-001), les éléments d'ouverture et de fond (sfltool, en administrateur, MAC-PRS-002), les
  crochets de connexion et les extensions d'autorisation (MAC-PRS-003) ; les réglages de root illisibles sans sudo
  rendent le crochet de connexion non vérifié, jamais « aucun crochet ». Les règles fourre-tout sont scindées : le
  durcissement de Windows en cinq (WIN-DUR-001 à 005), plus Windows Update coupé ou en pause (WIN-MAJ-003) et la
  session ouverte toute seule (WIN-SES-002) ; les réglages sysctl en trois (LNX-NOY-003, LNX-NOY-007, LNX-RES-003),
  dont les corrections s'ajoutent au fichier au lieu de se réécrire l'une l'autre. Un choix « c'est normal » sur
  l'ancienne alerte groupée du noyau Linux vaut pour les trois nouvelles ; au premier bilan après la mise à jour,
  l'historique peut encore la montrer réglée puis nouvelle. Chaque règle de la machine cite au moins une référence du
  CIS, de Microsoft ou de l'ANSSI (exigé par un test pour les trois systèmes), donnée aussi dans le JSON du bilan
  (« reference »). Un inventaire des logiciels, gardé scellé sur l'ordinateur et jamais envoyé, dit pendant une
  semaine chaque logiciel installé depuis le dernier bilan (COM-LOG-001) : effacé ou changé hors de Vanguard, il ne
  tait plus ce qui s'est installé entre-temps (tout est redit) ; une mise à jour dont le nom affiché porte la version
  (« Outil 1.3 (x64) ») n'est plus un nouveau logiciel ; une source qui ne se lit pas (Flatpak muet, ~/Applications
  illisible) ou une borne atteinte (sous-clés, entrées d'un dossier, 20 000 logiciels, clés sans nom en nombre) rend
  le bilan non vérifié au lieu de faire oublier des logiciels ou de les tronquer en silence ; les logiciels des autres
  sessions Windows ouvertes ne comptent plus. Enfin, chaque règle a son délai (10 min, 30 pour les mises à jour) :
  celle qui le dépasse est dite non vérifiée, les autres continuent. Rien de cela n'a encore tourné sur un vrai
  Windows ni sur un vrai Mac : tests sous Wine, clippy pour macOS.
- **Chaîne de confiance des mises à jour.** Une clé de secours, gardée hors ligne et chiffrée dès sa création, signe
  aussi les versions : la principale perdue ou volée, la mise à jour continue, et la clé de secours peut révoquer la
  principale (« revoque principale » à la fin du manifeste, qui reste lisible par les 0.85) ; retenue dans l'état
  scellé, la principale n'est alors plus jamais acceptée, et la plus haute version vue repart. La clé principale peut
  être chiffrée, sa phrase demandée une fois par publication (`outils/signer-versions.sh`, `--secours`, qui refuse une
  clé de secours en clair). Vanguard retient la plus haute version signée déjà vue et refuse un manifeste plus vieux ;
  une dernière version signée de plus de 45 jours, une horloge en retard qui ferait passer un vieux manifeste pour
  frais, ou une copie d'ici plus récente que la dernière version signée sur GitHub (un ancien manifeste a pu être
  remis en place) ne sont plus dites « à jour » ni « rien de plus récent », mais non vérifiées. Le programme macOS ne
  vient que d'une compilation de master, sans cache (une étiquette nommée master n'en reprend pas), et il est contrôlé
  avant d'être signé (commit, empreinte du journal de sa compilation, Mach-O universel, version). La copie locale de
  la surveillance passe par la mise à jour (jamais vers une version plus ancienne), et une nouvelle copie est essayée
  avant de remplacer l'ancienne (Linux et macOS) ; en root, un programme posé dans un dossier modifiable par d'autres
  n'est plus remplacé. Historique signé des versions : `vanguard verifier-moi [programme]` vérifie aussi une copie qui
  n'est plus la dernière, sans rien changer pour les copies déjà installées ; lancé sans terminal, il ne pose plus la
  question de l'historique, qui quittait avant l'avertissement final, et la 0.85 n'est plus dite absente de
  l'historique.
- **État de Vanguard scellé.** `appris.json`, `integrite.json`, `surveillance-botnets.txt`, les versions déjà vues,
  l'état de la machine au dernier passage de la surveillance, les changements déjà signalés par la surveillance
  d'intégrité, le temps réel et son rappel, l'audit, les sites et la passerelle déjà signalés, l'heure du dernier
  regard sur Téléchargements et les menaces non bloquées déjà signalées portent une empreinte BLAKE3 : changés hors de
  Vanguard (par un programme qui voudrait faire taire son alerte, ou couper la protection), ils ne comptent plus et le
  bilan le dit (COM-ETA-001) ; abîmés, ils ne font jamais taire une alerte. Ils ne se lisent que s'ils sont de simples
  fichiers de taille bornée (un tube nommé figeait la surveillance pour toujours) ; l'écriture ne suit plus de lien,
  et root n'écrit plus dans le dossier d'un compte. `sceaux.json` effacé ne fait plus accepter les fichiers d'état
  tels quels : ils restent « adoptés », dits au bilan, et les versions déjà vues ne sont alors pas crues ; la
  référence d'intégrité adoptée sert encore à comparer et reste signalée tant qu'elle n'est pas acceptée (un écart
  avec elle reste un écart, et le passage de version ne coupe pas la surveillance), jamais refaite sans accord.
  Effacés avec les sceaux, les fichiers d'état sont « inconnus » et tout est redit, et le bilan dit les sceaux
  refaits ; effacer l'historique en même temps ne fait plus un premier passage, et une 0.85 mise à jour n'a pas l'air
  de sceaux effacés. Un fichier critique rechangé est renotifié.
- **Deux campagnes d'attaque contre Vanguard lui-même**, le 23 octobre : 18 faiblesses corrigées par la première, puis
  10 contournements et régressions de ces corrections, et 12 par la seconde, chacune avec son essai. Celles qui
  touchent un sujet ci-dessus y sont décrites ; voici les autres. La clé USB : son menu Ventoy et ses images ISO (par
  leur taille) entrent dans le manifeste ; une clé reconnue dont le numéro de série a changé est signalée, une clé
  VANGUARD sans référence, là où d'autres clés ont la leur, est un avertissement moyen (changer aussi son jeton ne la
  ramène plus à une information), et seule une référence qui porte son jeton l'accuse d'un identifiant changé (un
  identifiant illisible n'accuse plus rien). Réseau local : l'UPnP n'est lu qu'à la passerelle (un appareil qui se dit
  box est signalé), jamais vers cette machine ni un autre hôte, et l'écoute continue après un datagramme trop gros,
  sans le compter ; le DNS est aussi éprouvé sur des noms tirés au hasard. La liste de MalwareBazaar ne se décompresse
  que jusqu'à sa taille annoncée, l'export de ThreatFox est borné de même, et le journal de sshd ne compte que les
  lignes écrites par root. Le nom d'une pièce jointe d'un courriel suspect passe filtré (caractères de direction,
  contrôles) dans le résultat, le journal et le rapport, comme tout message écrit d'un constat. La veille de nuit ne
  dépose plus dans la VM le programme d'une branche écrite par l'IA (à lancer après relecture,
  `vm-tester.sh --branche`), et ne transmet plus à l'IA qui corrige que le sujet, le fichier et la ligne d'une
  proposition.
- **Petits correctifs de sûreté.** Sous Windows, les programmes du système (netstat, netsh, powercfg, wevtutil,
  tasklist, schtasks, ipconfig, cmd, PowerShell…) sont lancés par leur chemin dans System32, demandé à Windows
  lui-même : un faux programme du même nom posé à côté de Vanguard (Téléchargements) ou dans le dossier courant ne
  peut plus cacher un port, un processus ou un réglage ; cmd ne cherche plus dans son dossier courant, et un test
  refuse tout nouveau lancement par le seul nom. La liste des pilotes vulnérables (LOLDrivers) n'est remplacée que par
  une réponse qui en est bien une : une page d'erreur ne coupe plus la vérification une semaine. Sous macOS,
  l'empreinte d'un téléchargement est calculée en Rust, sans md5 ni shasum, et le Bilan de confidentialité lit la base
  des autorisations par le lecteur SQLite de Vanguard, sans /usr/bin/sqlite3. Nettoyer : « Paquets téléchargés » n'est
  plus recommandé sans paccache, et dit qu'il efface de quoi revenir en arrière. Le menu, `--help` et le lanceur
  reprennent l'accroche de la vitrine (« Cyberdéfense portable des postes et des réseaux »). Du code mort retiré et
  des dépendances allégées (une crate de moins sous Windows, moins de fonctions compilées pour reqwest, tokio et
  futures) : 9 à 14 bibliothèques de moins selon le système.
- **Socle commun, sans doublons.** Ce que tout Vanguard partage vit dans `src/socle/`, une fois, testé une fois :
  dossier de Vanguard, écriture atomique et verrou (sortis du module réseau), cache des listes téléchargées (sorti
  d'abuse.ch), portée d'une adresse IP selon les RFC, dossier personnel, processus de Linux et macOS, JSON avec
  commentaires, os-release, empreintes ; l'inventaire des paquets quitte Gaming pour `machine/linux/paquets.rs`, et
  `sha1_smol` et le MD5 écrit à la main laissent la place à sha1 et md-5 de RustCrypto, déjà liés par YARA-X (aucune
  crate de plus). Des copies étaient fausses : une tentative SSH notée « ::ffff:192.168.1.5 » passait pour venue
  d'Internet ; une stratégie de Chrome avec « 1, // commentaire » devant « } » était dite illisible ; un paquet retenu
  (« hold ») n'avait pas de version ; un dossier ou un fichier non exécutable du même nom passait pour un programme
  installé avant une commande sudo ; un HOME vide faisait lire et écrire depuis le dossier courant. /proc illisible
  n'est plus compté comme vérifié (logiciels espions, lecteurs du clavier, caméra, prise de contrôle à distance), et
  un /proc monté avec hidepid est dit. Les listes de menaces et tldr s'écrivent par l'écriture atomique (sous Windows,
  Defender qui tenait l'ancienne copie la laissait en place). Les clés Run se lisent d'une seule façon, la plus sûre :
  « Quelqu'un contrôle mon ordi ? » et « Logiciels espions » voient aussi RunOnce et les noms mal formés, et
  « Logiciels espions » dit une clé illisible. Le bilan lit le Wi-Fi par nl80211 et wlanapi, comme l'audit du réseau
  (nmcli et netsh en secours), et juge les réseaux ouverts enregistrés de la même façon que lui : la protection
  retenue est celle que Windows a négociée (une borne WPA2/WPA3 jointe en WPA2 reste en WPA2), deux bornes du même nom
  aux protections différentes sans émetteur connu renvoient à nmcli, et les profils de NetworkManager se lisent aussi
  dans /run (netplan) et /usr/lib, avec nmcli en secours quand un fichier est refusé.
- **Qualité et livraison.** `outils/verifier.sh` compile le banc de fuzzing et passe quelques secondes sur chaque
  cible (deux de plus : le lecteur SQLite et la liste YAML d'Échap) ; la CI y passe cinq minutes par cible chaque
  nuit, et un banc sans cible échoue. Les tests qui ne peuvent pas tourner sur un ordinateur (outil absent, root d'un
  espace de noms) se disent « sautés » : `verifier.sh` les compte à côté des tests passés et en donne les raisons, et
  ceux sautés sur le vrai Windows et le Mac de la CI y sont comptés et montrés. Un vert qui n'a rien vérifié ne passe
  plus : sous `verifier.sh --seulement` (l'audit de nuit de la CI), une étape sautée ou non lancée échoue et un nom
  d'étape inconnu est refusé (`outils/essais-verifier.sh` l'essaie). La vérification des textes et un essai des menus
  au clavier, dans un vrai pseudo-terminal, sont dans le dépôt. La CI lance `verifier.sh` lui-même (une seule
  logique), les vraies distributions comptent, Windows tourne à chaque envoi, et le .exe livré (MinGW) est essayé sur
  un vrai Windows ; sans `.github/hors-code.txt`, la nuit teste Windows et le Mac au lieu de les sauter, et chaque
  nuit, même l'ordinateur de l'auteur éteint, les vraies sources téléchargées sont relues par leur lecteur (canaris de
  format). CI : `/dev/root` lu par son numéro comme findmnt, liens d'activation d'unités systemd disparues écartés
  comme systemctl, borne de temps du client HTTP local adaptée à Windows ; `claude-journal.yml` en analyse seule. Une
  page de version n'est publiée que si la VM a fait tourner ce .exe-là, et un .exe sans son manifeste (UTF-8,
  asInvoker) ne se compile plus ; un téléchargement raté de l'historique signé d'avant ne le remet plus à zéro avant
  d'effacer les pages d'avant : rien n'est signé ni publié (`signer-versions.sh --premier` pour la toute première
  fois). Une seule table d'outils pour le menu et la ligne de commande, comparée par des tests au README, à `--help`,
  au mode d'emploi de la clé et au tableau Structure ; `vanguard optimiser` (dont `annuler`) rejoint la ligne de
  commande, et l'aide du veilleur, des sites dangereux et des dernières failles retrouve sa commande. Chaîne Rust
  épinglée (`rust-toolchain.toml`) et recette de compilation commune (`outils/compiler-version.sh`) : deux
  compilations dans deux dossiers donnent le même programme. Extensions : isolement sous macOS aussi (sandbox-exec),
  sans `open`, Apple Events, presse-papiers ni disques branchés (/Volumes), par où une extension sortait du bac à
  sable (profil non vérifié sur un Mac), et auteur vérifié par une signature Ed25519 du dossier, dont la clé est
  retenue à l'approbation. Programme de test Windows ramené de 520 à 314 Mo ; essais sans clic dans la VM Windows (une
  file d'attente, `outils/vm-tester.sh`), menus compris, dans une vraie console. Veille continue (`outils/veille/`) :
  chaque nuit, sans IA, vérification, fuzzing et sources ; sur alerte seulement, une correction proposée dans une
  branche à part, jamais fusionnée ni envoyée d'elle-même.

## 22 octobre 2026, au soir : version 0.85

- **Dépôt des versions renommé** `d9v3/vanguard-update` (avant : vanguard-officiel). L'ancienne adresse redirige : les
  Vanguard déjà installés se mettent encore à jour.
- **Ce courriel est-il une arnaque ?** `vanguard courriel-suspect <fichier.eml>` (menu Antivirus et protection, en
  dernier) lit un courriel enregistré sans rien ouvrir : aucun lien suivi, aucune image chargée, aucune pièce jointe
  lancée. Il regarde le vrai expéditeur (nom affiché qui imite une marque ou cache une autre adresse, réponses envoyées
  ailleurs, domaine qui imite), le résultat SPF, DKIM et DMARC écrit par le fournisseur de réception — jamais celui
  qu'un expéditeur glisse plus bas, et un « réussi » ne compte que s'il vient sûrement du fournisseur —, chaque lien
  (texte affiché contre vraie adresse, examen du lien hors ligne, liens réécrits par Safe Links déballés), les pièces
  jointes (programme, double extension, macros, page web, image disque, raccourci, archive à mot de passe, PDF qui
  lance du code) écrites sous un nom neutre dans un dossier jetable pour YARA et l'antivirus, jamais ouvertes. Après
  accord, seuls les noms de domaine sortent pour leur âge et les listes publiques. Analyse MIME écrite pour Vanguard,
  bornée en taille, profondeur et nombre de parties (un courriel piégé est marqué incomplet, jamais dit lu). Un .msg
  d'Outlook : la marche pour l'enregistrer en .eml. Le verdict n'est jamais « sûr », et dit ce qui n'a pas pu être
  vérifié.
- **Le veilleur (Linux).** Entre deux passes de la surveillance horaire, un programme ou une connexion de quelques
  minutes passait inaperçu. Le veilleur, coupé par défaut et allumé seulement après avoir montré son unité
  (`vanguard veilleur on`, ou menu Réseau et Internet), écoute deux flux que Linux 6.6 et plus ouvre aux comptes
  ordinaires : chaque programme lancé, même de quelques millisecondes, et chaque connexion TCP ou UDP au moment où
  elle se ferme. Les programmes sont jugés comme au bilan (outil offensif connu, commande qui télécharge ou cache ce
  qu'elle lance, avec leur lignée : « npm → node → sh »), les connexions contre les serveurs de commande de botnets
  déjà téléchargés ; le grave va au tableau de bord et en notification, à débit borné. Il n'arrête rien, sans root
  ni code chargé dans le noyau. Un programme parti avant d'être lu est compté tel quel, jamais jugé sain ; le
  programme d'une connexion fermée n'est pas connu. Le bilan dit s'il est coupé, allumé, ou allumé mais à l'arrêt.
- **Retirer Vanguard de cet ordinateur.** `vanguard desinstaller` (menu Données) retrouve tout ce que Vanguard a posé
  ici, sans registre : la surveillance horaire, l'entretien du mois, la sauvegarde automatique, le veilleur (son unité
  reconnue à sa marque : une unité du même nom posée par quelqu'un d'autre reste), les fichiers-pièges, le raccourci et
  son icône, la copie du programme, et ce qu'une version d'avant le changement de nom avait laissé. Tout est montré
  avec ce qui sera fait, puis coché ; le dossier de données (carnet des appareils, historique, apprentissage,
  quarantaine) n'est jamais coché d'office et demande un second accord. Les changements faits sur le système se défont
  d'abord par leurs outils, ou sont dits avec la commande qui les défait ; la clé USB n'est jamais touchée. À la fin :
  ce qui est retiré, gardé, et ce qui a échoué ou n'a pas pu être vérifié. Sans droits d'administrateur.
- **Raccourci retiré avec son icône** (Linux) : `raccourci off` laissait l'icône ; elle part aussi, si c'est bien celle
  de Vanguard.
- **Une surveillance qui ne tourne plus est dite.** Le bilan vérifie que le programme lancé par la surveillance horaire
  et par l'entretien du mois existe encore (et rsync pour la sauvegarde), pas seulement la tâche, et dit comment la
  remettre.
- **Passes manquées rattrapées.** Activée maintenant, la surveillance rattrape sous Windows une heure manquée
  (ordinateur éteint ou en veille) et passe cinq minutes après l'ouverture de session ; sous Linux, elle rattrape au
  réveil l'heure manquée pendant une veille et passe cinq minutes après l'ouverture de session ; sous macOS, dès
  l'ouverture de session. Une surveillance déjà en place n'est pas changée en silence : le bilan la dit « d'une version
  d'avant », et `vanguard surveillance on` la met à jour.
- **Protection anti-hameçonnage imposée coupée, vue.** Une stratégie de Chrome, Chromium, Brave, Edge ou Firefox
  (fichier de /etc sous Linux, registre sous Windows, policies.json), lue comme le navigateur la lit, qui coupe Safe
  Browsing passe avant les Paramètres, qui ne peuvent plus la rallumer : un logiciel indésirable s'en sert. Le bilan la
  dit, avec l'endroit où la retirer ; une stratégie seulement recommandée compte tant que la personne n'a rien choisi.
  Des réglages de navigateur ou des stratégies illisibles ne passent plus pour une protection active.
- **Un DNS qui ne bloque pas les sites dangereux est dit.** Le bilan le signale (information) et renvoie à « DNS le plus
  rapide », où le Bouclier canadien « Protégé » ou Quad9 se posent en un choix, annulable. Rien n'est dit quand un DNS
  protège déjà, ou quand rien ne permet de le savoir (NextDNS, Pi-hole).
- **Dernières failles exploitées** (`vanguard dernieres-failles [--jours N]`). Celles que la CISA a ajoutées à son
  catalogue ces derniers jours (7 par défaut), les plus récentes d'abord, avec celles des rançongiciels ; sous Arch,
  celles qui touchent un paquet de cet ordinateur en tête. Le bilan donne aussi la date d'ajout d'une faille exploitée.
- **Failles activement exploitées en tête** (Linux, Arch). Les CVE des failles connues des paquets installés sont
  comparées au catalogue KEV de la CISA (failles dont une attaque réelle est connue), téléchargé en entier : la liste des
  logiciels ne sort pas de l'ordinateur. Une faille exploitée rend le constat critique et passe en tête, même sans
  correctif publié ; sans le catalogue, c'est dit. Une faille dans un paquet dont un programme écoute sur le réseau
  (un service par son unité systemd, sans droits root) est dite en tête, au moins élevée. La surveillance horaire notifie une faille critique nouvelle
  (exploitée, ou critique pour la distribution) ; les autres, qui changent chaque jour, restent au bilan.
- **Sites dangereux bloqués** (`vanguard sites-dangereux on|off`). Les hôtes d'URLhaus et les domaines des serveurs
  de commande de ThreatFox (clé abuse.ch) sont envoyés nulle part (0.0.0.0 et ::) par le fichier hosts, après accord
  et avec les droits d'administrateur. Le bloc de Vanguard est entre deux marques datées : `off` le retire exactement,
  le reste du fichier ne change jamais. L'écriture vérifie l'empreinte du fichier préparé et celle du hosts lu au
  départ : rien n'est écrit si l'un a changé entre-temps. Le bilan dit quand la liste a plus d'une semaine. Sous
  Windows, 5 000 noms au plus (au-delà, le client DNS ralentit) ; ailleurs, 20 000. Dans le menu Protection, avec
  « Dernières failles exploitées » ; `desinstaller` rappelle de les retirer avant.
- **Site qui distribue des logiciels malveillants, signalé.** Les noms que l'ordinateur a demandés (mémoire DNS : sans
  droits sous Windows, en root sous Linux) sont comparés aux hôtes d'URLhaus, avec la clé abuse.ch : « Qui parle à
  Internet ? » le montre, et la surveillance horaire le notifie une fois (examen antivirus, fichiers téléchargés). Sans
  la liste, c'est dit ; le nom exact seulement, pour ne pas accuser tout un hébergeur.
- **Feodo Tracker figée, dite.** abuse.ch ne tient plus sa liste de serveurs de botnets à jour depuis le 4 mars 2026
  (une seule adresse). Sans ThreatFox (clé abuse.ch absente), c'était la seule liste lue, et rien ne disait qu'elle
  était figée : « Qui parle à Internet ? », le bilan, le blocage et le veilleur le disent maintenant parmi ce qui n'a
  pas pu être vérifié. Ses adresses servent encore ; avec la clé, ThreatFox suit les mêmes botnets à jour.

## 22 octobre 2026 : version 0.84.1

- **Serveurs d'IA ouverts au réseau, vus aussi sur Mac.** La règle qui repère un serveur d'IA local (Ollama, LM Studio,
  llama.cpp…) joignable depuis le réseau lit maintenant les ports en écoute du Mac ; elle était jusqu'ici toujours dite
  non vérifiée sous macOS. Les programmes sont nommés en entier : un nom coupé à neuf caractères ne se reconnaissait
  pas, et un serveur ouvert serait passé pour sain. Chaque prise garde le programme de son adresse : un serveur
  d'IA ouvert au Wi-Fi n'est plus caché par un autre programme qui tient le même port sur la machine elle-même.
  Sans droits d'administrateur, seuls les programmes du compte en cours sont nommés, et « aucun serveur d'IA » le
  dit ; si lsof ne répond pas, la règle reste non vérifiée. Le blocage des menaces en profite.
- **Connexion forcée par SSH, sur Mac.** Sans sshd, ni en écoute sur le port 22 ou sur celui de ssh dans
  /etc/services, ni en marche (un sshd de Homebrew sur un autre port), ni lancé par une plist de launchd, il n'y a
  rien à lire et Vanguard le dit, au lieu de marquer la règle non vérifiée à chaque bilan ; avec lui, la règle reste
  non vérifiée (le journal unifié de macOS n'est pas lu), jamais saine.
- **Bancs d'essai sans clé abuse.ch.** Sur le Mac de GitHub, sous Linux et dans la VM Windows, l'analyse YARA passe
  quand Vanguard dit les empreintes de MalwareBazaar non vérifiées faute de clé, et la reconnaissance par empreinte
  exacte s'essaie sur une copie posée pour l'essai, puis retirée : plus rien ne dépend des listes fermées le 21 octobre.
- **Présentation.** Vanguard se présente comme la cyberdéfense portable des postes et des réseaux (README, page des
  fonctions, description du dépôt, fichiers de la clé), dans un vocabulaire professionnel : le routeur, le réseau
  local, l'adresse Internet publique. La page des fonctions de GitHub Pages est de nouveau refaite à
  chaque publication : elle en était restée à la 0.82, le programme lancé par un chemin relatif depuis un autre
  dossier.

## 21 octobre 2026, au soir : version 0.84

- **Blocage des menaces, en un clic.** Chaque menace trouvée propose « Bloquer » : le geste est montré, fait après ton
  accord, noté dans « Ce que Vanguard a changé » et défait exactement par `vanguard blocage annuler` (seul l'arrêt
  d'un programme ne se défait pas). Selon la menace : le programme arrêté puis mis en quarantaine, la connexion fermée
  au pare-feu (ufw, nftables, Pare-feu Windows, pf), un lancement retiré du démarrage, la liste de blocage des pilotes
  vulnérables de Windows activée (effective au redémarrage), le port d'un serveur d'IA fermé au réseau, un agent d'IA
  remis à demander avant d'agir. Menu Antivirus et protection › Blocage des menaces, ou `vanguard blocage`.
- **Protection active, qui bloque le certain.** Acceptée une fois, elle bloque toute seule ce qui ne fait aucun doute,
  puis prévient : un fichier dont l'empreinte est dans MalwareBazaar, un outil d'attaque connu en marche, une
  connexion vers un serveur de commande connu (Feodo Tracker, ThreatFox). Le douteux reste une alerte avec son bouton.
  Elle tourne au bilan et dans la surveillance horaire. Quatre catégories (programmes, connexions, démarrage et
  pilotes, agents d'IA), chacune désactivée, en un clic, ou automatique pour les programmes et les connexions. En
  administrateur, elle ne bloque rien toute seule : ses réglages peuvent être écrits par n'importe quel programme du
  compte, et le certain s'y propose d'un clic.
- **Jamais un blocage qui ferait plus de mal que la menace** : ni Vanguard, ni un programme du système ou un processus
  critique, ni une session à distance en cours (SSH, Bureau à distance, RustDesk, AnyDesk, Tailscale…), ni une adresse
  locale ou un DNS public ; un interpréteur (python3, PowerShell) n'est jamais mis en quarantaine, au plus le script
  qu'il lance. Sans les droits nécessaires, rien n'est fait à moitié.
- **Paramètres, tous au même endroit** (Cette machine › Paramètres, « s » au menu principal, ou `vanguard parametres`) :
  langue, emojis, travail sans Internet, protection en temps réel, surveillance horaire, entretien du mois, alertes
  apprises, blocage, restrictions des extensions et clé abuse.ch. Chaque changement montre la valeur d'avant et la commande pour la remettre ; les alertes
  apprises et le blocage ouvrent leur propre écran (« Ce que Vanguard a appris », Blocage des menaces). La langue, les
  emojis et le travail sans Internet restent choisis d'un lancement à l'autre (VANGUARD_LANG, VANGUARD_EMOJI et
  VANGUARD_HORS_LIGNE l'emportent toujours).
- **La protection en temps réel de Vanguard se coupe, pour un temps ou jusqu'à reprise** (Paramètres, ou `vanguard
  parametres temps-reel non --pendant 1h|4h`) : la surveillance horaire et la protection active du blocage s'arrêtent
  d'un coup, après ton accord et la liste de ce qui s'arrête, sans que leurs réglages changent. Elle reprend toute seule
  à l'échéance ; tant qu'elle est coupée, c'est redit en tête du menu et sur ses lignes Surveillance et Blocage, dans
  chaque bilan (sans effet sur la note), dans « Qui parle à Internet ? », dans le blocage et sur le tableau de la
  surveillance, par une notification à la première passe puis chaque jour, et dans l'entretien du mois : un programme
  qui la couperait en douce se voit. Defender, le pare-feu et l'UAC ne sont jamais touchés, et un blocage déjà fait
  reste en place.
- **Extensions : tes propres programmes dans Vanguard, sans toucher à son code** (menu 12 Extensions,
  `vanguard extensions`). Un plugin est un dossier avec un manifeste `plugin.toml`, ajouté une fois depuis un dossier
  ou une archive .zip (`vanguard plugin ajouter`) ; un script du laboratoire est un fichier posé tel quel
  (`vanguard labo`), pour essayer une idée vite. Leurs constats sont montrés à part, ne comptent jamais dans la note,
  et vont dans une section à part du rapport HTML avec `--rapport`. Pour écrire un plugin en Rust : la bibliothèque
  `extensions/sdk`, sans dépendance, et un exemple complet.
- **Une extension est vérifiée avant de tourner.** Avant l'accord, tout son dossier ou son archive est analysé (YARA,
  empreintes de MalwareBazaar) et chaque fichier haché (SHA-256) : un fichier changé, ajouté ou retiré, et il faut la
  réapprouver. C'est la copie vérifiée qui tourne, sans accès au terminal, avec un délai et une sortie bornés : au-delà,
  elle est arrêtée avec tout ce qu'elle a lancé ; sous Linux, ce qu'elle laisse derrière elle est arrêté aussi quand
  elle finit d'elle-même. Une archive ne peut rien écrire hors de son dossier. Sous Linux, `--isole` la lance sans
  réseau, le dossier personnel masqué. Un manifeste ne fait que demander la confiance totale ou de tourner avec le bilan
  ou la surveillance : c'est accordé par une question à part, et l'accord tombe au moindre changement. En
  administrateur, rien du dossier des extensions ne lève une garde : rien n'y tourne tout seul, et chaque lancement est
  demandé. L'interrupteur **Restrictions** (Extensions › 3, Paramètres, ou pour un seul plugin ou script) coupe ces
  garde-fous pour ce qui est à toi ; une seule chose reste : le dossier des extensions doit être à toi, fermé aux autres
  comptes.
- **YARA-X 1.22.0**, qui corrige huit failles connues de wasmtime, la bibliothèque sur laquelle tourne YARA, dont une
  sur les Mac à puce Apple. Chaque bibliothèque utilisée est maintenant vérifiée à chaque version et chaque nuit
  (cargo deny) : failles connues, licences compatibles avec la GPL, provenance (crates.io seulement). Les deux avis
  restants, sans correctif publié, viennent de YARA-X et ne s'appliquent pas à l'usage qu'en fait Vanguard (la raison
  est notée).
- **Calculs vérifiés dans la version publiée** (guide de l'ANSSI, LANG-ARITH) : un nombre qui déborde sur une donnée
  hostile (une taille lue dans un paquet réseau, un journal, un programme Windows) arrête la vérification en cause au
  lieu de repartir à zéro en silence et de fausser la suite ; le reste du bilan continue.
- **Listes d'abuse.ch avec ta clé.** Le 21 octobre, abuse.ch a fermé ses listes publiques : MalwareBazaar, URLhaus et
  ThreatFox demandent désormais une clé gratuite, à créer sur auth.abuse.ch. Vanguard la prend dans Paramètres ou dans
  « Qui parle à Internet ? », la garde sur cet ordinateur (lisible par le compte seul), ne la montre que masquée et ne
  l'écrit jamais dans une adresse affichée ni dans un journal. Sans clé, ou avec une clé refusée, ces listes sont dites
  non vérifiées, jamais saines ; Feodo Tracker reste sans clé.
- **Linux lu sans commandes de plus.** Un client D-Bus écrit pour Vanguard lit les services en échec, la durée du
  démarrage et la santé des disques (UDisks2), à la place de systemctl, systemd-analyze et busctl ; les réglages de
  GNOME et les autorisations des applications Flatpak se lisent dans leurs fichiers (GVDB) ; le journal de systemd et
  ses données compressées (zstd) se lisent en Rust, journalctl et pacman restant en secours. Sous macOS, les comptes
  administrateurs se lisent par la bibliothèque du système, sans dscl.
- **Chaque programme publié porte la liste de ses dépendances** (cargo auditable) : n'importe qui peut le vérifier
  contre les failles connues avec `cargo audit bin`, et une faille connue arrête la publication. cargo audit s'ajoute à
  cargo deny dans chaque vérification, et le code défaillant est refusé dans tout l'arbre des dépendances.
- **Entrées hostiles mises à l'épreuve** : des tests de propriétés sur les lecteurs de données venues d'ailleurs (box,
  DNS, HTTP, bail DHCP, journaux, réglages des agents d'IA, pilotes et événements de Windows) et un banc de fuzzing. Deux
  plantages trouvés et corrigés : une date démesurée dans un bail macOS, et un « cmd /c » imbriqué qui débordait la pile.
  Les sommes de tailles de fichiers sont bornées, un fichier qui fait planter l'analyse YARA reste comparé aux
  empreintes, et une mesure DNS dont le fil plante est dite non vérifiée.
- **Outils de la clé de secours** : la clé se tient à jour même branchée en permanence (programme et images chaque
  jour, nouvelles images cherchées le 1er et le 15 du mois, chaque téléchargement annoncé), Ventoy est vérifié sur la clé
  et sa mise à jour proposée, puis faite sans rien effacer après le mot de passe ; Windows 11 est signalé au-delà de six
  mois.
- **Signaler une faille** : SECURITY.md dit comment (le signalement privé de GitHub), ce qu'il faut joindre, et ce qui
  suit la correction (avis de sécurité publié, CVE si la faille le mérite).
- **Relecture de sécurité.** Un outil d'attaque n'est certain que par le nom du programme lui-même : un script lancé par
  un interpréteur et qui porte le nom exact de l'outil (python3 laZagne.py) n'est qu'un doute, et un nom qui ne fait que
  commencer comme l'outil (python3 sharphound_parser.py) n'est plus signalé. Le programme est revérifié au moment même
  de l'arrêt (son numéro pouvait passer à un autre). La règle ufw qui ferme un port passe avant les autorisations, et le
  port n'est dit fermé qu'une fois vérifié. En automatique, une adresse où un autre compte a une connexion établie n'est
  jamais bloquée. Un fichier de réglages illisible (paramètres, blocage, extensions) est d'abord copié à côté, tel quel,
  avant d'être réécrit ; pour les extensions, rien n'est écrit tant qu'il n'a pas pu être mis de côté.

## 21 octobre 2026, au soir : version 0.83

- **Chasse aux menaces en direct.** Une connexion réussie depuis une adresse qui venait de rater au moins dix mots de
  passe : un mot de passe deviné, signalé en critique (journal de sshd sous Linux ; sous Windows, en administrateur,
  le journal de sécurité pour le Bureau à distance et les partages, et celui d'OpenSSH ; macOS : non vérifié). Une
  lecture bornée ou trop longue est dite partielle, jamais saine sans réserve. Les programmes en marche suspects :
  outil offensif connu (Mimikatz, Rubeus, SharpHound, LaZagne, XMRig…), ligne de commande qui télécharge ou cache ce
  qu'elle exécute, programme lancé de Téléchargements, d'un dossier temporaire ou de la corbeille ; de la ligne, seuls
  le programme et le motif sont montrés, jamais un secret écrit autour.
- **Chronologie de l'incident** dans `vanguard traces` (CHRONOLOGIE.txt) : ce que la collecte a lu de daté, remis dans
  l'ordre du temps sur les 7 derniers jours, avec la technique MITRE ATT&CK quand elle est évidente : connexions
  acceptées ou refusées, sudo, comptes créés, services et tâches ajoutés, journaux effacés, détections de Defender,
  fichiers récents qui parlent. Un journal qui ne remonte pas la semaine dit pourquoi.
- **Portes cachées de Windows et pilotes du noyau** : les DLL que Windows charge lui-même (paquets de LSA,
  AppCertDlls, moniteurs d'impression, fournisseurs de temps, catalogue Winsock) ; les pilotes rangés là où rien
  d'installé n'en pose, ou connus pour être vulnérables (liste LOLDrivers, une fois par semaine). Lecture seule, sans
  PowerShell.
- **Mémoire des programmes** (`vanguard memoire`, à la demande) : les 308 règles YARA appliquées à la mémoire des
  programmes qui tournent, où vit un logiciel malveillant « sans fichier », sous Linux et Windows (macOS : non
  vérifié). La mémoire de LSASS et des processus protégés n'est jamais lue, rien de ce qui est lu n'est gardé, et ce
  qui n'a pas pu l'être est dit.
- **Agents d'IA** : un serveur d'IA local (Ollama, LM Studio, ComfyUI) ouvert au réseau sans mot de passe ; un agent
  réglé pour tout faire sans demander, un serveur MCP lancé sans version fixée, joint sans chiffrement ou avec une clé
  écrite en clair, dans les réglages de Claude Code, Claude Desktop, Cursor, VS Code, Windsurf et Gemini CLI (le nom
  de la clé seulement, jamais sa valeur).
- **Corrections Windows sans PowerShell** : quatorze réglages de durcissement d'une liste fermée (WDigest, NLA du Bureau
  à distance, NTLMv2 seul, LLMNR, WPAD, UAC…) appliqués par Vanguard lui-même, relancé en administrateur : la fenêtre
  de Windows nomme Vanguard, le point de restauration passe d'abord et la valeur d'avant est notée pour annuler
  exactement ; seuls Entrée ou oui appliquent. Mêlées à une correction hors de la liste, elles passent par le script,
  comme avant.
- **Vérifier ma sauvegarde** : une copie réécrite après la sauvegarde (plus récente que son original, et différente),
  comme par un rançongiciel qui chiffre le disque de sauvegarde, est dite abîmée ; elle passait pour « modifiée
  depuis ».
- **Guide des commandes : 1 085 commandes**, dont celles de Vanguard pour se défendre et dépanner, et de quoi vérifier
  à la main ce que signalent les nouvelles règles.
- **Plus justes.** Sous Windows, Vanguard lancé en administrateur se croyait sans droits (Windows refusait la lecture
  de son élévation, que Wine acceptait) : `vanguard traces` y laissait de côté le journal de sécurité, et la fenêtre
  administrateur des corrections se refermait sans rien faire. Un fil de l'analyse YARA qui plantait faisait conclure
  « sain » sans avoir lu ses fichiers : ils sont maintenant dits non analysés. Sans journalctl, les traces reprennent
  aussi le dernier fichier tourné de /var/log (auth.log.1…). Dans ce qui se lance tout seul sous Linux, « nc -e » est
  vu dans ( … ), après ; ou & et derrière un chemin, et un script téléchargé passé à ash, à « sudo -p x sh », à
  « sudo -s » ou à su aussi. La garde contre une DLL posée à côté du programme est exigée à la compilation : elle
  pouvait disparaître.

## 21 octobre 2026 : version 0.82

- **Audit du réseau, domaine par domaine** (`vanguard audit-reseau`). Six notes : exposition à Internet (ports
  ouverts par UPnP, lus par un client UPnP écrit en Rust), Wi-Fi (chiffrement, WPS, réseaux voisins, lus par nl80211
  sous Linux et l'API Wi-Fi de Windows), séparation des appareils (objets connectés sur le réseau des ordinateurs,
  serveur DHCP pirate, intégrité ARP), DNS et certificats, objets connectés, ordinateurs. Ce qui n'a pas pu être
  vérifié est dit et ne compte jamais comme sain : sans assez de domaines vérifiés, pas de note.
- **Windows lu sans PowerShell.** Comptes, démarrage, tâches planifiées, partages, Defender, BitLocker, Windows
  Update, santé du disque et lenteur se lisent par les API de Windows (registre, WMI, COM). Le bilan est plus rapide
  et marche même quand PowerShell est bloqué ; PowerShell ne sert plus qu'en secours.
- **macOS et Linux lus sans commandes.** Sous macOS, les réglages se lisent par un lecteur de plist écrit pour
  Vanguard ; sous Linux, par /proc, /sys et les fichiers du système.
- **Box et objets connectés** (`vanguard objets`) : modèle et logiciel de la box, administration en HTTP seul,
  caméras, imprimantes, NAS, et le rappel de changer leur mot de passe d'origine. La seule demande envoyée à un
  appareil est SNMP « décris-toi », avec le mot de passe de lecture d'usine « public » : elle est annoncée à l'écran.
- **Ordinateur d'un proche** (`vanguard proche`) : trois questions, le bilan, un résumé en mots simples et une page
  à lui laisser.
- **Bilan de confidentialité** (`vanguard acces`) : qui a accès à la position, aux contacts, à la caméra et au micro,
  sur les trois systèmes.
- **Sauvegardes relues pour de vrai** (`vanguard verifier-sauvegarde`) et **tableau de bord de la surveillance**
  dans le navigateur (`vanguard tableau`).
- **Mots de passe des navigateurs** (`vanguard navigateurs`) : comptés et leur protection décrite, jamais lus ni
  envoyés ; la vérification intégrée de chaque navigateur est indiquée.
- **Bouclier canadien** proposé parmi les DNS rapides : le DNS public de l'ACEI, qui bloque les sites malveillants.
- **Windows : une DLL posée à côté de Vanguard n'est plus chargée.** Le programme ne prend ses bibliothèques que dans
  System32 (DependentLoadFlags du PE), y compris lancé depuis une clé USB ou Téléchargements ; le déploiement refuse
  un programme qui n'a pas cette garde.
- **PowerShell en fenêtre cachée** dans un lancement automatique : dit en information, plus en alerte.
- **Une relecture de sécurité** a corrigé de nombreux faux « sain » ; la page des fonctions se publie toute seule
  à chaque version (https://d9v3.github.io/vanguard-beta/).

## 20 octobre 2026 : version 0.81

- **Linux, le bilan voit plus loin.** Redirections ICMP acceptées (IPv4 et IPv6) et filtre des adresses d'origine
  coupé, corrigés dans `99-vanguard.conf` sans jamais relâcher une interface réglée en strict ; espaces de noms
  ouverts à tous les programmes (une information : Flatpak, Chrome et Steam en ont besoin) ; dossiers de commandes
  (PATH, celui de sudo) que d'autres comptes peuvent modifier, où une fausse commande prendrait la place de la vraie ;
  pas de blocage après des mots de passe faux, mots de passe de moins de 8 caractères (PAM).
- **SSH.** Ports renvoyés ouverts à tout le réseau (`GatewayPorts`), affichage X11 renvoyé, trop d'essais de mot de
  passe par connexion ; corrigés par un rechargement de sshd, qui ne coupe aucune connexion en cours. Algorithmes
  cassés (SHA-1 pour l'échange de clés, CBC, 3DES, arcfour, MD5, DSA) rouverts dans la configuration, lue dans
  l'ordre exact des Include : retirés par une ligne de `00-vanguard.conf`, vérifiée par `sshd -t` avant le
  rechargement.
- **Windows.** Recherche automatique du proxy (WPAD), par laquelle un appareil d'un Wi-Fi public peut détourner la
  navigation ; aucun blocage des comptes après des mots de passe faux (corrigé comme Windows 11 : 10 essais,
  10 minutes) ; longueur minimale des mots de passe. Un compte sans mot de passe exigé est décrit tel qu'il est
  (« accepte un mot de passe vide ») et se corrige depuis Vanguard : un mot de passe devient exigé, l'actuel ne
  change pas.
- **macOS.** Découverte automatique du proxy allumée ; dossiers de commandes ouverts à tous ; définitions de
  XProtect, l'antivirus intégré, trop vieilles ; profils de configuration installés hors gestion d'entreprise (un
  logiciel publicitaire s'en sert pour imposer un proxy, un DNS ou un certificat).
- **Guide des commandes : 1 040 commandes** (98 de plus), surtout pour la sécurité et le dépannage : lynis, programmes
  SUID, comptes bloqués, ClamAV, signatures gpg, WireGuard, certificats, exposition des services, needrestart, sbctl,
  dnf needs-restarting ; sous Windows, réseau public ou privé, dossiers partagés, puce TPM, signature d'un programme,
  effacement de l'espace libre, test de la mémoire ; sous macOS, ce qui se lance tout seul, accès à la caméra, au
  micro et à l'écran, empreinte d'un fichier, trafic par programme ; sous Omarchy, 60 commandes de plus : firmware,
  trousseaux et heure qui bloquent une mise à jour, paquets orphelins, cache de pacman, clé FIDO2, serveur SSH et
  groupe docker à couper, réseau et vitesse, partage par LocalSend, captures et texte de l'écran, luminosité, écran
  de démarrage, applications web, jeux et services à installer, remise à neuf. Les exemples de tldr-pages se
  renouvellent aussi pendant la surveillance et l'entretien du mois, sans ouvrir le guide.
- **Secrets dans les projets git.** Vanguard relit l'historique des projets du dossier personnel, où un mot de passe,
  une clé d'API ou un jeton écrit un jour reste, même effacé ensuite : clés reconnues à leur forme (AWS, GitHub,
  GitLab, Google, Stripe, Slack…), clés privées, mots de passe dans une adresse ou dans le code ; gitleaks, s'il est
  installé, ajoute ses règles. Aucun secret n'est affiché ni gardé.
- **YARA sans rien installer.** Les 308 règles sont appliquées par YARA-X (le moteur YARA en Rust de VirusTotal,
  licence BSD), compilé dans Vanguard sous Linux, Windows et macOS : plus de moteur à installer ni à proposer, et
  quatre fichiers lus à la fois. Un fichier de plus de 256 Mo ou plus long que 30 s à analyser est dit, jamais compté
  comme sain. Le programme passe d'environ 10 à 25 Mo.
- **Antivirus par empreintes, partout, même depuis la clé.** L'analyse YARA compare aussi chaque fichier lu aux
  empreintes SHA-256 de MalwareBazaar (abuse.ch, domaine public) : un fichier qui y est, c'est ce logiciel malveillant
  précis, sans doute possible, proposé en quarantaine. La liste complète se met à jour une fois par semaine, les
  48 dernières heures chaque jour ; sans Internet, la copie gardée sert, et sans copie, c'est dit.
- **Outils libres reconnus, s'ils sont installés.** « Failles des images Docker » : trivy dit les failles connues,
  graves ou critiques, des images Docker ou Podman ; absent, Vanguard propose de l'installer par l'outil du système. Après
  des connexions SSH ratées, le bilan dit si fail2ban, sshguard ou CrowdSec bloque déjà les adresses qui insistent.
- **Windows, les portes dérobées classiques.** Débogueur posé sur un programme d'accessibilité de l'écran de
  connexion (IFEO, SilentProcessExit), sethc ou utilman remplacés par cmd, Shell ou Userinit de Winlogon détournés,
  AppInit_DLLs, abonnements WMI qui lancent une commande : au bilan, suivis par la surveillance, corrigés quand
  l'état d'origine est connu exactement, sinon la marche à suivre. Et les journaux d'événements des 7 derniers
  jours : rafales de mots de passe faux par le réseau, journal de sécurité effacé, comptes créés, services installés
  suspects ; sans droits administrateur, le journal de sécurité est dit illisible, jamais sain.
- **Linux, les signes d'un rootkit.** Processus cachés, programmes qui tournent sans fichier (memfd, effacés, lancés
  depuis /tmp ou /dev/shm), module du noyau qui se cache ou modules non signés inconnus, carte réseau en mode
  promiscuité ; lus dans /proc et /sys en quelques millisecondes. Pas de correction automatique : la marche à suivre,
  avec rkhunter et chkrootkit en deuxième avis.
- **Empoisonneur de noms démasqué.** Pendant le scan du réseau, sans le ralentir, Vanguard demande en LLMNR, NetBIOS
  et mDNS un nom tiré au hasard, qui n'existe pas : l'appareil qui y répond est un outil comme Responder, qui vole
  les mots de passe Windows du réseau. Alerte élevée, et notification de la surveillance horaire.
- **Collecter les traces** (Dépanner, `vanguard traces`, et première étape d'« Après une infection », cochée
  d'office ; devant un rançongiciel ou une prise de contrôle, juste après la coupure d'Internet, qui ne peut pas
  attendre). Avant de nettoyer, ce qu'un spécialiste voudra voir, dans un dossier daté sur la clé ou dans le dossier
  de Vanguard : processus avec l'empreinte SHA-256 de leur programme, connexions, ce qui se lance tout seul, bilan en
  JSON, comptes, journaux des 7 derniers jours, fichiers récents ; un LISEZMOI et un MANIFESTE que `sha256sum -c`
  vérifie. Lecture seule, rien n'est envoyé ; Vanguard prévient que le dossier contient des données personnelles.
- **« Qui parle à Internet ? » reconnaît les serveurs de commande de botnets** : listes de Feodo Tracker et de
  ThreatFox (abuse.ch), avec le nom du logiciel malveillant, clé abuse.ch facultative (indisponibles ou trop vieilles,
  c'est dit, jamais comptées comme vides). La mémoire DNS aussi : un programme qui a demandé le nom d'un serveur de
  commande connu se voit, même la connexion fermée. Les connexions des autres comptes sont comparées aussi ; un
  serveur trouvé mène à « Après une infection », Internet coupé d'abord. La surveillance horaire prévient quand un
  programme parle à un serveur de commande connu. Et le dossier temporaire du compte est reconnu où qu'il soit (un
  TEMP déplacé laissait passer un programme lancé de là).
- **Mise à jour depuis GitHub, sans la clé.** « Mettre Vanguard à jour » prend la dernière version publiée, et le
  menu principal l'annonce. Rien n'est cru sur parole : chaque version est signée en Ed25519 sur l'ordinateur de
  l'auteur, et Vanguard refuse un manifeste mal signé, une version qui n'est pas plus récente, ou un programme dont
  la taille, l'empreinte ou la version ne sont pas celles signées. Qui prendrait le compte GitHub ne pourrait pas
  faire installer autre chose. Les programmes signés sont publiés à part (d9v3/vanguard-officiel), le code dans d9v3/vanguard-beta.
- **Client HTTPS en Rust** : listes, registres, fuites, tldr, débit et listes noires sans curl ; redirections en HTTPS
  seulement. Le programme prend 2 à 3 Mo.
- **Lu directement par le système** : connexions, processus, droits et compte, registre des traces et journaux
  d'événements, sans ss, tasklist, taskkill, whoami, pgrep, id ni PowerShell ; plus rapide, et rien ne dépend de la
  langue de Windows. Sans droits, le journal de sécurité est dit non vérifié (avant, il passait pour sain sans avoir
  été lu).
- **Nettoyage de Windows** : chemins écrits en entier, jamais le dossier courant quand une variable comme TEMP est
  vide ; la file d'impression se vide sans risque.
- **Plus justes et plus sûrs.** Sous Windows, un compte sans dossier Démarrage ne fait plus prendre chaque fichier
  du dossier courant pour un « raccourci suspect » (alerte élevée à tort, surtout lancé depuis la clé) ; les
  dernières commandes rapides (notifications, df sur un volume réseau mort…) ont un délai et ne figent plus la
  surveillance ; la liste des clés connues ne perd plus une note quand deux s'écrivent en même temps.
- **Clé de secours : l'installateur d'Omarchy** dans le menu de démarrage, à côté d'Arch, Debian, Fedora et
  SystemRescue : complet, sans Internet, tenu à jour comme eux et vérifié par la clé qui signe les paquets d'Omarchy.
- **Pour les tests** : scripts PowerShell du programme analysés et rejoués avec pwsh à chaque vérification, dans
  un bac à sable fermé au système ; test de la machine virtuelle Windows qui compte les étapes sautées, compare chaque passe à la
  précédente et vérifie les réglages de la 0.79 ; scripts déposés depuis Linux et lancés par la VM
  sur son accord.
- **Relecture indépendante avant la publication** : un compte au mot de passe vide qu'une correction aurait fait
  passer pour sain, une limite d'essais SSH trop stricte qui pouvait fermer la porte, un `chmod` qui aurait cassé
  `/tmp` mis dans le PATH ; corrigés.

## 19 octobre 2026, au soir : version 0.78

- **Nouveau nom : Vanguard**, avec son logo, un V en bouclier et un cadenas. Sur un ordinateur où il a déjà
  tourné, rien ne se perd : données, sauvegarde automatique, raccourci et réglages suivent le nouveau nom tout seuls.
- **Bilan bien plus rapide.** Sous Linux, de 7 secondes à moins d'une : les commandes ne sont plus attendues par
  pauses fixes de 50 ms, les paquets se vérifient en parallèle, le Wi-Fi n'attend plus un nouveau balayage. Sous
  Windows, une dizaine de lancements de PowerShell de moins : pare-feu, UAC, Bureau à distance et verrouillage lus
  directement dans le registre, ports en écoute lus par netstat et tasklist.
- **Windows.** Installation de paquets MSI avec les droits du système, protection dans le cloud de Defender coupée,
  protection contre les exploits coupée (DEP, ASLR, CFG, SEHOP), Windows Update coupé (service ou stratégie),
  services au chemin sans guillemets dans un dossier modifiable par tous ; BitLocker suspendu ou en attente ne compte
  plus comme chiffré.
- **Linux et macOS.** Session qui s'ouvre toute seule sans disque chiffré (GDM, SDDM, LightDM), mémoire des
  programmes root lisible après un plantage, touches magiques du noyau ; sauvegarde Time Machine non chiffrée,
  partage à distance du Mac qui accepte root ou les comptes sans mot de passe.
- **Plus justes.** Fichiers inclus de la configuration SSH lus, réseaux Wi-Fi ouverts mieux reconnus, DNS sur cet ordinateur mesuré aussi
  sur un site nouveau (sa mémoire répondait en moins d'une milliseconde), dnf-automatic
  qui ne fait que télécharger, réglages d'APT lus dans leur ordre, interface anglaise complète, nombres à virgule écrits à la française,
  longs messages coupés entre deux mots, jamais au milieu d'un mot ; sous Windows, un pare-feu dont aucun profil ne
  se lit n'est plus compté comme vérifié (pas de note), et un Bureau à distance imposé par une stratégie de groupe est
  reconnu ; une interface de VPN n'est plus prise pour le réseau local.
- **Scan du réseau deux fois plus rapide** (de 20 à 8-10 secondes sur un réseau de onze appareils) : la box est
  interrogée sur l'UPnP dès le début, en fond (elle met jusqu'à 8 secondes à répondre), et les ports TCP, UDP et les
  noms des appareils sont cherchés en même temps. Mêmes sondes, rien de retiré.
- **Guide des commandes refait.** Une entrée par système : Omarchy, Arch, Fedora, Debian et Ubuntu, autres Linux,
  Windows 11, macOS ; chaque distribution a sa présentation, ses marches à suivre « Pas à pas » (mettre à jour,
  installer, faire de la place, réparer, pare-feu, NVIDIA, nouvelle version…) et ses programmes, puis ceux communs à
  Linux ; Windows 11 et macOS ont aussi les leurs (réparer Windows, réseau, sécurité, lenteur, Time Machine…), tous
  les systèmes aussi (clé SSH, git) ; plus de vingt programmes communs à Linux en plus (heure, noyau, Wi-Fi,
  diagnostic réseau, comptes, son, imprimantes, démarrage UEFI…), openSUSE et Docker ; 942 commandes. On tape ce
  qu'on cherche et les commandes paraissent au fil de la frappe ; chacune a sa page, pour la copier, ou la lancer
  ici quand elle ne fait que lire (sa sortie défile dans Vanguard, Échap l'arrête).
- **Plus de 30 000 commandes en plus** : les exemples de tldr-pages (licence CC BY 4.0), téléchargés tout seuls chaque
  semaine et déjà sur la clé (même sans Internet, le guide les a dès le premier lancement), en français quand ils
  sont traduits ; à copier seulement. Dans toutes les recherches, ce qui commence par le mot tapé passe devant.
- **Plus sûr : la clé reconnue à son jeton.** Un volume qui porte le témoin d'une clé VANGUARD n'est plus la clé
  pour autant : depuis sa copie locale (surveillance, entretien, raccourci), Vanguard ne lit et n'écrit que sur une
  clé lancée depuis elle ou connue de cet ordinateur (jeton `vanguard.jeton` posé au déploiement, partition des
  journaux comprise) ; un volume inconnu est dit tel au menu et ignoré. Le carnet de la clé a sa référence ici :
  modifié hors de Vanguard, ou revenu sans sa protection, il n'est ni lu ni réécrit et le bilan le dit
  (`vanguard manifeste --accepter` quand c'est voulu).
- **Prédiction des mots dans tous les menus** et les listes à cocher : la fin du mot le plus probable s'affiche en
  gris, Tab la complète.
- **Bilan plus profond.** Sécurité de la plateforme d'après fwupd (niveau HSI : TPM, protection du BIOS, IOMMU),
  verrouillage du noyau et signature des modules, BPF, auditd ; sous Windows, journalisation des scripts PowerShell,
  Credential Guard (Entreprise, Éducation), Sysmon. Scan approfondi d'un appareil : versions des services par nmap
  s'il est installé. Les nouvelles règles ont un identifiant stable (« vanguard regles »).
- **Plus sûr.** Le bac à sable n'atteint plus le bus du système ni Docker ; sous Windows, le script de correction est
  vérifié juste avant de tourner en administrateur (un script modifié entre-temps ne part pas) ; les données de
  Vanguard sont réservées à ton compte. La sauvegarde automatique reconnaît son disque à son identifiant (UUID),
  plus à son nom : un autre disque au même nom ne reçoit plus tes fichiers. Tout texte venu d'ailleurs (nom
  d'appareil, de fichier, d'imprimante) passe par une seule protection avant d'entrer dans une commande, et un test
  le vérifie dans tout le code.
- **Vanguard se met à jour depuis la clé.** La copie posée sur un ordinateur (surveillance, entretien, raccourci) ne
  suivait pas la clé : lancé depuis une clé plus récente, Vanguard le dit au menu, et la mise à jour se fait sur
  accord (9.9 ou `vanguard se-mettre-a-jour`), relue et comparée avant de remplacer l'ancienne ; jamais vers une
  version plus ancienne, et jamais depuis une clé seulement branchée.
- **Une seule publication par jour.** Ce journal regroupe les versions par jour ; seule la dernière garde sa page de
  téléchargement, et le Mac de GitHub ne compile plus qu'une fois par publication.

## 19 octobre 2026 : versions 0.62 à 0.77

- **Bilan bien plus complet sous Windows.** Authentification réseau LM ou NTLMv1, empreintes LM, signature et accès
  invité des partages, comptes listés anonymement, client SMBv1, Registre à distance, UAC qui ne demande plus rien,
  stratégie de PowerShell, macros d'Office toutes permises, exclusions de Defender trop larges, Secure Boot,
  WDigest, protection de LSA, PowerShell 2, SmartScreen, intégrité de la mémoire, mises à jour en pause, et le
  verrouillage de l'écran.
- **Linux et macOS.** Mises à jour de sécurité automatiques, réglages du noyau (tubes et fichiers dans /tmp,
  compteurs du processeur), client SSH qui ne vérifie pas les serveurs, serveur SSH qui accepte les comptes sans
  mot de passe, sudo qui ne redemande jamais le mot de passe, cups-browsed ouvert au réseau, affichage X11 ouvert à
  tous, réseaux Wi-Fi ouverts qui se reconnectent tout seuls.
- **Partout.** Nouveaux administrateurs et navigation détournée (proxy imposé, fichier hosts) signalés ; heure
  de l'ordinateur, fin de support du système, comptes oubliés, mots de passe gardés par le navigateur, fichiers
  sensibles qui traînent.
- **Nouveaux outils.** Sauvegarde automatique, compte piraté, rapport à laisser sur place, raccourci sur le Bureau,
  et « Ce que Vanguard a changé » : chaque correction est notée et datée, et le rapport HTML la résume.
- **Prudence.** Les partitions de la clé ne sont plus proposées comme disque ; Vérifier ma clé et Time Machine plus
  prudents ; noms de disque piégés refusés dans les sauvegardes automatiques.

## 18 octobre 2026 : versions 0.52 à 0.61

- **Dépannage pas à pas** (réseau, sécurité, entretien, après une infection, nouvel ordinateur ou départ), guide
  des commandes et apprentissage.
- **Nouvelles défenses.** Faux technicien et prise de contrôle à distance, partages ouverts à tous, blocages de
  Windows Defender, fichiers-pièges contre les rançongiciels, Bluetooth, Téléchargements surveillés, quarantaine
  réversible, caméra et micro.
- **Vanguard se vérifie lui-même** : manifeste de la clé, failles des dépendances chaque nuit, vérifier une copie,
  vérifier ma clé, données de la clé chiffrées, « Mes ordinateurs ».
- **Confort.** Programmes au démarrage, menus qui défilent, recherche dans les listes à cocher, copie d'une commande
  du guide, émojis bien alignés, noms piégés rendus inoffensifs à l'écran.
- **Code allégé et rangé comme le menu**, au même comportement ; moins de fausses alertes.

## 17 octobre 2026 : versions 0.9.5 à 0.51

- **Vanguard prend son nom**, avec son logo bouclier et une présentation refaite.
- **Bilan élargi.** DNS et certificats racine, extensions et réglages de sécurité des navigateurs, santé de
  l'ordinateur, mots de passe et adresses courriel fuités, persistance cachée, failles connues des paquets, journaux
  effacés, intégrité des fichiers critiques, usurpation ARP de la box, ports ouverts vers Internet par UPnP.
- **Outils.** Mises à jour de tout le système, pilotes compris ; Réparer et nettoyage approfondi ; Optimiser, avec
  des réglages qui s'annulent exactement ; jeu sous Windows et sous Linux ; diagnostic de l'ordinateur ; logiciels
  essentiels ; bac à sable pour programmes inconnus ; test de connexion pour le jeu.
- **Suivi.** Changements depuis le dernier bilan et courbe des notes, surveillance de cette machine, rapport texte
  d'urgence, point de restauration automatique avant chaque correction.
- **Clé USB** protégée en écriture, journal des erreurs, antivirus d'une clé ; français et anglais partout ; menus au
  clavier (flèches, Entrée, Échap) ; audit en parallèle, trois fois plus rapide ; macOS au niveau de Linux et Windows.

## 16 octobre 2026 : versions 0.2 à 0.9.4

- **Premières versions.** Scan du réseau local et base des appareils, audit de Linux (Docker, pare-feu, UDP, clés
  SSH, verrouillage, noyau durci, AppArmor ou SELinux, sauvegardes, sudo) et de Windows.
- **Menu Réparer** pour Linux, Windows et macOS.
- **Fiabilité.** Plus aucune commande en échec prise pour « tout va bien », délais sur les commandes, base des
  appareils sûre ; le Bureau à distance en cours n'est jamais coupé.
