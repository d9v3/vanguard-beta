# Modèle de menace

*[English](MODELE-DE-MENACE.en.md)*

Ce que Vanguard protège, contre qui, et ce qu'il ne protège pas. Cette page fixe le cadre des fonctions : chacune
devrait pouvoir dire quelle menace d'ici elle couvre. Les failles de Vanguard lui-même (un défaut du programme, de la
clé USB ou de la mise à jour) relèvent d'une autre page : [SECURITY.md](SECURITY.md).

## Ce que Vanguard protège

- **L'ordinateur sur lequel il tourne** : ses réglages de sécurité, ses mises à jour, ce qui s'y lance au démarrage,
  ce qui y tourne et ce qui parle à Internet. Linux, puis Windows.
- **Le réseau local vu depuis cet ordinateur** : le routeur, les appareils connectés, ce qui est ouvert vers
  Internet, le Wi-Fi.
- **Les données de la personne** : ses fichiers (pièges contre les rançongiciels, vérification de la sauvegarde), ses
  secrets (fuites de mots de passe et d'adresses courriel, clés SSH sans phrase de passe, clés privées et jetons
  laissés dans des fichiers), sa vie privée (logiciels espions).
- **Sa clé USB** : protégée en écriture ailleurs que sur l'ordinateur de son propriétaire, contre les vers de clé ;
  son carnet peut être chiffré par une phrase, contre une clé perdue ou prêtée.

## Contre qui : les menaces couvertes

| Menace | Ce que fait Vanguard |
|---|---|
| Un logiciel malveillant connu sur l'ordinateur | Moteur de Vanguard (empreintes de MalwareBazaar et de ClamAV, règles YARA, signatures de ClamAV, heuristiques) avec l'antivirus du système, mémoire des programmes, lancements au démarrage, signes d'un rootkit ; blocage après accord, ou de lui-même pour ce qui ne fait aucun doute (protection active). |
| Un rançongiciel | Fichiers-pièges vérifiés chaque heure ; sous Linux, une fois allumé, un veilleur en direct qui arrête un cas quasi certain avec la protection active. |
| Une faiblesse de réglage ou une faille non corrigée | Bilan noté de A à F, mises à jour manquantes, failles activement exploitées du catalogue de la CISA, fin de support ; pour l'instant chaque correction après accord (la direction : [Mode autonome](#mode-autonome)), annulable sauf celle qui rallume une protection (pare-feu, antivirus, chiffrement, UAC, SELinux, durcissement du noyau sous Linux, durcissement de Windows et protections de Defender). Baisser une protection reste le choix de la personne, jamais celui de Vanguard (voir [Baisses par choix](#baisses-par-choix)). |
| Une exposition vers Internet | Ports que le routeur ouvre (demandés au routeur lui-même, ouvertures UPnP comprises), IPv6 publique sans pare-feu ; dans les journaux, les mots de passe devinés et les connexions au Bureau à distance depuis l'extérieur. |
| Un intrus sur le réseau local ou le Wi-Fi | Inventaire des appareils et des nouveaux venus, faux point d'accès, DNS et certificats détournés ; mode Wi-Fi public en déplacement. |
| Un proche qui surveille la personne | Logiciels espions, prise de contrôle à distance (faux technicien). |
| Une arnaque | Liens examinés sans les ouvrir, fichiers téléchargés vérifiés, fuites de comptes. |
| Un agent d'IA qui agit trop | Serveurs d'IA ouverts au réseau, agents qui agissent sans demander, serveurs MCP mal protégés. La porte que Vanguard ouvre lui-même aux assistants est en lecture seule (voir [La porte de lecture pour les assistants d'IA](#la-porte-de-lecture-pour-les-assistants-dia)). |

Le détail de chaque menace, menu par menu : [Fonctions de sécurité, menace par menace](README.md#fonctions-de-sécurité-menace-par-menace).

## Ce que Vanguard ne protège pas

- **Un attaquant qui a déjà les droits d'administrateur.** Il peut arrêter Vanguard, effacer ses traces ou fausser ce
  que le système lui répond. Vanguard ne se protège pas contre la désactivation : il signale seulement que sa
  surveillance a été coupée. Lancé lui-même en administrateur, Vanguard ne bloque rien de lui-même, parce que ses
  réglages de blocage peuvent être écrits par n'importe quel programme du compte.
- **Le noyau et le micrologiciel.** Vanguard ne charge rien dans le noyau. Il relève les signes d'un rootkit
  (processus cachés, modules du noyau qui se cachent ou non signés), mais un rootkit bien fait peut mentir au
  système qui l'interroge. Secure Boot est vérifié et le micrologiciel (BIOS, UEFI) mis à jour après accord, mais rien
  ne le surveille en direct.
- **Une menace nouvelle, encore sans signature.** Les détections reposent surtout sur des listes connues ; ce qui n'y
  est pas encore peut passer. Vanguard complète l'antivirus du système (Microsoft Defender, ClamAV) : il ne le
  remplace pas.
- **Ce que le moteur de Vanguard ne voit pas.** Son verdict (certain, famille, suspect, sain, non vérifié) vient des
  empreintes (MalwareBazaar, ClamAV), des règles YARA, des signatures de ClamAV et de huit heuristiques, sur ce qui est
  écrit sur le disque. Il n'a ni analyse dans le nuage, ni lecture de la mémoire, ni AMSI : un script ou une macro qui
  ne se déchiffre qu'à l'exécution lui échappe. Sous Windows, il ne refuse aucun lancement : seul Defender le fait. «
  Sain » veut dire « rien de connu dans ce qui a été lu ». Une source attendue absente ou une partie non lue donne «
  non vérifié » ; une source facultative absente (base de ClamAV, empreintes de MalwareBazaar) est dite avec le
  verdict, et le résultat versé au rapport la compte comme non vérifiée. Les heuristiques se contournent (programme
  signé avec un certificat volé, entropie diluée, nom ordinaire) et peuvent se tromper. Pour elles, « signé » veut dire
  « une signature Authenticode est présente », jamais vérifiée (ni chaîne, ni correspondance avec le fichier) : une
  signature copiée d'un autre programme, ou auto-signée, suffit à faire taire « programme sans signature ». Elles ne
  rendent donc qu'un « suspect », qui ne déclenche aucun geste tout seul : un clic, et une clé `normales` liée au
  contenu exact pour faire taire un faux positif. Une règle de famille (YARA, signature de ClamAV) part aussi d'un
  clic. Seule une empreinte connue (ou l'essai EICAR) peut mener à la quarantaine sans clic, si la protection active le
  permet, et la quarantaine reste annulable. Sous Windows, Defender allumé, le moteur n'est qu'un second avis. Defender
  coupé par la personne (Options de défense), il devient le principal et l'analyse dit ce qui manque. Defender coupé
  sans choix noté, ou illisible : rien n'est conclu.
- **Tout, en temps réel.** Hors des deux veilleurs de Linux (programmes, connexions et fichiers arrivés ;
  anti-rançongiciel ; coupés par défaut), de la surveillance en direct de l'intégrité des fichiers critiques et du
  blocage de Defender, la surveillance passe chaque heure, entre deux bilans.
- **Chaque lancement, sans exception de temps (garde des lancements, Linux).** Le garde (`vanguard garde on`, coupé
  par défaut) ne bloque jamais l'ordinateur : quand il ne peut pas répondre, il laisse passer. Deux fenêtres en
  découlent. Pendant une relance du garde (environ une seconde), les lancements sont permis sans être vus. Un garde
  figé fait attendre chaque lancement jusqu'à son chien de garde (environ cinq secondes), puis systemd le tue et tout
  ce qui attendait passe. Un lancement sans verdict en 250 ms passe aussi, noté. Un fil de tri figé (un disque qui ne
  répond plus) est remplacé après environ cinq secondes (quatre fils au plus en tout) et dit au bilan ; d'ici là, les
  lancements passent au bout de 250 ms. Le veilleur des programmes reste la deuxième ligne. Le garde ne refuse que le
  certain (une empreinte des listes, ou la marque d'essai), jamais un programme du système, de Vanguard ou lancé par
  init.
- **Ce que le garde des lancements ne voit pas (Linux).** Il juge le fichier qu'un `execve` ouvre (le programme, ou le
  script lancé directement et son interprète), sur un système de fichiers local qu'il a marqué. Il ne juge pas un
  script passé à son interprète (`bash script.sh`, `python3 script.py`), un programme passé à l'éditeur de liens
  (`ld.so ./programme`), ni une bibliothèque chargée par dlopen ou LD_PRELOAD : ce sont de simples ouvertures. Il ne
  voit aucun lancement depuis FUSE (dont les AppImage), overlay, squashfs (les snaps), un partage réseau (NFS, SMB,
  9p), ni depuis un système de fichiers neuf monté dans un espace de noms privé (`unshare`, sans root sur la plupart
  des distributions). Il ne marque que ext2/3/4, btrfs, xfs, f2fs, tmpfs, vfat, exfat, msdos, ntfs3, bcachefs et jfs :
  tout autre type n'est pas vu (ZFS compris, ainsi qu'erofs, udf et iso9660). Une marque vaut pour tout un système de
  fichiers (son superbloc) : un montage lié du même disque, même dans un espace de noms privé, reste couvert. Un
  système de fichiers monté après le démarrage du garde (une clé USB) est marqué en une seconde environ ; un lancement
  dans cette seconde n'est pas vu. Un programme de plus de 64 Mio passe à son premier lancement et n'est jugé qu'après
  coup ; sur FAT et exFAT (clés USB), où rien n'est gardé en cache faute d'horodatage fiable, il n'est jamais arrêté à
  temps. L'antivirus et le veilleur des programmes restent la ligne pour ces voies.
- **Ce que le temps réel des fichiers ne voit pas (Linux).** Le veilleur marque, sans droits, Téléchargements, le
  Bureau, ~/.local/bin et ~/.config/autostart (marques fanotify d'inode, les seules permises à un compte ordinaire).
  Il voit un fichier fermé après écriture ou arrivé par renommage, enfant DIRECT de l'un d'eux. Il ne voit pas : un
  sous-dossier (une archive décompressée dans `Téléchargements/dossier/`), un autre dossier (Documents, /tmp, une clé
  USB), un fichier écrit avant le démarrage du veilleur ou pendant qu'il est coupé ou en pause, ni un programme lancé
  sans être écrit dans ces dossiers (le veilleur des programmes et le garde le jugent à son lancement). Le temps réel
  tient en 128 Mio de mémoire : il prend les règles YARA, les heuristiques et les empreintes de MalwareBazaar des
  dernières 48 heures ; la base ClamAV et la liste complète des empreintes servent aux analyses à la demande et à la
  passe horaire. Un fichier de plus de 32 Mio, illisible ou parti avant d'être lu n'est pas examiné : il est compté
  non vérifié, jamais sain. Un fichier arrivé quand la file est pleine (256 en attente), ou perdu par un débordement de
  la file du noyau, est compté puis repris par une relecture du dossier (par son nom, ou par la liste des fichiers
  changés depuis la perte, les plus récents et les plus anciens d'abord) ; tant qu'elle n'a pas fini, le bilan dit
  « au moins N perte(s) » en alerte. Limites dites : au-delà de 4096 noms perdus, ceux du milieu sont oubliés et tout
  le dossier est relu ; un dossier de plus de 50 000 entrées ne peut pas être relu : la perte y est abandonnée après
  trois essais, gardée en alerte au bilan et retentée toutes les 2 minutes (l'analyse `vanguard antivirus` le reprend
  en entier). Un fichier en cours de téléchargement (« .part »,
  « .crdownload ») n'est examiné qu'à son renommage final : il est compté non vérifié (la passe horaire, elle,
  l'examine). Un lien n'est jamais suivi. Il ne voit pas non plus un contenu qui change sans fermeture après écriture
  ni renommage : un lien dur créé dans ces dossiers (`link()`, événement que le veilleur ne demande pas au noyau), une
  écriture par `mmap(MAP_SHARED)` après la fermeture, un `truncate()` par chemin ; la passe horaire reprend les deux
  derniers (modifiés dans la semaine), un lien dur vers un fichier plus ancien n'est repris que par l'analyse
  « Rapide ». Un fichier à plusieurs noms (liens durs) n'est jamais mis en quarantaine : ses permissions à zéro
  toucheraient aussi les autres noms ; et la quarantaine n'isole que l'inode examiné. Ce qui n'a pas pu être vérifié
  est dit au journal chaque heure. Un dossier surveillé remplacé sous son nom (déplacé puis recréé) est vu en une
  demi-seconde, compté, dit et marqué de nouveau ; ce qui y arrive entre-temps n'est pas vu. Supprimé, il est dit
  « plus surveillé » jusqu'à son retour. La passe horaire reprend les fichiers de la semaine posés dans ces dossiers
  (64 Mio au plus, 300 fichiers, une minute en tout) ; l'analyse « Rapide » les reprend tous. Un programme malveillant
  du compte peut éteindre le veilleur, comme les autres.
- **La page visitée.** Vanguard n'a pas d'extension de navigateur : la page ouverte n'est pas examinée. Il examine un
  lien qu'on lui donne, bloque après accord des sites dangereux connus par le fichier hosts
  (`vanguard sites-dangereux`), et le mode Wi-Fi public passe à un DNS qui filtre.
- **Les autres appareils du réseau.** Il les observe, il ne les corrige pas et ne les attaque jamais : le routeur est
  lu, jamais modifié ; le seul mot de passe essayé est la communauté SNMP « public », et l'essai est annoncé.
- **Les comptes en ligne.** Les fuites connues sont signalées ; le compte lui-même relève du service qui l'héberge.
- **Les réglages SSH propres à certains serveurs.** Vanguard lit la configuration du client SSH (`~/.ssh/config` et
  ses `Include` ; `/etc/ssh/ssh_config` seulement pour l'échange post-quantique : le prêt de l'agent ou la
  vérification coupée écrits dans ce fichier du système ne sont pas signalés) avec les règles d'OpenSSH 10.6 (la
  forme `Match host=…` comprise, qu'un client plus ancien refuse ; un motif de liste de 1023 octets ou plus, que SSH
  ne compare jamais, rend la portée douteuse ; une liste `KexAlgorithms` de plus de 4096 octets est dite non lue),
  mais il ne juge que ce qui peut valoir pour tous les serveurs : un réglage sous un `Host` ou un `Match` qui nomme un serveur n'est pas signalé. Il ne voit pas non plus
  que plusieurs `Host` précis, mis ensemble, couvrent tous les noms (un par première lettre, par exemple). Un en-tête
  que SSH applique peut-être à tous (`Match user`, `Match exec`, `Host *.*`…) est traité comme global : il donne
  l'alerte, et Vanguard n'annonce jamais sur sa foi un échange post-quantique « proposé » ni des réglages
  « corrects ». Les alertes sont bornées : une par réglage et par fichier, seize au plus, le reste compté.
- **Une entrée du démarrage changée pendant le geste (Linux).** `demarrage --retirer` refuse une entrée d'autostart
  changée entre sa lecture et son écriture, dans le même lancement. L'empreinte, elle, ne désigne que le chemin : une
  entrée changée après la liste montrée (`demarrage --json`, la fenêtre) et avant le geste est retirée telle qu'elle
  est alors, et la note garde ce contenu-là, remis à l'octet près. Restent des fenêtres de l'ordre de la microseconde,
  qu'il faut déjà les droits du compte pour viser : un contenu échangé juste après la relecture est perdu (l'ancien
  est écrit masqué, la note dit ce qui a été montré) ; un dossier autostart déplacé hors du dossier personnel après
  son ouverture reçoit l'écriture là où il est (le lien posé à sa place n'est pas suivi). Une entrée rangée derrière
  un lien (dotfiles), une entrée qui est elle-même un lien ou un tube, un `XDG_CONFIG_HOME` ou un `HOME` relatifs ou
  avec `..` ne sont ni lus ni proposés, et la liste le dit (« non vérifié », dans `demarrage --json` comme dans la
  liste à cocher du terminal), jamais « aucun programme ». Une entrée d'autostart qui ne se lit pas bornée (64 Kio ou
  plus, pas en UTF-8) n'est ni retirée ni remise par-dessus (une note d'un ancien retrait ne l'écrase pas), et la
  liste le dit ; une entrée qui, une fois masquée, dépasserait 64 Kio est dite « à garder » et refusée avant toute
  écriture. Limite connue, pour la 0.95 : le fichier d'unité systemd du compte est encore lu sans borne pour en tirer
  sa commande.
- **La perte des données.** Un programme malveillant du compte peut éteindre le veilleur anti-rançongiciel : la
  sauvegarde reste la vraie protection.
- **Un ordinateur volé allumé et déverrouillé.** Le chiffrement du disque (BitLocker, FileVault, LUKS) protège un
  ordinateur éteint ; Vanguard le vérifie et le recommande.
- **Le détournement du flux d'exécution de Vanguard lui-même.** Ses programmes publiés portent l'ASLR, une mémoire
  de données non exécutable et, sous Linux, la marque du RELRO complet, vérifiés avant chaque publication
  (`vanguard deploiement verifier-binaire`) ; le démarrage de musl n'appliquant pas cette marque, Vanguard met
  lui-même le segment PT_GNU_RELRO en lecture seule au lancement (`src/socle/relro.rs`). Le contrôle du flux (CFG sous Windows, CET partout) n'y est pas : MinGW
  et Rust stable ne le posent pas de façon fiable. Il est affiché sans être exigé, à revoir si la compilation de
  Windows passe un jour à llvm-mingw ou MSVC.
- **Ce que lit un ordinateur emprunté.** La protection en écriture empêche qu'on modifie la clé, pas qu'on la lise :
  le carnet n'est à l'abri que chiffré.
- **L'origine de la liste montrée dans la fenêtre administrateur (Windows).** Le processus élevé vérifie que son
  parent est le processus annoncé et que le fichier de son programme a les mêmes octets que le sien : cela prouve quel
  fichier a lancé le parent, pas quel code y tourne. Un programme du même compte peut piloter un Vanguard non élevé de
  ce compte, ou lancer lui-même le vrai vanguard.exe et tenir le tube à sa place ; la liste reçue ne vient alors pas
  de ce que vous avez demandé. Ce qui reste : la liste fermée des gestes, les ordres rejugés par le processus élevé, le
  script montré en entier après la vérification de son empreinte, et votre Entrée. Comparez ce qui est montré à ce
  que vous venez de demander. Un tel programme pouvait déjà demander lui-même l'élévation de PowerShell ; il faudrait
  une signature du programme pour aller plus loin (décision de l'auteur).
- **La copie de Vanguard posée sur cet ordinateur.** Vanguard note dans un registre scellé l'empreinte et la version
  de chaque copie qu'il pose dans votre dossier. Il ne remplace jamais une copie plus récente par un programme plus
  ancien, ni une copie plus récente qu'il ne reconnaît pas (ni notée, ni publiée et signée pour ce système, selon
  l'historique signé des versions) : c'est dit « non vérifié » et rien n'est posé. Une liste des copies effacée, vidée,
  abîmée ou changée hors de Vanguard n'est jamais lue comme « rien de noté » : une clé refuse alors de poser sa copie,
  ne refait pas la liste, et dit la sortie (remettre la clé à la dernière version publiée, puis relancer depuis la clé
  avec Internet : Vanguard vérifie que son numéro n'est pas plus ancien que la dernière version signée et que ses
  octets sont dans l'historique signé des versions pour ce système, puis refait la liste ; une pose ailleurs ne lève
  jamais ce doute) ; la mise à jour depuis GitHub remplace alors la copie par la dernière version signée seulement, et
  le dit ; une copie déjà à ce numéro, ou absente, n'est pas remplacée et le doute reste dit. Si les versions déjà vues
  ont aussi été changées hors de Vanguard, la dernière version signée est inconnue jusqu'à ce que vous lanciez
  « vanguard se-mettre-a-jour » avec Internet et acceptiez de repartir de la version signée reçue (les versions vues ne
  sont oubliées qu'une fois ce manifeste signé reçu, jamais hors ligne) ; d'ici là, tout reste
  « non vérifié », jamais compté sain. Ce qui reste : les sceaux de ce registre sont sans secret, une barrière et pas un
  coffre ; un programme de votre compte qui réécrit le registre avec
  ses sceaux peut y faire noter une autre copie, ou effacer la note, et un état entièrement effacé (registre et sceaux)
  ressemble à un ordinateur neuf : une clé plus ancienne y repose sa copie sans rien en savoir. Cette protection ne
  vient qu'avec les versions qui la contiennent : une clé publiée avant elle ne lit pas la liste des copies. Quand
  l'historique signé ne répond pas (hors ligne, GitHub injoignable ou filtré, historique absent ou mal signé, ou pas de
  version publiée pour ce système), une copie plus récente posée par une version d'avant ce registre ne peut pas être
  jugée et est refusée. La sortie d'une liste en doute ne demande pas un manifeste récent : un ancien manifeste signé,
  remis en place, peut faire passer une clé ancienne pour la dernière. La surveillance, l'entretien, le veilleur
  (Linux) et « se-mettre-a-jour » rendent un code de sortie non nul après un refus, même quand l'entrée se termine sur
  une question qui le suit (un « n » de votre part n'en est pas ; GitHub injoignable non plus, sauf quand la liste des
  copies est en doute : le doute est alors dit, avec un code non nul) ; des versions déjà vues changées hors de Vanguard
  rendent un code non nul, même après « repartir », quand il y a ici un programme de Vanguard à mettre à jour (une
  copie posée, ou le programme lancé hors de la clé et remplaçable) ; sans rien à mettre à jour, elles ne sont ni dites
  ni comptées (code nul), sauf quand la liste des copies est aussi en doute ; en root avec le dossier d'un autre
  compte, rien n'est promis ; le raccourci rend encore un code nul. Les copies temporaires de Vanguard sont reconnues
  dans le dossier du compte (`XDG_RUNTIME_DIR` ou `TMPDIR`) : un programme du compte peut y poser une copie exacte de
  Vanguard et la faire prendre pour la clé du lancement ; aucun gain trouvé pour lui, qui a déjà les droits du compte.

## Ce que Vanguard suppose

- **Le programme est le vrai.** Vérifiez son empreinte SHA-256 au téléchargement (`SHA256SUMS.txt`) ; chaque mise à
  jour est signée en Ed25519 et refusée si elle est mal signée, plus ancienne, ou si sa taille ou son empreinte ne
  correspond pas. Le programme n'a pas encore de certificat de signature de code.
- **Personne d'autre ne pilote Claude sur le dépôt du code.** Claude sur GitHub (.github/workflows/claude.yml) peut
  écrire dans le dépôt et lance cargo build et cargo test, pour vérifier ce qu'il corrige. Il ne se lance que pour le
  propriétaire, sur un fil (ticket ou demande de fusion du dépôt lui-même, jamais d'un fork) dont chaque commentaire,
  revue et commentaire de revue est du propriétaire ou des robots de Claude et de GitHub Actions. Juste avant Claude,
  le fil est verrouillé, puis relu de la même façon, et il le reste jusqu'à la fin du travail ; un second `@claude`
  sur le même fil attend la fin du premier. Restent : ceux qui ont un accès en écriture au dépôt, qui peuvent écrire
  même sur un fil verrouillé ; ce qu'il lit ailleurs que dans le fil (un ticket lié, une page, un texte d'un autre
  recopié par le propriétaire) ; et le code du dépôt lui-même, que cargo build et cargo test exécutent.
- **Le système répond juste au moment du bilan.** Un poste déjà compromis en administrateur peut tromper toutes ses
  lectures (voir plus haut).
- **Les listes et les outils tiers sont justes.** Les listes de menaces, de versions et de failles (abuse.ch, CISA,
  éditeurs) et les outils que Vanguard lance sans les avoir écrits (ClamAV, trivy, gitleaks) sont crus tels quels ;
  une liste trop vieille est dite non vérifiée.
- **Les variables du compte que gardent les lectures.** Un outil du système lancé pour lire tourne sous votre compte,
  avec un environnement vidé sauf une courte liste (la langue, le terminal, le bureau, HOME, TMPDIR, TZ, les dossiers
  XDG, le proxy). Ce qu'un programme de votre compte peut encore y changer : le proxy (http_proxy…) peut faire échouer
  ou détourner une lecture par le réseau : par https, elle est alors dite non vérifiée, pas saine (relu au recontrôle
  de la 0.95) ; par un miroir en http, ce n'est pas vérifié ; XDG_DATA_DIRS change les valeurs par défaut que
  gsettings lit ; XDG_DATA_HOME est gardé mais FLATPAK_USER_DIR retiré, si bien que des applications Flatpak du compte
  installées ailleurs par cette variable ne sont pas vues ; DBUS_SESSION_BUS_ADDRESS et XDG_RUNTIME_DIR désignent le
  bus de session, qu'un faux bus servi par un programme du compte peut remplacer pour ce qui se lit par lui
  (gsettings, systemctl --user). Ces lectures portent sur l'état du compte lui-même, qu'un tel programme peut de toute
  façon changer (voir le point suivant).
- **Les programmes de votre compte ne visent pas Vanguard lui-même.** Vanguard garde son état (ce qu'il a déjà vu, ce
  que vous avez réglé, les défenses que vous avez allumées) dans un dossier de votre compte. Un programme malveillant
  qui tourne sous votre compte peut donc fausser cet état. Vanguard voit et dit la falsification simple (un fichier
  changé, effacé ou daté dans le futur) et ne s'y fie plus : aucune défense ne se coupe, aucune alerte ne se tait.
  Deux limites : le dossier de Vanguard effacé en entier le ramène à son premier usage, où il réapprend sans rien
  dire ; et un programme qui vise exprès ce mécanisme (il réécrit aussi les sceaux de Vanguard, ou les efface avec
  leurs témoins) n'est pas vu. Un programme qui garde le verrou des sceaux (sceaux.verrou) empêche Vanguard d'écrire
  son état et son journal des événements tant qu'il le garde : Vanguard ne l'attend qu'une fois, puis une seconde en
  tout, le dit au bilan, et compte les événements qu'il n'a pas pu noter pour les dire une fois le verrou rendu. Ceux
  d'un Vanguard tué pendant ce temps se perdent sans être comptés, et ce compte, écrit sans sceau, peut être effacé.
  Chaque fichier se scelle en deux temps : Vanguard note d'abord le contenu qu'il va poser (« en attente »), puis
  l'écrit et le scelle. Tué entre les deux, il accepte ensuite l'ancien contenu comme le nouveau, jusqu'à ce qu'une
  commande qui peut écrire relise ce fichier ; tué pendant un retrait, le contenu retiré, remis par un autre programme,
  se lit intact. Les deux contenus sont de Vanguard, et forger une attente demande de réécrire ses sceaux (voir plus
  haut). Une version plus ancienne de Vanguard, remise après une mise à jour, ne connaît pas ces attentes : elle dit
  falsifié un fichier laissé entre les deux temps (sens sûr).
  Les mises à jour sous Arch (checkupdates) se lisent avec une base à part, dans un dossier au nom tiré au hasard,
  fermé aux autres comptes, sous le dossier temporaire : un programme du compte qui guette sa création peut y poser
  sa propre liste des paquets installés avant checkupdates, et la lecture peut alors dire « à jour ». Ce n'est pas vu.
  La vraie parade, un service qui tourne sous un autre compte que le vôtre (administrateur), est prévue pour une
  version à venir.
- **Vanguard agit, la personne garde la main.** Ce qui protège, entretient ou améliore est fait pour elle, noté et
  annulable ; une baisse de protection reste son choix (voir [Mode autonome](#mode-autonome)). Aujourd'hui, rien
  n'est encore modifié sans son accord. Ce qu'elle accepte s'annule une correction à la fois,
  sauf ce qui rallume une protection (dont le durcissement du noyau sous Linux) et l'arrêt d'un programme ; une
  correction dont l'état d'avant ne se relève pas est dite « non annulable » avant d'être appliquée. Les réglages de
  durcissement de Windows (WDigest, NLA…) et les protections de Defender sont, eux aussi, des protections : l'annulation
  ne les défait pas, et une note forgée ne peut plus les faire baisser. Une note d'annulation acceptée sans sceau
  d'avant (hors d'une mise à jour depuis une version qui scelle déjà, 0.86 ou plus) n'est pas remise : c'est une
  barrière contre un fichier posé par un autre programme, pas une porte fermée, puisqu'un programme qui réécrit aussi
  les sceaux de Vanguard n'est pas vu (voir plus haut). C'est pourquoi les protections ne se défont plus du tout par
  l'annulation. La personne peut toujours les baisser elle-même, dans Windows ou dans les Options de défense, par le
  chemin décrit plus bas.
- **Les essais ont leurs limites.** Vanguard est essayé sur l'ordinateur de l'auteur, une VM Windows, un second PC
  Windows et les machines de GitHub (Windows, vraies distributions Linux) ; d'autres cas restent à essayer sur du vrai
  matériel (autres distributions, vrai routeur UPnP, démarrage de la clé).

## Mode autonome

**Prévu, pas encore fait.** Aujourd'hui, chaque correction attend l'accord de la personne ; seule la protection
active, une fois mise en marche, bloque seule ce qui ne fait aucun doute. La direction du produit : ce qui protège,
entretient ou améliore se fera seul, sans être montré avant, mais avec l'état d'avant noté (ou un point de
restauration), journalisé, annulable exactement, et un compte rendu après. Chaque fonction ne le deviendra qu'avec son
propre code et ses freins ; ce que ce document dit d'elle (« après accord ») reste vrai jusque-là.

**Reste toujours demandé** : toute baisse de protection (par les Options de défense, voir [Baisses par
choix](#baisses-par-choix)), tout geste qui coupe une connexion, supprime ou déplace des données de la personne,
désactive quelque chose ou ne s'annule pas exactement. L'Agent ne recevra pas les corrections automatiques.

**Freins prévus** :

- une liste fermée de gestes permis, chacun rejugé sur l'état relu juste avant d'agir ;
- un plafond par passe et par jour, et un disjoncteur qui arrête tout au-delà ;
- un constat qui revient après sa correction devient une alerte, pas une nouvelle correction ;
- jamais par-dessus un choix de la personne, qui reste scellé ;
- un interrupteur du mode autonome, scellé ; l'éteindre est une baisse par choix ;
- la ligne « Ce que Vanguard a changé » posée avant le geste, pas après ;
- rien d'automatique sur le pare-feu entrant, les ports, le réseau ni la prise en main à distance.

## La fenêtre

**La fenêtre revient en 0.96, vérifiée.** En 0.94, `vanguard` lançait tout exécutable nommé `vanguard-fenetre` posé
à côté de lui, sur la foi de son nom et de son emplacement, pas de son contenu : un faux aurait pu dire « ouverte » à
sa place ; la 0.95 ne la lançait plus du tout. Depuis la 0.96, `vanguard` ne lance que la fenêtre compilée avec lui :
`outils/compiler-version.sh` compile la fenêtre d'abord et grave son empreinte SHA-256 dans `vanguard`, que l'auteur
signe (manifeste et historique des versions) ; l'empreinte de la fenêtre est donc signée avec lui, sans clé ni
signature de plus. Sous Linux, ses octets sont lus par une poignée ouverte sans suivre de lien, copiés dans un
fichier en mémoire scellé (memfd : plus rien ne peut le changer), l'empreinte est calculée sur cette copie, et c'est
elle qui est lancée, pas le chemin : une fenêtre remplacée sur le disque après la vérification ne tourne pas. Sous
Windows, le fichier est tenu ouvert en lecture seule partagée (personne ne peut l'écrire, l'effacer ni le renommer
tant que la poignée vit), et ses dossiers tenus aussi, du calcul de l'empreinte jusqu'à « ouverte » ; Windows lance
pourtant par le chemin : voir les limites de « La fenêtre ». Une empreinte différente, un programme compilé
sans empreinte (`cargo build`, les essais) ou une marque illisible : aucune fenêtre, le menu, la raison dite.

`vanguard` sans argument ouvre la fenêtre de Vanguard (`vanguard-fenetre`, un programme à part posé à côté de
`vanguard`) quand la personne est devant un écran graphique ; sinon, le menu du terminal, comme avant. Ses
gardes :

- **Elle ne fait rien d'elle-même : des lectures, et quatre gestes acceptés un à un.** Ce qui change l'ordinateur
  passe seulement par quatre gestes, chacun montré dans la fenêtre puis accepté, et rejugé par `vanguard` : retirer ou
  remettre un programme du démarrage, appliquer une correction du compte, la remettre comme avant, installer la mise à
  jour de Vanguard (chacun décrit plus bas). Tout le reste est lecture : elle relance le programme `vanguard` posé à
  côté d'elle (chemin absolu, jamais cherché dans le PATH ; lancée d'un fichier en mémoire, elle reçoit ce chemin de
  `vanguard` par `--vanguard` avec son empreinte, et lui applique les mêmes gardes) avec une commande d'une liste
  fermée, qui ne change rien à l'ordinateur (`audit`, `protection`, `evenements`, `diagnostic`, `test-connexion`…),
  toujours en `--json`,
  sans argument libre, sans shell, entrée fermée, une à la fois, avec un délai et un bouton Arrêter (sous Linux, tout
  le groupe de processus est arrêté, et ce qui en reste à la fin de la commande aussi ; `vanguard` n'est récolté
  qu'après, pour que ce numéro de groupe ne puisse pas être celui d'un autre ; un processus sorti du groupe qui
  garderait les sorties ouvertes n'y retient pas la fenêtre, qui lâche les tuyaux). La console de la fenêtre n'accepte
  que les noms de cette liste. Sous Linux, ce `vanguard` doit être un fichier ordinaire au compte de la fenêtre ou à
  root, que ni le groupe ni les autres ne peuvent modifier, dans des dossiers (jusqu'à `/`) que ni le groupe ni les
  autres ne peuvent modifier non plus (sauf un dossier à « sticky bit », comme `/tmp`), sinon il n'est pas lancé : la
  même règle que pour la fenêtre, plus bas, revérifiée avant chaque commande, et pas seulement à l'ouverture.
- **Premier geste, en deux temps : un programme retiré du démarrage ou remis.** L'écran du démarrage montre l'état de
  chaque programme qui se lance à l'ouverture de session. Un programme ordinaire a « Retirer du démarrage », un
  programme retiré par Vanguard a « Remettre » ; un programme à garder ou un pare-feu n'a aucun bouton, sa raison est
  dite. Un clic n'ouvre qu'une confirmation dans la fenêtre (nom, commande, ce qui va se passer, fenêtre
  administrateur si le programme est de tout l'ordinateur) ; seul « Accepter » lance le changement, un à la fois,
  boutons grisés pendant qu'une commande tourne, sans « tout retirer ». La fenêtre ne propose que les gestes que
  `vanguard demarrage --json` vient d'écrire, et n'envoie que la sorte (retirer ou remettre) et l'empreinte du
  programme (32 chiffres hexadécimaux, calculée par `vanguard`) : jamais un nom, une commande ou un chemin. La forme
  lancée est fermée, `vanguard demarrage --retirer|--remettre <empreinte> --json`, et `vanguard` rejuge tout : sans
  l'accord du geste (`--accord`, celui que `demarrage --json` donne et qui lie le nom, la commande entière et la
  portée), rien n'est fait, l'empreinte seule ne désignant plus rien (la fenêtre rend tel quel l'accord que la liste a
  donné, sans le recalculer ; sous Linux, son relais l'ajoute à la forme fermée) ; empreinte mal formée, inconnue,
  ambiguë, programme à garder, pare-feu, notes de Vanguard illisibles ou changées hors de Vanguard (ni retrait ni
  remise tant qu'elles le sont), « remettre » un programme qui se lance déjà (remis ou réécrit hors de Vanguard,
  peut-être devenu un programme à garder : la vieille note ne l'écrase pas, ni par l'annulation d'un blocage ni par «
  Tout remettre comme avant »), tout est refusé sans rien changer ; ce qui change passe par la même correction que le
  terminal (point de restauration, valeur d'avant notée, une seule fenêtre administrateur, jamais sudo). La console ne
  lance aucun changement, sous aucune forme tapée. « Accepter » revérifie que le geste est encore dans la dernière
  liste lue : une liste relue qui ne le contient plus ferme la confirmation (« La liste a changé : rien n'a changé.
  »), comme changer d'écran ; la veille des alertes continue pendant qu'une confirmation est ouverte. Un changement
  lancé ne s'interrompt pas (le couper au milieu laisserait un état à moitié fait) : Arrêter n'y fait rien, et sous
  Linux la fermeture de la fenêtre non plus (le relais le laisse finir) ; on l'arrête en refusant la fenêtre
  administrateur. Seul son délai, 15 minutes (la fenêtre administrateur de Windows peut attendre), le coupe. Côté
  `vanguard`, un changement tient le verrou des notes (`reglages.verrou`) de leur lecture à leur dernière écriture,
  comme l'optimiseur du terminal et « Tout remettre comme avant » : deux Vanguard ne changent pas les notes en même
  temps, le second refuse sans rien changer. « Remettre » relit les notes sous ce verrou et exige le même réglage noté
  qu'à la première lecture (sinon refusé, rien écrit) ; « Retirer » un programme qui se lance remplace une vieille
  note restée d'avant par la valeur lue maintenant, pour que « Remettre » ramène l'état d'avant ce retrait-là. Sous
  Linux, cette valeur d'avant (l'entrée d'autostart) est lue en une seule ouverture qui ne suit pas un lien, n'attend
  pas un tube et s'arrête à 64 Kio : sinon refusé, rien changé (une entrée qui est un lien ne se retire donc pas
  d'ici), et une entrée ainsi illisible n'est proposée ni pour être retirée ni pour être remise (la liste dit qu'elle
  n'a pas été lue), et « Remettre » ne l'écrase jamais. Une entrée qui, masquée, ne se relirait plus dans cette borne
  est refusée avant d'être écrite. La liste et le nom d'une entrée retirée se lisent de même, bornés, sans attendre un
  tube ; une entrée réécrite garde ses droits. Chaque changement fait ou refusé est écrit au journal des événements
  (sorte, nom nettoyé, issue, empreinte) ; un refus identique au précédent (même empreinte, même sorte, même raison)
  ne s'y réécrit pas pendant 10 minutes, pour qu'une rafale de demandes ne noie pas les alertes ; un changement fait
  s'y écrit toujours. Sa fin est dite (fait, refusé, échec, avec la raison), puis la liste est relue ; seule la
  dernière ligne de la sortie, un JSON du même geste, avec le code 0, dit « fait » : tout le reste est un échec,
  jamais un succès (`fenetre/src/attaques.rs`, essais B1 à B3). Essais :
  `une_confirmation_ne_bloque_rien_et_suit_la_liste` (`fenetre/src/appli.rs`), les essais du relais
  (`fenetre/src/relais.rs`), `verrou_des_notes_tenu_puis_rendu` et ceux de `src/optimiser/demarrage.rs`
  (`seul_un_programme_note_se_remet`, `pare_feu_reconnu_par_son_paquet`),
  `valeur_d_avant_d_autostart_ni_lien_ni_tube_ni_trop_gros`, `entree_trop_grosse_ni_proposee_ni_ecrite` et
  `liste_et_noms_lus_bornes`, `remise_sur_une_entree_pas_lue_n_ecrit_rien`,
  `entree_trop_grosse_une_fois_masquee_refusee_avant_d_ecrire` (`src/optimiser/linux.rs`), et de bout en bout, avec un
  dossier personnel jetable, `demarrage_retire_puis_remet_a_l_octet_pres` et le module `demarrage_sous_attaque`
  (`tests/programme.rs` : remise par-dessus un programme qui se lance, par la fenêtre et par « Tout remettre comme
  avant », retrait sur des notes douteuses, changements simultanés, lien, tube, entrée trop grosse, droits, verrou
  tenu, notes forgées ou rejouées, refus répétés). Le geste écrit par `vanguard demarrage --json` porte aussi un
  accord : une empreinte BLAKE3 (64 chiffres hexadécimaux) de la sorte, de l'empreinte, du nom, de la commande et de
  la portée montrés, et de l'empreinte du nom et de la commande entiers (le texte montré est coupé à 80 et 160 signes
  : deux commandes qui ne diffèrent qu'après la coupe donnent deux accords). L'objet du constat (une entrée
  d'autostart) part vers la fenêtre en « ~/… », plus par le chemin du dossier personnel ; l'empreinte reste celle du
  chemin entier, comme avant. Rendu avec `--accord <accord>`, `vanguard` relit les programmes une seule fois sous le
  verrou des notes, et cette même lecture juge l'accord et décide du geste (retirer ou remettre) : il exige le même
  accord : un programme dont la commande, le nom ou la portée ont changé entre la liste et le clic est refusé (« a
  changé depuis la liste »), rien n'est écrit, et l'accord d'un « retirer » ne vaut pas pour « remettre ». Sans
  `--accord`, rien n'est retiré ni remis (« accord manquant ») ; la fenêtre le lit strictement et le rend dans sa
  trame de changement, avec la sorte et l'empreinte. Une fenêtre prise en main peut toujours relire la liste et rendre
  l'accord du moment : il ne prouve pas qu'une personne a cliqué, seulement que ce qui est changé est ce qui a été
  montré. Essais : `accord_de_chaque_champ_montre` (`src/optimiser/demarrage/resultat.rs`),
  `une_seule_lecture_juge_l_accord_et_choisit` (`src/optimiser/demarrage.rs`),
  `demarrage_l_accord_tient_ce_qui_a_ete_montre` (`tests/programme.rs`).
- **Une correction du compte, montrée puis appliquée, puis remise comme avant (commandes et fenêtre).** Le
  bilan (`audit --json`) donne à chaque constat corrigeable un jeton (32 chiffres hexadécimaux) ; `vanguard correction
  --voir <jeton> [--json]` relance la seule règle du jeton et montre tout ce que la correction ferait (commandes,
  droits, valeurs d'avant, annulation) avec un accord, l'empreinte BLAKE3 de tout ce qui est montré (et, pour chaque
  fichier, sa sorte, son périphérique et son numéro d'inode). Il écrit seulement le carnet des aperçus (jeton, accord,
  heure ; scellé, dossier de données 0700), rien d'autre. Un carnet altéré (changé hors de Vanguard, ou illisible) est
  remplacé par un neuf, et c'est dit : « carnet des aperçus altéré : remplacé » au `--voir` (sur la sortie d'erreur en
  JSON), puis une alerte « carnet-altere » au journal des événements au geste suivant ; les aperçus d'avant ne valent
  plus. En mode lecture seule, `--appliquer` et `--annuler` sont refusés net (code 2), avant toute lecture. `vanguard
  correction --appliquer <jeton> --accord <accord> [--json]` ne fait qu'une correction à la fois, et seulement une
  correction du compte qui s'annule exactement : aujourd'hui, les droits (chmod) de fichiers du dossier personnel
  (`permise_au_compte`, `src/machine/apercu.rs`, est la seule porte ; tout le reste, et tout ce qui demanderait les
  droits d'administrateur, est refusé et se fait depuis le terminal). Au moment d'agir, `vanguard` tient le verrou des
  notes, relit l'état avec les mêmes règles que l'aperçu, refait ses gardes (propriétaire, sorte de fichier, lien
  physique, nom UTF-8, aucun lien sur le chemin), recalcule l'accord et le compare (changé depuis l'aperçu : refusé,
  rien changé), puis consomme l'entrée du carnet (2 s au moins après l'aperçu, 10 minutes au plus ; absente,
  falsifiée, déjà servie : refusé), écrit d'abord sa trace (une ligne « en cours » dans « Ce que Vanguard a changé »,
  et son événement), puis note la valeur d'avant avec la sorte et l'inode du fichier (sinon rien n'est appliqué), pose
  chaque droit et complète la trace. Les droits sont lus et posés sans shell ni programme lancé : chaque élément du
  chemin est ouvert depuis le dossier personnel sans suivre de lien (openat, O_NOFOLLOW), lu sur le descripteur
  (fstat) et posé sur lui (fchmod), seulement s'il a encore la valeur relue et qu'il est le même fichier (même sorte,
  même périphérique, même inode : sinon « changé depuis », rien changé) ; un lien sur le chemin est refusé. `vanguard
  changements --json` dit, pour chaque correction du compte qu'on peut remettre d'ici, le geste `voir-annulation` et
  son jeton ; `vanguard changements --voir <jeton>` montre chaque fichier, ses droits d'aujourd'hui, ceux d'avant et
  ceux que Vanguard a posés (« changé depuis » si quelqu'un y a touché), avec un accord ; `vanguard changements
  --annuler <jeton> --accord <accord>` remet exactement les droits d'avant, une seule fois, sous les mêmes gardes, sur
  le fichier noté seulement (autre sorte ou autre inode : refusé, rien changé), et refuse une note plus récente sur le
  même fichier quand elle est montrée (à remettre d'abord) ; une note plus récente qui n'est pas montrée ne bloque
  jamais. Seul « fait », relu « revenu », sort avec le code 0 ; « pas-revenu » sort avec 1. Chaque demande, faite ou
  refusée, va au journal des événements : la règle, le jeton et l'issue typée seulement (« faite », « refusée (change-depuis)
  », « en échec (echec) »…), jamais un nom de fichier ni une commande ; la raison détaillée, qui peut nommer un
  fichier, ne va qu'à l'écran et à la fenêtre. Ce qui part vers la fenêtre nomme les fichiers « ~/… », jamais par le
  chemin du dossier personnel. Ce que l'accord ne prouve pas : qu'une personne a cliqué. Une fenêtre prise, ou un
  autre programme du compte, peut demander l'aperçu puis l'appliquer ; elle n'obtient ainsi qu'un durcissement des
  droits de fichiers du compte, une correction à la fois, noté au journal et remis exactement d'un geste ; rien qui
  monte en droits. Le carnet des aperçus et les notes sont scellés, mais le sceau est une barrière, pas un coffre : un
  programme du compte qui sait resceller peut antidater le carnet (le délai de 2 s ne tient plus), y remettre un vieux
  carnet (le même geste rejoué sans nouvel aperçu) ou forger une note (des droits comme 0666, 1777, 0000 ou 0200 sont
  acceptés, 4755 refusé ; une note sans identité de fichier vise le fichier qui porte le nom aujourd'hui ; une note
  redirigée vers un autre fichier : l'aperçu montre la vraie cible, mais la ligne de « Ce que Vanguard a changé »
  garde l'ancien nom). Tout reste dans le dossier personnel (hors de lui, `..`, chemin relatif, lien : refusé), et ce
  programme pourrait déjà changer ces droits lui-même. Le JSON de ces commandes (`commandes`, `avant.geste`,
  `valeurs.chemin`) porte les noms exacts, caractères bidirectionnels et de largeur nulle compris (les messages et
  l'écran texte les rendent inoffensifs) : la fenêtre doit les nettoyer avant de les montrer. Ces commandes sont cachées de l'aide en ligne (elles servent à la fenêtre) et décrites ici et dans
  le tableau des commandes. Tout ou rien : si un fichier est refusé, ceux déjà posés sont remis comme avant ; si cette
  remise échoue, c'est dit fichier par fichier, et un fichier jamais touché n'est jamais dit « changé depuis ». Un
  arrêt brutal (Vanguard tué au milieu) laisse la trace écrite avant d'agir : la ligne se montre « interrompue » dans
  « Ce que Vanguard a changé » et se remet comme une autre (« rien à défaire » si la valeur d'avant n'était pas encore
  notée) ; une note sans ligne, d'avant ce changement, se montre de même. Une annulation tuée en route laisse de même
  sa ligne « annulation interrompue, à reprendre », notée avant de rien remettre, jamais « annulable » comme si rien
  n'avait bougé ; une seconde annulation la finit. Finie, la ligne est dite défaite avant que la note soit oubliée :
  tuée entre les deux, elle dit « défaite », jamais « fait ». Le point d'arrêt des essais
  (`VANGUARD_ESSAI_ARRET`), comme l'outil dit absent des essais (`VANGUARD_ESSAI_ABSENT`, qui ne fait que retirer),
  n'existe que dans un programme de débogage, jamais dans celui publié. Essais
  (`tests/programme.rs`, dossier personnel jetable) : `appliquer_une_correction_du_compte_une_seule_fois`,
  `appliquer_refuse_un_etat_change_depuis_l_apercu`, `carnet_falsifie_ou_note_impossible_rien_n_est_applique`,
  `remettre_comme_avant_exactement_une_seule_fois`, `remettre_dans_l_ordre_et_sur_l_etat_montre`,
  `remettre_refuse_un_lien`, `tue_apres_la_pose_la_ligne_est_interrompue_et_se_remet`,
  `tue_avant_la_pose_rien_n_est_dit_change`, `annulation_tuee_en_route_ne_se_dit_ni_annulable_ni_faite`,
  `le_journal_ne_nomme_ni_fichier_ni_commande` ;
  `refuse_un_lien_a_chaque_element`, `un_autre_fichier_sous_le_meme_nom_n_est_pas_touche` (`src/optimiser/droits.rs`),
  `une_ligne_refusee_fait_remettre_les_lignes_deja_posees`, `en_lecture_seule_rien_ne_s_applique`
  (`src/machine/appliquer.rs`), `seul_le_revenu_est_un_succes` (`src/machine/annuler.rs`).
  Depuis la fenêtre : « Voir la correction » sur un constat du bilan, ou « Remettre comme avant » sur une ligne de
  « Ce que Vanguard a changé », ouvre une feuille qui montre l'aperçu lu strictement (`fenetre/src/donnees/correction.rs`,
  `fenetre/src/donnees/changements.rs` : textes bornés, nettoyés et montrés signe par signe, caractères
  bidirectionnels et de largeur nulle rendus visibles). Un aperçu contradictoire, coupé, plus large que la feuille,
  qui demanderait l'administrateur ou ne s'annule pas n'a pas de bouton qui change : la raison est dite (et, pour une
  correction qui demande d'autres droits, la commande se copie pour le terminal). Le bouton qui change (« Appliquer cette correction », « Remettre comme avant ») reste
  grisé 2 secondes après que l'aperçu est montré ; un geste à la fois, sans « tout appliquer ». La fenêtre ne renvoie
  que le jeton et l'accord de l'aperçu, tels quels : sa trame porte la sorte, 16 octets de jeton et 32 d'accord (tout
  à zéro pour un « voir », jamais pour un geste qui change, sinon la trame est rejetée), et le relais bâtit lui-même la
  forme fermée `vanguard correction --appliquer|changements --annuler <jeton> --accord <accord> --json`. Sous Linux, le
  relais, qui a les droits du compte, rejuge de son côté : un geste qui change n'est admis que s'il porte le jeton et
  l'accord du dernier aperçu que le relais a lui-même relayé pour cette famille (lus dans la sortie de `vanguard`, pas
  dans ce que dit la fenêtre), 2 secondes à 10 minutes après lui, rien d'autre ne tournant ; l'admettre consomme cet
  aperçu et la liste qui l'offrait (un second envoi est refusé : il faut un nouvel aperçu). Un geste qui change ne
  s'interrompt pas (ni Arrêter, ni la fermeture de la fenêtre). Son issue n'est lue qu'aux formes exactes de
  `vanguard` (« fait » avec le code 0 ; pour une annulation, « revenu » avec 0 ou « pas-revenu » avec 1, dit tel quel)
  ; un refus fait relire un aperçu neuf ; tout le reste est un échec ou une issue inconnue, jamais un succès. Après
  une correction faite, « Annuler cette correction » n'est offert que si la liste relue de « Ce que Vanguard a
  changé » offre son jeton. Ces bornes de la fenêtre et du relais s'ajoutent à celles de `vanguard`, qui rejuge tout
  (carnet, délai, accord, verrou), sans les remplacer : une fenêtre prise peut toujours enchaîner liste, aperçu et
  accord sans personne, dans les mêmes limites (un durcissement du compte à la fois, 2 s au moins chacun, noté au
  journal) ; « Remettre comme avant » est une baisse de sécurité aux mêmes bornes. Sous Windows, il n'y a pas de
  relais : les bornes sont celles de la fenêtre et de `vanguard`. Essais : `rien_ne_s_accepte_avant_deux_secondes`,
  `appliquer_puis_remettre_de_bout_en_bout` (`fenetre/src/appli.rs`, un faux `vanguard`),
  `un_geste_qui_change_ne_part_qu_apres_son_apercu`, `seul_l_accord_d_un_apercu_montre_est_retenu`,
  `le_relais_ne_laisse_partir_que_l_accord_montre_apres_deux_secondes` (`fenetre/src/relais.rs`),
  `un_texte_plus_large_que_la_feuille_empeche_d_appliquer_d_ici` (`fenetre/src/dessin/bilan/correction.rs`),
  `le_bouton_qui_change_attend_deux_secondes` (`fenetre/src/dessin/captures.rs`), et les cibles de fuzz
  `fenetre_relais` et `fenetre_donnees`.
- **La mise à jour de Vanguard, montrée puis installée (commande et fenêtre).** `vanguard se-mettre-a-jour --voir
  --json` cherche la mise à jour (la clé VANGUARD d'où il tourne, sinon GitHub : manifeste signé Ed25519, jamais une
  version plus ancienne que la plus haute déjà vue) et montre d'où elle vient, la version visée, son empreinte SHA-256,
  sa taille et chaque programme qu'elle remplacerait avec sa version d'aujourd'hui, avec un accord qui lie chacun de ces
  champs ; il ne tourne qu'en lecture seule et n'écrit, liste fermée, que le carnet des aperçus (`apercus.json`, son
  verrou `apercus.lock`) et, comme le terminal pour tout manifeste signé vu, la plus haute version vue et la révocation
  de la clé principale (`versions/plus-haute-vue.txt`, `versions/principale-revoquee.txt`), avec le registre des sceaux,
  son témoin et son verrou (`sceaux.json`, `sceaux.temoin`, `sceaux.verrou`) ; rien d'installé. Si ce plancher ne
  s'écrit pas (verrou des sceaux tenu par un autre Vanguard), l'aperçu le dit : « non vérifié, réessayez dans un instant
  ». « À jour » ne se dit que vérifié : un manifeste trop vieux, une horloge en retard ou GitHub sans réponse donnent «
  non vérifié » (code 1), jamais « à jour ». `vanguard se-mettre-a-jour --appliquer --accord <accord> --json` refait
  l'aperçu au moment d'agir et n'installe que si l'accord recalculé est le même (une autre version, une autre empreinte,
  une clé changée entre les deux : refusé, rien changé), consomme l'entrée du carnet (2 s à 10 minutes après l'aperçu,
  une seule fois), puis garde chaque vérification d'avant : signature, taille et empreinte, copie écrite à côté, relue,
  comparée et essayée (sous Windows, pas encore d'essai : la fenêtre ne dit alors que « relu et comparé »), mise en
  place d'un coup (sinon l'ancienne reste ; sous Windows, une ancienne qui tourne encore est mise de côté,
  `vanguard.exe.ancien`, effacée ensuite, à la lecture de l'état ou après l'accord suivant, seulement si la copie est un
  fichier à son nom et ce reste un fichier ordinaire (un lien ou un dossier à ce nom reste) ; après un double échec de
  renommage, elle est gardée, avec son chemin dit : elle reste sous ce nom tant que rien n'est à sa place ; essais
  `le_reste_du_programme_est_garde_sans_copie_a_sa_place`, `un_lien_au_nom_du_reste_n_est_pas_retire`,
  `le_double_echec_dit_ou_reste_l_ancienne` (`src/mise_a_jour.rs`) et
  `le_reste_d_une_mise_a_jour_s_efface_apres_l_accord` (`src/mise_a_jour/apercu.rs`)) ; il dit chaque programme remplacé
  ou pas (code 0 seulement si tous l'ont été). La fenêtre de Vanguard posée à côté d'un programme remplacé le suit,
  montrée comme une ligne de plus
  de l'aperçu, donc liée par l'accord : celle de GitHub téléchargée après l'accord seulement et vérifiée contre
  l'empreinte gravée dans le programme vérifié (une autre, ou aucune reçue : rien n'est remplacé) ; posée, elle est
  relue par la copie provisoire tenue ouverte sous Linux (le même fichier, les octets reçus), par son nom sous Windows
  (les octets comparés), sinon un échec, et sa ligne du résultat relit la fenêtre posée, sans suivre de lien. Celle de
  la clé suit seulement si c'est celle que grave son programme ; là mais pas posable (illisible, un lien, ou une autre),
  elle n'est jamais comptée absente : le programme est posé seul, celle d'ici n'est pas touchée, et « fenêtre de la clé
  non vérifiée » est dit (aperçu, question du terminal), avec la raison au résultat. Depuis GitHub (0.97), une fenêtre
  absente à côté d'un programme remplacé est ajoutée là où le lancement la cherche (« sa fenêtre, nouvelle ici »), au
  même accord, tout ou rien ; et au même numéro, un programme d'ici qui est exactement celui que l'auteur a signé
  (taille et empreinte du manifeste), sans sa fenêtre ou avec une autre, se voit proposer sa fenêtre seule (« ajoutée
  seule », « remplacée seule »), jugée contre l'empreinte qu'il grave, sans retélécharger le programme ; un programme
  d'ailleurs au même numéro, rien (sa fenêtre ne se juge pas d'ici, il garde le menu). Deux programmes du même dossier
  partagent une seule fenêtre : elle est jugée et posée une fois. Ce qui était à chaque chemin de fenêtre (rien, une
  empreinte SHA-256, un lien et ce qu'il désigne, un fichier que le lancement refuse avec son empreinte, ou rien de
  lisible) est dans l'accord sans être affiché : changé entre l'aperçu et le clic, refusé, rien téléchargé. Un lien, ou
  un fichier que le lancement refuse (droits, propriétaire), n'est jamais compté « sa fenêtre juste », même aux bons
  octets : sa fenêtre est proposée en réparation ; il n'est jamais lu à travers un lien (ouvert sans le suivre). La
  fenêtre est jugée par la règle entière du lancement (le fichier, `lancer_fenetre::refusee`, et, sous Unix, chaque
  dossier du chemin, `lancer_fenetre::dossiers_refuses` ; sous Windows, le lancement ne juge pas les dossiers) : un
  dossier que le lancement refuse (un lien, d'un autre compte, ouvert en écriture au groupe ou aux autres sans bit
  collant) ne se répare pas en reposant la fenêtre ; c'est dit dans l'aperçu et au résultat, avec la raison, jamais
  compté « vérifiée », et aucune réparation n'est proposée (une fenêtre seule n'y est pas posée).
  Ces dossiers sont jugés avec le compte qui met à jour, comme au lancement (choix voulu, plus strict) : sous sudo,
  un dossier de la personne est « d'un autre compte » pour root ; la mise à jour le dit et finit en code 1, même si
  le lancement par la personne l'accepterait. Le programme n'est
  jamais bloqué par sa fenêtre (ronde 3 de la 0.97) : à côté d'une fenêtre d'ici qui ne se lit pas (droits, dossier,
  tube ou fichier spécial, trop grande), ou pour une copie qui est un lien, le programme est posé seul, et sa fenêtre
  n'est ni touchée ni téléchargée ; c'est un geste à part de l'aperçu (« programme seul, sa fenêtre ne se lit pas : non
  touchée, le menu s'ouvrira », « programme seul, la copie est un lien »), donc dans l'accord : redevenue lisible, ou la
  copie qui n'est plus un lien (ou l'est devenue), entre l'aperçu et le clic, et rien n'est fait, le programme compris.
  Une copie qui est un lien ne reçoit sa fenêtre ni à côté du lien ni à côté du fichier qu'il désigne, sous Linux comme
  sous Windows, et c'est dit sur sa ligne ; le lien est revérifié au moment de la pose (une copie devenue un lien depuis
  l'aperçu : rien n'est posé). Le programme posé remplace le lien lui-même par un fichier (un renommage sur son nom,
  jamais à travers lui, sous les deux systèmes) : sa ligne dit de relancer la mise à jour, qui posera alors la fenêtre
  (depuis la clé, si celle de la clé est vérifiée) ; une copie en lien déjà à jour (même version, rien de posé) dit de
  poser la copie elle-même à la place du lien. Depuis la clé, la copie en lien se regarde avant la fenêtre de la clé :
  même avec une fenêtre de la clé non vérifiée, le programme est posé seul, jamais refusé à chaque essai ; sa ligne dit
  alors les deux raisons (la copie était un lien, la fenêtre de la clé n'est pas vérifiée, et pourquoi), sans dire qu'un
  nouveau tour posera la fenêtre. Au même numéro, la fenêtre seule d'une copie en lien, illisible ou dans un dossier
  refusé est laissée de côté, avec sa ligne dans l'aperçu (donc dans l'accord) et sa raison. Dans
  tous ces cas, le résultat dit « non vérifié » et pourquoi, jamais suivi d'une coche « rien de plus récent » ; à
  l'application, le code est 1 ; le verdict qui n'est pas « à jour » (version signée trop vieille, plus récente ici)
  reste dit. Quand il ne reste que des fenêtres seules et que la version n'est pas vérifiée à jour, l'aperçu de la
  fenêtre porte « non vérifié », comme le terminal. La nouvelle fenêtre s'écrit sous un nom provisoire tiré au hasard
  (`vanguard-fenetre.nouveau-<32 chiffres hexadécimaux>`, 128 bits de la source d'aléa du système), créé neuf (O_EXCL :
  jamais par-dessus un fichier, jamais par un lien) ; un nom déjà pris n'est jamais repris, un autre est tiré. Seul ce
  fichier-là est effacé, jamais celui d'un autre : sous Linux, reconnu au même fichier (appareil et inode) ; sous
  Windows, à ses octets (effacer une copie des mêmes octets ne perd rien). Sous Windows, la fenêtre qui tourne encore
  est mise de côté sous un nom tiré de même (`.ancien-<32 chiffres hexadécimaux>`), effacé ensuite ; ce ménage et la
  désinstallation ne retirent que des fichiers ordinaires à ces noms exacts (un dossier ou un lien à ce nom reste). Le
  ménage ne retire rien tant que la fenêtre n'est pas un fichier à son nom : après un double échec de renommage, ce
  reste est la dernière copie de l'ancienne, gardé, et son chemin est dit. Après un échec (le programme qui ne se pose
  pas, ou la fenêtre seule fausse à la relecture), ce qui était là y revient, seulement par-dessus la fenêtre posée : un
  fichier avec ses octets et son mode, jamais l'écriture du groupe ou des autres ni un bit spécial (mode & 0755) ; un
  mode ou un propriétaire qui ne revient pas tel quel est dit (« remise avec ses octets, en fichier neuf de ce compte
  »), un lien en dur vers elle n'est pas gardé (elle revient en fichier neuf) ; un lien en lien (sous Windows, il n'est
  pas refait et la fenêtre posée reste, dit) ; un fichier refusé au lancement avec les droits d'un fichier neuf (0755, à
  ce compte), dit ; ce qui ne revient pas est dit, avec la raison ; un échec avant le renommage, où rien n'a bougé, ne
  dit rien de remis. Reste, connu : entre la dernière relecture de la fenêtre en place et le renommage qui pose la
  nouvelle, le temps d'écrire et de relire la copie provisoire, un programme du même compte peut y glisser un autre
  fichier ; il est alors remplacé par la fenêtre vérifiée (relue par son descripteur sous Linux ; sous Windows, par son
  nom, les octets comparés), et, si le programme ne se pose pas, ce qui revient est ce qui a été relu et montré, pas ce
  fichier-là ; de même entre la relecture qui décide d'un retour et ce retour, et entre la relecture d'un dossier et la
  pose. Un tel programme a déjà les droits du compte : il ne gagne rien qu'il n'ait pas. Le terminal pose par le même
  chemin (`vanguard se-mettre-a-jour`, liste et question). En mode lecture seule, `--appliquer` est refusé net (code 2).
  Depuis la fenêtre : la carte « Mettre à jour Vanguard » des réglages ouvre la feuille de l'aperçu, lu strictement
  (`fenetre/src/donnees/mise_a_jour.rs` : forme exacte, textes bornés et montrés signe par signe) ; « Installer cette
  mise à jour » attend 2 secondes et ne renvoie que l'accord montré. Le jeton de ce geste est fixe
  (`Empreinte::MISE_A_JOUR`) : aucune liste ne l'offre, la trame et le relais refusent tout autre jeton pour lui, et le
  relais ne l'admet qu'avec l'accord du dernier aperçu qu'il a lui-même relayé, comme une correction. La fenêtre ne
  télécharge, ne vérifie et n'écrit rien elle-même. Ce que l'accord ne prouve pas : qu'une personne a cliqué ; une
  fenêtre prise peut enchaîner aperçu et accord, et n'obtient qu'une version signée par l'auteur, jamais plus ancienne,
  que le menu installerait de même, notée au journal. Essais : `la_cle_ne_pose_que_ce_que_l_apercu_a_montre`,
  `une_cle_changee_apres_l_apercu_est_refusee`, `github_ne_retient_ni_ne_telecharge_avant_l_accord`,
  `rien_de_verifie_n_est_jamais_a_jour`, `l_accord_lie_chaque_champ`, `github_propose_la_fenetre_seule_au_meme_numero`,
  `github_ne_pose_jamais_une_fenetre_seule_fausse`, `github_ne_propose_pas_de_fenetre_pour_un_programme_d_ailleurs`,
  `une_fenetre_changee_entre_l_apercu_et_le_clic_change_l_accord`, `une_fenetre_illisible_n_est_jamais_touchee`,
  `une_fenetre_illisible_ne_laisse_de_cote_que_sa_copie`, `deux_programmes_du_meme_dossier_partagent_leur_fenetre`,
  `une_fenetre_seule_garde_le_non_verifie_du_verdict`, `l_apercu_dit_le_geste_de_chaque_ligne`,
  `la_cle_pose_le_programme_seul_a_cote_d_une_fenetre_illisible`, `la_cle_dit_sa_fenetre_illisible_ou_en_lien`,
  `des_copies_laissees_de_cote_gardent_le_non_verifie_du_verdict`, `la_fenetre_de_la_cle_suit_ce_que_l_apercu_a_montre`
  (`src/mise_a_jour/apercu.rs`), `une_fenetre_montree_illisible_n_est_jamais_comptee_pareille`,
  `une_fenetre_seule_ne_se_pose_que_telle_que_montree`, `deux_programmes_du_meme_dossier_posent_leur_fenetre_une_fois`,
  `une_fenetre_illisible_laisse_poser_son_programme_seul`, `une_fenetre_laissee_puis_changee_ne_fait_rien_poser`,
  `un_lien_ou_une_fenetre_refusee_n_est_jamais_juste`,
  `un_lien_a_la_place_de_la_fenetre_n_est_jamais_lu_et_revient_en_lien`,
  `le_retour_d_une_fenetre_absente_n_efface_pas_un_fichier_etranger`,
  `une_fenetre_posee_mais_fausse_a_la_relecture_est_remise`, `un_nom_provisoire_d_un_autre_n_est_jamais_efface`,
  `seule_l_absence_vraie_compte_absente`, `une_copie_en_lien_laisse_sa_fenetre`,
  `une_copie_en_lien_pose_son_programme_seul_meme_si_la_cle_n_a_pas_de_fenetre_verifiee`,
  `une_copie_devenue_un_lien_ne_fait_rien_poser`, `un_dossier_que_le_lancement_refuse_est_dit_jamais_repare`,
  `un_dossier_refuse_ne_cache_pas_ce_qui_sera_fait_a_la_fenetre`, `un_nom_provisoire_deja_pris_n_est_jamais_repris`,
  `le_menage_ne_retire_que_les_restes_d_une_pose`, `l_ancienne_fenetre_revient_avec_ses_droits_ou_c_est_dit`,
  `rien_n_est_dit_remis_quand_rien_n_a_bouge` (`src/mise_a_jour/sa_fenetre.rs`),
  `remplacer_pose_le_programme_seul_a_cote_d_une_fenetre_illisible` (`src/mise_a_jour.rs`), `mise_a_jour_depuis_la_cle`,
  `l_apercu_d_une_mise_a_jour_hors_ligne_n_est_pas_a_jour_et_n_ecrit_rien` (`tests/programme.rs`),
  `mettre_a_jour_ne_part_qu_avec_l_accord_montre` (`fenetre/src/appli.rs`),
  `la_mise_a_jour_ne_passe_qu_apres_son_apercu` (`fenetre/src/relais.rs`), `la_mise_a_jour_n_a_que_son_jeton`
  (`fenetre/src/protocole.rs`), `non_verifie_ne_se_lit_jamais_a_jour` (`fenetre/src/donnees/mise_a_jour.rs`).
- **Les couleurs : enregistrées par `vanguard`, jamais par la fenêtre.** L'écran Vanguard règle, pour chaque thème, un
  des six préréglages ou les couleurs du système, et les cinq couleurs vives (accent, grave, moyen, à surveiller,
  sain). La fenêtre les montre tout de suite, sans rien écrire ; « Enregistrer… » ouvre une confirmation (avant,
  après) et seul « Accepter » lance la forme fermée `vanguard couleurs --theme <sombre|clair> --base <mot> --vifs <5 ×
  6 chiffres hexadécimaux> --json` (ou `--defaut`), que le relais rebâtit d'une trame de 24 octets exacts. `vanguard`
  rejuge tout (mots fermés, couleurs strictes) et écrit dans parametres.json, scellé, sous le verrou parametres.lock
  que prend tout changement de ce fichier (la fenêtre et le terminal ne s'effacent pas l'un l'autre), la valeur
  d'avant lue dans la même relecture ; « Revenir à celles d'avant » remet exactement cette valeur (la valeur : parti
  d'un fichier absent, il reste un `{}` scellé, qui se lit comme l'absence, et garde le sceau qui ferait juger
  durement un fichier posé plus tard). Une couleur qui se verrait à peine sur un des fonds du thème (contraste sous
  1,5:1) est refusée trois fois, par la fenêtre, par le relais et par `vanguard`, et une couleur gardée qui le serait
  ne vaut pas (couleurs de Vanguard) ; sous 3:1, deux gravités trop proches ou l'accent (qui dit aussi « à corriger »)
  trop près d'une gravité, ce n'est qu'une remarque (prévenir, pas interdire), redite dans la confirmation, « grave »
  pris pour « sain » en premier et en gras. Une fenêtre prise en main ne peut donc que poser des couleurs laides ou
  trompeuses (un « sain » rouge), jamais rendre une alerte illisible : chaque mot d'état, d'alerte, de gravité ou de
  remarque s'écrit à l'encre du thème, qui n'est pas réglable, et la couleur réglable ne marque que son point, sa
  barre ou sa bande (essai `aucun_mot_n_est_ecrit_dans_une_couleur_de_gravite`, `fenetre/src/dessin/captures.rs`) ;
  une gravité n'est donc jamais dite par la couleur seule, toujours aussi en mots. Chaque changement fait est noté au
  journal des événements (le thème, le préréglage d'avant et celui d'après) ; assumé : pas de limite de fréquence, et
  la fenêtre en bac à sable y gagne un canal qui dure, minime (deux fois 16 octets de couleurs qu'elle choisit, gardés
  scellés). Les couleurs du système sont lues par `vanguard` seul (le bac à sable de la fenêtre ne voit pas le dossier
  personnel) : le colors.toml du thème d'Omarchy (le premier des deux emplacements qui en donne), fichier ordinaire
  dont le dernier composant n'est pas suivi s'il est un lien (`O_NOFOLLOW`), borné à 64 Kio, ou la couleur
  d'accentuation de Windows (l'accent seul) ; un instantané, relu à chaque ouverture. Un parametres.json changé hors
  de Vanguard (même sans couleurs dedans), effacé, illisible ou absent après des sceaux refaits rend les couleurs de
  Vanguard, et la raison est dite dans les coulisses et sur l'écran Vanguard. Surtout, `vanguard couleurs` n'écrit
  jamais par-dessus un fichier illisible (les autres réglages, une défense coupée par choix, le « non » au partage,
  seraient remis en silence à leur défaut) ni effacé ou changé hors de Vanguard (le rescellement effacerait la trace)
  : refusé, rien d'écrit, et la fenêtre ne propose rien d'enregistrer ; c'est aux Paramètres, qui disent ce qu'ils ont
  ignoré, de le réécrire. Une confirmation ouverte fige le brouillon : ce qu'elle montre est ce qui s'enregistre.
  Le réglage « Animations réduites » suit le même chemin, sans confirmation (cosmétique, un clic l'annule) : la forme
  fermée `vanguard couleurs --animations <toutes|reduites> --json`, rebâtie d'une trame de 7 octets exacts, gardée
  dans `couleurs` (donc remise à son défaut avec elles sur un fichier douteux), mêmes refus, même verrou, chaque
  changement noté (avant, après) ; la fenêtre le relit à l'ouverture dans la même réponse que les couleurs, et un
  refus ou un échec le laisse valoir pour cette fois seulement, dit dans les coulisses (essais
  `les_animations_ne_s_ecrivent_pas_sur_un_fichier_douteux`, `src/parametres/couleurs.rs`,
  `les_animations_de_la_fenetre_se_gardent_d_une_ouverture_a_l_autre`, `tests/programme.rs`).
  Essais : `les_couleurs_se_proposent_s_enregistrent_par_vanguard_et_s_annulent` (`fenetre/src/appli.rs`),
  `des_couleurs_passent_seules_et_lisibles` (`fenetre/src/relais.rs`), ceux de `fenetre/src/couleurs.rs`,
  `fenetre/src/donnees/couleurs.rs` et `src/parametres/couleurs.rs` (`un_changement_s_annule_exactement`,
  `une_demande_invalide_est_refusee`, `un_fichier_change_hors_de_vanguard_rend_les_couleurs_de_vanguard`,
  `un_fichier_illisible_rend_les_couleurs_de_vanguard`, `des_couleurs_gardees_invalides_ne_valent_pas`) et
  `un_fichier_douteux_ne_propose_rien_et_la_confirmation_fige_le_brouillon` (`fenetre/src/dessin/captures.rs`).
- **Ses réponses sont lues avec méfiance.** Taille bornée, lignes coupées, séquences de terminal et caractères de
  contrôle retirés, JSON lu sans jamais planter (lecteurs, console et progression fuzzés : `fenetre_donnees`, `fenetre_saisie`, `fenetre_progression`) ; une
  réponse illisible est dite telle, jamais comptée saine. Comme dans le terminal (`ui::affichable`), un caractère qui
  retourne ou cache un texte (sens d'écriture, invisibles, blancs qui n'en sont pas) y devient « � », et une espace
  d'une autre largeur (insécable, fine, ultrafine, cadratin, idéographique) une espace ordinaire : elle ne colle plus
  deux morceaux d'un nom, et un nombre écrit à la française reste lisible. Un sélecteur de variante (U+FE00 à U+FE0E,
  U+E0100 à U+E01EF, mongols) est retiré : légitime en japonais, en chinois, en mongol, il ne cache plus rien entre
  deux lettres et le nom reste lisible ; celui des émojis (U+FE0F) reste. Les invisibles rares (U+206A à U+206F,
  U+FFF9 à U+FFFB, U+17B4, U+17B5) deviennent « � ». Assumé : deux noms qui ne diffèrent que par un sélecteur se
  montrent pareil (le jugement, lui, voit le sélecteur, et la clé d'un choix accepté l'écrit `\u{…}` : un choix ne
  couvre jamais l'autre nom). Assumé aussi : une lettre d'une autre écriture qui
  ressemble à une latine (« а » cyrillique dans « Sаlon ») reste telle quelle, pour ne pas abîmer les noms écrits dans
  ces langues ; et un état est jugé après le retrait de ses espaces de fin, ce qui ne change rien tant qu'il est un mot
  fixe de `vanguard`, jamais un nom venu de l'extérieur. La note du bilan n'est montrée que si Vanguard la dit fiable
  (`fiable` dans `audit --json`) ; quand des points n'ont pas pu être vérifiés, la note est dite incomplète, à côté du
  chiffre, avec leur nombre.
- **Aucune connexion, aucun fichier.** La fenêtre n'ouvre aucune porte réseau, aucune page web, et n'exécute aucun
  JavaScript (aucune bibliothèque HTTP parmi ses dépendances) ; elle n'écrit aucun fichier (thème et langue ne sont pas
  gardés), sauf, sous Linux, avant son bac à sable, le dossier `XDG_RUNTIME_DIR/vanguard` et le nœud de la prise d'une
  seule fenêtre (ci-dessous), qui reste après sa fermeture et que la fenêtre suivante retire s'il est mort. Sa seule
  écoute est le canal privé d'une seule fenêtre, ci-dessous. Les commandes qu'elle lance joignent Internet comme dans le
  terminal (par exemple `test-connexion`, `logiciels-perimes`).
- **Une seule fenêtre (0.98).** Relancer `vanguard` quand sa fenêtre est ouverte lui demande de revenir devant, sans
  en ouvrir une deuxième. Le canal est privé au compte et à la session graphique : sous Linux, une prise Unix (jamais
  abstraite) dans `XDG_RUNTIME_DIR/vanguard`, dossier créé en 0700 puis vérifié avec son parent (vrais dossiers, à ce
  compte, fermés au groupe et aux autres), sans repli vers /tmp, créée avant le bac à sable et servie dès la fin de
  celui-ci ; sous Windows, un tube nommé d'une seule instance (FILE_FLAG_FIRST_PIPE_INSTANCE,
  PIPE_REJECT_REMOTE_CLIENTS), au nom lié au SID et à la session, dont la liste d'accès ne nomme que ce compte. Le
  message est fermé et de taille fixe : une demande (un octet et un nombre aléatoire frais de 16 octets), une réponse
  (un octet et le même nombre), délais courts et bornés en tout ; rien d'autre n'est lu. La fenêtre sert une demande à
  la fois et, entre deux retours devant, attend son tour (cadence) au lieu de sauter une demande. Elle ne répond que
  si une fenêtre existe et a été priée de revenir : sans fenêtre (encore en train de s'ouvrir, ou sans écran), elle ne
  répond rien et une fenêtre de plus s'ouvre. Les modes en ligne de commande ne sont pas concernés
  (`src/demarrage/une_fenetre.rs`, `fenetre/src/une_fenetre.rs`, `src/socle/une_fenetre.rs`).
  - *Garanti.* Rien n'est envoyé avant que `vanguard` ait prouvé que le programme à l'autre bout est la fenêtre qu'il
    aurait lancée ; sinon il n'envoie rien, le dit, et ouvre sa fenêtre comme avant. Sous Linux, elle prend la place
    de l'imposteur ; sous Windows, l'imposteur garde le tube tant qu'il vit, et la nouvelle fenêtre n'a pas de canal
    (elle réessaie de le créer toutes les 2 s). Un autre compte ne reçoit rien et ne se fait pas passer pour la
    fenêtre. Un programme du même compte qui prend le canal non plus, tant qu'il ne pilote pas la vraie fenêtre. Une
    réponse doit reprendre le nombre de la demande, et un octet qui attendait déjà dans le canal avant la demande est
    refusé : une réponse écrite d'avance ne passe pas. Linux : c'est le processus qui parle qui est vérifié, pas celui
    qui a ouvert l'écoute (qui peut avoir passé la prise à un autre, puis être devenu la vraie image par exec). La
    fenêtre envoie d'abord un octet d'accueil, auquel le noyau attache son expéditeur (SCM_CREDENTIALS et SCM_PIDFD,
    demandés avant la connexion). Cet expéditeur doit être du même compte et du même espace de noms utilisateur (dans
    un espace de noms à lui, un processus peut faire mentir son `/proc/<pid>/exe`), tenu par son pidfd pendant la
    lecture de son image, et son image doit avoir l'empreinte gravée. Chaque octet de la réponse doit venir du même
    processus, et son image doit être encore le même fichier après la réponse. Windows : le tube doit avoir ce compte
    pour propriétaire et pour seul nom de sa liste d'accès (GetSecurityInfo). Son processus serveur
    (GetNamedPipeServerProcessId), tenu ouvert jusqu'à la fin de l'échange (son numéro n'est pas redonné entre-temps),
    doit être du même compte, de la même session et d'un niveau d'intégrité au moins égal à celui de `vanguard` (un
    programme du même compte enfermé en intégrité basse ne passe pas). Le fichier au chemin de son image doit avoir
    l'empreinte gravée : une autre copie de la même version (clé USB, copie installée) est la même fenêtre. Deux
    lancements en même temps : un verrou par session, tenu jusqu'à ce que la fenêtre lancée dise « ouverte » (le canal
    existe déjà à ce moment) ; un verrou qui ne se prend pas est dit.
  - as garanti.* Du code du même compte qui pilote la vraie fenêtre (ptrace, LD_PRELOAD, injection sous Windows) : il
    est déjà ce compte, et ce canal ne lui donne rien de plus qu'un octet. Un programme du même compte peut aussi
    lancer lui-même la vraie fenêtre sur un affichage caché (elle est vérifiée et répond : rien ne s'ouvre), effacer
    la prise ou passer `--remplacer-prise`. Sous Windows, un imposteur qui passe sa poignée du tube à un complice,
    puis finit, pourrait voir son numéro de processus redonné à une vraie fenêtre qu'il relance, que `vanguard`
    vérifierait à sa place (non vérifié sur un vrai Windows). Sous Linux, un programme du même compte qui envoie
    l'accueil, devient un autre programme par exec puis redevient la vraie image avant le dernier contrôle échappe aux
    contrôles d'image ; il peut aussi, sans répondre, lire la demande (elle ne contient qu'un nombre jetable). Un
    imposteur du même compte qui ne répond pas (Linux comme Windows) n'est pas délogé : il garde le canal, chaque
    lancement le dit et ouvre une fenêtre de plus. Sous Windows, c'est le fichier présent au chemin de l'image qui est
    lu, pas l'image chargée en mémoire : un programme du même compte qui remplace ce fichier après le lancement de son
    imposteur passerait (le fichier de la fenêtre est ouvert sans partage d'écriture pendant la lecture, mais pas
    avant). Le tube ne porte pas d'étiquette d'intégrité à lui : c'est `vanguard` qui compare les niveaux.
    FILE_FLAG_FIRST_PIPE_INSTANCE n'est pas appliqué par Wine : son essai n'est conclu que sur un vrai Windows (CI).
    La fenêtre ne reconnaît que le compte (Linux) ou la session (Windows) de celui qui demande : un programme du même
    compte peut la faire revenir devant, au rythme de la cadence, ou l'empêcher de répondre en occupant le canal (le
    service est en série ; un client est gardé au plus le temps de l'échange) : une fenêtre de plus s'ouvre alors. «
    Elle revient devant » n'est affirmé que si Hyprland a accepté de lui donner le focus (sa fenêtre Wayland de classe
    `vanguard`, pas une fenêtre XWayland) ; sinon, et ailleurs qu'Hyprland, `vanguard` dit qu'il lui a été demandé de
    revenir (le bureau en décide). Chaque question à Hyprland est bornée à 2 s, et l'ensemble à environ 8 s. Au tout
    début, avant que la fenêtre existe, un second lancement hors verrou (verrou non pris, lancé à la main, démarrage
    de plus de 20 s) ouvre une seconde fenêtre. Un autre compte local qui prend le nom du tube d'avance annule la
    fonction pour la victime (refus d'accès : `vanguard` le dit au lancement suivant ; la fenêtre, sans console, ne
    peut pas le dire, et réessaie de créer le tube toutes les 2 s) ; il ne reçoit rien. La session du client est lue
    d'après son processus (GetNamedPipeClientProcessId puis ProcessIdToSessionId) ; GetNamedPipeClientSessionId
    n'apporterait pas de garantie de plus, il n'est pas utilisé. Sous Windows, `--remplacer-prise` est sans effet : la
    première instance du tube ne se prend pas à un vivant. Sans dossier ou tube sûr (pas de `XDG_RUNTIME_DIR`, dossier
    ouvert ou à un autre compte, noyau sans SO_PASSPIDFD, avant Linux 6.5), aucun canal : une fenêtre de plus, comme
    avant, jamais un canal moins sûr.
- **Un bac à sable (Linux).** Au démarrage, avant tout le reste, la fenêtre se dédouble : un relais (`vanguard-relais`)
  garde les droits de votre compte et lance seul `vanguard` ; la fenêtre s'enferme (Landlock et no_new_privs,
  `fenetre/src/bac_a_sable.rs`) et ne fait plus que lui demander une commande de la liste fermée, par son numéro
  (`fenetre/src/relais.rs`). Enfermée, elle peut lire les fichiers du système (bibliothèques, pilotes et réglages :
  /usr, /etc, /lib*, /opt, /proc, /sys, /run sauf /run/user et /run/media) et, de votre compte, ses seuls thèmes de
  curseurs (~/.icons, ~/.local/share/icons, ~/.cursors) et son fichier de touches mortes (~/.XCompose) ; parler à son
  affichage (la socket de Wayland, ou celles d'X11 et le fichier ~/.Xauthority, jamais les deux) et à la carte graphique
  (/dev/dri, /dev/nvidia*) ; rien d'autre : ni lire votre dossier personnel (clés SSH, navigateurs, jetons), /tmp, /var
  ou les disques branchés, ni écrire un fichier (pas même le cache des shaders, qu'un programme piégé pourrait
  empoisonner), ni lancer un programme, ni (Landlock 4, Linux 6.7) ouvrir une connexion, ni (Landlock 6, Linux 6.12)
  envoyer un signal hors d'elle ou, sous Wayland, joindre une socket abstraite, ni (Landlock 9) joindre une autre socket
  Unix que celle de l'affichage (le bus D-Bus, par exemple). Le relais ne comprend que « lancer la commande n de la
  liste, en telle langue », « retirer ou remettre le programme de telle empreinte, en telle langue » et
  « arrêter » ; une demande hors de ce protocole (longueur, sorte ou langue inconnue) l'arrête (protocole fuzzé,
  `fenetre_relais`) ; il retrouve lui-même le `vanguard` voisin et rejoue sa garde ; il ne se laisse pas observer
  (PR_SET_DUMPABLE à 0). Un changement, il le borne lui-même, sans croire la fenêtre : seulement pour une empreinte et
  une sorte qu'il a vues ensemble, dans le même geste, dans la dernière sortie de `demarrage --json` qu'il a lui-même
  relayée (« remettre » n'y passe pas pour un programme que la liste offrait de retirer) ; seulement quand rien
  d'autre ne tourne, et rien d'autre ne se lance tant qu'il tourne ; « arrêter » ne le coupe pas (essais
  `le_relais_ne_comprend_que_le_changement_de_forme_fermee`, `seuls_les_gestes_de_la_liste_sont_vus`,
  `aucun_nom_ne_fabrique_un_geste_vu`, `une_sorte_que_la_liste_n_offrait_pas_est_refusee`,
  `le_relais_refuse_la_sorte_que_la_liste_n_offrait_pas`, `un_changement_vu_passe_seul_et_ne_se_coupe_pas`). Quand la fenêtre se ferme, il arrête les lectures en cours,
  laisse finir un changement lancé, puis s'en va. Pourquoi pas `vanguard` aussi :
  enfermé, il verrait moins (no_new_privs seul fait disparaître la vérification de sudo du bilan ; Landlock lui cache
  les autres processus et le bus système), et un bilan qui voit moins sans le dire serait pire. À l'ouverture, la
  console de la fenêtre dit si le bac est actif, avec quelle version de Landlock et ce que ce noyau ne sait pas
  retirer ; sans Landlock (noyau d'avant 5.13, ou Landlock coupé), ou si le relais ne démarre pas, elle le dit en orange
  et garde les droits du compte : jamais un `vanguard` lancé depuis le bac. Les coulisses (« Vanguard — Coulisses »,
  ouvertes de l'en-tête de la console) montrent ce que fait la fenêtre : chaque commande et ses arguments, par où elle
  part (relais ou fenêtre), son pid (rendu par le relais dans une trame de 9 octets exacts), sa fin, ses lignes, et les
  saisies refusées avec la raison ; en mémoire seulement, bornées, nettoyées comme le reste, en lecture seule (la vue
  ne reçoit qu'un état qu'elle ne peut pas changer : rien ne s'y lance, rien n'en est écrit).
- **Le menu reste le choix sûr.** La fenêtre ne s'ouvre pas sans terminal (un script qui écrit les choix), en SSH ou
  au Bureau à distance, en administrateur (root, sudo, console administrateur), sans écran graphique, quand elle n'est
  pas posée à côté (le menu le dit alors et, si aucune autre garde ne joue, propose de l'ajouter par la mise à jour
  vérifiée, jamais par un autre chemin), quand son empreinte n'est pas celle gravée dans ce `vanguard` (ou qu'il
  n'en grave aucune), quand
  (sous Linux) elle n'est pas un fichier ordinaire à ce compte ou à root que ni le groupe ni les autres ne peuvent
  modifier, dans des dossiers que ni le groupe ni les autres ne peuvent modifier, quand le fichier en mémoire ne peut
  pas être lancé (noyau réglé `vm.memfd_noexec=2`, politique SELinux ou AppArmor qui le refuse : jamais de repli vers
  le chemin), quand une bibliothèque injectée dans les programmes de la session est signalée en alerte
  (/etc/ld.so.preload, LD_PRELOAD inconnu ; AppInit_DLLs sous Windows : la raison est dite), ou quand elle ne dit pas
  « ouverte » dans les 20 secondes. `vanguard --menu` force le menu. Sous Linux, elle ne reçoit qu'une liste fermée de
  variables (l'écran, la langue, les dossiers XDG, la session, le proxy, les réglages de Vanguard) et un PATH fixe :
  ni LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, ni GTK_MODULES, LIBGL_*, ni VANGUARD_ORIGINE. Le `vanguard` qu'elle relance
  est celui qui l'a ouverte : `vanguard` lui donne l'empreinte SHA-256 de son propre programme (`--empreinte-vanguard`,
  lue sous Linux sur l'image qui tourne), et à chaque commande la fenêtre relit le fichier, le copie dans un fichier en
  mémoire scellé, compare l'empreinte de cette copie et ne lance qu'elle, jamais le chemin. Lancé de cette copie,
  `vanguard` n'a plus de fichier : la fenêtre lui donne, dans son seul environnement (jamais dans le sien),
  VANGUARD_ORIGINE égale au chemin qu'elle a vérifié, pour que sa mise à jour, sa clé et sa tâche se rapportent au bon
  fichier. `vanguard` ne la croit que dans sa copie temporaire de la clé ou dans cette image reconnue strictement (nom
  exact `/memfd:vanguard`, fichier sans lien, sceaux d'écriture, de taille et des sceaux posés), et seulement si le
  fichier désigné a exactement les octets du programme qui tourne ; sinon elle est ignorée et l'écart dit, et dans
  cette image `vanguard` s'arrête au démarrage (« rien n'est fait, rouvrez la fenêtre »), sans repli vers un autre
  chemin. Un programme du compte qui lancerait lui-même une telle image
  n'y gagne rien : désigner un fichier aux mêmes octets revient à lancer ce fichier, comme une fausse copie de la clé
  posée par ce compte (reste déjà accepté), et ce qu'il avait lancé avant de devenir Vanguard (même processus après un
  exec) reste jugé. Un tel enfant d'avant peut même lui donner des frères nés après l'exec (clone avec CLONE_PARENT)
  ou lui confier ses orphelins (PR_SET_CHILD_SUBREAPER survit à l'exec), que rien ne distingue de ses vrais enfants :
  un Vanguard qui a encore un enfant quand son exec est lu, ou dont les enfants ne se lisent pas
  (`/proc/<pid>/task/*/children`), est un porteur, que le veilleur juge lui-même avec tout ce qu'il lance, et il en
  va de même si sa naissance n'a pas été vue ou qu'une fiche a pu être oubliée depuis (table pleine, événements
  perdus). Au démarrage du veilleur, chaque Vanguard déjà en marche qui a un enfant, dans sa table ou chez le noyau
  (un enfant caché à la lecture de /proc compris, sans ligne de commande ni programme lisible), est aussi un porteur.
  Après des événements perdus, le noyau jette le reste en silence jusqu'à ce que la file soit vide : de la perte
  (et du démarrage du veilleur, où l'abonnement a pu consommer cette unique perte) jusqu'à la file vue vide, rien ne
  passe la marque, au pire des alertes de trop pendant la rafale. Ensuite, comme après un balayage de la table, les
  maillons d'avant ne la passent plus et chaque Vanguard qui la passe encore est revu : un autre départ (numéro repris
  après une fin perdue), un départ inconnu ou une autre image en font un porteur. Les enfants sont lus
  aussitôt le programme tenu, avant sa lecture et sa reconnaissance ; un Vanguard qui lance une commande avant cette
  lecture, ou dont un fil finit à chaque lecture, reste un porteur : course acceptée, au pire des alertes de trop.
  Sans enfant, le veilleur écarte ce Vanguard et ce qu'il lance ensuite, daté depuis son dernier exec. Le
  bilan et la chasse n'écartent les descendants que du processus qui les fait, et seulement s'il n'avait aucun enfant
  au début de son `main`. Au pire, une alerte de trop sur ce qu'un tel Vanguard lance. Limite acceptée : un programme
  du compte qui trace le processus (PTRACE_TRACEME avant l'exec, ou un ancêtre qui s'y attache ensuite) peut faire
  tourner son propre code dans l'image authentique, qui reste reconnue ; ce compte peut déjà tout ce que ce code
  ferait, comme avec la fausse copie de la clé. Le nom `/memfd:vanguard` ne fait jamais reconnaître Vanguard, ni, sous Linux, un chemin seul : le
  bilan, la chasse, le veilleur, le blocage et la quarantaine ne reconnaissent un autre processus comme Vanguard que
  par le même fichier (périphérique et inode) ou par les mêmes octets (empreinte BLAKE3) qu'un candidat : un processus
  qui tourne d'un des chemins de ce Vanguard (hors de cette image ; dans l'image, seulement l'origine vérifiée), ou
  l'image scellée de la fenêtre. Les octets ne sont lus que sous des bornes (même taille d'abord, verdict gardé tant
  que le fichier ne change pas, quatre lectures par seconde au plus, et une de plus réservée pour reconfirmer un Vanguard
  déjà reconnu ; plein, le cache perd ses verdicts faux avant les vrais) ; au-delà, ou illisible (un processus d'un
  autre compte), le processus n'est pas Vanguard et il est jugé : un Vanguard jamais vu, lancé pendant une inondation
  de copies de même taille, peut ainsi être jugé comme un autre. Sous Windows, le chemin du programme reconnaît encore
  Vanguard. Un programme quelconque lancé d'un memfd nommé « vanguard », ou refait au chemin de Vanguard, reste donc
  montré, jugé et traitable, et deux `vanguard` lancés par la fenêtre ne se dénoncent pas l'un l'autre comme
  « programme sans fichier » (LNX-PRS-004). L'élévation par pkexec, qui exécute un chemin,
  prend dans cette image l'origine vérifiée, seulement si elle est à l'abri d'un remplacement (fichier et dossiers à
  root, que ni le groupe ni les autres ne peuvent modifier) ; sans origine vérifiée, pkexec n'est pas proposé, jamais
  de repli. Remplacé depuis
  l'ouverture, même par ce compte ou par une mise à jour : il n'est pas lancé, la raison est dite et la fenêtre demande
  d'être rouverte ; après une mise à jour réussie, elle dit tout de suite de la rouvrir, sans croire la nouvelle
  empreinte. Ouverte seule, sans `vanguard`, la fenêtre prend l'empreinte de son voisin à l'ouverture (confiance au
  premier usage).
- **Ses bibliothèques.** Sous Windows, comme `vanguard.exe`, elle ne charge ses DLL que de System32 : celles qu'elle
  importe (DependentLoadFlags), et celles qu'une bibliothèque ouvre par leur nom après le démarrage
  (SetDefaultDllDirectories, première ligne du programme ; opengl32.dll par exemple). Une DLL posée à côté d'elle,
  sur la clé ou dans Téléchargements, n'est jamais chargée. Sous Linux, elle est liée à la glibc du système (ses
  bibliothèques d'affichage se chargent à l'exécution) : seul l'interpréteur `/lib64/ld-linux-x86-64.so.2` est
  permis, sans dossier de bibliothèques écrit dans le programme (ni RPATH ni RUNPATH), vérifié à chaque passe de
  `outils/verifier.sh` (`vanguard deploiement verifier-binaire --glibc`).
- **Limites.** Comme le programme, elle suppose que son dossier n'est modifiable que par vous : une fausse fenêtre
  posée à côté n'est plus lancée, mais qui peut remplacer `vanguard` peut remplacer les deux. Sous Windows, le
  lancement est vérifié sous Wine seulement (pas encore sur un vrai Windows), et le processus n'est pas créé suspendu
  pour comparer son image à la poignée tenue : sous Windows, c'est le chemin qui est lancé ; la poignée sans partage
  d'écriture garantit les octets du fichier, pas le chemin jusqu'à lui. Les dossiers du chemin sont tenus aussi
  pendant le lancement (ni renommés ni effacés ; un lien ou une jonction ni re-pointé ni défait) ; restent ouverts les
  dossiers de l'autre côté d'une jonction et une lettre de lecteur redéfinie pour la session (`subst`,
  DefineDosDevice), jusqu'au lancement suspendu puis comparé, au lot suivant, dans la machine virtuelle. De même quand
  la fenêtre relance `vanguard.exe` : l'empreinte est celle des octets lus sur la poignée tenue, mais c'est le chemin
  qui est lancé ; et `vanguard.exe` lancé hors de sa copie temporaire lit sa propre empreinte par son chemin, pas sur
  l'image qui tourne. Sous Windows, la fenêtre et `vanguard` ne vérifient que le fait
  que l'autre soit un fichier ordinaire : ni son propriétaire, ni les droits (ACL) du fichier et de ses dossiers, que
  Windows ne laisse pas lire aussi simplement ; un dossier où d'autres comptes peuvent écrire n'est donc pas refusé
  sous Windows. Sous Windows, chaque commande lancée est mise dans son propre objet de travail (job object) : Arrêter, le délai et la fin de la commande arrêtent aussi ce qu'elle a lancé, et tout s'arrête si la fenêtre s'arrête ; un processus lancé dans le court instant d'avant son entrée dans l'objet y échapperait. Sous
  Linux, pas encore de lecteur d'écran ni de copier-coller. Le bac à sable de la fenêtre ne retient pas ce que
  l'affichage permet à toute fenêtre, et Wayland n'y est jamais compté comme sûr d'office. Sous X11, tout programme de
  l'écran peut taper dans les autres fenêtres et lire leur presse-papiers, et les sockets abstraites restent
  joignables (X11 en a besoin). Sous Wayland, cela dépend du compositeur : Hyprland (sans enforce_permissions) et ceux
  de wlroots offrent à toute fenêtre, par la socket même où elle dessine, un clavier et un pointeur virtuels
  (zwp_virtual_keyboard, zwlr_virtual_pointer), le presse-papiers des autres (data-control, wlr et ext), la capture de
  l'écran (screencopy, image-copy-capture) et celle des fenêtres (hyprland_toplevel_export) ; Landlock n'y peut rien.
  Une fenêtre prise en main pourrait donc taper dans un terminal ouvert, voir l'écran ou lire le presse-papiers ; vos
  fichiers, eux, lui restent fermés. Le bac protège aussi moins avant Landlock 9 (elle peut encore joindre les sockets
  Unix du compte, dont le bus de session, d'où `systemd-run` lancerait un programme, et celles d'X11 même sous
  Wayland) et avant Landlock 6 (les sockets abstraites, dont celle de Xwayland). Les réglages de pilote de votre compte
  (~/.drirc, ~/.nv) ne sont pas lus : la carte garde ses valeurs par défaut.
  La confirmation d'un changement du démarrage protège d'un clic de trop, pas d'une fenêtre prise en main : celle-ci
  pourrait « accepter » à votre place. Ce qu'elle obtient alors reste borné par ce qui ne dépend pas d'elle : sous
  Linux, le relais n'accepte que la forme fermée, un geste (empreinte et sorte) qu'il a vu dans la dernière liste, un
  changement à la fois ; `vanguard` rejuge tout et ne retire jamais un programme à garder ni un pare-feu ; ce qui est
  retiré se remet exactement (valeur d'avant notée) ; chaque geste est au journal des événements, où il se voit. Le
  relais ne met aucune pause entre deux changements : une fenêtre prise en main peut enchaîner liste et changement et
  retirer, l'un après l'autre, tous les programmes ordinaires (`le_relais_n_impose_aucun_intervalle_entre_deux_changements`),
  chacun au journal et chacun se remet (par la liste du démarrage ou « Tout remettre comme avant » : ces
  retraits ne sont pas dans « Ce que Vanguard a changé », `changements --json`). Les notes de Vanguard et leurs sceaux (`src/sceau.rs`) sont une barrière
  contre un fichier posé par un autre programme, pas un coffre : un programme de votre compte qui garde une copie des
  notes avec leurs sceaux peut la reposer plus tard ; « Remettre » ramènerait alors une ancienne valeur notée d'un
  programme qui ne se lance plus (par-dessus un programme qui se lance, c'est refusé : `notes_forgees_ou_rejouees`).
  Le journal des événements est borné (13 mois, 20 Mio en tout, les plus vieux mois partent d'abord) : des refus
  identiques ne s'y écrivent qu'une fois par 10 minutes (`des_refus_repetes_ne_noient_pas_le_journal`), mais des
  demandes pour des empreintes toutes différentes s'écrivent chacune, et assez d'entre elles pousseraient de vieilles
  alertes hors du journal. Sous Windows, il n'y
  a pas de relais : ces bornes-là sont celles de `vanguard` seul, et fermer la fenêtre arrête aussi un changement en
  cours (objet de travail) ; la valeur d'avant étant notée avant tout changement, il se remet quand même.

## La porte de lecture pour les assistants d'IA

`vanguard mcp` est une porte en lecture seule pour un assistant d'IA que la personne branche elle-même (un client
MCP) : il peut lire ce que Vanguard a déjà écrit, sans pouvoir rien changer. **Linux seulement** : sous Windows, la
commande refuse de démarrer (code 2) tant qu'elle n'a pas été essayée sur un vrai Windows.

- **Ce qu'elle donne.** Cinq outils, une liste fermée : `etat` (journal vérifié ou non, dernier examen de chaque outil,
  alertes des 30 derniers jours par gravité, protection et interrupteurs), `evenements` (le journal, page par page),
  `constats` (les derniers résultats des examens), `bilans` (score et nombre de problèmes de chaque bilan) et `identite`
  (numéro de version, sans la date de compilation, et empreinte SHA-256 du programme qui tourne). Un bilan n'est dit
  vérifié que s'il porte une empreinte crue par la chaîne ; un historique sans aucune empreinte est dit `non-verifiee`
  (`un_bilan_sans_empreinte_n_est_pas_dit_verifie`). Cette empreinte est un BLAKE3 sans clé : elle montre qu'un bilan
  n'a pas été abîmé, pas qui l'a écrit, car un programme du compte peut la recalculer. Aucun ne lance d'examen, ne va
  sur le réseau (le processus entier est mis hors ligne) ni n'ouvre un fichier de la personne. Un nom d'outil n'est
  reconnu que tel quel : ni majuscules, ni blancs, ni chemin (`la_liste_des_outils_est_fermee`).
- **Ce qu'elle ne donne jamais.** Ni lignes de commande, ni chemins (d'un programme, seul le nom court sort), ni
  numéros de processus, ni comptes, ni adresses des connexions, ni nom de l'ordinateur ou du réseau, ni paramètres,
  ni secrets, ni le contenu d'un fichier, ni les commandes d'une correction. Un essai plante ces valeurs (inventées)
  dans le journal, les examens et l'historique, puis vérifie qu'aucune ne sort, par aucun outil
  (`rien_d_exclu_ne_sort_de_la_porte`). Le texte venu de l'ordinateur, rangé à part (plus bas), fait exception : il
  peut citer un nom.
- **Elle n'écrit rien, sauf sa note.** Elle lit les notes scellées sans les adopter ni les réparer ; un essai compare
  les empreintes de tout le dossier avant et après une session (`une_session_entiere_n_ecrit_rien`). La seule écriture
  est une note de session au journal : sa durée, le nombre d'appels par outil, les refus par code et la raison de la
  fin, jamais les arguments ni les réponses. Elle est écrite au premier appel servi, avant sa réponse, puis complétée à
  la fin ; un arrêt demandé (SIGTERM, SIGINT, SIGHUP) finit la session et la note. Seul un SIGKILL coupe sans note de
  fin, et la note d'ouverture reste. La porte ne crée rien : sur un compte où Vanguard n'a jamais tourné (ni journal ni
  sceaux), rien n'est noté. Un frein borne ce qu'un client peut ajouter au journal : 12 notes et 1 alerte par heure au
  plus ; les suivantes sont seulement comptées dans un petit fichier à part et dites par la note suivante. Rien n'est
  écrit non plus quand le journal du mois a pris le quart de sa taille permise : les alertes de Vanguard gardent leur
  place. Une note coupée au milieu est défaite : le journal du mois est remis à sa taille d'avant et sa tête reprise
  sans l'annonce, et le compte des notes retenues n'est effacé qu'après une note écrite en entier
  (`une_note_coupee_de_la_porte_est_defaite`). Pour qu'une note ne soit pas coupée, la porte refuse de démarrer sous un
  plafond de taille de fichier (`ulimit -f`), ou s'il ne se lit pas (`la_porte_refuse_un_plafond_de_taille_de_fichier`),
  le relit avant chaque note (`sous_un_plafond_de_taille_la_porte_n_ecrit_rien`) et ignore le signal de dépassement
  (SIGXFSZ) : une écriture refusée rend une erreur au lieu de tuer la porte au milieu de sa note. Sous un plafond posé
  en cours de session (`prlimit --pid`), rien de cette session n'est écrit : ni sa note, ni son alerte, et sa retenue
  n'est pas comptée non plus (la session suivante ne l'annonce pas). Qui lance la porte a déjà ce pouvoir : il peut
  aussi ne jamais la lancer et lire les fichiers de Vanguard sans elle. Limite : si la remise
  à la taille échoue elle-même, la ligne coupée reste ; la prochaine écriture de Vanguard la note comme une rupture du
  journal, sans rien adopter en silence. Sa propre note ne rend pas le journal « pas à jour » : il est relu juste après
  (`la_note_de_la_porte_ne_rend_pas_son_journal_perime`). La personne peut donc voir que son assistant lit Vanguard, et
  à quel rythme. C'est une trace de bonne foi, pas une barrière : un programme du compte peut lire les fichiers de
  Vanguard sans la porte.
- **Elle n'écoute rien.** Ni port, ni socket : seul le programme qui l'a lancée lui parle, par l'entrée et la sortie
  standard. Elle ne demande aucun droit et ne donne rien que le compte ne puisse déjà lire. Elle refuse de tourner
  en root (code 2, rien sur la sortie, rien au journal : `la_porte_refuse_root`) et refuse un terminal en entrée
  (`la_porte_refuse_un_terminal`) : elle est faite pour un programme, pas pour une personne au clavier. Ce refus est
  une aide contre une erreur de frappe, pas une garde : un programme peut toujours lui donner un tube.
- **Le client est tenu pour hostile.** Un message fait 64 Kio au plus, borné pendant la lecture même, et doit finir en
  10 secondes ; une réponse doit être écrite en 10 secondes, sans quoi la session finit (un client qui ne lit pas sa
  sortie ne bloque pas la porte). Une session s'arrête après 15 minutes de silence (une ligne vide ne le rompt pas :
  `les_lignes_vides_ne_rompent_pas_le_silence`), 8 heures ou 10 000 demandes ; après une longue pause, l'assistant
  relance la porte (l'outil peut sembler arrêté jusque-là). Plus de 20 demandes en une seconde (les lignes vides ne
  comptent pas, et le refus porte l'id de la demande), plus de 64 lignes vides dans la session
  (`les_lignes_vides_sont_bornees`), un message qui n'est pas du JSON valide, une enveloppe fausse (champ inconnu ou en
  double, `id` hors de l'ASCII visible), un lot ou trois notifications inconnues ferment la session ; une demande de
  méthode inconnue reçoit son refus sans rien fermer. Les paramètres sont un objet, ou absents (`null` vaut absent) :
  une demande aux paramètres d'une autre forme reçoit son refus, une notification du protocole est comptée comme
  refusée, sans réponse (`les_params_sont_un_objet_ou_absents`). La page suivante d'`evenements` se demande par un
  curseur qui désigne une place exacte : la lecture finit même quand des événements portent le même id
  (`la_pagination_finit_meme_avec_des_ids_en_double`) ; un `avant` donné par l'id d'un événement en double garde
  l'ancien sens (le plus récent de ce nom). Un signe hostile est noté en plus par une alerte moyenne : un assistant
  ordinaire attend ses réponses et n'en envoie pas, donc il est piégé, mal écrit ou ce n'est pas lui
  (`une_session_n_ecrit_que_sa_note_et_le_client_hostile_est_note`). Une réponse fait 256 Kio au plus ; une page trop
  longue est raccourcie et le dit.
- **Tout ce qu'elle rend est non fiable.** Un titre d'alerte, un message de constat ou un nom de programme peut citer un
  attaquant (un fichier nommé pour donner des ordres à l'assistant, par exemple). Chaque réponse est marquée `"teinte":
  "non-fiable"`, sous trois formes : dans `_meta` d'un résultat, dans `error.data` d'une erreur, et en tête du résultat
  d'un outil, dans son texte comme dans `structuredContent`, avant tout contenu
  (`la_teinte_est_en_tete_de_chaque_reponse`, vérifié dans la ligne écrite). Les noms (gravité, famille, règle, raison,
  fin) sortent d'une liste fermée, ou vides. Le texte venu de l'ordinateur (titre, message, catégorie, nom de programme)
  sort à part, sous la forme `{"texte_externe": …, "non_fiable": true}`, par une liste blanche de mots : seuls sortent
  les mots que Vanguard écrit lui-même dans ses propres messages (les chaînes de ses macros de texte, en français et en
  anglais, tirées du code à chaque compilation par son arbre syntaxique, en suivant les modules comme le compilateur,
  sans les essais : environ 8 300 mots ; une forme que cette lecture ne sait pas juger, un module introuvable ou un
  fichier `.rs` de `src/` qu'aucun module ne déclare arrête la compilation). Tout autre mot devient « … »,
  comme les chiffres, les chemins, les adresses, les jetons, les noms qui ne sont pas des mots du vocabulaire et tout
  signe hors d'une petite ponctuation fixe (jamais une parenthèse ni un crochet ; ceux qui entourent un mot sont
  jetés) ; plusieurs « … » de suite n'en font qu'un, et la sortie fait 400 octets au plus
  (`chaque_mot_de_la_sortie_est_du_vocabulaire`, essai de propriété). Le texte est normalisé avant d'être jugé (pleine
  chasse, invisibles, guillemets, accents latins recomposés) ; une lettre qui en imite une autre (cyrillique, signe
  Kelvin, ligature, lettre mathématique) n'est pas ramenée : le mot n'est pas connu et sort « … ». Un mot d'une seule
  lettre ne sort que s'il est « a », « à » ou « y » ; un mot suivi de points de suspension (« admin… ») ou coupé par la
  borne de lecture (8 192 octets) sort « … ». Deux filets retiennent des valeurs qui peuvent être faites de mots connus.
  Dès qu'un mot annonce un secret (mot de passe, phrase de passe, password, passwd, pwd, mdp, passphrase, clé, key,
  code, PIN, NIP, PSK, jeton, token, secret, secrète, passe, seed, phrase de récupération, recovery phrase,
  identifiant, login, au singulier ou au pluriel, en toute casse, avec ou sans tiret, sans séparateur exigé), tout le
  reste du texte devient un seul « … », pas seulement jusqu'au premier point ; seule exception, une annonce niée
  (« sans mot de passe », « no password ») sans « : » ni « = » qui la suive, quand la négation finit par une lettre et
  que l'annonce commence par une lettre : aucun signe entre les deux (point, « ! », « ? », deux-points, parenthèse
  ouvrante ou fermante), et rien que des espaces simples (un saut de ligne, une tabulation, une espace insécable
  ou un caractère de contrôle font une annonce), comme dans le message de Vanguard sur un réseau Wi-Fi sans mot de passe. Une annonce écrite dans
  une parenthèse retenue (« (mot de passe WPA2) ») coupe aussi tout ce qui suit. Une valeur
  écrite avant l'annonce (« maison rouge est le mot de passe ») n'est pas retenue. Dans une alerte du veilleur, chaque
  « (PID n) » ouvre son propre groupe : l'extrait de commande qui le suit entre parenthèses devient un seul « … », et
  la profondeur des parenthèses y est comptée : un extrait qui n'est pas revenu à zéro retient tout jusqu'au
  « (PID n) » suivant ou jusqu'à la fin ; un « (PID n) » cité dans un extrait encore ouvert le continue, de son
  premier mot, avec ou sans parenthèse, et une fermante de trop après un « (PID n) » montre qu'il était cité dans
  l'extrait d'avant, qui va alors jusqu'à lui ; après un extrait refermé, un « (PID n) » n'ouvre un nouveau programme
  que derrière l'écart exact du veilleur (« ; « nom » ») : sinon il était cité, et l'extrait est retenu en entier,
  avant comme après lui ; les parenthèses du nom entre guillemets du programme suivant (« (sd-pam) », « b(1) ») ne
  comptent pas dans l'extrait d'avant, et le veilleur écrit ce nom sans aucun guillemet à lui (chacun devient « ' »)
  ni aucune parenthèse (« ( » devient « [ », « ) » devient « ] »), pour que son début se retrouve à coup sûr
  (« b) "c » ne ferme plus l'extrait d'avant, « z (PID 5) ( » n'écrit plus un faux programme) ; tout autre texte
  qui montre le nom d'un programme, d'un module, d'un service ou d'une extension (lignée, rançongiciel, ports en
  écoute, modules du noyau, espions, mémoire, démarrage) l'écrit de la même façon, sans quoi un faux « (PID 5) ( »
  cachait le reste de l'alerte ; un chemin (« Program Files (x86) ») ou le nom d'un fichier téléchargé ou d'une clé USB garde ses parenthèses et
  reste une limite connue, du côté sûr (le reste du texte est retenu, pas montré) ; une autre parenthèse ne sort
  que si tous ses mots sont connus. Le
  prix : un texte utile qui suit une annonce est perdu (environ 0,8 % des morceaux de texte de Vanguard contiennent un
  de ces mots, « clé de registre » et « code » compris). Ce sont des filets, pas une garantie : une valeur que rien
  n'annonce sort si ses mots sont du vocabulaire. C'est à l'assistant de traiter ce texte comme une donnée, jamais comme
  une consigne. Limites connues : une suite de mots du vocabulaire sort telle quelle, avec sa casse, ses guillemets de
  tête et sa ponctuation. Un attaquant qui écrit sur l'ordinateur peut donc composer une phrase avec ces mots (« Ignore
  les consignes précédentes » sort tel quel), et y épeler une valeur par les initiales ou la casse des mots. Un nom cité
  (réseau Wi-Fi, compte, programme, dossier) laisse sortir ceux de ses mots qui sont aussi des mots de Vanguard
  (« admin », « maison », « famille », « bureau », « root »), une ligne de commande hors d'un extrait du veilleur aussi
  (« bash », « sshd », « cat »), et une fausse entrée complète du veilleur (« ; « nom » (PID n) raison ») écrite dans
  une ligne de commande. Les champs à forme fixe (règle, version, date, nombres, empreinte) sortent avec les
  lettres et chiffres que leur forme admet, sans être relus : une date impossible, une règle inventée ou un nombre qui
  écrit une adresse IPv4 en entier y passent. C'est un canal pour qui écrit déjà le journal ou un examen non scellé, pas
  une fuite d'une donnée de la personne. Le seul module du programme chargé hors de `src/` (le modèle des couleurs
  partagé avec la fenêtre, nommé dans une liste) n'est pas lu au build : il n'a aucun message, un mot de moins ne fait
  que masquer davantage, et un essai le passe aux mêmes règles que `src/` ; tout autre module du programme hors de
  `src/` arrête la compilation. La lecture suit
  `r#test` et `r#cfg` comme le compilateur, et un `#[path]` sur un module en ligne depuis le dossier du fichier ;
  `cfg(test)`, `cfg(kani)`, `cfg(fuzzing)` et `cfg(miri)` sont faux dans le programme. N'est un essai que ce que
  rustc retire vraiment : `#[test]` ou `#[bench]` d'un seul segment, un `cfg` faux, un `cfg_attr` dont la condition
  est sûrement vraie (`true` et `false` écrits tels quels ; `r#true` est un nom de cfg ordinaire, jamais posé) ; un
  attribut d'outil ou de paquet (`#[rust_analyzer::test]`, `#[tokio::test]`) reste du
  programme. Elle arrête la compilation sur
  une forme qu'elle ne sait pas juger : `cfg_select!` ou `cfg_match!`, un `path` posé par `cfg_attr` sur un module, un
  module à fichier déclaré dans un bloc (fonction, `const`), et toute macro hors d'une liste blanche jugée (`format!`,
  `write!`, `json!`, `vec!`…) appelée dans un appel de texte ou dont le corps en contient un (`cfg_if!`, une enveloppe
  d'un autre paquet, une macro maison qui choisirait par `cfg`, quelle que soit la forme de ses bras), comme un nom
  que la lecture reconnaît à son nom (macros de texte, liste blanche, macros d'essais, `concat`, `include`, `test`,
  `bench`) donné à autre chose : définition (`macro_rules!`, `macro`), `use` qui le renomme ou le tire d'un autre
  paquet, appel par le chemin d'un autre paquet (seules les macros de texte elles-mêmes, au premier niveau de
  `src/langue.rs`, sont définies sous leur nom), le nom
  d'un paquet admis pris par un module, un `use` ou un `extern crate` (`mod alloc`), un `extern crate` d'un paquet
  non admis, un chemin du programme vers un nom réservé qui passe par un module (`crate::pont::tr!`, où `pont` peut
  être un autre paquet ; seule exception, `crate::ui::tr`, admis si `src/ui.rs` réexporte la vraie macro), et, dans
  le corps d'une macro lu
  jeton par jeton, deux règles d'ensemble : aucune métavariable (`$x`, `$( … )`) si ce corps contient un texte (elle
  peut valoir n'importe quel jeton : le nom d'une autre macro, « ! », « # »), et aucun mot qui lie un nom ou tire un
  fichier (`use`, `mod`, `extern`, `macro_rules`, `include`), ni là, ni dans l'appel d'une macro hors de la liste
  blanche (qui pourrait le recombiner) ; enfin `#[macro_use]` et tout `include!` autre que la base des fabricants
  (`OUT_DIR`), comme `use … as` qui renommerait `include!`. Le
  script de compilation (`build.rs`), la lecture qu'il inclut et la configuration de cargo du dépôt sont jugés par une
  empreinte de tout le fichier, et `Cargo.toml` par la liste exacte de ses cibles et de ses paquets de compilation
  (`outils/essais-signature.sh`) : un changement y demande une relecture voulue. Le dépôt n'a ni fichier hérité que
  cargo ou rustup préférerait au fichier jugé (`.cargo/config`, `rust-toolchain`), ni aucun lien symbolique suivi par git (même
  sous `target/`), ni aucun lien non suivi hors de `target/` et `.git/` (`target` peut être un lien vers un autre
  disque) ; hors de la racine d'un dépôt git, les liens suivis sont « non vérifiés », un échec. Une macro à bras
  d'une autre forme n'est plus une limite : toute macro inconnue autour d'un texte arrête la compilation, quels que
  soient ses bras. Contrôlé, sans être garanti, par le contrôle croisé (`outils/vocabulaire-binaire.py`) : chaque
  mot du vocabulaire doit se trouver, octet pour octet, dans l'un des programmes publiés (Linux ou
  Windows, compilés comme une version, avec LTO) ; un seul absent arrête `outils/compiler-version.sh` sans poser son repère, donc sans publication, et nomme le
  mot et son fichier (`outils/verifier.sh` le refait sur les programmes du commit vérifié, étape
  « vocabulaire-binaire »). Une ruse que la lecture n'a pas vue (macro d'un autre paquet prise par une importation
  globale, `cfg!(test)` dans une expression, toute forme encore inconnue) donne un mot que rustc n'a pas gardé : il
  manque aux programmes et la publication s'arrête. Le code compilé mais jamais exécuté est retiré de la lecture à la
  source, jamais du contrôle : fonctionnalité absente de la compilation, branche qu'un `cfg!` fixe écarte, élément
  dit `dead_code` (par un `cfg_attr`, seulement si sa condition est sûrement vraie sous Linux), et une courte liste
  de textes exacts, chacun dans sa fonction nommée (`TEXTES_MORTS`, une cause par fonction ; un texte qui n'y est plus
  arrête la compilation). Ce qui reste : le mot d'une ruse qui se trouve aussi ailleurs dans les programmes passe (le
  contrôle juge des octets, pas une origine : listes de marques et de mots-clés, chemins, code machine). Mesuré sur
  les programmes de version, pour des mots absents du vocabulaire : tout mot de 2 lettres s'y trouve, 49,5 % des suites
  de 3 lettres au hasard, 7,2 % de celles de 4 lettres, 8,9 % des mots d'un dictionnaire anglais (cracklib-small)
  et 3,9 % d'un dictionnaire français (fr_CA). Le contrôle attrape donc une ruse dont le mot est long ou rare, pas un
  mot court ou courant. Exiger une frontière de mot a été mesuré puis écarté : 51 vrais morceaux du vocabulaire
  (« BLOCAGE », « TRUST », adresses web) ne s'y trouvent que collés à d'autres lettres, et la publication
  s'arrêterait. Restent aussi : seuls les programmes publiés sont contrôlés, pas une compilation de
  développement ; le programme Windows n'a pas la porte et ne compte que dans l'union ; la configuration de cargo hors du dépôt et une macro d'un
  paquet ordinaire qui lirait le disque restent non vérifiées.
- **Elle ne peut pas prouver qu'elle est le vrai Vanguard.** Un faux programme posé au même chemin répondrait la même
  chose, `identite` comprise ; et un programme du compte peut écrire dans les fichiers de Vanguard (les sceaux sont une
  barrière, pas un coffre : voir « Les programmes de votre compte ne visent pas Vanguard lui-même »). La preuve se fait
  avant le lancement, par le client : lancer un chemin absolu épinglé, jamais une recherche dans PATH ; vérifier que le
  fichier et ses dossiers ne sont pas inscriptibles par d'autres ; comparer son empreinte SHA-256 à celle de la version
  publiée (`SHA256SUMS.txt`, ou la liste signée en Ed25519 des mises à jour) ; lancer les octets vérifiés (sous Linux,
  le descripteur ouvert pour le calcul) ; puis vérifier qu'`identite` redonne la même empreinte. Aucune poignée de main
  signée : une clé dans le programme ou sur l'ordinateur se lirait par le même compte, et aurait l'air d'une preuve sans
  l'être.
- **Un client reconnu n'est jamais exempté.** La porte répond pareil à tout client et ne change rien à la
  surveillance : pas de liste blanche, pas d'alerte adoucie. L'audit des agents d'IA juge la configuration de
  l'assistant qui la lance avec les mêmes règles que les autres.

## Baisses par choix

Vanguard ne baisse jamais une protection de lui-même. La personne, elle, peut en baisser une : c'est son ordinateur,
et un réglage trop strict peut gêner un logiciel dont elle a besoin. Ce choix passe toujours par le même chemin, fait
pour qu'un autre programme ne puisse pas le faire à sa place.

**Ce qu'elle peut baisser.** Dans les Options de défense (`vanguard options-defense`, outil 4.10 sous Windows, 4.9 sous Linux) :

- sous Windows, chaque option de Microsoft Defender (temps réel, cloud, envoi d'échantillons, logiciels indésirables,
  protection réseau, accès contrôlé aux dossiers, comportement, téléchargements, scripts, blocage à la première
  détection), une exclusion de l'analyse, un programme permis malgré l'accès contrôlé aux dossiers, chacune des 19
  règles ASR (bloquer, audit ou désactivée), le Pare-feu Windows de chaque profil (allumé, entrées, sorties, tout
  bloquer) et ses règles existantes, et la remise d'une valeur qu'une correction de Vanguard avait changée
  (`--remettre`) ;
- sous Linux, le pare-feu (ufw, firewalld ou nftables), coupé ou rallumé.

Ailleurs, deux baisses seulement, chacune seule et avec la même question : à la sortie du mode Wi-Fi public, chaque
remise qui rend le profil Public moins bloqué (entrées permises, règles entrantes de nouveau suivies) ou remet le
réseau en Privé, dans sa propre fenêtre administrateur (un pare-feu Public trouvé coupé à l'entrée est allumé,
même s'il l'était par choix, et recoupé seulement si la personne le demande, par une question à part) ; sous Linux,
retirer un pare-feu (reconnu par son paquet) des programmes au démarrage. Un service ajouté à la main qui lance un
programme de pare-feu (nft, iptables, ufw, firewall-cmd…), directement ou par un script qu'il nomme (un niveau), ou
qui en pilote un par `systemctl` ou `service`, ne se désactive pas depuis le bilan : un pare-feu se coupe par les
Options de défense.

**Pourquoi c'est permis, et comment.**

- **La baisse part seule.** Une liste qui mêle une baisse à d'autres changements est refusée en entier : une baisse
  ne peut pas se glisser dans une liste de corrections acceptée d'un bloc.
- **Elle est jugée de nouveau, puis montrée.** Le processus administrateur (Windows) ou root (Linux) relit l'état
  lui-même et décide si le geste renforce ou baisse, sans croire ce que la demande en dit. Il montre ce qui change ;
  sous Windows, aussi ce qui protège encore.
- **Elle est confirmée.** La question dit : « Ces changements rendent votre PC MOINS protégé. Les avez-vous demandés
  vous-même, dans Vanguard, à l'instant ? Si ce n'est pas vous, répondez N. » Entrée seule dit non. Sous Windows, la
  réponse n'est lue que d'une vraie console ; sous Linux, sur le terminal de la personne (/dev/tty), jamais sur
  l'entrée du programme. Sans console ni terminal, la réponse vaut non.
- **Elle est notée d'abord.** La valeur d'avant est écrite avant le geste ; si la note ne s'écrit pas, rien n'est
  baissé. Sous Windows, les notes sont sous HKLM `SOFTWARE\Vanguard\ChoixAvant`, que seuls les administrateurs
  écrivent, chacune avec son empreinte SHA-256 : une famille de notes par chemin de remise, toutes sous cette clé
  (les choix des Options, que « Rallumer » remet ; les valeurs changées par une correction, remises par « Ce que
  Vanguard a changé » et « Tout remettre comme avant »), 256 valeurs au plus, et un dépassement dit son remède. Sous
  Linux, elles sont dans `/var/lib/vanguard/avant`, à root, un fichier par geste, avec trois noms fixes pour les
  pare-feu (ufw, firewalld, nftables) : le dossier ne se liste pas et un fichier ne se lit pas sans droits (0711 et
  0600), et une note qui n'est pas à root n'est pas lue. Seul le
  processus administrateur ou root se sert de cette note pour remettre ; la copie gardée dans « Ce que Vanguard a
  changé » ne sert qu'à l'affichage.
- **Elle laisse une trace.** Sous Windows, chaque baisse écrit aussi une entrée dans le journal d'événements de
  Windows (Application, source « Vanguard »), qui reste si Vanguard est retiré. Le bilan dit la protection baissée
  « par votre choix », avec la date, suivie de « Si ce n'est pas vous : Rallumer » : la baisse n'est jamais comptée
  comme saine.
- **« Rallumer » la remet.** Sous Windows, il remet la valeur d'avant si elle protège au moins comme « allumé »,
  sinon la valeur sûre : une note forgée ou abîmée ne fait jamais rallumer plus faible. Sous Linux, il remet l'état
  noté avant la coupure ; sans note, il allume le pare-feu, un renforcement non annulable. Un rallumage n'est jamais
  recoupé par l'annulation.
- **« C'est moi ».** Une protection baissée hors de Vanguard peut être notée « par votre choix »
  (`--noter`), avec la même question ; le bilan cesse alors d'alerter, et « Rallumer » reste proposé.

**Ce que Vanguard refuse, quoi qu'il arrive.**

- **La protection contre les falsifications de Defender** (Tamper Protection) n'est jamais contournée. Quand elle
  bloque un réglage, Vanguard ouvre la page de Windows où elle se trouve : c'est la personne qui la coupe, puis la
  rallume.
- **Les services de défense eux-mêmes.** Vanguard ne propose pas d'arrêter le service de Defender (WinDefend), celui
  du pare-feu (mpssvc) ni le moteur de filtrage (BFE).
- **La session à distance en cours.** Sous Windows, pendant une session à distance (Bureau à distance, SSH, AnyDesk,
  VPN…), ou quand les connexions ne se lisent pas, le pare-feu du réseau en cours ne peut pas tout bloquer, bloquer
  les sorties, fermer un port de la session ni désactiver une règle qui la laisse passer. Couper le pare-feu
  n'ouvre que davantage : ce n'est pas refusé pour cette raison. Sous Linux, un geste de défense ne désactive jamais
  une unité qui porte une session (sshd, l'écran de connexion : gdm, sddm, lightdm…, systemd-logind, dbus, polkit,
  xrdp), ni le réseau, le tunnel, le VPN ou le pare-feu qu'elles traversent, ni le service d'où descend la session de
  Vanguard. C'est un refus, sans question.
- **Les tables nftables des autres.** Couper nftables retire, en une seule transaction et après une sauvegarde
  vérifiée par `nft -c`, chaque table qui n'est pas à Vanguard ; jamais tout le jeu de règles d'un coup. Les tables
  d'iptables-nft (Docker, libvirt, fail2ban…), reconnues à leur nom ou à leur forme, et les tables marquées `owner`
  ou `persist` ne sont jamais retirées ; celles de Vanguard non plus.
- **L'isolement du réseau.** Isoler l'ordinateur garde la session à distance en cours : elle est trouvée avant la
  moindre règle, et si elle ne peut pas l'être avec certitude (tunnel, VPN, connexions illisibles), l'isolement est
  refusé. Il ne retire rien du pare-feu existant ; sa levée ne retire que ce qui porte le nom de Vanguard et remet les
  réglages notés avant, même si la note est perdue (sans note, le pare-feu reste fermé à l'entrée, jamais plus
  ouvert). Sous Linux, l'état est dans des dossiers de root et un état abîmé au démarrage garde l'ordinateur isolé.
  L'isolement automatique d'un rançongiciel quasi certain (accord à part, protection active) passe par la même
  élévation montrée : un programme du compte ne peut ni isoler ni lever sans elle ; le service durci du veilleur ne
  peut pas l'obtenir seul, et l'alerte le dit.

  Ce qui passe encore pendant l'isolement, et ses limites :
  - La session gardée l'est par sa connexion exacte (adresse et port distants, port local 22 ou 3389), dans son seul
    sens : rien d'autre vers cette adresse, et une connexion que ce PC ouvre vers l'extérieur (client SSH) n'est pas
    une session à garder. Une fois coupée, elle ne revient pas, même depuis la même adresse.
  - Pendant l'isolement demandé par la personne, les serveurs de Vanguard ne sont joignables qu'en HTTPS (TCP 443).
    Leurs adresses sont souvent celles d'un hébergeur (CDN) partagées avec d'autres sites : tout site HTTPS servi par
    ces mêmes adresses reste joignable, et un programme hostile peut s'en servir pour sortir des données. L'isolement
    automatique d'un rançongiciel ne garde aucun serveur de Vanguard (l'élevé le décide d'après l'ordre, qui ne peut
    pas en demander) : ce résidu ne vaut pas pour lui, et Vanguard ne se met plus à jour jusqu'à la levée.
  - Le DNS en place reste joignable sur le port 53 : un programme hostile peut faire sortir des données par des noms
    demandés à ce résolveur (tunnel DNS).
  - Sous Linux, une copie de Vanguard tourne en root à chaque démarrage tant que dure l'isolement (bornée par le
    durcissement de son unité) ; elle est copiée du Vanguard qui a demandé l'isolement : s'il vit dans un dossier du
    compte, un programme du compte qui l'a remplacé avant le mot de passe devient root, comme pour toute élévation
    (vérifier le programme avant de le copier est un lot à part).
  - Les sessions que Vanguard ne reconnaît pas sont coupées : mosh (qui continue en UDP), et une session qui passe par
    IPsec sans interface (ESP et IKE ne sont pas gardés).
  - Sous Linux, un `restart` ou un `reload` de nftables remet la table (son unité suit nftables) ; un `systemctl stop
    nftables` ou un `nft flush ruleset` d'un administrateur la retire jusqu'au prochain démarrage, et le bandeau dit
    encore « isolé ».
  - Sous Linux, une machine virtuelle pontée au niveau 2 (réseau « bridged », macvtap, pont relié à la carte réseau)
    n'est pas filtrée par l'isolement : ses trames sont commutées sans passer par les crochets IP de l'ordinateur, sauf
    si `br_netfilter` est actif, ce qui n'est pas le réglage par défaut. Elle garde tout son réseau pendant que
    l'ordinateur est isolé ; une machine virtuelle ou un conteneur routés (NAT de libvirt, Docker) sont coupés.
  - Sous Windows, le pare-feu ne bloque, vers une adresse gardée, que TCP, UDP et ICMP (les autres protocoles vers elle
    passent) ; pendant l'isolement demandé par la personne, une connexion entrante depuis le port 443 d'un serveur de
    Vanguard n'est pas refusée (Windows ne distingue pas une connexion établie) ; le canal UDP de RDP n'est pas gardé (RDP retombe sur TCP) ; les messages
    ICMPv4 d'erreur d'une session gardée (taille de paquet) ne sont pas permis par une règle, et il n'a pas été vérifié
    que le pare-feu les laisse passer ; et le trafic des machines virtuelles (Hyper-V, WSL2) peut ne pas passer par le
    pare-feu de l'ordinateur.

**Les gardes contre le verrouillage (Linux).** Un geste de défense qui peut couper la personne de son ordinateur
(verrouiller root ou son propre compte, retirer le dernier administrateur, rendre sudo, su et pkexec inutilisables)
n'est pas refusé : c'est peut-être ce qu'il faut faire. Il est précédé d'un AVERTISSEMENT, et la question `[o/N]` dit
non par défaut ; s'il ne pourra pas être défait, c'est dit (« non annulable »). Couper le pare-feu alors qu'une
session SSH est peut-être ouverte donne aussi un avertissement : « Si vous êtes connecté de loin, répondez non ».

**Ce que Vanguard ne fait jamais de lui-même.** Aucune baisse ne vient de « Corriger les problèmes trouvés », des
« Réglages recommandés », de « Tout remettre comme avant », de la réponse automatique aux alertes (protection active) ni de la
surveillance. « Tout remettre comme avant » rallume ce qui a été baissé, jamais l'inverse. Le mode Wi-Fi public
allume un pare-feu trouvé coupé et ne le recoupe jamais de lui-même. Sous Windows, un essai vérifie dans le code que
les lignes de baisse ne se fabriquent que dans les Options de défense et à la sortie du mode Wi-Fi public.

**Limite.** Sous Windows, un programme qui pilote le vrai Vanguard peut faire apparaître la question, mais il ne
peut pas y répondre : Windows empêche un programme non élevé d'envoyer des touches à la fenêtre administrateur. Si
Vanguard tourne déjà en administrateur, ou si le contrôle de compte (UAC) est coupé, un programme hostile qui le
pilote est lui-même administrateur : il a déjà gagné (voir plus haut). Il en va de même, sous Linux, d'un programme
qui tourne déjà en root.

**Les alertes déclarées normales.** « C'est normal chez moi » tait une alerte 90 jours (elle revient plus tôt si elle
devient plus grave), dans une liste scellée comme le reste de l'état de Vanguard ; une date à venir ne prolonge rien.
Une alerte à corriger soi-même ne se déclare normale que si sa règle relève ce que le choix lierait : aujourd'hui, sous Linux, seulement une ligne d'une unité systemd de l'utilisateur (sous /etc/systemd/user, seulement si le fichier et chaque dossier de son chemin réel sont à root seul) ou une ligne de lancement (exec-once, exec_on_start…) d'un fichier de ~/.config/hypr, jugé par son chemin réel (un lien qui en sort, du fichier, du dossier ou d'un sous-dossier, n'y est pas) (décision de l'auteur, 10 nov. 2026) : une ligne d'un profil de shell, d'environment.d ou des réglages de systemd, une ligne de Hyprland qui pose une variable ou vient d'un fichier inclus hors de ~/.config/hypr, un lanceur .desktop, une ligne de cron, de préchargement ou d'une unité du système, et une variable de la session restent levés jusqu'au retrait de la ligne (l'information des services du système ajoutés à la main, que seul root écrit, garde son choix lié) (le refus nomme le fichier et la ligne, et dit pourquoi), et un choix d'avant hors de ce périmètre revient à chaque bilan tant que la ligne est là, avec cette raison ; la détection, elle, juge chaque ligne dans la forme que son vrai lecteur exécute, et ce qu'elle ne sait pas ramener à cette forme est levé (« non lu », « non suivi »), jamais compté comme sain (relecture adverse du 11 nov. 2026) : le shell (lignes continuées par « \ ») ; systemd (une unité ou un .desktop tel que systemd l'assemble : « \ » en fin de ligne, fins de ligne « \r » et « \0 », BOM en tête de chaque ligne, commentaires au milieu d'une ligne continuée ; codes « % » remplacés, un code inconnu étant levé ; échappements et guillemets décodés ; chemin simplifié (« //tmp », « /var/../tmp ») ; chaque commande d'une ligne à « ; » ; tous les préfixes « @ - : + ! | » ; les réglages qui changent ce qui se lance sans ligne Exec : LD_PRELOAD et LD_AUDIT toujours, PATH, LD_LIBRARY_PATH, ExecSearchPath et EnvironmentFile quand ils mènent à un dossier caché ou temporaire ; un dossier d'ajouts « .d » qui est un lien, suivi et dit) ; Hyprland tel que le lit hyprlang (lignes jointes par « \ » sans espace ; variables « $nom = … » remplacées sur la valeur entière avant la coupe en champs, la plus longue d'abord, sous tout nom que hyprlang accepte, une variable sans valeur connue dans une ligne qui lance étant levée ; mots-clés dans une catégorie ; raccourcis « bind… » et gestes qui lancent une commande, exec et execr, règles « [ … ] » ôtées ; greffons « plugin » ; clés de hypridle qui lancent (on-timeout, lock_cmd…) ; toute autre clé qui nomme un programme exécutable d'un dossier caché ou temporaire ; « source » suivi, relatif au fichier qui l'inclut et quelle que soit l'extension, une inclusion à variable ou à guillemets étant levée) ; Lua au mieux (texte découpé comme Lua le lit : longues chaînes et longs commentaires, échappements « \ddd », « \xHH », « \z », « \u{…} », appels avec ou sans parenthèses ; les commandes des appels qui lancent, o.bind, hl.bind, exec_cmd, exec_raw, o.launch, hl.plugin.load, os.execute, io.popen, dont l'argument lancé doit être littéral (des chaînes, jointes ou non par « .. » ; depuis la troisième vérification, une valeur posée par « local x = "…" », os.getenv ou une table n'y suffit plus) ; un argument qui ne s'y ramène pas, une fonction de lancement renommée ou redéfinie, load, loadstring, package.path, un require calculé, un accès « os[…] » calculé et ce qui dépasse 4096 appels sont levés ; chaque fichier .lua et .conf de ~/.config/hypr est lu, sous-dossiers compris) ; les dossiers d'unités que systemd lit en plus des habituels (user.attached, chaque XDG_CONFIG_DIRS et XDG_DATA_DIRS que le compte peut changer, et /run/user/<uid> quand XDG_RUNTIME_DIR mène ailleurs, l'écart étant dit) ; les générateurs de systemd des sessions (tout programme d'un dossier du compte, que systemd 262 ne lit pas mais qu'une autre version pourrait lire ; dans un dossier du système, ce qui n'est pas à root seul ; dans un espace de noms d'utilisateurs, seul ce qui appartient au compte, root s'y voyant sous une autre identité) et les unités du dossier de la session (XDG_RUNTIME_DIR/systemd, transient/ de systemd-run compris, jugées par leur contenu) : les raccourcis, les greffons, ce qui est levé « non lu » ou « non suivi », les unités des dossiers lus en plus ou de la session et les générateurs ne se déclarent pas normaux (une ligne de lancement d'une unité du compte ou de ~/.config/hypr que Vanguard ramène à sa forme finale se déclare comme si elle était écrite simplement) ; depuis la deuxième vérification adverse (11 nov. 2026), aussi : chaque commande simple d'une ligne de shell (Hyprland passe ses exec à « /bin/sh -c », Lua ses exec_cmd : après « && », « ; », « | », « & », dans « ( ) », « { } », « $( ) », derrière « cd », une affectation, une redirection d'entrée ou une enveloppe connue comme env, gamemoderun, xdg-terminal-exec, hyprctl dispatch exec ou sh -c), ce qui ne s'y coupe pas sûrement étant levé ; les codes « %u », « %t »… et les variables d'une unité (« $A », « ${A} », « $$ ») remplacés comme systemd les remplace ; les réglages d'unité qui mènent à un dossier caché ou temporaire (WorkingDirectory, StandardInput, RootDirectory, BindPaths, variables qui font charger du code, fichier de variables) ; ~/.config/systemd/user.conf et user.conf.d ; les services D-Bus de la session écrits par le compte (~/.local/share/dbus-1/services, jamais déclarables) ; une inclusion « source » au-delà de 64 fichiers, par un joker dans le dossier ou depuis un dossier temporaire, dite ; Lua lu avec ses portées (paramètres, variables de boucle, « _G », « _ENV », une bibliothèque passée comme valeur), les aides d'Omarchy qui lancent, le require et le dofile résolus comme le chargeur d'Omarchy (~/.local/state, ~/.config, /usr/share/omarchy, puis ~/.config/hypr), un module introuvable ou pris hors des fichiers lus étant levé ; les modules que ce chargeur prend hors de ~/.config/hypr (~/.local/state/default, ~/.local/state/hypr, ~/.config/default, le thème courant, les bascules, les dispositions), jamais déclarables, un module qui en masque un autre étant dit ; un sous-dossier de modules en lien suivi et dit, un dossier à plus de 8 niveaux dit ; une copie conforme de la bibliothèque d'Omarchy (même chemin relatif, même SHA-256, original à root seul) dite en une ligne d'information, ses lignes non comptées ; au-delà des 6 lignes montrées, les autres comptées par fichier ; depuis la troisième vérification adverse (11 nov. 2026), la détection est une liste permise : elle ne se tait que sur une ligne dont toute la forme est reconnue sûre, le reste étant levé « non lu » avec sa raison (forme, programme, lanceur, variable, chemin relatif, réglage d'unité, fichier de variables, longueur), jamais compté comme sain : au shell, seules les commandes simples (sans tube, redirection, sous-commande, joker, bloc, variable inconnue ni commande interne), chaque programme étant un chemin absolu hors d'un dossier temporaire, caché ou de /proc, ou un nom nu trouvé dans les dossiers du système ou du compte (~/.local/bin, ~/.local/share/omarchy/bin, ~/.cargo/bin, exports de flatpak), et chaque lanceur connu (env, setsid, nohup, uwsm app, flatpak run, systemctl, hyprctl, xdg-terminal-exec…) lu selon ses options, une option ou un lanceur inconnu étant levé ; un filet textuel, indépendant de cette lecture, lève en plus au niveau élevé toute ligne qui nomme un dossier temporaire ou caché (/tmp, /dev/shm, /run/user, ~/.x, ./, ../, %t) ; à systemd, une liste fermée de clés par section, une clé inconnue ou une valeur qui ne se vérifie pas étant levée, Environment= lu seulement en [Service] et [Socket], les ajouts « .d » fusionnés à l'unité avant de remplacer ses variables, les unités dont elle dépend suivies, StandardInputText= et StandardInputData= levés, un EnvironmentFile= à joker, relatif, illisible ou trop gros levé, user.conf lu avec ses espaces ; à D-Bus, aussi $XDG_RUNTIME_DIR/dbus-1/services et les dossiers de XDG_DATA_DIRS que le compte peut changer, une adresse « unixexec: » levée ; /var/run, /proc/self/task/<n>/root et /proc/self/cwd ramenés à leur vrai chemin ; les variables qui changent ce qui se lance (HOME, PATH, LD_*, BASH_ENV…) levées ; en Lua, seul l'argument lancé se juge et il doit être littéral (les autres, règles d'exec_cmd ou mode d'io.popen, sont du texte), un nom de module à point levé (Omarchy charge alors a/b.lua) ; une ligne de plus de 8192 caractères levée sans être lue ; les fichiers du système à root seul sautés, sauf dans un espace de noms d'utilisateurs, où root ne se croit pas ; limites de la détection : la liste permise accepte tout chemin absolu hors d'un dossier temporaire, caché ou de /proc, si bien qu'un programme rangé dans ~/.config/x ou ~/bin et lancé par une unité toute simple n'est jamais signalé (~/.local/share/x l'est dans une unité, pas dans Hyprland) ; une variable qui mène à un dossier visible du dossier personnel n'est pas levée ; l'argument d'un programme qui n'est ni un interpréteur ni un lanceur connu n'est lu que par le filet (dossier temporaire ou caché) : un programme hors des listes qui lancerait son argument n'est pas su ; un nom nu se cherche d'abord dans les dossiers du système, alors que le vrai PATH de la session peut mettre ~/.local/bin devant (un programme du compte qui en masque un du système n'est pas dit) ; ce qui est rangé dans les dossiers du compte acceptés se lance sans être signalé ; la ligne Exec= d'un service D-Bus se lit comme systemd la lirait (le bus ne remplace ni code « % » ni variable : un tel mot est levé, jamais tu) ; un « source » vers un dossier caché du dossier personnel (« ~/.dotfiles ») est suivi et jugé sans être dit ; un XDG_STATE_HOME déplacé n'est suivi que pour les modules d'Omarchy ; SYSTEMD_UNIT_PATH et les autres dossiers de systemd posés par variable sont refusés, sans lire les dossiers qu'ils nomment ; Lua n'est pas exécuté : les valeurs posées dans toutes les portées sont réunies, sans suivre l'ordre du programme, hl.env n'est pas jugé, le chemin de modules réel de Hyprland est supposé comprendre ~/.config/hypr et l'ordre de recherche est celui de bootstrap.lua d'Omarchy (relu le 11 nov. 2026), « ./?.lua » (dossier courant) n'est pas résolu (un module qui ne serait que là est dit introuvable), OMARCHY_PATH est jugé là où il est posé (variable qui fait charger du code) et non suivi, et les fichiers de /usr/share/omarchy, à root, ne sont pas lus ; une copie de la bibliothèque d'Omarchy n'est reconnue que si l'original est à root seul, ce qui ne se croit jamais dans un espace de noms d'utilisateurs (unshare -r) : là, ses lignes restent levées, et les fichiers du système à root seul (ajouts « .d » de /etc/systemd/system) y sont jugés eux aussi, d'où des lignes qui n'apparaissent pas hors de lui ; les ajouts que uwsm écrit pour la session (/run/user/<uid>/systemd/user : code « %I », EnvironmentFile=-%t/uwsm/env_session.conf) sont levés : bruit connu, à taire un jour par leur forme exacte ; une valeur Lua posée à part (« local terminal = "kitty" » puis exec_cmd(terminal)) est levée « non lue » : le prix voulu de la liste permise; une alerte critique à corriger soi-même ne se
déclare pas, une ligne en forme de porte dérobée (shell vers le réseau) non plus. Vanguard montre, avant le choix,
chaque ligne signalée sans exception (fichier:ligne, empreinte du fichier, programme, script ou bibliothèque désignés
et leur empreinte) ; le choix se confirme toujours (taper « normal » dès le niveau élevé), seulement au clavier dans
un terminal (entrée et sortie : un choix venu d'un tube est refusé), et l'état est relevé de nouveau à la confirmation
: un fichier changé pendant la lecture fait tout refuser. Chaque choix est noté au journal, et la liste ne s'écrit que
sous son verrou, relue juste avant : deux Vanguard ouverts en même temps ne s'écrasent pas un choix. Le choix est lié
à cet état exact : une ligne ajoutée ou changée, une autre source dans la même alerte, le fichier, un ajout de systemd
(dossiers .d, y compris ceux de la session et de priorité, et ceux d'un XDG_CONFIG_HOME ou XDG_DATA_HOME déplacé),
y compris sous un alias de l'unité ou un alias d'alias et dans /run/systemd/user, le programme lancé ou le script
passé à un interpréteur changé, remplacé par un lien ou effacé, et tout changement d'un fichier qui pose des
variables pour les sessions (profils de bash, zsh et fish, Hyprland et les fichiers qu'il lit par « source = »,
environment.d, configuration du gestionnaire systemd, pam_env), lu en entier, même un commentaire, font revenir
l'alerte, qui dit alors pourquoi et où. Une unité ne se déclare que si chacune de ses directives, et de celles de
ses ajouts, est d'une courte liste fermée (décrire, ordonner, relancer, Type, User, Nice, les variables de la liste
sûre, des dépendances vers des cibles « .target », les lignes Exec) : toute autre (PrivateTmp, JoinsNamespaceOf,
LoadCredential, PAMName, OnFailure, OnSuccess, UnsetEnvironment, une section [Socket]…), un ExecStart= vide, une
dépendance vers un service ou une variable dont la valeur est un chemin la fait refuser ; chaque ligne Exec de l'unité
et de ses ajouts est montrée et liée avec ce qu'elle lance, comme la ligne signalée. Un fichier des variables qui
nomme une variable qui fait charger du code (LD_*, BASH_ENV, ENV, PYTHON*, NODE_OPTIONS, GTK_MODULES…, même échappée, coupée par des guillemets ou par « \ » en fin de ligne : la ligne se lit jointe, comme le shell et environment.d la lisent ; AWKLIBPATH et VSSCRIPT_PATH aussi, hors d'un fichier que seul root peut changer, ce qui ne se croit jamais dans un espace de noms d'utilisateurs) fait tout refuser, et le refus nomme le fichier et la ligne. Les « source » se suivent à
tous les niveaux : ceux de Hyprland, aussi hors de ~/.config/hypr et par un joker dans le dernier nom ; ceux d'un
profil en position de commande, aussi derrière « && » ou dans un « if … fi », par un chemin absolu ou sous ~ ou
$HOME ; aussi coupés par « \ » ; ceux qui ne se suivent pas (chemin relatif ou calculé) sont listés dans le détail. Un lancement d'un fichier que Hyprland lit par « source = » hors de ~/.config/hypr est signalé, sans se déclarer. Le détail montre une ligne
pour les fichiers des variables liés, puis en clair chaque ligne qui pose une variable hors de la liste sûre. Les
dossiers du chemin réel d'un fichier lié, derrière un lien de dossier, sont comparés aussi. ~/.xsessionrc,
~/.bash_logout et les fichiers de zsh sous ZDOTDIR sont lus. Ce qui ne se relève pas sans ambiguïté (une variable, un tube, du code dans la
ligne, un module, un lanceur comme env ou sudo, un ajout qui redirige le programme, son dossier de travail ou son
environnement, une variable de service hors d'une courte liste connue (LANG, TZ, DISPLAY…) ou écrite avec une barre
oblique inversée, un fichier illisible, un octet qui n'est pas de l'UTF-8 dans la ligne, son fichier ou un chemin, un
script au retour chariot ou au caractère invisible, cherchés sur les octets bruts, un fichier lu par un interpréteur
qui n'est pas du texte, l'entrée standard d'un service, un chemin par /proc ou /dev ou avec « . » ou « .. », qui
désigne un autre fichier selon le programme qui le lit, un argument qui n'est ni une option ni un chemin absolu pour un
programme que Vanguard ne reconnaît pas comme interpréteur, y compris après « -- » et dans la valeur d'une option, une
copie d'un interpréteur du système sous un autre nom, ou un programme qui ne se compare pas à eux, un dossier
personnel absent ou qui ne se lit pas, un dossier des démarrages du compte illisible, plus de 12 lignes) ne
peut pas être déclaré normal ; un fichier lié trop long ou qui n'est pas du texte n'est pas montré, ce qui est dit (son
empreinte se compare avec sha256sum) ; la confirmation compare aussi l'appareil, l'inode et les dates de chaque
fichier et de chaque dossier au-dessus de lui, si bien qu'un fichier ou un de ses dossiers échangé puis remis pendant
la lecture se voit ; une liste reprise ou gardée telle quelle après une falsification perd les états qu'elle disait.
Limites : un programme cherché dans le PATH et ce que le script ou le programme lancé lit à son tour (fichier sourcé,
import, bibliothèque, « dofile » d'une configuration Lua) ne sont pas liés ; un programme que Vanguard ne reconnaît
pas peut lire un fichier nommé par une option collée (« -fMakefile ») : rien ne lie ce qu'il lit ; un profil est un
programme : ses variables au nom calculé et les fichiers qu'il lit par un chemin calculé (« . "$DOSSIER/x" ») ne sont
pas suivis (ils sont listés dans le détail), mais son propre contenu est lié ; les variables qui disent où chercher
(PATH, HOME, XDG_*, ZDOTDIR) ou qui choisissent un pilote par son nom (__GLX_VENDOR_LIBRARY_NAME, LIBVA_DRIVER_NAME)
ou qu'un fichier de root pose pour un seul programme (AWKLIBPATH de /etc/profile.d/gawk.sh, d'un paquet de base d'Arch) ne sont liées que par le contenu entier de leur fichier, pas par ce qu'elles désignent, et une variable posée par
« eval » ou par un export au nom calculé ne se voit pas ; la liste fermée des directives et le refus des variables
qui font charger du code font que des unités durcies (ProtectSystem…) ou un compte qui pose LD_PRELOAD ne se déclarent
plus normaux, du côté sûr  ; une variable posée pendant la session (systemctl --user
set-environment) et l'environnement de Vanguard lui-même ne sont pas liés ; un fichier à en-tête ELF mais malformé, à la
place du programme, est lié par son empreinte sans être vérifié comme un texte, alors qu'un shell pourrait le lire ; un fichier lancé de plus de 32 Mio (node, deno)
ou un fichier non ELF de plus de 1 Mio ne se lie pas, donc ne se déclare pas ; les dossiers ajoutés par
XDG_CONFIG_DIRS ou XDG_DATA_DIRS ne sont pas suivis ; l'état n'est comparé qu'à chaque bilan, si bien qu'un programme
qui remet le contenu d'origine avant chaque passage ne se voit pas ; lier tout l'environnement fait revenir les
alertes acceptées à chaque changement d'un profil, de Hyprland ou de /etc/profile.d (une mise à jour de paquet
comprise), du côté sûr, et un dossier du chemin changé entre le bilan et la confirmation fait refuser le choix, à
refaire ; un programme hostile qui ouvre lui-même un pseudo-terminal peut répondre à la place de la personne, mais le
choix reste alors noté au journal ; sous Windows, les clés Run et les tâches se déclarent encore par leur seule ligne
de commande.

## Ce qui sort de l'ordinateur

Les listes de menaces, de versions et de failles sont téléchargées en entier, les mêmes pour tous. Ce que Vanguard
envoie lui-même :

- **Sous Windows**, la liste des logiciels installés ne sort pas : leurs versions sont jugées sur ces listes.
- **Sous Arch Linux, après accord** (Paramètres › Paquets de l'AUR, coupé par défaut) : le nom des paquets
  installés hors des dépôts officiels, à aur.archlinux.org, pour connaître leur dernière version (règle LNX-MAJ-006
  et mises à jour de l'AUR) ; sans cet accord, ces paquets ne sont pas vérifiés, ce qui est dit.
- **Après accord** : l'adresse courriel aux services qui cherchent ses fuites, l'adresse Internet publique aux quatre
  listes noires (Spamhaus, SpamCop, DroneBL, PSBL), le nom du domaine d'un lien examiné.
- **Un mot de passe vérifié** : seuls 5 caractères de son empreinte, à Have I Been Pwned ; jamais le mot de passe.
- **Avec une clé abuse.ch** : la clé, à abuse.ch.
- **En mode Wi-Fi public** : les requêtes DNS, au Bouclier canadien de l'ACEI.
- **La recherche de mise à jour** : une demande à GitHub.
- **Le relevé d'amélioration** : rien dans cette version. Le relais qui le recevra n'est pas déployé et le programme
  n'a pas son adresse ; sans elle, Vanguard ne prépare aucun envoi et n'ouvre aucune connexion (un essai le compte).
  Ce qui partirait un jour, après l'avis montré au lancement ou votre « oui » (avant la 1.0, il faudra répondre
  « oui »), jamais après « Non », est décrit plus bas (« Le relevé d'amélioration et son relais »).
- Un rapport de faille préparé par Vanguard n'est jamais envoyé par lui : la personne le relit et l'envoie elle-même.
- **La porte de lecture pour les assistants d'IA** (`vanguard mcp`) n'envoie rien : elle ne parle qu'au programme qui
  l'a lancée. Mais un assistant branché peut transmettre ce qu'il lit à un modèle en ligne : c'est pourquoi elle
  rend le moins possible (ni chemins, ni lignes de commande, ni comptes, ni adresses, ni secrets), et c'est à la
  personne de choisir l'assistant qu'elle y branche.

Cette liste est fermée : Vanguard refuse de joindre en HTTPS un hôte qui n'est pas dans le premier tableau (même au
bout d'une redirection), et un test du dépôt échoue si le code nomme une destination absente de ces tableaux, ou si
un tableau en nomme une que le code ne joint plus. Un proxy réglé dans le système reçoit les connexions HTTPS de
Vanguard (le chiffrement reste de bout en bout jusqu'au site) ; l'adresse publique jugée par les listes noires est
alors celle de sa sortie.

### Sites joints en HTTPS

| Site | Pour quoi | Ce qui part |
|---|---|---|
| `api.pwnedpasswords.com` | Mot de passe vérifié | 5 caractères de son empreinte |
| `haveibeenpwned.com`, `api.xposedornot.com` | Fuites d'une adresse courriel, après accord (le premier avec une clé) | L'adresse courriel ; la clé de Have I Been Pwned |
| `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `urlhaus-api.abuse.ch` | Listes de MalwareBazaar, ThreatFox et URLhaus | La clé abuse.ch |
| `feodotracker.abuse.ch` | Serveurs de botnets | Rien |
| `raw.githubusercontent.com` | Indicateurs de logiciels espions (Échap) | Rien |
| `www.cisa.gov` | Failles exploitées (KEV) | Rien |
| `www.loldrivers.io` | Pilotes vulnérables | Rien |
| `armmf.adobe.com`, `clients.config.office.net`, `edgeupdates.microsoft.com`, `res.public.onecdn.static.microsoft`, `product-details.mozilla.org`, `versionhistory.googleapis.com`, `versions.brave.com`, `slack.com`, `formulae.brew.sh`, `endoflife.date`, `codeload.github.com` | Dernières versions des logiciels et avis de sécurité, listes entières | Rien |
| `aur.archlinux.org` | Paquets de l'AUR, après accord | Le nom des paquets installés hors des dépôts officiels |
| `github.com`, `release-assets.githubusercontent.com`, `objects.githubusercontent.com` | Mise à jour de Vanguard, pages d'aide tldr | Rien |
| `rdap.org` | Âge du domaine d'un lien examiné, après accord | Le nom de domaine ; rdap.org renvoie la demande au registre du domaine (un seul saut, en HTTPS), seule redirection permise hors de ce tableau |
| `1.1.1.1` | Adresse Internet publique (listes noires), certificat présenté (HTTPS intercepté) | Rien |
| `speed.cloudflare.com` | Débit de la connexion, sur demande | Des octets sans contenu, reçus puis envoyés : environ 500 Mo au plus dans chaque sens |

### Connexions directes

| Destination | Pour quoi | Ce qui part |
|---|---|---|
| `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001` (Cloudflare), `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9` (Quad9), `8.8.8.8`, `8.8.4.4`, `2001:4860:4860::8888`, `2001:4860:4860::8844` (Google), `94.140.14.14`, `94.140.15.15`, `2a10:50c0::ad1:ff`, `2a10:50c0::ad2:ff` (AdGuard), `149.112.121.20`, `149.112.122.20`, `2620:10a:80bb::20`, `2620:10a:80bc::20` (Bouclier canadien) | DNS le plus rapide (questions DNS) ; audit DNS et « Pas d'Internet » (Cloudflare, Quad9, Google) : la connexion s'établit-elle, en TCP 443 ? qualité de la connexion et sonde post-quantique vers `1.1.1.1` | Des noms courants, les mêmes pour tous ; l'adresse Internet publique, comme à tout site |
| `www.amazon.com`, `www.apple.com`, `www.google.com`, `www.microsoft.com`, `www.wikipedia.org`, `www.youtube.com`, `www.example.com` | Noms demandés pour mesurer ou vérifier le DNS | Le nom, au DNS |
| `one.one.one.one`, `dns.google`, `dns.quad9.net`, `internetsociety.org`, `dnssec-failed.org` | Audit DNS : réponses connues, DNSSEC | Le nom, au DNS utilisé |
| `stun.cloudflare.com`, `stun.l.google.com`, `stun1.l.google.com` | Type de NAT, et adresse vue d'Internet à chaque audit complet du réseau (jamais hors ligne) | L'adresse Internet publique et le port, comme à tout site |
| `zen.spamhaus.org`, `bl.spamcop.net`, `dnsbl.dronebl.org`, `psbl.surriel.com` | Listes noires d'adresses, après accord | L'adresse Internet publique, dans une question DNS |
| `dbl.spamhaus.org`, `multi.surbl.org`, `dbltest.com`, `test.surbl.org` | Listes noires de domaines, pour un lien examiné, après accord (et leur nom de test) | Le nom de domaine, dans une question DNS |

Le bilan demande aussi au DNS du système un nom tiré au hasard sous .com, qui ne nomme pas Vanguard (le DNS
invente-t-il des réponses ?), sauf hors ligne. Les noms des sites de ces tableaux passent par le DNS du système,
comme pour tout programme ; en mode Wi-Fi public (et après accord dans « DNS le plus rapide »), ce DNS devient le
Bouclier canadien ou le DNS choisi, pour tout l'ordinateur. La liste des connexions sortantes demande à ce DNS le
nom inverse de chaque adresse distante. Le reste des connexions directes reste sur le réseau local : la box (UPnP, sondes SSH et HTTPS), les imprimantes,
les caméras, le balayage des appareils, LLMNR et mDNS.

### Programmes lancés par Vanguard

Pendant le bilan, sans accord à part, Vanguard demande les mises à jour en attente aux outils du système, qui
interrogent leurs dépôts : checkupdates, dnf, apt, zypper, flatpak, snap, fwupdmgr (micrologiciels, LVFS) ; yay ou
paru seulement avec l'accord pour l'AUR. Sur demande ou après accord, il lance des programmes qui joignent leurs
propres serveurs : le gestionnaire de paquets (pacman, apt, dnf, winget), flatpak (`dl.flathub.org`), freshclam pour
ClamAV, la mise à jour des signatures de Defender, trivy pour les conteneurs (sa base de failles) ; nmap, lui,
n'interroge que les appareils du réseau local. Une page ouverte dans le navigateur après accord (pages de
« Signaler », portail du Wi-Fi public : l'adresse de la sonde du système, celle de NetworkManager sous Linux, montrée
avant) est jointe par le navigateur. Une extension ajoutée par la personne a le réseau de l'ordinateur, sauf lancée
isolée (Linux). Ces destinations dépendent de ces programmes, pas de Vanguard.

### Le relevé d'amélioration et son relais

Depuis la 0.89.1, Vanguard tient un relevé local de son propre fonctionnement, pour que l'auteur sache ce qui échoue
ou ralentit chez les autres. Quatre étapes ; les deux dernières n'ont pas lieu tant que le relais n'est pas déployé,
ce qui est le cas aujourd'hui :

- **Sur l'ordinateur.** Le relevé note chaque jour, en comptes agrégés, les erreurs de Vanguard, ses lenteurs, le
  résultat des corrections et les choix faits dans Vanguard, avec la plateforme réduite à une liste fermée. Une voie
  ouverte y garde des noms, parce qu'un problème se comprend mal sans eux : nom et version des logiciels, services et
  pilotes en cause, modèle du processeur et de la carte graphique (sans numéro de série), textes d'erreur nettoyés par
  `amelioration::texte` (chemins, adresses et jetons retirés) ou jetés en entier. Il ne contient jamais : le contenu
  d'un fichier, les arguments d'une commande, un mot de passe, l'historique du navigateur, un texte tapé, la liste de
  vos fichiers, de vos comptes, de vos réseaux ou de vos appareils, ni l'inventaire de vos logiciels. Il est rangé
  dans `amelioration/` (scellé, 96 Kio par jour au plus, 90 jours, 10 Mo au total) et le lot qui en sortirait se lit,
  octet pour octet, par « Voir ce qui serait envoyé ». Répondre « Non » au partage l'efface, avec la file d'envoi et
  l'identifiant d'installation ; ce « Non » est aussi noté à part (`partage-non`), qu'une version plus ancienne qui
  réécrit les paramètres ne touche pas, et tient jusqu'à un « Oui » donné dans Vanguard. `VANGUARD_ENVOI=0` le
  coupe.
- **La file d'envoi, sans hôte.** `RELAIS` est vide dans le code et la liste fermée des sites HTTPS (`HOTES`, le
  premier tableau ci-dessus) ne contient aucun relais : aucun lot n'est préparé, aucun fichier d'envoi n'est écrit,
  aucun fil ni aucune connexion n'est lancé. Même avec un relais, rien ne partirait sous les essais, sous Wine, dans
  la CI, avec `VANGUARD_ENVOI=0`, depuis une clé, en root (Linux), dans une compilation de développement, hors ligne,
  ni avant l'avis montré au lancement ou votre « oui » (avant la 1.0, il faudra répondre « oui »), ni après « Non » au
  partage, ni pour ce qui a été relevé avant le jour de l'accord.
- **Le relais, une fois déployé.** Son adresse entrera alors dans `HOTES` et dans le premier tableau, au même titre
  que les autres sites. Vanguard ne le joindra qu'en HTTPS, sans suivre de redirection ; il n'enverra qu'un lot par
  jour au plus (96 Kio, relu strictement avant de partir), avec un identifiant d'installation tiré au hasard et
  renouvelé tous les 90 jours ; trois essais par jour au plus, 24 h d'attente après un 429 ou un 503, sept jours
  gardés au plus. Seul le code de réponse est lu, jamais le corps : il n'existe aucun canal descendant, et aucune
  consigne, règle ni mise à jour ne peut venir par le relais. Le code du relais est dans le dépôt (`relais/`) : il
  contrôle le même schéma, strictement, et une couche du détecteur de secrets, refuse un lot où elle sonne (la lecture
  stricte complète est refaite chez l'auteur), ne garde pas l'adresse IP (une empreinte de son préfixe, au sel tiré
  chaque jour et effacé le lendemain) et efface ce qui n'est pas relevé après 14 jours.
- **Chez l'auteur.** Chaque lot relevé est relu comme s'il venait de n'importe qui : la même lecture stricte, les
  refus comptés, une quarantaine pour tout lot où le détecteur de secrets sonne (jamais lu plus loin). Une source
  (l'empreinte du préfixe d'adresse) ne compte qu'une fois par jour, quel que soit son nombre de lots, et un signal
  demande au moins 5 sources dans 3 réseaux /16. Un faux positif probable, la voie qu'un empoisonneur prendrait pour
  faire assouplir une règle, ne va jamais à l'IA de la veille : seulement dans un ticket, que l'auteur juge. Les noms
  et textes venus des lots n'entrent dans un ticket que dans un bloc de données fermé par un marqueur tiré au hasard,
  que ces données ne contiennent pas (`~~~~donnees-` suivi de 16 chiffres hexadécimaux), et un nom jamais approuvé par
  l'auteur ne paraît ailleurs que par son empreinte (`inconnu#…`). Rien d'un lot n'est une consigne, et la veille ne
  fusionne ni ne pousse jamais rien.
