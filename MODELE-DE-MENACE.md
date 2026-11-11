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
| Une faiblesse de réglage ou une faille non corrigée | Bilan noté de A à F, mises à jour manquantes, failles activement exploitées du catalogue de la CISA, fin de support ; chaque correction après accord, annulable sauf celle qui rallume une protection (pare-feu, antivirus, chiffrement, UAC, SELinux, durcissement du noyau sous Linux, durcissement de Windows et protections de Defender). Baisser une protection reste le choix de la personne, jamais celui de Vanguard (voir [Baisses par choix](#baisses-par-choix)). |
| Une exposition vers Internet | Ports que le routeur ouvre (demandés au routeur lui-même, ouvertures UPnP comprises), IPv6 publique sans pare-feu ; dans les journaux, les mots de passe devinés et les connexions au Bureau à distance depuis l'extérieur. |
| Un intrus sur le réseau local ou le Wi-Fi | Inventaire des appareils et des nouveaux venus, faux point d'accès, DNS et certificats détournés ; mode Wi-Fi public en déplacement. |
| Un proche qui surveille la personne | Logiciels espions, prise de contrôle à distance (faux technicien). |
| Une arnaque | Liens examinés sans les ouvrir, fichiers téléchargés vérifiés, fuites de comptes. |
| Un agent d'IA qui agit trop | Serveurs d'IA ouverts au réseau, agents qui agissent sans demander, serveurs MCP mal protégés. |

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
  La vraie parade, un service qui tourne sous un autre compte que le vôtre (administrateur), est prévue pour une
  version à venir.
- **La personne décide.** Rien n'est modifié sans son accord. Ce qu'elle accepte s'annule une correction à la fois,
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

## La fenêtre

`vanguard` sans argument ouvre la fenêtre de Vanguard (`vanguard-fenetre`, un programme à part posé à côté de
`vanguard`) quand la personne est devant un écran graphique ; sinon, le menu du terminal, comme avant. Ses gardes :

- **Elle ne fait rien d'elle-même.** Elle relance le programme `vanguard` posé à côté d'elle (chemin absolu, jamais
  cherché dans le PATH) avec une commande d'une liste fermée, qui ne change rien à l'ordinateur
  (`audit`, `protection`, `evenements`, `diagnostic`, `test-connexion`…), toujours en `--json`, sans argument libre,
  sans shell, entrée fermée, une à la fois, avec un délai et un bouton Arrêter (sous Linux, tout le groupe de
  processus est arrêté, et ce qui en reste à la fin de la commande aussi ; `vanguard` n'est récolté qu'après, pour
  que ce numéro de groupe ne puisse pas être celui d'un autre ; un processus sorti du groupe qui garderait les sorties ouvertes n'y retient pas la fenêtre, qui lâche les tuyaux). La console de la fenêtre n'accepte que les noms de cette liste. Sous Linux, ce `vanguard`
  doit être un fichier ordinaire au compte de la fenêtre ou à root, que ni le groupe ni les autres ne peuvent
  modifier, dans des dossiers (jusqu'à `/`) que ni le groupe ni les autres ne peuvent modifier non plus (sauf un
  dossier à « sticky bit », comme `/tmp`), sinon il n'est pas lancé : la même règle que pour la fenêtre, plus bas,
  revérifiée avant chaque commande, et pas seulement à l'ouverture.
- **Un seul changement, en deux temps : un programme du démarrage.** L'écran du démarrage montre l'état de chaque
  programme qui se lance à l'ouverture de session. Un programme ordinaire a « Retirer du démarrage », un programme
  retiré par Vanguard a « Remettre » ; un programme à garder ou un pare-feu n'a aucun bouton, sa raison est dite. Un
  clic n'ouvre qu'une confirmation dans la fenêtre (nom, commande, ce qui va se passer, fenêtre administrateur si le
  programme est de tout l'ordinateur) ; seul « Accepter » lance le changement, un à la fois, boutons grisés pendant
  qu'une commande tourne, sans « tout retirer ». La fenêtre ne propose que les gestes que `vanguard demarrage --json`
  vient d'écrire, et n'envoie que la sorte (retirer ou remettre) et l'empreinte du programme (32 chiffres
  hexadécimaux, calculée par `vanguard`) : jamais un nom, une commande ou un chemin. La forme lancée est fermée,
  `vanguard demarrage --retirer|--remettre <empreinte> --json`, et `vanguard` rejuge tout : empreinte mal formée,
  inconnue, ambiguë, programme à garder, pare-feu, notes de Vanguard illisibles ou changées hors de Vanguard (ni
  retrait ni remise tant qu'elles le sont), « remettre » un programme qui se lance déjà (remis ou réécrit hors de
  Vanguard, peut-être devenu un programme à garder : la vieille note ne l'écrase pas, ni par l'annulation d'un blocage
  ni par « Tout remettre comme avant »), tout est refusé sans rien changer ; ce qui change passe par la même correction que le terminal (point de restauration,
  valeur d'avant notée, une seule fenêtre administrateur, jamais sudo). La console ne lance aucun changement, sous
  aucune forme tapée. « Accepter » revérifie que le geste est encore dans la dernière liste lue : une liste relue qui
  ne le contient plus ferme la confirmation (« La liste a changé : rien n'a changé. »), comme changer d'écran ; la
  veille des alertes continue pendant qu'une confirmation est ouverte. Un changement lancé ne s'interrompt pas (le
  couper au milieu laisserait un état à moitié fait) : Arrêter n'y fait rien, et sous Linux la fermeture de la fenêtre
  non plus (le relais le laisse finir) ; on l'arrête en refusant la fenêtre administrateur. Seul son délai, 15 minutes
  (la fenêtre administrateur de Windows peut attendre), le coupe. Côté `vanguard`, un changement tient le verrou des
  notes (`reglages.verrou`) de leur lecture à leur dernière écriture, comme l'optimiseur du terminal et « Tout
  remettre comme avant » : deux Vanguard ne changent pas les notes en même temps, le second refuse sans rien changer.
  « Remettre » relit les notes sous ce verrou et exige le même réglage noté qu'à la première lecture (sinon refusé,
  rien écrit) ; « Retirer » un programme qui se lance remplace une vieille note restée d'avant par la valeur lue
  maintenant, pour que « Remettre » ramène l'état d'avant ce retrait-là. Sous Linux, cette valeur d'avant (l'entrée
  d'autostart) est lue en une seule ouverture qui ne suit pas un lien, n'attend pas un tube et s'arrête à 64 Kio :
  sinon refusé, rien changé (une entrée qui est un lien ne se retire donc pas d'ici). Chaque changement fait ou refusé
  est écrit au journal des événements (sorte, nom nettoyé, issue, empreinte) ; un refus identique au précédent (même
  empreinte, même sorte, même raison) ne s'y réécrit pas pendant 10 minutes, pour qu'une rafale de demandes ne noie pas
  les alertes ; un changement fait s'y écrit toujours. Sa fin est dite (fait, refusé, échec, avec la
  raison), puis la liste est relue ; seule la dernière ligne de la sortie, un JSON du même geste, avec le code 0, dit
  « fait » : tout le reste est un échec, jamais un succès (`fenetre/src/attaques.rs`, essais B1 à B3). Essais :
  `une_confirmation_ne_bloque_rien_et_suit_la_liste` (`fenetre/src/appli.rs`), les essais du relais
  (`fenetre/src/relais.rs`), `verrou_des_notes_tenu_puis_rendu` et ceux de `src/optimiser/demarrage.rs`
  (`seul_un_programme_note_se_remet`, `pare_feu_reconnu_par_son_paquet`),
  `valeur_d_avant_d_autostart_ni_lien_ni_tube_ni_trop_gros` (`src/optimiser/linux.rs`), et de bout en bout, avec un
  dossier personnel jetable, `demarrage_retire_puis_remet_a_l_octet_pres` et le module `demarrage_sous_attaque`
  (`tests/programme.rs` : remise par-dessus un programme qui se lance, par la fenêtre et par « Tout remettre comme
  avant », retrait sur des notes douteuses, changements simultanés, lien, verrou tenu, notes forgées ou rejouées,
  refus répétés).
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
- **Aucune connexion, aucun fichier.** La fenêtre n'ouvre aucune porte réseau, aucun serveur, aucune page web, et
  n'exécute aucun JavaScript (aucune bibliothèque HTTP parmi ses dépendances) ; elle n'écrit aucun fichier (thème et
  langue ne sont pas gardés). Les commandes qu'elle lance joignent Internet comme dans le terminal (par exemple
  `test-connexion`, `logiciels-perimes`).
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
  pas posée à côté, quand (sous Linux) elle n'est pas un fichier ordinaire à ce compte ou à root que ni le groupe ni
  les autres ne peuvent modifier, dans des dossiers que ni le groupe ni les autres ne peuvent modifier, ou quand elle
  ne dit pas « ouverte » dans les 20 secondes. `vanguard --menu` force
  le menu.
- **Ses bibliothèques.** Sous Windows, comme `vanguard.exe`, elle ne charge ses DLL que de System32 : celles qu'elle
  importe (DependentLoadFlags), et celles qu'une bibliothèque ouvre par leur nom après le démarrage
  (SetDefaultDllDirectories, première ligne du programme ; opengl32.dll par exemple). Une DLL posée à côté d'elle,
  sur la clé ou dans Téléchargements, n'est jamais chargée. Sous Linux, elle est liée à la glibc du système (ses
  bibliothèques d'affichage se chargent à l'exécution) : seul l'interpréteur `/lib64/ld-linux-x86-64.so.2` est
  permis, sans dossier de bibliothèques écrit dans le programme (ni RPATH ni RUNPATH), vérifié à chaque passe de
  `outils/verifier.sh` (`vanguard deploiement verifier-binaire --glibc`).
- **Limites.** Comme le programme, elle suppose que son dossier n'est modifiable que par vous : qui peut remplacer
  `vanguard-fenetre` peut aussi remplacer `vanguard`. Sous Windows, la fenêtre et `vanguard` ne vérifient que le fait
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
  chacun au journal et chacun se remet. Les notes de Vanguard et leurs sceaux (`src/sceau.rs`) sont une barrière
  contre un fichier posé par un autre programme, pas un coffre : un programme de votre compte qui garde une copie des
  notes avec leurs sceaux peut la reposer plus tard ; « Remettre » ramènerait alors une ancienne valeur notée d'un
  programme qui ne se lance plus (par-dessus un programme qui se lance, c'est refusé : `notes_forgees_ou_rejouees`).
  Le journal des événements est borné (13 mois, 20 Mio en tout, les plus vieux mois partent d'abord) : des refus
  identiques ne s'y écrivent qu'une fois par 10 minutes (`des_refus_repetes_ne_noient_pas_le_journal`), mais des
  demandes pour des empreintes toutes différentes s'écrivent chacune, et assez d'entre elles pousseraient de vieilles
  alertes hors du journal. Sous Windows, il n'y
  a pas de relais : ces bornes-là sont celles de `vanguard` seul, et fermer la fenêtre arrête aussi un changement en
  cours (objet de travail) ; la valeur d'avant étant notée avant tout changement, il se remet quand même.

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
Une alerte à corriger soi-même ne se déclare normale que si sa règle relève ce que le choix lierait : aujourd'hui, les
programmes lancés au démarrage et les préchargements sous Linux ; une alerte critique à corriger soi-même ne se
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
nomme une variable qui fait charger du code (LD_*, BASH_ENV, ENV, PYTHON*, NODE_OPTIONS, GTK_MODULES…, même échappée
ou coupée par des guillemets) fait tout refuser, et le refus nomme le fichier et la ligne. Les « source » se suivent à
tous les niveaux : ceux de Hyprland, aussi hors de ~/.config/hypr et par un joker dans le dernier nom ; ceux d'un
profil en position de commande, aussi derrière « && » ou dans un « if … fi », par un chemin absolu ou sous ~ ou
$HOME ; ceux qui ne se suivent pas (chemin relatif ou calculé) sont listés dans le détail. Le détail montre une ligne
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
ou qu'un seul programme lit (AWKLIBPATH, posé par un paquet de base d'Arch, VSSCRIPT_PATH) ne sont liées que par le contenu entier de leur fichier, pas par ce qu'elles désignent, et une variable posée par
« eval » ou par un export au nom calculé ne se voit pas ; la liste fermée des directives et le refus des variables
qui font charger du code font que des unités durcies (ProtectSystem…) ou un compte qui pose LD_PRELOAD ne se déclarent
plus normaux, du côté sûr ; un « exec-once » de Hyprland dans un fichier inclus hors de ~/.config/hypr n'est pas
encore signalé ; une variable posée pendant la session (systemctl --user
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
