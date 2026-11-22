# Historique des versions

*[English](CHANGELOG.en.md)*

Ce que chaque journée a apporté à Vanguard, la plus récente en haut. Depuis le 19 octobre 2026, Vanguard a en principe
une seule publication par jour, qui regroupe le travail de la journée ; le 21 octobre en a eu deux, la 0.82 au matin et
la 0.84 au soir, qui reprend la 0.83 livrée juste avant elle. Depuis le 7 novembre 2026, plus d'une publication le même
jour est permise ; elles se suivent dans le paragraphe de leur journée. Seule la dernière version a sa page de
téléchargement et garde son étiquette dans le dépôt. Le commit de chaque version porte son numéro à la fin de son
titre : `git log --oneline -F --grep '(v0.62.0)'`, par exemple, le retrouve, pour la recompiler au besoin.

## 0.98 (en préparation)

- **Touche « / » partout.** Dans n'importe quel menu, « / » ouvre « Rechercher dans Vanguard » : les outils, les
  réglages et le guide entiers, ouverts comme depuis l'accueil ; Échap ramène au menu d'où vous veniez. Dans une
  liste à cocher, « / » ne filtre que la liste, pour garder les cases déjà cochées.
- **Pastilles des commandes du guide.** La page d'une commande montre « ⚠ modifie le système », « Administrateur »,
  « Fenêtre » ou « Longue », tirées de ce que le guide sait déjà d'elle.
- **Guide Windows : les commandes administrateur le disent.** Les commandes que Windows refuse hors d'un
  terminal administrateur (netsh, chkdsk /f, powercfg, sc.exe, pnputil, reagentc…) le disent, et sfc et DISM sont
  marquées longues ; un essai empêche d'en ajouter une sans marque.
- **Guide : par thème.** Le menu du guide gagne « Par thème » (10) : paquets, réseau, disques, sécurité, services,
  matériel, comptes, démarrage, outils. Chaque thème montre d'abord les programmes de votre système, puis ceux des
  autres, chacun avec son chemin (« 6.11 ipconfig »), qui ouvre la même page.
- **Guide : communs à Linux repliés.** Le menu d'une distribution montre ses pas-à-pas et ses programmes, puis une
  seule ligne « Commandes communes à Linux » qui les ouvre. Leurs numéros ne changent pas : « 1.20.3 » marche
  toujours, au menu comme dans vanguard guide, qui les montre encore tous.

## 22 novembre 2026 : version 0.97.0

- **Dépanner avec Claude, depuis la clé : une option, coupée par défaut, et un téléchargement vérifié.** Claude Code,
  l'assistant d'Anthropic, peut voyager sur la clé pour dépanner l'ordinateur d'un proche ; `CLAUDE_CLE=oui` dans
  `~/.config/vanguard/images-cle.conf` l'allume. Chaque jour (minuterie vanguard-claude-cle.timer, allumée seule au
  dépôt suivant si elle manque), Vanguard prend la version qu'Anthropic annonce « stable » et la vérifie : la signature
  d'Anthropic sur la liste des empreintes, avec la clé fixée dans Vanguard et reconnue par son empreinte, jamais une
  clé lue sur le serveur (une clé expirée ou révoquée dans cette copie est refusée), puis la taille et l'empreinte de
  chaque binaire. Une version plus ancienne que la dernière vérifiée est refusée, au téléchargement comme sur la clé,
  et notifiée une fois par annonce. `outils/claude-cle.sh --etat` dit ce que contient le cache et distingue « ne se
  vérifie plus » (code 1) de « vérification impossible ici » (code 3, un dossier temporaire plein par exemple), qui
  n'efface rien ; une panne qui revient après un succès est notifiée de nouveau. Le dépôt pose Claude Code sur la clé
  avec ses consignes de dépannage : diagnostiquer en lecture seule, expliquer la cause avant de corriger, ne rien
  changer sans accord, ne jamais baisser la sécurité, respecter la vie privée du proche.
- **Sur l'ordinateur visité, le lanceur vérifie avant de lancer, puis efface.** « Depanner avec Claude.bat » sous
  Windows (10 version 1809 ou plus récent), `bash -p …/Claude/depanner.sh` sous Linux ou sur SystemRescue démarré
  depuis la clé. Le lanceur demande d'abord l'accord du propriétaire de l'ordinateur, puis revérifie le programme
  copié : sous Linux, la signature d'Anthropic sur la liste des empreintes et l'empreinte ; sous Windows, la signature
  Authenticode contrôlée par Windows, faite par « Anthropic, PBC » (nom, pays, numéro d'entreprise et registre du
  Delaware, lus champ par champ dans les octets du certificat, chacun une seule fois et à sa valeur exacte), et
  l'empreinte. Rien n'est installé : le programme tourne d'un dossier temporaire à soi, effacé en sortant, et la
  connexion au compte Claude n'est jamais écrite sur la clé. Les connecteurs du compte et les serveurs MCP ne sont pas
  chargés, le navigateur de cet ordinateur ne s'ouvre pas (l'adresse de connexion s'ouvre sur le téléphone), et les
  journaux de Claude Code de la session partent avec le dossier. En sortant (/exit, Ctrl+C, terminal fermé ; sous
  Windows, un gardien si la fenêtre est fermée par sa croix), le lanceur déconnecte le compte, en temps borné :
  « Déconnecté » n'est dit que si Anthropic a confirmé la fin de la connexion, sinon il demande de la terminer sur
  claude.ai. Ce qui n'a pas pu être effacé est nommé, jamais compté comme effacé ; un disque du proche monté dans le
  dossier de la session n'est jamais effacé, et c'est dit. Une session laissée en plan (panne, terminal tué) est
  déconnectée puis effacée au lancement suivant.
- **Ce que le lanceur refuse.** Un dossier temporaire partagé (/tmp, /var/tmp), ou sous un dossier qu'un autre compte
  peut écrire ; des consignes posées pour Claude au-dessus du dossier de travail (CLAUDE.md, CLAUDE.local.md,
  AGENTS.md, .mcp.json, un dossier .claude) ; des réglages imposés à Claude Code par l'ordinateur (/etc/claude-code,
  C:\Program Files\ClaudeCode, stratégies du registre). Seule exception : le dossier .claude du dossier personnel
  (Claude Code déjà utilisé sur cet ordinateur), où seules des consignes font refuser ; sous Windows, seulement si le
  chemin du dossier personnel au dossier de session ne passe par aucun lien ni jonction. Sous Windows sont aussi
  refusés un dossier temporaire hors d'un disque local en NTFS ou ReFS, un TEMP de plus d'environ 140 caractères
  (Claude Code y couperait le nom de son journal, qui resterait), et toute commande de PowerShell qui ne vient pas de
  Windows : les vérifications passent par les modules de Windows, pris par leur chemin, et un module posé dans le
  compte ou une commande chargée en mémoire font refuser. Avant toute commande de Claude Code, l'environnement du PC
  qui choisirait le serveur, le compte, le mandataire, les certificats, le traçage ou du code à charger est retiré, et
  le profil Anthropic de cet ordinateur n'est pas lu. Sous Linux, le lanceur se relance avec `bash -p` : ni une
  fonction ni une option de bash exportée par le PC n'est suivie, ni donnée à Claude Code et à ses commandes, et ses
  propres commandes (gpg, sha256sum…) viennent des dossiers du système, jamais du PATH du PC. Sous WSL, les réglages
  imposés de Windows font refuser ; la politique du registre n'est pas lue d'ici : c'est dit, et l'accord est demandé.
- **Sur la clé, chaque binaire est relu au retour, et un seul sort est dit.** Chaque binaire posé est noté (son
  empreinte) et relu entier au dépôt suivant, comme avant la reprise d'un déploiement arrêté. Un binaire changé
  pendant le voyage est dit et notifié avant la copie, même si le dépôt s'arrête ensuite, puis remplacé par la copie
  vérifiée ; sans copie à remettre, il est retiré, sauf s'il fait partie d'une version signée qui se vérifie entière
  (« signé et vérifié, laissé »). Un binaire sans note de dépôt est dit « laissé sur la clé, PAS vérifié ni
  remplacé ». Chaque binaire a un seul sort (remplacé, retiré, laissé ou gardé), jamais un « remplacé » qui n'a pas eu
  lieu. Une clé qui porte une version signée plus récente que le cache, posée d'un autre ordinateur, est gardée sans
  faire monter la protection contre le retour de cet ordinateur ; cache absent ou vide, une version signée de la clé
  est vérifiée par son propre manifeste signé et dite signée et vérifiée, mais pas posée d'ici. Ces alertes sortent en
  code 2, que `outils/deployer.sh` dit comme une alerte sur un binaire de Claude/, sans prétendre « remplacé ».
  Réglage coupé, seul ce que Vanguard a posé est retiré de la clé, et seulement si la note de cette clé existe.
- **Lever un blocage de version : `outils/claude-cle.sh --accepter-version X`, et `--annuler-acceptation`.** Le
  pointeur « stable » n'est pas signé : une version authentique plus récente, prise une fois, bloque ensuite les plus
  anciennes. Seul le propriétaire lève ce blocage. Dans un terminal seulement, la commande exige une version écrite
  simplement (2.0.6, pas 2.00.6), présente dans le cache ou dernière annonce refusée ; elle montre ce qui change,
  demande de taper « ACCEPTER X », puis le mot de passe d'administrateur (fenêtre polkit qui affiche « Vanguard :
  baisse de protection, Claude Code X ») ; un refus ne change rien. Le journal (~/.local/state/vanguard) est écrit
  avant la baisse, sans quoi rien ne change ; les versions plus hautes du cache sont déplacées de côté, jamais
  effacées, et plus reprises si le serveur les annonce de nouveau (notifié une fois, dit par `--etat`) ; chaque baisse
  est notifiée. `--annuler-acceptation`, dans un terminal en tapant « ANNULER », sans polkit puisqu'elle remonte la
  protection, remet d'après une trace gardée hors du cache la note d'avant et les versions qui se vérifient encore ;
  une vérification impossible pour l'instant rend l'annulation « partielle » (code 2), la trace est gardée et la
  commande est à relancer ; une note vide ou abîmée n'est jamais réécrite. Les deux commandes passent d'abord une
  porte, tout en haut du script, faite seulement d'affectations, d'expansions et de `[[ ]]` (aucune fonction ne la
  remplace) et lue en locale C : une fonction de bash exportée, BASH_ENV, ENV, SHELLOPTS, BASHOPTS ou un environnement
  illisible font refuser, rien changé, fenêtre polkit pas demandée. Elles se relancent ensuite dans un bash propre
  (`env -i`, une liste fermée de variables) et le vérifient : toute autre variable, une option de bash, une fonction,
  un alias, un piège (trap) ou un builtin coupé font refuser de même.
- **Limites dites, aussi dans le mode d'emploi de la clé.** Sur l'ordinateur visité, le lanceur prouve « signé par
  Anthropic », pas « dernière version » : une clé restée au tiroir, ou rechargée avec une version plus ancienne mais
  signée, passe ; Vanguard la voit au retour. Une révocation publiée plus tard par Anthropic n'est connue qu'avec une
  mise à jour de Vanguard. Le lanceur voyage avec le programme : il voit une copie abîmée, pas une clé réécrite en
  entier. Sous Linux, lancé sans `-p`, ce que le PC a exporté pour le traçage ou BASH_ENV tourne avant la première
  ligne ; sans gpg, la signature d'Anthropic ne se vérifie pas : c'est dit, et l'accord est demandé. Sous Windows, la
  liste des empreintes n'est pas vérifiée par une signature (seule la signature Authenticode du programme l'est),
  Claude Code se fie aux certificats installés dans Windows, un C:\.claude apparu pendant la session n'est pas vu, et
  Set-StrictMode et Import-Module, pris par leur type .NET, ont été essayés sous Windows PowerShell 5.1 d'un vrai
  Windows 11, seuls puis dans le lanceur entier (avec un faux claude.exe). Un virus qui tourne déjà sous le même
  compte peut lire la connexion pendant la session. La porte de `--accepter-version` arrête un environnement piégé,
  hérité ou posé par mégarde, une minuterie ou un programme lancé sans personne devant l'écran, pas un programme qui
  a déjà le compte : il peut déplacer les dossiers du cache à la main, et une telle baisse n'est ni signalée ni notée
  (seules celles de la commande le sont) ; la fenêtre polkit est la demande générale de pkexec, qu'un programme du
  même compte peut imiter. Windows et Linux 64 bits (x86-64) seulement. Le lot a passé plusieurs relectures adverses
  et une campagne d'attaque, et le lanceur Windows a été essayé sur un vrai Windows 11, en plus de PowerShell sous
  Linux avec des doublures.
- **Le journal des erreurs et le brouillon de `vanguard signaler` passent par le masquage commun**, le même que les
  textes envoyés : numéros de série, mots de passe après `-p` ou `--password`, `net use`, clés Wi-Fi, jetons, adresses
  MAC et IP (toutes, en « <mac> » et « <ip> »), chemins (« <chemin .ext> ») et adresses web (« <url> »). Le texte
  montré est celui qui est écrit puis envoyé ; un faux repère écrit dans un message (« <ip> » au milieu d'un jeton)
  est désarmé. La commande écrite au journal est réduite argument par argument : il n'en reste que les sous-commandes,
  les options connues et les mots de l'aide ; un fichier devient « <chemin .pdf> », un lien « <url> », un mot libre
  « <valeur> » ; le journal, la porte et le brouillon posent le même marqueur. Un nom de fichier nu (« CV-Bob-Exemple.pdf », « Zoé.Tremblay.docm ») est masqué d'après une liste fermée d'extensions
  (documents, archives, sons, programmes…) ; l'extension montrée est toujours une extension connue, jamais la suite d'un
  nom (« jean.tremblay ») ni celle d'un dossier de compte (« prenom.nom » sous /home) ; un dossier personnel est remplacé par
  « ~ » avant le masquage, même avec une espace ; un chemin sous un dossier personnel (maison, « ~ », « Users\x »,
  « /run/media/x », « Documents/… », « file:// » d'une maison) est retiré jusqu'à la fin de la ligne, ou jusqu'au
  guillemet qui le ferme ; ailleurs, un nom à espaces est pris jusqu'au guillemet ou à la parenthèse qui le ferme, ou
  jusqu'à « : » ; un chemin coupé à gauche par « … » est retiré jusqu'à la fin de la ligne, et un extrait coupé
  commence par « … » puis au début d'un mot ; « //hôte/… » n'est une adresse web que collé derrière « " ' = ( »,
  ailleurs c'est un partage réseau ; une adresse web est retirée entière, quel que soit son schéma, commencée par
  « www. » ou « // », ou avec une seule barre (« https:/… »), une requête collée à un chemin partant avec lui jusqu'à
  la fin de la ligne,
  même collée à une option (« --url=https://… ») ; un secret est masqué avant et après l'anonymisation, qui
  pouvait cacher son début (« -u alice:… ») ; un champ fichier ou programme du brouillon est remplacé en entier ; une
  valeur trop longue est coupée à une espace avant le masquage ; seule la version du noyau est gardée, sans sa suite.
  Les entrées écrites avant la 0.97 ne partent plus seules sur GitHub : elles attendent l'accord de l'auteur
  (`--accord`), et c'est dit. Limites : le diagnostic perd le préfixe du fabricant des MAC, les chemins et les IP ; les
  tickets d'erreurs déjà ouverts peuvent revenir sous une nouvelle signature ; un secret fait seulement de mots
  courants (« -p 'maison rouge' ») ou sans mot-clé devant lui peut rester ; dans un texte libre, un nom de fichier à
  espaces sans guillemets, hors d'un dossier personnel, peut garder sa fin, et une adresse web sans schéma, « www. » ni
  « // » (« exemple.com/page ») reste ; après un chemin personnel, le reste de la ligne est perdu (jusqu'au dernier guillemet fermant de la ligne, s'il était ouvert devant lui) ; ne sont pas lus comme personnels, et un nom à espaces peut y garder sa fin : un dossier personnel écrit par une autre variable que « ~ », « $HOME » et « %USERPROFILE% » (« ${HOME}/… », « $env:USERPROFILE\… », « %HOMEPATH%\… »), une adresse d'un autre schéma que « file:// » (« smb:// », « sftp:// » : elle s'arrête à la première espace) et un dossier de compte sous une autre tête que celles connues (« D:\Profils\… », « /srv/comptes/… », hors la maison de cet ordinateur) ; un chemin collé derrière « < » ou « * » (« sort </home/… ») n'est pas lu, un chemin relatif dont le premier élément est le compte (« "alice\\Mes documents\\…" ») garde ce compte, ce qui suit une coupure écrite (« \n », « \r », « \t », « \u000a »…) peut être lu comme un chemin (« src\nettoyer\mod.rs » devient « src\n<chemin> »), et un chemin derrière « compte@hôte: » (« scp bob@nas:/home/… ») est coupé à la première espace ; dans le doute, on masque plus : tout « \/ » redevient « / », et une expression de sed, une regex ou une route web écrite ainsi (« sed 's/\/usr/…' », « ^\/api\/v1 ») perd ses « \ » ou est masquée, « // » compte comme une barre (« total.size//chunk.size », un commentaire « // »), « 10$US/mois » ou « s/$PREFIX/usr/ » sont lus comme des chemins, une barre derrière un caractère écrit en code (« \x41/… », « \0/… ») ou derrière une option collée (« -I/… ») ouvre un chemin, un élément en « prénom.nom » (« projets/zoe.martin/notes ») suffit à masquer un chemin relatif, le dernier élément d'un chemin relatif peut aller jusqu'au mot à extension qui suit (« Documents/rapport et la suite.pdf »), une ligne qui porte une séquence de terminal (couleur, lien OSC 8, titre), même écrite (« \x1b[0m »), est retirée entière (« [ligne retirée : séquence de terminal] »), une adresse web dont la requête a une espace brute (« ?nom=Zoé Martin ») garde la fin du nom, un extrait coupé « … (2/3) terminé » perd sa fin, et dans un JSON compact, la valeur suivante qui contient « = » ou « & » peut partir avec une adresse, et une adresse entre guillemets échappés (« \"https://…\" ») peut emporter le champ suivant ou laisser la fin d'un chemin collé derrière elle ; un partage dont un dossier a des espaces, derrière un guillemet jamais fermé ou « What= » (« mount -t cifs "//nas/Photos de Zoé Martin », « What=//nas/Photos de … »), et une adresse « file:// » vers un hôte (« file://nas/partage/… ») gardent la fin du nom ; une maison suivie d'une espace qui ouvre un autre nom de compte (la maison du compte « Zoé » devant le dossier du compte « Zoé Dupont ») est remplacée, et la fin du nom (« Dupont ») reste ; le détail est coupé à 3000 octets (une
  valeur du brouillon à 4000 caractères) avant le masquage, dont le coût croît vite avec la longueur ; un texte que le
  masquage ne stabilise pas est remplacé en entier par « [texte retiré : masquage instable] ».
- **Le journal du système est lu en entier, comme `journalctl`.** Après un redémarrage, le journal peut redonner à
  une nouvelle entrée le numéro d'une entrée plus ancienne. Vanguard la prenait pour une copie et la sautait. Une entrée
  est maintenant reconnue par tout son en-tête (numéro, heure, démarrage, empreinte) et les fichiers sont fusionnés dans
  l'ordre d'écriture, pas par l'heure seule, qui peut reculer quand l'horloge se règle au démarrage.
- **Nouvelle porte de lecture pour les assistants d'IA (`vanguard mcp`), sous Linux seulement.** Un assistant que vous
  branchez peut lire l'état de Vanguard, ses événements et ses constats, sans pouvoir rien changer. Elle passe seulement
  par l'entrée et la sortie du programme, sans port ni réseau, refuse de tourner en administrateur et marque tout ce
  qu'elle rend comme non fiable. Un texte venu de l'ordinateur (message d'un constat, titre d'une alerte, nom d'un
  programme) n'en sort que fait des mots que Vanguard écrit lui-même dans ses messages, en français et en anglais ; tout
  autre mot, chiffre ou signe devient « … », ce qui retient les chemins, les adresses et toute valeur à chiffres ou à
  signes. Ces mots sont lus dans le code à chaque compilation, par son arbre syntaxique, comme le compilateur suit les
  modules, sans les essais ; une forme que cette lecture ne sait pas juger arrête la compilation. Chaque mot doit aussi
  se retrouver tel quel dans les programmes publiés, sans quoi rien n'est publié : un texte que le compilateur n'a pas
  gardé (une ruse que la lecture n'aurait pas vue) se voit là. Après un mot qui
  annonce un secret (mot de passe, clé, code, PIN, NIP, jeton, secret, seed, phrase de récupération, identifiant,
  login…), tout le reste du texte est retenu, et l'extrait de commande de chaque programme d'une alerte du veilleur
  aussi ; le prix : une phrase utile qui suit un de ces mots est perdue. Limites, dites au modèle de menace : un nom fait
  de mots de Vanguard (« admin », « maison ») sort, avec sa casse ; une valeur écrite avant l'annonce (« maison rouge
  est le mot de passe ») n'est pas retenue ; un attaquant qui écrit sur l'ordinateur peut composer une phrase avec ces
  mots ; les champs à forme fixe (règle, version, date, nombres) sortent sans être relus. Une session servie est notée dans le journal, sans jamais le
  remplir ; un programme qui lui envoie des messages anormaux est coupé, et une alerte le dit. Elle refuse de démarrer
  sous un plafond de taille de fichier (`ulimit -f`), qui pourrait couper sa note au milieu ; une note coupée malgré
  tout est défaite, et le journal reste lisible. Après 15 minutes de silence, elle se ferme ; l'assistant la relance.
  Sous Windows, la commande refuse de démarrer tant qu'elle n'a pas été essayée sur un vrai Windows.
- **Le masqueur des adresses, commun au journal des erreurs et au brouillon de signalement, en retient plus.** Dans
  le doute, il masque. Une adresse IPv4 portée dans une IPv6 (« ::ffff:… ») ; une adresse IPv4 suivie d'un port
  (« .443 », « .123456 ») ou de lettres collées (« .443x », « 23abc »), quel que soit le mot qui la précède (« paquet »,
  « règle », « version », « -v ») ; une adresse IPv6 pleine suivie d'un point, d'un port (« …:ef01:443 ») ou d'une IPv4
  (« …:abcd:198.51.100.23 ») ; une adresse IPv6 suivie d'un deux-points (« fd12:…:6: Connection refused »,
  « fe80::1%eth0: … », « %eth0:546 »), précédée d'une étiquette collée (« addr:fd12::7 ») ou d'un point
  (« fd12::7.fd12::8 », « ...10.0.0.5 ») ; une zone écrite avec des tirets, des traits bas ou un point suivi d'un
  chiffre (« %br-lan », « %eth0.100 ») ; des points idéographiques (« 。 ») : tout cela est maintenant masqué en entier.
  Un mot collé après le point (« 5::6.Le reste ») garde sa place. Les adresses IPv6 sont lues par une grammaire
  stricte, sans regarder ce qui les entoure : toute suite de chiffres hexadécimaux, de deux-points et de points qui
  compte au moins deux deux-points et un chiffre est masquée, quelle que soit l'étiquette collée devant
  (« remote_addr: », « X-Forwarded-For: », « nas.lan: ») ou le mot collé derrière ; tout mot collé derrière elle est
  masqué avec elle, jusqu'à l'espace, car un dernier groupe fait de lettres a-f ne se distingue pas du début d'un mot
  (prix accepté : « …::7:Connection refused » donne « <ip> refused »). Seule exception, pour garder la
  chronologie : une heure de forme exacte (HH:MM ou HH:MM:SS, deux chiffres par groupe, heures 00 à 23, minutes 00 à
  59, secondes 00 à 60, peut-être suivie de « . » et de 1 à 9 chiffres), bornée des deux côtés par un caractère qui
  n'est ni hexadécimal, ni « : », ni « . » ; « 12:34:56 » et « 08:15:02.123456 » restent lisibles, mais pas
  « 12:34:56:78 », « 24:00:00 », « 12:34:5a » ni « 12:34::1 ». Prix accepté : une heure suivie d'un point de phrase
  (« 12:34:56. »), un rapport (« 1:2:3 »), une version à deux-points (« 7.6.7:1:80 ») ou une adresse de périphérique
  PCI (« 0000:00:02.0 ») sont masqués aussi ; dans un journal de bureau mesuré, environ une ligne sur seize garde
  ainsi un masque (au lieu de deux sur trois quand toute heure était masquée). Une étiquette qui finit
  par une lettre hexadécimale la perd (« hôte:fd12::7 » donne « hôt<ip> »). Ne restent lisibles que des numéros qui ne peuvent pas
  être une adresse avec son port : une version à suffixe connu (« 1.2.3.4rc1 », « 4.19.0.0beta », « alpha », « esr ») ;
  après « version », « build », « section », « contrôle », « pilote », « release » et leurs formes anglaises, un
  cinquième nombre d'un ou deux chiffres derrière un premier nombre sous 100 (« version 1.2.3.4.5 ») ; une suite de six
  nombres ou plus (« 1.2.3.4.5.6 »). Limites connues : « version 10.0.0.5.22 » reste donc en clair (une adresse privée
  et un port de deux chiffres après un de ces mots), comme une adresse suivie de deux nombres ou plus (« .443.80 »),
  prise pour une version ; une adresse collée derrière des lettres ou un chiffre (« hôte198.51.100.23 »,
  « 0198.51.100.23 ») reste en clair ; une adresse IPv6 écrite sans aucun chiffre (« fd::ab ») ressemble trop à un mot
  pour être reconnue ; un point suivi de lettres finit la zone (« %eth0.vlan5 » laisse « .vlan5 ») : aucun octet
  d'adresse n'en sort ; un numéro de quatre nombres est pris pour une adresse même nommé (« version 6.1.0.2 » garde son
  nom, pas ses nombres). Par la porte des assistants, aucune de ces formes ne sort : ce ne sont pas des mots
  de Vanguard.

- **Fenêtre absente : le menu le dit et propose de l'ajouter.** Quand rien d'autre ne garde le menu, il dit en une
  ligne que la fenêtre manque et donne l'entrée « Mettre Vanguard à jour », qui l'ajoute après l'avoir montrée,
  vérifiée contre l'empreinte gravée. En SSH, au Bureau à distance, en administrateur ou sans écran, rien n'est
  proposé ; sans Internet, depuis la clé ou dans un dossier qu'on ne peut pas écrire, la raison est dite.
- **Fenêtre : une rubrique en liste et page, en un clic.** Dans une fenêtre large, une rubrique montre à gauche la liste
  de ses commandes (titre et état) et à droite la page de la commande choisie ; un clic dans la liste change la page
  sans rien ajouter à Retour, ↑ et ↓ changent de commande, Entrée ou F5 la relancent, jamais pendant une saisie. Une
  fenêtre étroite garde ses cartes. Une lecture rapide (3 min au plus, qui ne change rien), jamais lue ou lue il y a
  plus d'une heure, se relance seule à l'ouverture de sa page, une fois. Une lecture longue et les scans du réseau
  (appareils, audit du réseau, caméras cachées, NAT) ne partent jamais seuls : ils attendent le bouton « Lancer ».
- **Fenêtre : elle ne relance que le `vanguard` qui l'a ouverte.** Elle relançait le même chemin pendant des heures,
  sans revoir le contenu : un `vanguard` remplacé par ce compte lui faisait afficher ses réponses et recevait ses
  gestes. `vanguard` lui donne maintenant l'empreinte SHA-256 de son propre programme ; à chaque commande, la fenêtre
  relit le fichier, le copie dans un fichier en mémoire scellé, compare son empreinte et ne lance que cette copie,
  jamais le chemin. Remplacé depuis l'ouverture (une mise à jour aussi) : rien n'est lancé, la raison est dite, et il
  suffit de rouvrir la fenêtre ; après une mise à jour réussie, elle le dit tout de suite. Sous Linux, le `vanguard`
  lancé de cette copie reçoit, dans son seul environnement, le chemin vérifié (`VANGUARD_ORIGINE`) : il ne le croit que
  dans cette image reconnue strictement et vers un fichier à ses octets exacts, et sa mise à jour, sa clé et sa tâche
  gardent le bon fichier ; ce chemin manquant ou refusé, il s'arrête et dit de rouvrir la fenêtre, sans repli. Il se
  reconnaît par le fichier ou les octets, jamais par le nom `/memfd:vanguard` ni par un chemin seul : un autre
  programme lancé d'un memfd à ce nom ou refait à son chemin reste montré et traitable, ce qu'un programme avait lancé
  avant de devenir Vanguard reste jugé (un Vanguard qui a encore un enfant au moment de l'exec, ou déjà en marche avec
  un enfant quand le veilleur démarre, voit tout ce qu'il lance jugé : cet enfant peut lui donner des frères ou ses
  orphelins ; une racine partie dont le numéro est repris après des événements perdus ne passe plus la marque), une
  inondation de copies de même taille ne fait plus oublier un Vanguard déjà reconnu, et deux `vanguard` de la fenêtre
  ne se dénoncent plus l'un l'autre. pkexec y exécute le chemin vérifié, seulement s'il est à root et protégé ; sinon
  il n'est pas proposé. Sous Windows, le fichier est tenu et son empreinte comparée, mais c'est encore le chemin qui
  est lancé (limites dites au modèle de menace). Ouverte seule, sans `vanguard`, la fenêtre fait confiance à son
  voisin au premier usage.
- **La mise à jour pose aussi la fenêtre qui manque.** Quand `vanguard` est déjà au numéro publié sur GitHub mais
  que sa fenêtre manque à côté, n'est pas la sienne, ou serait refusée au lancement (un lien, de mauvais droits), la
  mise à jour propose de la poser. Seulement si le programme d'ici est exactement celui publié, et toujours vérifiée
  contre l'empreinte gravée dans `vanguard` ; montrée dans l'aperçu, posée seulement après votre accord, et remise
  comme avant si la relecture échoue (avec ses droits, ou c'est dit). L'état de chaque fenêtre montrée entre dans
  l'accord : si elle change entre l'aperçu et le clic, rien n'est fait.
- **Une fenêtre qui ne se lit pas ne bloque plus la mise à jour du programme.** Si la fenêtre d'ici ne se lit pas
  (droits, dossier à son nom), si la copie est un lien, ou si la fenêtre de la clé ne se vérifie pas, le programme
  est mis à jour seul : sa fenêtre n'est pas touchée, c'est montré dans l'aperçu comme un geste à part, et redit au
  résultat comme « non vérifié ». Un dossier que le lancement refuse est dit, sans réparation proposée (la reposer
  ne réparerait rien). Les fichiers provisoires portent un nom tiré au hasard, jamais un nom devinable.
- **Console de la fenêtre : dix lectures de plus, et une valeur tapée.** agent, camera-micro, logiciels, nettoyer,
  desinstaller, sites-dangereux, parametres, blocage, verifier-sauvegarde et ordinateurs se tapent dans la Console,
  toujours lancées en lecture seule (`--json`) ; chaque mot qui agit (on, off, annuler, --appliquer…) y est refusé.
  Ces commandes, avec `--liste` quand elles en ont un, donnent un JSON seul sans rien changer ; `--json` est refusé
  (code 2) dès qu'il va avec un geste qui change, y compris dans la queue d'un réglage de `parametres`, où il était
  avalé et laissait changer la langue. Huit lectures prennent une valeur (`vanguard console <commande> -- <valeur>` :
  chercher, lien, evenements --incident, dernieres-failles, journaux-windows, verifier-fichier, courriel-suspect,
  verifier-moi) : la valeur est bornée et jugée deux fois, par la fenêtre puis par `vanguard`, sans tiret au début,
  ni caractère de contrôle, ni inversion de sens ; un chemin n'est permis qu'après son chemin réel, pour un fichier
  ordinaire sous Téléchargements, Bureau ou Documents du compte, ou sur un support amovible ; le reste est hors ligne
  et la valeur est masquée au journal. Un fichier donné est ouvert une seule fois, et ce qui est vérifié est
  exactement ce qui est lu (plus d'écart entre les deux).
- **Console : les dossiers liés ou déclarés, jugés plus juste.** Sous Linux, un endroit permis qui est un lien
  symbolique (~/Documents vers ~/Nextcloud/Documents) est suivi une seule fois, quand les endroits sont faits, et
  seulement si sa cible est un dossier visible sous le dossier personnel : un lien changé ensuite n'est pas suivi, un
  lien qui sort du dossier personnel n'est jamais suivi, même pour vérifier sa cible, et un lien vers un dossier caché
  ou vers le dossier personnel est refusé avec cette raison. Un dossier déclaré dans ~/.config/user-dirs.dirs ne
  compte que si son nom, sans tenir compte des majuscules, est l'un de ceux que xdg-user-dirs donne à
  Téléchargements, Bureau ou Documents (liste fermée, tirée de xdg-user-dirs 0.20) : `XDG_DESKTOP_DIR="$HOME/Projets"`
  ne fait plus d'un projet un endroit permis. Une maison à la racine (« / ») ne donne aucun endroit permis, et un
  chemin sur un support amovible est refusé avec sa cause quand le compte n'est pas dans /etc/passwd. Sous Windows,
  ces trois dossiers viennent de Windows lui-même (SHGetKnownFolderPath) ; Bureau et Documents sauvegardés dans
  OneDrive sont acceptés, mais OneDrive entier (même déplacé sous un autre nom), Images, Vidéos, Musique et les autres
  dossiers connus ne sont jamais permis ; chaque dossier de la lecture est ouvert sous le précédent et tenu de façon
  que nul ne le renomme pendant qu'on lit (vérifié sous Wine, pas encore sur un vrai Windows).
- **Console sous Windows : trois cas de plus au banc de la VM.** `outils/test-windows/test.ps1` fabrique, sur le vrai
  Windows de la VM, un fichier OneDrive « en ligne seulement » (un espace réservé de l'API des fichiers en nuage, sans
  compte OneDrive) et un fichier marqué hors ligne : la Console doit les refuser, sans rien rapatrier. Il refuse aussi,
  quelques secondes, la liste du dossier des profils au compte de la session, puis déplace Documents dans OneDrive
  comme le fait la sauvegarde de OneDrive : la Console doit toujours lire Documents, et refuser OneDrive lui-même.
  Chaque changement est remis tel quel et relu ; sinon, le banc le dit avec la commande qui le remet.
- **Linux : une mise à jour qui ne se vérifie pas dit pourquoi.** Firmware : une erreur rendue par fwupd est nommée,
  et sinon fwupd est dit injoignable, avec sa cause ; le remède « fwupdmgr refresh », souvent faux, n'est plus donné.
  Flatpak : « hors ligne ? » devient la vraie raison (pas de réponse en 40 s, code de retour et première ligne de
  l'erreur de flatpak, par exemple un dépôt injoignable). Jamais « à jour » sur une erreur, comme avant.
- **Linux : le témoin de `journalctl` coupé au milieu d'une lettre accentuée ne passe plus pour vide.** Avant, toutes
  les entrées des fichiers du journal semblaient cachées par journalctl (fausse alerte). Un témoin illisible est dit
  « non vérifié », jamais compté comme sain.
- **Un Vanguard arrêté au mauvais moment ne fait plus attendre deux minutes.** Pour rester compatible avec les
  versions d'avant la 0.87, Vanguard pose aussi leur ancien fichier de verrou, créé vide puis marqué. Arrêté entre les
  deux, il laissait un fichier vide, que chacun prenait pour une 0.86 encore ouverte : le journal, les notes des
  réglages et la liste des appareils restaient bloqués deux minutes. Le fichier naît maintenant déjà marqué, d'un coup
  (lien physique ; sur une clé FAT, comme avant). Un essai le guette 3 000 fois et ne doit jamais le voir sans sa
  marque.
- **Le principe de Vanguard, réécrit : Vanguard agit, vous gardez la main.** Ce qui protège, entretient ou améliore
  l'ordinateur se fera seul, l'état d'avant noté, journalisé, annulable exactement, avec un compte rendu après ; seule
  une baisse de protection attend votre choix, et reste demandé tout geste qui coupe une connexion, supprime ou déplace
  vos données, désactive quelque chose ou ne s'annule pas exactement. C'est la direction : rien ne change encore dans
  le programme, chaque correction attend toujours votre accord. Le modèle de menace gagne une section « Mode
  autonome » qui dit ce qui est prévu et ses freins (liste fermée de gestes, plafond et disjoncteur, interrupteur
  scellé, rien d'automatique sur le réseau ni la prise en main à distance).
- **Les textes envoyés pour améliorer Vanguard masquent plus de formes.** Le nettoyeur commun prend maintenant : un
  numéro de série annoncé, dans ses écritures courantes (« Serial Number: », « serial-number », « iSerial » de lsusb,
  « S/N », « N° de série », « Seriennummer », « DiskSerialNumber »…), même écrit en plusieurs morceaux ; une phrase de
  passe ou un secret annoncés par `:` ou `=`, en français, en anglais ou en allemand (« password: », « pass-phrase: »,
  « wifi_psk= », « PGPASSWORD= », « mot de passe : », « phrase secrète : », « Passwort: », la clé Wi-Fi que montre
  `netsh wlan show profile key=clear`), jusqu'à la fin de leur phrase, même avec des espaces ; un mot de passe donné à
  son option, collé ou entre guillemets, espaces comprises (`-pXXX`, `-p 'XXX YYY'`, `-p=XXX`, `-uNOM:XXX`, une liste
  de Python) ou à `net use`, même avec un chemin entre guillemets ; une adresse MAC à tirets ou à soulignés collée à
  un mot, à points (`abcd.ef12.3456`) ou cachée dans un nom d'interface (`enx…`, `wlx…`) ; une IPv6 écrite en nom
  inverse (`….ip6.arpa`) ou à tirets ; une IPv4 collée à un mot (`host198.51.100.23`) ou à tirets dans un nom d'hôte
  (`ip-10-1-2-3`, `ec2-…`) ; un chemin relatif vers un fichier ou par un dossier personnel (`Documents/impots.pdf`,
  `../Marie/notes`, `projet/.ssh/…`). Le relais, qui refuse un texte où il reste un secret, reconnaît les mêmes
  annonces de secrets ; les autres formes sont masquées par Vanguard avant l'envoi. Les versions, les heures, les
  dates et les fichiers du dépôt de Vanguard (`src/…/mod.rs`, `outils/verifier.sh`) restent lisibles. Limites : un
  chemin relatif sans extension, sans point ni dossier personnel (`projets/Marie`) reste lisible, comme quatre nombres
  à tirets sans nom d'hôte autour ; une phrase de passe emporte tout le reste de sa phrase.
- **La veille de nuit juge chaque crate par ses propres exceptions.** Elle passait `cargo audit` sur quatre
  `Cargo.lock` avec la seule liste d'avis admis de Vanguard, et depuis l'arbre, où `.cargo/audit.toml` taisait ces
  avis pour toutes les crates. Elle lit maintenant chaque `Cargo.lock` du dépôt, fenêtre et preuves comprises, depuis
  un dossier vide, et un avis n'est admis que par le `deny.toml` de sa propre crate (`outils/failles-programmes.sh
  --exceptions-depot`, la même correspondance que la vérification complète). Une correction proposée par l'IA de nuit
  ne peut plus toucher aucun `deny.toml` ni aucun dossier `.cargo/`, où qu'ils soient : celui de la fenêtre manquait.
  Elle est aussi refusée si elle ajoute un lien symbolique, ou si elle déplace un fichier protégé hors de son chemin
  (un renommage cachait jusque-là le chemin de départ). Un `deny.toml` illisible ne coupe plus l'audit des autres
  crates : seuls ses avis comptent tous.
- **Sécurité des dépendances.** wasmtime 48.0.9 (avis RUSTSEC-2026-0566 à RUSTSEC-2026-0573 : mémoire qui
  grossit sans borne dans wasi, arrêts sur des fonctions absentes, pointeur périmé du ramasse-miettes, paniques), amené
  par YARA-X ; url 2.5.9 (avis RUSTSEC-2026-0592 : une adresse `blob:` imbriquée faisait déborder la pile en
  calculant son origine), amené par reqwest.
- **Rust 1.100.0.** Les programmes sont maintenant compilés avec la dernière version de Rust, qui apporte ses
  correctifs ; ses nouvelles remarques de clippy sont réglées dans le code, sans en faire taire aucune.

## 15 novembre 2026 : version 0.96.0

La 0.95 n'a pas été publiée : tout son travail est dans cette version.

- **La fenêtre de Vanguard est livrée, de façon sûre.** Sur un bureau graphique, `vanguard` ouvre maintenant la
  fenêtre (`vanguard-fenetre`), sinon le menu du terminal, comme avant ; `vanguard --menu` le force. Elle n'est lancée
  que si son empreinte SHA-256 est celle gravée dans `vanguard` à la compilation : comme `vanguard` est signé, cette
  empreinte l'est aussi. Ce sont les octets vérifiés qui sont lancés, pas le chemin : sous Linux, une copie en mémoire
  scellée (memfd) ; sous Windows, le fichier tenu ouvert sans partage d'écriture pendant le lancement, ainsi que ses
  dossiers (ni renommés ni remplacés pendant ce temps). Une fausse fenêtre posée à côté n'est jamais lancée : le menu,
  et la raison dite (un lancement refusé par le système dit aussi pourquoi). Un programme compilé sans empreinte
  (`cargo build`, les essais) ne lance aucune fenêtre. `vanguard -h` dit « Sans argument : la fenêtre sur un bureau
  graphique, sinon le menu ».
- **Rien du compte n'entre dans la fenêtre.** Elle ne reçoit qu'une liste fermée de variables d'environnement
  (affichage, langue, dossiers XDG, mandataires) et un PATH propre ; si une bibliothèque injectée dans les programmes
  de la session est signalée (`LD_PRELOAD`…), la fenêtre n'est pas lancée : le menu, qui ne l'exécute pas.
  `VANGUARD_ORIGINE` n'est crue que dans la copie temporaire que `vanguard` se fait sur une clé ; ailleurs, la
  variable est ignorée. La fenêtre reçoit le programme à relancer (`--vanguard <chemin>`) et garde ses propres
  vérifications sur ce chemin, même s'il n'est pas en UTF-8.
- **Corriger, remettre comme avant et mettre à jour depuis la fenêtre.** « Voir la correction » montre l'aperçu de
  Vanguard en entier ; « Appliquer cette correction » s'active 2 secondes après, seulement pour une correction du
  compte qui s'annule exactement et dont tout le texte se voit (sinon la raison est dite). L'écran
  « Ce que Vanguard a changé » montre chaque changement avec son état, et « Remettre comme avant » sur chaque
  correction qui se remet, par le même aperçu et le même délai. Un geste à la fois, qui ne s'interrompt pas ; la
  fenêtre ne renvoie que le jeton et l'accord de l'aperçu, et Vanguard rejuge tout de son côté. La carte
  « Mettre à jour Vanguard » montre d'abord d'où vient la mise à jour, la version visée, son empreinte, sa taille et
  chaque programme remplacé ; rien ne s'installe avant « Installer cette mise à jour ». Dans chaque rubrique, toute la
  carte d'une commande est un bouton (souris, ou Tab puis Entrée) qui ouvre sa page ; dans le bilan,
  « Ce qui va bien » passe à la ligne au lieu de déborder.
- **La fenêtre voyage avec le programme.** La page de la version, le dépôt des mises à jour et la clé portent la
  fenêtre Linux et Windows, jugée comme le programme (empreinte, failles connues, confidentialité, SHA256SUMS). Une
  mise à jour depuis GitHub (terminal ou fenêtre) télécharge la fenêtre de la nouvelle version après l'accord et la
  vérifie contre l'empreinte gravée dans le nouveau programme, tout ou rien ; depuis la clé, la fenêtre de la clé suit
  si c'est la sienne, et si elle ne peut pas être posée, le programme l'est seul et c'est dit. L'aperçu la montre
  comme une ligne de plus. La fenêtre posée est relue (le même fichier, les octets reçus, sinon un échec) ; une
  fenêtre apparue, partie ou changée depuis l'aperçu n'est jamais remplacée : rien n'est posé pour ce programme, et la
  raison est dite. La désinstallation enlève aussi la fenêtre.
- **Depuis la 0.94, la fenêtre se pose une fois à la main.** La mise à jour de la 0.94 ne connaît pas la fenêtre :
  elle pose le programme seul, qui ouvre le menu du terminal ; une mise à jour suivante ne l'ajoute pas (elle ne
  remplace qu'une fenêtre déjà là). Pour l'avoir, prenez sur la page de la version `vanguard-fenetre-linux-x86_64` ou
  `vanguard-fenetre-windows-x86_64.exe`, et posez-la à côté du programme (la clé VANGUARD la porte déjà).
- **Limites de la fenêtre** (dites au [modèle de menace](MODELE-DE-MENACE.md)). Windows : vérifié sous Wine seulement,
  sans lancement suspendu ni vérification de l'image du processus ; les dossiers derrière une jonction et une lettre
  de lecteur redéfinie (`subst`) ne sont pas tenus. Un noyau qui refuse l'exécution d'un memfd (`vm.memfd_noexec=2`,
  SELinux, AppArmor) : le menu, sans repli. La fenêtre ne revérifie pas encore le contenu du `vanguard` qu'elle
  relance : le compte qui remplacerait ce fichier n'est pas arrêté par elle.
- **Mettre Vanguard à jour après avoir vu ce qui s'installe.** `vanguard se-mettre-a-jour --voir` dit, sans rien
  installer, d'où vient la mise à jour (la clé VANGUARD, ou GitHub, signée par l'auteur), la version visée, son
  empreinte SHA-256, sa taille et chaque programme qu'elle remplacerait, avec sa version d'aujourd'hui.
  `--appliquer --accord <accord>` installe seulement ce qui a été montré, de 2 s à 10 minutes après l'aperçu, une
  seule fois : une autre version, une autre clé ou une copie changée entre les deux est refusée. La copie provisoire
  est tenue ouverte du début à la fin : relue, essayée et, une fois en place, revérifiée (le même fichier, les mêmes
  octets ; sous Windows, les octets seulement) avant de dire « fait ». Les vérifications de toujours restent ;
  « à jour » n'est dit que vérifié, sinon « non vérifié ». Commandes cachées de l'aide en ligne.
- **Appliquer une correction du bilan, puis la remettre comme avant (Linux).** `vanguard correction --voir <jeton>`
  (le jeton vient de `audit --json`) montre la correction et son accord ; `--appliquer <jeton> --accord <accord>` la
  fait, une à la fois, de 2 s à 10 minutes après l'aperçu, une seule fois. Seules les corrections du compte qui
  s'annulent exactement sont permises : les droits d'un fichier du dossier personnel. `vanguard changements --voir
  <jeton>` montre ce que « remettre comme avant » ferait, et `--annuler <jeton> --accord <accord>` le fait. Sous
  Windows, ces gestes ne sont pas encore offerts ; en mode lecture seule, ils sont refusés.
- **Ce qui protège ces gestes.** Tout est relu et rejugé au moment d'agir : un état changé depuis l'aperçu, ou un
  fichier remplacé (reconnu à sa sorte et à son numéro d'inode), est refusé sans rien changer. Plusieurs fichiers :
  tout ou rien. La trace « Ce que Vanguard a changé » s'écrit avant de toucher un fichier : Vanguard arrêté net laisse
  une ligne « interrompue », qui se remet comme une autre ; rien n'y prouve que Vanguard a posé la valeur, et l'écart
  avec ce qui est là se montre avant la remise. Une note écrite par une version d'avant la 0.95, sans l'identité du
  fichier, ne se remet pas toute seule : la valeur à remettre à la main est dite. Les droits d'un fichier du compte se
  lisent, se posent et se remettent sans shell ni lien suivi (la remise passait par `chmod`, qui suit les liens). Le
  journal des événements ne garde ni nom de fichier ni commande ; chaque fichier scellé s'écrit en deux temps, comme le
  sceau des réglages.
- **Mise à jour plus honnête.** Une copie échangée par un autre programme pendant la mise à jour n'est plus laissée en
  place : l'ancienne copie est remise (réécrite depuis ce que Vanguard en tient si son second nom a été effacé
  entre-temps), ou Vanguard dit exactement ce qui est en place (« ne la lancez pas »). L'ancienne copie est reconnue par
  ce que Vanguard en tient ouvert, plus par un numéro de fichier que le système peut redonner à un autre, et elle n'est
  dite « remise » ou « restée en place » que si ses octets sont encore ceux que Vanguard a lus en la mettant de côté
  (empreinte BLAKE3) ; une copie qui est un lien symbolique est reconnue à ce qu'il désigne et au fichier au bout, tenu
  ouvert de même. Réécrite (ou, au bout d'un lien, remplacée) entre-temps par un autre programme, elle est dite changée,
  à ne pas lancer : Vanguard la revoit juste avant de la poser à sa place, et ne la pose pas s'il la voit changée
  (laissée sous son nom de côté, elle est à déplacer avant de refaire la mise à jour) ; un changement fait dans
  l'instant entre ce contrôle et la pose n'est vu qu'après, et dit de même. Si elle ne peut pas être mise de côté avant
  le remplacement (par exemple, elle ne se lit pas, dépasse 512 Mio ou est un lien vers rien, ou son nom de côté,
  `vanguard.precedent`, est pris par un dossier ou par un autre fichier), la mise à jour de cette copie est refusée
  avant de rien remplacer, et le chemin en cause est dit, avec le geste à faire ; ce qui est à ce nom n'est jamais
  effacé, sauf un second nom de la copie en place. Si la remise échoue, l'ancienne copie est gardée sous un nom que le
  message donne, à mettre à l'abri, seulement si elle y est encore inchangée (pour un lien, le fichier au bout aussi) ;
  sinon, ou si même cela rate, le message dit qu'elle est perdue. Une nouvelle copie tenue ouverte en écriture (« Text
  file busy ») est dite comme telle ; un nom provisoire occupé (un dossier) est dit avec le chemin à retirer. Chaque
  refus de la mise en place dit « rien n'est remplacé », aussi à la première pose de la copie de cet ordinateur.
  Limites : un changement fait après cette dernière vérification n'est pas vu ; sur un système de fichiers sans liens
  physiques (FAT, exFAT), ou pour une copie d'un autre compte quand le système les interdit (fs.protected_hardlinks),
  l'ancienne copie ne peut pas être mise de côté : la mise à jour de cette copie est refusée (« Operation not
  permitted »).
- **Annuler sans toucher un autre fichier.** « Ce que Vanguard a changé » ne remet plus des droits plus larges sur un
  fichier qui n'est plus celui que Vanguard a corrigé (remplacé, autre inode) : la remise est refusée, avec sa raison,
  et la ligne montre les droits d'aujourd'hui et ceux qui seraient remis.
- **Refus plus clairs.** « Ça a changé depuis l'aperçu » dit aussi la cause possible : un aperçu fait dans une autre
  langue (VANGUARD_LANG, langue du système).
- **Une aide n'écrit rien.** `vanguard --help`, `-h`, `help` et l'aide d'une commande ne créent plus aucun fichier
  (sceaux) dans le dossier de données.
- **Programmes au démarrage : l'accord devient obligatoire.** `vanguard demarrage --retirer` et `--remettre`
  demandent maintenant `--accord`, celui que `demarrage --json` donne pour ce geste : sans lui, rien n'est retiré ni
  remis (code 2), et un programme dont le nom, la commande ou la portée a changé depuis la liste est refusé. L'accord
  lie le nom et la commande entiers, pas le texte coupé à l'écran. « Remettre » n'écrase plus une entrée réécrite à la
  main depuis son retrait : c'est refusé, la raison est dite et le contenu est gardé.
- **Programmes au démarrage : là où Vanguard n'écrit pas, il le dit.** Un dossier d'autostart modifiable par le
  groupe ou par tous, ou qui porte un bit spécial, n'est plus écrit : ses entrées restent montrées, sans bouton, et le
  dossier est nommé une fois avec ses droits et la commande `chmod` exacte, si c'est votre choix de le corriger. Les
  dossiers que Vanguard crée le sont en 0700, quel que soit l'umask : le premier retrait marche aussi sur Ubuntu et
  Fedora, où il était refusé. Le rapport, le journal et `--json` écrivent le dossier personnel « ~ ».
- **Programmes au démarrage : ce qui n'a pas été lu est dit.** /etc/xdg/autostart est toujours lu, même quand
  XDG_CONFIG_DIRS ne le nomme pas. Un fichier de service du compte se lit borné à 64 Kio, sans suivre de lien ;
  autrement, il est dit « pas lu ». La commande montrée est celle que systemd lance, compléments « .service.d »
  appliqués. « Pourquoi c'est lent ? » dit les dossiers qu'il n'a pas pu lire au lieu de « aucun programme trouvé »,
  et `demarrage --json` ne compte une vérification que si une source a vraiment été lue.
- **Les entrées de bureau et les unités lues comme les lanceurs les lisent (Linux).** Une entrée de démarrage
  (.desktop) se lit comme systemd la lit et comme GLib (gio, gnome-session) la lance : retours chariot seuls, octets
  nuls, marque BOM, échappements, « %f » collé dans un mot, « %c ». Une forme que deux lanceurs liraient différemment
  est levée en nommant la forme. Un ExecStart= écrit en « \xNN » ou en octal se lit en octets, comme systemd ; ce qui
  ne se décode pas sûrement est dit non vérifié.
- **Une ligne qui écrit dans un lieu de démarrage est levée.** Une ligne lancée au démarrage qui nomme
  ~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc ou un dossier qui en contient (~/.config,
  ~/.local) peut y poser un lancement à chaque passage : elle est levée, aussi par un lien, un chemin relatif lu depuis
  son vrai dossier de départ, /proc/self/cwd, un lien physique ou le lieu d'un autre bureau (KDE, Sway, i3…). Un
  chemin qui ne se suit pas avec certitude est dit non vérifié. Limite : une copie sur le dossier personnel entier
  n'est pas comptée.
- **La sauvegarde automatique, plus difficile à détourner (Linux).** Elle lance maintenant rsync et findmnt du
  système par « env -i » ; une sauvegarde posée avant la 0.95 est signalée, avec la marche à suivre (l'annuler, puis
  la remettre). Elle n'est tue au bilan que si rsync, findmnt et env ne peuvent être changés que par root. Elle est
  levée si son disque est un montage FUSE, une image qui appartient au compte, ou introuvable dans /sys (non vérifié),
  et quand on refuse de la déclarer normale, le message dit ce qui la change et comment le retirer.
- **Les variables et les réglages qui changent ce qu'un programme lance.** Le bilan lit les fichiers de variables du
  gestionnaire de session (environment.d, user.conf et user.conf.d, uwsm) : HOME, LD_*, RSYNC_* ou XDG_RUNTIME_DIR
  posés là lèvent la sauvegarde, et un dossier d'unités déplacé est relu. ~/.pam_environment est lu par la sauvegarde
  seulement (les mêmes variables la lèvent), pas jugé au bilan : pam_env ne le lit qu'avec « user_readenv=1 », qui
  n'est pas son réglage par défaut. environment.d et user.conf se
  lisent comme systemd les lit : un retour chariot seul ou un octet NUL coupe une ligne, une suite de ligne en « \ » se
  joint aussi en CRLF, et seuls l'espace, la tabulation et les fins de ligne précèdent un commentaire (« # » ou « ; »).
  Dans un profil de shell et dans les fichiers d'uwsm, seul « # » ouvre un commentaire : une ligne qui commence par
  « // », « -- » ou « ; » n'en est plus un. Ces fichiers sont aussi lus là où leurs lecteurs les cherchent hors de
  ~/.config (XDG_CONFIG_HOME de la session ou posé au gestionnaire, et pour uwsm chaque dossier de XDG_CONFIG_HOME,
  XDG_CONFIG_DIRS et XDG_DATA_DIRS, de la session ou posé au gestionnaire, que le compte peut changer, même hors du
  dossier personnel ; un dossier relatif est lu depuis le dossier personnel, comme uwsm le lit), par le bilan comme par
  la sauvegarde. Un fichier d'uwsm n'est sauté que si seul root peut changer chaque entrée traversée pour l'atteindre,
  liens compris ; un dossier, une entrée ou un fichier d'uwsm qui ne se lit pas est dit, non vérifié, au bilan comme à
  la sauvegarde. Un dossier d'uwsm placé sous un dossier que le bilan lit déjà pour autre chose (~/.config/systemd, par
  exemple) est jugé lui aussi. Les greffons d'uwsm (« uwsm/plugins/*.sh » sous ~/.local/share, /usr/local/share,
  /usr/share et chaque XDG_DATA_HOME et XDG_DATA_DIRS de la session ou posé au gestionnaire) se jugent comme ses
  fichiers, par le bilan comme par la sauvegarde ; un dossier de greffons qui ne se lit pas est dit comme tel, non
  vérifié, et lève la sauvegarde ; tous les « .sh » comptent, même ceux qu'uwsm ne chargera pas pour votre bureau. Un
  joker (« * », « ? », « [ ») dans XDG_CONFIG_HOME, XDG_CONFIG_DIRS ou XDG_DATA_DIRS de la session n'est pas développé :
  il est dit au bilan, non vérifié, ne se déclare pas normal et lève la sauvegarde ; de même pour un saut de ligne,
  qu'uwsm peut retirer en fin de valeur. XDG_DATA_HOME de la session est lu tel quel, comme uwsm le lit. Un morceau posé
  au gestionnaire qui commence ou finit par un blanc ne se résout pas (dit, non vérifié), ni un XDG_CONFIG_HOME ou un
  XDG_DATA_HOME posé qui contient « : » (systemd le prend en entier, uwsm peut le couper), sauf la forme entière
  « ${XDG_DATA_HOME:-/dossier} » d'un fichier d'environment.d à root seul, lue comme systemd la lit (dans user.conf,
  /etc/environment ou pam_env.conf, qui ne la développent pas, elle reste non résolue, dite) ; « ~/x » ou « $HOME/x »
  posé se lit des deux façons : remplacé par le dossier personnel et tel quel, depuis le dossier personnel. Comptent les
  fichiers qu'uwsm lit : « env » et « env-<bureau> » du dossier d'uwsm, chaque fichier de ses « env.d » et
  « env-<bureau>.d » sauf ceux qu'uwsm saute (« *.bak », « *~ », « *.disabled », « *.example », « *.sample »,
  « *.broken »), et « ~/.config/uwsm/default », qu'inclut le fichier d'uwsm d'Omarchy. Les fichiers cachés d'un « .d »
  (« .cache »), que le motif d'uwsm ne voit que si l'option « dotglob » de bash est posée (un BASHOPTS hérité de la
  session), se jugent pour lever seulement : un préchargement, un dossier caché ou temporaire, un PATH relatif, ou ce
  qui change ce qu'uwsm lit ensuite (variable d'uwsm, HOME, variable spéciale du shell comme BASHOPTS ou IFS, nom de
  bureau, inclusion, « eval ») est dit, élevé, avec cette condition, et lève la sauvegarde ; un fichier caché sain, ou
  que bash refuse lui-même (un octet NUL dans sa première ligne, comme « .10-x.swp » de vim), se tait ; un fichier caché
  que Vanguard ne lit pas sûrement (octet NUL plus loin, que bash retire, texte hors UTF-8, plus de 1 Mio, illisible,
  ligne qui n'est pas simple) est dit non vérifié, avec la même condition, lève la sauvegarde, et ce qu'il pose de
  suspect se lève quand même ; « default-id », des notes ou une copie de travail (« env.bak », « .env.swp ») en haut du
  dossier ne se jugent plus. Un nom de bureau hors lettres, chiffres, « _ », « . » et « - », dans XDG_CURRENT_DESKTOP de
  la session ou dans le DesktopNames d'une session d'uwsm (wayland-sessions), ou une ligne DesktopNames avec un octet de
  contrôle ou non ASCII, est dit, non vérifié (uwsm en tire un fichier « env-… » ailleurs, que Vanguard ne lit pas), ne
  se déclare pas normal et lève la sauvegarde. Un fichier de variables d'uwsm (de chaque dossier qu'il lit) ou un
  greffon que le compte peut changer, et chaque fichier qu'ils incluent, à tous les niveaux et quel que soit son
  propriétaire, ne se juge que s'il n'a que des lignes simples : ligne vide, commentaire entier, « NOM=valeur » ou
  « export NOM=valeur », « export NOM », et « . chemin » ou « source chemin » avec un chemin absolu ou « ~/… » écrit en
  toutes lettres, jusqu'à 64 fichiers inclus. La valeur est sans guillemet, « $ », accent grave, barre oblique inverse,
  parenthèse, « ; », « & », « | », « < », « > », « # », « ~ », accolade, joker (« * », « ? », « [ », « ] ») ni blanc ;
  ou tout entière entre apostrophes ; ou tout entière entre guillemets doubles, sans guillemet, accent grave, barre
  oblique inverse ni octet de contrôle, « $ » n'y servant qu'à « $PATH » ou « ${PATH} » qui forme un morceau entier
  entre « : » (ou la valeur entière), et à « $HOME » ou « ${HOME} » au tout début d'un morceau, suivi de « / » ou de la
  fin du morceau ; ailleurs (« /$HOME/.x », « $PATH/.x », « $HOMEx »), la ligne n'est pas simple. La valeur est calculée
  avant d'être jugée : « $HOME » devient le dossier personnel sous sa forme normale, « $PATH » le PATH posé plus haut
  dans le même fichier (sinon celui du système), puis la valeur entière, blancs et « ; » entre guillemets ou apostrophes
  compris, se juge comme écrite en toutes lettres (`export PATH="$HOME/.local/bin:$PATH"` comme
  « /home/alice/.local/bin:… »). Vanguard ne lit pas le shell : un fichier qui a une autre ligne (eval, fonction,
  condition, « ~+ », « {a,b} », commentaire en fin de ligne, octet NUL, texte hors UTF-8…), qui pose une variable que le
  shell d'uwsm ou ses programmes lisent pour changer la suite (IFS, EXECIGNORE, BASH_ENV, BASH_*, ENV, GLOBIGNORE,
  CDPATH, LANG, LC_*…), ou qui lit « $HOME » ou « ~/ » alors qu'un fichier d'uwsm pose HOME, n'est pas jugé : il est dit
  à part, non vérifié (jamais compté sain, sans gravité devinée), avec ce qu'il faut récrire, et il lève la sauvegarde.
  Dans un fichier jugé, une ligne qui écrit XDG_CURRENT_DESKTOP est dite, non vérifiée, élevée et non déclarable, car
  uwsm relit ce nom pour chaque dossier suivant, sauf à une valeur fixe de lettres, chiffres, « _ », « . » et « - »
  (« sway », « GNOME:sway », entre guillemets ou non), dite en information ; de même pour une variable d'uwsm
  (`__NOM__`) ou HOME, et pour une inclusion relative ou d'un dossier. Un profil du shell ou un fichier d'uwsm qui
  contient un octet NUL, que le shell retire avant de lire, est dit aussi, non vérifié ; et un « env.d » qui est un lien
  vers un dossier se suit partout, comme uwsm le suit : la sauvegarde juge ce qu'il contient au lieu de se lever parce
  qu'il ne se lit pas comme un fichier. Dans un profil, une valeur entre guillemets ou apostrophes n'est plus coupée au
  premier blanc qu'elle contient, seulement au premier blanc hors guillemets. Partout où Vanguard juge une variable de
  recherche ou d'injection (PATH, LD_LIBRARY_PATH, SSH_ASKPASS, GIT_SSH… ; fichiers d'uwsm, profils, environment.d,
  user.conf, unités, Hyprland, commandes), la valeur se juge sous plusieurs lectures, et une seule suspecte suffit :
  telle qu'écrite ; sans aucun guillemet ni barre oblique inverse, où qu'ils soient (« /usr/bin:"/home/alice/.x" »,
  « "$HOME"/.x ») ; chaque morceau entre « : » simplifié (« .. », « // », « . »), que la valeur lise « $HOME » ou
  « $PATH » ou non ; et la valeur entière simplifiée comme un seul chemin (« /home/alice/a:b/../.x/demande » d'un
  SSH_ASKPASS, qui n'est pas une liste). « /home/alice/a b/../.x » se lève donc comme « $HOME/a b/../.x ». Chaque format
  ne fait que sa propre coupe : environment.d garde le reste entier de la ligne, blancs et « ; » compris, comme systemd
  (avant, la valeur s'y coupait au premier blanc, comme dans le shell) ; user.conf, lui, coupe DefaultEnvironment= et
  ManagerEnvironment= en mots comme systemd, guillemets compris, et chaque mot pose une variable
  (« DefaultEnvironment=PATH=/usr/bin LANG=C ») ; user.conf, user.conf.d et les Environment= des unités joignent une
  ligne finie par « \ » exactement comme systemd (mesuré sur systemd 262) : la barre devient une espace, un commentaire
  au milieu se saute, une ligne vide finit la suite, « \\ » (deux barres) et « \ » suivi d'une espace ne joignent pas
  (une ligne finie par « \ » suivi d'un blanc est dite non vérifiée : systemd ne la joint pas à la suivante ; ce qui est
  écrit avant la barre reste posé) (avant, ils se joignaient comme un shell, et « DefaultEnvironment=A=1 \ », puis
  « # note \ », puis « PATH=/home/alice/.x » se taisait). Des faux élevés reculent, fidèles à systemd (mesuré : la
  variable suspecte n'y est jamais posée) : « DefaultEnvironment=B\ » suivi de « ASH_ENV=… », que systemd lit comme
  ASH_ENV, et « DefaultEnvironment=A=1 \\ » (deux barres) suivi de « PATH=… », que systemd refuse comme clé inconnue,
  se taisent ; une ligne finie par « \ » suivi d'un blanc, puis une ligne suspecte, passe d'élevée à non vérifiée ; dans un profil, chaque
  commande de la ligne, coupée hors guillemets à « ; », « & » et « | », se juge jusqu'au commentaire (« true && export
  PATH=… ») ; dans fish, chaque mot sans ses guillemets, jusqu'au commentaire ou au « ; » (avant, « set -gx PATH
  /usr/local/bin $PATH # mes outils » se levait à tort). BASHOPTS ou SHELLOPTS posé à la session (environment.d,
  user.conf, un profil) est élevé : « dotglob » fait lire à uwsm les fichiers cachés de ses « .d ». Un PATH avec un
  morceau vide ou relatif (« . », « .x », « :: », « : » au début ou à la fin), qui fait chercher chaque programme lancé
  par son nom dans le dossier courant, est élevé dans un fichier d'uwsm, un profil du shell (fish compris),
  environment.d et user.conf de systemd. Les lignes « exec » des réglages de popt (~/.popt, /etc/popt) se jugent comme
  des lancements. Un fichier qu'un profil ou un fichier d'uwsm lit par « . » ou « source » se juge aussi ligne à ligne,
  avec la même règle que ~/.bashrc (une ligne qui nomme LD_PRELOAD se signale, même si elle ne fait que le lire), quand
  l'inclusion est écrite en toutes lettres en position de commande et que son chemin est absolu ou sous « ~/ » ou
  « $HOME/ », jusqu'à 64 fichiers inclus. Un dossier personnel écrit autrement (« /home/alice/. », « /home//alice ») se
  lit sous sa forme normale ; un HOME avec « .. » n'est pas suivi (le dossier tiré de la base des comptes le remplace,
  et sans lui, aucun chemin relatif ni vide n'en tient lieu) et le bilan dit le dossier personnel inconnu, non vérifié.
  Limites : dans un profil, une inclusion écrite autrement (chemin relatif ou calculé par une variable, boucle sur un
  dossier, eval) n'est pas suivie, et le bilan ne le signale pas, un fichier inclus illisible, trop gros ou qui n'est
  pas en UTF-8 n'est pas jugé, et une valeur entre guillemets écrite sur plusieurs lignes n'est pas suivie d'une ligne à
  l'autre, et peut cacher la ligne qui la suit ; les fichiers d'uwsm du système à root seul, et ce qu'ils incluent, ne
  se jugent pas ainsi ; ~/.profile, qu'uwsm lit avant ses fichiers dans le même shell, n'est pas jugé de la règle d'uwsm
  (choix de l'auteur) : une ligne qui y change le nom de bureau ou une variable d'uwsm, y définit une fonction ou un
  alias, ou y lance une commande quelconque, n'est pas vérifiée ; un PATH posé par une ligne simple n'est jugé que pour
  ses dossiers cachés et ses morceaux vides ou relatifs : un dossier ordinaire du compte placé devant ceux du système
  peut changer chaque programme qu'uwsm, ou ce qu'il lance, trouve ensuite par PATH (tr, sh, env, systemctl,
  xdg-user-dirs-update…) ; Vanguard ne lit pas le réglage « dotglob » de la session : un fichier caché d'un « .d » se
  juge sous cette condition, dite ; une ligne qui n'y est pas simple n'est lue que commande par commande, sans lire le
  shell ; bash 5.3 refuse aussi un fichier avec un octet NUL en deuxième ligne après « #! », que Vanguard dit non
  vérifié par prudence (un programme ELF, avec un octet NUL dans ses premiers octets, se tait comme binaire) ; un PATH
  relatif posé par une unité de systemd ou une ligne « env = » de Hyprland, et un LD_LIBRARY_PATH relatif, ne sont pas
  signalés ; hors d'une ligne simple, un morceau de PATH qui lit une variable (« $… »), commence par « ~ » ou « % », ou
  une valeur qui contient « ` », « \ », « { » ou « ( » (« ${PATH:+$PATH:}$1 » d'Arch) n'est pas jugé relatif ; un « ~ »
  entre apostrophes (`export PATH='~/bin:/usr/bin'`) et « path=(. $path) » de zsh sont seulement dits non vérifiés, et
  ~/.cshrc n'est pas lu ; une condition ou une boucle d'un profil (« if …; then export …; fi ») se lit commande par
  commande, sans lire le shell ; XDG_DATA_DIRS, XDG_CONFIG_DIRS, GIT_EXEC_PATH ou TMPDIR posés vers un dossier caché ne
  sont pas signalés, ni un dossier caché plus loin que le premier niveau du dossier personnel (« ~/outils/.x », règle
  commune) ; un cycle d'inclusions entre fichiers d'uwsm n'est pas dit au bilan (la sauvegarde se lève) ; dans un
  profil, une ligne qui n'est pas simple ne se calcule pas (« /$HOME/.x » n'y est pas lu comme le dossier personnel) :
  elle est dite non vérifiée. Une variable posée en cours de session ou par une ligne « env = » de Hyprland n'est pas
  vérifiée ; un dossier déplacé par un profil de shell (HOME, ZDOTDIR, XDG_CONFIG_HOME) est dit, mais ce qui se lit sous
  lui n'est pas jugé.
- **Ce que Vanguard ne sait pas lire sûrement est dit non vérifié.** Dans un profil du shell (bash, sh, zsh, fish), un
  fichier d'uwsm, environment.d et user.conf, une ligne qui touche une variable surveillée (PATH, LD_*, BASH_ENV,
  BASHOPTS, SSH_ASKPASS, EDITOR, PAGER, PERL5OPT… ; FPATH, MODULE_PATH, PROMPT_COMMAND et ZDOTDIR s'y ajoutent, et dans
  un profil HOME et XDG_CONFIG_HOME, qui décident des fichiers lus ensuite) ne se tait que dans une forme simple que
  Vanguard calcule entièrement : « NOM=valeur » ou « export NOM=valeur », la valeur littérale, entre guillemets ou
  apostrophes ou non, qui ne lit que « $HOME » en tête d'un morceau et la variable elle-même (« $PATH »), sans « $( »,
  « ` », « ${…:-…} », « & », « | » ni barre oblique inverse ; dans fish, chaque instruction de la ligne, « set -x NOM
  mot… » ou « fish_add_path dossier… », « ~ » et « $HOME » en tête d'un mot compris (« set -q », « set -e », « set -n »
  et « set -S » ne posent rien : la suite de la ligne se juge) ; dans environment.d, « NOM=valeur » ; dans user.conf,
  chaque mot de DefaultEnvironment=. Une forme simple dont la valeur est suspecte est élevée. Dans le shell (bash, sh,
  zsh, uwsm), toute autre ligne ne se tait que si chacune de ses commandes, coupée par un découpeur strict, est l'une
  des formes d'une liste blanche, fermée et écrite en un seul endroit : un programme ou une fonction lancés par leur nom
  (sans argument « $…=… ») ; une commande sans effet (« : », « true », « echo », « test »…) ; « [[ … ]] » sans rien
  après son « ]] » et « (( … )) » seul ; « for NOM in … », « for (( … )) », « case MOT in » et une définition de
  fonction ; « export », « declare », « typeset », « local » et « readonly » de noms ordinaires écrits tels quels, sans
  « -n », « -i » ni « -T », la valeur sans « $ » ni « ` » hors guillemets ; « read » et « mapfile -t » d'un nom
  ordinaire ; « set », « shopt », « unset », « setopt », « unsetopt » et « zmodload » aux mots fixes, sans « -A » ;
  « let » sans calcul qui pose et « getopts » aux mots fixes ; « bind » sans « -x », « bindkey » sans « -s », « zstyle »
  sans option, « emulate -L » ou « -R » ; « autoload » et « zle » de zsh aux mots fixes ; « trap » et « alias » au corps
  sûr ; « printf » et « print » au format littéral ; « wait » sans « -p », « hash -r », « enable -a », « -p » ou « -s »,
  « command -v », « exec » d'une commande sûre ; un outil d'activation courant (« eval "$(mise activate bash)" ») ;
  « source » ou « . » d'un chemin fixe qui ne lit que HOME, XDG_CONFIG_HOME, XDG_DATA_HOME, ZDOTDIR, OMARCHY_PATH,
  NVM_DIR, ZSH ou __fish_config_dir. Une commande qui tourne à part (avant « | » ou « & », dans « ( … ) ») se tait
  aussi. Le découpeur rend la ligne non vérifiée dès qu'il doute (« $'…' », « ` », « \ » hors guillemets, un guillemet
  ou une parenthèse qu'il ne referme pas). Il lit chaque ligne seule (seules les lignes finies par « \ » se joignent) :
  une valeur entre guillemets ouverte sur plusieurs lignes n'est pas suivie et peut cacher la ligne qui la suit (la
  limite écrite plus haut vaut aussi pour cette liste blanche). Une fonction de bash-completion qui pose une variable
  par son nom (« _comp_upvars », « _comp_get_words » et toute « _comp_… », « _upvars », « _get_comp_words_by_ref »,
  « _init_completion »…) appelée avec un argument calculé (« _comp_upvars -v $a$b … ») est dite non vérifiée ; un nom
  surveillé écrit en clair dans ses arguments (« _upvars -v PATH … ») l'était déjà. Tout le reste est dit au bilan, non
  vérifié, en nommant le fichier et la ligne, jamais compté sain : « builtin export », « command export », un alias vers
  export, eval ou source (« alias e='x=1 export' » compris), « declare -n », « read -a », « mapfile -d », « printf
  -vPATH », « printf "-v" », « compgen -V », « wait -p », « hash -p », « eval "$(f)" » d'une fonction du fichier, « .
  $f » d'une variable posée dans le fichier, « set -A », « emulate sh -c », « - eval », « if [[ … ]] { … } » de zsh, un
  nom de commande qui se calcule (« ex${z}port », « $X »), « . <(…) », « source /dev/stdin ». fish n'est plus lu
  finement : dès qu'une configuration de fish existe (config.fish, fish_variables, conf.d, functions, completions de
  ~/.config/fish ou du fish de XDG_CONFIG_HOME ; vendor_conf.d, vendor_functions.d, vendor_completions.d et
  generated_completions de ~/.local/share/fish ou du fish de XDG_DATA_HOME ; config.fish, conf.d, functions,
  completions de /etc/fish et de /usr/local/etc/fish ; config.fish, functions, completions de /usr/share/fish et de
  /usr/local/share/fish ; vendor_conf.d, vendor_functions.d, vendor_completions.d de fish sous /usr/share,
  /usr/local/share et chaque dossier de XDG_DATA_DIRS), le bilan
  dit « fish : non vérifié » en nommant ce qui est présent (huit endroits au plus, puis le nombre des autres) :
  fonctions chargées à la demande, variables universelles, compléments et conf.d des paquets ne sont pas lus, et ce que
  fish pose ou lance n'est pas jugé ; les endroits hors de cette liste ne sont pas comptés (~/.config/fish/fishd.*,
  ~/.cache/fish, le fish d'un profil de Nix, un fish_function_path posé par un profil du shell). Les formes simples
  suspectes de fish restent élevées. Un dossier de fish du système
  que seul root peut changer ne se dit que si fish est là (un endroit du compte est présent, ou le programme fish est
  installé) : sans fish, les dossiers vendor_*.d que d'autres paquets installent ne se disent pas. Le prix : un
  ~/.config/fish/conf.d qu'un autre programme a rempli, sans que fish soit installé, suffit pour que « fish : non
  vérifié » s'affiche, avec ce dossier et les vendor_*.d de /usr/share/fish. Dans fish, environment.d et user.conf,
  toute ligne hors de la forme simple qui touche une variable surveillée, par son nom ou par un nom calculé (« set -gx
  $n … », « … | source »), est dite de même. Si une ligne dite se lit encore sans doute comme suspecte (« true && export
  PATH=.x:$PATH », « fish_add_path ~/.x » dans un « if »), elle reste élevée, dans environment.d et user.conf aussi
  (« PATH=/home/alice/.x:"$PATH" », un nom décodé comme « DefaultEnvironment=P\x41TH=… », lu PATH) ; dans environment.d,
  où une variable qui n'y est pas posée est vide, « ${NOPE:+x}/home/alice/.x », « /home/alice/${NOPE:-.x} » et
  « $NOPE/home/alice/.x » sont élevés. Un HOME, un ZDOTDIR ou un XDG_CONFIG_HOME posé ailleurs qu'à sa place d'ordinaire
  est dit non vérifié, et élevé vers un dossier caché ou temporaire. Dans un fichier d'environnement de la session
  (environment.d, user.conf, uwsm), une telle ligne lève aussi la sauvegarde : ce qu'elle pose n'est pas lu. Les outils
  d'activation courants (« eval "$(mise activate bash)" », « zoxide init fish | source ») et les formes ordinaires (« [[
  -f ~/.x ]] && source ~/.x », « for ((i=0; i<$n; i++)) », « command -q zoxide », « autoload -Uz compinit ») se taisent.
  Avant, ces formes se lisaient de plusieurs façons devinées, et certaines se taisaient (« export
  PATH=${NOPE:-a&b}:/home/alice/.x », « export "PATH=/home/alice/.x:$PATH" », « PERL5OPT="-I/home/alice/.x -MX" »,
  « SSH_ASKPASS=/home/alice/.demande », « shopt -s dotglob; export BASHOPTS », « set -q X; set -gx PATH /home/alice/.x »
  et « fish_add_path » dans un bloc de fish). Deux faux élevés disparaissent : « PATH=/usr/bin:/a/.. » (chaque morceau
  se simplifie seul) et « PATH=/usr/bin # /home/alice/.x » d'environment.d (une seule valeur littérale, sous /usr).
  Limites : ce qu'écrit un outil d'activation permis n'est pas lu ; un fichier inclus par un chemin qui lit l'une des
  variables permises (« source "$OMARCHY_PATH/default/bash/rc" », « . "${OMARCHY_PATH%/}/default/uwsm/default" ») n'est
  pas suivi, et la ligne se tait ; dans environment.d et user.conf, HOME et XDG_CONFIG_HOME ne sont pas jugés comme un
  dossier déplacé : Vanguard y lit seulement les unités de systemd sous le dossier posé, et un XDG_CONFIG_HOME ou un
  XDG_DATA_HOME posé là n'est pas suivi pour fish (seuls ceux de la session le sont) ; dans environment.d, une
  variable posée plus haut (HOME, XDG_CONFIG_HOME ou toute autre, dans l'ordre du générateur de systemd : par nom de
  fichier, ~/.config/environment.d, /etc, /run, /usr/local/lib puis /usr/lib) est suivie : une variable surveillée qui
  la lit (« $HOME », « ${HOME} », « ${X:-…} », « ${X:+…} ») est dite non vérifiée en nommant la variable et la ligne qui
  la pose, et élevée si sa valeur, développée comme le générateur la développe, est suspecte (« HOME=/home/alice/.x »
  puis « PATH=$HOME/bin ») ; « export HOME=… » ne pose rien pour le générateur, et « %h » n'y est pas développé ; si le
  fichier et ceux qui posent ne sont changeables que par root, rien n'est dit ; un fichier d'environment.d qui a une ligne
  finie par « \ » (une barre ou plusieurs, suivie ou non d'un blanc ou d'un retour chariot), que le générateur ne joint
  pas comme Vanguard la lit, est dit non vérifié en entier et lève la sauvegarde, sauf s'il est à root seul ; un fichier
  d'environment.d de /etc, /run, /usr/local/lib ou /usr/lib qui lit une variable que le compte peut changer est dit non
  vérifié en entier et lève la sauvegarde ; rien n'y est calculé : il suffit que le nom soit écrit juste après « $ »
  ou « ${ » sur une même ligne du fichier, commentaire ou suite d'une valeur entre guillemets comprise, dans le mot d'un
  « ${X:-…} » ou « ${X:+…} » aussi, imbriqué ou non, la variable elle-même comprise (« PATH=$PATH:… » quand le compte
  pose PATH) ; une variable que le compte peut changer est posée par un environment.d du compte, par
  ManagerEnvironment= ou DefaultEnvironment= d'un user.conf ou user.conf.d du compte (une valeur écrite avec « " »,
  « ' » ou « \ » n'est pas lue : elle vaut pour tous les noms), par un fichier du système (environment.d, user.conf,
  user.conf.d) qui n'est pas à root seul, ou par une ligne qui en lit une, quel que soit le fichier qui l'écrit ; un
  fichier du système dont une ligne en lit une compte aussi pour tout ce qu'il pose ; une ligne d'un fichier à root
  seul ne rend jamais une telle variable à root ; celles de la session (profils, ~/.pam_environment) ne sont pas
  comptées ; limites : un nom séparé de son « $ » par « \ », « " » ou « ' » (« $\A », « "$"A ») dans un fichier
  à root seul n'est pas relevé, et « % » (« %u ») de ManagerEnvironment= ou DefaultEnvironment= n'est pas développé ;
  « : ${PATH::=/home/alice/.x} » de zsh et
  « PATH =… » d'environment.d (une espace avant « = ») sont dits non vérifiés, pas élevés ; dans le shell, une variable
  posée plus haut dans le fichier n'est pas suivie (« PATH=$X:$PATH » est dit, pas élevé) ; une valeur lue dans un
  calcul, ou construite en morceaux sur plusieurs lignes, n'est pas suivie ; une ligne hors forme d'un fichier que seul
  root peut changer n'est pas dite (celles d'Omarchy, comme « ${EDITOR:-…} », se taisent donc) ; dans un fichier du
  compte, des formes courantes sont dites non vérifiées sans être fautives : « [[ … && … ]] » et « [[ … || … ]] » (« [[
  -z $DISPLAY && $XDG_VTNR -eq 1 ]] »), « [[ x =~ (x) ]] », le « \. "$NVM_DIR/nvm.sh" » de NVM, « for f in …; do source
  "$f"; done », la fonction « zd() » d'Omarchy, « local x=$(…) », « command ssh … », « source <(kubectl completion
  bash) », « enable -n kill », « autoload » dans un fichier de bash, « export VISUAL="$EDITOR" », « ${EDITOR:-…} »,
  « PATH=~/bin:$PATH », « path=(…) » de zsh, « ZDOTDIR=$HOME/.config/zsh », « PROMPT_COMMAND="history -a; …" », « eval
  "$(dircolors -b ~/.dircolors)" » et l'« eval » de lesspipe de Debian, un alias qui lance « $EDITOR », le corps d'un
  « << », une ligne dans un « case », « shopt -s dotglob » ; dans environment.d et user.conf, un « %h » ou une barre
  oblique inverse finale est dit non vérifié ; une ligne hors forme d'un fichier de session peut lever la sauvegarde
  pour une forme sans danger.
- **Les programmes du système, pris par leur chemin.** Le bilan, les traces, la surveillance, la sauvegarde et les
  autres lectures de la machine lancent pacman, systemctl, journalctl, ss, crontab, ping et les autres depuis les
  dossiers du système, jamais par le PATH du compte : un faux programme posé dans ~/.local/bin ne peut plus cacher une
  connexion ou une ligne du journal. L'autodiagnostic fait de même pour ses lectures croisées (id, dpkg-query, sshd et
  les autres). Sous Linux, ils ne reçoivent plus l'environnement du compte (PATH, BASH_ENV,
  LD_PRELOAD…) : un script du système comme checkupdates ne relance plus un faux pacman posé dans ~/.local/bin, et
  « Système à jour » n'est plus dit sans vérification. Les outils que vous installez vous-même (docker, podman, git,
  nmap, trivy, gitleaks) restent cherchés dans le PATH, exprès, comme xdg-open, qui ouvre une page ou un fichier avec
  l'application que votre compte a choisie.
- **Lectures de la machine, prises au système.** clamscan et upnpc se lancent et se disent présents depuis les dossiers
  du système, jamais par le PATH du compte. checkupdates travaille dans un dossier neuf et privé, effacé ensuite : une
  base posée d'avance au nom connu ne lui fait plus dire « à jour ». Un outil du système écrit en Python (ufw,
  firewall-cmd, dnf) ne charge plus les paquets Python du compte. Un démon Docker désigné par une variable (DOCKER_HOST,
  DOCKER_CONTEXT autre que « default », DOCKER_CONFIG), même réglée avec des espaces ou des octets non UTF-8, ou par un
  contexte choisi dans ~/.docker/config.json, est dit non vérifié au lieu d'être lu, pour les ports publiés comme pour
  les failles des images ; un port de conteneur exposé au réseau, déjà vu par le démon du système ou par les processus,
  reste signalé. Le config.json est lu presque comme le lit la CLI de Docker (ce qui diffère est dit non vérifié) : vide
  ou fait de blancs, il laisse le contexte par défaut, comme pour elle ; la clé du contexte sans tenir compte de la
  casse, chaque doublon compris, un fichier lié (stow, home-manager) suivi ; un HOME ou un DOCKER_CONFIG relatif, ou qui
  contient « .. », rend le démon non vérifié (la CLI défait « .. » dans le texte du chemin, le système le suit après un
  lien : ce ne serait pas forcément le même dossier). Quand l'API de Docker ne répond pas, la CLI lancée par Vanguard
  vise la prise du système, sans les réglages de la maison, pour les ports comme pour les images. Limite : un démon
  choisi pour de bon (Docker Desktop, Docker sans root, colima, hôte distant) n'est plus lu du tout ; un port qu'il
  publie n'est plus signalé, seulement dit non vérifié.
- **La taille de la fenêtre sans programme du compte.** Sans terminal, Vanguard ne lance plus `tput` (cherché dans
  le PATH du compte) pour connaître la taille de l'écran.
- **Analyse ClamAV : seul le fichier vraiment examiné est touché.** Chaque fichier signalé est revérifié à part avant
  que Vanguard propose de l'isoler ou de le supprimer, et le geste ne vise que ce fichier-là. Un fichier au nom piégé
  (avec un retour à la ligne) ne peut plus faire viser un autre de vos fichiers. L'analyse rapide lit de nouveau
  Téléchargements et les autres endroits à risque, même quand /tmp contient des fichiers récents. Ce qui n'a pas pu
  être analysé ou confirmé est indiqué « non vérifié », jamais « sain ».
- **Quarantaine : remettre un fichier ne peut plus servir à écrire ailleurs.** Un fichier n'est remis qu'à sa place
  d'origine, depuis le dossier de la quarantaine ; sous Linux, jamais au travers d'un raccourci (lien) posé par un
  autre compte. Sous Windows aussi, chaque dossier du chemin est vérifié et tenu pendant la remise, et un dossier
  effacé depuis l'isolement est recréé. Quand un relevé existe, Vanguard vérifie que le contenu remis est bien celui
  qui a été isolé ; sinon, le fichier reste en quarantaine et Vanguard montre les deux empreintes. Sous Windows, quand
  Vanguard tourne en administrateur, plus rien ne sort de la quarantaine : Vanguard explique comment le faire à la
  main, en sécurité. Quand Vanguard refuse de remettre un fichier pour une raison de sécurité (dossier d'origine,
  empreinte, administrateur), il dit comment le sortir soi-même. Les droits spéciaux d'un fichier ne sont pas remis,
  mais Vanguard le dit et donne la commande pour les remettre. Les entrées mises de côté sont montrées par leur nom et
  signalées dans les traces d'incident. Un chemin qui contient « .. » est résolu avant l'isolement. Une analyse YARA
  lancée sur un dossier relatif (« vanguard yara . ») met de nouveau en quarantaine ce qu'elle trouve.
- **Le relevé des changements ne perd plus une note.** Deux Vanguard qui notaient en même temps (la surveillance et
  une commande) relisaient chacun le relevé puis le réécrivaient : la note de l'un pouvait disparaître, par exemple
  celle qui permet de remettre un fichier mis en quarantaine. Chaque note se prend maintenant sous un verrou, de la
  lecture à l'écriture ; s'il ne se prend pas, rien n'est écrit par-dessus et c'est dit.
- **Windows : une mise à jour bloquée par un dossier le dit.** Un dossier au nom de la copie provisoire
  (`vanguard.exe.nouveau`) est nommé, avec quoi faire, aussi sur un vrai Windows, qui répondait « Accès refusé » là où
  Wine et Linux disent « Le fichier existe ».
- **Windows : une racine ajoutée au seul compte est montrée.** Un certificat racine ajouté au seul compte de
  l'utilisateur, par exemple par un programme qui intercepte le trafic HTTPS, est maintenant signalé dans le bilan,
  quel que soit son nom, au moins au niveau moyen. Si ce magasin ne peut pas être lu, le bilan dit « non vérifié » au
  lieu de « rien d'ajouté ». Une racine posée dans le compte ne peut plus cacher celle de l'ordinateur, et le bilan ne
  propose plus un retrait que Vanguard refuserait ensuite.
- **Recherche de secrets : un projet reçu ne fait plus rien lancer.** La recherche de secrets dans les projets git ne
  peut plus être piégée par un projet reçu (par exemple une archive décompressée) : ni git ni gitleaks ne lancent plus
  un programme choisi par les réglages de ce projet, et rien n'est téléchargé. Avec un git plus ancien que la version
  2.31, gitleaks n'est plus lancé (c'est dit), et un projet que gitleaks n'a lu qu'en partie n'est plus compté comme
  relu. Dans le guide, les commandes git, « yay -Qua » (qui peut lancer git) et « claude mcp list » ne se lancent plus
  depuis Vanguard et ne sont plus dites sans effet : elles peuvent lancer des programmes choisis ailleurs, et se
  tapent dans un terminal.
- **Linux : le bilan des partages voit tous les partages.** Il voit maintenant les dossiers partagés depuis le
  gestionnaire de fichiers (« Partager ce dossier » avec accès invité) et les partages NFS rangés dans /etc/exports.d.
  Il n'est plus trompé par un fichier de partage écrit de façon inhabituelle, ni par un partage NFS écrit sur
  plusieurs lignes ou sans client nommé. S'il ne peut pas lire ces réglages, il dit « impossible de vérifier » au lieu
  de « aucun partage ouvert ».
- **/etc/ld.so.preload lu comme le lit le chargeur de Linux (glibc).** Ce fichier fait charger des bibliothèques dans
  tous les programmes, root compris. Le chargeur de glibc n'ignore pas toujours une ligne qui commence par « # » : dès
  le deuxième « # » du fichier, une ligne « # /chemin.so » peut être chargée. Vanguard reprend sa lecture telle
  quelle, sur les octets, et y ajoute la lecture « un # ferme sa ligne » : un nom vu par l'une des deux compte. Un nom
  fini par un retour chariot est jugé comme le fichier qu'il nomme, qui n'est pas celui du paquet ; une note en fin de
  ligne ne compte plus comme une bibliothèque. Le bilan, le retrait d'une ligne après confirmation et l'avis du
  démarrage lisent ce fichier de la même façon.
- **Le retrait d'une ligne de /etc/ld.so.preload refuse ce qui changerait autre chose que cette ligne.** Il refuse une
  ligne qui ne fait rien charger (vide, ou un commentaire que le chargeur ignore). Il refuse aussi, sans poser de
  question et sans rien écrire, un retrait qui ferait charger au chargeur un nom qu'il ne chargeait pas : ce qu'il
  efface d'un « # » dépend de la taille du fichier, et retirer une ligne peut réveiller une ligne « # … » cachée. Le
  refus nomme ce qui serait chargé (chaque nom une fois, les chemins d'abord, cinq au plus, le « # » seul compté à
  part) et demande de corriger le fichier à la main. Si la ligne retirée arrêtait le chargeur (un octet nul), les
  lignes suivantes, déjà montrées au bilan, seront chargées après : la question le dit avant le oui.
- **Une ligne introuvable n'est plus un succès.** Quand le retrait d'une ligne de démarrage, ou la mise en commentaire
  d'une ligne de proxy, ne retrouve pas la ligne désignée (fichier changé depuis le bilan, ligne qui n'est pas du
  texte UTF-8), c'est un échec dit, « pas fait », et non plus « déjà fait ». Une ligne signalée qui n'est pas du texte
  UTF-8 n'est plus offerte au retrait automatique : l'alerte dit qu'elle est à retirer à la main.
- **Une ligne signalée d'un fichier de démarrage n'est plus retirée seule que dans un fichier fait d'affectations
  simples.** Une ligne finie par « \ » (même suivie de blancs), ou qui suit une telle ligne, n'est jamais retirée
  seule : le shell et systemd la joignent à la suivante (systemd, même après un commentaire). Dans un fichier lu par
  un shell ou comme un fichier de variables (/etc/profile, /etc/profile.d, bashrc, zsh, fish, /etc/environment,
  environment.d…), Vanguard ne lit pas le shell : une ligne n'est retirée seule que si elle est « NOM=valeur » ou
  « export NOM=valeur » et que TOUT le fichier, en UTF-8, n'est fait que de lignes vides, de commentaires entiers
  (« # » en début de ligne, après des espaces ou des tabulations) et de lignes de cette forme. La valeur est faite de
  lettres, chiffres et « / . _ - : + , = @ % » (vide permise, sans « = » en tête ni après un « : », que zsh
  développe), ou tout entière entre guillemets simples avec ces signes et des espaces ; après elle, des blancs
  seulement (ni commentaire, ni « \r »). Les lignes sont coupées au seul « \n » : pour bash et sh, un « \r » final
  fait partie de la valeur. Un fichier écrit sous Windows (« \r\n ») n'est donc pas de cette forme, et
  « LD_PRELOAD=\r », qui précharge un fichier nommé « \r », reste signalé. Le NOM est fait de majuscules, chiffres et
  « _ », n'est posé qu'une fois dans le fichier, et n'est pas une variable que le shell lit, pose ou garde lui-même
  (IFS, PATH, ENV, HOME, PWD, OLDPWD, LANG, UID, EUID, PPID, GID, EGID, USERNAME, TMPDIR, GLOBSORT, TERMCAP, TZ, et
  ceux que mksh garde en lecture seule comme KSHUID… 118 noms, et tout NOM qui commence par BASH_, LC_, SHELL, ZSH,
  ZLE, COMP, READLINE_, HIST, PROMPT ou RPROMPT). Pour bash, sh, dash et ash (essayés), un tel fichier ne lance,
  n'ouvre, ne lit et ne teste rien qu'une autre de ses lignes verrait, et rend toujours 0. Une ligne de plus de 1 000
  octets, n'importe où dans le fichier, fait refuser tout retrait : pam_env de Linux-PAM 1.4.0 à 1.5.3 arrête sans
  erreur la lecture de /etc/environment à une ligne de 8 191 octets ou plus, et retirer une ligne réveillerait les
  suivantes. /etc/rc.local, que le système lance lui-même, ne garde le retrait que si sa première ligne est
  « #!/bin/sh » ou « #!/bin/bash » (ou /usr/bin/sh, /usr/bin/bash), sans option ou avec la seule « -e » : pour un
  autre interpréteur, « NOM=valeur » n'est pas une affectation. Tout le reste reste signalé, au même niveau, avec la
  correction à faire à la main : le bilan ne l'offre plus, et le retrait la refuse, sans question et sans rien écrire,
  s'il la reçoit quand même. Une seule ligne ainsi fait tomber le retrait automatique de TOUTES les lignes signalées
  du constat : l'alerte le dit. Un fichier de plus de 100 000 lignes ou de 4 Mio n'est pas jugé : retrait refusé, dit
  dans l'alerte. La règle du « \ » vaut pour tout fichier autre que /etc/ld.so.preload. Hors de /etc/ld.so.preload,
  Vanguard ne retire plus lui-même qu'une sorte de ligne : une affectation de LD_PRELOAD ou de LD_AUDIT qui précharge
  vraiment, dans un fichier d'affectations simples comme ci-dessus. Une autre variable suspecte (PYTHONPATH…) ou une
  commande reste signalée, au même niveau, à corriger à la main : le retrait ne l'admet que si le bilan l'offre, par
  la même règle. Une ligne qui vide LD_PRELOAD ou LD_AUDIT (« LD_PRELOAD= », « export LD_AUDIT= »,
  « UnsetEnvironment=LD_PRELOAD ») ne précharge rien : elle n'est plus signalée. Une unité systemd (et ses ajouts
  « .service.d/*.conf »), /etc/crontab, /etc/cron.d, /etc/anacrontab, un raccourci .desktop et les réglages de GDM,
  SDDM et LightDM ne sont jamais corrigés ligne à ligne par Vanguard lui-même : une ligne peut y en retenir une autre
  (« ExecStartPre= » ou « ExecCondition= » qui échoue empêche « ExecStart= » ; « SHELL= » ou « PATH= » fait échouer
  les tâches de cron qui suivent), et un gestionnaire de connexion lit plusieurs fichiers, chacun à sa façon, la
  dernière valeur l'emportant. L'alerte le dit, la correction est à la main, et Vanguard la refuse même si on la lui
  demande, qu'il s'agisse de retirer une ligne ou d'en mettre une en commentaire. Ces fichiers sont reconnus à leur
  nom exact ; un script rangé ailleurs dans ces dossiers reste du shell. Le jugement est fait une fois par fichier, en
  temps linéaire. Limites : dans un vrai bashrc ou /etc/profile (une commande, un « alias », un « if »), aucune ligne
  n'est retirée seule, la correction est toujours à la main ; un NOM posé deux fois fait refuser tout le fichier, même
  si les deux lignes partent ensemble ; « LD_PRELOAD='' » (guillemets vides), « Environment=LD_PRELOAD= » dans une
  unité et « Exec=env LD_PRELOAD= … » dans un .desktop restent signalés (à la main). La règle ne voit pas ce que
  définissent d'autres fichiers lus avant (une fonction ou un alias « export », « readonly », « set -e »), ni ce que
  fait de la variable retirée le code lu après le fichier (le fichier qui le lit, un programme lancé). Rejouée avec
  bash, sh (bash en mode POSIX), dash et busybox ash : zsh, fish, csh, ksh et mksh n'ont pas été essayés, et fish ne
  lit pas « NOM=valeur » comme bash : un fichier .fish garde toujours le geste à la main.
- **Une ligne de proxy n'est plus mise en commentaire que là où une ligne se retire sans danger.** Depuis la 0.92.0,
  la réparation de la navigation mettait en commentaire les lignes « http_proxy=… » des fichiers de démarrage du
  système (/etc/environment, /etc/profile, /etc/profile.d…) en ne regardant que la ligne : une ligne qui ouvrait un
  guillemet sans le fermer se commentait, et la commande que le guillemet tenait se lançait alors à chaque ouverture
  de session. Une ligne commentée est une ligne retirée pour celui qui lit le fichier : la mise en commentaire suit
  maintenant la règle du retrait ci-dessus, au bilan comme au moment de l'appliquer, même si on la demande. Seule une
  affectation simple en majuscules (HTTP_PROXY, HTTPS_PROXY, FTP_PROXY, ALL_PROXY) dans un fichier d'affectations
  simples est commentée par Vanguard ; jamais dans une unité, cron, anacron, un .desktop, un réglage de gestionnaire
  de connexion ni /etc/ld.so.preload. Le reste (minuscules « http_proxy », guillemets doubles, un vrai /etc/profile,
  un /etc/environment qui pose PATH, comme celui d'Ubuntu) est signalé, le fichier nommé, à mettre en commentaire à la
  main.
- **L'ouverture automatique d'une session n'est plus coupée par Vanguard lui-même.** Depuis la 0.92.0, Vanguard
  retirait la ligne qui ouvre la session sans mot de passe dans GDM, SDDM ou LightDM. Chacun lit plusieurs fichiers,
  SDDM avec son propre lecteur, et la dernière valeur l'emporte : retirer la ligne vue pouvait laisser, ou réveiller,
  celle d'un autre fichier. L'alerte reste, au même niveau ; la correction se fait à la main (réglages des
  utilisateurs du bureau, ou la ligne du fichier nommé), avec la raison dite.
- **L'ouverture automatique d'une session est mieux lue, et une annulation douteuse n'est plus crue.** Fichiers lus :
  SDDM, tous les fichiers de /usr/lib/sddm/sddm.conf.d et /etc/sddm.conf.d, quel que soit leur nom, puis
  /etc/sddm.conf ; LightDM, les « .conf » de /usr/share, /usr/local/share, /etc/xdg puis /etc/lightdm, et la session
  d'invité (« autologin-guest ») ; GDM, custom.conf (/etc/gdm, /etc/gdm3) et daemon.conf (Debian) ; chaque fichier
  compté à son gestionnaire par son dossier. Une ligne de SDDM se lit comme SDDM 0.21.0 la lit, d'après sa source : le
  « # » coupe la ligne, et « [Autologin] # note » ouvre bien la section. Une ouverture posée dans un fichier n'est
  tenue pour annulée que par une ligne plus loin dans le même fichier, même section, même clé ; annulée ailleurs (un
  autre fichier, une autre section, une autre casse, une valeur que le gestionnaire ne comprend pas), elle est dite
  « non vérifiée », le fichier nommé, et non « pas d'ouverture automatique ». Un fichier ou un dossier de ces
  gestionnaires qui ne se lit pas (droits, pas du texte, plus de 1 Mio, plus de 1 000 fichiers) est nommé, non
  vérifié. Limites : GDM, SDDM et LightDM n'ont pas été lancés (sources de SDDM 0.21.0, de LightDM 1.32.0 et des
  réglages de GDM lues) ; Vanguard lit aussi les fichiers cachés et les fichiers de GDM de toutes les distributions,
  et peut donc signaler une ouverture que le gestionnaire ne lit pas ; ce que SDDM et GDM font d'une marque UTF-8
  (BOM) en tête de fichier n'a pas été vérifié (Vanguard la saute) ; /run/gdm/custom.conf n'est pas lu ; Vanguard ne
  lit pas encore une ligne tout à fait comme GLib et Qt : espace Unicode en début de ligne, octet NUL après un titre
  de section, marque UTF-8 en tête d'une autre ligne que la première, fichier de GDM qui s'arrête à une faute ; dans
  ces cas rares, qui demandent d'écrire dans /etc, une ouverture peut ne pas être vue.
- **L'avis du démarrage ne se tait plus sur /etc/ld.so.preload.** Un octet qui n'est pas de l'UTF-8 le rendait muet ;
  un fichier illisible aussi. Illisible (un lien vers une cible absente compris), il est maintenant dit
  « non vérifié », avec la raison ; trop gros pour être lu en entier, la suite non lue est dite.
- **Le bilan ne se tait plus sur un fichier ou un dossier de démarrage illisible.** Un /etc/ld.so.preload présent mais
  illisible (droits, dossier à sa place, boucle de liens, lien vers une cible absente) laissait le bilan en vert ; il
  est maintenant levé, « non vérifié », avec la même raison que l'avis du démarrage (le bilan le lève en niveau élevé,
  l'avis le dit en niveau moyen). Les autres fichiers de démarrage et de configuration que le bilan lit (shell,
  environnement, cron, démarrage de session) et leurs dossiers (/etc/cron.d, /etc/profile.d, dossiers d'unités et de
  démarrage de session…) sont levés aussi, sauf s'ils sont à root seul (un /etc/crontab en 600 ou un /etc/cron.d en
  700, par exemple) : dits en information. Un lien d'un de ces dossiers dont la cible ne se voit pas (un dossier fermé
  sur son chemin) est levé aussi. Ne sont pas levés : ce qui est absent, un lien vers une cible absente dans un de ces
  dossiers, un lien vers /dev/null (un fichier masqué), un chemin impossible (un fichier à la place d'un des dossiers
  du chemin) ; un dossier à la place d'un de ces autres fichiers est dit en information.
- **Les fichiers `EnvironmentFile=` d'un service se lisent comme systemd les lit.** Un commentaire se ferme au bout de
  sa ligne, un retour chariot seul coupe aussi une ligne. Une ligne finie par « \ » ne continue que dans une valeur :
  un commentaire ou une ligne sans « = » ne cache plus la ligne suivante. Les échappements d'une valeur sont défaits
  comme systemd les défait (« \x » hors guillemets, « \" \\ \` \$ » entre guillemets doubles, rien entre guillemets
  simples) ; la forme écrite et la forme défaite se jugent toutes deux, et une variable reprise par « ${VAR} » dans
  une ligne Exec= s'y développe sous la forme que le service reçoit. Une variable comme LD_PRELOAD posée juste après
  un commentaire, ou cachée par un échappement, est vue.
- **Un texte d'erreur nettoyé avec une seule règle des accents.** Le nettoyage d'un texte d'erreur (relevé local, et
  relais prêt mais pas en service) et sa relecture finale suivent maintenant la même règle pour les accents écrits à
  part (U+0300 à U+036F) : un accent n'est gardé qu'après une lettre, deux au plus de suite ; après un chiffre, une
  ponctuation ou rien, il est retiré, et U+034F, invisible, ne l'est jamais. Les deux règles écrites à part avaient
  divergé ; le relais en garde une copie, essayée sur les mêmes textes.
- **Plus solide.** Chaque caractère de format d'Unicode (ceux qui changent le sens de lecture ou cachent du texte)
  s'affiche « � », d'après la table d'Unicode 17. Un nom qui n'est pas en UTF-8 (verrou, rapport, interface WireGuard)
  est ouvert sous son vrai nom et montré avec ses octets en `\xFF`. Quand le système refuse un fil, Vanguard continue
  en « mode réduit », le dit, et ce qui n'a pas pu se faire est non vérifié. Un fichier inclus dans la configuration
  de sshd qui ne se relit pas est dit non vérifié au lieu d'être tu.
- **Un programme d'un dossier temporaire redevient suspect sous Windows.** Depuis la 0.95, un dossier analysé
  (`vanguard yara <dossier>`, l'antivirus) passe sous son chemin réel, `\\?\C:\…` sous Windows, qui ne commençait
  jamais comme `%TEMP%` ou Téléchargements : un programme sans signature qui s'y trouvait n'y était plus dit suspect.
  Chaque dossier est maintenant comparé sous sa forme écrite et sous son chemin réel, sans le préfixe ni la casse ; un
  dossier déclaré par un lien symbolique compte aussi sous Linux. Trouvé par l'essai de la VM Windows, avant la
  publication.
- **La ligne des couleurs se ferme dans la console.** À l'ouverture, la fenêtre relit les couleurs gardées
  (`vanguard couleurs --json`) ; la commande finissait tout de suite, mais sa ligne restait « en cours » et son
  compteur montait sans fin. Elle se ferme maintenant (« couleurs lues », ou l'erreur), comme celle d'un changement
  des couleurs. Un essai exige que chaque commande finie ferme sa ligne, réussie ou non.
- **Vérification et publication.** Les outils du dépôt ne disent plus vert sans avoir vérifié : une étape sautée est
  un échec sur GitHub (sauf exceptions nommées), et les essais sautés sont comptés jusqu'à la dernière ligne.
  shellcheck, cargo audit sur les verrous des crates à part et les nombres des README comparés au code s'ajoutent.
  SECURITY.md ne promet plus « au plus une version par jour » : une correction part dans la version suivante,
  parfois le jour même. Chaque outil Python du dépôt (garde-fou de confidentialité, crochets Git, vérification,
  publication) se lance isolé (`python3 -I`) : un module posé dans le dossier de l'outil ou dans PYTHONPATH ne peut
  plus désarmer le garde-fou avant un commit ou un envoi.
- **Les essais Windows de la VM portent la fenêtre.** `outils/vm-tester.sh --exe vanguard.exe --fenetre
  vanguard-fenetre.exe` dépose la fenêtre avec le programme ; sans `--exe`, elle est compilée avec lui et son
  empreinte gravée. Le dépôt est refusé, raison dite, si la fenêtre manque alors que `vanguard.exe` en nomme une, si
  elle n'est pas celle dont il porte l'empreinte, si ses marques se contredisent, ou si le surveillant de la VM est
  d'avant la version 3. Les empreintes et la signature d'un travail sont prises sur les fichiers préparés côté Linux,
  jamais sur leurs copies du dossier partagé, que la VM peut réécrire. `test.ps1` a une étape « Fenêtre (0.96) » : la
  fenêtre posée doit être celle dont `vanguard.exe` porte l'empreinte, puis `vanguard-fenetre --version` est lancée
  (30 s au plus) ; une fenêtre absente, autre ou illisible est un problème, jamais une étape sautée, et une autre
  fenêtre n'est jamais lancée. `outils/vm-tester.sh --verdict`, la porte de publication, exige un travail signé qui
  portait la fenêtre.
- **La page des fonctions a l'allure de la fenêtre.** La page des fonctions (GitHub Pages) reprend les couleurs, les
  onglets et les cartes de la fenêtre 0.96, lus dans son code à chaque rendu. Un onglet « Prise en main » la parcourt
  en dix étapes, dans l'ordre d'un premier usage (accueil, bilan, correction montrée puis relue, remettre comme avant,
  alertes, appareils, guide, page de commande, console). La section « À venir » est tirée du ticket public des pistes
  (#1). La console cherche dans la page : un mot tapé (accents et majuscules ignorés) masque les sections qui ne l'ont
  pas et surligne les passages ; Entrée passe au suivant, Échap remet tout. Les captures montrent la fenêtre, plus le
  terminal.
- **Des captures du README prises dans la fenêtre.** Six écrans (bilan, accueil, alertes, appareils, connexions
  sortantes, guide), en français et en anglais, dessinés par les essais de la fenêtre, sans écran, sur des données
  inventées : rien de l'ordinateur n'est lu. Ils remplacent les captures du menu du terminal et sont refaits à chaque
  version publiée.
- **Les tickets suivent chaque version, tout seuls.** À chaque version publiée, `outils/tickets-version.py` coche dans
  le ticket des pistes (#1) les points en gras de la version, remplace sa section « en préparation », et ferme les
  tickets « journal » que les commits de la version disent corrigés. Chaque texte passe d'abord la garde de
  confidentialité ; un corps vide, ou raccourci de plus de 20 %, est refusé.

## 12 novembre 2026 : version 0.94.0

- **« C'est normal chez moi », lié à ce qui est vraiment là (Linux).** Pour une alerte à corriger soi-même, Vanguard
  montre avant le choix chaque ligne signalée (fichier:ligne, la ligne entière), l'empreinte SHA-256 du fichier qui la
  porte et celle de chaque programme qu'elle lance ; à partir du niveau élevé, il faut taper « normal ». Le choix vaut
  90 jours, au clavier d'un terminal seulement, et ne tait l'alerte que pour cet état exact : un programme lancé
  changé, une ligne ajoutée, un lien posé à la place ou un fichier effacé, et elle revient en nommant ce qui a changé.
- **Ce qui se déclare, ce qui ne se déclare jamais.** Seules une unité systemd de l'utilisateur (une courte liste de
  réglages permis, chaque ligne Exec liée ; une unité de /etc/systemd/user seulement si root seul peut la changer) et
  une ligne de lancement d'un fichier de ~/.config/hypr, lu par son chemin réel, se déclarent normales. Jamais : une
  alerte critique (une bibliothèque hors paquet préchargée partout), une porte dérobée, une ligne ambiguë (variable,
  tube, chemin relatif, `bash -c '…'`), plus de 12 lignes ou une ligne trop longue pour être montrée en entier, ni
  .bashrc, .profile, environment.d, .desktop, crontab ou LD_PRELOAD de la session : la raison et le fichier:ligne sont
  dits, avec « retirez ou déplacez la ligne ». Sous Windows, rien ne change.
- **Ce qui revient.** Un ancien choix hors de ce périmètre revient à chaque bilan tant que la ligne est là, avec la
  raison ; un ancien choix fait sans l'état exact de ses fichiers revient aussi, à redéclarer après lecture du détail.
  La détection voit maintenant un préchargement coupé par « \ » en fin de ligne, une variable de Hyprland qui cache ce
  qu'elle lance, un lancement dans un fichier inclus hors de ~/.config/hypr, et une unité remplacée par un lien ne
  disparaît plus du bilan.
- **Ce qui relance un programme au démarrage, lu comme le système le lit (Linux).** Chaque ligne se juge telle que
  systemd, Hyprland ou sa configuration Lua l'exécute vraiment : variables remplacées, lignes coupées par « \ »
  recollées, échappements décodés, chemins simplifiés. Sont lus en plus les raccourcis de Hyprland qui lancent une
  commande, les générateurs de systemd, les unités de la session et les dossiers d'unités oubliés jusqu'ici. Ce que
  Vanguard ne sait pas lire jusqu'au bout est signalé, jamais compté comme sain, et rien de cela ne se déclare normal.
- **La configuration du client SSH lue comme SSH la lit.** Le bilan (réglages risqués) et le contrôle post-quantique
  découpent maintenant chaque ligne comme SSH, déplient les Include au fil de la lecture et suivent la portée des Host
  et Match jusque dans les fichiers inclus ; un en-tête que SSH applique peut-être à tous compte comme global pour
  l'alerte. ForwardAgent, StrictHostKeyChecking et WarnWeakCrypto sont jugés selon les valeurs que SSH accepte. Ce que
  Vanguard ne lit pas jusqu'au bout (forme non interprétée, motif d'Include qu'il ne résout pas comme SSH, fichier
  inclus trop gros, illisible ou trop profond, tube ou fichier spécial dans ~/.ssh) est dit « non lu » ou « non
  vérifié », jamais sain. Un octet hors UTF-8 ne cache plus une clé sans phrase de passe ou lisible par d'autres, et
  une configuration qui s'inclut elle-même ne remplit plus la mémoire.
- **Les cas limites de SSH, lus comme OpenSSH 10.** La forme « Match host=… » (critère=valeur) est lue comme
  OpenSSH 10 ; un motif de liste de 1023 octets ou plus sous « Match host » ou « originalhost », que SSH ne compare
  jamais, rend la portée douteuse au lieu de sûre. La comparaison des jokers ne s'appelle plus elle-même : une valeur
  KexAlgorithms géante ne fait plus planter Vanguard, et une liste de plus de 4096 octets est dite non lue. Une valeur
  qui écarte le post-quantique, placée après un en-tête douteux qui le propose, est dite comme un doute (« peut
  écarter »). /etc/ssh/ssh_config n'est lu que pour le post-quantique : le prêt de l'agent ou la vérification coupée
  écrits là ne sont pas signalés.
- **Aperçu d'une correction, sans rien changer.** Dans `audit --json`, chaque constat qui se corrige porte un jeton ;
  une commande en lecture seule relit sa seule règle et dit ce que la correction ferait (commandes, droits, valeurs
  d'avant, annulation), sans rien lancer ni noter.
- **Seize outils de plus en `--json`** (pour les scripts) : intégrité, dernières failles, mises à jour,
  démarrage, antivirus et son état, YARA, mémoire, secrets, verifier-moi, changements, règles, caméras cachées, type de
  NAT, canaux Wi-Fi et conteneurs. Aucune question, rien de changé (ni quarantaine, ni installation) ; ce qui n'a pas
  pu se voir rend le tout non vérifié. `secrets` ne donne jamais la valeur d'une fuite, `nat` n'écrit pas l'adresse
  publique, `canaux-wifi` pas le nom des réseaux ; sans Internet, rien ne part (ni STUN, ni arch-audit).
- **Commandes avancées.** `vanguard demarrage --retirer <empreinte>` retire du démarrage un seul programme, désigné
  par l'empreinte que `demarrage --json` donne avec son nom et sa commande : taper la commande vaut accord, sans autre
  question ; jamais un programme à garder ni un pare-feu, et il reste installé. La valeur d'avant est notée d'abord, et
  `--remettre <empreinte>` le remet exactement comme avant. `vanguard couleurs` (hors de l'aide) règle déjà les
  couleurs de la fenêtre à venir, gardées dans parametres.json. `vanguard --menu` (ou `--terminal`) ouvre toujours le
  menu du terminal, et `audit --json` dit si sa note est fiable.
- **La souris dans le menu du terminal.** Un clic ouvre une ligne (ou la coche dans une liste), le survol l'éclaire
  avec son aperçu, la roulette défile, le clic droit revient, et les touches de la ligne d'aide se cliquent. Un double
  clic n'ouvre plus deux écrans d'un coup. Maj et glisser sélectionne toujours le texte ; hors des menus, la souris est
  rendue au terminal.
- **Tableau de bord** (`vanguard tableau-de-bord`). Un fond de nuit, cyan pour ce qui va bien, ambre pour ce qui
  attend ; le logo s'ouvre sur un radar puis rejoint le rail de gauche, une courbe des alertes de 30 jours, une icône
  par partie du menu. Toujours sans JavaScript ; sans animation quand le mouvement réduit est demandé.
- **Textes piégés.** Les blancs qui n'en sont pas (remplissages coréens, Braille vide, joint de graphèmes) et des
  invisibles rares deviennent « � » à l'écran : un nom de réseau ou d'appareil ne paraît plus vide ni pareil à un
  autre. Les espaces d'une autre largeur (insécable, fine…) sont montrées comme une espace ordinaire, sans faire d'un
  nom de fichier normal un nom piégé. Les sélecteurs de variante sont retirés de l'affichage (celui des émojis reste),
  et un accès accepté pour un nom ne couvre plus un nom qui n'en diffère que par l'un d'eux.
- **Liste noire.** Quand le travail sans Internet est demandé, l'écran ne demande plus l'adresse publique à
  Cloudflare ni aux listes, même après un oui ; il le dit.
- **Correctifs.** Antivirus : clamscan n'est plus lancé quand il n'a rien à analyser (il lisait le dossier courant),
  et une base ClamAV de plus d'une semaine n'est plus dite à jour. Secrets : un historique ou une recherche coupés à
  leur borne sont dits au lieu d'un ✔, un dépôt lu à moitié est non vérifié, la recherche s'arrête après 20 minutes et
  ses rapports, qui nomment les auteurs des commits, sont effacés. Conteneurs : plus de « relancez avec sudo ».
  Alertes déclarées normales : deux déclarations en même temps (le blocage, une sortie de quarantaine, le menu, la
  remise à zéro) ne s'effacent plus l'une l'autre ; une sortie de quarantaine perdue y renvoyait le fichier à la
  passe suivante.
- **Renforcé après une campagne d'attaque.** `vanguard` sans argument ne lance aucun programme « vanguard-fenetre »,
  même posé à côté de lui : il ouvre le menu du terminal. Le bilan ne prend pas pour suspecte l'unité du veilleur que
  Vanguard pose lui-même (une valeur en pourcentage, comme `CPUQuota=20%`, n'est pas un code de systemd). L'unité de
  la sauvegarde automatique n'est tue que telle que Vanguard l'écrit, mot pour mot, et seulement si ce que Vanguard
  regarde ne peut rien changer à ce que rsync lance : aucun fichier ~/.popt (rsync le lit au départ, et une ligne de ce fichier peut lui
  faire lancer un autre programme), aucun complément de l'unité dans le compte, une destination qui est un vrai
  dossier du disque. Sinon elle est signalée comme toute copie par rsync dans une unité du compte (vers
  ~/.config/autostart, par exemple), sans pouvoir être déclarée normale ; un fichier de réglages de popt du système
  qui n'est écrit que par root est dit « non vérifié », en information. Disque débranché, sa destination ne se voit
  pas : une information, pas une alerte (rien ne se copie sans le disque), revue au bilan suivant disque branché.
  Pas encore regardé : un dossier personnel (HOME) changé pour le gestionnaire de session, qui ferait lire à rsync
  un autre fichier .popt ; ce réglage donne déjà au compte un faux dossier personnel entier, et sera jugé plus tard.
  `demarrage --retirer` et `--remettre` ne suivent plus aucun dossier qui est un lien (~/.config ou son dossier
  autostart remplacé par un lien) : rien ne s'écrit hors du dossier personnel. Une entrée rangée derrière un lien, ou
  elle-même un lien ou un tube, n'est pas proposée, et la liste la dit « non vérifiée » (dans `--json` comme dans la
  liste à cocher du terminal), jamais « aucun programme » ; un `systemctl --user` qui ne répond pas est dit aussi.
  Un service activé que systemd lit ailleurs que dans ~/.config/systemd/user (un dossier du compte qui passe avant
  celui du système, comme ~/.local/share/systemd/user, même sous le nom d'un service du système), ou un service du
  système que le compte complète (« nom.service.d »), est dit non vérifié aussi.
  Une seule lecture fait ce qui est montré, noté et écrit : une entrée changée entre cette lecture et son écriture,
  dans le même lancement, n'est pas écrite (l'empreinte d'une liste montrée plus tôt ne désigne que le chemin). Les
  entrées se lisent bornées, sans attendre un tube, au démarrage comme dans `vanguard lenteur` : une entrée de 64 Kio
  ou plus n'est ni retirée (elle l'était sans pouvoir être remise) ni remise par-dessus, une entrée qui, masquée,
  dépasserait cette borne est refusée avant d'être écrite, un fichier remplacé par un tube ne fige plus la liste, et
  une entrée réécrite garde ses droits ; `vanguard lenteur` dit le nombre d'entrées qu'il n'a pas pu lire, au lieu
  de les compter absentes. Le sceau des réglages s'écrit en deux temps : un arrêt brutal entre un fichier et son
  sceau ne fait plus crier au falsifié.
- **Sécurité des dépendances.** rustix 1.1.6 (avis RUSTSEC-2026-0486 : dans ses fonctions des attributs étendus,
  des octets jamais écrits étaient marqués comme initialisés pour un tampon vide), amené par crossterm.
- **Essais.** Cinq nouvelles cibles de fuzzing (ce qu'une ligne de démarrage lance et, pour la fenêtre à venir, les
  réponses qu'elle lit, sa console, son relais et sa progression), qui ont trouvé et fait corriger de vrais défauts.
- **Gardé pour la 0.95.** La fenêtre de Vanguard, ses écrans et ses gestes (voir, appliquer ou annuler une correction
  depuis elle) ne sont pas encore livrés : `vanguard` ouvre le menu du terminal, comme avant.

## 9 novembre 2026 : version 0.93.0

- **Le temps réel des fichiers (Linux).** Le veilleur examine maintenant chaque fichier écrit dans les dossiers à
  risque (Téléchargements, Bureau, ~/.local/bin, ~/.config/autostart), dès sa fermeture après écriture ou son arrivée
  par renommage, sans droits d'administrateur (fanotify, un groupe par dossier, aucun lien suivi). Un fichier certain
  va en quarantaine annulable selon les réglages, une famille connue se règle en un clic, un fichier suspect donne une
  alerte. Le tout tient en 128 Mio de mémoire (règles YARA, heuristiques, empreintes des dernières 48 heures). Un
  fichier perdu (file pleine, débordement du noyau) est compté puis repris par une relecture du dossier ; ce qui n'a
  pas pu être vérifié est dit, jamais compté sain, et la passe horaire reprend les dossiers. Un seul accord à
  l'allumage du veilleur. Essayé sous des inondations de milliers de fichiers dans de vraies VM Arch, Fedora et Debian.
- **ClamAV devient facultatif.** Vanguard ne propose plus de l'installer : son moteur fait l'analyse et lit toujours
  lui-même la base ClamAV installée. clamscan devient un second avis réglable (Paramètres › second-avis, lancé par
  défaut s'il est là ; coupé, c'est dit à chaque analyse). L'option « pua » ajoute les programmes indésirables aux
  analyses à la demande seulement, jamais au continu, où une empreinte met en quarantaine toute seule.
- **État de l'antivirus** (6.1.5, `vanguard antivirus --etat`) : le moteur utilisé, les bases et leur date, ce que le
  moteur ne lit pas (7z, RAR, bytecode de ClamAV…), le second avis, les PUA et le temps réel des fichiers. Rien n'est
  lancé ni changé ; `--detail` compte ce que la base ClamAV écarte (environ 10 s).
- **Quarantaine plus sûre.** Elle n'isole que le fichier examiné, jamais un lien dur vers un autre ; un contenu déjà
  en quarantaine n'y entre pas deux fois, et un contenu qu'on en a sorti n'y retourne pas tout seul.
- **Tableau de bord refait** (5.8, `vanguard tableau-de-bord`). Une vue d'ensemble lime sur noir, ou claire d'un
  clic, toujours sans script ni requête : la surveillance du réseau, le dernier bilan (note, réseau, problèmes,
  historique chaîné), les alertes des 30 derniers jours par gravité (anneau et graphique), la protection (veilleur,
  temps réel, quarantaine) et les nouveaux appareils. Toutes les fonctions du menu du terminal y sont reprises, avec
  leur place et leur commande, qu'un clic sélectionne pour la copier.
- **Coulisses** (Paramètres, éteintes par défaut, `vanguard parametres coulisses oui|non|voir`) : chaque commande
  lancée par Vanguard montrée en une ligne grise (programme, arguments abrégés, secrets cachés, durée, issue) ; les 200
  dernières restent en mémoire seulement, jamais sur le disque ni dans le journal.
- **Correctifs.** Analyser un appareil : Entrée seule revient, une cible mal tapée est dite sans aller au journal.
  Post-quantique : le profil laissé par un navigateur désinstallé est sans objet, plus « version illisible ». Rendre
  le réseau (Windows) : aucune fenêtre administrateur quand plus aucune règle ne coupe le programme.

## 8 novembre 2026 : version 0.92.0

- **De nouveaux gestes face à chaque menace.** En plus de Bloquer : **Suspendre** (le programme gelé, repris par
  `vanguard blocage reprendre`, rappelé à chaque bilan), **Couper son réseau** (le programme tourne mais ne parle plus
  à personne, rendu par `vanguard blocage rendre-reseau` ; sous Linux, ce processus seul ; sous Windows, deux règles du
  pare-feu sur son fichier), **Surveiller de plus près** (Linux : une alerte à chacun de ses lancements, pendant 7
  jours) et **Faire confiance** (un mot tapé, lié à l'empreinte du fichier, 90 jours). Un geste refusé par un
  garde-fou reste visible, grisé, avec sa raison. Chaque type d'alerte (rançongiciel, serveur de commande, outil
  d'attaque, malware connu…) a sa suite de gestes, prise dans une liste fermée. Une alerte notifiée se reprend par
  `vanguard alerte <id>` : relue dans le journal scellé, la menace est rejugée avant tout geste.
- **Isoler l'ordinateur du réseau** (`vanguard blocage isoler`, Linux et Windows). Tout est coupé, en entrée comme en
  sortie, sauf la session à distance en cours, le DNS et les serveurs de Vanguard ; le coût est dit avant l'accord, et
  `vanguard blocage lever-isolement` remet le réseau exactement comme avant. Avec un accord de plus (`vanguard veilleur
  isolement on`), un rançongiciel quasi certain gelé par le veilleur fait aussi isoler l'ordinateur avant son arrêt.
  Essayé sur un vrai Windows : session à distance gardée, Internet coupé puis rendu, pare-feu identique après la levée.
- **Le veilleur arrête le malware connu à son lancement (Linux).** Avec la protection active et un accord à part
  (`vanguard veilleur connus on`), un programme du compte dont l'empreinte est celle d'un malware connu est gelé avec
  ce qu'il a lancé, sa preuve relevée, puis arrêté et mis en quarantaine. Seulement un fichier posé dans les dossiers
  du compte : jamais un programme du système ou installé, un processus critique, Vanguard ni un accès à distance
  pendant une session. Un garde des lancements en root (fanotify, du noyau Linux) est livré en préparation, caché :
  il n'apparaîtra au menu et au bilan qu'une fois fini.
- **Un moteur d'analyse commun, avec ses propres heuristiques.** Chaque fichier analysé reçoit un seul verdict :
  certain (empreinte MalwareBazaar, signature sûre de ClamAV, fichier d'essai EICAR), famille (règle YARA, signature
  ClamAV), suspect, sain ou non vérifié. « Sain » seulement si tout a été lu. Les bases de ClamAV déjà installées sont
  lues par Vanguard lui-même, sans lancer clamscan, et seulement si aucun compte ordinaire ne peut les modifier. Des
  heuristiques (programme sans signature dans les Téléchargements, contenu compressé comme par un paqueteur, double
  extension, macro qui se lance à l'ouverture, PowerShell encodé, script qui télécharge puis lance…) donnent au plus
  « suspect », jamais une quarantaine à elles seules. `vanguard verifier-fichier`, les téléchargements, le courriel
  suspect et les extensions passent par ce moteur.
- **Programmes publiés compilés par zig.** Linux et Windows sont compilés par zig et cargo-zigbuild, épinglés et
  vérifiés par leur empreinte, ici comme dans la CI : deux compilations donnent le même programme, octet pour octet.
  Le programme Windows importe l'UCRT, fournie par Windows 10 et 11 sans rien installer.
- **Moins de faux constats.** La protection post-quantique de Zen, Floorp et Waterfox se lit maintenant (version de
  leur moteur) ; sans le groupe docker, un démon Docker arrêté est reconnu sain ; un journal d'événements de Windows
  désactivé et vide n'est plus dit « vidé ou remplacé » ; les « non vérifié » attendus (un choix de la personne,
  l'état de l'ordinateur) ne vont plus au journal des erreurs ni en ticket, mais restent « non vérifié » au bilan.

## 7 novembre 2026 : version 0.91.0

- **Vanguard ne vise plus macOS.** Plus de programme pour le Mac, plus de compilation ni d'essais sur le Mac de GitHub,
  plus de partition MACOS sur les nouvelles clés de secours (une clé déjà écrite garde la sienne jusqu'à sa prochaine
  réécriture). Le déploiement retire de la clé le programme macOS, son mode d'emploi et son lanceur. Un Vanguard pour
  Mac déjà installé ne trouve plus de mise à jour, sans erreur ; il ne recevra pas non plus de changement de clé : le
  désinstaller. Les nomenclatures (SBOM) sont produites et attestées par le travail « nomenclatures » de `ci.yml`, et
  `outils/publier-version.sh` vérifie toujours cette attestation avant de publier.
- **Le cadre de tête prend toute la largeur de la fenêtre, les titres aussi.** Dans les menus, il suit la fenêtre
  quand on la redimensionne, panneau d'aperçu compris (la dernière colonne reste libre, pour l'ancienne console de
  Windows) ; sur les autres écrans, il prend la largeur au moment de l'affichage. Dans une fenêtre étroite, il
  rétrécit au lieu de déborder : la précision de droite est coupée (« … ») ou retirée avant le titre. Les titres
  « ━━ » et sous-titres « ── » font de même, dans les menus, les listes à cocher et la recherche ; à côté du panneau
  d'aperçu, ils s'arrêtent une colonne avant lui. Le texte des listes garde sa largeur. Sans terminal (tube, rapport),
  cadre et titres gardent leurs 76 colonnes.
- **Calculs vérifiés partout (règles de l'ANSSI pour Rust).** Sous Linux, tout le programme refuse les débordements
  de calcul et les conversions de nombres qui tronquent : chaque calcul est vérifié, et une valeur hors bornes donne
  une erreur dite plutôt qu'un nombre faux. Chaque erreur du programme a son message lisible ; la phrase de passe et
  la clé de session sont effacées de la mémoire après usage. Les parties Windows restent à relire
  (CONFORMITE-ANSSI.md).
- **Les menus se souviennent de l'outil lancé.** En revenant dans un groupe, la surbrillance revient sur l'outil lancé
  la dernière fois, retrouvé par lui-même et non par son numéro.

## 6 novembre 2026 : version 0.90.0

- **Options de défense, en un écran** (`vanguard options-defense`, outil 4.10 sous Windows, 4.9 sous Linux). Ce qui
  défend l'ordinateur, chaque option lue avec ce qui l'impose et réglable d'ici :
  - sous Windows : les réglages de Microsoft Defender, ses exclusions et ses programmes permis ; les 19 règles de
    réduction de la surface d'attaque (ASR), chacune à bloquer, en audit ou désactivée ; le Pare-feu Windows de chaque
    profil et ses règles existantes ; les stratégies (GPO, Intune) qui imposent une valeur, un antivirus tiers, un PC
    géré ;
  - sous Linux : le pare-feu (ufw, firewalld ou nftables), son état, le couper ou le rallumer.

  Renforcer se fait après accord. **Baisser est le choix de la personne, jamais celui de Vanguard** : la baisse est
  montrée par le processus administrateur (root sous Linux), confirmée par un « o » tapé (Entrée seule dit non), sa
  valeur d'avant notée d'abord ; le bilan la dit « par votre choix » et « Rallumer » la remet. MODELE-DE-MENACE.md a
  une section « Baisses par choix » qui dit aussi ce que Vanguard refuse quoi qu'il arrive : contourner la protection
  contre les falsifications, arrêter le service de Defender ou du pare-feu, fermer le pare-feu sur le réseau d'une
  session à distance en cours, retirer les tables d'iptables-nft de Docker, libvirt ou fail2ban.

- **Gestes de défense confirmés, sous Windows et sous Linux.** Une bonne part de ce que le bilan et la chasse aux
  menaces trouvent ne reste plus un conseil « à faire à la main » : Vanguard le défait lui-même, en administrateur
  (root sous Linux), après avoir rejugé ce qu'il voit, montré le geste et reçu un oui. La valeur d'avant est notée et
  « Ce que Vanguard a changé » l'annule ; un geste qui ne s'annulera pas est dit « non annulable » avant la question.
  - Windows : SmartScreen, intégrité de la mémoire, protection LSA et Credential Guard rallumés ; stratégies qui
    affaiblissent retirées hors domaine et hors gestion ; exclusions de Defender retirées ; compte local désactivé ;
    mot de passe posé sur un compte qui n'en a pas, tapé dans la fenêtre administrateur seulement ; touches
    rémanentes remises par `sfc /scanfile` ; OpenSSH corrigé ; racines de certificat ajoutées retirées ; lancements
    cachés (Run, tâches, dossier Démarrage, abonnements WMI) retirés, le vrai Defender reconnu à sa place et à sa
    signature, jamais à son seul nom ; un outil de prise de contrôle lancé mais pas connecté retiré (connecté :
    refusé).
  - Linux : compte caché verrouillé (jamais supprimé), compte retiré d'un groupe sensible, sudo sans mot de passe
    durci (validé par visudo), setuid ou capacités suspects retirés, service ou démarrage ajouté en cachette défait,
    serveur SSH durci (validé par `sshd -t`, les sessions ouvertes restent), programme suspect arrêté après la copie de
    ses traces, programme de Vanguard remplacé hors de Vanguard remis (l'imposteur gardé en quarantaine). Un geste qui
    pourrait couper la personne de son ordinateur reçoit un AVERTISSEMENT, et la question dit non par défaut.

- **Gardes du blocage.** Le blocage ne touche jamais la session à distance en cours (jugée par l'ascendance du
  programme et par le port réel du Bureau à distance) ; une signature Microsoft ne fait que refuser un geste, jamais
  l'autoriser pour un autre programme ; Edge, Office et Teams signés Microsoft ne sont pas mis en quarantaine, sans
  immunité pour un programme qui prendrait leur nom ; une quarantaine en administrateur ne suit jamais un lien ; un
  chemin court (8.3) se juge aussi en long. `vanguard blocage juger` dit ce que le blocage ferait, sans rien faire.

- **Moins de PowerShell, sous Windows comme sous Linux.** Les comptes, racines de certificat et partages, la
  persistance (Run, tâches, Démarrage commun, abonnements WMI) et Defender passent par le processus administrateur de
  Vanguard sans PowerShell ; sous Linux, les services se règlent par systemd sur le bus, avec polkit, sans `sudo
  systemctl`.

- **Petites choses.** Dans les menus, le curseur du terminal ne sautille plus d'une ligne à l'autre. Une correction
  rend un code de sortie qui dit ce qui a été fait. Le lecteur des journaux .evtx suit evtx 0.15.1 (RUSTSEC-2026-0431).

## 3 novembre 2026 : version 0.89.1

- **Agent Vanguard (sans IA).** Une partie de Vanguard qui l'aide à mieux tourner sur votre ordinateur, sans IA et
  sans rien envoyer. Il a quatre missions, chacune avec son interrupteur (Paramètres › Agent Vanguard,
  `vanguard parametres auto-reglage`) :
  - **délais et seconds essais** : une règle du bilan qui frôle son délai deux semaines de suite, ou le dépasse deux
    fois en 7 jours, voit son délai monter une fois, jamais plus haut ; une règle dont le « non vérifié » passager se
    résout le plus souvent au bilan suivant est relancée une fois à la fin du bilan, dans le délai total ;
  - **cache du passage horaire** : le passage horaire de la surveillance reprend, une fois sur deux au plus, le
    résultat récent de quelques vérifications lentes, avec son âge (« vérifié il y a 40 min »). Un bilan lancé à la
    main vérifie tout à neuf. Le pare-feu, l'antivirus, les connexions à distance, les ports et la persistance ne
    sont jamais repris. Une durée qui se trompe raccourcit, et trop d'écarts coupent la cache de la règle ;
  - **relevé local** (voir le partage, plus bas) ;
  - **avis sur les corrections** : une correction qui échoue deux fois le dit, et répondre « tout » la laisse hors du
    lot pour la proposer ensuite seule ; une correction qui ne tient pas le dit aussi.

  Les règles et ce qu'elles jugent ne changent jamais : couper une mission, ou tout l'Agent, ne retire aucune
  vérification. Chaque changement est noté avec sa valeur d'avant dans un journal scellé et s'annule (`annuler
  <règle>`, `tout-remettre`). `vanguard agent` montre ses missions, leur dernier tour et son journal, en lecture
  seule ; `--json` donne la même vue pour un script, sans aucune donnée personnelle. Les règles du bilan partent
  aussi la plus longue d'abord, pour que le bilan ne finisse pas sur elle.

- **Partage avec l'auteur, préparé : rien ne part dans cette version.** Paramètres › Partage avec l'auteur (`vanguard
  parametres partage oui|non|voir`). Le relevé local note chaque jour, sur l'ordinateur et en comptes agrégés, les
  erreurs de Vanguard, ses lenteurs, le résultat des corrections, les choix faits dans Vanguard, le matériel (sans
  numéro de série) et le nom et la version des logiciels, services et pilotes en cause.
  - Jamais de mot de passe, de contenu de fichier, de site visité, de texte tapé, d'argument de commande ni
    d'inventaire des logiciels ; un texte d'erreur est nettoyé ou jeté en entier.
  - Le relais de l'auteur n'est pas en service : Vanguard n'a aucune adresse où envoyer et n'ouvre aucune connexion
    pour cela. MODELE-DE-MENACE.md décrit ce qui partira le jour où il le sera, et comment.
  - « Voir ce qui serait envoyé » montre le prochain lot en file ou, sinon, le lot du relevé le plus récent refait
    pour le voir, octet pour octet. « Non » arrête le relevé et l'efface, avec la file d'envoi et l'identifiant
    d'installation. `VANGUARD_ENVOI=0` l'emporte toujours.

- **Revenir à la 0.89.0, puis à la 0.89.1.** Rien de dangereux, mais deux choses se voient :
  - la 0.89.0 réécrit les mesures de l'autodiagnostic (`autotest/mesures.json`) sans sceau. De retour en 0.89.1, le
    bilan le dit par une alerte élevée (« L'état de Vanguard a été changé hors de Vanguard »), avec sa cause
    possible : une version 0.89.0 ou plus ancienne a servi ici. Les mesures repartent de zéro, et l'alerte disparaît
    quand le bilan suivant réécrit le fichier avec son sceau. Aucune alerte n'est tue, aucune vérification retirée ;
  - un réglage changé dans la 0.89.0 réécrit le fichier des paramètres sans la réponse au partage. Un « Non » n'est
    pas oublié pour autant : il est aussi noté à part (`partage-non`, dans le dossier de Vanguard), que la 0.89.0 ne
    touche pas, et il tient jusqu'à ce que vous répondiez « Oui ». Sans « Non », c'est comme au premier lancement :
    l'avis du partage revient.

  Les fichiers de l'Agent (`agent/`, `autotest/cache.json`, `autotest/reglage.json`) ne sont pas touchés par la
  0.89.0.

- **Pour l'auteur.** Le journal des erreurs est trié en causes suivies d'une nuit à l'autre, et la veille de nuit
  alerte sur ces causes et sur une lenteur de l'autodiagnostic. Le code du relais (`relais/`, non déployé), la relève
  de ses lots et les signaux de la flotte sont prêts : chaque lot y est relu comme une donnée hostile, une source ne
  vote qu'une fois par jour, et un faux positif probable ne va jamais à l'IA, seulement dans un ticket.

## 1er novembre 2026 : version 0.89

- **Services de Windows réglés par Vanguard lui-même, sans PowerShell.** Vanguard arrête, démarre, désactive ou remet
  un service directement par le gestionnaire de services de Windows, sans lancer PowerShell. Cela vaut pour le
  Registre à distance, la découverte SSDP, Windows Update, l'heure, la télémétrie, la file d'impression, le dossier
  Temp et le cache de Windows Update. C'est la fenêtre administrateur de Vanguard qui le fait.
  - Chaque service n'a que les actions prévues pour lui : aucune ne peut couper une protection de Windows.
  - Les services qui en dépendent sont arrêtés d'abord, puis relancés ensuite.
  - Un dossier vidé ne suit jamais un lien qui mènerait ailleurs.
  - Un réglage de l'optimiseur qui ne peut rien envoyer est dit « non fait », au lieu d'être compté fait.

- **Pare-feu et type de réseau sans PowerShell.** Rallumer le pare-feu, le mode Wi-Fi public et le choix du réseau
  (public ou privé) passent directement par Windows, et chaque changement est relu.
  - Aucune ligne ne peut couper le pare-feu.
  - « Bloquer toutes les connexions entrantes » est refusé pendant une connexion à distance (Bureau à distance, SSH),
    ou quand Vanguard ne peut pas savoir s'il y en a une.
  - « Bloquer le port » ne vise jamais SSH ni le Bureau à distance, ni le port d'une session à distance ouverte.
  - Ce qui rend le PC moins protégé, comme rouvrir les entrées ou repasser un réseau en Privé, est dit comme tel avant
    d'être fait.

- **Corrections du registre sans PowerShell.** Onze corrections passent directement par Windows : couper le Bureau à
  distance, NetBIOS et SMBv1, l'heure par Internet, Winlogon, les débogueurs piégés (IFEO), « toujours installer en
  administrateur », etc.
  - Juste avant d'écrire, Vanguard relit la valeur et la juge de nouveau.
  - Une valeur déjà bonne n'est pas réécrite, et c'est dit.
  - La valeur d'avant est notée, pour Défaire.
  - NetBIOS est coupé sur chaque carte réseau, et Vanguard dit qu'il faut redémarrer.

- **Guillemets des services posés tout seuls, et dit.** Le chemin d'un service
  peut contenir une espace sans guillemets : un autre programme pourrait alors se glisser à sa place. La correction
  acceptée ajoute elle-même les guillemets et le dit : « Vanguard ajoute les guillemets au chemin du service X ».
  - Elle ne le fait que si seuls les guillemets changent et que le programme cité existe.
  - Les dossiers du chemin (%ProgramFiles%, %SystemRoot%, %SystemDrive%, %ProgramData%…) sont demandés à Windows,
    jamais pris dans les réglages d'un programme, qu'un autre programme aurait pu changer.
  - Une variable inconnue laisse la correction à faire à la main, sans rien écrire.
  - Le changement passe par le gestionnaire de services, comme Windows le prévoit, et non en écrivant directement
    dans le registre.

- **Sceaux : plus de fausse alerte « refaits ».** Vanguard scelle ses fichiers d'état pour voir si un autre programme
  les change. Avant, un verrou resté seul faisait dire à tort que les sceaux avaient été refaits, avec une alerte
  élevée. Cela arrivait avec un Vanguard arrêté au mauvais moment, un disque plein, ou deux Vanguard lancés ensemble
  au premier usage.
  - La 0.89 pose un témoin juste après le premier vrai sceau. C'est lui, avec le journal des événements, qui montre
    qu'une version qui scelle a déjà servi sur cet ordinateur.
  - Le verrou laissé par une 0.86 à 0.88 compte encore comme témoin s'il date d'avant le 30 novembre 2026. Une mise à
    jour depuis ces versions garde donc sa protection.

- **Images SVG jointes à un courriel : les pièges cachés sont vus.** Une image SVG peut contenir un script ou un lien, comme une page web.
  - Un script caché autrement que par une balise `<script>` en clair (nom préfixé, gestionnaire `onload`, adresse
    `javascript:`, HTML intégré, animation, entités de la DTD) rend l'image « active ».
  - Une image compressée (.svgz) est décompressée, avec des bornes de taille et de temps, puis jugée ; ses liens et
    ses formulaires sont examinés.
  - Une image en UTF-16 est lue comme une autre.
  - Une image trop lente à lire est arrêtée au bout de 5 secondes et dite « pas vérifiée en entier ».
  - Un SVG ordinaire d'Illustrator ou d'Inkscape ne se dit plus « contient du script » : il garde seulement une
    information.

- **Archives zip jointes : lues sans croire ce qu'elles annoncent.**
  - Une archive précédée d'autres octets (programme auto-extractible, bourrage, derrière un PDF) est quand même
    ouverte, et c'est dit.
  - Le contenu est relu entrée par entrée, sans croire le sommaire de l'archive.
  - Une archive coupée ou illisible est dite « pas vérifiée ».
  - Le nom de chaque fichier de l'archive est jugé en entier, caractères invisibles et retournement (U+202E)
    compris : un « .exe » au bout d'un très long nom n'est plus perdu.

- **Noms de fichiers piégés par des caractères invisibles.** « facture.pdf[U+200B].exe », avec un
  caractère invisible entre « .pdf » et « .exe », passait pour un document. Les caractères invisibles sont
  maintenant retirés avant de juger le nom, et dits « nom piégé ». Cela vaut pour les fichiers téléchargés, les
  pièces jointes et les noms dans les archives jointes. Les accents et les autres écritures ne donnent aucun signe.

- **Analyse par Microsoft Defender : plus de « ✔ » à tort.** Defender peut trouver une menace, la retirer, et répondre quand même « tout va bien » par son
  code.
  - Vanguard lit maintenant ce que Defender écrit, et le compare à la liste des menaces que Defender a notées pendant
    l'analyse. Une menace notée compte toujours.
  - Une exclusion qui couvre le fichier ou le dossier analysé enlève le « ✔ » : rien n'est garanti, et c'est dit.
  - Sans droits d'administrateur, les exclusions sont cachées : le résultat est dit « invérifiable », jamais « ✔ ».
  - Un fichier que Defender a sauté parce qu'il est exclu est dit « impossible à vérifier », plus « logiciel
    malveillant connu ».
  - Defender est lancé depuis son vrai dossier, et une ligne par minute montre que l'analyse avance.
  - L'analyse complète dit que, sous Windows, Defender analyse tout l'ordinateur.

- **Point de restauration de Windows vraiment créé, et vérifié.**
  Avant, Vanguard pouvait dire « OK » sans qu'aucun point ne soit gardé.
  - Le point est demandé à Windows comme le fait Windows lui-même, puis Vanguard relit la liste : seul un point
    nouveau compte.
  - Si le point est sauté ou refusé, la raison est dite, puis la question « continuer sans point ? ».
  - Répondre non arrête tout et dit « arrêté à votre demande : rien n'a changé », et non « une étape a échoué ».

- **Fenêtre administrateur de Vanguard : plus de programme pris au hasard.** Ce que Vanguard lance en
  administrateur ne peut plus être remplacé par un programme posé dans le compte.
  - DISM, sfc, chkdsk, netsh, w32tm, ipconfig, net accounts, powercfg et Defender sont lancés depuis le dossier de
    Windows, avec des réglages fixes, jamais par leur seul nom. winget est pris dans App Installer de Microsoft.
  - PowerShell et ces programmes démarrent avec un environnement réduit à ce que Windows fournit ; les réglages du
    compte (variables, dossiers déplacés) ne les suivent plus.
  - Toute la liste est vérifiée avant la demande d'administrateur ; une liste mal formée est refusée sans rien
    faire.
  - Chaque échec est dit en phrases, avec quoi faire, le détail technique entre parenthèses.
  - Retirer les menaces de Defender passe aussi par cette fenêtre : il n'y a plus qu'une seule forme de demande
    d'administrateur, celle qui nomme Vanguard.

- **Vérification du disque (chkdsk) : plus de fausse promesse.** Quand chkdsk ne peut pas
  vérifier le disque, Vanguard ne dit plus « échec » ni « à finir au redémarrage » : rien n'est programmé. Il dit
  « disque à vérifier » et quoi faire (lancer `chkdsk X: /f` en administrateur), avec la vraie lettre du disque de
  Windows.

- **Fichier hosts de Windows : jamais laissé vide.** Windows ou l'antivirus tient parfois ce fichier
  quelques secondes. Vanguard réessaie au lieu d'échouer, écrit le fichier d'un coup, et remet l'ancien contenu si
  l'écriture rate.

- **UPnP de la box : un échec n'est plus « rien d'ouvert ».** Quand l'outil `upnpc` est installé
  mais échoue, ou que la box ne répond pas, le résultat est dit « non vérifié ». Avant, il disait que l'outil était
  absent, ou que l'UPnP était actif sans rien d'ouvert.

- **Certificats racine (Linux) et clé VANGUARD : un fichier illisible n'est jamais compté vide.**
  - Un fichier de certificats illisible, ou dont Vanguard ne sait pas lire le nom, n'est plus « aucun certificat
    ajouté » : il est nommé, avec la commande qui le retire.
  - Un dossier de la clé VANGUARD qui ne s'ouvre pas ne la laisse plus « inchangée ».

- **Clé VANGUARD : une copie ne passe plus pour elle.**
  - Deux clés au même identifiant sont dites « en double » : il faut en débrancher une. Aucune n'est choisie selon
    l'ordre de branchement.
  - Une même clé vue par deux chemins ne compte plus comme sa propre copie.
  - La partition de démarrage (VTOYEFI) devenue illisible, renommée ou absente est dite, au lieu d'être sautée sans
    un mot. Une clé refaite exprès sans Ventoy s'accepte par `--accepter-vtoyefi`.

- **Mises à jour : les dossiers du programme vérifiés jusqu'en haut.** Une mise à jour
  faite en root vérifie chaque dossier au-dessus du programme, pas seulement le dernier : un compte ne peut
  plus glisser son propre dossier à la place. Une clé de signature retirée par la clé de secours le reste, même si
  les sceaux sont refaits.

- **Verrous remplacés : dits au bilan.** Un dossier, un lien ou un fichier aux droits
  retirés, posé à la place d'un verrou de Vanguard, empêchait d'écrire le journal des événements, la liste des
  appareils du réseau ou les alertes, sans un mot. C'est maintenant un constat élevé au bilan, qui dit ce qui ne
  s'écrit plus.

- **ClamAV : signatures trouvées, rien installé sans le demander.**
  - Le dossier des signatures réglé dans freshclam.conf est passé à l'analyse : elle ne finit plus en échec faute
    de signatures.
  - La commande d'installation de ClamAV et celle des signatures sont montrées avant la question qui les accepte.
  - Sans clavier, ou avec une entrée fermée, la réponse est « non » : rien n'est installé ni activé tout seul.
  - Vérifier un fichier sans ClamAV donne quand même son verdict.

- **Liste MalwareBazaar abîmée : dite.** Une copie de la liste complète qui ne s'ouvre plus n'est plus
  prise pour une liste vide : l'avertissement le dit, au lieu de dire « analysé » avec les seules empreintes récentes.

- **Menus : un aperçu à droite.** Quand la fenêtre est assez large (110 colonnes et plus), un
  panneau à droite du menu montre la description de la ligne choisie et ce qu'elle ouvre. La recherche montre aussi
  l'aperçu du résultat. Les petites fenêtres restent comme avant.

- **Protections des programmes vérifiées avant de partir.** `vanguard deploiement verifier-binaire` (ancien nom :
  `verifier-pe`, gardé) lit dans leurs en-têtes, sans les lancer, les protections des programmes publiés : sous Linux
  PIE, marque du RELRO complet (PT_GNU_RELRO dans les données et sur la section dynamique, BIND_NOW), pile non exécutable, aucun segment écrivable et exécutable ;
  sous Windows ASLR à haute entropie (avec LARGE_ADDRESS_AWARE, qu'il exige), DEP et relocalisations, en plus des DLL
  de System32 et du manifeste ; sous macOS chaque tranche en PIE, une __PAGEZERO de 4 Gio et, sur arm64, une
  seule signature, qui tient dans la tranche. Chacun doit aussi être du système et de l'architecture livrés (ELF x86-64
  64 bits petit-boutiste, PE32+ AMD64, tranches Mac arm64 et x86_64) : les scripts disent lequel ils attendent
  (`--attendu linux|windows|macos`), et un .exe remplacé par un programme Linux, ou un programme 32 bits, est refusé.
  verifier.sh vérifie toujours le programme de débogage qu'il vient de compiler, et les programmes de publication
  seulement s'ils sont ceux compilés de ce commit (`outils/compiler-version.sh`) ; le déploiement, la publication et
  la CI vérifient ceux qui partent, avant de les envoyer, et refusent un programme qui en perd une. CFG et CET sont
  affichés sans être exigés.

- **RELRO appliqué pour de bon sous Linux.** Le programme Linux (static-pie musl) portait la marque du RELRO complet,
  mais le démarrage de musl ne l'applique pas : la GOT et `.data.rel.ro` restaient écrivables pendant toute la vie
  du processus. Vanguard met désormais lui-même ce segment en lecture seule au lancement, comme le fait le chargeur
  de glibc ; un échec est noté au journal sans empêcher le démarrage.

- **Solidité.** Travail interne, sans changement visible : le code ne peut plus
  planter sur une donnée inattendue (règles « anti-panique » partout), le code risqué (`unsafe`) est refusé partout
  sauf aux endroits nommés avec leur raison, les lecteurs de données hostiles ne font ni débordement ni conversion
  hasardeuse, certains sont prouvés par Miri et Kani chaque semaine, les dépendances sont relues avec cargo vet, et le
  code est relu selon le guide Rust de l'ANSSI.

## 26 octobre 2026 : version 0.88

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
  sur preuve : la tête du journal des événements, scellée, écrite par la version d'avant. Cette preuve ferme le champ
  en clair des sceaux ramené en arrière à la main ; scellée comme le reste, elle peut être recalculée par un programme
  qui vise exprès ce mécanisme (limite du modèle de menace). Sans elle (journal effacé, tête réécrite), des sceaux
  ramenés à une forme d'avant n'acceptent ce qui est là que tel quel, sans le croire, et le bilan dit les sceaux
  refaits ; sans aucune trace du journal (une version d'avant qui n'avait encore rien noté, ou tout effacé), rien
  n'est repris non plus, et le bilan le dit un cran plus bas avec ces deux causes. Le bilan et le menu notent la tête
  du journal dès leur début, pour la prochaine mise à jour. Ces sceaux d'avant sont jugés avant que le journal laisse
  sa moindre trace (verrou, dossier) : les siennes ne les font plus dire refaits. Une version plus ancienne repassée
  ici (une clé ou un Mac restés en arrière) se dit au bilan un cran plus bas, sans rien faire reprendre, un mois ou
  tant qu'un fichier qu'elle a laissé n'est pas réécrit. Un verrou des sceaux gardé par un autre programme ne fait
  plus attendre qu'une fois, une seconde en tout, et se dit au bilan ; vanguard --version n'attend rien ; les
  événements qui n'ont pu être notés sont comptés et dits au bilan une fois le verrou rendu, même s'il en manque
  d'autres pendant qu'il les dit (si Vanguard est tué avant, ses événements en attente se perdent sans compte ; ce
  compte, écrit sans sceau, peut être effacé), et « sceaux refaits » retombe une fois dit. Un test relit le code pour
  que chaque nom de fichier scellé n'y paraisse que là où il est permis, exceptions dites ; VANGUARD_ORIGINE n'est
  crue qu'aux octets du programme qui tourne. Le modèle de menace dit les limites : le dossier effacé en entier, et un
  programme qui vise exprès ce mécanisme.
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
- **Lectures et preuves resserrées (quatrième campagne d'attaque).** Journaux de Windows : une action de tâche écrite
  avec des attributs (`<Exec id="…">`), un préfixe d'espace de noms (`<task:Exec>`), un blanc avant « > », une section
  CDATA ou des références numériques (`&#112;`) est lue (EVT-TAC-001), une balise écrite dans un commentaire, une
  instruction ou une CDATA n'en est pas une (un `</Arguments>` dans une CDATA ne coupe plus la valeur, un `<Command>`
  en commentaire ne passe plus avant la vraie), une balise `<Command/>` vide n'efface plus la suivante, et toute balise
  d'action ouverte de plus que les actions lues donne une alerte au lieu d'un silence ; la commande encodée de
  PowerShell est reconnue sous toutes ses formes (`-e`, `-enc`, `--enc`, `-EncodedCommand:…`, `-e^nc`, tirets
  typographiques « –enc ») dans les processus, les tâches, les services et les blocs de script (EVT-PRC-001,
  EVT-TAC-001), et jugée sur sa valeur : un nom d'encodage ou un numéro de page de codes (« gc $f -enc byte »,
  « Out-File -en BigEndianUnicode ») n'en est pas une, ni « certutil -encode » ; dans un script, il faut un base64 qui
  décode en texte UTF-16 lisible, « -EncodedCommand » en entier, ou une variable passée à PowerShell nommé. Mémoire :
  une image chargée dont le code est mappé loin de son en-tête se lit en un seul morceau, et l'analyse est dite
  incomplète plutôt que saine ; une image intacte hors des dossiers du système (un programme lancé de ~/.cache ou de
  /var/tmp) est lue en mémoire au lieu d'être « laissée au scan de fichiers », qui ne la lisait pas, une fois pour tous
  les processus qui la chargent, mais comptée lue seulement après un processus lu en entier (un processus leurre qui
  remplit sa part ne la fait plus sauter ailleurs) ; elle est nommée par son fichier (Linux : périphérique, inode et
  dates ; Windows : volume, identifiant du fichier et date d'écriture, qu'un programme peut remettre à l'ancienne après
  avoir récrit le fichier : une fenêtre étroite, pendant une même analyse). Un fichier de données mappé sans code (un
  journal de systemd) n'est ni lu ni dit morcelé, sauf s'il commence par un en-tête ELF ou PE, et un fichier mappé sans
  code dont le début n'est pas mappé ou pas lisible est laissé sans être compté (rien ne s'exécute d'une page sans
  « x ») ; les bibliothèques de l'hôte vues par les jeux de Steam (/run/host/usr) sont reconnues comme celles du
  système. Seules les images des dossiers du système restent non lues, et c'est dit. Sous Windows, ces changements
  n'ont pas encore été essayés sur un vrai Windows. Corpus de détection : chaque version par système d'une fonction du
  fil d'une règle (ses conditions `cfg` évaluées comme pour le programme publié : essais, banc de fuzzing, mode
  débogage et fonctionnalités exclus) doit appeler la suivante, y compris le lecteur des tentatives de connexion sur
  chaque système, et le bilan et le corpus passent par le même juge pour les connexions forcées (COM-CPT-003).
  Décompression : l'archive d'une extension, la liste complète de MalwareBazaar et les fichiers gzip (bases de pacman,
  listes téléchargées) se lisent avant une échéance et, quand leur taille est annoncée, avec des octets compressés
  plausibles pour elle : des blocs deflate vides ne tiennent plus le processeur des minutes ; une archive d'extension
  trop lente est dite « délai dépassé », pas « illisible ». L'archive d'une extension refuse aussi deux entrées aux
  mêmes octets, et deux fois le même nom.
- **macOS maintenu, sans nouveautés propres.** Le programme macOS reste publié et testé automatiquement sur un Mac
  de GitHub ; il n'a jamais été essayé sur un vrai Mac, et la page, les README et les notices le disent.
- **Optimiser refusé en administrateur.** Les outils d'Optimiser (logiciels, nettoyage, réglages, jeux, mesures du
  réseau) refusent de tourner quand Vanguard a été élevé depuis un compte ordinaire (`sudo vanguard`, console
  administrateur avec l'UAC) : ils installent, effacent ou lisent ce que le réseau envoie, et chaque geste
  d'administrateur se demande déjà au moment voulu. « Tout remettre comme avant » n'est jamais refusé ; root seul et
  Windows sans UAC gardent les outils, avec l'avertissement.
- **Le durcissement du noyau ne s'annule plus.** Sous Linux, la correction qui durcit le noyau (ASLR, ptrace, liens
  de /tmp…) est désormais une protection, comme le pare-feu : elle ne se défait plus. Une note d'annulation ne remet
  jamais une clé du noyau sous sa valeur sûre, ni ne retire le fichier 99-vanguard.conf ; celles de la 0.86 et de la
  0.87, qui restaient dites annulables à vie, sont retirées une fois, et c'est dit. S'il gêne (un routeur, un VPN),
  retirer Vanguard dit comment le défaire à la main : retirer sa ligne du fichier, puis `sudo sysctl --system`. Un reglages.json accepté
  sans sceau d'avant (hors d'une mise à jour depuis une version qui scelle déjà, 0.86 ou plus) n'est plus rejoué en
  administrateur, comme le mode Wi-Fi public et la sauvegarde. Un historique venu d'une version sans sceaux (0.85 ou
  avant) n'est donc plus rejoué : ses réglages d'Optimiser ne s'annulent plus par Vanguard ; sa copie est gardée à
  côté (reglages.adopte-….json), une seule par contenu, et c'est dit une fois.
- **Le durcissement de Windows et les protections de Defender ne s'annulent plus.** Les quatorze réglages de
  durcissement de Windows (WDigest, NLA, LSA, UAC…) et les protections de Defender (règles ASR, protection réseau,
  logiciels indésirables, dossiers contrôlés), que le bilan ou Optimiser les pose, sont désormais des protections :
  « Tout remettre comme avant » ne les défait plus, et une note d'annulation forgée ne peut plus les faire baisser
  en administrateur. La personne peut toujours les changer dans Windows. Leurs notes de la 0.86 et de la 0.87 sont
  retirées une fois ; Vanguard retient seulement qu'il a posé une protection de Defender, pour dire plus fort au
  bilan qu'elle a été coupée ensuite. À prouver dans la VM Windows.
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
  plus entrer dans la référence de la clé ce qui y a changé entre-temps : si rien d'autre ne diffère, ce que le
  déploiement pose et qui diffère est retiré de la clé, puis reposé, et chaque fichier retiré est dit avec ce qui le
  reposera (un programme Mac sans compilation récupérée, ou les exemples tldr hors ligne, n'y reviennent pas) ; si
  autre chose diffère, rien n'est retiré et la reprise est refusée, la clé gardant la preuve. Le point sûr que la clé
  de secours ne dépasse pas se forge lui aussi avec la clé principale volée : signé par elle, ses versions (date et
  début des empreintes) sont montrées à l'auteur, et la clé de secours ne signe rien, pas même le manifeste de la
  version, sans « contresigner » tapé dans un terminal (sans terminal, elle refuse). Seul l'auteur sait ce qu'il a
  publié : une version forgée sous un numéro qu'il reconnaît, sans date ni empreinte qu'il remarque, passe encore.
  Claude sur GitHub ne se lance plus sur un ticket ou une demande de fusion écrits par un autre que le propriétaire,
  ni sur un fil où un autre a commenté ou relu, ni sur un ticket du journal de la clé (écrit depuis n'importe quel
  ordinateur) : il les lirait comme des consignes. Juste avant Claude, le fil est verrouillé et relu, ce qui ferme les
  minutes entre ce contrôle et sa lecture ; un second `@claude` sur le même fil attend la fin du premier, qui sinon le
  déverrouillait sous lui. Le modèle de menace dit ce qui reste.
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
