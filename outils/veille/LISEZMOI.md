# Veille continue de Vanguard

Les tests, les corrections et les adaptations de Vanguard tournent tout seuls, et s'adaptent : chaque nuit une chaîne
**sans IA** vérifie tout, fuzze, relit les vraies sources du programme et relève ce qui a changé dans le monde (failles
exploitées, avis RUSTSEC, liste d'Échap). L'IA (`claude -p`) ne part que **sur alerte** et **une fois par semaine**.
Elle **propose** dans une branche `veille/AAAA-MM-JJ-<sujet>` ; **l'auteur fusionne**. La veille ne fusionne, n'envoie
et ne publie jamais rien.

## Quand

| Quoi | Quand | IA | Durée |
|---|---|---|---|
| Nuit (`nuit.sh`) | chaque jour à 03 h 30 (après le renouvellement du quota du vendredi à 3 h) | non | ~1 h 45 (le jeudi, plus les preuves : 45 min au plus) |
| Correction sur alerte (`alerte.sh`) | lancée par la nuit, si une alerte tient dans le budget | oui | ≤ 4 h 30 (correction, verifier.sh, relecture : 90 min chacun au plus ; pas de VM) |
| Relecture hebdomadaire (`hebdo.sh`) | vendredi à 05 h 30 | oui, lecture seule | ≤ 90 min |
| Rappel (`matin.sh`) | 08 h 30, si la notification de la nuit n'a pas été vue | non | secondes |

Un jeu en cours (`gamemoded -s`) ou la VM réservée (`.test-en-cours.txt`) reporte la passe, et c'est dit. La nuit
manquée (ordinateur éteint) n'est pas rattrapée en journée (`Persistent=false`, à confirmer).

## La nuit, sans IA

1. Le worktree `~/Projects/vanguard-veille`, **détaché**, remis sur la tête de `master` (reset seulement s'il est
   listé par git et détaché : jamais le worktree d'une session).
2. `outils/verifier.sh` complet (non modifié ; `verifier-dernier.txt` est sauvegardé puis remis).
3. Proptest à la **graine du jour** (`PROPTEST_RNG_SEED=AAAAMMJJ`) : d'autres entrées chaque nuit ; un échec se rejoue
   avec la graine du rapport.
   Puis l'autotest de la base sur cet ordinateur (`vanguard autotest --json`, lecture seule, hors ligne) : un écart
   (code 1) met l'étape en échec ; « rien de fautif, du non vérifié » (code 2) la dit sautée. Sa durée, celle de
   chaque règle et la tête sont gardées dans `etat/durees.tsv` (60 nuits) si l'autotest a rendu 0 ou 2. Voir
   « Lenteur » plus bas.
   Puis le **journal des erreurs** rapatrié par `deployer.sh` (`retours/journal-cet-ordinateur.txt`,
   `retours/journal-cle.txt`), trié par le programme de la base (`vanguard compte-rendu journal`,
   `src/compte_rendu/triage.rs`) : les entrées regroupées en causes (champs validés de la ligne `§` seulement, jamais
   le détail ni la commande), rangées par score, 20 en file au plus ; la suite d'une nuit à l'autre dans
   `etat/causes.json`. Voir « Journal des erreurs » plus bas.
   Puis la **relève des envois** du relais (`releve-envois.sh`, étape `envois`) et leur lecture par le programme de la
   base (`vanguard compte-rendu flotte`, étape `flotte`). Voir « Envois » plus bas.
4. `outils/fuzz.sh tout 300` : corpus suivi avant/après (il grandit : c'est l'adaptation), plantages nouveaux
   (SHA-256 jamais vu), cibles du banc absentes de `fuzz.sh`. Le dimanche, `cargo fuzz cmin`.
   **Le jeudi seulement** (la relecture hebdomadaire du vendredi lit les sept dernières nuits ; celle du vendredi,
   finie après 05 h 30, n'y serait pas) : `outils/preuves.sh`, borné à 45 min.
   Miri interprète, pour Linux puis pour Windows, les essais qui exercent les `unsafe` portant sur la mémoire de
   Vanguard (comportement indéfini = échec), puis Kani prouve les lecteurs de `outils/preuves/` pour toutes les
   entrées dans sa borne. Sans Miri ou sans Kani : « sautée », l'outil absent dit (l'autre tourne quand même). Les
   autres nuits, l'étape n'apparaît pas. Mesuré le 30 octobre 2026 (Kani 0.68, CBMC 6.11) : la plus lourde des
   preuves, `nom_borne` (noms DNS), prend environ 5 min 15 s et 6,1 Go de mémoire de pointe (5,7 Gio) ; Kani en
   tout, environ 6 min ; Miri, moins d'une minute.
5. `cargo audit --json` sur les quatre `Cargo.lock`, base RUSTSEC fraîche : avis nouveaux depuis la veille.
6. **Canaris** (`src/canaris.rs`, essais `#[ignore]` lancés avec `VANGUARD_CANARIS`) : chaque source réelle
   (`sources::SOURCES`, KEV, Échap, LOLDrivers, Feodo) téléchargée par **la même demande que le programme** et relue
   par **son lecteur** ; une réponse 200 refusée = format changé (redemandée 10 min plus tard avant d'alerter). Puis
   les essais existants plus exigeants (`VANGUARD_ESSAI_PERIMES`, `VANGUARD_ESSAI_ECHAP`) sur ces copies. Nouvelles
   failles exploitées (KEV) avec le logiciel suivi qui les couvre, ou rien (écart de couverture). abuse.ch est
   sauté : la clé de l'auteur ne passe jamais par la veille.
7. `outils/liens.py` complet ; un lien mort trois nuits de suite devient une alerte.
8. `outils/vm-tester.sh --delai 30` s'il existe (sinon « sautée »), borné à 50 min : au-delà, le travail reste dans la
   file de la VM (`vm-tester.sh --attendre <id>`) et la nuit écrit quand même son rapport.
9. Rapport `~/.cache/vanguard-dev/veille/AAAA-MM-JJ.json` et `.md`, `dernier.txt` (une ligne), **une** notification
   du bureau si une étape échoue, s'il y a une alerte, une proposition en attente, une étape sautée sans l'avoir
   demandée (`--sans-…`), y compris dans verifier.sh, ou un canari qui n'a pas lu sa source (`http-404`,
   `sans-reponse`…). « Tout est vert » seulement si tout a été vérifié.

Jamais de silence : une nuit reportée deux fois de suite, une partie qui trouve le verrou pris (alerte.sh envoie alors
quand même le résumé de la nuit), une partie arrêtée par systemd (`TimeoutStartSec`) ou à la main, notifient.

## Envois

Les lots que les ordinateurs envoient au relais (`relais/worker.js`, effacés à la lecture) sont relevés chaque nuit,
puis lus par le programme ; ni l'IA ni le rapport n'ouvrent ce qui vient d'un lot.

- **Configuration**, lue à chaque nuit, jamais dans le dépôt (le relais n'est pas encore déployé) :
  `~/.config/vanguard-dev/relais-adresse`, l'origine du relais seule sur sa ligne (`https://hote[:port]`, sans chemin
  ni paramètre ; le script ajoute `/v1/releve`), et `~/.config/vanguard-dev/relais-secret`, le secret de relève
  (32 à 256 caractères `[A-Za-z0-9_-]`, fichier ordinaire à soi, `chmod 600`). Sans le premier, les deux étapes sont
  « sautées : relais pas configuré » sans notification ; avec l'adresse mais sans secret, c'est une étape sautée
  imprévue, notifiée.
- **Relève** (`releve-envois.sh`) : `GET /v1/releve`, le secret dans l'en-tête (passé à curl par son entrée standard,
  jamais en argument), HTTPS seulement (TLS 1.2 au moins), aucune redirection, 20 s pour se connecter, 2 min par
  réponse, 20 réponses au plus. Chaque réponse est gardée telle quelle, une par ligne, dans
  `~/.local/share/vanguard/retours/envois/AAAA-MM-JJ.jsonl` (dossier 700, fichiers 600), même illisible (le relais
  l'a déjà effacée) : 5 Mio par réponse, 8 Mio par nuit (une réponse de plus n'est demandée que s'il reste 5 Mio de
  place : en pratique une seule grosse réponse par nuit ; le reste attend au relais, 14 jours), 90 jours gardés. Une
  réponse coupée en cours de route est perdue (le relais l'a effacée) : en échec, dit. Sans Internet,
  relais occupé (429) ou en panne (5xx) : sautée, la raison dite ; secret refusé (401), redirection, réponse trop
  grosse ou illisible : en échec. `--sans-reseau` saute la relève, pas la lecture.
- **Références** (`references-flotte.sh`) tirées de l'arbre de la veille : `versions.tsv` (chaque étiquette `vX.Y.Z`
  et sa date, en UTC) et, pour les trois mineures les plus récentes, les règles (`tests/regles-connues.txt`, sans les
  retirées), les outils (`commande: "…"` de `src/main.rs`) et les fichiers suivis sous `src/` à l'étiquette.
- **Lecture** (`src/compte_rendu/flotte.rs`) : chaque lot passe par `envoi::lire`, la lecture stricte du relais. Ne
  sont pas comptés, mais comptés comme refusés : enveloppe hors motif (jour, source, réseau large), lot trop gros ou
  hors schéma (JSON cassé, clé en trop, séquence de terminal), version non publiée, plus ancienne que les trois
  dernières mineures ou datée d'avant sa publication, `version_avant` douteuse, jour trop loin de la réception,
  version sans références, règle, outil ou fichier absents de l'arbre de la version, doublon. Un lot où le détecteur
  de secrets sonne va en **quarantaine** : compté, jamais lu plus loin. Une réponse illisible est comptée
  « illisible » ; une raison de refus du relais inconnue, « inconnue ». La ligne de comptes de la nuit est dans
  `nuits/<jour>/flotte-comptes.txt`.
- **Agrégats** : une voix par source et par jour de réception (la source est l'empreinte que le relais calcule avec
  le sel du jour) : chaque nombre pris à son maximum sur les lots d'une source, puis sommé d'une source à l'autre ;
  le même résultat quel que soit l'ordre des lots. Par clé : `[sources, réseaux larges, somme]`, pour tous et par
  groupe (famille, classe de machine). Une voix garde 2 000 clés et 8 installations au plus (les plus petites dans
  l'ordre du texte, pour rester indépendant de l'ordre). Seuls les comptes de sources (et de réseaux larges) valent
  comme signal : une source peut parler pour deux versions ou deux groupes (une voix dans chacun), et pousser la
  somme d'une clé jusqu'au maximum du schéma ; ne jamais sommer d'une version ou d'un groupe à l'autre. Un fichier de
  relève écarté (lien, tube, trop gros, illisible) : l'état n'est pas récrit cette nuit et l'étape échoue. Un jour qui
  se fige pendant des nuits manquées garde le calcul de la dernière nuit qui l'a vu. État dans `etat/flotte/<version>.json` (2 Mio au plus, écrit de façon
  atomique ; un jour reçu il y a plus de 29 jours est figé ; gardé tant que sa mineure est parmi les trois dernières)
  et `etat/flotte/releve.json` (ce que chaque nuit a lu et refusé, 120 jours).
- **Signaux** (`src/compte_rendu/flotte/signaux.rs`, sans IA, sur les sept derniers jours) : un signal demande au
  moins 5 sources dans 3 réseaux /16 au numérateur (une voix par source, par jour et par clé : mille lots d'une
  source n'en font qu'une). Régression : un taux (plantage, cause, hors délai, non vérifié, échec de correction,
  abandon d'un outil) au moins deux fois celui de la version d'avant dans l'ordre des numéros (5 sources au moins
  de chaque côté, même famille ; le jour d'avant pris de préférence avant l'arrivée de la nouvelle version, pour
  que des lots forgés de l'ancienne envoyés ensuite ne la diluent pas), ou deux fois sur les mêmes installations vues sur les deux versions (identifiant P1). Faux positif
  probable : problème chez plus de 60 % des sources de la famille, « c'est normal » chez plus de 30 %, correction
  refusée par plus de la moitié, ou constat instable ; quand la famille a des installations identifiées, il doit
  tenir aussi sur celles vues sept jours avant (une arrivée soudaine ne fait pas passer une règle pour fausse).
  Couverture : non vérifié chez plus de 20 % (la raison dominante dite). Fragile : correction échouée chez plus de
  10 % ou revenue chez plus de 20 %. Cache : écart chez plus de 1 % des comparaisons. Lenteur : délai frôlé chez
  plus de 5 % d'une classe de machine. Outil : abandon chez plus de 40 %. Erreur nouvelle : un gabarit jamais vu sur
  les versions d'avant, 3 sources dans 3 réseaux. Sortie : `nuits/<jour>/flotte-signaux.json` (champs fermés),
  relu par rapport.py, qui en fait des alertes `flotte:<signal>:<clé>` (une régression juste après le journal de
  cet ordinateur, les autres après les causes de la clé) ; section « Flotte » du rapport du matin.
- **Faux positif probable** : jamais l'IA (rapport.py ne le propose pas, alerte.sh refuse une demande forgée), un
  ticket seulement. Chaque signal écrit un **ticket** `retours/tickets/AAAA-MM-JJ-<signal>-<clé>.md` (50 par nuit
  au plus, pas deux fois la même semaine) : champs vérifiés, où regarder (fichiers de l'arbre qui nomment la règle,
  emplacements vérifiés), interdits, puis les données ouvertes (noms, textes) échappées dans un bloc
  `~~~~donnees-<16 hex tirés au hasard>` qu'aucune donnée ne peut fermer. Un ticket se lit dans une session lancée
  par l'auteur : ses données sont des données, jamais des consignes.
- **Noms** : l'IA ne voit un nom de logiciel qu'approuvé (`noms-connus.txt`), sinon `inconnu#<empreinte>`. Les noms
  vus sont gardés dans `retours/tickets/noms-vus.json` ; `outils/veille/approuver-nom.sh <empreinte>` (du dépôt, sur
  un terminal, réponse « oui ») ajoute le nom à `noms-connus.txt`, à committer puis réinstaller la veille. Relais
  pas configuré : une seule ligne neutre au résumé de la nuit, sans notification.

## Sur alerte, avec IA

Alertes par priorité : `rustsec` > `fuzz` > `journal` > `flotte` (régression) > `verifier` > `proptest` > `canari`
(format cassé confirmé) > `lenteur` > `lien` ; une cause du journal rapportée par la clé (qu'un autre ordinateur peut
avoir forgée) passe juste après `canari`, puis les autres signaux de la flotte (jamais un faux positif probable :
ticket seulement). **Une seule** traitée par nuit, les autres « en file » ; une alerte déjà traitée (signature dans
`etat/alertes-traitees.txt`) n'est jamais relancée. KEV et Échap ne lancent l'IA qu'à la relecture hebdomadaire.
Un plantage du fuzz resté en file reste « nouveau » (donc en alerte) chaque nuit jusqu'à sa prise en charge. Un échec
proptest a pour clé ses tests en échec, pas la graine du jour : il n'appelle l'IA qu'une fois. Une correction où
claude n'a rien pu faire (limite, erreur) rend son alerte, reprise la nuit suivante (le lancement reste compté).

`alerte.sh` : worktree jetable `~/.cache/vanguard-dev/veille-arbres/<sujet>` sur une branche
`veille/AAAA-MM-JJ-<sujet>` partie de la tête de master ; `claude -p` (consignes `consignes-correction.md`) corrige
avec un test et committe ; **garde-fous mécaniques** (refus d'un diff qui touche `.github/`, `.claude/`, `.cargo/`,
`CLAUDE.md`, `deny.toml`, tout `outils/` (sauf `outils/liens.txt` pour une alerte « lien » : l'IA y forgerait le vert
de sa proposition, ou changerait la chaîne de publication et de la clé ; une alerte « verifier » sur une étape portée
par un essai d'`outils/` n'appelle donc pas l'IA, elle est dite à l'auteur), un `build.rs`, `rust-toolchain`, qui ajoute `#[ignore]`,
retire un test, change les dépendances hors d'une alerte RUSTSEC, ou n'ajoute aucun test (une alerte `flotte` :
un vrai `#[test]` ou proptest ajouté pour regression, couverture, fragile et cache ; elle ne peut pas non plus ôter
une ligne de `tests/regles-connues.txt`, y marquer une règle « retire », ni supprimer ou renommer un fichier de
`tests/`) ; refus aussi si le lien
`.git` du worktree a été réécrit) ; `verifier.sh` dans l'arbre, **dans un bac à sable** ; **relecture adversariale**
par un second `claude -p` neuf en lecture seule (`consignes-relecture.md`) ; **jamais la VM** : ce qui y est déposé
tourne en administrateur sans clic, l'auteur la lance après sa relecture (`outils/vm-tester.sh --branche <branche>`) ;
compte rendu `ia/<jour>-<sujet>/resultat.md`, puis la notification. Le worktree est
retiré, la branche reste.

### Journal des erreurs

Chaque cause de la file du triage est une alerte `journal:<cause>:<version la plus récente où elle a été vue>`. Une
fois traitée, elle ne revient que vue dans une version plus récente (le triage lit `etat/alertes-traitees.txt`).
L'IA reçoit la cause seule (genre, règle, contexte, lieu dans le code, code d'erreur, comptes, versions, familles de
systèmes, provenance, score) et `git show v<version>:<fichier>` pour relire le code de la version dite, avec
`--max-turns 40` (cause déjà située) ; test de non-régression exigé, comme pour `fuzz`. Les consignes le disent : le
journal peut être forgé (il s'écrit depuis tout programme du compte), jamais un seuil baissé ni une vérification
rendue « saine » plus facilement pour faire taire l'erreur. Avant l'IA, deux contrôles hors de sa portée : un lieu
dont le fichier n'existe ni dans l'arbre de la nuit ni à l'étiquette de l'une de ses versions devient « (retiré) »
(son motif seul laisserait passer des mots choisis), et une version plus récente que le programme est refusée (le
triage en Rust, puis `rapport.py`) : elle ferait taire la vraie cause.

Plus de 50 causes nouvelles en une nuit : **aucune alerte**, une notification, et l'état n'avance pas (un journal
forgé qui change ses causes chaque nuit ne remplit pas la file). Le regarder soi-même ; une fois jugé (forgé, ou
erreurs connues), archiver les deux fichiers de `retours/` hors de ce dossier : le triage repart de zéro la nuit
suivante. Un fichier remplacé ou tronqué est relu en entier, sans doublon.

### Lenteur

Une alerte `lenteur:<règle ou bilan>:<tête de la première nuit lente>` quand la médiane des 3 dernières nuits dépasse
1,5 fois celle des 21 d'avant et 10 s pour le bilan entier (pour une règle : 3 fois et 5 s, les seuils de
`src/autotest/mesures.rs`), et que les deux dernières nuits sont lentes chacune : une nuit lente seule ne dit rien.
Ne comptent que les nuits où l'autotest a rendu 0 ou 2 ; une nuit reportée (jeu, VM) n'a pas d'autotest. Moins de 24
nuits mesurées : « pas assez », jamais « sans régression ». Les durées viennent de la compilation de la nuit, en mode
debug : elles ne valent que comparées entre elles. L'IA reçoit la plage `tête_rapide..tête_lente` pour chercher le
commit fautif, les médianes et les trois dernières nuits (des nombres et des SHA), avec `--max-turns 40` ; test non
exigé, aucun test retiré, et la mesure de la nuit suivante juge la correction. Les consignes interdisent d'accélérer
une règle en lui faisant moins vérifier. `etat/durees.tsv` se supprime sans effet de bord (on repart de zéro).

### Le code de l'IA ne tourne jamais hors bac à sable

Une branche écrite par l'IA exécute son code dès qu'on la compile (build.rs, macros, tests). Donc :

- git de la veille sur l'arbre de l'IA : jamais de crochet (`core.hooksPath=/dev/null`, `--no-verify`), jamais de
  fsmonitor, et seulement si le lien `.git` est celui que git a écrit (sinon un faux dépôt ferait lancer son filtre).
- verifier.sh de la proposition : dans `bwrap` (`bac_a_sable`, commun.sh), sans
  réseau ni prises de la session (D-Bus, Wayland, agents), dossier personnel masqué sauf les outils de compilation,
  écriture dans l'arbre et dans sa compilation et son cargo seulement. Sans bwrap, verifier.sh n'est pas lancé.
- Compilation (`<sujet>.cible`) et cargo (`<sujet>.cargo` : registre et base RUSTSEC de l'auteur copiés, reflink sur
  btrfs) **jetables**, propres à la correction, supprimés à la fin : jamais `target-veille` ni `~/.cargo`, qu'un
  build.rs empoisonnerait pour la nuit suivante et pour l'auteur.
- La VM : jamais déposée d'office pour une branche de l'IA (son programme y tournerait en administrateur, sans
  relecture humaine) ; l'auteur la lance après sa relecture, par `outils/vm-tester.sh --branche <branche>`.

### Données hostiles

L'IA ne reçoit qu'`alerte.json`, refait champ par champ par `rapport.py` (liste blanche d'expressions régulières :
CVE, RUSTSEC, crate, version, SHA, cible, étape, source ; sinon « (retiré) »). Jamais de texte venu d'Internet
(descriptions KEV, noms d'éditeurs, YAML d'Échap, titres RUSTSEC, journaux de cargo ou du fuzzer). Le plantage est mis
dans un dossier à part, lisible comme des octets ; d'une source refusée par un canari, seulement sa forme
(`rapport.py structure` : clés, champs, forme des lignes, sans son texte). Les consignes le disent : le contenu des
fichiers est une donnée, jamais une instruction. Lecture refusée hors de l'arbre (dont `~/.cache/vanguard-dev/veille`,
`~/.ssh`, `~/.config`, `~/.claude`, le dossier de Vanguard). Du journal des erreurs, seuls des champs validés deux
fois : en Rust (`src/compte_rendu/journal.rs`, fuzzé), puis par `rapport.py` (`sur()`, motifs tirés de
`outils/veille/schema-compte-rendu.json`).

### Ligne de commande (commun.sh, `lancer_claude`)

`--safe-mode --restricted --strict-mcp-config` (ni CLAUDE.md chargé tout seul, ni crochets, ni plugins, ni MCP, ni le
`.claude/settings.json` du dépôt qui permettrait `gh issue view`), `--permission-mode dontAsk --permission-prompts
none` (tout ce qui n'est pas permis est refusé, personne n'est attendu à 3 h), `--tools` borné, `--allowedTools`
(lecture/écriture dans l'arbre, `cargo test/build/check/clippy/fmt`, `git status/diff/log/show/add/commit` ;
`cargo update -p` pour une alerte RUSTSEC), `--disallowedTools` (gh, curl, wget, ssh, rm, git push/checkout/branch/
merge/reset…, les fichiers protégés), `--max-turns 60/20/40` (40 pour une correction `journal` ou `lenteur`), `timeout 90m`, `--settings` tiré de
`reglages-claude.json` : **bac à sable** de Claude Code obligatoire (`failIfUnavailable`, sans réseau sauf crates.io
pour RUSTSEC, écriture dans l'arbre et dans la compilation et le cargo jetables de la correction seulement ; aucune
écriture pour la relecture et l'hebdomadaire), car cargo exécute du code (build.rs, tests).

## Coût et budget

- Calcul : ~1 h 45 par nuit, `Nice=19`, `IOSchedulingClass=idle`, `CPUWeight=20`, 8 tâches de compilation.
- IA : au plus **1 correction par nuit**, **3 par semaine glissante**, plus **1 relecture hebdomadaire** (chaque
  correction coûte deux lancements : correction et relecture). **Une seule proposition en attente à la fois** : tant
  qu'une branche `veille/*` n'est ni fusionnée ni supprimée, aucune nouvelle correction. Une correction = un seul
  passage, jamais relancée. Limite d'usage atteinte : plus d'IA avant le lendemain.
- `--max-budget-usd 5` ne compte qu'en facturation à l'API ; sous l'abonnement, les tours et le temps font foi.
- Suivi : `~/.cache/vanguard-dev/veille/etat/budget.tsv`.

## Couper

- L'IA seule : `touch ~/.cache/vanguard-dev/veille/COUPER-IA` (la nuit continue sans IA).
- Tout : `touch ~/.cache/vanguard-dev/veille/COUPER-TOUT` (la nuit, la relecture et toute correction, même déjà
  demandée), ou `outils/veille/installer.sh --retirer`.

## Une proposition attend

Le rapport du matin (`AAAA-MM-JJ.md`, section « Ce qui t'attend ») et `ia/<jour>-<sujet>/resultat.md` disent la
branche, les garde-fous, verifier.sh et le verdict de la relecture.

- Relire : `git log -p master..veille/AAAA-MM-JJ-<sujet>`
- Accepter : la fusionner soi-même dans master, comme une branche de lot (jamais fait par la veille).
- Refuser : `git branch -D veille/AAAA-MM-JJ-<sujet>` (débloque la file).
- Le rappel de 08 h 30 : `matin.sh --vu` le coupe pour la nuit en cours.

## Installer

`outils/veille/installer.sh [révision]` copie `outils/veille/` de la révision (master par défaut) dans
`~/.local/share/vanguard-veille/<sha>/`, **figée** (la nuit remet elle-même le worktree sur master ; un commit ne
change pas en silence ce qui tourne avec l'IA) et active les minuteries. Le rapport prévient quand `outils/veille/` de
master a changé depuis : réinstaller. Le worktree `~/Projects/vanguard-veille` est créé par la première nuit.

## Essais

- `outils/veille/essai.sh` : toute la chaîne sur des faux, sous `unshare -rn` (sans réseau), sans IA ; vérifie les
  rapports, une seule notification, la priorité et la file, chaque garde-fou, les arguments exacts de claude et que
  le texte hostile d'une KEV n'atteint jamais l'IA. La relève et la lecture des envois y tournent contre un faux
  relais HTTPS sur 127.0.0.1 (certificat jetable) qui sert des lots hostiles ; le vrai programme, compilé avant
  d'entrer dans le banc, les lit.
- À la main, sans IA, sur une base réelle : `nuit.sh --sans-ia --sans-vm --fuzz-secondes 15` avec `VANGUARD_VEILLE`
  et `VANGUARD_VEILLE_ARBRE` vers un dossier d'essai.
- `bash -n` et l'analyse Python passent par `outils/verifier.sh` ; shellcheck n'est pas installé ici.

## Téléphone

`PushNotification` de Claude Code n'atteint le téléphone qu'avec Remote Control connecté ou dans une routine cloud ;
un `claude -p` lancé par systemd n'a ni l'un ni l'autre, la notification n'irait probablement nulle part (pas essayé :
un essai enverrait une vraie notification). Possibles, chacun avec l'accord de l'auteur : un essai unique de
`PushNotification` par `claude -p` ; KDE Connect (réseau local, logiciel libre, à installer sur le PC et le
téléphone) ; une routine claude.ai (Anthropic, mais les données sortent du PC). Aucun service tiers (ntfy.sh,
Pushover, Gmail…) sans accord.

## Fichiers

`commun.sh` (chemins, verrou, budget, ligne de commande de claude), `nuit.sh`, `alerte.sh`, `hebdo.sh`, `matin.sh`,
`rapport.py` (rapports, état, entrées sûres de l'IA), `releve-envois.sh`, `references-flotte.sh`, `approuver-nom.sh` et
`noms-connus.txt` (envois), `consignes-*.md` et `schema-*.json` (prompts fixes et formes
des réponses, versionnés), `reglages-claude.json` (permissions et bac à sable), `systemd/`, `installer.sh`, `essai.sh`.
État : `~/.cache/vanguard-dev/veille/` (rapports, `etat/`, `canaris/<jour>/` gardés 7 jours, `nuits/<jour>/` 15
jours, `ia/`, `journal/`).

## Sur demande

Une relecture ou une correction demandée par l'auteur se fait **tout de suite**, même si celle de la semaine ou de la
nuit a déjà eu lieu : les limites de budget ne valent que pour les passages automatiques. Les interrupteurs
(`COUPER-IA`, `COUPER-TOUT`) et la limite d'usage de Claude, eux, valent toujours.

    VANGUARD_VEILLE_DEMANDE=1 ~/.local/share/vanguard-veille/courante/hebdo.sh     # relecture de sécurité maintenant
    VANGUARD_VEILLE_DEMANDE=1 ~/.local/share/vanguard-veille/courante/nuit.sh      # passage de nuit maintenant
