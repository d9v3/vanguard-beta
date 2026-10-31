# Veille continue de Vanguard

Les tests, les corrections et les adaptations de Vanguard tournent tout seuls, et s'adaptent : chaque nuit une chaîne
**sans IA** vérifie tout, fuzze, relit les vraies sources du programme et relève ce qui a changé dans le monde (failles
exploitées, avis RUSTSEC, liste d'Échap). L'IA (`claude -p`) ne part que **sur alerte** et **une fois par semaine**.
Elle **propose** dans une branche `veille/AAAA-MM-JJ-<sujet>` ; **l'auteur fusionne**. La veille ne fusionne, n'envoie
et ne publie jamais rien.

## Quand

| Quoi | Quand | IA | Durée |
|---|---|---|---|
| Nuit (`nuit.sh`) | chaque jour à 03 h 30 (après le renouvellement du quota du vendredi à 3 h) | non | ~1 h 45 |
| Correction sur alerte (`alerte.sh`) | lancée par la nuit, si une alerte tient dans le budget | oui | ≤ 4 h 30 (correction, verifier.sh, relecture : 90 min chacun au plus ; pas de VM) |
| Relecture hebdomadaire (`hebdo.sh`) | vendredi à 05 h 30 | oui, lecture seule | ≤ 90 min |
| Rappel (`matin.sh`) | 08 h 30, si la notification de la nuit n'a pas été vue | non | secondes |

Un jeu en cours (`gamemoded -s`) ou la VM réservée (`.test-en-cours.txt`) reporte la passe, et c'est dit. La nuit
manquée (ordinateur éteint) n'est pas rattrapée en journée (`Persistent=false`, à confirmer).

## La nuit, sans IA

1. Le worktree `~/Projects/vanguard-veille`, **détaché**, remis sur la tête de `prochaine` (reset seulement s'il est
   listé par git et détaché : jamais le worktree d'une session).
2. `outils/verifier.sh` complet (non modifié ; `verifier-dernier.txt` est sauvegardé puis remis).
3. Proptest à la **graine du jour** (`PROPTEST_RNG_SEED=AAAAMMJJ`) : d'autres entrées chaque nuit ; un échec se rejoue
   avec la graine du rapport.
4. `outils/fuzz.sh tout 300` : corpus suivi avant/après (il grandit : c'est l'adaptation), plantages nouveaux
   (SHA-256 jamais vu), cibles du banc absentes de `fuzz.sh`. Le dimanche, `cargo fuzz cmin`.
   **Le vendredi seulement** (avant la relecture hebdomadaire de 05 h 30) : `outils/preuves.sh`, borné à 45 min.
   Miri interprète, pour Linux puis pour Windows, les essais qui exercent les `unsafe` portant sur la mémoire de
   Vanguard (comportement indéfini = échec), puis Kani prouve les lecteurs de `outils/preuves/` pour toutes les
   entrées dans sa borne. Sans Miri ou sans Kani : « sautée », dite. Les autres nuits, l'étape n'apparaît pas.
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

## Sur alerte, avec IA

Alertes par priorité : `rustsec` > `fuzz` > `verifier` > `proptest` > `canari` (format cassé confirmé) > `lien`. **Une
seule** traitée par nuit, les autres « en file » ; une alerte déjà traitée (signature dans
`etat/alertes-traitees.txt`) n'est jamais relancée. KEV et Échap ne lancent l'IA qu'à la relecture hebdomadaire.
Un plantage du fuzz resté en file reste « nouveau » (donc en alerte) chaque nuit jusqu'à sa prise en charge. Un échec
proptest a pour clé ses tests en échec, pas la graine du jour : il n'appelle l'IA qu'une fois. Une correction où
claude n'a rien pu faire (limite, erreur) rend son alerte, reprise la nuit suivante (le lancement reste compté).

`alerte.sh` : worktree jetable `~/.cache/vanguard-dev/veille-arbres/<sujet>` sur une branche
`veille/AAAA-MM-JJ-<sujet>` partie de la tête de prochaine ; `claude -p` (consignes `consignes-correction.md`) corrige
avec un test et committe ; **garde-fous mécaniques** (refus d'un diff qui touche `.github/`, `.claude/`, `.cargo/`,
`CLAUDE.md`, `deny.toml`, tout `outils/` (sauf `outils/liens.txt` pour une alerte « lien » : l'IA y forgerait le vert
de sa proposition, ou changerait la chaîne de publication et de la clé ; une alerte « verifier » sur une étape portée
par un essai d'`outils/` n'appelle donc pas l'IA, elle est dite à l'auteur), un `build.rs`, `rust-toolchain`, qui ajoute `#[ignore]`,
retire un test, change les dépendances hors d'une alerte RUSTSEC, ou n'ajoute aucun test ; refus aussi si le lien
`.git` du worktree a été réécrit) ; `verifier.sh` dans l'arbre, **dans un bac à sable** ; **relecture adversariale**
par un second `claude -p` neuf en lecture seule (`consignes-relecture.md`) ; **jamais la VM** : ce qui y est déposé
tourne en administrateur sans clic, l'auteur la lance après sa relecture (`outils/vm-tester.sh --branche <branche>`) ;
compte rendu `ia/<jour>-<sujet>/resultat.md`, puis la notification. Le worktree est
retiré, la branche reste.

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
`~/.ssh`, `~/.config`, `~/.claude`, le dossier de Vanguard).

### Ligne de commande (commun.sh, `lancer_claude`)

`--safe-mode --restricted --strict-mcp-config` (ni CLAUDE.md chargé tout seul, ni crochets, ni plugins, ni MCP, ni le
`.claude/settings.json` du dépôt qui permettrait `gh issue view`), `--permission-mode dontAsk --permission-prompts
none` (tout ce qui n'est pas permis est refusé, personne n'est attendu à 3 h), `--tools` borné, `--allowedTools`
(lecture/écriture dans l'arbre, `cargo test/build/check/clippy/fmt`, `git status/diff/log/show/add/commit` ;
`cargo update -p` pour une alerte RUSTSEC), `--disallowedTools` (gh, curl, wget, ssh, rm, git push/checkout/branch/
merge/reset…, les fichiers protégés), `--max-turns 60/20/40`, `timeout 90m`, `--settings` tiré de
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

- Relire : `git log -p prochaine..veille/AAAA-MM-JJ-<sujet>`
- Accepter : la fusionner soi-même dans prochaine, comme une branche de lot (jamais fait par la veille).
- Refuser : `git branch -D veille/AAAA-MM-JJ-<sujet>` (débloque la file).
- Le rappel de 08 h 30 : `matin.sh --vu` le coupe pour la nuit en cours.

## Installer

`outils/veille/installer.sh [révision]` copie `outils/veille/` de la révision (prochaine par défaut) dans
`~/.local/share/vanguard-veille/<sha>/`, **figée** (la nuit remet elle-même le worktree sur prochaine ; un commit ne
change pas en silence ce qui tourne avec l'IA) et active les minuteries. Le rapport prévient quand `outils/veille/` de
prochaine a changé depuis : réinstaller. Le worktree `~/Projects/vanguard-veille` est créé par la première nuit.

## Essais

- `outils/veille/essai.sh` : toute la chaîne sur des faux, sous `unshare -rn` (sans réseau), sans IA ; vérifie les
  rapports, une seule notification, la priorité et la file, chaque garde-fou, les arguments exacts de claude et que
  le texte hostile d'une KEV n'atteint jamais l'IA.
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
`rapport.py` (rapports, état, entrées sûres de l'IA), `consignes-*.md` et `schema-*.json` (prompts fixes et formes
des réponses, versionnés), `reglages-claude.json` (permissions et bac à sable), `systemd/`, `installer.sh`, `essai.sh`.
État : `~/.cache/vanguard-dev/veille/` (rapports, `etat/`, `canaris/<jour>/` gardés 7 jours, `nuits/<jour>/` 15
jours, `ia/`, `journal/`).

## Sur demande

Une relecture ou une correction demandée par l'auteur se fait **tout de suite**, même si celle de la semaine ou de la
nuit a déjà eu lieu : les limites de budget ne valent que pour les passages automatiques. Les interrupteurs
(`COUPER-IA`, `COUPER-TOUT`) et la limite d'usage de Claude, eux, valent toujours.

    VANGUARD_VEILLE_DEMANDE=1 ~/.local/share/vanguard-veille/courante/hebdo.sh     # relecture de sécurité maintenant
    VANGUARD_VEILLE_DEMANDE=1 ~/.local/share/vanguard-veille/courante/nuit.sh      # passage de nuit maintenant
