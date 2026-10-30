---
name: livrer
description: Livrer la publication du jour de Vanguard — numéro de version, commit de version, livraison de la branche (Mac de GitHub, vérification, fusion dans master, déploiement : binaire, clé USB, GitHub) puis les mises à jour qui suivent. Une fois par jour, quand le travail de la journée est fini et que /verifier passe.
---

Une seule publication par jour sur GitHub (CLAUDE.md, « Façon de travailler ») : le travail de la journée
s'accumule sur une branche (worktree), en commits ordinaires sans numéro de version ni envoi. Pour la clé entre-temps,
sans rien envoyer : `VANGUARD_INTERMEDIAIRE=1 outils/deployer.sh --local`.

1. Version dans Cargo.toml : correctif seul 0.x.y+1, fonction 0.x+1.0. Regarde d'abord celle de master
   (`git show master:Cargo.toml`) : une autre session a pu l'avancer. Puis `cargo build` (Cargo.lock suit).
   Paragraphe du jour dans CHANGELOG.md et CHANGELOG.en.md.
2. `git add` de tes propres fichiers seulement, puis UN commit de version en tête de la branche, « … (vX.Y.Z) » :
   ce qui change et pourquoi, une puce par sujet (ce sont les notes de la page de la version), avec la ligne
   Co-Authored-By. Vérifie avec `git show --stat HEAD`.
3. `outils/livrer-branche.sh <branche> <worktree>` : rebase sur master, garde-fou de confidentialité, passage sur le
   Mac de GitHub, `outils/verifier.sh` pendant qu'il compile, fusion rapide dans master, puis `outils/deployer.sh`
   (compile, installe, pousse sur GitHub, met la clé et la VM à jour ; pour une version publiée, refait aussi les
   captures du README, commit à part). Il s'arrête à la première étape en échec, sans rien fusionner : corriger,
   puis relancer. Si l'arbre principal a des changements non committés d'une autre session sur les mêmes
   fichiers : arrête-toi et demande. Si les captures n'ont pas pu se faire, le dire. Rien n'est poussé si un détail
   personnel paraît ou si un lien est mort (`outils/liens.py`) : corriger, puis relancer `outils/deployer.sh`.
   Un lien douteux montré : l'ouvrir (WebFetch) ; bon mais refusé aux programmes, l'ajouter à `outils/liens.txt`.
4. Page de la version (Releases) : `deployer.sh` la publie tout seul pour chaque publication, 0.x.0 comme 0.x.y
   (`outils/publier-version.sh` : trois programmes, empreintes, nomenclatures (SBOM, cargo-cyclonedx 0.5.9 requis
   ici), notes tirées des commits de version depuis la page précédente, aperçu par `--notes` ; version macOS reprise
   d'un passage de master sur le Mac dont l'attestation est vérifiée, puis copiée sur la clé ; notification ; seule la dernière version garde sa page). Une version intermédiaire
   (`VANGUARD_INTERMEDIAIRE=1`) n'en a pas : la ligne « sans page sur GitHub » le dit, et la suivante la reprendra.
   S'il l'a ratée, il dit pourquoi : corriger, puis relancer `outils/publier-version.sh`.
5. Mises à jour qui suivent chaque version :
   - page du dépôt : toute seule après chaque envoi (`outils/github.py` applique `.github/depot.json` : description
     et version, lien du journal, sujets, options). Si les fonctions ont changé, réécrire la description dans
     `.github/depot.json`, en anglais, 350 caractères au plus avec la version ;
   - journal du projet (document Claude) : ligne d'historique, version en tête, fonctions, pistes ;
   - liste des fonctions : README.md, README.en.md, outils/LISEZMOI.txt, outils/README.txt ; tableau Structure de
     CONTRIBUTING.md et CONTRIBUTING.en.md si un module change.
   - page des fonctions : `deployer.sh` l'a refaite tout seul pour la version (docs/index.html, servie par GitHub
     Pages à https://d9v3.github.io/vanguard-beta/ : vérifier la ligne « Page des fonctions refaite »). Si des
     fonctions changent, les écrire AVANT la livraison dans outils/page-fonctions.html (rangée par menace, à la main
     comme les README, avec les étiquettes « nouveau » et la section « Nouveautés ») ; les nombres (règles, commandes,
     tests, VM) et la liste des commandes se remplissent seuls. Puis la même page sur claude.ai
     (https://claude.ai/artifact/NG3P6Gq6XQaWRXqVvEFDMC, partagée par lien) : `python3 outils/page-fonctions.py`
     (le fragment, sans --complet), `python3 outils/confidentialite.py --texte` dessus, puis l'outil Artifact à la
     même adresse (`url`).
6. Compte rendu : la version, ce qui a changé, ce qui est vérifié, ce qui ne l'est pas encore (Windows réel,
   Mac réel…).
