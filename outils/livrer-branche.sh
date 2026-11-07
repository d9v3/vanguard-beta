#!/usr/bin/env bash
# Livre la publication du jour, une branche déjà commitée (commit de version « … (vX.Y.Z) » en tête) : rebase sur
# master, garde-fou de confidentialité, vérification complète, fusion rapide dans master, déploiement
# (outils/deployer.sh : binaire, clé, VM, GitHub, page de la version), puis ménage de la branche et du worktree.
# S'arrête à la première étape en échec, sans rien fusionner.
#   outils/livrer-branche.sh <branche> <worktree>
# VANGUARD_INTERMEDIAIRE=1 : version intermédiaire d'une série (deployer.sh : sans page ni dépôt dans la VM).
set -euo pipefail
BRANCHE=$1
ARBRE=$2
# L'arbre principal (master), où se font la fusion et le déploiement : celui qui porte le .git commun.
DEPOT=$(dirname "$(git -C "$ARBRE" rev-parse --path-format=absolute --git-common-dir)")
export CARGO_TARGET_DIR=$DEPOT/target
JOURNAUX=$HOME/.cache/vanguard-dev

cd "$ARBRE"
[[ -z $(git status --porcelain) ]] || { echo "✖ $ARBRE a des changements non commités"; exit 1; }
# Master déjà à la base de la branche : rien à rebaser (un rebase referait à plat les fusions de la journée, en
# faux conflits).
git merge-base --is-ancestor master HEAD || git rebase -q master
# Rien de personnel ne part sur GitHub : vu ici, avant la vérification et la fusion (deployer.sh le revoit avant
# d'envoyer master).
python3 outils/confidentialite.py --plage origin/master "$BRANCHE" || { echo "✖ détail personnel : rien n'est fusionné"; exit 1; }
echo "· vérification complète"
if ! outils/verifier.sh >"$JOURNAUX/verif-$BRANCHE.log" 2>&1; then
  tail -30 "$JOURNAUX/verif-$BRANCHE.log"
  exit 1
fi
echo "· fusion et déploiement"
cd "$DEPOT"
git merge -q --ff-only "$BRANCHE"
git worktree remove "$ARBRE"
# Fusionnée à l'instant (fusion rapide) : -D, car -d refuse une branche qui suit origin/master pas encore à jour.
git merge-base --is-ancestor "$BRANCHE" master && git branch -q -D "$BRANCHE"
outils/deployer.sh >"$JOURNAUX/deploiement-$BRANCHE.log" 2>&1 || { tail -30 "$JOURNAUX/deploiement-$BRANCHE.log"; exit 1; }
grep -E "Clé VANGUARD|publiée|sans page|Durées" "$JOURNAUX/deploiement-$BRANCHE.log" | tail -4
