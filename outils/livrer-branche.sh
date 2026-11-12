#!/usr/bin/env bash
# Livre la publication du jour, une branche déjà commitée (commit de version « … (vX.Y.Z) » en tête) : rebase sur
# master, garde-fou de confidentialité, vérification complète, fusion rapide dans master, déploiement
# (outils/deployer.sh : binaire, clé, VM, GitHub, page de la version), puis ménage de la branche et du worktree.
#   outils/livrer-branche.sh <branche> <worktree>
# VANGUARD_INTERMEDIAIRE=1 : version intermédiaire d'une série (deployer.sh : sans page ni dépôt dans la VM).
#
# Ce qui est fusionné et déployé est le commit vérifié, noté juste après le rebase, jamais le nom de la branche : un
# commit posé sur la branche pendant la vérification (une autre fenêtre) fait refuser la livraison, rien fusionné ;
# un master qui dépasse ce commit après la fusion (une autre fenêtre l'a fusionné, puis a commité) fait refuser le
# déploiement.
# Limites : un commit posé sur master pendant deployer.sh lui-même partirait avec lui (deployer.sh fait ses propres
# commits, liste des fabricants, captures, page des fonctions : sa tête n'est pas celle vérifiée, à borner en 0.95) ;
# confidentialite.py est celui du lot jugé, puis celui de master une fois fusionné (deployer.sh), donc le même.
# S'arrête à la première étape en échec, sans rien fusionner. Le déploiement passe avant le ménage : un ménage raté
# (worktree verrouillé, branche gardée) est dit, sans défaire une livraison faite.
# Essais : outils/essais-livrer-branche.sh (dépôts jetables, faux verifier.sh et deployer.sh).
set -euo pipefail
usage() { echo "usage : $0 <branche> <worktree>" >&2; exit 2; }
[[ $# -eq 2 ]] || usage
BRANCHE=$1
[[ -n $BRANCHE && $BRANCHE != master ]] || { echo "✖ branche « $BRANCHE » : il faut la branche du lot, pas master" >&2; exit 2; }
[[ -d $2 ]] || { echo "✖ $2 n'est pas un dossier (arguments inversés ? $0 <branche> <worktree>)" >&2; exit 2; }
ARBRE=$(realpath "$2")
# L'arbre principal (master), où se font la fusion et le déploiement : celui qui porte le .git commun.
COMMUN=$(git -C "$ARBRE" rev-parse --path-format=absolute --git-common-dir 2>/dev/null) ||
  { echo "✖ $ARBRE n'est pas dans un dépôt git" >&2; exit 2; }
DEPOT=$(realpath "$(dirname "$COMMUN")")
[[ $ARBRE != "$DEPOT" ]] || { echo "✖ $ARBRE est l'arbre principal, pas le worktree du lot" >&2; exit 2; }
[[ $(git -C "$ARBRE" rev-parse --show-toplevel) == "$ARBRE" ]] ||
  { echo "✖ $ARBRE n'est pas la racine d'un worktree" >&2; exit 2; }
[[ $(git -C "$ARBRE" branch --show-current) == "$BRANCHE" ]] || { echo "✖ $ARBRE n'est pas sur $BRANCHE" >&2; exit 2; }
# L'arbre principal sur master et propre : sinon la fusion échouerait après la vérification, ou partirait d'un état
# que personne n'a vu. Vu avant la longue vérification, puis de nouveau juste avant la fusion.
arbre_principal_pret() {
  [[ $(git -C "$DEPOT" branch --show-current) == master ]] ||
    { echo "✖ l'arbre principal ($DEPOT) n'est pas sur master"; return 1; }
  # Les fichiers non suivis aussi : deployer.sh refuse de compiler avec un fichier non suivi dans src, assets… ; vu
  # ici, avant la vérification, plutôt qu'après la fusion.
  [[ -z $(git -C "$DEPOT" status --porcelain) ]] ||
    { echo "✖ l'arbre principal ($DEPOT) a des changements non commités ou des fichiers non suivis"; return 1; }
}
arbre_principal_pret || { echo "✖ rien n'est fusionné"; exit 1; }
export CARGO_TARGET_DIR=$DEPOT/target
JOURNAUX=$HOME/.cache/vanguard-dev
mkdir -p "$JOURNAUX"
NOM=${BRANCHE//\//-}

cd "$ARBRE"
[[ -z $(git status --porcelain) ]] || { echo "✖ $ARBRE a des changements non commités"; exit 1; }
# Master déjà à la base de la branche : rien à rebaser (un rebase referait à plat les fusions de la journée, en
# faux conflits).
git merge-base --is-ancestor master HEAD || git rebase -q master
# Le commit vérifié, noté une fois : tout ce qui suit (garde-fou, fusion, déploiement) porte sur lui seul.
SHA=$(git rev-parse HEAD)
# Rien de personnel ne part sur GitHub : vu ici, avant la vérification et la fusion (deployer.sh le revoit avant
# d'envoyer master).
# Code 1 : un détail trouvé ; tout autre code (2 : rien conclu) : le garde-fou n'a pas pu juger, dit tel quel.
GARDE=0
python3 outils/confidentialite.py --plage origin/master "$SHA" || GARDE=$?
if ((GARDE == 1)); then
  echo "✖ détail personnel : rien n'est fusionné"
  exit 1
elif ((GARDE != 0)); then
  echo "✖ garde-fou de confidentialité en panne (code $GARDE), rien conclu : rien n'est fusionné"
  exit 1
fi
echo "· vérification complète de ${SHA:0:12}"
if ! outils/verifier.sh >"$JOURNAUX/verif-$NOM.log" 2>&1; then
  tail -30 "$JOURNAUX/verif-$NOM.log"
  echo "✖ vérification en échec : rien n'est fusionné"
  exit 1
fi
# Le code de sortie ne suffit pas : seule une passe complète, rien sauté, finit sur « Tout est vert ».
grep -q "^Tout est vert" "$JOURNAUX/verif-$NOM.log" ||
  { tail -5 "$JOURNAUX/verif-$NOM.log"; echo "✖ la vérification ne dit pas « Tout est vert » : rien n'est fusionné"; exit 1; }
# Rien n'a bougé pendant la vérification : ni le worktree, ni sa tête, ni la branche.
[[ -z $(git status --porcelain) ]] || { echo "✖ $ARBRE a changé pendant la vérification : rien n'est fusionné"; exit 1; }
[[ $(git rev-parse HEAD) == "$SHA" && $(git rev-parse "refs/heads/$BRANCHE") == "$SHA" ]] ||
  { echo "✖ $BRANCHE a bougé pendant la vérification (vérifié : ${SHA:0:12}) : rien n'est fusionné"; exit 1; }
echo "· fusion et déploiement"
cd "$DEPOT"
arbre_principal_pret || { echo "✖ rien n'est fusionné"; exit 1; }
git merge -q --ff-only "$SHA"
# « Already up to date » réussit aussi quand master contient déjà le commit vérifié et l'a dépassé : déployer HEAD
# serait déployer des commits jamais vérifiés.
[[ $(git rev-parse HEAD) == "$SHA" ]] || {
  echo "✖ master ($(git rev-parse --short=12 HEAD)) dépasse le commit vérifié (${SHA:0:12}) : rien n'est déployé"
  echo "  master le contient déjà ; relancer la livraison sur la branche rebasée sur ce master"
  exit 1
}
outils/deployer.sh >"$JOURNAUX/deploiement-$NOM.log" 2>&1 || {
  tail -30 "$JOURNAUX/deploiement-$NOM.log"
  echo "✖ déploiement en échec : master contient ${SHA:0:12}, worktree et branche gardés"
  exit 1
}
grep -E "Clé VANGUARD|publiée|sans page|Durées" "$JOURNAUX/deploiement-$NOM.log" | tail -4 || true
# Le ménage, une fois la livraison faite : son échec se dit, il ne défait rien.
menage=()
git worktree remove "$ARBRE" 2>/dev/null || menage+=("worktree $ARBRE gardé (git worktree remove a refusé)")
# Fusionnée à l'instant (fusion rapide) : -D, car -d refuse une branche qui suit origin/master pas encore à jour ;
# seulement si elle est encore au commit livré.
if [[ $(git rev-parse -q --verify "refs/heads/$BRANCHE") == "$SHA" ]] && git merge-base --is-ancestor "$SHA" master; then
  git branch -q -D "$BRANCHE" 2>/dev/null || menage+=("branche $BRANCHE gardée (git branch -D a refusé)")
else
  menage+=("branche $BRANCHE gardée (elle n'est plus au commit livré)")
fi
if ((${#menage[@]})); then
  printf '⚠ livré (%s), ménage à finir à la main :\n' "${SHA:0:12}"
  printf '  %s\n' "${menage[@]}"
fi
echo "✔ livré : ${SHA:0:12}"
