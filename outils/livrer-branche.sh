#!/usr/bin/env bash
# Livre la publication du jour, une branche déjà commitée (commit de version « … (vX.Y.Z) » en tête) : rebase sur
# master, garde-fou de confidentialité, vérification complète, fusion rapide dans master, déploiement
# (outils/deployer.sh : binaire, clé, VM, GitHub, page de la version), puis ménage de la branche et du worktree.
#   outils/livrer-branche.sh <branche> <worktree> [--sans-controle-sources]
# VANGUARD_INTERMEDIAIRE=1 : version intermédiaire d'une série (deployer.sh : sans page ni dépôt dans la VM).
#
# Ce qui est fusionné et déployé est le commit vérifié, noté juste après le rebase, jamais le nom de la branche : un
# commit posé sur la branche pendant la vérification (une autre fenêtre) fait refuser la livraison, rien fusionné ;
# un master qui dépasse ce commit après la fusion (une autre fenêtre l'a fusionné, puis a commité) fait refuser le
# déploiement.
# Le garde-fou de confidentialité est celui de master (git show), jamais celui du lot jugé : un lot qui le viderait
# ne se rendrait pas vert lui-même (comme la CI depuis 50f78225).
# deployer.sh reçoit le commit vérifié (VANGUARD_COMMIT_VERIFIE) : il refuse de partir d'un autre, et n'envoie sur
# GitHub que lui plus ses propres commits (liste des fabricants, captures, page des fonctions) ; un commit posé sur
# master pendant le déploiement fait refuser l'envoi (envoi_borne).
# Rien de parti sur GitHub (envoi refusé, sans Internet) : la livraison n'est faite qu'ici, c'est dit (« ⚠ … rien
# n'est parti sur GitHub »), worktree et branche gardés, code 3 ; jamais « ✔ livré ».
# S'arrête à la première étape en échec, sans rien fusionner. Le déploiement passe avant le ménage : un ménage raté
# (worktree verrouillé, branche gardée) est dit, sans défaire une livraison faite.
# Essais : outils/essais-livrer-branche.sh (dépôts jetables, faux verifier.sh et deployer.sh).
set -euo pipefail
usage() { echo "usage : $0 <branche> <worktree> [--sans-controle-sources]" >&2; exit 2; }
# --sans-controle-sources : le seul contournement du contrôle des sources (plus bas), un choix de l'auteur tapé à la
# livraison, montré et noté ; jamais une variable d'environnement, qui resterait posée sans qu'on la voie.
CONTOURNER=""
if [[ $# -eq 3 && $3 == --sans-controle-sources ]]; then
  CONTOURNER=1
elif [[ $# -ne 2 ]]; then
  usage
fi
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
# L'arbre `$1` est propre (rien de non commité, aucun fichier non suivi). Propre se prouve : un git status qui échoue
# (index abîmé, dépôt illisible) n'écrit rien, ce qui passerait pour un arbre propre ([[ ]] ne voit pas l'échec d'une
# substitution, set -e non plus) ; c'est un refus, dit (relecture 0.94, N-2).
# ETAT garde ce que git status a vu, pour nommer les fichiers en cause dans le refus.
propre() {
  ETAT=$(git -C "$1" status --porcelain) || { echo "✖ git status a échoué dans $1 : rien n'est fusionné"; exit 1; }
  [[ -z $ETAT ]]
}
# Les fichiers en cause (« ?? » : non suivi), dix au plus : un refus qui dit lequel se règle sans chercher.
en_cause() { head -n 10 <<<"$ETAT" | sed 's/^/    /'; }
# L'arbre principal sur master et propre : sinon la fusion échouerait après la vérification, ou partirait d'un état
# que personne n'a vu. Vu avant la longue vérification, puis de nouveau juste avant la fusion.
arbre_principal_pret() {
  [[ $(git -C "$DEPOT" branch --show-current) == master ]] ||
    { echo "✖ l'arbre principal ($DEPOT) n'est pas sur master"; return 1; }
  # Les fichiers non suivis aussi : deployer.sh refuse de compiler avec un fichier non suivi dans src, assets… ; vu
  # ici, avant la vérification, plutôt qu'après la fusion.
  propre "$DEPOT" || {
    echo "✖ l'arbre principal ($DEPOT) a des changements non commités ou des fichiers non suivis (« ?? ») :"
    en_cause
    return 1
  }
}
arbre_principal_pret || { echo "✖ rien n'est fusionné"; exit 1; }
export CARGO_TARGET_DIR=$DEPOT/target
JOURNAUX=$HOME/.cache/vanguard-dev
mkdir -p "$JOURNAUX"
NOM=${BRANCHE//\//-}

cd "$ARBRE"
propre "$ARBRE" || { echo "✖ $ARBRE a des changements non commités"; exit 1; }
# Master déjà à la base de la branche : rien à rebaser (un rebase referait à plat les fusions de la journée, en
# faux conflits).
git merge-base --is-ancestor master HEAD || git rebase -q master
# Le commit vérifié, noté une fois : tout ce qui suit (garde-fou, fusion, déploiement) porte sur lui seul.
SHA=$(git rev-parse HEAD)
# Rien de personnel ne part sur GitHub : vu ici, avant la vérification et la fusion (deployer.sh le revoit avant
# d'envoyer master).
# Code 1 avec son constat (« N détail(s) personnel(s) dans ») : un détail trouvé ; tout autre code (2 : rien conclu),
# ou un code 1 sans constat (Python qui plante, sa trace) : le garde-fou n'a pas pu juger, dit tel quel (N-1).
# Le garde-fou pris dans master, lancé isolé (python3 -I) depuis le worktree : celui du lot pourrait avoir été
# vidé par le lot même. Introuvable dans master : refus, jamais un repli sur celui du lot.
JUGE=$(mktemp "$JOURNAUX/confidentialite-master.XXXXXX")
trap 'rm -f "$JUGE"' EXIT
git -C "$DEPOT" show master:outils/confidentialite.py >"$JUGE" 2>/dev/null ||
  { echo "✖ master n'a pas de outils/confidentialite.py lisible : rien n'est jugé, rien n'est fusionné"; exit 1; }
GARDE=0
SORTIE_GARDE=$(python3 -I "$JUGE" --plage origin/master "$SHA" 2>&1) || GARDE=$?
[[ -z $SORTIE_GARDE ]] || printf '%s\n' "$SORTIE_GARDE" >&2
if ((GARDE == 1)) && grep -q '^Confidentialité : [0-9]* détail(s) personnel(s) dans' <<<"$SORTIE_GARDE"; then
  echo "✖ détail personnel : rien n'est fusionné"
  exit 1
elif ((GARDE != 0)); then
  echo "✖ garde-fou de confidentialité en panne (code $GARDE), rien conclu : rien n'est fusionné"
  exit 1
# Un code 0 ne suffit pas : un script vide, ou qui ne lit rien, sort aussi en 0. Le témoin que le garde-fou a jugé
# le lot : « Confidentialité : N commit(s) relu(s). », N au moins 1 (le lot a au moins un commit de plus que GitHub ;
# relecture 0.95, V-5).
elif ! grep -qE '^Confidentialité : [1-9][0-9]* commit\(s\) relu\(s\)\.$' <<<"$SORTIE_GARDE"; then
  echo "✖ le garde-fou de master ne dit pas avoir relu le lot (« Confidentialité : N commit(s) relu(s). », N ≥ 1) :"
  echo "  rien n'est jugé, rien n'est fusionné"
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
propre "$ARBRE" || { echo "✖ $ARBRE a changé pendant la vérification : rien n'est fusionné"; exit 1; }
[[ $(git rev-parse HEAD) == "$SHA" && $(git rev-parse "refs/heads/$BRANCHE") == "$SHA" ]] ||
  { echo "✖ $BRANCHE a bougé pendant la vérification (vérifié : ${SHA:0:12}) : rien n'est fusionné"; exit 1; }
# Les sources du catalogue (outils/controle-sources.py, conception C5) : une source qui s'est dégradée (paquet Arch
# périmé, application Flathub en fin de vie ou de licence changée, identifiant winget disparu) arrête la livraison,
# comme une source qu'on n'a pas pu vérifier (code 2 : réseau, délai, limite) ; seul --sans-controle-sources la laisse
# passer, dit et noté (date, commit, code ; aucun texte libre). Après la vérification : le catalogue exporté
# (outils/catalogue-sources.json) est alors prouvé égal au catalogue compilé (logiciels::tests).
# Le contrôle est celui de master, comme le garde-fou de confidentialité : un lot qui le viderait ne se rendrait pas
# vert lui-même. Seule exception, le premier passage, quand master ne l'a pas encore : celui du lot, dit.
# Code 0 avec « Sources : N vérifiée(s), saines » (N ≥ 1), sinon rien n'est fusionné : une trace de Python sort en 1
# sans le témoin « N dégradation(s) », dite comme une panne.
CONTROLE=$(mktemp "$JOURNAUX/controle-sources.XXXXXX")
trap 'rm -f "$JUGE" "$CONTROLE"' EXIT
if git -C "$DEPOT" cat-file -e master:outils/controle-sources.py 2>/dev/null; then
  git -C "$DEPOT" show master:outils/controle-sources.py >"$CONTROLE"
  ORIGINE=master
elif [[ -z $(git -C "$DEPOT" log -1 --format=%H master -- outils/controle-sources.py) ]] &&
  git show "$SHA:outils/controle-sources.py" >"$CONTROLE" 2>/dev/null; then
  # Seulement si master ne l'a jamais eu : un contrôle retiré de master (par un lot d'avant) ne laisse pas un lot
  # apporter le sien, vide.
  ORIGINE="le lot (master ne l'a pas encore)"
else
  echo "✖ master n'a pas (ou plus) outils/controle-sources.py, et le lot ne peut pas l'apporter : les sources ne sont"
  echo "  pas contrôlées, rien n'est fusionné"
  exit 1
fi
echo "· sources du catalogue (contrôle de $ORIGINE)"
SOURCES=0
SORTIE_SOURCES=$(python3 -I "$CONTROLE" --catalogue "$ARBRE/outils/catalogue-sources.json" \
  --admis "$ARBRE/outils/controle-sources-admis.json" 2>&1) || SOURCES=$?
[[ -z $SORTIE_SOURCES ]] || printf '%s\n' "$SORTIE_SOURCES" | tail -n 40
CONTOURNE=""
if ((SOURCES != 0)) || ! grep -qE '^Sources : [1-9][0-9]* vérifiée\(s\), saines' <<<"$SORTIE_SOURCES"; then
  if ((SOURCES == 1)) && grep -qE '^Sources : [1-9][0-9]* dégradation\(s\)' <<<"$SORTIE_SOURCES"; then
    CAUSE="source(s) dégradée(s)"
  elif ((SOURCES == 2)) && grep -q '^Sources : ' <<<"$SORTIE_SOURCES"; then
    CAUSE="source(s) non vérifiée(s), rien conclu"
  else
    CAUSE="contrôle en panne ou sans témoin (code $SOURCES)"
  fi
  if [[ -z $CONTOURNER ]]; then
    echo "✖ sources du catalogue : $CAUSE : rien n'est fusionné"
    echo "  corriger le catalogue, admettre la dégradation dans outils/controle-sources-admis.json (raison, date,"
    echo "  jusqu_au), réessayer plus tard (réseau), ou relancer avec --sans-controle-sources (noté)"
    exit 1
  fi
  printf '%s\t%s\t%s\tcode %s\n' "$(date -Iseconds)" "$SHA" "$BRANCHE" "$SOURCES" \
    >>"$JOURNAUX/controle-sources-contournements.log"
  echo "⚠ sources du catalogue : $CAUSE ; contourné par --sans-controle-sources, noté dans"
  echo "  $JOURNAUX/controle-sources-contournements.log"
  CONTOURNE=" (sources du catalogue non contrôlées : --sans-controle-sources)"
fi
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
# Le commit vérifié lui est donné : deployer.sh refuse de partir d'un autre (une fenêtre entre cette garde et sa
# lecture de HEAD), et n'envoie rien de plus que ses propres commits (envoi_borne).
# Code 8 : déployé ici, mais la borne a refusé l'envoi sur GitHub (relecture 0.95, W-1) : traité plus bas avec les
# autres « rien n'est parti », seulement si sa raison est dans le journal ; sinon, un échec comme un autre.
DEPLOI=0
VANGUARD_COMMIT_VERIFIE=$SHA outils/deployer.sh >"$JOURNAUX/deploiement-$NOM.log" 2>&1 || DEPLOI=$?
# deployer.sh finit en code 0 quand rien ne part sur GitHub pour une raison du moment (garde-fou, lien mort, refus de
# GitHub, sans Internet), en code 8 quand la borne le refuse : la raison, avec ses lignes en retrait, est montrée
# ici, pas laissée dans le journal (relecture 0.95, V-4).
PAS_ENVOYE=$(awk '/^(Rien n.est envoyé sur GitHub|GitHub refuse l.envoi|GitHub injoignable : le code)/ { p = 1; print; next }
  p && /^  / { print; next } { p = 0 }' "$JOURNAUX/deploiement-$NOM.log")
if ((DEPLOI != 0)) && ! [[ $DEPLOI == 8 && -n $PAS_ENVOYE ]]; then
  tail -30 "$JOURNAUX/deploiement-$NOM.log"
  echo "✖ déploiement en échec (code $DEPLOI) : master contient ${SHA:0:12}, worktree et branche gardés"
  exit 1
fi
grep -E "Clé VANGUARD|publiée|sans page|Durées" "$JOURNAUX/deploiement-$NOM.log" | tail -4 || true
if [[ -n $PAS_ENVOYE ]]; then
  head -n 15 <<<"$PAS_ENVOYE"
  echo "⚠ fusionné et déployé ici (${SHA:0:12}), mais rien n'est parti sur GitHub : worktree et branche gardés"
  echo "  journal : $JOURNAUX/deploiement-$NOM.log"
  # Un commit posé à la main sur master n'est jamais vérifié : deployer.sh le refuserait à chaque relance (relecture
  # 0.95, W-2). Il passe par une livraison, qui le vérifie et le note.
  echo "  cause réglée sans commit (Internet ou lien revenu) : relancer outils/deployer.sh"
  echo "  cause qui demande un commit (lien corrigé, détail retiré) ou commit d'ailleurs sur master : une branche posée"
  echo "  sur master (worktree neuf, le correctif dessus s'il en faut un), livrée par outils/livrer-branche.sh"
  exit 3
fi
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
echo "✔ livré : ${SHA:0:12}$CONTOURNE"
