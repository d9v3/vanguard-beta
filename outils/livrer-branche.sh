#!/usr/bin/env bash
# Livre la publication du jour, une branche déjà commitée (commit de version « … (vX.Y.Z) » en tête) : rebase sur
# master, passage sur le Mac de GitHub, vérification complète pendant qu'il compile, fusion rapide dans master,
# déploiement (outils/deployer.sh : binaire, clé, VM, GitHub, page de la version), puis ménage de la branche et du
# worktree. S'arrête à la première étape en échec, sans rien fusionner.
#   outils/livrer-branche.sh <branche> <worktree>
# VANGUARD_INTERMEDIAIRE=1 : version intermédiaire d'une série, sans passage sur le Mac (seule la dernière y passe).
set -euo pipefail
BRANCHE=$1
ARBRE=$2
# L'arbre principal (master), où se font la fusion et le déploiement : celui qui porte le .git commun.
DEPOT=$(dirname "$(git -C "$ARBRE" rev-parse --path-format=absolute --git-common-dir)")
export CARGO_TARGET_DIR=$DEPOT/target
JOURNAUX=$HOME/.cache/vanguard-dev
# Le passage sur le Mac de GitHub, attendu au plus ATTENTE_MAC secondes : GitHub coupe son travail à 60 minutes
# (.github/workflows/macos.yml, timeout-minutes), plus la file d'attente du runner et le travail « utile » d'avant.
# Sans délai, un runner qui ne vient jamais tenait la livraison ouverte sans fin. Code 124 : délai passé, dit ici.
ATTENTE_MAC=$((70 * 60))
attendre_mac() { # exécution, secondes au plus
  local code=0
  # -k : un gh qui ignore TERM est tué 10 s plus tard ; timeout rend alors 137 (KILL), le même délai passé.
  timeout -k 10 "$2" gh run watch "$1" --exit-status --interval 20 >/dev/null 2>&1 || code=$?
  ((code != 137)) || code=124
  if ((code == 124)); then
    echo "✖ Mac de GitHub pas fini après $(($2 / 60)) minutes : rien n'est fusionné. Où il en est : gh run view $1 (bloqué : gh run cancel $1) ; puis relancer la livraison, qui relance le Mac."
  elif ((code != 0)); then
    echo "✖ Mac de GitHub en échec : gh run view $1 --log-failed"
  fi
  return "$code"
}

cd "$ARBRE"
[[ -z $(git status --porcelain) ]] || { echo "✖ $ARBRE a des changements non commités"; exit 1; }
# Master déjà à la base de la branche : rien à rebaser (un rebase referait à plat les fusions de la journée, en
# faux conflits).
git merge-base --is-ancestor master HEAD || git rebase -q master
COMMIT=$(git rev-parse HEAD)
# Le Mac de GitHub d'abord, la vérification d'ici pendant qu'il compile (3 min 30 d'attente sinon perdues) ; une
# vérification en échec annule la compilation.
ID=""
if [[ -z ${VANGUARD_INTERMEDIAIRE:-} ]]; then
  # Rien de personnel ne part sur GitHub, même sur une branche de passage.
  python3 outils/confidentialite.py --plage origin/master "$BRANCHE" || { echo "✖ détail personnel : rien n'est envoyé"; exit 1; }
  echo "· Mac de GitHub lancé"
  git push -q origin "$BRANCHE" || { echo "✖ branche refusée par GitHub (déjà là avec un autre historique ?)"; exit 1; }
  # Le passage lancé ici, et pas un autre : celui de ce commit, absent avant la demande. Prendre le dernier passage
  # de la branche après une attente fixe pouvait tomber sur un ancien, ou sur aucun, et la fusion partait alors sans
  # attendre le Mac.
  AVANT=$(gh run list --workflow macos.yml --commit "$COMMIT" --limit 20 --json databaseId -q '.[].databaseId')
  # Avec l'essai complet (outils/test-macos/essai.sh) : chaque publication passe aussi sur un vrai Mac, ses résultats
  # rapatriés ici après la fusion.
  gh workflow run macos.yml --ref "$BRANCHE" -f essai_complet=true >/dev/null
  for _ in {1..30}; do
    ID=$(gh run list --workflow macos.yml --commit "$COMMIT" --event workflow_dispatch --limit 1 --json databaseId \
      -q '.[0].databaseId // ""')
    [[ -n $ID ]] && ! grep -qx -- "$ID" <<<"$AVANT" && break
    ID=""
    sleep 5
  done
  [[ -n $ID ]] || { echo "✖ le Mac de GitHub n'a pas démarré : rien n'est fusionné"; exit 1; }
fi
echo "· vérification complète"
if ! outils/verifier.sh >"$JOURNAUX/verif-$BRANCHE.log" 2>&1; then
  tail -30 "$JOURNAUX/verif-$BRANCHE.log"
  [[ -z $ID ]] || gh run cancel "$ID" >/dev/null 2>&1 || true
  exit 1
fi
if [[ -n $ID ]]; then
  echo "· attente du Mac de GitHub"
  attendre_mac "$ID" "$ATTENTE_MAC" || exit 1
fi
if [[ -n $ID ]]; then
  # Les résultats de l'essai complet sur le Mac, lisibles ici comme ceux de la VM Windows : un dossier par passage.
  ESSAI_MAC="$HOME/.local/share/vanguard/essais-macos/$(date +%Y-%m-%d_%H-%M)"
  if gh run download "$ID" -n essai-macos -D "$ESSAI_MAC" >/dev/null 2>&1; then
    echo "· essai sur le Mac : $(grep -E '^=== Fin' "$ESSAI_MAC/journal.txt" 2>/dev/null | sed 's/=== //; s/ ===//') ($ESSAI_MAC)"
  else
    echo "· essai sur le Mac : résultats non récupérés (gh run download $ID -n essai-macos)"
  fi
fi
echo "· fusion et déploiement"
cd "$DEPOT"
git merge -q --ff-only "$BRANCHE"
git push -q origin --delete "$BRANCHE" 2>/dev/null || true
git worktree remove "$ARBRE"
# Fusionnée à l'instant (fusion rapide) : -D, car -d refuse une branche qui suit origin/master pas encore à jour.
git merge-base --is-ancestor "$BRANCHE" master && git branch -q -D "$BRANCHE"
outils/deployer.sh >"$JOURNAUX/deploiement-$BRANCHE.log" 2>&1 || { tail -30 "$JOURNAUX/deploiement-$BRANCHE.log"; exit 1; }
grep -E "Clé VANGUARD|publiée|sans page|Durées" "$JOURNAUX/deploiement-$BRANCHE.log" | tail -4
