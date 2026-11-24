#!/usr/bin/env bash
# Les canaris de format, pour la CI de nuit (ci.yml, « canaris ») : chaque vraie source téléchargée et relue par le
# lecteur du programme (src/canaris.rs), puis le verdict de chacune (canaris.json) lu ici : jusqu'au 24 nov. 2026, la
# CI ne le lisait pas, et une source au format changé y passait verte si aucun autre essai ne la relisait.
#   outils/canaris-ci.sh <dossier>
# Échec : une source lue deux fois de suite à un format que le lecteur refuse, aucune source lue, un essai absent
# (renommé) ou sauté. Une source injoignable est dite (avertissement), pas un échec : ce n'est pas notre code.
set -euo pipefail
cd "$(dirname "$0")/.."

D=${1:?outils/canaris-ci.sh <dossier>}
mkdir -p "$D"
D=$(cd "$D" && pwd)
export VANGUARD_CANARIS=$D
canari() { # nom exact de l'essai
  bash outils/essais-reels.sh --sans-saut -- \
    cargo test -q --locked --bin vanguard "canaris::$1" -- --ignored --exact
}
formats_refuses() { jq -er '[.[] | select(.etat == "format") | .id] | join(" ")' "$D/canaris.json"; }

rm -f "$D/canaris.json"
canari canaris_telecharger
REFUSES=$(formats_refuses)
if [[ -n $REFUSES ]]; then
  echo "format refusé ($REFUSES) : deuxième essai dans ${VANGUARD_CANARIS_ATTENTE:-60} s"
  sleep "${VANGUARD_CANARIS_ATTENTE:-60}"
  rm -f "$D/canaris.json"
  canari canaris_telecharger
  REFUSES=$(formats_refuses)
fi
LUES=$(jq -er '[.[] | select(.etat == "ok")] | length' "$D/canaris.json")
AILLEURS=$(jq -er '[.[] | select(.etat != "ok" and .etat != "format" and .etat != "sautee") | "\(.id) (\(.etat))"]
  | join(", ")' "$D/canaris.json")
[[ -z $AILLEURS ]] || echo "::warning::sources injoignables, pas vérifiées cette nuit : $AILLEURS"
echo "$LUES source(s) lue(s) par le lecteur du programme"
[[ -z $REFUSES ]] || { echo "✖ format changé, deux fois de suite : $REFUSES"; exit 1; }
((LUES > 0)) || { echo "✖ aucune source lue : rien n'est vérifié"; exit 1; }

# Les essais plus exigeants, sur ces copies : chacun seulement si la sienne est là (une source injoignable est déjà
# dite plus haut, et n'est pas un échec), l'essai des éditeurs si toutes le sont.
ESSAIS=()
[[ ! -f $D/formula.json ]] || ESSAIS+=(vraie_copie_si_presente)
[[ ! -f $D/ioc.yaml ]] || ESSAIS+=(vrai_fichier_d_echap)
[[ -n $AILLEURS ]] || ESSAIS+=(vraies_copies_si_presentes)
if [[ -f $D/kev.json ]]; then
  canari canaris_kev
else
  echo "::warning::catalogue KEV absent : ses nouvelles failles ne sont pas relues"
fi
if ((${#ESSAIS[@]} < 3)); then
  echo "::warning::essais sur vraies copies pas tous lancés (source injoignable) : ${#ESSAIS[@]} sur 3"
fi
((${#ESSAIS[@]} == 0)) ||
  VANGUARD_ESSAI_PERIMES=$D VANGUARD_ESSAI_ECHAP=$D/ioc.yaml bash outils/essais-reels.sh \
    --au-moins "${#ESSAIS[@]}" --sans-saut -- cargo test -q --locked --bin vanguard -- "${ESSAIS[@]}"
