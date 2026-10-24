#!/usr/bin/env bash
# La date du code d'un commit (HEAD par défaut) : celle du dernier commit, lui ou un ancêtre, qui a touché ce que le
# programme intègre (tout sauf .github/hors-code.txt), en secondes. Gravée dans les programmes (SOURCE_DATE_EPOCH,
# build.rs) par outils/compiler-version.sh et par .github/workflows/macos.yml, et revérifiée par
# outils/publier-version.sh : les commits des captures et de la page des fonctions, faits après la compilation, ne
# changent plus la date des programmes, et les trois systèmes d'une même version gravent la même (campagne d'attaque
# n° 3 : le Mac compilait la tête, Linux et Windows le commit d'avant). Sans hors-code.txt ou sans git : la date du
# commit lui-même.
#   outils/date-du-code.sh [commit]
set -euo pipefail
cd "$(dirname "$0")/.."
COMMIT=${1:-HEAD}
HORS_CODE=$(grep -v '^#' .github/hors-code.txt 2>/dev/null | head -n 1 || true)
# Un clone superficiel (actions/checkout sans fetch-depth: 0) n'a pas les commits d'avant : sa date serait fausse.
if [[ $(git rev-parse --is-shallow-repository 2>/dev/null) == true ]]; then
  echo "date-du-code.sh : clone superficiel, date du commit lui-même (fetch-depth: 0 pour la vraie)" >&2
  HORS_CODE=
fi
if [[ -n $HORS_CODE ]]; then
  while read -r sha date; do
    # Le premier commit (sans parent) compte, comme un commit qui touche le code ; une fusion se juge sur son premier
    # parent.
    if ! git rev-parse -q --verify "$sha^" >/dev/null ||
      git diff --name-only "$sha^" "$sha" | grep -vqE "$HORS_CODE"; then
      echo "$date"
      exit 0
    fi
  done < <(git log --first-parent --format='%H %ct' "$COMMIT")
fi
git log -1 --format=%ct "$COMMIT"
