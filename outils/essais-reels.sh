#!/usr/bin/env bash
# Une commande d'essais (cargo test avec un filtre) qui doit avoir vraiment essayé quelque chose. `cargo test -- <nom>`
# rend 0 quand le filtre ne trouve aucun essai (un essai renommé rend le contrôle muet), et un essai qui rend la main
# tôt compte comme réussi (src/essais.rs). Sortie montrée en entier ; code de la commande si elle échoue, sinon 1 si
# moins de N essais ont réussi, ou si l'un d'eux s'est dit sauté (--sans-saut).
#   outils/essais-reels.sh [--au-moins N] [--sans-saut] -- cargo test …
# Aussi sous Git Bash (travail « windows » de ci.yml) : rien d'autre que bash et les outils POSIX.
set -euo pipefail

AU_MOINS=1 SANS_SAUT=
while (($#)); do
  case $1 in
    --au-moins) AU_MOINS=${2-}; shift 2 || exit 2 ;;
    --sans-saut) SANS_SAUT=1; shift ;;
    --) shift; break ;;
    *) echo "outils/essais-reels.sh [--au-moins N] [--sans-saut] -- commande" >&2; exit 2 ;;
  esac
done
[[ $AU_MOINS =~ ^[1-9][0-9]{0,3}$ ]] && (($# > 0)) ||
  { echo "outils/essais-reels.sh [--au-moins N] [--sans-saut] -- commande" >&2; exit 2; }

JOURNAL=$(mktemp) SAUTS=$(mktemp)
trap 'rm -f "$JOURNAL" "$SAUTS"' EXIT
# Sans --sans-saut, la liste demandée par l'appelant (VANGUARD_TESTS_SAUTES) reste la sienne.
[[ -z $SANS_SAUT ]] || export VANGUARD_TESTS_SAUTES=$SAUTS

CODE=0
# Sans couleur : la ligne « test result: ok. » est lue telle quelle.
CARGO_TERM_COLOR=never "$@" 2>&1 | tee "$JOURNAL" || CODE=$?
((CODE == 0)) || exit "$CODE"
REUSSIS=$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed;.*/\1/p' "$JOURNAL" |
  awk '{ n += $1 } END { print n + 0 }')
if ((REUSSIS < AU_MOINS)); then
  echo "✖ $REUSSIS essai(s) réussi(s), $AU_MOINS attendu(s) au moins : rien n'est conclu ($*)"
  exit 1
fi
if [[ -s $SAUTS ]]; then
  echo "✖ essai(s) sauté(s), non vérifiés :"
  sed 's/^/    /' "$SAUTS"
  exit 1
fi
