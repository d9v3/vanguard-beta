#!/usr/bin/env bash
# Essais de outils/verifier.sh lui-même, sur ce que lance l'audit de nuit de la CI (--seulement) : un vert qui n'a
# rien vérifié y passerait inaperçu chaque nuit, sans personne devant l'écran.
#   1. Une étape demandée qui se dit sautée (ici Wine absent : tests Windows, corpus de détection sous Wine) fait
#      échouer, avec sa raison.
#   2. Une étape demandée qui ne tourne jamais sous --seulement (la mise en forme) fait échouer.
#   3. Un nom d'étape inconnu (mal écrit, ou renommé sans suivre ci.yml) est refusé, code 2.
#   4. Une étape demandée qui réussit (scripts Python) donne bien « Tout est vert ».
# Chaque essai ne lance que des étapes de quelques secondes, sans Internet ni compilation.
# Lancé par outils/verifier.sh.
#   outils/essais-verifier.sh
set -uo pipefail
cd "$(dirname "$0")/.."
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

# Le script lancé comme la CI le lance ; sa sortie et son code gardés pour les essais.
lancer() {
  SORTIE=$("$@" 2>&1)
  CODE=$?
}

lancer env VANGUARD_WINE=/inexistant/wine bash outils/verifier.sh --seulement tests-windows
if ((CODE == 1)) && grep -q '✖ tests Windows.*sautée, rien vérifié : Wine absent' <<<"$SORTIE"; then
  ok "étape demandée et sautée : un échec, avec sa raison"
else
  ko "étape demandée et sautée (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer env VANGUARD_WINE=/inexistant/wine bash outils/verifier.sh --seulement regression-detection-windows
if ((CODE == 1)) && grep -q '✖ régression de détection Windows.*sautée, rien vérifié : Wine absent' <<<"$SORTIE"; then
  ok "corpus de détection demandé sous Wine, Wine absent : un échec, avec sa raison"
else
  ko "corpus de détection demandé sous Wine, Wine absent (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer bash outils/verifier.sh --seulement mise-en-forme
if ((CODE == 1)) && grep -q 'mise en forme.*non lancé' <<<"$SORTIE"; then
  ok "étape demandée et jamais lancée : un échec"
else
  ko "étape demandée et jamais lancée (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer bash outils/verifier.sh --seulement dependances,failles-connue
if ((CODE == 2)) && grep -q 'étape inconnue : failles-connue' <<<"$SORTIE"; then
  ok "nom d'étape inconnu : refusé, code 2"
else
  ko "nom d'étape inconnu (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

lancer bash outils/verifier.sh --seulement python
if ((CODE == 0)) && grep -q '✔ scripts Python' <<<"$SORTIE" && grep -q '^Tout est vert' <<<"$SORTIE"; then
  ok "étape demandée et réussie : tout est vert"
else
  ko "étape demandée et réussie (code $CODE) : $(tail -n 2 <<<"$SORTIE")"
fi

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "verifier.sh : tout est juste."
