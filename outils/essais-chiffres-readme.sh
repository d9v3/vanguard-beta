#!/usr/bin/env bash
# Essais de outils/chiffres-readme.py, la garde des nombres des README, sur des copies des deux README :
#   1. Les vrais README : code 0 (« plus de 300 règles » n'y est pas pris pour le nombre exact).
#   2. Un nombre vieilli (règles du bilan, modules sans unsafe, comptes d'unsafe, règles YARA), en français ou en
#      anglais : code 1, le fichier, la ligne et le bon nombre nommés.
#   3. « plus de N » au-dessus du vrai nombre : code 1.
#   4. Une phrase attendue qui change de forme : code 2 (rien n'est conclu), jamais un vert.
#   5. Les comptes d'unsafe sont ceux de compte_unsafe (lue dans outils/verifier.sh) : un seul calcul, deux lecteurs.
# Lancé par outils/verifier.sh (étape « chiffres-readme »).
#   outils/essais-chiffres-readme.sh
set -uo pipefail
cd "$(dirname "$0")/.."
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

COPIE=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-chiffres.XXXX")
trap 'rm -rf "$COPIE"' EXIT

# Les README copiés, l'un d'eux changé par sed ($1 : fr ou en, $2 : l'expression), puis jugés.
juger() {
  cp README.md "$COPIE/README.md" && cp README.en.md "$COPIE/README.en.md" || return 1
  if [[ -n ${1:-} ]]; then
    local f=$COPIE/README.md
    [[ $1 == en ]] && f=$COPIE/README.en.md
    cp "$f" "$COPIE/avant" && sed -i "$2" "$f"
    cmp -s "$f" "$COPIE/avant" && { SORTIE="(sed n'a rien changé : $2)"; CODE=99; return 0; }
  fi
  SORTIE=$(python3 -I outils/chiffres-readme.py --lisez-moi "$COPIE/README.md" "$COPIE/README.en.md" 2>&1)
  CODE=$?
}

juger
((CODE == 0)) && ok "vrais README : à jour" || ko "vrais README (code $CODE) : $SORTIE"

# Un nombre vieilli : code 1, avec le motif attendu dans le message.
vieilli() {
  local nom=$1 langue=$2 expression=$3 attendu=$4
  juger "$langue" "$expression"
  ((CODE == 1)) && grep -qE -- "$attendu" <<<"$SORTIE" && ok "$nom : vieilli, nommé" ||
    ko "$nom (code $CODE) : $SORTIE"
}
vieilli "règles du bilan (fr)" fr 's/[0-9]\+ règles à identifiant stable/7 règles à identifiant stable/' \
  '^✖ README\.md:[0-9]+ : règles du bilan : \[7, '
vieilli "règles Windows (en)" en 's/, [0-9]\+ on Windows/, 7 on Windows/' '^✖ README\.en\.md:[0-9]+ : règles du bilan'
vieilli "modules sans unsafe (en)" en 's/(`forbid`) in [0-9]\+ modules/(`forbid`) in 7 modules/' \
  '^✖ README\.en\.md:[0-9]+ : modules sans unsafe : \[7\] écrit'
vieilli "comptes d'unsafe (fr)" fr 's/[0-9]\+ blocs `unsafe extern`/7 blocs `unsafe extern`/' \
  '^✖ README\.md:[0-9]+ : comptes d.unsafe'
vieilli "règles YARA (fr)" fr 's/[0-9]\+ règles de ReversingLabs, empreintes/7 règles de ReversingLabs, empreintes/' \
  '^✖ README\.md:[0-9]+ : règles YARA : \[7\]'
vieilli "plus de N règles au-dessus du vrai (en)" en 's/over 300 rules/over 9000 rules/' \
  '^✖ README\.en\.md:[0-9]+ : « plus de 9000 »'

# Une phrase qui change de forme : rien n'est conclu (code 2), jamais vert.
juger en 's/\([0-9]\+\) ReversingLabs rules, MalwareBazaar/\1 rules from ReversingLabs, MalwareBazaar/'
((CODE == 2)) && grep -q 'phrase « règles YARA » introuvable' <<<"$SORTIE" &&
  ok "phrase changée de forme : rien n'est conclu (code 2)" || ko "phrase changée de forme (code $CODE) : $SORTIE"
juger fr 's/refusé sans recours (`forbid`) dans/refusé (`forbid`) dans/'
((CODE == 2)) && ok "phrase des modules sans unsafe disparue : code 2" || ko "phrase disparue (code $CODE) : $SORTIE"

# Un seul calcul de l'unsafe : celui de verifier.sh (compte_unsafe) et celui de la garde disent les mêmes nombres.
fonction=$(awk '/^compte_unsafe\(\) \{/,/^\}/' outils/verifier.sh)
shell=$(bash -c "$fonction
compte_unsafe" | sed -nE 's/.*unsafe dans src\/ : ([0-9]+) blocs, ([0-9]+) blocs extern, ([0-9]+) fn, ([0-9]+) impl, ([0-9]+) attributs$/\1 \2 \3 \4 \5/p')
python=$(python3 -I outils/chiffres-readme.py --unsafe)
[[ -n $fonction && -n $shell && $shell == "$python" ]] && ok "comptes d'unsafe : les mêmes que verifier.sh ($python)" ||
  ko "comptes d'unsafe : verifier.sh « $shell », chiffres-readme.py « $python »"

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "chiffres-readme.py : tout est juste."
