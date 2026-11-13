#!/usr/bin/env bash
# Essais de la garde des caisses de la fenêtre (outils/caisses-fenetre.sh) et de sa place dans la recette des
# programmes publiés (outils/compiler-version.sh), avec une cale cargo dans le PATH, de faux programmes et de faux
# arbres aux valeurs inventées : rien n'est compilé, rien de l'ordinateur n'est lu.
#   1. La recette : la fenêtre compilée une cible par appel de cargo (jamais deux --target dans un même appel :
#      compilées ensemble, les cibles partagent leurs options, et la fenêtre Linux emportait zbus et zvariant), puis
#      caisses-fenetre.sh --programmes sur les deux fenêtres, avant que leur empreinte soit calculée pour être gravée
#      dans vanguard, son échec arrêtant tout. Trois recettes abîmées (cibles jointes, garde retirée, garde après
#      l'empreinte) sont refusées : le lecteur de la recette refuse pour de vrai.
#   2. --programmes : tout dans l'arbre de sa cible → 0 ; une caisse hors de l'arbre → 1 ; rien de lisible dans un
#      programme, programme absent ou cargo tree en échec → 2 (rien n'est conclu, jamais un vert).
#   3. Sans argument (le cliquet de outils/verifier.sh) : l'arbre de chaque cible est comparé à sa LISTE de référence
#      (outils/caisses-fenetre/<cible>.txt, noms et versions), jamais à un nombre : une caisse remplacée par une autre
#      à nombre égal, une de plus, une de moins, une retirée revenue ou la même caisse d'une autre source que
#      crates.io (chemin local, dépôt git) → 1, la différence montrée ; cargo tree en échec ou une ligne d'une forme
#      inconnue → 2.
#   4. outils/failles-programmes.sh --fenetre n'écarte les avis de zbus et zvariant (HORS_CIBLES) que si aucune des
#      caisses retirées de la fenêtre (RETIREES de caisses-fenetre.sh, HORS_CIBLES comprises) ne se lit dans les
#      octets du programme audité (même lecture que --programmes) : un faux programme qui porte zvariant, ou zbus sans
#      zvariant, est refusé ; un programme où rien ne se lit est « non vérifié », jamais vert ; un programme sain
#      passe (cale cargo-audit à la version de la CI).
# Lancé par outils/verifier.sh (étape « fenêtre »).
#   outils/essais-caisses-fenetre.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ECHECS=0
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }
T=$(mktemp -d "${TMPDIR:-/tmp}/essais-caisses-fenetre.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
LINUX=x86_64-unknown-linux-gnu
WINDOWS=x86_64-pc-windows-gnu

# La cale cargo : « cargo tree » seulement, l'arbre de chaque cible lu dans $CALE_ARBRES/<cible>.txt (« nom version »
# par ligne) ; absent, cargo tree échoue. Avec -i <caisse> : la caisse si elle est dans l'arbre, rien sinon.
mkdir -p "$T/bin" "$T/arbres"
cat >"$T/bin/cargo" <<'EOF'
#!/usr/bin/env bash
[[ ${1:-} == tree ]] || exit 101
cible= inverse=
while (($#)); do
  case $1 in
    --target) cible=$2 && shift ;;
    -i) inverse=$2 && shift ;;
  esac
  shift
done
f=$CALE_ARBRES/$cible.txt
[[ -f $f ]] || { echo "error: cale : pas d'arbre pour « $cible »" >&2; exit 101; }
if [[ -n $inverse ]]; then
  awk -v n="$inverse" '$1 == n { print $1 " v" $2 }' "$f"
  exit 0
fi
echo "vanguard-fenetre v0.1.0 (/depot-invente/fenetre)"
# « nom version [suite] » devient « nom vversion [suite] » : la suite (« (proc-macro) », « (*) », une source autre que
# crates.io) passe telle quelle, comme cargo tree l'écrit.
awk '!/^#/ && NF { $2 = "v" $2; print }' "$f"
EOF
# La cale cargo-audit, à la version qu'épingle la CI (failles-programmes.sh l'exige) : elle dit avoir lu la liste
# de chaque programme, sans faille.
AUDIT_CI=$(sed -n 's/.*cargo-audit@\([0-9][0-9.]*\).*/\1/p' .github/workflows/ci.yml | head -1)
cat >"$T/bin/cargo-audit" <<EOF
#!/usr/bin/env bash
[[ \${1:-} == --version ]] && { echo "cargo-audit $AUDIT_CI"; exit 0; }
touch "$T/audit-lance"
for p in "\$@"; do
  [[ -f \$p ]] && echo "Found 'cargo auditable' data in \$p (3 dependencies)"
done
exit 0
EOF
chmod +x "$T/bin/cargo" "$T/bin/cargo-audit"
export CALE_ARBRES=$T/arbres PATH="$T/bin:$PATH" VANGUARD_HORS_LIGNE=1

# Un faux programme : des octets quelconques, puis les chemins de panique des caisses données (« nom-version »).
programme() {
  local f=$1 c
  shift
  printf '\177ELF\0\0octets-inventes\0' >"$f"
  for c in "$@"; do
    printf '/cargo/registry/src/index.crates.io-0123456789abcdef/%s/src/lib.rs\0' "$c" >>"$f"
  done
}
arbre() { printf '%s\n' "${@:2}" >"$T/arbres/$1.txt"; }
lance() { SORTIE=$(bash "$@" 2>&1) && CODE=0 || CODE=$?; }

echo "1. La recette de la fenêtre (outils/compiler-version.sh)"
# Les lignes logiques d'un script (suites « \ », « || », « && » et « | » jointes), sans les commentaires, chacune
# précédée du numéro de sa dernière ligne.
logiques() {
  awk '{ sub(/^[ \t]+/, "") } /^#/ { next }
    { l = l $0; if (l ~ /\\$/) { sub(/\\$/, "", l); next } if (l ~ /(\|\||&&|\|)$/) { l = l " "; next }
      print NR ": " l; l = "" }' "$1"
}
# Code 0 si la recette compile la fenêtre une cible par appel, puis la garde des octets (qui arrête tout), avant
# l'empreinte gravée. Sinon, dit pourquoi.
recette() {
  local lignes appels a n garde empreinte derniere
  lignes=$(logiques "$1")
  appels=$(grep -E 'cargo +(zig)?build' <<<"$lignes" | grep -F fenetre/Cargo.toml)
  [[ -n $appels ]] || { echo "aucune compilation de la fenêtre trouvée"; return 1; }
  while read -r a; do
    n=$(grep -o -- '--target' <<<"$a" | wc -l)
    ((n == 1)) || { echo "un appel de cargo avec $n --target pour la fenêtre (ligne ${a%%:*})"; return 1; }
  done <<<"$appels"
  derniere=$(tail -1 <<<"$appels" | cut -d: -f1)
  garde=$(grep -F 'outils/caisses-fenetre.sh --programmes "$FENETRE_LINUX" "$FENETRE_WINDOWS"' <<<"$lignes" |
    grep -E 'exit 1' | head -1 | cut -d: -f1)
  empreinte=$(grep -E 'VANGUARD_FENETRE_SHA256_(LINUX|WINDOWS)=' <<<"$lignes" | head -1 | cut -d: -f1)
  [[ -n $garde ]] || { echo "caisses-fenetre.sh --programmes n'est pas appelé (ou son échec n'arrête rien)"; return 1; }
  [[ -n $empreinte ]] || { echo "empreinte de la fenêtre introuvable"; return 1; }
  ((derniere < garde && garde < empreinte)) ||
    { echo "garde ligne $garde : pas entre la compilation (ligne $derniere) et l'empreinte (ligne $empreinte)"; return 1; }
}
r=$(recette outils/compiler-version.sh) && ok "compiler-version.sh : une cible par appel, garde des octets avant l'empreinte" ||
  ko "compiler-version.sh : $r"
# Les recettes abîmées, chacune vérifiée changée avant d'être jugée.
abimee() { # nom, puis le programme sed
  sed "$2" outils/compiler-version.sh >"$T/$1.sh"
  if cmp -s outils/compiler-version.sh "$T/$1.sh"; then
    ko "recette « $1 » : l'abîmer n'a rien changé (recette réécrite ? adapter cet essai)"
  elif r=$(recette "$T/$1.sh"); then
    ko "recette « $1 » acceptée"
  else
    ok "recette « $1 » refusée : $r"
  fi
}
abimee cibles-jointes "s/--target \"\$cible\"\$/--target $LINUX --target $WINDOWS/"
abimee sans-garde '/caisses-fenetre.sh --programmes/,/exit 1; }/d'
abimee garde-apres "/caisses-fenetre.sh --programmes/,/exit 1; }/d; \$a\\
bash outils/caisses-fenetre.sh --programmes \"\$FENETRE_LINUX\" \"\$FENETRE_WINDOWS\" || exit 1"

echo "2. --programmes : chaque caisse des octets dans l'arbre de sa cible"
arbre $LINUX "alpha 1.2.0" "beta 0.3.1" "gamma 4.0.0"
arbre $WINDOWS "alpha 1.2.0" "delta 2.0.0"
programme "$T/fenetre" alpha-1.2.0 beta-0.3.1
programme "$T/fenetre.exe" alpha-1.2.0 delta-2.0.0
lance outils/caisses-fenetre.sh --programmes "$T/fenetre" "$T/fenetre.exe"
((CODE == 0)) && ok "tout dans l'arbre : code 0" || ko "tout dans l'arbre : code $CODE ($SORTIE)"
programme "$T/fenetre" alpha-1.2.0 zvariant-5.15.1
lance outils/caisses-fenetre.sh --programmes "$T/fenetre" "$T/fenetre.exe"
((CODE == 1)) && [[ $SORTIE == *"zvariant 5.15.1"* ]] && ok "caisse hors de l'arbre (zvariant) : code 1, nommée" ||
  ko "caisse hors de l'arbre : code $CODE ($SORTIE)"
programme "$T/fenetre"
lance outils/caisses-fenetre.sh --programmes "$T/fenetre" "$T/fenetre.exe"
((CODE == 2)) && [[ $SORTIE == *"rien n'est conclu"* ]] && ok "aucune caisse lisible : code 2, rien n'est conclu" ||
  ko "aucune caisse lisible : code $CODE ($SORTIE)"
lance outils/caisses-fenetre.sh --programmes "$T/absent" "$T/fenetre.exe"
((CODE == 2)) && ok "programme absent : code 2" || ko "programme absent : code $CODE ($SORTIE)"
programme "$T/fenetre" alpha-1.2.0
rm "$T/arbres/$WINDOWS.txt"
lance outils/caisses-fenetre.sh --programmes "$T/fenetre" "$T/fenetre.exe"
((CODE == 2)) && ok "cargo tree en échec : code 2" || ko "cargo tree en échec : code $CODE ($SORTIE)"

echo "3. Le cliquet : l'arbre de chaque cible comparé à sa liste de référence"
for c in $LINUX $WINDOWS; do
  REF=outils/caisses-fenetre/$c.txt
  if [[ ! -s $REF ]]; then
    ko "$REF absente ou vide"
    continue
  fi
  grep -v '^#' "$REF" >"$T/ref-$c.txt"
done
if [[ -s $T/ref-$LINUX.txt && -s $T/ref-$WINDOWS.txt ]]; then
  remet() { cp "$T/ref-$LINUX.txt" "$T/arbres/$LINUX.txt" && cp "$T/ref-$WINDOWS.txt" "$T/arbres/$WINDOWS.txt"; }
  remet
  lance outils/caisses-fenetre.sh
  ((CODE == 0)) && ok "arbres égaux aux listes : code 0" || ko "arbres égaux aux listes : code $CODE ($SORTIE)"
  # Une caisse remplacée par une autre : le nombre ne change pas.
  premiere=$(head -1 "$T/ref-$LINUX.txt")
  { echo "caisse-inventee 9.9.9"; tail -n +2 "$T/ref-$LINUX.txt"; } >"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"caisse-inventee 9.9.9"* && $SORTIE == *"$premiere"* ]] &&
    ok "caisse remplacée à nombre égal : code 1, les deux montrées" || ko "caisse remplacée : code $CODE ($SORTIE)"
  remet && echo "caisse-inventee 9.9.9" >>"$T/arbres/$WINDOWS.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"caisse-inventee 9.9.9"* ]] && ok "une caisse de plus : code 1, montrée" ||
    ko "une caisse de plus : code $CODE ($SORTIE)"
  remet && tail -n +2 "$T/ref-$WINDOWS.txt" >"$T/arbres/$WINDOWS.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"$(head -1 "$T/ref-$WINDOWS.txt")"* ]] && ok "une caisse de moins : code 1, montrée" ||
    ko "une caisse de moins : code $CODE ($SORTIE)"
  remet && echo "zbus 5.15.0" >>"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"retirées revenues"*zbus* ]] && ok "caisse retirée revenue (zbus) : code 1" ||
    ko "caisse retirée revenue : code $CODE ($SORTIE)"
  # Même nom, même version, autre source (relecture du 12 nov. 2026) : un [patch.crates-io] vers une copie locale ou
  # un dépôt git. cargo deny et cargo vet passaient, et la liste, sans la source, aussi.
  remet && { echo "$premiere (/srv/copie-inventee/caisse)"; tail -n +2 "$T/ref-$LINUX.txt"; } >"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"autre source que crates.io"*"$premiere (chemin local)"* &&
    $SORTIE != *copie-inventee* ]] && ok "même caisse par un chemin local : code 1, dite, sans le chemin" ||
    ko "même caisse par un chemin local : code $CODE ($SORTIE)"
  remet && { echo "$premiere (https://example.com/depot-invente#0123abcd)"; tail -n +2 "$T/ref-$LINUX.txt"; } \
    >"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"$premiere (autre source)"* && $SORTIE != *example.com* ]] &&
    ok "même caisse par un dépôt git : code 1, dite" || ko "même caisse par un dépôt git : code $CODE ($SORTIE)"
  # Ce que cargo tree ajoute sans changer la source : « (proc-macro) », « (*) » (déjà montrée plus haut).
  remet && { echo "$premiere (proc-macro) (*)"; echo "$premiere (*)"; echo "$premiere (proc-macro)"
    tail -n +2 "$T/ref-$LINUX.txt"; } >"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 0)) && ok "(proc-macro) et (*) : la même caisse de crates.io, code 0" ||
    ko "(proc-macro) et (*) : code $CODE ($SORTIE)"
  remet && { echo "$premiere [forme-inventee]"; tail -n +2 "$T/ref-$LINUX.txt"; } >"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 2)) && [[ $SORTIE == *"forme inconnue"* ]] && ok "ligne de cargo tree d'une forme inconnue : code 2" ||
    ko "ligne d'une forme inconnue : code $CODE ($SORTIE)"
  remet && rm "$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 2)) && ok "cargo tree en échec : code 2" || ko "cargo tree en échec : code $CODE ($SORTIE)"
fi

echo "4. failles-programmes.sh --fenetre : zbus et zvariant écartés seulement s'ils ne sont pas dans les octets"
arbre $LINUX "alpha 1.2.0" "beta 0.3.1"
arbre $WINDOWS "alpha 1.2.0" "delta 2.0.0"
programme "$T/fenetre" alpha-1.2.0 zvariant-5.15.1
programme "$T/fenetre.exe" alpha-1.2.0 delta-2.0.0
lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
((CODE != 0)) && [[ $SORTIE == *zvariant*RUSTSEC-2026-0370* && $SORTIE != *"✔"* ]] &&
  ok "zvariant dans les octets : RUSTSEC-2026-0370 pas écarté, refusé (code $CODE)" ||
  ko "zvariant dans les octets : code $CODE ($SORTIE)"
# zbus lu, zvariant non lu (relecture du 12 nov. 2026) : zbus ne se compile pas sans zvariant, et une lecture des
# octets qui ne voit pas zvariant ne prouve pas qu'il manque. Toute caisse retirée de la fenêtre lue dans les octets
# refuse.
programme "$T/fenetre" alpha-1.2.0 zbus-5.19.0 accesskit_unix-0.24.1
lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
((CODE != 0)) && [[ $SORTIE == *"zbus 5.19.0"*RUSTSEC-2026-0370* && $SORTIE != *"✔"* ]] &&
  ok "zbus dans les octets sans zvariant : avis pas écartés, refusé (code $CODE)" ||
  ko "zbus dans les octets sans zvariant : code $CODE ($SORTIE)"
programme "$T/fenetre"
lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
((CODE != 0)) && [[ $SORTIE == *"non vérifié"* && $SORTIE != *"✔"* ]] &&
  ok "rien de lisible dans les octets : « non vérifié », code $CODE" || ko "rien de lisible : code $CODE ($SORTIE)"
rm -f "$T/audit-lance"
programme "$T/fenetre" alpha-1.2.0 beta-0.3.1
lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
((CODE == 0)) && [[ -e $T/audit-lance && $SORTIE == *"✔"* ]] && ok "programme sain : audité, code 0" ||
  ko "programme sain : code $CODE ($SORTIE)"

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "Caisses de la fenêtre : recette, octets, listes et failles, tout refuse ce qu'il doit."
