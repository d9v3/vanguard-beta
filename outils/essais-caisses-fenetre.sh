#!/usr/bin/env bash
# Essais de la garde des caisses de la fenêtre (outils/caisses-fenetre.sh) et de sa place dans la recette des
# programmes publiés (outils/compiler-version.sh), avec une cale cargo dans le PATH, de faux programmes et de faux
# arbres aux valeurs inventées : rien n'est compilé, rien de l'ordinateur n'est lu.
#   1. La recette : la fenêtre compilée une cible par appel de cargo (jamais deux --target dans un même appel :
#      compilées ensemble, les cibles partagent leurs options, et la fenêtre Linux emportait zbus et zvariant), puis
#      caisses-fenetre.sh --programmes sur les deux fenêtres, avant que leur empreinte soit calculée pour être gravée
#      dans vanguard, son échec arrêtant tout. Trois recettes abîmées (cibles jointes, garde retirée, garde après
#      l'empreinte) sont refusées : le lecteur de la recette refuse pour de vrai. Et caisses-fenetre.sh --vanguard sur
#      les deux vanguard, après leur compilation, avant le repère, son échec arrêtant tout (quatre recettes abîmées).
#   2 bis. --vanguard : la même preuve, cibles musl et Windows, vanguard lui-même ôté de son arbre ; une caisse de
#      Windows seulement dans vanguard Linux → 1 ; cargo tree en échec, un seul programme → 2.
#   2. --programmes : tout dans l'arbre de sa cible → 0 ; une caisse hors de l'arbre, ou d'une autre source que
#      crates.io dans l'arbre (chemin local, source remplacée) → 1 ; rien de lisible dans un programme, programme
#      absent ou cargo tree en échec → 2 (rien n'est conclu, jamais un vert).
#   3. Sans argument (le cliquet de outils/verifier.sh) : l'arbre de chaque cible est comparé à sa LISTE de référence
#      (outils/caisses-fenetre/<cible>.txt, noms et versions), jamais à un nombre : une caisse remplacée par une autre
#      à nombre égal, une de plus, une de moins, une retirée revenue ou la même caisse d'une autre source que
#      crates.io (chemin local, dépôt git, source remplacée) → 1, la différence montrée ; cargo tree ou cargo metadata
#      en échec, ou une ligne d'une forme inconnue → 2.
#   4. outils/failles-programmes.sh --fenetre n'écarte les avis de zbus et zvariant (HORS_CIBLES) que si aucune des
#      caisses retirées de la fenêtre (RETIREES de caisses-fenetre.sh, HORS_CIBLES comprises) ne se lit dans les
#      octets du programme audité (même lecture que --programmes) : un faux programme qui porte zvariant, ou zbus sans
#      zvariant, est refusé ; un programme où rien ne se lit est « non vérifié », jamais vert ; un programme sain
#      passe (cale cargo-audit à la version de la CI). Et rien n'est audité si une caisse d'une autre source que
#      crates.io est dans l'arbre d'une cible, ou si une caisse lue dans les octets n'est pas dans la liste de la cible
#      du programme (lue dans son en-tête, ELF ou MZ : une fenêtre Linux qui porte une caisse de Windows seulement est
#      refusée ; la liste versionnée fait foi, pas l'arbre du moment) ; en-tête inconnu : non vérifié.
#   5. failles-programmes.sh --depot (Internet simulé par une cale curl) : les avis HORS_CIBLES écartés et dits
#      écartés seulement si cargo tree prouve leur absence des deux cibles ; compilée ou cargo tree en échec : code 1,
#      aucun --ignore posé, « pas écartées ».
#   6. Dans une copie du dépôt (jamais les vraies listes) : --ecrire écrit des arbres sains, mais jamais une autre
#      source ni une retirée ; une autre source inscrite à la main dans la liste reste refusée, sans coche ✔ ; la
#      liste des retirées illisible (--retirees en échec), la liste d'une cible absente ou d'une forme inconnue
#      (« # raison ») rendent failles-programmes.sh --fenetre « non vérifié ».
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
# Ce que la garde propose quand --ecrire accepterait (ronde 2 du 13 nov. 2026, R5 : pas quand il refuse).
VOULU_ECRIRE="Voulu : outils/caisses-fenetre.sh --ecrire"
WINDOWS=x86_64-pc-windows-gnu

# La cale cargo : « cargo tree » et « cargo metadata », l'arbre de chaque cible lu dans $CALE_ARBRES/<cible>.txt
# (« nom version » par ligne) ; absent, les deux échouent. Avec -i <caisse> : la caisse si elle est dans l'arbre, rien
# sinon. metadata : chaque caisse de l'arbre sans source écrite est de crates.io, lue dans le registre de CARGO_HOME,
# sauf celles de $CALE_ARBRES/<cible>.remplacees, lues dans une copie (une source remplacée : cargo garde l'identité
# « crates.io ») ; $CALE_ARBRES/<cible>.metadata-echec le fait échouer. La racine de l'arbre : la fenêtre, ou vanguard
# pour le Cargo.toml du dépôt (--vanguard).
mkdir -p "$T/bin" "$T/arbres"
cat >"$T/bin/cargo" <<'EOF'
#!/usr/bin/env bash
commande=${1:-}
[[ $commande == tree || $commande == metadata ]] || exit 101
cible= inverse= manifeste=
while (($#)); do
  case $1 in
    --target | --filter-platform) cible=$2 && shift ;;
    --manifest-path) manifeste=$2 && shift ;;
    -i) inverse=$2 && shift ;;
  esac
  shift
done
f=$CALE_ARBRES/$cible.txt
[[ -f $f ]] || { echo "error: cale : pas d'arbre pour « $cible »" >&2; exit 101; }
if [[ $commande == metadata ]]; then
  [[ ! -e $CALE_ARBRES/$cible.metadata-echec ]] || { echo "error: cale : metadata en échec" >&2; exit 101; }
  touch "$CALE_ARBRES/$cible.remplacees"
  awk -v maison="$CARGO_HOME" 'NR == FNR { r[$1 " " $2] = 1; next }
    /^#/ || !NF { next }
    { s = "\"registry+https://github.com/rust-lang/crates.io-index\""
      m = maison "/registry/src/index.crates.io-0123456789abcdef/" $1 "-" $2 "/Cargo.toml"
      if ($0 ~ /\(\//) { s = "null"; m = "/depot-invente/copie/Cargo.toml" }
      else if ($0 ~ /\(http/) { s = "\"git+https://example.com/depot-invente\""; m = maison "/git/checkouts/x/Cargo.toml" }
      else if (r[$1 " " $2]) m = "/srv/copie-inventee/" $1 "-" $2 "/Cargo.toml"
      p = p (p ? "," : "") "{\"name\":\"" $1 "\",\"version\":\"" $2 "\",\"source\":" s ",\"manifest_path\":\"" m "\"}" }
    END { print "{\"packages\":[" p "]}" }' "$CALE_ARBRES/$cible.remplacees" "$f"
  exit 0
fi
if [[ -n $inverse ]]; then
  awk -v n="$inverse" '$1 == n { print $1 " v" $2 }' "$f"
  exit 0
fi
if [[ $manifeste == */fenetre/Cargo.toml ]]; then
  echo "vanguard-fenetre v0.1.0 (/depot-invente/fenetre)"
else
  echo "vanguard v0.1.0 (/depot-invente)"
fi
# « nom version [suite] » devient « nom vversion [suite] » : la suite (« (proc-macro) », « (*) », une source autre que
# crates.io) passe telle quelle, comme cargo tree l'écrit.
awk '!/^#/ && NF { $2 = "v" $2; print }' "$f"
EOF
# La cale cargo-audit, à la version qu'épingle la CI (failles-programmes.sh l'exige) : elle dit avoir lu la liste
# de chaque programme, sans faille, et note ses arguments (un par ligne) dans $T/audit-args.
AUDIT_CI=$(sed -n 's/.*cargo-audit@\([0-9][0-9.]*\).*/\1/p' .github/workflows/ci.yml | head -1)
cat >"$T/bin/cargo-audit" <<EOF
#!/usr/bin/env bash
[[ \${1:-} == --version ]] && { echo "cargo-audit $AUDIT_CI"; exit 0; }
touch "$T/audit-lance"
printf '%s\n' "\$@" >>"$T/audit-args"
for p in "\$@"; do
  [[ -f \$p ]] && echo "Found 'cargo auditable' data in \$p (3 dependencies)"
done
exit 0
EOF
chmod +x "$T/bin/cargo" "$T/bin/cargo-audit"
export CALE_ARBRES=$T/arbres PATH="$T/bin:$PATH" VANGUARD_HORS_LIGNE=1 CARGO_HOME=/srv/cargo-invente

# Un faux programme : un en-tête (MZ pour un .exe, ELF sinon), des octets quelconques, puis les chemins de panique des
# caisses données (« nom-version »).
programme() {
  local f=$1 c
  shift
  local entete=$'\177ELF'
  [[ $f == *.exe ]] && entete=MZ
  printf '%s\0\0octets-inventes\0' "$entete" >"$f"
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
# Vanguard (décision (a), ronde Fable du 13 nov. 2026) : la garde de ses octets après sa compilation, avant le repère,
# et son échec arrête tout.
recette_vanguard() {
  local lignes compile garde repere
  lignes=$(logiques "$1")
  compile=$(grep -E 'cargo +(zig)?build' <<<"$lignes" | grep -vF fenetre/Cargo.toml | tail -1 | cut -d: -f1)
  local debut='^[0-9]+: bash outils/caisses-fenetre\.sh --vanguard '
  debut+='"\$CIBLES/x86_64-unknown-linux-musl/release/vanguard" '
  local fin='"\$CIBLES/x86_64-pc-windows-gnu/release/vanguard\.exe" \|\| \{.*exit 1; \}$'
  garde=$(grep -E "$debut$fin" <<<"$lignes" | head -1 | cut -d: -f1)
  repere=$(grep -F 'echo "commit $COMMIT"' <<<"$lignes" | head -1 | cut -d: -f1)
  [[ -n $compile && -n $repere ]] || { echo "compilation de vanguard ou repère introuvable"; return 1; }
  [[ -n $garde ]] || { echo "caisses-fenetre.sh --vanguard n'est pas appelé (ou son échec n'arrête rien)"; return 1; }
  ((compile < garde && garde < repere)) ||
    { echo "garde ligne $garde : pas entre la compilation (ligne $compile) et le repère (ligne $repere)"; return 1; }
}
r=$(recette_vanguard outils/compiler-version.sh) &&
  ok "compiler-version.sh : garde des octets de vanguard après sa compilation, avant le repère" ||
  ko "compiler-version.sh, vanguard : $r"
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
abimee_v() { # nom, puis le programme sed
  sed "$2" outils/compiler-version.sh >"$T/$1.sh"
  if cmp -s outils/compiler-version.sh "$T/$1.sh"; then
    ko "recette « $1 » : l'abîmer n'a rien changé (recette réécrite ? adapter cet essai)"
  elif r=$(recette_vanguard "$T/$1.sh"); then
    ko "recette « $1 » acceptée"
  else
    ok "recette « $1 » refusée : $r"
  fi
}
abimee_v vanguard-sans-garde '/caisses-fenetre.sh --vanguard/,/exit 1; }/d'
abimee_v vanguard-garde-sans-arret '/caisses-fenetre.sh --vanguard/,/exit 1; }/s/exit 1; }/true; }/'
abimee_v vanguard-sans-bash 's#^bash outils/caisses-fenetre.sh --vanguard#true outils/caisses-fenetre.sh --vanguard#'
abimee_v vanguard-garde-apres "/caisses-fenetre.sh --vanguard/,/exit 1; }/d; \$a\\
bash outils/caisses-fenetre.sh --vanguard \"\$CIBLES/x86_64-unknown-linux-musl/release/vanguard\" \\\\\\
\"\$CIBLES/x86_64-pc-windows-gnu/release/vanguard.exe\" || { exit 1; }"

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
# Une autre source refusée aussi par --programmes (ronde 2 du 13 nov. 2026 : seul le mode sans argument la refusait).
# Une caisse par un chemin local ne laisse aucun chemin sous registry/src : les octets ne la montrent pas.
arbre $LINUX "alpha 1.2.0" "beta 0.3.1 (/srv/copie-inventee/beta)" "gamma 4.0.0"
programme "$T/fenetre" alpha-1.2.0
lance outils/caisses-fenetre.sh --programmes "$T/fenetre" "$T/fenetre.exe"
((CODE == 1)) && [[ $SORTIE == *"autre source que crates.io"*"beta 0.3.1 (chemin local)"* &&
  $SORTIE != *copie-inventee* ]] &&
  ok "une caisse par un chemin local dans l'arbre : code 1, dite, sans le chemin" ||
  ko "une caisse par un chemin local dans l'arbre : code $CODE ($SORTIE)"
arbre $LINUX "alpha 1.2.0" "beta 0.3.1" "gamma 4.0.0"
echo "delta 2.0.0" >"$T/arbres/$WINDOWS.remplacees"
lance outils/caisses-fenetre.sh --programmes "$T/fenetre" "$T/fenetre.exe"
((CODE == 1)) && [[ $SORTIE == *"autre source que crates.io"*"delta 2.0.0 (autre source)"* ]] &&
  ok "une caisse d'une source remplacée dans l'arbre : code 1, dite" ||
  ko "une caisse d'une source remplacée dans l'arbre : code $CODE ($SORTIE)"
rm "$T/arbres/$WINDOWS.remplacees"
lance outils/caisses-fenetre.sh --programmes "$T/absent" "$T/fenetre.exe"
((CODE == 2)) && ok "programme absent : code 2" || ko "programme absent : code $CODE ($SORTIE)"
programme "$T/fenetre" alpha-1.2.0
rm "$T/arbres/$WINDOWS.txt"
lance outils/caisses-fenetre.sh --programmes "$T/fenetre" "$T/fenetre.exe"
((CODE == 2)) && ok "cargo tree en échec : code 2" || ko "cargo tree en échec : code $CODE ($SORTIE)"

echo "2 bis. --vanguard : la même preuve pour vanguard, cibles musl et Windows"
MUSL=x86_64-unknown-linux-musl
arbre $MUSL "alpha 1.2.0" "beta 0.3.1"
arbre $WINDOWS "alpha 1.2.0" "delta 2.0.0"
programme "$T/vanguard" alpha-1.2.0 beta-0.3.1
programme "$T/vanguard.exe" alpha-1.2.0 delta-2.0.0
lance outils/caisses-fenetre.sh --vanguard "$T/vanguard" "$T/vanguard.exe"
((CODE == 0)) && [[ $SORTIE == *"toutes dans l'arbre de $MUSL"* ]] &&
  ok "vanguard, tout dans l'arbre de sa cible (musl, pas celui de la fenêtre) : code 0" ||
  ko "vanguard, tout dans l'arbre : code $CODE ($SORTIE)"
# Une caisse de l'arbre Windows seulement, compilée dans vanguard Linux (options partagées d'un appel joint).
programme "$T/vanguard" alpha-1.2.0 delta-2.0.0
lance outils/caisses-fenetre.sh --vanguard "$T/vanguard" "$T/vanguard.exe"
((CODE == 1)) && [[ $SORTIE == *"delta 2.0.0"* ]] &&
  ok "vanguard Linux avec une caisse de Windows seulement : code 1" ||
  ko "vanguard Linux avec une caisse de Windows seulement : code $CODE ($SORTIE)"
arbre $MUSL "alpha 1.2.0" "beta 0.3.1 (/srv/copie-inventee/beta)"
programme "$T/vanguard" alpha-1.2.0
lance outils/caisses-fenetre.sh --vanguard "$T/vanguard" "$T/vanguard.exe"
((CODE == 1)) && [[ $SORTIE == *"beta 0.3.1 (chemin local)"* && $SORTIE != *"vanguard 0.1.0"* ]] &&
  ok "vanguard, une caisse par un chemin local : code 1 (vanguard lui-même n'est pas compté)" ||
  ko "vanguard, une caisse par un chemin local : code $CODE ($SORTIE)"
rm "$T/arbres/$MUSL.txt"
lance outils/caisses-fenetre.sh --vanguard "$T/vanguard" "$T/vanguard.exe"
((CODE == 2)) && ok "vanguard, cargo tree en échec : code 2" ||
  ko "vanguard, cargo tree en échec : code $CODE ($SORTIE)"
lance outils/caisses-fenetre.sh --vanguard "$T/vanguard"
((CODE == 2)) && ok "vanguard, un seul programme : code 2" || ko "vanguard, un seul programme : code $CODE ($SORTIE)"

echo "3. Le cliquet : l'arbre de chaque cible comparé à sa liste de référence"
for c in $LINUX $WINDOWS; do
  REF=outils/caisses-fenetre/$c.txt
  if [[ ! -s $REF ]]; then
    ko "$REF absente ou vide"
    continue
  fi
  cp "$REF" "$T/ref-$c.txt"
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
  ((CODE == 1)) && [[ $SORTIE == *"caisse-inventee 9.9.9"* && $SORTIE == *"$VOULU_ECRIRE"* ]] &&
    ok "une caisse de plus : code 1, montrée, --ecrire proposé" ||
    ko "une caisse de plus : code $CODE ($SORTIE)"
  remet && tail -n +2 "$T/ref-$WINDOWS.txt" >"$T/arbres/$WINDOWS.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"$(head -1 "$T/ref-$WINDOWS.txt")"* ]] && ok "une caisse de moins : code 1, montrée" ||
    ko "une caisse de moins : code $CODE ($SORTIE)"
  remet && echo "zbus 5.15.0" >>"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"retirées revenues"*zbus* && $SORTIE != *"$VOULU_ECRIRE"* &&
    $SORTIE == *"--ecrire n'écrit jamais"* ]] &&
    ok "caisse retirée revenue (zbus) : code 1, sans proposer --ecrire (qui la refuse)" ||
    ko "caisse retirée revenue : code $CODE ($SORTIE)"
  # Même nom, même version, autre source (relecture du 12 nov. 2026) : un [patch.crates-io] vers une copie locale ou
  # un dépôt git. La copie locale passe cargo deny et cargo vet (le dépôt git, cargo deny le refuse déjà : unknown-git
  # = "deny", essais du 13 nov. 2026), et la liste, sans la source, la laissait passer aussi.
  remet && { echo "$premiere (/srv/copie-inventee/caisse)"; tail -n +2 "$T/ref-$LINUX.txt"; } >"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"autre source que crates.io"*"$premiere (chemin local)"* &&
    $SORTIE != *copie-inventee* && $SORTIE != *"$VOULU_ECRIRE"* ]] &&
    ok "même caisse par un chemin local : code 1, dite, sans le chemin, sans proposer --ecrire" ||
    ko "même caisse par un chemin local : code $CODE ($SORTIE)"
  remet && { echo "$premiere (https://example.com/depot-invente#0123abcd)"; tail -n +2 "$T/ref-$LINUX.txt"; } \
    >"$T/arbres/$LINUX.txt"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"$premiere (autre source)"* && $SORTIE != *example.com* &&
    $SORTIE != *"$VOULU_ECRIRE"* ]] &&
    ok "même caisse par un dépôt git : code 1, dite, sans proposer --ecrire" ||
    ko "même caisse par un dépôt git : code $CODE ($SORTIE)"
  # Une source remplacée ([source.crates-io] replace-with vers un dossier, dans un .cargo/config.toml) : cargo garde
  # l'identité « crates.io », cargo tree n'écrit aucune source, cargo deny ne voit rien (relecture du 12 nov. 2026).
  # La caisse n'est pas lue dans le registre de CARGO_HOME : refusée, sans le chemin.
  remet && echo "$premiere" >"$T/arbres/$LINUX.remplacees"
  lance outils/caisses-fenetre.sh
  ((CODE == 1)) && [[ $SORTIE == *"autre source que crates.io"*"$premiere (autre source)"* &&
    $SORTIE != *copie-inventee* && $SORTIE != *"$VOULU_ECRIRE"* ]] &&
    ok "même caisse par une source remplacée : code 1, dite, sans le chemin, sans proposer --ecrire" ||
    ko "même caisse par une source remplacée : code $CODE ($SORTIE)"
  rm "$T/arbres/$LINUX.remplacees"
  remet && touch "$T/arbres/$WINDOWS.metadata-echec"
  lance outils/caisses-fenetre.sh
  ((CODE == 2)) && [[ $SORTIE == *"rien n'est conclu"* ]] && ok "cargo metadata en échec : code 2" ||
    ko "cargo metadata en échec : code $CODE ($SORTIE)"
  rm "$T/arbres/$WINDOWS.metadata-echec"
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
# Les programmes portent des caisses des vraies listes (la garde compare les octets à
# outils/caisses-fenetre/<cible>.txt), et l'arbre de chaque cible est sa liste.
if [[ -s $T/ref-$LINUX.txt && -s $T/ref-$WINDOWS.txt ]]; then
  remet
  nv() { sed -n "$2p" "$T/ref-$1.txt" | tr ' ' '-'; } # la n-ième caisse d'une liste, « nom-version »
  L1=$(nv $LINUX 1) L2=$(nv $LINUX 2) W1=$(nv $WINDOWS 1) W2=$(nv $WINDOWS 2)
  programme "$T/fenetre.exe" "$W1" "$W2"
  programme "$T/fenetre" "$L1" zvariant-5.15.1
  lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
  ((CODE != 0)) && [[ $SORTIE == *zvariant*RUSTSEC-2026-0370* && $SORTIE != *"dépendances listées"* ]] &&
    ok "zvariant dans les octets : RUSTSEC-2026-0370 pas écarté, refusé (code $CODE)" ||
    ko "zvariant dans les octets : code $CODE ($SORTIE)"
  # zbus lu, zvariant non lu (relecture du 12 nov. 2026) : zbus ne se compile pas sans zvariant, et une lecture des
  # octets qui ne voit pas zvariant ne prouve pas qu'il manque. Toute caisse retirée de la fenêtre lue dans les octets
  # refuse.
  programme "$T/fenetre" "$L1" zbus-5.19.0 accesskit_unix-0.24.1
  lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
  ((CODE != 0)) && [[ $SORTIE == *"zbus 5.19.0"*RUSTSEC-2026-0370* && $SORTIE != *"dépendances listées"* ]] &&
    ok "zbus dans les octets sans zvariant : avis pas écartés, refusé (code $CODE)" ||
    ko "zbus dans les octets sans zvariant : code $CODE ($SORTIE)"
  programme "$T/fenetre"
  lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
  ((CODE != 0)) && [[ $SORTIE == *"non vérifié"* && $SORTIE != *"dépendances listées"* ]] &&
    ok "rien de lisible dans les octets : « non vérifié », code $CODE" || ko "rien de lisible : code $CODE ($SORTIE)"
  rm -f "$T/audit-lance"
  programme "$T/fenetre" "$L1" "$L2"
  lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
  ((CODE == 0)) && [[ -e $T/audit-lance && $SORTIE == *"✔"* ]] && ok "programme sain : audité, code 0" ||
    ko "programme sain : code $CODE ($SORTIE)"
  # Ronde 2 du 13 nov. 2026 : un programme falsifié (chemins des retirées changés) gardait l'avis écarté. Chaque caisse
  # lue dans les octets doit être dans la liste de la cible du programme, lue dans son en-tête.
  refuse() { # nom de l'essai, puis le texte attendu dans la sortie
    rm -f "$T/audit-lance"
    lance outils/failles-programmes.sh --fenetre "$T/fenetre" "$T/fenetre.exe"
    ((CODE != 0)) && [[ ! -e $T/audit-lance && $SORTIE == *"$2"* && $SORTIE != *"dépendances listées"* ]] &&
      ok "$1 : refusé, rien d'audité (code $CODE)" || ko "$1 : code $CODE ($SORTIE)"
  }
  programme "$T/fenetre" "$L1" caisse-inventee-9.9.9
  refuse "une caisse hors de la liste de sa cible dans les octets" "caisse-inventee 9.9.9"
  # Relecture adverse du lot 097 (C1) : la comparaison se fait à la liste versionnée, pas à l'arbre du moment.
  # Partout ailleurs l'arbre de la cale est la liste : comparer à l'arbre restait vert. Ici l'arbre a la caisse de plus.
  echo "caisse-inventee 9.9.9" >>"$T/arbres/$LINUX.txt"
  refuse "une caisse de l'arbre du moment, absente de la liste versionnée" "caisse-inventee 9.9.9"
  remet
  wseule=$(LC_ALL=C comm -13 <(LC_ALL=C sort "$T/ref-$LINUX.txt") <(LC_ALL=C sort "$T/ref-$WINDOWS.txt") | head -1)
  programme "$T/fenetre" "$L1" "${wseule/ /-}"
  refuse "une caisse de Windows seulement dans la fenêtre Linux ($wseule)" "$wseule"
  programme "$T/fenetre" "$L1" "$L2"
  printf 'XX\0/cargo/registry/src/index.crates.io-0123456789abcdef/%s/src/lib.rs\0' "$W1" >"$T/fenetre.exe"
  refuse "un programme ni ELF ni MZ" "rien n'est conclu"
  programme "$T/fenetre.exe" "$W1" "$W2"
  # Ronde 2 du 13 nov. 2026 : une autre source n'était refusée que par le mode sans argument.
  { echo "$(head -1 "$T/ref-$LINUX.txt") (/srv/copie-inventee/caisse)"; tail -n +2 "$T/ref-$LINUX.txt"; } \
    >"$T/arbres/$LINUX.txt"
  refuse "une caisse par un chemin local dans l'arbre" "$(head -1 "$T/ref-$LINUX.txt") (chemin local)"
  remet && head -1 "$T/ref-$WINDOWS.txt" >"$T/arbres/$WINDOWS.remplacees"
  refuse "une caisse d'une source remplacée dans l'arbre" "$(head -1 "$T/ref-$WINDOWS.txt") (autre source)"
  rm "$T/arbres/$WINDOWS.remplacees"
else
  ko "listes de référence illisibles : failles-programmes.sh --fenetre pas essayé"
fi

echo "5. failles-programmes.sh --depot : les avis HORS_CIBLES écartés seulement si cargo tree l'a prouvé"
# Relecture du 12 nov. 2026 (C5) : la preuve en échec, le code était bien 1, mais les --ignore étaient posés quand même
# et la ligne « écartées car compilées par aucune de ses deux cibles » s'affichait. Avec Internet (cale curl) : --depot
# s'arrête sinon (code 77) avant toute preuve.
if [[ -s $T/ref-$LINUX.txt && -s $T/ref-$WINDOWS.txt ]]; then
  mkdir -p "$T/reseau" && printf '#!/bin/sh\nexit 0\n' >"$T/reseau/curl" && chmod +x "$T/reseau/curl"
  depot() { # le texte attendu (ou refusé, « ! texte ») dans la sortie, le code attendu, le nom de l'essai
    rm -f "$T/audit-args"
    SORTIE=$(PATH="$T/reseau:$PATH" env -u VANGUARD_HORS_LIGNE bash outils/failles-programmes.sh --depot 2>&1) &&
      CODE=0 || CODE=$?
  }
  remet
  depot
  ((CODE == 0)) && [[ $SORTIE == *"écartées car compilées par aucune de ses deux cibles"* ]] &&
    grep -qx RUSTSEC-2026-0370 "$T/audit-args" && ok "--depot, preuve faite : avis écartés, code 0" ||
    ko "--depot, preuve faite : code $CODE ($SORTIE)"
  echo "zvariant 5.15.1" >>"$T/arbres/$LINUX.txt"
  depot
  ((CODE == 1)) && [[ $SORTIE == *"zvariant compilée pour $LINUX"* && $SORTIE != *"écartées car"* ]] &&
    ! grep -qx RUSTSEC-2026-0370 "$T/audit-args" && ok "--depot, zvariant compilée : avis pas écartés, code 1" ||
    ko "--depot, zvariant compilée : code $CODE ($SORTIE ; $(paste -sd' ' "$T/audit-args"))"
  remet && rm "$T/arbres/$WINDOWS.txt"
  depot
  ((CODE == 1)) && [[ $SORTIE == *"cargo tree a échoué"* && $SORTIE != *"écartées car"* ]] &&
    ! grep -qE '^RUSTSEC-2026-037[012]$' "$T/audit-args" && ok "--depot, cargo tree en échec : rien d'écarté, code 1" ||
    ko "--depot, cargo tree en échec : code $CODE ($SORTIE ; $(paste -sd' ' "$T/audit-args"))"
  remet
else
  ko "listes de référence illisibles : --depot pas essayé"
fi

echo "6. Dans une copie du dépôt : --ecrire, la coche d'une cible refusée, la liste des retirées illisible"
# Ronde 2 du 13 nov. 2026 : trois mutations laissaient ce banc vert (le refus de --ecrire retiré, une coche ✔ à côté
# d'un ✖, l'échec de --retirees ignoré). Une copie, parce que --ecrire écrit les listes : jamais celles du dépôt.
if [[ -s $T/ref-$LINUX.txt && -s $T/ref-$WINDOWS.txt ]]; then
  D=$T/depot
  mkdir -p "$D/outils/caisses-fenetre" "$D/.github/workflows"
  cp outils/caisses-fenetre.sh outils/failles-programmes.sh outils/exceptions-rustsec.py "$D/outils/"
  cp deny.toml "$D/" && cp .github/workflows/ci.yml "$D/.github/workflows/"
  ecrites() { cp "$T/ref-$LINUX.txt" "$D/outils/caisses-fenetre/$LINUX.txt"
    cp "$T/ref-$WINDOWS.txt" "$D/outils/caisses-fenetre/$WINDOWS.txt"; }
  ecrites && remet
  lance "$D/outils/caisses-fenetre.sh" --ecrire
  ((CODE == 0)) && cmp -s "$T/ref-$LINUX.txt" "$D/outils/caisses-fenetre/$LINUX.txt" &&
    ok "--ecrire sur des arbres sains : code 0, listes écrites" ||
    ko "--ecrire sur des arbres sains : code $CODE ($SORTIE)"
  # Une autre source dans l'arbre : --ecrire ne l'inscrit jamais dans la liste versionnée.
  ecrites && { echo "$premiere (/srv/copie-inventee/caisse)"; tail -n +2 "$T/ref-$LINUX.txt"; } >"$T/arbres/$LINUX.txt"
  lance "$D/outils/caisses-fenetre.sh" --ecrire
  ((CODE == 1)) && [[ $SORTIE == *"$LINUX : caisses d'une autre source"*"liste non écrite"* ]] &&
    cmp -s "$T/ref-$LINUX.txt" "$D/outils/caisses-fenetre/$LINUX.txt" &&
    ! grep -q 'chemin local' "$D/outils/caisses-fenetre/$LINUX.txt" &&
    ok "--ecrire avec une caisse par un chemin local : code 1, liste pas écrite" ||
    ko "--ecrire avec une caisse par un chemin local : code $CODE ($SORTIE)"
  ecrites && remet && echo "zbus 5.15.0" >>"$T/arbres/$WINDOWS.txt"
  lance "$D/outils/caisses-fenetre.sh" --ecrire
  ((CODE == 1)) && [[ $SORTIE == *"retirées revenues, liste non écrite"* ]] &&
    cmp -s "$T/ref-$WINDOWS.txt" "$D/outils/caisses-fenetre/$WINDOWS.txt" &&
    ok "--ecrire avec une retirée revenue : code 1, liste pas écrite" ||
    ko "--ecrire avec une retirée revenue : code $CODE ($SORTIE)"
  # Une autre source inscrite à la main dans la liste ET dans l'arbre : listes égales, mais refusée, sans coche ✔.
  ecrites && remet
  { echo "$premiere (chemin local)"; tail -n +2 "$T/ref-$LINUX.txt"; } >"$D/outils/caisses-fenetre/$LINUX.txt"
  { echo "$premiere (/srv/copie-inventee/caisse)"; tail -n +2 "$T/ref-$LINUX.txt"; } >"$T/arbres/$LINUX.txt"
  lance "$D/outils/caisses-fenetre.sh"
  ((CODE == 1)) && [[ $SORTIE == *"✖ $LINUX : caisses d'une autre source"* && $SORTIE != *"✔ $LINUX"* &&
    $SORTIE == *"✔ $WINDOWS"* ]] && ok "autre source inscrite dans la liste : code 1, aucune coche ✔ pour $LINUX" ||
    ko "autre source inscrite dans la liste : code $CODE ($SORTIE)"
  # Relecture du 12 nov. 2026 (C4) : une ligne « # raison » donnait un rouge sans fin (« - # raison », et --ecrire,
  # proposé, l'effaçait). Une liste n'a pas de commentaire : la raison d'une caisse va dans le message de commit.
  ecrites && remet
  { echo "# raison inventée d'une caisse"; cat "$T/ref-$LINUX.txt"; } >"$D/outils/caisses-fenetre/$LINUX.txt"
  lance "$D/outils/caisses-fenetre.sh"
  ((CODE == 2)) && [[ $SORTIE == *"message de commit"* && $SORTIE != *"$VOULU_ECRIRE"* ]] &&
    ok "une ligne « # raison » dans une liste : code 2, la raison va dans le message de commit" ||
    ko "une ligne « # raison » dans une liste : code $CODE ($SORTIE)"
  { cat "$T/ref-$LINUX.txt"; echo "caisse sans version"; } >"$D/outils/caisses-fenetre/$LINUX.txt"
  lance "$D/outils/caisses-fenetre.sh"
  ((CODE == 2)) && [[ $SORTIE == *"caisse sans version"* ]] &&
    ok "une ligne d'une autre forme dans une liste : code 2" ||
    ko "une ligne d'une autre forme dans une liste : code $CODE ($SORTIE)"
  { cat "$T/ref-$LINUX.txt"; echo "caisse-inventee 1.0.0 (remarque)"; } >"$D/outils/caisses-fenetre/$LINUX.txt"
  lance "$D/outils/caisses-fenetre.sh"
  ((CODE == 2)) && [[ $SORTIE == *"caisse-inventee 1.0.0 (remarque)"* ]] &&
    ok "une parenthèse autre que la source refusée : code 2" ||
    ko "une parenthèse autre que la source refusée : code $CODE ($SORTIE)"
  # La liste des retirées illisible (caisses-fenetre.sh --retirees en échec) : rien ne retombe sur les trois
  # HORS_CIBLES seules ; non vérifié, rien d'audité, même pour un programme sain.
  ecrites && remet
  mv "$D/outils/caisses-fenetre.sh" "$D/outils/caisses-fenetre-vraie.sh"
  cat >"$D/outils/caisses-fenetre.sh" <<'EOF'
#!/usr/bin/env bash
[[ ${1:-} != --retirees ]] || { echo "cale : --retirees en échec" >&2; exit 2; }
exec bash "$(dirname "$0")/caisses-fenetre-vraie.sh" "$@"
EOF
  programme "$T/fenetre" "$L1" "$L2"
  programme "$T/fenetre.exe" "$W1" "$W2"
  rm -f "$T/audit-lance"
  lance "$D/outils/failles-programmes.sh" --fenetre "$T/fenetre" "$T/fenetre.exe"
  ((CODE != 0)) && [[ ! -e $T/audit-lance && $SORTIE == *"liste des caisses retirées illisible"* &&
    $SORTIE != *"dépendances listées"* ]] && ok "--retirees en échec : non vérifié, rien d'audité (code $CODE)" ||
    ko "--retirees en échec : code $CODE ($SORTIE)"
  mv "$D/outils/caisses-fenetre-vraie.sh" "$D/outils/caisses-fenetre.sh"
  rm -f "$T/audit-lance"
  lance "$D/outils/failles-programmes.sh" --fenetre "$T/fenetre" "$T/fenetre.exe"
  ((CODE == 0)) && [[ -e $T/audit-lance ]] && ok "la même copie, --retirees lisible : audité, code 0" ||
    ko "la même copie, --retirees lisible : code $CODE ($SORTIE)"
  # Relecture adverse du lot 097 (C2) : la liste de la cible absente, ou d'une forme inconnue (« # raison »), n'était
  # essayée que dans le mode sans argument. failles --fenetre (par --publies) : non vérifié, rien d'audité.
  sans_liste() { # nom de l'essai
    rm -f "$T/audit-lance"
    lance "$D/outils/failles-programmes.sh" --fenetre "$T/fenetre" "$T/fenetre.exe"
    ((CODE != 0)) && [[ ! -e $T/audit-lance && $SORTIE == *"caisses des programmes non vérifiées"* &&
      $SORTIE != *"dépendances listées"* ]] && ok "$1 : non vérifié, rien d'audité (code $CODE)" ||
      ko "$1 : code $CODE ($SORTIE)"
  }
  rm "$D/outils/caisses-fenetre/$LINUX.txt"
  sans_liste "failles --fenetre, liste de la cible absente"
  { echo "# raison inventée d'une caisse"; cat "$T/ref-$LINUX.txt"; } >"$D/outils/caisses-fenetre/$LINUX.txt"
  sans_liste "failles --fenetre, une ligne « # raison » dans la liste de la cible"
  ecrites
else
  ko "listes de référence illisibles : --ecrire pas essayé"
fi

((ECHECS == 0)) || { echo "$ECHECS essai(s) en échec."; exit 1; }
echo "Caisses de la fenêtre : recette, octets, listes et failles, tout refuse ce qu'il doit."
