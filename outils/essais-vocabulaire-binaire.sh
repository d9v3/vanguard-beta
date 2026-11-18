#!/usr/bin/env bash
# Essais de outils/vocabulaire-binaire.py (le contrôle croisé V1 du vocabulaire de la porte MCP), sur de faux programmes
# et un petit programme compilé ici, dans un dossier jetable : rien du vrai programme n'est lu.
#   1. Chaque morceau dans un des programmes : code 0 ; un morceau dans le seul programme Windows suffit (union).
#   2. Un morceau dans aucun programme : code 1, le morceau nommé avec le fichier source qui l'écrit ; un morceau qui
#      ne se trouve que dans le bloc du vocabulaire lui-même (le seul endroit où une ruse le met) : absent aussi.
#   3. Un morceau qui ne se trouve que dans une donnée effacée (--donnees : règles, fabricants.rs) : absent.
#   4. Rien n'est conclu (code 2, jamais un vert) : vocabulaire introuvable dans un programme, présent deux fois,
#      différent d'un programme à l'autre, deux candidats dans le même programme, mal formé (pas trié, ligne vide),
#      donnée introuvable, fichier illisible.
#   5. Un vrai programme compilé comme la publication (rustc, opt-level 3, LTO, une unité, symboles retirés) : le
#      texte d'une fonction jamais appelée et le nom d'une variable lue par env! n'y sont pas (absents nommés) ; le
#      texte vivant y est. C'est ce que le contrôle attrape d'une ruse : un texte que rustc ne garde pas.
#   6. Branché dans outils/compiler-version.sh avant l'écriture du repère (le bloc lu tel quel, l'outil remplacé par un
#      faux) : un refus arrête le script, un vert le laisse continuer avec les deux programmes et chaque OUT_DIR.
# Lancé par outils/verifier.sh (étape « vocabulaire-binaire ») ; code 77 (sauté) sans rustc pour le cas 5.
#   outils/essais-vocabulaire-binaire.sh
set -uo pipefail
RACINE=$(cd "$(dirname "$0")/.." && pwd)
OUTIL=$RACINE/outils/vocabulaire-binaire.py
T=$(mktemp -d "${TMPDIR:-/tmp}/essais-vocabulaire.XXXXXX")
trap 'rm -rf "$T"' EXIT
ECHECS=0
SAUTE=""
ok() { echo "  ✔ $*"; }
ko() { echo "  ✖ $*"; ECHECS=$((ECHECS + 1)); }

# Un faux programme : du bruit, le vocabulaire donné (s'il y en a un), puis les octets donnés (« @fichier » : ce
# fichier, octet pour octet, fin de ligne comprise).
programme() { # sortie vocabulaire|- octets|@fichier…
  local sortie=$1 voc=$2 x
  shift 2
  {
    head -c 4096 /dev/zero | tr '\0' 'x'
    [ "$voc" = - ] || cat "$voc"
    for x in "$@"; do
      if [[ $x == @* ]]; then cat "${x#@}"; else printf '%s' "$x"; fi
    done
  } >"$sortie"
}

# Lance l'outil ; le code dans $CODE, la sortie (stdout et stderr) dans $T/sortie.
lancer() {
  python3 -I "$OUTIL" "$@" >"$T/sortie" 2>&1
  CODE=$?
}

attendre() { # nom code-attendu [motif dans la sortie]…
  local nom=$1 attendu=$2
  shift 2
  if [ "$CODE" != "$attendu" ]; then
    ko "$nom : code $CODE, $attendu attendu ($(tr '\n' ' ' <"$T/sortie" | cut -c1-300))"
    return
  fi
  local motif
  for motif in "$@"; do
    grep -qF -- "$motif" "$T/sortie" || { ko "$nom : « $motif » absent de la sortie ($(tr '\n' ' ' <"$T/sortie" | cut -c1-300))"; return; }
  done
  ok "$nom"
}

mkdir -p "$T/src/porte"
printf 'alerte\nbloqué\npare-feu\n' >"$T/voc.txt"
printf 'fn a() { tr!("Pare-feu bloqué", "x"); }\n' >"$T/src/porte/a.rs"
printf 'fn b() { tr!("alerte", "x"); }\n' >"$T/src/b.rs"

echo "1. Tout présent, Linux et Windows ensemble"
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…bloqué…"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "un programme qui porte chaque morceau" 0 "3 morceaux"
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…"
programme "$T/windows" "$T/voc.txt" "…bloqué…"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux" "$T/windows"
attendre "un morceau dans le seul programme Windows" 0
# Windows aujourd'hui : la porte n'y est pas servie, rustc en retire le vocabulaire ; ses textes comptent quand même.
programme "$T/windows" - "…bloqué…"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux" "$T/windows"
attendre "un programme sans la porte à côté d'un qui la porte" 0 "sans la porte : $T/windows"

echo "2. Un morceau absent, nommé"
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…"
programme "$T/windows" "$T/voc.txt" "…alerte…"
lancer --sources "$T/src" --vocabulaire "$T/voc.txt" -- "$T/linux" "$T/windows"
attendre "« bloqué » dans aucun programme" 1 "« bloqué »" "$T/src/porte/a.rs" "1 morceau(x) sur 3"
if grep -qF "« alerte »" "$T/sortie"; then ko "un morceau présent nommé absent"; else ok "seul l'absent est nommé"; fi
# Le seul « bloqué » est celui du bloc : effacé, il ne compte pas.
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…bloqu"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "un morceau coupé ne compte pas" 1 "« bloqué »"

echo "3. Un morceau qui n'est que dans une donnée"
printf 'rule r { strings: \x24a = "bloqué" }\n' >"$T/regles.yara"
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…" "@$T/regles.yara"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "sans --donnees, la règle le porte" 0
lancer --donnees "$T/regles.yara" --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "une règle effacée ne le porte plus" 1 "« bloqué »"
# fabricants.rs : la chaîne NOMS, relue de sa forme {:?} (échappements compris).
printf '// x\npub static NOMS: &str = "Bloqué \\"Cie\\" pare\\u{2d}feu\\\\Sàrl";\npub static DEBUTS: [u32; 1] = [0];\n' \
  >"$T/fabricants.rs"
programme "$T/linux" "$T/voc.txt" "…alerte…bloqué…" 'Bloqué "Cie" pare-feu\Sàrl'
lancer --donnees "$T/fabricants.rs" --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "les noms des fabricants effacés" 1 "« pare-feu »"
mkdir -p "$T/vide"
printf 'pub static AUTRE: &str = "x";\n' >"$T/vide/fabricants.rs"
lancer --donnees "$T/vide/fabricants.rs" --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "un fabricants.rs sans NOMS" 2 "NOMS"
# --a-cote : la donnée prise dans le dossier du vocabulaire porté, jamais dans celui d'un autre candidat.
mkdir -p "$T/out1" "$T/out2"
cp "$T/voc.txt" "$T/out1/vocabulaire.txt"
cp "$T/regles.yara" "$T/out1/regles.yara"
printf 'alerte\nzone\n' >"$T/out2/vocabulaire.txt"
printf 'autre\n' >"$T/out2/regles.yara"
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…" "@$T/regles.yara"
lancer --a-cote regles.yara --vocabulaire "$T/out2/vocabulaire.txt" --vocabulaire "$T/out1/vocabulaire.txt" -- "$T/linux"
attendre "--a-cote prend la donnée à côté du vocabulaire porté" 1 "« bloqué »"
lancer --a-cote ../out1/regles.yara --vocabulaire "$T/out1/vocabulaire.txt" -- "$T/linux"
attendre "--a-cote refuse un chemin" 2 "un nom de fichier"

echo "4. Rien de conclu"
programme "$T/linux" - "…alerte…pare-feu…bloqué…"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "pas de vocabulaire dans le programme" 2 "aucun des programmes ne porte"
programme "$T/windows" - "…alerte…pare-feu…bloqué…"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux" "$T/windows"
attendre "aucun programme ne porte le vocabulaire" 2 "aucun des programmes ne porte"
programme "$T/linux" "$T/voc.txt" "…" "@$T/voc.txt" "alerte pare-feu bloqué"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "le vocabulaire deux fois" 2 "2 fois"
printf 'alerte\nbloqué\nzone\n' >"$T/voc2.txt"
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…bloqué…"
programme "$T/windows" "$T/voc2.txt" "…alerte…pare-feu…bloqué…zone"
lancer --vocabulaire "$T/voc.txt" --vocabulaire "$T/voc2.txt" -- "$T/linux" "$T/windows"
attendre "un vocabulaire différent par programme" 2 "un autre vocabulaire"
programme "$T/linux" "$T/voc.txt" "…" "@$T/voc2.txt"
lancer --vocabulaire "$T/voc.txt" --vocabulaire "$T/voc2.txt" -- "$T/linux"
attendre "deux candidats dans un programme" 2 "2 des vocabulaires"
lancer --vocabulaire "$T/voc.txt" --vocabulaire "$T/manque.txt" -- "$T/linux"
attendre "un candidat illisible" 2 "illisible"
for mal in 'bloqué\nalerte\n' 'alerte\n\nbloqué\n' 'alerte\nalerte\n' 'alerte' 'une ligne\n'; do
  printf '%b' "$mal" >"$T/mal.txt"
  programme "$T/linux" "$T/mal.txt" "…"
  lancer --vocabulaire "$T/mal.txt" -- "$T/linux"
  attendre "vocabulaire mal formé ($(printf '%s' "$mal" | tr '\n' '|'))" 2 "pas la forme de build.rs"
done
programme "$T/linux" "$T/voc.txt" "…alerte…pare-feu…bloqué…"
lancer --donnees "$T/regles.yara" --vocabulaire "$T/voc.txt" -- "$T/linux"
attendre "une donnée que le programme n'embarque pas" 2 "introuvable"
lancer --vocabulaire "$T/voc.txt" -- "$T/linux" "$T/manque"
attendre "un programme illisible" 2 "illisible"

echo "5. Un vrai programme compilé comme la publication"
if ! command -v rustc >/dev/null; then
  echo "  rustc absent : cas sauté"
  SAUTE="rustc absent"
else
  mkdir -p "$T/vrai"
  # Les mots sont inventés et longs : rien d'autre dans un programme Rust ne les porte par hasard.
  printf 'motmortinvente\nmotvivantinvente\nNOM_INVENTE_VOC\n' | LC_ALL=C sort >"$T/vrai/vocabulaire.txt"
  cat >"$T/vrai/main.rs" <<'RUST'
const BRUT: &str = include_str!("vocabulaire.txt");
#[allow(dead_code)]
fn jamais() -> &'static str {
    "motmortinvente"
}
fn main() {
    let n = std::env::args().count();
    let texte = if n > 9 { "motvivantinvente" } else { "court" };
    println!("{} {} {}", std::hint::black_box(BRUT).lines().count(), texte, env!("NOM_INVENTE_VOC"));
}
RUST
  if NOM_INVENTE_VOC=valeur nice -n 19 rustc --edition 2024 -C opt-level=3 -C lto=fat -C codegen-units=1 \
    -C strip=symbols -o "$T/vrai/programme" "$T/vrai/main.rs" >"$T/rustc.log" 2>&1; then
    lancer --sources "$T/vrai" --vocabulaire "$T/vrai/vocabulaire.txt" -- "$T/vrai/programme"
    attendre "le code mort et le nom d'env! sont absents" 1 "« motmortinvente »" "« NOM_INVENTE_VOC »" \
      "2 morceau(x) sur 3"
    if grep -qF "« motvivantinvente »" "$T/sortie"; then
      ko "le texte vivant compté absent"
    else
      ok "le texte vivant est présent"
    fi
  else
    ko "rustc a échoué : $(tail -3 "$T/rustc.log" | tr '\n' ' ')"
  fi
fi

echo "6. Branché dans outils/compiler-version.sh, avant le repère"
# Le bloc du contrôle, lu tel quel dans compiler-version.sh, lancé avec l'outil remplacé par un faux : son refus
# arrête le script (aucun repère après), son vert le laisse continuer ; chaque OUT_DIR des deux cibles est candidat.
bloc=$(awk '/^VOCABULAIRES=\(\)$/,/^# Relu après/' "$RACINE/outils/compiler-version.sh")
debut=$(grep -n '^VOCABULAIRES=()$' "$RACINE/outils/compiler-version.sh" | cut -d: -f1)
# shellcheck disable=SC2016 # la ligne du repère, lue telle quelle : $COMMIT n'est pas à remplacer ici
repere=$(grep -nxF '  echo "commit $COMMIT"' "$RACINE/outils/compiler-version.sh" | cut -d: -f1)
mkdir -p "$T/cibles/x86_64-unknown-linux-musl/release/build/vanguard-a/out" \
  "$T/cibles/x86_64-pc-windows-gnu/release/build/vanguard-b/out"
touch "$T/cibles/x86_64-unknown-linux-musl/release/build/vanguard-a/out/vocabulaire.txt" \
  "$T/cibles/x86_64-pc-windows-gnu/release/build/vanguard-b/out/vocabulaire.txt"
bloc_lance() { # code de l'outil
  CIBLES=$T/cibles bash -c "python3() { echo \"\$*\" >'$T/appel'; return $1; }
$bloc
echo apres" >"$T/sortie" 2>&1
  CODE=$?
}
if [ -z "$bloc" ] || [ -z "$debut" ] || [ -z "$repere" ] || [ "$debut" -ge "$repere" ]; then
  ko "le contrôle n'est pas dans compiler-version.sh avant l'écriture du repère"
else
  bloc_lance 1
  if [ "$CODE" = 1 ] && ! grep -qx apres "$T/sortie" && grep -qF "aucun repère" "$T/sortie"; then
    ok "un absent arrête compiler-version.sh avant le repère"
  else
    ko "un absent n'arrête pas compiler-version.sh (code $CODE) : $(tr '\n' ' ' <"$T/sortie" | cut -c1-200)"
  fi
  bloc_lance 0
  if [ "$CODE" = 0 ] && grep -qx apres "$T/sortie" &&
    grep -qF -- "--vocabulaire $T/cibles/x86_64-pc-windows-gnu/release/build/vanguard-b/out/vocabulaire.txt" "$T/appel" &&
    grep -qF -- "--vocabulaire $T/cibles/x86_64-unknown-linux-musl/release/build/vanguard-a/out/vocabulaire.txt" "$T/appel" &&
    grep -qE -- '-- [^ ]+/x86_64-unknown-linux-musl/release/vanguard [^ ]+/x86_64-pc-windows-gnu/release/vanguard\.exe$' "$T/appel"; then
    ok "un vert laisse continuer, les deux programmes et chaque OUT_DIR donnés"
  else
    ko "le contrôle de compiler-version.sh n'est pas appelé comme il faut (code $CODE) : $(cat "$T/appel" 2>/dev/null)"
  fi
fi

if [ "$ECHECS" -gt 0 ]; then
  echo "✖ essais du vocabulaire des programmes : $ECHECS échec(s)"
  exit 1
fi
if [ -n "$SAUTE" ]; then
  echo "essais du vocabulaire des programmes : sautés en partie ($SAUTE)"
  exit 77
fi
echo "✔ essais du vocabulaire des programmes : tout passe"
