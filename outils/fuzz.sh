#!/usr/bin/env bash
# Fuzzing des lecteurs de données venues d'ailleurs (cargo-fuzz, libFuzzer, chaîne nightly) : le banc de fuzz/, hors
# de la compilation de Vanguard. outils/verifier.sh le compile et passe quelques secondes sur chaque cible à chaque
# vérification (un module renommé dans src/ casse une cible, et cela se voit tout de suite) ; la CI y passe cinq
# minutes par cible chaque nuit (.github/workflows/ci.yml, travail « fuzzing ») ; à la main, après avoir touché à un
# lecteur, ou une nuit entière. Le corpus (ce que le fuzzer a appris) et les plantages restent hors du dépôt, dans
# ~/.cache/vanguard-dev/fuzz/ (VANGUARD_FUZZ pour un autre dossier) ; les graines de départ, aux valeurs inventées,
# sont dans fuzz/graines/.
#   outils/fuzz.sh                  toutes les cibles, 60 s chacune
#   outils/fuzz.sh igd              une cible
#   outils/fuzz.sh tout 600         toutes, 10 min chacune
# Sans cargo-fuzz ou sans la chaîne nightly : rien n'est lancé, code 77 (« sautée » pour verifier.sh).
# Prérequis : rustup toolchain install nightly --profile minimal ; cargo install --locked cargo-fuzz.
# Un plantage : corriger le module, ajouter un test de non-régression avec la donnée trouvée (le fichier de
# plantages/<cible>/), puis relancer la cible.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

# Les cibles sont celles de fuzz/Cargo.toml (chaque [[bin]] après le paquet) : une seule liste, une cible ajoutée
# là est passée ici sans rien recopier.
mapfile -t CIBLES < <(sed -n 's/^name = "\(.*\)"$/\1/p' fuzz/Cargo.toml | tail -n +2)
# Aucune cible lue (fichier absent, forme changée) : « Aucun plantage » ne voudrait rien dire, rien n'aurait tourné.
((${#CIBLES[@]})) || { echo "✖ aucune cible lue dans fuzz/Cargo.toml : rien à fuzzer"; exit 1; }
QUOI=${1:-tout}
DUREE=${2:-60}
FUZZ=${VANGUARD_FUZZ:-$HOME/.cache/vanguard-dev/fuzz}
# Les programmes de fuzzing se compilent dans le target/ de CET arbre, jamais dans un dossier commun : deux worktrees
# qui fuzzent en même temps s'écraseraient leurs binaires, et l'un essaierait le code de l'autre (faux plantage, ou
# pire, faux « aucun plantage »). Le corpus et les plantages, eux, restent communs à tous les arbres.
CIBLE_FUZZ=$PWD/target/fuzz

usage() {
  # "${CIBLES[*]}" joint les cibles par le premier caractère d'IFS.
  local IFS='|'
  echo "usage : outils/fuzz.sh [tout|${CIBLES[*]}] [secondes par cible, 60 par défaut]" >&2
  exit 2
}
[[ $DUREE =~ ^[1-9][0-9]*$ ]] || usage
case $QUOI in
  tout) liste=("${CIBLES[@]}") ;;
  *) [[ " ${CIBLES[*]} " == *" $QUOI "* ]] || usage; liste=("$QUOI") ;;
esac
command -v cargo-fuzz >/dev/null || { echo "cargo-fuzz absent (cargo install --locked cargo-fuzz)"; exit 77; }
rustup toolchain list | grep -q '^nightly' ||
  { echo "chaîne nightly absente (rustup toolchain install nightly --profile minimal)"; exit 77; }

# Toutes compilées d'abord, d'un seul cargo : une cible cassée par un changement de src/ (fonction renommée, cale
# qui ne suit plus) s'arrête ici, avec l'erreur du compilateur, avant toute minute de fuzzing.
mkdir -p "$FUZZ"
COMPILATION=$FUZZ/compilation-$$.log
# La cible de nightly, dite : sans elle, cargo-fuzz prend celle pour laquelle il a été compilé, musl pour le
# programme que publient ses auteurs (la CI), où ni la bibliothèque standard de nightly ni AddressSanitizer ne sont.
HOTE=$(rustc +nightly -vV | sed -n 's/^host: //p')
if ! cargo +nightly fuzz build --target "$HOTE" --fuzz-dir fuzz --target-dir "$CIBLE_FUZZ" >"$COMPILATION" 2>&1; then
  echo "✖ banc de fuzzing : compilation en échec (journal : $COMPILATION)"
  grep -E '^error|^ *--> ' "$COMPILATION" | head -n 12 | sed 's/^/      /'
  exit 1
fi
rm -f "$COMPILATION"

ECHECS=0
for c in "${liste[@]}"; do
  corpus=$FUZZ/corpus/$c
  plantages=$FUZZ/plantages/$c
  journal=$FUZZ/$c.log
  mkdir -p "$corpus" "$plantages"
  echo "▶ $c, $DUREE s"
  # Le premier dossier reçoit ce que le fuzzer découvre ; les graines ne sont que lues. Compilé hors du dépôt, avec
  # les vérifications de débordement (comme la version publiée) et AddressSanitizer, par défaut chez cargo-fuzz.
  if cargo +nightly fuzz run --target "$HOTE" --fuzz-dir fuzz --target-dir "$CIBLE_FUZZ" "$c" "$corpus" "fuzz/graines/$c" -- \
    -max_total_time="$DUREE" -artifact_prefix="$plantages/" -print_final_stats=1 >"$journal" 2>&1; then
    executions=$(grep -o 'stat::number_of_executed_units: *[0-9]*' "$journal" | grep -o '[0-9]*$')
    couverture=$(grep -o 'cov: [0-9]*' "$journal" | tail -n1 | grep -o '[0-9]*$')
    printf '  ✔ %-12s %s exécutions, couverture %s, corpus de %s entrées\n' "$c" "${executions:-?}" \
      "${couverture:-?}" "$(find "$corpus" -type f | wc -l)"
  else
    ECHECS=$((ECHECS + 1))
    echo "  ✖ $c : plantage ou erreur de compilation (journal : $journal ; données : $plantages/)"
    grep -E '^(thread .* panicked|==[0-9]+==ERROR|SUMMARY|error)' "$journal" | head -n 5 | sed 's/^/      /'
  fi
done
((ECHECS == 0)) || { echo "$ECHECS cible(s) en échec."; exit 1; }
echo "Aucun plantage."
