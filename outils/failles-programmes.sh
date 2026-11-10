#!/usr/bin/env bash
# Failles connues des programmes compilés, lues dans la liste de leurs dépendances, versions comprises, que chacun
# porte (cargo auditable build, section .dep-v0) : cargo audit bin ne lit que le programme, pas le code source, comme
# le ferait quiconque l'a téléchargé. Les avis sont traités comme par cargo deny (deny.toml) : une faille, une
# bibliothèque abandonnée ou au code défaillant (unsound), un avis « notice » arrête tout ; une version retirée de
# crates.io (yanked), elle, est seulement signalée. Les seules exceptions sont celles de deny.toml, où est leur preuve :
# cargo audit lit aussi le .cargo/audit.toml du dossier courant (à défaut, celui de ~/.cargo) et ajoute ses exceptions
# sans le dire ; il tourne donc dans un dossier à lui, dont l'audit.toml vide masque les autres. Un programme sans sa
# liste est refusé : cargo audit n'en retrouverait qu'une partie (messages de panique) et pourrait dire vert à tort. La
# liste vient de cargo metadata : elle compte parfois une dépendance facultative qui n'est pas compilée (9 de plus que cargo tree pour
# Linux comme pour Windows, le 21 oct. 2026), d'où au pire une alerte de trop, jamais une de moins. cargo-audit est
# celui de la CI (.github/workflows/ci.yml) : le même jugement ici et là-bas.
#   outils/failles-programmes.sh <programme>...
#   outils/failles-programmes.sh --outil   cargo-audit seulement (présent, version de la CI), avant une compilation
#   outils/failles-programmes.sh --depot   Cargo.lock du dépôt et celui de la fenêtre, jugés de même (étape « failles connues » de
#                                          outils/verifier.sh, que la CI lance aussi chaque nuit) : code 77 sans
#                                          cargo-audit ou sans Internet, où une base pas à jour dirait vert à tort
# Lancé par outils/deployer.sh (après chaque compilation), par outils/publier-version.sh sur les deux programmes qu'il
# publie, et par la CI sur ceux qu'elle compile (ci.yml). Sans Internet : la base RustSec du dernier téléchargement, et c'est dit.
set -euo pipefail
RACINE=$(cd "$(dirname "$0")/.." && pwd)

if (($# == 0)); then
  echo "outils/failles-programmes.sh <programme>... (ou --outil, --depot)" >&2
  exit 2
fi
if [[ $1 == --depot ]]; then
  # Les exceptions de .cargo/audit.toml (que cargo audit lirait seul, à côté de Cargo.lock) doivent être celles de
  # deny.toml : une seule liste, deux copies comparées.
  python3 -I "$RACINE/outils/exceptions-rustsec.py" --audit-toml || exit 1
  command -v cargo-audit >/dev/null || { echo "cargo-audit absent (cargo install --locked cargo-audit)"; exit 77; }
  if [[ -n ${VANGUARD_HORS_LIGNE:-} ]] || ! curl -fsI --max-time 5 https://github.com >/dev/null 2>&1; then
    echo "sans Internet, base RustSec pas à jour"
    exit 77
  fi
fi
# Une autre version de cargo-audit pourrait juger autrement que la CI : celle qu'elle pose (tool: …,cargo-audit@X).
ATTENDUE=$(sed -n 's/.*cargo-audit@\([0-9][0-9.]*\).*/\1/p' "$RACINE/.github/workflows/ci.yml" | head -1)
PRESENTE=$(cargo-audit --version 2>/dev/null | awk '{ print $2 }' || true)
if [[ -z $ATTENDUE ]]; then
  echo "✖ version de cargo-audit introuvable dans .github/workflows/ci.yml (tool: …,cargo-audit@X)" >&2
  exit 1
fi
if [[ $PRESENTE != "$ATTENDUE" ]]; then
  echo "✖ cargo-audit ${PRESENTE:-absent} ici, $ATTENDUE dans la CI (.github/workflows/ci.yml) : il faut le même." >&2
  echo "  cargo install cargo-audit --locked --version $ATTENDUE" >&2
  exit 1
fi
if [[ $1 == --outil ]]; then
  exit 0
fi

OPTIONS=(--color never --deny unmaintained --deny unsound)
# La fenêtre (fenetre/Cargo.lock) n'a aucune exception dans fenetre/deny.toml (ignore = []) : celles de Vanguard,
# venues de YARA-X, ne la couvrent pas. Mais cargo audit lit Cargo.lock sans cible, et il y trouve des bibliothèques
# que ni Linux ni Windows ne compilent (zvariant, zbus_names, zvariant_derive, abandonnées : sous accesskit_unix,
# que la fenêtre ne prend pas sous Linux, fenetre/Cargo.toml). Leur avis n'est écarté ici que si `cargo tree` dit,
# pour chacune des deux cibles, que la bibliothèque n'y est pas ; cargo deny, cible par cible, les refuse sinon.
OPTIONS_FENETRE=("${OPTIONS[@]}")
HORS_CIBLES=(RUSTSEC-2026-0370:zvariant RUSTSEC-2026-0371:zbus_names RUSTSEC-2026-0372:zvariant_derive)
# Les exceptions de deny.toml, par leur identifiant RustSec (outils/exceptions-rustsec.py, qui les donne aussi à
# outils/verifier.sh) ; une exception d'une autre forme y est refusée plutôt que perdue en route.
EXCEPTIONS=$(python3 -I "$RACINE/outils/exceptions-rustsec.py")
for id in $EXCEPTIONS; do
  OPTIONS+=(--ignore "$id")
done
if [[ $1 != --depot ]] && { [[ -n ${VANGUARD_HORS_LIGNE:-} ]] || ! curl -fsI --max-time 5 https://github.com >/dev/null 2>&1; }; then
  OPTIONS+=(--no-fetch --stale)
  echo "⚠ sans Internet : base RustSec du dernier téléchargement, qui ignore les failles publiées depuis"
fi

# Le dossier de cargo audit, retiré à la fin. cargo-audit y est lancé lui-même, sans passer par cargo, qui lirait la
# configuration de ce dossier et de ses parents (/tmp compris), alias de commandes compris.
TRAVAIL=$(mktemp -d "${TMPDIR:-/tmp}/failles-programmes.XXXXXX")
trap 'rm -rf "$TRAVAIL"' EXIT
mkdir "$TRAVAIL/.cargo"
echo "# outils/failles-programmes.sh : aucune exception ici, seulement celles de deny.toml (--ignore)." \
  >"$TRAVAIL/.cargo/audit.toml"

# Le Cargo.lock du dépôt, lu depuis ce dossier-là (son audit.toml vide) : même jugement que pour les programmes.
if [[ $1 == --depot ]]; then
  CODE=0
  SORTIE=$(cd "$TRAVAIL" && cargo-audit audit "${OPTIONS[@]}" --file "$RACINE/Cargo.lock" 2>&1) || CODE=$?
  for exception in "${HORS_CIBLES[@]}"; do
    for cible in x86_64-unknown-linux-gnu x86_64-pc-windows-gnu; do
      # Un cargo tree qui échoue (sources pas encore téléchargées…) ne dit rien : refusé, jamais lu comme absente.
      if ! arbre=$(cargo tree -q --locked --manifest-path "$RACINE/fenetre/Cargo.toml" --target "$cible" \
        -e normal,build -i "${exception#*:}" 2>/dev/null); then
        echo "✖ fenêtre : cargo tree a échoué pour $cible, ${exception%%:*} pas écartée"
        CODE=1
      elif [[ -n $arbre ]]; then
        echo "✖ fenêtre : ${exception#*:} compilée pour $cible, ${exception%%:*} ne s'écarte plus"
        CODE=1
      fi
    done
    OPTIONS_FENETRE+=(--ignore "${exception%%:*}")
  done
  SORTIE+=$'\n'"fenetre/Cargo.lock :"$'\n'$(cd "$TRAVAIL" && cargo-audit audit "${OPTIONS_FENETRE[@]}" \
    --file "$RACINE/fenetre/Cargo.lock" 2>&1) || CODE=1
  printf '%s\n' "$SORTIE"
  # cargo audit n'a pas d'option pour refuser une « notice » : comptée ici (une version retirée de crates.io reste un
  # simple avertissement).
  if awk '$1 == "Warning:" && $2 != "yanked" { n++ } END { exit !n }' <<<"$SORTIE"; then
    echo "✖ avis que cargo deny refuse aussi (notice)"
    CODE=1
  fi
  [[ -z $EXCEPTIONS ]] || echo "exceptions de deny.toml : $(printf '%s\n' "$EXCEPTIONS" | paste -sd, - | sed 's/,/, /g')"
  echo "fenêtre : écartées car compilées par aucune de ses deux cibles : ${HORS_CIBLES[*]%%:*}"
  exit "$CODE"
fi

# Chaque programme par son chemin complet (cargo audit tourne dans son dossier à lui), sous son nom pour l'affichage.
NOMS=()
CHEMINS=()
for programme in "$@"; do
  if [[ ! -f $programme ]]; then
    echo "✖ $programme : introuvable. Ces programmes ne partent nulle part."
    exit 1
  fi
  case $programme in
    /*) chemin=$programme ;;
    *) chemin=$PWD/$programme ;;
  esac
  NOMS+=("$programme")
  CHEMINS+=("$chemin")
done

CODE=0
SORTIE=$(cd "$TRAVAIL" && cargo-audit audit "${OPTIONS[@]}" bin "${CHEMINS[@]}" 2>&1) || CODE=$?
# « Found 'cargo auditable' data in <programme> (N dependencies) » : la liste complète a été lue.
liste_lue() { grep -qF "'cargo auditable' data in $1 (" <<<"$SORTIE"; }
SANS_LISTE=0
for ((i = 0; i < ${#CHEMINS[@]}; i++)); do
  liste_lue "${CHEMINS[i]}" || SANS_LISTE=1
done
# Les avis que cargo audit ne compte qu'en avertissement (« Warning: notice ») et que cargo deny refuse : tous, sauf
# une version retirée de crates.io. Il n'a pas d'option pour refuser une « notice » ; l'abandon et le code défaillant
# sont déjà refusés plus haut (--deny), et le sont encore ici.
AVIS=$(awk '$1 == "Warning:" && $2 != "yanked" { n++ } END { print n + 0 }' <<<"$SORTIE")
if ((CODE != 0 || SANS_LISTE || AVIS)); then
  printf '%s\n' "$SORTIE"
  for ((i = 0; i < ${#CHEMINS[@]}; i++)); do
    liste_lue "${CHEMINS[i]}" ||
      echo "✖ ${NOMS[i]} : sans la liste de ses dépendances (à recompiler par cargo auditable build)"
  done
  if ((CODE != 0 || AVIS)); then
    echo "✖ cargo audit : failles connues, avis que cargo deny refuse (abandon, code défaillant, notice) ou"
    echo "  vérification impossible (voir ci-dessus). Une faille se corrige en mettant la dépendance à jour ; une"
    echo "  exception ne s'admet que dans deny.toml, avec sa preuve."
  fi
  echo "Ces programmes ne partent nulle part."
  exit 1
fi
# Les avertissements qui ne bloquent pas (version retirée de crates.io) restent visibles.
grep -q '^warning' <<<"$SORTIE" && printf '%s\n' "$SORTIE"
for ((i = 0; i < ${#CHEMINS[@]}; i++)); do
  nombre=$(grep -F "'cargo auditable' data in ${CHEMINS[i]} (" <<<"$SORTIE" |
    sed -n 's/.*(\([0-9]*\) dependencies).*/\1/p')
  echo "✔ ${NOMS[i]} : $nombre dépendances listées, aucune faille connue"
done
if [[ -n $EXCEPTIONS ]]; then
  echo "  exceptions de deny.toml : $(printf '%s\n' "$EXCEPTIONS" | paste -sd, - | sed 's/,/, /g')"
fi
