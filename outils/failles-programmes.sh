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
#   outils/failles-programmes.sh --fenetre <programme>...   la fenêtre (vanguard-fenetre) : sans les exceptions de
#                                          Vanguard (fenetre/deny.toml n'en a aucune) ; seulement HORS_CIBLES, prouvées
#                                          par cargo tree et absentes des octets du programme (sinon : refusé, ou non
#                                          vérifié si rien ne s'y lit)
#   outils/failles-programmes.sh --outil   cargo-audit seulement (présent, version de la CI), avant une compilation
#   outils/failles-programmes.sh --depot   Cargo.lock du dépôt, de la fenêtre et des crates à part (fuzz, extensions,
#                                          preuves Kani), jugés de même (étape « failles connues » de
#                                          outils/verifier.sh, que la CI lance aussi chaque nuit) : code 77 sans
#                                          cargo-audit ou sans Internet, où une base pas à jour dirait vert à tort
# Lancé par outils/deployer.sh (après chaque compilation), par outils/publier-version.sh sur les programmes qu'il
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
FENETRE=
if [[ $1 == --fenetre ]]; then
  FENETRE=1
  shift
  (($# > 0)) || { echo "outils/failles-programmes.sh --fenetre <programme>..." >&2; exit 2; }
fi

OPTIONS=(--color never --deny unmaintained --deny unsound)
# La fenêtre (fenetre/Cargo.lock) n'a aucune exception dans fenetre/deny.toml (ignore = []) : celles de Vanguard,
# venues de YARA-X, ne la couvrent pas. Mais cargo audit lit Cargo.lock sans cible, et il y trouve des bibliothèques
# que ni Linux ni Windows ne compilent (zvariant, zbus_names, zvariant_derive, abandonnées : sous accesskit_unix,
# que la fenêtre ne prend pas sous Linux, fenetre/Cargo.toml). Leur avis n'est écarté ici que si `cargo tree` dit,
# pour chacune des deux cibles, que la bibliothèque n'y est pas (cargo deny, cible par cible, les refuse sinon) et,
# avec --fenetre, qu'elle ne se lit pas non plus dans les octets du programme audité (hors_cibles_absentes_des_octets).
OPTIONS_FENETRE=("${OPTIONS[@]}")
# Les crates à part, chacune avec son Cargo.lock : le banc de fuzzing (fuzz/deny.toml), la bibliothèque des
# extensions et l'exemple en Rust (extensions/deny.toml), les preuves Kani (outils/preuves). Aucune exception
# (ignore = [] dans leurs deny.toml) : celles de Vanguard, venues de YARA-X, ne les couvrent pas.
OPTIONS_A_PART=("${OPTIONS[@]}")
A_PART=(fuzz/Cargo.lock extensions/sdk/Cargo.lock extensions/exemples/rust-exemple/Cargo.lock outils/preuves/Cargo.lock)
HORS_CIBLES=(RUSTSEC-2026-0370:zvariant RUSTSEC-2026-0371:zbus_names RUSTSEC-2026-0372:zvariant_derive)
# Les exceptions de deny.toml, par leur identifiant RustSec (outils/exceptions-rustsec.py, qui les donne aussi à
# outils/verifier.sh) ; une exception d'une autre forme y est refusée plutôt que perdue en route.
EXCEPTIONS=$(python3 -I "$RACINE/outils/exceptions-rustsec.py")
# La fenêtre : aucune des exceptions de Vanguard. Sa liste de dépendances gravée en compte pourtant plus qu'elle n'en
# compile : cargo auditable la tire de `cargo metadata`, qui unit les options de toutes les plateformes (l'option
# accesskit d'eframe, prise pour Windows seulement, y amène accesskit_unix et zvariant sous Linux aussi ; vu sur la
# fenêtre Linux de la 0.96 ; 243 caisses listées pour 152 dans son arbre le 12 nov. 2026). Jusque-là, ce code y
# était aussi compilé (les deux cibles dans un seul appel de cargo) ; outils/compiler-version.sh les compile
# désormais une à la fois, et outils/caisses-fenetre.sh --programmes prouve sur les octets que la preuve par cargo
# tree vaut pour le programme. Seules les HORS_CIBLES s'écartent, par la même preuve que pour --depot (plus bas), et
# seulement si elles ne se lisent pas dans les octets du programme audité.
[[ -z $FENETRE ]] || EXCEPTIONS=
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

# Les erreurs de cargo tree, gardées pour la fin : écrites après la sortie de cargo audit, juste avant le code de
# retour, elles restent dans les dernières lignes que montre outils/verifier.sh. Une erreur identique pour plusieurs
# cibles ou crates n'est écrite qu'une fois, sous tous ses titres (montrer_erreurs_arbre).
declare -A ERREURS_ARBRE=()
ORDRE_ERREURS=()
montrer_erreurs_arbre() {
  local erreur
  for erreur in "${ORDRE_ERREURS[@]}"; do
    printf '%s\n%s\n' "${ERREURS_ARBRE["$erreur"]}" "$erreur"
  done
}

# Les avis HORS_CIBLES de la fenêtre, ajoutés à OPTIONS_FENETRE en --ignore ; code 1 si l'une d'elles est compilée
# pour une de ses deux cibles, ou si cargo tree ne peut pas le dire (alors l'avis compte : --fenetre refuse).
hors_cibles_prouvees() {
  local code=0 exception cible arbre erreur titre
  for exception in "${HORS_CIBLES[@]}"; do
    for cible in x86_64-unknown-linux-gnu x86_64-pc-windows-gnu; do
      # Un cargo tree qui échoue (sources pas encore téléchargées…) ne dit rien : refusé, jamais lu comme absente.
      # Son erreur est montrée : jetée, elle laissait la CI de nuit rouge quatre nuits sans cause écrite.
      if ! arbre=$(cargo tree -q --locked --manifest-path "$RACINE/fenetre/Cargo.toml" --target "$cible" \
        -e normal,build -i "${exception#*:}" 2>"$TRAVAIL/arbre.err"); then
        erreur=$(tail -n 5 "$TRAVAIL/arbre.err" | sed 's/^/    /')
        [[ -n $erreur ]] || erreur="    (cargo tree n'a rien écrit)"
        titre="✖ fenêtre : cargo tree a échoué pour $cible, ${exception%%:*} pas écartée"
        if [[ -v ERREURS_ARBRE["$erreur"] ]]; then
          ERREURS_ARBRE["$erreur"]+=$'\n'"$titre"
        else
          ERREURS_ARBRE["$erreur"]=$titre
          ORDRE_ERREURS+=("$erreur")
        fi
        code=1
      elif [[ -n $arbre ]]; then
        echo "✖ fenêtre : ${exception#*:} compilée pour $cible, ${exception%%:*} ne s'écarte plus"
        code=1
      fi
    done
    OPTIONS_FENETRE+=(--ignore "${exception%%:*}")
  done
  return "$code"
}

# Les HORS_CIBLES lues dans les octets de chaque programme (outils/caisses-fenetre.sh --caisses : la même lecture que
# la garde de outils/compiler-version.sh). cargo tree juge l'arbre, pas le programme : compilé autrement (les deux
# cibles dans un seul appel de cargo), le programme a déjà emporté zvariant, et son avis ne s'écarte alors pas. Les
# octets ne prouvent qu'une présence (une caisse qui ne panique jamais n'y laisse pas de chemin) : l'absence, elle,
# tient à cargo tree et à la recette (outils/essais-caisses-fenetre.sh). Code 1 si l'une y est, ou si rien ne se lit
# dans un programme (non vérifié, jamais compté comme sain).
hors_cibles_absentes_des_octets() {
  local code=0 programme vues exception
  for programme in "$@"; do
    if ! vues=$(bash "$RACINE/outils/caisses-fenetre.sh" --caisses "$programme" 2>&1); then
      echo "✖ fenêtre : $programme, caisses illisibles dans ses octets ($(tail -n 1 <<<"$vues")) :" \
        "${HORS_CIBLES[*]%%:*} non vérifiées, pas écartées"
      code=1
      continue
    fi
    for exception in "${HORS_CIBLES[@]}"; do
      if awk -v n="${exception#*:}" '$1 == n { t = 1 } END { exit !t }' <<<"$vues"; then
        echo "✖ fenêtre : ${exception#*:} dans les octets de $programme, ${exception%%:*} n'est pas écartée"
        code=1
      fi
    done
  done
  return "$code"
}

# Le Cargo.lock du dépôt, lu depuis ce dossier-là (son audit.toml vide) : même jugement que pour les programmes.
if [[ $1 == --depot ]]; then
  CODE=0
  SORTIE=$(cd "$TRAVAIL" && cargo-audit audit "${OPTIONS[@]}" --file "$RACINE/Cargo.lock" 2>&1) || CODE=$?
  hors_cibles_prouvees || CODE=1
  SORTIE+=$'\n'"fenetre/Cargo.lock :"$'\n'$(cd "$TRAVAIL" && cargo-audit audit "${OPTIONS_FENETRE[@]}" \
    --file "$RACINE/fenetre/Cargo.lock" 2>&1) || CODE=1
  for verrou in "${A_PART[@]}"; do
    SORTIE+=$'\n'"$verrou :"$'\n'$(cd "$TRAVAIL" && cargo-audit audit "${OPTIONS_A_PART[@]}" \
      --file "$RACINE/$verrou" 2>&1) || CODE=1
  done
  printf '%s\n' "$SORTIE"
  # cargo audit n'a pas d'option pour refuser une « notice » : comptée ici (une version retirée de crates.io reste un
  # simple avertissement).
  if awk '$1 == "Warning:" && $2 != "yanked" { n++ } END { exit !n }' <<<"$SORTIE"; then
    echo "✖ avis que cargo deny refuse aussi (notice)"
    CODE=1
  fi
  [[ -z $EXCEPTIONS ]] || echo "exceptions de deny.toml : $(printf '%s\n' "$EXCEPTIONS" | paste -sd, - | sed 's/,/, /g')"
  echo "fenêtre : écartées car compilées par aucune de ses deux cibles : ${HORS_CIBLES[*]%%:*}"
  montrer_erreurs_arbre
  exit "$CODE"
fi

# La fenêtre : ses avis HORS_CIBLES écartés seulement s'ils sont prouvés hors de ses deux cibles et ne se lisent pas
# dans ses octets ; sinon, rien ne part.
if [[ -n $FENETRE ]]; then
  OPTIONS_FENETRE=("${OPTIONS[@]}")
  PROUVE=0
  hors_cibles_prouvees || PROUVE=1
  hors_cibles_absentes_des_octets "$@" || PROUVE=1
  ((PROUVE == 0)) || { montrer_erreurs_arbre; echo "Ces programmes ne partent nulle part."; exit 1; }
  OPTIONS=("${OPTIONS_FENETRE[@]}")
  echo "fenêtre : écartées car compilées par aucune de ses deux cibles et absentes des octets lus :" \
    "${HORS_CIBLES[*]%%:*}"
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
