#!/usr/bin/env bash
# Les caisses de la fenêtre (fenetre/), cible par cible : ce que cargo deny, clippy et ses essais jugent, et ce que ses
# programmes publiés contiennent vraiment.
#   outils/caisses-fenetre.sh            l'arbre de chaque cible (cargo tree, dépendances normales et de compilation,
#                                        dédoublonnées par nom et version) égal, noms et versions, à sa liste versionnée
#                                        outils/caisses-fenetre/<cible>.txt (la différence montrée), et aucune des
#                                        RETIREES (étape « fenêtre » de outils/verifier.sh)
#   outils/caisses-fenetre.sh --ecrire   refait ces listes depuis l'arbre de chaque cible (jamais avec une RETIREE), à
#                                        relire dans le diff : chaque caisse de plus passe à cargo deny et cargo vet
#   outils/caisses-fenetre.sh --programmes <fenêtre Linux> <fenêtre Windows>
#                                        chaque caisse nommée dans les octets d'un programme (les chemins de ses
#                                        messages de panique) est dans l'arbre de sa cible, et aucune caisse de cet
#                                        arbre n'est d'une autre source que crates.io (outils/compiler-version.sh,
#                                        après la compilation de la fenêtre)
#   outils/caisses-fenetre.sh --vanguard <vanguard Linux> <vanguard Windows>
#                                        la même preuve pour vanguard (Cargo.toml de la racine, cibles musl et
#                                        Windows), qui se compile encore en un appel pour ses deux cibles
#                                        (outils/compiler-version.sh, après sa compilation, avant le repère)
#   outils/caisses-fenetre.sh --publies <programme>...
#                                        aucune caisse d'une autre source dans l'arbre des deux cibles, et chaque caisse
#                                        nommée dans les octets d'un programme dans la liste versionnée de sa cible,
#                                        lue dans son en-tête (ELF : Linux, MZ : Windows ; autre : rien n'est conclu),
#                                        pour outils/failles-programmes.sh --fenetre
#   outils/caisses-fenetre.sh --caisses <programme>
#                                        les caisses nommées dans ses octets, « nom version » par ligne (la même
#                                        lecture, pour outils/failles-programmes.sh --fenetre)
#   outils/caisses-fenetre.sh --retirees les RETIREES, une par ligne (une seule liste, pour failles-programmes.sh)
# Code 0 : conforme ; 1 : une caisse de trop, une retirée revenue, une caisse d'une autre source que crates.io ou une
# liste changée ; 2 : rien n'est conclu (cargo tree en échec ou mal lu, liste de référence absente ou vide, aucune
# caisse lue dans un programme, en-tête inconnu), jamais un vert.
# Essais : outils/essais-caisses-fenetre.sh.
#
# Pourquoi les octets : compilées par un seul appel de cargo (--target Linux --target Windows), les deux cibles
# partagent leurs options (features). L'option accesskit d'eframe, prise pour Windows seulement (fenetre/Cargo.toml),
# s'activait ainsi sous Linux aussi : la fenêtre Linux publiée aurait embarqué accesskit_unix, zbus et zvariant
# (abandonnées : RUSTSEC-2026-0370, 0371, 0372, que fenetre/deny.toml refuse), 2,8 Mo et une cinquantaine de caisses
# que cargo tree, cargo deny, clippy et les essais, lancés cible par cible, ne voyaient pas. Mesuré le 12 nov. 2026 ;
# outils/compiler-version.sh compile une cible à la fois, et ce script prouve sur les octets que le programme
# livré est bien celui qui est jugé.
# Pourquoi des listes et pas des nombres : une caisse remplacée par une autre, au même nombre, passait sans être dite.
set -uo pipefail
# Un seul ordre de tri, celui des octets : comm compare les listes triées de la même façon partout.
export LC_ALL=C
RACINE=$(cd "$(dirname "$0")/.." && pwd)
MANIFESTE=$RACINE/fenetre/Cargo.toml
CIBLES=(x86_64-unknown-linux-gnu x86_64-pc-windows-gnu)
# Le paquet jugé, ôté de son propre arbre.
PAQUET=vanguard-fenetre
# La liste exacte par cible (nom et version), versionnée : elle ne change pas sans qu'on le voie dans le diff. Une
# caisse de plus s'y ajoute (et passe à cargo deny et cargo vet), sa raison dans le message de commit : une liste n'a
# pas de commentaire, --ecrire la récrit en entier ; une de moins s'en retire avec le code.
REFERENCES=$RACINE/outils/caisses-fenetre
# Ce qui ne revient dans aucune cible : le lecteur d'écran d'accesskit sous Linux et tout ce qu'il amène (zbus et ses
# formats, abandonnés), refusés par fenetre/deny.toml (fenetre/Cargo.toml, « Pas sous Linux pour l'instant »).
RETIREES=(accesskit_unix accesskit_atspi_common atspi atspi-common atspi-proxies atspi-connection zbus zbus_names
  zbus_macros zbus_xml zbus-lockstep zvariant zvariant_derive zvariant_utils)

# L'arbre d'une cible, « nom version » par ligne, trié, sans la fenêtre elle-même. cargo tree écrit
# « nom vversion [(proc-macro)] [(source)] [(*)] » : la source n'y est que si elle n'est pas crates.io. Elle est
# gardée, sous une forme qui ne dit aucun chemin de cet ordinateur : « (chemin local) » ou « (autre source) ». Sans
# elle, un [patch.crates-io] vers une copie modifiée, de même nom et de même version, passait ici comme cargo deny et
# cargo vet (relecture du 12 nov. 2026). Une caisse d'une source remplacée (remplacees, plus bas) devient
# « (autre source) » elle aussi. Code 2 si cargo tree ou cargo metadata échoue, ne dit rien ou écrit une ligne d'une
# forme inconnue : un arbre vide ou mal lu n'est pas un arbre sain.
arbre() {
  local sortie remplacees
  sortie=$(cargo tree -q --locked --manifest-path "$MANIFESTE" --target "$1" -e normal,build --prefix none \
    --format '{p}') || { echo "✖ cargo tree a échoué pour $1 : rien n'est conclu" >&2; return 2; }
  sortie=$(sed -E 's/ \(\*\)$//; s/^([^ ]+ v[^ ]+) \(proc-macro\)/\1/
    s#^([^ ]+) v([^ ]+) \(/[^)]*\)$#\1 \2 (chemin local)#
    s#^([^ ]+) v([^ ]+) \(.*\)$#\1 \2 (autre source)#
    s#^([^ ]+) v([^ ]+)$#\1 \2#' <<<"$sortie" | grep -v "^$PAQUET " | sort -u)
  [[ -n $sortie ]] || { echo "✖ cargo tree n'a rien dit pour $1 : rien n'est conclu" >&2; return 2; }
  grep -qvE '^[A-Za-z0-9_-]+ [0-9][^ ]*( \((chemin local|autre source)\))?$' <<<"$sortie" &&
    { echo "✖ cargo tree a écrit pour $1 une ligne d'une forme inconnue : rien n'est conclu" >&2; return 2; }
  remplacees=$(remplacees "$1") || { echo "✖ cargo metadata a échoué pour $1 : rien n'est conclu" >&2; return 2; }
  if [[ -n $remplacees ]]; then
    sortie=$(awk 'NR == FNR { r[$0] = 1; next } { print (r[$0] ? $0 " (autre source)" : $0) }' \
      <(printf '%s\n' "$remplacees") <(printf '%s\n' "$sortie") | sort -u)
  fi
  printf '%s\n' "$sortie"
}

# Les caisses que cargo dit de crates.io mais qu'il lit ailleurs que dans son registre, « nom version » par ligne. Une
# source remplacée ([source.crates-io] replace-with vers un dossier, dans un .cargo/config.toml du dépôt, d'un dossier
# parent ou de CARGO_HOME) garde l'identité « crates.io » : cargo tree n'écrit alors aucune source, et cargo deny ne
# voit rien (relecture du 12 nov. 2026). Une caisse de crates.io se lit dans
# $CARGO_HOME/registry/src/index.crates.io-<16 chiffres hexadécimaux>/<nom>-<version>/, le chemin tel que cargo l'écrit
# (CARGO_HOME tel qu'il est donné, joint au dossier courant, « .. » retiré sur le texte, mais aucun lien résolu), et
# nulle part ailleurs. Une source se remplace en entier : toutes les caisses de crates.io de l'arbre sont alors dites.
# Code non nul si cargo metadata échoue ou se lit mal.
remplacees() {
  cargo metadata -q --locked --format-version 1 --manifest-path "$MANIFESTE" --filter-platform "$1" |
    python3 -I -c '
import json, os, re, sys
maison = os.path.normpath(os.path.join(os.getcwd(), sys.argv[1]))
registre = re.escape(maison.rstrip("/") + "/registry/src/") + r"index\.crates\.io-[0-9a-f]{16}/"
for p in json.load(sys.stdin)["packages"]:
    if re.match(r"(registry|sparse)\+", p["source"] or "") and not re.fullmatch(
        registre + re.escape(p["name"] + "-" + p["version"]) + "/Cargo.toml", p["manifest_path"]):
        print(p["name"], p["version"])
' "${CARGO_HOME:-$HOME/.cargo}"
}

# Les caisses d'une autre source que crates.io dans une liste (« nom version (source) » par ligne).
autres_sources() {
  grep -E ' \((chemin local|autre source)\)$' <<<"$1"
}

# La liste versionnée d'une cible, triée. Code 2 si elle est absente, illisible, vide ou si une ligne n'a pas la forme
# « nom version » (avec, écrite à la main, la source que la garde refuse) : rien n'est conclu. Relecture du 12 nov.
# 2026 (C4) : une ligne « # raison » donnait un rouge sans fin (« - # raison »), et --ecrire, proposé, l'effaçait.
reference() {
  local f=$REFERENCES/$1.txt contenu autres
  contenu=$(cat -- "$f" 2>/dev/null) || { echo "✖ $f : absente ou illisible, rien n'est conclu" >&2; return 2; }
  contenu=$(grep -v '^[[:space:]]*$' <<<"$contenu" | sort -u)
  [[ -n $contenu ]] || { echo "✖ $f : vide, rien n'est conclu" >&2; return 2; }
  autres=$(grep -vE '^[A-Za-z0-9_-]+ [0-9][^ ]*( \((chemin local|autre source)\))?$' <<<"$contenu")
  if [[ -n $autres ]]; then
    echo "✖ $f : $(wc -l <<<"$autres") ligne(s) d'une autre forme que « nom version »," \
      "dont « $(head -1 <<<"$autres") » (une liste n'a pas de commentaire : la raison d'une caisse va dans" \
      "le message de commit), rien n'est conclu" >&2
    return 2
  fi
  printf '%s\n' "$contenu"
}

# Les retirées présentes dans une liste, « nom version » par ligne.
revenues() {
  awk 'NR == FNR { r[$1] = 1; next } r[$1] { print $1 " " $2 }' <(printf '%s\n' "${RETIREES[@]}") <(printf '%s\n' "$1")
}

# Les caisses nommées dans les octets d'un programme, « nom version » par ligne : les chemins de leurs sources
# (…/registry/src/<index>/<nom>-<version>/…), gardés par les messages de panique, même allégé (strip) et chemins
# retirés (/cargo/registry/…). Seulement celles qui peuvent paniquer : une preuve qu'une caisse est là, jamais qu'elle
# n'y est pas ; d'où la comparaison dans ce sens-là seulement. Code 2 si le programme ne se lit pas (grep : 2) ;
# rien de trouvé n'est pas une erreur ici (grep : 1), c'est à l'appelant de refuser une liste vide.
dans_programme() {
  local brut
  brut=$(LC_ALL=C grep -aoE 'registry/src/[^/[:space:]]+/[A-Za-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*/' "$1")
  (($? <= 1)) || return 2
  [[ -n $brut ]] || return 0
  sed -E 's#^registry/src/[^/]+/##; s#/$##; s#^(.*)-([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*)$#\1 \2#' <<<"$brut" | sort -u
}

# La cible d'un programme, lue dans ses premiers octets : « \177ELF » pour Linux, « MZ » pour Windows. Code 2 sinon.
cible_du_programme() {
  local entete
  entete=$(head -c 4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n') || return 2
  case $entete in
    7f454c46) echo "${CIBLES[0]}" ;;
    4d5a*) echo "${CIBLES[1]}" ;;
    *) return 2 ;;
  esac
}

# Les caisses d'une autre source que crates.io dans l'arbre d'une cible, dites ; code 1 s'il y en a. Toujours
# refusées, même inscrites à la main dans la liste : cargo deny, cargo vet et cargo audit ne les jugent pas comme des
# caisses de crates.io, et la garde des octets ne les voit pas (leur chemin n'est pas sous registry/src).
sources_refusees() { # cible, arbre
  local a
  a=$(autres_sources "$2") || return 0
  echo "✖ $1 : caisses d'une autre source que crates.io : $(paste -sd, - <<<"$a" | sed 's/,/, /g')"
  return 1
}

CODE=0
if [[ ${1:-} == --retirees ]]; then
  (($# == 1)) || { echo "outils/caisses-fenetre.sh --retirees" >&2; exit 2; }
  printf '%s\n' "${RETIREES[@]}"
  exit 0
fi
if [[ ${1:-} == --caisses ]]; then
  (($# == 2)) || { echo "outils/caisses-fenetre.sh --caisses <programme>" >&2; exit 2; }
  [[ -f $2 && -r $2 ]] || { echo "✖ $2 : introuvable ou illisible, rien n'est conclu" >&2; exit 2; }
  vues=$(dans_programme "$2") || { echo "✖ $2 : lecture impossible, rien n'est conclu" >&2; exit 2; }
  [[ -n $vues ]] || { echo "✖ $2 : aucune caisse lue dans ses octets, rien n'est conclu" >&2; exit 2; }
  printf '%s\n' "$vues"
  exit 0
fi
# Ronde Fable du 13 nov. 2026, décision (a) : vanguard se compile encore en un appel pour ses deux cibles, qui
# partagent alors leurs options, comme la fenêtre avant ; sa preuve sur les octets est la même. Séparer ses appels
# (avec un job reproductible dans la CI) viendra plus tard. Mesuré le 13 nov. 2026 sur les vanguard du lot 096 :
# aucune caisse hors de l'arbre de sa cible.
if [[ ${1:-} == --vanguard ]]; then
  (($# == 3)) || { echo "outils/caisses-fenetre.sh --vanguard <vanguard Linux> <vanguard Windows>" >&2; exit 2; }
  MANIFESTE=$RACINE/Cargo.toml
  PAQUET=vanguard
  CIBLES=(x86_64-unknown-linux-musl x86_64-pc-windows-gnu)
  set -- --programmes "$2" "$3"
fi
if [[ ${1:-} == --programmes ]]; then
  (($# == 3)) || { echo "outils/caisses-fenetre.sh --programmes <fenêtre Linux> <fenêtre Windows>" >&2; exit 2; }
  PROGRAMMES=("$2" "$3")
  for i in 0 1; do
    cible=${CIBLES[i]} programme=${PROGRAMMES[i]}
    [[ -f $programme ]] || { echo "✖ $programme : introuvable, rien n'est conclu" >&2; exit 2; }
    attendues=$(arbre "$cible") || exit 2
    # Ronde 2 du 13 nov. 2026 : une autre source n'était refusée que par le mode sans argument, que la compilation
    # ne lance pas.
    sources_refusees "$cible" "$attendues" || CODE=1
    vues=$(dans_programme "$programme") || { echo "✖ $programme : lecture impossible, rien n'est conclu" >&2; exit 2; }
    if [[ -z $vues ]]; then
      echo "✖ $programme : aucune caisse lue dans ses octets, rien n'est conclu" >&2
      exit 2
    fi
    de_trop=$(comm -23 <(printf '%s\n' "$vues") <(printf '%s\n' "$attendues"))
    if [[ -n $de_trop ]]; then
      echo "✖ $programme : $(wc -l <<<"$de_trop") caisses compilées hors de l'arbre de $cible (que cargo deny," \
        "clippy et les essais jugent), dont : $(head -8 <<<"$de_trop" | paste -sd, - | sed 's/,/, /g')"
      CODE=1
    else
      echo "✔ $programme : $(wc -l <<<"$vues") caisses lues dans ses octets, toutes dans l'arbre de $cible"
    fi
  done
  exit "$CODE"
fi
# Les programmes publiés, quelle que soit la façon dont ils ont été compilés : comparés à la liste versionnée, pas à
# l'arbre du moment. Ronde 2 du 13 nov. 2026 : failles-programmes.sh --fenetre ne cherchait dans les octets que les
# RETIREES ; un programme d'une autre recette (une caisse de plus, ou des chemins changés) gardait l'avis écarté.
if [[ ${1:-} == --publies ]]; then
  shift
  (($# > 0)) || { echo "outils/caisses-fenetre.sh --publies <programme>..." >&2; exit 2; }
  for cible in "${CIBLES[@]}"; do
    liste=$(arbre "$cible") || exit 2
    sources_refusees "$cible" "$liste" || CODE=1
  done
  for programme in "$@"; do
    [[ -f $programme && -r $programme ]] ||
      { echo "✖ $programme : introuvable ou illisible, rien n'est conclu" >&2; exit 2; }
    cible=$(cible_du_programme "$programme") ||
      { echo "✖ $programme : ni ELF ni MZ, cible inconnue, rien n'est conclu" >&2; exit 2; }
    attendue=$(reference "$cible") || exit 2
    vues=$(dans_programme "$programme") || { echo "✖ $programme : lecture impossible, rien n'est conclu" >&2; exit 2; }
    [[ -n $vues ]] || { echo "✖ $programme : aucune caisse lue dans ses octets, rien n'est conclu" >&2; exit 2; }
    de_trop=$(comm -23 <(printf '%s\n' "$vues") <(printf '%s\n' "$attendue"))
    if [[ -n $de_trop ]]; then
      echo "✖ $programme : $(wc -l <<<"$de_trop") caisses hors de outils/caisses-fenetre/$cible.txt, dont :" \
        "$(head -8 <<<"$de_trop" | paste -sd, - | sed 's/,/, /g')"
      CODE=1
    else
      echo "✔ $programme : $(wc -l <<<"$vues") caisses lues dans ses octets, toutes dans" \
        "outils/caisses-fenetre/$cible.txt"
    fi
  done
  exit "$CODE"
fi
if [[ ${1:-} == --ecrire ]]; then
  (($# == 1)) || { echo "outils/caisses-fenetre.sh --ecrire" >&2; exit 2; }
  mkdir -p "$REFERENCES" || exit 2
  for cible in "${CIBLES[@]}"; do
    liste=$(arbre "$cible") || exit 2
    r=$(revenues "$liste")
    if [[ -n $r ]]; then
      echo "✖ $cible : caisses retirées revenues, liste non écrite : $(paste -sd, - <<<"$r" | sed 's/,/, /g')"
      CODE=1
      continue
    fi
    a=$(autres_sources "$liste")
    if [[ -n $a ]]; then
      echo "✖ $cible : caisses d'une autre source que crates.io, liste non écrite : $(paste -sd, - <<<"$a" | sed 's/,/, /g')"
      CODE=1
      continue
    fi
    printf '%s\n' "$liste" >"$REFERENCES/$cible.txt.nouveau" && mv -f "$REFERENCES/$cible.txt.nouveau" "$REFERENCES/$cible.txt" ||
      exit 2
    echo "écrit : outils/caisses-fenetre/$cible.txt ($(wc -l <<<"$liste") caisses), à relire dans le diff"
  done
  exit "$CODE"
fi
(($# == 0)) || {
  echo "outils/caisses-fenetre.sh [--ecrire | --programmes <fenêtre Linux> <fenêtre Windows> |" \
    "--vanguard <vanguard Linux> <vanguard Windows> | --publies <programme>... | --caisses <programme> |" \
    "--retirees]" >&2
  exit 2
}

# Une différence montrée ligne à ligne (40 au plus par sens), « + » dans l'arbre seulement, « - » dans la liste seulement.
montrer() {
  local signe=$1 lignes=$2 n
  [[ -n $lignes ]] || return 0
  n=$(wc -l <<<"$lignes")
  head -40 <<<"$lignes" | sed "s/^/    $signe /"
  ((n <= 40)) || echo "    … et $((n - 40)) autres"
}

for cible in "${CIBLES[@]}"; do
  liste=$(arbre "$cible") || exit 2
  attendue=$(reference "$cible") || exit 2
  nombre=$(wc -l <<<"$liste")
  r=$(revenues "$liste")
  if [[ -n $r ]]; then
    echo "✖ $cible : caisses retirées revenues : $(paste -sd, - <<<"$r" | sed 's/,/, /g')"
    CODE=1
  fi
  a=$(autres_sources "$liste")
  sources_refusees "$cible" "$liste" || CODE=1
  en_plus=$(comm -13 <(printf '%s\n' "$attendue") <(printf '%s\n' "$liste"))
  en_moins=$(comm -23 <(printf '%s\n' "$attendue") <(printf '%s\n' "$liste"))
  if [[ -n $en_plus || -n $en_moins ]]; then
    echo "✖ $cible : $nombre caisses, l'arbre n'est plus celui de outils/caisses-fenetre/$cible.txt" \
      "($(wc -l <<<"$attendue")) :"
    montrer + "$en_plus"
    montrer - "$en_moins"
    # Ronde 2 du 13 nov. 2026 (R5) : --ecrire était proposé même quand il refuse (retirée revenue, autre source).
    if [[ -n $r || -n $a ]]; then
      echo "  Voulu : d'abord retirer du code ce qui est refusé plus haut ;" \
        "--ecrire n'écrit jamais une caisse retirée ni une autre source."
    else
      echo "  Voulu : outils/caisses-fenetre.sh --ecrire, puis le diff relu" \
        "(une caisse de plus se dit, sa raison dans le message de commit)."
    fi
    CODE=1
  elif [[ -z $r && -z $a ]]; then
    echo "✔ $cible : $nombre caisses, celles de outils/caisses-fenetre/$cible.txt, aucune retirée revenue"
  fi
done
exit "$CODE"
