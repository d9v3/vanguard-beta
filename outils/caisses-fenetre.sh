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
#                                        messages de panique) est dans l'arbre de sa cible (outils/compiler-version.sh,
#                                        après la compilation de la fenêtre)
# Code 0 : conforme ; 1 : une caisse de trop, une retirée revenue ou une liste changée ; 2 : rien n'est conclu (cargo
# tree en échec, liste de référence absente ou vide, aucune caisse lue dans un programme), jamais un vert.
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
# La liste exacte par cible (nom et version), versionnée : elle ne change pas sans qu'on le voie dans le diff. Une
# caisse de plus s'y ajoute avec sa raison (et passe à cargo deny et cargo vet) ; une de moins s'en retire avec le code.
REFERENCES=$RACINE/outils/caisses-fenetre
# Ce qui ne revient dans aucune cible : le lecteur d'écran d'accesskit sous Linux et tout ce qu'il amène (zbus et ses
# formats, abandonnés), refusés par fenetre/deny.toml (fenetre/Cargo.toml, « Pas sous Linux pour l'instant »).
RETIREES=(accesskit_unix accesskit_atspi_common atspi atspi-common atspi-proxies atspi-connection zbus zbus_names
  zbus_macros zbus_xml zbus-lockstep zvariant zvariant_derive zvariant_utils)

# L'arbre d'une cible, « nom version » par ligne, trié, sans la fenêtre elle-même. Code 2 si cargo tree échoue ou ne
# dit rien : un arbre vide n'est pas un arbre sain.
arbre() {
  local sortie
  sortie=$(cargo tree -q --locked --manifest-path "$MANIFESTE" --target "$1" -e normal,build --prefix none \
    --format '{p}') || { echo "✖ cargo tree a échoué pour $1 : rien n'est conclu" >&2; return 2; }
  sortie=$(sed 's/ (.*//; s/ v/ /' <<<"$sortie" | grep -v '^vanguard-fenetre ' | sort -u)
  [[ -n $sortie ]] || { echo "✖ cargo tree n'a rien dit pour $1 : rien n'est conclu" >&2; return 2; }
  printf '%s\n' "$sortie"
}

# La liste versionnée d'une cible, triée. Code 2 si elle est absente, illisible ou vide : rien n'est conclu.
reference() {
  local f=$REFERENCES/$1.txt contenu
  contenu=$(cat -- "$f" 2>/dev/null) || { echo "✖ $f : absente ou illisible, rien n'est conclu" >&2; return 2; }
  contenu=$(grep -v '^[[:space:]]*$' <<<"$contenu" | sort -u)
  [[ -n $contenu ]] || { echo "✖ $f : vide, rien n'est conclu" >&2; return 2; }
  printf '%s\n' "$contenu"
}

# Les retirées présentes dans une liste, « nom version » par ligne.
revenues() {
  awk 'NR == FNR { r[$1] = 1; next } r[$1] { print $1 " " $2 }' <(printf '%s\n' "${RETIREES[@]}") <(printf '%s\n' "$1")
}

# Les caisses nommées dans les octets d'un programme, « nom version » par ligne : les chemins de leurs sources
# (…/registry/src/<index>/<nom>-<version>/…), gardés par les messages de panique, même allégé (strip) et chemins
# retirés (/cargo/registry/…). Seulement celles qui peuvent paniquer : une preuve qu'une caisse est là, jamais qu'elle
# n'y est pas ; d'où la comparaison dans ce sens-là seulement.
dans_programme() {
  LC_ALL=C grep -aoE 'registry/src/[^/[:space:]]+/[A-Za-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*/' "$1" |
    sed -E 's#^registry/src/[^/]+/##; s#/$##; s#^(.*)-([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*)$#\1 \2#' | sort -u
}

CODE=0
if [[ ${1:-} == --programmes ]]; then
  (($# == 3)) || { echo "outils/caisses-fenetre.sh --programmes <fenêtre Linux> <fenêtre Windows>" >&2; exit 2; }
  PROGRAMMES=("$2" "$3")
  for i in 0 1; do
    cible=${CIBLES[i]} programme=${PROGRAMMES[i]}
    [[ -f $programme ]] || { echo "✖ $programme : introuvable, rien n'est conclu" >&2; exit 2; }
    attendues=$(arbre "$cible") || exit 2
    vues=$(dans_programme "$programme")
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
    printf '%s\n' "$liste" >"$REFERENCES/$cible.txt.nouveau" && mv -f "$REFERENCES/$cible.txt.nouveau" "$REFERENCES/$cible.txt" ||
      exit 2
    echo "écrit : outils/caisses-fenetre/$cible.txt ($(wc -l <<<"$liste") caisses), à relire dans le diff"
  done
  exit "$CODE"
fi
(($# == 0)) || { echo "outils/caisses-fenetre.sh [--ecrire | --programmes <fenêtre Linux> <fenêtre Windows>]" >&2; exit 2; }

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
  en_plus=$(comm -13 <(printf '%s\n' "$attendue") <(printf '%s\n' "$liste"))
  en_moins=$(comm -23 <(printf '%s\n' "$attendue") <(printf '%s\n' "$liste"))
  if [[ -n $en_plus || -n $en_moins ]]; then
    echo "✖ $cible : $nombre caisses, l'arbre n'est plus celui de outils/caisses-fenetre/$cible.txt" \
      "($(wc -l <<<"$attendue")) :"
    montrer + "$en_plus"
    montrer - "$en_moins"
    echo "  Voulu : outils/caisses-fenetre.sh --ecrire, puis le diff relu (une caisse de plus se dit, avec sa raison)."
    CODE=1
  elif [[ -z $r ]]; then
    echo "✔ $cible : $nombre caisses, celles de outils/caisses-fenetre/$cible.txt, aucune retirée revenue"
  fi
done
exit "$CODE"
