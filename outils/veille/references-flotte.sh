#!/usr/bin/env bash
# Les références de la lecture des envois (vanguard compte-rendu flotte --references) tirées de l'arbre de la veille :
# un lot n'est cru que s'il parle d'une version publiée, et seulement des règles, outils et fichiers qu'elle avait.
#   references-flotte.sh <arbre> <sortie>
# <sortie>/versions.tsv : « X.Y.Z<TAB>AAAA-MM-JJ » par étiquette vX.Y.Z (date de l'étiquette, en UTC) ;
# <sortie>/<X.Y.Z>/{regles,outils,fichiers}.txt pour les versions des trois mineures les plus récentes :
#   regles.txt    les identifiants de tests/regles-connues.txt à l'étiquette, sans ceux marqués « retire » ;
#   outils.txt    les `commande: "…"` non vides de src/main.rs et src/menu/outils.rs (après la 0.93.0) à l'étiquette ;
#   fichiers.txt  les fichiers suivis sous src/ à l'étiquette.
# Une version dont une source manque n'a pas de dossier : ses lots sont refusés « sans référence », comptés.
# Seules les étiquettes au motif exact sont lues ; chaque ligne écrite passe le motif que le programme revérifie.
set -uo pipefail
# Les motifs en octets : une plage comme [!-~] dépend sinon de la langue du système.
export LC_ALL=C
(($# == 2)) || { echo "usage : references-flotte.sh <arbre> <sortie>" >&2; exit 2; }
ARBRE=$1 SORTIE=$2
rm -rf -- "${SORTIE:?}" && mkdir -p -- "$SORTIE" || exit 1

TZ=UTC git -C "$ARBRE" for-each-ref 'refs/tags/v*' \
  --format='%(refname:strip=2)%09%(creatordate:format-local:%Y-%m-%d)' |
  sed -nE 's/^v((0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2}))\t([0-9]{4}-[0-9]{2}-[0-9]{2})$/\1\t\5/p' |
  sort -V >"$SORTIE/versions.tsv"
[[ -s $SORTIE/versions.tsv ]] || { echo "aucune étiquette vX.Y.Z dans $ARBRE" >&2; exit 1; }

mapfile -t mineures < <(cut -f1 "$SORTIE/versions.tsv" | cut -d. -f1,2 | sort -uV | tail -n3)
while IFS=$'\t' read -r v _; do
  m=${v%.*}
  printf '%s\n' "${mineures[@]}" | grep -qxF -- "$m" || continue
  d=$SORTIE/$v
  mkdir -p -- "$d"
  if git -C "$ARBRE" show "v$v:tests/regles-connues.txt" 2>/dev/null |
    awk '!/^#/ && NF && $0 !~ /(^|[ \t])retire([ \t]|$)/ { print $1 }' |
    grep -E '^[A-Z]{3}-[A-Z]{3}-[0-9]{3}$' | sort -u >"$d/regles.txt" &&
    { git -C "$ARBRE" show "v$v:src/main.rs" && { git -C "$ARBRE" show "v$v:src/menu/outils.rs" || true; }; } 2>/dev/null | grep -oE 'commande: "[a-z][a-z0-9-]{0,30}[a-z0-9]?"' |
    sed -E 's/^commande: "(.*)"$/\1/' | grep -E '^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$' | sort -u >"$d/outils.txt" &&
    git -C "$ARBRE" ls-tree -r --name-only "v$v" -- src 2>/dev/null | grep -E '^src/[[:graph:]]{1,296}$' | sort -u \
      >"$d/fichiers.txt" &&
    [[ -s $d/regles.txt && -s $d/outils.txt && -s $d/fichiers.txt ]]; then
    :
  else
    rm -rf -- "${d:?}"
    echo "v$v : une source manque, pas de référence" >&2
  fi
done <"$SORTIE/versions.tsv"
echo "références : $(wc -l <"$SORTIE/versions.tsv") version(s), mineures ${mineures[*]}"
