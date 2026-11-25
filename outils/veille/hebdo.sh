#!/usr/bin/env bash
# La relecture de sécurité hebdomadaire de la veille continue (outils/veille/LISEZMOI.md), le vendredi à 05 h 30,
# après la nuit et le renouvellement du quota de la semaine : un claude -p en LECTURE SEULE relit, en adversaire, les
# commits de la semaine sur master (git log --since) et propose des adaptations à partir des signaux des nuits
# (KEV hors des logiciels suivis, RUSTSEC, Échap, fuzz, canaris). Le résultat va dans AAAA-MM-JJ-hebdo.md ; une
# proposition « évidente » peut lancer UNE correction par alerte.sh (même budget, même file).
#   hebdo.sh
set -uo pipefail
source "$(dirname "$0")/commun.sh"

# Les bibliothèques en retard de l'arbre de veille (outils/retards.py), ajoutées à la page de la semaine, IA ou non ;
# jamais montrées à l'IA. Le code 1 (épinglage sans raison, réponse illisible) et l'absence du script y sont dits.
ajouter_retards() {
  local lu code=0
  lu=$(mktemp) || return 0
  {
    printf '\n## Bibliothèques en retard\n\n'
    if [[ -f $ARBRE/outils/retards.py ]]; then
      timeout --kill-after=10 10m python3 -I "$ARBRE/outils/retards.py" >"$lu" 2>&1 </dev/null || code=$?
      # Seulement ses lignes, en bloc de code toujours refermé ; une coupure et un arrêt (délai) sont dits.
      printf '```\n'
      head -c 20000 "$lu" | tr -d '`' | iconv -c -f UTF-8 -t UTF-8
      printf '\n```\n'
      (($(stat -c %s "$lu") <= 20000)) || echo "Coupé : plus de 20 000 octets."
      case $code in
        0) ;;
        1) echo "À corriger ou non vérifiés : lignes ✖." ;;
        *) echo "Non vérifiés : retards.py arrêté avant la fin." ;;
      esac
    else
      echo "Non vérifiés : outils/retards.py absent de l'arbre de veille."
    fi
  } >>"$VEILLE/$JOUR-hebdo.md"
  rm -f "$lu"
}

[[ -e $VEILLE/COUPER-TOUT ]] && { journal "COUPER-TOUT présent : rien"; exit 0; }
# La nuit finit à 07 h 35 au plus tard (03 h 30, 5 min de hasard, 4 h) : attendue jusqu'à 07 h 40.
prendre_verrou 7800
REPORT=$(raison_de_reporter)
if [[ -n $REPORT ]]; then
  journal "relecture reportée : $REPORT"
  printf '# Relecture de sécurité de la semaine — %s\n\nReportée : %s\n\nBibliothèques en retard : pas cherchées cette semaine.\n' "$JOUR" "$REPORT" >"$VEILLE/$JOUR-hebdo.md"
  exit 0
fi
REFUS=$(refus_ia hebdo)
if [[ -n $REFUS ]]; then
  journal "pas de relecture hebdomadaire : $REFUS"
  printf '# Relecture de sécurité de la semaine — %s\n\nNon lancée : %s\n' "$JOUR" "$REFUS" >"$VEILLE/$JOUR-hebdo.md"
  ajouter_retards
  exit 0
fi
# L'arbre de veille, remis sur la base par la nuit ; lu seulement ici.
[[ -d $ARBRE ]] || { journal "arbre de veille absent : la nuit n'a jamais tourné"; exit 1; }

DOSSIER=$VEILLE/ia/$JOUR-hebdo
mkdir -p "$DOSSIER"
git -C "$DEPOT" log --since='7 days ago' --format=%H "$BASE" >"$DOSSIER/commits.txt"
python_rapport hebdo-entree --veille "$VEILLE" --jour "$JOUR" --base "$BASE" --commits "$DOSSIER/commits.txt" \
  "$DOSSIER/hebdo-entree.json" || exit 1
reglages_claude "$ARBRE" "$DOSSIER/reglages.json" 0 0
noter_lancement hebdo 0 "$TOURS_HEBDO" lance
journal "relecture hebdomadaire de $(wc -l <"$DOSSIER/commits.txt") commit(s)"
lancer_claude "$ARBRE" hebdo "$DOSSIER/hebdo-entree.json" "$DOSSIER/hebdo.json" "$DOSSIER/reglages.json" -- \
  "Read(./**)" "Glob" "Grep" "Bash(git diff *)" "Bash(git log *)" "Bash(git show *)"
journal "claude (hebdo) : code $?"
noter_quota_si_atteint "$DOSSIER/hebdo.json"
python_rapport hebdo "$DOSSIER" "$VEILLE/$JOUR-hebdo.md" >/dev/null
ajouter_retards

if [[ -f $DOSSIER/evidente.json && $(jq -r .sujet "$DOSSIER/evidente.json") =~ ^[a-z0-9][a-z0-9_-]{0,39}$ ]]; then
  REFUS=$(refus_ia correction)
  if [[ -z $REFUS ]]; then
    jq -n --arg j "$JOUR" --arg s "hebdo:$(jq -r .sujet "$DOSSIER/evidente.json")" \
      --arg t "$(git -C "$DEPOT" rev-parse "$BASE")" --arg e "$DOSSIER/evidente.json" \
      '{jour: $j, signature: $s, tete: $t, evidente: $e}' >"$VEILLE/alerte-demandee.json"
    exec 9>&-
    exec "$ICI/alerte.sh"
  fi
  printf '\nProposition évidente non lancée : %s\n' "$REFUS" >>"$VEILLE/$JOUR-hebdo.md"
fi
notifier "Vanguard veille" "Relecture de la semaine écrite : $VEILLE/$JOUR-hebdo.md"
