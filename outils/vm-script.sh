#!/usr/bin/env bash
# Dépose un script PowerShell dans la machine virtuelle Windows de test, qui le lance elle-même : sans droits
# administrateur, dans les 5 minutes, si son menu des tests a accepté les scripts déposés depuis Linux (choix 7).
# Sa sortie revient dans resultats/<date>_script-<nom>/ (sortie.txt, FINI.txt avec le code).
#   outils/vm-script.sh essai.ps1             dépose, et rend la main
#   outils/vm-script.sh --attendre essai.ps1  attend la fin (20 min au plus) et montre la sortie
# Personne ne tape dans la VM à la place de l'utilisateur : les touches envoyées d'ici n'arrivent pas à Windows.
set -euo pipefail
ATTENDRE=
[[ ${1:-} == --attendre ]] && { ATTENDRE=1; shift; }
SCRIPT=${1:?usage : outils/vm-script.sh [--attendre] <script.ps1>}
[[ $SCRIPT == *.ps1 && -f $SCRIPT ]] || { echo "Pas un script .ps1 : $SCRIPT" >&2; exit 1; }
VM="$HOME/Windows/VANGUARD-TEST"
[[ -d $VM ]] || { echo "Dossier de la VM absent : $VM" >&2; exit 1; }
mkdir -p "$VM/a-lancer"
NOM=$(basename "$SCRIPT")
# PowerShell 5.1 lit en ANSI un script sans BOM : les accents casseraient. Le BOM est ajouté s'il manque.
if [[ $(head -c3 "$SCRIPT" | od -An -tx1 | tr -d ' ') == efbbbf ]]; then
  cp -f "$SCRIPT" "$VM/a-lancer/$NOM"
else
  { printf '\xef\xbb\xbf'; cat "$SCRIPT"; } >"$VM/a-lancer/$NOM"
fi
DEPOT=$(date +%s)
echo "Déposé : a-lancer/$NOM (lancé dans les 5 minutes si le choix 7 du menu des tests est accepté)."
[[ -n $ATTENDRE ]] || exit 0
# Le dossier du résultat porte la date de Windows : on prend le plus récent pour ce nom, plus jeune que le dépôt.
for _ in $(seq 240); do
  # shellcheck disable=SC2045 # ls -t : le plus récent d'abord, l'ordre compte
  for d in $(ls -dt "$VM"/resultats/*_script-"${NOM%.ps1}" 2>/dev/null); do
    if [[ -f $d/FINI.txt && $(stat -c %Y "$d/FINI.txt") -ge $DEPOT ]]; then
      echo "== $(basename "$d") : $(tr -d '\r' <"$d/FINI.txt" | sed '1s/^\xef\xbb\xbf//')"
      tr -d '\r' <"$d/sortie.txt" | sed '1s/^\xef\xbb\xbf//'
      exit 0
    fi
  done
  sleep 5
done
if [[ -f $VM/a-lancer/$NOM ]]; then
  echo "Pas lancé au bout de 20 min : le choix 7 du menu des tests est-il accepté (et le 6 activé) ?" >&2
else
  echo "Pris par la VM mais pas fini au bout de 20 min." >&2
fi
exit 1
