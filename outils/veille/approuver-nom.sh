#!/usr/bin/env bash
# Approuver un nom de logiciel vu par la flotte (outils/veille/LISEZMOI.md, « Envois ») : seul chemin par lequel un
# nom venu d'un ordinateur peut atteindre l'IA de nuit. Sans approbation, l'IA ne voit que `inconnu#<empreinte>`.
#   outils/veille/approuver-nom.sh <empreinte>     (16 chiffres hexadécimaux, avec ou sans « inconnu# » ou « # »)
# Le nom est montré tel que `affichable()` le rend (sans séquence de terminal ni balise) ; il n'est ajouté à
# noms-connus.txt (à côté de ce script, dans le dépôt) que si l'auteur répond « oui » sur un terminal. Sans terminal :
# refusé, jamais par un tube ni par un programme. Ensuite : committer noms-connus.txt et réinstaller la veille
# (installer.sh), qui ne lit que sa copie figée.
set -uo pipefail
ICI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RETOURS=${VANGUARD_VEILLE_RETOURS:-${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/retours}
NOMS=$ICI/noms-connus.txt
VUS=$RETOURS/tickets/noms-vus.json

(($# == 1)) || { echo "usage : approuver-nom.sh <empreinte>" >&2; exit 2; }
EMPREINTE=${1#inconnu}
EMPREINTE=${EMPREINTE#\#}
[[ $EMPREINTE =~ ^[0-9a-f]{16}$ ]] || { echo "empreinte illisible : 16 chiffres hexadécimaux attendus" >&2; exit 2; }
# Un humain devant un terminal, à l'entrée comme à la sortie : ni tube, ni programme qui répondrait « oui ».
[[ -t 0 && -t 1 ]] || { echo "refusé : approuver un nom demande un terminal (l'auteur, pas un programme)" >&2; exit 1; }
[[ -f $VUS && ! -L $VUS ]] || { echo "aucun nom vu ($VUS absent) : attendre une nuit de la veille" >&2; exit 1; }

NOM=$(python3 -I "$ICI/rapport.py" nom-vu "$VUS" "$EMPREINTE")
code=$?
case $code in
  0) ;;
  2) printf 'Nom vu : %s\n' "$NOM"; echo "refusé : ce nom a des caractères qui ne s'affichent pas tels quels" >&2; exit 1 ;;
  *) exit 1 ;;
esac
if grep -qxF -- "$NOM" "$NOMS" 2>/dev/null; then
  echo "déjà approuvé : $NOM"
  exit 0
fi
printf 'Nom vu sous inconnu#%s : %s\n' "$EMPREINTE" "$NOM"
echo "Ce nom vient d'ordinateurs que vous ne connaissez pas : l'approuver le montrera tel quel à l'IA de nuit."
read -r -p "L'approuver ? (oui/non) " reponse
[[ $reponse == oui ]] || { echo "rien n'est changé"; exit 1; }
[[ -w $NOMS || ( ! -e $NOMS && -w $ICI ) ]] ||
  { echo "refusé : $NOMS n'est pas modifiable (lancer le script du dépôt, pas la copie installée)" >&2; exit 1; }
printf '%s\n' "$NOM" >>"$NOMS"
echo "Ajouté à $NOMS : le committer, puis réinstaller la veille (outils/veille/installer.sh)."
