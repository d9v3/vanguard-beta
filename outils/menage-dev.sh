#!/usr/bin/env bash
# Ménage des fichiers de développement devenus inutiles, chaque semaine (vanguard-menage.timer) : seulement ce qui se
# recrée tout seul ou ne sert plus, jamais ce qui a de la valeur (images et sauvegardes de la clé, outils, brouillons,
# equipe.md, historique des tests de la VM).
#   outils/menage-dev.sh          faire le ménage
#   outils/menage-dev.sh --voir   dire ce qui partirait, sans rien effacer
set -euo pipefail

VOIR=
[[ ${1:-} == --voir ]] && VOIR=1
DEV=${XDG_CACHE_HOME:-$HOME/.cache}/vanguard-dev
IMAGES=${XDG_CACHE_HOME:-$HOME/.cache}/vanguard/images-cle
VM=$HOME/Windows/VANGUARD-TEST/resultats
# Un dossier de compilation inutilisé depuis ce temps se recompile en quelques minutes au besoin.
JOURS_COMPILATION=14
# Les passes de la VM : les plus récentes restent toujours, les autres partent après ce temps.
JOURS_VM=30
PASSES_GARDEES=20
# Un torrent en cours (Kali, outils/images-cle.sh) reprend à la recherche suivante, qui peut ne venir que dans quinze
# jours : gardé tant qu'il a avancé depuis moins de ce temps.
JOURS_TORRENT=30

libere=0
retires=0
retirer() { # chemin raison
  local ko
  ko=$(du -sk "$1" 2>/dev/null | cut -f1)
  ko=${ko:-0}
  if ((ko >= 1048576)); then printf '  %5s Go  %s (%s)\n' $((ko / 1048576)) "$1" "$2"; else printf '  %5s Mo  %s (%s)\n' $((ko / 1024)) "$1" "$2"; fi
  # --one-file-system : jamais à travers un montage qui se serait glissé dedans.
  [[ -n $VOIR ]] || rm -rf --one-file-system -- "$1"
  libere=$((libere + ko))
  retires=$((retires + 1))
}

# Jours depuis la dernière activité d'un dossier : le plus récent sur trois niveaux (cargo n'écrit qu'au fond ; avec
# --target, seul <triplet>/<profil>/deps, au troisième, change de date à chaque compilation).
inactif_depuis() {
  local plus
  plus=$(find "$1" -maxdepth 3 -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
  echo $((($(date +%s) - ${plus%.*}) / 86400))
}

# Dossiers de compilation (target-<session>, target-mesure, repro-target…) : inutilisés depuis 14 jours.
for d in "$DEV"/target-* "$DEV"/repro-target; do
  [[ -d $d && ! -L $d ]] || continue
  j=$(inactif_depuis "$d")
  ((j >= JOURS_COMPILATION)) && retirer "$d" "compilation inutilisée depuis $j jours, se recrée"
done

# Les autres dossiers de compilation, où qu'ils soient dans les deux premiers niveaux (une-fenetre/cible-attaque…) : le
# CACHEDIR.TAG que cargo y écrit dit que tout s'y recrée ; aucun autre dossier n'est touché. Même délai. Un outil
# compilé là pour servir (un dossier « …-install ») est gardé : le recréer demande de le retélécharger.
for tag in "$DEV"/*/CACHEDIR.TAG "$DEV"/*/*/CACHEDIR.TAG; do
  d=${tag%/*}
  [[ -f $tag && ! -L $tag && ! -L $d && ! -L ${d%/*} && $d != *-install &&
    $d != "$DEV"/target-* && $d != "$DEV"/repro-target ]] || continue
  grep -q '^# This file is a cache directory tag created by cargo\.$' "$tag" || continue
  # Dans un dossier lui-même de compilation (une cible de plus) : retiré avec lui, ou gardé avec lui.
  [[ ! -e ${d%/*}/CACHEDIR.TAG ]] || continue
  j=$(inactif_depuis "$d")
  ((j >= JOURS_COMPILATION)) && retirer "$d" "compilation inutilisée depuis $j jours, se recrée"
done

# Journaux d'échec de verifier.sh, un dossier par arbre : plus de 30 jours.
for d in "$DEV"/verifier-echecs/*; do
  [[ -e $d && ! -L $d && -n $(find "$d" -maxdepth 0 -mtime +29 2>/dev/null) ]] || continue
  retirer "$d" "journaux d'une vérification d'il y a plus de 30 jours"
done

# Restes d'essais interrompus (verifier.sh, essais en pty, signatures d'essai, un --importer tué…) : plus d'un jour.
# Sauf un torrent en cours (son .torrent et l'image commencée) : effacé, il repartirait de zéro, et une image de 16 Gio
# qui ne se prend pas en une seule passe de 5 heures ne finirait jamais.
for d in "$DEV"/verifier.* "$DEV"/essai-* "$DEV"/maison-* "$DEV"/vecteur.* "$DEV"/depot-versions.* \
  "$IMAGES"/.nouveau-* "$IMAGES"/.import-* "$IMAGES"/.trousseau.* "$IMAGES"/.verification.*; do
  [[ -e $d && ! -L $d ]] || continue
  if [[ $d == "$IMAGES"/.nouveau-* && -n $(find "$d" -maxdepth 1 -name '*.torrent' -print -quit 2>/dev/null) &&
    -n $(find "$d" -maxdepth 1 -name '*.iso' -size +0 -print -quit 2>/dev/null) ]]; then
    j=$(inactif_depuis "$d")
    ((j >= JOURS_TORRENT)) && retirer "$d" "torrent arrêté depuis $j jours, que rien ne reprendra"
    continue
  fi
  [[ -n $(find "$d" -maxdepth 0 -mtime +0 2>/dev/null) ]] && retirer "$d" "reste d'un essai ou d'un téléchargement interrompu"
done

# Passes de la VM : les 20 plus récentes restent ; les autres partent après 30 jours. historique.txt et
# dernier-rapport.html restent toujours.
if [[ -d $VM ]]; then
  mapfile -t passes < <(find "$VM" -mindepth 1 -maxdepth 1 -type d -name '20*' -printf '%f\n' | sort -r)
  for ((i = PASSES_GARDEES; i < ${#passes[@]}; i++)); do
    d=$VM/${passes[i]}
    [[ -n $(find "$d" -maxdepth 0 -mtime +$((JOURS_VM - 1)) 2>/dev/null) ]] && retirer "$d" "passe de la VM de plus de $JOURS_VM jours"
  done
fi

if ((retires == 0)); then
  echo "Rien à effacer."
  exit 0
fi
total=$(awk -v k="$libere" 'BEGIN { if (k >= 1048576) printf "%.1f Go", k / 1048576; else printf "%d Mo", k / 1024 }')
if [[ -n $VOIR ]]; then
  echo "$retires élément(s), $total : rien n'a été effacé (--voir)."
else
  echo "$retires élément(s) effacé(s), $total libérés."
  # Prévenu seulement quand ça vaut la peine.
  ((libere >= 1048576)) && command -v notify-send >/dev/null &&
    notify-send -a Vanguard -i vanguard "Ménage du développement" "$total libérés ($retires élément(s))." || true
fi
