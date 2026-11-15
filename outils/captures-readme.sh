#!/usr/bin/env bash
# Captures du README (assets/captures/fenetre-*.png, en français et en anglais) et image de partage du dépôt
# (assets/partage.png), prises dans la fenêtre : outils/captures-fenetre.sh les dessine sans écran ni carte graphique,
# sur des données inventées, rien de l'ordinateur n'est lu. Ce script en garde quelques-unes (thème sombre,
# 1280×800) sous un nom stable, puis fait l'image de partage (1280×640, le haut de l'accueil en anglais).
# outils/deployer.sh le lance pour chaque version publiée ; il faut Pillow (python-pillow).
#   outils/captures-readme.sh            refait tout (rendu, puis copie)
#   outils/captures-readme.sh DOSSIER    copie seulement, depuis les captures déjà faites dans DOSSIER
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# écran de captures-fenetre.sh (français, anglais) → nom dans assets/captures (fenetre-<nom>[-en].png)
ECRANS=(
  "bilan bilan bilan"
  "accueil accueil accueil"
  "alertes alertes alertes"
  "appareils appareils appareils"
  "commande-connexions-sortantes commande-connexions-sortantes connexions"
  "guide guide guide"
)

if (($# > 1)); then
  echo "usage : outils/captures-readme.sh [DOSSIER]" >&2
  exit 2
fi
TRAVAIL=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/captures-readme.XXXXXX")
trap 'rm -rf -- "$TRAVAIL"' EXIT
if (($# == 1)); then
  SOURCE=$1
else
  SOURCE=$TRAVAIL/rendu
  VANGUARD_CAPTURES=$SOURCE bash outils/captures-fenetre.sh >/dev/null
fi

# Tout est vérifié avant la première copie : une capture manquante ne laisse pas un README à moitié refait.
SORTIE=$TRAVAIL/sortie
mkdir -p "$SORTIE"
for ligne in "${ECRANS[@]}"; do
  read -r fr en nom <<<"$ligne"
  for paire in "$fr-fr:fenetre-$nom" "$en-en:fenetre-$nom-en"; do
    f=$SOURCE/${paire%%:*}-sombre-1280x800.png
    [[ -f $f && ! -L $f ]] || { echo "✖ capture absente : $f" >&2; exit 1; }
    cp -- "$f" "$SORTIE/${paire#*:}.png"
  done
done
python3 -I - "$SOURCE/accueil-en-sombre-1280x800.png" "$SORTIE/partage.png" <<'PY'
import sys
from PIL import Image

with Image.open(sys.argv[1]) as image:
    if image.size != (1280, 800):
        sys.exit(f"✖ {sys.argv[1]} : {image.size}, attendu (1280, 800)")
    image.crop((0, 0, 1280, 640)).save(sys.argv[2], optimize=True)
PY

mkdir -p assets/captures
for f in "$SORTIE"/fenetre-*.png; do
  cp -- "$f" "assets/captures/${f##*/}"
done
cp -- "$SORTIE/partage.png" assets/partage.png
# outils/deployer.sh ne les refait pas deux fois pour la même version.
sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1 >assets/captures/VERSION
echo "Captures du README refaites : ${#ECRANS[@]} écrans × 2 langues, et assets/partage.png."
