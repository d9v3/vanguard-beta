#!/usr/bin/env bash
# Captures de la fenêtre (vanguard-fenetre) en PNG, sans fenêtre ni écran : chaque écran (accueil, bilan, alertes,
# appareils, chaque rubrique, une page de commande, guide), en français et en anglais, sombre et clair, en 1280×800 et
# 1920×1080 ; puis les images clés de l'ouverture (ouverture/). egui dessine comme d'habitude et un rendu logiciel
# des essais (fenetre/src/dessin/captures.rs) remplit ses triangles : aucune carte graphique, aucun bureau, rien de
# l'écran n'est lu ; rien n'est lancé (le programme des essais est un faux chemin, refusé avant tout lancement).
# Données inventées. Sortie hors du dépôt : ~/.cache/vanguard-dev/captures-fenetre/ (VANGUARD_CAPTURES pour un autre
# dossier). Un seul fil : la langue et le thème sont ceux de tout le programme d'essai.
#   outils/captures-fenetre.sh
set -euo pipefail
cd "$(dirname "$0")/../fenetre"
export VANGUARD_CAPTURES=${VANGUARD_CAPTURES:-$HOME/.cache/vanguard-dev/captures-fenetre}
# Optimisé : le rendu logiciel de 152 images prend quelques secondes, plusieurs minutes sans.
cargo test -q --locked --release --bin vanguard-fenetre dessin::captures::captures -- --ignored --exact \
    --test-threads=1 --nocapture
