#!/usr/bin/env bash
# Installe (ou réinstalle) sur le PC de développement les unités systemd de l'utilisateur qui tiennent la clé USB à
# jour : vanguard-compilation.path (après chaque compilation) lance vanguard-copie.service, et vanguard-cle.service part
# au branchement de la clé. Les images Linux de la clé (outils/images-cle.sh) : vanguard-images.timer les cherche le
# 1er et le 15 du mois (et les copie aussitôt si la clé est branchée), vanguard-images-cle.service les copie au
# branchement ; seulement sur un ordinateur dont le réglage local demande la clé de secours (CLE_SECOURS=oui, voir
# images-cle.sh) : sans lui, ces unités ne copient rien.
# vanguard-cle-maj.timer remet chaque jour la clé restée branchée à jour (outils/maj-cle.sh : programme et images).
# vanguard-menage.timer fait chaque semaine le ménage des fichiers de développement devenus inutiles
# (outils/menage-dev.sh).
#   outils/systemd/installer.sh
set -euo pipefail
cd "$(dirname "$0")"
UNITES="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
# Les unités lancent %h/Projects/vanguard/outils/deployer.sh (%h : dossier personnel) : le dépôt doit être là.
if [[ $(cd ../.. && pwd -P) != $(cd "$HOME/Projects/vanguard" 2>/dev/null && pwd -P) ]]; then
  echo "Attention : les unités lancent ~/Projects/vanguard/outils/deployer.sh, pas celui de $(cd ../.. && pwd)." >&2
fi

# Réinstallation (dépôt déplacé, unités changées) : les liens d'avant sont retirés, puis refaits.
for unite in vanguard-copie.service vanguard-cle.service vanguard-compilation.path vanguard-images.service \
  vanguard-images.timer vanguard-images-cle.service vanguard-cle-maj.service vanguard-cle-maj.timer \
  vanguard-menage.service vanguard-menage.timer; do
  systemctl --user disable "$unite" >/dev/null 2>&1 || true
  rm -f "$UNITES/$unite" "$UNITES"/*.wants/"$unite"
done
systemctl --user link "$PWD/vanguard-copie.service" >/dev/null
systemctl --user enable "$PWD/vanguard-cle.service" >/dev/null
systemctl --user enable --now "$PWD/vanguard-compilation.path" >/dev/null
systemctl --user link "$PWD/vanguard-images.service" >/dev/null
systemctl --user enable --now "$PWD/vanguard-images.timer" >/dev/null
systemctl --user enable "$PWD/vanguard-images-cle.service" >/dev/null
systemctl --user link "$PWD/vanguard-cle-maj.service" >/dev/null
systemctl --user enable --now "$PWD/vanguard-cle-maj.timer" >/dev/null
systemctl --user link "$PWD/vanguard-menage.service" >/dev/null
systemctl --user enable --now "$PWD/vanguard-menage.timer" >/dev/null
systemctl --user daemon-reload
echo "Unités installées : vanguard-compilation.path, vanguard-copie.service, vanguard-cle.service, vanguard-images.timer,"
echo "vanguard-images.service, vanguard-images-cle.service, vanguard-cle-maj.timer, vanguard-cle-maj.service,"
echo "vanguard-menage.timer, vanguard-menage.service."
