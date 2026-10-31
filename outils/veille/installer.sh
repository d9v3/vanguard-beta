#!/usr/bin/env bash
# Installe (ou réinstalle) la veille continue (outils/veille/LISEZMOI.md) sur le PC de développement : une copie FIGÉE
# de outils/veille/ à un commit donné, dans ~/.local/share/vanguard-veille/<sha>/ (« courante » pointe dessus), et les
# unités systemd de l'utilisateur qui la lancent. Figée parce que nuit.sh remet lui-même le worktree de veille sur
# master (un script bash changé pendant qu'il tourne se lit de travers) et qu'un commit sur master ne doit pas
# changer en silence ce qui tourne la nuit avec l'IA : le rapport dit quand outils/veille/ a changé depuis
# (« réinstaller »). Suit le modèle de outils/systemd/installer.sh.
#   outils/veille/installer.sh [révision]   copie outils/veille/ de la révision (master par défaut), active les
#                                           minuteries nuit (03 h 30), hebdo (vendredi 05 h 30) et matin (08 h 30)
#   outils/veille/installer.sh --retirer    retire les unités (la copie et les rapports restent)
# N'active rien d'autre : le worktree ~/Projects/vanguard-veille est créé par la première nuit.
set -euo pipefail
cd "$(dirname "$0")/../.."
UNITES="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DESTINATION=$HOME/.local/share/vanguard-veille
LISTE=(vanguard-veille-nuit.service vanguard-veille-nuit.timer vanguard-veille-alerte.service
  vanguard-veille-hebdo.service vanguard-veille-hebdo.timer vanguard-veille-matin.service vanguard-veille-matin.timer)

retirer() {
  local unite
  for unite in "${LISTE[@]}"; do
    systemctl --user disable --now "$unite" >/dev/null 2>&1 || true
    rm -f "$UNITES/$unite" "$UNITES"/*.wants/"$unite"
  done
  systemctl --user daemon-reload
}

if [[ ${1:-} == --retirer ]]; then
  retirer
  echo "Unités de la veille retirées. La copie ($DESTINATION) et les rapports (~/.cache/vanguard-dev/veille) restent."
  exit 0
fi

REVISION=${1:-master}
SHA=$(git rev-parse --verify "$REVISION^{commit}")
ARBRE_VEILLE=$(git rev-parse "$SHA:outils/veille")
COPIE=$DESTINATION/$SHA
if [[ ! -d $COPIE ]]; then
  mkdir -p "$COPIE.part"
  git archive "$SHA" outils/veille | tar -x -C "$COPIE.part" --strip-components=2
  echo "$SHA" >"$COPIE.part/.source"
  echo "$ARBRE_VEILLE" >"$COPIE.part/.arbre"
  # Lecture seule : la copie qui tourne ne change qu'en réinstallant.
  chmod -R a-w "$COPIE.part"
  mv "$COPIE.part" "$COPIE"
fi
ln -sfn "$SHA" "$DESTINATION/courante"

retirer
for unite in vanguard-veille-nuit.service vanguard-veille-alerte.service vanguard-veille-hebdo.service \
  vanguard-veille-matin.service; do
  systemctl --user link "$COPIE/systemd/$unite" >/dev/null
done
for minuterie in vanguard-veille-nuit.timer vanguard-veille-hebdo.timer vanguard-veille-matin.timer; do
  systemctl --user enable --now "$COPIE/systemd/$minuterie" >/dev/null
done
systemctl --user daemon-reload
echo "Veille installée depuis $REVISION ($SHA) : $COPIE"
echo "Minuteries : vanguard-veille-nuit (03 h 30), vanguard-veille-hebdo (vendredi 05 h 30), vanguard-veille-matin (08 h 30)."
echo "Couper l'IA : touch ~/.cache/vanguard-dev/veille/COUPER-IA ; tout couper : COUPER-TOUT, ou --retirer."
