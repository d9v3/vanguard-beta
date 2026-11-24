#!/bin/sh
# Lancé par GNOME au branchement de la clé (après accord : « Lancer le logiciel ? »), ou à la main.
# Vanguard ouvre sa fenêtre sur un bureau graphique, sinon son menu : il part d'un terminal dans les deux cas.
# Lancé hors du dossier de la clé : sur un autre ordinateur, Vanguard la remonte en lecture seule, ce qui est
# impossible si un terminal y est ouvert.
VANGUARD="$(cd "$(dirname "$0")" && pwd)/Linux/vanguard"
cd "$HOME" || cd /
for t in xdg-terminal-exec ptyxis kgx gnome-terminal konsole xfce4-terminal mate-terminal lxterminal qterminal tilix \
  alacritty kitty foot ghostty wezterm x-terminal-emulator xterm; do
  command -v "$t" >/dev/null || continue
  case $t in
    gnome-terminal | ptyxis) exec "$t" -- "$VANGUARD" ;;
    wezterm) exec wezterm start -- "$VANGUARD" ;;
    kitty | foot) exec "$t" "$VANGUARD" ;;
    *) exec "$t" -e "$VANGUARD" ;;
  esac
done
# Aucun terminal trouvé : lancé d'un bureau, rien ne se verrait ; c'est dit.
if [ ! -t 1 ]; then
  MSG="Aucun terminal trouvé. Ouvrez-en un, puis tapez : / No terminal found. Open one, then type: $VANGUARD"
  zenity --info --no-markup --title=Vanguard --text="$MSG" 2>/dev/null || notify-send Vanguard "$MSG" 2>/dev/null
fi
exec "$VANGUARD"
