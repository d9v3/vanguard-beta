#!/usr/bin/env bash
# Les outils de compilation qui font les octets des programmes publiés en dehors de la chaîne Rust, une ligne
# « nom=valeur » chacun, toujours dans le même ordre. Mesuré à la 0.91.0 (CONTRIBUTING.md, « Compilation
# reproductible ») : la chaîne Rust était la même ici et dans la CI, mais pas la chaîne C de la distribution (gcc, ld,
# musl, mingw-w64), qui faisait différer les empreintes d'Arch (ici) et d'Ubuntu (CI), jusqu'au runtime C du .exe.
# Depuis, outils/compiler-version.sh compile le C, lie les deux programmes, fournit leur bibliothèque C, compile les
# ressources du .exe (zig rc) et ses bibliothèques d'import (zig dlltool) par zig, épinglé et vérifié
# (outils/chaine-zig.sh), par cargo-zigbuild : plus rien de la distribution. Restent relevés :
#   - rustc, zig et cargo-zigbuild : ceux du dossier de outils/chaine-zig.sh (VANGUARD_CHAINE_ZIG, sinon
#     ~/.cache/vanguard-dev/chaine-zig), ou à défaut ceux du PATH ; ce script ne pose rien ;
#   - cargo-auditable, qui écrit la liste des dépendances dans chaque programme : sa version, lue dans le programme
#     même (le chemin de sa source, « cargo-auditable-X.Y.Z/src/ », gardé pour ses messages d'erreur, quand il a été
#     posé par cargo install), sinon « inconnue ».
# Écrit par outils/compiler-version.sh dans son repère (lignes « outil … ») et par la CI dans son journal
# (OUTILS-VANGUARD …) ; outils/publier-version.sh montre ceux qui diffèrent quand les empreintes diffèrent. Ne décide
# rien : seule l'égalité des empreintes compte. Un outil absent : « absent ».
#   outils/chaine-c.sh
set -uo pipefail
# Depuis le dépôt : rustup y prend la chaîne de rust-toolchain.toml.
cd "$(dirname "$0")/.." || exit 1
export LC_ALL=C

# La première ligne de la sortie, réduite à des caractères sûrs (elle passe dans un journal, puis à un terminal).
propre() { head -n 1 | tr -cd 'A-Za-z0-9 ._:+()/,~-' | cut -c1-120; }
ligne() { # nom, valeur
  printf '%s=%s\n' "$1" "${2:-absent}"
}
# Un outil de la chaîne de zig : celui de son dossier, sinon celui du PATH.
outil_zig() { # nom
  local dans=${VANGUARD_CHAINE_ZIG:-$HOME/.cache/vanguard-dev/chaine-zig}/bin/$1
  if [[ -x $dans ]]; then echo "$dans"; else command -v "$1" 2>/dev/null; fi
}

ligne rustc "$(rustc --version 2>/dev/null | propre)"
ZIG=$(outil_zig zig)
ligne zig "$([[ -n $ZIG ]] && "$ZIG" version 2>/dev/null | propre)"
ZIGBUILD=$(outil_zig cargo-zigbuild)
ligne cargo-zigbuild "$([[ -n $ZIGBUILD ]] && "$ZIGBUILD" --version 2>/dev/null | propre)"
AUDITABLE=$(command -v cargo-auditable 2>/dev/null)
VERSIONS=$([[ -n $AUDITABLE ]] && grep -aoE 'cargo-auditable-[0-9]+\.[0-9]+\.[0-9]+/src/' "$AUDITABLE" | sort -u)
if [[ -z $AUDITABLE ]]; then
  ligne cargo-auditable absent
elif [[ $(wc -l <<<"$VERSIONS") -eq 1 && -n $VERSIONS ]]; then
  VERSIONS=${VERSIONS#cargo-auditable-}
  ligne cargo-auditable "${VERSIONS%/src/}"
else
  ligne cargo-auditable inconnue
fi
