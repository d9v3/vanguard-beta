#!/usr/bin/env bash
# Les outils de compilation qui font les octets des programmes publiés en dehors de la chaîne Rust, une ligne
# « nom=valeur » chacun, toujours dans le même ordre. Mesuré à la 0.91.0 (CONTRIBUTING.md, « Compilation
# reproductible ») : la chaîne Rust était la même ici et dans la CI, mais pas la chaîne C de la distribution (gcc, ld,
# musl, mingw-w64), qui faisait différer les empreintes d'Arch (ici) et d'Ubuntu (CI), jusqu'au runtime C du .exe.
# Depuis, outils/compiler-version.sh compile le C, lie les deux programmes et fournit leur bibliothèque C par zig, épinglé
# et vérifié (outils/chaine-zig.sh), par cargo-zigbuild. Restent relevés :
#   - rustc, zig et cargo-zigbuild : ceux du dossier de outils/chaine-zig.sh (VANGUARD_CHAINE_ZIG, sinon
#     ~/.cache/vanguard-dev/chaine-zig), ou à défaut ceux du PATH ; ce script ne pose rien ;
#   - windres de MinGW, encore celui de la distribution : il compile les ressources du .exe (icône, version,
#     manifeste, build.rs par winresource) après les avoir passées au préprocesseur du gcc de MinGW (windres-cpp).
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
ligne windres "$(x86_64-w64-mingw32-windres --version 2>/dev/null | propre)"
ligne windres-cpp "$(x86_64-w64-mingw32-gcc --version 2>/dev/null | propre)"
