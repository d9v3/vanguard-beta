#!/usr/bin/env bash
# Les outils de compilation qui font les octets des programmes publiés en dehors de la chaîne Rust, une ligne
# « nom=valeur » chacun, toujours dans le même ordre. Mesuré à la 0.91.0 (CONTRIBUTING.md, « Compilation
# reproductible ») : la chaîne Rust est la même ici et dans la CI, mais pas ceux-ci, et c'est eux qui font différer
# les empreintes d'Arch (ici) et d'Ubuntu (CI) :
#   - Linux : gcc, par musl-gcc, compile le C de ring et de blake3, et en garde le nom dans la section .comment du
#     programme (« GCC: (GNU) 16.2.1 » contre « GCC: (Ubuntu 15.2.0-16ubuntu1) ») ; gcc et ld le lient ;
#   - Windows : gcc et ld de MinGW compilent ce C et lient le .exe (version de l'éditeur de liens gravée dans l'en-tête
#     PE), et la bibliothèque libmsvcrt.a de mingw-w64 choisit le runtime C que le .exe importe : msvcrt.dll sous
#     Ubuntu, les DLL api-ms-win-crt-* (UCRT) sous Arch, pour le même -lmsvcrt de rustc.
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

ligne rustc "$(rustc --version 2>/dev/null | propre)"
# L'éditeur de liens de la cible musl : rustc appelle « cc », qui appelle ld.
ligne cc "$(cc --version 2>/dev/null | propre)"
ligne ld "$(ld --version 2>/dev/null | propre)"
# musl-gcc est un petit script qui lance gcc (REALGCC, ou celui qu'il nomme) avec le fichier de spécifications de
# musl ; la bibliothèque musl est à côté de ce fichier, et dit sa version quand on la lance.
MUSL_GCC=$(command -v musl-gcc 2>/dev/null || true)
REEL= SPECS=
if [[ -n $MUSL_GCC ]]; then
  REEL=$(sed -n 's/.*exec "\${REALGCC:-\([^}]*\)}".*/\1/p' "$MUSL_GCC" | head -n 1)
  SPECS=$(grep -oE -- '-specs "?[^" ]+' "$MUSL_GCC" | head -n 1 | sed 's/^-specs "\{0,1\}//')
fi
ligne musl-gcc "$([[ -n $REEL ]] && "$REEL" --version 2>/dev/null | propre)"
ligne musl "$([[ -n $SPECS && -x ${SPECS%/*}/libc.so ]] && "${SPECS%/*}/libc.so" 2>&1 | sed -n 's/^Version //p' | propre)"
ligne mingw-gcc "$(x86_64-w64-mingw32-gcc --version 2>/dev/null | propre)"
ligne mingw-fils "$(x86_64-w64-mingw32-gcc -v 2>&1 | sed -n 's/^Thread model: //p' | propre)"
ligne mingw-ld "$(x86_64-w64-mingw32-ld --version 2>/dev/null | propre)"
ligne mingw-w64 "$(printf '#include <_mingw.h>\n' | x86_64-w64-mingw32-gcc -dM -E -x c - 2>/dev/null |
  awk '$2 == "__MINGW64_VERSION_MAJOR" { a = $3 } $2 == "__MINGW64_VERSION_MINOR" { b = $3 }
    $2 == "__MINGW64_VERSION_BUGFIX" { c = $3 } END { if (a != "") print a "." b "." c }' | propre)"
# Le runtime C que lie -lmsvcrt : les noms de DLL que la bibliothèque d'importation contient.
MSVCRT=$(x86_64-w64-mingw32-gcc -print-file-name=libmsvcrt.a 2>/dev/null || true)
RUNTIME=
if [[ -f $MSVCRT ]]; then
  if grep -aqi 'api-ms-win-crt-' "$MSVCRT"; then
    RUNTIME=ucrt
  elif grep -aqi 'msvcrt\.dll' "$MSVCRT"; then
    RUNTIME=msvcrt
  fi
fi
ligne mingw-runtime "$RUNTIME"
