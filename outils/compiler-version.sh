#!/usr/bin/env bash
# Compile les deux programmes publiés d'ici (Linux statique musl, Windows MinGW), toujours de la même façon :
# outils/deployer.sh avant chaque déploiement, la CI pour sa compilation reproductible (.github/workflows/ci.yml), et
# quiconque veut refaire un programme publié à partir de son étiquette. Une seule recette, pour que deux compilations
# du même code donnent les mêmes octets :
#   - la chaîne Rust de rust-toolchain.toml (rustup la pose d'elle-même), cargo-auditable dans la version de la CI ;
#   - Cargo.lock tel quel (--locked) ;
#   - les chemins de la compilation retirés des programmes : le dossier du dépôt devient /vanguard et celui de cargo
#     (CARGO_HOME, bibliothèques téléchargées) /cargo. Sans cela, ils gardent /home/<compte>/… ou /home/runner/…, et
#     le même code compilé dans deux dossiers donne deux programmes (et un nom de compte publié avec chaque version).
#     RUSTFLAGS remplace les rustflags d'un ~/.cargo/config.toml personnel : seuls ceux-ci comptent ;
#   - la date gravée est celle du commit (build.rs), jamais l'heure de la compilation ; l'éditeur de liens de MinGW
#     n'écrit pas l'heure dans l'en-tête PE (--no-insert-timestamp, build.rs).
# Ce qui peut encore différer d'un ordinateur à l'autre, et que cette recette ne fixe pas : les versions de musl-gcc
# et de MinGW (gcc, binutils, ses bibliothèques de démarrage), qui compilent le C de ring et lient les programmes
# (YARA-X n'y entre plus : c'est l'oracle des tests). Le résumé de la mesure est dans CONTRIBUTING.md, section « Compilation reproductible ».
#   outils/compiler-version.sh [options de cargo build en plus]
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
RACINE=$PWD
CARGO_DOSSIER=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)
export RUSTFLAGS="--remap-path-prefix=$RACINE=/vanguard --remap-path-prefix=$CARGO_DOSSIER=/cargo"
# Le C (ring) : ses chemins aussi, pour les messages d'assertion qu'il garde même dans un programme allégé.
for cible in x86_64_unknown_linux_musl x86_64_pc_windows_gnu; do
  export "CFLAGS_$cible=-ffile-prefix-map=$RACINE=/vanguard -ffile-prefix-map=$CARGO_DOSSIER=/cargo"
done
exec cargo auditable build --release --locked --target x86_64-unknown-linux-musl --target x86_64-pc-windows-gnu "$@"
