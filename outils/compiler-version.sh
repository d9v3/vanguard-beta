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
#   - la date gravée est celle du code (outils/date-du-code.sh, par SOURCE_DATE_EPOCH que lit build.rs), jamais
#     l'heure de la compilation ; l'éditeur de liens de MinGW
#     n'écrit pas l'heure dans l'en-tête PE (--no-insert-timestamp, build.rs).
# Ce qui peut encore différer d'un ordinateur à l'autre, et que cette recette ne fixe pas : les versions de musl-gcc
# et de MinGW (gcc, binutils, ses bibliothèques de démarrage), qui compilent le C de ring et lient les programmes
# (YARA-X n'y entre plus : c'est l'oracle des tests). Le résumé de la mesure est dans CONTRIBUTING.md, section « Compilation reproductible ».
# Le repère de la compilation, target/.compilation : le commit compilé, si l'arbre du programme était propre (aucun
# changement non commité ni fichier non suivi dans ce que le programme intègre), et l'empreinte SHA-256 des deux
# programmes, relevée à la sortie de cargo. outils/publier-version.sh et outils/deployer.sh n'envoient que ces
# octets-là : un target/ partagé avec les worktrees, une compilation ordinaire ou un fichier modifié le temps d'une
# compilation ne partent plus signés (campagne d'attaque n° 3).
#   outils/compiler-version.sh [options de cargo build en plus]
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
RACINE=$PWD
CARGO_DOSSIER=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)
# Ce qui changerait en silence le programme publié, venu de l'environnement (règle DENV-CARGO-ENVVARS du guide de
# l'ANSSI) : un autre compilateur que celui de rust-toolchain.toml, un programme intercalé, des options qui passent
# avant RUSTFLAGS, les mêmes réglages sous leur nom de configuration (CARGO_BUILD_…), un profil release changé
# (CARGO_PROFILE_…), un autre éditeur de liens (CARGO_TARGET_…_LINKER). cargo auditable pose lui-même son
# intercalaire, après ceci.
unset RUSTUP_TOOLCHAIN RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_ENCODED_RUSTFLAGS
while read -r variable; do
  unset "$variable"
done < <(compgen -e | grep -E '^CARGO_(BUILD_|PROFILE_|TARGET_[A-Z0-9_]+_(LINKER|RUSTFLAGS|RUNNER)$)' || true)
# De même pour le C de ring (cc-rs) : un autre compilateur, archiveur ou option, pour toutes les cibles ou une seule.
# Les CFLAGS de chaque cible sont reposés plus bas.
while read -r variable; do
  unset "$variable"
done < <(compgen -e | grep -E '^((TARGET_|HOST_)?(CC|CXX|AR|CFLAGS|CXXFLAGS|CRATE_CC_NO_DEFAULTS))(_.+)?$' || true)
# Une chaîne posée pour ce dossier (rustup override) passe aussi avant rust-toolchain.toml : refusée.
CHAINE=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
[[ $(rustc --version) == "rustc $CHAINE "* ]] ||
  { echo "rustc n'est pas celui de rust-toolchain.toml ($CHAINE) : $(rustc --version)" >&2; exit 1; }
export RUSTFLAGS="--remap-path-prefix=$RACINE=/vanguard --remap-path-prefix=$CARGO_DOSSIER=/cargo"
# Le C (ring) : ses chemins aussi, pour les messages d'assertion qu'il garde même dans un programme allégé.
for cible in x86_64_unknown_linux_musl x86_64_pc_windows_gnu; do
  export "CFLAGS_$cible=-ffile-prefix-map=$RACINE=/vanguard -ffile-prefix-map=$CARGO_DOSSIER=/cargo"
done
# La date gravée : celle du code (outils/date-du-code.sh), pas du dernier commit, pour que les commits des captures et
# de la page des fonctions ne la changent pas et que le Mac de GitHub grave la même. Une date déjà donnée l'emporte.
if [[ -z ${SOURCE_DATE_EPOCH:-} ]]; then
  DATE_DU_CODE=$(bash outils/date-du-code.sh 2>/dev/null || true)
  [[ -z $DATE_DU_CODE ]] || export SOURCE_DATE_EPOCH=$DATE_DU_CODE
fi
CIBLES=${CARGO_TARGET_DIR:-target}
REPERE=$CIBLES/.compilation
rm -f "$REPERE"
# L'arbre du programme lu avant la compilation : ce que cargo compile, c'est cet état-là.
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo inconnu)
PROPRE=non
if [[ $COMMIT != inconnu && -z $(git status --porcelain -- src build.rs assets Cargo.toml Cargo.lock .cargo \
  rust-toolchain.toml 2>/dev/null) ]]; then
  PROPRE=oui
fi
cargo auditable build --release --locked --target x86_64-unknown-linux-musl --target x86_64-pc-windows-gnu "$@"
# Relu après : un fichier changé pendant la compilation la rend douteuse.
[[ $PROPRE == oui && $(git rev-parse HEAD) == "$COMMIT" && -z $(git status --porcelain -- src build.rs assets \
  Cargo.toml Cargo.lock .cargo rust-toolchain.toml 2>/dev/null) ]] || PROPRE=non
{
  echo "commit $COMMIT"
  echo "propre $PROPRE"
  echo "linux-x86_64 $(sha256sum "$CIBLES/x86_64-unknown-linux-musl/release/vanguard" | cut -d' ' -f1)"
  echo "windows-x86_64 $(sha256sum "$CIBLES/x86_64-pc-windows-gnu/release/vanguard.exe" | cut -d' ' -f1)"
} >"$REPERE.nouveau"
mv -f "$REPERE.nouveau" "$REPERE"
