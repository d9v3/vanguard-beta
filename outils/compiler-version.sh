#!/usr/bin/env bash
# Compile les programmes publiés d'ici (vanguard : Linux statique musl, Windows MinGW ; sa fenêtre, vanguard-fenetre :
# Linux glibc, Windows MinGW), toujours de la même façon :
# outils/deployer.sh avant chaque déploiement, la CI pour sa compilation reproductible (.github/workflows/ci.yml), et
# quiconque veut refaire un programme publié à partir de son étiquette. Une seule recette, pour que deux compilations
# du même code donnent les mêmes octets, ici (Arch) comme dans la CI (Ubuntu) :
#   - la chaîne Rust de rust-toolchain.toml (rustup la pose d'elle-même), cargo-auditable dans la version de la CI
#     (vérifiée) ;
#   - la chaîne C épinglée, la même sur tous les systèmes : zig (compilateur C, éditeur de liens, musl, mingw-w64 et
#     leur runtime) et cargo-zigbuild, posés et vérifiés par outils/chaine-zig.sh (empreinte et signature) ; plus rien
#     de gcc, ld, musl ni mingw-w64 de la distribution dans le programme. Mesuré à la 0.91.0 (CONTRIBUTING.md,
#     « Compilation reproductible ») : c'étaient eux qui faisaient différer les empreintes d'Arch et d'Ubuntu, jusqu'au
#     runtime C du .exe (msvcrt.dll sous Ubuntu, UCRT sous Arch). Avec zig, le .exe importe l'UCRT (les DLL
#     api-ms-win-crt-*, livrées avec Windows 10 et 11, sans redistribuable). Les ressources du .exe (icône, version,
#     manifeste) passent par zig rc (build.rs) et ses bibliothèques d'import (raw-dylib) par zig dlltool : plus rien
#     de MinGW ni de binutils de la distribution ;
#   - Cargo.lock tel quel (--locked) ;
#   - les chemins de la compilation retirés des programmes : le dossier du dépôt devient /vanguard et celui de cargo
#     (CARGO_HOME, bibliothèques téléchargées) /cargo. Sans cela, ils gardent /home/<compte>/… ou /home/runner/…, et
#     le même code compilé dans deux dossiers donne deux programmes (et un nom de compte publié avec chaque version).
#     RUSTFLAGS remplace les rustflags d'un ~/.cargo/config.toml personnel : seuls ceux-ci comptent ;
#   - la date gravée est celle du code (outils/date-du-code.sh, par SOURCE_DATE_EPOCH que lit build.rs), jamais
#     l'heure de la compilation ; l'éditeur de liens de zig n'écrit pas l'heure dans l'en-tête PE (-Brepro,
#     build.rs) ;
#   - le cache de zig (la bibliothèque C, compiler-rt, le C de ring et de blake3 compilés) est neuf à chaque
#     compilation et retiré après : rien d'une compilation d'avant, ni d'un autre worktree, n'entre dans celle-ci.
# La fenêtre d'abord, par la même recette : vanguard grave l'empreinte SHA-256 de sa fenêtre (build.rs,
# VANGUARD_FENETRE_SHA256_LINUX / _WINDOWS) et ne lance jamais une autre fenêtre (src/demarrage/empreinte_fenetre.rs).
# Comme vanguard est signé, l'empreinte de sa fenêtre l'est aussi ; et l'empreinte de vanguard dépend de sa fenêtre :
# deux compilations qui donnent le même vanguard ont compilé la même fenêtre.
# Le repère de la compilation, target/.compilation : le commit compilé, si l'arbre du programme était propre (aucun
# changement non commité ni fichier non suivi dans ce que le programme intègre, fenêtre comprise), l'empreinte SHA-256
# des quatre programmes, relevée à la sortie de cargo, puis les outils de la chaîne (pour dire, à la publication, lesquels
# diffèrent de ceux de la CI ; ils ne décident rien). outils/publier-version.sh et outils/deployer.sh n'envoient que ces
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
# intercalaire, après ceci. De même pour cargo-zigbuild et zig : un autre zig (CARGO_ZIGBUILD_ZIG_…, ou le paquet
# Python ziglang, que cargo-zigbuild essaie avant tout autre), une autre bibliothèque de zig (ZIG_LIB_DIR), un autre
# cache ; tous reposés plus bas.
unset RUSTUP_TOOLCHAIN RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_ENCODED_RUSTFLAGS
while read -r variable; do
  unset "$variable"
done < <(compgen -e | grep -E '^(CARGO_ZIGBUILD_|ZIG_)' || true)
while read -r variable; do
  unset "$variable"
done < <(compgen -e | grep -E '^CARGO_(BUILD_|PROFILE_|TARGET_[A-Z0-9_]+_(LINKER|RUSTFLAGS|RUNNER)$)' || true)
# De même pour le C de ring (cc-rs) : un autre compilateur, archiveur ou option, pour toutes les cibles ou une seule.
# Les CFLAGS de chaque cible sont reposés plus bas.
while read -r variable; do
  unset "$variable"
done < <(compgen -e | grep -E '^((TARGET_|HOST_)?(CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|CRATE_CC_NO_DEFAULTS))(_.+)?$' || true)
# Une chaîne posée pour ce dossier (rustup override) passe aussi avant rust-toolchain.toml : refusée.
CHAINE=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
[[ $(rustc --version) == "rustc $CHAINE "* ]] ||
  { echo "rustc n'est pas celui de rust-toolchain.toml ($CHAINE) : $(rustc --version)" >&2; exit 1; }
# cargo-auditable : celui de la CI (.github/workflows/ci.yml), vérifié ici et non plus seulement par
# outils/deployer.sh ; un autre écrirait une autre liste des dépendances, donc un autre programme. Celui que cargo
# prendra (son dossier de programmes d'abord), sa version lue dans le programme même (outils/chaine-c.sh). Une autre
# version est refusée ; une version qui ne s'y lit pas aussi, sauf dans la CI (GITHUB_ACTIONS), qui le prend déjà
# compilé, épinglé à la version de ci.yml, sans le chemin de sa source : ici, cargo install le pose avec.
AUDITABLE_CI=$(sed -n 's/.*cargo-auditable@\([0-9][0-9.]*\).*/\1/p' .github/workflows/ci.yml | head -1)
[[ -n $AUDITABLE_CI ]] || { echo "version de cargo-auditable introuvable dans .github/workflows/ci.yml" >&2; exit 1; }
AUDITABLE=$(PATH="$CARGO_DOSSIER/bin:$PATH" bash outils/chaine-c.sh | sed -n 's/^cargo-auditable=//p')
case $AUDITABLE in
  "$AUDITABLE_CI") ;;
  inconnue)
    [[ ${GITHUB_ACTIONS:-} == true ]] || {
      echo "cargo-auditable : version non lue dans le programme (posé autrement que par cargo install ?), refusé" \
        "hors de la CI. cargo install cargo-auditable --locked --version $AUDITABLE_CI" >&2
      exit 1
    }
    echo "cargo-auditable : version non lue dans le programme ; dans la CI, celle qu'épingle ci.yml ($AUDITABLE_CI)." >&2
    ;;
  *)
    echo "cargo-auditable ${AUDITABLE:-absent} ici, $AUDITABLE_CI dans la CI : une autre liste des dépendances, un autre" \
      "programme. cargo install cargo-auditable --locked --version $AUDITABLE_CI" >&2
    exit 1
    ;;
esac
# La chaîne C : zig et cargo-zigbuild épinglés, vérifiés à chaque compilation (outils/chaine-zig.sh), en tête du
# PATH, devant le dossier des programmes de cargo (que cargo, sinon, regarde en premier pour ses sous-commandes).
ZIG_BIN=$(bash outils/chaine-zig.sh)
export PATH="$ZIG_BIN:$CARGO_DOSSIER/bin:$PATH"
[[ $(command -v cargo-zigbuild) == "$ZIG_BIN/cargo-zigbuild" && $(command -v zig) == "$ZIG_BIN/zig" ]] ||
  { echo "zig ou cargo-zigbuild pris ailleurs que dans $ZIG_BIN" >&2; exit 1; }
# Ce zig-là et aucun autre : la commande donnée tout de suite (cargo-zigbuild ne cherche alors ni Python ni le PATH).
export CARGO_ZIGBUILD_ZIG_COMMAND=$ZIG_BIN/zig CARGO_ZIGBUILD_ZIG_PATH=$ZIG_BIN/zig
export CARGO_ZIGBUILD_PYTHON_PATH=/nonexistent/python3
mkdir -p "${CARGO_TARGET_DIR:-target}"
ZIG_CACHE=$(mktemp -d "${CARGO_TARGET_DIR:-target}/cache-zig.XXXXXX")
ZIG_CACHE=$(cd "$ZIG_CACHE" && pwd -P)
trap 'rm -rf "$ZIG_CACHE"' EXIT
export ZIG_GLOBAL_CACHE_DIR=$ZIG_CACHE/global ZIG_LOCAL_CACHE_DIR=$ZIG_CACHE/local
# Les enveloppes de cargo-zigbuild (zig cc, ar, … par cible) : neuves elles aussi, jamais celles d'avant.
export CARGO_ZIGBUILD_CACHE_DIR=$ZIG_CACHE/enveloppes
# dlltool : rustc le cherche dans le PATH sous ce nom pour les bibliothèques d'import du .exe (raw-dylib de
# windows-link), et cargo-zigbuild préfère celui de MinGW s'il en trouve un. Ici, ce nom mène à cargo-zigbuild, qui,
# appelé ainsi, passe la main à zig dlltool (le zig ci-dessus) : celui de la distribution, s'il y en a un, n'est
# jamais pris.
mkdir "$ZIG_CACHE/outils"
ln -s "$ZIG_BIN/cargo-zigbuild" "$ZIG_CACHE/outils/x86_64-w64-mingw32-dlltool"
export PATH="$ZIG_CACHE/outils:$PATH"
[[ $(command -v x86_64-w64-mingw32-dlltool) == "$ZIG_CACHE/outils/x86_64-w64-mingw32-dlltool" ]] ||
  { echo "dlltool pris ailleurs que dans $ZIG_CACHE/outils" >&2; exit 1; }
export RUSTFLAGS="--remap-path-prefix=$RACINE=/vanguard --remap-path-prefix=$CARGO_DOSSIER=/cargo"
# Le C (ring) : ses chemins aussi, pour les messages d'assertion qu'il garde même dans un programme allégé.
for cible in x86_64_unknown_linux_musl x86_64_unknown_linux_gnu x86_64_pc_windows_gnu; do
  export "CFLAGS_$cible=-ffile-prefix-map=$RACINE=/vanguard -ffile-prefix-map=$CARGO_DOSSIER=/cargo"
done
# La date gravée : celle du code (outils/date-du-code.sh), pas du dernier commit, pour que les commits des captures et
# de la page des fonctions ne la changent pas et que les nomenclatures de GitHub portent la même. Une date déjà donnée
# l'emporte.
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
# Ce que les programmes intègrent : vanguard, et sa fenêtre (fenetre/, dont l'empreinte est gravée dans vanguard).
ARBRE=(src build.rs assets Cargo.toml Cargo.lock .cargo rust-toolchain.toml fenetre)
if [[ $COMMIT != inconnu && -z $(git status --porcelain -- "${ARBRE[@]}" 2>/dev/null) ]]; then
  PROPRE=oui
fi
# cargo-auditable posé à la main par son seul nom, comme le ferait « cargo auditable » : celui-ci s'y met par son
# chemin complet, que cargo mêle au -C metadata de Vanguard (~/.cargo/bin ici, /home/runner/.cargo/bin dans la CI :
# deux programmes différents). Trouvé par le PATH, le nom est le même partout. Le JSON reprend ce que
# « cargo auditable » transmettrait pour « --locked » (CargoArgs de cargo-auditable 0.7).
auditable() {
  CARGO_AUDITABLE_ORIG_ARGS='{"offline":false,"locked":true,"frozen":false,"config":[]}' \
    RUSTC_WORKSPACE_WRAPPER=cargo-auditable "$@"
}
# La fenêtre : la glibc de zig (Linux : ses bibliothèques d'affichage se chargent à l'exécution, fenetre/.cargo), dans
# son propre dossier de compilation (son Cargo.lock à elle). Les options données au script vont à vanguard seulement.
FENETRE_CIBLES=$CIBLES/fenetre
FENETRE_LINUX=$FENETRE_CIBLES/x86_64-unknown-linux-gnu/release/vanguard-fenetre
FENETRE_WINDOWS=$FENETRE_CIBLES/x86_64-pc-windows-gnu/release/vanguard-fenetre.exe
rm -f "$FENETRE_LINUX" "$FENETRE_WINDOWS"
CARGO_TARGET_DIR=$FENETRE_CIBLES auditable cargo zigbuild --release --locked --manifest-path fenetre/Cargo.toml \
  --target x86_64-unknown-linux-gnu --target x86_64-pc-windows-gnu
VANGUARD_FENETRE_SHA256_LINUX=$(sha256sum "$FENETRE_LINUX" | cut -d' ' -f1)
VANGUARD_FENETRE_SHA256_WINDOWS=$(sha256sum "$FENETRE_WINDOWS" | cut -d' ' -f1)
export VANGUARD_FENETRE_SHA256_LINUX VANGUARD_FENETRE_SHA256_WINDOWS
auditable cargo zigbuild --release --locked --target x86_64-unknown-linux-musl --target x86_64-pc-windows-gnu "$@"
# Chaque vanguard porte gravée l'empreinte de sa fenêtre, et aucune autre marque (« AUCUNE » : build.rs n'aurait pas
# vu la variable).
for paire in "x86_64-unknown-linux-musl/release/vanguard $VANGUARD_FENETRE_SHA256_LINUX" \
  "x86_64-pc-windows-gnu/release/vanguard.exe $VANGUARD_FENETRE_SHA256_WINDOWS"; do
  read -r p h <<<"$paire"
  marques=$(LC_ALL=C grep -aoE 'VANGUARD-FENETRE:([0-9a-f]{64}|AUCUNE);' "$CIBLES/$p" | sort -u || true)
  if [[ $marques != "VANGUARD-FENETRE:$h;" ]]; then
    echo "✖ $CIBLES/$p : l'empreinte de sa fenêtre ($h) n'y est pas gravée seule : ${marques:-aucune marque}" >&2
    exit 1
  fi
done
# Jamais de programme sans la liste de ses dépendances (section .dep-v0, relue par cargo audit bin) : si
# cargo-auditable venait à ne plus être appelé, cargo compilerait quand même, sans rien dire.
for p in "$CIBLES/x86_64-unknown-linux-musl/release/vanguard" "$CIBLES/x86_64-pc-windows-gnu/release/vanguard.exe" \
  "$FENETRE_LINUX" "$FENETRE_WINDOWS"; do
  if ! LC_ALL=C grep -qaF .dep-v0 "$p"; then
    echo "✖ $p : sans la liste de ses dépendances (section .dep-v0 de cargo-auditable)" >&2
    exit 1
  fi
done
# Relu après : un fichier changé pendant la compilation la rend douteuse.
[[ $PROPRE == oui && $(git rev-parse HEAD) == "$COMMIT" && -z $(git status --porcelain -- "${ARBRE[@]}" 2>/dev/null) ]] ||
  PROPRE=non
{
  echo "commit $COMMIT"
  echo "propre $PROPRE"
  echo "linux-x86_64 $(sha256sum "$CIBLES/x86_64-unknown-linux-musl/release/vanguard" | cut -d' ' -f1)"
  echo "windows-x86_64 $(sha256sum "$CIBLES/x86_64-pc-windows-gnu/release/vanguard.exe" | cut -d' ' -f1)"
  echo "fenetre-linux-x86_64 $VANGUARD_FENETRE_SHA256_LINUX"
  echo "fenetre-windows-x86_64 $VANGUARD_FENETRE_SHA256_WINDOWS"
  bash outils/chaine-c.sh | sed 's/^/outil /'
} >"$REPERE.nouveau"
mv -f "$REPERE.nouveau" "$REPERE"
