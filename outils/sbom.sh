#!/usr/bin/env bash
# Les nomenclatures logicielles (SBOM, CycloneDX 1.5 en JSON) des programmes publiés : toutes les dépendances compilées
# dans chacun, versions et licences comprises, sans celles qui ne servent qu'à compiler (--no-build-deps). Une par
# cible : Linux, Windows et les deux moitiés du programme Mac universel, qui n'ont pas tout à fait les mêmes.
# Les mêmes octets ici et sur le Mac de GitHub : .github/workflows/macos.yml les fait attester avec le programme Mac,
# et outils/publier-version.sh les refait ici, les compare à celles du passage et vérifie l'attestation avant de les
# joindre à la page. D'où la date du code (outils/date-du-code.sh) plutôt que l'heure, une version de cargo-cyclonedx
# épinglée, et le chemin du dépôt sur la machine (dossier personnel ici, celui du Mac là-bas) ramené à « . ».
# Tourne aussi sur le bash 3.2 de macOS.
#   outils/sbom.sh <dossier de sortie>
set -euo pipefail
VERSION=0.5.9
[[ $# -eq 1 ]] || { echo "usage : outils/sbom.sh <dossier de sortie>" >&2; exit 2; }
mkdir -p "$1"
SORTIE=$(cd "$1" && pwd)
cd "$(dirname "$0")/.."
RACINE=$(pwd -P)

# Une autre version écrirait d'autres octets que celle du Mac de GitHub : refusée, jamais suivie.
if [[ $(cargo cyclonedx --version 2>/dev/null) != *" $VERSION" ]]; then
  echo "sbom.sh : cargo-cyclonedx $VERSION attendu, pas « $(cargo cyclonedx --version 2>/dev/null || echo absent) »" >&2
  echo "  (cargo install --locked cargo-cyclonedx@$VERSION ; pacman peut en poser une plus récente)" >&2
  exit 1
fi
# cargo cyclonedx n'a pas de --locked : un Cargo.lock en retard serait refait en silence, et la nomenclature dirait
# d'autres versions que celles compilées.
cargo metadata --locked --format-version 1 >/dev/null
SOURCE_DATE_EPOCH=$(bash outils/date-du-code.sh)
export SOURCE_DATE_EPOCH

# cargo cyclonedx écrit à côté de Cargo.toml : rien n'y reste, même interrompu.
trap 'rm -f sbom-*.json' EXIT
while read -r nom cible; do
  cargo cyclonedx </dev/null -q -f json --spec-version 1.5 --no-build-deps --target "$cible" --override-filename "sbom-$nom"
  sed "s#path+file://$RACINE#path+file://.#g" "sbom-$nom.json" >"$SORTIE/vanguard-$nom.cdx.json"
  rm -f "sbom-$nom.json"
  if grep -q 'file:///' "$SORTIE/vanguard-$nom.cdx.json"; then
    echo "sbom.sh : un chemin de cette machine reste dans vanguard-$nom.cdx.json" >&2
    exit 1
  fi
done <<'CIBLES'
linux-x86_64 x86_64-unknown-linux-musl
windows-x86_64 x86_64-pc-windows-gnu
macos-aarch64 aarch64-apple-darwin
macos-x86_64 x86_64-apple-darwin
CIBLES
ls "$SORTIE"/vanguard-*.cdx.json
