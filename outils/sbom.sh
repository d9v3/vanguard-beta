#!/usr/bin/env bash
# Les nomenclatures logicielles (SBOM, CycloneDX 1.5 en JSON) des programmes publiés : toutes les dépendances compilées
# dans chacun, versions et licences comprises, sans celles qui ne servent qu'à compiler (--no-build-deps). Une par
# cible : Linux et Windows, qui n'ont pas tout à fait les mêmes.
# Les mêmes octets ici et sur le Linux de GitHub : le travail « nomenclatures » de .github/workflows/ci.yml les fait
# attester (sur master), et outils/publier-version.sh les refait ici, les compare à celles du passage et vérifie
# l'attestation avant de les joindre à la page. D'où la date du code (outils/date-du-code.sh) plutôt que l'heure, une
# version de cargo-cyclonedx épinglée, et le chemin du dépôt sur la machine (dossier personnel ici, celui de GitHub
# là-bas) ramené à « . ».
#   outils/sbom.sh <dossier de sortie>
#   outils/sbom.sh --noms        les noms des fichiers, un par ligne, sans rien faire (liens.py --version)
#   outils/sbom.sh --fenetre <dossier de sortie>
#                                celles de la fenêtre (fenetre/, vanguard-fenetre), à part : outils/verifier.sh les
#                                fait, mais elle n'est pas encore publiée, donc ni dans --noms ni sur la page
#                                (celle de Linux nomme en trop accesskit_unix et ce qu'il amène, zvariant compris,
#                                que Linux ne compile pas : cargo cyclonedx ne sépare pas les fonctions par cible ;
#                                une ligne de trop, jamais une de moins)
set -euo pipefail
VERSION=0.5.9
CIBLES='linux-x86_64 x86_64-unknown-linux-musl
windows-x86_64 x86_64-pc-windows-gnu'
PROGRAMME=vanguard
CRATE=.
if [[ $# -eq 2 && $1 == --fenetre ]]; then
  CIBLES='linux-x86_64 x86_64-unknown-linux-gnu
windows-x86_64 x86_64-pc-windows-gnu'
  PROGRAMME=vanguard-fenetre
  CRATE=fenetre
  shift
fi
[[ $# -eq 1 ]] || { echo "usage : outils/sbom.sh [--fenetre] <dossier de sortie> | --noms" >&2; exit 2; }
if [[ $1 == --noms ]]; then
  while read -r nom _; do echo "vanguard-$nom.cdx.json"; done <<<"$CIBLES"
  exit 0
fi
mkdir -p "$1"
SORTIE=$(cd "$1" && pwd)
cd "$(dirname "$0")/.."
RACINE=$(pwd -P)

# Une autre version écrirait d'autres octets que celle du passage de GitHub : refusée, jamais suivie.
if [[ $(cargo cyclonedx --version 2>/dev/null) != *" $VERSION" ]]; then
  echo "sbom.sh : cargo-cyclonedx $VERSION attendu, pas « $(cargo cyclonedx --version 2>/dev/null || echo absent) »" >&2
  echo "  (cargo install --locked cargo-cyclonedx@$VERSION ; pacman peut en poser une plus récente)" >&2
  exit 1
fi
# cargo cyclonedx n'a pas de --locked : un Cargo.lock en retard serait refait en silence, et la nomenclature dirait
# d'autres versions que celles compilées.
cargo metadata --locked --format-version 1 --manifest-path "$CRATE/Cargo.toml" >/dev/null
SOURCE_DATE_EPOCH=$(bash outils/date-du-code.sh)
export SOURCE_DATE_EPOCH
cd "$CRATE"

# cargo cyclonedx écrit à côté de Cargo.toml : rien n'y reste, même interrompu.
trap 'rm -f sbom-*.json' EXIT
while read -r nom cible; do
  cargo cyclonedx </dev/null -q -f json --spec-version 1.5 --no-build-deps --target "$cible" --override-filename "sbom-$nom"
  # cargo abrège l'identifiant du paquet en « #0.89.0 » quand le dossier du dépôt s'appelle comme lui (vanguard ici),
  # et écrit « #vanguard@0.89.0 » sinon (vanguard-beta sur GitHub) : toujours la forme longue.
  sed -e "s#path+file://$RACINE#path+file://.#g" -e 's|path+file://\.#\([0-9]\)|path+file://.#vanguard@\1|g' \
    "sbom-$nom.json" >"$SORTIE/$PROGRAMME-$nom.cdx.json"
  rm -f "sbom-$nom.json"
  if grep -q 'file:///' "$SORTIE/$PROGRAMME-$nom.cdx.json"; then
    echo "sbom.sh : un chemin de cette machine reste dans $PROGRAMME-$nom.cdx.json" >&2
    exit 1
  fi
done <<<"$CIBLES"
ls "$SORTIE"/"$PROGRAMME"-*.cdx.json
