#!/usr/bin/env bash
# cargo-fuzz pour la CI (outils/fuzz.sh, étape fuzz de verifier.sh) : le programme que ses auteurs publient, à
# l'empreinte épinglée ici (celle que GitHub a notée pour la publication), dans ~/.cargo/bin. taiki-e/install-action
# ne connaît pas cargo-fuzz : « fallback: none » refusait, et la CI tombait avant les tests.
# Monter la version : la nouvelle empreinte se lit avec
#   gh api repos/rust-fuzz/cargo-fuzz/releases/tags/<version> -q '.assets[]|select(.name|test("linux-musl"))|.digest'
set -euo pipefail
VERSION=0.13.2
EMPREINTE=b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c
NOM="cargo-fuzz-$VERSION-x86_64-unknown-linux-musl.tar.gz"
dossier=$(mktemp -d)
trap 'rm -rf "$dossier"' EXIT
curl -fsSL --retry 3 -o "$dossier/$NOM" "https://github.com/rust-fuzz/cargo-fuzz/releases/download/$VERSION/$NOM"
echo "$EMPREINTE  $dossier/$NOM" | sha256sum -c --quiet
tar -xzf "$dossier/$NOM" -C "$dossier" cargo-fuzz
install -D -m 755 "$dossier/cargo-fuzz" "${CARGO_HOME:-$HOME/.cargo}/bin/cargo-fuzz"
cargo fuzz --version
