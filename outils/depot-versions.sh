#!/usr/bin/env bash
# Crée le dépôt PUBLIC des versions (d9v3/vanguard-update), d'où Vanguard se met à jour sans la clé : il ne contient
# qu'un LISEZMOI et, à chaque publication, les programmes et leur manifeste signé (outils/publier-version.sh). Le code
# est dans d9v3/vanguard-beta. À lancer une seule fois, avec l'accord de l'auteur : ce dépôt est visible de tous.
#   outils/depot-versions.sh          créer le dépôt (rien si il existe déjà)
#   outils/depot-versions.sh --voir   montrer le LISEZMOI, sans rien créer
set -euo pipefail
cd "$(dirname "$0")/.."

DEPOT=d9v3/vanguard-update
lisezmoi() {
  cat <<'FIN'
# Vanguard — published versions

This repository only holds the published programs of Vanguard (security check and repair kit for PCs and home
networks), so that Vanguard can update itself without its USB key. The source code lives elsewhere.

Each release has the two programs (`vanguard-windows-x86_64.exe`, `vanguard-linux-x86_64`), their SHA-256
fingerprints, and `derniere.txt`: the version, then the fingerprint and size of each program, signed with
Ed25519 (`derniere.txt.sig`) on the author's computer. Vanguard only installs a program described by a manifest that
the author's key signed, and only a newer version: a change made here by anyone else is refused.

---

Ce dépôt ne contient que les programmes publiés de Vanguard, pour qu'il se mette à jour sans sa clé USB. Chaque
version a les deux programmes, leurs empreintes SHA-256 et `derniere.txt`, signé en Ed25519 sur l'ordinateur de
l'auteur : Vanguard n'installe qu'un programme décrit par un manifeste que cette clé a signé, et jamais une version
plus ancienne.
FIN
}

if [[ ${1:-} == --voir ]]; then
  lisezmoi
  exit 0
fi
if gh repo view "$DEPOT" >/dev/null 2>&1; then
  echo "Le dépôt $DEPOT existe déjà."
  exit 0
fi
travail=$(mktemp -d "$HOME/.cache/vanguard-dev/depot-versions.XXXX")
trap 'rm -rf "$travail"' EXIT
lisezmoi >"$travail/README.md"
python3 outils/confidentialite.py --texte <"$travail/README.md" || { echo "LISEZMOI : rien de créé."; exit 1; }
gh repo create "$DEPOT" --public --disable-issues --disable-wiki \
  --description "Signed published programs of Vanguard (the source code lives elsewhere)"
# Le même auteur que le dépôt du code : pseudonyme et adresse noreply de GitHub, jamais un vrai nom.
git -C "$travail" init -q -b main
git -C "$travail" add README.md
git -C "$travail" -c user.name=d9v3 -c user.email="$(git config user.email)" commit -q -m "Dépôt des versions publiées"
git -C "$travail" push -q "https://github.com/$DEPOT.git" main
echo "Dépôt public créé : https://github.com/$DEPOT"
