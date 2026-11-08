#!/usr/bin/env bash
# La chaîne C des programmes publiés, la même ici et dans la CI : zig (compilateur C, éditeur de liens, musl et
# mingw-w64 fournis avec lui) et cargo-zigbuild (qui le branche à cargo), chacun dans une version épinglée.
# Pourquoi : mesuré à la 0.91.0 (CONTRIBUTING.md, « Compilation reproductible »), la chaîne Rust était la même des deux
# côtés, mais gcc, binutils, musl et mingw-w64 venaient de la distribution (Arch ici, Ubuntu dans la CI) et faisaient
# différer les empreintes, jusqu'au runtime C importé par le .exe. Un seul fichier zig, vérifié, sur les deux systèmes,
# sans root ni conteneur.
# Ce qui est vérifié avant d'utiliser quoi que ce soit, et refusé sinon :
#   - l'archive de zig : son SHA-256, écrit ici (ZIG_SHA256), ET sa signature minisign, par la clé publique de la
#     Zig Software Foundation écrite dans le dépôt (outils/zig-minisign.pub, relevée sur https://ziglang.org/download/) ;
#     le nom du fichier signé (champ « file: » du commentaire de confiance, que minisign ne vérifie pas lui-même) doit
#     être celui demandé, sinon une archive plus ancienne, bien signée, passerait (attaque par retour en arrière) ;
#   - l'arbre de zig, à chaque usage : le même que l'archive gardée, fichier par fichier (tar --compare), sans fichier en
#     plus, l'archive elle-même revérifiée (SHA-256) ;
#   - cargo-zigbuild : posé par cargo install --locked --version =X (source de crates.io, dépendances de son Cargo.lock,
#     sommes vérifiées par cargo), puis l'archive .crate que cargo a téléchargée comparée à ZIGBUILD_SHA256 ; sa
#     version relue à chaque usage.
# Rien ne demande root : tout va dans un dossier de l'utilisateur, ~/.cache/vanguard-dev/chaine-zig ici, celui que
# donne VANGUARD_CHAINE_ZIG ailleurs (la CI : un dossier du runner, neuf à chaque passage, jamais un cache restauré).
# Téléchargement : ziglang.org. Avec VANGUARD_ZIG_MIROIRS=1 (la CI), d'abord les miroirs de la communauté, dans un
# ordre tiré au hasard, puis ziglang.org en dernier : le projet zig demande que les CI ne chargent pas son site, qui
# tient sur un seul serveur (https://ziglang.org/download/community-mirrors/). Un miroir ne peut rien glisser : la
# même empreinte et la même signature sont exigées, d'où qu'elle vienne.
# Versions : stables, publiées depuis au moins deux semaines quand elles ont été choisies (zig 0.17.0 le 1er oct.
# 2026, cargo-zigbuild 0.24.0 le 21 oct. 2026). À monter à la main, dans un commit à part, avec ZIG_SHA256 et
# ZIGBUILD_SHA256, puis une compilation reproductible de contrôle dans la CI.
#   outils/chaine-zig.sh                 pose ce qui manque, vérifie, et écrit le dossier de zig et cargo-zigbuild
#   outils/chaine-zig.sh --versions      « zig=… » et « cargo-zigbuild=… » attendus, sans rien poser
#   outils/chaine-zig.sh --verifier-signature <fichier> <signature> <nom attendu> [clé publique]
#                                        la vérification minisign seule (outils/essais-signature.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
DEPOT=$PWD

ZIG_VERSION=0.17.0
ZIG_ARCHIVE=zig-x86_64-linux-$ZIG_VERSION.tar.xz
ZIG_SHA256=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
ZIG_CLE=$DEPOT/outils/zig-minisign.pub
ZIGBUILD_VERSION=0.24.0
ZIGBUILD_SHA256=cfd0dbe23ae1b71e74014ba62e3262d6b2fdf76251828644823bdfd21ce5d84e

dire() { echo "chaine-zig.sh : $*" >&2; }
refus() { dire "$*"; exit 1; }

# La signature minisign (https://jedisct1.github.io/minisign/) vérifiée par openssl, sans poser minisign :
#   clé publique, 2e ligne en base64 : « Ed », numéro de clé (8 octets), clé Ed25519 (32) ;
#   signature, 4 lignes : commentaire libre, base64 de « ED » + numéro de clé + signature Ed25519 (64) du BLAKE2b-512
#   du fichier, « trusted comment: … », base64 de la signature Ed25519 (64) de la première signature suivie du
#   commentaire de confiance (qui le protège : on ne peut ni le changer ni le recoller sous une autre signature).
# « Ed » (fichier signé tel quel, l'ancienne forme) n'est pas accepté : zig signe en « ED ».
# Code 0 seulement si tout passe ; sinon la raison sur la sortie d'erreur et 1.
verifier_signature() { # fichier, signature, nom attendu, clé publique
  local fichier=$1 signature=$2 nom=$3 cle=$4 t commentaire code=1
  t=$(mktemp -d)
  (
    set -euo pipefail
    [[ -f $fichier && -f $signature && -f $cle ]] || { echo "fichier, signature ou clé absent"; exit 1; }
    [[ $(sed -n 1p "$cle") == "untrusted comment: "* && $(wc -l <"$cle") -eq 2 ]] || { echo "clé publique illisible"; exit 1; }
    sed -n 2p "$cle" | base64 -d >"$t/cle" 2>/dev/null || { echo "clé publique illisible"; exit 1; }
    [[ $(wc -c <"$t/cle") -eq 42 && $(head -c 2 "$t/cle") == Ed ]] || { echo "clé publique illisible"; exit 1; }
    [[ $(wc -l <"$signature") -eq 4 && $(sed -n 1p "$signature") == "untrusted comment: "* &&
      $(sed -n 3p "$signature") == "trusted comment: "* ]] || { echo "signature illisible (forme)"; exit 1; }
    sed -n 2p "$signature" | base64 -d >"$t/sig" 2>/dev/null || { echo "signature illisible (base64)"; exit 1; }
    [[ $(wc -c <"$t/sig") -eq 74 && $(head -c 2 "$t/sig") == ED ]] ||
      { echo "signature d'une autre forme que « ED » (BLAKE2b puis Ed25519)"; exit 1; }
    cmp -s <(head -c 10 "$t/sig" | tail -c 8) <(head -c 10 "$t/cle" | tail -c 8) ||
      { echo "signature faite par une autre clé (numéro de clé différent)"; exit 1; }
    tail -c 64 "$t/sig" >"$t/sig64"
    # La clé Ed25519 brute en DER (en-tête SubjectPublicKeyInfo fixe de RFC 8410), pour openssl.
    { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; tail -c 32 "$t/cle"; } >"$t/cle.der"
    openssl pkey -pubin -inform DER -in "$t/cle.der" -out "$t/cle.pem" 2>/dev/null || { echo "clé refusée par openssl"; exit 1; }
    openssl dgst -blake2b512 -binary "$fichier" >"$t/empreinte"
    openssl pkeyutl -verify -pubin -inkey "$t/cle.pem" -rawin -in "$t/empreinte" -sigfile "$t/sig64" >/dev/null 2>&1 ||
      { echo "signature du fichier fausse"; exit 1; }
    commentaire=$(sed -n 3p "$signature")
    commentaire=${commentaire#trusted comment: }
    sed -n 4p "$signature" | base64 -d >"$t/globale" 2>/dev/null || { echo "signature du commentaire illisible"; exit 1; }
    [[ $(wc -c <"$t/globale") -eq 64 ]] || { echo "signature du commentaire illisible"; exit 1; }
    { cat "$t/sig64"; printf '%s' "$commentaire"; } >"$t/message"
    openssl pkeyutl -verify -pubin -inkey "$t/cle.pem" -rawin -in "$t/message" -sigfile "$t/globale" >/dev/null 2>&1 ||
      { echo "commentaire de confiance non signé par cette clé"; exit 1; }
    # Le commentaire de zig : « timestamp:…<TAB>file:<nom><TAB>hashed » ; un seul champ file:, et le bon.
    [[ $(tr '\t' '\n' <<<"$commentaire" | grep -c '^file:') -eq 1 ]] &&
      tr '\t' '\n' <<<"$commentaire" | grep -qxF "file:$nom" ||
      { echo "signature d'un autre fichier que $nom (commentaire : $(tr '\t' ' ' <<<"$commentaire" | tr -cd 'A-Za-z0-9 ._:-' | cut -c1-120))"; exit 1; }
  ) >"$t/raison" && code=0
  ((code == 0)) || dire "signature refusée pour $nom : $(head -n 1 "$t/raison")"
  rm -rf "$t"
  return "$code"
}

if [[ ${1:-} == --verifier-signature ]]; then
  [[ $# -eq 4 || $# -eq 5 ]] || refus "usage : --verifier-signature <fichier> <signature> <nom attendu> [clé publique]"
  verifier_signature "$2" "$3" "$4" "${5:-$ZIG_CLE}"
  exit
fi
if [[ ${1:-} == --versions ]]; then
  echo "zig=$ZIG_VERSION"
  echo "cargo-zigbuild=$ZIGBUILD_VERSION"
  exit 0
fi
[[ $# -eq 0 ]] || refus "option inconnue : $1"
command -v openssl >/dev/null || refus "openssl absent : la signature de zig ne peut pas être vérifiée."

DOSSIER=${VANGUARD_CHAINE_ZIG:-$HOME/.cache/vanguard-dev/chaine-zig}
mkdir -p "$DOSSIER"
DOSSIER=$(cd "$DOSSIER" && pwd -P)
ZIG_DOSSIER=$DOSSIER/zig-x86_64-linux-$ZIG_VERSION
ZIG_GARDEE=$DOSSIER/$ZIG_ARCHIVE
ZIGBUILD_DOSSIER=$DOSSIER/cargo-zigbuild-$ZIGBUILD_VERSION
# Deux compilations lancées ensemble (deux worktrees) ne posent pas la chaîne en même temps.
exec 9>"$DOSSIER/.verrou"
flock 9

empreinte_juste() { [[ -f $1 && $(sha256sum "$1" | cut -d' ' -f1) == "$ZIG_SHA256" ]]; }

# Une archive gardée dont l'empreinte a changé n'est plus utilisée : retirée, puis retéléchargée et revérifiée.
if [[ -e $ZIG_GARDEE ]] && ! empreinte_juste "$ZIG_GARDEE"; then
  dire "archive de zig gardée modifiée (SHA-256 ≠ $ZIG_SHA256) : retirée, refaite depuis le téléchargement."
  rm -f "$ZIG_GARDEE" "$ZIG_GARDEE.minisig"
  rm -rf "$ZIG_DOSSIER"
fi

telecharger_zig() {
  local t sources=() source miroirs
  t=$(mktemp -d "$DOSSIER/.telechargement.XXXXXX")
  if [[ -n ${VANGUARD_ZIG_MIROIRS:-} ]]; then
    # La liste des miroirs : seulement des adresses https:// aux caractères sûrs ; une liste illisible n'empêche pas
    # le repli sur ziglang.org.
    miroirs=$(curl -fsS --proto '=https' --tlsv1.2 --max-time 30 https://ziglang.org/download/community-mirrors.txt \
      2>/dev/null | grep -xE 'https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?' | shuf || true)
    while read -r source; do
      [[ -n $source ]] && sources+=("${source%/}/$ZIG_ARCHIVE")
    done <<<"$miroirs"
  fi
  sources+=("https://ziglang.org/download/$ZIG_VERSION/$ZIG_ARCHIVE")
  for source in "${sources[@]}"; do
    rm -f "$t/archive" "$t/archive.minisig"
    curl -fsS --proto '=https' --tlsv1.2 --max-time 600 -o "$t/archive" "$source?source=vanguard" 2>/dev/null &&
      curl -fsS --proto '=https' --tlsv1.2 --max-time 60 -o "$t/archive.minisig" "$source.minisig?source=vanguard" \
        2>/dev/null || { dire "pas de réponse de ${source%/*}"; continue; }
    if ! empreinte_juste "$t/archive"; then
      dire "archive de ${source%/*} refusée : SHA-256 $(sha256sum "$t/archive" | cut -c1-16)… ≠ ${ZIG_SHA256:0:16}…"
      continue
    fi
    verifier_signature "$t/archive" "$t/archive.minisig" "$ZIG_ARCHIVE" "$ZIG_CLE" || continue
    mv -f "$t/archive.minisig" "$ZIG_GARDEE.minisig"
    mv -f "$t/archive" "$ZIG_GARDEE"
    rm -rf "$t"
    dire "zig $ZIG_VERSION téléchargé de ${source%/*}, empreinte et signature vérifiées."
    return 0
  done
  rm -rf "$t"
  refus "zig $ZIG_VERSION : aucune archive à la bonne empreinte et bien signée."
}

# L'archive, revérifiée à chaque usage : l'empreinte (la signature l'a été au téléchargement, l'empreinte la lie).
if ! empreinte_juste "$ZIG_GARDEE"; then
  telecharger_zig
fi
empreinte_juste "$ZIG_GARDEE" || refus "archive de zig gardée illisible."

# Ce que l'archive contient : un seul dossier, ni chemin absolu, ni « .. », ni lien, ni fichier spécial.
contenu_sur() {
  local liste
  liste=$(tar -tvJf "$ZIG_GARDEE") || return 1
  ! grep -qvE '^[-d]' <<<"$liste" || { dire "l'archive contient autre chose que des fichiers et des dossiers."; return 1; }
  ! tar -tJf "$ZIG_GARDEE" | grep -qvE "^zig-x86_64-linux-$ZIG_VERSION(/|$)" ||
    { dire "l'archive contient un chemin hors de son dossier."; return 1; }
  ! tar -tJf "$ZIG_GARDEE" | grep -qE '(^|/)\.\.(/|$)' || { dire "l'archive contient « .. »."; return 1; }
}
extraire_zig() {
  local t
  contenu_sur || refus "archive de zig refusée."
  t=$(mktemp -d "$DOSSIER/.extraction.XXXXXX")
  tar -xJf "$ZIG_GARDEE" -C "$t" --no-same-owner
  rm -rf "$ZIG_DOSSIER"
  mv "$t/zig-x86_64-linux-$ZIG_VERSION" "$ZIG_DOSSIER"
  rm -rf "$t"
}
# L'arbre de zig : chaque fichier de l'archive, au même contenu, à la même taille, au même mode ; aucun en plus
# (un en-tête glissé dans un dossier d'inclusion passerait avant le vrai). Les propriétaires diffèrent toujours
# (archive à un autre compte, extraite sans root) : seule cette différence-là est tolérée.
arbre_conforme() {
  local ecarts nombre_archive nombre_arbre
  [[ -d $ZIG_DOSSIER ]] || return 1
  ecarts=$(tar -dJf "$ZIG_GARDEE" -C "$DOSSIER" 2>&1 |
    grep -vE ': (Uid|Gid) differs$' || true)
  [[ -z $ecarts ]] || { dire "arbre de zig différent de l'archive : $(head -n 1 <<<"$ecarts" | cut -c1-160)"; return 1; }
  nombre_archive=$(tar -tJf "$ZIG_GARDEE" | grep -vc '/$')
  nombre_arbre=$(find "$ZIG_DOSSIER" ! -type d | wc -l)
  [[ $nombre_archive -eq $nombre_arbre ]] ||
    { dire "arbre de zig : $nombre_arbre fichiers, l'archive en a $nombre_archive."; return 1; }
}
if ! arbre_conforme; then
  [[ ! -d $ZIG_DOSSIER ]] || dire "arbre de zig refait depuis l'archive vérifiée."
  extraire_zig
  arbre_conforme || refus "arbre de zig toujours différent de l'archive après extraction."
fi
[[ $("$ZIG_DOSSIER/zig" version) == "$ZIG_VERSION" ]] || refus "zig ne dit pas sa version $ZIG_VERSION."

# cargo-zigbuild : compilé par la chaîne Rust du dépôt (rust-toolchain.toml), hors du dépôt (sa configuration de cargo
# viserait musl), dans un dossier à part puis mis en place seulement une fois la source vérifiée.
zigbuild_pose() {
  [[ -x $ZIGBUILD_DOSSIER/bin/cargo-zigbuild &&
    $("$ZIGBUILD_DOSSIER/bin/cargo-zigbuild" --version 2>/dev/null) == "cargo-zigbuild $ZIGBUILD_VERSION" ]]
}
if ! zigbuild_pose; then
  CHAINE=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
  CARGO_DOSSIER=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
  t=$(mktemp -d "$DOSSIER/.zigbuild.XXXXXX")
  (cd "$DOSSIER" && RUSTUP_TOOLCHAIN=$CHAINE cargo install --locked --quiet --no-track --version "=$ZIGBUILD_VERSION" \
    --root "$t" cargo-zigbuild) || { rm -rf "$t"; refus "cargo install cargo-zigbuild $ZIGBUILD_VERSION a échoué."; }
  # La source que cargo a compilée : l'archive .crate de son dossier de téléchargement, une seule, à notre empreinte.
  mapfile -t CRATES < <(find "$CARGO_DOSSIER/registry/cache" -maxdepth 2 -name "cargo-zigbuild-$ZIGBUILD_VERSION.crate" 2>/dev/null)
  if [[ ${#CRATES[@]} -ne 1 || $(sha256sum "${CRATES[0]}" | cut -d' ' -f1) != "$ZIGBUILD_SHA256" ]]; then
    rm -rf "$t"
    refus "source de cargo-zigbuild $ZIGBUILD_VERSION introuvable ou à une autre empreinte que $ZIGBUILD_SHA256."
  fi
  rm -rf "$ZIGBUILD_DOSSIER"
  mv "$t" "$ZIGBUILD_DOSSIER"
  zigbuild_pose || refus "cargo-zigbuild ne dit pas sa version $ZIGBUILD_VERSION."
  dire "cargo-zigbuild $ZIGBUILD_VERSION posé, source vérifiée."
fi

# Le dossier à mettre en tête du PATH : zig et cargo-zigbuild, et rien d'autre.
mkdir -p "$DOSSIER/bin"
ln -sfn "$ZIG_DOSSIER/zig" "$DOSSIER/bin/zig"
ln -sfn "$ZIGBUILD_DOSSIER/bin/cargo-zigbuild" "$DOSSIER/bin/cargo-zigbuild"
echo "$DOSSIER/bin"
