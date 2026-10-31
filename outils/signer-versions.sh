#!/usr/bin/env bash
# Signe la version publiée pour la mise à jour depuis GitHub : derniere.txt (la version gravée, puis l'empreinte
# SHA-256 et la taille du programme de chaque système) et derniere.txt.sig (Ed25519, clé privée de cet ordinateur).
# Et l'historique signé des versions : historique.txt, les blocs de derniere.txt de toutes les versions publiées, la
# plus récente en tête, et historique.txt.sig. Chaque publication retire la page d'avant : sans lui, une copie qui
# n'est plus la dernière (une 0.84 sur la clé d'un ami) ne se comparait plus à rien de signé. L'historique d'avant
# (DOSSIER/avant/historique.txt et .sig, que outils/publier-version.sh reprend de la version d'avant ; à défaut,
# DOSSIER/avant/derniere.txt et .sig, pour y faire entrer la version d'avant) n'est repris que si sa signature est
# celle d'une des deux clés gravées. derniere.txt garde sa forme et son domaine à l'octet près : les copies déjà
# installées (0.85.0 et d'avant) le lisent sans rien savoir de l'historique (outils/essais-signature.sh le prouve).
# Vanguard n'installe qu'un programme décrit par un manifeste que la clé principale ou la clé de secours a signé
# (src/mise_a_jour/github.rs : CLE_PUBLIQUE, CLE_SECOURS).
#   outils/signer-versions.sh DOSSIER             DOSSIER : celui de publier-version.sh, avec les trois programmes
#   outils/signer-versions.sh --secours DOSSIER   signé par la clé de secours (la principale perdue ou volée)
#   outils/signer-versions.sh --secours --revoquer DOSSIER
#                                                 la clé principale volée : « revoque principale » ajoutée à la fin
#                                                 de derniere.txt, que chaque Vanguard retient et après quoi il refuse
#                                                 la principale pour toujours (à redonner à chaque version qui suit,
#                                                 pour les ordinateurs qui n'auraient pas vu la première). Après les
#                                                 lignes des programmes : les copies 0.85 trouvent la leur avant elle.
#                                                 Jamais dans l'historique, que github.rs lit ligne par programme.
#                                                 Refusé si l'un des programmes n'a pas PRINCIPALE_RETIREE à true
#                                                 (github.rs, marque gravée) : ils la retirent aussi de leur code.
#   outils/signer-versions.sh --premier DOSSIER   sans rien d'avant : l'historique commence à cette version (la
#                                                 toute première publication seulement ; sinon, refusé)
#   outils/signer-versions.sh --point-sur FICHIER …   le point sûr (voir plus bas) pris dans FICHIER (et FICHIER.sig)
#   outils/signer-versions.sh --passe-droit NOM …     un passe-droit pris par outils/publier-version.sh pour cette
#                                                 version (sans-empreintes-ci, sans-vm), gardé dans son bloc de
#                                                 l'historique signé : jamais dans derniere.txt. Répétable.
# LE POINT SÛR : le dernier historique que cet ordinateur a publié, gardé ici par outils/publier-version.sh une fois la
# version en ligne (~/.local/state/vanguard-dev/historique-publie.txt et .sig ; VANGUARD_HISTORIQUE_PUBLIE pour un
# autre), signé par une clé gravée. Ce qui est téléchargé de vanguard-update s'y compare : la clé principale volée et le
# dépôt des versions pris suffiraient sinon à faire contresigner par la clé de secours un bloc forgé (campagne
# d'attaque n° 3), ou à tronquer l'historique en le retirant. Ainsi :
#   - clé principale : l'historique d'avant doit contenir tout le point sûr, et rien qu'il n'ait (une version que cet
#     ordinateur n'a pas publiée, c'est la principale entre d'autres mains) ; sinon refusé ;
#   - clé de secours : un historique d'avant signé par la principale n'est jamais repris au-delà du point sûr : ses
#     blocs sont ceux du point sûr, les autres écartés et nommés ; sans point sûr, refusé (--point-sur une copie
#     gardée ailleurs, une sauvegarde) ; signé par le secours lui-même, il est repris. Un point sûr signé par la
#     principale se forge avec elle (campagne d'attaque n° 4) : ses versions, leur date et le début de leur empreinte
#     sont montrés, et rien n'est contresigné sans « contresigner » tapé dans le terminal par l'auteur, qui seul sait
#     ce qu'il a publié : --secours sur un tel point sûr, sans terminal (une tâche, un tube), refuse donc toujours,
#     et ne laisse aucune signature, pas même celle de derniere.txt ;
#   - avec un point sûr, ni le repli sur derniere.txt ni --premier : l'historique publié a disparu, il ne repart pas.
#   outils/signer-versions.sh --cle [--secours]   la clé publique, sous la forme que github.rs grave
# La clé privée ne quitte jamais cet ordinateur : ni GitHub, ni la clé USB. Chiffrée (« BEGIN ENCRYPTED PRIVATE KEY »,
# voir la commande de chiffrement donnée à l'auteur), sa phrase est demandée une fois par signature, dans le terminal
# ou par zenity, puis passée à openssl par un descripteur : ni la phrase ni la clé en clair ne touchent le disque.
set -euo pipefail
cd "$(dirname "$0")/.."

SECOURS=
PREMIER=
REVOQUER=
PASSE_DROITS=()
POINT_SUR=${VANGUARD_HISTORIQUE_PUBLIE:-${XDG_STATE_HOME:-$HOME/.local/state}/vanguard-dev/historique-publie.txt}
ARGS=()
while (($#)); do
  case $1 in
    --secours) SECOURS=1 ;;
    --premier) PREMIER=1 ;;
    --revoquer) REVOQUER=1 ;;
    --point-sur) POINT_SUR=${2:?--point-sur FICHIER}; shift ;;
    --passe-droit) PASSE_DROITS+=("${2:?--passe-droit sans-empreintes-ci|sans-vm}"); shift ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [[ -n $SECOURS ]]; then
  CLE=${VANGUARD_CLE_SECOURS:-$HOME/.config/vanguard-dev/versions-secours-ed25519.pem}
  GRAVEE=CLE_SECOURS
else
  CLE=${VANGUARD_CLE_VERSIONS:-$HOME/.config/vanguard-dev/versions-ed25519.pem}
  GRAVEE=CLE_PUBLIQUE
fi
# Le préfixe du message signé, le même que DOMAINE dans github.rs ; celui de l'historique, DOMAINE_HISTORIQUE.
DOMAINE='vanguard-versions 1'
DOMAINE_HISTORIQUE='vanguard-historique 1'

erreur() { echo "✖ $*" >&2; exit 1; }
# Seule la clé de secours révoque (github.rs ne croit la ligne que d'elle) : signée par la principale, elle ne ferait
# rien, sinon croire à une révocation qui n'a pas eu lieu.
[[ -z $REVOQUER || -n $SECOURS ]] || erreur "--revoquer va avec --secours : la principale ne se révoque pas elle-même"
for p in "${PASSE_DROITS[@]+"${PASSE_DROITS[@]}"}"; do
  [[ $p == sans-empreintes-ci || $p == sans-vm ]] || erreur "passe-droit inconnu : $p (sans-empreintes-ci ou sans-vm)"
done
# Ce qui retient la révocation sur un ordinateur s'efface avec ses sceaux (github.rs, revocation_retenue) : les
# programmes qui révoquent retirent donc aussi la principale de leur code, et une fois installés, elle n'y revient plus.
# Lu dans chacun (github.rs, PRINCIPALE_GRAVEE), pas dans le code source, qui a pu changer depuis ; avant la phrase de
# la clé. Un programme absent est refusé plus bas.
if [[ -n $REVOQUER ]]; then
  for f in "${1:-.}"/vanguard-{linux-x86_64,windows-x86_64.exe,macos}; do
    # Les deux marques à la fois (un programme macOS universel dont une seule moitié la retire) : refusé aussi.
    [[ ! -f $f ]] || { grep -aq 'VANGUARD-PRINCIPALE:RETIREE;' "$f" && ! grep -aq 'VANGUARD-PRINCIPALE:GARDEE;' "$f"; } ||
      erreur "--revoquer : $f accepte encore la principale ; mettez PRINCIPALE_RETIREE à true dans \
src/mise_a_jour/github.rs, puis recompilez les programmes à signer avec (outils/compiler-version.sh)"
  done
fi
# Signés par la principale, les programmes la gardent : un programme qui la retire, une fois installé, n'accepterait
# plus rien de ce qu'elle signe (seule la clé de secours le mettrait encore à jour) ; un programme sans marque ne vient
# pas de ce code. Lu dans chacun, comme pour --revoquer.
if [[ -z $SECOURS ]]; then
  for f in "${1:-.}"/vanguard-{linux-x86_64,windows-x86_64.exe,macos}; do
    [[ ! -f $f ]] || { grep -aq 'VANGUARD-PRINCIPALE:GARDEE;' "$f" && ! grep -aq 'VANGUARD-PRINCIPALE:RETIREE;' "$f"; } ||
      erreur "$f ne porte pas la seule marque de la principale gardée (VANGUARD-PRINCIPALE:GARDEE) : \
PRINCIPALE_RETIREE à false dans src/mise_a_jour/github.rs, puis recompilez (outils/compiler-version.sh)"
  done
fi
[[ -r $CLE ]] || erreur "clé de signature absente : $CLE"
# La clé de secours vit hors ligne, loin de la principale : en clair, la moindre copie (instantané de /home,
# sauvegarde) les mettrait côte à côte et un seul vol donnerait les deux. Chiffrée seulement.
if [[ -n $SECOURS ]] && ! grep -q 'BEGIN ENCRYPTED PRIVATE KEY' "$CLE"; then
  erreur "clé de secours en clair, refusée : la chiffrer (openssl pkcs8 -topk8 -v2 aes-256-cbc) et la garder hors ligne"
fi

# La phrase d'une clé chiffrée, demandée une seule fois : chaque appel d'openssl la relit par le descripteur 3, un
# tube (jamais un fichier, ni la ligne de commande que ps montrerait).
PHRASE=
if grep -q 'BEGIN ENCRYPTED PRIVATE KEY' "$CLE"; then
  if [[ -t 0 ]]; then
    read -rs -p "Phrase de la clé de signature ($(basename "$CLE")) : " PHRASE
    echo >&2
  elif command -v zenity >/dev/null && [[ -n ${WAYLAND_DISPLAY:-}${DISPLAY:-} ]]; then
    PHRASE=$(zenity --password --title "Vanguard : signer la version" 2>/dev/null) || erreur "signature annulée"
  else
    erreur "clé chiffrée, et ni terminal ni zenity pour demander sa phrase"
  fi
  [[ -n $PHRASE ]] || erreur "phrase vide : rien n'est signé"
fi
# openssl avec la clé privée : « -passin fd:3 » seulement si elle est chiffrée (une clé en clair n'en veut pas).
avec_cle() {
  if [[ -n $PHRASE ]]; then
    "$@" -passin fd:3 3< <(printf '%s' "$PHRASE")
  else
    "$@"
  fi
}

# La clé publique (PEM), tirée une fois de la clé privée : une phrase fausse s'arrête ici, avant toute signature.
PUBLIQUE_PEM=$(avec_cle openssl pkey -in "$CLE" -pubout 2>/dev/null) || erreur "clé illisible (phrase fausse ?) : $CLE"
publique() { openssl pkey -pubin -pubout -outform DER <<<"$PUBLIQUE_PEM" | tail -c 32 | od -An -tu1 | tr -s ' \n' ' ' |
  sed 's/^ //; s/ $//'; }

if [[ ${1:-} == --cle ]]; then
  publique | sed 's/ /, /g'
  exit 0
fi
D=${1:?usage : outils/signer-versions.sh [--secours] [--premier] DOSSIER | --cle [--secours]}

# Rien d'avant (ni historique ni manifeste) : seulement à la toute première publication, dite par --premier. Un
# téléchargement raté chez publier-version.sh ressemblerait sinon à une première fois : l'historique repartirait de
# cette version, puis les pages d'avant seraient effacées, et les versions d'avant perdues pour de bon.
[[ -n $PREMIER || -f $D/avant/historique.txt || -f $D/avant/derniere.txt ]] ||
  erreur "ni historique ni manifeste d'avant dans $D/avant : rien n'est signé (--premier pour la toute première fois)"

# La clé privée doit être celle dont github.rs grave la clé publique : sinon, chaque Vanguard refuserait la version.
gravee=$(sed -n "/^const $GRAVEE:/,/^];/p" src/mise_a_jour/github.rs | tail -n +2 | grep -oE '[0-9]+' | tr '\n' ' ' |
  sed 's/ $//')
[[ -n $gravee && $gravee == "$(publique)" ]] || erreur "la clé privée ne correspond pas à $GRAVEE de src/mise_a_jour/github.rs"

# Les octets de FICHIER de DEBUT à DEBUT+N, en hexadécimal collé.
octets() { od -An -tx1 -v -j "$2" -N "$3" "$1" | tr -d ' \n'; }
# Un entier de 4 octets petit-boutiste lu à DEBUT.
entier_le() { local h; h=$(octets "$1" "$2" 4); echo $((16#${h:6:2}${h:4:2}${h:2:2}${h:0:2})); }

# Chaque programme est-il bien celui de son système ? Le Mac vient d'un runner de GitHub, et c'est la clé de l'auteur
# qui le signe : au moins sa forme se vérifie ici (Mach-O universel, Apple Silicon et Intel, rien d'autre), comme
# celle des deux autres (ELF x86-64, PE x86-64), avant que la signature ne s'y engage.
architecture_attendue() {
  local systeme=$1 f=$2 h pe
  case $systeme in
    linux-x86_64)
      # ELF, 64 bits, petit-boutiste ; e_machine (octet 18) = 0x3e, x86-64.
      [[ $(octets "$f" 0 6) == 7f454c460201 && $(octets "$f" 18 2) == 3e00 ]]
      ;;
    windows-x86_64)
      # « MZ », puis l'en-tête PE à l'adresse lue en 0x3c : « PE\0\0 », machine 0x8664.
      [[ $(octets "$f" 0 2) == 4d5a ]] || return 1
      pe=$(entier_le "$f" 60)
      [[ $(octets "$f" "$pe" 6) == 504500006486 ]]
      ;;
    macos)
      # Mach-O universel (0xcafebabe, gros-boutiste) à deux architectures : arm64 (0x0100000c) et x86_64
      # (0x01000007), dans n'importe quel ordre.
      h=$(octets "$f" 0 48)
      [[ ${h:0:16} == cafebabe00000002 ]] || return 1
      local a=${h:16:8} b=${h:56:8}
      [[ "$a $b" == "0100000c 01000007" || "$a $b" == "01000007 0100000c" ]]
      ;;
    *) return 1 ;;
  esac
}

declare -A FICHIERS=([linux-x86_64]=vanguard-linux-x86_64 [windows-x86_64]=vanguard-windows-x86_64.exe [macos]=vanguard-macos)
version=
for systeme in linux-x86_64 windows-x86_64 macos; do
  f=$D/${FICHIERS[$systeme]}
  [[ -f $f ]] || erreur "programme absent : $f"
  architecture_attendue "$systeme" "$f" || erreur "$f n'est pas un programme $systeme (forme ou architecture)"
  v=$(grep -aoE 'VANGUARD-VERSION:[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+;' "$f" | head -1 | sed 's/^VANGUARD-VERSION://; s/;$//')
  [[ -n $v ]] || erreur "pas de version gravée dans $f"
  # Les trois viennent du même commit : même numéro, même date. Sinon, l'un d'eux n'est pas de cette version.
  [[ -z $version || $v == "$version" ]] || erreur "versions différentes : $version et $v ($f)"
  version=$v
done
# La version gravée est celle de Cargo.toml : un programme d'une autre version ne se signe pas sous ce numéro.
cargo=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[[ ${version%%+*} == "$cargo" ]] || erreur "version gravée $version, Cargo.toml dit $cargo"

# Les signatures d'un passage d'avant, s'il en reste, ne survivent pas à un refus de celui-ci.
rm -f "$D/derniere.txt.sig" "$D/historique.txt.sig"
{
  echo "version $version"
  for systeme in linux-x86_64 windows-x86_64 macos; do
    f=$D/${FICHIERS[$systeme]}
    echo "$systeme $(sha256sum "$f" | cut -d' ' -f1) $(stat -c %s "$f")"
  done
  [[ -z $REVOQUER ]] || echo "revoque principale"
} >"$D/derniere.txt"


# --- L'historique des versions ---------------------------------------------------------------------------------------

# Une clé gravée dans github.rs (32 octets en décimal), en clé publique PEM pour openssl : l'en-tête DER d'une clé
# Ed25519 (SubjectPublicKeyInfo), puis les 32 octets.
pem_de_gravee() {
  local octets
  octets=$(sed -n "/^const $1:/,/^];/p" src/mise_a_jour/github.rs | tail -n +2 | grep -oE '[0-9]+' |
    awk '{ printf "%02x", $1 }')
  [[ ${#octets} == 64 ]] || return 1
  echo "-----BEGIN PUBLIC KEY-----"
  printf '%b' "$(printf '302a300506032b6570032100%s' "$octets" | sed 's/../\\x&/g')" | base64
  echo "-----END PUBLIC KEY-----"
}
# La clé gravée qui a signé un fichier d'avant avec ce domaine-là (CLE_PUBLIQUE ou CLE_SECOURS), ou code 1.
signe_par_une_gravee() { # $1 : fichier, $2 : domaine
  local message_avant cle gravee code=1
  [[ -f $1.sig ]] || return 1
  message_avant=$(mktemp "$D/.avant.XXXX")
  cle=$(mktemp "$D/.gravee.XXXX")
  { printf '%s\n' "$2"; cat "$1"; } >"$message_avant"
  for gravee in CLE_PUBLIQUE CLE_SECOURS; do
    pem_de_gravee "$gravee" >"$cle" 2>/dev/null || continue
    if openssl pkeyutl -verify -pubin -inkey "$cle" -rawin -in "$message_avant" -sigfile "$1.sig" >/dev/null 2>&1; then
      echo "$gravee"
      code=0
      break
    fi
  done
  rm -f "$message_avant" "$cle"
  return "$code"
}

# Les blocs d'un historique ou d'un manifeste, un par ligne (ses lignes jointes par « | »), sans celui de cette
# version-ci (une signature refaite ne la compte pas deux fois) ni la ligne de révocation ; dans leur ordre.
blocs() { # fichier
  awk -v ici="version $version" '
    function sortir() { if (b != "" && garder) print b; b = "" }
    /^version / { sortir(); b = $0; garder = ($0 != ici); next }
    /^revoque / { next }
    { if (b != "") b = b "|" $0 }
    END { sortir() }' "$1"
}
# Les blocs de $1 absents de $2 (listes de blocs), dans l'ordre de $1.
absents() { grep -vxF -f <(printf '%s\n' "$2") <<<"$1" || true; }
versions_de() { cut -d'|' -f1 <<<"$1" | sed 's/^version //' | paste -sd' '; }

# Le point sûr (en-tête) : signé par une clé gravée, sinon rien ne se signe sur une référence douteuse.
POINT=""
POINT_PAR=""
if [[ -f $POINT_SUR ]]; then
  POINT_PAR=$(signe_par_une_gravee "$POINT_SUR" "$DOMAINE_HISTORIQUE") ||
    erreur "point sûr mal signé ($POINT_SUR) : rien n'est signé sur une référence douteuse"
  POINT=$(blocs "$POINT_SUR")
fi
# Ce que la clé de secours va contresigner d'après un point sûr de la principale, montré à l'auteur : une version par
# ligne, sa date gravée et le début de l'empreinte de chaque programme. Le voleur de la principale réécrit le point
# sûr aussi bien que l'historique : seul l'auteur reconnaît ce qu'il a publié. Rien sans « contresigner » tapé.
confirmer_point() { # blocs
  local bloc v date
  echo "La clé de secours va contresigner ces versions, d'après un point sûr signé par la clé principale ($POINT_SUR)."
  echo "La principale volée le réécrit aussi : ne confirmez que si chacune est bien une version que vous avez publiée."
  while IFS= read -r bloc; do
    [[ -n $bloc ]] || continue
    v=$(cut -d'|' -f1 <<<"$bloc" | sed 's/^version //')
    date=$(date -ud "@${v##*+}" +%F 2>/dev/null || echo "date illisible")
    echo "  $v ($date) $(cut -d'|' -f2- <<<"$bloc" | tr '|' '\n' | awk '{ printf "%s %.12s  ", $1, $2 }')"
  done <<<"$1"
  [[ -t 0 ]] || erreur "pas de terminal pour confirmer le point sûr signé par la clé principale : rien n'est signé"
  local reponse
  read -r -p "Tapez « contresigner » pour continuer : " reponse
  [[ $reponse == contresigner ]] || erreur "non confirmé : rien n'est signé"
}

AVANT=$D/avant
anciens=""
if [[ -f $AVANT/historique.txt ]]; then
  signee_par=$(signe_par_une_gravee "$AVANT/historique.txt" "$DOMAINE_HISTORIQUE") ||
    erreur "historique d'avant mal signé ($AVANT/historique.txt) : rien n'est ajouté à un historique douteux"
  avant=$(blocs "$AVANT/historique.txt")
  if [[ -n $SECOURS && $signee_par == CLE_PUBLIQUE ]]; then
    # La principale est peut-être entre d'autres mains : rien de ce qu'elle a signé après le point sûr.
    [[ -f $POINT_SUR ]] || erreur "historique d'avant signé par la clé principale, et pas de point sûr ($POINT_SUR) : \
la clé de secours ne contresigne pas ce que la principale, peut-être volée, a pu y ajouter. --point-sur FICHIER : un \
historique publié gardé ailleurs (sauvegarde)."
    ecartes=$(absents "$avant" "$POINT")
    [[ -z $ecartes ]] || echo "⚠ Écartées de l'historique (signées par la clé principale après le point sûr) : \
$(versions_de "$ecartes")."
    [[ $POINT_PAR == CLE_SECOURS ]] || confirmer_point "$POINT"
    anciens=$POINT
  else
    if [[ -n $POINT && -z $SECOURS ]]; then
      manquants=$(absents "$POINT" "$avant")
      en_plus=$(absents "$avant" "$POINT")
      [[ -z $manquants ]] || erreur "l'historique publié n'a plus des versions que cet ordinateur avait publiées \
($(versions_de "$manquants")) : tronqué ou réécrit, rien n'est signé"
      [[ -z $en_plus ]] || erreur "l'historique publié a des versions que cet ordinateur n'a pas publiées \
($(versions_de "$en_plus")) : la clé principale est peut-être entre d'autres mains (--secours --revoquer). Publiées \
par vous ailleurs : gh release download -R d9v3/vanguard-update -p 'historique.txt*', puis --point-sur ce fichier"
    fi
    anciens=$avant
  fi
elif [[ -n $POINT ]]; then
  # Cet ordinateur a déjà publié un historique : qu'il manque en ligne n'est pas une première fois.
  erreur "pas d'historique d'avant dans $AVANT, alors que cet ordinateur en a publié un ($POINT_SUR) : retiré du \
dépôt des versions ? Rien n'est signé (l'historique ne repart pas de zéro)"
elif [[ -f $AVANT/derniere.txt ]]; then
  signee_par=$(signe_par_une_gravee "$AVANT/derniere.txt" "$DOMAINE") ||
    erreur "manifeste d'avant mal signé ($AVANT/derniere.txt) : il n'entre pas dans l'historique"
  [[ -z $SECOURS || $signee_par == CLE_SECOURS ]] || erreur "manifeste d'avant signé par la clé principale, sans \
point sûr ($POINT_SUR) : la clé de secours ne le contresigne pas (--point-sur FICHIER)"
  anciens=$(blocs "$AVANT/derniere.txt")
  echo "Historique commencé à partir du manifeste signé de la version d'avant."
else
  echo "Pas d'historique d'avant : il commence à cette version."
fi
# Signé seulement ici, une fois l'historique d'avant jugé et le point sûr confirmé : un refus plus haut ne laisse
# aucun derniere.txt.sig, que publier-version.sh pourrait publier seul (relecture adverse de la campagne 4).
message=$(mktemp "$D/.message.XXXX")
publique_pem=$(mktemp "$D/.publique.XXXX")
trap 'rm -f "$message" "$publique_pem"' EXIT
{ printf '%s\n' "$DOMAINE"; cat "$D/derniere.txt"; } >"$message"
printf '%s\n' "$PUBLIQUE_PEM" >"$publique_pem"
avec_cle openssl pkeyutl -sign -inkey "$CLE" -rawin -in "$message" -out "$D/derniere.txt.sig"
# Revérifiée avec la clé publique seule, comme le fera Vanguard.
openssl pkeyutl -verify -pubin -inkey "$publique_pem" -rawin -in "$message" \
  -sigfile "$D/derniere.txt.sig" >/dev/null || erreur "la signature ne se vérifie pas"
echo "Version $version signée ($GRAVEE) : $D/derniere.txt et derniere.txt.sig"
anciens=$(tr '|' '\n' <<<"$anciens")
# Un passe-droit pris pour cette version, dans son bloc et pour toujours (les versions suivantes reprennent le bloc
# tel quel) : « passe-droit-NOM », une empreinte de zéros et une taille nulle. Sous la forme d'une ligne de programme,
# la seule que lire_historique (src/mise_a_jour/github.rs) accepte : les copies déjà installées refuseraient sinon
# l'historique entier. Aucun programme n'a une empreinte de zéros : la ligne ne désigne jamais un fichier.
{
  grep -v '^revoque ' "$D/derniere.txt"
  for p in "${PASSE_DROITS[@]+"${PASSE_DROITS[@]}"}"; do
    echo "passe-droit-$p $(printf '0%.0s' {1..64}) 0"
  done
  [[ -z $anciens ]] || printf '%s\n' "$anciens"
} >"$D/historique.txt"
{ printf '%s\n' "$DOMAINE_HISTORIQUE"; cat "$D/historique.txt"; } >"$message"
avec_cle openssl pkeyutl -sign -inkey "$CLE" -rawin -in "$message" -out "$D/historique.txt.sig" 2>/dev/null ||
  erreur "historique non signé"
# La phrase n'a plus d'usage : oubliée tout de suite.
PHRASE=
openssl pkeyutl -verify -pubin -inkey "$publique_pem" -rawin -in "$message" \
  -sigfile "$D/historique.txt.sig" >/dev/null || erreur "la signature de l'historique ne se vérifie pas"
echo "Historique signé : $(grep -c '^version ' "$D/historique.txt") version(s), $D/historique.txt et historique.txt.sig"
