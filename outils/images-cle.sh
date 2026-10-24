#!/usr/bin/env bash
# Images Linux de la clé de secours, tenues à jour toutes seules : Omarchy (son installateur complet, sans Internet),
# Arch Linux, Debian et Fedora en installateurs par Internet, SystemRescue (réparer, sauver des fichiers, tester la
# mémoire) ; en option, Kali Linux en live complète (ses outils de sécurité, sans rien installer ; publiée en torrent
# seulement : aria2c la télécharge, puis elle est vérifiée comme les autres par la liste signée du projet).
# PAR DÉFAUT, AUCUNE : une clé préparée par les outils du dépôt ne porte que le programme. Seul le réglage local de
# l'ordinateur, hors du dépôt, fait la clé de secours : CLE_SECOURS=oui dans ~/.config/vanguard/images-cle.conf, et
# au besoin IMAGES="…" et IMAGES_EN_PLUS="kali" (le détail plus bas, à TENUES).
#   outils/images-cle.sh --chercher     dernières versions téléchargées dans le cache et vérifiées (minuterie
#                                       vanguard-images.timer, le 1er et le 15 du mois, qui les copie ensuite sur la
#                                       clé si elle est branchée) ; une image mal signée est effacée
#   outils/images-cle.sh --importer FICHIER  fait entrer dans le cache une image déjà téléchargée ailleurs (client
#                                       torrent, autre ordinateur), vérifiée de la même façon ; le fichier reste là
#   outils/images-cle.sh --verifier     revérifie signature et empreinte des images du cache
#   outils/images-cle.sh --cle [POINT]  met à jour sur la clé VANGUARD les images qu'elle a déjà : la nouvelle version
#                                       copiée, puis l'ancienne retirée (au branchement : vanguard-images-cle.service ;
#                                       chaque jour si la clé reste branchée : vanguard-cle-maj.timer)
#   outils/images-cle.sh --toutes POINT pose aussi celles qui manquent (nouvelle clé : cle-secours.sh --ecrire ; ou
#                                       une image en option ajoutée à une clé qui ne l'a pas encore)
#   outils/images-cle.sh --menu POINT   réécrit ventoy/ventoy.json d'après les images de ISO/
#   outils/images-cle.sh --etat         ce qui est dans le cache et sur la clé
#   outils/images-cle.sh --sortes       les sortes d'images tenues sur cet ordinateur (lu par cle-secours.sh) ; rien
#                                       sans le réglage de la clé de secours
#   outils/images-cle.sh --secours      « oui » (code 0) si le réglage local demande la clé de secours, « non » (1)
# Le cache peut être un lien vers un autre disque : disque absent, rien n'est fait ni recréé ailleurs, et une
# notification le dit.
# Chaque image est vérifiée par la signature de son projet, avec une clé fixée ici (outils/cles-images/ et les
# empreintes ci-dessous) : jamais une clé lue sur le serveur qui sert l'image, qu'un serveur piégé fournirait avec
# son image. Une nouvelle clé (Fedora en change à chaque version) arrive avec une mise à jour de Vanguard ; d'ici là,
# l'image est refusée et la notification le dit. Windows 11 et la récupération de macOS restent à part
# (cle-secours.sh) : Microsoft ne donne qu'un lien de 24 heures, et la récupération de macOS télécharge macOS
# elle-même.
set -euo pipefail
# Ctrl-C (lancé à la main) arrête tout : sans ce piège, bash attendrait la fin de la commande en cours, puis
# continuerait comme si de rien n'était (aria2c, que Ctrl-C atteint par timeout --foreground, s'arrête proprement et
# rend un code ordinaire, qui ferait prendre la version d'avant de Kali).
trap 'trap - INT; kill -INT $$' INT
cd "$(dirname "$0")/.."

CACHE=${VANGUARD_IMAGES:-${XDG_CACHE_HOME:-$HOME/.cache}/vanguard/images-cle}
CLES=$PWD/outils/cles-images
MIO=$((1024 * 1024))
# Place gardée sur la clé pour Vanguard, sa base et ses rapports.
MARGE_MIO=512
# La clé de secours (ces images, Ventoy pour les démarrer, les partitions WIN11 et MACOS de cle-secours.sh) ne se fait
# que sur un ordinateur dont le réglage local la demande. Sans lui, une clé préparée par les outils du dépôt ne porte
# que le programme (Vanguard, sa base, ses rapports, VANGUARDLOG) : rien n'est cherché, copié, importé ni proposé, les
# commandes qui poseraient une image refusent en disant comment l'allumer, et les minuteries de recopie ne font rien.
# Le réglage, hors du dépôt, dans ~/.config/vanguard/images-cle.conf, une ligne par valeur (la dernière compte) :
#   CLE_SECOURS=oui                                        la clé de secours sur cet ordinateur (seul « oui » l'allume)
#   IMAGES="systemrescue arch omarchy debian fedora"        les images Linux tenues ; sans cette ligne, ces cinq-là
#   IMAGES_EN_PLUS="kali"                                   des images en plus de celles d'IMAGES (Kali Linux, 16 Gio)
# Espaces ou virgules entre les noms ; « # » commence un commentaire. Lu, jamais sourcé : rien de ce fichier ne
# s'exécute. Quel que soit l'ordre écrit, les images vont sur la clé dans l'ordre de TENUES (la plus utile d'abord) ;
# Kali, en option, en dernier : sur la clé seulement s'il reste la place après les autres, et retirée de la clé quand
# une nouvelle version d'une autre image n'y tient plus (copier_sur_cle).
TENUES=(systemrescue arch omarchy debian fedora kali)
PAR_DEFAUT="systemrescue arch omarchy debian fedora"
EN_OPTION="kali"
REGLAGE=${XDG_CONFIG_HOME:-$HOME/.config}/vanguard/images-cle.conf
ALLUMER="Pour la faire sur cet ordinateur : une ligne CLE_SECOURS=oui dans $REGLAGE (le détail : en-tête de \
outils/images-cle.sh)."
# Les lignes « NOM=… » du réglage, sans commentaire ni guillemets ; rien si le nom n'y est pas.
reglage() { # nom
  [[ -r $REGLAGE ]] || return 0
  # Fins de ligne de Windows (un fichier écrit là-bas, ou recopié de la clé) : le « \r » collerait au dernier nom.
  sed -n "s/\r//g; s/#.*//; s/^[[:space:]]*$1[[:space:]]*=//p" "$REGLAGE" | tr -d "\"'" | tr ',' ' '
}
SECOURS=""
SORTES=()
if [[ $(reglage CLE_SECOURS | tail -1 | tr -d '[:space:]') == oui ]]; then
  SECOURS=oui
  voulues=$PAR_DEFAUT
  # La ligne IMAGES présente, même vide : elle seule dit les images (vide : aucune image Linux, WIN11 et MACOS
  # restent).
  [[ -z $(sed -n 's/\r//g; s/#.*//; /^[[:space:]]*IMAGES[[:space:]]*=/p' "$REGLAGE") ]] || voulues=$(reglage IMAGES | tail -1)
  voulues+=" $(reglage IMAGES_EN_PLUS | tail -1)"
  # Lus par read, pas développés par le shell : un « * » du réglage reste un mot inconnu.
  read -ra liste <<<"$voulues"
  voulues=" ${liste[*]} "
  for s in "${liste[@]}"; do
    # Écrite deux fois (« kali,kali ») : comptée une fois, sans rien dire, ce n'est pas une erreur.
    [[ " ${TENUES[*]} " == *" $s "* ]] ||
      echo "· $REGLAGE : « $s » n'est pas une image que la clé sait tenir (${TENUES[*]}), ignorée." >&2
  done
  for s in "${TENUES[@]}"; do
    [[ $voulues != *" $s "* ]] || SORTES+=("$s")
  done
elif [[ -n $(reglage IMAGES)$(reglage IMAGES_EN_PLUS) ]]; then
  echo "· $REGLAGE : des images demandées sans CLE_SECOURS=oui, ignorées (la clé ne porte que le programme)." >&2
fi
# La clé de secours n'est pas demandée : dit, et code 1 (les fonctions qui poseraient une image s'arrêtent là).
secours_demandee() { # ce qui n'est pas fait
  [[ -z $SECOURS ]] || return 0
  echo "· Clé de secours pas demandée sur cet ordinateur : $1 La clé ne porte que le programme. $ALLUMER"
  return 1
}
# Facultatives : leur absence du cache n'empêche pas de faire une clé (cle-secours.sh --ecrire vérifie le cache).
FACULTATIVES=" $EN_OPTION "

# Clés principales qui signent les images de chaque projet. Arch : celle de son responsable des images (trousseau
# archlinux-keyring, « PGP fingerprint » de archlinux.org/download). Debian : « Debian CD signing key »
# (debian.org/CD/verify). Fedora : une clé par version, 43 à 46 (fedoraproject.org/fedora.gpg et le paquet
# fedora-repos). SystemRescue : celle de son auteur (system-rescue.org/security). Omarchy : celle de ses paquets
# (la clé « Omarchy » du paquet omarchy-keyring), qui signe aussi son image. Kali : « Kali Linux Archive Automatic
# Signing Key (2025) », la même empreinte sur archive.kali.org et dans sa documentation (« Download official Kali Linux
# images »), vérifiée le 21 oct. 2026.
declare -A SIGNATAIRES=(
  [arch]="3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C"
  [debian]="DF9B9C49EAA9298432589D76DA87E80D6294BE9B 10460DAD76165AD81FBC0CE9988021A964E6EA7D"
  [fedora]="C6E7F081CF80E13146676E88829B606631645531 36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6
            4F50A6114CD5C6976A7F1179655A4B02F577861E D924B10D3E810DABDD8B56B596E7E91491211FCE"
  [systemrescue]="0FF11AF081E98345594812037091115F8320B897"
  [omarchy]="40DFB630FF42BCFFB047046CF0134EE680CAC571"
  [kali]="827C8569F2518CC677FECA1AED65462EC8D5E4C5"
)
# Noms des images de chaque sorte : les anciennes versions se reconnaissent sur la clé et dans le cache.
declare -A MOTIFS=(
  [arch]='archlinux-*-x86_64.iso'
  [debian]='debian-*-amd64-netinst.iso'
  [fedora]='Fedora-Everything-netinst-x86_64-*.iso'
  [systemrescue]='systemrescue-*-amd64.iso'
  [omarchy]='omarchy-*.iso'
  [kali]='kali-linux-*-live-everything-amd64.iso'
)
declare -A NOMS=([arch]="Arch Linux" [debian]=Debian [fedora]=Fedora [systemrescue]=SystemRescue [omarchy]=Omarchy
  [kali]="Kali Linux")

ETAT=${XDG_STATE_HOME:-$HOME/.local/state}/vanguard

erreur() { echo "✖ $*" >&2; exit 1; }
lire() { curl -fsSL --retry 3 --connect-timeout 20 --max-time 120 "$1"; }
avertir() { # titre texte
  command -v notify-send >/dev/null && notify-send -a Vanguard -i vanguard -- "$1" "$2" || true
}

# Taille lisible : « 1,5 Gio », « 820 Mio ».
lisible() { # octets
  awk -v o="$1" 'BEGIN {
    if (o >= 1073741824) s = sprintf("%.1f Gio", o / 1073741824); else s = sprintf("%d Mio", (o + 1048575) / 1048576)
    sub(/\./, ",", s); print s }'
}

# Le cache (comme le dossier de cle-secours.sh) peut être un lien vers un autre disque. Disque débranché : le lien
# mène nulle part. Rien n'est alors recréé à sa place, ni dans ~/.cache ni à côté du point de montage (sur le tmpfs de
# /run/media, en mémoire, où 16 Gio d'images rempliraient la RAM) : le lien mort est écrit, code 0 ; code 1 si le
# dossier est là, ou simplement pas encore créé (première recherche).
lien_mort() { # dossier
  local d=$1
  while [[ ! -e $d ]]; do
    if [[ -L $d ]]; then
      echo "$d"
      return 0
    fi
    [[ $d == */* ]] || return 1
    d=${d%/*}
    [[ -n $d ]] || return 1
  done
  return 1
}

# Le cache absent : dit à chaque fois, et une notification, une fois par semaine au plus : la recherche puis la copie
# du même service, la mise à jour du jour et chaque branchement la redonneraient sinon, tant que le disque manque
# (comme deja_dit de cle-secours.sh). Le cache revenu, la note part : une nouvelle absence se redit aussitôt. Code 0
# si le cache est là.
CACHE_ABSENT=$ETAT/images-cache-absent
cache_present() { # ce qui n'est pas fait, sans lui
  local lien quoi
  if ! lien=$(lien_mort "$CACHE"); then
    rm -f "$CACHE_ABSENT"
    return 0
  fi
  quoi="$lien mène à $(readlink "$lien")"
  echo "✖ Cache des images introuvable : $quoi, absent (disque débranché ?). $1" >&2
  if [[ $(cat "$CACHE_ABSENT" 2>/dev/null) != "$quoi" || -z $(find "$CACHE_ABSENT" -mmin -10080 2>/dev/null) ]]; then
    mkdir -p "$ETAT" && printf '%s\n' "$quoi" >"$CACHE_ABSENT"
    avertir "Images de la clé : cache absent" "$quoi, introuvable : disque débranché ? $1 Rien n'est recréé \
ailleurs ; une fois le disque rebranché, la minuterie reprend d'elle-même."
  fi
  return 1
}

# --- Dernières versions ----------------------------------------------------------------------------------------------
# Chaque fonction écrit « nom_de_l_image adresse_du_dossier » : le dossier de cette version précise, pour que l'image
# et sa signature viennent de la même version même si une nouvelle sort pendant le téléchargement.

derniere_arch() {
  local nom
  nom=$(lire https://geo.mirror.pkgbuild.com/iso/latest/ |
    grep -oE 'archlinux-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-x86_64\.iso' | sort -u | tail -1)
  [[ -n $nom ]] || return 1
  local date=${nom#archlinux-}
  echo "$nom https://geo.mirror.pkgbuild.com/iso/${date%-x86_64.iso}/"
}

derniere_debian() {
  local nom
  nom=$(lire https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/ |
    grep -oE 'debian-[0-9]+(\.[0-9]+)*-amd64-netinst\.iso' | sort -uV | tail -1)
  [[ -n $nom ]] || return 1
  local version=${nom#debian-}
  echo "$nom https://cdimage.debian.org/debian-cd/${version%-amd64-netinst.iso}/amd64/iso-cd/"
}

# Fedora : la plus récente des versions publiées (pas les bêtas, rangées dans releases/test/).
derniere_fedora() {
  lire https://fedoraproject.org/releases.json | python3 -I -c '
import json, sys
images = [r["link"] for r in json.load(sys.stdin)
          if r.get("arch") == "x86_64" and r.get("variant") == "Everything" and "/releases/test/" not in r["link"]
          and r["link"].rsplit("/", 1)[-1].startswith("Fedora-Everything-netinst-x86_64-")
          and r["link"].endswith(".iso")]
def version(lien):
    v = lien.rsplit("/", 1)[-1].removeprefix("Fedora-Everything-netinst-x86_64-").removesuffix(".iso")
    return [int(x) for x in v.replace("-", ".").split(".") if x.isdigit()]
if images:
    lien = max(images, key=version)
    dossier, nom = lien.rsplit("/", 1)
    print(nom, dossier.replace("://download.fedoraproject.org/", "://dl.fedoraproject.org/") + "/")
' | grep . || return 1
}

derniere_systemrescue() {
  local version
  version=$(lire https://www.system-rescue.org/Download/ | grep -oE 'systemrescue-[0-9]+(\.[0-9]+)*-amd64\.iso' |
    sed 's/^systemrescue-//; s/-amd64\.iso$//' | sort -uV | tail -1)
  [[ -n $version ]] || return 1
  echo "systemrescue-$version-amd64.iso https://fastly-cdn.system-rescue.org/releases/$version/"
}

# Omarchy : la page d'accueil donne le lien de l'image du moment (iso.omarchy.org ne liste pas ses fichiers).
derniere_omarchy() {
  local nom
  nom=$(lire https://omarchy.org/ | grep -oE 'omarchy-[0-9]+(\.[0-9]+)*\.iso' | sort -uV | tail -1)
  [[ -n $nom ]] || return 1
  echo "$nom https://iso.omarchy.org/"
}

# Kali : la live complète (« everything »), dans le dossier de sa version (cdimage.kali.org/kali-AAAA.N/). current/
# ne liste que les .torrent : le nom de l'image en est tiré.
derniere_kali() {
  local nom
  nom=$(lire https://cdimage.kali.org/current/ |
    grep -oE 'kali-linux-[0-9]{4}\.[0-9]+[a-z]?-live-everything-amd64\.iso' | sort -uV | tail -1)
  [[ -n $nom ]] || return 1
  local version=${nom#kali-linux-}
  echo "$nom https://cdimage.kali.org/kali-${version%-live-everything-amd64.iso}/"
}

# Kali, la version d'avant la dernière : son dossier reste sur cdimage.kali.org quelque temps. Le repli quand le torrent
# de la nouvelle n'a encore aucune source (le traceur de Kali refuse un torrent qu'il n'a pas encore enregistré).
precedente_kali() { # nom de la dernière
  local derniere=${1#kali-linux-} version
  derniere=${derniere%-live-everything-amd64.iso}
  version=$(lire https://cdimage.kali.org/ | grep -oE 'kali-[0-9]{4}\.[0-9]+[a-z]?/' | sed 's|^kali-||; s|/$||' |
    sort -uV | awk -v d="$derniere" '$0 == d {exit} {p = $0} END {print p}')
  [[ -n $version && $version != "$derniere" ]] || return 1
  echo "kali-linux-$version-live-everything-amd64.iso https://cdimage.kali.org/kali-$version/"
}

# Dossiers où le projet range une version précise, pour une image importée : le dossier des versions publiées,
# puis celui des archives, où partent les anciennes.
dossiers_version() { # sorte nom
  local v
  case $1 in
    arch)
      v=${2#archlinux-}
      v=${v%-x86_64.iso}
      echo "https://geo.mirror.pkgbuild.com/iso/$v/ https://archive.archlinux.org/iso/$v/"
      ;;
    debian)
      v=${2#debian-}
      v=${v%-amd64-netinst.iso}
      echo "https://cdimage.debian.org/debian-cd/$v/amd64/iso-cd/" \
        "https://cdimage.debian.org/cdimage/archive/$v/amd64/iso-cd/"
      ;;
    fedora)
      v=${2#Fedora-Everything-netinst-x86_64-}
      v=${v%%-*}
      echo "https://dl.fedoraproject.org/pub/fedora/linux/releases/$v/Everything/x86_64/iso/" \
        "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/$v/Everything/x86_64/iso/"
      ;;
    systemrescue)
      v=${2#systemrescue-}
      echo "https://fastly-cdn.system-rescue.org/releases/${v%-amd64.iso}/"
      ;;
    omarchy) echo "https://iso.omarchy.org/" ;;
    kali)
      v=${2#kali-linux-}
      v=${v%-live-everything-amd64.iso}
      echo "https://cdimage.kali.org/kali-$v/ https://old.kali.org/kali-images/kali-$v/"
      ;;
  esac
}

# Fichiers de signature à télécharger avec l'image (noms dans le dossier de la version).
signatures() { # sorte nom
  case $1 in
    arch | omarchy) echo "$2.sig" ;;
    systemrescue) echo "$2.asc" ;;
    debian) echo "SHA512SUMS SHA512SUMS.sign" ;;
    kali) echo "SHA256SUMS SHA256SUMS.gpg" ;;
    fedora)
      local v=${2#Fedora-Everything-netinst-x86_64-}
      echo "Fedora-Everything-${v%.iso}-x86_64-CHECKSUM"
      ;;
  esac
}

# --- Vérification ----------------------------------------------------------------------------------------------------

# La signature est-elle d'une des clés principales attendues pour cette sorte ? Le trousseau est jetable, dans le
# cache (pas dans /tmp, au quota partagé), et ne contient que la clé du projet.
signe_par() { # sorte statut_gpg
  local f
  for f in ${SIGNATAIRES[$1]}; do
    grep -q "^\[GNUPG:\] VALIDSIG .* $f\$" <<<"$2" && return 0
  done
  return 1
}

# Vérifie une image et ses signatures, rangées dans un même dossier. Code 0 si tout est bon ; sinon la raison sur la
# sortie d'erreur. Pour Kali, le même contrôle vaut pour son .torrent, qui est aussi dans la liste signée.
verifier_image() { # sorte dossier nom
  local sorte=$1 d=$2 nom=$3 trousseau statut attendue
  trousseau=$(mktemp -d "$CACHE/.trousseau.XXXX")
  chmod 700 "$trousseau"
  gpg --homedir "$trousseau" --quiet --import "$CLES/$sorte.asc" 2>/dev/null
  case $sorte in
    arch | systemrescue | omarchy)
      local sig
      sig=$(signatures "$sorte" "$nom")
      statut=$(gpg --homedir "$trousseau" --status-fd 1 --verify "$d/$sig" "$d/$nom" 2>/dev/null || true)
      ;;
    debian)
      statut=$(gpg --homedir "$trousseau" --status-fd 1 --verify "$d/SHA512SUMS.sign" "$d/SHA512SUMS" 2>/dev/null ||
        true)
      attendue=$(awk -v n="$nom" '$2 == n || $2 == "*" n {print $1}' "$d/SHA512SUMS")
      ;;
    kali)
      statut=$(gpg --homedir "$trousseau" --status-fd 1 --verify "$d/SHA256SUMS.gpg" "$d/SHA256SUMS" 2>/dev/null ||
        true)
      attendue=$(awk -v n="$nom" '$2 == n || $2 == "*" n {print $1}' "$d/SHA256SUMS" 2>/dev/null || true)
      ;;
    fedora)
      # La liste signée en clair : seules les lignes que gpg a vérifiées (sa sortie) sont lues, pas le fichier.
      local liste
      liste=$(signatures fedora "$nom")
      statut=$(gpg --homedir "$trousseau" --status-fd 1 --output "$trousseau/liste" --decrypt "$d/$liste" \
        2>/dev/null || true)
      attendue=$(sed -n "s/^SHA256 ($nom) = \([0-9a-f]\{64\}\)\$/\1/p" "$trousseau/liste" 2>/dev/null || true)
      ;;
  esac
  rm -rf "$trousseau"
  if ! signe_par "$sorte" "$statut"; then
    if grep -q '^\[GNUPG:\] \(NO_PUBKEY\|ERRSIG\)' <<<"$statut"; then
      echo "signée par une clé que Vanguard ne connaît pas encore (une mise à jour de Vanguard l'apportera)" >&2
    else
      echo "signature absente ou fausse" >&2
    fi
    return 1
  fi
  case $sorte in
    debian)
      [[ $attendue =~ ^[0-9a-f]{128}$ && $(sha512sum "$d/$nom" | cut -d' ' -f1) == "$attendue" ]] ||
        { echo "empreinte différente de la liste signée" >&2; return 1; }
      ;;
    fedora | kali)
      [[ $attendue =~ ^[0-9a-f]{64}$ && $(sha256sum "$d/$nom" | cut -d' ' -f1) == "$attendue" ]] ||
        { echo "empreinte différente de la liste signée" >&2; return 1; }
      ;;
  esac
}

# L'image vérifiée d'une sorte dans le cache : celle qui a son empreinte (.sha256), écrite seulement après
# vérification.
image_prete() { # sorte
  local f
  for f in "$CACHE"/${MOTIFS[$1]}; do
    [[ -f $f && -f $f.sha256 ]] && { echo "$f"; return 0; }
  done
  return 1
}

# --- Cache : télécharger et vérifier ----------------------------------------------------------------------------------

# Taille d'un fichier à télécharger, d'après les en-têtes du serveur (celle du dernier, après les redirections) ;
# rien si le serveur ne la dit pas.
taille_distante() { # url
  curl -fsSIL --retry 2 --connect-timeout 20 --max-time 60 "$1" 2>/dev/null | tr -d '\r' |
    awk 'tolower($1) ~ /^http\// {t = ""}
      tolower($1) == "content-length:" {t = $2}
      END {if (t ~ /^[0-9]+$/) print t}' || true
}

# Taille de l'image d'un .torrent : la somme des « length » de ses fichiers (un seul pour Kali).
taille_torrent() { # fichier
  grep -aoE '6:lengthi[0-9]+e' "$1" 2>/dev/null | tr -dc '0-9\n' | sed 's/^6//' |
    awk '{s += $1} END {if (s > 0) printf "%d\n", s}' || true
}

# Au début de chaque téléchargement, une notification : quoi, et combien (16 Gio de Kali ne passent pas inaperçus
# sur une connexion lente ou facturée au volume).
annoncer() { # sorte nom octets (vide : inconnue) reprise (vide, ou « reprise »)
  local taille=${3:+$(lisible "$3")} torrent=""
  [[ $1 != kali ]] || torrent=" (torrent, jusqu'à 5 heures)"
  echo "  ${4:+reprise, }${taille:-taille inconnue}"
  avertir "Images de la clé : ${4:+reprise du }téléchargement" "${NOMS[$1]} : $2, ${taille:-taille inconnue}$torrent."
}

# Télécharge l'image dans le dossier de la version, où sont déjà ses signatures ; en échec, RAISON dit pourquoi.
# Kali ne publie sa live complète qu'en torrent : aria2c la prend, sans la repartager ensuite. Le .torrent vient d'un
# miroir (cdimage.kali.org renvoie ailleurs) : il est vérifié par la liste signée avant qu'aria2c le lise, et
# l'image le sera après. Le traceur de Kali refuse un torrent qu'il n'a pas encore enregistré (« not authorized ») :
# la DHT, amorcée par un point d'entrée connu, trouve les pairs sans lui. Sans débit pendant 10 minutes, aria2c
# abandonne ; au bout de 5 heures, il est arrêté (le service en laisse 8), et Ctrl-C l'atteint aussi (--foreground,
# lancé à la main) ; un torrent coupé reprend où il en était à la recherche suivante (son fichier .aria2).
telecharger() { # sorte url nom dossier
  RAISON="téléchargement interrompu"
  if [[ $1 != kali ]]; then
    annoncer "$1" "$3" "$(taille_distante "$2$3")" ""
    curl -fL --retry 3 --connect-timeout 20 --progress-bar -o "$4/$3" "$2$3"
    return
  fi
  if ! command -v aria2c >/dev/null; then
    RAISON="aria2c manque (paquet aria2) : Kali n'est publiée qu'en torrent"
    return 1
  fi
  if [[ ! -s $4/$3.torrent ]] && ! lire "$2$3.torrent" >"$4/$3.torrent"; then
    RAISON="torrent introuvable"
    return 1
  fi
  local r code=0
  if ! r=$(verifier_image kali "$4" "$3.torrent" 2>&1); then
    rm -f "$4/$3.torrent"
    RAISON="torrent refusé : $r"
    return 1
  fi
  annoncer kali "$3" "$(taille_torrent "$4/$3.torrent")" "$([[ -s $4/$3 ]] && echo reprise)"
  rm -f "$4/.aria2.log"
  timeout --foreground --kill-after=1m 5h aria2c --seed-time=0 --bt-stop-timeout=600 --check-integrity=true \
    --enable-dht=true --dht-entry-point=router.bittorrent.com:6881 --dht-file-path="$CACHE/.dht.dat" \
    --bt-enable-lpd=false --max-overall-upload-limit=500K --file-allocation=none --summary-interval=0 \
    --console-log-level=error --log="$4/.aria2.log" --log-level=warn --dir="$4" "$4/$3.torrent" >/dev/null 2>&1 ||
    code=$?
  if ((code == 0)) && [[ -s $4/$3 && ! -e $4/$3.aria2 ]]; then
    return 0
  fi
  case $code in
    0) RAISON="torrent incomplet" ;;
    124 | 137) RAISON="plus de 5 heures de téléchargement : il reprendra à la prochaine recherche" ;;
    9) RAISON="pas la place dans le cache (16 Gio)" ;;
    *) RAISON="aucune source en 10 minutes : traceur qui refuse ce torrent, aucun pair" ;;
  esac
  tail -n 3 "$4/.aria2.log" 2>/dev/null | sed 's/^/    aria2c : /' || true
  return 1
}

# Range dans le cache une image vérifiée avec ses signatures (pour --verifier), puis son empreinte, le témoin d'une
# image vérifiée ; les versions d'avant de cette sorte partent ensuite, avec leurs signatures.
ranger() { # sorte dossier nom
  local sorte=$1 d=$2 nom=$3 f
  for f in $(signatures "$sorte" "$nom"); do mv -f "$d/$f" "$CACHE/$nom.${f##*.}"; done
  mv -f "$d/$nom" "$CACHE/$nom"
  sha256sum "$CACHE/$nom" | cut -d' ' -f1 >"$CACHE/$nom.sha256.part"
  mv -f "$CACHE/$nom.sha256.part" "$CACHE/$nom.sha256"
  for f in "$CACHE"/${MOTIFS[$sorte]}; do
    if [[ -f $f && $f != "$CACHE/$nom" ]]; then rm -f "$f" "$f".*; fi
  done
}

# Dossier du téléchargement d'une version. Kali : un par version, pour que le torrent de chacune reprenne où il en
# était (la dernière, ou la précédente prise à sa place quand la dernière n'a pas de source : le dossier de l'une ne
# vide pas celui de l'autre). Les autres sortes : un seul, vidé à chaque fois (curl repart de zéro).
dossier_neuf() { # sorte nom
  if [[ $1 == kali ]]; then
    local v=${2#kali-linux-}
    echo "$CACHE/.nouveau-kali-${v%-live-everything-amd64.iso}"
  else
    echo "$CACHE/.nouveau-$1"
  fi
}

# Les torrents de Kali en cours, sauf ceux des versions données : plus rien ne les reprendrait, et chacun garde jusqu'à
# 16 Gio.
retirer_kali_sauf() { # noms des images dont le torrent reste…
  local d n garde
  for d in "$CACHE"/.nouveau-kali-*; do
    [[ -d $d ]] || continue
    garde=""
    for n in "$@"; do [[ $d == "$(dossier_neuf kali "$n")" ]] && garde=1; done
    [[ -n $garde ]] || rm -rf "$d"
  done
}

# Une version d'une sorte : téléchargée avec ses signatures, vérifiée, rangée. Code 1 si le téléchargement échoue,
# 2 si l'image est refusée (et effacée) ; RAISON dit pourquoi.
prendre() { # sorte nom url
  local sorte=$1 nom=$2 url=$3 neuf f r
  neuf=$(dossier_neuf "$sorte" "$nom")
  # Un torrent coupé reprend où il en était, même arrêté avant la vérification (aria2c revérifie chaque morceau).
  [[ $sorte == kali && -e $neuf/$nom ]] || rm -rf "$neuf"
  mkdir -p "$neuf"
  echo "↓ ${NOMS[$sorte]} : $nom"
  for f in $(signatures "$sorte" "$nom"); do
    lire "$url$f" >"$neuf/$f" || true
  done
  if ! telecharger "$sorte" "$url" "$nom" "$neuf"; then
    [[ $sorte == kali && -s $neuf/$nom ]] || rm -rf "$neuf"
    return 1
  fi
  if ! r=$(verifier_image "$sorte" "$neuf" "$nom" 2>&1); then
    rm -rf "$neuf"
    RAISON="$r, image effacée"
    echo "✖ ${NOMS[$sorte]} : $RAISON"
    return 2
  fi
  ranger "$sorte" "$neuf" "$nom"
  rm -rf "$neuf"
  echo "✔ ${NOMS[$sorte]} : $nom vérifiée (signature du projet)"
}

chercher() {
  secours_demandee "aucune image n'est cherchée ni téléchargée." || return 0
  cache_present "Rien n'est cherché ni téléchargé." || return 0
  mkdir -p "$CACHE"
  local sorte ligne nom url neuves=() echecs=() replis=() prets=() perdus=() code
  for sorte in "${SORTES[@]}"; do
    if ! ligne=$("derniere_$sorte" 2>/dev/null); then
      echo "· ${NOMS[$sorte]} : dernière version introuvable (pas d'Internet, ou site changé)"
      perdus+=("${NOMS[$sorte]}")
      continue
    fi
    read -r nom url <<<"$ligne"
    if [[ -f $CACHE/$nom && -f $CACHE/$nom.sha256 ]]; then
      echo "✔ ${NOMS[$sorte]} : $nom, déjà prête"
      prets+=("${NOMS[$sorte]}")
      # La dernière Kali est prête : plus aucun torrent ne sert.
      [[ $sorte != kali ]] || retirer_kali_sauf
      continue
    fi
    code=0
    prendre "$sorte" "$nom" "$url" || code=$?
    if ((code == 0)); then
      neuves+=("$nom")
      [[ $sorte != kali ]] || retirer_kali_sauf
    elif ((code == 2)) || [[ $sorte != kali ]]; then
      echecs+=("${NOMS[$sorte]} : $RAISON")
    else
      # Kali sans source : la version d'avant reste (sur la clé, et dans le cache s'il l'a). Un cache sans Kali prend
      # la précédente, seulement si le torrent n'a rien reçu : un torrent qui avançait reprendra là où il en est.
      local avant raison=$RAISON
      echo "· Kali Linux : $nom pas téléchargée ($raison)"
      # Un torrent sans source n'est pas une image refusée : la notification le dit à part, sans échec.
      if avant=$(image_prete kali); then
        # Une Kali prête reste : seul le torrent de la dernière peut encore servir.
        retirer_kali_sauf "$nom"
        replis+=("$nom pas téléchargée ($raison) ; ${avant##*/} reste, nouvel essai à la prochaine recherche.")
      elif [[ $raison == aucune\ source* && ! -s $(dossier_neuf kali "$nom")/$nom ]] &&
        ligne=$(precedente_kali "$nom"); then
        read -r avant url <<<"$ligne"
        # Le torrent de la précédente reprend où il en était ; ceux des autres versions ne serviront plus.
        retirer_kali_sauf "$avant"
        code=0
        prendre kali "$avant" "$url" || code=$?
        if ((code == 0)); then
          neuves+=("$avant")
          replis+=("$nom pas téléchargée ($raison) ; la version d'avant, $avant, prise à sa place.")
        elif ((code == 2)); then
          echecs+=("Kali Linux : $avant : $RAISON")
        else
          replis+=("$nom pas téléchargée ($raison), ni $avant ($RAISON) ; nouvel essai à la prochaine recherche.")
        fi
      else
        # La dernière a reçu quelque chose : elle reprendra, et la précédente ne sera plus prise à sa place.
        if [[ -s $(dossier_neuf kali "$nom")/$nom ]]; then retirer_kali_sauf "$nom"; fi
        replis+=("$nom pas téléchargée ($raison) ; nouvel essai à la prochaine recherche.")
      fi
    fi
  done
  # Le démarrage de la clé aussi : un Ventoy plus récent que celui épinglé est signalé, jamais pris tout seul.
  outils/cle-secours.sh --ventoy-publie || true
  if ((${#neuves[@]})); then
    avertir "Clé VANGUARD : nouvelles images prêtes" \
      "$(printf '%s\n' "${neuves[@]}")
Sur la clé, chacune remplace sa version d'avant : aussitôt si la clé est branchée (recherche de la minuterie), sinon à \
son prochain branchement. Une image que la clé n'a pas encore n'y va pas toute seule : outils/images-cle.sh --toutes \
POINT."
  fi
  if ((${#replis[@]})); then
    avertir "Clé VANGUARD : Kali Linux pas mise à jour" "$(printf '%s\n' "${replis[@]}")"
  fi
  if ((${#echecs[@]})); then
    avertir "Clé VANGUARD : image refusée" "$(printf '%s\n' "${echecs[@]}")"
    return 1
  fi
  # Rien de neuf, ni refusé ni en retard : dit aussi, pour qu'une recherche faite se distingue d'une minuterie arrêtée.
  if ((${#neuves[@]} + ${#replis[@]} == 0)); then
    local texte=""
    ((${#prets[@]} == 0)) || texte="Déjà à jour : $(joindre "${prets[@]}")."
    if ((${#perdus[@]})); then
      texte+="${texte:+$'\n'}Pas jointes (pas d'Internet, ou site changé) : $(joindre "${perdus[@]}") ; nouvel \
essai à la prochaine recherche."
    fi
    ((${#prets[@]})) || echo "Rien de vérifié : nouvel essai à la prochaine minuterie."
    avertir "Images de la clé : rien de nouveau" "$texte"
  fi
}

# Des noms séparés par des virgules.
joindre() { # nom…
  local IFS=,
  local texte="$*"
  echo "${texte//,/, }"
}

# Une image téléchargée ailleurs (client torrent, autre ordinateur) entre dans le cache vérifiée comme les autres : sa
# sorte d'après son nom, les signatures de sa version prises chez son projet, puis la même vérification, faite sur la
# copie rangée dans le cache et non sur le fichier d'origine, qui reste où il est (un client torrent continue de le
# partager). Sur le même disque, la copie ne prend pas de place (reflink) ; sinon, elle en prend autant que l'image.
importer() { # fichier
  local fichier=$1 nom sorte="" s prete url trouve="" d f ok r
  secours_demandee "rien n'est importé." >&2 || exit 1
  [[ -f $fichier ]] || erreur "$fichier : pas un fichier."
  cache_present "Rien n'est importé." || exit 1
  nom=${fichier##*/}
  local attendus=()
  for s in "${SORTES[@]}"; do
    attendus+=("${MOTIFS[$s]}")
    # shellcheck disable=SC2053 # motif voulu
    if [[ $nom == ${MOTIFS[$s]} ]]; then sorte=$s; fi
  done
  [[ -n $sorte ]] || erreur "$nom : pas une image que la clé tient sur cet ordinateur (noms attendus : ${attendus[*]})."
  if [[ -f $CACHE/$nom && -f $CACHE/$nom.sha256 ]]; then
    echo "✔ ${NOMS[$sorte]} : $nom, déjà prête dans le cache"
    return 0
  fi
  if prete=$(image_prete "$sorte") && [[ $(printf '%s\n' "$nom" "${prete##*/}" | sort -V | tail -1) != "$nom" ]]; then
    erreur "le cache a déjà ${prete##*/}, plus récente que $nom : rien d'importé."
  fi
  mkdir -p "$CACHE"
  d=$CACHE/.import-$sorte
  rm -rf "$d"
  mkdir -p "$d"
  # Retiré à la sortie, quelle qu'elle soit : refus, copie ratée (disque plein, image illisible), Ctrl-C. Une copie
  # depuis un autre disque garde sinon jusqu'à 16 Gio dans le cache, jusqu'au prochain import de la même sorte.
  # shellcheck disable=SC2064 # le chemin, fixé maintenant
  trap "rm -rf $(printf %q "$d")" EXIT
  for url in $(dossiers_version "$sorte" "$nom"); do
    ok=1
    for f in $(signatures "$sorte" "$nom"); do
      lire "$url$f" >"$d/$f" 2>/dev/null || ok=0
    done
    if ((ok)); then
      trouve=$url
      break
    fi
  done
  if [[ -z $trouve ]]; then
    erreur "signatures de $nom introuvables chez ${NOMS[$sorte]} (pas d'Internet, ou version retirée) : rien d'importé."
  fi
  echo "→ ${NOMS[$sorte]} : $nom copiée dans le cache, puis vérifiée (signatures de $trouve)…"
  cp --reflink=auto "$fichier" "$d/$nom"
  if ! r=$(verifier_image "$sorte" "$d" "$nom" 2>&1); then
    erreur "${NOMS[$sorte]} : $nom, $r : rien d'importé (téléchargement pas fini, ou image abîmée)."
  fi
  ranger "$sorte" "$d" "$nom"
  rm -rf "$d"
  trap - EXIT
  echo "✔ ${NOMS[$sorte]} : $nom vérifiée (signature du projet), prête dans le cache"
  avertir "Clé VANGUARD : image importée" "$nom vérifiée. Elle ira sur la clé à son prochain branchement si la clé \
en a déjà une version (sinon : outils/images-cle.sh --toutes POINT)."
}

# Revérifie chaque image prête du cache avec les signatures gardées à côté. Une facultative absente est dite, sans
# compter comme une erreur.
verifier_cache() {
  local sorte image tout=0 lien
  secours_demandee "aucune image à vérifier." || return 0
  if lien=$(lien_mort "$CACHE"); then
    echo "  ✖ Images Linux : cache introuvable ($lien mène à $(readlink "$lien"), absent : disque débranché ?)"
    return 1
  fi
  for sorte in "${SORTES[@]}"; do
    if ! image=$(image_prete "$sorte"); then
      if [[ $FACULTATIVES == *" $sorte "* ]]; then
        echo "  · ${NOMS[$sorte]} : pas d'image prête (facultative : outils/images-cle.sh --chercher ou --importer)"
      else
        echo "  ✖ ${NOMS[$sorte]} : pas d'image prête (outils/images-cle.sh --chercher)"
        tout=1
      fi
      continue
    fi
    local d nom f raison
    d=$(mktemp -d "$CACHE/.verification.XXXX")
    nom=${image##*/}
    ln -s "$image" "$d/$nom"
    for f in $(signatures "$sorte" "$nom"); do
      [[ -f $image.${f##*.} ]] && ln -s "$image.${f##*.}" "$d/$f"
    done
    if raison=$(verifier_image "$sorte" "$d" "$nom" 2>&1); then
      echo "  ✔ ${NOMS[$sorte]} : $nom (signature du projet)"
    else
      echo "  ✖ ${NOMS[$sorte]} : $nom, $raison"
      tout=1
    fi
    rm -rf "$d"
  done
  return $tout
}

# --- Clé ------------------------------------------------------------------------------------------------------------

# La clé VANGUARD montée (témoin vanguard.cle), comme deployer.sh la cherche. Sans /run/media/$USER (rien de monté
# depuis le démarrage), find échoue : c'est « pas de clé », pas une erreur qui arrêterait le script en silence.
point_cle() {
  find "/run/media/$USER" -maxdepth 2 -name vanguard.cle -printf '%h\n' 2>/dev/null | head -1 || true
}

# Empreinte d'un fichier de la clé lu sur la clé même, pas dans la mémoire où la copie vient de passer (O_DIRECT,
# sinon une lecture ordinaire).
empreinte_sur_cle() { # fichier
  { dd if="$1" iflag=direct bs=4M status=none 2>/dev/null || cat "$1"; } | sha256sum | cut -d' ' -f1
}

libre_mio() { df --output=avail -B1M "$1" | tail -1 | tr -d ' '; }
taille_mio() { echo $((($(stat -c %s "$1") + MIO - 1) / MIO)); }

# Copie les images neuves sur la clé : sous un nom temporaire (que Ventoy ne montre pas), relue, puis renommée ;
# l'ancienne version n'est retirée qu'après. Si la place manque, l'ancienne est retirée d'abord (la clé reste
# démarrable avec les autres images) ; si ça ne suffit pas, une image en option de cet ordinateur (Kali) part pour
# une image tenue par défaut, plus utile en secours. Le même verrou que deployer.sh : les deux partent au branchement.
copier_sur_cle() { # point (facultatif), toutes (facultatif : aussi les sortes absentes de la clé)
  local point=${1:-} toutes=${2:-}
  # Au branchement et chaque jour (les services), rien à faire n'est pas une erreur ; demandé à la main (--toutes),
  # c'est un refus.
  if ! secours_demandee "aucune image n'est copiée sur la clé."; then
    [[ -z $toutes ]] || return 1
    return 0
  fi
  [[ -n $point ]] || point=$(point_cle)
  [[ -n $point && -d $point ]] || { echo "Clé VANGUARD non branchée : rien à copier."; return 0; }
  # Au branchement, un cache absent n'est pas une erreur de la clé : dit, puis arrêt sans rien toucher. Demandé à la
  # main (--toutes, nouvelle clé), il en est une.
  if ! cache_present "La clé n'est pas mise à jour."; then
    [[ -z $toutes ]] || return 1
    return 0
  fi
  exec 9>"${XDG_RUNTIME_DIR:-/tmp}/vanguard-deployer.lock"
  flock 9
  local iso=$point/ISO sorte image nom copiees=() manque=() echecs=() cedees=() p interrompues=" "
  mkdir -p "$iso"
  # Copies interrompues (clé retirée en route, ordinateur éteint, relecture différente) : jamais montrées par Ventoy,
  # retirées ici. Leur sorte compte comme déjà sur la clé : faute de place, son ancienne version a pu partir avant la
  # copie, et la clé n'en aurait sinon plus aucune jusqu'à un --toutes lancé à la main.
  for p in "$iso"/.*.part; do
    [[ -f $p ]] || continue
    p=${p##*/.}
    for sorte in "${SORTES[@]}"; do
      # shellcheck disable=SC2053 # motif voulu
      if [[ ${p%.part} == ${MOTIFS[$sorte]} ]]; then interrompues+="$sorte "; fi
    done
  done
  find "$iso" -maxdepth 1 -name '.*.part' -delete
  for sorte in "${SORTES[@]}"; do
    image=$(image_prete "$sorte") || continue
    nom=${image##*/}
    if [[ -f $iso/$nom && $(stat -c %s "$iso/$nom") == "$(stat -c %s "$image")" ]]; then
      continue
    fi
    local anciennes=() a anciennes_mio=0 besoin
    while IFS= read -r -d '' a; do
      anciennes+=("$a")
      anciennes_mio=$((anciennes_mio + $(taille_mio "$a")))
    done < <(find "$iso" -maxdepth 1 -iname "${MOTIFS[$sorte]}" ! -name "$nom" -print0)
    # Au branchement, seulement ce que la clé a déjà : on ne remplit pas une clé qu'on n'a pas préparée pour ça.
    if [[ -z $toutes && ! -f $iso/$nom && $interrompues != *" $sorte "* ]] && ((${#anciennes[@]} == 0)); then
      continue
    fi
    besoin=$(($(taille_mio "$image") + MARGE_MIO))
    if (($(libre_mio "$point") < besoin)); then
      # Les images en option vont en dernier : une image tenue par défaut qui ne tient pas, même sans son ancienne
      # version, prend leur place. Seulement celles que cet ordinateur tient : une Kali posée par un autre reste.
      local options=() options_mio=0 o s
      if [[ $FACULTATIVES != *" $sorte "* ]] && (($(libre_mio "$point") + anciennes_mio < besoin)); then
        for s in "${SORTES[@]}"; do
          [[ $FACULTATIVES == *" $s "* ]] || continue
          while IFS= read -r -d '' o; do
            options+=("$o")
            options_mio=$((options_mio + $(taille_mio "$o")))
          done < <(find "$iso" -maxdepth 1 -iname "${MOTIFS[$s]}" -print0)
        done
      fi
      if (($(libre_mio "$point") + anciennes_mio + options_mio < besoin)); then
        manque+=("${NOMS[$sorte]} (il manque $((besoin - $(libre_mio "$point") - anciennes_mio - options_mio)) Mio)")
        continue
      fi
      if ((${#options[@]})); then
        rm -f "${options[@]}"
        for o in "${options[@]}"; do cedees+=("${o##*/}, pour ${NOMS[$sorte]}"); done
      fi
      if (($(libre_mio "$point") < besoin)); then
        rm -f "${anciennes[@]}"
        anciennes=()
      fi
    fi
    echo "→ ${NOMS[$sorte]} : $nom sur la clé…"
    # Écriture puis relecture : une dizaine de Mio par seconde en tout sur une clé USB lente (l'image de Kali, 16 Gio,
    # y prend près d'une demi-heure).
    avertir "Clé VANGUARD : copie de ${NOMS[$sorte]}" \
      "Ne retire pas la clé avant la fin (jusqu'à $((($(taille_mio "$image") + 599) / 600)) min sur une clé lente)."
    local part=$iso/.$nom.part
    if ! cp "$image" "$part" || ! sync "$part" || [[ $(empreinte_sur_cle "$part") != "$(cat "$image.sha256")" ]]; then
      # Vidée, pas retirée : son nom reste la trace de la copie à refaire au prochain passage (l'ancienne version a pu
      # partir faute de place). Clé retirée en route : la copie y est restée, avec le même effet.
      : >"$part" 2>/dev/null || true
      echecs+=("${NOMS[$sorte]} : copie différente de l'image vérifiée, refaite au prochain passage")
      continue
    fi
    mv -f "$part" "$iso/$nom"
    ((${#anciennes[@]})) && rm -f "${anciennes[@]}"
    copiees+=("$nom")
  done
  menu "$point"
  sync -f "$point/ventoy/ventoy.json"
  redire_au_manifeste "$point" "${copiees[@]}"
  if ((${#copiees[@]})); then
    avertir "Clé VANGUARD : images à jour" "$(printf '%s\n' "${copiees[@]}")"
  fi
  if ((${#manque[@]})); then
    avertir "Clé VANGUARD : pas la place" "$(printf '%s\n' "${manque[@]}")"
  fi
  if ((${#cedees[@]})); then
    avertir "Clé VANGUARD : image en option retirée" "$(printf '%s\n' "${cedees[@]}")
Les images en option passent après les autres. La remettre s'il reste la place : outils/images-cle.sh --toutes POINT."
  fi
  if ((${#echecs[@]})); then
    avertir "Clé VANGUARD : copie ratée" "$(printf '%s\n' "${echecs[@]}")"
    return 1
  fi
}

# Le manifeste de la clé (src/protection/manifeste.rs) relève ISO/ (taille) et ventoy/ (empreinte) : ce qui est posé
# ici lui est redit, seulement les images copiées et vérifiées à l'instant, et le menu qui vient d'être réécrit. Une
# image que ce script n'a pas posée reste hors de la référence : le bilan la dit nouvelle. Sans vanguard, ou sans
# référence pour cette clé (pas encore déployée, ou d'avant les images) : dit, le bilan les dira changées.
redire_au_manifeste() { # point, images copiées…
  local point=$1 programme n args=()
  shift
  programme=$(command -v vanguard || true)
  # Hors des essais (outils/essais-cle.sh), la copie de cargo install, que le PATH des services n'a pas.
  [[ -n $programme || -n ${VANGUARD_ESSAI:-} ]] || programme=$HOME/.cargo/bin/vanguard
  if [[ -z $programme || ! -x $programme ]]; then
    echo "· manifeste de la clé : vanguard introuvable, images non redites (le bilan les dira changées)"
    return 0
  fi
  for n in "$@"; do args+=(--image "$n"); done
  "$programme" manifeste --images "$point" "${args[@]}" ||
    echo "· manifeste de la clé : images non redites (le bilan les dira changées)"
}

# ventoy.json : Ventoy ne cherche que dans ISO/ (pas dans les dossiers de Vanguard), menu en français, un nom clair pour
# chaque image présente. Écrit à côté puis renommé : une clé retirée en route garde l'ancien menu ; et seulement s'il
# change (chaque écriture use un peu la clé, et la mise à jour du jour repasse sur une clé restée branchée).
menu() { # point
  local point=$1
  secours_demandee "le menu de Ventoy n'est pas écrit." || return 1
  mkdir -p "$point/ventoy"
  find "$point/ISO" -maxdepth 1 -type f -iname '*.iso' -printf '%f\n' 2>/dev/null | sort | python3 -I -c '
import fnmatch, json, sys
noms = [
    (["Win11*.iso", "Windows11*.iso"], "Windows 11 (secours, si le PC ne propose pas WIN11)"),
    (["archlinux-*.iso"], "Arch Linux : installer par Internet"),
    (["debian-*-netinst.iso"], "Debian : installer par Internet"),
    (["Fedora-Everything-netinst-*.iso"], "Fedora : installer par Internet"),
    (["systemrescue-*.iso"], "SystemRescue : réparer, sauver des fichiers, tester la mémoire"),
    (["omarchy-*.iso"], "Omarchy : installer (sans Internet)"),
    (["kali-linux-*-live-everything-*.iso"], "Kali Linux : outils de sécurité (live complète)"),
]
alias = []
for image in sys.stdin.read().split("\n"):
    for motifs, nom in noms:
        if image and any(fnmatch.fnmatch(image.lower(), m.lower()) for m in motifs):
            alias.append({"image": "/ISO/" + image, "alias": nom})
            break
print(json.dumps({"control": [{"VTOY_DEFAULT_SEARCH_ROOT": "/ISO"}, {"VTOY_MENU_LANGUAGE": "fr_FR"}],
                  "menu_alias": alias}, ensure_ascii=False, indent=2))
' >"$point/ventoy/ventoy.json.part"
  if cmp -s "$point/ventoy/ventoy.json.part" "$point/ventoy/ventoy.json"; then
    rm -f "$point/ventoy/ventoy.json.part"
  else
    mv -f "$point/ventoy/ventoy.json.part" "$point/ventoy/ventoy.json"
  fi
}

etat() {
  local sorte image point lien
  secours_demandee "aucune image n'est tenue." || true
  echo "Cache ($CACHE) :"
  if lien=$(lien_mort "$CACHE"); then
    echo "  ✖ introuvable : $lien mène à $(readlink "$lien"), absent (disque débranché ?)"
  fi
  for sorte in "${SORTES[@]}"; do
    if image=$(image_prete "$sorte"); then echo "  ✔ ${NOMS[$sorte]} : ${image##*/}"
    else echo "  · ${NOMS[$sorte]} : rien de prêt"; fi
  done
  point=$(point_cle)
  if [[ -z $point ]]; then
    echo "Clé VANGUARD : pas branchée."
    return
  fi
  echo "Clé ($point/ISO, $(libre_mio "$point") Mio libres) :"
  local f
  for f in "$point"/ISO/*.iso; do
    [[ -f $f ]] || continue
    local statut="" s
    [[ -n $SECOURS ]] || statut="(pas tenue sur cet ordinateur)"
    for s in "${SORTES[@]}"; do
      # shellcheck disable=SC2053 # motif voulu
      if [[ ${f##*/} == ${MOTIFS[$s]} ]]; then
        image=$(image_prete "$s" || true)
        if [[ -z $image ]]; then statut="(rien dans le cache pour comparer)"
        elif [[ ${image##*/} == "${f##*/}" ]]; then statut="à jour"
        else statut="ancienne : ${image##*/} ira au prochain branchement"; fi
      fi
    done
    echo "  ${f##*/} $statut"
  done
}

# Lu par outils/essais-cle.sh (source) : les fonctions seulement, rien n'est lancé.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
case ${1:-} in
  --chercher) chercher ;;
  --importer) importer "${2:?image à importer}" ;;
  --verifier) verifier_cache ;;
  --cle) copier_sur_cle "${2:-}" ;;
  --toutes) copier_sur_cle "${2:?point de montage de la clé}" toutes ;;
  --menu) menu "${2:?point de montage de la clé}" && redire_au_manifeste "$2" ;;
  --etat) etat ;;
  --sortes) echo "${SORTES[*]}" ;;
  --secours) if [[ -n $SECOURS ]]; then echo oui; else echo non; exit 1; fi ;;
  *) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
