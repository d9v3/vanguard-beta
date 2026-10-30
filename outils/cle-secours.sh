#!/usr/bin/env bash
# Clé de secours : la clé VANGUARD démarre aussi les ordinateurs, pour réparer ou réinstaller Linux, Windows et macOS.
# FAITE PAR DÉFAUT, sauf sur un ordinateur dont le réglage local la coupe : une ligne CLE_SECOURS=non dans
# ~/.config/vanguard/images-cle.conf (le détail : en-tête de outils/images-cle.sh). Là, une clé ne porte que le
# programme (outils/preparer-cle.sh : VANGUARD et VANGUARDLOG, ni images, ni Ventoy, ni WIN11, ni MACOS), et chaque
# commande ci-dessous refuse en le disant, sauf --a-jour (appelée au branchement et chaque jour), qui ne fait rien, et
# --ventoy-publie, qui ne fait que lire GitHub (--racine, la partie root, ne part que de --ecrire).
#   1 VANGUARD     partition de Ventoy, exFAT : Vanguard comme avant (témoin vanguard.cle), et ses images dans ISO/ :
#                 Omarchy (installateur complet), Arch Linux, Debian et Fedora en installateurs par Internet, SystemRescue
#                 (réparer, sauver des fichiers, tester la mémoire), puis, s'il reste la place, Windows 11 en
#                 secours. Les images Linux viennent de outils/images-cle.sh, qui les vérifie et les tient à jour au
#                 branchement ; en option, Kali Linux (live complète, 16 Gio, avant Windows), seulement sur un
#                 ordinateur dont le réglage local la demande (voir images-cle.sh). Attribut GPT « lecture seule »
#                 (bit 60) : Windows la monte en lecture seule.
#   2 VTOYEFI     32 Mio, démarrage de Ventoy (UEFI) ; ne jamais y toucher.
#   3 VANGUARDLOG  64 Mio, exFAT, modifiable partout : le journal des erreurs (src/journal.rs).
#   4 MACOS       HFS+ : la récupération de macOS, téléchargée chez Apple (BaseSystem), pour les Mac Intel.
#   5 WIN11       FAT32 : l'installation de Windows 11, qui démarre d'elle-même (menu de démarrage du PC), Secure Boot
#                 actif, sans ajouter de clé (MOK) au PC comme Ventoy le demande. install.wim y est découpé en morceaux
#                 de moins de 4 Go (limite d'un fichier en FAT32) par wimlib ; l'installation de Windows les relit.
# Ventoy (GPL-3.0) démarre les images posées dans la partition 1 ; il exige d'y rester, suivi de sa partition
# VTOYEFI, et laisse ajouter les nôtres dans la place réservée en fin de clé (-r).
#
# PRÉPARATION : rien n'est écrit sur un disque sans --ecrire, qui EFFACE la clé (après une sauvegarde).
#   outils/cle-secours.sh --plan [/dev/sdX] [DOSSIER] la disposition, la place, les commandes ; rien n'est lancé
#   outils/cle-secours.sh --essai [DOSSIER_IMAGES]    la disposition jouée sur une image de disque, sans root
#   outils/cle-secours.sh --telecharger DOSSIER       télécharge les images et les vérifie
#   outils/cle-secours.sh --verifier DOSSIER          vérifie les images, et la partition WIN11 si elle est montée
#   outils/cle-secours.sh --ecrire /dev/sdX DOSSIER   sauvegarde, EFFACE et refait la clé (root : une fenêtre pkexec)
#   outils/cle-secours.sh --windows /dev/sdX DOSSIER  remplit ou répare la partition WIN11 d'une clé déjà faite,
#                                                     sans rien effacer d'autre (ni root)
# Windows 11 se télécharge à la main chez Microsoft (lien valable 24 h) : --telecharger dit comment.
#
# LA CLÉ DÉJÀ FAITE, tenue à jour sans rien effacer :
#   outils/cle-secours.sh --a-jour [POINT]        la clé branchée : Ventoy lu sur la clé ; plus ancien que l'épingle,
#                                                 sa mise à jour est proposée (notification à cliquer ; chaque jour par
#                                                 outils/maj-cle.sh, et au branchement). Windows 11 de plus de six mois
#                                                 est signalé : son image se prend à la main chez Microsoft
#   outils/cle-secours.sh --ventoy-maj [/dev/sdX] met Ventoy à jour sur la clé, sans rien effacer (root : une fenêtre
#                                                 pkexec ; journal dans ~/.local/state/vanguard/ventoy/)
#   outils/cle-secours.sh --accepter-vtoyefi      la partition de démarrage VTOYEFI de la clé branchée, telle qu'elle
#                                                 est, prise pour référence (--a-jour compare l'empreinte de ses
#                                                 fichiers à chaque passage, et alerte sur un écart) ; partie de la
#                                                 clé, sa référence retirée
#   outils/cle-secours.sh --installer-racine      une fois, et après chaque changement d'épingle : la partie root de
#                                                 --ventoy-maj (outils/ventoy-racine.sh), copiée en fichier de root
#   outils/cle-secours.sh --ventoy-publie         (développement) GitHub a-t-il un Ventoy plus récent que l'épingle ?
# Le dossier des images (DOSSIER) et le cache d'images-cle.sh peuvent être des liens vers un autre disque : disque
# absent, rien n'est recréé à leur place.
# Essais : VANGUARD_VTOYEFI et VANGUARD_WIN11, des dossiers lus à la place des partitions VTOYEFI et WIN11 de la clé ;
# outils/essais-cle.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
# L'épingle de Ventoy (VENTOY, VENTOY_SHA256), cle_ventoy et les petites fonctions communes : dans la partie root de la
# mise à jour, pour qu'une seule épingle fasse foi (outils/ventoy-racine.sh).
# shellcheck source=outils/ventoy-racine.sh
source outils/ventoy-racine.sh

VENTOY_DEPOT=https://github.com/ventoy/Ventoy/releases
# La partie root installée, que pkexec lance (--installer-racine la pose). VANGUARD_RACINE en désigne une autre, dans
# les essais seulement (VANGUARD_ESSAI, posée par outils/essais-cle.sh) : racine_installee ne demande qu'un fichier de
# root identique à celui du dépôt, et une variable du compte ferait sinon lancer par pkexec n'importe quel programme de
# root recopié dans le dépôt.
RACINE=/usr/local/libexec/vanguard/ventoy-racine
if [[ -n ${VANGUARD_RACINE:-} && -n ${VANGUARD_ESSAI:-} ]]; then
  RACINE=$VANGUARD_RACINE
elif [[ -n ${VANGUARD_RACINE:-} ]]; then
  echo "· VANGUARD_RACINE ignorée hors des essais (sans VANGUARD_ESSAI) : la partie root reste $RACINE." >&2
fi
# Ce qui a été proposé ou dit (une fois par jour au plus), et les journaux des mises à jour de Ventoy.
ETAT=${XDG_STATE_HOME:-$HOME/.local/state}/vanguard
OPENCORE=1.0.8
MACRECOVERY_SHA256=3023a9b4ca79a5255d93c00f25ab5df37e6f938b729b797d9ecea56184b17aff
# Récupération de macOS : Monterey par défaut, la plus récente des Mac Intel sans puce T2 (2015 à 2017), qui
# démarrent sur une clé sans réglage ; les Mac T2 (2018 à 2020) le refusent tant qu'on ne l'a pas permis dans
# Utilitaire Sécurité au démarrage. Autre version : VANGUARD_MACOS_CARTE (identifiants de macrecovery).
MACOS_CARTE=${VANGUARD_MACOS_CARTE:-Mac-E43C1C25D4880AD6}
MIO=$((1024 * 1024))
JOURNAL_MIO=64
VTOYEFI_MIO=$((VTOYEFI_OCTETS / MIO))
# Taille de la récupération de Monterey (volume HFS+ de 2,68 Gio) arrondie ; mesurée sur l'image quand elle est là.
MACOS_MIO_ESTIME=2816
# Images Linux (Omarchy 6,4 Go, Arch 1,5, Debian 0,8, Fedora 1,2, SystemRescue 1,3 en 2026) avec de quoi grandir ; mesurées dans
# le cache de images-cle.sh quand elles y sont. Windows 11 : l'ISO multi-édition, de 7,2 à 7,9 Go selon la langue.
LINUX_MIO_ESTIME=12032
WINDOWS_ISO_MIO_ESTIME=7534
# Kali Linux, live complète : 15 694 Mio en 2026.2, 16 066 en 2026.3. À part des autres images Linux : elle ne va dans
# ISO/ que s'il reste la place après elles (images-cle.sh la copie en dernier), et une clé se fait sans elle.
KALI_MIO_ESTIME=16384
IMAGES_LINUX=${VANGUARD_IMAGES:-${XDG_CACHE_HOME:-$HOME/.cache}/vanguard/images-cle}
# Partition WIN11 sans l'image sous la main : de quoi tenir l'ISO la plus grosse.
WINDOWS_MIO_ESTIME=8192
# Morceaux de install.wim : 3800 Mio, sous la limite d'un fichier en FAT32 (4 Gio moins un octet).
MORCEAU_MIO=3800
FAT32_MAX=4294967295
# Place gardée dans VANGUARD pour Vanguard lui-même, sa base et ses rapports, avant d'y mettre Windows en secours.
MARGE_VANGUARD_MIO=512
TYPE_DONNEES=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
TYPE_EFI=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
TYPE_HFS=48465300-0000-11AA-AA11-00306543ECAC

# Taille d'un fichier en Mio (arrondie au-dessus), ou la valeur donnée s'il manque.
taille_mio() { # fichier valeur_par_defaut
  if [[ -f $1 ]]; then echo $((($(stat -c %s "$1") + MIO - 1) / MIO)); else echo "$2"; fi
}

# --- Images -------------------------------------------------------------------------------------------------------

# L'image de Windows : « Win11_25H2_French_x64.iso » autrefois, « Windows11_Client_x64_fr-ca_….iso » maintenant. Les
# dossiers d'images peuvent être des liens vers un autre disque : find -H les suit.
fichier_windows() { find -H "$1" -maxdepth 1 \( -iname 'Win11*.iso' -o -iname 'Windows11*.iso' \) -print -quit; }
fichier_macos() { echo "$1/macos/BaseSystem.dmg"; }

# Empreinte attendue de l'image de Windows, celle que Microsoft publie pour cette langue : VANGUARD_WINDOWS_SHA256,
# sinon le fichier <image>.sha256 posé à côté (sa première ligne). Vide si aucune des deux, ou si ce n'en est pas une.
empreinte_windows() { # image
  local e=${VANGUARD_WINDOWS_SHA256:-}
  if [[ -z $e && -f $1.sha256 ]]; then e=$(awk 'NR == 1 {print $1}' "$1.sha256"); fi
  e=${e,,}
  if [[ $e =~ ^[0-9a-f]{64}$ ]]; then echo "$e"; fi
}

# Fichiers d'une image ISO : « taille<TAB>chemin », sans les dossiers ni les images de démarrage que 7z montre dans
# [BOOT]. Une entrée est lue en entier avant d'être écrite : selon le format, 7z donne sa taille avant de dire que
# c'est un dossier (Folder, Attributes ou Mode).
fichiers_iso() { # image
  7z l -slt -ba "$1" 2>/dev/null | awk '
    function sortir() {
      if (chemin != "" && !dossier && taille != "" && chemin !~ /^\[BOOT\]/) print taille "\t" chemin
    }
    /^Path = / { sortir(); chemin = substr($0, 8); dossier = 0; taille = "" }
    /^Folder = \+/ || /^Attributes = D/ || /^Mode = d/ { dossier = 1 }
    /^Size = [0-9]+$/ { taille = substr($0, 8) }
    END { sortir() }'
}

# Place des images Linux, sans Kali : celles prêtes dans le cache (toutes les cinq), sinon l'estimation.
linux_mio() {
  local octets n
  read -r n octets < <(find -H "$IMAGES_LINUX" -maxdepth 1 -name '*.iso' ! -name 'kali-linux-*' \
    -exec test -f {}.sha256 \; -printf '%s\n' 2>/dev/null | awk '{s += $1; n++} END {printf "%d %d\n", n, s}')
  if ((n == 5)); then echo $(((octets + MIO - 1) / MIO + 256)); else echo "$LINUX_MIO_ESTIME"; fi
}

# Kali Linux est-elle tenue sur cet ordinateur ? Coupée par défaut : seul le réglage local d'images-cle.sh l'allume.
kali_voulue() { [[ " $(outils/images-cle.sh --sortes 2>/dev/null) " == *" kali "* ]]; }

# Un dossier d'images qui est un lien vers un autre disque, débranché : le lien mort, et code 0 (comme dans
# images-cle.sh). Rien n'est alors recréé à sa place : un mkdir -p le referait vide, dans ~/.cache ou sur le tmpfs de
# /run/media, et les images s'y téléchargeraient.
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
dossier_joignable() { # dossier
  local lien
  if lien=$(lien_mort "$1"); then
    erreur "dossier des images introuvable : $lien mène à $(readlink "$lien") (disque débranché ?). Rien n'est recréé \
ailleurs."
  fi
}

# Place de Kali Linux : celle prête dans le cache, sinon l'estimation.
kali_mio() {
  local octets
  octets=$(find -H "$IMAGES_LINUX" -maxdepth 1 -name 'kali-linux-*-live-everything-amd64.iso' \
    -exec test -f {}.sha256 \; -printf '%s\n' 2>/dev/null | head -1)
  if [[ -n $octets ]]; then echo $(((octets + MIO - 1) / MIO)); else echo "$KALI_MIO_ESTIME"; fi
}

# Volume HFS+ de la récupération de macOS dans l'image d'Apple : (nom dans l'image, taille en octets).
volume_macos() { # BaseSystem.dmg
  # Colonnes de 7z : [date heure] attributs taille taille_compressée nom.
  7z l -tdmg "$1" 2>/dev/null | awk '$NF ~ /\.hfs$/ && $(NF-2) ~ /^[0-9]+$/ {print $NF, $(NF-2); exit}'
}

# L'image de Windows a-t-elle un sources/install.wim ? awk lit toute la liste : avec « | grep -q », grep s'arrête à la
# première ligne trouvée, la commande qui écrit la liste reçoit SIGPIPE, et pipefail fait échouer le test. C'est ce
# qui avait laissé une partition WIN11 sans install.wim, et sa vérification muette.
a_install_wim() { # image
  fichiers_iso "$1" | awk -F'\t' '$2 ~ /(^|\/)sources\/install\.wim$/ {t = 1} END {exit !t}'
}

# Partition WIN11 comparée à l'image : chaque fichier (sauf install.wim) présent à la même taille, les morceaux .swm
# à la taille préparée et lisibles par wimlib, le démarrage UEFI là, et rien au-delà de 4 Go (limite de FAT32).
verifier_windows() { # point_de_montage image dossier_des_morceaux (facultatif)
  local win=$1 iso=$2 prep=${3:-} faux=0 taille chemin
  if [[ ! -f $win/efi/boot/bootx64.efi ]]; then
    echo "  ✖ WIN11 : pas de efi/boot/bootx64.efi, le PC ne pourra pas la démarrer"
    faux=1
  fi
  local manquants=0 fichiers=0
  while IFS=$'\t' read -r taille chemin; do
    [[ $chemin =~ (^|/)install\.wim$ ]] && continue
    fichiers=$((fichiers + 1))
    [[ -f $win/$chemin && $(stat -c %s "$win/$chemin") == "$taille" ]] || manquants=$((manquants + 1))
  done < <(fichiers_iso "$iso")
  if ((fichiers == 0)); then
    echo "  ✖ WIN11 : l'image de Windows ne se lit pas"
    faux=1
  elif ((manquants > 0)); then
    echo "  ✖ WIN11 : $manquants fichier(s) sur $fichiers absent(s) ou d'une autre taille que dans l'image"
    faux=1
  else
    echo "  ✔ WIN11 : les $fichiers fichiers de l'image, à la bonne taille"
  fi
  if a_install_wim "$iso"; then
    local morceaux=("$win"/sources/install*.swm)
    if [[ ! -f ${morceaux[0]} ]]; then
      echo "  ✖ WIN11 : install.wim n'y est pas (morceaux sources/install*.swm absents)"
      faux=1
    else
      local differents=0 m
      if [[ -n $prep ]]; then
        for m in "$prep"/install*.swm; do
          [[ -f $win/sources/${m##*/} && $(stat -c %s "$win/sources/${m##*/}") == "$(stat -c %s "$m")" ]] ||
            differents=$((differents + 1))
        done
        [[ $(find "$win/sources" -maxdepth 1 -iname 'install*.swm' | wc -l) == "$(find "$prep" -maxdepth 1 \
          -name 'install*.swm' | wc -l)" ]] || differents=$((differents + 1))
      fi
      if ((differents > 0)); then
        echo "  ✖ WIN11 : les morceaux de install.wim ne sont pas ceux préparés"
        faux=1
      elif ! command -v wimlib-imagex >/dev/null; then
        echo "  · WIN11 : ${#morceaux[@]} morceau(x) de install.wim ; wimlib absent, leur contenu n'est pas relu"
      elif wimlib-imagex info "$win/sources/install.swm" >/dev/null 2>&1; then
        echo "  ✔ WIN11 : install.wim en ${#morceaux[@]} morceau(x), lisible par wimlib"
      else
        echo "  ✖ WIN11 : wimlib ne relit pas sources/install.swm"
        faux=1
      fi
    fi
  fi
  if [[ -n $(find "$win" -type f -size +4194303k -print -quit) ]]; then
    echo "  ✖ WIN11 : un fichier dépasse 4 Go, ce que FAT32 ne garde pas"
    faux=1
  fi
  return $faux
}

verifier() { # dossier [cle : aussi la partition WIN11, si elle est montée]
  local d=$1 avec_cle=${2:-} tout=0
  echo "Images de $d :"
  if empreinte_ok "$d/ventoy-$VENTOY-linux.tar.gz" "$VENTOY_SHA256"; then echo "  ✔ Ventoy $VENTOY"
  else echo "  ✖ Ventoy $VENTOY absent ou différent"; tout=1; fi
  outils/images-cle.sh --verifier || tout=1
  local windows attendue
  windows=$(fichier_windows "$d")
  attendue=$([[ -n $windows ]] && empreinte_windows "$windows" || true)
  if [[ -z $windows ]]; then
    echo "  ✖ Windows 11 absent (voir --telecharger)"; tout=1
  elif [[ -z $attendue ]]; then
    echo "  ✖ Windows 11 pas vérifié : il faut l'empreinte publiée par Microsoft pour cette langue, dans"
    echo "    VANGUARD_WINDOWS_SHA256=<empreinte> ou dans le fichier $(basename "$windows").sha256 à côté de l'image"
    tout=1
  elif empreinte_ok "$windows" "$attendue"; then echo "  ✔ Windows 11 ($(basename "$windows"))"
  else echo "  ✖ Windows 11 différent de l'empreinte de Microsoft"; tout=1; fi
  # macOS : macrecovery a vérifié l'image au téléchargement (liste des morceaux signée par Apple) ; on revérifie
  # avec sa propre fonction.
  if [[ -f $(fichier_macos "$d") ]] && empreinte_ok "$d/macrecovery.py" "$MACRECOVERY_SHA256" &&
    python3 -I -c 'import importlib.util as u, sys
s = u.spec_from_file_location("macrecovery", sys.argv[1]); m = u.module_from_spec(s); s.loader.exec_module(m)
m.verify_image(sys.argv[2], sys.argv[3])' "$d/macrecovery.py" "$(fichier_macos "$d")" "$d/macos/BaseSystem.chunklist" \
      >/dev/null 2>&1 && [[ -n $(volume_macos "$(fichier_macos "$d")") ]]; then
    echo "  ✔ Récupération de macOS (signée par Apple)"
  else echo "  ✖ Récupération de macOS absente ou pas vérifiée"; tout=1; fi
  # La partition WIN11 d'une clé déjà faite, si elle est montée : comparée à l'image (seulement à la demande, pas
  # avant d'effacer : la clé à refaire peut garder une version plus ancienne de Windows).
  if [[ -n $avec_cle ]]; then
    local win
    win=$(findmnt -no TARGET -S LABEL=WIN11 2>/dev/null | head -1 || true)
    if [[ -z $win ]]; then
      echo "Partition WIN11 : pas montée, non vérifiée."
    elif [[ -z $windows ]]; then
      echo "Partition WIN11 ($win) : pas d'image de Windows à laquelle la comparer, non vérifiée."
    else
      echo "Partition WIN11 ($win) :"
      local prep=""
      [[ -n $attendue && -d $d/windows-${attendue:0:16} ]] && prep=$d/windows-${attendue:0:16}
      verifier_windows "$win" "$windows" "$prep" || tout=1
    fi
  fi
  return $tout
}

telecharger() { # dossier
  local d=$1
  mkdir -p "$d/macos"
  local recuperer=(curl -fL --retry 3 --progress-bar)
  empreinte_ok "$d/ventoy-$VENTOY-linux.tar.gz" "$VENTOY_SHA256" ||
    "${recuperer[@]}" -o "$d/ventoy-$VENTOY-linux.tar.gz" \
      "https://github.com/ventoy/Ventoy/releases/download/v$VENTOY/ventoy-$VENTOY-linux.tar.gz"
  # Omarchy, Arch, Debian, Fedora et SystemRescue : dans le cache de images-cle.sh, vérifiés par la signature de leur
  # projet.
  outils/images-cle.sh --chercher || true
  # macrecovery (OpenCorePkg, licence BSD) demande l'image de récupération aux serveurs d'Apple et la vérifie.
  "${recuperer[@]}" -o "$d/macrecovery.py" \
    "https://raw.githubusercontent.com/acidanthera/OpenCorePkg/$OPENCORE/Utilities/macrecovery/macrecovery.py"
  empreinte_ok "$d/macrecovery.py" "$MACRECOVERY_SHA256" || erreur "macrecovery.py n'est pas celui attendu."
  [[ -f $(fichier_macos "$d") ]] ||
    python3 -I "$d/macrecovery.py" -b "$MACOS_CARTE" -m 00000000000000000 -o "$d/macos" download
  cat <<EOF

Windows 11 se télécharge à la main (Microsoft ne donne qu'un lien valable 24 heures) :
  1. https://www.microsoft.com/fr-ca/software-download/windows11, section « Télécharger l'image disque
     (ISO) de Windows 11 pour les appareils x64 » : « Windows 11 (multi-edition ISO for x64 devices) ».
  2. La langue : « Français canadien » par défaut (ou celle des ordinateurs à réinstaller), puis le lien
     64 bits : enregistrer l'image (Windows11_….iso ou Win11_….iso) dans $d.
  3. L'empreinte SHA256 de cette langue, dans le tableau « Vérifier votre téléchargement » de la même page :
     dans un fichier <image>.sha256 à côté de l'image (une ligne), ou VANGUARD_WINDOWS_SHA256=<empreinte>
     devant la commande. Puis : $0 --verifier $d
  4. wimlib, qui découpe install.wim pour la partition FAT32 : sudo pacman -S wimlib (ou le paquet wimlib de
     la distribution).
EOF
  verifier "$d" || true
}

# --- Disposition ----------------------------------------------------------------------------------------------------

# Place réservée par Ventoy en fin de clé : le journal, macOS, Windows, et 2 Mio d'alignement et de table GPT de
# secours.
reserve_mio() { echo $((JOURNAL_MIO + $1 + $2 + 2)); } # macos_mio windows_mio

# Taille de la partition macOS : le volume d'Apple arrondi au multiple de 64 Mio au-dessus.
macos_mio() { # dossier (facultatif)
  local volume
  volume=$([[ -n ${1:-} && -f $(fichier_macos "$1") ]] && volume_macos "$(fichier_macos "$1")" || true)
  if [[ -n $volume ]]; then
    local blocs=$(((${volume#* } + 64 * MIO - 1) / (64 * MIO)))
    echo $((blocs * 64))
  else
    echo "$MACOS_MIO_ESTIME"
  fi
}

# Taille de la partition WIN11 : le contenu de l'image, plus 5 % et 256 Mio (tables de FAT32, en-têtes des morceaux
# de install.wim, pilotes ajoutés plus tard), arrondie au multiple de 64 Mio au-dessus. Estimée sans l'image, ou si
# elle ne se lit pas (encore en téléchargement).
windows_mio() { # dossier (facultatif)
  local iso octets
  iso=$([[ -n ${1:-} && -d ${1:-} ]] && fichier_windows "$1" || true)
  octets=0
  [[ -n $iso ]] && { octets=$(fichiers_iso "$iso" | awk -F'\t' '{s += $1} END {printf "%d\n", s}') || octets=0; }
  if ((octets < 1024 * MIO)); then
    echo "$WINDOWS_MIO_ESTIME"
  else
    local mio=$((octets / MIO + octets / MIO / 20 + 256))
    echo $(((mio + 63) / 64 * 64))
  fi
}

# Partitions 3, 4 et 5, ajoutées dans la place réservée, pour sfdisk --append.
partitions_ajoutees() { # macos_mio windows_mio
  printf 'size=%dMiB, type=%s, name="VANGUARDLOG"\n' "$JOURNAL_MIO" "$TYPE_DONNEES"
  printf 'size=%dMiB, type=%s, name="MACOS"\n' "$1" "$TYPE_HFS"
  printf 'size=%dMiB, type=%s, name="WIN11"\n' "$2" "$TYPE_DONNEES"
}

# La place de VANGUARD : d'abord Vanguard et sa base (marge), les images Linux ; Kali Linux, puis Windows en secours,
# s'ils tiennent (dans l'ordre où images-cle.sh --toutes et --ecrire les copient). Les lignes pour --plan ; code 1 si
# même les images Linux ne tiennent pas.
place_vanguard() { # vanguard_mio iso_windows_mio
  local libre=$(($1 - MARGE_VANGUARD_MIO - $(linux_mio))) kali
  kali=$(kali_mio)
  if ((libre < 0)); then
    echo "✖ Clé trop petite : il manque $((-libre)) Mio pour Vanguard et les images Linux."
    return 1
  elif ! kali_voulue; then
    :
  elif ((libre >= kali)); then
    echo "Kali Linux aussi dans ISO/ (live complète, $kali Mio)."
    libre=$((libre - kali))
  else
    echo "Pas la place pour Kali Linux dans ISO/ (il manque $((kali - libre)) Mio) : la clé se fait sans elle."
  fi
  if ((libre >= $2)); then
    echo "Windows 11 aussi dans ISO/, en secours ($2 Mio) : il restera ~$(((libre - $2) / 1024)) Gio."
  else
    echo "Pas la place pour Windows 11 en secours dans ISO/ (il manque $(($2 - libre)) Mio) : il ne démarrera que"
    echo "par sa partition WIN11. Il restera ~$((libre / 1024)) Gio."
  fi
}

plan() { # disque (facultatif), dossier (facultatif)
  local disque=${1:-/dev/sdX} d=${2:-} octets macos windows iso_windows
  octets=$([[ -b $disque ]] && lsblk -bdno SIZE "$disque" || echo 31037849600)
  macos=$(macos_mio "$d")
  windows=$(windows_mio "$d")
  iso_windows=$(taille_mio "$([[ -n $d && -d $d ]] && fichier_windows "$d" || true)" "$WINDOWS_ISO_MIO_ESTIME")
  local reserve vanguard
  reserve=$(reserve_mio "$macos" "$windows")
  vanguard=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  cat <<EOF
Clé de $(numfmt --to=iec-i --suffix=o --format='%.1f' "$octets") ($disque), table GPT :
  1 VANGUARD     $(printf '%6d' "$vanguard") Mio  exFAT, Ventoy + Vanguard + ISO/ (lecture seule sous Windows)
  2 VTOYEFI     $(printf '%6d' "$VTOYEFI_MIO") Mio  FAT, démarrage de Ventoy
  3 VANGUARDLOG  $(printf '%6d' "$JOURNAL_MIO") Mio  exFAT, journal des erreurs
  4 MACOS       $(printf '%6d' "$macos") Mio  HFS+, récupération de macOS (Mac Intel)
  5 WIN11       $(printf '%6d' "$windows") Mio  FAT32, installation de Windows 11 (démarre seule, Secure Boot actif)

Dans VANGUARD : Vanguard et sa base ($MARGE_VANGUARD_MIO Mio gardés), les images Linux $(linux_mio) Mio (Omarchy, Arch,
Debian, Fedora, SystemRescue).
$(place_vanguard "$vanguard" "$iso_windows" || true)

Commandes de --ecrire (rien n'est lancé ici) :
  avant d'effacer                 → images vérifiées ; install.wim découpé en morceaux de $MORCEAU_MIO Mio
                                    (wimlib-imagex split), à côté des images, et relu (wimlib-imagex verify)
  sauvegarde de la clé montée     → ${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/sauvegarde-cle-<date>/
                                    (sans ISO/, ni les partitions MACOS et WIN11 : elles se refont)
  pkexec (une fenêtre)            → sh Ventoy2Disk.sh -I -g -r $reserve -L VANGUARD $disque
                                    sfdisk --append $disque   (VANGUARDLOG, MACOS, WIN11)
                                    mkfs.exfat -L VANGUARDLOG $(partition "$disque" 3)
                                    7z e -so -tdmg BaseSystem.dmg <volume>.hfs | dd of=$(partition "$disque" 4)
                                    mkfs.fat -F 32 -n WIN11 $(partition "$disque" 5)
                                    sfdisk --part-attrs $disque 1 GUID:60
  sans root                       → témoins, ISO/ (images-cle.sh --toutes) et ventoy/ventoy.json ; WIN11 : 7z x de l'image sans
                                    install.wim, ses morceaux .swm, vérification, démontage ; base remise,
                                    deployer.sh --accepter-cle
EOF
}

# --- Windows dans sa partition FAT32 ----------------------------------------------------------------------------------

# install.wim découpé en morceaux (.swm) de moins de 4 Go, une fois pour toutes, à côté des images : avant d'effacer
# quoi que ce soit (une erreur arrête tout sans rien perdre), et réutilisé tant que l'image de Windows est la même
# (son empreinte dans le nom du dossier). Écrit le chemin du dossier.
preparer_windows() { # dossier
  local d=$1 iso attendue prep
  iso=$(fichier_windows "$d")
  attendue=$(empreinte_windows "$iso")
  [[ -n $attendue ]] || erreur "l'image de Windows doit être vérifiée avant d'être préparée."
  prep=$d/windows-${attendue:0:16}
  # Déjà prêt, sauf si l'image a un install.wim dont les morceaux manquent (préparation d'avant le correctif de
  # a_install_wim, qui concluait à tort qu'il n'y en avait pas).
  if [[ -f $prep/pret ]] && { ! a_install_wim "$iso" || compgen -G "$prep/install*.swm" >/dev/null; }; then
    echo "$prep"
    return
  fi
  # FAT32 ne garde pas un fichier de 4 Go ou plus : seul install.wim est découpé, rien d'autre ne doit dépasser.
  local trop
  trop=$(fichiers_iso "$iso" | awk -F'\t' -v max="$FAT32_MAX" '$1 > max && $2 !~ /(^|\/)install\.wim$/ {print $2}')
  [[ -z $trop ]] || erreur "l'image de Windows a un fichier de 4 Go ou plus, autre que install.wim : $trop
  (une image faite par l'outil de création de média a install.esd : prendre l'ISO de la page de Microsoft)."
  rm -rf "$prep"
  mkdir -p "$prep"
  if a_install_wim "$iso"; then
    echo "Windows : install.wim découpé en morceaux de $MORCEAU_MIO Mio (quelques minutes)…" >&2
    7z e -y -o"$prep" "$iso" 'sources/install.wim' >/dev/null
    [[ -f $prep/install.wim ]] || erreur "install.wim ne s'extrait pas de l'image de Windows."
    wimlib-imagex split "$prep/install.wim" "$prep/install.swm" "$MORCEAU_MIO" >&2
    rm -f "$prep/install.wim"
    wimlib-imagex verify "$prep/install.swm" --ref="$prep/install*.swm" >&2 ||
      erreur "les morceaux de install.wim ne se relisent pas."
  fi
  touch "$prep/pret"
  echo "$prep"
}

# Partition WIN11 : l'image de Windows sans install.wim (7z), puis ses morceaux préparés, puis tout est revérifié.
remplir_windows() { # point_de_montage image dossier_des_morceaux
  local win=$1 iso=$2 prep=$3
  echo "Partition WIN11 : copie de Windows 11 (quelques minutes)…"
  7z x -y -o"$win" "$iso" '-x![BOOT]' '-xr!install.wim' >/dev/null
  if compgen -G "$prep/install*.swm" >/dev/null; then
    cp "$prep"/install*.swm "$win/sources/"
  fi
  sync
  verifier_windows "$win" "$iso" "$prep" || erreur "la partition WIN11 ne correspond pas à l'image de Windows."
}

# --- Essai sur une image de disque (aucun disque réel, aucun root) ---------------------------------------------------

# Début et taille (en secteurs) d'une partition de l'image : debut_taille image numéro.
debut_taille() {
  sfdisk --json "$1" | python3 -c 'import json, sys
p = json.load(sys.stdin)["partitiontable"]["partitions"][int(sys.argv[1]) - 1]
print(p["start"], p["size"])' "$2"
}

essai() { # dossier d'images (facultatif : la récupération de macOS y est écrite pour de vrai, l'image de Windows lue)
  local images=${1:-} dossier image octets=31037849600
  # Dans le cache, pas dans /tmp : /tmp est souvent en mémoire, avec un quota trop petit pour une clé de 29 Gio
  # (l'image est creuse, mais la récupération de macOS y est écrite pour de vrai).
  mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/vanguard-dev"
  dossier=$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/vanguard-dev/cle-secours-essai.XXXX")
  image=$dossier/cle.img
  truncate -s "$octets" "$image"
  local macos windows reserve vanguard
  macos=$(macos_mio "$images")
  windows=$(windows_mio "$images")
  reserve=$(reserve_mio "$macos" "$windows")
  vanguard=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  # Ce que fait Ventoy2Disk.sh -g -r : partition 1 au premier Mio, VTOYEFI juste après, la place réservée au bout.
  sfdisk --quiet --label gpt "$image" <<EOF
start=2048, size=${vanguard}MiB, type=$TYPE_DONNEES, name="Ventoy"
size=${VTOYEFI_MIO}MiB, type=$TYPE_EFI, name="VTOYEFI"
EOF
  # Puis ce que fait --ecrire : les partitions 3, 4 et 5 dans la place réservée, la lecture seule de la 1.
  partitions_ajoutees "$macos" "$windows" | sfdisk --quiet --append "$image"
  sfdisk --quiet --part-attrs "$image" 1 GUID:60
  local debut3 debut4 taille4 debut5 taille5
  read -r debut3 _ < <(debut_taille "$image" 3)
  read -r debut4 taille4 < <(debut_taille "$image" 4)
  read -r debut5 taille5 < <(debut_taille "$image" 5)
  truncate -s "${JOURNAL_MIO}M" "$dossier/journal.img"
  mkfs.exfat -L VANGUARDLOG "$dossier/journal.img" >/dev/null
  dd if="$dossier/journal.img" of="$image" bs=1M seek="$((debut3 * 512))" oflag=seek_bytes conv=notrunc,sparse status=none
  if [[ -n $images && -f $(fichier_macos "$images") ]]; then
    local volume
    volume=$(volume_macos "$(fichier_macos "$images")")
    ((${volume#* } <= taille4 * 512)) || erreur "le volume de macOS ne tient pas dans sa partition"
    7z e -so -tdmg "$(fichier_macos "$images")" "${volume% *}" 2>/dev/null |
      dd of="$image" bs=4M seek="$((debut4 * 512))" oflag=seek_bytes conv=notrunc,sparse status=none
  fi
  # FAT32 formatée dans l'image même, à sa place : mkfs.fat --offset, sans monter ni root (taille en blocs d'1 Kio).
  # Il prévient que l'image continue après la partition (table GPT de secours) : seule une erreur est montrée.
  mkfs.fat -F 32 -n WIN11 --offset="$debut5" "$image" "$((taille5 / 2))" >/dev/null 2>"$dossier/mkfs.txt" ||
    { cat "$dossier/mkfs.txt" >&2; erreur "mkfs.fat n'a pas formaté la partition WIN11 de l'image."; }
  echo "Image d'essai : $image"
  sfdisk --dump "$image" | sed 's/^/  /'
  local n debut
  for n in 3 4 5; do
    read -r debut _ < <(debut_taille "$image" "$n")
    [[ $n == 4 && ! (-n $images && -f $(fichier_macos "$images")) ]] && continue
    echo "Partition $n : $(blkid -p -O "$((debut * 512))" -o export "$image" | grep -E '^(TYPE|LABEL|VERSION)=' |
      tr '\n' ' ')"
  done
  echo
  plan "" "$images" | sed -n '/^Dans VANGUARD/,/^$/p' | sed '/^$/d'
  # La copie dans la FAT32 : avec mtools (mcopy écrit dans l'image sans la monter), sinon elle n'est pas essayée.
  if command -v mcopy >/dev/null; then
    echo "WIN11 : fichier d'essai copié par mcopy dans la FAT32 de l'image, puis relu :"
    echo "vanguard" >"$dossier/essai.txt"
    mcopy -i "$image@@$((debut5 * 512))" "$dossier/essai.txt" ::/
    mdir -i "$image@@$((debut5 * 512))" ::/ | sed 's/^/  /'
  else
    echo "WIN11 : mtools absent, la copie dans la FAT32 n'est pas essayée ici (seulement son formatage)."
  fi
  local iso
  iso=$([[ -n $images && -d $images ]] && fichier_windows "$images" || true)
  if [[ -n $iso ]]; then
    local trop
    trop=$(fichiers_iso "$iso" | awk -F'\t' -v max="$FAT32_MAX" '$1 > max && $2 !~ /(^|\/)install\.wim$/ {print $2}')
    echo "Image de Windows ($(basename "$iso")) : partition WIN11 de $windows Mio ;" \
      "$([[ -z $trop ]] && echo "aucun fichier de 4 Go ou plus hors install.wim" || echo "✖ trop gros : $trop")."
    command -v wimlib-imagex >/dev/null ||
      echo "  wimlib absent : le découpage de install.wim n'est pas essayé (sudo pacman -S wimlib)."
  fi
  echo "(à effacer après lecture : rm -r $dossier)"
}

# --- Écriture de la clé ----------------------------------------------------------------------------------------------

# Partie root, lancée par pkexec : Ventoy, partitions 3 à 5, formatage, macOS, lecture seule. Le disque est
# revérifié ici (même numéro de série, même taille) : entre la question et la fenêtre de mot de passe, une autre
# clé a pu prendre son nom.
racine() { # disque serie octets dossier macos_mio windows_mio
  local disque=$1 serie=$2 octets=$3 d=$4 macos=$5 windows=$6
  [[ $macos =~ ^[0-9]+$ && $windows =~ ^[0-9]+$ ]] || erreur "tailles de partitions incomprises."
  [[ $(lsblk -dno RM,TRAN "$disque" | tr -s ' ') == "1 usb" ]] || erreur "$disque n'est plus une clé USB."
  [[ $(lsblk -dno SERIAL "$disque") == "$serie" && $(lsblk -bdno SIZE "$disque") == "$octets" ]] ||
    erreur "$disque n'est plus la clé choisie."
  local tmp
  tmp=$(mktemp -d)
  # Ventoy2Disk.sh va tourner en root : l'archive est recopiée ici, hors d'atteinte du compte, et c'est cette copie
  # qui est vérifiée puis ouverte. La vérification faite avant la fenêtre pkexec ne suffit pas : le fichier a pu
  # changer depuis.
  cp "$d/ventoy-$VENTOY-linux.tar.gz" "$tmp/ventoy.tar.gz"
  if ! empreinte_ok "$tmp/ventoy.tar.gz" "$VENTOY_SHA256"; then
    rm -rf "$tmp"
    erreur "l'archive de Ventoy n'est plus celle vérifiée : abandon, rien n'a été effacé."
  fi
  tar -xzf "$tmp/ventoy.tar.gz" -C "$tmp"
  # Ventoy demande deux fois s'il peut tout effacer : la question a déjà été posée, en clair, avant. -L : le nom
  # VANGUARD, que Vanguard et deployer.sh cherchent (avec le témoin vanguard.cle).
  (cd "$tmp/ventoy-$VENTOY" && printf 'y\ny\n' | sh Ventoy2Disk.sh -I -g -r "$(reserve_mio "$macos" "$windows")" \
    -L VANGUARD "$disque")
  udevadm settle
  # Le bureau monte tout seul les partitions neuves de Ventoy (VTOYEFI, VANGUARD) : sfdisk refuse alors un disque
  # « utilisé ». On démonte, on ajoute les partitions sans relire tout le disque (--no-reread), et le noyau les prend
  # par partx, ce qu'il accepte même si le bureau remonte une partition entre-temps.
  demonter_partitions "$disque"
  partitions_ajoutees "$macos" "$windows" | sfdisk --no-reread --append "$disque"
  partx -u "$disque"
  udevadm settle
  local n
  for n in 3 4 5; do liberer "$(partition "$disque" "$n")"; done
  mkfs.exfat -L VANGUARDLOG "$(partition "$disque" 3)"
  local volume
  volume=$(volume_macos "$(fichier_macos "$d")")
  7z e -so -tdmg "$(fichier_macos "$d")" "${volume% *}" | dd of="$(partition "$disque" 4)" bs=4M conv=fsync status=progress
  mkfs.fat -F 32 -n WIN11 "$(partition "$disque" 5)"
  sfdisk --no-reread --part-attrs "$disque" 1 GUID:60
  sync
  rm -rf "$tmp"
}

# Partie root : démonte les partitions d'un disque que le bureau a montées.
demonter_partitions() { # disque
  local part
  while read -r part; do
    if findmnt -rno TARGET -S "$part" >/dev/null; then umount "$part"; fi
  done < <(lsblk -lnpo NAME "$1" | tail -n +2)
}

# Partie root : une partition neuve, démontée si le bureau l'a montée, et vidée des signatures d'un ancien système
# de fichiers resté à cet endroit de la clé (le bureau pourrait sinon la monter pendant qu'on l'écrit).
liberer() { # partition
  if findmnt -rno TARGET -S "$1" >/dev/null; then umount "$1"; fi
  wipefs -aq "$1"
}

# Le bureau monte souvent les nouvelles partitions tout seul : on prend le point de montage, ou on monte.
monter() { # partition
  local point
  for _ in {1..10}; do
    point=$(findmnt -nro TARGET -S "$1" | head -1 || true)
    [[ -n $point ]] && echo "$point" && return
    udisksctl mount -b "$1" >/dev/null 2>&1 || sleep 1
  done
  return 1
}

# Partition WIN11 d'une clé de secours déjà faite, remplie ou réparée sans rien effacer d'autre ni root : après une
# nouvelle image de Windows, ou une écriture restée incomplète. Les fichiers de l'image sont recopiés par-dessus, les
# morceaux de install.wim ajoutés, puis tout est revérifié.
completer_windows() { # disque dossier
  local disque=$1 d=$2 part win prep
  part=$(partition "$disque" 5)
  [[ -b $part && $(lsblk -no PARTLABEL "$part") == WIN11 ]] ||
    erreur "$disque n'a pas de partition WIN11 : ce n'est pas une clé de secours (voir --ecrire)."
  command -v wimlib-imagex >/dev/null ||
    erreur "il manque wimlib-imagex, qui découpe install.wim pour la partition FAT32 : sudo pacman -S wimlib."
  verifier "$d" || erreur "toutes les images doivent être vérifiées avant d'écrire."
  prep=$(preparer_windows "$d")
  # Montée en lecture seule par une vérification précédente : démontée puis remontée pour écrire.
  if [[ ,$(findmnt -rno OPTIONS -S "$part" || true), == *,ro,* ]]; then udisksctl unmount -b "$part" >/dev/null; fi
  win=$(monter "$part") || erreur "partition WIN11 impossible à monter."
  remplir_windows "$win" "$(fichier_windows "$d")" "$prep"
  udisksctl unmount -b "$part" >/dev/null
  echo "Partition WIN11 complète et vérifiée."
}

ecrire() { # disque dossier
  local disque=$1 d=$2
  [[ -b $disque && $(lsblk -dno RM,TRAN "$disque" | tr -s ' ') == "1 usb" ]] ||
    erreur "$disque n'est pas une clé USB amovible : abandon."
  for outil in sfdisk mkfs.exfat mkfs.fat 7z gpg pkexec udisksctl; do
    command -v "$outil" >/dev/null || erreur "il manque $outil."
  done
  command -v wimlib-imagex >/dev/null ||
    erreur "il manque wimlib-imagex, qui découpe install.wim pour la partition FAT32 : sudo pacman -S wimlib."
  verifier "$d" || erreur "toutes les images doivent être vérifiées avant d'effacer la clé."
  # Tout ce qui peut échouer se fait avant d'effacer : la place, puis le découpage de install.wim.
  local octets macos windows reserve vanguard
  octets=$(lsblk -bdno SIZE "$disque")
  macos=$(macos_mio "$d")
  windows=$(windows_mio "$d")
  reserve=$(reserve_mio "$macos" "$windows")
  vanguard=$((octets / MIO - 1 - VTOYEFI_MIO - reserve))
  place_vanguard "$vanguard" "$(taille_mio "$(fichier_windows "$d")" "$WINDOWS_ISO_MIO_ESTIME")" >/dev/null ||
    erreur "clé trop petite pour Vanguard et les images Linux (voir --plan) : rien n'a été effacé."
  local prep
  prep=$(preparer_windows "$d")
  plan "$disque" "$d"
  lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS "$disque"
  read -rp "Tout le contenu de $disque va être effacé. Taper EFFACER pour continuer : " reponse
  [[ $reponse == EFFACER ]] || exit 1
  # Sauvegarde de ce qui est monté (la base donnees/ surtout), puis démontage. Sans ISO/ (une clé de secours déjà
  # faite y garde ~15 Go d'images, qui se retéléchargent), ni les partitions MACOS et WIN11, qui se refont.
  local sauvegarde part point
  sauvegarde="${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/sauvegarde-cle-$(date +%Y%m%d-%H%M%S)"
  while read -r part; do
    point=$(findmnt -no TARGET -S "$part" | head -1 || true)
    case $(lsblk -no PARTLABEL "$part") in
      VTOYEFI | MACOS | WIN11) ;;
      *)
        if [[ -n $point ]]; then
          mkdir -p "$sauvegarde/${part##*/}"
          find "$point" -mindepth 1 -maxdepth 1 ! -name ISO -exec cp -r {} "$sauvegarde/${part##*/}/" \;
        fi
        ;;
    esac
    udisksctl unmount -b "$part" >/dev/null 2>&1 || true
  done < <(lsblk -lnpo NAME "$disque" | tail -n +2)
  [[ -d $sauvegarde ]] && echo "Sauvegarde : $sauvegarde"
  pkexec --keep-cwd "$PWD/outils/cle-secours.sh" --racine "$disque" "$(lsblk -dno SERIAL "$disque")" \
    "$octets" "$(realpath "$d")" "$macos" "$windows"
  udevadm settle
  # Le démarrage que Ventoy vient d'écrire, depuis l'archive épinglée : sa référence (controler_vtoyefi).
  local version_vt empreinte_vt
  read -r version_vt empreinte_vt <<<"$(vtoyefi_de "$disque")"
  noter_vtoyefi "$disque" "$version_vt" "$empreinte_vt"
  local cle journal win
  cle=$(monter "$(partition "$disque" 1)") || erreur "partition VANGUARD impossible à monter."
  journal=$(monter "$(partition "$disque" 3)") || erreur "partition VANGUARDLOG impossible à monter."
  win=$(monter "$(partition "$disque" 5)") || erreur "partition WIN11 impossible à monter."
  touch "$cle/vanguard.cle" "$journal/vanguard-journal.cle"
  mkdir -p "$cle/ISO" "$cle/ventoy"
  local windows_iso
  windows_iso=$(fichier_windows "$d")
  remplir_windows "$win" "$windows_iso" "$prep"
  udisksctl unmount -b "$(partition "$disque" 5)" >/dev/null
  outils/images-cle.sh --toutes "$cle"
  # Windows aussi dans ISO/, en secours pour un PC dont le menu ne propose pas WIN11, s'il reste la place : c'est
  # la première image laissée de côté.
  local libre
  libre=$(($(df --output=avail -B1M "$cle" | tail -1)))
  if ((libre - MARGE_VANGUARD_MIO >= $(taille_mio "$windows_iso" "$WINDOWS_ISO_MIO_ESTIME"))); then
    cp "$windows_iso" "$cle/ISO/"
  else
    echo "Pas la place pour Windows 11 en secours dans ISO/ : il démarre par sa partition WIN11 seulement."
  fi
  outils/images-cle.sh --menu "$cle"
  # La base donnees/ : celle de cette sauvegarde, sinon celle de la plus récente sauvegarde qui en a une. Une passe
  # interrompue après l'effacement laisse une clé vide, dont la sauvegarde suivante n'a plus de base.
  local ancienne
  ancienne=$(find "$sauvegarde" -maxdepth 2 -type d -name donnees -print -quit 2>/dev/null || true)
  [[ -n $ancienne ]] || ancienne=$(find "${sauvegarde%/*}" -maxdepth 3 -type d \
    \( -path '*/sauvegarde-cle-*/donnees' -o -path '*/sauvegarde-cle-*/*/donnees' \) 2>/dev/null | sort -r | head -1)
  if [[ -n $ancienne ]]; then
    cp -r "$ancienne" "$cle/" && echo "Base remise sur la clé : $ancienne"
  else
    echo "Aucune base donnees/ trouvée dans les sauvegardes : la clé démarre sans base."
  fi
  sync
  # Une clé neuve, que l'auteur vient d'effacer : adoptée par cet ordinateur (deployer.sh refuse un jeton inconnu).
  outils/deployer.sh --accepter-cle "$cle"
  lsblk -o NAME,SIZE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS "$disque"
}

# --- La clé déjà faite : Ventoy à jour, Windows 11 pas trop vieux -----------------------------------------------------

avertir() { # titre texte
  command -v notify-send >/dev/null && notify-send -a Vanguard -i vanguard -- "$1" "$2" || true
}

# Une notification qui attend un clic. Le serveur d'Omarchy n'affiche aucun bouton : un clic gauche sur la carte lance
# l'action « default », la seule qu'il connaisse (mako, dunst et GNOME la lancent aussi au clic), un clic droit la
# ferme ; le texte dit donc quoi faire. Urgence critique : elle reste jusqu'au clic (une normale part au bout de 30 s
# au plus). Sans réponse au bout du délai, elle est remplacée par une ordinaire qui le dit, et qui s'en va : un clic
# tardif ne tomberait sur rien. --foreground : lancée à la main, Ctrl-C atteint notify-send, qui ferme la notification,
# et le script s'arrête aussitôt (sinon, il attendrait la fin du délai, la notification encore à l'écran). Écrit
# « oui » sur un clic ; rien si elle est fermée, ou laissée sans réponse.
proposer() { # délai_s titre texte texte_sans_réponse libellé
  command -v notify-send >/dev/null || return 0
  local sortie code=0 id
  sortie=$(timeout --foreground "$1" notify-send -a Vanguard -i vanguard -u critical -p -A "default=$5" -- "$2" "$3" \
    2>/dev/null) || code=$?
  id=$(sed -n 1p <<<"$sortie")
  if [[ $(sed -n 2p <<<"$sortie") == default ]]; then
    echo oui
  elif ((code == 124)) && [[ $id =~ ^[1-9][0-9]*$ ]]; then
    notify-send -a Vanguard -i vanguard -r "$id" -- "$2" "$4" 2>/dev/null || true
  fi
}

# Ce qui a déjà été dit, pour ne pas le redire à chaque passage (le minuteur du jour et chaque branchement).
deja_dit() { # nom texte minutes
  [[ $(cat "$ETAT/$1" 2>/dev/null) == "$2" && -n $(find "$ETAT/$1" -mmin -"$3" 2>/dev/null) ]]
}
noter() { # nom texte
  mkdir -p "$ETAT" && printf '%s\n' "$2" >"$ETAT/$1"
}

# La clé VANGUARD de cet ordinateur (témoin vanguard.cle et jeton connu ici, outils/cle-commun.sh), comme deployer.sh
# la cherche.
# Sans lui (une copie partielle des outils), la clé n'est pas cherchée : rien n'y est écrit.
if [[ -f $(dirname "${BASH_SOURCE[0]}")/cle-commun.sh ]]; then
  # shellcheck source=outils/cle-commun.sh
  source "$(dirname "${BASH_SOURCE[0]}")/cle-commun.sh"
else
  cle_connue() { echo "· outils/cle-commun.sh absent : la clé VANGUARD n'est pas cherchée." >&2; return 2; }
fi
point_cle() { cle_connue || true; }

# Le disque d'une clé montée (/dev/sda pour /dev/sda1) ; rien si ce n'est pas une partition d'un disque. Deux montages
# l'un sur l'autre au même endroit : celui du dessus, le seul visible, est le dernier de la liste.
disque_de() { # point
  local source
  source=$(findmnt -nvo SOURCE -T "$1" 2>/dev/null | tail -1 || true)
  [[ -n $source && $(lsblk -dno TYPE "$source" 2>/dev/null) == part ]] || return 0
  echo "/dev/$(lsblk -dno PKNAME "$source")"
}

# Version de Ventoy d'un dossier VTOYEFI : « set VENTOY_VERSION="1.1.18" » dans grub/grub.cfg, là où Ventoy2Disk.sh
# la lit lui-même.
version_ventoy() { # dossier
  sed -n 's/^[[:space:]]*set[[:space:]]\{1,\}VENTOY_VERSION="\([0-9][0-9.]*\)".*/\1/p' "$1/grub/grub.cfg" 2>/dev/null |
    head -1 || true
}

# L'empreinte du contenu d'un dossier VTOYEFI : le SHA-256 de la liste de ses fichiers, chacun avec le sien (32 Mio en
# tout, lus en une seconde). « illisible » si un seul fichier ou dossier ne se lit pas, ou s'il est vide : un fichier
# rendu illisible ne doit pas faire taire la comparaison (campagne d'attaque n° 4, C-B1).
empreinte_vtoyefi() { # dossier
  local liste
  if liste=$(cd "$1" 2>/dev/null && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum 2>/dev/null) &&
    [[ -n $liste ]]; then
    sha256sum <<<"$liste" | cut -d' ' -f1
  else
    echo illisible
  fi
}

# Version de Ventoy d'une clé et empreinte de sa partition de démarrage (« version empreinte »), lues sans rien
# écrire : sa partition VTOYEFI, montée par le bureau, sinon montée en lecture seule le temps de lire. Jamais un mot
# vide (read décalerait l'empreinte à la place de la version) : « ? » pour une version pas lue, « absente » pour une
# clé sans partition VTOYEFI (introuvable ou renommée), « illisible » pour une partition pas montée ou aux fichiers
# illisibles.
# VANGUARD_VTOYEFI : un dossier lu à sa place (essais ; absent, la partition l'est aussi).
vtoyefi_de() { # disque
  local p2 point montee="" version="" empreinte=illisible
  if [[ -n ${VANGUARD_VTOYEFI:-} ]]; then
    if [[ ! -d $VANGUARD_VTOYEFI ]]; then echo "? absente"; return 0; fi
    version=$(version_ventoy "$VANGUARD_VTOYEFI")
    echo "${version:-?} $(empreinte_vtoyefi "$VANGUARD_VTOYEFI")"
    return 0
  fi
  if [[ -z $1 ]]; then echo "? illisible"; return 0; fi
  p2=$(partition "$1" 2)
  if [[ ! -b $p2 || $(lsblk -dno LABEL "$p2" 2>/dev/null) != VTOYEFI ]]; then echo "? absente"; return 0; fi
  point=$(findmnt -nro TARGET -S "$p2" 2>/dev/null | head -1 || true)
  if [[ -z $point ]] && command -v udisksctl >/dev/null && udisksctl mount -b "$p2" -o ro >/dev/null 2>&1; then
    montee=1
    point=$(findmnt -nro TARGET -S "$p2" 2>/dev/null | head -1 || true)
  fi
  if [[ -n $point ]]; then
    version=$(version_ventoy "$point")
    empreinte=$(empreinte_vtoyefi "$point")
  fi
  if [[ -n $montee ]]; then udisksctl unmount -b "$p2" >/dev/null 2>&1 || true; fi
  echo "${version:-?} $empreinte"
}

ventoy_de() { # disque : la version seule, rien si elle n'a pas été lue
  local version _
  read -r version _ <<<"$(vtoyefi_de "$1")"
  [[ $version == "?" ]] || echo "$version"
}

# La partition de démarrage VTOYEFI (le chargeur que tout ordinateur exécute avant même Ventoy) comparée à sa
# référence sur cet ordinateur, par l'empreinte de tous ses fichiers : jugée par sa seule version, elle pouvait être
# réécrite en voyage sans que rien ne le voie (campagne d'attaque n° 3). La référence (~/.local/state/vanguard/
# vtoyefi/<numéro de série>) s'écrit après chaque mise à jour de Ventoy faite ici, et à la première relève d'une clé
# (sa confiance du jour : dit) ; un écart n'est jamais repris tout seul : notification, puis --accepter-vtoyefi.
REFERENCES_VTOYEFI=$ETAT/vtoyefi
reference_vtoyefi() { # disque : le chemin de sa référence, ou rien (numéro de série illisible)
  local serie
  serie=$(lsblk -dno SERIAL "$1" 2>/dev/null | tr -cd 'A-Za-z0-9._-' || true)
  [[ -n $serie ]] && echo "$REFERENCES_VTOYEFI/$serie"
  return 0
}
noter_vtoyefi() { # disque version empreinte
  local ref
  ref=$(reference_vtoyefi "$1")
  [[ -n $ref && -n $3 && $3 != illisible && $3 != absente ]] || return 0
  mkdir -p "$REFERENCES_VTOYEFI" && printf '%s %s\n' "$2" "$3" >"$ref"
}
controler_vtoyefi() { # disque version empreinte : 1 si elle a changé ou ne se lit plus (dit)
  local ref
  ref=$(reference_vtoyefi "$1")
  if [[ -z $ref ]]; then
    echo "· Démarrage de la clé (VTOYEFI) : pas comparé (numéro de série de la clé illisible)."
    return 0
  fi
  if [[ ($3 == illisible || $3 == absente) && ! -s $ref ]]; then
    echo "· Démarrage de la clé (VTOYEFI) : pas comparé (partition absente ou illisible, aucune référence ici)."
    return 0
  fi
  # Relevée ici, elle se lisait : absente ou illisible aujourd'hui, elle n'est plus comparée, ce qui est en soi un
  # écart. Une clé refaite sans Ventoy, c'est voulu : --accepter-vtoyefi retire alors la référence, sans quoi l'alerte
  # reviendrait à chaque passage.
  if [[ $3 == absente ]]; then
    echo "✖ Démarrage de la clé (VTOYEFI) introuvable (partition absente ou renommée) : impossible de le comparer à sa"
    echo "  référence. À ne démarrer nulle part avant d'avoir compris pourquoi. Voulu (clé refaite sans Ventoy) :"
    echo "  outils/cle-secours.sh --accepter-vtoyefi retire sa référence."
    avertir "Clé VANGUARD : démarrage (VTOYEFI) introuvable" "Sa partition de démarrage n'est plus là où elle était à \
sa dernière relève ici. Ne démarrez aucun ordinateur sur cette clé avant d'avoir compris pourquoi. Si c'est voulu : \
outils/cle-secours.sh --accepter-vtoyefi."
    return 1
  fi
  if [[ $3 == illisible ]]; then
    echo "✖ Démarrage de la clé (VTOYEFI) illisible (fichier sans droit de lecture, partition pas montée) :"
    echo "  impossible de le comparer à sa référence. À ne démarrer nulle part avant d'avoir compris pourquoi."
    avertir "Clé VANGUARD : démarrage (VTOYEFI) illisible" "Sa partition de démarrage ne se lit plus comme à sa \
dernière relève ici : rien ne dit qu'elle est intacte. Ne démarrez aucun ordinateur sur cette clé avant d'avoir \
compris pourquoi."
    return 1
  fi
  if [[ ! -s $ref ]]; then
    noter_vtoyefi "$@"
    echo "· Démarrage de la clé (VTOYEFI) : première relève ici, prise pour référence (Ventoy $2)."
    return 0
  fi
  if [[ $(cat "$ref") == "$2 $3" ]]; then
    echo "✔ Démarrage de la clé (VTOYEFI) identique à sa référence."
    return 0
  fi
  echo "✖ Démarrage de la clé (VTOYEFI) changé hors de ce script depuis sa référence (Ventoy $2 sur la clé) : possible"
  echo "  piège, à ne démarrer nulle part. Remis à neuf par une mise à jour de Ventoy ; voulu : outils/cle-secours.sh"
  echo "  --accepter-vtoyefi."
  avertir "Clé VANGUARD : démarrage (VTOYEFI) modifié" "Ses fichiers ne sont plus ceux relevés ici après la dernière \
mise à jour de Ventoy. Ne démarrez aucun ordinateur sur cette clé avant d'avoir compris pourquoi."
  return 1
}
accepter_vtoyefi() { # la clé branchée : sa partition de démarrage telle qu'elle est devient la référence
  local point disque version empreinte ref
  point=$(point_cle)
  [[ -n $point ]] || erreur "Clé VANGUARD non branchée (ou au jeton inconnu de cet ordinateur)."
  disque=$(disque_de "$point")
  read -r version empreinte <<<"$(vtoyefi_de "$disque")"
  ref=$(reference_vtoyefi "$disque")
  # Plus de partition VTOYEFI : la clé n'a plus de démarrage à comparer. Sa référence retirée, et dit : la prochaine
  # relève d'une VTOYEFI sur cette clé sera reprise comme une première.
  if [[ $empreinte == absente && -n $ref ]]; then
    [[ -e $ref ]] || erreur "VTOYEFI introuvable sur la clé, et aucune référence ici : rien à faire."
    rm -f -- "$ref"
    echo "✔ Plus de partition VTOYEFI sur la clé : sa référence est retirée. Si Ventoy y revient, sa première relève"
    echo "  sera prise pour référence (et dite)."
    return 0
  fi
  [[ $empreinte != illisible && $empreinte != absente && -n $ref ]] || erreur "VTOYEFI illisible : rien n'est noté."
  noter_vtoyefi "$disque" "$version" "$empreinte"
  echo "✔ Démarrage de la clé (VTOYEFI, Ventoy $version) pris pour référence."
}

# L'archive de Ventoy épinglée, rangée avec les images (téléchargée au besoin), vérifiée par son empreinte : son chemin,
# ou code 1.
archive_ventoy() {
  local a=$IMAGES_LINUX/ventoy-$VENTOY-linux.tar.gz lien
  if lien=$(lien_mort "$IMAGES_LINUX"); then
    echo "  Cache des images introuvable : $lien mène à $(readlink "$lien") (disque débranché ?)." >&2
    return 1
  fi
  if ! empreinte_ok "$a" "$VENTOY_SHA256"; then
    mkdir -p "$IMAGES_LINUX"
    rm -f "$a.part"
    if ! curl -fsSL --retry 3 --connect-timeout 20 --max-time 600 -o "$a.part" \
      "$VENTOY_DEPOT/download/v$VENTOY/ventoy-$VENTOY-linux.tar.gz" || ! empreinte_ok "$a.part" "$VENTOY_SHA256"; then
      rm -f "$a.part"
      return 1
    fi
    mv -f "$a.part" "$a"
  fi
  realpath "$a"
}

# La partie root installée (outils/ventoy-racine.sh, copiée par --installer-racine) peut-elle servir ? Un fichier de
# root, dans un dossier de root, que personne d'autre ne peut modifier, identique à celle du dépôt : même épingle, mêmes
# vérifications. Sinon la raison, et code 1.
racine_installee() {
  local f u m
  [[ -f $RACINE ]] || { echo "la partie root de la mise à jour de Ventoy n'est pas installée ($RACINE)"; return 1; }
  for f in "$RACINE" "${RACINE%/*}"; do
    read -r u m < <(stat -c '%u %a' "$f")
    if [[ $u != 0 ]] || ((8#$m & 8#022)); then
      echo "$f n'est pas à root, ou d'autres que root peuvent le modifier"
      return 1
    fi
  done
  cmp -s "$RACINE" outils/ventoy-racine.sh ||
    { echo "la partie root installée n'est pas celle du dépôt (épingle de Ventoy changée depuis ?)"; return 1; }
}

# Une fois, puis après chaque changement d'épingle : la partie root copiée en fichier de root, là où pkexec la lance.
# C'est le seul moment où du code du dépôt passe en root ; lancé à la main, ce qui change est montré avant la fenêtre du
# mot de passe. Le fichier du dépôt n'est lu qu'une fois, dans une copie dont viennent le diff, l'empreinte et ce que
# root installe : relu dans le dépôt, il aurait pu changer entre le diff et le mot de passe. La copie est au compte elle
# aussi : le fichier installé, à root, qui ne change plus, doit avoir son empreinte.
installer_racine() {
  local source=$PWD/outils/ventoy-racine.sh copie empreinte raison
  if racine_installee >/dev/null; then
    echo "✔ Partie root déjà installée, identique à celle du dépôt : $RACINE (Ventoy $VENTOY)."
    return 0
  fi
  command -v pkexec >/dev/null || erreur "il manque pkexec."
  copie=$(mktemp --tmpdir ventoy-racine.XXXXXXXX) || erreur "copie de la partie root impossible."
  # Retirée même après une erreur ; son nom est pris tout de suite (copie est locale).
  # shellcheck disable=SC2064
  trap "rm -f -- $(printf %q "$copie")" EXIT
  cp -- "$source" "$copie" || erreur "$source pas copiée."
  if [[ -f $RACINE ]]; then
    echo "Ce qui change dans la partie root installée ($RACINE) :"
    diff -u --label "$RACINE" --label "$source" "$RACINE" "$copie" || true
  fi
  empreinte=$(sha256sum "$copie" | cut -d' ' -f1)
  echo "La fenêtre du mot de passe administrateur s'ouvre : $copie (copie de $source, SHA-256 $empreinte)" \
    "installée dans $RACINE (root, 755)."
  pkexec /usr/bin/install -D -o root -g root -m 0755 "$copie" "$RACINE" ||
    erreur "partie root pas installée (fenêtre fermée, ou mot de passe refusé)."
  empreinte_ok "$RACINE" "$empreinte" || erreur "$RACINE n'est pas la copie montrée (changée pendant la fenêtre du mot \
de passe ?) : à relire avant de s'en servir."
  raison=$(racine_installee) || erreur "$raison."
  rm -f -- "$copie"
  trap - EXIT
  echo "✔ Partie root installée : $RACINE (Ventoy $VENTOY épinglé)."
}

# Ventoy sur la clé branchée. Plus ancien que celui épinglé : la mise à jour, qui n'efface rien, est proposée par une
# notification à cliquer (avec la commande à lancer plus tard), au plus une fois par jour pour une même version. Sur un
# clic, --ventoy-maj tout de suite, sur la clé relevée au moment de la proposition (numéro de série et taille). Sans la
# partie root installée, rien n'est proposé : la notification dit comment l'installer.
verifier_ventoy() { # point de la clé
  local point=$1 disque version empreinte raison commande serie octets reponse
  disque=$(disque_de "$point")
  read -r version empreinte <<<"$(vtoyefi_de "$disque")"
  # Comparée avant la version : une ligne VENTOY_VERSION retirée de grub.cfg ne fait pas sauter la comparaison.
  controler_vtoyefi "$disque" "$version" "$empreinte" || return 1
  if [[ $version == "?" ]]; then
    echo "· Ventoy : version pas lue (VTOYEFI introuvable ou illisible) : non vérifié."
    return 0
  fi
  if ! plus_ancienne "$version" "$VENTOY"; then
    echo "✔ Ventoy $version sur la clé (épinglé ici : $VENTOY)."
    return 0
  fi
  echo "↑ Ventoy $version sur la clé, $VENTOY épinglé ici : mise à jour sans rien effacer, après accord."
  if ! raison=$(cle_ventoy "$disque"); then
    echo "  ✖ Mise à jour impossible : $raison."
    return 1
  fi
  commande="$PWD/outils/cle-secours.sh --ventoy-maj"
  if ! raison=$(racine_installee); then
    echo "  ✖ $raison : une fois, dans un terminal : $PWD/outils/cle-secours.sh --installer-racine, puis $commande"
    if ! deja_dit ventoy-racine "$version $VENTOY" 1200; then
      noter ventoy-racine "$version $VENTOY"
      avertir "Clé VANGUARD : Ventoy $version → $VENTOY" "Le démarrage de la clé peut se mettre à jour sans rien \
effacer, mais sa partie root est à installer d'abord ($raison). Une fois, dans un terminal : \
$PWD/outils/cle-secours.sh --installer-racine, puis $commande"
    fi
    return 0
  fi
  if ! archive_ventoy >/dev/null; then
    echo "  ✖ Archive de Ventoy $VENTOY pas téléchargée, ou différente de l'empreinte épinglée : nouvel essai au prochain"
    echo "    passage."
    return 1
  fi
  if deja_dit ventoy-propose "$version $VENTOY" 1200; then
    echo "  Déjà proposée aujourd'hui ; à la main : $commande"
    return 0
  fi
  noter ventoy-propose "$version $VENTOY"
  # La clé de la proposition, relevée maintenant : après le clic, c'est elle qui est mise à jour, ou rien.
  serie=$(lsblk -dno SERIAL "$disque")
  octets=$(lsblk -bdno SIZE "$disque")
  reponse=$(proposer 900 "Clé VANGUARD : Ventoy $version → $VENTOY" "Clic sur cette notification : le démarrage de \
la clé est mis à jour, sans rien effacer (le mot de passe administrateur est demandé). Clic droit : plus tard, dans un \
terminal : $commande" "Pas de réponse dans le quart d'heure : rien n'a changé. Plus tard, dans un terminal : \
$commande" "Mettre à jour")
  if [[ $reponse == oui ]]; then
    ventoy_maj "$disque" "$serie" "$octets"
  else
    echo "  Pas acceptée (fermée, ou pas de réponse dans le quart d'heure) ; plus tard : $commande"
  fi
}

# Un refus de --ventoy-maj, dit aussi par une notification : après un clic, rien d'autre ne le montrerait.
refuser_ventoy() { # raison
  echo "✖ Ventoy pas mis à jour : $1." >&2
  avertir "Clé VANGUARD : Ventoy pas mis à jour" "$1."
}

# Mise à jour de Ventoy sur la clé, sans rien effacer : l'archive épinglée vérifiée ici, puis la partie root installée,
# par pkexec (une fenêtre de mot de passe), journalisée dans ~/.local/state/vanguard/ventoy/. La clé visée est celle de
# la proposition (numéro de série et taille relevés alors) ou, lancée à la main, celle branchée maintenant ; une clé qui
# a déjà cette version, ou une plus récente, n'est pas touchée (la partie root le revérifie). Le même verrou que
# deployer.sh et images-cle.sh : rien d'autre n'écrit la clé pendant ce temps. Ventoy démonte les partitions de la clé
# pour écrire : celles qui étaient montées le sont de nouveau après.
ventoy_maj() { # disque serie octets (facultatifs : la clé branchée, relevée maintenant)
  local disque=${1:-} serie=${2:-} octets=${3:-} point raison version archive journal part code=0 apres pourquoi
  local montees=()
  if [[ -z $disque ]]; then
    point=$(point_cle)
    [[ -n $point ]] || erreur "Clé VANGUARD non branchée."
    disque=$(disque_de "$point")
  fi
  if ! raison=$(cle_ventoy "$disque"); then
    refuser_ventoy "$raison : rien n'est fait"
    return 1
  fi
  [[ -n $serie ]] || serie=$(lsblk -dno SERIAL "$disque")
  [[ -n $octets ]] || octets=$(lsblk -bdno SIZE "$disque")
  if ! meme_cle "$disque" "$serie" "$octets"; then
    refuser_ventoy "$disque n'est plus la clé de la proposition (numéro de série ou taille) : rien n'est fait"
    return 1
  fi
  version=$(ventoy_de "$disque")
  if [[ -n $version ]] && ! plus_ancienne "$version" "$VENTOY"; then
    echo "✔ Ventoy $version déjà sur la clé (épinglé ici : $VENTOY) : rien à faire."
    return 0
  fi
  if ! raison=$(racine_installee); then
    refuser_ventoy "$raison ; une fois, dans un terminal : $PWD/outils/cle-secours.sh --installer-racine"
    return 1
  fi
  command -v pkexec >/dev/null || erreur "il manque pkexec."
  if ! archive=$(archive_ventoy); then
    refuser_ventoy "archive de Ventoy $VENTOY pas téléchargée, ou différente de l'empreinte épinglée"
    return 1
  fi
  mkdir -p "$ETAT/ventoy"
  journal=$ETAT/ventoy/maj-$(date +%Y%m%d-%H%M%S).log
  exec 9>"${XDG_RUNTIME_DIR:-/tmp}/vanguard-deployer.lock"
  echo "Ventoy ${version:-?} → $VENTOY sur $disque : attente des autres écritures de la clé (verrou de deployer.sh)…"
  flock 9
  # L'attente a pu durer : une autre clé a pu prendre son nom entre-temps.
  if ! meme_cle "$disque" "$serie" "$octets"; then
    flock -u 9
    refuser_ventoy "$disque n'est plus la clé de la proposition (numéro de série ou taille) : rien n'est fait"
    return 1
  fi
  while read -r part; do
    if [[ -n $(findmnt -nro TARGET -S "$part" 2>/dev/null || true) ]]; then montees+=("$part"); fi
  done < <(lsblk -lnpo NAME "$disque" | tail -n +2)
  echo "La fenêtre du mot de passe administrateur s'ouvre ($RACINE). Journal : $journal"
  pkexec "$RACINE" "$disque" "$serie" "$octets" "$archive" 2>&1 | tee -a "$journal" || code=${PIPESTATUS[0]}
  udevadm settle 2>/dev/null || true
  for part in "${montees[@]}"; do
    if [[ -z $(findmnt -nro TARGET -S "$part" 2>/dev/null || true) ]] && command -v udisksctl >/dev/null; then
      udisksctl mount -b "$part" >/dev/null 2>&1 || true
    fi
  done
  flock -u 9
  local empreinte_apres
  read -r apres empreinte_apres <<<"$(vtoyefi_de "$disque")"
  [[ $apres != "?" ]] || apres=""
  echo "Ventoy lu sur la clé après la mise à jour : ${apres:-pas lu}." | tee -a "$journal"
  if ((code == 0)) && [[ $apres == "$VENTOY" ]]; then
    # Ce que la partie root vient d'écrire, depuis l'archive épinglée : la nouvelle référence du démarrage.
    noter_vtoyefi "$disque" "$apres" "$empreinte_apres"
    echo "✔ Ventoy $VENTOY sur la clé ; rien n'a été effacé." | tee -a "$journal"
    avertir "Clé VANGUARD : Ventoy $VENTOY installé" "Rien n'a été effacé. Journal : $journal"
    return 0
  fi
  if ((code == RIEN_A_FAIRE)); then
    echo "✔ Ventoy ${apres:-?} sur la clé, pas plus ancien que $VENTOY : rien n'a été écrit." | tee -a "$journal"
    return 0
  fi
  case $code in
    0) pourquoi="la clé dit encore Ventoy ${apres:-?}" ;;
    126) pourquoi="fenêtre du mot de passe fermée : rien n'a changé" ;;
    127) pourquoi="pas d'autorisation (mot de passe refusé, ou aucune fenêtre de mot de passe possible) : rien n'a \
changé ; la commande se lance aussi dans un terminal : $PWD/outils/cle-secours.sh --ventoy-maj" ;;
    *) pourquoi="la partie root s'est arrêtée (code $code)" ;;
  esac
  echo "✖ Ventoy pas mis à jour : $pourquoi." | tee -a "$journal" >&2
  avertir "Clé VANGUARD : Ventoy pas mis à jour" "$pourquoi. Journal : $journal"
  return 1
}

# Pour le développeur (images-cle.sh --chercher le lance) : GitHub a-t-il un Ventoy plus récent que l'épingle ? Rien
# n'est pris tout seul : l'archive n'a pas de signature et son empreinte ne se croit pas sur parole ; l'épingle
# (VENTOY et VENTOY_SHA256, dans outils/ventoy-racine.sh) change à la main, après vérification, puis la partie root
# se réinstalle (--installer-racine). Une notification par version.
ventoy_publie() {
  local derniere
  derniere=$(curl -fsS --max-time 30 -o /dev/null -w '%{redirect_url}' "$VENTOY_DEPOT/latest" 2>/dev/null |
    sed -n 's|.*/tag/v\([0-9][0-9.]*\)$|\1|p' || true)
  if [[ -z $derniere ]]; then
    echo "· Ventoy : dernière version de GitHub introuvable (pas d'Internet ?)."
  elif plus_ancienne "$VENTOY" "$derniere"; then
    echo "↑ Ventoy $derniere publié sur GitHub (épinglé ici : $VENTOY) : à vérifier, puis à épingler à la main."
    if [[ $(cat "$ETAT/ventoy-publie" 2>/dev/null) != "$derniere" ]]; then
      noter ventoy-publie "$derniere"
      avertir "Vanguard, développement : Ventoy $derniere publié" "Épinglé : $VENTOY (VENTOY et VENTOY_SHA256 dans \
outils/ventoy-racine.sh). L'archive n'est pas signée : comparer son empreinte à celle de la page de la version, \
épingler à la main, puis réinstaller la partie root : outils/cle-secours.sh --installer-racine."
    fi
  else
    echo "✔ Ventoy : $VENTOY épinglé, le dernier publié sur GitHub."
  fi
}

# L'âge de Windows 11 sur la clé : la date de ses fichiers, que 7z garde en les tirant de l'image (setup.exe de la
# partition WIN11, sinon celui de l'image dans ISO/). Plus de six mois : dit, au plus une fois par mois. Rien ne la
# remplace tout seul : Microsoft ne donne qu'un lien de 24 heures, et l'empreinte qui la vérifie se lit sur sa page.
verifier_windows_age() { # point de la clé
  local point=$1 disque p5 win=${VANGUARD_WIN11:-} date="" iso quand
  if [[ -z $win ]]; then
    disque=$(disque_de "$point")
    p5=$([[ -n $disque ]] && partition "$disque" 5 || true)
    if [[ -n $p5 && -b $p5 && $(lsblk -dno PARTLABEL "$p5" 2>/dev/null) == WIN11 ]]; then
      win=$(findmnt -nro TARGET -S "$p5" 2>/dev/null | head -1 || true)
    fi
  fi
  if [[ -n $win && -f $win/setup.exe ]]; then
    date=$(stat -c %Y "$win/setup.exe")
  else
    iso=$([[ -d $point/ISO ]] && fichier_windows "$point/ISO" || true)
    if [[ -n $iso ]]; then
      date=$(7z l -slt -ba "$iso" setup.exe 2>/dev/null | sed -n 's/^Modified = \([0-9-]* [0-9:]*\).*/\1/p' | head -1 ||
        true)
      [[ -z $date ]] || date=$(date -d "$date" +%s 2>/dev/null || true)
    fi
  fi
  if [[ -z $date ]]; then
    echo "· Windows 11 : ni partition WIN11 montée, ni image dans ISO/ : âge non vérifié."
    return 0
  fi
  quand=$(date -d "@$date" +%F)
  if (($(date +%s) - date <= 183 * 86400)); then
    echo "✔ Windows 11 : image du $quand."
    return 0
  fi
  echo "↑ Windows 11 : image du $quand, de plus de six mois ; une neuve se prend à la main chez Microsoft."
  if ! deja_dit windows-age "$quand" 43200; then
    noter windows-age "$quand"
    avertir "Clé VANGUARD : Windows 11 de plus de six mois" "Image du $quand (partition WIN11 et ISO/). Une \
installation se met à jour ensuite par Windows Update. Pour une image neuve : $PWD/outils/cle-secours.sh --telecharger \
DOSSIER dit comment la prendre chez Microsoft."
  fi
}

# La clé branchée est-elle à jour pour démarrer les ordinateurs ? Lancé par maj-cle.sh (chaque jour) et au branchement
# (vanguard-images-cle.service). Ventoy en dernier : sa proposition attend un clic un quart d'heure au plus.
a_jour() { # point de la clé (facultatif)
  local point=${1:-}
  [[ -n $point ]] || point=$(point_cle)
  if [[ -z $point || ! -d $point ]]; then
    echo "Clé VANGUARD non branchée : rien à vérifier."
    return 0
  fi
  verifier_windows_age "$point"
  # La récupération de macOS n'a pas d'âge qui compte : elle installe le dernier macOS, pris chez Apple au moment
  # d'installer. La réécrire demanderait root et --ecrire, qui efface la clé.
  echo "· Récupération de macOS : rien à tenir à jour (elle prend le dernier macOS chez Apple en installant)."
  verifier_ventoy "$point"
}

# Lu par outils/essais-cle.sh (source) : les fonctions seulement, rien n'est lancé.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
# La clé de secours se fait partout, sauf sur un ordinateur dont le réglage local la coupe (CLE_SECOURS=non, lu par
# images-cle.sh, le seul à lire ce fichier) : là, une clé ne porte que le programme. La partie root (--racine)
# n'est pas gardée ici : pkexec la lance avec le dossier de root, sans ce réglage, et seulement depuis --ecrire, qui
# l'a été ; --ventoy-publie ne fait que lire GitHub.
# images-cle.sh en panne (ni « oui » ni « non ») n'est pas un réglage qui dit non : c'est dit, code 1, même pour --a-jour.
secours_ici() {
  local r
  r=$(outils/images-cle.sh --secours 2>/dev/null) || true
  case $r in
    oui) return 0 ;;
    non) return 1 ;;
    *) erreur "outils/images-cle.sh --secours ne répond pas (« $r ») : clé de secours non vérifiée, rien n'est fait." ;;
  esac
}
case ${1:-} in
  --plan | --essai | --telecharger | --verifier | --ecrire | --windows | --ventoy-maj | --installer-racine | \
    --accepter-vtoyefi)
    secours_ici ||
      erreur "clé de secours coupée sur cet ordinateur : rien n'est préparé (ni images, ni Ventoy, ni WIN11, ni \
MACOS) ; la clé ne porte que le programme (outils/preparer-cle.sh). Pour la rallumer ici : retirer la ligne \
CLE_SECOURS=non de ${XDG_CONFIG_HOME:-$HOME/.config}/vanguard/images-cle.conf (le détail : en-tête de \
outils/images-cle.sh)."
    ;;
  --a-jour)
    if ! secours_ici; then
      echo "· Clé de secours coupée sur cet ordinateur : ni Ventoy ni Windows 11 à tenir à jour."
      exit 0
    fi
    ;;
esac
# Le dossier des images, s'il est donné : jamais recréé à la place d'un lien mort.
case ${1:-} in
  --plan) [[ -z ${3:-} ]] || dossier_joignable "$3" ;;
  --essai) [[ -z ${2:-} ]] || dossier_joignable "$2" ;;
  --telecharger | --verifier) dossier_joignable "${2:?dossier des images}" ;;
  --ecrire | --windows) dossier_joignable "${3:?dossier des images vérifiées}" ;;
esac
case ${1:-} in
  --plan) plan "${2:-}" "${3:-}" ;;
  --essai) essai "${2:-}" ;;
  --telecharger) telecharger "${2:?dossier des images}" ;;
  --verifier) verifier "${2:?dossier des images}" cle ;;
  --ecrire) ecrire "${2:?disque, par exemple /dev/sdb}" "${3:?dossier des images vérifiées}" ;;
  --windows) completer_windows "${2:?disque, par exemple /dev/sdb}" "${3:?dossier des images vérifiées}" ;;
  --racine) [[ $EUID -eq 0 ]] || erreur "--racine se lance par pkexec, depuis --ecrire."; racine "${@:2}" ;;
  --a-jour) a_jour "${2:-}" ;;
  --ventoy-maj) ventoy_maj "${2:-}" ;;
  --accepter-vtoyefi) accepter_vtoyefi ;;
  --installer-racine) installer_racine ;;
  --ventoy-publie) ventoy_publie ;;
  *) sed -n '2,47p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
