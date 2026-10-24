#!/usr/bin/env bash
# Prépare une clé USB VANGUARD : EFFACE la clé, puis la découpe en deux partitions exFAT (table GPT).
#   VANGUARD      programmes, guides, base, code source. Attribut GPT « lecture seule » (bit 60) : Windows la monte
#                 en lecture seule, la clé ne peut pas être modifiée sur l'ordinateur d'un autre. Linux ignore cet
#                 attribut : sur ce PC, elle reste modifiable et deployer.sh la met à jour comme avant.
#   VANGUARDLOG   64 Mio, modifiable partout : journal-erreurs.txt (voir src/journal.rs), rapatrié par deployer.sh.
# C'est la clé par défaut : le programme seul (Vanguard, sa base, ses rapports, le journal), ni images ni démarrage.
# La clé de secours, qui démarre aussi les ordinateurs, ne se fait que sur un ordinateur dont le réglage local la
# demande (outils/cle-secours.sh, outils/images-cle.sh).
# Sans sudo : udisks autorise l'utilisateur connecté à modifier une clé amovible.
#   outils/preparer-cle.sh /dev/sdX
# Le contenu actuel de la clé est d'abord sauvegardé dans ~/.local/share/vanguard/sauvegarde-cle-<date>/,
# puis sa base (donnees/) est remise sur la nouvelle partition.
set -euo pipefail
cd "$(dirname "$0")/.."

DISQUE=${1:?usage : outils/preparer-cle.sh /dev/sdX}
NOM=$(basename "$DISQUE")
OBJET=/org/freedesktop/UDisks2/block_devices/$NOM
DONNEES_GPT=ebd0a0a2-b9e5-4433-87c0-68b6b72699c7
LECTURE_SEULE=$((1 << 60))
JOURNAL_OCTETS=$((64 * 1024 * 1024))
MIO=$((1024 * 1024))

[[ $(lsblk -dno RM,TRAN "$DISQUE" | tr -s ' ') == "1 usb" ]] || {
  echo "$DISQUE n'est pas une clé USB amovible : abandon."
  exit 1
}
lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS "$DISQUE"
read -rp "Tout le contenu de $DISQUE va être effacé. Taper EFFACER pour continuer : " reponse
[[ $reponse == EFFACER ]] || exit 1

udisks() { busctl call --timeout=120 org.freedesktop.UDisks2 "$@"; }

# Sauvegarde de ce qui est monté (la base donnees/ surtout ; le reste se recopie), puis effacement des signatures
# des anciennes partitions : sinon un système de fichiers resté au même endroit réapparaît dans une nouvelle
# partition, et udiskie le monte avant qu'on ait pu la formater (« Device or resource busy »).
SAUVEGARDE="${XDG_DATA_HOME:-$HOME/.local/share}/vanguard/sauvegarde-cle-$(date +%Y%m%d-%H%M%S)"
while read -r part point; do
  if [[ -n $point ]]; then
    mkdir -p "$SAUVEGARDE/$part"
    cp -r "$point/." "$SAUVEGARDE/$part/"
  fi
  # udiskie peut remonter la partition entre deux commandes : on réessaie.
  for essai in {1..5}; do
    udisksctl unmount -b "/dev/$part" >/dev/null 2>&1 || true
    udisks "/org/freedesktop/UDisks2/block_devices/$part" org.freedesktop.UDisks2.Block Format 'sa{sv}' empty 0 \
      >/dev/null 2>&1 && break
    ((essai < 5)) || { echo "Impossible d'effacer /dev/$part (toujours utilisée ?) : abandon."; exit 1; }
    sleep 1
  done
done < <(lsblk -lnpo NAME,MOUNTPOINT "$DISQUE" | tail -n +2 | sed 's|^/dev/||')
[[ -d $SAUVEGARDE ]] && echo "Sauvegarde : $SAUVEGARDE"

# Table GPT neuve (les anciennes signatures sont effacées).
udisks "$OBJET" org.freedesktop.UDisks2.Block Format 'sa{sv}' gpt 0
TAILLE=$(busctl get-property org.freedesktop.UDisks2 "$OBJET" org.freedesktop.UDisks2.Block Size | awk '{print $2}')
# 1 Mio au début (alignement), 1 Mio à la fin (copie de la table GPT), 64 Mio pour le journal.
TAILLE_VANGUARD=$(((TAILLE - 2 * MIO - JOURNAL_OCTETS) / MIO * MIO))
# Nom du volume exFAT : 11 caractères au plus (d'où VANGUARDLOG).
creer() { # offset taille nom
  udisks "$OBJET" org.freedesktop.UDisks2.PartitionTable CreatePartitionAndFormat 'ttssa{sv}sa{sv}' \
    "$1" "$2" "$DONNEES_GPT" "$3" 0 exfat 1 label s "$3" | awk -F'"' '{print $2}'
}
P1=$(creer "$MIO" "$TAILLE_VANGUARD" VANGUARD)
P2=$(creer $((MIO + TAILLE_VANGUARD)) 0 VANGUARDLOG)
busctl call org.freedesktop.UDisks2 "$P1" org.freedesktop.UDisks2.Partition SetFlags 'ta{sv}' "$LECTURE_SEULE" 0
udevadm settle

# Le bureau monte souvent les nouvelles partitions tout seul : on prend le point de montage, ou on monte.
monter() {
  local point
  for _ in {1..10}; do
    point=$(findmnt -nro TARGET -S "$1" | head -1 || true)
    [[ -n $point ]] && echo "$point" && return
    udisksctl mount -b "$1" >/dev/null 2>&1 || sleep 1
  done
  return 1
}
CLE=$(monter "/dev/$(basename "$P1")")
JOURNAL=$(monter "/dev/$(basename "$P2")")
touch "$CLE/vanguard.cle" "$JOURNAL/vanguard-journal.cle"
# Base la plus récente parmi les sauvegardes (une préparation interrompue puis relancée sauvegarde une clé vide).
ANCIENNE=$(ls -dt "${XDG_DATA_HOME:-$HOME/.local/share}"/vanguard/sauvegarde-cle-*/*/donnees 2>/dev/null | head -1 || true)
if [[ -n $ANCIENNE ]]; then
  cp -r "$ANCIENNE" "$CLE/"
  echo "Base remise sur la clé : $ANCIENNE"
fi
# Une clé neuve, que l'auteur vient d'effacer : son jeton est tiré et cet ordinateur l'adopte (sans cela, deployer.sh
# refuse un volume au jeton inconnu).
outils/deployer.sh --accepter-cle "$CLE"
lsblk -o NAME,SIZE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS "$DISQUE"
echo "Attribut lecture seule (Windows) : $(udisksctl info -b "/dev/$(basename "$P1")" | awk '/Flags:/{print $2}')"
