#!/usr/bin/env bash
# Essais des outils de la clé VANGUARD (images-cle.sh, cle-secours.sh, ventoy-racine.sh, menage-dev.sh, la partie clé
# de deployer.sh et cle-commun.sh, journal-vers-github.py avec un faux gh), sans rien
# toucher de l'ordinateur. Tout se passe dans un espace de noms à part (unshare -rmn : sans root ni Internet) où
# /run/media et /run/user sont cachés par des tmpfs : ni la vraie clé, ni la session (D-Bus, notifications) n'y sont
# plus. Une fausse clé (un tmpfs de la taille voulue), un faux cache d'images, de faux notify-send, aria2c, pkexec et
# curl, un PATH sans udisksctl, sudo, systemctl, sfdisk ni mkfs ; les disques (lsblk, sfdisk…) sont simulés par des
# fonctions, dans les scripts lus par source : aucun vrai disque n'est ouvert. Lancé par outils/verifier.sh ; code 77
# (sauté) sans espaces de noms d'utilisateur.
#   outils/essais-cle.sh
set -uo pipefail
cd "$(dirname "$0")/.."
DEPOT=$PWD

if [[ -z ${ESSAIS_CLE_DEDANS:-} ]]; then
  # La raison d'un essai sauté en première ligne : verifier.sh la montre.
  unshare -rmn true 2>/dev/null || { echo "espaces de noms d'utilisateur indisponibles"; exit 77; }
  # Le seul essai avec le vrai compte : la partie root refuse de tourner sans root (elle s'arrête avant tout le reste).
  sortie=$(bash outils/ventoy-racine.sh /dev/sdz SERIE 1 /nulle-part 2>&1)
  if [[ $? == 1 && $sortie == *"se lance en root par pkexec"* ]]; then
    echo "  ✔ partie root : refusée sans root"
  else
    echo "  ✖ partie root : lancée sans root ($sortie)"
    exit 1
  fi
  ESSAIS_CLE_DEDANS=1 ESSAIS_CLE_UID=$(id -u) exec unshare -rmn --propagation private bash "$0" "$@"
fi

# --- Le banc ---------------------------------------------------------------------------------------------------------

[[ $(awk 'NR == 1 {print ($1 == 0 && $2 != 0) ? "oui" : "non"}' /proc/self/uid_map) == oui ]] ||
  { echo "pas dans un espace de noms d'utilisateur à part : abandon"; exit 1; }
# Sans /run/media (la CI de GitHub), impossible de le créer sous le /run du vrai root : un tmpfs sur /run entier, dans
# cet espace de noms seulement, le permet (et cache /run/user avec lui).
if [[ ! -d /run/media ]]; then
  /usr/bin/mount -t tmpfs -o size=1M tmpfs /run && mkdir /run/media || { echo "/run pas caché : abandon"; exit 1; }
fi
for d in /run/media "/run/user/$ESSAIS_CLE_UID"; do
  [[ -d $d ]] || continue
  /usr/bin/mount -t tmpfs -o size=1M tmpfs "$d" || { echo "$d pas caché : abandon"; exit 1; }
  [[ $(findmnt -no FSTYPE -M "$d" | tail -1) == tmpfs && -z $(ls -A "$d") ]] ||
    { echo "$d pas caché : abandon"; exit 1; }
done

mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/vanguard-dev"
# Sous vanguard-dev/essai-* : un banc resté là (essais tués) part au ménage de la semaine (outils/menage-dev.sh).
BANC=$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/vanguard-dev/essai-cle.XXXX") || exit 1
nettoyer() {
  cd / || return
  findmnt -rno TARGET | grep "^$BANC/" | sort -r | xargs -r -n1 /usr/bin/umount 2>/dev/null
  rm -rf "$BANC"
}
trap nettoyer EXIT
mkdir -p "$BANC"/{bin,faux,maison,xdg-cache,etat,run,donnees,config,tmp,cache,disque,aria2}

# Rien du vrai compte : dossiers, session, Internet (déjà coupé). Le témoin de la clé est cherché sous /run/media/$USER.
# VANGUARD_RACINE n'est écoutée que dans les essais (VANGUARD_ESSAI).
export BANC USER=alice HOME=$BANC/maison XDG_CACHE_HOME=$BANC/xdg-cache XDG_STATE_HOME=$BANC/etat \
  XDG_RUNTIME_DIR=$BANC/run XDG_DATA_HOME=$BANC/donnees XDG_CONFIG_HOME=$BANC/config TMPDIR=$BANC/tmp \
  VANGUARD_IMAGES=$BANC/cache VANGUARD_RACINE=$BANC/libexec/vanguard/ventoy-racine VANGUARD_ESSAI=1
unset DBUS_SESSION_BUS_ADDRESS DISPLAY WAYLAND_DISPLAY VANGUARD_VTOYEFI VANGUARD_WIN11 ESSAIS_CLE_DEDANS

# Les commandes du système, sauf celles qui touchent un disque, un montage, root, systemd, la session ou Internet.
find /usr/bin -maxdepth 1 \( -type f -o -type l \) ! -name udisksctl ! -name pkexec ! -name sudo ! -name sudoedit \
  ! -name su ! -name doas ! -name run0 ! -name systemctl ! -name systemd-run ! -name notify-send ! -name aria2c \
  ! -name curl ! -name wget ! -name gdbus ! -name busctl ! -name dbus-send ! -name sfdisk ! -name sgdisk \
  ! -name parted ! -name fdisk ! -name gdisk ! -name wipefs ! -name partx ! -name losetup ! -name mount \
  ! -name umount ! -name udevadm ! -name 'mkfs*' ! -name mkexfatfs ! -name mke2fs ! -name sync \
  -exec ln -s -t "$BANC/bin" {} +

cat >"$BANC/faux/notify-send" <<'FIN'
#!/usr/bin/env bash
# Faux notify-send : chaque appel noté dans $BANC/notifications.log (arguments séparés par « | »). Comme le vrai
# (libnotify 0.8) : -p écrit le numéro de la notification ; avec -A, il attend la réponse. ESSAI_CLIC : default (un
# clic, « default » écrit), ferme (fermée sans clic), sinon il attend comme une notification laissée là (Ctrl-C : il la
# ferme et sort sans erreur ; tué par timeout, il ne dit rien). ESSAI_SERIE_APRES_CLIC : une autre clé prend le nom du
# disque pendant la proposition.
printf '%s|' "$@" >>"$BANC/notifications.log"
echo >>"$BANC/notifications.log"
attendre="" numero=""
for a in "$@"; do case $a in -A | --action | --action=*) attendre=1 ;; -p | --print-id) numero=1 ;; esac; done
n=$(($(cat "$BANC/notifications.id" 2>/dev/null || echo 0) + 1))
echo "$n" >"$BANC/notifications.id"
[[ -z $numero ]] || echo "$n"
[[ -n $attendre ]] || exit 0
[[ -z ${ESSAI_SERIE_APRES_CLIC:-} ]] || echo "$ESSAI_SERIE_APRES_CLIC" >"$BANC/disque/serie"
case ${ESSAI_CLIC:-attend} in
  default) echo default; exit 0 ;;
  ferme) exit 0 ;;
esac
sleep 60 &
attente=$!
trap 'kill $attente 2>/dev/null; exit 0' INT
trap 'kill $attente 2>/dev/null; exit 143' TERM
wait $attente
FIN

cat >"$BANC/faux/aria2c" <<'FIN'
#!/usr/bin/env bash
# Faux aria2c : chaque appel noté dans $BANC/aria2c.log (l'image, et « reprise » si l'image commencée était là). Son
# comportement pour chaque image dans $BANC/aria2/<image> : partiel (4 Kio de plus et un .aria2), lent (attend ; Ctrl-C
# ou TERM : arrêt propre), sinon aucune source. Code 7 dans tous les cas, comme le vrai sans image finie.
dir="" torrent=""
for a in "$@"; do case $a in --dir=*) dir=${a#--dir=} ;; --*) ;; *) torrent=$a ;; esac; done
nom=$(basename "${torrent%.torrent}")
etat=debut
[[ -s $dir/$nom ]] && etat=reprise
echo "$nom $etat" >>"$BANC/aria2c.log"
case $(cat "$BANC/aria2/$nom" 2>/dev/null) in
  partiel) head -c 4096 /dev/urandom >>"$dir/$nom"; : >"$dir/$nom.aria2" ;;
  lent)
    sleep 60 &
    p=$!
    trap 'kill $p 2>/dev/null; exit 7' INT TERM
    wait $p
    ;;
esac
exit 7
FIN

cat >"$BANC/faux/pkexec" <<'FIN'
#!/usr/bin/env bash
# Faux pkexec : ses arguments notés dans $BANC/pkexec.log. ESSAI_PKEXEC : lance (exécute la commande, seulement
# /usr/bin/install vers le banc : --installer-racine), reussi (0, et le faux VTOYEFI dit la version ESSAI_VERSION), un
# code (126, 127, 3…) ; sinon 0, sans rien lancer. ESSAI_PIEGE, avec lance : un programme du compte change un fichier
# pendant la fenêtre du mot de passe (source : celui qu'install va copier ; sinon ce chemin), sous le banc seulement.
printf '%s\n' "$*" >>"$BANC/pkexec.log"
case ${ESSAI_PKEXEC:-0} in
  lance)
    [[ $1 == /usr/bin/install && ${!#} == "$BANC"/* ]] || { echo "faux pkexec : refusé ($*)" >&2; exit 1; }
    arguments=("$@")
    piege=${ESSAI_PIEGE:-}
    [[ $piege != source ]] || piege=${arguments[-2]}
    if [[ -n $piege ]]; then
      [[ $piege == "$BANC"/* ]] || { echo "faux pkexec : piège hors du banc ($piege)" >&2; exit 1; }
      echo "# piégée pendant la fenêtre du mot de passe" >>"$piege"
    fi
    exec "$@"
    ;;
  reussi)
    [[ $VANGUARD_VTOYEFI == "$BANC"/* ]] || exit 1
    sed -i "s/VENTOY_VERSION=\"[0-9.]*\"/VENTOY_VERSION=\"$ESSAI_VERSION\"/" "$VANGUARD_VTOYEFI/grub/grub.cfg"
    ;;
  *) exit "${ESSAI_PKEXEC:-0}" ;;
esac
FIN

cat >"$BANC/faux/sync" <<'FIN'
#!/usr/bin/env bash
# Faux sync : ESSAI_SYNC=echec fait échouer celui d'une copie en cours (.part), comme une clé qui lâche.
if [[ ${ESSAI_SYNC:-} == echec && ${!#} == *.part ]]; then exit 1; fi
exec /usr/bin/sync "$@"
FIN
printf '#!/bin/sh\necho "curl: (6) pas d'"'"'Internet dans les essais" >&2\nexit 6\n' >"$BANC/faux/curl"
printf '#!/bin/sh\nexit 0\n' >"$BANC/faux/udevadm"
chmod +x "$BANC"/faux/*
export PATH=$BANC/faux:$BANC/bin

# Le réglage local de la clé de secours (lu par images-cle.sh, jamais sourcé) : allumé pour les essais de la clé de
# secours, retiré pour ceux de la clé par défaut, qui ne porte que le programme.
REGLAGE=$BANC/config/vanguard/images-cle.conf
mkdir -p "${REGLAGE%/*}"
reglage() { printf '%s\n' "$@" >"$REGLAGE"; } # lignes…
reglage CLE_SECOURS=oui

# Une fausse clé /dev/sdz, lue par source après le script essayé : USB amovible, VANGUARD (exFAT) et VTOYEFI (32 Mio) de
# Ventoy ; son numéro de série, sa taille, ses attributs GPT et sa version de Ventoy dans $BANC/disque/. Les écritures
# (sfdisk, Ventoy2Disk.sh -u) y sont notées, jamais faites.
cat >"$BANC/simul-disque.sh" <<'FIN'
D=/dev/sdz
bloc() { [[ $1 == "$D" || $1 == "${D}1" || $1 == "${D}2" ]]; }
lsblk() {
  case "$*" in
    "-dno TYPE $D") echo disk ;;
    "-dno RM,TRAN $D") echo "1 usb" ;;
    "-dno SERIAL $D") cat "$BANC/disque/serie" 2>/dev/null ;;
    "-bdno SIZE $D") cat "$BANC/disque/taille" 2>/dev/null ;;
    "-dno LABEL ${D}1") echo VANGUARD ;;
    "-dno FSTYPE ${D}1") echo exfat ;;
    "-dno LABEL ${D}2" | "-dno PARTLABEL ${D}2") echo VTOYEFI ;;
    "-dno FSTYPE ${D}2") echo vfat ;;
    "-bdno SIZE ${D}2") echo 33554432 ;;
    "-lnpo TYPE $D") printf 'disk\npart\npart\n' ;;
    "-lnpo MOUNTPOINTS $D") printf '\n/run/media/alice/VANGUARD\n\n' ;;
    "-lnpo NAME $D") printf '%s\n' "$D" "${D}1" "${D}2" ;;
    *" $D" | *" ${D}"[0-9]) echo "lsblk simulé : $* inconnu" >&2; return 1 ;;
    *) command lsblk "$@" ;;
  esac
}
sfdisk() {
  case "$*" in
    "--part-attrs $D 1") cat "$BANC/disque/attributs" ;;
    "--no-reread --part-attrs $D 1 "*)
      echo "${!#}" >"$BANC/disque/attributs"
      echo "sfdisk $*" >>"$BANC/disque/ecritures"
      ;;
    *) echo "sfdisk simulé : $* refusé" >&2; return 1 ;;
  esac
}
FIN

# Disque, archive de Ventoy (fausse, 9.9.9 : son empreinte remplace l'épingle dans les essais de la partie root), partie
# root installée (une copie de celle du dépôt : dans l'espace de noms, les fichiers du compte sont à root).
cle_simulee() { # version de Ventoy sur la clé
  printf 'SERIE-A\n' >"$BANC/disque/serie"
  printf '31037849600\n' >"$BANC/disque/taille"
  printf 'GUID:60\n' >"$BANC/disque/attributs"
  printf '%s\n' "$1" >"$BANC/disque/ventoy"
  rm -f "$BANC/disque/ecritures" "$BANC/pkexec.log" "$BANC/notifications.log" "$BANC/notifications.id"
  rm -rf "$BANC/etat"
  mkdir -p "$BANC/vtoyefi/grub"
  printf 'set VENTOY_VERSION="%s"\n' "$1" >"$BANC/vtoyefi/grub/grub.cfg"
}
mkdir -p "$BANC/archive/ventoy-9.9.9/ventoy"
echo 9.9.9 >"$BANC/archive/ventoy-9.9.9/ventoy/version"
cat >"$BANC/archive/ventoy-9.9.9/Ventoy2Disk.sh" <<'FIN'
# Faux Ventoy2Disk.sh : -l dit la version de la fausse clé ; -u lit la réponse, note l'écriture et pose la version
# 9.9.9. ESSAI_U=retire : la clé est retirée pendant (plus de numéro de série) ; attributs : Ventoy les change ; lent :
# comme VentoyWorker.sh, le démarrage écrit, puis VTOYEFI et les attributs changés ; son numéro dans en-cours, et dans
# masque-u les signaux qu'ignore un de ses programmes (grep, qui n'y touche pas : bash ignore toujours SIGQUIT pour
# lui-même, et gawk SIGPIPE). VTOYEFI est écrite par un programme qui remet Ctrl-C par défaut (un programme C le
# peut toujours) et s'arrête sur une sortie ratée : il attend que l'essai ait envoyé ses signaux, puis en dit plus que
# ce qu'un sed garde avant d'écrire (4 Kio), et encore une ligne.
case $1 in
  -l) echo "*****"; echo "Ventoy Version in Disk: $(cat "$BANC/disque/ventoy")"; echo "Disk Partition Style  : GPT" ;;
  -u)
    read -r r
    echo "Ventoy2Disk.sh -u $2 ($r)" >>"$BANC/disque/ecritures"
    if [ "${ESSAI_U:-}" = lent ]; then
      grep '^SigIgn' /proc/self/status >"$BANC/disque/masque-u"
      echo "démarrage écrit" >>"$BANC/disque/ecritures"
      echo $$ >"$BANC/disque/en-cours"
      python3 -I -c 'import os, signal, sys, time
signal.signal(signal.SIGINT, signal.SIG_DFL)
for _ in range(100):
    if os.path.exists(sys.argv[1] + "/signaux"):
        break
    time.sleep(0.1)
for i in range(60):
    print(f"esp partition processing ... {i:02d} " + "." * 60, flush=True)
time.sleep(0.3)
print("update esp partition attribute", flush=True)
with open(sys.argv[1] + "/ecritures", "a") as f:
    f.write("VTOYEFI écrite\n")' "$BANC/disque"
      : >"$BANC/disque/attributs"
    fi
    echo 9.9.9 >"$BANC/disque/ventoy"
    case ${ESSAI_U:-} in retire) : >"$BANC/disque/serie" ;; attributs) : >"$BANC/disque/attributs" ;; esac
    [ "${ESSAI_U:-}" != lent ] || : >"$BANC/disque/fin-u"
    ;;
esac
FIN
tar -czf "$BANC/ventoy-9.9.9.tar.gz" -C "$BANC/archive" ventoy-9.9.9
FAUSSE_SHA256=$(sha256sum "$BANC/ventoy-9.9.9.tar.gz" | cut -d' ' -f1)
install -D -m 0755 outils/ventoy-racine.sh "$VANGUARD_RACINE"
EPINGLE=$(sed -n 's/^VENTOY=//p' outils/ventoy-racine.sh)

# Pseudo-terminal : la commande lancée, Ctrl-C au bout de $1 s ; « fin <secondes> <signal|code> » au plus $2 s après.
# Lancés en arrière-plan (verifier.sh), les essais héritent d'un Ctrl-C ignoré, qu'aucun script ne peut rétablir : il
# est rendu à la commande, comme dans un terminal.
cat >"$BANC/pty.py" <<'FIN'
import os, pty, select, signal, sys, time
apres, plus = float(sys.argv[1]), float(sys.argv[2])
pid, fd = pty.fork()
if pid == 0:
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGQUIT, signal.SIG_DFL)
    os.execvp(sys.argv[3], sys.argv[3:])
sortie, debut, envoye, etat = b"", time.time(), None, None
while etat is None and time.time() - debut < apres + plus:
    if envoye is None and time.time() - debut >= apres:
        os.write(fd, b"\x03")
        envoye = time.time()
    if select.select([fd], [], [], 0.05)[0]:
        try:
            sortie += os.read(fd, 65536)
        except OSError:
            pass
    fini, statut = os.waitpid(pid, os.WNOHANG)
    if fini:
        etat = statut
if etat is None:
    os.killpg(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("fin jamais")
else:
    quoi = f"signal{os.WTERMSIG(etat)}" if os.WIFSIGNALED(etat) else f"code{os.WEXITSTATUS(etat)}"
    print(f"fin {time.time() - (envoye or debut):.1f} {quoi}")
sys.stdout.write(sortie.decode("utf-8", "replace"))
FIN

# Un groupe de processus à part, comme une commande au premier plan d'un terminal : Ctrl-C (SIGINT) et sa fermeture
# (SIGHUP) atteignent tout le groupe. Les signaux rendus au défaut : les essais héritent de SIGINT et SIGQUIT ignorés,
# et python ignore SIGPIPE.
cat >"$BANC/groupe.py" <<'FIN'
import os, signal, sys
os.setpgid(0, 0)
for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGHUP, signal.SIGPIPE):
    signal.signal(s, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])
FIN

ESSAIS=0
ECHECS=0
voir() { # libellé commande… : la commande doit réussir ; code 1 sinon (pour montrer le détail)
  ESSAIS=$((ESSAIS + 1))
  if "${@:2}"; then
    echo "  ✔ $1"
    return 0
  fi
  ECHECS=$((ECHECS + 1))
  echo "  ✖ $1"
  return 1
}
dit() { grep -qF -- "$2" "$1" 2>/dev/null; } # fichier texte
pas_dit() { ! grep -qF -- "$2" "$1" 2>/dev/null; }
montrer() { sed 's/^/      | /' "$1"; } # le détail d'un essai raté

# --- Partie root (ventoy-racine.sh lue par source, disque simulé, fausse archive) -----------------------------------

partie_root() { # arguments de mettre_a_jour… : son code de sortie, sa sortie dans $BANC/sortie
  (
    source outils/ventoy-racine.sh
    VENTOY=9.9.9 VENTOY_SHA256=${ESSAI_SHA256:-$FAUSSE_SHA256}
    source "$BANC/simul-disque.sh"
    mettre_a_jour "$@"
  ) >"$BANC/sortie" 2>&1
}
ecrit() { dit "$BANC/disque/ecritures" "$1"; }
rien_ecrit() { [[ ! -s $BANC/disque/ecritures ]]; }

echo "Partie root de la mise à jour de Ventoy :"
cle_simulee 1.1.10
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé plus ancienne : Ventoy2Disk.sh -u, réponse « y », code 0" \
  eval '((code == 0)) && ecrit "Ventoy2Disk.sh -u /dev/sdz (y)" && ! ecrit sfdisk' || montrer "$BANC/sortie"

cle_simulee 9.9.9
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé déjà à la version épinglée : rien d'écrit, code 3" eval '((code == 3)) && rien_ecrit' ||
  montrer "$BANC/sortie"
cle_simulee 10.0.1
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé plus récente que l'épingle : jamais ramenée en arrière (code 3)" eval '((code == 3)) && rien_ecrit' ||
  montrer "$BANC/sortie"

cle_simulee 1.1.10
partie_root /dev/sdz SERIE-B 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "autre numéro de série que celui de la proposition : refus, rien d'écrit" \
  eval '((code == 1)) && rien_ecrit && dit "$BANC/sortie" "n'"'"'est plus la clé proposée"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_U=retire partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé retirée pendant Ventoy2Disk.sh -u : table GPT pas touchée, et c'est dit" \
  eval '((code == 1)) && ! ecrit sfdisk && pas_dit "$BANC/sortie" "changés par Ventoy" &&
    dit "$BANC/sortie" "retirée pendant la mise à jour"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_U=attributs partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "attributs changés par Ventoy : la lecture seule (GUID:60) remise" \
  eval '((code == 0)) && ecrit "sfdisk --no-reread --part-attrs /dev/sdz 1 GUID:60"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_SHA256=0000000000000000000000000000000000000000000000000000000000000000 partie_root /dev/sdz SERIE-A 31037849600 \
  "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "archive autre que celle épinglée : refus avant Ventoy" eval '((code == 1)) && rien_ecrit' ||
  montrer "$BANC/sortie"

cle_simulee ""
partie_root /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "version de la clé illisible : refus" eval '((code == 1)) && rien_ecrit' || montrer "$BANC/sortie"

cle_simulee 1.1.10
: >"$BANC/disque/serie"
partie_root /dev/sdz "" 31037849600 "$BANC/ventoy-9.9.9.tar.gz"
code=$?
voir "clé sans numéro de série : refus" eval '((code == 1)) && rien_ecrit' || montrer "$BANC/sortie"

# Ctrl-C (SIGINT au groupe du terminal), sa fermeture (SIGHUP) ou un SIGTERM pendant Ventoy2Disk.sh -u : l'écriture va
# au bout, et la lecture seule est remise. Le compte est simulé comme cle-secours.sh lance la partie root (sa sortie
# lue par tee, que le même Ctrl-C tue), dans un groupe à part (groupe.py) ; une fin de session (systemd) envoie aussi
# SIGTERM et SIGHUP à tous les processus de Ventoy. Ses programmes héritent de l'ignorance : le masque de l'un d'eux
# le dit.
attendre() { # condition, évaluée : vraie dans les 10 s ?
  local i
  for ((i = 0; i < 100; i++)); do
    eval "$1" && return 0
    sleep 0.1
  done
  return 1
}
ignores() { # masque SigIgn (hexadécimal), signaux… : tous ignorés ?
  local m=$((16#${1:-0})) s
  for s in "${@:2}"; do (((m >> ($(kill -l "$s") - 1)) & 1)) || return 1; done
}
cle_simulee 1.1.10
rm -f "$BANC/disque/"{en-cours,signaux,fin-u,masque-u} "$BANC/journal-u"
ESSAI_U=lent python3 -I "$BANC/groupe.py" bash -c '{ source outils/ventoy-racine.sh; VENTOY=9.9.9 VENTOY_SHA256=$1
    source "$BANC/simul-disque.sh"; mettre_a_jour /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz"; } 2>&1 |
  tee -a "$BANC/journal-u"' essai "$FAUSSE_SHA256" >"$BANC/sortie" 2>&1 &
groupe=$!
attendre '[[ -s $BANC/disque/en-cours ]]'
ventoy=$(cat "$BANC/disque/en-cours" 2>/dev/null)
for s in INT TERM HUP; do kill -s "$s" -- "-$groupe" 2>/dev/null; done
if [[ $ventoy =~ ^[1-9][0-9]*$ ]]; then for s in TERM HUP; do kill -s "$s" -- "-$ventoy" 2>/dev/null; done; fi
: >"$BANC/disque/signaux"
wait "$groupe" 2>/dev/null
attendre '! kill -0 -- "-$groupe" 2>/dev/null' && attendre '[[ -e $BANC/disque/fin-u ]]'
voir "Ctrl-C, SIGTERM ou SIGHUP pendant Ventoy2Disk.sh -u : écrit jusqu'au bout, la lecture seule remise" \
  eval 'ecrit "Ventoy2Disk.sh -u /dev/sdz (y)" && ecrit "démarrage écrit" && ecrit "VTOYEFI écrite" &&
    [[ $(cat "$BANC/disque/ventoy") == 9.9.9 && $(cat "$BANC/disque/attributs") == GUID:60 ]] &&
    ecrit "sfdisk --no-reread --part-attrs /dev/sdz 1 GUID:60" && pas_dit "$BANC/journal-u" "esp partition"' ||
  { montrer "$BANC/disque/ecritures"; montrer "$BANC/journal-u"; montrer "$BANC/sortie"; }
voir "les programmes de Ventoy héritent de SIGINT, SIGQUIT, SIGTERM, SIGHUP et SIGPIPE ignorés" \
  ignores "$(cut -f2 "$BANC/disque/masque-u" 2>/dev/null)" INT QUIT TERM HUP PIPE ||
  echo "      | masque : $(cat "$BANC/disque/masque-u" 2>/dev/null)"

# Ignorés pendant l'écriture seulement : après, Ctrl-C arrête de nouveau la partie root.
cle_simulee 1.1.10
python3 -I "$BANC/groupe.py" bash -c 'source outils/ventoy-racine.sh; VENTOY=9.9.9 VENTOY_SHA256=$1
  source "$BANC/simul-disque.sh"; avant=$(trap -p INT QUIT TERM HUP PIPE)
  mettre_a_jour /dev/sdz SERIE-A 31037849600 "$BANC/ventoy-9.9.9.tar.gz" >/dev/null 2>&1
  apres=$(trap -p INT QUIT TERM HUP PIPE); echo "avant [$avant], après [$apres]"; [[ $apres == "$avant" ]]' \
  essai "$FAUSSE_SHA256" >"$BANC/sortie" 2>&1
code=$?
voir "signaux rendus après Ventoy2Disk.sh -u (ignorés pendant l'écriture seulement)" \
  eval '((code == 0)) && ecrit "Ventoy2Disk.sh -u /dev/sdz (y)"' || montrer "$BANC/sortie"

# --- Proposition et mise à jour, côté compte (cle-secours.sh lue par source) ----------------------------------------

compte() { # commande… dans cle-secours.sh, la fausse clé /dev/sdz branchée : sortie dans $BANC/sortie
  (
    source outils/cle-secours.sh
    source "$BANC/simul-disque.sh"
    point_cle() { echo "$BANC/point"; }
    disque_de() { echo /dev/sdz; }
    archive_ventoy() { echo "$BANC/ventoy-9.9.9.tar.gz"; }
    "$@"
  ) >"$BANC/sortie" 2>&1
}
export VANGUARD_VTOYEFI=$BANC/vtoyefi
RACINE=$VANGUARD_RACINE

echo "Proposition de Ventoy et --ventoy-maj :"
cle_simulee 1.1.10
ESSAI_CLIC=default ESSAI_PKEXEC=reussi ESSAI_VERSION=$EPINGLE compte verifier_ventoy "$BANC/point"
voir "notification à cliquer : action « default », urgence critique (le serveur d'Omarchy n'a pas de bouton)" \
  dit "$BANC/notifications.log" "|-u|critical|-p|-A|default=Mettre à jour|" || montrer "$BANC/notifications.log"
voir "un clic : la partie root installée lancée par pkexec, sur la clé de la proposition" \
  dit "$BANC/pkexec.log" "$RACINE /dev/sdz SERIE-A 31037849600 $BANC/ventoy-9.9.9.tar.gz" || montrer "$BANC/sortie"
voir "puis la version relue sur la clé, et dite" dit "$BANC/sortie" "✔ Ventoy $EPINGLE sur la clé" ||
  montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_CLIC=default ESSAI_SERIE_APRES_CLIC=SERIE-B compte verifier_ventoy "$BANC/point"
voir "une autre clé a pris son nom pendant la proposition : rien n'est lancé, et c'est dit" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/notifications.log" "Ventoy pas mis à jour"' || montrer "$BANC/sortie"

cle_simulee 1.1.99
compte ventoy_maj
voir "--ventoy-maj sur une clé plus récente que l'épingle : rien à faire, pas de mot de passe demandé" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/sortie" "déjà sur la clé"' || montrer "$BANC/sortie"

# La partition de démarrage jugée par ses fichiers, pas par sa version : réécrite en voyage à version égale, vue.
cle_simulee 1.1.99
compte verifier_ventoy "$BANC/point"
voir "VTOYEFI : première relève prise pour référence, et dit" \
  eval 'dit "$BANC/sortie" "première relève ici" && [[ -s $BANC/etat/vanguard/vtoyefi/SERIE-A ]]' ||
  montrer "$BANC/sortie"
compte verifier_ventoy "$BANC/point"
voir "VTOYEFI inchangée : identique à sa référence" dit "$BANC/sortie" "identique à sa référence" ||
  montrer "$BANC/sortie"
echo piege >"$BANC/vtoyefi/grub/grubx64.efi"
compte verifier_ventoy "$BANC/point"
code=$?
voir "VTOYEFI changée à version égale : alerte, code 1, la référence reste" \
  eval '((code == 1)) && dit "$BANC/notifications.log" "démarrage (VTOYEFI) modifié" &&
    dit "$BANC/sortie" "--accepter-vtoyefi"' || montrer "$BANC/sortie"
compte accepter_vtoyefi
compte verifier_ventoy "$BANC/point"
voir "--accepter-vtoyefi : la partition telle qu'elle est devient la référence" \
  dit "$BANC/sortie" "identique à sa référence" || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_CLIC=default VANGUARD_RACINE=$BANC/absente/ventoy-racine compte verifier_ventoy "$BANC/point"
voir "partie root pas installée : rien de proposé, la notification dit comment l'installer" \
  eval '[[ ! -s $BANC/pkexec.log ]] && pas_dit "$BANC/notifications.log" "|-A|" &&
    dit "$BANC/notifications.log" "--installer-racine"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
cp outils/ventoy-racine.sh "$BANC/autre-racine"
echo "# modifiée" >>"$BANC/autre-racine"
VANGUARD_RACINE=$BANC/autre-racine compte ventoy_maj
voir "partie root installée différente de celle du dépôt : refus" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/sortie" "pas celle du dépôt"' || montrer "$BANC/sortie"
cle_simulee 1.1.10
cp outils/ventoy-racine.sh "$BANC/autre-racine"
chmod 0777 "$BANC/autre-racine"
VANGUARD_RACINE=$BANC/autre-racine compte ventoy_maj
voir "partie root modifiable par d'autres que root : refus" \
  eval '[[ ! -s $BANC/pkexec.log ]] && dit "$BANC/sortie" "d'"'"'autres que root"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
( unset VANGUARD_ESSAI; compte ventoy_maj )
voir "VANGUARD_RACINE hors des essais (sans VANGUARD_ESSAI) : ignorée, et dit ; pkexec ne la lance pas" \
  eval 'dit "$BANC/sortie" "VANGUARD_RACINE ignorée hors des essais" && pas_dit "$BANC/pkexec.log" "$RACINE" &&
    dit "$BANC/sortie" "/usr/local/libexec/vanguard/ventoy-racine"' || montrer "$BANC/sortie"

cle_simulee 1.1.10
ESSAI_PKEXEC=lance VANGUARD_RACINE=$BANC/libexec2/vanguard/ventoy-racine compte installer_racine
voir "--installer-racine : une copie du dépôt installée en fichier de root par install, identique, 755, puis retirée" \
  eval 'dit "$BANC/pkexec.log" "/usr/bin/install -D -o root -g root -m 0755 $TMPDIR/ventoy-racine." &&
    dit "$BANC/pkexec.log" " $BANC/libexec2/vanguard/ventoy-racine" &&
    cmp -s outils/ventoy-racine.sh "$BANC/libexec2/vanguard/ventoy-racine" &&
    [[ $(stat -c %a "$BANC/libexec2/vanguard/ventoy-racine") == 755 ]] &&
    ! compgen -G "$TMPDIR/ventoy-racine.*" >/dev/null' || montrer "$BANC/sortie"

# Un programme du compte change un fichier pendant la fenêtre du mot de passe : le dépôt (le diff montré venait de sa
# copie), ou la copie elle-même (ce que root a installé est vérifié par son empreinte). Dans un faux dépôt, pour ne
# jamais toucher au vrai ; une partie root plus ancienne déjà installée, pour que le diff se montre.
F=$BANC/depot-racine
racine_piegee() { # ESSAI_PIEGE : sortie dans $BANC/sortie, code de sortie de --installer-racine
  rm -rf "$F" "$BANC/libexec3"
  mkdir -p "$F/outils"
  cp outils/cle-secours.sh outils/ventoy-racine.sh outils/images-cle.sh "$F/outils/"
  install -D -m 0755 outils/ventoy-racine.sh "$BANC/libexec3/vanguard/ventoy-racine"
  sed -i 's/^VENTOY=.*/VENTOY=1.1.10/' "$BANC/libexec3/vanguard/ventoy-racine"
  rm -f "$BANC/pkexec.log"
  ESSAI_PKEXEC=lance ESSAI_PIEGE=$1 VANGUARD_RACINE=$BANC/libexec3/vanguard/ventoy-racine \
    bash "$F/outils/cle-secours.sh" --installer-racine >"$BANC/sortie" 2>&1
}
racine_piegee "$F/outils/ventoy-racine.sh"
code=$?
voir "--installer-racine, le dépôt changé pendant le mot de passe : root a la copie montrée, et le refus est dit" \
  eval '((code == 1)) && cmp -s outils/ventoy-racine.sh "$BANC/libexec3/vanguard/ventoy-racine" &&
    dit "$BANC/sortie" "+VENTOY=$EPINGLE" && dit "$BANC/sortie" "pas celle du dépôt" &&
    ! compgen -G "$TMPDIR/ventoy-racine.*" >/dev/null' || montrer "$BANC/sortie"
racine_piegee source
code=$?
voir "--installer-racine, la copie changée pendant le mot de passe : vue à son empreinte, et dite" \
  eval '((code == 1)) && dit "$BANC/sortie" "n'"'"'est pas la copie montrée" &&
    ! compgen -G "$TMPDIR/ventoy-racine.*" >/dev/null' || montrer "$BANC/sortie"

echo "Notification à cliquer (proposer) :"
cle_simulee 1.1.10
debut=$SECONDS
ESSAI_CLIC=attend compte proposer 1 "Titre" "Texte" "Sans réponse à temps" "Mettre à jour"
voir "pas de réponse dans le délai : rien de choisi, la notification remplacée par une ordinaire qui le dit" \
  eval '[[ ! -s $BANC/sortie ]] && ((SECONDS - debut < 10)) &&
    dit "$BANC/notifications.log" "|-r|1|--|Titre|Sans réponse à temps|" &&
    [[ $(grep -c "|-A|" "$BANC/notifications.log") == 1 ]]' || montrer "$BANC/notifications.log"
cle_simulee 1.1.10
ESSAI_CLIC=ferme compte proposer 5 "Titre" "Texte" "Sans réponse" "Mettre à jour"
voir "fermée sans clic : rien de choisi, rien de remplacé" \
  eval '[[ ! -s $BANC/sortie && $(wc -l <"$BANC/notifications.log") == 1 ]]' || montrer "$BANC/notifications.log"

echo "Ctrl-C (lancé à la main, dans un terminal) :"
cle_simulee 1.1.10
python3 -I "$BANC/pty.py" 1.5 10 env ESSAI_CLIC=attend bash -c 'source outils/cle-secours.sh
  source "$BANC/simul-disque.sh"; disque_de() { echo /dev/sdz; }
  archive_ventoy() { echo "$BANC/ventoy-9.9.9.tar.gz"; }
  verifier_ventoy "$BANC/point"; echo APRÈS' "$DEPOT/outils/essais-cle.sh" >"$BANC/sortie" 2>&1
voir "pendant la proposition de Ventoy : arrêt aussitôt, rien d'autre de lancé" \
  eval 'grep -qE "^fin [0-9]\.[0-9] signal2$" "$BANC/sortie" && pas_dit "$BANC/sortie" APRÈS &&
    [[ ! -s $BANC/pkexec.log ]]' || montrer "$BANC/sortie"
mkdir -p "$BANC/pty"
echo lent >"$BANC/aria2/kali-linux-2026.3-live-everything-amd64.iso"
echo torrent >"$BANC/pty/kali-linux-2026.3-live-everything-amd64.iso.torrent"
python3 -I "$BANC/pty.py" 1.5 10 bash -c 'source outils/images-cle.sh; verifier_image() { return 0; }
  telecharger kali https://exemple.invalid/ kali-linux-2026.3-live-everything-amd64.iso "$BANC/pty" || true
  echo APRÈS' "$DEPOT/outils/essais-cle.sh" >"$BANC/sortie" 2>&1
voir "pendant le torrent de Kali : aria2c arrêté, le script aussi (pas de repli lancé)" \
  eval 'grep -qE "^fin [0-9]\.[0-9] signal2$" "$BANC/sortie" && pas_dit "$BANC/sortie" APRÈS' || montrer "$BANC/sortie"

# --- Images (images-cle.sh) ------------------------------------------------------------------------------------------

echo "Images de la clé :"
USER=bob bash outils/images-cle.sh --cle >"$BANC/sortie" 2>&1
code=$?
voir "sans /run/media/\$USER : « rien à copier », sans erreur" \
  eval '((code == 0)) && dit "$BANC/sortie" "non branchée : rien à copier"' || montrer "$BANC/sortie"
USER=bob bash outils/images-cle.sh --etat >"$BANC/sortie" 2>&1
code=$?
voir "--etat sans /run/media/\$USER : « pas branchée », sans erreur" \
  eval '((code == 0)) && dit "$BANC/sortie" "pas branchée"' || montrer "$BANC/sortie"

sortes() { bash outils/images-cle.sh --sortes 2>"$BANC/sortie-erreurs"; }
# La clé par défaut, sans réglage local : le programme seul. Aucune image cherchée, copiée, importée ni proposée, ni
# menu de Ventoy ; les commandes qui en poseraient refusent en disant comment allumer la clé de secours, et celles des
# services (--chercher, --cle, --a-jour) ne font rien, sans erreur.
rm -f "$REGLAGE"
mkdir -p "$BANC/cache0" "$BANC/cle0/ISO"
IMAGE0=$BANC/cache0/systemrescue-12.03-amd64.iso
echo sr >"$IMAGE0"
sha256sum "$IMAGE0" | cut -d' ' -f1 >"$IMAGE0.sha256"
echo ancienne >"$BANC/cle0/ISO/systemrescue-12.02-amd64.iso"
: >"$BANC/cle0/vanguard.cle"
rm -f "$BANC/aria2c.log" "$BANC/notifications.log" "$BANC/pkexec.log"
images0() { VANGUARD_IMAGES=$BANC/cache0 bash outils/images-cle.sh "$@" >>"$BANC/sortie0" 2>&1; }
: >"$BANC/sortie0"
voir "sans réglage : aucune sorte d'image tenue, « --secours » dit non" \
  eval '[[ -z $(sortes) && $(bash outils/images-cle.sh --secours) == non ]] && ! bash outils/images-cle.sh --secours >/dev/null' ||
  montrer "$BANC/sortie-erreurs"
(
  source outils/images-cle.sh
  for s in arch debian fedora systemrescue omarchy kali; do eval "derniere_$s() { echo appel >>\"$BANC/derniere0\"; }"; done
  lire() { echo "faux $1"; }
  VANGUARD_IMAGES=$BANC/cache0 CACHE=$BANC/cache0 chercher
) >>"$BANC/sortie0" 2>&1
c1=$?
images0 --cle "$BANC/cle0"
c2=$?
images0 --toutes "$BANC/cle0"
c3=$?
VANGUARD_IMAGES=$BANC/cache0 bash outils/images-cle.sh --importer "$IMAGE0" >"$BANC/sortie0-import" 2>&1
c4=$?
images0 --menu "$BANC/cle0"
c5=$?
VANGUARD_IMAGES=$BANC/cache0 bash outils/images-cle.sh --verifier >"$BANC/sortie0-verifier" 2>&1
c6=$?
voir "sans réglage : rien cherché ni copié ni importé, ni menu de Ventoy (0 pour les services, 1 à la main)" \
  eval '((c1 == 0 && c2 == 0 && c3 == 1 && c4 == 1 && c5 == 1 && c6 == 0)) && [[ ! -e $BANC/derniere0 ]] &&
    [[ ! -s $BANC/aria2c.log && ! -e $BANC/cle0/ISO/${IMAGE0##*/} && ! -e $BANC/cle0/ventoy ]] &&
    [[ -f $BANC/cle0/ISO/systemrescue-12.02-amd64.iso && ! -s $BANC/notifications.log ]] &&
    dit "$BANC/sortie0" "pas demandée sur cet ordinateur : aucune image n'"'"'est cherchée" &&
    dit "$BANC/sortie0" "pas demandée sur cet ordinateur : aucune image n'"'"'est copiée" &&
    dit "$BANC/sortie0" "pas demandée sur cet ordinateur : le menu de Ventoy n'"'"'est pas écrit" &&
    dit "$BANC/sortie0-import" "pas demandée sur cet ordinateur : rien n'"'"'est importé." &&
    dit "$BANC/sortie0-verifier" "pas demandée sur cet ordinateur : aucune image à vérifier." &&
    dit "$BANC/sortie0" "CLE_SECOURS=oui dans"' ||
  { echo "      codes $c1 $c2 $c3 $c4 $c5 $c6"; montrer "$BANC/sortie0"; montrer "$BANC/sortie0-import"
    montrer "$BANC/sortie0-verifier"; }
: >"$BANC/sortie0"
for c in "--plan /dev/sdz" "--telecharger $BANC/dossier0" "--ecrire /dev/sdz $BANC/dossier0" \
  "--windows /dev/sdz $BANC/dossier0" "--verifier $BANC/dossier0" --essai --ventoy-maj --installer-racine; do
  # shellcheck disable=SC2086 # la commande et ses arguments, voulus en mots
  bash outils/cle-secours.sh $c >>"$BANC/sortie0" 2>&1 && echo "ACCEPTÉE : $c" >>"$BANC/sortie0"
done
bash outils/cle-secours.sh --a-jour "$BANC/cle0" >>"$BANC/sortie0" 2>&1
c1=$?
voir "sans réglage : cle-secours.sh refuse tout (images, Ventoy, WIN11, MACOS) et le dit ; --a-jour ne fait rien" \
  eval '((c1 == 0)) && pas_dit "$BANC/sortie0" ACCEPTÉE &&
    [[ $(grep -c "clé de secours pas demandée sur cet ordinateur : rien n" "$BANC/sortie0") == 8 ]] &&
    dit "$BANC/sortie0" "ni Ventoy ni Windows 11 à tenir à jour" && [[ ! -e $BANC/dossier0 ]] &&
    [[ ! -s $BANC/pkexec.log && ! -s $BANC/notifications.log ]]' || montrer "$BANC/sortie0"
# images-cle.sh en panne (ni « oui » ni « non ») : pas pris pour un réglage qui dit non.
P=$BANC/depot-panne
mkdir -p "$P/outils"
cp outils/cle-secours.sh outils/ventoy-racine.sh "$P/outils/"
printf '#!/bin/sh\nexit 2\n' >"$P/outils/images-cle.sh"
chmod +x "$P/outils/images-cle.sh"
bash "$P/outils/cle-secours.sh" --a-jour "$BANC/cle0" >"$BANC/sortie0" 2>&1
c1=$?
voir "images-cle.sh en panne : --a-jour le dit, code 1 (pas « pas demandée »)" \
  eval '((c1 == 1)) && dit "$BANC/sortie0" "ne répond pas" && pas_dit "$BANC/sortie0" "pas demandée"' ||
  montrer "$BANC/sortie0"
printf 'CLE_SECOURS=oui\r\nIMAGES="arch debian"\r\nIMAGES_EN_PLUS="kali"\r\n' >"$REGLAGE"
voir "réglage aux fins de ligne de Windows : lu comme les autres" \
  eval '[[ $(sortes) == "arch debian kali" && ! -s $BANC/sortie-erreurs ]]' || montrer "$BANC/sortie-erreurs"
reglage 'IMAGES="arch debian"' 'IMAGES_EN_PLUS="kali"'
voir "des images demandées sans CLE_SECOURS=oui : ignorées, et dit" \
  eval '[[ -z $(sortes) ]] && dit "$BANC/sortie-erreurs" "sans CLE_SECOURS=oui, ignorées"' ||
  montrer "$BANC/sortie-erreurs"
reglage CLE_SECOURS=non 'IMAGES="arch"'
voir "CLE_SECOURS autre que « oui » : clé de secours éteinte" eval '[[ -z $(sortes) ]]' || montrer "$BANC/sortie-erreurs"
reglage CLE_SECOURS=oui 'IMAGES="fedora, arch"'
voir "CLE_SECOURS=oui et IMAGES : seulement celles-là, dans l'ordre de copie (la plus utile d'abord)" \
  eval '[[ $(sortes) == "arch fedora" && ! -s $BANC/sortie-erreurs ]]' || montrer "$BANC/sortie-erreurs"
reglage CLE_SECOURS=oui 'IMAGES=""'
voir "CLE_SECOURS=oui et IMAGES vide : aucune image Linux, la clé de secours quand même" \
  eval '[[ -z $(sortes) && $(bash outils/images-cle.sh --secours) == oui ]]' || montrer "$BANC/sortie-erreurs"
reglage CLE_SECOURS=oui 'IMAGES="arch *"'
voir "un « * » dans IMAGES : un mot inconnu, pas les fichiers du dossier" \
  eval '[[ $(sortes) == arch ]] && dit "$BANC/sortie-erreurs" "« * »"' || montrer "$BANC/sortie-erreurs"

# Kali Linux, coupée par défaut sur une clé de secours : seul le réglage local de l'ordinateur l'allume, lu sans être
# exécuté.
reglage CLE_SECOURS=oui
voir "clé de secours, Kali coupée par défaut : ni cherchée, ni copiée, ni proposée" \
  eval '[[ $(sortes) == "systemrescue arch omarchy debian fedora" ]]' || montrer "$BANC/sortie-erreurs"
mkdir -p "$BANC/cache8" "$BANC/cle8/ISO" "$BANC/cle8/ventoy"
IMAGE8=$BANC/cache8/kali-linux-2026.3-live-everything-amd64.iso
echo kali >"$IMAGE8"
sha256sum "$IMAGE8" | cut -d' ' -f1 >"$IMAGE8.sha256"
echo ancienne >"$BANC/cle8/ISO/kali-linux-2026.2-live-everything-amd64.iso"
rm -f "$BANC/aria2c.log" "$BANC/notifications.log"
chercher8() { # tout est « nouveau » : derniere_* répond pour chaque sorte, rien ne se télécharge
  (
    source outils/images-cle.sh
    for s in arch debian fedora systemrescue omarchy; do eval "derniere_$s() { return 1; }"; done
    derniere_kali() { echo "kali-linux-2026.4-live-everything-amd64.iso https://exemple.invalid/kali-2026.4/"; }
    lire() { echo "faux $1"; }
    verifier_image() { return 0; }
    chercher
  ) >"$BANC/sortie" 2>&1
}
VANGUARD_IMAGES=$BANC/cache8 chercher8
VANGUARD_IMAGES=$BANC/cache8 bash outils/images-cle.sh --cle "$BANC/cle8" >>"$BANC/sortie" 2>&1
VANGUARD_IMAGES=$BANC/cache8 bash outils/images-cle.sh --importer "$IMAGE8" >"$BANC/sortie-import" 2>&1
code=$?
( source outils/cle-secours.sh; IMAGES_LINUX=$BANC/cache8 place_vanguard 30000 7534 ) >"$BANC/sortie-place" 2>&1
voir "Kali coupée : aucun torrent, la Kali du cache pas copiée sur la clé, une image de Kali pas importée" \
  eval '[[ ! -s $BANC/aria2c.log ]] && ! compgen -G "$BANC/cache8/.nouveau-kali-*" >/dev/null &&
    [[ ! -e $BANC/cle8/ISO/${IMAGE8##*/} && -f $BANC/cle8/ISO/kali-linux-2026.2-live-everything-amd64.iso ]] &&
    ((code == 1)) && dit "$BANC/sortie-import" "pas une image que la clé tient sur cet ordinateur"' ||
  { montrer "$BANC/sortie"; montrer "$BANC/sortie-import"; }
voir "Kali coupée : le plan de la clé ne la compte pas" \
  eval 'pas_dit "$BANC/sortie-place" Kali && dit "$BANC/sortie-place" "Windows 11 aussi"' ||
  montrer "$BANC/sortie-place"
voir "Kali coupée : le menu de Ventoy garde son nom si l'image est déjà sur la clé" \
  dit "$BANC/cle8/ventoy/ventoy.json" '"alias": "Kali Linux' || montrer "$BANC/cle8/ventoy/ventoy.json"

# Le réglage : une ligne, des guillemets ou non, un commentaire ; jamais exécuté (une commande dedans ne part pas).
printf 'CLE_SECOURS="oui"\n# images en plus\nIMAGES_EN_PLUS="kali" # pour moi\n$(touch %s/execute)\n' "$BANC" >"$REGLAGE"
voir "réglage IMAGES_EN_PLUS=\"kali\" : Kali allumée, en dernier ; le fichier lu sans être exécuté" \
  eval '[[ $(sortes) == "systemrescue arch omarchy debian fedora kali" && ! -e $BANC/execute ]]' ||
  montrer "$BANC/sortie-erreurs"
reglage CLE_SECOURS=oui "IMAGES_EN_PLUS='kali,windows'"
voir "réglage avec une image inconnue : ignorée et dite, Kali allumée quand même" \
  eval '[[ $(sortes) == "systemrescue arch omarchy debian fedora kali" ]] &&
    dit "$BANC/sortie-erreurs" "« windows »"' ||
  montrer "$BANC/sortie-erreurs"
reglage CLE_SECOURS=oui 'IMAGES_EN_PLUS="kali,kali"'
voir "réglage avec Kali en double : comptée une fois, sans message" \
  eval '[[ $(sortes) == "systemrescue arch omarchy debian fedora kali" && ! -s $BANC/sortie-erreurs ]]' ||
  montrer "$BANC/sortie-erreurs"
rm -f "$BANC/aria2c.log"
VANGUARD_IMAGES=$BANC/cache8 chercher8
VANGUARD_IMAGES=$BANC/cache8 bash outils/images-cle.sh --cle "$BANC/cle8" >>"$BANC/sortie" 2>&1
voir "Kali allumée : son torrent lancé, la Kali du cache copiée sur la clé à la place de l'ancienne" \
  eval 'dit "$BANC/aria2c.log" "kali-linux-2026.4-live-everything-amd64.iso" &&
    cmp -s "$BANC/cle8/ISO/${IMAGE8##*/}" "$IMAGE8" &&
    [[ ! -e $BANC/cle8/ISO/kali-linux-2026.2-live-everything-amd64.iso ]]' || montrer "$BANC/sortie"
( source outils/cle-secours.sh; IMAGES_LINUX=$BANC/cache8 place_vanguard 30000 7534 ) >"$BANC/sortie-place" 2>&1
voir "Kali allumée : le plan de la clé la compte" dit "$BANC/sortie-place" "Kali Linux aussi" ||
  montrer "$BANC/sortie-place"

# Le cache, lien vers un autre disque débranché : jamais recréé, ni à sa place ni au bout du lien.
reglage CLE_SECOURS=oui
mkdir -p "$BANC/cle9/ISO"
ln -s "$BANC/disque2/vanguard-images" "$BANC/lien-images"
ln -s "$BANC/disque2/cle-secours" "$BANC/lien-secours"
rm -f "$BANC/notifications.log"
images9() { VANGUARD_IMAGES=$BANC/lien-images bash outils/images-cle.sh "$@" >>"$BANC/sortie9" 2>&1; }
: >"$BANC/sortie9"
images9 --chercher
c1=$?
images9 --cle "$BANC/cle9"
c2=$?
images9 --toutes "$BANC/cle9"
c3=$?
images9 --verifier
c4=$?
images9 --importer "$IMAGE8"
c5=$?
VANGUARD_IMAGES=$BANC/lien-images/sous bash outils/images-cle.sh --chercher >>"$BANC/sortie9" 2>&1
c6=$?
VANGUARD_IMAGES=$BANC/lien-images bash outils/cle-secours.sh --telecharger "$BANC/lien-secours" >>"$BANC/sortie9" 2>&1
c7=$?
voir "cache sur un disque débranché : arrêt propre (0 tout seul, 1 demandé à la main), une seule notification" \
  eval '((c1 == 0 && c2 == 0 && c3 == 1 && c4 == 1 && c5 == 1 && c6 == 0 && c7 == 1)) &&
    [[ $(grep -c "Images de la clé : cache absent" "$BANC/notifications.log") == 1 ]] &&
    dit "$BANC/sortie9" "dossier des images introuvable : $BANC/lien-secours mène à"' ||
  { echo "      codes $c1 $c2 $c3 $c4 $c5 $c6 $c7"; montrer "$BANC/sortie9"; }
voir "cache sur un disque débranché : aucun dossier recréé, ni au bout du lien, ni à sa place" \
  eval '[[ -L $BANC/lien-images && -L $BANC/lien-secours && ! -e $BANC/disque2 ]] &&
    [[ -z $(ls -A "$BANC/cle9/ISO") ]] && ! compgen -G "$BANC/xdg-cache/vanguard/images-cle*" >/dev/null' ||
  { ls -la "$BANC" "$BANC/cle9/ISO"; }
# Le disque revenu, puis reparti : la nouvelle absence se redit aussitôt.
mkdir -p "$BANC/disque2/vanguard-images"
images9 --cle "$BANC/cle9"
rm -rf "$BANC/disque2"
images9 --cle "$BANC/cle9"
voir "cache revenu puis reparti : la nouvelle absence se redit" \
  eval '[[ $(grep -c "Images de la clé : cache absent" "$BANC/notifications.log") == 2 ]]' ||
  montrer "$BANC/notifications.log"

# Une recherche sans rien de neuf, et le début d'un téléchargement : chacun sa notification.
mkdir -p "$BANC/cache10"
echo arch >"$BANC/cache10/archlinux-2026.11.01-x86_64.iso"
echo x >"$BANC/cache10/archlinux-2026.11.01-x86_64.iso.sha256"
rm -f "$BANC/notifications.log"
chercher10() { # date de la dernière Arch
  local date=$1
  (
    source outils/images-cle.sh
    for s in debian fedora systemrescue omarchy; do eval "derniere_$s() { return 1; }"; done
    derniere_arch() { echo "archlinux-$date-x86_64.iso https://exemple.invalid/arch/"; }
    lire() { echo "faux $1"; }
    curl() { # les en-têtes : une redirection, puis la taille (1,5 Gio) ; le téléchargement, lui, échoue
      if [[ $* == *-fsSIL* ]]; then
        printf 'HTTP/2 302\r\ncontent-length: 0\r\n\r\nHTTP/2 200\r\nContent-Length: 1610612736\r\n\r\n'
      else
        return 22
      fi
    }
    chercher
  ) >"$BANC/sortie" 2>&1
}
VANGUARD_IMAGES=$BANC/cache10 chercher10 2026.11.01
voir "recherche sans rien de neuf : « rien de nouveau », ce qui est à jour et ce qui n'a pas répondu" \
  eval 'dit "$BANC/notifications.log" "|Images de la clé : rien de nouveau|Déjà à jour : Arch Linux." &&
    dit "$BANC/notifications.log" "Pas jointes (pas d'"'"'Internet, ou site changé) : SystemRescue, Omarchy,"' ||
  { montrer "$BANC/notifications.log"; montrer "$BANC/sortie"; }
rm -f "$BANC/notifications.log"
VANGUARD_IMAGES=$BANC/cache10 chercher10 2026.12.01
voir "début d'un téléchargement : son nom et sa taille, avant curl ; « rien de nouveau » pas dit" \
  eval 'dit "$BANC/notifications.log" \
    "|Images de la clé : téléchargement|Arch Linux : archlinux-2026.12.01-x86_64.iso, 1,5 Gio.|" &&
    pas_dit "$BANC/notifications.log" "rien de nouveau"' ||
  { montrer "$BANC/notifications.log"; montrer "$BANC/sortie"; }
mkdir -p "$BANC/kali10"
printf 'd8:announce0:4:infod6:lengthi16852080640e4:name42:kali-linux-2026.4-live-everything-amd64.isoee' \
  >"$BANC/kali10/kali-linux-2026.4-live-everything-amd64.iso.torrent"
echo morceau >"$BANC/kali10/kali-linux-2026.4-live-everything-amd64.iso"
rm -f "$BANC/notifications.log"
( source outils/images-cle.sh; verifier_image() { return 0; }
  telecharger kali https://exemple.invalid/ kali-linux-2026.4-live-everything-amd64.iso "$BANC/kali10" ) \
  >"$BANC/sortie" 2>&1
voir "début d'un torrent de Kali : sa taille lue dans le .torrent, et « reprise » s'il était commencé" \
  dit "$BANC/notifications.log" \
  "|Images de la clé : reprise du téléchargement|Kali Linux : kali-linux-2026.4-live-everything-amd64.iso, 15,7 Gio (" ||
  { montrer "$BANC/notifications.log"; montrer "$BANC/sortie"; }

# Les essais de Kali qui suivent : allumée par le réglage.
reglage CLE_SECOURS=oui 'IMAGES_EN_PLUS="kali"'

# Une fausse Kali de 8 Mio : avec les 512 Mio gardés, la nouvelle (520 Mio) ne tient sur la clé de 524 Mio que si
# l'ancienne part d'abord, comme la vraie Kali sur la vraie clé.
mkdir -p "$BANC/cache5" "$BANC/cle5"
/usr/bin/mount -t tmpfs -o size=524M tmpfs "$BANC/cle5"
mkdir -p "$BANC/cle5/ISO"
IMAGE5=$BANC/cache5/kali-linux-2026.3-live-everything-amd64.iso
head -c $((8 * 1024 * 1024)) /dev/urandom >"$IMAGE5"
sha256sum "$IMAGE5" | cut -d' ' -f1 >"$IMAGE5.sha256"
NEUVE=$BANC/cle5/ISO/kali-linux-2026.3-live-everything-amd64.iso
PART=$BANC/cle5/ISO/.kali-linux-2026.3-live-everything-amd64.iso.part
copier() { VANGUARD_IMAGES=$BANC/cache5 bash outils/images-cle.sh --cle "$BANC/cle5" >"$BANC/sortie" 2>&1; }
head -c 100000 /dev/urandom >"$PART"
copier
code=$?
voir "copie de Kali interrompue (clé retirée), plus aucune Kali sur la clé : refaite au passage suivant" \
  eval '((code == 0)) && cmp -s "$NEUVE" "$IMAGE5" && [[ ! -e $PART ]]' || montrer "$BANC/sortie"
rm -f "$NEUVE"
head -c $((8 * 1024 * 1024)) /dev/urandom >"$BANC/cle5/ISO/kali-linux-2026.2-live-everything-amd64.iso"
rm -f "$BANC/notifications.log"
ESSAI_SYNC=echec copier
code=$?
voir "copie ratée après le retrait de l'ancienne (faute de place) : sa trace reste, vide" \
  eval '((code == 1)) && [[ -f $PART && ! -s $PART ]] && ! compgen -G "$BANC/cle5/ISO/kali-*.iso" >/dev/null &&
    dit "$BANC/notifications.log" "copie ratée"' || montrer "$BANC/sortie"
copier
code=$?
voir "et la copie se refait au passage suivant" \
  eval '((code == 0)) && cmp -s "$NEUVE" "$IMAGE5"' || montrer "$BANC/sortie"
# La relecture d'une image (vanguard deploiement relire-image, faux ici) : une Kali remplacée par une autre de même
# taille, que la taille seule ne voyait pas, est recopiée ; son empreinte vérifiée part à la référence.
cat >"$BANC/faux-vanguard" <<'FIN'
#!/usr/bin/env bash
echo "$*" >>"$BANC/faux-vanguard.log"
if [[ "$1 $2" == "deploiement relire-image" && -n ${ESSAI_RELUE:-} ]]; then echo "ISO/$ESSAI_RELUE"; exit 2; fi
exit 0
FIN
chmod +x "$BANC/faux-vanguard"
SHA5=$(cat "$IMAGE5.sha256")
rm -f "$BANC/faux-vanguard.log" "$BANC/notifications.log"
VANGUARD_PROGRAMME=$BANC/faux-vanguard copier
code=$?
voir "image intacte relue : pas recopiée ; la relecture a l'empreinte vérifiée du cache" \
  eval '((code == 0)) && dit "$BANC/faux-vanguard.log" "deploiement relire-image $BANC/cle5 --empreinte ${IMAGE5##*/}=$SHA5" &&
    pas_dit "$BANC/notifications.log" "copie de"' || { montrer "$BANC/sortie"; montrer "$BANC/faux-vanguard.log"; }
head -c $((8 * 1024 * 1024)) /dev/urandom >"$NEUVE"
rm -f "$BANC/faux-vanguard.log" "$BANC/notifications.log"
ESSAI_RELUE=${IMAGE5##*/} VANGUARD_PROGRAMME=$BANC/faux-vanguard copier
code=$?
voir "image remplacée par une autre de même taille : dite, recopiée, son empreinte redite à la référence" \
  eval '((code == 0)) && cmp -s "$NEUVE" "$IMAGE5" && dit "$BANC/notifications.log" "image remplacée" &&
    dit "$BANC/faux-vanguard.log" "manifeste --images $BANC/cle5 --image ${IMAGE5##*/}=$SHA5"' ||
  { montrer "$BANC/sortie"; montrer "$BANC/faux-vanguard.log"; }
# La clé trouvée toute seule (branchement, chaque jour) et changée depuis sa référence : aucune image n'y est écrite.
cat >"$BANC/faux-vanguard-ecart" <<FIN
#!/usr/bin/env bash
case "\$1 \$2" in
  "deploiement cle") echo "$BANC/cle5" ;;
  "deploiement comparer-cle") exit 2 ;;
esac
exit 0
FIN
chmod +x "$BANC/faux-vanguard-ecart"
head -c $((8 * 1024 * 1024)) /dev/urandom >"$NEUVE"
cp "$NEUVE" "$BANC/neuve-avant"
ESSAI_RELUE=${IMAGE5##*/} VANGUARD_IMAGES=$BANC/cache5 VANGUARD_PROGRAMME=$BANC/faux-vanguard-ecart \
  bash outils/images-cle.sh --cle >"$BANC/sortie" 2>&1
voir "clé trouvée seule mais changée depuis sa référence : aucune image écrite, et dit" \
  eval 'cmp -s "$NEUVE" "$BANC/neuve-avant" && dit "$BANC/sortie" "aucune image copiée"' || montrer "$BANC/sortie"
/usr/bin/umount "$BANC/cle5"

# Kali cède sa place : une nouvelle SystemRescue (14 Mio) ne tient pas sur la clé de 530 Mio, même sans l'ancienne
# (1 Mio), à cause de la Kali (12 Mio) ; la Kali part, pas une image tenue par défaut.
mkdir -p "$BANC/cache11" "$BANC/cle11"
/usr/bin/mount -t tmpfs -o size=530M tmpfs "$BANC/cle11"
mkdir -p "$BANC/cle11/ISO"
SR11=$BANC/cache11/systemrescue-12.03-amd64.iso
KALI11=$BANC/cache11/kali-linux-2026.3-live-everything-amd64.iso
head -c $((14 * 1024 * 1024)) /dev/urandom >"$SR11"
head -c $((12 * 1024 * 1024)) /dev/urandom >"$KALI11"
for f in "$SR11" "$KALI11"; do sha256sum "$f" | cut -d' ' -f1 >"$f.sha256"; done
cle11() { # Kali sur la clé, une ancienne SystemRescue ; puis --cle
  rm -f "$BANC/cle11/ISO"/*.iso "$BANC/notifications.log"
  cp "$KALI11" "$BANC/cle11/ISO/"
  head -c $((1024 * 1024)) /dev/urandom >"$BANC/cle11/ISO/systemrescue-12.02-amd64.iso"
  VANGUARD_IMAGES=$BANC/cache11 bash outils/images-cle.sh --cle "$BANC/cle11" >"$BANC/sortie" 2>&1
}
cle11
code=$?
voir "Kali allumée : retirée de la clé pour une nouvelle SystemRescue qui n'y tenait pas, et dit" \
  eval '((code == 0)) && cmp -s "$BANC/cle11/ISO/${SR11##*/}" "$SR11" &&
    [[ ! -e $BANC/cle11/ISO/${KALI11##*/} && ! -e $BANC/cle11/ISO/systemrescue-12.02-amd64.iso ]] &&
    dit "$BANC/notifications.log" "|Clé VANGUARD : image en option retirée|${KALI11##*/}, pour SystemRescue" &&
    pas_dit "$BANC/notifications.log" "pas la place"' || { montrer "$BANC/sortie"; montrer "$BANC/notifications.log"; }
reglage CLE_SECOURS=oui
cle11
code=$?
reglage CLE_SECOURS=oui 'IMAGES_EN_PLUS="kali"'
voir "Kali coupée sur cet ordinateur : la Kali de la clé reste, la SystemRescue « pas la place »" \
  eval '((code == 0)) && [[ -e $BANC/cle11/ISO/${KALI11##*/} && ! -e $BANC/cle11/ISO/${SR11##*/} ]] &&
    dit "$BANC/notifications.log" "|Clé VANGUARD : pas la place|SystemRescue (il manque"' ||
  { montrer "$BANC/sortie"; montrer "$BANC/notifications.log"; }
/usr/bin/umount "$BANC/cle11"

# Un import interrompu (copie ratée, Ctrl-C) ne laisse rien dans le cache : jusqu'à 16 Gio pour Kali.
mkdir -p "$BANC/cache12" "$BANC/import12"
echo arch >"$BANC/import12/archlinux-2026.10.01-x86_64.iso"
importer12() { # ce que fait cp
  # SIGINT remis par défaut, comme au terminal : lancé en arrière-plan (verifier.sh), il est ignoré dès le départ, et
  # bash ne peut alors pas le piéger.
  VANGUARD_IMAGES=$BANC/cache12 python3 -I -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])' bash -c 'source outils/images-cle.sh; lire() { echo faux; }; '"cp() { $1; }"'
    importer "$0"' "$BANC/import12/archlinux-2026.10.01-x86_64.iso" >"$BANC/sortie" 2>&1
}
importer12 "echo 'cp: disque plein' >&2; return 1"
c1=$?
# Dans un sous-shell : le shell qui attend un programme tué par Ctrl-C s'arrête lui aussi, comme au terminal.
(importer12 'kill -INT $$; sleep 5')
c2=$?
voir "import interrompu (copie ratée, Ctrl-C) : le dossier de l'import retiré" \
  eval '((c1 == 1 && c2 == 130)) && [[ -d $BANC/cache12 && -z $(ls -A "$BANC/cache12") ]] &&
    [[ -f $BANC/import12/archlinux-2026.10.01-x86_64.iso ]]' ||
  { echo "      codes $c1 $c2"; ls -la "$BANC/cache12"; montrer "$BANC/sortie"; }

# Kali dont la dernière version n'a aucune source : la précédente est prise à sa place, et son torrent reprend.
mkdir -p "$BANC/cache7/.nouveau-kali-2026.1"
echo vieux >"$BANC/cache7/.nouveau-kali-2026.1/kali-linux-2026.1-live-everything-amd64.iso"
echo partiel >"$BANC/aria2/kali-linux-2026.2-live-everything-amd64.iso"
rm -f "$BANC/aria2/kali-linux-2026.3-live-everything-amd64.iso" "$BANC/aria2c.log"
chercher_kali() {
  (
    source outils/images-cle.sh
    for s in arch debian fedora systemrescue omarchy; do eval "derniere_$s() { return 1; }"; done
    derniere_kali() { echo "kali-linux-2026.3-live-everything-amd64.iso https://exemple.invalid/kali-2026.3/"; }
    precedente_kali() { echo "kali-linux-2026.2-live-everything-amd64.iso https://exemple.invalid/kali-2026.2/"; }
    lire() { echo "faux $1"; }
    verifier_image() { return 0; }
    chercher
  ) >>"$BANC/sortie7" 2>&1
}
VANGUARD_IMAGES=$BANC/cache7 chercher_kali
VANGUARD_IMAGES=$BANC/cache7 chercher_kali
voir "Kali : le torrent de la précédente, prise à la place de la dernière, reprend à la recherche suivante" \
  eval '[[ $(tail -1 "$BANC/aria2c.log") == "kali-linux-2026.2-live-everything-amd64.iso reprise" ]] &&
    [[ ! -e $BANC/cache7/.nouveau-kali-2026.3 ]] &&
    [[ -s $BANC/cache7/.nouveau-kali-2026.2/kali-linux-2026.2-live-everything-amd64.iso ]]' ||
  { montrer "$BANC/aria2c.log"; montrer "$BANC/sortie7"; }
voir "Kali : le torrent d'une version qui ne servira plus est retiré" \
  eval '[[ ! -e $BANC/cache7/.nouveau-kali-2026.1 ]]'

# --- Mise à jour du jour (maj-cle.sh) -------------------------------------------------------------------------------

echo "Mise à jour du jour :"
# Une copie de maj-cle.sh dans un faux dépôt : ses trois étapes y sont fausses. deployer.sh refuse comme le vrai
# (refuser) : son repère noté, sa notification ; ESSAI_DEPLOYER=rate : un autre échec, sans repère.
M=$BANC/depot-maj
mkdir -p "$M/outils" /run/media/alice/VANGUARD
: >/run/media/alice/VANGUARD/vanguard.cle
cp outils/maj-cle.sh "$M/outils/"
cat >"$M/outils/deployer.sh" <<'FIN'
#!/usr/bin/env bash
[[ ${ESSAI_DEPLOYER:-} == rate ]] && exit 1
[[ ${ESSAI_DEPLOYER:-} == ok ]] && exit 0
echo empreinte >"$XDG_RUNTIME_DIR/vanguard-refus.empreinte"
notify-send -a Vanguard -i vanguard "Vanguard : programmes refusés" "Faille connue"
exit 1
FIN
printf '#!/bin/sh
exit 0
' >"$M/outils/images-cle.sh"
printf '#!/bin/sh
exit 0
' >"$M/outils/cle-secours.sh"
chmod +x "$M"/outils/*.sh
rm -f "$BANC/notifications.log" "$BANC/run/vanguard-refus.empreinte"
bash "$M/outils/maj-cle.sh" >"$BANC/sortie" 2>&1
code=$?
voir "programmes refusés par deployer.sh : une seule notification, la sienne ; code 1" \
  eval '((code == 1)) && [[ $(wc -l <"$BANC/notifications.log") == 1 ]] &&
    dit "$BANC/notifications.log" "programmes refusés" && dit "$BANC/sortie" "déjà dit par sa notification"' ||
  { montrer "$BANC/sortie"; montrer "$BANC/notifications.log"; }
rm -f "$BANC/notifications.log" "$BANC/run/vanguard-refus.empreinte"
ESSAI_DEPLOYER=rate bash "$M/outils/maj-cle.sh" >"$BANC/sortie" 2>&1
code=$?
voir "programme raté pour une autre raison : la notification du jour le dit" \
  eval '((code == 1)) && dit "$BANC/notifications.log" "mise à jour du jour incomplète|Raté : programme."' ||
  { montrer "$BANC/sortie"; montrer "$BANC/notifications.log"; }
# Sans le réglage de la clé de secours : le vrai images-cle.sh le dit, et ni les images ni le démarrage ne passent.
cp outils/images-cle.sh "$M/outils/"
printf '#!/bin/sh\necho "$*" >>"$BANC/maj0.log"\nexit 0\n' >"$M/outils/cle-secours.sh"
rm -f "$REGLAGE" "$BANC/notifications.log" "$BANC/maj0.log"
ESSAI_DEPLOYER=ok bash "$M/outils/maj-cle.sh" >"$BANC/sortie" 2>&1
code=$?
voir "mise à jour du jour sans clé de secours : le programme seul, ni images ni démarrage ; code 0" \
  eval '((code == 0)) && [[ ! -e $BANC/maj0.log && ! -s $BANC/notifications.log ]] &&
    pas_dit "$BANC/sortie" "== images" && dit "$BANC/sortie" "ni images ni démarrage"' ||
  { montrer "$BANC/sortie"; montrer "$BANC/notifications.log"; }
reglage CLE_SECOURS=oui
rm -rf /run/media/alice

# --- Déploiement de la clé (deployer.sh, cle-commun.sh) ------------------------------------------------------------

echo "Déploiement de la clé :"
# La partition des journaux : celle du même disque, au jeton de la clé (findmnt et lsblk simulés).
J=0123456789abcdef0123456789abcdef
mkdir -p "$BANC/log-a" "$BANC/log-b" "$BANC/cle-j"
echo "$J" >"$BANC/cle-j/vanguard.jeton"
journal_simule() { # jeton de VANGUARDLOG sur le disque de la clé (vide : sans jeton), « ailleurs » : sur un autre disque
  (
    # shellcheck source=outils/cle-commun.sh
    source outils/cle-commun.sh
    findmnt() {
      case "$*" in
        "-nvo SOURCE -T $BANC/cle-j") echo /dev/sdy1 ;;
        "-nro TARGET -S /dev/sdy3") echo "$BANC/log-a" ;;
        "-nro TARGET -S /dev/sdx1") echo "$BANC/log-b" ;;
      esac
    }
    lsblk() {
      case "$*" in
        "-dno PKNAME /dev/sdy1") echo sdy ;;
        "-lnpo NAME,LABEL /dev/sdy") printf '/dev/sdy\n/dev/sdy1 VANGUARD\n/dev/sdy3 %s\n' "$ESSAI_LABEL_Y" ;;
        "-lnpo NAME,LABEL /dev/sdx") printf '/dev/sdx1 VANGUARDLOG\n' ;;
      esac
    }
    journal_de_la_cle "$BANC/cle-j"
  )
}
rm -f "$BANC/log-a/vanguard.jeton"
voir "VANGUARDLOG du même disque, sans jeton encore : prise" \
  eval '[[ $(ESSAI_LABEL_Y=VANGUARDLOG journal_simule 2>/dev/null) == "$BANC/log-a" ]]'
echo "$J" | tr 'a-f' 'A-F' >"$BANC/log-a/vanguard.jeton"
voir "VANGUARDLOG au jeton de la clé : prise" \
  eval '[[ $(ESSAI_LABEL_Y=VANGUARDLOG journal_simule 2>/dev/null) == "$BANC/log-a" ]]'
echo ffffffffffffffffffffffffffffffff >"$BANC/log-a/vanguard.jeton"
voir "VANGUARDLOG au jeton d'une autre clé : refusée, dit" \
  eval 'sortie=$(ESSAI_LABEL_Y=VANGUARDLOG journal_simule 2>&1); (($? == 1)) && [[ $sortie == *"autre clé"* ]]'
voir "seul un volume VANGUARDLOG d'un autre disque : rien" \
  eval '[[ -z $(ESSAI_LABEL_Y=AUTRE journal_simule 2>/dev/null) ]]'

# deployer.sh lui-même, dans un faux dépôt : un faux vanguard (la clé connue par les jetons de $BANC/connus, la
# référence par l'empreinte de chaque fichier), sans compilation ni GitHub (--sans-compiler, repère « local »).
DD=$BANC/depot-dep
mkdir -p "$DD/outils" "$DD/assets/icones" "$DD/target/x86_64-unknown-linux-musl/release" "$BANC/faux-dep"
cp outils/deployer.sh outils/cle-commun.sh outils/LISEZMOI.txt outils/README.txt "$DD/outils/"
cp -r outils/cle "$DD/outils/"
printf '#!/bin/sh\nexit 0\n' | tee "$DD/outils/verifier-masque.sh" "$DD/outils/failles-programmes.sh" \
  >"$BANC/faux-dep/pgrep"
: >"$DD/outils/licences-tierces.py"
sed -i 's/exit 0/exit 1/' "$BANC/faux-dep/pgrep"
chmod +x "$DD"/outils/*.sh "$DD"/outils/*.py "$BANC/faux-dep/pgrep"
: >"$DD/LICENSE"
: >"$DD/LICENCES-TIERCES.txt"
: >"$DD/assets/vanguard.ico"
: >"$DD/assets/icones/vanguard-16.png"
cat >"$DD/target/x86_64-unknown-linux-musl/release/vanguard" <<'FIN'
#!/usr/bin/env bash
# Faux vanguard du banc : chaque appel noté dans $BANC/vanguard.log.
echo "$*" >>"$BANC/vanguard.log"
releve() { (cd "$1" && find . -type f ! -path './donnees/*' -print0 | sort -z | xargs -0 -r sha256sum); }
case "$1 ${2:-}" in
  "--version ") echo "Vanguard 0.0.0-essai" ;;
  "deploiement cle")
    inconnu=0
    for v in /run/media/"$USER"/*; do
      [[ -f $v/vanguard.cle ]] || continue
      j=$(tr -d '[:space:]' <"$v/vanguard.jeton" 2>/dev/null)
      if [[ -n $j ]] && grep -qxF "$j" "$BANC/connus" 2>/dev/null; then echo "$v"; exit 0; fi
      inconnu=1
      echo "Volume au témoin de la clé, sans jeton connu : $v" >&2
    done
    exit $((inconnu * 3)) ;;
  "deploiement comparer-cle")
    [[ -f $BANC/reference ]] || { echo "aucune référence" >&2; exit 3; }
    diff <(releve "$3") "$BANC/reference" >&2 || exit 2 ;;
  "deploiement temoins")
    [[ -s $3/vanguard.jeton ]] || echo fedcba9876543210fedcba9876543210 >"$3/vanguard.jeton"
    echo temoin >"$3/vanguard.cle" ;;
  "manifeste --ecrire")
    releve "$3" >"$BANC/reference"
    tr -d '[:space:]' <"$3/vanguard.jeton" >>"$BANC/connus"
    echo >>"$BANC/connus" ;;
esac
exit 0
FIN
chmod +x "$DD/target/x86_64-unknown-linux-musl/release/vanguard"
# Le repère de outils/compiler-version.sh : ces octets-là, et pas d'autres, partent.
printf 'commit 0000000000000000000000000000000000000000\npropre oui\nlinux-x86_64 %s\n' \
  "$(sha256sum "$DD/target/x86_64-unknown-linux-musl/release/vanguard" | cut -d' ' -f1)" >"$DD/target/.compilation"
deployer() { # arguments… : sortie dans $BANC/sortie, code de sortie rendu
  rm -f "$BANC/notifications.log" "$BANC/vanguard.log"
  touch "$BANC/run/vanguard-deployer-local"
  PATH=$BANC/faux-dep:$PATH bash "$DD/outils/deployer.sh" "$@" >"$BANC/sortie" 2>&1
}
etat_cle() { (cd "$1" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum); }
K=/run/media/alice/VANGUARD
mkdir -p "$K"
echo temoin >"$K/vanguard.cle"
echo "$J" >"$K/vanguard.jeton"
echo "$J" >"$BANC/connus"
(cd "$K" && find . -type f -print0 | sort -z | xargs -0 sha256sum) >"$BANC/reference"
deployer --sans-compiler
code=$?
voir "clé connue, identique à sa référence : programme et code source copiés, référence réécrite ; code 0" \
  eval '((code == 0)) && [[ -f $K/Linux/vanguard && -d $K/source/outils ]] &&
    dit "$BANC/vanguard.log" "deploiement comparer-cle $K" && dit "$BANC/vanguard.log" "manifeste --ecrire $K"' ||
  { montrer "$BANC/sortie"; }
# Le voyage : un raccourci planté. Rien n'est écrit (ni copie, ni référence), une notification le dit.
echo piege >"$K/Photos.lnk"
echo "ancien" >"$K/Linux/vanguard"
etat_cle "$K" >"$BANC/avant"
cp "$BANC/reference" "$BANC/reference-avant"
deployer --sans-compiler
code=$?
voir "clé changée en voyage : rien n'y est écrit, la référence reste, notification ; code 1" \
  eval '((code == 1)) && cmp -s <(etat_cle "$K") "$BANC/avant" && cmp -s "$BANC/reference" "$BANC/reference-avant" &&
    pas_dit "$BANC/vanguard.log" "manifeste --ecrire" && pas_dit "$BANC/vanguard.log" "temoins" &&
    dit "$BANC/notifications.log" "Clé VANGUARD changée" && dit "$BANC/sortie" "Photos.lnk"' ||
  { montrer "$BANC/sortie"; montrer "$BANC/vanguard.log"; }
deployer --accepter-cle
code=$?
voir "--accepter-cle : la clé réécrite, sa référence forcée telle quelle ; code 0" \
  eval '((code == 0)) && dit "$BANC/vanguard.log" "manifeste --ecrire $K --forcer" &&
    ! grep -qx ancien "$K/Linux/vanguard" && [[ -f $K/Photos.lnk ]]' || montrer "$BANC/sortie"
# Un volume étranger au témoin VANGUARD (jeton inconnu), la vraie clé débranchée : il ne reçoit rien.
rm -rf "$K"
mkdir -p "$K"
echo temoin >"$K/vanguard.cle"
echo eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee >"$K/vanguard.jeton"
etat_cle "$K" >"$BANC/avant"
deployer --sans-compiler
code=$?
voir "volume VANGUARD au jeton inconnu : rien n'y est écrit (ni programme, ni source), notification ; code 0" \
  eval '((code == 0)) && cmp -s <(etat_cle "$K") "$BANC/avant" && [[ ! -e $K/source ]] &&
    dit "$BANC/notifications.log" "Volume VANGUARD inconnu"' || { montrer "$BANC/sortie"; montrer "$BANC/vanguard.log"; }
deployer --accepter-cle "$K"
code=$?
voir "--accepter-cle DOSSIER : le volume adopté (programme copié, référence forcée)" \
  eval '((code == 0)) && [[ -f $K/Linux/vanguard ]] && dit "$BANC/vanguard.log" "manifeste --ecrire $K --forcer"' ||
  montrer "$BANC/sortie"
rm -rf /run/media/alice
# Le programme remplacé depuis sa compilation (une compilation ordinaire, un autre worktree) : rien n'est copié.
mkdir -p "$K"
echo temoin >"$K/vanguard.cle"
echo "$J" >"$K/vanguard.jeton"
(cd "$K" && find . -type f -print0 | sort -z | xargs -0 sha256sum) >"$BANC/reference"
cp "$DD/target/.compilation" "$BANC/compilation"
sed -i 's/^linux-x86_64 .*/linux-x86_64 0000/' "$DD/target/.compilation"
deployer --sans-compiler
code=$?
voir "programmes pas ceux de compiler-version.sh : rien n'est copié sur la clé" \
  eval '((code == 0)) && [[ ! -e $K/Linux ]] && dit "$BANC/sortie" "pas ceux de outils/compiler-version.sh"' ||
  montrer "$BANC/sortie"
deployer --accepter-cle
code=$?
voir "… et --accepter-cle refuse (code 1)" eval '((code == 1)) && [[ ! -e $K/Linux ]]' || montrer "$BANC/sortie"
cp "$BANC/compilation" "$DD/target/.compilation"
rm -rf /run/media/alice
# --accepter-cle quand la dernière compilation vient d'un worktree : un échec dit, pas un succès silencieux.
mkdir -p "$K"
echo temoin >"$K/vanguard.cle"
echo '/x/.git/worktrees/b/HEAD' >"$DD/target/x86_64-unknown-linux-musl/release/vanguard.d"
deployer --accepter-cle "$K"
code=$?
voir "--accepter-cle sur une compilation de worktree : code 1, rien copié" eval '((code == 1)) && [[ ! -e $K/Linux ]]' ||
  montrer "$BANC/sortie"
rm -f "$DD/target/x86_64-unknown-linux-musl/release/vanguard.d"
rm -rf /run/media/alice
# Un journal au-delà de la borne de src/journal.rs (4 Mio) : mis de côté, rien n'en part vers GitHub.
mkdir -p "$BANC/donnees/vanguard"
{ echo "== 2026-10-24 · vanguard 0.86.0 · linux · fr · bilan"; head -c $((5 * 1024 * 1024)) /dev/zero | tr '\0' x; } \
  >"$BANC/donnees/vanguard/journal-erreurs.txt"
deployer --sans-compiler
voir "journal démesuré (5 Mio) : mis de côté, rien à envoyer sur GitHub, et dit" \
  eval 'dit "$BANC/sortie" "démesuré" && [[ ! -s $BANC/donnees/vanguard/retours/a-envoyer-github.txt ]] &&
    compgen -G "$BANC/donnees/vanguard/retours/journal-demesure-*" >/dev/null' || montrer "$BANC/sortie"

# --- Journal vers GitHub (journal-vers-github.py) -------------------------------------------------------------------

echo "Journal vers GitHub :"
# Un faux gh : chaque appel noté, un ticket créé par « issue create » (numéro suivant), aucun trouvé par la recherche.
mkdir -p "$BANC/faux-gh" "$BANC/retours"
cat >"$BANC/faux-gh/gh" <<'FIN'
#!/usr/bin/env bash
echo "$*" >>"$BANC/gh.log"
case "$1 $2" in
  "issue create") n=$(($(cat "$BANC/gh.n" 2>/dev/null || echo 0) + 1)); echo "$n" >"$BANC/gh.n"
    echo "https://github.com/exemple/depot/issues/$n" ;;
  "issue view") echo OPEN ;;
esac
exit 0
FIN
chmod +x "$BANC/faux-gh/gh"
journal_force() { # nombre d'erreurs distinctes, chacune deux fois, numéro de la première (0 par défaut)
  local i
  for ((i = ${2:-0}; i < $1 + ${2:-0}; i++)); do
    for _ in 1 2; do printf '== 2026-10-24 · vanguard 0.86.0 · linux · fr · bilan\n[contexte %s]\nerreur inventée %s\n\n' \
      "$(printf '%s' "$i" | tr 0-9 a-j)" "$(printf '%s' "$i" | tr 0-9 k-t)"; done
  done >"$BANC/retours/a-envoyer-github.txt"
}
envoyer() { # arguments… : sortie dans $BANC/sortie
  rm -f "$BANC/gh.log" "$BANC/notifications.log"
  PATH=$BANC/faux-gh:$PATH python3 -I outils/journal-vers-github.py "$@" "$BANC/retours/a-envoyer-github.txt" \
    >"$BANC/sortie" 2>&1
}
tickets() { grep -c '^issue create' "$BANC/gh.log" 2>/dev/null || true; }
journal_force 3
envoyer
voir "doublons regroupés : une erreur vue deux fois, un seul ticket ; l'envoi dit (notification)" \
  eval '[[ $(tickets) == 3 ]] && dit "$BANC/notifications.log" "3 ticket(s) créé(s)" &&
    [[ ! -s $BANC/retours/a-envoyer-github.txt ]]' || { montrer "$BANC/sortie"; montrer "$BANC/gh.log"; }
rm -f "$BANC/retours/envois-github.json" "$BANC/retours/tickets-github.json"
journal_force 8
envoyer
voir "8 erreurs distinctes : 5 tickets par passage, les 3 autres attendent, et c'est dit" \
  eval '[[ $(tickets) == 5 ]] && dit "$BANC/notifications.log" "envoi du journal plafonné" &&
    [[ $(grep -c "^== " "$BANC/retours/a-envoyer-github.txt") == 6 ]]' || { montrer "$BANC/sortie"; }
journal_force 9 10
envoyer
voir "le même jour : 10 tickets au plus, le reste attend" \
  eval '[[ $(tickets) == 5 ]] && dit "$BANC/notifications.log" "plafonné"' || montrer "$BANC/sortie"
journal_force 3 30
envoyer
voir "plafond du jour atteint : plus aucun ticket" eval '[[ $(tickets) == 0 ]]' || montrer "$BANC/sortie"
rm -f "$BANC/retours/envois-github.json" "$BANC/retours/tickets-github.json"
journal_force 60
cp "$BANC/retours/a-envoyer-github.txt" "$BANC/journal-60"
envoyer
voir "journal forgé (60 erreurs distinctes) : rien n'est envoyé ni retiré, l'accord est demandé" \
  eval '[[ $(tickets) == 0 ]] && cmp -s "$BANC/retours/a-envoyer-github.txt" "$BANC/journal-60" &&
    dit "$BANC/notifications.log" "journal à regarder avant tout envoi"' || montrer "$BANC/sortie"
envoyer --accord
voir "--accord : l'auteur l'envoie quand même, 50 tickets au plus par passage" \
  eval '[[ $(tickets) == 50 ]]' || montrer "$BANC/sortie"

# --- Ménage (menage-dev.sh) ------------------------------------------------------------------------------------------

echo "Ménage du développement :"
I=$BANC/xdg6/vanguard/images-cle
mkdir -p "$I/.nouveau-kali-2026.3" "$I/.nouveau-kali-2026.1" "$I/.nouveau-arch"
for f in "$I/.nouveau-kali-2026.3/kali-linux-2026.3-live-everything-amd64.iso" \
  "$I/.nouveau-kali-2026.1/kali-linux-2026.1-live-everything-amd64.iso" \
  "$I/.nouveau-arch/archlinux-2026.11.01-x86_64.iso"; do
  head -c 4096 /dev/urandom >"$f"
done
: >"$I/.nouveau-kali-2026.3/kali-linux-2026.3-live-everything-amd64.iso.aria2"
: >"$I/.nouveau-kali-2026.3/kali-linux-2026.3-live-everything-amd64.iso.torrent"
: >"$I/.nouveau-kali-2026.1/kali-linux-2026.1-live-everything-amd64.iso.torrent"
find "$I/.nouveau-kali-2026.3" "$I/.nouveau-arch" -exec touch -d '7 days ago' {} +
find "$I/.nouveau-kali-2026.1" -exec touch -d '40 days ago' {} +
XDG_CACHE_HOME=$BANC/xdg6 bash outils/menage-dev.sh --voir >"$BANC/sortie" 2>&1
voir "torrent de Kali en cours (7 jours) gardé pour reprendre ; un curl interrompu et un torrent abandonné partent" \
  eval 'pas_dit "$BANC/sortie" ".nouveau-kali-2026.3" && dit "$BANC/sortie" ".nouveau-arch" &&
    dit "$BANC/sortie" ".nouveau-kali-2026.1" && [[ -d $I/.nouveau-arch ]]' || montrer "$BANC/sortie"

echo "$ESSAIS essais, $ECHECS en échec."
((ECHECS == 0))
