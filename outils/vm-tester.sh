#!/usr/bin/env bash
# Essai de Vanguard dans la machine virtuelle Windows de test, sans un clic : compile le programme Windows, le dépose
# avec ses scripts d'essai dans la file d'essais (~/Windows/VANGUARD-TEST/file-essais/<id>/), attend que la VM l'ait
# fait (test.ps1 -Auto -SansOuvrir en administrateur, puis les menus dans une vraie console) et résume le résultat.
# Dans la VM, une seule fois : double-clic sur INSTALLER-ESSAIS-AUTO.bat (une fenêtre UAC ; --installer l'y pose).
#   outils/vm-tester.sh                       l'arbre courant (HEAD, « modifie=oui » s'il n'est pas propre)
#   outils/vm-tester.sh --branche B           la branche B (son worktree, ou un worktree temporaire)
#   outils/vm-tester.sh --exe chemin.exe      un programme déjà compilé (rien compilé ; passé à verifier-pe)
#   options : --sans-console --sans-test --langues fr,en --delai MIN (60) --sans-attendre
#   outils/vm-tester.sh --attendre <id>       attendre (de nouveau) un travail déjà déposé
#   outils/vm-tester.sh --installer           pose INSTALLER-/DESINSTALLER-ESSAIS-AUTO.bat dans la VM
#   outils/vm-tester.sh --essai-local         essais de ce script et du surveillant, sans VM (pwsh)
# Code de sortie : 0 si tout est passé dans la VM, 1 sinon (problèmes, refus, délai, VM muette).
# Jamais d'exécution du programme ici (binfmt le confierait à Wine) ; rien n'est touché à la VM elle-même : seulement
# des fichiers dans le dossier partagé. Ce qui est déposé s'exécute en administrateur dans la VM (voir
# outils/test-windows/LISEZMOI.txt, « ESSAIS SANS CLIC »).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
DEPOT=$PWD
VM=${VANGUARD_VM_DOSSIER:-$HOME/Windows/VANGUARD-TEST}
FILE=$VM/file-essais
# Délais, raccourcis par les essais : pas de l'attente, prise en charge par une VM libre, attente en file derrière
# d'autres travaux (ou une passe du menu), marge après le délai du travail, battement périmé (la VM écrit le sien
# toutes les 20 à 30 s).
PAS=${VM_TESTER_PAS:-5}
PRIS_S=${VM_TESTER_PRIS_S:-300}
FILE_S=${VM_TESTER_FILE_S:-10800}
MARGE_S=${VM_TESTER_MARGE_S:-600}
VIEUX_S=${VM_TESTER_VIEUX_S:-120}
# Sources des scripts d'essai et crochet après chaque copie : seulement pour --essai-local, jamais vers la vraie VM.
SOURCES=
CROCHET=
if [[ -n ${VM_TESTER_SOURCES:-} && -n ${VANGUARD_VM_DOSSIER:-} && $VM != "$HOME/Windows/"* ]]; then
  SOURCES=$VM_TESTER_SOURCES
  CROCHET=${VM_TESTER_CROCHET:-}
fi
MOTIF_ID='^[0-9]{8}-[0-9]{6}-[0-9a-f]{7,12}-[0-9a-z]{4}$'

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

BRANCHE_DEMANDEE= EXE= TEST=oui CONSOLE=oui LANGUES=fr,en DELAI=60 ATTENDRE=1 SUIVRE= MODE=essai
while (($#)); do
  case $1 in
    --branche) BRANCHE_DEMANDEE=${2:?--branche B}; shift ;;
    --exe) EXE=${2:?--exe chemin}; shift ;;
    --sans-console) CONSOLE=non ;;
    --sans-test) TEST=non ;;
    --langues) LANGUES=${2:?--langues fr,en}; shift ;;
    --delai) DELAI=${2:?--delai MIN}; shift ;;
    --sans-attendre) ATTENDRE= ;;
    --attendre) SUIVRE=${2:?--attendre <id>}; MODE=suivre; shift ;;
    --installer) MODE=installer ;;
    --essai-local) MODE=essai-local ;;
    -h | --help) usage; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[[ $TEST == non && $CONSOLE == non ]] && { echo "--sans-test et --sans-console : plus rien à faire." >&2; exit 2; }
[[ $LANGUES =~ ^(fr|en)(,(fr|en))?$ ]] || { echo "--langues : fr, en ou fr,en" >&2; exit 2; }
[[ $DELAI =~ ^[0-9]+$ ]] && ((DELAI >= 5 && DELAI <= 120)) || { echo "--delai : de 5 à 120 minutes" >&2; exit 2; }
[[ -n $BRANCHE_DEMANDEE && -n $EXE ]] && { echo "--branche ou --exe, pas les deux." >&2; exit 2; }

# Une valeur d'un fichier « cle=valeur » écrit par Windows (CRLF, BOM possible).
cle() { [[ -f $1 ]] && tr -d '\r' <"$1" | sed '1s/^\xef\xbb\xbf//' | awk -v k="$2" 'index($0, k "=") == 1 { print substr($0, length(k) + 2); exit }'; }
# Âge en secondes d'un fichier, d'après sa date posée par Samba (l'horloge de Linux) ; vide s'il manque.
age() { [[ -e $1 ]] && echo $(($(date +%s) - $(stat -c %Y "$1"))); }
heure() { date -d "@$(stat -c %Y "$1")" +%H:%M; }

# Ce qu'on sait de la VM, d'après le battement de la tâche et le témoin des passes du menu ; vide si tout va bien.
diagnostic() {
  local b=$FILE/battement.txt a etat t=$VM/resultats/.test-en-cours.txt
  if [[ ! -d $VM ]]; then
    echo "dossier partagé absent ($VM) : la VM n'a jamais été lancée ?"
    return
  fi
  if [[ ! -f $b ]]; then
    echo "tâche Vanguard-File-Essais pas installée : double-clic une fois sur INSTALLER-ESSAIS-AUTO.bat dans la VM"
    echo "(outils/vm-tester.sh --installer pour l'y poser)."
    return
  fi
  etat=$(cle "$b" etat)
  a=$(age "$b")
  if [[ $etat == desinstalle ]]; then
    echo "file d'essais désinstallée dans la VM : la réinstaller (INSTALLER-ESSAIS-AUTO.bat)."
  elif ((a > VIEUX_S)); then
    echo "dernier signe de la VM il y a $((a / 60)) min : VM éteinte, session fermée (la tâche ne tourne qu'avec la"
    echo "session ouverte) ou Windows en veille.$(processus_vm)"
  elif [[ $etat == en-pause* ]]; then
    echo "la VM attend : ${etat#en-pause } (témoin resultats/.test-en-cours.txt ; qui garde la VM le retire)."
  elif [[ $etat == erreur* ]]; then
    echo "le surveillant signale : $etat"
  elif [[ $etat == travail* ]]; then
    echo "la VM fait un travail de la file : ${etat#travail }."
  elif [[ -n $(find "$t" -mmin -180 2>/dev/null) ]]; then
    if [[ $(head -c12 "$t" 2>/dev/null) == "file-essais " ]]; then
      echo "témoin resultats/.test-en-cours.txt d'un travail de la file depuis $(heure "$t")."
    else
      echo "témoin resultats/.test-en-cours.txt depuis $(heure "$t") : VM réservée ou passe du menu en cours."
    fi
  fi
}

# La VM en vie (battement frais) et occupée : un autre travail de la file, ou en pause pour une passe du menu ; vide
# sinon (ou si c'est le travail <id> lui-même). Le temps passé ainsi ne compte pas dans le délai de prise en charge.
vm_occupee() {
  local b=$FILE/battement.txt a etat
  a=$(age "$b") || return 0
  ((a <= VIEUX_S)) || return 0
  etat=$(cle "$b" etat)
  case $etat in
    "travail $1"*) ;;
    travail*) echo "fait un autre travail (${etat#travail })" ;;
    en-pause*) echo "attend : ${etat#en-pause }" ;;
  esac
}

# En lecture seule : jamais docker, omarchy-windows-vm ni xfreerdp3 touchés.
processus_vm() {
  [[ -n $SOURCES ]] && return
  local q=non x=non
  pgrep -x qemu-system-x86_64 >/dev/null 2>&1 && q=oui
  pgrep -x xfreerdp3 >/dev/null 2>&1 && x=oui
  echo " (qemu en marche : $q ; fenêtre RDP xfreerdp3 : $x)"
}

ARBRE_TEMP=
nettoyer_arbre() {
  [[ -n $ARBRE_TEMP ]] && git -C "$DEPOT" worktree remove --force "$ARBRE_TEMP" >/dev/null 2>&1
  ARBRE_TEMP=
}

# L'arbre à tester (ARBRE), son commit, sa branche, s'il est propre ; le programme Windows compilé (EXE).
preparer_programme() {
  local cible
  ARBRE=$DEPOT
  if [[ -n $BRANCHE_DEMANDEE ]]; then
    git -C "$DEPOT" rev-parse --verify -q "refs/heads/$BRANCHE_DEMANDEE^{commit}" >/dev/null ||
      { echo "Branche inconnue : $BRANCHE_DEMANDEE" >&2; exit 1; }
    ARBRE=$(git -C "$DEPOT" worktree list --porcelain |
      awk -v b="refs/heads/$BRANCHE_DEMANDEE" '/^worktree / { w = substr($0, 10) } $0 == "branch " b { print w; exit }')
    if [[ -z $ARBRE ]]; then
      ARBRE=$HOME/.cache/vanguard-dev/vm-tester/arbre-${BRANCHE_DEMANDEE//\//-}
      mkdir -p "${ARBRE%/*}"
      git -C "$DEPOT" worktree remove --force "$ARBRE" >/dev/null 2>&1
      git -C "$DEPOT" worktree add -q --detach "$ARBRE" "$BRANCHE_DEMANDEE" || exit 1
      ARBRE_TEMP=$ARBRE
      trap nettoyer_arbre EXIT
      export CARGO_TARGET_DIR=$HOME/.cache/vanguard-dev/vm-tester/target
    fi
  fi
  if [[ -n $EXE ]]; then
    [[ -f $EXE ]] || { echo "Programme absent : $EXE" >&2; exit 1; }
    verifier_pe "$EXE"
    COMMIT=inconnu BRANCHE="exe fourni" MODIFIE=non
    return
  fi
  COMMIT=$(git -C "$ARBRE" rev-parse HEAD)
  BRANCHE=${BRANCHE_DEMANDEE:-$(git -C "$ARBRE" branch --show-current)}
  BRANCHE=${BRANCHE:-détachée}
  MODIFIE=non
  [[ -n $(git -C "$ARBRE" status --porcelain --untracked-files=no) ]] && MODIFIE=oui
  cible=${CARGO_TARGET_DIR:-$ARBRE/target}
  echo "Compilation de $BRANCHE ($(git -C "$ARBRE" rev-parse --short HEAD)) pour Windows…"
  (cd "$ARBRE" && cargo build -q --release --target x86_64-pc-windows-gnu) || { echo "Compilation en échec." >&2; exit 1; }
  EXE=$cible/x86_64-pc-windows-gnu/release/vanguard.exe
  verifier_pe "$EXE"
}

# Comme deployer.sh : un programme qui chargerait une DLL posée à côté de lui, ou sans son manifeste, ne part pas,
# qu'il vienne d'être compilé ou qu'il soit fourni par --exe (il tournera en administrateur dans la VM). Vérifié par le
# programme Linux de ce dépôt-ci (src/pe.rs), qui sait le faire même si la branche essayée est d'avant. Aucune
# exception, même pour les essais : ils déposent un vrai petit PE qui porte ses gardes.
verifier_pe() {
  (cd "$DEPOT" && env -u CARGO_TARGET_DIR cargo build -q --target x86_64-unknown-linux-musl) ||
    { echo "Vanguard pour Linux pas compilé dans $DEPOT : $1 pas vérifié, rien déposé." >&2; exit 1; }
  "$DEPOT/target/x86_64-unknown-linux-musl/debug/vanguard" deploiement verifier-pe "$1" ||
    { echo "Programme refusé par « vanguard deploiement verifier-pe » : rien déposé ($1)." >&2; exit 1; }
}

# Copie un fichier dans le travail ; un .ps1 reçoit le BOM qui lui manque (PowerShell 5.1 lirait sinon en ANSI).
copier() {
  if [[ $1 == *.ps1 && $(head -c3 "$1" | od -An -tx1 | tr -d ' ') != efbbbf ]]; then
    { printf '\xef\xbb\xbf'; cat "$1"; } >"$2"
  else
    cp -f "$1" "$2"
  fi
  [[ -z $CROCHET ]] || eval "$CROCHET"
}

# Dépôt atomique : tout dans <id>.partiel (que la VM ignore), travail.txt en dernier, puis renommage.
deposer() {
  local src=${SOURCES:-$ARBRE/outils/test-windows} lanceur court alea p f
  lanceur="${SOURCES:-$ARBRE/outils/cle}/Lancer Vanguard.bat"
  court=0000000
  [[ $COMMIT != inconnu ]] && court=${COMMIT:0:7}
  alea=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c4)
  ID=$(date +%Y%m%d-%H%M%S)-$court-$alea
  mkdir -p "$FILE" || exit 1
  p=$FILE/$ID.partiel
  mkdir "$p" || exit 1
  copier "$EXE" "$p/vanguard.exe"
  local fichiers=(vanguard.exe)
  if [[ $TEST == oui ]]; then
    copier "$src/test.ps1" "$p/test.ps1"
    copier "$lanceur" "$p/Lancer Vanguard.bat"
    fichiers+=(test.ps1 "Lancer Vanguard.bat")
  fi
  if [[ $CONSOLE == oui ]]; then
    copier "$src/essais-console.ps1" "$p/essais-console.ps1"
    fichiers+=(essais-console.ps1)
  fi
  {
    printf 'format=1\r\nid=%s\r\ncommit=%s\r\nbranche=%s\r\nmodifie=%s\r\ncree=%s\r\n' \
      "$ID" "$COMMIT" "${BRANCHE//[$'\r\n']/ }" "$MODIFIE" "$(date -Iseconds)"
    printf 'test=%s\r\nconsole=%s\r\nlangues=%s\r\ndelai_minutes=%s\r\n' "$TEST" "$CONSOLE" "$LANGUES" "$DELAI"
    for f in "${fichiers[@]}"; do printf 'sha256.%s=%s\r\n' "$f" "$(sha256sum "$p/$f" | cut -d' ' -f1)"; done
  } >"$p/travail.txt.tmp"
  mv "$p/travail.txt.tmp" "$p/travail.txt"
  [[ -z $CROCHET ]] || eval "$CROCHET"
  # Un lien symbolique, Samba le suit lui-même : la VM verrait un fichier ordinaire, venu d'ailleurs. Jamais déposé.
  if [[ -n $(find "$p" -mindepth 1 -type l -print -quit) ]]; then
    echo "Lien symbolique dans le travail ($(find "$p" -mindepth 1 -type l -printf '%f ' | head -c200)) : rien déposé." >&2
    rm -rf "$p"
    exit 1
  fi
  sync "$p"/* 2>/dev/null
  mv "$p" "$FILE/$ID" || exit 1
  echo "Travail déposé : $ID ($BRANCHE, $([[ $COMMIT == inconnu ]] && echo "commit inconnu" || echo "${COMMIT:0:7}")$([[ $MODIFIE == oui ]] && echo ", arbre modifié"))"
}

# Le résumé d'un travail fini ; code 0 si tout est passé.
resumer() {
  local d=$FILE/$1 f=$FILE/$1/fini.txt t=$FILE/$1/travail.txt code etat duree c
  code=$(cle "$f" code) etat=$(cle "$f" etat) duree=$(cle "$f" duree_s)
  c=$(cle "$t" commit)
  echo "Essai $1 (${c:0:7}, $(cle "$t" branche)) : pris $(cle "$d/pris.txt" pris | cut -c12-16), fini $(cle "$f" fin | cut -c12-16) ($(((${duree:-0} + 30) / 60)) min), administrateur : $(cle "$f" admin)"
  case $etat in
    refuse) echo "  REFUSÉ par la VM (rien lancé) : $(cle "$f" raison)" ;;
    delai) echo "  DÉLAI DÉPASSÉ : $(cle "$f" raison)" ;;
    erreur) echo "  ERREUR du surveillant : $(cle "$f" raison)" ;;
  esac
  if [[ -n $(cle "$f" test.ok) ]]; then
    echo "  test.ps1 : $(cle "$f" test.ok) OK · $(cle "$f" test.bugs) problème(s) · $(cle "$f" test.echecs) commande(s) en échec · $(cle "$f" test.sautees) sautée(s)"
  elif [[ $(cle "$t" test) == oui && $etat != refuse ]]; then
    echo "  test.ps1 : pas de bilan"
  fi
  if [[ -n $(cle "$f" console.ok) ]]; then
    echo "  console  : $(cle "$f" console.ok) OK · $(cle "$f" console.bugs) problème(s) · $(cle "$f" console.sautees) sauté(s)"
    [[ -f $d/resultats/console/resume.txt ]] &&
      tr -d '\r' <"$d/resultats/console/resume.txt" | sed '1s/^\xef\xbb\xbf//' | grep -E '^SAUTE ' | head -5 | sed 's/^/    /'
  elif [[ $(cle "$t" console) == oui && $etat != refuse ]]; then
    echo "  console  : pas de résumé"
  fi
  [[ $etat == problemes ]] && echo "  Problèmes : $(cle "$f" raison)"
  if [[ $code != 0 ]]; then
    [[ -f $d/resultats/console/resume.txt ]] &&
      tr -d '\r' <"$d/resultats/console/resume.txt" | sed '1s/^\xef\xbb\xbf//' | grep -E '^BUG ' | head -10 | sed 's/^/    /'
    [[ -f $d/resultats/journal.txt ]] &&
      tr -d '\r' <"$d/resultats/journal.txt" | sed '1s/^\xef\xbb\xbf//' | grep -E '^BUG : ' | head -10 | sed 's/^/    ✖ /'
  fi
  [[ -n $(cle "$f" rapport) ]] && echo "  Rapport : $d/resultats/rapport-test.html"
  echo "  Dossier : $d"
  [[ $code == 0 ]]
}

# Ctrl-C pendant l'attente : le travail reste déposé, et la VM le fera quand même.
interrompu() {
  local d=$FILE/$INTERROMPU_ID
  echo
  echo "Interrompu : le travail reste déposé ($d)."
  echo "Pour l'annuler, tant que pris.txt n'existe pas : rm -r \"$d\" ; pour le suivre : outils/vm-tester.sh --attendre $INTERROMPU_ID"
  exit 130
}

# Attend que la VM prenne puis finisse le travail ; une ligne de progrès par minute au plus.
attendre() {
  local id=$1 d=$FILE/$1 debut libre maintenant dernier=0 delai partie occupe vu= etat a ailleurs=
  [[ -f $d/travail.txt ]] || { echo "Travail inconnu : $d" >&2; return 1; }
  delai=$(cle "$d/travail.txt" delai_minutes)
  INTERROMPU_ID=$id
  trap interrompu INT
  debut=$(date +%s) libre=$debut
  while [[ ! -f $d/pris.txt && ! -f $d/fini.txt ]]; do
    maintenant=$(date +%s)
    # Derrière un autre travail (une autre fenêtre, une relance après Ctrl-C) ou une passe du menu : ce travail attend
    # son tour, et seul le temps où la VM est libre ou muette compte dans le délai de prise en charge.
    occupe=$(vm_occupee "$id")
    if [[ -n $occupe ]]; then
      libre=$maintenant
      [[ $occupe != "$vu" ]] && echo "  … la VM $occupe : ce travail attend son tour."
      vu=$occupe
    fi
    if ((maintenant - libre > PRIS_S || maintenant - debut > FILE_S)); then
      if ((maintenant - debut > FILE_S)); then
        echo "Pas pris par la VM en $((FILE_S / 60)) min : elle est restée occupée."
      else
        echo "Pas pris par la VM en $((PRIS_S / 60)) min $((PRIS_S % 60)) s."
      fi
      diagnostic
      echo "Le travail reste dans la file et la VM le fera quand elle le pourra (en administrateur) :"
      echo "  pour en lire le résultat : outils/vm-tester.sh --attendre $id"
      echo "  pour l'annuler, tant que pris.txt n'existe pas : rm -r \"$d\""
      return 1
    fi
    if ((maintenant - dernier >= 60)); then
      dernier=$maintenant
      ((maintenant > debut)) && echo "  … en attente de la VM depuis $(((maintenant - debut) / 60)) min"
    fi
    sleep "$PAS"
  done
  [[ -f $d/fini.txt ]] || echo "Pris par la VM ; essais en cours (jusqu'à ${delai:-60} min)…"
  debut=$(date +%s) dernier=$debut
  while [[ ! -f $d/fini.txt ]]; do
    maintenant=$(date +%s)
    if ((maintenant - debut > ${delai:-60} * 60 + MARGE_S)); then
      echo "Pas fini en $((${delai:-60} + MARGE_S / 60)) min ($d)."
      diagnostic
      return 1
    fi
    # Le battement dit ce que fait la VM. Frais mais plus sur ce travail (boucle arrêtée en route puis relancée,
    # file réinstallée ou désinstallée), ou muet trop longtemps (VM éteinte ou redémarrée) : il ne sera pas fini ici,
    # et la boucle suivante le finira en erreur. Un délai de grâce couvre le retard du partage.
    etat=$(cle "$FILE/battement.txt" etat) a=$(age "$FILE/battement.txt")
    if [[ -n $a ]] && ((a <= VIEUX_S)) && [[ $etat != "travail $id"* ]]; then
      ailleurs=${ailleurs:-$maintenant}
      if ((maintenant - ailleurs > VIEUX_S)); then
        echo "La VM ne fait plus ce travail (elle dit : ${etat:-rien}) : sa boucle a été arrêtée en route (VM redémarrée,"
        echo "session fermée, file réinstallée). Elle le finira en erreur ; outils/vm-tester.sh --attendre $id pour le voir."
        return 1
      fi
    else
      ailleurs=
    fi
    if { [[ -z $a ]] && ((maintenant - debut > 3 * VIEUX_S)); } || { [[ -n $a ]] && ((a > 3 * VIEUX_S)); }; then
      echo "La VM est muette depuis $((${a:-$((maintenant - debut))} / 60)) min en plein travail ($d)."
      diagnostic
      echo "Si elle revient, elle finira ce travail en erreur : outils/vm-tester.sh --attendre $id pour le voir."
      return 1
    fi
    if ((maintenant - dernier >= 60)); then
      dernier=$maintenant
      partie=$(cle "$FILE/en-cours.txt" partie)
      echo "  … $(((maintenant - debut) / 60)) min${partie:+ ($partie)}"
      [[ -n $(diagnostic) ]] && diagnostic | sed 's/^/  ⚠ /'
    fi
    sleep "$PAS"
  done
  trap - INT
  resumer "$id"
}

installer() {
  [[ -d $VM ]] || { echo "Dossier partagé absent : $VM (la VM n'a jamais été lancée ?)" >&2; exit 1; }
  mkdir -p "$VM/programme" || exit 1
  local f
  for f in essais-auto-installation.ps1 surveillant-essais.ps1; do copier "outils/test-windows/$f" "$VM/programme/$f"; done
  cp -f outils/test-windows/INSTALLER-ESSAIS-AUTO.bat outils/test-windows/DESINSTALLER-ESSAIS-AUTO.bat "$VM/"
  echo "Posé dans $VM : dans la VM, double-clic une fois sur INSTALLER-ESSAIS-AUTO.bat (une fenêtre UAC)."
  echo "Réinstaller met le surveillant à jour ; DESINSTALLER-ESSAIS-AUTO.bat le retire."
}

# --- Essais sans VM ----------------------------------------------------------------------------------------------------
# Le côté VM est joué par le vrai surveillant (pwsh, -EssaiLocal) sur un dossier jetable, avec un faux test.ps1 et de
# faux essais de console qui écrivent le bilan voulu sans rien lancer ; vanguard.exe est un faux fichier.
essai_local() {
  local PWSH=${VANGUARD_PWSH:-$HOME/.cache/vanguard-dev/pwsh/pwsh} T ESSAIS=0 ECHECS=0 SAUTES=0 ID id2 VMD SRC code
  T=$(mktemp -d "${TMPDIR:-/tmp}/vm-tester-essai.XXXX") || exit 1
  # shellcheck disable=SC2064
  trap "rm -rf '$T'" EXIT
  # pwsh laisse ses tubes dans TMPDIR quand il est arrêté (essai du délai) : ils partent avec le banc.
  mkdir -p "$T/tmp" && export TMPDIR=$T/tmp
  # Un vrai petit PE32+ qui porte les gardes que vérifie verifier-pe (comme pe::essais::gardes_d_essai) : Load Config
  # de 148 octets, DependentLoadFlags 0x800, manifeste n° 1 ; jamais lancé.
  python3 - "$T/vanguard.exe" <<'EOF2' || { echo "faux vanguard.exe : écriture en échec"; exit 1; }
import struct, sys
v = bytearray(0x800)
def m16(a, x): v[a:a + 2] = struct.pack('<H', x)
def m32(a, x): v[a:a + 4] = struct.pack('<I', x)
v[0:2] = b'MZ'; m32(0x3C, 0x40); v[0x40:0x44] = b'PE\0\0'; m16(0x44, 0x8664); m16(0x46, 2); m16(0x54, 240)
f = 0x58; m16(f, 0x20B); m32(f + 108, 16); r = f + 112
m32(r + 80, 0x1000); m32(r + 84, 148); m32(0x200, 148); m16(0x200 + 78, 0x800)
for i, (nom, rva, brut) in enumerate([(b'.rdata', 0x1000, 0x200), (b'.rsrc', 0x2000, 0x400)]):
    s = f + 240 + 40 * i
    v[s:s + len(nom)] = nom; m32(s + 8, 0x200); m32(s + 12, rva); m32(s + 16, 0x200); m32(s + 20, brut)
man = (b'<assembly><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/>'
       b'</requestedPrivileges></security><windowsSettings><activeCodePage>UTF-8</activeCodePage></windowsSettings>'
       b'</assembly>')
m32(r + 16, 0x2000); m32(r + 20, 0x200); b = 0x400
for niveau, nom, suite in [(0, 24, 0x80000018), (0x18, 1, 0x80000030), (0x30, 0x409, 0x48)]:
    m16(b + niveau + 14, 1); m32(b + niveau + 16, nom); m32(b + niveau + 20, suite)
m32(b + 0x48, 0x2060); m32(b + 0x4C, len(man)); v[b + 0x60:b + 0x60 + len(man)] = man
open(sys.argv[1], 'wb').write(v)
EOF2
  printf 'MZ programme abîmé pour les essais\n' >"$T/abime.exe"
  local avec_pwsh=1
  [[ -x $PWSH ]] || avec_pwsh=

  voir() { # libellé commande… : la commande doit réussir
    ESSAIS=$((ESSAIS + 1))
    if "${@:2}"; then echo "  ✔ $1"; return 0; fi
    ECHECS=$((ECHECS + 1)); echo "  ✖ $1"; sed 's/^/      | /' "$T/sortie" 2>/dev/null | head -30; return 1
  }
  sauter() { SAUTES=$((SAUTES + 1)); echo "  ↷ $1 : sauté (pwsh absent : $PWSH)"; }
  dit() { grep -qF -- "$1" "$T/sortie"; }
  nouvelle_vm() { VMD=$T/vm$((++N))/VANGUARD-TEST; mkdir -p "$VMD/resultats" "$VMD/file-essais"; }
  # Faux scripts d'essai : test.ps1 écrit bilan.txt et un rapport (ou ne finit jamais), laisse une trace s'il tourne ;
  # essais-console.ps1 écrit le résumé voulu.
  sources() { # bugs sautees attente(0/1) lignes-de-console…
    SRC=$T/sources$((++N)); mkdir -p "$SRC"
    cat >"$SRC/test.ps1" <<EOF
\$r = Join-Path (Join-Path \$PSScriptRoot 'resultats') '2026-10-23_14-25-30_vtest'
New-Item -ItemType Directory -Force -Path \$r | Out-Null
Add-Content -LiteralPath '$T/trace-$N' -Value "lancé ; extra copié : \$(Test-Path (Join-Path \$PSScriptRoot 'extra.ps1')) ; arguments : \$args"
if ($3) { Start-Sleep -Seconds 600 }
Set-Content -LiteralPath (Join-Path \$r 'bilan.txt') -Value "ok=212\`r\`nbugs=$1\`r\`nechecs=0\`r\`nsautees=$2\`r\`nversion=0.0.0"
Set-Content -LiteralPath (Join-Path \$r 'rapport-test.html') -Value '<html></html>'
Set-Content -LiteralPath (Join-Path \$r 'journal.txt') -Value "OK : a\`r\`n$( (($1 > 0)) && echo 'BUG : panne inventée' )"
EOF
    local lignes
    lignes=$(printf "'%s'," "${@:4}")
    cat >"$SRC/essais-console.ps1" <<EOF
param([string]\$Exe, [string]\$Sortie, [string]\$Langues, [int]\$LimiteMinutes)
Set-Content -LiteralPath (Join-Path \$Sortie 'resume.txt') -Value @(${lignes%,}) -Encoding UTF8
EOF
    printf '@echo off\r\n' >"$SRC/Lancer Vanguard.bat"
    TRACE=$T/trace-$N
  }
  tour() { "$PWSH" -NoProfile -NonInteractive -File "$DEPOT/outils/test-windows/surveillant-essais.ps1" -EssaiLocal -Racine "$VMD" -UnTour "$@" >>"$T/tours" 2>&1; }
  vmt() { # options de vm-tester.sh… : sortie dans $T/sortie, code dans $code
    env VANGUARD_VM_DOSSIER="$VMD" VM_TESTER_SOURCES="$SRC" VM_TESTER_PAS=0.2 VM_TESTER_PRIS_S="${PRIS:-3}" \
      VM_TESTER_MARGE_S=5 VM_TESTER_VIEUX_S="${VIEUX:-120}" VM_TESTER_CROCHET="${CROCHET_ESSAI:-}" bash "$DEPOT/outils/vm-tester.sh" --exe "$T/vanguard.exe" --delai 5 "$@" >"$T/sortie" 2>&1
    code=$?
    local n
    n=$(sed -n 's/^Travail déposé : \([^ ]*\).*/\1/p' "$T/sortie")
    [[ -z $n ]] || ID=$n
  }
  fini() { cle "$VMD/file-essais/$1/fini.txt" "$2"; }
  local N=0 TRACE

  # Le pilote des essais de console, sur une fausse console (la classe PiloteConsoleVg remplacée par une copie qui
  # répond ce qu'on veut, le reste du script inchangé) : ce qu'il conclut d'un écran illisible, d'une console
  # introuvable ou d'un Vanguard arrêté, selon l'hôte. Une vingtaine de secondes (l'attente du menu) : en fond.
  pilote_factice() { # nom hôte brancher lire secondes-de-vie-de-la-cible
    local dir=$T/pilote-$1 cible
    mkdir -p "$dir"
    cible=$( (sleep "$5" >/dev/null 2>&1 & echo $!))
    env VG_FAUX_BRANCHER="$3" VG_FAUX_LIRE="$4" "$PWSH" -NoProfile -NonInteractive -File "$T/essais-console-factice.ps1" -Etape pilote \
      -Cible "$cible" -Fenetre 1 -Hote "$2" -Langue fr -Sortie "$dir" -RectInitial r1,1,1,1 >"$dir/sortie" 2>&1
    kill "$cible" 2>/dev/null
    tr -d '\r' <"$dir/pilote-$2-fr.txt" 2>/dev/null >"$dir/lignes"
  }
  local pilotes=()
  if [[ -n $avec_pwsh ]]; then
    cat >"$T/faux-pilote.cs" <<'EOF2'
using System;
public static class PiloteConsoleVg {
  static int Env(string n) { int v; return int.TryParse(Environment.GetEnvironmentVariable(n), out v) ? v : 0; }
  public static int Brancher(int pid) { return Env("VG_FAUX_BRANCHER"); }
  public static void Detacher() { }
  public static long FenetreDeLaConsole() { return 0; }
  public static int ProcessusDeLaConsole() { return 2; }
  public static string Lire(out int colonnes, out int rangees, out int erreur) { colonnes = 78; rangees = 20; erreur = Env("VG_FAUX_LIRE"); return ""; }
  public static int Touche(ushort vk, ushort scan, char car, bool etendue) { return 0; }
  public static int[] Rect(long f) { return new int[] { 660, 300, 600, 440 }; }
  public static int[] RectDwm(long f) { return Rect(f); }
  public static int[] Zone(long f) { return new int[] { 0, 0, 1920, 1040 }; }
  public static string Classe(long f) { return "ConsoleWindowClass"; }
  public static long Racine(long f) { return f; }
  public static bool Existe(long f) { return false; }
  public static bool Fermer(long f) { return true; }
  public static bool Placer(long f, int x, int y) { return true; }
  public static string Tampon() { return "78x9001"; }
  public static int ProcessusDe(long f) { return 0; }
  public static long[] Fenetres(string c) { return new long[0]; }
}
EOF2
    # Le chef aussi, sur la même fausse console : seuls changent ce que Linux n'a pas (System32, Program Files, la
    # liste des processus par CIM). Le lancement de conhost y échoue (« BUG <hôte> <langue> erreur du chef »), Windows
    # Terminal y est sauté : une ligne par hôte et par langue, ce qui suffit à voir les paramètres mal découpés.
    python3 - "$DEPOT/outils/test-windows/essais-console.ps1" "$T/faux-pilote.cs" "$T/essais-console-factice.ps1" "$T/essais-console-chef.ps1" <<'EOF2'
import re, sys
s = open(sys.argv[1], encoding='utf-8-sig').read()
faux = open(sys.argv[2], encoding='utf-8').read()
s, n = re.subn(r"(?ms)^\$srcPilote = @'\n.*?^'@$", lambda m: "$srcPilote = @'\n" + faux + "'@", s, count=1)
assert n == 1
open(sys.argv[3], 'w', encoding='utf-8-sig').write(s)
for avant, apres in [("$systeme = [Environment]::SystemDirectory", "$systeme = '/nulle-part/System32'"),
                     ("[Environment]::GetFolderPath('ProgramFiles')", "'/nulle-part'"),
                     ("Get-AppxPackage -Name 'Microsoft.WindowsTerminal*' -ErrorAction Stop", "@()")]:
    assert s.count(avant) == 1, avant
    s = s.replace(avant, apres)
s, n = re.subn(r"(?m)^function Vanguards \{.*\}$", "function Vanguards { @() }", s, count=1)
assert n == 1
open(sys.argv[4], 'w', encoding='utf-8-sig').write(s)
EOF2
    pilote_factice conhost-illisible conhost 0 6 40 & pilotes+=($!)
    pilote_factice wt-illisible wt 0 6 40 & pilotes+=($!)
    pilote_factice conhost-attache conhost 31 0 40 & pilotes+=($!)
    pilote_factice wt-arrete wt 0 6 6 & pilotes+=($!)
  fi

  echo "File d'essais (vm-tester.sh, surveillant-essais.ps1), sans VM :"
  # 0. Un programme fourni par --exe passe par verifier-pe comme un programme compilé ; sans pwsh (rien ne tourne).
  nouvelle_vm; sources 0 0 0 'OK conhost fr C1 menu'
  vmt --exe "$T/abime.exe" --sans-attendre
  voir "--exe abîmé : refusé par verifier-pe, rien déposé, code 1" \
    eval '((code == 1)) && dit "refusé par « vanguard deploiement verifier-pe » : rien déposé" && [[ -z $(ls -A "$VMD/file-essais") ]]'
  vmt --sans-attendre
  voir "--exe qui porte ses gardes : accepté, travail déposé" eval '((code == 0)) && dit "Travail déposé"'
  if [[ -n $avec_pwsh ]]; then
    # 1. Tout passe, la VM jouée en même temps par une boucle de tours.
    nouvelle_vm; sources 0 4 0 'OK conhost fr C1 menu' 'OK conhost fr C2 hauteur' 'OK conhost en C1 menu'
    (while [[ ! -f $T/stop1 ]]; do tour; sleep 0.2; done) &
    local boucle=$!
    vmt
    touch "$T/stop1"; wait "$boucle"
    voir "tout passe : code 0, nombres et rapport résumés" eval '((code == 0)) && dit "212 OK · 0 problème(s)" && dit "3 OK · 0 problème(s)" && dit "rapport-test.html" && [[ ! -e $VMD/file-essais/$ID/vanguard.exe ]]'
    voir "test.ps1 lancé avec -SurPlace (rien de lancé hors du dossier protégé)" grep -q -- "-SurPlace" "$TRACE"
    voir "fini.txt complet, en-cours et témoin retirés, historique" eval '[[ $(fini "$ID" etat) == ok && $(fini "$ID" test.sautees) == 4 && ! -e $VMD/file-essais/en-cours.txt && ! -e $VMD/resultats/.test-en-cours.txt ]] && grep -q "$ID  ok" "$VMD/file-essais/historique.txt"'

    # 2. Deux problèmes dans test.ps1 et un dans la console : code 1, les problèmes montrés.
    nouvelle_vm; sources 2 0 0 'OK conhost fr C1 menu' 'BUG conhost fr C3 pas centrée'
    vmt --sans-attendre; tour; vmt --attendre "$ID"
    voir "problèmes : code 1, lignes BUG de la console et du journal montrées" eval '((code == 1)) && dit "2 problème(s)" && dit "pas centrée" && dit "✖ BUG : panne inventée"'

    # 3. Programme changé après travail.txt : refusé, rien lancé.
    nouvelle_vm; sources 0 0 0 'OK x'
    vmt --sans-attendre; printf 'x' >>"$VMD/file-essais/$ID/vanguard.exe"; tour; vmt --attendre "$ID"
    voir "empreinte fausse : refusé, test.ps1 pas lancé, code 1" eval '[[ $(fini "$ID" code) == 2 && ! -e $TRACE ]] && ((code == 1)) && dit "REFUSÉ" && dit "empreinte de « vanguard.exe »"'

    # 4. Fichier hors de la liste permise ou « .. » : refusé ; fichier en plus non listé : ignoré, jamais copié.
    nouvelle_vm; sources 0 0 0 'OK x'
    vmt --sans-attendre; printf 'Write-Host x\n' >"$VMD/file-essais/$ID/evil.ps1"
    printf 'sha256.evil.ps1=%s\r\n' "$(sha256sum "$VMD/file-essais/$ID/evil.ps1" | cut -d' ' -f1)" >>"$VMD/file-essais/$ID/travail.txt"
    tour
    voir "nom hors liste : refusé, rien lancé" eval '[[ $(fini "$ID" code) == 2 && $(fini "$ID" raison) == *"hors de la liste"* && ! -e $TRACE ]]'
    vmt --sans-attendre; printf 'sha256..=%064d\r\n' 0 >>"$VMD/file-essais/$ID/travail.txt"; tour
    voir "nom « .. » : refusé" eval '[[ $(fini "$ID" code) == 2 && ! -e $TRACE ]]'
    vmt --sans-attendre; printf 'Write-Host x\n' >"$VMD/file-essais/$ID/extra.ps1"; tour
    voir "fichier en plus non listé : ignoré (pas copié), travail fait" eval '[[ $(fini "$ID" code) == 0 ]] && grep -q "extra copié : False" "$TRACE"'

    # 5. Un dossier .partiel n'est jamais pris.
    nouvelle_vm; sources 0 0 0 'OK x'
    vmt --sans-attendre; mv "$VMD/file-essais/$ID" "$VMD/file-essais/$ID.partiel"; tour
    voir "dossier .partiel ignoré" eval '[[ ! -e $VMD/file-essais/$ID.partiel/pris.txt && ! -e $TRACE ]]'

    # 6. Deux travaux : un à la fois, dans l'ordre des noms.
    nouvelle_vm; sources 0 0 0 'OK x'
    vmt --sans-attendre; id2=$ID; sleep 1.1; vmt --sans-attendre
    tour
    voir "deux travaux : le plus ancien seul au premier tour" eval '[[ -f $VMD/file-essais/$id2/fini.txt && ! -e $VMD/file-essais/$ID/pris.txt ]]'
    tour
    voir "deux travaux : le second au tour suivant" eval '[[ $(fini "$ID" code) == 0 ]]'

    # 7. Témoin d'une passe du menu (ou VM réservée) : rien pris ; périmé (plus de 3 h) : pris.
    nouvelle_vm; sources 0 0 0 'OK x'
    printf 'x' >"$VMD/resultats/.test-en-cours.txt"
    vmt --sans-attendre; tour
    voir "témoin frais : rien pris, battement « en-pause »" eval '[[ ! -e $VMD/file-essais/$ID/pris.txt && $(cle "$VMD/file-essais/battement.txt" etat) == en-pause* ]]'
    touch -d '4 hours ago' "$VMD/resultats/.test-en-cours.txt"; tour
    voir "témoin périmé : travail pris et fait" eval '[[ $(fini "$ID" code) == 0 ]]'

    # 10. test.ps1 qui ne finit pas : arrêté au délai, fini.txt quand même.
    nouvelle_vm; sources 0 0 1 'OK x'
    vmt --sans-attendre; tour -DelaiSecondes 4; vmt --attendre "$ID"
    voir "délai dépassé : arrêté, fini.txt « delai », code 1" eval '[[ $(fini "$ID" code) == 3 ]] && ((code == 1)) && dit "DÉLAI DÉPASSÉ" && ! pgrep -f "prive-surveillant/travaux/$ID/test.ps1" >/dev/null'

    # 11. Essais de console sautés seulement : code 0, mais les sautés montrés.
    nouvelle_vm; sources 0 0 0 'OK conhost fr C1 menu' 'SAUTE wt fr C1-C8 Windows Terminal absent' 'SAUTE wt en C1-C8 Windows Terminal absent'
    vmt --sans-attendre; tour; vmt --attendre "$ID"
    voir "sautés seuls : code 0, « 2 sauté(s) » et leur raison montrés" eval '((code == 0)) && dit "2 sauté(s)" && dit "Windows Terminal absent"'

    # 11 b. Partie console demandée, rien de réussi (tout sauté) : jamais un vert.
    nouvelle_vm; sources 0 0 0 'SAUTE conhost fr C1-C8 x' 'SAUTE wt fr C1-C8 Windows Terminal absent'
    vmt --sans-attendre; tour; vmt --attendre "$ID"
    voir "console : 0 OK, tout sauté : code 1, « aucun essai réussi »" eval '((code == 1)) && [[ $(fini "$ID" code) == 1 ]] && dit "aucun essai réussi"'

    # 12. --sans-console : pas de partie console, ni dans travail.txt ni au résumé.
    nouvelle_vm; sources 0 0 0 'OK x'
    vmt --sans-console --sans-attendre; tour; vmt --attendre "$ID"
    voir "--sans-console : console=non, pas de partie console" eval '((code == 0)) && [[ $(cle "$VMD/file-essais/$ID/travail.txt" console) == non ]] && ! grep -q "sha256.essais-console" "$VMD/file-essais/$ID/travail.txt" && ! dit "console  :"'

    # 15. Boucle tuée net en plein test.ps1 (VM redémarrée, réinstallation) : son témoin ne met pas la file en pause ;
    #     au tour suivant, le travail abandonné finit en erreur, ses processus sont arrêtés, et la file repart.
    nouvelle_vm; sources 0 0 1 'OK x'
    vmt --sans-attendre
    local orphelin=$ID boucle2
    "$PWSH" -NoProfile -NonInteractive -File "$DEPOT/outils/test-windows/surveillant-essais.ps1" -EssaiLocal -Racine "$VMD" >>"$T/tours" 2>&1 &
    boucle2=$!
    for _ in $(seq 150); do [[ -f $TRACE ]] && break; sleep 0.1; done
    kill -9 "$boucle2"; wait "$boucle2" 2>/dev/null
    voir "boucle tuée : test.ps1 orphelin en marche, témoin « file-essais » resté" eval '[[ -f $TRACE && ! -f $VMD/file-essais/$orphelin/fini.txt ]] && grep -q "^file-essais $orphelin " "$VMD/resultats/.test-en-cours.txt" && pgrep -f "travaux/$orphelin/test.ps1" >/dev/null'
    sources 0 0 0 'OK x'
    vmt --sans-attendre; tour
    voir "orphelin fini en erreur, test.ps1 arrêté, témoin et en-cours retirés" eval '[[ $(fini "$orphelin" code) == 4 && $(fini "$orphelin" raison) == *"arrêté en plein travail"* ]] && ! pgrep -f "travaux/$orphelin/test.ps1" >/dev/null && [[ ! -e $VMD/resultats/.test-en-cours.txt && ! -e $VMD/file-essais/en-cours.txt ]]'
    voir "file repartie aussitôt : le travail suivant pris et fait au même tour" eval '[[ $(fini "$ID" code) == 0 ]]'
    vmt --attendre "$orphelin"
    voir "--attendre l'orphelin : code 1, la raison dite" eval '((code == 1)) && dit "arrêté en plein travail"'

    # 16. Témoin d'une passe du menu lancée pendant un travail : le travail ne le retire pas en finissant.
    nouvelle_vm; sources 0 0 0 'OK x'
    vmt --sans-attendre
    printf '%s\n' "$(date -Iseconds)" >"$T/temoin-menu"
    ( for _ in $(seq 200); do grep -qs '^file-essais ' "$VMD/resultats/.test-en-cours.txt" && { cp "$T/temoin-menu" "$VMD/resultats/.test-en-cours.txt"; break; }; sleep 0.02; done ) &
    local remplace=$!
    tour; wait "$remplace"
    voir "témoin d'une autre passe gardé à la fin du travail" eval '[[ $(fini "$ID" code) == 0 ]] && cmp -s "$T/temoin-menu" "$VMD/resultats/.test-en-cours.txt"'

    # 17. La VM fait un autre travail : celui-ci attend son tour au-delà du délai de prise en charge, puis il est fait.
    nouvelle_vm; sources 0 0 0 'OK x'
    vmt --sans-attendre
    ( for _ in $(seq 20); do printf 'format=1\r\netat=travail 20261023-000000-0000000-autr (test.ps1)\r\n' >"$VMD/file-essais/battement.txt"; sleep 0.2; done; tour ) &
    local occupe=$!
    PRIS=1 vmt --attendre "$ID"
    wait "$occupe"
    voir "VM occupée par un autre travail : attend son tour (pas d'échec à 1 s), puis fait, code 0" eval '((code == 0)) && dit "attend son tour" && dit "fait un autre travail"'
    # 20. Le chef des essais de console lancé par le surveillant (-Langues fr,en, -Hotes par défaut) : une ligne par
    #     hôte et par langue. Un tableau rangé dans un paramètre [string] du même nom (PowerShell ne distingue pas
    #     $Langues de $langues) donnait une seule ligne « conhost wt fr en » et un Start-Process sans programme.
    nouvelle_vm; sources 0 0 0 'OK x'
    cp "$T/essais-console-chef.ps1" "$SRC/essais-console.ps1"
    vmt --sans-attendre; tour
    local R=$VMD/file-essais/$ID/resultats/console/resume.txt
    voir "chef lancé par le surveillant : conhost et wt, fr et en, chacun à part" eval 'tr -d "\r" <"$R" | sed "1s/^\xef\xbb\xbf//" >"$T/chef-lignes" &&
      grep -q "^BUG conhost fr erreur du chef" "$T/chef-lignes" && grep -q "^BUG conhost en erreur du chef" "$T/chef-lignes" &&
      grep -q "^SAUTE wt fr C1-C8" "$T/chef-lignes" && grep -q "^SAUTE wt en C1-C8" "$T/chef-lignes" && (($(wc -l <"$T/chef-lignes") == 4)) ||
      { cp "$R" "$T/sortie" 2>/dev/null; false; }'
    "$PWSH" -NoProfile -NonInteractive -File "$T/essais-console-chef.ps1" -Exe "$T/vanguard.exe" -Sortie "$T/chef-direct" -Hotes wt,conhost \
      -Langues ' EN , fr' >"$T/sortie" 2>&1
    voir "chef, -Hotes wt,conhost -Langues « EN , fr » : quatre essais, dans l'ordre demandé" eval 'tr -d "\r" <"$T/chef-direct/resume.txt" | sed "1s/^\xef\xbb\xbf//" | cut -d" " -f1-3 |
      tr "\n" "|" | grep -qx "SAUTE wt en|SAUTE wt fr|BUG conhost en|BUG conhost fr|"'
  else
    for s in "tout passe" "problèmes" "empreinte fausse" "liste fermée" ".partiel" "deux travaux" "témoin" "délai" "sautés seuls" "--sans-console" \
      "boucle tuée" "témoin d'une autre passe" "VM occupée" "pilote factice" "chef des essais de console"; do sauter "$s"; done
  fi

  # 18. Pris, puis la VM dit faire autre chose (battement frais) ou se tait : vm-tester.sh n'attend pas tout le délai.
  nouvelle_vm; sources 0 0 0 'OK x'
  vmt --sans-attendre
  printf 'format=1\r\nid=%s\r\npris=x\r\n' "$ID" >"$VMD/file-essais/$ID/pris.txt"
  ( for _ in $(seq 40); do printf 'format=1\r\netat=attente\r\n' >"$VMD/file-essais/battement.txt"; sleep 0.1; done ) &
  local rafraichi=$!
  VIEUX=1 vmt --attendre "$ID"
  wait "$rafraichi"
  voir "pris, battement frais sur autre chose : abandon en quelques secondes, code 1" eval '((code == 1)) && dit "ne fait plus ce travail"'
  printf 'format=1\r\netat=travail %s (test.ps1)\r\n' "$ID" >"$VMD/file-essais/battement.txt"; touch -d '10 seconds ago' "$VMD/file-essais/battement.txt"
  VIEUX=1 vmt --attendre "$ID"
  voir "pris, battement muet : abandon, code 1, diagnostic" eval '((code == 1)) && dit "muette" && dit "--attendre"'

  # 19. Lien symbolique dans le travail (Samba le suivrait) : rien déposé.
  nouvelle_vm; sources 0 0 0 'OK x'
  ID=
  CROCHET_ESSAI='[[ -f $p/travail.txt ]] && ln -s /etc/hostname "$p/lien"' vmt --sans-attendre
  voir "lien symbolique : refusé, rien déposé, code 1" eval '((code == 1)) && dit "Lien symbolique" && [[ -z $ID ]] && [[ -z $(ls -A "$VMD/file-essais") ]]'

  # 8. Pas de battement : tâche pas installée.
  nouvelle_vm; sources 0 0 0 'OK x'
  PRIS=1 vmt
  voir "sans battement : « tâche pas installée », code 1" eval '((code == 1)) && dit "pas installée" && dit "INSTALLER-ESSAIS-AUTO.bat"'

  # 9. Battement vieux de 10 min : VM éteinte ou session fermée.
  nouvelle_vm; sources 0 0 0 'OK x'
  printf 'format=1\r\netat=attente\r\n' >"$VMD/file-essais/battement.txt"; touch -d '10 minutes ago' "$VMD/file-essais/battement.txt"
  PRIS=1 vmt
  voir "battement vieux : « VM éteinte, session fermée », code 1" eval '((code == 1)) && dit "il y a 10 min" && dit "session fermée"'

  # 13. Écriture atomique : pendant les copies, aucun dossier de travail sans .partiel.
  nouvelle_vm; sources 0 0 0 'OK x'
  CROCHET_ESSAI="ls -a '$VMD/file-essais' >>'$T/listes'" vmt --sans-attendre
  voir "dépôt atomique : seulement <id>.partiel pendant les copies, puis <id>" eval '[[ -n $ID && -d $VMD/file-essais/$ID && ! -e $VMD/file-essais/$ID.partiel ]] && grep -qx "$ID.partiel" "$T/listes" && ! grep -qx "$ID" "$T/listes"'
  voir "travail.txt : format, id, empreintes justes" eval '(cd "$VMD/file-essais/$ID" && [[ $(cle travail.txt format) == 1 && $(cle travail.txt id) == "$ID" ]] && [[ $ID =~ $MOTIF_ID ]] &&
    tr -d "\r" <travail.txt | sed -n "s/^sha256\.\(.*\)=\(.*\)/\2  \1/p" | sha256sum -c --quiet)'

  # 14. File désinstallée dans la VM : rien déposé.
  nouvelle_vm; sources 0 0 0 'OK x'
  printf 'format=1\r\netat=desinstalle\r\n' >"$VMD/file-essais/battement.txt"
  ID=
  vmt
  voir "file désinstallée : rien déposé, code 1" eval '((code == 1)) && dit "désinstallée" && [[ -z $ID ]]'

  if ((${#pilotes[@]})); then
    wait "${pilotes[@]}"
    local P=$T/pilote
    voir "pilote, conhost, écran illisible : BUG (jamais sauté), aucun OK" eval 'grep -q "^BUG conhost fr C1 lecture de l.écran impossible (erreur 6)" "$P-conhost-illisible/lignes" && ! grep -q "^OK" "$P-conhost-illisible/lignes"'
    voir "pilote, Windows Terminal, écran illisible : sauté avec la raison, ni BUG ni OK" eval 'grep -q "^SAUTE wt fr C1 lecture de l.écran impossible sous Windows Terminal" "$P-wt-illisible/lignes" && ! grep -qE "^(BUG|OK)" "$P-wt-illisible/lignes"'
    voir "pilote, conhost, console introuvable : BUG" eval 'grep -q "^BUG conhost fr C1 console de Vanguard introuvable (AttachConsole : erreur 31)" "$P-conhost-attache/lignes"'
    voir "pilote, Vanguard arrêté avant le menu : BUG même sous Windows Terminal" eval 'grep -q "^BUG wt fr C1 Vanguard s.est arrêté" "$P-wt-arrete/lignes" && ! grep -q "^OK" "$P-wt-arrete/lignes"'
  fi

  echo "$ESSAIS essais, $ECHECS en échec$([[ $SAUTES -gt 0 ]] && echo ", $SAUTES sautés (partie PowerShell)")."
  ((ECHECS == 0)) || exit 1
  ((ESSAIS > 0)) || exit 77
  exit 0
}

case $MODE in
  essai-local) essai_local ;;
  installer) installer; exit 0 ;;
  suivre)
    [[ $SUIVRE =~ $MOTIF_ID ]] || { echo "Id de travail illisible : $SUIVRE" >&2; exit 2; }
    attendre "$SUIVRE"
    exit $?
    ;;
esac

[[ -d $VM ]] || { echo "Dossier partagé absent : $VM (la VM n'a jamais été lancée ?)" >&2; exit 1; }
if [[ $(cle "$FILE/battement.txt" etat) == desinstalle ]]; then
  echo "File d'essais désinstallée dans la VM : la réinstaller (INSTALLER-ESSAIS-AUTO.bat) ; rien déposé." >&2
  exit 1
fi
preparer_programme
avis=$(diagnostic)
[[ -n $avis ]] && echo "$avis" | sed 's/^/⚠ /'
deposer
[[ -n $ATTENDRE ]] || { echo "Pour attendre le résultat : outils/vm-tester.sh --attendre $ID"; exit 0; }
attendre "$ID"
code=$?
nettoyer_arbre
exit "$code"
