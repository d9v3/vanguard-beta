#!/usr/bin/env bash
# Claude Code (l'assistant en ligne de commande d'Anthropic) sur la clé VANGUARD, pour dépanner l'ordinateur d'un
# proche : « Depanner avec Claude.bat » sous Windows, Claude/depanner.sh sous Linux ou sur un système démarré depuis la
# clé (SystemRescue). Mode d'emploi : outils/cle/Claude/LISEZMOI.txt ; consignes données à Claude :
# outils/cle/Claude/CLAUDE.md.
#   outils/claude-cle.sh --chercher   la version « stable » téléchargée et vérifiée dans le cache (minuterie
#                                     vanguard-claude-cle.timer, chaque jour) ; déjà là : revérifiée, rien n'est
#                                     téléchargé (quelques octets lus sur le serveur)
#   outils/claude-cle.sh --cle POINT  pose la version vérifiée du cache sur la clé (outils/deployer.sh, qui tient le
#                                     verrou de la clé) ; réglage coupé : retire de la clé ce que ce script y a posé
#   outils/claude-cle.sh --relire POINT  dit (code 2) un binaire de la clé changé depuis le dernier dépôt, sans rien
#                                     retirer (outils/deployer.sh, avant de reprendre un déploiement arrêté)
#   outils/claude-cle.sh --etat       ce qui est dans le cache
#   outils/claude-cle.sh --active     code 0 si le réglage local le demande, 1 sinon
# EN OPTION, COUPÉ PAR DÉFAUT : près de 600 Mo d'un programme tiers, qui demande un compte Claude. Le réglage local
# (~/.config/vanguard/images-cle.conf, le même que la clé de secours, lu, jamais sourcé) l'allume : CLAUDE_CLE=oui.
# Toute autre valeur, ou pas de ligne : coupé.
#
# Confiance : le manifeste de chaque version (empreinte SHA-256 et taille de chaque binaire) est signé par la clé
# « Anthropic Claude Code Release Signing », fixée ici (outils/cles-images/claude-code.asc) et reconnue par son
# empreinte, celle que publie la documentation d'Anthropic (code.claude.com, docs/en/setup) : jamais une clé lue sur
# le serveur qui sert les binaires. Seules les lignes d'un manifeste dont gpg a vérifié la signature sont lues ; un
# binaire qui n'a pas la taille et l'empreinte du manifeste signé est effacé. Une version plus ancienne que la
# dernière vérifiée est refusée, au téléchargement comme sur la clé (un serveur piégé ne fait pas revenir une version
# à faille).
# Ce que la copie fixée ne sait pas : une révocation publiée plus tard par Anthropic. Une clé expirée ou révoquée DANS
# cette copie est refusée ; si Anthropic change de clé ou révoque la sienne, la nouvelle copie et sa nouvelle empreinte
# arrivent avec une mise à jour de Vanguard (outils/cles-images/claude-code.asc, EMPREINTE_CLE ici et dans
# outils/cle/Claude/depanner.sh), jamais par le serveur.
# Le jeton de connexion à Claude n'est JAMAIS sur la clé : les lanceurs le gardent dans un dossier temporaire de
# l'ordinateur visité, effacé en sortant (outils/cle/Claude/depanner.ps1 et depanner.sh).
#
# Sur la clé, ce qui voyage peut être remplacé : chaque binaire posé est noté ici (son SHA-256, au jeton de la clé) et
# relu entier au déploiement suivant. Un binaire qui a changé pendant le voyage est dit (notification, code 2), puis
# remplacé par la copie vérifiée. Le manifeste de la clé (src/protection/manifeste.rs) ne compare que la taille d'un
# fichier de plus de 64 Mio : cette relecture le complète. Sous Windows, le lanceur vérifie en plus la signature
# Authenticode « Anthropic, PBC » de claude.exe avant de le lancer.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

SOURCE=https://downloads.claude.ai/claude-code-releases
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/vanguard/claude-cle
CLE_GPG=$PWD/outils/cles-images/claude-code.asc
EMPREINTE_CLE=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
SIGNATAIRE="d'Anthropic"
# Les crochets des essais (outils/essais-claude-cle.sh), sous VANGUARD_ESSAI seulement : une autre source (un faux
# serveur, file://), un autre cache (le ménage y efface des dossiers), une autre clé de confiance. Toujours dits en
# première ligne, et jamais sur une vraie clé (poser, plus bas).
# Le dépôt dont les unités de systemd sont liées (outils/systemd/installer.sh) ; voir minuterie, plus bas.
DEPOT_UNITES=$HOME/Projects/vanguard
CROCHETS=""
if [[ -n ${VANGUARD_ESSAI:-} ]]; then
  [[ -n ${VANGUARD_CLAUDE_SOURCE:-} ]] && { SOURCE=$VANGUARD_CLAUDE_SOURCE; CROCHETS+=", source"; }
  [[ -n ${VANGUARD_CLAUDE_CACHE:-} ]] && { CACHE=$VANGUARD_CLAUDE_CACHE; CROCHETS+=", cache"; }
  [[ -n ${VANGUARD_CLAUDE_DEPOT:-} ]] && { DEPOT_UNITES=$VANGUARD_CLAUDE_DEPOT; CROCHETS+=", dépôt des unités"; }
  if [[ -n ${VANGUARD_CLAUDE_CLE_GPG:-} ]]; then
    CLE_GPG=$VANGUARD_CLAUDE_CLE_GPG EMPREINTE_CLE=${VANGUARD_CLAUDE_EMPREINTE:-} SIGNATAIRE="de la clé d'essai"
    CROCHETS+=", clé de confiance"
  fi
  [[ -z $CROCHETS ]] || echo "· Crochets d'essai actifs (VANGUARD_ESSAI) : ${CROCHETS#, }." >&2
fi
REGLAGE=${XDG_CONFIG_HOME:-$HOME/.config}/vanguard/images-cle.conf
ETAT=${XDG_STATE_HOME:-$HOME/.local/state}/vanguard
# Les deux plateformes tenues : dossier du serveur, nom du binaire, dossier sur la clé.
PLATEFORMES=("linux-x64 claude Linux" "win32-x64 claude.exe Windows")
# Ce que ce script pose sur la clé, sous Claude/ (src/protection/manifeste.rs, depose_par_le_deploiement, a la même
# liste) ; le lanceur Windows, à la racine.
FIXES=(CLAUDE.md depanner.ps1 depanner.sh LISEZMOI.txt README.txt)
SIGNES=(manifest.json manifest.json.sig claude-code.asc)
LANCEUR="Depanner avec Claude.bat"
# Place laissée libre sur la clé après la copie (les rapports de Vanguard, sa base).
MARGE_MIO=512
# Remplis par version_verifiee : l'empreinte signée de chaque plateforme ; par poser : la note de la clé en cours.
declare -A VERIFIEES=() NOTEE=()

tmp=""
erreur() { echo "✖ $*" >&2; exit 1; }
[[ $EMPREINTE_CLE =~ ^[0-9A-F]{40}$ ]] || erreur "Empreinte de la clé de confiance de forme inattendue."
avertir() { # titre texte
  command -v notify-send >/dev/null && notify-send -a Vanguard -i vanguard -- "$1" "$2" || true
}
# Petits fichiers seulement (liste des versions, manifeste) : un serveur qui en enverrait des Go est coupé à 1 Mo.
lire() { curl -fsSL --proto '=https,file' --retry 3 --connect-timeout 20 --max-time 120 --max-filesize 1048576 "$1"; }

# Comme reglage() d'outils/images-cle.sh : les lignes « NOM=… », sans commentaire, guillemets, BOM ni « \r ».
reglage() { # nom
  [[ -r $REGLAGE ]] || return 0
  sed -n "1s/^\xEF\xBB\xBF//; s/\r//g; s/#.*//; s/^[[:space:]]*\(export[[:space:]]\+\)\?$1[[:space:]]*=//p" "$REGLAGE" |
    tr -d "\"' \t"
}
active() { [[ $(reglage CLAUDE_CLE | tail -1 | tr '[:upper:]' '[:lower:]') == oui ]]; }

# Le cache peut être un lien vers un autre disque (comme celui des images) : disque absent, rien n'est recréé à la
# place, dans ~/.cache ou sur le tmpfs de /run/media.
cache_present() {
  local d=$CACHE
  while [[ ! -e $d ]]; do
    [[ -L $d ]] && { echo "· Cache de Claude Code absent ($d mène à un disque débranché) : rien n'est fait." >&2; return 1; }
    [[ $d == */* ]] || break
    d=${d%/*}
    [[ -n $d ]] || break
  done
  return 0
}

# Vérifie la signature du manifeste d'un dossier ; écrit sur la sortie le manifeste tel que gpg l'a vérifié. Code 1
# (la raison sur la sortie d'erreur) sinon. Code 3 si la vérification n'a pas pu se faire ici (dossier temporaire
# plein ou sans droit d'écriture, clé de confiance pas chargée) : une panne de cet ordinateur ne passe jamais pour une
# signature fausse (le cache serait effacé, et l'alerte crierait au piège).
# Le trousseau jetable fermé : ses processus arrêtés et son dossier de sockets (/run/user/…/gnupg/d.…) retiré, sans
# quoi chaque vérification en laisse un.
trousseau_ferme() { # dossier
  gpgconf --homedir "$1" --kill all 2>/dev/null
  gpgconf --homedir "$1" --remove-socketdir 2>/dev/null
  rm -rf -- "$1"
}
manifeste_verifie() { # dossier
  local d=$1 trousseau statut
  trousseau=$(mktemp -d "${TMPDIR:-/tmp}/vanguard-claude-gpg.XXXXXX" 2>/dev/null) ||
    { echo "vérification impossible ici : dossier temporaire (${TMPDIR:-/tmp}) plein ou sans droit d'écriture" >&2; return 3; }
  # La clé fixée, chargée et retrouvée par son empreinte : un import raté (disque plein) n'est pas « clé inconnue ».
  if ! chmod 700 "$trousseau" || ! gpg --homedir "$trousseau" --quiet --batch --import "$CLE_GPG" 2>/dev/null ||
    ! gpg --homedir "$trousseau" --batch --list-keys "$EMPREINTE_CLE" >/dev/null 2>&1; then
    trousseau_ferme "$trousseau"
    echo "vérification impossible ici : clé de confiance pas chargée dans gpg (dossier temporaire ${TMPDIR:-/tmp} plein ?)" >&2
    return 3
  fi
  # La signature détachée porte sur les octets du fichier : ceux-là sont copiés à part, puis lus après vérification,
  # pour qu'un fichier changé entre la vérification et la lecture ne passe pas.
  if [[ -f $d/manifest.json ]] && ! cp -- "$d/manifest.json" "$trousseau/manifest.json" 2>/dev/null; then
    trousseau_ferme "$trousseau"
    echo "vérification impossible ici : manifeste pas copié dans le dossier temporaire (${TMPDIR:-/tmp} plein ?)" >&2
    return 3
  fi
  statut=$(gpg --homedir "$trousseau" --batch --status-fd 1 --verify "$d/manifest.json.sig" "$trousseau/manifest.json" \
    2>/dev/null || true)
  # GOODSIG, et VALIDSIG … <empreinte de la clé principale> en dernier champ : la clé fixée ici, et elle seule.
  # VALIDSIG sort aussi pour une clé expirée ou révoquée, ou une signature expirée : refusées.
  if ! grep -q '^\[GNUPG:\] GOODSIG ' <<<"$statut" ||
    ! grep -q "^\[GNUPG:\] VALIDSIG .* $EMPREINTE_CLE\$" <<<"$statut" ||
    grep -q '^\[GNUPG:\] \(EXPKEYSIG\|REVKEYSIG\|EXPSIG\) ' <<<"$statut"; then
    trousseau_ferme "$trousseau"
    if grep -q '^\[GNUPG:\] \(NO_PUBKEY\|ERRSIG\)' <<<"$statut"; then
      echo "manifeste signé par une clé que Vanguard ne connaît pas (une mise à jour de Vanguard l'apportera)" >&2
    else
      echo "signature du manifeste absente ou fausse" >&2
    fi
    return 1
  fi
  cat "$trousseau/manifest.json"
  trousseau_ferme "$trousseau"
}

# Lit dans un manifeste vérifié (entrée standard) la version, ou « empreinte taille binaire » d'une plateforme ; rien
# (code 1) si la forme n'est pas celle attendue. Le binaire doit être exactement le nom attendu : un « ../ » ou un
# autre nom n'entre pas dans un chemin.
champ() { # version | plateforme nom-attendu
  python3 -I -c '
import json, re, sys
m = json.load(sys.stdin)
if sys.argv[1] == "version":
    v = m.get("version")
    if isinstance(v, str) and re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}", v):
        print(v); sys.exit(0)
    sys.exit(1)
p = m.get("platforms", {}).get(sys.argv[1], {})
c, t, b = p.get("checksum"), p.get("size"), p.get("binary")
if isinstance(c, str) and re.fullmatch(r"[0-9a-f]{64}", c) and type(t) is int and 0 < t < 2**31 and b == sys.argv[2]:
    print(c, t, b); sys.exit(0)
sys.exit(1)' "$@" 2>/dev/null
}

# La dernière version vérifiée du cache (le témoin .verifiee n'est écrit qu'après la vérification de tout), ou rien.
derniere() {
  # Seulement les dossiers de version (nom x.y.z, pas un lien, avec leur manifeste) : un autre nom, ou un témoin seul,
  # ne passe jamais pour la plus récente.
  local d n
  for d in "$CACHE"/*/.verifiee; do
    n=${d%/.verifiee}
    [[ ${n##*/} =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ && -f $d && ! -L $n && -f $n/manifest.json ]] && echo "${n##*/}"
  done | sort -V | tail -1
}

# Vérifie un dossier de version : manifeste signé, de cette version, et chaque binaire à sa taille et à son empreinte.
# Rien n'y est suivi : un lien à la place du dossier, du manifeste ou de sa signature est refusé. L'empreinte signée
# de chaque plateforme est gardée dans VERIFIEES (la copie sur la clé y est comparée).
version_verifiee() { # dossier version
  local d=$1 v=$2 m ligne plat bin _dossier sha taille f
  VERIFIEES=()
  [[ -d $d && ! -L $d ]] || { echo "$d : pas un dossier" >&2; return 1; }
  for f in manifest.json manifest.json.sig; do
    [[ -f $d/$f && ! -L $d/$f ]] || { echo "$f : absent, ou pas un fichier ordinaire" >&2; return 1; }
  done
  m=$(manifeste_verifie "$d") || return $?
  [[ $(champ version <<<"$m") == "$v" ]] || { echo "le manifeste signé n'est pas celui de la version $v" >&2; return 1; }
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin _dossier <<<"$ligne"
    read -r sha taille _ < <(champ "$plat" "$bin" <<<"$m") ||
      { echo "$plat : absent du manifeste signé, ou de forme inattendue" >&2; return 1; }
    [[ -f $d/$plat/$bin && ! -L $d/$plat/$bin ]] || { echo "$plat/$bin : absent" >&2; return 1; }
    [[ $(stat -c %s "$d/$plat/$bin") == "$taille" ]] || { echo "$plat/$bin : taille différente du manifeste" >&2; return 1; }
    [[ $(sha256sum "$d/$plat/$bin" | cut -d' ' -f1) == "$sha" ]] ||
      { echo "$plat/$bin : empreinte différente du manifeste signé" >&2; return 1; }
    VERIFIEES[$plat]=$sha
  done
}

# La plus haute version jamais vérifiée ici, notée hors du cache (un cache vidé ou redescendu ne la fait pas oublier) ;
# rien si la note n'existe pas. Une note présente mais vide, abîmée ou illisible (disque plein pendant son écriture)
# n'est jamais prise pour « pas de note » : code 1, la raison sur la sortie d'erreur ; la protection contre le retour
# ne tombe pas avec elle.
NOTE_VERSION=$ETAT/claude-cle-version
haute_notee() {
  local h
  [[ -e $NOTE_VERSION || -L $NOTE_VERSION ]] || return 0
  h=$(head -c 33 -- "$NOTE_VERSION" 2>/dev/null) || h=""
  if [[ ! -f $NOTE_VERSION || ${#h} -gt 32 || ! $(tr -d '[:space:]' <<<"$h") =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ ]]; then
    echo "note de la dernière version vérifiée ($NOTE_VERSION) vide, abîmée ou illisible" >&2
    return 1
  fi
  tr -d '[:space:]' <<<"$h"
  echo
}
# La note, écrite d'un coup (nom provisoire, puis renommée) puis relue : jamais à moitié, et un échec (disque plein,
# dossier en lecture seule) est dit (code 1), jamais suivi d'un « ✔ ».
noter_haute() { # version
  { mkdir -p -- "$ETAT" && printf '%s\n' "$1" >"$NOTE_VERSION.tmp" && mv -f -T -- "$NOTE_VERSION.tmp" "$NOTE_VERSION" &&
    [[ $(haute_notee 2>/dev/null) == "$1" ]]; } 2>/dev/null && return 0
  rm -f -- "$NOTE_VERSION.tmp" 2>/dev/null
  echo "✖ Note de la dernière version vérifiée ($1) pas écrite dans $NOTE_VERSION (disque plein, ou dossier en lecture seule ?)." >&2
  avertir "Claude Code : note de version pas écrite" "La $1 est vérifiée, mais sa note n'a pas pu être écrite ($NOTE_VERSION)."
  return 1
}
# Rien n'est effacé ni téléchargé quand la vérification ne peut pas se faire sur cet ordinateur (code 3 de
# manifeste_verifie) : dit, notifié une fois par raison, code 1.
impossible() { # raison
  echo "✖ Vérification de Claude Code impossible sur cet ordinateur ($1) : rien n'est effacé ni téléchargé." >&2
  if [[ $(cat "$ETAT/claude-cle-impossible" 2>/dev/null) != "$1" ]]; then
    avertir "Claude Code : vérification impossible" "$1. Rien n'est effacé ; la clé garde ce qu'elle a."
    mkdir -p "$ETAT" 2>/dev/null && echo "$1" >"$ETAT/claude-cle-impossible" 2>/dev/null
  fi
  return 1
}
# La note illisible : rien n'est téléchargé ni posé tant qu'elle n'est pas réparée (dit et notifié).
note_abimee() {
  echo "✖ La note de la dernière version vérifiée ($NOTE_VERSION) est vide ou abîmée : rien n'est téléchargé ni posé." >&2
  echo "  La regarder ; y écrire la dernière version posée sur la clé (par exemple 2.1.0), ou l'effacer si elle est" >&2
  echo "  perdue (la protection contre le retour repart alors de la plus récente du cache)." >&2
  avertir "Claude Code : note de version abîmée" "$NOTE_VERSION est vide ou abîmée : rien n'est téléchargé ni posé."
}
plus_ancienne() { # a b : code 0 si a est plus ancienne que b
  [[ $1 != "$2" && $(printf '%s\n' "$1" "$2" | sort -V | head -1) == "$1" ]]
}

chercher() {
  active || { echo "Claude Code sur la clé : coupé sur cet ordinateur (CLAUDE_CLE=oui dans $REGLAGE l'allume)."; return 0; }
  cache_present || return 0
  mkdir -p "$CACHE" || return 1
  # Le verrou hors du cache, comme ceux du déploiement : un lien planté dans le cache ne fait rien écrire ailleurs.
  exec 8>>"${XDG_RUNTIME_DIR:-/tmp}/vanguard-claude-cle.lock" || return 1
  flock 8
  local v avant haute notee m ligne plat bin _dossier sha taille raison reste code
  # Un téléchargement tué (arrêt brutal, kill -9) laisse son dossier partiel : sous le verrou, aucun n'est en cours.
  # Seulement ces noms-là (.x.y.z.XXXXXX), de vrais dossiers.
  for reste in "$CACHE"/.[0-9]*.??????; do
    [[ ${reste##*/} =~ ^\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}\.[A-Za-z0-9]{6}$ && -d $reste && ! -L $reste ]] &&
      rm -rf -- "$reste"
  done
  v=$(lire "$SOURCE/stable" | tr -d '[:space:]') || { echo "✖ Version stable de Claude Code illisible (Internet ?)." >&2; return 1; }
  [[ $v =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ ]] || { echo "✖ Version stable de forme inattendue : rien n'est téléchargé." >&2; return 1; }
  notee=$(haute_notee 2>/dev/null) || { note_abimee; return 1; }
  avant=$(derniere)
  # La plus récente du cache, si ce n'est pas celle annoncée, revérifiée elle aussi : une copie abîmée ou un témoin
  # posé à la main ne bloque pas les mises à jour. La protection contre le retour tient par la note (haute_notee).
  # Une vérification impossible ici (code 3) n'efface rien.
  while [[ -n $avant && $avant != "$v" ]]; do
    raison=$(version_verifiee "$CACHE/$avant" "$avant" 2>&1)
    code=$?
    ((code == 0)) && break
    ((code != 3)) || { impossible "$raison"; return 1; }
    echo "⚠ Claude Code $avant du cache ne se vérifie plus ($raison) : effacé." >&2
    rm -rf -- "${CACHE:?}/$avant"
    avant=$(derniere)
  done
  # Avant tout le reste, même quand la version annoncée est déjà dans le cache : une annonce plus ancienne que la plus
  # haute version vérifiée est refusée et dite (le cache a pu redescendre en même temps que le serveur).
  haute=$(printf '%s\n' "$avant" "$notee" | sed '/^$/d' | sort -V | tail -1)
  if [[ -n $haute ]] && plus_ancienne "$v" "$haute"; then
    echo "✖ Le serveur annonce Claude Code $v, plus ancien que la $haute déjà vérifiée : refusé." >&2
    # Notifié une fois par annonce : la minuterie repasse chaque jour, la même alerte n'use pas l'attention.
    if [[ $(cat "$ETAT/claude-cle-refus" 2>/dev/null) != "$v<$haute" ]]; then
      avertir "Claude Code : version plus ancienne refusée" "Le serveur annonce la $v ; la $haute a déjà été vérifiée."
      mkdir -p "$ETAT" && echo "$v<$haute" >"$ETAT/claude-cle-refus"
    fi
    return 1
  fi
  if [[ $v == "$avant" ]]; then
    # Revérifiée, pas crue sur son témoin : une copie abîmée ou changée est effacée, puis téléchargée de nouveau.
    raison=$(version_verifiee "$CACHE/$v" "$v" 2>&1)
    code=$?
    if ((code == 0)); then
      # Notée ici aussi : un cache rempli autrement (ou une note perdue) garde sa protection contre le retour.
      noter_haute "$haute" || return 1
      echo "Claude Code $v : déjà dans le cache, revérifié."
      return 0
    fi
    ((code != 3)) || { impossible "$raison"; return 1; }
    echo "⚠ Claude Code $v du cache ne se vérifie plus ($raison) : effacé, téléchargé de nouveau." >&2
    rm -rf -- "${CACHE:?}/$v"
    avant=$(derniere)
  fi
  # Global, pas local : le piège de sortie le lit après la fin de la fonction.
  tmp=$(mktemp -d "$CACHE/.$v.XXXXXX") || return 1
  # Arrêté en route ou refusé : le dossier partiel part, rien ne passe pour vérifié.
  trap 'rm -rf -- "$tmp"' EXIT
  for f in manifest.json manifest.json.sig; do
    curl -fsSL --proto '=https,file' --retry 3 --connect-timeout 20 --max-time 120 --max-filesize 1048576 \
      -o "$tmp/$f" "$SOURCE/$v/$f" ||
      { echo "✖ $v/$f : pas téléchargé." >&2; return 1; }
  done
  m=$(manifeste_verifie "$tmp" 2>"$tmp/.raison")
  code=$?
  if ((code != 0)); then
    raison=$(cat "$tmp/.raison")
    ((code != 3)) || { impossible "$raison"; return 1; }
    echo "✖ Claude Code $v refusé : $raison." >&2
    avertir "Claude Code $v refusé" "$raison"
    return 1
  fi
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin _dossier <<<"$ligne"
    read -r sha taille _ < <(champ "$plat" "$bin" <<<"$m") ||
      { echo "✖ $plat : absent du manifeste signé, ou de forme inattendue." >&2; return 1; }
    mkdir -p "$tmp/$plat"
    echo "Claude Code $v ($plat, $((taille / 1048576)) Mio)…"
    curl -fL --proto '=https,file' --retry 3 --connect-timeout 20 --max-filesize "$taille" --speed-limit 10240 --speed-time 120 --progress-bar \
      -o "$tmp/$plat/$bin" "$SOURCE/$v/$plat/$bin" || { echo "✖ $plat/$bin : pas téléchargé." >&2; return 1; }
  done
  raison=$(version_verifiee "$tmp" "$v" 2>&1)
  code=$?
  if ((code != 0)); then
    ((code != 3)) || { impossible "$raison"; return 1; }
    echo "✖ Claude Code $v refusé : $raison." >&2
    avertir "Claude Code $v refusé" "$raison"
    return 1
  fi
  rm -f "$tmp/.raison"
  rm -rf "${CACHE:?}/$v"
  # Un mv raté laisse le trap effacer le dossier temporaire.
  mv -- "$tmp" "$CACHE/$v" || { echo "✖ Claude Code $v : pas rangé dans le cache." >&2; return 1; }
  trap - EXIT
  touch "$CACHE/$v/.verifiee"
  # Deux versions gardées : la nouvelle, et celle d'avant, le temps que la clé passe à la nouvelle.
  local d
  noter_haute "$v" || return 1
  # Seulement les dossiers de version (nom x.y.z, avec leur manifeste) : rien d'autre n'est effacé.
  for d in "$CACHE"/*/; do
    d=${d%/}
    [[ ${d##*/} =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ && -f $d/manifest.json && ! -L $d ]] || continue
    [[ ${d##*/} == "$v" || ${d##*/} == "$avant" ]] || rm -rf -- "$d"
  done
  echo "✔ Claude Code $v vérifié (signature $SIGNATAIRE, empreintes) dans le cache."
}

# Le SHA-256 de chaque binaire posé sur la clé, noté ici au jeton de la clé (jamais sur la clé).
note_de() { echo "$ETAT/claude-cle-$1.sha256"; }
# Le jeton de la clé (32 caractères hexadécimaux), ou rien.
jeton_de() { # point
  local j
  j=$(head -c 64 "$1/vanguard.jeton" 2>/dev/null | tr -d '[:space:]' | tr 'A-F' 'a-f')
  [[ $j =~ ^[0-9a-f]{32}$ ]] && echo "$j"
  return 0
}
BINAIRES_CLE=(Claude/Linux/claude Claude/Windows/claude.exe)
# Relire la clé, pas la mémoire : les pages du fichier sont lâchées (après sync, elles sont propres).
relache() { # fichier
  python3 -I -c 'import os,sys
fd=os.open(sys.argv[1],os.O_RDONLY)
os.posix_fadvise(fd,0,0,os.POSIX_FADV_DONTNEED)
os.close(fd)' "$1" 2>/dev/null || true
}
# Les binaires notés qui ont changé sur la clé depuis le dernier dépôt, relus entiers (« Claude/… », chacun précédé
# d'une espace) ; un lien ou un non-fichier à leur place compte comme changé. Un binaire absent ne compte pas : un
# dépôt arrêté en route en laisse un (poser), et outils/deployer.sh appelle --relire avant que la reprise d'un
# déploiement ne retire quoi que ce soit.
changes() { # point note
  local p=$1 note=$2 chemin sha
  [[ -f $note ]] || return 0
  for chemin in "${BINAIRES_CLE[@]}"; do
    [[ -e $p/$chemin || -L $p/$chemin ]] || continue
    grep -qF " $chemin" "$note" || continue
    sha=""
    if [[ -f $p/$chemin && ! -L $p/$chemin ]]; then
      relache "$p/$chemin"
      sha=$(sha256sum <"$p/$chemin" | cut -d' ' -f1)
    fi
    grep -qxF "$sha $chemin" "$note" || printf ' %s' "$chemin"
  done
}
# La note, réécrite d'un coup (nom provisoire, puis renommée) : jamais à moitié.
ecrire_note() { # note
  local c
  for c in "${!NOTEE[@]}"; do echo "${NOTEE[$c]} $c"; done | sort -k2 >"$1.tmp" && mv -f -- "$1.tmp" "$1"
}
# Un petit fichier posé : copié seulement s'il a changé, en remplaçant ce qui est là (jamais en le suivant), puis relu.
copier_relu() { # source destination
  cmp -s -- "$1" "$2" 2>/dev/null && return 0
  cp -T --remove-destination -- "$1" "$2" && cmp -s -- "$1" "$2"
}

# Retire de la clé ce que ce script y a posé, et rien d'autre ; les dossiers seulement vides. Seulement si la note de
# cette clé existe : sans elle, rien ne dit que ces fichiers viennent d'ici (ceux de la personne, un autre jeton) ;
# ils restent, et c'est dit. Chaque fichier retiré est nommé ; la note part après.
retirer() { # point note
  local p=$1 note=$2 f ligne _p _b dossier retires=()
  if [[ -z $note || ! -f $note ]]; then
    [[ ! -e $p/Claude && ! -e $p/$LANCEUR ]] ||
      echo "Claude Code coupé ; Claude/ sur la clé n'a pas été posé d'ici (pas de note) : laissé tel quel."
    return 0
  fi
  if [[ -d $p/Claude && ! -L $p/Claude ]]; then
    for f in "${FIXES[@]}" "${SIGNES[@]}"; do
      [[ -f $p/Claude/$f && ! -L $p/Claude/$f ]] && rm -f -- "$p/Claude/$f" && retires+=("Claude/$f")
    done
    for ligne in "${PLATEFORMES[@]}"; do
      read -r _p _b dossier <<<"$ligne"
      [[ -L $p/Claude/$dossier ]] && continue
      [[ -f $p/Claude/$dossier/$_b && ! -L $p/Claude/$dossier/$_b ]] && rm -f -- "$p/Claude/$dossier/$_b" &&
        retires+=("Claude/$dossier/$_b")
      rmdir -- "$p/Claude/$dossier" 2>/dev/null
    done
    rmdir -- "$p/Claude" 2>/dev/null
  fi
  [[ -f $p/$LANCEUR && ! -L $p/$LANCEUR ]] && rm -f -- "$p/$LANCEUR" && retires+=("$LANCEUR")
  rm -f -- "$note"
  ((${#retires[@]})) || return 0
  echo "Claude Code retiré de la clé (coupé sur cet ordinateur) :"
  printf '  %s\n' "${retires[@]}"
}

# Un binaire changé pendant le voyage qu'on ne peut pas remplacer par la copie vérifiée (coupé, cache absent,
# place, copie ratée) : retiré de la clé, jamais laissé là. Code 2.
# Ceux de la liste « remplacés » (changés pendant le voyage, déjà remplacés par la copie vérifiée avant la panne)
# sont dits aussi : la panne qui suit ne fait jamais oublier qu'ils avaient changé.
retirer_change() { # point changes raison [remplacés]
  local p=$1 chemin restes=""
  for chemin in $2; do
    # Un lien à la place du binaire est retiré lui-même (rm ne suit pas) ; jamais au travers d'un dossier lien.
    [[ $chemin =~ ^Claude/(Linux/claude|Windows/claude\.exe)$ && ! -L $p/Claude && ! -L $p/${chemin%/*} ]] &&
      rm -f -- "${p:?}/$chemin" 2>/dev/null
    # Relu après coup : un dossier (ou ce qu'on n'a pas pu retirer) à la place du binaire n'est jamais dit « retiré ».
    [[ ! -e $p/$chemin && ! -L $p/$chemin ]] || restes+=" $chemin"
  done
  if [[ -z $restes ]]; then
    echo "✖ Sur la clé, changé depuis le dernier dépôt :$2. Pas de copie vérifiée à remettre ($3) : retiré." >&2
  else
    echo "✖ Sur la clé, changé depuis le dernier dépôt :$2. Pas de copie vérifiée à remettre ($3)." >&2
    echo "  PAS retiré (dossier ou lien à sa place, ou effacement refusé) :$restes. À regarder, puis effacer à la main." >&2
  fi
  [[ -z ${4:-} ]] || echo "  Changé aussi, déjà remplacé par la copie vérifiée :$4." >&2
  echo "  Un programme remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
  if [[ -z $restes ]]; then
    avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$2${4:-}. Retiré de la clé ($3) ou remplacé \
par la copie vérifiée ; un programme remplacé est un piège possible."
  else
    avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$2${4:-}. PAS retiré :$restes (à effacer à la \
main) ; un programme remplacé est un piège possible."
  fi
  exit 2
}
# Rien n'est posé (code 1) ; un binaire changé pendant le voyage, lui, ne reste jamais sur la clé, et il est toujours
# dit (code 2), même s'il a déjà été remplacé avant la panne (vu, la liste du début, dans poser).
refuser() { # point changes raison texte
  local remplaces=${vu:-} c
  for c in $2; do remplaces=${remplaces// $c/}; done
  [[ -z $2 ]] || retirer_change "$1" "$2" "$3" "$remplaces"
  if [[ -n $remplaces ]]; then
    echo "✖ $4" >&2
    echo "✖ Sur la clé, changé depuis le dernier dépôt :$remplaces. Remplacé par la copie vérifiée avant la panne ;" >&2
    echo "  un programme remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
    avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$remplaces. Remplacé par la copie vérifiée \
(le reste du dépôt a raté) ; un programme remplacé est un piège possible."
    exit 2
  fi
  erreur "$4"
}

# La minuterie qui remplit le cache (vanguard-claude-cle.timer) n'est allumée que par outils/systemd/installer.sh :
# après une mise à jour du dépôt, rien ne la posait, et la clé restait sans Claude Code. Chaque pose réglage allumé
# la vérifie donc ; absente, elle est liée et allumée depuis le dépôt des unités (jamais depuis une autre copie de
# travail, qui peut disparaître), et une première recherche part aussitôt, en arrière-plan. Rien de root : les
# unités de l'utilisateur. Annulable : systemctl --user disable vanguard-claude-cle.timer.
minuterie() {
  local unites=$PWD/outils/systemd etat_m
  command -v systemctl >/dev/null || return 0
  etat_m=$(systemctl --user is-enabled vanguard-claude-cle.timer 2>/dev/null)
  [[ $etat_m != enabled ]] || return 0
  if [[ $(pwd -P) != $(cd "$DEPOT_UNITES" 2>/dev/null && pwd -P) ]]; then
    echo "⚠ Minuterie de Claude Code (vanguard-claude-cle.timer) pas allumée : lancer outils/systemd/installer.sh." >&2
    return 0
  fi
  if systemctl --user link "$unites/vanguard-claude-cle.service" >/dev/null 2>&1 &&
    systemctl --user enable --now "$unites/vanguard-claude-cle.timer" >/dev/null 2>&1; then
    echo "Minuterie de Claude Code (vanguard-claude-cle.timer) allumée : elle manquait (${etat_m:-absente})."
    systemctl --user start --no-block vanguard-claude-cle.service >/dev/null 2>&1 &&
      echo "  Première recherche lancée en arrière-plan ; la clé l'aura au dépôt suivant."
  else
    echo "⚠ Minuterie de Claude Code (vanguard-claude-cle.timer) pas allumée (systemctl a refusé) :" \
      "lancer outils/systemd/installer.sh." >&2
  fi
}

# La version que porte déjà la clé, si elle se vérifie entière : manifeste signé par la clé fixée, et chaque binaire
# à la taille et à l'empreinte de ce manifeste. VERSION_CLE la reçoit (rien sinon), et CLE_SHA l'empreinte de chaque
# binaire. Rien n'est suivi : un lien à la place d'un dossier ou d'un fichier, et ce n'est pas vérifié. Les binaires
# ne sont relus que si la version signée est plus récente que « plus_que ».
declare -A CLE_SHA=()
VERSION_CLE=""
version_cle() { # point plus_que
  local c=$1/Claude m vc ligne plat bin dossier sha taille f
  VERSION_CLE="" CLE_SHA=()
  [[ -d $c && ! -L $c ]] || return 0
  for f in manifest.json manifest.json.sig; do [[ -f $c/$f && ! -L $c/$f ]] || return 0; done
  m=$(manifeste_verifie "$c" 2>/dev/null) || return 0
  vc=$(champ version <<<"$m") || return 0
  plus_ancienne "$2" "$vc" || return 0
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    read -r sha taille _ < <(champ "$plat" "$bin" <<<"$m") || return 0
    [[ ! -L $c/$dossier && -f $c/$dossier/$bin && ! -L $c/$dossier/$bin ]] || return 0
    [[ $(stat -c %s "$c/$dossier/$bin") == "$taille" ]] || return 0
    relache "$c/$dossier/$bin"
    [[ $(sha256sum <"$c/$dossier/$bin" | cut -d' ' -f1) == "$sha" ]] || return 0
    CLE_SHA[Claude/$dossier/$bin]=$sha
  done
  VERSION_CLE=$vc
}

# La clé garde sa version signée plus récente (version_cle) : ses binaires notés tels quels, la note de version montée à
# elle, le lanceur et les consignes remis à jour ; son manifeste signé reste le sien. Un binaire qui a changé depuis
# le dernier dépôt d'ici est dit : c'est la version signée de la clé, pas un programme inconnu.
garder_cle() { # point version-du-cache note changés
  local p=$1 f c
  NOTEE=()
  for c in "${!CLE_SHA[@]}"; do NOTEE[$c]=${CLE_SHA[$c]}; done
  vu=""
  { mkdir -p "$ETAT" && ecrire_note "$3"; } || refuser "$p" "" "note pas écrite" "Note du dépôt pas écrite ($3)."
  noter_haute "$VERSION_CLE" || refuser "$p" "" "note de version pas écrite" "Note de version pas écrite : rien n'est posé."
  for f in "${FIXES[@]}"; do
    copier_relu "outils/cle/Claude/$f" "$p/Claude/$f" || refuser "$p" "" "copie ratée" "Claude/$f pas copié sur la clé."
  done
  copier_relu "$CLE_GPG" "$p/Claude/claude-code.asc" || refuser "$p" "" "copie ratée" "Claude/claude-code.asc pas copié sur la clé."
  copier_relu "outils/cle/$LANCEUR" "$p/$LANCEUR" || refuser "$p" "" "copie ratée" "$LANCEUR pas copié sur la clé."
  sync -f "$p/Claude/CLAUDE.md" 2>/dev/null || true
  echo "⚠ La clé porte déjà Claude Code $VERSION_CLE (signé, vérifié), plus récent que le cache ($2) : gardé, pas" >&2
  echo "  redescendu. Lancer outils/claude-cle.sh --chercher pour que cet ordinateur ait la même." >&2
  [[ -z $4 ]] ||
    echo "  Changé depuis le dernier dépôt d'ici :$4 ; c'est la version $VERSION_CLE signée (posée d'un autre ordinateur ?)." >&2
  avertir "Claude Code plus récent sur la clé" "La clé porte la $VERSION_CLE signée ; le cache n'a que la $2. Gardée sur la \
clé, pas redescendue."
}

poser() { # point
  local p=$1 jeton v d note="" ligne plat bin dossier change="" vu besoin libre chemin haute f s c sha part inconnu=""
  # Les crochets d'essai ne touchent jamais une vraie clé.
  [[ -z $CROCHETS || $(realpath -m -- "$p") != /run/media/* ]] ||
    erreur "Crochets d'essai actifs : rien n'est posé sur une clé de /run/media ($p)."
  [[ -d $p && -f $p/vanguard.cle ]] || erreur "$p n'est pas une clé VANGUARD."
  # Ce qui a changé pendant le voyage, d'abord, quoi qu'il arrive ensuite (coupé, cache absent, place) : relu
  # entier, comparé à la note du dernier dépôt.
  jeton=$(jeton_de "$p")
  if [[ -n $jeton ]]; then
    note=$(note_de "$jeton")
    change=$(changes "$p" "$note")
  fi
  vu=$change
  if ! active; then
    retirer "$p" "$note"
    [[ -z $change ]] || retirer_change "$p" "$change" "Claude Code coupé"
    return 0
  fi
  minuterie
  if ! cache_present; then
    [[ -z $change ]] || retirer_change "$p" "$change" "cache absent"
    return 0
  fi
  v=$(derniere)
  if [[ -z $v ]]; then
    [[ -z $change ]] || retirer_change "$p" "$change" "cache vide"
    echo "Claude Code pas encore dans le cache (outils/claude-cle.sh --chercher) : la clé reste sans lui."
    return 0
  fi
  d=$CACHE/$v
  # La note illisible : rien n'est posé (elle ne vaut jamais « pas de note »).
  if ! haute=$(haute_notee 2>/dev/null); then
    note_abimee
    refuser "$p" "$change" "note de version abîmée" "Note de version abîmée : rien n'est posé sur la clé."
  fi
  # Rien n'est suivi sur la clé : chaque dossier est un vrai dossier, chaque fichier écrit un fichier ordinaire, ou
  # absent.
  for chemin in Claude Claude/Linux Claude/Windows; do
    [[ ! -L $p/$chemin && (! -e $p/$chemin || -d $p/$chemin) ]] ||
      refuser "$p" "$change" "chemin piégé sur la clé" "$p/$chemin : lien symbolique, ou pas un dossier : rien n'est posé."
  done
  for chemin in "${FIXES[@]/#/Claude/}" "${SIGNES[@]/#/Claude/}" "${BINAIRES_CLE[@]}" Claude/Linux/.claude.part \
    Claude/Windows/.claude.exe.part "$LANCEUR"; do
    [[ ! -L $p/$chemin && (! -e $p/$chemin || -f $p/$chemin) ]] ||
      refuser "$p" "$change" "chemin piégé sur la clé" \
        "$p/$chemin : lien symbolique, ou pas un fichier ordinaire : rien n'est posé."
  done
  [[ -n $jeton ]] || erreur "Jeton de la clé illisible : rien n'est posé."
  # Jamais plus ancienne que la plus haute version vérifiée ici : un cache redescendu (version récente effacée, copie
  # d'un autre ordinateur) ne fait pas revenir une version à faille sur la clé.
  if [[ -n $haute ]] && plus_ancienne "$v" "$haute"; then
    avertir "Claude Code : version plus ancienne refusée" "Le cache n'a que la $v ; la $haute a déjà été vérifiée. \
Rien n'est posé sur la clé."
    refuser "$p" "$change" "cache plus ancien que la version vérifiée" \
      "Claude Code $v du cache, plus ancien que la $haute déjà vérifiée : rien n'est posé (relancer --chercher)."
  fi
  # La clé porte déjà, signée et entière, une version plus récente que le cache (posée d'un autre ordinateur, ou cache
  # et note de cet ordinateur revenus ensemble en arrière) : elle n'est pas redescendue.
  version_cle "$p" "$v"
  if [[ -n $VERSION_CLE ]]; then
    garder_cle "$p" "$v" "$note" "$change"
    return 0
  fi
  # Revérifié avant chaque copie : le cache est sur un disque de cet ordinateur, mais une copie abîmée ne doit pas
  # partir sur la clé. Une vérification impossible ici (dossier temporaire plein) est dite comme telle.
  # Pas dans un sous-shell : VERIFIEES (les empreintes signées) sert à la copie.
  version_verifiee "$d" "$v"
  case $? in
    0) ;;
    3) refuser "$p" "$change" "vérification impossible ici" \
      "Vérification de Claude Code $v impossible sur cet ordinateur (raison ci-dessus) : rien n'est posé." ;;
    *) refuser "$p" "$change" "cache qui ne se vérifie plus" \
      "Claude Code $v du cache ne se vérifie plus : rien n'est posé (relancer --chercher)." ;;
  esac
  # Un binaire déjà là sans ligne valable dans la note de dépôt (note absente ou abîmée, jeton changé, posé par autre
  # chose) : on ne sait pas d'où il vient. Remplacé par la copie vérifiée, et dit, comme un binaire changé.
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    c=Claude/$dossier/$bin
    [[ -e $p/$c || -L $p/$c ]] || continue
    grep -qE "^[0-9a-f]{64} ${c//./\\.}\$" "$note" 2>/dev/null && continue
    cmp -s "$d/$plat/$bin" "$p/$c" 2>/dev/null || inconnu+=" $c"
  done
  # Place : les binaires qui ne sont pas déjà là, plus la marge.
  besoin=$MARGE_MIO
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    cmp -s "$d/$plat/$bin" "$p/Claude/$dossier/$bin" 2>/dev/null ||
      besoin=$((besoin + $(stat -c %s "$d/$plat/$bin") / 1048576 + 1))
  done
  libre=$(($(df -Pk "$p" | awk 'NR == 2 { print $4 }') / 1024))
  ((libre >= besoin)) ||
    refuser "$p" "$change" "place insuffisante" "Place insuffisante sur la clé pour Claude Code ($besoin Mio voulus, $libre libres)."
  mkdir -p "$p/Claude/Linux" "$p/Claude/Windows" "$ETAT" ||
    refuser "$p" "$change" "dossiers pas créés" "Dossiers de Claude/ pas créés sur la clé."
  # La note du dernier dépôt, reprise : chaque binaire y est réécrit dès qu'il est posé et relu.
  NOTEE=()
  if [[ -f $note ]]; then
    while read -r s c; do
      [[ $s =~ ^[0-9a-f]{64}$ && $c =~ ^Claude/(Linux/claude|Windows/claude\.exe)$ ]] && NOTEE[$c]=$s
    done <"$note"
  fi
  # Chaque binaire : l'ancien retiré, le nouveau copié sous un nom provisoire, relu sur la clé et comparé à l'empreinte
  # signée, noté, puis renommé. Arrêté en route, la clé n'a jamais sous son vrai nom un binaire à moitié écrit ni un
  # binaire que la note ne connaît pas : pas de fausse alerte au dépôt suivant. Le nom provisoire est de ceux que le
  # déploiement dépose (src/protection/manifeste.rs) : la reprise d'un déploiement arrêté le retire.
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    c=Claude/$dossier/$bin part=Claude/$dossier/.$bin.part
    relache "$p/$c"
    if cmp -s "$d/$plat/$bin" "$p/$c" 2>/dev/null; then
      NOTEE[$c]=${VERIFIEES[$plat]}
      change=${change// $c/}
      continue
    fi
    if ! rm -f -- "${p:?}/$c" || ! cp -T --remove-destination -- "$d/$plat/$bin" "$p/$part"; then
      rm -f -- "${p:?}/$part"
      refuser "$p" "$change" "copie ratée" "Copie de $c ratée."
    fi
    sync -f "$p/$part" 2>/dev/null || true
    relache "$p/$part"
    sha=$(sha256sum <"$p/$part" | cut -d' ' -f1)
    if [[ $sha != "${VERIFIEES[$plat]}" ]]; then
      rm -f -- "${p:?}/$part"
      refuser "$p" "$change" "copie différente" "$c relu sur la clé : différent de la copie vérifiée, retiré."
    fi
    NOTEE[$c]=$sha
    ecrire_note "$note" || { rm -f -- "${p:?}/$part"; refuser "$p" "$change" "note pas écrite" "Note du dépôt pas écrite ($note)."; }
    mv -f -T -- "$p/$part" "$p/$c" || { rm -f -- "${p:?}/$part"; refuser "$p" "$change" "copie ratée" "$c pas renommé sur la clé."; }
    change=${change// $c/}
  done
  ecrire_note "$note" || refuser "$p" "$change" "note pas écrite" "Note du dépôt pas écrite ($note)."
  # Les petits fichiers : le lanceur et les consignes du dépôt, le manifeste signé et sa signature du cache, la clé de
  # confiance du dépôt (celle qui a vérifié le manifeste, jamais une copie du cache).
  for f in "${FIXES[@]}"; do
    copier_relu "outils/cle/Claude/$f" "$p/Claude/$f" || refuser "$p" "$change" "copie ratée" "Claude/$f pas copié sur la clé."
  done
  for f in "${SIGNES[@]}"; do
    s=$d/$f
    [[ $f != claude-code.asc ]] || s=$CLE_GPG
    copier_relu "$s" "$p/Claude/$f" || refuser "$p" "$change" "copie ratée" "Claude/$f pas copié sur la clé."
  done
  copier_relu "outils/cle/$LANCEUR" "$p/$LANCEUR" || refuser "$p" "$change" "copie ratée" "$LANCEUR pas copié sur la clé."
  sync -f "$p/Claude/CLAUDE.md" 2>/dev/null || true
  echo "✔ Claude Code $v sur la clé (vérifié, relu)."
  if [[ -n $vu ]]; then
    echo "✖ Sur la clé, changé depuis le dernier dépôt :$vu. Remplacé par la copie vérifiée ; un programme" >&2
    echo "  remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
    avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$vu. Remplacé par la copie vérifiée ; \
un programme remplacé est un piège possible."
    return 2
  fi
  if [[ -n $inconnu ]]; then
    echo "⚠ Déjà sur la clé, sans ligne dans la note de dépôt d'ici :$inconnu. Remplacé par la copie vérifiée ; s'il ne vient pas" >&2
    echo "  de Vanguard (autre ordinateur, autre jeton), regarder d'où il vient." >&2
    avertir "Claude Code inconnu sur la clé" "Déjà là sans note de dépôt :$inconnu. Remplacé par la copie vérifiée."
    return 2
  fi
}

# Avant la reprise d'un déploiement arrêté (outils/deployer.sh) : la reprise retire de la clé ce que le déploiement
# pose et qui diffère de sa référence, binaires de Claude compris, et poser ne verrait plus qu'un binaire absent. Un
# binaire changé pendant le voyage est donc dit ici, avant (notification, code 2) ; rien n'est retiré ni écrit.
relire() { # point
  local p=$1 jeton change
  [[ -d $p && -f $p/vanguard.cle ]] || erreur "$p n'est pas une clé VANGUARD."
  jeton=$(jeton_de "$p")
  [[ -n $jeton ]] || return 0
  change=$(changes "$p" "$(note_de "$jeton")")
  [[ -n $change ]] || return 0
  echo "✖ Sur la clé, changé depuis le dernier dépôt :$change. Dit avant la reprise du déploiement, qui peut le" >&2
  echo "  retirer ; un programme remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
  avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$change (dit avant la reprise du déploiement) ; \
un programme remplacé est un piège possible."
  return 2
}

etat() {
  local v d
  cache_present || return 0
  v=$(derniere)
  if active; then echo "Claude Code sur la clé : allumé ($REGLAGE)."; else echo "Claude Code sur la clé : coupé."; fi
  [[ -n $v ]] || { echo "Cache : vide ($CACHE)."; return 0; }
  d=$CACHE/$v
  echo "Cache : Claude Code $v ($CACHE)."
  if version_verifiee "$d" "$v"; then echo "  signature et empreintes : bonnes"; else echo "  ✖ ne se vérifie plus"; fi
}

case ${1:-} in
  --chercher) chercher ;;
  --cle) [[ $# == 2 ]] || erreur "Usage : outils/claude-cle.sh --cle POINT"; poser "$2" ;;
  --relire) [[ $# == 2 ]] || erreur "Usage : outils/claude-cle.sh --relire POINT"; relire "$2" ;;
  --etat) etat ;;
  --active) active ;;
  *) sed -n '2,17p' "$0" | sed 's/^# \?//'; [[ ${1:-} == -h || ${1:-} == --help ]] ;;
esac
