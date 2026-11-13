#!/usr/bin/env bash
# Claude Code (l'assistant en ligne de commande d'Anthropic) sur la clé VANGUARD, pour dépanner l'ordinateur d'un
# proche : « Depanner avec Claude.bat » sous Windows, Claude/depanner.sh sous Linux ou sur un système démarré depuis la
# clé (SystemRescue). Mode d'emploi : outils/cle/Claude/LISEZMOI.txt ; consignes données à Claude :
# outils/cle/Claude/CLAUDE.md.
#   outils/claude-cle.sh --chercher   la version « stable » téléchargée et vérifiée dans le cache (minuterie
#                                     vanguard-images.timer) ; déjà là : rien n'est téléchargé
#   outils/claude-cle.sh --cle POINT  pose la version vérifiée du cache sur la clé (outils/deployer.sh, qui tient le
#                                     verrou de la clé) ; réglage coupé : retire de la clé ce que ce script y a posé
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
# dernière vérifiée est refusée (un serveur piégé ne fait pas revenir une version à faille).
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
# Une autre source (un faux serveur, file://), dans les essais seulement (outils/essais-claude-cle.sh).
[[ -n ${VANGUARD_ESSAI:-} && -n ${VANGUARD_CLAUDE_SOURCE:-} ]] && SOURCE=$VANGUARD_CLAUDE_SOURCE
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/vanguard/claude-cle
# Un autre cache, dans les essais seulement : le ménage y efface des dossiers.
[[ -n ${VANGUARD_ESSAI:-} && -n ${VANGUARD_CLAUDE_CACHE:-} ]] && CACHE=$VANGUARD_CLAUDE_CACHE
CLE_GPG=$PWD/outils/cles-images/claude-code.asc
EMPREINTE_CLE=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
[[ -n ${VANGUARD_ESSAI:-} && -n ${VANGUARD_CLAUDE_CLE_GPG:-} ]] &&
  { CLE_GPG=$VANGUARD_CLAUDE_CLE_GPG; EMPREINTE_CLE=$VANGUARD_CLAUDE_EMPREINTE; }
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

tmp=""
erreur() { echo "✖ $*" >&2; exit 1; }
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
# (la raison sur la sortie d'erreur) sinon.
# Le trousseau jetable fermé : ses processus arrêtés et son dossier de sockets (/run/user/…/gnupg/d.…) retiré, sans
# quoi chaque vérification en laisse un.
trousseau_ferme() { # dossier
  gpgconf --homedir "$1" --kill all 2>/dev/null
  gpgconf --homedir "$1" --remove-socketdir 2>/dev/null
  rm -rf -- "$1"
}
manifeste_verifie() { # dossier
  local d=$1 trousseau statut
  trousseau=$(mktemp -d "${TMPDIR:-/tmp}/vanguard-claude-gpg.XXXXXX") || return 1
  chmod 700 "$trousseau"
  gpg --homedir "$trousseau" --quiet --batch --import "$CLE_GPG" 2>/dev/null
  # La signature détachée porte sur les octets du fichier : ceux-là sont copiés à part, puis lus après vérification,
  # pour qu'un fichier changé entre la vérification et la lecture ne passe pas.
  cp -- "$d/manifest.json" "$trousseau/manifest.json" 2>/dev/null
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
  local d
  for d in "$CACHE"/*/.verifiee; do
    [[ -f $d ]] && basename "${d%/.verifiee}"
  done | sort -V | tail -1
}

# Vérifie un dossier de version : manifeste signé, de cette version, et chaque binaire à sa taille et à son empreinte.
version_verifiee() { # dossier version
  local d=$1 v=$2 m ligne plat bin _dossier sha taille
  m=$(manifeste_verifie "$d") || return 1
  [[ $(champ version <<<"$m") == "$v" ]] || { echo "le manifeste signé n'est pas celui de la version $v" >&2; return 1; }
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin _dossier <<<"$ligne"
    read -r sha taille _ < <(champ "$plat" "$bin" <<<"$m") ||
      { echo "$plat : absent du manifeste signé, ou de forme inattendue" >&2; return 1; }
    [[ -f $d/$plat/$bin && ! -L $d/$plat/$bin ]] || { echo "$plat/$bin : absent" >&2; return 1; }
    [[ $(stat -c %s "$d/$plat/$bin") == "$taille" ]] || { echo "$plat/$bin : taille différente du manifeste" >&2; return 1; }
    [[ $(sha256sum "$d/$plat/$bin" | cut -d' ' -f1) == "$sha" ]] ||
      { echo "$plat/$bin : empreinte différente du manifeste signé" >&2; return 1; }
  done
}

chercher() {
  active || { echo "Claude Code sur la clé : coupé sur cet ordinateur (CLAUDE_CLE=oui dans $REGLAGE l'allume)."; return 0; }
  cache_present || return 0
  mkdir -p "$CACHE" || return 1
  exec 8>"$CACHE/.verrou"
  flock 8
  local v avant haute m ligne plat bin _dossier sha taille raison
  v=$(lire "$SOURCE/stable" | tr -d '[:space:]') || { echo "✖ Version stable de Claude Code illisible (Internet ?)." >&2; return 1; }
  [[ $v =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ ]] || { echo "✖ Version stable de forme inattendue : rien n'est téléchargé." >&2; return 1; }
  avant=$(derniere)
  # La plus haute version jamais vérifiée ici est notée hors du cache : un cache vidé ne fait pas revenir une
  # version plus ancienne.
  haute=$(head -c 32 "$ETAT/claude-cle-version" 2>/dev/null | tr -d '[:space:]')
  [[ $haute =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ ]] || haute=""
  haute=$(printf '%s\n' "$avant" "$haute" | sed '/^$/d' | sort -V | tail -1)
  if [[ $v == "$avant" ]]; then
    # Notée ici aussi : un cache rempli autrement (ou une note perdue) garde sa protection contre le retour.
    mkdir -p "$ETAT" && echo "$haute" >"$ETAT/claude-cle-version"
    echo "Claude Code $v : déjà dans le cache, vérifié."
    return 0
  fi
  if [[ -n $haute && $(printf '%s\n' "$v" "$haute" | sort -V | tail -1) != "$v" ]]; then
    echo "✖ Le serveur annonce Claude Code $v, plus ancien que la $haute déjà vérifiée : refusé." >&2
    avertir "Claude Code : version plus ancienne refusée" "Le serveur annonce la $v ; la $haute a déjà été vérifiée."
    return 1
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
  if ! m=$(manifeste_verifie "$tmp" 2>"$tmp/.raison"); then
    raison=$(cat "$tmp/.raison")
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
  if ! raison=$(version_verifiee "$tmp" "$v" 2>&1); then
    echo "✖ Claude Code $v refusé : $raison." >&2
    avertir "Claude Code $v refusé" "$raison"
    return 1
  fi
  cp -- "$CLE_GPG" "$tmp/claude-code.asc"
  rm -f "$tmp/.raison"
  rm -rf "${CACHE:?}/$v"
  # Un mv raté laisse le trap effacer le dossier temporaire.
  mv -- "$tmp" "$CACHE/$v" || { echo "✖ Claude Code $v : pas rangé dans le cache." >&2; return 1; }
  trap - EXIT
  touch "$CACHE/$v/.verifiee"
  # Deux versions gardées : la nouvelle, et celle d'avant, le temps que la clé passe à la nouvelle.
  local d
  mkdir -p "$ETAT" && echo "$v" >"$ETAT/claude-cle-version"
  # Seulement les dossiers de version (nom x.y.z, avec leur manifeste) : rien d'autre n'est effacé.
  for d in "$CACHE"/*/; do
    d=${d%/}
    [[ ${d##*/} =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$ && -f $d/manifest.json && ! -L $d ]] || continue
    [[ ${d##*/} == "$v" || ${d##*/} == "$avant" ]] || rm -rf -- "$d"
  done
  echo "✔ Claude Code $v vérifié (signature d'Anthropic, empreintes) dans le cache."
}

# Le SHA-256 de chaque binaire posé sur la clé, noté ici au jeton de la clé (jamais sur la clé).
note_de() { echo "$ETAT/claude-cle-$1.sha256"; }

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
retirer_change() { # point changes raison
  local p=$1 chemin
  for chemin in $2; do
    [[ $chemin =~ ^Claude/(Linux/claude|Windows/claude\.exe)$ && ! -L $p/$chemin ]] && rm -f -- "${p:?}/$chemin"
  done
  echo "✖ Sur la clé, changé depuis le dernier dépôt :$2. Pas de copie vérifiée à remettre ($3) : retiré." >&2
  echo "  Un programme remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
  avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$2. Retiré de la clé ($3) ; \
un programme remplacé est un piège possible."
  exit 2
}

poser() { # point
  local p=$1 jeton v d note ligne plat bin dossier change="" besoin libre sha chemin
  [[ -d $p && -f $p/vanguard.cle ]] || erreur "$p n'est pas une clé VANGUARD."
  # Ce qui a changé pendant le voyage, d'abord, quoi qu'il arrive ensuite (coupé, cache absent, place) : relu
  # entier, comparé à la note du dernier dépôt.
  jeton=$(head -c 64 "$p/vanguard.jeton" 2>/dev/null | tr -d '[:space:]' | tr 'A-F' 'a-f')
  if [[ $jeton =~ ^[0-9a-f]{32}$ ]]; then
    note=$(note_de "$jeton")
    if [[ -f $note ]]; then
      while read -r sha chemin; do
        [[ $chemin =~ ^Claude/(Linux/claude|Windows/claude\.exe)$ && -f $p/$chemin ]] || continue
        [[ $(sha256sum "$p/$chemin" | cut -d' ' -f1) == "$sha" ]] || change+=" $chemin"
      done <"$note"
    fi
  fi
  if ! active; then
    retirer "$p" "${note:-}"
    [[ -z $change ]] || retirer_change "$p" "$change" "Claude Code coupé"
    return 0
  fi
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
  # Revérifié avant chaque copie : le cache est sur un disque de cet ordinateur, mais une copie abîmée ne doit pas
  # partir sur la clé.
  if ! version_verifiee "$d" "$v"; then
    [[ -z $change ]] || retirer_change "$p" "$change" "cache qui ne se vérifie plus"
    erreur "Claude Code $v du cache ne se vérifie plus : rien n'est posé (relancer --chercher)."
  fi
  for chemin in "$p/Claude" "$p/Claude/Linux" "$p/Claude/Windows" "$p/$LANCEUR"; do
    [[ ! -L $chemin ]] || erreur "$chemin est un lien symbolique : rien n'est posé."
  done
  [[ $jeton =~ ^[0-9a-f]{32}$ ]] || erreur "Jeton de la clé illisible : rien n'est posé."
  # Un binaire déjà là sans note de dépôt (jeton changé, note perdue, posé par autre chose) : on ne sait pas d'où il
  # vient. Remplacé par la copie vérifiée, et dit, comme un binaire changé.
  local inconnu=""
  if [[ ! -f $note ]]; then
    for ligne in "${PLATEFORMES[@]}"; do
      read -r plat bin dossier <<<"$ligne"
      [[ ! -e $p/Claude/$dossier/$bin ]] || cmp -s "$d/$plat/$bin" "$p/Claude/$dossier/$bin" || inconnu+=" Claude/$dossier/$bin"
    done
  fi
  # Place : les binaires qui ne sont pas déjà là, plus la marge.
  besoin=$MARGE_MIO
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    cmp -s "$d/$plat/$bin" "$p/Claude/$dossier/$bin" 2>/dev/null ||
      besoin=$((besoin + $(stat -c %s "$d/$plat/$bin") / 1048576 + 1))
  done
  libre=$(($(df -Pk "$p" | awk 'NR == 2 { print $4 }') / 1024))
  if ((libre < besoin)); then
    [[ -z $change ]] || retirer_change "$p" "$change" "place insuffisante"
    erreur "Place insuffisante sur la clé pour Claude Code ($besoin Mio voulus, $libre libres)."
  fi
  mkdir -p "$p/Claude/Linux" "$p/Claude/Windows" "$ETAT" || return 1
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    cmp -s "$d/$plat/$bin" "$p/Claude/$dossier/$bin" 2>/dev/null || cp -f -- "$d/$plat/$bin" "$p/Claude/$dossier/$bin" ||
      { [[ -z $change ]] || retirer_change "$p" "$change" "copie ratée"; erreur "Copie de $dossier/$bin ratée."; }
  done
  for f in "${FIXES[@]}"; do
    cmp -s "outils/cle/Claude/$f" "$p/Claude/$f" 2>/dev/null || cp -f -- "outils/cle/Claude/$f" "$p/Claude/$f"
  done
  for f in "${SIGNES[@]}"; do
    cmp -s "$d/$f" "$p/Claude/$f" 2>/dev/null || cp -f -- "$d/$f" "$p/Claude/$f"
  done
  cmp -s "outils/cle/$LANCEUR" "$p/$LANCEUR" 2>/dev/null || cp -f -- "outils/cle/$LANCEUR" "$p/$LANCEUR"
  sync -f "$p/Claude/Windows/claude.exe" 2>/dev/null || true
  # Relire la clé, pas la mémoire : les pages de la copie sont lâchées (après sync, elles sont propres).
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    python3 -I -c 'import os,sys
fd=os.open(sys.argv[1],os.O_RDONLY)
os.posix_fadvise(fd,0,0,os.POSIX_FADV_DONTNEED)
os.close(fd)' "$p/Claude/$dossier/$bin" 2>/dev/null || true
  done
  # La note : relue sur la clé après la copie, pour noter ce qui y est vraiment.
  {
    for ligne in "${PLATEFORMES[@]}"; do
      read -r plat bin dossier <<<"$ligne"
      echo "$(sha256sum "$p/Claude/$dossier/$bin" | cut -d' ' -f1) Claude/$dossier/$bin"
    done
  } >"$note.tmp" && mv -f "$note.tmp" "$note"
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    cmp -s "$d/$plat/$bin" "$p/Claude/$dossier/$bin" || erreur "$dossier/$bin relu sur la clé : différent de la copie vérifiée."
  done
  echo "✔ Claude Code $v sur la clé (vérifié, relu)."
  if [[ -n $change ]]; then
    echo "✖ Sur la clé, changé depuis le dernier dépôt :$change. Remplacé par la copie vérifiée ; un programme" >&2
    echo "  remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
    avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$change. Remplacé par la copie vérifiée ; \
un programme remplacé est un piège possible."
    return 2
  fi
  if [[ -n $inconnu ]]; then
    echo "⚠ Déjà sur la clé, sans note de dépôt ici :$inconnu. Remplacé par la copie vérifiée ; s'il ne vient pas" >&2
    echo "  de Vanguard (autre ordinateur, autre jeton), regarder d'où il vient." >&2
    avertir "Claude Code inconnu sur la clé" "Déjà là sans note de dépôt :$inconnu. Remplacé par la copie vérifiée."
    return 2
  fi
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
  --etat) etat ;;
  --active) active ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \?//'; [[ ${1:-} == -h || ${1:-} == --help ]] ;;
esac
