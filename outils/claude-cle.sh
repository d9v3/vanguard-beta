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
#   outils/claude-cle.sh --etat       ce qui est dans le cache (code 1 : ne se vérifie plus ; 3 : pas vérifiable ici)
#   outils/claude-cle.sh --accepter-version X  baisse la protection contre le retour jusqu'à X (terminal, confirmé,
#                                     accord polkit, noté, notifié) ; --annuler-acceptation la remet
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
# Limite, dite (LISEZMOI) : « stable » est un pointeur du serveur, pas signé. La signature prouve qu'une version vient
# d'Anthropic, pas qu'elle est la « stable » du jour : une version authentique d'un autre canal, plus récente, peut
# être prise par --chercher, et bloque ensuite les plus anciennes (dit à chaque fois). Le blocage se lève par le
# choix du propriétaire seulement : outils/claude-cle.sh --accepter-version X (dans un terminal : montre ce qui
# change, demande de taper « ACCEPTER X » puis l'accord polkit, journalise d'abord, déplace les versions plus hautes
# du cache, note et notifie ; annulable par --annuler-acceptation). Écrire la note à la main ne suffit pas : le cache
# garde la version trop haute. Une version venue par la clé, elle, ne bloque rien : la clé la garde, la note de cet
# ordinateur ne monte pas.
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
#
# La porte de --accepter-version et --annuler-acceptation, AVANT toute commande : écrite seulement avec des
# affectations, des expansions et le mot-clé [[ ]], qu'aucune fonction ne remplace. Hors mode POSIX, bash cherche
# une fonction avant tout builtin, même exec, exit, builtin, declare, read, printf ou « : » : une fonction exportée
# (variable BASH_FUNC_nom%%) remplaçait chaque refus écrit avec une commande, et le script baissait la protection
# en disant « rien changé ». La porte lit l'environnement de départ de ce bash (/proc/$$/environ, qu'aucune
# commande ne réécrit) et refuse une fonction exportée, BASH_ENV (un fichier lu par bash avant ce script), SHELLOPTS
# ou BASHOPTS (options posées avant la première ligne), ENV, et une lecture vide ou impossible. Son arrêt est
# l'expansion ${refus:?…} d'une variable vide, qui arrête un bash non interactif (code 1) sans passer par aucun nom
# de commande. Les octets nuls de environ sont perdus par $(<…) : les noms se suivent sans séparateur, d'où ENV
# testé comme variable (« *ENV=* » prendrait VIRTUAL_ENV) ; bash ne lit ENV qu'en interactif, et seul un fichier
# BASH_ENV (refusé ici) pourrait l'effacer avant la porte. PS4 est remis d'abord : sous traçage (bash -x), un PS4
# hérité est développé à chaque commande tracée, juste avant elle ; « $((porte=1)) » réécrivait ainsi porte entre sa
# lecture et le [[ ]] qui la juge, et la porte s'ouvrait. Il ne l'est plus qu'une fois, sur la ligne qui le remet,
# avant que la porte ne lise environ.
# La porte compare des OCTETS (des noms de variables) avec un motif de [[ ]], qui lit des CARACTÈRES selon la locale.
# Dans une locale multi-octets autre que UTF-8 (GBK, BIG5, SJIS), le dernier octet d'une valeur et la lettre qui le
# suit formaient un seul caractère : « *BASH_FUNC_* » ne voyait plus le nom suivant, et la porte s'ouvrait. Une
# telle locale se fabrique sans root (localedef, puis LOCPATH vers son dossier) ; LANG ou LC_CTYPE suffisaient aussi.
# D'où LC_ALL=C (bash refait setlocale à l'affectation, et LC_ALL passe devant LANG et LC_*) et LOCPATH vidé, par
# affectation, avant la lecture : le motif redevient une comparaison d'octets. Rien d'autre ne change le motif ici :
# nocasematch ne vient que de BASHOPTS (refusé ; il élargirait le refus), extglob est toujours actif dans [[ ]] et
# aucun motif d'ici n'en use, GLOBIGNORE, IFS et noglob ne touchent ni [[ ]] ni ces affectations (vérifié, essais).
# --accepter-version et --annuler-acceptation tournent donc en locale C : leurs messages sont écrits tels quels.
# Pourquoi pas un « #!/usr/bin/env -S -i … » qui nettoie l'environnement : « bash outils/claude-cle.sh » (deployer.sh,
# les essais, quiconque) lit le fichier sans passer par le shebang, et la porte doit tenir dans les deux cas.
# Passée la porte, aucune fonction ni aucun alias ne viennent de l'environnement : les « exit 1 », exec et erreur de
# la suite sont les vrais builtins. Portée, dite : la porte arrête les pièges d'environnement hérités ou posés par
# mégarde. Pas un attaquant qui a déjà le compte : du code qui tourne dans ce bash avant la porte (LD_PRELOAD, un
# bash -i, -l ou -c, un script qui source celui-ci, un fichier BASH_ENV écrit pour la tromper, qui peut poser un
# alias sur [[) passe à côté ; il peut aussi baisser la protection à la main (plus bas, accepter), et une telle
# baisse n'est ni signalée ni notée.
PS4='+ '
if [[ ${1-} == --accepter-version || ${1-} == --annuler-acceptation ]]; then
  # shellcheck disable=SC2034 # LOCPATH : lue par la libc, pas par ce script
  LC_ALL=C LOCPATH=
  { porte=$(</proc/$$/environ); } 2>/dev/null
  [[ -n $porte && $porte != *BASH_FUNC_* && $porte != *BASH_ENV=* && $porte != *SHELLOPTS=* && $porte != *BASHOPTS=* &&
    -z ${BASH_ENV+x}${ENV+x} ]] ||
    refus='' porte=${refus:?Environnement pas propre (fonction de bash exportée, BASH_ENV, ENV, SHELLOPTS ou \
BASHOPTS, ou /proc/$$/environ illisible) : rien changé.}
  porte=
fi
set -uo pipefail
# Le fichier lancé, en chemin absolu, pris AVANT le cd : « outils/.. » (chemin relatif) était d'abord cherché dans
# CDPATH, et la relance plus bas lançait alors un autre claude-cle.sh, celui du dossier trouvé par CDPATH. Un chemin
# absolu ne passe jamais par CDPATH ; CDPATH vidé en plus pour ce cd.
ICI=${BASH_SOURCE[0]}
[[ $ICI == /* ]] || ICI=$PWD/$ICI
CDPATH='' cd -- "${ICI%/*}/.." || exit 1
# --accepter-version et --annuler-acceptation tournent dans un bash propre, une fois la porte passée (plus haut) :
# relancés par /usr/bin/env -i (PATH fixe, ni SHELLOPTS ni variable inconnue), avec les seules variables de GARDEES.
# Une seule liste fermée, pour la relance comme pour la relecture qui suit : une variable hors de GARDEES n'est pas
# transmise, et refusée si elle est là quand même (la marque forgée). Les VANGUARD_CLAUDE_* y sont nommées une à une
# (les crochets des essais, lus seulement sous VANGUARD_ESSAI, plus bas) : une autre, même au nom proche, est laissée
# tomber par la relance, jamais transmise puis refusée par ce même script.
# Relancé, la marque VANGUARD_CLE_RELANCE n'est pas crue (l'appelant peut l'écrire lui-même) : l'environnement de
# départ de ce bash est relu dans /proc/$$/environ, et tout nom hors de GARDEES y est refusé ; ses options aussi ($-,
# SHELLOPTS, BASHOPTS : celles de la relance, rien d'autre ; R10-PORTE-1, plus bas). Au second rang, après
# la porte (qui a déjà refusé fonctions exportées et BASH_ENV) : refusé aussi s'il reste une fonction, un alias, un
# piège (trap) ou un builtin coupé (enable -n), posés par du code lancé dans ce bash avant lui (bash -c, un script qui
# source celui-ci) ; utile contre une erreur, pas contre un programme écrit exprès (voir la portée de la porte). Sous
# VANGUARD_ESSAI, le PATH des essais est gardé (leurs doublures de notify-send et systemctl) : la fenêtre polkit et la
# lecture au clavier ne passent jamais par le PATH.
GARDEES=(VANGUARD_CLE_RELANCE PATH HOME USER LOGNAME TERM LANG LANGUAGE LC_ALL LC_CTYPE LC_MESSAGES TMPDIR XDG_CACHE_HOME
  XDG_CONFIG_HOME XDG_STATE_HOME XDG_RUNTIME_DIR DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS VANGUARD_ESSAI
  VANGUARD_CLAUDE_SOURCE VANGUARD_CLAUDE_CACHE VANGUARD_CLAUDE_DEPOT VANGUARD_CLAUDE_CLE_GPG VANGUARD_CLAUDE_EMPREINTE)
# Les mots précédés de « \ » (\builtin, \read…) ne passent pas par les alias : voulu.
# shellcheck disable=SC1001,SC1012
case ${1:-} in
  --accepter-version | --annuler-acceptation)
    if [[ ${VANGUARD_CLE_RELANCE:-} != 1 ]]; then
      garder=(VANGUARD_CLE_RELANCE=1 PATH=/usr/local/bin:/usr/bin:/bin)
      [[ -z ${VANGUARD_ESSAI:-} ]] || garder=(VANGUARD_CLE_RELANCE=1 "PATH=$PATH")
      for n in "${GARDEES[@]:2}"; do
        [[ -z ${!n+x} ]] || garder+=("$n=${!n}")
      done
      # La porte passée, exec et exit sont les vrais builtins : aucune fonction ne peut les remplacer ici.
      exec /usr/bin/env -i "${garder[@]}" /bin/bash --noprofile --norc -- "$ICI" "$@"
      echo "✖ Relance dans un bash propre impossible (/usr/bin/env, /bin/bash) : rien changé." >&2
      exit 1
    fi
    sale=""
    # R10-PORTE-1 : la marque forgée sautait la relance, seul endroit qui remet à zéro les options de bash ; celles
    # de la ligne de commande (bash -f, -e, -C, -O nocasematch…) ne sont pas dans l'environnement, la porte ne les
    # voit pas. Sous -f, « "$CACHE"/*/ » restait un motif littéral : rien mis de côté, et pourtant « ✔ ». La marque
    # ne suffit donc jamais : l'état du shell doit être celui de la relance, mesuré par « /usr/bin/env -i /bin/bash
    # --noprofile --norc » de bash 5.3, après « set -uo pipefail » plus haut. Rien que des expansions et [[ ]] (un
    # mot réservé) : aucune commande qu'une fonction remplacerait. $-, SHELLOPTS et BASHOPTS sont tenus par bash
    # (en lecture seule ; hérités, refusés par la porte). Un bash plus récent aux défauts changés est refusé : le
    # sens sûr, et le témoin des essais (l'environnement exact de la relance) le montre aussitôt.
    [[ $- == "huB" && $SHELLOPTS == "braceexpand:hashall:interactive-comments:nounset:pipefail" &&
      $BASHOPTS == "checkwinsize:cmdhist:complete_fullquote:extquote:force_fignore:globasciiranges:globskipdots:\
hostcomplete:interactive_comments:patsub_replacement:progcomp:promptvars:sourcepath" ]] ||
      sale+=" (options de bash)"
    [[ -z $(\builtin \declare -F) ]] || sale+=" (une fonction de bash)"
    if [[ -r /proc/$$/environ ]]; then
      while IFS= \builtin \read -r -d '' e; do
        n=${e%%=*} ok=0
        for g in "${GARDEES[@]}"; do [[ $n != "$g" ]] || ok=1; done
        ((ok)) || sale+=" ${n:0:40}"
      done </proc/$$/environ
    else
      sale+=" (/proc/$$/environ illisible)"
    fi
    [[ -z $(\builtin \alias -p) ]] || sale+=" (un alias)"
    # Un signal ignoré au départ (trap -- '' SIGPIPE, hérité d'un appelant comme python) ne lance rien : pas compté.
    pieges=$(\builtin \trap -p)
    while IFS= \builtin \read -r e; do
      [[ -z $e || $e =~ ^trap\ --\ \'\'\ SIG[A-Z0-9+-]+$ ]] || { sale+=" (un piège trap)"; break; }
    done <<<"$pieges"
    [[ -z $(\builtin \enable -n) ]] || sale+=" (un builtin coupé)"
    if [[ -n $sale ]]; then
      echo "✖ Environnement pas propre :$sale. Rien changé." >&2
      exit 1
    fi
    unset sale e n ok g pieges
    ;;
esac

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
# La marque d'une vérification impossible sur cet ordinateur (impossible, plus bas) : notifiée une fois par raison.
IMPOSSIBLE=$ETAT/claude-cle-impossible
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
  # La vérification a pu se faire ici, bonne ou fausse : une panne notée avant (impossible, plus bas) est finie, et la
  # même panne, revenue plus tard, sera notifiée de nouveau.
  rm -f -- "$IMPOSSIBLE" 2>/dev/null
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
    [[ $(sha256sum <"$d/$plat/$bin" | cut -d' ' -f1) == "$sha" ]] ||
      { echo "$plat/$bin : empreinte différente du manifeste signé" >&2; return 1; }
    VERIFIEES[$plat]=$sha
  done
  return 0
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
# La raison arrive déjà préfixée (« vérification impossible ici : … ») : le préfixe n'est pas redit. Une
# vérification allée au bout, bonne ou fausse, efface la marque (manifeste_verifie) : la même panne, revenue plus
# tard, est notifiée de nouveau.
impossible() { # raison
  local r=${1#vérification impossible ici : }
  echo "✖ Vérification de Claude Code impossible sur cet ordinateur ($r) : rien n'est effacé ni téléchargé." >&2
  if [[ $(cat "$IMPOSSIBLE" 2>/dev/null) != "$r" ]]; then
    avertir "Claude Code : vérification impossible" "$r. Rien n'est effacé ; la clé garde ce qu'elle a."
    mkdir -p "$ETAT" 2>/dev/null && echo "$r" >"$IMPOSSIBLE" 2>/dev/null
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

# Le déblocage, choix du propriétaire seulement : --accepter-version X baisse la protection contre le retour en
# arrière jusqu'à X (une version trop haute prise une fois, par erreur ou par un serveur piégé, bloquait sinon toutes
# les plus anciennes, sans issue : la note seule ne suffit pas, le cache garde la version trop haute). X doit exister :
# dans le cache, ou la dernière annonce refusée par --chercher. Dans un terminal seulement ; montre ce qui change ;
# demande de taper « ACCEPTER X », puis l'accord fort du propriétaire (fenêtre polkit d'administrateur) ; les dossiers
# du cache plus hauts que X sont DÉPLACÉS (jamais effacés) dans un dossier daté du cache (mis-de-cote-…) ; la note
# devient X ; ces versions sont notées « écartées » (la clé ne les garde plus) ; c'est écrit au journal AVANT de rien
# changer (pas de journal, pas de baisse), et notifié après. La trace de l'acceptation (note d'avant, versions
# déplacées) est rangée hors du cache, dans le dossier d'état. Annulable : --annuler-acceptation (terminal et
# confirmation tapée, sans polkit : une hausse de protection) remet les versions de la trace qui se vérifient, la note
# d'avant, et retire les versions écartées ; une version pas remise pour une panne passagère (vérification
# impossible pour l'instant, déplacement raté) reste écartée et dans la trace : « annulation partielle », à relancer.
# Portée, dite : le terminal arrête une minuterie, un tuyau, une entrée redirigée, pas un programme qui se fabrique un
# terminal ; la fenêtre polkit, elle, demande le mot de passe du propriétaire. Un programme qui tourne déjà sous ce
# compte peut toujours déplacer les dossiers et réécrire la note à la main, sans cette commande : ni polkit ni
# notification ne l'en empêchent, et une telle baisse ne laisse ni notification ni ligne au journal (seules les
# baisses faites par cette commande sont notées et notifiées ; LISEZMOI).
ECARTEES=$ETAT/claude-cle-ecartees
JOURNAL=$ETAT/claude-cle-journal
ACCEPTATIONS=$ETAT/claude-cle-acceptations
ecartee() { # version : code 0 si --accepter-version l'a mise de côté
  grep -qxF -- "$1" "$ECARTEES" 2>/dev/null
}
# Une ligne datée au journal ; code 1 si elle n'a pas pu s'écrire (jamais suivi d'un « Journal : … »).
journal() { # texte
  { mkdir -p -- "$ETAT" && [[ ! -L $JOURNAL ]] &&
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >>"$JOURNAL"; } 2>/dev/null
}
FORME_VERSION='^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$'
# La forme simple, celle qu'on tape : sans zéro en tête. 2.00.6 n'est pas 2.0.6 pour sort -V : elle ferait mettre de
# côté la vraie 2.0.6.
FORME_SIMPLE='^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,5})$'
# Le verrou partagé avec --chercher, jamais tenu pendant une attente au clavier ; une recherche en cours est attendue
# 10 minutes au plus, et c'est dit.
verrou() {
  exec 8>>"${XDG_RUNTIME_DIR:-/tmp}/vanguard-claude-cle.lock" || return 1
  flock -n 8 && return 0
  echo "· Une recherche de Claude Code tient le verrou (téléchargement en cours ?) : attente, 10 minutes au plus…"
  flock -w 600 8
}
# L'accord fort du propriétaire pour une baisse de protection : la fenêtre d'administrateur du bureau (polkit), qui
# ne lance que /usr/bin/true. Un refus, une fenêtre fermée, pkexec absent : rien changé. Chemins absolus, appelés par
# « builtin command » (une fonction du même nom ne passe pas devant) ; ni option ni variable de ce script ne la
# sautent (les essais changent une COPIE de ce script, jamais celui-ci). Ce que la fenêtre autorise y est écrit :
# pkexec met la ligne de commande dans sa demande (« Authentication is needed to run `$(cmdline_short)' as the super
# user », relu dans /usr/bin/pkexec, polkit 128), d'où l'argument lisible, ignoré par true ; la version (forme
# simple, relue ici) est son seul morceau variable, et la ligne tient en 80 signes, sans quoi pkexec la raccourcit.
# Limite, dite : c'est la demande générale de pkexec (« exécuter en super-utilisateur »), pas une action polkit à
# Vanguard (il faudrait poser un fichier d'action, root) ; un programme du même compte peut ouvrir une fenêtre au
# même texte.
accord_fort() { # version
  [[ $1 =~ $FORME_SIMPLE ]] || { echo "✖ Version de forme inattendue : pas d'accord demandé." >&2; return 1; }
  echo "Accord de l'administrateur demandé (fenêtre polkit : « Vanguard : baisse de protection, Claude Code $1 »)…"
  [[ -x /usr/bin/pkexec ]] || { echo "✖ /usr/bin/pkexec absent : pas d'accord fort possible." >&2; return 1; }
  builtin command /usr/bin/pkexec --keep-cwd /usr/bin/true "Vanguard : baisse de protection, Claude Code $1"
}
# Ce qu'une acceptation de X changerait, sans rien écrire : notee, note_txt et hauts, ceux de l'appelant.
plan_accepter() { # version
  local d n
  hauts=() notee="" note_txt="absente"
  if notee=$(haute_notee 2>/dev/null); then
    [[ -z $notee ]] || note_txt=$notee
  else
    notee="" note_txt="abîmée"
  fi
  for d in "$CACHE"/*/; do
    d=${d%/}
    n=${d##*/}
    [[ $n =~ $FORME_VERSION && ! -L $d ]] || continue
    plus_ancienne "$1" "$n" && hauts+=("$n")
  done
}
accepter() { # version
  local x=$1 notee note_txt hauts=() n vu sauvegarde trace rep refus
  [[ $x =~ $FORME_SIMPLE ]] || erreur "Version de forme inattendue : « $x » (par exemple 2.0.6, sans zéro en tête). Rien changé."
  [[ -t 0 && -t 1 ]] ||
    erreur "--accepter-version baisse une protection : seulement dans un terminal, avec une confirmation tapée. Rien changé."
  cache_present || erreur "Cache absent : rien changé."
  mkdir -p "$CACHE" || erreur "Cache pas créé : rien changé."
  # Une version qui existe : une faute de frappe (2.0.60) ne baisse rien.
  refus=$(head -c 64 -- "$ETAT/claude-cle-refus" 2>/dev/null)
  refus=${refus%%<*}
  [[ (-d $CACHE/$x && ! -L $CACHE/$x && -f $CACHE/$x/.verifiee) || $x == "$refus" ]] ||
    erreur "La $x n'est ni dans le cache ni la dernière version annoncée puis refusée par --chercher (faute de frappe ?) : rien changé."
  plan_accepter "$x"
  if ((${#hauts[@]} == 0)) && [[ $note_txt != abîmée ]] && { [[ -z $notee ]] || ! plus_ancienne "$x" "$notee"; }; then
    echo "Rien à baisser : ni la note (${note_txt}) ni le cache ne dépassent la $x."
    return 0
  fi
  echo "Ceci BAISSE la protection de Claude Code contre le retour à une version plus ancienne :"
  echo "  note de la plus haute version vérifiée : $note_txt → $x ($NOTE_VERSION)"
  if ((${#hauts[@]})); then
    echo "  mis de côté (déplacés, pas effacés) : ${hauts[*]}, dans $CACHE/mis-de-cote-…"
    echo "  une clé qui porte l'une d'elles ne la garde plus : la version du cache la remplace au dépôt suivant"
  fi
  echo "  ensuite, une annonce du serveur à partir de la $x est acceptée"
  echo "Annulable : outils/claude-cle.sh --annuler-acceptation. Pour confirmer, taper : ACCEPTER $x"
  echo "(une fenêtre d'administrateur suit)"
  # Ni l'attente au clavier ni la fenêtre polkit ne tiennent le verrou : la minuterie n'attend pas une personne. Tout
  # est recalculé sous le verrou, et refusé si ça a changé entre-temps.
  builtin read -r rep || rep=""
  [[ $rep == "ACCEPTER $x" ]] || { echo "Pas confirmé : rien changé."; return 1; }
  accord_fort "$x" || erreur "Accord de l'administrateur (polkit) pas donné : rien changé."
  vu="$note_txt|${hauts[*]}"
  verrou || erreur "Verrou pas pris : rien changé."
  plan_accepter "$x"
  [[ "$note_txt|${hauts[*]}" == "$vu" ]] ||
    erreur "La note ou le cache a changé pendant la question : rien changé (relancer --accepter-version)."
  # Noté AVANT de rien changer : une baisse qui ne peut pas être notée n'est pas faite, et une baisse arrêtée en route
  # laisse au moins cette ligne.
  journal "accepter-version $x : début ; note $note_txt → $x ; à mettre de côté : ${hauts[*]:-rien}" ||
    erreur "Journal ($JOURNAL) pas écrit : rien changé."
  sauvegarde=$(mktemp -d "$CACHE/mis-de-cote-$(date '+%Y%m%d-%H%M%S').XXXXXX") || erreur "Dossier de sauvegarde pas créé : rien changé."
  # La trace, hors du cache (le cache peut être un lien vers un autre disque) : seule elle dit ce qu'on annule.
  trace=$ACCEPTATIONS/${sauvegarde##*/}
  if ! { mkdir -p -- "$ACCEPTATIONS" && printf '%s\n' "$note_txt" "${hauts[@]}" >"$trace"; } 2>/dev/null; then
    rm -f -- "${trace:?}"
    rmdir -- "$sauvegarde"
    erreur "Trace de l'acceptation pas écrite ($trace) : rien changé."
  fi
  for n in "${hauts[@]}"; do
    mv -T -- "$CACHE/$n" "$sauvegarde/$n" ||
      erreur "$n pas déplacé dans $sauvegarde : la note n'est pas changée (--annuler-acceptation remet ce qui l'a été)."
  done
  if ((${#hauts[@]})); then
    printf '%s\n' "${hauts[@]}" >>"$ECARTEES" || erreur "Liste des versions écartées pas écrite : la note n'est pas changée."
  fi
  noter_haute "$x" || return 1
  rm -f -- "$ETAT/claude-cle-refus"
  # Chaque baisse réussie est notifiée : faite sans le propriétaire, elle se voit.
  avertir "Claude Code : protection baissée" "Version $x acceptée (note $note_txt → $x ; mis de côté : ${hauts[*]:-rien}). \
Pas vous ? outils/claude-cle.sh --annuler-acceptation"
  echo "✔ Version $x acceptée. Note : $x ; mis de côté : ${hauts[*]:-rien} ($sauvegarde)."
  if journal "accepter-version $x : fait ($sauvegarde)"; then
    echo "  Journal : $JOURNAL. Pour annuler : outils/claude-cle.sh --annuler-acceptation"
  else
    echo "⚠ La fin n'a pas pu être notée au journal ($JOURNAL) ; le début l'est. Pour annuler :" \
      "outils/claude-cle.sh --annuler-acceptation" >&2
  fi
}
# La dernière trace d'acceptation (nom daté, fichier ordinaire du dossier d'état), ou rien.
derniere_trace() {
  local f t=""
  for f in "$ACCEPTATIONS"/mis-de-cote-*; do
    [[ ${f##*/} =~ ^mis-de-cote-[0-9]{8}-[0-9]{6}\.[A-Za-z0-9]{6}$ && -f $f && ! -L $f ]] && t=${f##*/}
  done
  echo "$t"
}
# Défait la dernière acceptation, d'après sa trace (dossier d'état), jamais d'après ce que le cache contient : chaque
# version de la trace est remise si elle se vérifie (signée, entière), sinon laissée de côté et dite ; la note est
# remise à la plus haute des deux (celle d'avant, celle d'aujourd'hui ; abîmée, refusé). Une version remise, ou refusée pour de bon
# (absente, ne se vérifie pas), n'est plus écartée et sort de la trace. Une panne passagère (vérification impossible
# ici, code 3 : dossier temporaire plein ; déplacement raté) ne consomme rien : la version reste écartée et dans la
# trace, l'annulation est dite partielle (code 2), et une relance la reprend.
annuler_acceptation() {
  local t s v w avant notee rep raison rc passe lignes=() versions=() remis=() laisses=() passagers=() reste
  [[ -t 0 && -t 1 ]] ||
    erreur "--annuler-acceptation : seulement dans un terminal, avec une confirmation tapée. Rien changé."
  cache_present || erreur "Cache absent : rien changé."
  t=$(derniere_trace)
  [[ -n $t ]] || { echo "Aucune acceptation à annuler (pas de trace dans $ACCEPTATIONS)."; return 0; }
  mapfile -t lignes <"$ACCEPTATIONS/$t" || erreur "Trace $ACCEPTATIONS/$t illisible : rien changé."
  avant=${lignes[0]:-}
  versions=("${lignes[@]:1}")
  [[ $avant =~ $FORME_VERSION || $avant == absente || $avant == abîmée ]] ||
    erreur "Trace $ACCEPTATIONS/$t abîmée (note d'avant « $avant ») : rien changé."
  for v in "${versions[@]}"; do
    [[ $v =~ $FORME_VERSION ]] || erreur "Trace $ACCEPTATIONS/$t abîmée (version « $v ») : rien changé."
  done
  # Une note vide ou abîmée est l'état le plus fermé (--chercher et --cle s'arrêtent) : jamais prise pour « pas de
  # note », ni réécrite ici sans accord fort (une note montée plus haut que celle de la trace redescendrait). Relue
  # avant la question, puis sous le verrou (abîmée pendant la question).
  haute_notee >/dev/null 2>&1 || erreur "La note de la dernière version vérifiée ($NOTE_VERSION) est vide ou abîmée :" \
    "l'annulation ne la réécrit pas. La réparer d'abord (voir --chercher). Rien changé."
  echo "Annuler l'acceptation ${t#mis-de-cote-} :"
  echo "  note remise à la $avant si elle est plus haute que l'actuelle ($NOTE_VERSION)"
  echo "  remis dans le cache, s'ils se vérifient : ${versions[*]:-rien} (de $CACHE/$t)"
  echo "Pour confirmer, taper : ANNULER"
  builtin read -r rep || rep=""
  [[ $rep == ANNULER ]] || { echo "Pas confirmé : rien changé."; return 1; }
  verrou || erreur "Verrou pas pris : rien changé."
  [[ $(derniere_trace) == "$t" ]] || erreur "Les acceptations ont changé pendant la question : rien changé (relancer)."
  notee=$(haute_notee 2>/dev/null) || erreur "La note de la dernière version vérifiée ($NOTE_VERSION) est devenue vide" \
    "ou abîmée pendant la question : l'annulation ne la réécrit pas. La réparer d'abord. Rien changé."
  journal "annuler-acceptation $t : début" || erreur "Journal ($JOURNAL) pas écrit : rien changé."
  s=$CACHE/$t
  for v in "${versions[@]}"; do
    if [[ -L $s || ! -d $s ]]; then
      laisses+=("$v (dossier $s absent, ou lien)")
    elif [[ -L $s/$v || ! -d $s/$v ]]; then
      laisses+=("$v (absent, ou lien)")
    elif [[ -e $CACHE/$v || -L $CACHE/$v ]]; then
      laisses+=("$v (déjà de nouveau dans le cache)")
    else
      raison=$(version_verifiee "$s/$v" "$v" 2>&1)
      rc=$?
      if ((rc == 3)); then
        passagers+=("$v")
        laisses+=("$v (pas vérifiable ici pour l'instant : $raison)")
      elif ((rc != 0)); then
        laisses+=("$v (ne se vérifie pas : $raison)")
      elif mv -T -- "$s/$v" "$CACHE/$v"; then
        remis+=("$v")
      else
        passagers+=("$v")
        laisses+=("$v (pas déplacé)")
      fi
    fi
    passe=0
    for w in "${passagers[@]}"; do [[ $w != "$v" ]] || passe=1; done
    if ((!passe)) && [[ -f $ECARTEES ]]; then
      reste=$(grep -vxF -- "$v" "$ECARTEES")
      if [[ -n $reste ]]; then printf '%s\n' "$reste" >"$ECARTEES"; else rm -f -- "$ECARTEES"; fi
    fi
  done
  if [[ $avant =~ $FORME_VERSION ]]; then
    if [[ -z $notee ]] || plus_ancienne "$notee" "$avant"; then noter_haute "$avant" || return 1; fi
  fi
  if ((${#passagers[@]})); then
    # La trace gardée, réduite à ce qui reste à remettre (écrite d'un coup) ; pas réécrite, elle reste entière, et
    # la relance refait le tout (une version déjà remise y est « déjà de nouveau dans le cache »).
    { printf '%s\n' "$avant" "${passagers[@]}" >"$ACCEPTATIONS/$t.tmp" &&
      mv -f -T -- "$ACCEPTATIONS/$t.tmp" "$ACCEPTATIONS/$t"; } 2>/dev/null || rm -f -- "$ACCEPTATIONS/$t.tmp"
    journal "annuler-acceptation $t : partielle ; remis ${remis[*]:-rien} ; à relancer : ${passagers[*]} ; note $(haute_notee 2>/dev/null)" ||
      echo "⚠ La fin n'a pas pu être notée au journal ($JOURNAL) ; le début l'est." >&2
    echo "⚠ Annulation partielle : remis dans le cache : ${remis[*]:-rien} ; note : $(haute_notee 2>/dev/null)."
    echo "  Pas remis pour une panne passagère, toujours écartés, trace gardée : ${passagers[*]}. Relancer" \
      "outils/claude-cle.sh --annuler-acceptation une fois la panne passée."
    echo "  Laissés dans $s :"
    printf '  %s\n' "${laisses[@]}"
    return 2
  fi
  rm -f -- "${ACCEPTATIONS:?}/${t:?}"
  ((${#laisses[@]})) || rmdir -- "$s" 2>/dev/null
  journal "annuler-acceptation $t : remis ${remis[*]:-rien} ; note $(haute_notee 2>/dev/null)" ||
    echo "⚠ La fin n'a pas pu être notée au journal ($JOURNAL) ; le début l'est." >&2
  echo "✔ Acceptation annulée : remis dans le cache : ${remis[*]:-rien} ; note : $(haute_notee 2>/dev/null)."
  ((${#laisses[@]} == 0)) || {
    echo "⚠ Pas remis, laissés dans $s (à regarder, puis effacer à la main) :"
    printf '  %s\n' "${laisses[@]}"
  }
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
  # Une version mise de côté par le propriétaire (--accepter-version) n'est pas reprise, même annoncée de nouveau.
  # Tant qu'elle est annoncée, cet ordinateur ne se met plus à jour : notifié une fois par version (la minuterie
  # repasse chaque jour), et dit par --etat.
  if ecartee "$v"; then
    echo "· Le serveur annonce Claude Code $v, mise de côté par --accepter-version : pas reprise" \
      "(outils/claude-cle.sh --annuler-acceptation la reprend)."
    if [[ $(cat "$ETAT/claude-cle-ecartee-annoncee" 2>/dev/null) != "$v" ]]; then
      avertir "Claude Code $v pas reprise" "Le serveur annonce la $v, mise de côté par --accepter-version : pas de mise \
à jour tant qu'elle est annoncée. outils/claude-cle.sh --annuler-acceptation la reprend."
      mkdir -p "$ETAT" && echo "$v" >"$ETAT/claude-cle-ecartee-annoncee"
    fi
    return 0
  fi
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
# La seule règle de lecture de la note de dépôt, pour changes, sans_note (poser) et NOTEE : la ligne d'un binaire est
# celle qui finit par « ␠chemin ». Sans telle ligne, le binaire est sans note (inconnu) ; avec une, il est noté, et
# changé si aucune ne porte exactement son empreinte (64 hexadécimaux minuscules) : une ligne abîmée compte donc comme
# un changement, jamais aussi comme « sans note ». Un binaire est soit changé, soit sans note, jamais les deux : un
# seul sort dit (avant, une ligne abîmée le mettait dans les deux listes, « laissé sur la clé » puis « retiré »).
ligne_notee() { grep -qE " ${2//./\\.}\$" "$1" 2>/dev/null; } # note chemin
# L'empreinte notée d'un binaire (la première ligne valable), ou rien.
empreinte_notee() { # note chemin
  grep -E "^[0-9a-f]{64} ${2//./\\.}\$" "$1" 2>/dev/null | head -1 | cut -c1-64
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
    ligne_notee "$note" "$chemin" || continue
    sha=""
    if [[ -f $p/$chemin && ! -L $p/$chemin ]]; then
      relache "$p/$chemin"
      sha=$(sha256sum <"$p/$chemin" | cut -d' ' -f1)
    fi
    { [[ -n $sha ]] && grep -qxF "$sha $chemin" "$note"; } || printf ' %s' "$chemin"
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
# Les binaires de la clé sans ligne valable dans la note de dépôt d'ici, dits sur CHAQUE refus de poser, même avant
# que le cache ne soit vérifié (note de version abîmée, chemin piégé, cache plus ancien, vide ou qui ne se vérifie
# plus) : sans_note, dans poser, est su dès la note lue. Avant la comparaison au cache (inconnu_calcule vide), chacun
# est « laissé sur la clé, PAS vérifié » ; après, seuls ceux qui diffèrent de la copie vérifiée (inconnu) sont dits,
# avec ce qu'ils sont devenus (remplacé, retiré, laissé) : jamais un « remplacé » qui n'a pas eu lieu. Code 0 si
# quelque chose a été dit (l'appelant sort alors en code 2), 1 sinon.
dire_inconnus() { # point raison
  local c liste="" i_remplaces="" i_retires="" i_laisses=""
  if [[ -n ${inconnu_calcule:-} ]]; then
    liste=${inconnu:-}
    for c in $liste; do
      if [[ "${inconnu_reste:-} " != *" $c "* ]]; then i_remplaces+=" $c"
      elif [[ -e $1/$c || -L $1/$c ]]; then i_laisses+=" $c"
      else i_retires+=" $c"; fi
    done
  else
    for c in ${sans_note:-}; do
      [[ -e $1/$c || -L $1/$c ]] && liste+=" $c" i_laisses+=" $c"
    done
  fi
  [[ -n $liste ]] || return 1
  echo "⚠ Déjà sur la clé, sans ligne dans la note de dépôt d'ici :$liste." >&2
  [[ -z $i_remplaces ]] || echo "  Remplacé par la copie vérifiée avant la panne :$i_remplaces." >&2
  [[ -z $i_retires ]] || echo "  Retiré de la clé, PAS remplacé ($2) :$i_retires." >&2
  if [[ -n $i_laisses && -n ${inconnu_calcule:-} ]]; then
    echo "  Laissé sur la clé, PAS remplacé ($2) :$i_laisses. S'il ne vient pas de Vanguard, l'effacer." >&2
  elif [[ -n $i_laisses ]]; then
    echo "  Laissé sur la clé, PAS vérifié ni remplacé ($2) :$i_laisses. S'il ne vient pas de Vanguard, l'effacer." >&2
  fi
  [[ -z $i_retires$i_laisses ]] || avertir "Claude Code inconnu sur la clé" "Déjà là sans note de dépôt :$liste. \
Copie vérifiée pas posée ($2)${i_retires:+ ; retiré :$i_retires}${i_laisses:+ ; laissé sur la clé :$i_laisses}."
  return 0
}
# Rien n'est posé (code 1) ; un binaire changé pendant le voyage, lui, ne reste jamais sur la clé, et il est toujours
# dit (code 2), même s'il a déjà été remplacé avant la panne (vu, la liste du début, dans poser). Un binaire sans
# ligne dans la note est dit aussi (dire_inconnus), code 2. Tout est dit AVANT de sortir : un binaire inconnu ne fait
# jamais taire ce que sont devenus les binaires changés déjà remplacés, ni l'inverse.
refuser() { # point changes raison texte
  local remplaces=${vu:-} c dit=""
  for c in $2; do remplaces=${remplaces// $c/}; done
  echo "✖ $4" >&2
  dire_inconnus "$1" "$3" && dit=1
  # retirer_change dit aussi les binaires changés déjà remplacés ($remplaces), puis sort en code 2.
  [[ -z $2 ]] || retirer_change "$1" "$2" "$3" "$remplaces"
  # Changés mais identiques à la copie vérifiée (egaux, dans poser) : déjà dits avant ce refus, jamais « remplacés ».
  [[ -z ${egaux:-} ]] || dit=1
  if [[ -n $remplaces ]]; then
    echo "✖ Sur la clé, changé depuis le dernier dépôt :$remplaces. Remplacé par la copie vérifiée avant la panne ;" >&2
    echo "  un programme remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
    avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$remplaces. Remplacé par la copie vérifiée \
(le reste du dépôt a raté) ; un programme remplacé est un piège possible."
    dit=1
  fi
  [[ -z $dit ]] || exit 2
  exit 1
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

# La clé garde sa version signée plus récente (version_cle) : ses binaires notés tels quels, le lanceur et les
# consignes remis à jour ; son manifeste signé reste le sien. La note de version de cet ordinateur (NOTE_VERSION) ne
# monte PAS : elle dit ce que ce PC a vérifié chez lui, et une version venue par la clé (d'un autre canal, ou posée
# exprès) ne doit ni bloquer --chercher ni faire refuser le cache aux dépôts suivants. Un binaire gardé qui ne vient
# pas d'un dépôt d'ici (changé pendant le voyage, ou sans ligne dans la note de dépôt) est dit : code 2, notifié,
# comme un binaire inconnu ; au dépôt suivant, noté ici, il ne l'est plus.
garder_cle() { # point version-du-cache note changés
  local p=$1 f c pas_d_ici="" rate=""
  for c in "${!CLE_SHA[@]}"; do
    grep -qxF "${CLE_SHA[$c]} $c" "$3" 2>/dev/null || pas_d_ici+=" $c"
  done
  # Les copies d'abord, la note de dépôt seulement après elles : une copie ratée ne fait jamais oublier que les
  # binaires ne viennent pas d'ici (la note les connaîtrait, et le dépôt suivant se tairait).
  for f in "${FIXES[@]}"; do
    copier_relu "outils/cle/Claude/$f" "$p/Claude/$f" || { rate="Claude/$f pas copié sur la clé."; break; }
  done
  [[ -n $rate ]] || copier_relu "$CLE_GPG" "$p/Claude/claude-code.asc" || rate="Claude/claude-code.asc pas copié sur la clé."
  [[ -n $rate ]] || copier_relu "outils/cle/$LANCEUR" "$p/$LANCEUR" || rate="$LANCEUR pas copié sur la clé."
  # L'alerte de provenance AVANT d'écrire la note : une note pas écrite, un sync qui échoue, un arrêt (Ctrl+C,
  # fenêtre fermée pendant un sync long) ne la font jamais taire ; arrêté avant la note, le dépôt suivant la redit.
  [[ -z $pas_d_ici ]] || provenance "$4" "$pas_d_ici"
  if [[ -z $rate ]]; then
    NOTEE=()
    for c in "${!CLE_SHA[@]}"; do NOTEE[$c]=${CLE_SHA[$c]}; done
    { mkdir -p "$ETAT" && ecrire_note "$3"; } 2>/dev/null || rate="Note du dépôt pas écrite ($3)."
  fi
  if [[ -n $rate ]]; then
    echo "✖ $rate" >&2
    [[ -n $pas_d_ici ]] || exit 1
    echo "  Le dépôt n'est pas fini : ce sera redit au dépôt suivant." >&2
    exit 2
  fi
  sync -f "$p/Claude/CLAUDE.md" 2>/dev/null || true
  echo "⚠ La clé porte déjà Claude Code $VERSION_CLE (signé, vérifié), plus récent que le cache ($2) : gardé, pas" >&2
  echo "  redescendu ; lanceur et consignes remis à jour." >&2
  if [[ -z $pas_d_ici ]]; then
    # Notifié une fois par couple (version de la clé, version du cache) : chaque dépôt le redit, pas le bureau.
    if [[ $(cat "$ETAT/claude-cle-plus-recent" 2>/dev/null) != "$VERSION_CLE>$2" ]]; then
      avertir "Claude Code plus récent sur la clé" "La clé porte la $VERSION_CLE signée ; le cache n'a que la $2. Gardée \
sur la clé, pas redescendue."
      { echo "$VERSION_CLE>$2" >"$ETAT/claude-cle-plus-recent"; } 2>/dev/null
    fi
    return 0
  fi
  return 2
}
# Des binaires gardés sur la clé (signés, vérifiés) qui ne viennent pas d'un dépôt d'ici : dit et notifié. La raison
# (facultative) : pourquoi ils restent quand la clé n'est pas gardée parce que plus récente (cache absent ou vide).
provenance() { # changés pas-d-ici [raison]
  local c reste=$2 suite="Gardée (plus récente que le cache)"
  for c in $1; do reste=${reste// $c/}; done
  # R10-CR-1 : un vrai choix. « ${3:+…}${3:-…} » collait la raison une seconde fois (${3:-X} rend $3 lui-même).
  [[ -z ${3:-} ]] || suite="Laissée sur la clé ($3)"
  if [[ -n $1 ]]; then
    echo "✖ Changé depuis le dernier dépôt d'ici :$1. C'est la version $VERSION_CLE, signée par Anthropic et vérifiée," >&2
  else
    echo "✖ Pas posé d'ici (aucune ligne dans la note de dépôt) :$2. C'est la version $VERSION_CLE, signée et vérifiée," >&2
  fi
  echo "  mais elle ne vient pas de cet ordinateur : posée d'un autre ordinateur, ou remplacée pendant le voyage. Si la" >&2
  echo "  clé n'est passée par aucun autre ordinateur avec Vanguard, regarder où elle est allée." >&2
  # Changés et sans note à la fois : chacun nommé, dans la même version signée.
  [[ -z $1 || -z $reste ]] || echo "  Pas posé d'ici non plus (aucune ligne dans la note de dépôt) :$reste." >&2
  [[ -z ${3:-} ]] || echo "  Laissé sur la clé tel quel, pas remplacé ($3)." >&2
  avertir "Claude Code changé sur la clé" "La clé porte la $VERSION_CLE signée, qui ne vient pas d'un dépôt d'ici :$2. \
$suite ; regarder où la clé est allée."
}
# Cache absent ou vide (R9-CR-3) : les binaires sans note sont vérifiés avec la clé elle-même, son manifeste signé et
# la seule clé de confiance du dépôt (version_cle). Entière, signée, ni mise de côté ni plus ancienne que la plus haute
# vérifiée ici : dite signée et vérifiée, pas posée d'ici (provenance), sans le conseil de l'effacer ; le reste,
# « PAS vérifié » (dire_inconnus). Code 0 si quelque chose a été dit (l'appelant sort en code 2), 1 sinon.
# R10-CR-3 : les binaires NOTÉS mais changés aussi (change, de poser). Signés de la même version vérifiée entière, ils
# ne sont plus retirés comme un piège (la clé d'un autre ordinateur, vidée) : sortis de change, dits par provenance
# (changé depuis le dépôt d'ici, signé et vérifié, laissé). Seul ce qui ne se vérifie pas va à retirer_change. Le même
# binaire signé n'a plus deux sorts selon qu'une vieille ligne de note existe ici ou non.
dire_sans_cache() { # point raison
  local c signes="" changes_signes="" haute_ici rien=1
  if [[ -n ${sans_note:-}${change:-} ]]; then
    version_cle "$1" 0.0.0
    if [[ -n $VERSION_CLE ]] && ! ecartee "$VERSION_CLE" && haute_ici=$(haute_notee 2>/dev/null) &&
      ! { [[ -n $haute_ici ]] && plus_ancienne "$VERSION_CLE" "$haute_ici"; }; then
      for c in ${sans_note:-}; do
        [[ -z ${CLE_SHA[$c]:-} ]] || signes+=" $c"
      done
      for c in ${change:-}; do
        [[ -z ${CLE_SHA[$c]:-} ]] || changes_signes+=" $c"
      done
    fi
    [[ -n $signes$changes_signes ]] || VERSION_CLE=""
    for c in $signes; do sans_note=${sans_note// $c/}; done
    for c in $changes_signes; do change=${change// $c/}; done
    [[ -z $signes$changes_signes ]] || { provenance "$changes_signes" "$changes_signes$signes" "$2"; rien=0; }
  fi
  dire_inconnus "$1" "$2" && rien=0
  VERSION_CLE="" CLE_SHA=()
  return $rien
}

poser() { # point
  local p=$1 jeton v d note="" ligne plat bin dossier change="" vu besoin libre chemin haute f s c sha part inconnu="" \
    inconnu_reste="" inconnu_calcule="" sans_note="" dit="" egaux=""
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
  # Les binaires déjà là sans ligne dans la note (note absente, jeton changé, posés par autre chose ; ligne_notee) :
  # sus dès maintenant, dits sur chaque refus qui suit (dire_inconnus), même avant la vérification du cache. Jamais
  # aussi dans change : la même règle de lecture.
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    c=Claude/$dossier/$bin
    [[ -e $p/$c || -L $p/$c ]] || continue
    ligne_notee "$note" "$c" || sans_note+=" $c"
  done
  if ! active; then
    retirer "$p" "$note"
    [[ -z $change ]] || retirer_change "$p" "$change" "Claude Code coupé"
    return 0
  fi
  minuterie
  if ! cache_present; then
    dire_sans_cache "$p" "cache absent" && dit=1
    [[ -z $change ]] || retirer_change "$p" "$change" "cache absent"
    [[ -z $dit ]] || return 2
    return 0
  fi
  v=$(derniere)
  if [[ -z $v ]]; then
    dire_sans_cache "$p" "cache vide" && dit=1
    [[ -z $change ]] || retirer_change "$p" "$change" "cache vide"
    # R10-CR-2 : « la clé reste sans lui » seulement si aucun binaire n'y est (laissé, signé ou pas vérifié).
    f=""
    for ligne in "${PLATEFORMES[@]}"; do
      read -r plat bin dossier <<<"$ligne"
      [[ ! -e $p/Claude/$dossier/$bin && ! -L $p/Claude/$dossier/$bin ]] || f=1
    done
    if [[ -n $f ]]; then
      echo "Claude Code pas encore dans le cache (outils/claude-cle.sh --chercher) : rien n'est posé d'ici, la clé garde ce qu'elle porte."
    else
      echo "Claude Code pas encore dans le cache (outils/claude-cle.sh --chercher) : la clé reste sans lui."
    fi
    [[ -z $dit ]] || return 2
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
  [[ -n $jeton ]] || refuser "$p" "$change" "jeton de la clé illisible" "Jeton de la clé illisible : rien n'est posé."
  # Jamais plus ancienne que la plus haute version vérifiée ici : un cache redescendu (version récente effacée, copie
  # d'un autre ordinateur) ne fait pas revenir une version à faille sur la clé.
  if [[ -n $haute ]] && plus_ancienne "$v" "$haute"; then
    avertir "Claude Code : version plus ancienne refusée" "Le cache n'a que la $v ; la $haute a déjà été vérifiée. \
Rien n'est posé sur la clé."
    refuser "$p" "$change" "cache plus ancien que la version vérifiée" \
      "Claude Code $v du cache, plus ancien que la $haute déjà vérifiée : rien n'est posé (relancer --chercher)."
  fi
  # La clé porte déjà, signée et entière, une version plus récente que le cache (posée d'un autre ordinateur) et pas
  # plus ancienne que la plus haute vérifiée ici : elle n'est pas redescendue, et le lanceur est remis à jour. La note
  # anti-retour ne monte pas pour autant (seulement par --chercher) : sinon chaque dépôt suivant était refusé, une
  # fausse alerte à chaque fois et le lanceur jamais remis à jour. Une version mise de côté par --accepter-version
  # n'est pas gardée : le choix du propriétaire la fait remplacer par celle du cache.
  version_cle "$p" "$v"
  if [[ -n $VERSION_CLE ]] && ecartee "$VERSION_CLE"; then
    echo "· La clé porte Claude Code $VERSION_CLE, mise de côté par --accepter-version : remplacée par la $v du cache."
    VERSION_CLE=""
  fi
  if [[ -n $VERSION_CLE ]] && ! { [[ -n $haute ]] && plus_ancienne "$VERSION_CLE" "$haute"; }; then
    garder_cle "$p" "$v" "$note" "$change"
    return
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
  # Un binaire sans ligne valable dans la note (sans_note) qui diffère de la copie vérifiée : on ne sait pas d'où il
  # vient. Remplacé par la copie vérifiée, et dit, comme un binaire changé ; identique à elle, il est seulement noté.
  for ligne in "${PLATEFORMES[@]}"; do
    read -r plat bin dossier <<<"$ligne"
    c=Claude/$dossier/$bin
    [[ "$sans_note " == *" $c "* ]] || continue
    cmp -s "$d/$plat/$bin" "$p/$c" 2>/dev/null || inconnu+=" $c"
  done
  inconnu_reste=$inconnu inconnu_calcule=1
  # R9-CR-2 : un binaire changé depuis le dernier dépôt d'ici mais identique à la copie vérifiée (posé par un autre
  # ordinateur, la même version) n'est pas recopié : jamais « va être remplacé » ni « remplacé » pour lui. Il sort de
  # vu et de change, et il est dit tout de suite, avant tout refus qui suit et avant la première écriture de la note :
  # gardé, code 2 (il ne vient pas d'un dépôt d'ici, comme dans garder_cle).
  for c in $vu; do
    plat=linux-x64 bin=claude
    [[ $c != Claude/Windows/claude.exe ]] || plat=win32-x64 bin=claude.exe
    { [[ ! -L $p/$c ]] && cmp -s "$d/$plat/$bin" "$p/$c" 2>/dev/null; } || continue
    egaux+=" $c" vu=${vu// $c/} change=${change// $c/}
  done
  if [[ -n $egaux ]]; then
    echo "✖ Sur la clé, changé depuis le dernier dépôt d'ici :$egaux. Identique à la copie vérifiée de la $v : gardé tel" >&2
    echo "  quel, pas recopié. Posé d'un autre ordinateur ? Si la clé n'est passée par aucun autre ordinateur avec" >&2
    echo "  Vanguard, regarder où elle est allée." >&2
    avertir "Claude Code changé sur la clé" "Changé depuis le dernier dépôt d'ici :$egaux. Identique à la copie vérifiée \
de la $v : gardé ; regarder où la clé est allée."
  fi
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
  for c in "${BINAIRES_CLE[@]}"; do
    s=$(empreinte_notee "$note" "$c")
    [[ -z $s ]] || NOTEE[$c]=$s
  done
  # L'alerte d'un binaire changé ou inconnu, AVANT la première écriture de la note : arrêté pendant la copie (Ctrl+C,
  # fenêtre fermée pendant un sync), la note connaîtrait déjà le nouveau binaire, ou l'ancien serait retiré (un
  # binaire absent ne compte pas) : le dépôt suivant se tairait. Elle dit ce qui est vrai à ce moment (« va être
  # remplacé ») ; « remplacé » n'est dit qu'après la copie réussie, et une copie ratée est dite (refuser).
  if [[ -n $vu ]]; then
    echo "✖ Sur la clé, changé depuis le dernier dépôt :$vu. Va être remplacé par la copie vérifiée (ci-dessous) ; un" >&2
    echo "  programme remplacé pendant le voyage est un piège possible : regarder où la clé est allée." >&2
    avertir "Claude Code changé sur la clé" "Changé pendant le voyage :$vu. Va être remplacé par la copie vérifiée \
(le résultat est dit au terminal) ; un programme remplacé est un piège possible."
  fi
  if [[ -n $inconnu ]]; then
    echo "⚠ Déjà sur la clé, sans ligne dans la note de dépôt d'ici :$inconnu. Va être remplacé par la copie vérifiée" >&2
    echo "  (ci-dessous) ; s'il ne vient pas de Vanguard (autre ordinateur, autre jeton), regarder d'où il vient." >&2
    avertir "Claude Code inconnu sur la clé" "Déjà là sans note de dépôt :$inconnu. Va être remplacé par la copie \
vérifiée (le résultat est dit au terminal)."
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
    change=${change// $c/} inconnu_reste=${inconnu_reste// $c/}
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
  [[ -z $vu$inconnu ]] || echo "  Changé ou inconnu, remplacé par la copie vérifiée :$vu$inconnu." >&2
  # L'alerte est déjà dite (plus haut, avant la note) ; le code la rappelle.
  [[ -z $vu && -z $inconnu && -z $egaux ]] || return 2
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
  local v d raison
  cache_present || return 0
  v=$(derniere)
  if active; then echo "Claude Code sur la clé : allumé ($REGLAGE)."; else echo "Claude Code sur la clé : coupé."; fi
  [[ -n $v ]] || { echo "Cache : vide ($CACHE)."; return 0; }
  d=$CACHE/$v
  echo "Cache : Claude Code $v ($CACHE)."
  [[ ! -s $ECARTEES ]] || echo "  mises de côté par --accepter-version (pas reprises) : $(tr '\n' ' ' <"$ECARTEES")" \
    "(outils/claude-cle.sh --annuler-acceptation les reprend)"
  # Trois réponses, jamais confondues : bonne (0), fausse (1), pas vérifiable ici (3, ni bonne ni fausse). La raison
  # dans la ligne même (sortie normale) : un appelant qui ne lit que celle-ci la voit aussi.
  raison=$(version_verifiee "$d" "$v" 2>&1)
  case $? in
    0) echo "  signature et empreintes : bonnes" ;;
    3) echo "  ⚠ vérification impossible sur cet ordinateur (${raison#vérification impossible ici : }) : ni bonne ni" \
      "fausse, pas comptée comme saine"
      return 3 ;;
    *) echo "  ✖ ne se vérifie plus ($raison)"
      return 1 ;;
  esac
}

case ${1:-} in
  --chercher) chercher ;;
  --cle) [[ $# == 2 ]] || erreur "Usage : outils/claude-cle.sh --cle POINT"; poser "$2" ;;
  --relire) [[ $# == 2 ]] || erreur "Usage : outils/claude-cle.sh --relire POINT"; relire "$2" ;;
  --etat) etat ;;
  --accepter-version) [[ $# == 2 ]] || erreur "Usage : outils/claude-cle.sh --accepter-version X"; accepter "$2" ;;
  --annuler-acceptation) [[ $# == 1 ]] || erreur "Usage : outils/claude-cle.sh --annuler-acceptation"; annuler_acceptation ;;
  --active) active ;;
  *) sed -n '2,19p' "$0" | sed 's/^# \?//'; [[ ${1:-} == -h || ${1:-} == --help ]] ;;
esac
