#!/usr/bin/env bash
# Dépanner avec Claude, sous Linux (ou sur SystemRescue démarré depuis la clé) :
#   bash -p /chemin/de/la/clé/Claude/depanner.sh
# Troubleshoot with Claude, on Linux. See README.txt.
#
# Comme depanner.ps1 sous Windows : rien n'est installé. Le binaire est copié dans un dossier temporaire à soi, vérifié
# là (le manifeste de la clé doit être signé par la clé de publication d'Anthropic, reconnue par son empreinte, et la
# copie doit avoir l'empreinte que ce manifeste donne), puis lancé de là. Le jeton de connexion et la conversation y
# restent (CLAUDE_CONFIG_DIR) ; en sortant, même par Ctrl+C ou terminal fermé : déconnexion, puis effacement.
# Limite, dite : ce script et la clé publique voyagent sur la même clé que le binaire. La vérification attrape une
# copie abîmée ou un binaire remplacé seul ; la clé entière remplacée, seul Vanguard la voit (il relit chaque binaire
# à chaque mise à jour de la clé, outils/claude-cle.sh). Sous Windows, la signature Authenticode, vérifiée par Windows
# lui-même, ne dépend pas de la clé.
# Autre limite, dite : sur l'ordinateur visité, le lanceur prouve « signé par Anthropic », pas « dernière version ».
# Une version plus ancienne mais authentique, remise sur la clé pendant le voyage (binaire, manifeste et signature),
# est lancée ; Vanguard la voit au retour (« changé depuis le dernier dépôt »).

# « bash -p » : bash n'importe alors ni les fonctions exportées par le PC (une fonction « gpg » passerait avant le PATH
# fixé plus bas et dirait « bonne signature »), ni SHELLOPTS (traçage avec une invite piégée), ni BASH_ENV, ENV, CDPATH
# ou GLOBIGNORE. Lancé sans -p : relancé avec, avant toute autre commande (rien que des mots du shell jusque-là).
# Limite, dite : sans -p, ce que le PC a exporté pour le traçage ou BASH_ENV tourne avant cette ligne ; LISEZMOI dit
# donc « bash -p ».
if [[ $- != *p* ]]; then
  [[ -f ${BASH_SOURCE[0]:-} ]] || { printf '  Lancez : bash -p depanner.sh\n' >&2; exit 1; }
  exec "$BASH" -p -- "${BASH_SOURCE[0]}" "$@"
fi
set -uo pipefail
unset CDPATH

# Le dossier de la clé sans « dirname » (une commande du PATH du PC) et sans CDPATH ; jamais sur deux lignes.
ICI=${BASH_SOURCE[0]}
if [[ $ICI == */* ]]; then ICI=${ICI%/*}; else ICI=.; fi
ICI=$(cd -P -- "${ICI:-/}" >/dev/null && pwd -P) || exit 1
[[ $ICI == /* && $ICI != *$'\n'* ]] || exit 1
CLE=${ICI%/*}
EMPREINTE_CLE=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
PLACE_MIO=700
# « auth logout » sort avec le code 0 même sans Internet : Claude Code efface le jeton de ce PC, et ne peut pas dire
# au serveur de le révoquer. Une version récente le dit (« … didn't confirm the login was revoked ») ; une ancienne
# affiche le même succès dans les deux cas. « Déconnecté » n'est donc dit que sur preuve : code 0, ce texte de
# succès, pas l'avertissement, et un binaire vérifié qui sait l'écrire (REVOCATION_DITE dedans).
DECONNECTE="Successfully logged out from your Anthropic account."
REVOCATION_DITE="didn't confirm the login was revoked"
# Réglages imposés à tout l'ordinateur (« managed ») : Claude Code les lit là, et ses skills sous $GERE/.claude.
GERE=/etc/claude-code
# Sous WSL (noyau de Microsoft), Claude Code lit aussi ceux de Windows : C:\Program Files\ClaudeCode, vu d'ici en /mnt/c.
NOYAU=/proc/version
GERE_WINDOWS="/mnt/c/Program Files/ClaudeCode"
# Les disques montés : rien n'est jamais effacé dessous (un disque du proche monté dans le dossier de travail).
MONTAGES=/proc/self/mountinfo
# Les commandes de ce script (gpg, sha256sum, cp…) viennent des dossiers du système, jamais d'un PATH posé par le PC
# visité : un faux gpg en tête du PATH dirait « bonne signature ». Claude Code, lui, garde le PATH du PC pour dépanner.
CHEMINS_SURS=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin
PATH_PC=${PATH:-$CHEMINS_SURS}
PATH=$CHEMINS_SURS
export PATH

dire() { printf '  %s\n' "$1"; [[ -z ${2:-} ]] || printf '  \e[90m%s\e[0m\n' "$2"; }
# Oui seulement par « o », « oui », « y » ou « yes » (majuscules permises) : « ok non » ou « yo » ne valent pas accord.
accord() { local r; read -r -p "  $1 [o/y/N] " r || return 1; r=${r,,}; r=${r//[[:space:]]/}; [[ $r =~ ^(o|oui|y|yes)$ ]]; }
arret() { printf '\n  \e[31m✖ %s\e[0m\n' "$1"; [[ -z ${2:-} ]] || printf '    \e[90m%s\e[0m\n' "$2"; exit 1; }

case $(uname -m) in
  x86_64 | amd64) ;;
  *) arret "Processeur $(uname -m) : seul Claude Code pour x86-64 est sur la clé." "Only the x86-64 Claude Code is on the key." ;;
esac
# L'environnement du PC visité ne choisit ni le serveur, ni le compte, ni les certificats, ni le mandataire, ni le code
# chargé ; retiré d'abord, avant toute commande de Claude Code (même la déconnexion des restes d'une session).
# Aussi : les certificats que Claude Code lit sous d'autres noms, le journal des clés TLS, le traçage bêta et ses
# adresses, les mandataires d'agent et le choix du serveur de connexion.
# Limite, dite : sans « bash -p », BASH_ENV posé avant ce script s'exécute avant lui (plus haut).
while IFS= read -r v; do
  case ${v^^} in
    ANTHROPIC_* | CLAUDE_* | NODE_* | BUN_* | SSL_CERT_* | AWS_* | GOOGLE_* | VERTEX_* | OTEL_* | GIT_* | LD_* | \
      ANT_* | CCR_* | AZURE_* | HTTP_PROXY | HTTPS_PROXY | ALL_PROXY | NO_PROXY | GRPC_PROXY | REQUESTS_CA_BUNDLE | \
      CURL_CA_BUNDLE | BROWSER | BASH_ENV | ENV | SESSION_INGRESS_URL | ENABLE_CLAUDEAI_MCP_SERVERS | SSLKEYLOGFILE | \
      GRPC_DEFAULT_SSL_ROOTS_FILE_PATH | NIX_SSL_CERT_FILE | DENO_CERT | PIP_CERT | CARGO_HTTP_CAINFO | \
      HTTPLIB2_CA_CERTS | CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE | HEX_CACERTS_PATH | ENABLE_BETA_TRACING_DETAILED | \
      ENABLE_ENHANCED_TELEMETRY_BETA | BETA_TRACING_ENDPOINT | VOICE_STREAM_BASE_URL | MCP_CLIENT_SECRET | \
      AGENT_PROXY_URL | USE_LOCAL_OAUTH | USE_STAGING_OAUTH | CLOUD_ML_REGION) unset "$v" ;;
  esac
done < <(compgen -e)
SOURCE=$ICI/Linux/claude
[[ -f $SOURCE ]] || arret "Claude Code n'est pas sur cette clé (Claude/Linux/claude)." "Claude Code is not on this key."

printf '\n  \e[31mDépanner avec Claude (Vanguard)\e[0m\n  \e[90mTroubleshoot with Claude (Vanguard)\e[0m\n\n'
dire "Claude Code, l'assistant d'Anthropic, va lire cet ordinateur pour trouver la panne. Ce qu'il lit (journaux," \
  "Claude Code, Anthropic's assistant, will read this computer to find the problem. What it reads (logs,"
dire "réglages, noms de fichiers) part chez Anthropic pour être analysé. Il demande avant toute commande qui change" \
  "settings, file names) is sent to Anthropic for analysis. It asks before any command that changes something;"
dire "quelque chose ; certaines commandes de simple lecture passent sans demander, et ce qu'elles montrent part aussi" \
  "some read-only commands run without asking, and what they show is sent to Anthropic too."
dire "chez Anthropic. Il faut un compte Claude (abonnement Pro ou Max, ou console Anthropic)." \
  "A Claude account is needed (Pro or Max plan, or Anthropic Console)."
echo
dire "Connexion : sur VOTRE téléphone, jamais dans le navigateur de cet ordinateur (il garderait votre compte)." \
  "Sign in on YOUR phone, never in this computer's browser (it would keep your account signed in)."
echo
accord "Le propriétaire de cet ordinateur est d'accord ? / Does the owner of this computer agree?" ||
  { dire "Rien n'a été lancé." "Nothing was started."; exit 0; }

# Un dossier temporaire où un programme peut s'exécuter (pas « noexec »), assez grand pour la copie, et à l'abri :
# lui et chaque dossier au-dessus à root ou à ce compte, sans écriture pour le groupe ni les autres. Claude Code lit
# les consignes (CLAUDE.md, AGENTS.md, .claude/) de chaque dossier au-dessus du dossier de travail : dans /tmp, un
# autre compte pourrait en poser une, même après la vérification plus bas. Celui de la session (mémoire vive), sinon
# le cache du compte (créé au besoin), sinon TMPDIR, sinon /run pour root (SystemRescue : son dossier personnel vit
# dans une petite réserve en mémoire) ; /tmp et /var/tmp, partagés, jamais.
a_l_abri() { # dossier
  local p o m moi
  moi=$(id -u)
  p=$(cd -- "$1" 2>/dev/null && pwd -P) || return 1
  while :; do
    read -r o m < <(stat -c '%u %a' -- "$p" 2>/dev/null) || return 1
    [[ $o == 0 || $o == "$moi" ]] && ((!(8#$m & 8#022))) || return 1
    [[ $p != / ]] || return 0
    p=${p%/*}
    [[ -n $p ]] || p=/
  done
}
cache=${XDG_CACHE_HOME:-${HOME:-}/.cache}
[[ $cache != /* || -e $cache ]] || (umask 077 && mkdir -p -- "$cache") 2>/dev/null
# Le chemin réel (pwd -P), jamais celui donné : Claude Code lit les consignes au-dessus du chemin réel, et un chemin
# relatif ne vaudrait plus rien après le « cd » du lancement. Chaque dossier à l'abri est gardé dans « bases » : les
# restes d'une session d'avant y sont cherchés, même si elle avait pris un autre dossier que celle-ci.
base=""
bases=()
for d in "${XDG_RUNTIME_DIR:-}" "$cache" "${TMPDIR:-}" /run; do
  [[ -n $d && -d $d && ! -L $d ]] || continue
  a_l_abri "$d" || continue
  d=$(cd -- "$d" 2>/dev/null && pwd -P) || continue
  bases+=("$d")
  [[ -z $base && -w $d ]] || continue
  if command -v findmnt >/dev/null; then
    findmnt -no OPTIONS -T "$d" 2>/dev/null | tr ',' '\n' | grep -qx noexec && continue
  fi
  (($(df -Pk "$d" 2>/dev/null | awk 'NR == 2 { print $4 + 0 }') / 1024 >= PLACE_MIO)) || continue
  base=$d
done
[[ -n $base ]] || arret "Pas de dossier à soi (ni /tmp, partagé) avec $PLACE_MIO Mio libres où lancer un programme." \
  "No private folder (not the shared /tmp) with $PLACE_MIO MiB free where a program may run."

DOSSIER=$(mktemp -d "$base/vanguard-claude.XXXXXXXX") || arret "Dossier temporaire impossible à créer."
chmod 700 "$DOSSIER"
EXE=$DOSSIER/claude
lancee=""
# Ce que Claude Code reçoit, pour la session comme pour chaque déconnexion :
# - TMPDIR et XDG_CACHE_HOME dans le dossier : ses fichiers passagers et ses journaux (~/.cache/claude-cli-nodejs)
#   partent avec lui ; CLAUDE_CODE_SKIP_MCP_DEBUG_LOG_FILES : pas de journal des serveurs MCP du tout ;
# - ENABLE_CLAUDEAI_MCP_SERVERS=0 (et --strict-mcp-config au lancement) : les connecteurs du compte (courriel,
#   fichiers en ligne, agenda) ne sont pas chargés ;
# - BROWSER vers un fichier qui n'existe pas : le navigateur de ce PC ne s'ouvre jamais sur la page de connexion
#   (l'adresse s'affiche, à ouvrir sur le téléphone) ;
# - ANTHROPIC_CONFIG_DIR vers un dossier vide de la session : un profil Anthropic du PC (~/.config/anthropic) ne
#   choisit ni le compte ni le serveur ; Claude Code le cherche là d'abord ;
# - le PATH du PC, pour dépanner avec ses commandes ;
# - HOME en chemin réel : Claude Code arrête sa remontée (skills, commandes) au dossier personnel comparé tel quel ;
#   donné à travers un lien, il chercherait aussi les skills du dossier personnel, que le contrôle plus bas permet.
# Le dossier personnel en chemin réel, comme $d plus bas (pwd -P) : un HOME donné à travers un lien garde son exception.
# - sans les fonctions exportées par le PC (BASH_FUNC_…%%) : bash -p ne les lit pas, mais les passe à ses enfants ;
#   chaque commande que Claude Code lance dans bash les lirait. Ni le traçage : SHELLOPTS et BASHOPTS hérités restent
#   exportés et bash y écrit ses propres options (nounset, pipefail), que chaque commande de Claude prendrait.
export -n SHELLOPTS BASHOPTS 2>/dev/null
unset PS4
SANS_FONCTIONS=()
while IFS= read -r -d '' v; do
  [[ $v == BASH_FUNC_* ]] && SANS_FONCTIONS+=(-u "${v%%=*}")
done 2>/dev/null </proc/$$/environ
maison=""
[[ -n ${HOME:-} ]] && maison=$(cd -P -- "$HOME" 2>/dev/null >/dev/null && pwd -P)
ENV_CLAUDE=("${SANS_FONCTIONS[@]}" TMPDIR="$DOSSIER/tmp" XDG_CACHE_HOME="$DOSSIER/cache" ANTHROPIC_CONFIG_DIR="$DOSSIER/anthropic" DISABLE_AUTOUPDATER=1
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 ENABLE_CLAUDEAI_MCP_SERVERS=0 CLAUDE_CODE_SKIP_MCP_DEBUG_LOG_FILES=1
  BROWSER="$DOSSIER/pas-de-navigateur" VANGUARD_CLE="$CLE" PATH="$PATH_PC")
[[ -z $maison ]] || ENV_CLAUDE+=(HOME="$maison")

# Une session : déconnexion avec un binaire vérifié, puis effacement. Sans condition : si Claude Code rangeait le
# jeton ailleurs que dans .credentials.json, il serait quand même déconnecté. Délai borné : hors ligne, rien ne
# bloque. La déconnexion tourne comme la session (même environnement, depuis le dossier de travail de celle-ci) :
# ses journaux restent dans ce dossier. « deconnexion » : oui seulement si le serveur l'a confirmée (DECONNECTE,
# plus haut) ; non si elle a été tentée sans cette preuve.
deconnexion=""
revocation_dite=""
nettoyer() { # dossier [binaire vérifié]
  local d=$1 exe=${2:-} sortie
  deconnexion=""
  [[ -d $d ]] || return 0
  if [[ -n $exe && -x $exe && -d $d/config && -d $DOSSIER/travail ]]; then
    deconnexion=non
    if sortie=$(cd -- "$DOSSIER/travail" &&
      timeout 20 env "${ENV_CLAUDE[@]}" CLAUDE_CONFIG_DIR="$d/config" "$exe" auth logout </dev/null 2>&1); then
      [[ -n $revocation_dite && $sortie == *"$DECONNECTE"* && $sortie != *"$REVOCATION_DITE"* ]] && deconnexion=oui
    fi
  fi
  local -a montes=()
  montes_dits=()
  if [[ -r $MONTAGES ]]; then
    mapfile -d '' montes < <(montages_sous "$d")
    montes_dits=("${montes[@]}")
  else
    # Montages illisibles : le dossier de travail, où un disque serait monté, est laissé (dit à la fin).
    montes=("$d/travail")
    montes_dits=("$d/travail (disques montés pas lisibles ici)")
  fi
  effacer_sauf "$d"
}
# Les points de montage à $1 ou dessous, séparés par un octet nul, tels que le noyau les donne (/proc/self/mountinfo,
# 5e champ ; espace, tabulation, saut de ligne et barre oblique inverse y sont écrits en octal : décodés).
montages_sous() { # dossier
  LC_ALL=C awk -v d="$1" '
    function dec(s,  r, o) {
      r = ""
      while (match(s, /\\[0-7][0-7][0-7]/)) {
        o = substr(s, RSTART + 1, 3)
        r = r substr(s, 1, RSTART - 1) sprintf("%c", substr(o, 1, 1) * 64 + substr(o, 2, 1) * 8 + substr(o, 3, 1))
        s = substr(s, RSTART + 4)
      }
      return r s
    }
    { m = dec($5); if (m == d || index(m, d "/") == 1) printf "%s%c", m, 0 }' "$MONTAGES"
}
# Efface $1 sans jamais descendre dans un disque monté dessous (« montes », du parent) : rm -rf viderait le disque
# du proche monté dans le dossier de travail, et --one-file-system ne voit pas un montage lié du même disque. Ce qui
# contient un montage reste ; le reste est effacé. Code 1 si quelque chose est resté.
effacer_sauf() { # chemin
  local p=$1 e m r=0
  for m in "${montes[@]}"; do [[ $m != "$p" ]] || return 1; done
  for m in "${montes[@]}"; do
    [[ $m == "$p"/* ]] || continue
    [[ -d $p && ! -L $p ]] || return 1
    for e in "$p"/* "$p"/.[!.]* "$p"/..?*; do
      [[ -e $e || -L $e ]] || continue
      effacer_sauf "$e" || r=1
    done
    return 1
  done
  rm -rf "${RM_UN_DISQUE[@]}" -- "$p" 2>/dev/null
  [[ ! -e $p && ! -L $p ]] || r=1
  return $r
}
# « --one-file-system » en ceinture, si ce rm le connaît (GNU) ; un rm qui ne le connaît pas efface quand même.
RM_UN_DISQUE=(--one-file-system)
rm -f --one-file-system -- "$DOSSIER/.essai-rm" 2>/dev/null || RM_UN_DISQUE=()
montes_dits=()
# shellcheck disable=SC2329 # appelée par « trap fin EXIT »
fin() {
  # Ignorés, pas remis par défaut : un second Ctrl+C pendant la déconnexion ne laisse pas le jeton derrière. PIPE
  # aussi : la sortie dans un tuyau dont le lecteur est mort (enregistrement, tee) ne tue plus le ménage. Les
  # messages viennent après la déconnexion et l'effacement.
  trap '' HUP INT TERM PIPE
  trap - EXIT
  local efface=oui
  nettoyer "$DOSSIER" "$lancee" || efface=""
  echo
  if [[ -n $efface ]]; then
    if [[ $deconnexion == oui ]]; then
      dire "✔ Déconnecté ; Claude Code, la connexion et la conversation sont effacés de cet ordinateur." \
        "✔ Logged out; Claude Code, the sign-in and the conversation are erased from this computer."
    elif [[ -n $lancee ]]; then
      dire "⚠ Déconnexion NON confirmée par Anthropic (hors ligne, ou version qui ne le dit pas) : fermez la session sur
  claude.ai. Claude Code, la connexion et la conversation sont effacés de cet ordinateur." \
        "⚠ Logout NOT confirmed by Anthropic (offline, or a version that does not tell): end the session on
  claude.ai. Claude Code, the sign-in and the conversation are erased from this computer."
    fi
  elif ((${#montes_dits[@]})); then
    dire "✖ Un disque est (ou peut être) encore monté dans la session : rien n'est effacé dessous (ses fichiers sont" \
      "✖ A disk is (or may be) still mounted inside the session: nothing under it is erased. Unmount it, then erase"
    dire "  intacts). Démontez-le (umount), puis effacez ce qui reste de $DOSSIER :" "  what is left of $DOSSIER:"
    for m in "${montes_dits[@]}"; do dire "    $m"; done
    [[ $deconnexion == oui || -z $lancee ]] || dire "⚠ Déconnexion NON confirmée : fermez aussi la session sur claude.ai." \
      "⚠ Logout NOT confirmed: also end the session on claude.ai."
  else
    dire "✖ $DOSSIER n'a pas pu être effacé en entier : à regarder, puis effacer à la main." \
      "✖ Could not fully erase $DOSSIER: check it, then erase it by hand."
    [[ $deconnexion == oui || -z $lancee ]] || dire "⚠ Déconnexion NON confirmée : fermez aussi la session sur claude.ai." \
      "⚠ Logout NOT confirmed: also end the session on claude.ai."
  fi
}
trap fin EXIT
# PIPE attrapé (pas ignoré : Claude Code et ses commandes le reçoivent normalement) : le ménage de fin a lieu.
trap 'exit 130' HUP INT TERM
trap 'exit 141' PIPE
# Tenu pendant toute la session : un second lancement ne prend pas ce dossier pour des restes à effacer.
exec 7>"$DOSSIER/.session"
command -v flock >/dev/null && flock -n 7

# Claude Code lit aussi, au-dessus du dossier de travail, les consignes (CLAUDE.md, AGENTS.md), les serveurs MCP
# (.mcp.json) et les dossiers .claude (consignes, skills, commandes, agents), et les réglages imposés à tout
# l'ordinateur : posés là par quelqu'un d'autre, ce seraient des consignes. Refusé, en le disant, avant toute
# commande de Claude Code. Le dossier personnel est l'exception pour .claude : Claude Code n'y cherche pas de skills,
# et le refuser bloquerait tout PC où l'on se sert déjà de Claude Code ; ses consignes y sont refusées quand même.
refus() { arret "$1 existe : Claude le lirait comme une consigne. Rien n'a été lancé." \
  "$1 exists: Claude would read it as an instruction. Nothing was started."; }
d=$DOSSIER
while [[ $d == /* && $d != / ]]; do
  d=${d%/*}
  [[ -n $d ]] || d=/
  noms=(CLAUDE.md CLAUDE.local.md AGENTS.md .mcp.json)
  if [[ -n $maison && $d == "$maison" ]]; then noms+=(.claude/CLAUDE.md .claude/AGENTS.md .claude/rules); else noms+=(.claude); fi
  for f in "${noms[@]}"; do
    [[ ! -e ${d%/}/$f && ! -L ${d%/}/$f ]] || refus "${d%/}/$f"
  done
done
[[ ! -e $GERE && ! -L $GERE ]] || arret "$GERE existe : cet ordinateur impose ses réglages à Claude Code. Rien n'a été lancé." \
  "$GERE exists: this computer imposes its settings on Claude Code. Nothing was started."
# Sous WSL, les réglages imposés de Windows comptent aussi. Leur politique du registre (HKLM et HKCU\SOFTWARE\Policies\
# ClaudeCode) ne se lit pas d'ici : dit, avec le lanceur Windows en recours (il la regarde).
if grep -qiE 'microsoft|wsl' "$NOYAU" 2>/dev/null; then
  [[ ! -e $GERE_WINDOWS && ! -L $GERE_WINDOWS ]] ||
    arret "$GERE_WINDOWS existe : Windows impose ses réglages à Claude Code, sous WSL aussi. Rien n'a été lancé." \
      "$GERE_WINDOWS exists: Windows imposes its settings on Claude Code, under WSL too. Nothing was started."
  [[ -d ${GERE_WINDOWS%/*} ]] || dire "⚠ WSL : le disque C: de Windows n'est pas vu en /mnt/c ; ses réglages imposés n'ont PAS pu être regardés." \
    "⚠ WSL: Windows' C: drive is not seen at /mnt/c; its imposed settings could NOT be checked."
  dire "⚠ WSL : la politique du registre de Windows pour Claude Code n'est PAS regardée d'ici. Mieux : le lanceur" \
    "⚠ WSL: Windows' registry policy for Claude Code is NOT checked from here. Better: the Windows launcher"
  dire "  Windows (« Depanner avec Claude.bat »), qui la regarde." "  (\"Depanner avec Claude.bat\"), which checks it."
  accord "Lancer quand même sous WSL ? / Run under WSL anyway?" || exit 0
fi

echo
dire "Copie et vérification de Claude Code…" "Copying and checking Claude Code…"
cp -- "$SOURCE" "$EXE" || arret "Copie ratée." "Copy failed."
sha=$(sha256sum "$EXE" | cut -d' ' -f1)

# Le manifeste, copié lui aussi : ce sont les octets vérifiés qui sont lus ensuite.
cp -- "$ICI/manifest.json" "$DOSSIER/manifest.json" 2>/dev/null || arret "Manifeste absent de la clé." "Manifest missing."
verifie=""
if command -v gpg >/dev/null; then
  mkdir -m 700 "$DOSSIER/gpg"
  gpg --homedir "$DOSSIER/gpg" --quiet --batch --import "$ICI/claude-code.asc" 2>/dev/null
  statut=$(gpg --homedir "$DOSSIER/gpg" --batch --status-fd 1 --verify "$ICI/manifest.json.sig" "$DOSSIER/manifest.json" \
    2>/dev/null || true)
  gpgconf --homedir "$DOSSIER/gpg" --kill all 2>/dev/null
  gpgconf --homedir "$DOSSIER/gpg" --remove-socketdir 2>/dev/null
  rm -rf -- "$DOSSIER/gpg"
  # GOODSIG et VALIDSIG de la clé fixée ; jamais une clé expirée ou révoquée, ni une signature expirée.
  { grep -q '^\[GNUPG:\] GOODSIG ' <<<"$statut" && grep -q "^\[GNUPG:\] VALIDSIG .* $EMPREINTE_CLE\$" <<<"$statut" &&
    ! grep -q '^\[GNUPG:\] \(EXPKEYSIG\|REVKEYSIG\|EXPSIG\) ' <<<"$statut"; } ||
    arret "Signature d'Anthropic absente ou fausse sur le manifeste : rien n'a été lancé. Mettez la clé à jour avec Vanguard." \
      "Anthropic's signature on the manifest is missing or wrong: nothing was started."
  verifie=oui
fi
# L'empreinte de « linux-x64 » dans ce manifeste : par python3 s'il est là (JSON lu pour de vrai), sinon par awk sur
# la forme indentée qu'Anthropic publie.
if [ -n "$(command -v python3)" ]; then
  attendu=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["platforms"]["linux-x64"]["checksum"])' \
    "$DOSSIER/manifest.json" 2>/dev/null)
else
  attendu=$(awk '/"linux-x64"[[:space:]]*:/ { p = 1 } p && /"checksum"/ { gsub(/[^0-9a-f]/, "", $2); print $2; exit }' \
  FS=: "$DOSSIER/manifest.json")
fi
[[ $attendu =~ ^[0-9a-f]{64}$ && $sha == "$attendu" ]] ||
  arret "Empreinte de Claude Code différente du manifeste : rien n'a été lancé. Mettez la clé à jour avec Vanguard." \
    "Claude Code checksum differs from the manifest: nothing was started."
version=$(awk -F'"' '/"version"/ { print $4; exit }' "$DOSSIER/manifest.json")
# Les octets vérifiés savent-ils dire une révocation pas confirmée ? Sinon, aucune déconnexion n'est « confirmée ».
grep -aqF -- "$REVOCATION_DITE" "$EXE" && revocation_dite=oui
if [[ -n $verifie ]]; then
  dire "✔ Claude Code $version, signature d'Anthropic et empreinte vérifiées." "✔ Claude Code $version, Anthropic signature and checksum verified."
else
  dire "⚠ gpg absent : la signature d'Anthropic n'a PAS pu être vérifiée ici (l'empreinte seule l'a été)." \
    "⚠ gpg missing: Anthropic's signature could NOT be verified here (only the checksum)."
  accord "Lancer quand même ? / Run anyway?" || exit 0
fi
chmod 700 "$EXE"
mkdir -m 700 "$DOSSIER/travail" || arret "Dossier de travail impossible à créer."
# Sans ses consignes, Claude dépannerait sans les règles (lecture seule, accord, sécurité jamais baissée) : refusé.
if ! { cp -- "$ICI/CLAUDE.md" "$DOSSIER/travail/CLAUDE.md" 2>/dev/null && [[ -s $DOSSIER/travail/CLAUDE.md ]] &&
  cmp -s -- "$ICI/CLAUDE.md" "$DOSSIER/travail/CLAUDE.md"; }; then
  arret "Consignes de dépannage (Claude/CLAUDE.md) absentes ou illisibles : rien n'a été lancé." \
    "Troubleshooting instructions (Claude/CLAUDE.md) missing or unreadable: nothing was started."
fi
mkdir -m 700 "$DOSSIER/config" "$DOSSIER/tmp" "$DOSSIER/cache" || arret "Dossier de travail impossible à créer."

# Ce qu'une session d'avant a laissé (terminal tué, panne), dans n'importe quel dossier à l'abri : déconnecté avec le
# binaire vérifié, puis effacé.
for b in "${bases[@]}"; do
  for d in "$b"/vanguard-claude.*; do
    [[ -d $d && ! -L $d && -O $d && $d != "$DOSSIER" ]] || continue
    # Une session qui tourne encore (autre terminal) tient son verrou : la laisser. Sans flock, impossible de le
    # savoir : un dossier de session est laissé.
    if [[ -f $d/.session ]]; then
      command -v flock >/dev/null || continue
      flock -n "$d/.session" true 2>/dev/null || continue
    fi
    if nettoyer "$d" "$EXE"; then
      dire "Restes d'une session précédente effacés." "Leftovers of a previous session erased."
      [[ $deconnexion != non ]] || dire "⚠ Sa déconnexion n'est PAS confirmée : fermez cette session sur claude.ai." \
        "⚠ Its logout is NOT confirmed: end that session on claude.ai."
    else
      dire "⚠ Restes d'une session précédente PAS effacés en entier : $d (à regarder, puis effacer à la main)." \
        "⚠ Leftovers of a previous session NOT fully erased: $d (check, then erase by hand)."
      for m in "${montes_dits[@]}"; do dire "    disque encore monté : $m" "    disk still mounted: $m"; done
      [[ $deconnexion == oui ]] || dire "⚠ Sa déconnexion n'est PAS confirmée : fermez cette session sur claude.ai." \
        "⚠ Its logout is NOT confirmed: end that session on claude.ai."
    fi
  done
done
lancee=$EXE
echo
dire "Pour finir : tapez /exit dans Claude. Après un ordinateur douteux : fermez aussi la session sur claude.ai." \
  "To finish: type /exit in Claude. After a doubtful computer: also end the session on claude.ai."
dire "Connecté dans le navigateur de cet ordinateur par erreur : déconnectez-vous de claude.ai avant de partir." \
  "Signed in in this computer's browser by mistake: sign out of claude.ai before leaving."
echo
cd "$DOSSIER/travail" || exit 1
env "${ENV_CLAUDE[@]}" CLAUDE_CONFIG_DIR="$DOSSIER/config" "$EXE" --strict-mcp-config
code=$?
cd / || true
exit "$code"
