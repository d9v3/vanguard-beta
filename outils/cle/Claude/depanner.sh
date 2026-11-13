#!/usr/bin/env bash
# Dépanner avec Claude, sous Linux (ou sur SystemRescue démarré depuis la clé) : bash /chemin/de/la/clé/Claude/depanner.sh
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
set -uo pipefail

ICI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P) || exit 1
CLE=${ICI%/*}
EMPREINTE_CLE=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
PLACE_MIO=700

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
while IFS= read -r v; do
  case ${v^^} in
    ANTHROPIC_* | CLAUDE_* | NODE_* | BUN_* | SSL_CERT_* | AWS_* | GOOGLE_* | VERTEX_* | OTEL_* | GIT_* | \
      HTTP_PROXY | HTTPS_PROXY | ALL_PROXY | NO_PROXY | REQUESTS_CA_BUNDLE | CURL_CA_BUNDLE | BROWSER) unset "$v" ;;
  esac
done < <(compgen -e)
SOURCE=$ICI/Linux/claude
[[ -f $SOURCE ]] || arret "Claude Code n'est pas sur cette clé (Claude/Linux/claude)." "Claude Code is not on this key."

printf '\n  \e[31mDépanner avec Claude (Vanguard)\e[0m\n  \e[90mTroubleshoot with Claude (Vanguard)\e[0m\n\n'
dire "Claude Code, l'assistant d'Anthropic, va lire cet ordinateur pour trouver la panne. Ce qu'il lit (journaux," \
  "Claude Code, Anthropic's assistant, will read this computer to find the problem. What it reads (logs,"
dire "réglages, noms de fichiers) part chez Anthropic pour être analysé. Il demande avant chaque commande, et ne" \
  "settings, file names) is sent to Anthropic for analysis. It asks before every command, and changes"
dire "change rien sans votre accord. Il faut un compte Claude (abonnement Pro ou Max, ou console Anthropic)." \
  "nothing without your consent. A Claude account is needed (Pro or Max plan, or Anthropic Console)."
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
base=""
for d in "${XDG_RUNTIME_DIR:-}" "$cache" "${TMPDIR:-}" /run; do
  [[ -n $d && -d $d && -w $d && ! -L $d ]] || continue
  a_l_abri "$d" || continue
  if command -v findmnt >/dev/null; then
    findmnt -no OPTIONS -T "$d" 2>/dev/null | tr ',' '\n' | grep -qx noexec && continue
  fi
  (($(df -Pk "$d" 2>/dev/null | awk 'NR == 2 { print $4 + 0 }') / 1024 >= PLACE_MIO)) || continue
  base=$d
  break
done
[[ -n $base ]] || arret "Pas de dossier à soi (ni /tmp, partagé) avec $PLACE_MIO Mio libres où lancer un programme." \
  "No private folder (not the shared /tmp) with $PLACE_MIO MiB free where a program may run."

DOSSIER=$(mktemp -d "$base/vanguard-claude.XXXXXXXX") || arret "Dossier temporaire impossible à créer."
chmod 700 "$DOSSIER"
EXE=$DOSSIER/claude
lancee=""

# Une session : déconnexion avec un binaire vérifié, puis effacement.
# Sans condition : si Claude Code rangeait le jeton ailleurs que dans .credentials.json, il serait quand même
# déconnecté. Délai borné : hors ligne, rien ne bloque.
nettoyer() { # dossier [binaire vérifié]
  local d=$1 exe=${2:-}
  [[ -d $d ]] || return 0
  if [[ -n $exe && -x $exe && -d $d/config ]]; then
    CLAUDE_CONFIG_DIR=$d/config timeout 20 "$exe" auth logout </dev/null >/dev/null 2>&1 || true
  fi
  rm -rf -- "$d"
  [[ ! -e $d ]]
}
# shellcheck disable=SC2329 # appelée par « trap fin EXIT »
fin() {
  # Ignorés, pas remis par défaut : un second Ctrl+C pendant la déconnexion ne laisse pas le jeton derrière.
  trap '' HUP INT TERM
  trap - EXIT
  echo
  if nettoyer "$DOSSIER" "$lancee"; then
    [[ -z $lancee ]] || dire "✔ Déconnecté ; Claude Code et la conversation sont effacés de cet ordinateur." \
      "✔ Logged out; Claude Code and the conversation are erased from this computer."
  else
    dire "✖ $DOSSIER n'a pas pu être effacé : à effacer à la main (rm -rf)." "✖ Could not erase $DOSSIER."
  fi
}
trap fin EXIT
trap 'exit 130' HUP INT TERM
# Tenu pendant toute la session : un second lancement ne prend pas ce dossier pour des restes à effacer.
exec 7>"$DOSSIER/.session"
command -v flock >/dev/null && flock -n 7

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
if command -v python3 >/dev/null; then
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
if [[ -n $verifie ]]; then
  dire "✔ Claude Code $version, signature d'Anthropic et empreinte vérifiées." "✔ Claude Code $version, Anthropic signature and checksum verified."
else
  dire "⚠ gpg absent : la signature d'Anthropic n'a PAS pu être vérifiée ici (l'empreinte seule l'a été)." \
    "⚠ gpg missing: Anthropic's signature could NOT be verified here (only the checksum)."
  accord "Lancer quand même ? / Run anyway?" || exit 0
fi
chmod 700 "$EXE"
lancee=$EXE

# Ce qu'une session d'avant a laissé (terminal tué, panne) : déconnecté avec le binaire vérifié, puis effacé.
for d in "$base"/vanguard-claude.*; do
  [[ -d $d && ! -L $d && -O $d && $d != "$DOSSIER" ]] || continue
  # Une session qui tourne encore (autre terminal) tient son verrou : la laisser. Sans flock, impossible de le
  # savoir : un dossier de session est laissé.
  if [[ -f $d/.session ]]; then
    command -v flock >/dev/null || continue
    flock -n "$d/.session" true 2>/dev/null || continue
  fi
  nettoyer "$d" "$EXE" && dire "Restes d'une session précédente effacés." "Leftovers of a previous session erased."
done

# Claude Code lit aussi les consignes des dossiers au-dessus du dossier de travail, et les réglages imposés à tout
# l'ordinateur : posés là par quelqu'un d'autre, ce seraient des consignes. Refusé, en le disant.
d=$DOSSIER
while [[ $d == /* && $d != / ]]; do
  d=${d%/*}
  [[ -n $d ]] || d=/
  for f in CLAUDE.md CLAUDE.local.md AGENTS.md .claude/CLAUDE.md .claude/AGENTS.md .claude/rules; do
    [[ ! -e ${d%/}/$f && ! -L ${d%/}/$f ]] || arret "${d%/}/$f existe : Claude le lirait comme une consigne. Rien n'a été lancé." \
      "${d%/}/$f exists: Claude would read it as an instruction. Nothing was started."
  done
done
for f in /etc/claude-code/CLAUDE.md /etc/claude-code/managed-settings.json /etc/claude-code/managed-settings.d \
  /etc/claude-code/managed-mcp.json; do
  [[ ! -e $f ]] || arret "$f existe : cet ordinateur impose ses réglages à Claude Code. Rien n'a été lancé." \
    "$f exists: this computer imposes its settings on Claude Code. Nothing was started."
done
mkdir -m 700 "$DOSSIER/travail" || arret "Dossier de travail impossible à créer."
# Sans ses consignes, Claude dépannerait sans les règles (lecture seule, accord, sécurité jamais baissée) : refusé.
if ! { cp -- "$ICI/CLAUDE.md" "$DOSSIER/travail/CLAUDE.md" 2>/dev/null && [[ -s $DOSSIER/travail/CLAUDE.md ]] &&
  cmp -s -- "$ICI/CLAUDE.md" "$DOSSIER/travail/CLAUDE.md"; }; then
  arret "Consignes de dépannage (Claude/CLAUDE.md) absentes ou illisibles : rien n'a été lancé." \
    "Troubleshooting instructions (Claude/CLAUDE.md) missing or unreadable: nothing was started."
fi
mkdir -m 700 "$DOSSIER/config" "$DOSSIER/tmp" || arret "Dossier de travail impossible à créer."
echo
dire "Pour finir : tapez /exit dans Claude. Après un ordinateur douteux : fermez aussi la session sur claude.ai." \
  "To finish: type /exit in Claude. After a doubtful computer: also end the session on claude.ai."
dire "Connecté dans le navigateur de cet ordinateur par erreur : déconnectez-vous de claude.ai avant de partir." \
  "Signed in in this computer's browser by mistake: sign out of claude.ai before leaving."
echo
cd "$DOSSIER/travail" || exit 1
TMPDIR=$DOSSIER/tmp CLAUDE_CONFIG_DIR=$DOSSIER/config DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 VANGUARD_CLE=$CLE \
  "$EXE"
code=$?
cd / || true
exit "$code"
