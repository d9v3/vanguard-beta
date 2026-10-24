#!/usr/bin/env bash
# Garde-fou : aucun mot d'attaque que Vanguard CHERCHE ne doit rester en clair dans le programme compilé.
#
# Pourquoi : écrits en clair dans le binaire, les noms de commandes d'outils offensifs et de contournements d'AMSI
# suffisent à une signature d'antivirus pour prendre Vanguard pour l'outil qu'il traque (Defender a supprimé une
# version sur la seule présence de « sekurlsa:: », « amsiscanbuffer »… ). src/masque.rs les brouille à la
# compilation ; ce script vérifie que le brouillage tient, dans les deux encodages (ASCII et UTF-16LE, celui de
# PowerShell et du PE).
#
# La liste interdite est ICI, dans l'outil, jamais dans src/ : compilée dans le programme, elle y remettrait en clair
# les mots qu'elle interdit. Elle est en minuscules et comparée tel quel (sensible à la casse) : le programme cherche
# ces mots en minuscules ; un nom d'outil AFFICHÉ garde sa casse de marque (« Mimikatz », « SharpHound »), ce n'est
# pas une signature et il reste lisible.
#
# Inspecte le binaire Linux (compilé ici, debug : les littéraux y sont comme en release), et le .exe Windows et le
# binaire release s'ils existent déjà — sans les compiler, pour rester court.
#   outils/verifier-masque.sh
set -uo pipefail
cd "$(dirname "$0")/.."

SAUTEE=77
command -v strings >/dev/null || { echo "strings absent (Arch : binutils)"; exit "$SAUTEE"; }

CIBLE_LINUX=x86_64-unknown-linux-musl
echo "compilation du binaire Linux (debug) à inspecter…"
if ! cargo build --quiet --target "$CIBLE_LINUX"; then
  echo "la compilation du binaire Linux a échoué"
  exit 1
fi

# Les mots qui ne doivent jamais figurer en clair : noms de commandes d'outils offensifs et noms internes d'AMSI.
# Aucun n'apparaît dans un message montré à l'utilisateur (ceux-là nomment l'outil avec sa casse de marque).
INTERDITS=(
  "sekurlsa::" "lsadump::" "kerberos::golden"
  "mimikatz" "invoke-mimikatz" "invoke-kerberoast" "invoke-shellcode"
  "invoke-reflectivepeinjection" "invoke-dllinjection" "powersploit" "invoke-bloodhound"
  "sharphound" "invoke-powershelltcp" "powercat" "invoke-dcsync" "invoke-tokenmanipulation"
  "get-gpppassword" "invoke-smbexec" "invoke-wmiexec" "invoke-thehash" "out-minidump"
  "get-keystrokes" "invoke-ninjacopy" "invoke-credentialinjection"
  "amsiutils" "amsiinitfailed" "amsiscanbuffer" "amsicontext" "amsiopensession"
  "minidumpwritedump" "rubeus" "lazagne" "xmrig"
)

# Les binaires à inspecter : le Linux qu'on vient de compiler (toujours frais), puis le .exe et le release s'ils sont
# là ET plus récents que src/ — un binaire plus ancien ne reflète plus le code (il sera recompilé avant d'être livré),
# l'inspecter ferait échouer à tort sur un vieux reste.
BINAIRES=("target/$CIBLE_LINUX/debug/vanguard")
NEUF_SRC=$(find src -name '*.rs' -printf '%T@\n' | sort -n | tail -1)
for autre in \
  "target/$CIBLE_LINUX/release/vanguard" \
  "target/x86_64-pc-windows-gnu/release/vanguard.exe" \
  "target/x86_64-pc-windows-gnu/debug/vanguard.exe"; do
  [[ -f $autre ]] || continue
  if (($(printf '%.0f' "$(stat -c %Y "$autre")") >= ${NEUF_SRC%.*})); then
    BINAIRES+=("$autre")
  else
    echo "  ignoré (plus ancien que src/, à recompiler) : $autre"
  fi
done

# Les mots interdits dans un fichier, pour un seul passage de grep -F par binaire et par encodage.
MOTIFS=$(mktemp)
trap 'rm -f "$MOTIFS"' EXIT
printf '%s\n' "${INTERDITS[@]}" >"$MOTIFS"

TROUVES=0
# Les chaînes d'un binaire qui contiennent un mot interdit ; rien si tout est propre. `$2…` : les options de
# strings pour l'encodage (ASCII par défaut, ou `-e l` pour l'UTF-16LE).
cherche() {
  local bin=$1 nom=$2
  shift 2
  local vus
  vus=$(strings -a "$@" -- "$bin" | grep -F -f "$MOTIFS" | sort -u)
  [[ -z $vus ]] && return 0
  echo "✖ $bin : mot(s) d'attaque en clair ($nom) :"
  sed 's/^/      /' <<<"$vus"
  TROUVES=$((TROUVES + 1))
}

for bin in "${BINAIRES[@]}"; do
  [[ -f $bin ]] || continue
  cherche "$bin" ASCII
  cherche "$bin" UTF-16LE -e l
  echo "  inspecté : $bin"
done

if ((TROUVES > 0)); then
  echo "$TROUVES mot(s) d'attaque en clair : voir src/masque.rs (liste_masquee!/mot_masque!)"
  exit 1
fi
echo "aucun mot d'attaque en clair dans ${#BINAIRES[@]} binaire(s)."
