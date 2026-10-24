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
# les mots qu'elle interdit. Un nom d'outil AFFICHÉ garde sa casse de marque (« Mimikatz », « SharpHound »), ce n'est
# pas une signature et il reste lisible : les mots de commande sont donc cherchés sans tenir compte de la casse (une
# régression les écrirait « AmsiScanBuffer », « Invoke-Mimikatz »…), les seuls noms de marque sont cherchés tels quels,
# en minuscules (le programme les cherche en minuscules ; affichés, ils sont capitalisés).
#
#   outils/verifier-masque.sh                 compile le binaire Linux (debug) et l'inspecte, plus le .exe et le
#                                             release s'ils sont déjà là et à jour (étape de verifier.sh) ;
#   outils/verifier-masque.sh <binaire>…      inspecte exactement ces binaires, sans rien compiler (après
#                                             outils/compiler-version.sh, sur le .exe et le release livrés).
set -uo pipefail
cd "$(dirname "$0")/.."

SAUTEE=77
command -v strings >/dev/null || { echo "strings absent (Arch : binutils)"; exit "$SAUTEE"; }

# verifier.sh et la CI suivent CARGO_TARGET_DIR : le binaire frais y va, pas forcément dans ./target.
CIBLE_DIR=${CARGO_TARGET_DIR:-target}
CIBLE_LINUX=x86_64-unknown-linux-musl

# Les mots de commande d'outils offensifs et noms internes d'AMSI : cherchés SANS la casse (jamais affichés tels
# quels). Aucun n'apparaît dans un message montré à l'utilisateur.
INTERDITS_SANS_CASSE=(
  "sekurlsa::" "lsadump::" "kerberos::golden"
  "invoke-mimikatz" "invoke-kerberoast" "invoke-shellcode"
  "invoke-reflectivepeinjection" "invoke-dllinjection" "powersploit" "invoke-bloodhound"
  "invoke-powershelltcp" "powercat" "invoke-dcsync" "invoke-tokenmanipulation"
  "get-gpppassword" "invoke-smbexec" "invoke-wmiexec" "invoke-thehash" "out-minidump"
  "get-keystrokes" "invoke-ninjacopy" "invoke-credentialinjection"
  "amsiutils" "amsiinitfailed" "amsiscanbuffer" "amsicontext" "amsiopensession"
  "minidumpwritedump" "setvalue(\$null,\$true)"
)
# Les noms de marque d'outils : cherchés EN MINUSCULES tels quels, pour ne pas confondre avec le nom affiché
# (« Mimikatz », « SharpHound », « Rubeus », « LaZagne », « XMRig »), qui, lui, est normal et lisible.
INTERDITS_AVEC_CASSE=("mimikatz" "sharphound" "rubeus" "lazagne" "xmrig")

MOTIFS_I=$(mktemp)
MOTIFS_C=$(mktemp)
trap 'rm -f "$MOTIFS_I" "$MOTIFS_C"' EXIT
printf '%s\n' "${INTERDITS_SANS_CASSE[@]}" >"$MOTIFS_I"
printf '%s\n' "${INTERDITS_AVEC_CASSE[@]}" >"$MOTIFS_C"

# Les binaires à inspecter : soit ceux donnés en argument, soit le Linux qu'on compile ici plus les artefacts à jour.
BINAIRES=()
if (($# > 0)); then
  BINAIRES=("$@")
else
  echo "compilation du binaire Linux (debug) à inspecter…"
  if ! cargo build --quiet --target "$CIBLE_LINUX"; then
    echo "la compilation du binaire Linux a échoué"
    exit 1
  fi
  LINUX_DEBUG="$CIBLE_DIR/$CIBLE_LINUX/debug/vanguard"
  if [[ ! -f $LINUX_DEBUG ]]; then
    echo "binaire Linux introuvable après compilation : $LINUX_DEBUG (CARGO_TARGET_DIR ?)"
    exit 1
  fi
  BINAIRES=("$LINUX_DEBUG")
  # Le .exe et le release seulement s'ils sont là ET plus récents que src/ : un binaire plus ancien ne reflète plus
  # le code (il sera recompilé avant d'être livré), l'inspecter ferait échouer à tort sur un vieux reste.
  NEUF_SRC=$(find src -name '*.rs' -printf '%T@\n' | sort -n | tail -1)
  for autre in \
    "$CIBLE_DIR/$CIBLE_LINUX/release/vanguard" \
    "$CIBLE_DIR/x86_64-pc-windows-gnu/release/vanguard.exe" \
    "$CIBLE_DIR/x86_64-pc-windows-gnu/debug/vanguard.exe"; do
    [[ -f $autre ]] || continue
    if (($(stat -c %Y "$autre") >= ${NEUF_SRC%.*})); then
      BINAIRES+=("$autre")
    else
      echo "  ignoré (plus ancien que src/, à recompiler) : $autre"
    fi
  done
fi

# Les chaînes d'un binaire qui contiennent un mot interdit ; rien si tout est propre. `$2…` : les options
# d'encodage de strings (ASCII par défaut, ou `-e l` pour l'UTF-16LE).
TROUVES=0
cherche() {
  local bin=$1 nom=$2
  shift 2
  local chaines vus
  chaines=$(strings -a "$@" -- "$bin")
  vus=$( { grep -iF -f "$MOTIFS_I" <<<"$chaines"; grep -F -f "$MOTIFS_C" <<<"$chaines"; } | sort -u)
  [[ -z $vus ]] && return 0
  echo "✖ $bin : mot(s) d'attaque en clair ($nom) :"
  sed 's/^/      /' <<<"$vus"
  TROUVES=$((TROUVES + 1))
}

INSPECTES=0
for bin in "${BINAIRES[@]}"; do
  if [[ ! -s $bin ]]; then
    echo "✖ binaire absent ou vide : $bin"
    TROUVES=$((TROUVES + 1))
    continue
  fi
  cherche "$bin" ASCII
  cherche "$bin" UTF-16LE -e l
  echo "  inspecté : $bin"
  INSPECTES=$((INSPECTES + 1))
done

if ((INSPECTES == 0)); then
  echo "aucun binaire à inspecter (rien compilé, rien donné) : rien vérifié"
  exit 1
fi
if ((TROUVES > 0)); then
  echo "$TROUVES binaire(s)/mot(s) en défaut : voir src/masque.rs (liste_masquee!/mot_masque!)"
  exit 1
fi
echo "aucun mot d'attaque en clair dans $INSPECTES binaire(s)."
