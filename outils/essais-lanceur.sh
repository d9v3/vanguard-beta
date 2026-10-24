#!/usr/bin/env bash
# Essais de « Lancer Vanguard.bat » (outils/cle) sous Wine, avec un faux powershell.exe : les codes qu'il rend (0, 3,
# 1, 1260), PowerShell introuvable, SystemRoot vide ou relatif, et des programmes posés à la racine de la clé, qui ne
# doivent jamais être lancés. Le faux powershell.exe (compilé ici par le gcc de MinGW) note chaque appel et sort avec
# le code voulu, sans rien lancer. Lancé par outils/verifier.sh à la fin des tests Windows, dans leur préfixe Wine
# jetable (WINEPREFIX) ; seul, il en crée un. Code 77 (sauté) sans Wine ou sans MinGW. Ce que fait le vrai Windows
# (Start-Process, Defender, cmd 32 bits, l'empreinte : le findstr de Wine ignore /v) n'est vu que dans la VM (test.ps1).
#   outils/essais-lanceur.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
DEPOT=$PWD
WINE=${VANGUARD_WINE:-$HOME/.local/share/Steam/compatibilitytools.d/GE-Proton11-9-x86_64/files/bin/wine}
[[ -x $WINE ]] || { echo "Wine absent ($WINE ; VANGUARD_WINE pour un autre)"; exit 77; }
command -v x86_64-w64-mingw32-gcc >/dev/null || { echo "x86_64-w64-mingw32-gcc absent (Arch : mingw-w64-gcc)"; exit 77; }

# Hors de /tmp (quota partagé) ; un banc resté là (essais tués) part au ménage de la semaine (outils/menage-dev.sh).
mkdir -p "$HOME/.cache/vanguard-dev"
T=$(mktemp -d "$HOME/.cache/vanguard-dev/essai-lanceur.XXXX") || exit 1
PROPRE=
if [[ -z ${WINEPREFIX:-} ]]; then
  export WINEPREFIX=$T/prefixe
  PROPRE=1
fi
nettoyer() {
  if [[ -n $PROPRE ]]; then
    "${WINE%/*}/wineserver" -k 2>/dev/null
    "${WINE%/*}/wineserver" -w 2>/dev/null
  fi
  rm -rf "$T"
}
trap nettoyer EXIT
export WINEDEBUG=-all
unset DISPLAY WAYLAND_DISPLAY

# Le chemin Windows d'un fichier de Linux : Wine montre la racine comme le lecteur Z:.
z() { local p=${1//\//\\}; echo "Z:$p"; }

# Faux powershell.exe : une ligne « <QUI> <arguments> » dans ESSAI_TRACE, puis le code ESSAI_CODE_PS (0 sans).
cat >"$T/faux.c" <<'FIN'
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
int main(void) {
  const char *trace = getenv("ESSAI_TRACE"), *code = getenv("ESSAI_CODE_PS");
  if (trace) {
    FILE *f = fopen(trace, "a");
    if (f) { fprintf(f, "%s %s\n", QUI, GetCommandLineA()); fclose(f); }
  }
  return code ? atoi(code) : 0;
}
FIN
for qui in systeme racine; do
  x86_64-w64-mingw32-gcc -O1 -s -DQUI="\"$qui\"" -o "$T/faux-$qui.exe" "$T/faux.c" ||
    { echo "faux powershell.exe : compilation en échec"; exit 1; }
done

# Le préfixe prêt (créé s'il est neuf), et son vrai dossier System32.
"$WINE" cmd /c exit 0 >/dev/null 2>&1
SYS32=$WINEPREFIX/drive_c/windows/system32
[[ -d $SYS32 ]] || { echo "préfixe Wine sans system32 : $SYS32"; exit 1; }
PS_SYS=$SYS32/WindowsPowerShell/v1.0/powershell.exe
mkdir -p "${PS_SYS%/*}"
poser_ps() { cp -f "$T/faux-systeme.exe" "$PS_SYS"; }
retirer_ps() { rm -f "$PS_SYS"; }

# La clé : le lanceur seul, sans Windows\vanguard.exe (le faux PowerShell ne lance rien), et à sa racine, des
# programmes piégés sous les noms qu'il appelle : powershell.exe, chcp.com, choice.exe, certutil.exe, findstr.exe, et
# un System32 pour un SystemRoot relatif.
CLE=$T/cle
mkdir -p "$CLE/Windows" "$CLE/System32/WindowsPowerShell/v1.0"
cp "$DEPOT/outils/cle/Lancer Vanguard.bat" "$CLE/"
for f in powershell.exe chcp.com choice.exe certutil.exe findstr.exe System32/WindowsPowerShell/v1.0/powershell.exe; do
  cp "$T/faux-racine.exe" "$CLE/$f"
done
# Un environnement changé avant le lanceur : SystemRoot et windir, puis l'appel, depuis la racine de la clé.
avec_env() { # nom SystemRoot windir
  printf '@set "SystemRoot=%s"\r\n@set "windir=%s"\r\n@call "%%~dp0Lancer Vanguard.bat"\r\n' "$2" "$3" >"$CLE/$1.bat"
}

ESSAIS=0 ECHECS=0
voir() { # libellé commande… : la commande doit réussir
  ESSAIS=$((ESSAIS + 1))
  if "${@:2}"; then echo "  ✔ $1"; return 0; fi
  ECHECS=$((ECHECS + 1)); echo "  ✖ $1"
  sed 's/^/      | sortie : /' "$T/sortie" | head -30
  sed 's/^/      | appels : /' "$T/trace" 2>/dev/null
  return 1
}
dit() { grep -qF -- "$1" "$T/sortie"; }
pas_dit() { ! grep -qF -- "$1" "$T/sortie"; }
appels() { cat "$T/trace" 2>/dev/null | grep -c "^$1 "; }
# Le lanceur (ou un .bat d'environnement) depuis la racine de la clé, comme un double-clic ; N au choix, puis
# Entrée pour la pause. Sa sortie dans $T/sortie, son code dans $code.
lancer() { # code-du-faux-powershell [bat]
  rm -f "$T/trace"
  (cd "$CLE" && printf 'N\r\n\r\n' | ESSAI_CODE_PS=$1 ESSAI_TRACE=$(z "$T/trace") \
    timeout 60 "$WINE" cmd /c "${2:-Lancer Vanguard.bat}" >"$T/sortie" 2>&1)
  code=$?
  tr -d '\r' <"$T/sortie" >"$T/sortie.lf" && mv "$T/sortie.lf" "$T/sortie"
}
DEFENDER='Windows could not start Vanguard'
SANS_PS='PowerShell is missing or blocked'

echo "Lanceur de la clé (Lancer Vanguard.bat), sous Wine :"
poser_ps
lancer 0
voir "PowerShell rend 0 : code 0, rien dit, Start-Process demandé" \
  eval '((code == 0)) && pas_dit "$DEFENDER" && pas_dit "$SANS_PS" && [[ $(appels systeme) == 1 ]] && grep -q "Start-Process" "$T/trace"'
voir "le powershell.exe de System32 lancé par son chemin complet" \
  grep -qiF 'WindowsPowerShell\v1.0\powershell.exe' "$T/trace"
voir "rien de la racine de la clé lancé (powershell.exe, chcp.com, System32 relatif)" eval '[[ $(appels racine) == 0 ]]'
lancer 3
voir "code 3 (Start-Process refusé) : Defender expliqué, empreinte dite illisible, code 1" \
  eval '((code == 1)) && dit "$DEFENDER" && dit "Checksum unreadable" && pas_dit "$SANS_PS" && [[ $(appels racine) == 0 ]]'
for c in 1 1260; do
  lancer "$c"
  voir "code $c (PowerShell bloqué) : dit sans accuser Defender, code 1" \
    eval '((code == 1)) && dit "$SANS_PS" && dit "(code $c)" && pas_dit "$DEFENDER" && [[ $(appels racine) == 0 ]]'
done
retirer_ps
lancer 0
voir "PowerShell absent de System32 : dit introuvable, pas Defender, celui de la racine pas lancé, code 1" \
  eval '((code == 1)) && dit "$SANS_PS" && dit "(code introuvable)" && pas_dit "$DEFENDER" && [[ $(appels racine) == 0 ]]'
poser_ps
avec_env relatif 'System32\..' '.'
lancer 0 relatif.bat
voir "SystemRoot et windir relatifs : pas de PowerShell cherché dans la clé, dit introuvable, code 1" \
  eval '((code == 1)) && dit "(code introuvable)" && pas_dit "$DEFENDER" && [[ ! -s $T/trace ]]'
avec_env vide '' ''
lancer 0 vide.bat
voir "SystemRoot et windir vides : dit introuvable, rien lancé, code 1" \
  eval '((code == 1)) && dit "(code introuvable)" && pas_dit "$DEFENDER" && [[ ! -s $T/trace ]]'
# Sans guillemets autour, set garde le guillemet dans la valeur.
printf '@set SystemRoot=C:\\windows"x\r\n@set "windir=C:\\windows&powershell.exe"\r\n@call "%%~dp0Lancer Vanguard.bat"\r\n' >"$CLE/special.bat"
lancer 0 special.bat
voir "SystemRoot et windir avec guillemet ou & : refusés, rien lancé, code 1" \
  eval '((code == 1)) && dit "(code introuvable)" && pas_dit "$DEFENDER" && [[ ! -s $T/trace ]]'
avec_env repli '' 'C:\windows\'
lancer 0 repli.bat
voir "SystemRoot vide, windir bon (barre finale) : PowerShell de System32 lancé, code 0" \
  eval '((code == 0)) && [[ $(appels systeme) == 1 && $(appels racine) == 0 ]]'

echo "$ESSAIS essais, $ECHECS en échec."
((ECHECS == 0))
