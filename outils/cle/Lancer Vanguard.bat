@echo off
rem Lance Vanguard dans sa propre fenetre (Windows ne lance rien tout seul depuis une cle USB).
rem Si Windows refuse (Defender l'a bloque, faux positif), le dit et propose d'ouvrir Securite Windows : c'est la
rem personne qui decide d'autoriser Vanguard, dans l'outil de Microsoft. Ce lanceur ne touche jamais a Defender.
setlocal
rem Une commande nommee sans chemin, cmd la cherche d'abord dans le dossier courant : la racine de la cle, ou
rem n'importe qui peut poser un powershell.exe ou un chcp.com. Chaque programme est donc appele par son chemin complet
rem dans System32, et cette variable retire en plus le dossier courant de la recherche (NeedCurrentDirectoryForExePath).
set "NoDefaultCurrentDirectoryInExePath=1"
rem System32 lu dans SystemRoot, sinon windir, et seulement s'il a la forme d'un chemin absolu X:\... : vide ou relatif,
rem il designerait la cle elle-meme. Un cmd 32 bits voit SysWOW64 a sa place, qui a les memes programmes en 32 bits.
set "SYS="
call :systeme SystemRoot
if not defined SYS call :systeme windir
if defined SYS "%SYS%\chcp.com" 65001 >nul
set "VANGUARD=%~dp0Windows\vanguard.exe"
set "PS="
if defined SYS set "PS=%SYS%\WindowsPowerShell\v1.0\powershell.exe"
rem Introuvable, il n'est pas appele : cmd rendrait 9009 ou 3 (chemin introuvable), et 3 doit rester le refus de Windows.
set "CODE=introuvable"
if not defined PS goto sans_powershell
if not exist "%PS%" goto sans_powershell
rem Start-Process echoue si le fichier manque ou si Windows refuse de le lancer (virus detecte, erreur 225) : code 3,
rem le seul qui veut dire « Windows a refuse Vanguard ». Tout autre code non nul vient de PowerShell lui-meme : bloque
rem par une strategie (AppLocker, restriction logicielle) ou arrete avant la commande. Ce n'est alors pas Defender, et
rem le dire ferait chercher une alerte qui n'existe pas.
"%PS%" -NoProfile -NonInteractive -Command "try { Start-Process -FilePath $env:VANGUARD -ErrorAction Stop } catch { exit 3 }; exit 0"
set "CODE=%errorlevel%"
if "%CODE%"=="0" exit /b 0
if not "%CODE%"=="3" goto sans_powershell
echo.
echo   Windows n'a pas pu lancer Vanguard.
echo   Windows could not start Vanguard.
echo.
echo   Le plus souvent, Microsoft Defender l'a bloqué : un faux positif connu, deviné par son
echo   apprentissage automatique (détection qui finit par « !ml »). Vanguard ne contourne pas
echo   Defender : c'est vous qui décidez de l'autoriser, dans Sécurité Windows.
echo   Usually Microsoft Defender blocked it: a known false positive, guessed by its machine
echo   learning (detection ending in "!ml"). Vanguard does not get around Defender: you decide
echo   whether to allow it, in Windows Security.
echo.
echo   Avant d'autoriser quoi que ce soit, vérifiez que c'est bien le vrai Vanguard : cette empreinte
echo   SHA-256 doit être celle de vanguard-windows-x86_64.exe dans SHA256SUMS.txt, sur la page de la
echo   version de Vanguard. Sinon, n'autorisez rien.
echo   Before allowing anything, check this is the real Vanguard: this SHA-256 checksum must match
echo   vanguard-windows-x86_64.exe in SHA256SUMS.txt, on Vanguard's release page. Otherwise, allow nothing.
rem certutil et findstr par leur chemin complet eux aussi ; « call » en tete, pour que la ligne ne commence pas par un
rem guillemet, que cmd /c retirerait avec le dernier.
set "EMPREINTE="
for /f "delims=" %%l in ('call "%SYS%\certutil.exe" -hashfile "%VANGUARD%" SHA256 2^>nul ^| "%SYS%\findstr.exe" /v ":"') do if not defined EMPREINTE set "EMPREINTE=%%l"
if defined EMPREINTE (echo   SHA-256 : %EMPREINTE%) else (echo   Empreinte illisible : programme absent ou verrouillé. / Checksum unreadable: program missing or locked.)
echo.
"%SYS%\choice.exe" /c OYN /n /m "  Ouvrir Sécurité Windows ? / Open Windows Security? [O/Y = oui/yes, N = non/no] "
if errorlevel 3 exit /b 1
start "" "windowsdefender://threat"
echo.
echo   1. Historique de protection : l'alerte de vanguard.exe, Actions, « Autoriser sur l'appareil ».
echo      Protection history: the vanguard.exe alert, Actions, "Allow on device".
echo   2. Puis relancez « Lancer Vanguard ». / Then run "Lancer Vanguard" again.
echo   Pour retirer l'autorisation plus tard : Protection contre les virus et menaces,
echo   « Menaces autorisées ». / To remove the permission later: Virus ^& threat protection,
echo   "Allowed threats".
echo.
pause
exit /b 1

:sans_powershell
rem PowerShell manque ou est bloque : rien n'a ete lance, et Defender n'y est pour rien.
echo.
echo   PowerShell est absent ou bloqué sur cet ordinateur (code %CODE%) : ce lanceur s'en sert
echo   pour démarrer Vanguard et savoir si Windows le refuse. Rien n'a été lancé, et ce n'est pas
echo   Microsoft Defender : il n'y a pas d'alerte à chercher dans Sécurité Windows.
echo   PowerShell is missing or blocked on this computer (code %CODE%): this launcher uses it to
echo   start Vanguard and to tell whether Windows refuses it. Nothing was started, and it is not
echo   Microsoft Defender: there is no alert to look for in Windows Security.
echo.
echo   Vous pouvez lancer Vanguard vous-même : Windows\vanguard.exe, sur cette clé.
echo   You can start Vanguard yourself: Windows\vanguard.exe, on this key.
echo.
pause
exit /b 1

:systeme
rem %1 : le nom d'une variable (SystemRoot, windir). SYS recoit son dossier System32 seulement si elle commence par
rem une lettre, deux-points et une barre oblique inverse, sans guillemet ni caractere special de cmd : sa valeur est
rem ensuite developpee sans guillemets autour (echo, for), ou elle lancerait une autre commande.
setlocal EnableDelayedExpansion
set "R=!%~1!"
if not defined R (endlocal & exit /b 1)
set "S=!R:"=!"
set "S=!S:&=!"
set "S=!S:|=!"
set "S=!S:<=!"
set "S=!S:>=!"
set "S=!S:(=!"
set "S=!S:)=!"
set "S=!S:%%=!"
if not "!S!"=="!R!" (endlocal & exit /b 1)
if not "!R:~1,2!"==":\" (endlocal & exit /b 1)
set "LETTRE="
for %%L in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do if /i "!R:~0,1!"=="%%L" set "LETTRE=1"
if not defined LETTRE (endlocal & exit /b 1)
if "!R:~-1!"=="\" set "R=!R:~0,-1!"
endlocal & set "SYS=%R%\System32"
exit /b 0
