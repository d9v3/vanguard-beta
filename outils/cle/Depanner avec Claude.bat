@echo off
rem Depanner avec Claude : lance Claude Code depuis la cle (Claude\depanner.ps1 fait tout : accord, verification de la
rem signature d'Anthropic, dossier temporaire efface en sortant). Mode d'emploi : Claude\LISEZMOI.txt.
setlocal
rem Comme Lancer Vanguard.bat : chaque programme par son chemin complet dans System32, et le dossier courant (la cle,
rem ou n'importe qui peut poser un powershell.exe) retire de la recherche des commandes.
set "NoDefaultCurrentDirectoryInExePath=1"
set "SYS="
call :systeme SystemRoot
if not defined SYS call :systeme windir
if not defined SYS goto sans_powershell
"%SYS%\chcp.com" 65001 >nul
set "PS=%SYS%\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" goto sans_powershell
rem -ExecutionPolicy Bypass pour ce script seulement, le temps de ce processus : la strategie de l'ordinateur ne
rem change pas. Une strategie imposee par l'entreprise (GPO) l'emporte, et le script ne se lance pas.
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Claude\depanner.ps1"
set "CODE=%errorlevel%"
rem La fenetre reste ouverte : le dernier message (refus, effacement) doit pouvoir se lire.
echo.
pause
exit /b %CODE%

:sans_powershell
echo.
echo   PowerShell est absent ou bloqué sur cet ordinateur : Claude Code ne peut pas être lancé d'ici.
echo   PowerShell is missing or blocked on this computer: Claude Code cannot be started from here.
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
