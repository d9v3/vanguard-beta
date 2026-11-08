@echo off
rem Essai de l isolement du reseau (defense R4) : il coupe le reseau de la VM, sauf la session a distance.
rem Eteint dans les tests ordinaires ; a lancer seulement avec l auteur devant la VM. Le menu s ouvre comme
rem d habitude, et le test (avec questions) fait en plus cet essai.
set VANGUARD_ESSAI_ISOLEMENT=1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0programme\menu.ps1"
if errorlevel 1 pause
