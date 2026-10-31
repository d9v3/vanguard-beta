---
paths:
  - "src/**/windows*"
  - "src/**/windows/**"
  - "outils/test-windows/**"
---

# Windows : pièges déjà rencontrés

- Vanguard lance Windows PowerShell 5.1 (`powershell`), jamais pwsh. `windows::powershell()` retire PSModulePath :
  lancé depuis pwsh 7, PowerShell 5.1 hériterait de ses modules et `Get-AuthenticodeSignature`, les certificats…
  ne se chargeraient pas.
- Un script .ps1 s'écrit avec BOM UTF-8, sinon PowerShell 5.1 le lit en ANSI et casse les accents.
- `ps()` attend un marqueur de fin : une sortie vide sans marqueur (PowerShell bloqué, absent) n'est pas une réponse.
- Registre : `New-Item -Force` sur une clé existante l'écrase, valeurs comprises ; la créer seulement si
  `Test-Path` dit qu'elle manque.
- HKCU dans la fenêtre administrateur = le compte qui l'ouvre (pas forcément la personne) : le HKCU de la personne
  s'écrit depuis Vanguard (winreg). HKCU\Software\Policies est en lecture seule pour l'utilisateur.
- Un processus lancé « runas » (ShellExecuteExW) est créé par le service AppInfo : il n'hérite ni poignée ni tube
  anonyme de Vanguard. Le processus élevé (`eleve.rs`) dialogue par un tube nommé à instance unique, PID vérifié des
  deux côtés ; `const` pour une table dont on compare les adresses se copie à chaque usage : `static`.
- Une DLL importée hors des « DLL connues » est cherchée d'abord à côté de vanguard.exe, avant `main` : la garde est
  DependentLoadFlags = 0x800 dans le Load Config du PE (`chargement.rs`, symbole `_load_config_used`, lu par GNU
  ld) ; `vanguard deploiement verifier-binaire` (`src/deploiement/binaire.rs`, lecteur `src/pe.rs`) refuse de
  déployer un programme qui ne l'a pas, ou à qui manque ASLR (DYNAMIC_BASE, HIGH_ENTROPY_VA), DEP (NX_COMPAT) ou ses
  relocalisations. Aucun contrôle à l'exécution ne la remplace : il arrive après le chargeur.
- La fenêtre administrateur répond par le fichier `.resultats` (une ligne ok/echec par correctif) : c'est un autre
  processus, son code de retour ne suffit pas.
- Vérifier un script généré : l'écrire depuis un test temporaire sous Wine (chemin `Z:\…`), puis l'analyser avec
  pwsh pour Linux (`[System.Management.Automation.Language.Parser]::ParseInput`) ; pwsh se télécharge depuis les
  versions GitHub de PowerShell (vérifier l'empreinte SHA-256).
- La machine virtuelle de test est en anglais : chercher les messages de Windows dans les deux langues.
