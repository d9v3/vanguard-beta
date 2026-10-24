VANGUARD for Windows — how to run it
===================================
Français : LISEZMOI.txt

The program: "vanguard.exe", in this folder. Windows 10 and 11 (64-bit), nothing to install.


1. THE EASIEST WAY

   Double-click "vanguard.exe" (here), or "Lancer Vanguard.bat" at the root of the key.
   Windows runs nothing by itself from a USB key (protection against viruses): you have to
   double-click.


2. IN POWERSHELL OR WINDOWS TERMINAL

   Right-click the Start button > "Terminal" (Windows 11) or "Windows PowerShell" (Windows 10).
   This command finds the key whatever its letter (D:, E:…) and starts Vanguard:

     & "$((Get-Volume -FileSystemLabel VANGUARD).DriveLetter):\Windows\vanguard.exe"

   If you know the letter of the key (here E:, see File Explorer > This PC):

     & "E:\Windows\vanguard.exe"
     & "E:\Windows\vanguard.exe" check


3. IN THE COMMAND PROMPT (cmd)

   Windows key, type "cmd", Enter. Then (replace E: with the letter of the key):

     E:\Windows\vanguard.exe
     E:\Windows\vanguard.exe check


4. USEFUL COMMANDS

   Nothing after "vanguard.exe": the menu. Otherwise:

     vanguard.exe check               full check: this machine, then the network
     vanguard.exe check --text        same check, report as plain text
     vanguard.exe fix                 check, then each fix shown and confirmed
     vanguard.exe audit               audit of this machine only
     vanguard.exe devices             local network scan
     vanguard.exe updates             updates: Windows, programs (winget), drivers…
     vanguard.exe repair              repairs: Internet, stuck Windows Update, full disk…
     vanguard.exe clean --list        space to gain, deleting nothing
     vanguard.exe connection-test     connection test: ping, speed, bufferbloat
     vanguard.exe antivirus <folder>  scan a key, a disk or a folder (Defender)
     vanguard.exe --help              every command (vanguard.exe <command> --help: the details)
     vanguard.exe --version           the version


5. GOOD TO KNOW

   - No need to open the terminal as administrator: each fix first shows what it will do, then asks
     for administrator consent itself (UAC window).
   - The program is not signed: SmartScreen may warn ("More info" > "Run anyway") and Microsoft
     Defender may flag it, because it scans ports. Started from the key, SmartScreen usually says
     nothing.
   - If Defender blocks Vanguard (false positive): "Lancer Vanguard.bat" says so and offers to open
     Windows Security. You choose "Allow on device" in the protection history; Vanguard never
     changes Defender itself.
   - In French:  $env:VANGUARD_LANG = "fr"  (PowerShell)  or  set VANGUARD_LANG=fr  (cmd), then the
     command.
   - Quit: q in the menu, or Ctrl+C.

Full guide (menu, key protection, language): README.txt at the root of the key.
