VANGUARD for macOS — how to run it
=================================
Français : LISEZMOI.txt

The program: "vanguard", in this folder. macOS 12 Monterey and later, Apple Silicon (M1, M2…) and
Intel Macs, nothing to install.


1. THE EASIEST WAY

   Double-click "Lancer Vanguard.command" at the root of the key: Terminal opens with the menu.


2. IN TERMINAL

   Open Terminal (Cmd+Space, type "Terminal", Enter; or Applications > Utilities) and type the path of
   the program, without first going into the key with "cd": on another Mac, Vanguard remounts the key
   read-only to protect it, which fails if Terminal is open in it.

     /Volumes/VANGUARD/macOS/vanguard

   Tips: type "/Volumes/VA" then the Tab key to complete; or drag the "vanguard" file from the Finder
   into the Terminal window, then Enter.


3. USEFUL COMMANDS

   Nothing after "vanguard": the menu. Otherwise ("vanguard" = /Volumes/VANGUARD/macOS/vanguard):

     vanguard check                full check: this Mac, then the network
     vanguard check --text         same check, report as plain text
     vanguard fix                  check, then each fix shown and confirmed
     vanguard audit                audit of this Mac only
     vanguard devices              local network scan
     vanguard updates              updates: macOS, Homebrew, App Store…
     vanguard repair               repairs: Internet, DNS, full disk…
     vanguard clean --list         space to gain, deleting nothing
     vanguard connection-test      connection test: ping, speed, bufferbloat
     vanguard antivirus <folder>   scan a key, a disk or a folder (ClamAV)
     vanguard --help               every command (vanguard <command> --help: the details)
     vanguard --version            the version


4. GOOD TO KNOW

   - A fix asks for your session password (sudo) when you accept it, never before.
   - Started from the key, Vanguard opens without a warning. Copied from the Internet or by AirDrop,
     macOS blocks it ("unidentified developer"): in Terminal, xattr -d com.apple.quarantine vanguard, or
     right-click > Open in the Finder.
   - Antivirus (ClamAV), software and gaming go through Homebrew, offered if it is missing.
   - In French:  VANGUARD_LANG=fr /Volumes/VANGUARD/macOS/vanguard
   - Quit: q in the menu, or Ctrl+C.

Full guide (menu, key protection, language): README.txt at the root of the key.
