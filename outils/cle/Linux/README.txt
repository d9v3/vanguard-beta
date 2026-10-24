VANGUARD for Linux — how to run it
=================================
Français : LISEZMOI.txt

The program: "vanguard", in this folder. Any 64-bit distribution (x86_64), nothing to install.


1. THE EASIEST WAY

   Double-click "autorun.sh" at the root of the key: a terminal opens with the menu.
   GNOME also offers it when the key is plugged in ("Run software?").


2. IN A TERMINAL

   Open a terminal (Ctrl+Alt+T on most desktops) and type the path of the program, without first going
   into the key with "cd": on another computer, Vanguard remounts the key read-only to protect it, which
   fails if a terminal is open in it.

     /run/media/$USER/VANGUARD/Linux/vanguard     Arch, Fedora, openSUSE, Manjaro…
     /media/$USER/VANGUARD/Linux/vanguard         Ubuntu, Debian, Mint, Pop!_OS…

   Where is the key mounted?   lsblk -o LABEL,MOUNTPOINT | grep VANGUARD
   Tip: type the start of the path, then the Tab key to complete it.


3. USEFUL COMMANDS

   Nothing after "vanguard": the menu. Otherwise ("vanguard" = the full path above):

     vanguard check                full check: this machine, then the network
     vanguard check --text         same check, report as plain text (server without a screen)
     vanguard fix                  check, then each fix shown and confirmed
     vanguard audit                audit of this machine only
     vanguard devices              local network scan
     vanguard updates              updates: system, Flatpak, Snap, firmware…
     vanguard repair               repairs: Internet, full disk, stuck updates…
     vanguard clean --list         space to gain, deleting nothing
     vanguard connection-test      connection test: ping, speed, bufferbloat
     vanguard antivirus <folder>   scan a key, a disk or a folder
     vanguard --help               every command (vanguard <command> --help: the details)
     vanguard --version            the version


4. GOOD TO KNOW

   - The terminal does not need root: a fix asks for your password (sudo) when you accept it, never
     before.
   - "Permission denied": the key is mounted without execute rights (noexec option). Copy the program,
     then run it:  cp /run/media/$USER/VANGUARD/Linux/vanguard ~/ && ~/vanguard
   - To install it on this computer: copy "vanguard" to ~/.local/bin, then just type "vanguard" in any
     terminal.
   - In French:  VANGUARD_LANG=fr /run/media/$USER/VANGUARD/Linux/vanguard
   - Quit: q in the menu, or Ctrl+C.


5. INSTALLING LINUX FROM THE KEY

   Boot the computer from the key (boot menu key: F12, F11, F8 or Esc depending on the PC), then pick
   from the Ventoy menu. Debian, Fedora and Arch install over the Internet (cable or Wi-Fi).
   - Omarchy: pick "Omarchy": its installer sets up everything (encrypted disk included), no Internet.
     By hand from Arch Linux (archinstall, then "curl -fsSL https://omarchy.org/install | bash"):
     https://learn.omacom.io/2/the-omarchy-manual/96/manual-installation
   - The images update themselves (Ventoy too, once you agree) when the key is plugged into the computer
     that prepares it, and every day if it stays plugged in there.

Full guide (menu, key protection, language): README.txt at the root of the key.
