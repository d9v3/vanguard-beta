VANGUARD — portable cyber defense for endpoints and networks
============================================================
Version française : LISEZMOI.txt

Vanguard hardens computers, detects vulnerabilities and intrusions (check graded from A to F, network audit,
threat hunting, YARA scan, logs, spyware, outdated software, post-quantum key exchange), blocks the threats it
finds, collects the evidence of an incident and prepares, without ever sending it, the report of a flaw to its
vendor. Every finding is explained; nothing is changed without consent. Also included: troubleshooting,
optimization, data and backup; in development, images that start a computer that no longer boots (ISO folder).

This USB key holds the program for Linux, Windows and macOS, its database and its source code.

  Linux/vanguard        Linux (any distribution, nothing to install)
                        Double-click autorun.sh, or in a terminal (outside the key):  <key>/Linux/vanguard
  Windows/vanguard.exe  Windows 10/11: double-click (or "Lancer Vanguard.bat" at the root).
  macOS/vanguard        macOS 12 and later (Apple Silicon and Intel): double-click "Lancer Vanguard.command" at the
                        root (Terminal opens).
  autorun.sh            Linux: GNOME offers to run it when the key is plugged in; otherwise double-click or ./autorun.sh
  donnees/              Device database (one notebook per network: the owner's, each friend's) and the latest
                        report (rapport.html, and rapport.md as plain text, readable without a browser). It travels with the key: any Vanguard that sees the key plugged in uses it. On another
                        computer the key is protected: the database is read there, and what is added stays on that computer.
  traces/               Traces collected after an infection (vanguard evidence), one dated folder per collection;
                        in clear text, with personal data. Away from the owner's computer, the key is protected:
                        they stay on that computer.
  source/               Full source code (Rust) with its git history.
  ISO/                  In development, missing from some keys: images that boot a computer, from the Ventoy
                        menu (Omarchy, Arch Linux, Debian, Fedora, SystemRescue and Windows 11).
                        How to: README.txt in the Linux folder, part 5.
  vanguard.cle          Marker file that makes the key recognized: do not delete it.

How to run each version, command line included (Terminal, PowerShell, Command Prompt): README.txt in the
Linux, Windows and macOS folders.

Protection: the key has two parts. VANGUARD (everything above) is read-only on Windows, and on Linux and macOS
Vanguard remounts it read-only itself at startup: another computer cannot modify the program. Only its owner's computer
can write to it. VANGUARDLOG, small and writable, holds journal-erreurs.txt: the errors encountered
(version, system, message), without user name, computer name or home folder. Back on the owner's computer, they
become GitHub issues, to improve Vanguard. It also holds ordinateurs.json (My computers: grade and problem categories
of each computer, without names), which never goes to GitHub.
Protected data: if the owner protected the key's data (Data menu), Vanguard asks for the passphrase on another
computer to read the device record; Enter with nothing, it goes on without the record. Windows
never starts anything by itself from a USB key (protection against viruses since Windows 7): double-click it.

To start: run Vanguard, choose "1. Full check", then "2. Fix".

Menu (↑ ↓ to select, Enter or → to run, Esc, ← or Backspace to go back; or the number, then Enter; the window
opened for Vanguard takes the menu's size)
Search: in any menu, type a word (wifi, disk, dns…): only the lines containing it stay, Enter opens the
highlighted one, Esc clears it. In the main menu, it also finds each tool of the submenus (“5.3”: group 5,
3rd tool, which can also be typed as is) and each page of the guide.
  1  Full check: machine + network, with what changed since the previous check
  2  Fix the problems found (each fix is shown, then confirmed)
  3  Detailed report in the browser, with the grade history

  4  This machine ›
       Security audit · Updates (system, programs, drivers, firmware)
       Repair and clean up (Internet, hijacked browsing, firewall, disk full, stuck updates…)
       Diagnostic (hardware, recent crashes and errors, text copy on the key)
       Critical file integrity (accounts, sudo, SSH, startup; live: vanguard integrity --live)
       What Vanguard has learned: your habits, and the alerts you declared normal ("i" when fixing, in monitoring,
         the watcher or blocking)
       Why is it slow? (processor, memory, disk, startup, programs started at login; remove them from
       startup or put them back, after your consent: vanguard startup)
       Computer specs (model, processor, memory, graphics card, disks; serial numbers on screen)
       Report to leave behind: a simple page for the person you helped, put on their Desktop
       What Vanguard changed: each fix run here, dated, successful or not; those marked "undoable" can be undone
         there one by one, then the previous state is read back
       Monthly check-up: one notification a month (grade, updates, space to free, new problems)
       Settings (also "s" in the main menu): language, emojis, working without the Internet, real-time
         protection, monitoring, check-up, learned alerts, blocking, extension restrictions, abuse.ch key
         (masked); the previous value is shown, except for learned alerts and blocking, which open their own
         screen (vanguard settings)
       Real-time protection: the hourly monitoring and the active protection of blocking turned off at once,
         after your consent, for 1 h, 4 h or until turned back on; never Defender, the firewall or UAC, and a
         block already made stays in place (vanguard settings real-time no --for 1h)
  5  Network and Internet ›
       Scan the network (and unmask a password thief like Responder)
       Network audit: six grades (Internet exposure, Wi-Fi, device separation, DNS and certificates, connected
         devices, computers), attacking nothing; also done by the full check (vanguard network-audit)
       Deep scan of one device · Name a device ("HP printer")
       Hourly monitoring (unknown device, problem on this machine, router impersonation,
         name poisoner, program landing in Downloads)
       Monitoring dashboard: alerts day by day, new devices (local page)
       Watcher (Linux): programs started and connections closed seen as they happen, off by default
         (vanguard watcher on); and, on request, personal folders watched live against ransomware: an alert
         within seconds, freeze then stop of an almost-certain case only with active protection
         (vanguard watcher ransomware on)
       Connection test for gaming (ping, jitter, speed, bufferbloat), compared with your habits
       Address on blocklists? (Spamhaus, SpamCop, DroneBL, PSBL, after your consent; vanguard blocklists)
       Crowded Wi-Fi? (nearby networks by channel, and the freest channel to set on the router)
       NAT type for gaming (open, moderate or strict) · Hidden cameras? (rental, someone else's place)
       Router and connected devices: the router's model, cameras, printers, NAS… and their default password
         (from the last scan, nothing is probed)
       Public Wi-Fi mode (café, hotel, airport): incoming connections closed, sharing and name announcement off,
         protective DNS, after your consent; everything put back exactly when you leave (vanguard public-wifi)
  6  Antivirus and protection ›
       Quick scan · Full scan of the home folder
       USB drive or folder, with USB worm traps (fake shortcuts, autorun)
       YARA scan: 308 rules for malware families (ransomware, password stealers…)
         and the fingerprints of known malware from MalwareBazaar (free abuse.ch key)
       Process memory: the YARA rules in the memory of running programs (fileless malware), on demand;
         the memory of LSASS and protected processes is never read (vanguard memory)
       Decoy files: decoys in your folders; ransomware touching them triggers the alert
       Windows Defender blocking: password theft, booby-trapped attachments, dangerous sites, ransomware
       Sandbox: run an unknown program with no network, away from your files
       Passwords: have they leaked? (only 5 characters of their fingerprint are sent)
       Browser passwords: counted and their protection described, never read; each browser's own check
       Email address: has it leaked? (sent to the search service, after your consent)
       Who talks to the Internet? Each program's connections, with the server's name, and known botnet
         servers (Feodo Tracker, ThreatFox); read-only
       Camera and mic: who uses them? (Windows: each program and the last time; read-only)
       Privacy check: who can access location, contacts, camera and microphone (read-only)
       Is my computer being controlled? Remote control tools (tech-support scam), removed after your consent
       Is this link dangerous? Checked without opening it; its age and public lists, after your consent
       Check a downloaded file: checksum compared with the site's, name and content, YARA, antivirus
       Quarantine: restore a file isolated by the antivirus or YARA (false positive), or delete it
       Secrets in git projects: passwords and keys forgotten in the history (and gitleaks, if present)
       Flaws in Docker images: known serious or critical flaws (trivy, if present)
       Block dangerous sites: URLhaus ones and ThreatFox command servers, in the hosts file, after your consent;
         removed exactly (vanguard dangerous-sites)
       Latest exploited flaws: those CISA just added to its catalog (vanguard latest-flaws)
       Is this email a scam? A saved email (.eml) examined without opening anything: sender, links, attachments
         (vanguard suspicious-email)
       Spyware: is someone watching me? Known servers and sites, programs reading the keyboard, monitoring
         permissions (read-only; vanguard spyware)
       Outdated software (Windows, macOS): browsers, Office, Acrobat, Java, 7-Zip… and their exploited flaws
         (read-only; vanguard outdated-software)
       Report a flaw to a vendor: a draft in the program's format (MSRC, Mozilla, GHSA advisory…), what is
         personal removed; nothing is ever sent (vanguard disclose)
       Threat blocking: one-click "Block" for each threat found (action shown, written down, undoable);
         active protection, once enabled, blocks clear-cut threats by itself (vanguard blocking)
  7  Install and play ›
       Software: the best ones, mostly open source, by category (browsers, passwords, office, video,
       design, system tools…) plus a starter pack, from the official source
       Gaming (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, MangoHud, Wine, Lutris…;
       macOS: Rosetta 2, Steam, Heroic, Epic, GOG, Prism, Metal counter)
  8  Optimize ›
       Clean up the system (caches, temporary files, packages, trash…: the space of each, to check)
       Recommended settings, in one go · Privacy (telemetry, ads, tracking, Recall…)
       Performance and reliability (fast startup, SSD…) · Comfort and files (file extensions shown,
       no autorun from USB drives, full right-click menu…)
       Fastest DNS (measured here; a DNS that protects you is kept) · Put everything back
       Each setting shows its state and can be reverted exactly: the previous value is put back. "Put everything
       back" also undoes check-up fixes, Gaming, blocks and public Wi-Fi mode (vanguard optimize undo).
  9  Data ›
       Back up or restore (nicknames, network history)
       Copy my files to an external disk (checked copy, nothing deleted, resumes after an interruption)
       Automatic backup to an external disk, with the system's tool (undoable)
       Check a copy: read back from the disk and compared with the originals (restore test)
       Check my drive: real capacity (fake drives), speeds, bad blocks; writes into the free space, then erases
       Shortcut on this computer: Vanguard copied here and started with one click
       My computers: those where the key ran a check, their grade and remaining problems (vanguard computers)
       Protect the key's data: device record encrypted by a passphrase, asked only elsewhere
       Update Vanguard: the copy on this computer, from the key or from GitHub (d9v3/vanguard-update,
         each version signed by the author and checked)
       Check my backup: the rsync backup read back, random files compared with their original
       Remove Vanguard from this computer: what it placed, shown then checked; data kept unless you agree
         twice (vanguard uninstall)
 10  Command guide › the useful commands of Omarchy, Arch, Fedora, Debian, Windows 11, macOS and all systems, by
       program, each one explained (⚠: it changes something), with step-by-step guides (update, repair, network,
       free up space…). Type what you are looking for: commands show up as
       you type; each one can be copied, or run here if it only reads. And the tldr-pages examples, already on
       the key and updated every week: to copy only. From the command line:
       vanguard guide fedora, vanguard guide winget, vanguard guide dns cache
 11  Troubleshoot step by step › no Internet, Wi-Fi dropping, slow computer, no sound, printer, disk full:
       two or three questions, then Vanguard checks and suggests the right repair.
       And: after an infection, new computer, computer leaving (sale, gift), hacked account,
       a relative's computer (three questions, a summary in plain words, the page to leave; vanguard relative).
       Collect the traces before cleaning up: processes, connections, startup, logs, recent files, in a
       dated folder with their fingerprints, and the incident timeline (CHRONOLOGIE.txt): everything dated,
       in time order (read-only, nothing is sent; vanguard evidence).
       From the command line: vanguard troubleshoot sound
 12  Extensions › your own programs, outside Vanguard's code: plugins (a folder with plugin.toml, added from a
       folder or a .zip archive), lab scripts dropped as they are, and the restrictions switch. Each one is scanned
       (YARA, MalwareBazaar) and approved by its fingerprints before it runs, never by itself as administrator; its
       findings never count in the grade.
       From the command line: vanguard plugin, vanguard lab, vanguard extensions
  q  Quit · s Settings
  Shortcuts from earlier versions, in the main menu: u updates, r repair, o diagnostic, i integrity,
  n name, c connection, a USB drive, b sandbox, p passwords, e email, l software, g gaming, d data.

The check covers, among others: firewall, open ports, updates, outdated software (Windows, macOS) and software
installed since the last check, encryption, accounts, password policy, SSH (its failed login attempts, its broken
algorithms; on Windows, the OpenSSH server and keys without a passphrase), guessed password (successful sign-in
after a burst of failures), Wi-Fi (and fake access points copying its name), programs started at boot, suspicious
running programs, Windows backdoors and hidden doors (LSA packages, print monitors…), Defender protections turned
off, startup security and background items on macOS, vulnerable drivers, rootkit signs on Linux, Windows event
logs, spyware, overly permissive AI agents, DNS, added root certificates, browser extensions, Bluetooth, clock,
end of support, forgotten accounts, browser passwords, sensitive files, backups, disk and battery health,
post-quantum key exchange (SSH, browsers, WireGuard; read-only). Each rule cites its reference (CIS, Microsoft or
ANSSI). Self-test: vanguard self-test runs every rule without changing anything and compares Vanguard's readings
with those of the system's tools (pacman, systemctl, ss, PowerShell…); the monitoring runs it again every week.

Language: French or English, following the system. To force English: the Settings menu ("s"), or
  Linux:   VANGUARD_LANG=en ./vanguard
  Windows: in the command prompt, set VANGUARD_LANG=en then vanguard.exe
  macOS:   VANGUARD_LANG=en <key>/macOS/vanguard
Menus shifted in the old Windows command prompt: set VANGUARD_EMOJI=0 (done by default outside Windows
Terminal).

Good to know
  - Fixes are never applied without confirmation. On Windows, fourteen settings from a fixed allowlist (WDigest,
    Remote Desktop NLA, NTLMv2, LLMNR, UAC…) are made by Vanguard itself, relaunched as administrator: Windows'
    prompt names it, and only Enter or yes applies them (threat blocking adds Microsoft's vulnerable driver
    blocklist). The other fixes, and those chosen along with them, are first written to a readable script (its path
    is shown). All of them ask for administrator approval.
  - Threat blocking: each threat found can be blocked with one click, after consent; active protection, once
    enabled, blocks clear-cut threats by itself (MalwareBazaar fingerprint, known attack tool, command server), then
    lets you know; as administrator, it blocks nothing by itself. Each block can be undone (vanguard blocking
    undo), except stopping a program. Before each action, Vanguard records what it will erase (program, command
    line, fingerprint, connections); the sealed event log links the alert, this evidence, the action and its undoing
    (vanguard events).
  - Each fix first records the previous state of what it changes, and can then be undone in "What Vanguard
    changed"; those that turn a protection back on (firewall, antivirus, BitLocker, UAC…) are never undone.
  - Before the first fix, update or repair that changes the system, a restore point is created automatically when
    the system allows one (snapper or timeshift configured on Linux, a restore point on Windows, a local Time
    Machine snapshot on macOS).
  - If you help someone connected remotely (Remote Desktop, SSH), Vanguard never cuts that access.
  - The program is not signed: SmartScreen may warn ("More info" > "Run anyway") and Microsoft Defender may
    flag it, because it scans ports. The source code is on the key and on GitHub (d9v3/vanguard-beta).
  - macOS: run from the key, Vanguard opens without a warning. Copied from the Internet or AirDrop, macOS blocks it
    ("unidentified developer"): right-click > Open, or System Settings > Privacy & Security > "Open Anyway".
    Antivirus, software and gaming go through Homebrew (offered if missing).
  - Kept on each computer, never on the key: the check history and the antivirus quarantine (so malware
    never travels on the key).

Vanguard is free software (GNU GPL v3 or later, see LICENSE.txt), provided without warranty.
The libraries it includes are listed in LICENCES-TIERCES.txt.

Use it only on your own network, or one you are allowed to audit.
