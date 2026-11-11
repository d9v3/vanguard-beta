//! L'aide de la ligne de commande : sa version anglaise et ses rubriques, longue et courte.

use crate::demarrage::arguments::Args;
use crate::langue;
use crate::menu::outils::{Action, GROUPES, Groupe};
use crate::ui::*;
use clap::CommandFactory;

/// Aide anglaise des commandes : la française est dans les commentaires de `Commande`.
#[rustfmt::skip] // une ligne par aide, que rustfmt étalerait sur quatre
pub(crate) const AIDES_EN: &[(&str, &str)] = &[
    ("bilan", "Full check: this computer, then the network"),
    ("audit", "Audit this computer (firewall, ports, SSH, updates, encryption…)"),
    ("corriger", "Audit the machine, then apply the fixes step by step. Exit code: 0 everything accepted is \
                  done (or nothing to do), 1 an accepted fix is not done (“N” or Enter in the administrator \
                  window, UAC declined, failure), 2 fixes declined in the list (“n” or Enter), the others done. \
                  “i” (normal for me) is not a decline"),
    ("appareils", "Network scan: devices, open ports, risks, changes since previous scans"),
    ("audit-reseau", "Network audit by domain: six grades (exposure to the Internet, Wi-Fi, segmentation, DNS and TLS, \
                      connected devices, computers) from the local network scan, this computer's network findings and \
                      a few more read-only checks, attacking nothing; what could not be checked is said, never counted \
                      as safe"),
    ("antivirus", "Malware scan: the Vanguard engine (fingerprints, YARA, installed ClamAV database, heuristics), \
                   with clamscan as a second opinion on Linux if installed, or Microsoft Defender first on Windows"),
    ("surveillance", "Turn hourly network monitoring on or off (notification for unknown devices)"),
    ("tableau-de-bord", "Dashboard in the browser: monitoring, the last check, protection, the alerts, the new devices, \
                 the suspicious connections and every menu feature. Local page, nothing is sent"),
    ("dernieres-failles", "Latest exploited flaws: those CISA added to its catalog (known real attacks) in the last \
                            days, newest first; on Arch, those affecting a package on this computer first"),
    ("sites-dangereux", "Dangerous sites blocked by the hosts file: URLhaus ones and ThreatFox command servers \
                          (abuse.ch key), after your consent and with administrator rights; \"off\" removes them \
                          exactly. Without argument: their state"),
    ("veilleur", "Watcher (Linux 6.6 and later): each program started and each connection closed, seen as they \
                   happen and judged as in the check, and each file placed in Downloads, the Desktop, ~/.local/bin \
                   or ~/.config/autostart, scanned by Vanguard's engine; with active protection, it can freeze and stop an almost \
                   certain ransomware. Off by default. Without argument: its state, then turning it on or off, after \
                   your consent. \"ransomware on|off\" sets the personal-folder ransomware watch"),
    ("entretien", "Monthly check-up: once a month, silently, the grade, waiting updates, space to free and new \
                   problems, in one notification; nothing is changed. Without argument: what it would say now"),
    ("mises-a-jour", "Updates: system, programs, drivers and firmware checked at once, then installed with your consent"),
    ("reparer", "Common repairs: network, hijacked browsing, firewall, antivirus, system files, disk, space, updates, \
                 time"),
    ("logiciels", "Software: the best programs, mostly open source (browsers, passwords, office, video, design, system \
                   tools…), by category: choose, then install from the system's official source"),
    ("diagnostic", "Computer diagnostic: hardware, system and recent problems (crashes, errors). Read only"),
    ("nettoyer", "Clean up the system: caches, temporary files, downloaded packages, old logs, trash… The space each \
                  item frees is shown first; check, then accept"),
    ("test-connexion", "Connection test for gaming: ping, jitter, packet loss, speed and bufferbloat"),
    ("appris", "What Vanguard has learned on this computer: the alerts declared normal, and forgetting them"),
    ("listes-noires", "Is your home's Internet address on a blocklist (Spamhaus, SpamCop, DroneBL, PSBL)? If so, a \
                       device is probably infected. After your consent: the lists see the address"),
    ("yara", "YARA scan: 308 rules for malware families (ReversingLabs) and MalwareBazaar's fingerprints, alongside \
              the antivirus. Without a folder: downloads, desktop, startup. Read-only"),
    ("memoire", "Memory of running processes passed through the 308 YARA rules: fileless malware lives nowhere else. \
                 Read-only, on demand; LSASS and protected processes: their memory is never read; nothing is kept"),
    ("secrets", "Secrets in the history of the home folder's git projects (passwords, API keys, tokens), searched by \
                 Vanguard, and also by gitleaks if installed. No secret is shown. Read-only"),
    ("conteneurs", "Known flaws in this computer's Docker or Podman images, by trivy if installed. Read-only"),
    ("parametres", "Settings: all of Vanguard's settings (language, emojis, working without the Internet, real-time \
                    protection, monitoring, monthly check-up, learned alerts, blocking, extension restrictions, \
                    abuse.ch key, ClamAV second opinion, unwanted programs (PUA), software versions, weekly self-test, AUR packages, Vanguard Agent, sharing with \
                    the author). \
                    No argument: their state; with a setting and a value: changes it, showing the \
                    previous value to go back. “real-time no --for 1h|4h” turns Vanguard's real-time protection off \
                    for that long (without --for: until turned back on), after your consent; never Defender, the \
                    firewall or UAC"),
    ("blocage", "Threat blocking: each threat found offers “Block” (the action shown, accepted, written down, \
                 undoable); active protection, after a consent given once, blocks what is certain by itself \
                 (MalwareBazaar fingerprint, known attack tool, command server), then warns you. No argument: the menu"),
    ("alerte", "A notified alert, by the identifier its notification gives: the alert is read again from the sealed \
                log, the threat looked for again and judged again, then its actions offered (block, suspend, watch \
                more closely, trust, ignore). Nothing but the identifier is taken from the command line"),
    ("canaux-wifi", "Crowded Wi-Fi: nearby networks by channel, and the freest channel to set on the router. Read-only"),
    ("nat", "NAT type for gaming (open, moderate or strict), from two public servers (STUN). Read-only"),
    ("cameras-cachees", "Hidden cameras: on a rental's or someone's network, the devices that look like cameras. Read-only"),
    ("objets-connectes", "Router and connected devices from the last kept scan: what the router announces (model, software), \
                its HTTP-only admin page, the cameras, printers, NAS… and their default password. Nothing is probed"),
    ("dns-rapide", "Fastest DNS: measures the current DNS and public ones, then offers the fastest, undoable. A DNS \
                    that protects (NextDNS, encrypted, filtering) is kept"),
    ("wifi-public", "Public Wi-Fi mode (café, hotel, airport): incoming connections closed on this network, file \
                     sharing and name announcement off, protective DNS (encrypted on Linux with systemd-resolved), \
                     after your consent and with administrator rights; \"off\" puts everything back exactly, \
                     \"portal\" reopens the network's login page. Without argument: its state"),
    ("pieges", "Decoy files against ransomware: place them (after your consent), see whether they are intact, or \
                remove them"),
    ("isoler", "Run an unknown program in a sandbox: no network, home folder hidden"),
    ("fuite-courriel", "Email address leaks: the address is sent to the search service, after your consent"),
    ("integrite", "Critical file integrity: BLAKE3 fingerprint reference, then what changed since"),
    ("fuite-mot-de-passe", "Check whether passwords have leaked (Have I Been Pwned); only 5 characters of their fingerprint \
                    are sent"),
    ("mots-de-passe-navigateurs", "Passwords saved in the browsers: how many and how protected (counted, never read), where to run \
                     the browser's built-in check (weak, reused, compromised), and the HIBP check of a typed password"),
    ("connexions-sortantes", "Who talks to the Internet? Each program's current connections, with the server's name. Read-only"),
    ("verifier-moi", "Check Vanguard itself: version, build date, SHA-256 fingerprint of the program (to compare with the release page), on the owner's key the key manifest, and after your consent the signed history of published versions; or another copy of Vanguard, by its fingerprint and that history"),
    ("acces-a-distance", "Is my computer being controlled? Remote control software (AnyDesk, TeamViewer, RustDesk…) installed, started at boot, running or downloaded: the fake technicians' tool. Removed after your consent; a running program asks for a second consent"),
    ("lien", "Is this link dangerous? Checked without ever opening it; after your consent, its age and public lists"),
    ("verifier-fichier", "Check a downloaded file: checksum compared with the site's, name and content, Vanguard's \
                          engine and the system's antivirus"),
    ("courriel-suspect", "Is this email a scam? A saved email (.eml) examined without opening anything: the sender \
                          and its authentication (SPF, DKIM, DMARC) as written by your provider, the links (shown \
                          text against real address) and the attachments (name, content, YARA, antivirus); after \
                          your consent, the domains' age and public lists"),
    ("logiciels-espions", "Spyware: known stalkerware servers and sites (Échap list, CC-BY 4.0) in current \
                           connections and the DNS cache, programs reading the keyboard, known monitoring \
                           software. Read-only"),
    ("logiciels-perimes", "Outdated software (Windows): browsers, Office, Acrobat, Java, 7-Zip, PuTTY and \
                           Slack compared with their latest version (publishers' sites, endoflife.date, Homebrew; \
                           public files downloaded in full, nothing about this computer is sent), each product's \
                           exploited flaws in CISA's catalog, Firefox and Edge checked flaw by flaw (Mozilla \
                           advisories, Microsoft's list). Read-only"),
    ("options-defense", "Windows defense options: Microsoft Defender (mode, real-time, cloud, tamper protection, \
                         each option), exclusions, ASR rules, Windows Firewall per profile, policies (GPO, Intune) \
                         that enforce a value, third-party antivirus, managed PC. On Linux: the firewall (ufw, \
                         firewalld, nftables), on or off. Each option can be chosen, what lowering changes is said; \
                         nothing is changed without being shown, then confirmed (administrator window, or a [y/N] \
                         question from Vanguard as administrator on Linux)"),
    ("signaler", "Prepare a report for a vendor (MSRC, Google, Chrome, Mozilla, Apple, GHSA advisory, CERT/CC, \
                  CERT-FR, Vanguard): sorted first (a known flaw is fixed by an update, malware is not a flaw), a \
                  draft in the program's format, what is personal removed, written on this computer and shown in \
                  full. Nothing is ever sent: you read it, copy it and submit it yourself"),
    ("camera-micro", "Camera and microphone: who uses them? On Windows, each program and the last time; on Linux, \
                      what holds them right now. Read-only"),
    ("bilan-confidentialite", "Privacy check: the apps that have access to the location, contacts, camera and microphone, and their \
               last use when it is recorded. Read-only"),
    ("quarantaine", "Quarantine: the files isolated by the antivirus or YARA, to put back in their place (false \
                     positive) or to delete for good"),
    ("exporter", "Back up the device database and the monitoring state to a JSON file"),
    ("importer", "Add a backup (or an appareils.json) to the current database, without erasing anything"),
    ("nommer", "Give a nickname to a device of the database (“HP printer”), by its IP or MAC"),
    ("jeux", "Gaming: components for games (Windows: Visual C++, DirectX…; Linux: Steam, Vulkan, GameMode, Wine…) \
                and system settings"),
    ("guide", "Command guide: the useful commands of Omarchy, Arch, Fedora, Debian, other Linux, Windows and all \
               systems, sorted by program, with step-by-step guides; plus the tldr-pages examples, downloaded \
               every week"),
    ("lenteur", "Why is it slow? What keeps the processor, memory and disk busy, startup, the programs started at \
                 login. Read only"),
    ("demarrage", "Startup programs: those that start at login, to remove or put back after your consent. Each removal \
                   is undone exactly (Block and respond › Put everything back)"),
    ("fiche-ordinateur", "Computer specs: model, motherboard, processor, memory, graphics card, disks, system. Serial numbers are \
               shown on screen only"),
    ("copier-fichiers", "Copy my files (Documents, Pictures, Desktop, Videos, Music) to an external disk: checked \
                         copy, nothing deleted or overwritten, an interrupted copy resumes"),
    ("verifier-copie", "Check a copy made by “Copy my files” (restore test): files spread over the whole copy, read \
                        back from the disk and compared with their original. Nothing is written or deleted"),
    ("verifier-sauvegarde", "Check my backup: the backup set up by Vanguard really read back, files spread over the \
                             whole backup compared with their original; for Déjà Dup and File History, \
                             the steps. Nothing is written or deleted"),
    ("verifier-cle", "Check my drive: real capacity (fake drives), speeds and bad blocks of a USB stick or an \
                      external disk. Writes into the free space after your consent, reads back, then erases; your \
                      files are not touched"),
    ("changements", "What Vanguard changed: each fix run on this computer, its date and its result"),
    ("evenements", "The event log: alerts, evidence recorded before an action, actions, undos, alerts declared normal \
                    and version changes, linked together, with the state of its sealed chain. Read only"),
    ("journaux-windows", "Windows logs: what happened? The EVT- rules (cleared traces, attack service, one more \
                          administrator, guessed password, Remote Desktop, PowerShell, Defender…) on this computer's \
                          logs (Windows) or a folder of .evtx (any system), then the alerts in time order. Read only"),
    ("rapport-a-laisser", "Report to leave behind: a simple page for the person you just helped (grade, what is left to do, \
                   what is fine), put on their Desktop after consent and opened in the browser"),
    ("sauvegarde-auto", "Automatic backup: set up with the system's tool (Déjà Dup or rsync every day, File \
                         History) to an external disk, after your consent, exactly undoable"),
    ("raccourci", "Shortcut on this computer: Vanguard copied here and started with one click (applications menu on \
                   Linux, Desktop on Windows). Without argument: the state, then the offer"),
    ("regles", "The check rules declared for this system: stable identifier, subject, hardening references"),
    ("autotest", "Self-test: Vanguard checks its own readings on this computer. Every check rule under a guard and a \
                  time limit, read only and proven so (fingerprints before and after), and its readings compared with \
                  those of the system's tools (pacman, systemctl, ss, PowerShell…). Nothing is changed; offline unless \
                  --internet; a gap goes to the error log, without any value from the computer. Exit code: 0 sound, \
                  1 gap, 2 not checked"),
    ("se-mettre-a-jour", "Update Vanguard on this computer: from a newer VANGUARD key, or from the latest version \
                          published on GitHub, signed by the author and checked; always after your consent, never to \
                          an older version"),
    ("desinstaller", "Remove Vanguard from this computer: what it placed there (monitoring, monthly check-up, \
                      automatic backup, decoy files, shortcut and icon, program copy, leftovers of an earlier \
                      version), found, shown, then checked. The data folder is removed only after a second consent; \
                      the USB key is never touched"),
    ("ordinateurs", "My computers: those where the VANGUARD key ran a check, their grade and remaining problems (on the \
     key's VANGUARDLOG partition)"),
    ("depanner", "Troubleshoot step by step: no Internet, Wi-Fi dropping, slow computer, no sound, printer, disk full; \
                  after an infection, new computer, computer leaving (sale, gift), hacked account, collect the \
                  evidence (“evidence [folder]”: processes, connections, startup, accounts, logs, recent files and \
                  timeline, in a dated folder; read-only), a relative's computer"),
    ("chercher", "Search for a tool, a guide page, a program or a setting: the ten best results, with their place in \
                  the menu and their command; in a terminal, a number opens the result. Synonyms (box, router) and \
                  typos included. Exit code 1 if nothing is found"),
    ("rapport", "Detailed report in the browser: this session's check if there is one, otherwise a full check first"),
    ("annuler", "Put everything back: undoes what Vanguard changed (Optimize settings, check-up fixes, gaming, blocks, \
                 public Wi-Fi mode), the previous value put back, after your consent. Like “optimize undo”"),
    ("protection", "Protection: the state of each switch (real-time, monitoring, maintenance, blocking, watcher, \
                    dangerous sites, public Wi-Fi, shortcut); “on” or “off” [--for 1h|4h] acts on real-time \
                    protection, like “settings real-time”"),
    ("plugins", "Plugins: programs of yours added to Vanguard without changing its code (tests, experimental tools), \
                each in a folder with a plugin.toml. “add <folder>” copies and approves it (SHA-256 fingerprints), \
                “approve <name>” after a change, “list”, “remove <name>”, or “<name> [arguments]” to run it \
                (“--report”: its findings in the HTML report); no argument: the list to choose from. Never as \
                administrator; outside the grade"),
    ("labo", "Lab: a script put as it is in the lab folder (.sh, .bash, .ps1, .py or a program), to try an idea \
              outside Vanguard's program. No argument: the list to choose from; “open”: the folder; “<file> \
              [arguments]” runs it (approved by its fingerprint on the first run). Never as administrator"),
    ("extensions", "Extensions: the menu of plugins and lab scripts, to choose and run"),
    ("agent", "The Vanguard Agent (no AI), read-only: its missions (time limits, cache, local record, notes on \
               fixes), their last run and its journal, without any personal data. Nothing is changed or sent. \
               Its switches are in Settings (“settings auto-tuning”)"),
    ("optimiser", "Optimize: the recommended settings, the privacy, performance and comfort ones, each \
                   shown, accepted, then exactly undoable; “undo” puts everything back as it was. No argument: the \
                   Optimize menu"),
];

/// Aide anglaise des options : (commande, option, aide).
#[rustfmt::skip]
pub(crate) const OPTIONS_EN: &[(&str, &str, &str)] = &[
    ("dernieres-failles", "jours", "How many days back (7 by default)"),
    ("dernieres-failles", "json", "The result as JSON, for a script: nothing changes on the computer; the catalog is \
                                   fetched again online if it is more than a day old. Offline, the saved copy only, \
                                   nothing matched against this computer's packages (said not checked)"),
    ("nettoyer", "liste", "Show what could be cleaned up and the space to gain, deleting nothing"),
    ("desinstaller", "liste", "Show what would be removed, without removing anything"),
    ("logiciels", "liste", "Show each program offered and its state, without installing anything"),
    ("logiciels", "recommandes", "Install the starter pack (browser, passwords, video, office, archives), after your \
                                  consent"),
    ("bilan", "html", "Also open the HTML report in the browser"),
    ("tableau-de-bord", "sans_ouvrir", "Write the page without opening it (no graphical display, over SSH)"),
    ("bilan", "texte", "Show the report as plain text (Markdown) in the terminal: no browser or graphical display \
                          needed"),
    ("appareils", "cible", "IP, CIDR network (10.0.0.0/24) or range (10.0.0.1-50). Default: your local network"),
    ("appareils", "ports", "“courants”/“common” (default), “tous”/“all” (1-65535) or a list “22,80,8000-8100”"),
    ("appareils", "timeout", "Connection timeout per port, in milliseconds"),
    ("appareils", "parallele", "Number of simultaneous connections"),
    ("audit-reseau", "html", "Also open the HTML report in the browser"),
    ("audit-reseau", "invite", "You are on the guest network: Vanguard checks that it is really separated from the main \
                                one"),
    ("antivirus", "complet", "The whole home folder instead of the risky places"),
    ("antivirus", "dossier", "A USB drive, external disk or folder to scan entirely"),
    ("antivirus", "etat", "The antivirus status, scanning nothing: engine, databases and their date, what is not read, \
                           second opinion and PUA choices, real-time file scanning"),
    ("antivirus", "detail", "With --status: read the whole ClamAV database to count what it skipped (about 10 seconds)"),
    ("antivirus", "json", "The result as JSON, for a script: the quick scan (or, with --status, the status), with no \
                           question; nothing is quarantined, nothing changes, nothing is downloaded"),
    ("isoler", "fichier", "Program or script to run"),
    ("pieges", "retirer", "Remove the decoy files placed"),
    ("veilleur", "sous_etat", "For “ransomware”: on or off"),
    ("yara", "complet", "The whole home folder instead of the risky places"),
    ("yara", "dossier", "A USB drive, external disk or folder to scan entirely"),
    ("yara", "json", "The result as JSON, for a script: the risky places, with no question; nothing is quarantined, \
                      nothing changes, nothing is downloaded"),
    ("memoire", "json", "The result as JSON, for a script: nothing changes"),
    ("integrite", "accepter", "Take the current state as the new reference (after a system update)"),
    ("integrite", "temps_reel", "Watch the critical files live until Ctrl-C"),
    ("integrite", "json", "The result as JSON, for a script: nothing is written; without a reference, none is \
                           set (said not checked)"),
    ("exporter", "fichier", "File to write (default: vanguard-sauvegarde-YYYY-MM-DD.json in the home or Documents \
                                folder)"),
    ("nommer", "appareil", "IP (on the current network) or MAC address of the device"),
    ("nommer", "surnom", "The nickname; empty to remove it"),
    ("lien", "adresse", "The link you received (in quotes if it contains “&” or “?”)"),
    ("verifier-fichier", "fichier", "The downloaded file"),
    ("courriel-suspect", "fichier", "The saved email (.eml): Thunderbird “Save As”, Gmail “Download message”, \
                                     Outlook on the web “Download”"),
    ("verifier-fichier", "empreinte", "The checksum published by the site (preferably SHA-256). Otherwise: a \
                                       SHA256SUMS or .sha256 next to it"),
    ("guide", "quoi", "A system (omarchy, arch, fedora, debian, windows, all; linux: the common programs; tldr; \
                       vanguard), a program (systemctl, winget, tar…), a path (6.7.2) or words to look for"),
    ("fiche-ordinateur", "json", "The specs as JSON, for a script (without the serial numbers)"),
    ("evenements", "json", "The log as JSON, for a script"),
    ("logiciels-espions", "json", "The result as JSON, for a script"),
    ("logiciels-perimes", "json", "The result as JSON, for a script"),
    ("options-defense", "json", "The result as JSON, for a script (no path, account name or computer name)"),
    ("options-defense", "choisir", "A Defender or firewall choice (pua bloquer, asr-GUID audit, \
                                    pare-feu-prive-actif non…; on Linux, pare-feu-ufw coupe…), shown then made as \
                                    administrator; lowering is confirmed there by a typed yes, its previous value \
                                    noted"),
    ("options-defense", "rallumer", "Turns a setting back on: the noted previous value if it protects, otherwise \
                                     the safe value (on Linux, pare-feu-ufw, pare-feu-firewalld or \
                                     pare-feu-nftables: the state noted before turning it off)"),
    ("options-defense", "exclure", "A scan exclusion (folder, program or type, then the text), shown then confirmed \
                                    in the administrator window like lowering"),
    ("options-defense", "permettre", "An app allowed despite controlled folder access, shown then confirmed like \
                                      lowering"),
    ("options-defense", "noter", "“It was me”: a value lowered outside Vanguard, noted “your choice” (same question \
                                  as lowering); the check stops alerting"),
    ("options-defense", "remettre", "Puts back what a registry fix noted (smartscreen, hvci, maj-pause… or \
                                     service:<name> for a service path): lowering, shown then confirmed in the \
                                     administrator window"),
    ("signaler", "incident", "The identifier of a log event (vanguard events): its incident is used"),
    ("signaler", "outil", "The last examination of a tool (PRO-ESP-001, PRO-PER-001, PRO-COU-001)"),
    ("signaler", "programme", "The program: msrc, google, chrome, mozilla, apple, ghsa, cert-cc, cert-fr or vanguard"),
    ("signaler", "langue", "The draft's language (fr or en); by default, the one the program reads"),
    ("signaler", "json", "The sorting and the draft as JSON, for a script: nothing written or recorded, no question"),
    ("signaler", "effacer", "List the kept drafts and erase them after your consent"),
    ("verifier-fichier", "json", "The result as JSON, for a script: nothing is asked; the system's antivirus is not \
                                  run (said not checked), Vanguard's engine is, its verdict apart"),
    ("courriel-suspect", "json", "The result as JSON, for a script: the examination on the computer only (neither \
                                  the online check nor the attachments scan, said not checked)"),
    ("evenements", "incident", "One incident's thread: this event, what caused it and what it caused"),
    ("journaux-windows", "dossier", "A folder of .evtx logs (winevt\\Logs of a mounted disk, folder of “troubleshoot \
                                    evidence”); without it, this Windows' logs"),
    ("journaux-windows", "jours", "How many days back (7 by default)"),
    ("journaux-windows", "json", "The result as JSON, for a script: nothing is asked"),
    ("autotest", "json", "The report as JSON, for a script (without any value read on the computer)"),
    ("autotest", "compte_rendu", "The report for Claude as JSON: one cause per gap, with its identifiers (the nightly \
                                  watch's format, without any value read on the computer)"),
    ("protection", "json", "The switches' state as JSON, for a script: nothing is changed"),
    ("diagnostic", "json", "The result as JSON, for a script: nothing changes"),
    ("lenteur", "json", "The result as JSON, for a script: nothing changes"),
    ("mises-a-jour", "json", "The result as JSON, for a script: nothing is installed, no question"),
    ("demarrage", "json", "The result as JSON, for a script: nothing is removed, no question. With --retirer or \
                           --remettre: the outcome on one JSON line, the last one"),
    ("demarrage", "retirer", "Remove from startup the only program with this fingerprint (32 hexadecimal digits, given \
                              by --json): an ordinary program that starts, never one to keep nor a firewall. It stays \
                              installed"),
    ("demarrage", "remettre", "Put back exactly as before the program with this fingerprint that Vanguard removed \
                               (from its note)"),
    ("connexions-sortantes", "json", "The result as JSON, for a script"),
    ("acces-a-distance", "json", "The result as JSON, for a script: nothing is removed, no question"),
    ("bilan-confidentialite", "json", "The result as JSON, for a script"),
    ("test-connexion", "json", "The result as JSON, for a script"),
    ("objets-connectes", "json", "The result as JSON, for a script"),
    ("lien", "json", "The result as JSON, for a script: without --internet, the examination on the computer only \
                      (domain age and public lists said not checked)"),
    ("lien", "internet", "Consent given in advance: the domain age and the public lists are asked online (for --json)"),
    ("listes-noires", "json", "The result as JSON, for a script: without --internet, nothing is sent and the address \
                               is said not checked"),
    ("listes-noires", "internet", "Consent given in advance: the four lists see the public address (for --json, which \
                                   asks nothing)"),
    ("autotest", "internet", "Let the rules that need it go on the Internet (updates, software versions)"),
    ("autotest", "detail", "Show on screen the values that differ (package, unit, account names), here only"),
    ("autotest", "une_par_une", "The rules one by one, for timings without their neighbours (slower)"),
    ("copier-fichiers", "destination", "A folder on an external disk (default: chosen among the plugged-in disks)"),
    ("verifier-copie", "dossier", "The disk or the folder of the copy (default: chosen among the plugged-in disks)"),
    ("verifier-cle", "dossier", "A folder of the drive or disk (default: chosen among the plugged-in disks)"),
    ("sauvegarde-auto", "annuler", "Remove the automatic backup set up by Vanguard (the backed-up files stay)"),
    ("depanner", "sujet", "The subject: internet, wifi, slow, sound, printer, disk, infection, new, leaving, account, \
                           evidence [folder], relative (or words that describe it)"),
    ("protection", "quoi", "on or off, then --for 1h or 4h for a cut that ends by itself"),
    ("chercher", "mots", "The words searched for"),
    ("guide", "sommaire", "For a system: the list of its programs and their path, without their commands"),
    ("chercher", "premier", "Open the best result right away"),
    ("plugins", "quoi", "add <folder>, approve <name>, list, remove <name>, or <name> [--report] [arguments]"),
    ("labo", "quoi", "open, list, or <file> [arguments]"),
    ("agent", "json", "The view in JSON (schema 1): nothing but closed names, rule identifiers, numbers and dates"),
    ("extensions", "sans_restrictions", "on: the extensions' restrictions turned off (no consent, fingerprint or scan, \
                                         with all your rights); off: back on. The extensions folder must stay yours \
                                         alone"),
    ("parametres", "quoi", "A setting (language, emojis, offline, real-time, monitoring, maintenance, learned, \
                              blocking, restrictions, abuse.ch, second-opinion, pua, software-versions, autotest, aur-packages, auto-tuning, \
                              sharing) and its \
                              value; real-time no also takes --for 1h or 4h"),
    ("blocage", "quoi", "“search”, “undo”, “status”, “auto” or “click” (active protection), a category (programs, \
                           connections, startup, agents) followed by a mode (off, click, auto), or “judge” a PID, \
                           “parent” or a file (what blocking would refuse, and why, without doing anything), \
                           “suspend” a PID (reversible) or “resume” (one PID, or all those Vanguard suspended)"),
    ("alerte", "id", "The alert's identifier, as the notification gives it (vanguard events shows them too)"),
    ("optimiser", "quoi", "recommended, privacy, performance, comfort or undo"),
    ("verifier-moi", "programme", "Another copy of Vanguard to check (from another key, an earlier version), by its \
                                     fingerprint and the signed version history"),
    ("depanner", "sujet", "The subject: internet, wifi, slow, sound, printer, disk, infection, new, leaving (or words \
                             describing it)"),
    ("secrets", "json", "The result as JSON, for a script: each secret's kind, file, line and commit, never the secret \
                         itself; nothing changes"),
    ("changements", "json", "The history as JSON, for a script: the most recent ones, with no offer to undo; nothing \
                             changes"),
    ("regles", "json", "The list as JSON, for a script: nothing changes"),
    ("verifier-moi", "json", "The result as JSON, for a script: with no question, so without the signed history (which \
                              asks for consent), said not compared; what could not be checked is said, nothing \
                              changes"),
    ("cameras-cachees", "json", "The result as JSON, for a script: nothing is asked, turned off or changed"),
    ("nat", "json", "The result as JSON, for a script: nothing changes; offline, nothing is sent"),
    ("canaux-wifi", "json", "The result as JSON, for a script: no search is started, nothing changes"),
    ("conteneurs", "json", "The result as JSON, for a script: nothing is installed or downloaded; at most 30 images \
                            and 10 minutes"),
];

/// La ligne de commande, avec son aide en anglais si l'interface est en anglais (l'aide écrite plus haut, en
/// commentaires, est la version française).
pub(crate) fn ligne_de_commande() -> clap::Command {
    let c = Args::command();
    if !langue::anglais() {
        return c;
    }
    let mut c = c
        .about(
            "Portable cyber defense for endpoints and networks: check, fixes, settings. No argument: the Vanguard \
                 window, or the menu.",
        )
        .mut_arg("menu", |a| {
            a.help("The terminal menu, even when the Vanguard window could open.")
        });
    for &(nom, aide) in AIDES_EN {
        c = c.mut_subcommand(nom, |s| s.about(aide));
    }
    for &(commande, option, aide) in OPTIONS_EN {
        c = c.mut_subcommand(commande, |s| s.mut_arg(option, |a| a.help(aide)));
    }
    c
}

/// Les commandes de la ligne de commande qui ne sont l'outil d'aucune ligne du menu, et la rubrique de `--help` où
/// elles vont.
const RUBRIQUE_DES_AUTRES: &[(&str, Groupe)] = &[
    ("protection", Groupe::Reagir),
    ("alerte", Groupe::Reagir),
    ("importer", Groupe::Vanguard),
    ("plugins", Groupe::Vanguard),
    ("labo", Groupe::Vanguard),
    ("agent", Groupe::Vanguard),
];

/// Le nom d'une commande dans la langue de l'interface : son alias anglais visible en anglais, s'il en a un.
pub(crate) fn nom_de_commande(commande: &clap::Command) -> String {
    if langue::anglais()
        && let Some(alias) = commande.get_visible_aliases().next()
    {
        return alias.to_string();
    }
    commande.get_name().to_string()
}

/// Les commandes de `--help`, rangées comme le menu : (rubrique, noms dans l'ordre des lignes), puis celles qui ne
/// sont dans aucune rubrique (aucune, d'après le test `l_aide_cite_chaque_commande`).
pub(crate) fn rubriques_de_l_aide() -> Vec<(String, Vec<String>)> {
    let clap = Args::command();
    let visibles: Vec<&clap::Command> = clap
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();
    let nom = |commande: &str| {
        visibles
            .iter()
            .find(|c| c.get_name() == commande)
            .map(|c| nom_de_commande(c))
    };
    let rubriques_fr = rubriques_des_commandes();
    let vus: Vec<&str> = rubriques_fr.iter().flat_map(|(_, n)| n.iter().copied()).collect();
    let mut rubriques: Vec<(String, Vec<String>)> = rubriques_fr
        .into_iter()
        .map(|(groupe, noms)| {
            let titre = match groupe {
                None => tr!("Bilan de sécurité", "Security check").to_string(),
                Some(g) => format!(
                    "{} {}",
                    GROUPES.iter().position(|x| *x == g).map_or(0, |i| i.saturating_add(4)),
                    g.titre()
                ),
            };
            (titre, noms.into_iter().filter_map(nom).collect())
        })
        .collect();
    let reste: Vec<String> = visibles
        .iter()
        .filter(|c| !vus.contains(&c.get_name()))
        .map(|c| nom_de_commande(c))
        .collect();
    if !reste.is_empty() {
        rubriques.push((tr!("Aussi", "Also").to_string(), reste));
    }
    rubriques
}

/// Les commandes visibles rangées comme le menu, par leur nom français : (groupe, aucun pour la rubrique du bilan ;
/// noms dans l'ordre des lignes). Sans langue : `--help` et le guide (10.9) s'en servent.
pub(crate) fn rubriques_des_commandes() -> Vec<(Option<Groupe>, Vec<&'static str>)> {
    let clap = Args::command();
    let existe = |commande: &str| {
        clap.get_subcommands()
            .any(|c| !c.is_hide_set() && c.get_name() == commande)
    };
    let mut vus: Vec<&'static str> = Vec::new();
    let mut ajouter = |liste: &mut Vec<&'static str>, commande: &'static str| {
        if !commande.is_empty() && !vus.contains(&commande) && existe(commande) {
            vus.push(commande);
            liste.push(commande);
        }
    };
    let mut rubriques = Vec::new();
    let mut premiere = Vec::new();
    for a in [Action::Complet, Action::Corriger, Action::Rapport] {
        ajouter(&mut premiere, a.outil().commande);
    }
    // La recherche de l'accueil, en ligne de commande.
    ajouter(&mut premiere, "chercher");
    rubriques.push((None, premiere));
    for g in GROUPES {
        let mut liste = Vec::new();
        // Les raccourcis d'incident (8.3 à 8.5) mènent à « depanner » : sa rubrique est celle de Dépanner.
        let raccourcis = [Action::DepannerInfection, Action::DepannerCompte, Action::Traces];
        for a in g.actions().into_iter().filter(|a| !raccourcis.contains(a)) {
            ajouter(&mut liste, a.outil().commande);
            for v in a.variantes() {
                ajouter(&mut liste, v.outil().commande);
            }
        }
        for (commande, _) in RUBRIQUE_DES_AUTRES.iter().filter(|(_, r)| *r == g) {
            ajouter(&mut liste, commande);
        }
        rubriques.push((Some(g), liste));
    }
    rubriques
}

/// `vanguard --help` : toutes les commandes en rubriques, aux noms et numéros du menu, générées depuis `OUTILS` et
/// clap (jamais écrites à la main).
pub(crate) fn aide_longue() -> String {
    use std::fmt::Write;
    let mut t = trf!(
        "Vanguard {} : cyberdéfense portable des postes et des réseaux.\nSans argument : le menu, ou la fenêtre de Vanguard si elle est installée à côté (--menu : toujours le menu).\n\nUsage : vanguard [commande] [options]\n\n",
        "Vanguard {}: portable cyber defense for endpoints and networks.\nNo argument: the menu, or the Vanguard window if it is installed alongside (--menu: always the menu).\n\nUsage: vanguard [command] [options]\n\n",
        env!("CARGO_PKG_VERSION")
    );
    let rubriques = rubriques_de_l_aide();
    let colonne = (rubriques.iter().map(|(r, _)| largeur_affichee(r)).max().unwrap_or(0)).saturating_add(2);
    for (rubrique, noms) in rubriques {
        let lignes = envelopper(&noms.join(", "), LARGEUR.saturating_sub(2).saturating_sub(colonne));
        for (i, ligne) in lignes.iter().enumerate() {
            let tete = if i == 0 { rubrique.as_str() } else { "" };
            let blanc = " ".repeat(colonne.saturating_sub(largeur_affichee(tete)));
            let _ = writeln!(t, "  {tete}{blanc}{ligne}");
        }
    }
    t += tr!(
        "\nDétail d'une commande : vanguard <commande> --help.\nAnciens noms de commandes : dans l'historique des versions (CHANGELOG.md).\nCe que Vanguard protège ou non : MODELE-DE-MENACE.md, dans le dépôt.\nCe que voient ses règles : COUVERTURE-ATTACK.md.\n",
        "\nDetail of a command: vanguard <command> --help.\nFormer command names: in the version history (CHANGELOG.en.md).\nWhat Vanguard protects or not: MODELE-DE-MENACE.en.md, in the repository.\nWhat its rules see: COUVERTURE-ATTACK.en.md.\n"
    );
    t
}

/// `vanguard -h` : l'essentiel, en une quinzaine de lignes.
pub(crate) fn aide_courte() -> String {
    use std::fmt::Write;
    let mut t = trf!(
        "Vanguard {} : cyberdéfense portable des postes et des réseaux.\nSans argument : le menu (↑ ↓, ou un mot), ou la fenêtre si elle est installée à côté ; --menu : toujours le menu.\n\n",
        "Vanguard {}: portable cyber defense for endpoints and networks.\nNo argument: the menu (↑ ↓, or a word), or the window if it is installed alongside; --menu: always the menu.\n\n",
        env!("CARGO_PKG_VERSION")
    );
    let clap = Args::command();
    let nom = |commande: &str| {
        clap.find_subcommand(commande)
            .map_or_else(|| commande.to_string(), nom_de_commande)
    };
    let lignes: [(String, &str); 7] = [
        (
            nom("bilan"),
            tr!("le bilan de sécurité complet", "the full security check"),
        ),
        (
            nom("corriger"),
            tr!(
                "corriger les problèmes trouvés, un à un",
                "fix the problems found, one by one"
            ),
        ),
        (
            nom("rapport"),
            tr!(
                "le rapport détaillé dans le navigateur",
                "the detailed report in the browser"
            ),
        ),
        (
            nom("protection"),
            tr!("l'état des protections ; les couper", "the protections: state, off, on"),
        ),
        (
            format!("{} [{}]", nom("depanner"), tr!("sujet", "subject")),
            tr!(
                "dépanner pas à pas (internet, son, lent…)",
                "troubleshooting (internet, sound, slow…)"
            ),
        ),
        (
            format!("{} <{}>", nom("chercher"), tr!("mots", "words")),
            tr!(
                "trouver un outil, un logiciel, un réglage",
                "find a tool, a program, a setting"
            ),
        ),
        (
            format!("{} [{}]", nom("guide"), tr!("quoi", "what")),
            tr!("les commandes utiles, expliquées", "useful commands, explained"),
        ),
    ];
    for (commande, quoi) in lignes {
        let _ = writeln!(t, "  vanguard {commande:<24}{quoi}");
    }
    t += tr!(
        "\nvanguard --help : toutes les commandes, rangées comme le menu.\n",
        "\nvanguard --help: every command, sorted like the menu.\n"
    );
    t
}
