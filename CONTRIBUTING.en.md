# Developing Vanguard

[Français](CONTRIBUTING.md) · **English**

The code, its comments and its internal names are in French; every text shown to the user exists in both languages
(`tr!("fr", "en")` in `src/langue.rs`).

With Claude Code: `CLAUDE.md` gives the project's commands and rules, `/verifier` and `/livrer` (`.claude/skills/`)
check everything and ship a version; a hook reformats Rust after each edit. On GitHub, `@claude` in an issue or a
pull request gets an answer, and each “journal” issue is analyzed automatically (`.github/workflows/claude*.yml`, to
turn on once with `/install-github-app`).

A security flaw? No public issue or pull request: report it privately, see [SECURITY.md](SECURITY.md#security).

## Layout

| File | Purpose |
|---|---|
| `src/main.rs` | menu and subcommands |
| `src/deploiement.rs` | steps of `outils/deployer.sh` handed to the program (`vanguard deploiement …`, hidden command): guards of vanguard.exe, key markers, the key's tldr archives |
| `src/ui.rs` | colors, titles, frames, bars, lines wrapped and aligned within 76 columns |
| `src/selection.rs` | keyboard menus and checklists (arrows, Enter, Esc or Backspace), word search in menus |
| `src/recherche.rs` | search: per-word score, synonyms ("box" → router), typos corrected; for the menu and `vanguard search` |
| `src/prediction.rs` | prediction of the word being typed, the same in every menu: its end in grey, Tab completes it |
| `src/langue.rs` | language choice and translation macros |
| `src/parametres.rs` | Settings menu and `vanguard settings`: the startup settings (language, emojis, offline) in parametres.json, read before anything is shown, an environment variable winning; real-time protection, monitoring, check-up, learned alerts, blocking, extension restrictions and abuse.ch key changed by their own code |
| `src/machine/mod.rs` | shared types, display, parallel execution of the checks |
| `src/machine/regles.rs` | registry of check rules: each one is declared where it is written (`inventory::submit!`), with a stable identifier (“LNX-PLT-001”) and at least one CIS, Microsoft or ANSSI reference; each runs under its time limit (beyond it: not checked, the check goes on); `vanguard rules` lists them |
| `src/machine/linux/plateforme.rs` | platform security according to fwupd (HSI), kernel lockdown, BPF, user namespaces, auditd: the first rules of the registry |
| `src/machine/linux/natif.rs` | native Linux reads, without launching a program: the PATH (a program's presence and path, system folders for what sudo runs), systemd units, processes, the pacman, dpkg (one "installed" rule, held packages included), Flatpak and Snap databases, disks, the root file system, the account's groups |
| `src/machine/linux/paquets.rs` | what is installed, read from the databases (pacman, dpkg, Flatpak), the command as a fallback; used by Gaming, software and protection |
| `src/machine/linux/dbus.rs` | small D-Bus client written for the project, without a library: system bus, EXTERNAL authentication, messages encoded and decoded by hand; only read methods are sent (failed units, startup duration and critical chain from systemd, SMART through udisks2) |
| `src/machine/linux/zstd.rs`, `journal_systemd.rs` | zstd decoder written for the project (RFC 8878: pacman databases in zstd, compressed journal fields); reading the systemd journal files through their hash table (errors of this boot, SSH failures), journalctl as a fallback |
| `src/machine/linux/`, `src/machine/windows/`, `src/machine/macos/` | per-system audit, one file per topic; on Windows, accounts (NetUserEnum, group S-1-5-32-544) and startup (Run keys through winreg, .lnk shortcuts read in Rust) without PowerShell, which stays as a fallback; `windows/corrections.rs` and `windows/eleve.rs`: the closed list of native fixes and the elevated process that applies them ("runas" relaunch, named pipe checked on both sides), PowerShell for the rest; `windows/chargement.rs`: imported DLLs taken from System32 only (the PE's Load Config); `ancrages.rs`: DLLs loaded by Windows itself (LSA packages, AppCertDlls, print monitors, time providers, Winsock catalog); `pilotes.rs`: kernel drivers (location, known vulnerable drivers from LOLDrivers) |
| `src/sqlite.rs` | SQLite reader written for the project, without sqlite3: counts a table's rows (browser logins) and reads a few columns (macOS TCC.db); bounded against a damaged database (looping pages, overflow, depth) |
| `src/plist.rs` | reader for Apple plists, XML and binary (“bplist00”), instead of defaults and plutil; bounded against a hostile file (size, depth, number of values, looping references) |
| `src/archives/` (`gzip.rs`, `tar.rs`, `zip.rs`, `crc32.rs`), `src/pe.rs` | archives read in Rust, without zcat, tar or unzip: gzip (CRC-32 and size checked for a downloaded file), tar (pax and GNU long names, cut archive refused), zip (tldr-pages; full check, CRC-32 included, for the key's copy); version and architecture of an .exe read from its version resource (RT_VERSION), piece by piece, without Windows functions, and the guards of the shipped vanguard.exe (DependentLoadFlags, manifest). Bounded in size and number of entries against a hostile file |
| `src/machine/windows/portes.rs`, `evenements.rs` | classic backdoors (debugger on a sign-in screen accessibility program through IFEO or SilentProcessExit, sethc and utilman replaced, Winlogon's Shell and Userinit, AppInit_DLLs, WMI subscriptions), fixed when the original state is known; event logs of the last 7 days (bursts of wrong passwords from the network, security log cleared, accounts created, suspicious services) |
| `src/machine/linux/dissimulation.rs`, `algorithmes_ssh.rs` | rootkit signs read from /proc and /sys: hidden processes, programs without a file (memfd, deleted, /tmp), a kernel module that hides, unknown unsigned modules, a card in promiscuous mode; broken sshd algorithms (configuration read in Include order), removed through `00-vanguard.conf` after `sshd -t` |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `partages.rs`, `sante.rs`, `wifi.rs`, `bluetooth.rs`, `agents_ia.rs` | checks shared by the three systems (partages.rs: file shares open to everyone; bluetooth.rs: visible computer, recently paired devices; agents_ia.rs: local AI server open to the network, risky settings of coding agents and their MCP servers, read without ever showing a secret value) |
| `src/machine/chasse.rs` | live threat hunting, on the three systems: successful sign-in from an address that had just failed at least ten passwords (sshd's log on Linux, 4625 then 4624 on Windows; not checked on macOS); suspicious running programs (known offensive tool, command line that downloads or hides what it runs, program started from Downloads, a temporary folder, Public or the recycle bin), judged by pure functions, Vanguard and what it starts left aside |
| `src/machine/linux/veilleur.rs` | the watcher: process connector (exec, fork, exit) and sock_diag socket ends ("destroy" groups) decoded by hand through libc, without root or eBPF; programs judged as COM-PRG-001, connections against the kept command servers; dashboard log at a bounded rate; user service off by default; it stops nothing |
| `src/machine/wifi/elements.rs`, `nl80211.rs`, `networkmanager.rs`, `wlanapi.rs`, `profils.rs` | Wi-Fi read without an external program: 802.11 beacon information elements (RSN and WPA ciphers, WPS) decoded byte by byte; access points heard by the Linux kernel (nl80211, last scan), kept by NetworkManager (D-Bus, read only) and by Windows (wlanapi); saved networks (NetworkManager, iwd, macOS, Windows profiles) |
| `src/machine/unix.rs` | checks shared by Linux and macOS: secret files, sudo |
| `src/machine/darwin.rs`, `macos/noyau.rs`, `macos/config_reseau.rs` | macOS read without launching a tool: libproc structures, routing table, process arguments and SIP written by hand from the XNU headers (sizes checked at compile time, bytes tested on Linux); processes, sockets, routes, neighbours, swap, SIP (csr_get_active_config through dlsym), startup options, mounts asked from the kernel; DNS, proxy and network services from SystemConfiguration; Apple's tool stays as a fallback, and oracle tests compare both on GitHub's Mac |
| `src/machine/heure.rs`, `fin_de_support.rs`, `comptes_oublies.rs`, `mots_de_passe.rs`, `sensibles.rs` | clock set automatically; system, abandoned programs and browsers without updates; unused accounts; unprotected browser passwords; sensitive files lying around |
| `src/changements.rs` | what Vanguard changed: each fix run by `machine::appliquer_chacune`, noted on the computer; a block with what undoes it exactly, never trimmed while it is in place; a check-up fix that can be undone, linked to its note, undone one by one |
| `src/signaler/` | `vanguard disclose` (French name `signaler`): prepare a report for a vendor without ever sending it; sorting (known flaw, malware, phishing, missed detection, bypass) in `tri.rs`, closed list of programs and their fields in `programmes.rs`, pure draft in `brouillon.rs`, three-layer privacy safeguard (reduce, mask, final check) in `garde.rs`, pure Markdown neutralization (fuzzing bench) in `markdown.rs`; no network code, checked by a closed list of calls |
| `src/evenements.rs` | `vanguard events [--json] [--incident id]`: the event log shown, the state of its chain first (a tampered log is read, but not verified), an incident's thread followed through `cause` |
| `src/journaux_windows/` | Windows event logs read by Vanguard itself, on every system: .evtx reader (`evtx/`: header, 64 KiB chunks checked by their CRC32, [MS-EVEN6] BinXml with templates and substitutions, `binxml.rs`, `valeurs.rs`), bounded in size, depth and work, what could not be read counted in a report; cross-read with the `evtx` crate in its tests); a single event form (`evenement.rs`) for two sources: a folder of .evtx files (`fichiers.rs`) and this computer's logs on Windows (`vivant.rs`, the event log service's XML turned into the reader's tree by `xml.rs`); gaps in the record number sequence (`trous.rs`: removed, missing, hot copy, unreadable, before export) |
| `src/annulation.rs` | “Put everything back”: check-up fixes, Optimize and Gaming settings, blocks and public Wi-Fi mode, shown then undone from the most recent to the oldest, in one administrator request, read back afterwards |
| `src/sauvegarde.rs`, `src/raccourci.rs`, `src/mise_a_jour.rs`, `src/a_laisser.rs` | guided automatic backup (Déjà Dup or rsync, Time Machine, File History) and check my backup (the rsync copy read back without cache, random files compared with their original; a newer original is not an error); shortcut on this computer; updating its copy from the key (version engraved in the program, read without running it) or from GitHub (`mise_a_jour/github.rs`: Ed25519-signed manifest published in d9v3/vanguard-update, the program's size, checksum and version checked); report to leave with the person you helped |
| `src/corriger.rs` | guided application of fixes |
| `src/socle/` | the common base, knowing nothing of the network or protection: Vanguard's folder, atomic write and lock (`fichiers.rs`), cache of downloaded lists (`cache.rs`), an IP address's scope per the RFCs (`adresses.rs`), home folder and disk space (`personnel.rs`), Linux and macOS processes (`processus.rs`), JSON with comments (`jsonc.rs`), os-release (`systeme.rs`), hex fingerprints (`hachage.rs`) |
| `src/reseau/mod.rs`, `src/reseau/scan.rs`, `ping.rs` | network scan (TCP connect, without root), ARP, network notebooks; ICMP echo without running ping |
| `src/reseau/nmap.rs` | service versions with nmap -sV, when installed: deep scan of a local network device, on the ports already found open |
| `src/reseau/empoisonnement.rs` | name poisoner (Responder): a random name that does not exist, asked over LLMNR, NetBIOS and mDNS during the scan; the device that answers both tries is flagged (packets written and read in Rust) |
| `src/risk.rs` | knowledge base of ports and risk levels |
| `src/reseau/connexion.rs` | connection test for gaming |
| `src/protection/antivirus.rs` | ClamAV / Defender, quarantine |
| `src/protection/yara.rs`, `src/protection/pieges.rs` | YARA scan (bundled rules, YARA-X compiled into the program); decoy files against ransomware |
| `src/protection/rancongiciel/` | ransomware watcher: live watching of personal folders (`notify`, already present), rule-based score per process group over a 10 s window (burst, encrypted content, names, ransom note, decoy touched, backups deleted), attribution by write counters and descriptors (`/proc/<pid>/io` and `fd`, without root or a new crate); with active protection and an almost-certain case, freeze of the lineage, evidence, stop and quarantine; decisions as pure functions (tested on Linux and Wine) |
| `src/protection/memoire.rs`, `src/machine/windows/memoire.rs` | program memory (`vanguard memory`, on demand): the YARA rules on the private or executable regions of running processes, bounded (64 MiB per region, 512 MiB per process, 4 GiB and 5 minutes in all); /proc/<pid>/maps and mem on Linux, VirtualQueryEx and ReadProcessMemory on Windows (LSASS, protected and critical processes never read); macOS not checked; nothing read is kept |
| `src/protection/empreintes.rs` | MalwareBazaar SHA-256 fingerprints (abuse.ch, with the key): full list every week (zip archive), recent ones every day, kept in Vanguard's folder and sorted; the YARA scan looks up every file it reads |
| `src/protection/abuse_ch.rs` | abuse.ch lists and the person's key (MalwareBazaar, URLhaus, ThreatFox since the public exports closed): kept on the computer (600), shown masked, never in a written address; without a key or with a refused one, lists not checked |
| `src/protection/outil.rs`, `src/protection/secrets_git.rs`, `src/protection/conteneurs.rs` | secrets in git project history (Vanguard's rules, plus gitleaks when present); open source tools run when installed, installation offered otherwise (trivy on Docker or Podman images) |
| `src/reseau/surveillance.rs` | systemd timer / Task Scheduler / launchd agent, notifications |
| `src/reseau/tableau.rs` | monitoring dashboard: alert log (bounded in number and age), single-file local HTML page (state, alerts by day, new devices, connections to botnets) |
| `src/audit/mod.rs`, `score.rs`, `fiches.rs` | network audit by domain (Exposure, Wi-Fi, Segmentation, DNS and TLS, Devices, Computers), defensive only: scores (100 minus penalties, no score when more than a third could not be checked), rule sheets (“COM-XXX-000” identifier, FR/EN subject, cited references) |
| `src/audit/exposition.rs`, `igd.rs`, `http_local.rs`, `ipv6.rs` | Exposure domain: what the home shows to the Internet from the scan, the address seen from the Internet (STUN) and IPv6; pure-Rust UPnP IGD client (SSDP, XML description, SOAP actions, all bounded; the gateway only, others claiming to be the router are reported; never this machine nor a host other than the description's) with its tiny HTTP/1.1 client for the local network; the computer's public IPv6 addresses and the neighbours that have one (netlink) |
| `src/audit/wifi.rs`, `segmentation.rs`, `arp.rs` | Wi-Fi (cipher of the connected network, WPS, several transmitters for one name, remembered networks), Segmentation (IoT devices alongside computers, guest network, who hands out addresses, IPv6 routers) and ARP integrity (router MAC that changes, a computer maker's address, one MAC for several IPs) domains |
| `src/audit/dns_tls.rs`, `dns_client.rs`, `bail.rs` | DNS and TLS domain: DNS handed out by the router compared with the computer's, encrypted DNS (DoT, DoH, DDR), resolver compared with two public resolvers, certificate exceptions and roots pushed into Firefox; home-made UDP DNS client (A, AAAA, TXT, SVCB, HTTPS, EDNS0, DO bit), bounded; DHCP lease and effective DNS configuration read from files and the registry |
| `src/audit/tls_pq.rs`, `ssh_kex.rs` | post-quantum side of the audit, without computing any key: hand-written TLS 1.3 ClientHello (X25519MLKEM768 only, empty key share, padded to 1,600 bytes) and reading of the answer (HelloRetryRequest or alert); KEXINIT of an SSH server on the local network read, then the connection closed; bounded, fuzzed |
| `src/audit/appareils.rs`, `postes.rs` | Devices (IoT devices recognised from the scan, nothing probed beyond the camera search) and Computers (this computer as seen from the network: the report's network findings; the other computers from the scan) domains |
| `src/rapport.rs`, `src/historique.rs` | HTML report, check history, grade curve |
| `src/modele/` | common findings model: `rule + object` key without translated text (`id.rs`), state healthy, not applicable, not checked with its reason, or problem (`etat.rs`, `raison.rs`), prefixes and tool identifiers (`registre.rs`), versioned inventory of state files from which `sceau` takes what it protects (`inventaire.rs`); common error channel `Echec` with its stable code (`raison.rs`); append-only event log, chained on the exact bytes, sealed head, sealed closed months, linked by `cause` (`evenement.rs`, `journal.rs`); serializable result of the tools run on their own, written to `examens/` and to the log (`resultat.rs`, used by the `resultat.rs` of `espions`, `perimes`, `courriel_suspect`, `acces`, `lien`, `sortantes`, `distance`, `diagnostic`, `lenteur`, `reseau::objets`, `reseau::connexion` and `reseau::listes_noires`); recognized rule frameworks: CIS, Microsoft, ANSSI (`reference.rs`) |
| `src/canaris.rs` | format canaries (tests only): each real source downloaded with the program's own request and read back by its reader; run by the night watch (`VANGUARD_CANARIS`), never by `cargo test` |
| `src/autotest/` | self-test (`vanguard autotest`, and every week with the monitoring): check rules under a guard and a time limit, findings invariants, report without any value read, exit code (`mod.rs`); process-wide read-only switch and proof by BLAKE3 fingerprints of the data folder (`lecture_seule.rs`); registry of the cross-checks native versus system tool, allowed read commands (`croisees.rs`, declared in `machine/linux/croisees.rs` and `machine/windows/croisees.rs`); timings log, duration of each rule summarized per day, slowdowns (`mesures.rs`) |
| `src/sceau.rs` | seals of Vanguard's state (accepted alerts, integrity reference, reported botnets, versions seen and revocation of the main key, Optimize's previous values, alerts declared normal, real-time, audit, sites and gateway already reported): changed outside Vanguard, it no longer counts and the check says so; deleted along with the seals, “unknown”, never a first run; only a plain file of bounded size; as root, only in a root-owned folder |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming/` | repairs, updates, gaming |
| `src/optimiser/` | privacy, performance and comfort settings, with exact undo; the same mechanism for check-up fixes and gaming settings (`annulables.rs`: gestures from a closed list, previous value read then sealed in reglages.json, jeux.json notes taken over); startup programs (`demarrage.rs`); Windows Defender blocking: ASR rules, network protection, PUA, controlled folder access (`defender.rs`) |
| `src/nettoyer/` | cleanup: items per system, space measured before and after |
| `src/logiciels/` | software to install: checked catalog (`catalogue.rs`), state and installation per system |
| `src/protection/fuites.rs`, `src/donnees.rs` | leaked passwords, data backup |
| `src/protection/cle.rs` | USB drive protection on Linux and macOS: partition remounted read-only away from the owner's computer |
| `src/guide/` | command guide: one file per system (`arch.rs`, `omarchy.rs`, `fedora.rs`, `debian.rs`: each distribution's programs and step-by-step guides; `linux.rs`: programs common to all, and openSUSE; `windows.rs`, `macos.rs`, `tous.rs`), menus and search (`mod.rs`), commands run here (`lancement.rs`), tldr-pages examples downloaded every week and copied to the key at deployment (`tldr.rs`, `tldr/cle.rs`) |
| `src/apprentissage.rs` | what Vanguard learns here: alerts declared normal (appris.json), habits |
| `src/reseau/listes_noires.rs` | the home's Internet address in blocklists (DNSBL), after consent |
| `src/entretien.rs` | monthly check-up: grade, updates, space, new problems, in one notification |
| `src/protection/sortantes.rs` | who talks to the Internet: established connections by program (ss, PowerShell, lsof), reverse DNS; botnet command servers (Feodo Tracker without a key, ThreatFox with the abuse.ch key: full export read by its header, and API) |
| `src/protection/environnement.rs` | at startup: library injected into the session (LD_PRELOAD, DYLD, AppInit_DLLs), judged like preloading |
| `src/protection/manifeste.rs` | check Vanguard itself (version, commit date, SHA-256) and key manifest (BLAKE3 checksums kept on the owner's computer, one reference per key, compared in the check; Ventoy menu and ISO image sizes included, restated by images-cle.sh; a recognized key whose volume identifier changed: reported) |
| `src/protection/cles_connues.rs` | VANGUARD keys known to this computer (`vanguard.jeton` token written at deployment, `cles-connues.json`); per key, the checksum of the record as Vanguard wrote it and its protection: a record changed outside Vanguard is neither read nor rewritten |
| `src/protection/distance.rs` | is my computer being controlled? remote control tools (installed, at boot, running, downloaded), in the check and as a guided walkthrough |
| `src/protection/espions/` | spyware: is someone watching me? `echap` (Échap list, CC-BY 4.0, downloaded when used, read by a bounded YAML reader written for the project; servers, sites, names), `connus` (desktop monitoring software, each pattern with its source), `clavier` (Linux: who holds /dev/input), `tcc` (macOS: Input Monitoring, Accessibility, Screen Recording), `windows` (installed, services, Run, processes); read-only, in the check without network |
| `src/protection/perimes/` | outdated software (Windows, macOS): `version` (strict comparison, per-publisher normalization), `sources` (closed table of fixed public files, downloaded in full, the same for everyone; copy kept one day, unreadable answer refused), `produits` (table of followed programs and their lines in CISA's catalog), `windows` and `macos` (inventory: executables, publishers' files, registry without RegLoadKey, Info.plist), `verdicts` (one rule per product), `mozilla_avis` (Mozilla advisories read without a YAML library: Firefox checked flaw by flaw), `rapport` (screen and check-up); read-only |
| `src/protection/courriel_suspect/` | is this email a scam? bounded, standalone MIME reading (`mime.rs`, fuzzed), sender and the provider's SPF/DKIM/DMARC (`entetes.rs`), links in text and HTML (`corps.rs`), attachments in a disposable folder (`pieces.rs`) |
| `src/protection/lien.rs` | is this link dangerous? local check (punycode, imitated brands…), then RDAP, URLhaus, Spamhaus DBL, SURBL |
| `src/protection/telechargement.rs` | check a downloaded file: checksum by the system's tool, name and content, YARA and antivirus; programs landing in Downloads, for monitoring |
| `src/protection/blocage/` | threat blocking: each threat offers “Block” (action shown, accepted, written down, undoable); active protection, after a consent given once, blocks what is certain by itself (MalwareBazaar fingerprint, known attack tool, command server) at the check-up and in the hourly monitoring; as administrator, the consent and the automatic modes in blocage.json (which any program of the account can write) block nothing by themselves (`pour_agir`). `parametres` (blocage.json: one mode per category), `menaces` (what is found), `gestes` (prepare, do, undo), `gardes` (pure safeguards: Vanguard, critical processes, system programs, remote sessions), `pare_feu` (ufw, nftables, Windows Firewall, pf) |
| `src/protection/temps_reel.rs` | Vanguard's real-time protection: turned off at once (temps-reel.json: start and end, 1 h, 4 h or until turned back on), it stops each monitoring run at its start and has what blocking is certain of offered with one click, without touching their settings; once its time is up it no longer counts, and the monitoring removes the file; unreadable, nothing is turned off; never Defender, the firewall or UAC; not set as administrator |
| `src/protection/quarantaine.rs`, `src/protection/camera.rs` | reversible quarantine, the single path for blocking, the antivirus and YARA: isolate (SHA-256 kept, action noted and undoable), put back exactly, delete; camera and microphone: who uses them (registry on Windows, /dev/video and pactl on Linux) |
| `src/protection/acces.rs` | privacy check: apps that can access location, contacts, camera and microphone (ConsentStore on Windows, Flatpak and Snap on Linux, TCC.db on macOS); read-only |
| `src/reseau/canaux.rs`, `src/reseau/nat.rs` | crowded Wi-Fi (nearby networks by channel); NAT type (home-made STUN client) |
| `src/dns_rapide.rs` | fastest DNS: measurement, protecting DNS kept, setting undone through `optimiser/` |
| `src/reseau/cameras.rs` | hidden cameras: maker, RTSP stream, ONVIF discovery (WS-Discovery), web page |
| `src/reseau/wifi_public/` | public Wi-Fi mode: sealed and validated previous state (`etat.rs`), pure commands and readings per system (`linux.rs`, `windows.rs`, `macos.rs`), suggestion and portal page without sending anything (`portail.rs`), turning on, off, safe shutdown and check finding (`mod.rs`) |
| `src/reseau/objets.rs` | router and connected devices: what the router announces (SNMP, UPnP, web header), admin over HTTP only, devices recognized by maker, name, ports and announcements; default-password advice, never checked (no attempt, nothing more probed); scan section and `vanguard smart-devices` from the notebook |
| `src/depanner/` | troubleshoot step by step: the paths (`mod.rs`), network and Wi-Fi (`reseau.rs`), sound (`son.rs`), printer (`imprimante.rs`), after an infection (`infection.rs`), new computer (`nouveau.rs`), computer leaving (`depart.rs`), hacked account (`compte.rs`), a relative's computer (`proche.rs`: three questions, a summary of five points at most ordered by the answers, tips for the page to leave behind), slow since an update (`depuis_maj.rs`) |
| `src/protection/preuve.rs`, `src/protection/sources.rs`, `src/protection/normales.rs` | the evidence recorded before each block or quarantine (process, command line, SHA-256, connections; "not possible (reason)" otherwise); the single path to threat sources (MalwareBazaar, offensive tools, COM-PRG-001) for blocking, the check and the watcher; watcher, monitoring and blocking alerts declared normal (sealed, 90 days) |
| `src/traces/` | collect the traces: processes with their SHA-256, network, startup, JSON check, accounts, logs of the last 7 days, recent files, what Vanguard saw and did (`vanguard.rs`: alerts, actions and their evidence, incident threads, state files copied), then LISEZMOI and MANIFESTE (`sha256sum -c` format), in a dated folder; shared part (`mod.rs`), per system (`linux.rs`, `windows.rs`, `macos.rs`, `unix.rs`), incident timeline (`chronologie.rs`: CHRONOLOGIE.txt, what was read with a date put back in time order over 7 days, 5,000 lines at most); read-only |
| `src/lenteur.rs`, `src/fiche.rs` | why it is slow (two-sample snapshot, startup); computer specs |
| `src/copier.rs` | copy my files to an external disk: checked copy (BLAKE3), resume, never overwrites; check a copy (restore test) |
| `src/verifier_cle.rs` | check my drive: real capacity, speeds and bad blocks, written into the free space and read back without cache, then erased |
| `src/passage.rs` | takeover of what a version from before the name change left (data, timers, shortcut, firewall rules), leftovers listed for the uninstall; to be removed at 1.0 |
| `src/desinstaller.rs` | remove Vanguard from a computer: what it placed, recomputed without a register (with passage.rs for earlier names), shown, checked; data after a second consent |
| `src/ordinateurs.rs` | my computers: each computer's visit noted on VANGUARDLOG (categories and levels only) |
| `src/plugins/` | extensions: plugins (`mod.rs`: safe folder, approval by SHA-256, checked copy then run, `manifeste.rs`: plugin.toml read by a bounded home-made parser, `archive.rs`: .zip unpacked in Rust), lab (`labo.rs`), findings protocol (`sortie.rs`), restrictions switch (`reglages.rs`), menus (`menu.rs`); see the Extensions section |
| `extensions/` | Rust library to write a plugin (`sdk/`, crate `vanguard-extension`, outside the workspace) and examples (`exemples/`); how-to (in French): `extensions/LISEZMOI.md` |
| `src/chiffrement.rs` | protected key data: encrypted record (XChaCha20-Poly1305), data key kept by the owner and wrapped by the passphrase (Argon2id) |
| `assets/oui.tsv` | manufacturers by MAC prefix (IEEE list), stored as sorted tables at compile time (`build.rs`) |
| `assets/yara/` | ReversingLabs YARA rules (MIT license), gathered by `outils/maj-yara.sh` |
| `assets/banniere-blanche.png`, `assets/banniere-noire.png`, `assets/icones/`, `assets/vanguard.ico` | the banner (no background, one per GitHub theme) and the icon (the V), drawn cell by cell in the terminal banner's lettering by `outils/icone.py` |
| `LICENCES-TIERCES.txt` | license notices of the included libraries (`outils/licences-tierces.py`) |
| `src/commande.rs` | runs system commands with a maximum delay (`commande::lancer`), outputs read in the background: a tool that stops answering never freezes Vanguard |
| `src/http.rs` | Vanguard's HTTPS requests (reqwest, instead of curl), bounded in size and time; an API key never goes through another program's command line |
| `src/journal.rs` | error log, anonymized, on the key's VANGUARDLOG partition or in Vanguard's folder; brought back by `outils/deployer.sh` |
| `src/diagnostic.rs` | computer diagnostic: hardware, system, recent errors and crashes; a text copy saved |
| `src/fenetre.rs` | the terminal window sized to each menu, centered on the screen |
| `src/essais.rs` | for tests only: a test that cannot run here says it was “skipped”, and `outils/verifier.sh` counts the skips |
| `src/machine/administrateurs.rs`, `journaux.rs`, `navigateur.rs`, `navigation_detournee.rs` | new administrators (noted the first time they are seen); sealed or cleared logs; browser security settings; imposed proxy and hijacked hosts file, in the check |
| `src/machine/logiciels_vus.rs`, `sshd.rs`, `windows/ssh.rs`, `windows/defender.rs`, `macos/parite.rs` | installed software kept from one check to the next (logiciels-vus.json, sealed, never sent); sshd_config reading shared by the three systems; OpenSSH server and .ssh keys on Windows (registry, WMI, file rights); Defender protections that “harden” turns on, re-read by the check; passwords, secure boot and persistence beyond launchd on macOS |
| `src/machine/post_quantique.rs` | read-only post-quantum check (COM-PQC-001 to 003): key exchange list that sshd and ssh really keep depending on the OpenSSH version (computed in `sshd.rs`), pre-shared key of WireGuard tunnels counted without ever keeping the keys; the browsers' post-quantum key exchange (COM-NAV-004) is in `navigateur.rs` |
| `src/mise_a_jour/github.rs` | update from GitHub: Ed25519-signed manifest (main or backup key), highest version already seen, freshness; signed history of versions, to check a copy that is not the latest |
| `src/protection/integrite.rs`, `isoler.rs`, `memoire_dns.rs` | critical file integrity (BLAKE3 fingerprints); sandbox for an unknown program (bubblewrap or firejail, Windows Sandbox, sandbox-exec), also used for extensions; the computer's DNS cache, read without flushing it |
| `src/protection/kev.rs`, `sites_bloques.rs`, `src/reseau/upnp.rs` | CISA catalog of exploited flaws; dangerous sites blocked by the hosts file (URLhaus, ThreatFox); ports opened to the Internet through UPnP |
| `fuzz/` | fuzzing bench, outside the program's build: one target per reader, which includes its `src/` module by path (`fuzz/cale/` for the rest), seeds with made-up values (`outils/fuzz.sh`) |

### Extensions (plugins and lab)

An extension adds a program without touching Vanguard's code: a plugin (folder + `plugin.toml`, a lasting tool) or a
lab script (dropped as it is). The how-to, the manifest and the findings protocol are in
[extensions/LISEZMOI.md](extensions/LISEZMOI.md) (in French); a plugin in Rust is written with
[extensions/sdk](extensions/sdk).

What must not change without rereading the design (`src/plugins/mod.rs`, at the top):

- an extension only runs on request and its findings never touch the grade: neither the audit, the history nor
  `risk::score` see them (separate section of the HTML report);
- restrictions on (the default): approval by SHA-256 of the whole folder, YARA and MalwareBazaar scan before
  consent, the hashed copy is the one that runs, no link followed, never by itself as administrator, no terminal
  (setsid, CREATE_NO_WINDOW), `commande::lancer_borne`, minimal environment;
- a manifest only asks (`confiance`, `dans_le_bilan`, `dans_la_surveillance`): only the person grants, and the grant
  is tied to the fingerprint (`reglages::Confiance`);
- as administrator, nothing in the folder lifts a guard: never by itself, and each run is asked;
- even with restrictions off, the extensions folder stays yours and closed to other accounts (`dossier_sur`).

The tests (`src/plugins/tests.rs`) run real scripts in throwaway folders, and `tests/programme.rs` adds then runs
the example plugin through the real program. `outils/verifier.sh` also builds and tests the sdk and the Rust example
(“extensions” step).

### Adding a check rule

A rule is written in its topic's file and declared there, with no central list:

```rust
inventory::submit! {
    crate::machine::regles::Regle {
        id: "LNX-NOY-002",                 // system, area, number: stable, never reused
        systeme: crate::machine::regles::Os::Linux,
        sujet: ("BPF réservé à root", "BPF reserved for root"),
        references: &["kernel.org : unprivileged_bpf_disabled"],
        verifier: || bpf().into_iter().collect(),
    }
}
```

The check runs it in parallel with the others, in rank order (`rang`: 10 for the firewall, 100 and up for the system,
500 and up for the common rules), and each of its findings carries its identifier up to the JSON report. The checks
from before the registry are declared in their system's `regles.rs` and in `src/machine/regles_communes.rs`; a new one
is better declared next to its check, with the `regle!` macro.
The judgment is written separately (`juger_…`, reading nothing from the system), to be tested on made-up data.

## Build, test, deploy

Requirements: `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu`, `musl` (musl-gcc), `mingw-w64-gcc`
and `clang`: YARA-X compiles a little C for each target (clang for clippy on the Mac targets, see
`outils/verifier.sh`). To deploy, also `cargo install cargo-auditable --locked --version 0.7.7` and
`cargo install cargo-audit --locked --version 0.22.2`, the versions of the CI (`.github/workflows/ci.yml`):
`deployer.sh` embeds in each program the list of its dependencies, versions included (`cargo auditable build`), then
looks for known vulnerabilities in it (`outils/failles-programmes.sh`); without them, or in another version, it refuses.

```sh
outils/deployer.sh     # builds Linux (musl, static) + Windows, installs locally, pushes to GitHub, updates the key
```

Slow check? `VANGUARD_CHRONO=1 vanguard audit --json >/dev/null` gives each check's time (they run at the same time:
the slowest one sets the duration).

Tests: `cargo test` (Linux, in a throwaway data folder: never the computer's real data); Windows tests under Wine
(`cargo test --target x86_64-pc-windows-gnu` with a Wine runner); `cargo clippy --all-targets` on the four targets
(Linux, Windows, `aarch64-apple-darwin`, `x86_64-apple-darwin`), in strict mode (pedantic), without any warning;
`cargo fmt --check`. Internal functions are tested in their module; `tests/programme.rs` runs the real program the
way a person would (help in both languages, menus left, lists, refusals respected, audit and scan of 127.0.0.1 in
JSON), with a throwaway home folder, without the user's key or session. Full runs: `outils/test-linux/essai.sh`, `outils/test-macos/essai.sh` (on a GitHub Mac) and, in
the Windows virtual machine, `TESTER-VANGUARD.bat` (dropped there by `deployer.sh`).

macOS: built and tested on a GitHub Mac (`.github/workflows/macos.yml`, universal Apple Silicon + Intel binary),
every night if the code changed or on demand (`gh workflow run macos.yml`). `deployer.sh` fetches the latest
successful build for the key.

Continuous integration (`.github/workflows/ci.yml`): on each push to master and each pull request,
`outils/verifier.sh --ci`, the same check as on the author's computer except Wine, then the check-up on real
distributions; a real Windows (PowerShell, registry) on each push, each pull request, every night if the code
changed (`.github/hors-code.txt`) and on demand (`gh workflow run ci.yml`), with the reproducible build and the
delivered .exe (MinGW) tried on Windows. Every night: cargo audit, cargo deny, and five minutes of fuzzing per
target. The repository is public: Linux and Windows minutes do not count.

Skipped tests: a test that cannot run on a computer (missing system tool, unreachable registry, root of a namespace)
does not return silently, it calls `crate::essais::saute("reason")` (`src/essais.rs`): `verifier.sh` counts these
skips next to the passed tests and shows their reasons, since a skipped test checked nothing. Menu navigation is
tried for real in a pseudo-terminal (`tests/programme.rs`, `menus_dans_un_terminal`), and the displayed texts are
compared with master (`outils/textes.py`).

Dependencies: `cargo deny` (`deny.toml`: known RustSec vulnerabilities, licenses from its list, crates.io only,
duplicates; `extensions/deny.toml` for the extensions library and the Rust example, which have no dependencies) and
`cargo audit` (a second opinion on vulnerabilities, with only the exceptions of `deny.toml`, which `.cargo/audit.toml`
copies), in `outils/verifier.sh` (skipped without the tool, cargo audit also without Internet) and every night in CI.
The list only keeps permissive licenses (MIT, Apache-2.0, BSD, ISC…), compatible with the GPL-3.0-or-later and with
a possible dual license of Vanguard: any other, even free and GPL-compatible (MPL, LGPL), first needs the author's
approval.

Fuzzing: `outils/fuzz.sh [target|tout] [seconds]` (cargo-fuzz and the nightly toolchain), on the readers of data coming
from elsewhere (plist, HTTP and DNS replies, timeline logs, Windows .evtx logs, the router's UPnP XML, SQLite, Échap's YAML, archives,
.exe resources…). `outils/verifier.sh` builds the bench and spends five seconds on each target (a target broken by a
change in `src/` shows at once), CI five minutes every night; its dependencies go through cargo deny
(`fuzz/deny.toml`). A target is added in `fuzz/Cargo.toml`, which `fuzz.sh` reads.

Dead links: `outils/liens.py` opens every link of the repository (documentation, the program's code except tests,
scripts, licenses) and checks the internal links of the Markdown pages: target file, heading of an anchor, downloads
of the latest release. It runs by itself before each push by `deployer.sh` and before each release page; CI checks
the internal links (`--hors-ligne`). A dead link stops the push, a doubtful one (a site refusing programs, a server
down) is only shown. Links that cannot be opened as they are (an API endpoint, a namespace) are described in
`outils/liens.txt`.


### Reproducible build

Published programs are built by `outils/compiler-version.sh`, the same recipe for `outils/deployer.sh`, CI and anyone
who wants to rebuild a program from its tag: the toolchain of `rust-toolchain.toml`, Cargo.lock as is, the CI's
cargo-auditable version, the commit date (never the build time), and the build paths removed (the repository becomes
`/vanguard`, cargo's folder `/cargo`). Measured on October 23, 2026: the same commit built in two different folders
of this computer gives two identical programs, Linux and Windows alike; before, home folder paths stayed in the .exe
(`~/Projects/vanguard/target/…`), and two folders gave two programs. What can still differ from one computer to
another: the versions of musl-gcc and MinGW (gcc, binutils, startup libraries), which compile the C of ring and
YARA-X and link the programs. CI writes the fingerprint of its builds in its log (`EMPREINTE-VANGUARD-LINUX`,
`-WINDOWS`), to compare with `SHA256SUMS.txt`; they are not yet the same as the author's computer's while these tools
differ (Arch versus Ubuntu).

## Screenshots and social preview

`outils/captures.py` retakes the README screenshots (`assets/captures/`, in French and English) and the repository's
social preview (`assets/partage.png`). `deployer.sh` runs it for each published version, since the menu shows its
number, and commits the images separately.

Vanguard really runs there, in an 80-column pseudo-terminal, from a fake key and on a copy of the data: nothing real is
touched. The network becomes “Salon”; MAC addresses (vendor prefix kept), IP addresses (a made-up network, lengths and
order kept), device names and the account's folders are replaced, at random on each run; only an excerpt of the
machine check with nothing personal in it is shown. Then the privacy guard rereads each image: if a detail of the
home is still visible, none is written.

```sh
uv run --no-project --with pyte python outils/captures.py [program] [--connexion | --sans-connexion]
```

## Privacy

`outils/confidentialite.py` keeps personal details from reaching GitHub. It runs by itself: on each commit (added
lines, file names, author, message), before each push by `deployer.sh`, before each release page (notes and compiled
programs), before each journal issue and before writing the screenshots. Once per copy of the repository:

```sh
git config core.hooksPath outils/hooks                                     # pre-commit and commit-msg hooks
git config user.email "<id>+<account>@users.noreply.github.com"           # commits without your email
```

What is personal is read on the computer, never written in the repository: `~/.config/vanguard-dev/confidentiel.txt`
(one phrase per line: name, emails, address…), the global Git identity, the home folder, the devices and MAC
addresses of Vanguard's database, the saved Wi-Fi networks. Other people's data (the key visits friends, and their
error journal comes back here) is recognized by its shape: account of a home folder, email, Windows SID; a journal
issue is masked before it is sent, MAC and IP addresses included. On GitHub, the CI runs it again on the commits of
each push and each pull request (`--generique --plage`): only data recognized by its shape, without the identity of the
machine running it. `python3 outils/confidentialite.py --depot`
rereads the whole repository and its history. In tests, made-up values: MAC addresses keeping the vendor prefix,
network “Salon”, accounts “alice”, “bob”, “Zoé”, “Jean Dupont”, emails `@example.com`.

Rust keeps the libraries' path in the programs (`/home/<account>/.cargo/registry/…`): to publish a version, build
with `rustflags = ["--remap-path-prefix=/home/<account>=~"]` in `~/.cargo/config.toml` (`publier-version.sh` refuses
a program that still contains the home folder).

## Publishing a version

`outils/publier-version.sh` creates the version's GitHub release with the three programs
(`vanguard-windows-x86_64.exe`, `vanguard-linux-x86_64`, `vanguard-macos`), their SHA-256 checksums and, as notes, the
commit of each version since the previous release (title and bullets), the newest first; the README's download
links always point to the latest one. `--notes` shows these notes without publishing anything.

Every release goes to the key, the VM and GitHub (the code), with its page, 0.x.0 as well as 0.x.y: one a day as a rule,
since fewer releases mean fewer Mac minutes on GitHub, and fewer new programs that Defender and SmartScreen do not know
yet. An intermediate version of a series delivered back to back (`VANGUARD_INTERMEDIAIRE=1 outils/deployer.sh`) goes to
the key and GitHub, without a page or a drop in the VM: nothing is lost, since the next release takes over the versions
before it. GitHub's Mac builds at night when the code changed, and for each release: the key's macOS version can lag
behind the other two, and the deployment says so. After each push, it also updates the repository page
(`outils/github.py`): English description followed by the latest published version, link, topics and options, written
in `.github/depot.json`. Only the social preview image is changed by hand (Settings > Social preview).

## The USB key

The key (exFAT, label `VANGUARD`, marker file `vanguard.cle`) holds `Linux/`, `Windows/`, `macOS/`, `donnees/` (device
database, portable), `source/` (this repository) and the guide in two languages (`README.txt`, `LISEZMOI.txt`, taken
from `outils/`). The check history and the quarantine stay on each computer.

On the development PC, it updates itself (systemd units in `outils/systemd/`, installed by
`outils/systemd/installer.sh`): after each build (`vanguard-copie.service`), each time it is plugged in, with the
latest version from GitHub, built if it is new (`vanguard-cle.service`, `deployer.sh --branchement`), and every day if
it stays plugged in (`vanguard-cle-maj.timer`, `outils/maj-cle.sh`: the program as on plug-in, then the images;
skipped without error when the key is not mounted).

The key has two partitions: `VANGUARD`, read-only everywhere except on its owner's computer (GPT attribute honored by
Windows; on Linux and macOS, Vanguard remounts it read-only itself), and `VANGUARDLOG`, which only receives the error
log, anonymized. `outils/preparer-cle.sh` prepares a new key.

In preparation, a rescue key that also boots computers: `outils/cle-secours.sh`, only on a computer whose local
setting asks for it (`CLE_SECOURS=oui` in `~/.config/vanguard/images-cle.conf`, read without being run; details at the
top of `outils/images-cle.sh`). Without it, the key only carries the program: no images, no Ventoy, no `WIN11` or
`MACOS`; the commands that would add them refuse and say so, and the timers copy nothing. Ventoy boots the Omarchy
installer, Arch, Debian and Fedora as network installers, SystemRescue and Windows 11 as a fallback, kept up to date by
`outils/images-cle.sh` (each project's signature checked, timer on the 1st and 15th of the month that copies right away
to a plugged-in key, copy on plug-in, a notification when each download starts and when nothing is new; an image
downloaded elsewhere enters the cache through `--importer`, checked the same way; the cache may be a link to another
disk: with that disk absent, nothing is recreated elsewhere; an optional image, off by default, only enters on a
computer whose local setting asks for it, read without being run); a FAT32 `WIN11` partition installs Windows 11 with
Secure Boot on, without adding a key to the PC (`install.wim` split by wimlib under the 4 GB limit); an HFS+ partition
holds the macOS recovery of Intel Macs; `VANGUARD` and `VANGUARDLOG` as before. `--plan` and `--essai` (on a disk image)
touch no disk; only `--ecrire` erases the key. Ventoy itself: its version on the key is read every day and on plug-in
(`cle-secours.sh --a-jour`); when older than the pinned one, its update, which erases nothing (`Ventoy2Disk.sh -u`,
logged), is offered by a notification to click. It goes through a separate root part, `outils/ventoy-racine.sh`,
installed once as a root-owned file (`cle-secours.sh --installer-racine`, in `/usr/local/libexec/vanguard/`) and run by
pkexec: the account cannot modify it, and it holds the pin and checks everything again (the key and its serial number,
the archive, an older version on the key). A newer Ventoy on GitHub is reported to the developer by the search on the
1st and 15th, never taken on its own: the archive is not signed, the pin changes by hand, then the root part is
reinstalled. Windows 11 older than six months (the date of its image's files) is reported by a notification, not
replaced: Microsoft only gives a 24-hour link, and the hash that checks the image is read on its page. The macOS
recovery has no age that matters: it installs the latest macOS, fetched from Apple at install time.
`outils/essais-cle.sh` (run by `outils/verifier.sh`) tests these tools without touching anything: separate namespace, no
Internet, fake key and fake disk.

## Errors and crashes

Vanguard records them with nothing personal (on the key, or in its folder when the key is not plugged in). On
deployment, `deployer.sh` brings them back and `outils/journal-vers-github.py` turns them into GitHub issues (label
“journal”) with `gh`: one issue per error, repeats as comments. No GitHub password in the program or on the key.
