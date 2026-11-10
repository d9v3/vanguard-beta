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
| `src/main.rs` | dispatch: the modules, the menu session, `main` sending each subcommand to its module |
| `src/demarrage/` | the command line (`arguments.rs`, clap), its help (`aide.rs`), the process rights at startup (`droits.rs`: elevated, coming from another account, refusing to optimize) and the window opened instead of the menu (`lancer_fenetre.rs`: when, checked, "open" awaited, otherwise the menu) |
| `src/menu/` | the interactive menu: the tool list, its groups and switches (`outils.rs`), the status at the top (`etat.rs`), search and command names (`recherche.rs`), display and launching (`lancer.rs`), its tests (`tests.rs`) |
| `src/deploiement.rs`, `src/deploiement/binaire.rs` | steps of `outils/deployer.sh` handed to the program (`vanguard deploiement …`, hidden command): key markers, the key's tldr archives; protections of the shipped programs read from their headers, without running them (`binaire.rs`, `verifier-binaire`): ELF (PIE, static, RELRO marking, non-executable stack, nothing writable and executable), PE (guards of vanguard.exe, ASLR, DEP, relocations); any other format is refused |
| `src/ui.rs` | colors, titles, frames, bars, lines wrapped and aligned within 76 columns |
| `src/selection.rs`, `src/selection/souris.rs` | keyboard menus and checklists (arrows, Enter, Esc or Backspace), word search in menus, preview of the highlighted line on the right (wide enough window); the mouse (`selection/souris.rs`: click, hover, wheel, right click, help-line buttons) |
| `src/descriptions.rs` | what the menu preview says about each tool and each group |
| `src/recherche.rs` | search: per-word score, synonyms ("box" → router), typos corrected; for the menu and `vanguard search` |
| `src/prediction.rs` | prediction of the word being typed, the same in every menu: its end in grey, Tab completes it |
| `src/langue.rs` | language choice and translation macros |
| `src/masque.rs` | hides in the binary the attack words Vanguard searches for (offensive tool command names, AMSI bypasses) through a compile-time XOR (`liste_masquee!`, `mot_masque!`), decoded in memory on first use: so an antivirus does not take Vanguard for the tool it hunts; the source stays in the clear |
| `src/parametres.rs` | Settings menu and `vanguard settings`: the startup settings (language, emojis, offline) in parametres.json, read before anything is shown, an environment variable winning; real-time protection, monitoring, check-up, learned alerts, blocking, extension restrictions and abuse.ch key changed by their own code; `src/parametres/partage.rs`: sharing with the author (batch A5), the switch of the record and of the sending (yes, no, unset), re-read from disk before each write and each send, "no" erases `envoi/`, `amelioration/` and the identifier; notice or question at launch depending on `PHASE`, "see" shows what would be sent; `src/parametres/agent.rs`: the Vanguard Agent (no AI) missions, one by one (a sealed switch each), and its journal, read-only, most recent first (batch G5) |
| `src/machine/mod.rs` | shared types, display, parallel execution of the checks |
| `src/machine/regles.rs` | registry of check rules: each one is declared where it is written (`inventory::submit!`), with a stable identifier (“LNX-PLT-001”) and at least one CIS, Microsoft or ANSSI reference; each runs under its time limit (beyond it: not checked, the check goes on); `vanguard rules` lists them |
| `src/machine/corpus.rs` | detection regression (tests only): the adapters that give the harmless fabricated cases of tests/corpus-detection to the rules' judging functions (a `corpus.rs` also in `linux/`, `windows/` and `journaux_windows/regles/`); `src/modele/corpus.rs` loads the cases, requires each to fire and its clean case to stay silent, and keeps the closed list of detection rules |
| `src/machine/linux/plateforme.rs` | platform security according to fwupd (HSI), kernel lockdown, BPF, user namespaces, auditd: the first rules of the registry |
| `src/machine/linux/natif.rs` | native Linux reads, without launching a program: the PATH (a program's presence and path, system folders for what sudo runs), systemd units, processes, the pacman, dpkg (one "installed" rule, held packages included), Flatpak and Snap databases, disks, the root file system, the account's groups |
| `src/machine/linux/paquets.rs` | what is installed, read from the databases (pacman, dpkg, Flatpak), the command as a fallback; used by Gaming, software and protection |
| `src/machine/linux/dbus.rs` | small D-Bus client written for the project, without a library: system bus, EXTERNAL authentication, messages encoded and decoded by hand; only read methods are sent (failed units, startup duration and critical chain from systemd, SMART through udisks2) |
| `src/machine/linux/zstd.rs`, `journal_systemd.rs` | zstd decoder written for the project (RFC 8878: pacman databases in zstd, compressed journal fields); reading the systemd journal files through their hash table (errors of this boot, SSH failures), journalctl as a fallback |
| `src/machine/linux/`, `src/machine/windows/` | per-system audit, one file per topic; on Windows, accounts (NetUserEnum, group S-1-5-32-544) and startup (Run keys through winreg, .lnk shortcuts read in Rust) without PowerShell, which stays as a fallback; `windows/corrections.rs` and `windows/eleve.rs`: the closed list of native fixes and the elevated process that applies them, blocking orders included ("runas" relaunch, named pipe checked on both sides), with the PowerShell script of a mixed list, read in memory and checked by its fingerprint, in the same and only UAC prompt; `windows/pare_feu.rs`: the blocking rules through INetFwPolicy2; `windows/chargement.rs`: imported DLLs taken from System32 only (the PE's Load Config); `windows/environnement.rs`: the reduced environment of what runs as administrator (variables computed by Windows, nothing from the account); `ancrages.rs`: DLLs loaded by Windows itself (LSA packages, AppCertDlls, print monitors, time providers, Winsock catalog); `pilotes.rs`: kernel drivers (location, known vulnerable drivers from LOLDrivers) |
| `src/sqlite.rs` | SQLite reader written for the project, without sqlite3: counts a table's rows (browser logins) and reads a few columns; bounded against a damaged database (looping pages, overflow, depth) |
| `src/archives/` (`gzip.rs`, `tar.rs`, `zip.rs`, `crc32.rs`), `src/pe.rs` | archives read in Rust, without zcat, tar or unzip: gzip (CRC-32 and size checked for a downloaded file), tar (pax and GNU long names, cut archive refused), zip (tldr-pages; full check, CRC-32 included, for the key's copy; entry-by-entry walk for file analysis); version and architecture of an .exe read from its version resource (RT_VERSION), piece by piece, without Windows functions, and the guards and protections of the shipped vanguard.exe (DependentLoadFlags, manifest, DllCharacteristics, relocations). Bounded in size and number of entries against a hostile file |
| `src/agent/` | Vanguard Agent (no AI) (batches G1 to G5): closed list of missions (kinds tuning, detection, record), each with its moments, its budget and a sealed state without free text (`agent/etat/`); a round never waits (lock taken, game running or read-only: skipped); every decision checked (the mission's kind, a lever of its own, safe direction only: a time limit that goes up, a cache duration that goes down), never a command, the network or elevation; chained and sealed log, 1 MiB and 90 days (`agent/journal.jsonl`); main switch: the self-tuning one, plus one per mission (`agent/agent.json`, sealed; doubtful: all off except a detection); `missions/`: `reglage.rs` (time limits that go up, second attempt of a rule at the end of the check-up) and `cache.rs` (hourly pass cache), adapters to `autotest::reglage` (L6, L6c); `releve.rs`, which writes the day's record (`amelioration`); `corrections.rs`, information only (a fix that fails or does not hold), with no access to fixes or blocking; called at the end of a check-up, at the hourly pass or at exit, depending on the mission (`tic`); `sortie.rs`: the view of `vanguard agent [--json]` and of Settings, schema 1, read without writing anything, closed names, rule identifiers, numbers and dates; boundaries: never lower detection, no command, network or elevation, no free text in a state or the log; states and log fuzzed |
| `src/amelioration/` | self-improvement, open lane (batch A1): error texts, software names and versions cleaned before being kept (paths, addresses, identifiers replaced by markers; three-layer secret detector: known prefixes, `key = value`, entropy; allowed characters only); a doubtful text is dropped whole and only the refusal is counted; pure module, fuzzed. Local record (batch A2, Vanguard Agent mission, Relevé genre): counters aggregated per day in `amelioration/jours/` (scans, rules, fixes, choices, tools, causes, cleaned texts, cache of unchanged results, hardware weekly), sealed; 96 KiB per day, 90 days, 10 MB in all; nothing sent, no command, no elevation; nothing under tests, Wine, CI, `VANGUARD_ENVOI=0`, as root or when run from a USB key; "No" to sharing stops and erases; a day converts into a send batch (A3); day reader fuzzed; boundary: every text, name or version from the computer goes through `amelioration::texte` (`texte.rs`) before being kept, never otherwise |
| `src/envoi/` | queue and sending (batch A4): the recorded day's batch (A2) queued one file per day in `envoi/file/`, seven days at most, strictly re-read before leaving; bounded state (`envoi/etat.json`, 2 KiB: attempts, waiting, installation identifier drawn every 90 days, previous version); platform reduced to a closed list (`plateforme.rs`); one thread at launch and one at each monitoring pass, under a lock; three attempts a day, 24 h of waiting after a 429 or a 503, a refused batch dropped, only the response code read (`http::poster_sans_lire`, no redirect); `RELAIS` is `None` until the relay is deployed: no connection; same guards as the record, plus offline, development build and consent (A5); boundary: no downward channel, nothing in the response steers the program; the day `RELAIS` gets an address, its host also goes into `http::HOTES` and MODELE-DE-MENACE.en.md |
| `src/analyse/` | base of Vanguard's own antivirus (batch AV1), no interface and no verdict: a file as a tree of parts (type recognised by content, inner path, size, SHA-256, facts, what was not read and why); readers written from their specification: ELF, Mach-O and universal binaries, OLE compound files ([MS-CFB]), VBA macros ([MS-OVBA]: compression, dir stream, procedures that run by themselves), Word and Excel 97 (encryption, XLM sheets), OOXML, shortcuts ([MS-SHLLINK]), texts and scripts; bounds (size, depth, parts, bytes produced and examined, compression ratio, time), quines; 7z, RAR, CAB, ISO, PDF, encrypted or truncated: reported as unchecked, never clean |
| `src/machine/windows/portes.rs`, `evenements.rs` | classic backdoors (debugger on a sign-in screen accessibility program through IFEO or SilentProcessExit, sethc and utilman replaced, Winlogon's Shell and Userinit, AppInit_DLLs, WMI subscriptions), fixed when the original state is known; event logs of the last 7 days (bursts of wrong passwords from the network, security log cleared, accounts created, suspicious services) |
| `src/machine/linux/dissimulation.rs`, `algorithmes_ssh.rs` | rootkit signs read from /proc and /sys: hidden processes, programs without a file (memfd, deleted, /tmp), a kernel module that hides, unknown unsigned modules, a card in promiscuous mode; broken sshd algorithms (configuration read in Include order), removed through `00-vanguard.conf` after `sshd -t` |
| `src/machine/dns.rs`, `certificats.rs`, `extensions.rs`, `partages.rs`, `sante.rs`, `wifi.rs`, `bluetooth.rs`, `agents_ia.rs` | checks shared by Linux and Windows (partages.rs: file shares open to everyone; bluetooth.rs: visible computer, recently paired devices; agents_ia.rs: local AI server open to the network, risky settings of coding agents and their MCP servers, read without ever showing a secret value) |
| `src/machine/chasse.rs` | live threat hunting, on Linux and Windows: successful sign-in from an address that had just failed at least ten passwords (sshd's log on Linux, 4625 then 4624 on Windows); suspicious running programs (known offensive tool, command line that downloads or hides what it runs, program started from Downloads, a temporary folder, Public or the recycle bin), judged by pure functions, Vanguard and what it starts left aside |
| `src/machine/linux/veilleur.rs` | the watcher: process connector (exec, fork, exit) and sock_diag socket ends ("destroy" groups) decoded by hand through libc, without root or eBPF; programs judged as COM-PRG-001, connections against the kept command servers; dashboard log at a bounded rate; user service off by default; it stops nothing |
| `src/machine/linux/veilleur_fichiers.rs` | the watcher's real-time file scanning, without privileges: one fanotify notification group per folder of the “Quick” list (closed after writing, arrived by rename; direct children only), read again through the marked folder and the name without following links (regular file, 32 MiB at most), bounded queue that merges repeated writes, verdict by `moteur::examiner_ouvert`; what is skipped counted as not checked, never clean; what is lost (full queue, overflow) counted then taken up again by a new reading of the folder (the name, or the files changed since the loss, from both ends), without queuing again what already waits there; its own writes ignored; the follow-up through `protection/blocage/en_direct.rs` (Certain: undoable quarantine according to the settings, Family: one click, Suspect: alert); no `unsafe` (the system call is in `fanotify.rs`) |
| `src/machine/wifi/elements.rs`, `nl80211.rs`, `networkmanager.rs`, `wlanapi.rs`, `profils.rs` | Wi-Fi read without an external program: 802.11 beacon information elements (RSN and WPA ciphers, WPS) decoded byte by byte; access points heard by the Linux kernel (nl80211, last scan), kept by NetworkManager (D-Bus, read only) and by Windows (wlanapi); saved networks (NetworkManager, iwd, Windows profiles) |
| `src/machine/unix.rs` | Linux checks on secret files and sudo (name kept: POSIX calls) |
| `src/machine/heure.rs`, `fin_de_support.rs`, `comptes_oublies.rs`, `mots_de_passe.rs`, `sensibles.rs` | clock set automatically; system, abandoned programs and browsers without updates; unused accounts; unprotected browser passwords; sensitive files lying around |
| `src/changements.rs` | what Vanguard changed: each fix run by `machine::appliquer_chacune`, noted on the computer; a block with what undoes it exactly, never trimmed while it is in place; a check-up fix that can be undone, linked to its note, undone one by one |
| `src/signaler/` | `vanguard disclose` (French name `signaler`): prepare a report for a vendor without ever sending it; sorting (known flaw, malware, phishing, missed detection, bypass) in `tri.rs`, closed list of programs and their fields in `programmes.rs`, pure draft in `brouillon.rs`, three-layer privacy safeguard (reduce, mask, final check) in `garde.rs`, pure Markdown neutralization (fuzzing bench) in `markdown.rs`; no network code, checked by a closed list of calls |
| `src/evenements.rs` | `vanguard events [--json] [--incident id]`: the event log shown, the state of its chain first (a tampered log is read, but not verified), an incident's thread followed through `cause` |
| `src/journaux_windows/` | Windows event logs read by Vanguard itself, on every system: .evtx reader (`evtx/`: header, 64 KiB chunks checked by their CRC32, [MS-EVEN6] BinXml with templates and substitutions, `binxml.rs`, `valeurs.rs`), bounded in size, depth and work, what could not be read counted in a report; cross-read with the `evtx` crate in its tests); a single event form (`evenement.rs`) for two sources: a folder of .evtx files (`fichiers.rs`) and this computer's logs on Windows (`vivant.rs`, the event log service's XML turned into the reader's tree by `xml.rs`); gaps in the record number sequence (`trous.rs`: removed, missing, hot copy, unreadable, before export); `EVT-` rules (`regles/`: engine without a screen, single event, burst or burst then success, what could not be read said “not verified” in `moteur.rs`; thirteen rules written from Microsoft's documentation and ATT&CK in `jeu.rs`, including scheduled tasks and process command lines, one fallback source being enough when Windows has two; findings and coverage, .evtx folder or live computer, and those of the check-up (WIN-JRN-003, in `src/machine/windows/evenements.rs`), in `resultat.rs`); “What happened?”: the alerts in time order and the period read per log, without a screen (`chronologie.rs`, used by the evidence's CHRONOLOGIE.txt), and `vanguard windows-logs` (`commande.rs`) |
| `src/annulation.rs` | “Put everything back”: check-up fixes, Optimize and Gaming settings, blocks and public Wi-Fi mode, shown then undone from the most recent to the oldest, in one administrator request, read back afterwards |
| `src/sauvegarde.rs`, `src/raccourci.rs`, `src/mise_a_jour.rs`, `src/a_laisser.rs` | guided automatic backup (Déjà Dup or rsync, File History) and check my backup (the rsync copy read back without cache, random files compared with their original; a newer original is not an error); shortcut on this computer; updating its copy from the key (version engraved in the program, read without running it) or from GitHub (`mise_a_jour/github.rs`: Ed25519-signed manifest published in d9v3/vanguard-update, the program's size, checksum and version checked); report to leave with the person you helped |
| `src/corriger.rs` | guided application of fixes |
| `src/socle/` | the common base, knowing nothing of the network or protection: Vanguard's folder, atomic write and lock (`fichiers.rs`), cache of downloaded lists (`cache.rs`), an IP address's scope per the RFCs (`adresses.rs`), home folder and disk space (`personnel.rs`), Linux processes (`processus.rs`), JSON with comments (`jsonc.rs`), os-release (`systeme.rs`), hex fingerprints (`hachage.rs`), conversions between integers and floats, the only ones to keep an `as` (`nombres.rs`), RELRO applied at startup on Linux, which musl does not apply (`relro.rs`) |
| `src/reseau/mod.rs`, `src/reseau/scan.rs`, `ping.rs` | network scan (TCP connect, without root), ARP, network notebooks; ICMP echo without running ping |
| `src/reseau/nmap.rs` | service versions with nmap -sV, when installed: deep scan of a local network device, on the ports already found open |
| `src/reseau/empoisonnement.rs` | name poisoner (Responder): a random name that does not exist, asked over LLMNR, NetBIOS and mDNS during the scan; the device that answers both tries is flagged (packets written and read in Rust) |
| `src/risk.rs` | knowledge base of ports and risk levels |
| `src/reseau/connexion.rs` | connection test for gaming |
| `src/protection/antivirus.rs` | on-demand scans: Vanguard engine, clamscan as an optional second opinion (Linux) or Defender (Windows), quarantine |
| `src/protection/etat_antivirus.rs` | “Antivirus status” screen (`vanguard antivirus --status`): engine, databases and their date from their headers, what is not read, second opinion and PUA, real-time file scanning; `--detail` loads the ClamAV database to count what it skipped |
| `src/protection/yara.rs`, `src/protection/pieges.rs` | YARA scan (bundled rules, applied by Vanguard's own engine); decoy files against ransomware |
| `src/protection/moteur.rs`, `src/protection/heuristiques.rs` | engine that examines one file and its common verdict (certain, family, suspicious, clean, not checked): read once by the analysis base (`src/analyse/`), every part (archive entry, OLE stream, macro, overlay) passed to the MalwareBazaar hashes, the YARA rules, the ClamAV signatures of the installed database, the test file and the heuristics; “clean” only if everything was read and no expected source was missing; hash → verdict interface; home-made heuristics (`heuristiques.rs`: “suspicious” only, each with its ATT&CK or vendor reference, silenced by the known-normal list) |
| `src/protection/clamav/` | native reading of the ClamAV databases found on the computer, without running clamscan: `cvd` (.cvd and .cld: header, gzip, tar, checked .info list; the .sign signature is not verified), `hashes` (file and section hashes), `ndb` and `ldb` (body and logical signatures, compiled in `corps` on the `motifs.rs` engine), `fp` (allow lists, ignored signatures), `signatures` (loading: PUA left out by default, hashes only or full database), `commun`; all fuzzed. `base`: the database is read only if it belongs to root or to the service account, and the reading account can neither write it nor belongs to its group, never as administrator; hash → verdict for the guard and the watcher, part-by-part examination of a file through the analysis base |
| `src/protection/regles_yara.rs`, `moteur_yara.rs`, `motifs.rs`, `oracle_yara.rs` | home-made YARA engine: reader for the subset of the language the rules use (anything else refused, named, “not checked”), conditions and the pe and elf modules (`moteur_yara.rs`, pe fields in `src/pe.rs`), multi-pattern search after Aho-Corasick, over a buffer or a bounded stream (`motifs.rs`, shared with the future ClamAV signatures); YARA-X only as the tests' oracle (`oracle_yara.rs`) |
| `src/protection/rancongiciel/` | ransomware watcher: live watching of personal folders (`notify`, already present), rule-based score per process group over a 10 s window (burst, encrypted content, names, ransom note, decoy touched, backups deleted), attribution by write counters and descriptors (`/proc/<pid>/io` and `fd`, without root or a new crate); with active protection and an almost-certain case, freeze of the lineage, evidence, stop and quarantine; decisions as pure functions (tested on Linux and Wine) |
| `src/protection/memoire.rs`, `src/machine/windows/memoire.rs` | program memory (`vanguard memory`, on demand): the YARA rules on the private or executable regions of running processes and on the loaded images their file no longer suffices to judge (file deleted or on tmpfs, private code pages), each image or allocation stitched back in one piece, bounded (64 MiB per region, 512 MiB per process, 4 GiB and 5 minutes in all); /proc/<pid>/smaps and mem on Linux, VirtualQueryEx, QueryWorkingSetEx and ReadProcessMemory on Windows (LSASS, protected and critical processes never read); nothing read is kept |
| `src/protection/empreintes.rs` | MalwareBazaar SHA-256 fingerprints (abuse.ch, with the key): full list every week (zip archive), recent ones every day, kept in Vanguard's folder and sorted; the YARA scan looks up every file it reads |
| `src/protection/abuse_ch.rs` | abuse.ch lists and the person's key (MalwareBazaar, URLhaus, ThreatFox since the public exports closed): kept on the computer (600), shown masked, never in a written address; without a key or with a refused one, lists not checked |
| `src/protection/outil.rs`, `src/protection/secrets_git.rs`, `src/protection/conteneurs.rs` | secrets in git project history (Vanguard's rules, plus gitleaks when present); open source tools run when installed, installation offered otherwise (trivy on Docker or Podman images) |
| `src/reseau/surveillance.rs` | systemd timer / Task Scheduler, notifications |
| `src/reseau/tableau.rs` | monitoring dashboard: alert log (bounded in number and age), single-file local HTML page (state, alerts by day, new devices, connections to botnets) |
| `src/audit/mod.rs`, `score.rs`, `fiches.rs` | network audit by domain (Exposure, Wi-Fi, Segmentation, DNS and TLS, Devices, Computers), defensive only: scores (100 minus penalties, no score when more than a third could not be checked), rule sheets (“COM-XXX-000” identifier, FR/EN subject, cited references) |
| `src/audit/exposition.rs`, `igd.rs`, `http_local.rs`, `ipv6.rs` | Exposure domain: what the home shows to the Internet from the scan, the address seen from the Internet (STUN) and IPv6; pure-Rust UPnP IGD client (SSDP, XML description, SOAP actions, all bounded; the gateway only, others claiming to be the router are reported; never this machine nor a host other than the description's) with its tiny HTTP/1.1 client for the local network; the computer's public IPv6 addresses and the neighbours that have one (netlink) |
| `src/audit/wifi.rs`, `segmentation.rs`, `arp.rs` | Wi-Fi (cipher of the connected network, WPS, several transmitters for one name, remembered networks), Segmentation (IoT devices alongside computers, guest network, who hands out addresses, IPv6 routers) and ARP integrity (router MAC that changes, a computer maker's address, one MAC for several IPs) domains |
| `src/audit/dns_tls.rs`, `dns_client.rs`, `bail.rs` | DNS and TLS domain: DNS handed out by the router compared with the computer's, encrypted DNS (DoT, DoH, DDR), resolver compared with two public resolvers, certificate exceptions and roots pushed into Firefox; home-made UDP DNS client (A, AAAA, TXT, SVCB, HTTPS, EDNS0, DO bit), bounded; DHCP lease and effective DNS configuration read from files and the registry |
| `src/audit/tls_pq.rs`, `ssh_kex.rs` | post-quantum side of the audit, without computing any key: hand-written TLS 1.3 ClientHello (X25519MLKEM768 only, empty key share, padded to 1,600 bytes) and reading of the answer (HelloRetryRequest or alert); KEXINIT of an SSH server on the local network read, then the connection closed; bounded, fuzzed |
| `src/audit/appareils.rs`, `postes.rs` | Devices (IoT devices recognised from the scan, nothing probed beyond the camera search) and Computers (this computer as seen from the network: the report's network findings; the other computers from the scan) domains |
| `src/rapport.rs`, `src/historique.rs` | HTML report, check history, grade curve |
| `src/modele/` | common findings model: `rule + object` key without translated text (`id.rs`), state healthy, not applicable, not checked with its reason, or problem (`etat.rs`, `raison.rs`), prefixes and tool identifiers (`registre.rs`), versioned inventory of state files from which `sceau` takes what it protects (`inventaire.rs`); common error channel `Echec` with its stable code (`raison.rs`); append-only event log, chained on the exact bytes, sealed head, sealed closed months, linked by `cause` (`evenement.rs`, `journal.rs`); serializable result of the tools run on their own, written to `examens/` and to the log (`resultat.rs`, used by the `resultat.rs` of `espions`, `perimes`, `courriel_suspect`, `telechargement`, `acces`, `lien`, `sortantes`, `distance`, `diagnostic`, `lenteur`, `reseau::objets`, `reseau::connexion` and `reseau::listes_noires`); recognized rule frameworks: CIS, Microsoft, ANSSI (`reference.rs`) |
| `src/canaris.rs` | format canaries (tests only): each real source downloaded with the program's own request and read back by its reader; run by the night watch (`VANGUARD_CANARIS`), never by `cargo test` |
| `src/autotest/` | self-test (`vanguard autotest`, and every week with the monitoring): check rules under a guard and a time limit, findings invariants, report without any value read, exit code (`mod.rs`); process-wide read-only switch and proof by BLAKE3 fingerprints of the data folder (`lecture_seule.rs`); registry of the cross-checks native versus system tool, allowed read commands (`croisees.rs`, declared in `machine/linux/croisees.rs` and `machine/windows/croisees.rs`); timings log, duration of each rule summarized per day, slowdowns (`mesures.rs`); bounded local self-tuning: start order of the rules, longest first, time limit of a rule that comes close to it two weeks in a row raised from 10 to 30 min, each change noted and undoable in Settings, never a detection threshold or rule, cache duration of a rule shortened when the cache is often wrong (`reglage.rs`, sealed `autotest/reglage.json`); cache of the hourly pass only: a few slow rules whose state changes little (table of durations), reused at most every other pass with their age, never a rule that can reveal an attack, cleared on every fix, requested check or undo, measured in `mesures.rs`, 10 MiB at most (`cache.rs`, sealed `autotest/cache.json`) |
| `src/sceau.rs` | seals of Vanguard's state (accepted alerts, integrity reference, reported botnets, versions seen and revocation of the main key, Optimize's previous values, alerts declared normal, real-time, audit, sites and gateway already reported): changed outside Vanguard, it no longer counts and the check says so; deleted along with the seals, “unknown”, never a first run; only a plain file of bounded size; as root, only in a root-owned folder |
| `src/reparer.rs`, `src/maj.rs`, `src/gaming/` | repairs, updates, gaming |
| `src/optimiser/` | privacy, performance and comfort settings, with exact undo; the same mechanism for check-up fixes and gaming settings (`annulables.rs`: gestures from a closed list, previous value read then sealed in reglages.json, jeux.json notes taken over); startup programs (`demarrage.rs`); Windows Defender blocking: basic ASR rules and those against booby-trapped documents (all 19 are set one by one in the defense options), network protection, PUA, controlled folder access (`defender.rs`) |
| `src/nettoyer/` | cleanup: items per system, space measured before and after |
| `src/logiciels/` | software to install: checked catalog (`catalogue.rs`), state and installation per system |
| `src/protection/fuites.rs`, `src/donnees.rs` | leaked passwords, data backup |
| `src/protection/cle.rs` | USB drive protection on Linux: partition remounted read-only away from the owner's computer |
| `src/guide/` | command guide: one file per system (`arch.rs`, `omarchy.rs`, `fedora.rs`, `debian.rs`: each distribution's programs and step-by-step guides; `linux.rs`: programs common to all, and openSUSE; `windows.rs`, `tous.rs`), menus and search (`mod.rs`), commands run here (`lancement.rs`), tldr-pages examples downloaded every week and copied to the key at deployment (`tldr.rs`, `tldr/cle.rs`) |
| `src/apprentissage.rs` | what Vanguard learns here: alerts declared normal (appris.json), habits |
| `src/reseau/listes_noires.rs` | the home's Internet address in blocklists (DNSBL), after consent |
| `src/voulues.rs`, `src/programmes_poses.rs` | wanted defenses (hourly monitoring, watcher, ransomware watch): turning on and off by Vanguard noted in a sealed state and in the log, a cut without Vanguard reported, a doubtful state never green; program started by each task (monitoring, check-up, watcher): path and BLAKE3 fingerprint sealed when placed and updated, compared at the check |
| `src/entretien.rs` | monthly check-up: grade, updates, space, new problems, in one notification |
| `src/protection/sortantes.rs` | who talks to the Internet: established connections by program (ss, PowerShell, lsof), reverse DNS; botnet command servers (Feodo Tracker without a key, ThreatFox with the abuse.ch key: full export read by its header, and API) |
| `src/protection/environnement.rs` | at startup: library injected into the session (LD_PRELOAD, DYLD, AppInit_DLLs), judged like preloading |
| `src/protection/manifeste.rs` | check Vanguard itself (version, commit date, SHA-256) and key manifest (BLAKE3 checksums kept on the owner's computer, one reference per key, compared in the check; Ventoy menu and ISO image sizes included, restated by images-cle.sh; a recognized key whose volume identifier changed: reported) |
| `src/protection/cles_connues.rs` | VANGUARD keys known to this computer (`vanguard.jeton` token written at deployment, `cles-connues.json`); per key, the checksum of the record as Vanguard wrote it and its protection: a record changed outside Vanguard is neither read nor rewritten |
| `src/protection/distance.rs` | is my computer being controlled? remote control tools (installed, at boot, running, downloaded), in the check and as a guided walkthrough |
| `src/protection/espions/` | spyware: is someone watching me? `echap` (Échap list, CC-BY 4.0, downloaded when used, read by a bounded YAML reader written for the project; servers, sites, names), `connus` (desktop monitoring software, each pattern with its source), `clavier` (Linux: who holds /dev/input), `windows` (installed, services, Run, processes); read-only, in the check without network |
| `src/protection/perimes/` | outdated software (Windows): `version` (strict comparison, per-publisher normalization), `sources` (closed table of fixed public files, downloaded in full, the same for everyone; copy kept one day, unreadable answer refused), `produits` (table of followed programs and their lines in CISA's catalog), `windows` (inventory: executables, publishers' files, registry without RegLoadKey), `verdicts` (one rule per product), `mozilla_avis` (Mozilla advisories read without a YAML library: Firefox checked flaw by flaw), `rapport` (screen and check-up); read-only |
| `src/protection/courriel_suspect/` | is this email a scam? bounded, standalone MIME reading (`mime.rs`, fuzzed), sender and the provider's SPF/DKIM/DMARC (`entetes.rs`), links in text and HTML (`corps.rs`), attachments in a disposable folder (`pieces.rs`) |
| `src/protection/lien.rs` | is this link dangerous? local check (punycode, imitated brands…), then RDAP, URLhaus, Spamhaus DBL, SURBL |
| `src/protection/telechargement.rs` | check a downloaded file: checksum by the system's tool, name and content, Vanguard's engine then the system's antivirus; result recorded and `--json` (`telechargement/resultat.rs`); programs landing in Downloads, for monitoring |
| `src/protection/blocage/` | threat blocking: each threat offers “Block” (action shown, accepted, written down, undoable); active protection, after a consent given once, blocks what is certain by itself (MalwareBazaar fingerprint, known attack tool, command server) at the check-up and in the hourly monitoring; as administrator, the consent and the automatic modes in blocage.json (sealed, but still writable by a program of the account that remakes the seal) block nothing by themselves (`pour_agir`). `parametres` (blocage.json: one mode per category), `menaces` (what is found), `gestes` (prepare, do, undo), `gardes` (pure safeguards: Vanguard, critical processes, system programs, remote sessions), `pare_feu` (ufw, nftables, Windows Firewall, pf), `ordres` (the closed list of steps done as administrator, with typed parameters, parsed again and judged again by whoever acts; their written form, parsed without I/O and fuzzed, in `ordres_ligne`), `arret` (stopping a process by its number and its program, without a race: pidfd on Linux) |
| `src/protection/isolement.rs`, `src/machine/linux/isolement.rs`, `src/machine/linux/nftables/isolement.rs`, `src/machine/windows/isolement.rs` | isolating the computer from the network (closed orders `Isoler` and `LeverIsolement`, re-judged by the elevated side): the current remote session found before any rule and kept by its exact connection (remote address and port, local port), refused if it cannot be with certainty; allowed: loopback, DHCP, the DNS in place (port 53), Vanguard's servers resolved at isolation time (HTTPS only), except for a ransomware isolation (verb `isoler-sans-serveurs`: no server, the elevated side does not resolve them). Linux: table `inet vanguard_isolement` (drop policy) set again at boot by its own oneshot unit `vanguard-isolement.service`, state in root folders; lifted by the table first, the state and unit only afterwards. Windows: Block rules inbound and outbound, by protocol and ports (exact complement of what is allowed, a new generation set before the old one is removed), “block all incoming connections” per profile, previous values noted in the description and restored exactly. Banner at each launch; lifted with `vanguard blocking undo` |
| `src/machine/vidage.rs`, `src/machine/windows/services_ecriture.rs` | acts of the elevated Windows process (`vanguard:service`, `vanguard:vider`, `vanguard:vider-file-impression`, `vanguard:mettre-de-cote`, closed table in `gestes.rs`): services stopped, started and set through the service manager (advapi32), dependents included, without PowerShell; Windows folders emptied or set aside without following a link or a junction, tested on Linux |
| `src/machine/assistant.rs`, `src/machine/gestes_unix.rs`, `src/machine/arret_designe.rs`, `src/machine/decoupe.rs` | the elevated helper of Linux (`vanguard appliquer-eleve`, hidden): Vanguard relaunched through pkexec, run0 or sudo, on the running image (/proc/<pid>/exe), which does the blocking orders and the Linux acts without any shell; channel through its input and output, list read again then judged again; an act that weakens or deletes waits for “yes” on the terminal. `gestes_unix`: the closed grammar of the acts (`vanguard:geste programme <id>`, table of fixed programs), fuzzed; `arret_designe`: stopping a designated remote-control program, judged (a session carried by it, stop commands read back), only after “no” to “are you connected through it?”; `decoupe`: where a list of fixes goes from native to shell, shared by Windows and Unix. The other fixes go through bash in an emptied environment (`commande::bash_propre`: system PATH, neither BASH_ENV nor startup file) |
| `src/machine/defense.rs`, `src/machine/defense_eleve.rs`, `src/machine/defense_eleve/`, `src/machine/note_avant_unix.rs` | Linux defence (accounts, rights, persistence, traces, network, system): `defense` builds the `vanguard:geste defense …` acts of a finding (all or none, at most 8); `defense_eleve` judges them again and does them in the elevated helper, without a shell (account locked, removed from a group, sudo addition checked by visudo, setuid and capabilities removed, service stopped, startup line removed, folder given back to root; `defense_eleve/systeme.rs`: SSH hardened by a sshd_config.d file checked by `sshd -t`, BPF kept for root, journal kept on disk, trust anchor removed, proxy commented out, Bluetooth device forgotten; `defense_eleve/programme.rs`: traces of a program copied before it is stopped; `defense_eleve/pose.rs`: a Vanguard program replaced outside Vanguard restored by a published and signed program, the other kept in quarantine, not undoable; `defense_eleve/pare_feu.rs`: the ufw, firewalld or nftables firewall turned off or back on by the person's choice, from the Defense options only, Vanguard's and iptables-nft's tables never removed), after a warning on /dev/tty when access may be lost (Enter = no), and notes the state before for Undo; `note_avant_unix`: the form of that note (root folder 0711, files 0600), without I/O and fuzzed |
| `src/machine/linux/netlink.rs`, `nftables.rs`, `couper.rs` | netlink written for the project: the nf_tables table `inet vanguard` added and removed in one batch (bytes checked against nft, test in a separate namespace), and cutting the connections already open through SOCK_DESTROY (instead of “ss -K”) |
| `src/protection/temps_reel.rs` | Vanguard's real-time protection: turned off at once (temps-reel.json: start and end, 1 h, 4 h or until turned back on), it stops each monitoring run at its start and has what blocking is certain of offered with one click, without touching their settings; once its time is up it no longer counts, and the monitoring removes the file; unreadable, nothing is turned off; never Defender, the firewall or UAC; not set as administrator |
| `src/protection/quarantaine.rs`, `src/protection/camera.rs` | reversible quarantine, the single path for blocking, the antivirus and YARA: isolate (SHA-256 kept, action noted and undoable), put back exactly, delete; camera and microphone: who uses them (registry on Windows, /dev/video and pactl on Linux) |
| `src/protection/acces.rs` | privacy check: apps that can access location, contacts, camera and microphone (ConsentStore on Windows, Flatpak and Snap on Linux); read-only |
| `src/reseau/canaux.rs`, `src/reseau/nat.rs` | crowded Wi-Fi (nearby networks by channel); NAT type (home-made STUN client) |
| `src/dns_rapide.rs` | fastest DNS: measurement, protecting DNS kept, setting undone through `optimiser/` |
| `src/reseau/cameras.rs` | hidden cameras: maker, RTSP stream, ONVIF discovery (WS-Discovery), web page |
| `src/reseau/wifi_public/` | public Wi-Fi mode: sealed and validated previous state (`etat.rs`), pure commands and readings per system (`linux.rs`, `windows.rs`), suggestion and portal page without sending anything (`portail.rs`), turning on, off, safe shutdown and check finding (`mod.rs`) |
| `src/reseau/objets.rs` | router and connected devices: what the router announces (SNMP, UPnP, web header), admin over HTTP only, devices recognized by maker, name, ports and announcements; default-password advice, never checked (no attempt, nothing more probed); scan section and `vanguard smart-devices` from the notebook |
| `src/depanner/` | troubleshoot step by step: the paths (`mod.rs`), network and Wi-Fi (`reseau.rs`), sound (`son.rs`), printer (`imprimante.rs`), after an infection (`infection.rs`), new computer (`nouveau.rs`), computer leaving (`depart.rs`), hacked account (`compte.rs`), a relative's computer (`proche.rs`: three questions, a summary of five points at most ordered by the answers, tips for the page to leave behind), slow since an update (`depuis_maj.rs`) |
| `src/protection/preuve.rs`, `src/protection/sources.rs`, `src/protection/normales.rs` | the evidence recorded before each block or quarantine (process, command line, SHA-256, connections; "not possible (reason)" otherwise); the single path to threat sources (MalwareBazaar, offensive tools, COM-PRG-001) for blocking, the check and the watcher; watcher, monitoring and blocking alerts declared normal (sealed, 90 days) |
| `src/traces/` | collect the traces: processes with their SHA-256, network, startup, JSON check, accounts, logs of the last 7 days, recent files, what Vanguard saw and did (`vanguard.rs`: alerts, actions and their evidence, incident threads, state files copied), then LISEZMOI and MANIFESTE (`sha256sum -c` format), in a dated folder; shared part (`mod.rs`), per system (`linux.rs`, `windows.rs`, `unix.rs`), incident timeline (`chronologie.rs`: CHRONOLOGIE.txt, what was read with a date put back in time order over 7 days, 5,000 lines at most; on Windows, the EVT- alerts at their time, through `journaux_windows.rs`); read-only |
| `src/lenteur.rs`, `src/fiche.rs` | why it is slow (two-sample snapshot, startup); computer specs |
| `src/copier.rs` | copy my files to an external disk: checked copy (BLAKE3), resume, never overwrites; check a copy (restore test) |
| `src/verifier_cle.rs` | check my drive: real capacity, speeds and bad blocks, written into the free space and read back without cache, then erased |
| `src/passage.rs` | takeover of what a version from before the name change left (data, timers, shortcut, firewall rules), leftovers listed for the uninstall; to be removed at 1.0 |
| `src/desinstaller.rs` | remove Vanguard from a computer: what it placed, recomputed without a register (with passage.rs for earlier names), shown, checked; data after a second consent |
| `src/options_defense.rs`, `options_defense/ecran.rs`, `options_defense/ecran/pare_feu.rs`, `options_defense/linux.rs` | defense options (4.10 on Windows, 4.9 on Linux); on Windows: model, interpretation (Defender mode, option values, ASR rule actions, GPO and Intune policies, firewall profiles, Security Center, managed PC), JSON without personal data, texts of the choices; the screen that chooses (`ecran.rs`: sub-screens, exclusions and allowed apps re-read, ASR rules one by one with the warning of the 8 left out of the Recommended settings, changes sent together under a single administrator prompt, result re-read); the firewall screen (`pare_feu.rs`: three profiles, four settings each, existing rules searched then enabled or disabled, never deleted, remote-session guards stated); the reads in `machine/windows/defense_etat.rs` (native WMI, INetFwPolicy2, registry); on Linux (`linux.rs`), the firewall read without rights (ufw's configuration, systemd's state, the note of a turn-off), its rules called unchecked: the root child reads them, judges, warns and asks |
| `src/machine/windows/*_ecriture.rs`, `choix_avant.rs`, `choix_note.rs`, `journal_evenements.rs`, `protege.rs`, `signature.rs`, `quarantaine.rs`, `demarrage_notes.rs`, `ssh_regles.rs` | defense actions of the elevated Windows process, each from one line of the closed grammar of `gestes.rs`, without PowerShell: Defender through WMI (`defender_ecriture`), root removed (`certificats_ecriture`), account disabled or password set (`comptes_ecriture`), a share's access removed, Run value, task, startup entry, Startup folder file and WMI subscription removed or disabled, registry settings (`reglages_ecriture`), hosts and DNS (`reseau_ecriture`), SSH permissions and sshd_config (`ssh_ecriture`, pure logic in `ssh_regles`); the “before” note of a person's choice under HKLM and “Turn back on” (`choix_avant`, form read by `choix_note`, fuzzed); one Windows event log entry per lowering (`journal_evenements`); the real Defender recognized by its location and signature (`protege`, `signature`: a signature only refuses); the elevated process's quarantine under %ProgramData% (`quarantaine`); the versioned copies of the Startup folder (`demarrage_notes`) |
| `src/ordinateurs.rs` | my computers: each computer's visit noted on VANGUARDLOG (categories and levels only) |
| `src/plugins/` | extensions: plugins (`mod.rs`: safe folder, approval by SHA-256, checked copy then run, `manifeste.rs`: plugin.toml read by a bounded home-made parser, `archive.rs`: .zip unpacked in Rust), lab (`labo.rs`), findings protocol (`sortie.rs`), restrictions switch (`reglages.rs`), menus (`menu.rs`); see the Extensions section |
| `extensions/` | Rust library to write a plugin (`sdk/`, crate `vanguard-extension`, outside the workspace) and examples (`exemples/`); how-to (in French): `extensions/LISEZMOI.md` |
| `src/chiffrement.rs` | protected key data: encrypted record (XChaCha20-Poly1305), data key kept by the owner and wrapped by the passphrase (Argon2id) |
| `assets/oui.tsv` | manufacturers by MAC prefix (IEEE list), stored as sorted tables at compile time (`build.rs`) |
| `assets/yara/` | ReversingLabs YARA rules (MIT license), gathered by `outils/maj-yara.sh` |
| `assets/banniere-blanche.png`, `assets/banniere-noire.png`, `assets/icones/`, `assets/vanguard.ico` | the banner (no background, one per GitHub theme) and the icon (the V), drawn cell by cell in the terminal banner's lettering by `outils/icone.py` |
| `LICENCES-TIERCES.txt` | license notices of the included libraries (`outils/licences-tierces.py`) |
| `src/commande.rs` | runs system commands with a maximum delay (`commande::lancer`), outputs read in the background: a tool that stops answering never freezes Vanguard |
| `src/coulisses.rs` | backstage (Settings, off by default): each command run, program and shortened, filtered arguments, duration, outcome, as a grey line on the terminal's error output; the last 200 in memory only (“see”), never on disk; `Suivie` for what does not go through `commande::lancer`, and a guard that refuses a direct launch |
| `src/compte_rendu/` | report for Claude (`vanguard autotest --report-for-claude`, hidden subcommand `vanguard compte-rendu`): error causes as validated fields, never a value read on the machine nor a text from the log, JSON read by the nightly watch then Markdown derived from it (`mod.rs`); patterned fields and closed lists shared with `outils/veille/schema-compte-rendu.json` (`champs.rs`); field line written at the end of each error-log entry and bounded log reader, fuzzed (`journal.rs`); triage of the log brought back by `outils/deployer.sh` into a queue of causes ranked by score, followed from one night to the next (`triage.rs`, `vanguard compte-rendu journal`); send batch of schema 2, 96 KiB at most, built, bounded and strictly re-read, with no bare `String` (`envoi.rs`, batch A3, fuzzed); reception at the author's (`flotte.rs`, batch A8, `vanguard compte-rendu flotte|envois`): each batch of the collection re-read by the same strict reading, refused if it names a version, rule or tool unknown to its tag, quarantined if the secret detector goes off, one voice per source and per day, a state made of closed lists, numbers and fingerprints; signals (`flotte/signaux.rs`, batch A9): at least 5 sources in 3 /16 networks, a likely false positive in a ticket only (never to the AI), open data in a block with a marker drawn at random, an unapproved name as `inconnu#…`; boundary: text from a batch is already cleaned by `amelioration::texte` and nothing in a batch is an instruction |
| `src/http.rs`, `src/http/envois.rs` | Vanguard's HTTPS requests (reqwest, instead of curl), bounded in size and time, to a closed list of hosts that the `envois` test compares with the threat model; an API key never goes through another program's command line |
| `src/journal.rs` | error log, anonymized, on the key's VANGUARDLOG partition or in Vanguard's folder; brought back by `outils/deployer.sh` |
| `src/diagnostic.rs` | computer diagnostic: hardware, system, recent errors and crashes; a text copy saved |
| `src/fenetre.rs` | the terminal window sized to each menu, centered on the screen |
| `src/essais.rs` | for tests only: a test that cannot run here says it was “skipped”, and `outils/verifier.sh` counts the skips |
| `src/machine/administrateurs.rs`, `journaux.rs`, `navigateur.rs`, `navigation_detournee.rs` | new administrators (noted the first time they are seen); sealed or cleared logs; browser security settings; imposed proxy and hijacked hosts file, in the check |
| `src/machine/logiciels_vus.rs`, `sshd.rs`, `windows/ssh.rs`, `windows/defender.rs` | installed software kept from one check to the next (logiciels-vus.json, sealed, never sent); sshd_config reading shared by Linux and Windows; OpenSSH server and .ssh keys on Windows (registry, WMI, file rights); Defender protections that “harden” turns on, re-read by the check |
| `src/machine/post_quantique.rs` | read-only post-quantum check (COM-PQC-001 to 003): key exchange list that sshd and ssh really keep depending on the OpenSSH version (computed in `sshd.rs`), pre-shared key of WireGuard tunnels counted without ever keeping the keys; the browsers' post-quantum key exchange (COM-NAV-004) is in `navigateur.rs` |
| `src/mise_a_jour/github.rs` | update from GitHub: Ed25519-signed manifest (main or backup key), highest version already seen, freshness; signed history of versions, to check a copy that is not the latest |
| `src/protection/integrite.rs`, `isoler.rs`, `memoire_dns.rs` | critical file integrity (BLAKE3 fingerprints); sandbox for an unknown program (bubblewrap or firejail, Windows Sandbox, sandbox-exec), also used for extensions; the computer's DNS cache, read without flushing it |
| `src/protection/kev.rs`, `sites_bloques.rs`, `src/reseau/upnp.rs` | CISA catalog of exploited flaws; dangerous sites blocked by the hosts file (URLhaus, ThreatFox); ports opened to the Internet through UPnP |
| `fuzz/` | fuzzing bench, outside the program's build: one target per reader, which includes its `src/` module by path (`fuzz/cale/` for the rest), seeds with made-up values (`outils/fuzz.sh`) |
| `fenetre/` | the Vanguard window (`vanguard-fenetre`, egui), a separate crate with its own Cargo.lock and `fenetre/deny.toml`; Linux with glibc, Windows; embedded fonts (`fenetre/polices/`, OFL) |
| `fenetre/src/commandes.rs`, `fenetre/src/lanceur.rs`, `fenetre/src/nettoyage.rs` | the closed list of commands run (fixed arguments, time limits); running the `vanguard` placed next to it (input closed, group killed on stop, bounded outputs); text cleaned before display; console and cleaning fuzzed (`fenetre_saisie`) |
| `fenetre/src/relais.rs`, `fenetre/src/bac_a_sable.rs` | Linux: the relay, split off at startup with the account's rights, the only one to start `vanguard` (numbered protocol, a request outside it = stop); the window's sandbox (Landlock according to the kernel version, no_new_privs; reading, display and graphics card only) |
| `fenetre/src/protocole.rs` | Linux: the frames between the window and its relay, alone, without any system call (read by the fuzzing bench, target `fenetre_relais`) |
| `fenetre/src/travail.rs` | Windows: each `vanguard` run in its own job object: Stop and the end of the command also kill what it started, and so does closing the window |
| `fenetre/src/appli.rs`, `fenetre/src/donnees/`, `fenetre/src/dessin/` | the window's state (screen, running command, console); JSON answers read without ever crashing (check, protection, journal, common result), fuzzed (`fenetre_donnees`); drawing, the only part that talks to egui (frame, screens, check, drawn icons) |

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

## Contribution rules

- Everything in Rust; small parts built in-house; no new dependency without the author's decision; audited
  cryptography only, never written for Vanguard.
- A new network destination: a line in "What leaves the computer" of MODELE-DE-MENACE.en.md (and the French page),
  otherwise the `envois` test fails.
- A new rule: its MITRE ATT&CK technique (detection) or mitigation (hardening) in its references, then
  `python3 outils/couverture-attack.py` to rebuild the map.
- A state file that Vanguard reads back: sealed, and a value changed outside Vanguard turns no defense off and grants
  no consent.

## Build, test, deploy

Requirements: `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu`, `musl` (musl-gcc), `mingw-w64-gcc`
and `clang`: ring (TLS) compiles a little C for each target, and so does YARA-X, the tests' oracle. Published
programs, however, are built by zig ("Reproducible build", below): `outils/compiler-version.sh` installs it itself,
without root, and takes nothing from the distribution. To deploy, also
`cargo install cargo-auditable --locked --version 0.7.7` and `cargo install cargo-audit --locked --version 0.22.2`,
the versions of the CI (`.github/workflows/ci.yml`): `deployer.sh` embeds in each program the list of its
dependencies, versions included (`cargo auditable build`), then looks for known vulnerabilities in it
(`outils/failles-programmes.sh`); without them, or in another version, it refuses.

```sh
outils/deployer.sh     # builds Linux (musl, static) + Windows, installs locally, pushes to GitHub, updates the key
```

Slow check? `VANGUARD_CHRONO=1 vanguard audit --json >/dev/null` gives each check's time (they run at the same time:
the slowest one sets the duration).

Tests: `cargo test` (Linux, in a throwaway data folder: never the computer's real data); Windows tests under Wine
(`cargo test --target x86_64-pc-windows-gnu` with a Wine runner); `cargo clippy --all-targets` on the two targets
(Linux and Windows), in strict mode (pedantic), without any warning; `cargo fmt --check`. Internal functions are
tested in their module; `tests/programme.rs` runs the real program the way a person would (help in both languages,
menus left, lists, refusals respected, audit and scan of 127.0.0.1 in JSON), with a throwaway home folder, without the
user's key or session. Full runs: `outils/test-linux/essai.sh` and, in the Windows virtual machine,
`TESTER-VANGUARD.bat` (dropped there by `deployer.sh`).

Vanguard no longer targets macOS: no code, no build, no published program. On master, on each push and on demand, the
`nomenclatures` job of `ci.yml` produces the SBOMs (CycloneDX, `outils/sbom.sh`), and a separate job, `attester`,
attests them (actions/attest, Sigstore) without running any repository code.

Continuous integration (`.github/workflows/ci.yml`): on each push to master and each pull request,
`outils/verifier.sh --ci`, the same check as on the author's computer except Wine, then the check-up on real
distributions; a real Windows (PowerShell, registry) on each push, each pull request, every night if the code changed
(`.github/hors-code.txt`) and on demand (`gh workflow run ci.yml`), with the reproducible build and the delivered .exe
(MinGW) tried on Windows. `verifier.sh` also checks the workflows with zizmor (offline) and builds everything with
`--locked`. The programs' protections (Linux: PIE, RELRO marking, non-executable stack, nothing writable and
executable; Windows: high-entropy ASLR, DEP, relocations, DLLs from System32, manifest), with the shipped system and
architecture (`--attendu linux|windows`: x86-64 ELF, PE32+ AMD64), are read from their headers by
`vanguard deploiement verifier-binaire`: on every `verifier.sh` run (the debug program, and the release ones when
built from this commit), in CI on the release ones, then before anything leaves in `deployer.sh` and
`publier-version.sh`. A refused program does not leave. Every night: cargo audit, cargo deny, and five minutes of
fuzzing per target. The repository is public: Linux and Windows minutes do not count.

Skipped tests: a test that cannot run on a computer (missing system tool, unreachable registry, root of a namespace)
does not return silently, it calls `crate::essais::saute("reason")` (`src/essais.rs`): `verifier.sh` counts these
skips next to the passed tests and shows their reasons, since a skipped test checked nothing. Menu navigation is
tried for real in a pseudo-terminal (`tests/programme.rs`, `menus_dans_un_terminal`), and the displayed texts are
compared with master (`outils/textes.py`).

Dependencies: `cargo deny` (`deny.toml`: known RustSec vulnerabilities, licenses from its list, crates.io only,
duplicates; `extensions/deny.toml` for the extensions library and the Rust example, which have no dependencies) and
`cargo audit` (a second opinion on vulnerabilities, with only the exceptions of `deny.toml`, which `.cargo/audit.toml`
copies), in `outils/verifier.sh` (skipped without the tool, cargo audit also without Internet) and every night in CI.
`cargo vet` (`supply-chain/`) also requires, at every verification and offline, an imported review (Google, Mozilla,
Bytecode Alliance, Zcash, ISRG) or an exemption at the exact number for each version: after a `cargo update`,
`cargo vet` (with Internet) reads the registries again and names what is missing; each remaining version gets its
exemption one by one, with its reason (`cargo vet add-exemption <crate> <version> --criteria … --notes "…"`), never
through `cargo vet regenerate exemptions`, which would exempt in one go an unknown dependency that came in with the
others; `cargo vet prune` removes what is no longer needed, and the diff of `supply-chain/config.toml` is read.
The list only keeps permissive licenses (MIT, Apache-2.0, BSD, ISC…), compatible with the GPL-3.0-or-later and with
a possible dual license of Vanguard: any other, even free and GPL-compatible (MPL, LGPL), first needs the author's
approval.

Fuzzing: `outils/fuzz.sh [target|tout] [seconds]` (cargo-fuzz and the nightly toolchain), on the readers of data
coming from elsewhere (HTTP and DNS replies, timeline logs, Windows .evtx logs, the router's UPnP XML, SQLite, Échap's
YAML, archives, .exe resources…). `outils/verifier.sh` builds the bench and spends five seconds on each target (a
target broken by a change in `src/` shows at once), CI five minutes every night; its dependencies go through cargo
deny (`fuzz/deny.toml`). A target is added in `fuzz/Cargo.toml`, which `fuzz.sh` reads.

Proofs: `outils/preuves.sh [tout|miri|kani]` (nightly toolchain with Miri, and Kani), every Thursday by the continuous
watch. Miri interprets the tests of the `unsafe` that work on Vanguard's own memory, and only them: the script runs
them by their exact name; a test that calls the system is not in its list; Kani proves, within a bound, a
few readers of hostile data (`outils/preuves/`, included by `#[cfg(kani)]` at the end of their module). To be rerun
after touching one of them; `outils/verifier.sh` compiles the Kani proofs at every check (a few seconds, without
running them).

Dead links: `outils/liens.py` opens every link of the repository (documentation, the program's code except tests,
scripts, licenses) and checks the internal links of the Markdown pages: target file, heading of an anchor, downloads
of the latest release. It runs by itself before each push (`git push`, `deployer.sh`) and before each release page; CI checks
the internal links (`--hors-ligne`). A dead link stops the push, a doubtful one (a site refusing programs, a server
down) is only shown. Links that cannot be opened as they are (an API endpoint, a namespace) are described in
`outils/liens.txt`.


### Reproducible build

Published programs are built by `outils/compiler-version.sh`, the same recipe for `outils/deployer.sh`, CI and anyone
who wants to rebuild a program from its tag: the toolchain of `rust-toolchain.toml`, Cargo.lock as is, the CI's
cargo-auditable version, the commit date (never the build time), and the build paths removed (the repository becomes
`/vanguard`, cargo's folder `/cargo`). Measured on October 23, 2026: the same commit built in two different folders
of this computer gives two identical programs, Linux and Windows alike; before, home folder paths stayed in the .exe
(`~/Projects/vanguard/target/…`), and two folders gave two programs. What still differs from one computer to
another, measured at 0.91.0 (same commit, same rustc 1.99.1, Arch here versus Ubuntu 26.04 in CI): the
distribution's C toolchain, which compiles the C of ring and blake3 and links the programs. For Windows, compared byte
by byte with the CI's .exe: same size, but the MinGW linker (binutils 2.47 versus 2.45.90) writes its version in the
PE header and lays out sections differently, and the mingw-w64 library (14.0.0 versus 13.0.0) makes the .exe import
another C runtime for the same `-lmsvcrt` from rustc: the UCRT DLLs (`api-ms-win-crt-*`) here, `msvcrt.dll` in CI;
the MinGW gcc differs too (16.2.0 versus 13.2.0). For Linux (CI does not keep its program): gcc, through musl-gcc,
leaves its name and version in the `.comment` section (16.2.1 here, Ubuntu's 15.2.0), and ld and musl differ too
(2.47 versus 2.46, 1.2.6 versus 1.2.5). Since then, the C toolchain is pinned, the same on both sides:
`outils/chaine-zig.sh` installs zig 0.17.0, downloaded from ziglang.org and checked by its SHA-256 fingerprint and by
its minisign signature (zig's public key in `outils/zig-minisign.pub`), and cargo-zigbuild 0.24.0
(`cargo install --locked`, its package's fingerprint checked), without root, in `~/.cache/vanguard-dev/chaine-zig` or
in CI's temporary folder; it refuses any file with another fingerprint. `outils/compiler-version.sh` then builds both
targets with `cargo zigbuild`, which makes zig the C compiler (ring, blake3) and the linker, with its own musl for
Linux and its own mingw-w64 for Windows. The .exe imports the UCRT C runtime (`api-ms-win-crt-*`), shipped with
Windows 10 and 11 without a redistributable, rather than `msvcrt.dll`, the old runtime kept for compatibility.
Measured on November 8, 2026: the same commit built this way in two different folders, with two zig installations,
gives two identical programs, Linux and Windows alike. The .exe's resources (icon, version information, manifest) go
through `zig rc` (`build.rs`) and its import libraries through `zig dlltool`: nothing from the distribution any more,
neither windres, nor its preprocessor, nor dlltool. These tools (rustc, zig, cargo-zigbuild, cargo-auditable) are
recorded on both sides by
`outils/chaine-c.sh` (build marker, `OUTILS-VANGUARD` lines of the CI log), and `outils/publier-version.sh` shows
those that differ. CI writes the fingerprint of its builds in its log (`EMPREINTE-VANGUARD-LINUX`, `-WINDOWS`), to
compare with `SHA256SUMS.txt`; `outils/publier-version.sh` takes those of a master run on the built commit, or on an
earlier or later commit that only changes files that are never compiled (screenshots, social preview, features page:
the closed list `HORS_COMPILATION`), in a straight line, without a merge and as plain files, and then says so in the
notes and in the signed history. If they differ from the author's computer's, `outils/publier-version.sh` refuses to
publish: it needs the override
`VANGUARD_PUBLIER_SANS_EMPREINTES_CI=1`, which is stated on the release page (notes, in French and English) and in the
signed version history (`historique.txt`, line `passe-droit-sans-empreintes-ci`, likewise `passe-droit-sans-vm` for
`VANGUARD_PUBLIER_SANS_VM=1`); a version published that way was not checked against CI.

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
lines, file names, author, message), before each push (`git push`, `deployer.sh`), before each release page (notes and compiled
programs), before each journal issue and before writing the screenshots. Once per copy of the repository:

```sh
git config core.hooksPath outils/hooks                                     # commit and push hooks
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

`outils/publier-version.sh` creates the version's GitHub release with the two programs (`vanguard-windows-x86_64.exe`,
`vanguard-linux-x86_64`), their SHA-256 checksums, their SBOMs (`vanguard-<system>.cdx.json`, made by
`outils/sbom.sh`, which needs cargo-cyclonedx 0.5.9: identical to those of the `nomenclatures` job of `ci.yml`, whose
attestation is checked before publishing) and, as notes, the commit of each version since the previous release (title
and bullets), the newest first; the README's download links always point to the latest one. `--notes` shows these
notes without publishing anything.

Every release goes to the key, the VM and GitHub (the code), with its page, 0.x.0 as well as 0.x.y: one a day as a
rule, since fewer releases mean fewer new programs that Defender and SmartScreen do not know yet. An intermediate
version of a series delivered back to back (`VANGUARD_INTERMEDIAIRE=1 outils/deployer.sh`) goes to the key and GitHub,
without a page or a drop in the VM: nothing is lost, since the next release takes over the versions before it. After
each push, it also updates the repository page (`outils/github.py`): English description followed by the latest
published version, link, topics and options, written in `.github/depot.json`. Only the social preview image is changed
by hand (Settings > Social preview).

## The USB key

The key (exFAT, label `VANGUARD`, marker file `vanguard.cle`) holds `Linux/`, `Windows/`, `donnees/` (device database,
portable), `source/` (this repository) and the guide in two languages (`README.txt`, `LISEZMOI.txt`, taken from
`outils/`). The check history and the quarantine stay on each computer.

On the development PC, it updates itself (systemd units in `outils/systemd/`, installed by
`outils/systemd/installer.sh`): after each build (`vanguard-copie.service`), each time it is plugged in, with the
latest version from GitHub, built if it is new (`vanguard-cle.service`, `deployer.sh --branchement`), and every day if
it stays plugged in (`vanguard-cle-maj.timer`, `outils/maj-cle.sh`: the program as on plug-in, then the images;
skipped without error when the key is not mounted).

The key has two partitions: `VANGUARD`, read-only everywhere except on its owner's computer (GPT attribute honored by
Windows; on Linux, Vanguard remounts it read-only itself), and `VANGUARDLOG`, which only receives the error log,
anonymized. `outils/preparer-cle.sh` prepares a new key.

In preparation, a rescue key that also boots computers: `outils/cle-secours.sh`, made by default, except on a computer
whose local setting turns it off (`CLE_SECOURS=non` in `~/.config/vanguard/images-cle.conf`, read without being run;
details at the top of `outils/images-cle.sh`). There, the key only carries the program: no images, no Ventoy, no
`WIN11`; the commands that would add them refuse and say so, and the timers copy nothing. Ventoy boots the Omarchy
installer, Arch, Debian and Fedora as network installers, SystemRescue and Windows 11 as a fallback, kept up to date
by `outils/images-cle.sh` (each project's signature checked, timer on the 1st and 15th of the month that copies right
away to a plugged-in key, copy on plug-in, a notification when each download starts and when nothing is new; an image
downloaded elsewhere enters the cache through `--importer`, checked the same way; the cache may be a link to another
disk: with that disk absent, nothing is recreated elsewhere; an optional image, off by default, only enters on a
computer whose local setting asks for it, read without being run); a FAT32 `WIN11` partition installs Windows 11 with
Secure Boot on, without adding a key to the PC (`install.wim` split by wimlib under the 4 GB limit); `VANGUARD` and
`VANGUARDLOG` as before. `--plan` and `--essai` (on a disk image) touch no disk; only `--ecrire` erases the key.
Ventoy itself: its version on the key is read every day and on plug-in (`cle-secours.sh --a-jour`); when older than
the pinned one, its update, which erases nothing (`Ventoy2Disk.sh -u`, logged), is offered by a notification to click.
It goes through a separate root part, `outils/ventoy-racine.sh`, installed once as a root-owned file
(`cle-secours.sh --installer-racine`, in `/usr/local/libexec/vanguard/`) and run by pkexec: the account cannot modify
it, and it holds the pin and checks everything again (the key and its serial number, the archive, an older version on
the key). A newer Ventoy on GitHub is reported to the developer by the search on the 1st and 15th, never taken on its
own: the archive is not signed, the pin changes by hand, then the root part is reinstalled. Windows 11 older than six
months (the date of its image's files) is reported by a notification, not replaced: Microsoft only gives a 24-hour
link, and the hash that checks the image is read on its page. `outils/essais-cle.sh` (run by `outils/verifier.sh`)
tests these tools without touching anything: separate namespace, no Internet, fake key and fake disk.

## Errors and crashes

Vanguard records them with nothing personal (on the key, or in its folder when the key is not plugged in). On
deployment, `deployer.sh` brings them back and `outils/journal-vers-github.py` turns them into GitHub issues (label
“journal”) with `gh`: one issue per error, repeats as comments. No GitHub password in the program or on the key.
